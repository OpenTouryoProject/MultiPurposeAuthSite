//**********************************************************************************
//* Copyright (C) 2017 Hitachi Solutions,Ltd.
//**********************************************************************************

#region Apache License
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License. 
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
#endregion

//**********************************************************************************
//* クラス名        ：AuthorizationCodeProvider
//* クラス日本語名  ：AuthorizationCodeProvider（ライブラリ）
//*
//* 作成日時        ：－
//* 作成者          ：－
//* 更新履歴        ：－
//*
//*  日時        更新者            内容
//*  ----------  ----------------  -------------------------------------------------
//*  2018/12/26  西野 大介         新規（分割
//*  2019/08/01  西野 大介         ReceiveをReceive＋ReceiveChallengeに分割
//*  2020/07/24  西野 大介         OIDCではredirect_uriは必須。
//*  2026/09/08  玄人 幸道         OIDCでもredirect_uriをcodeに紐付ける（#186）
//*  2026/09/11  玄人 幸道         request_uri 経路でも redirect_uri / PKCE を code に紐付ける（#197）
//*  2026/09/24  玄人 幸道         有効期限を検証する（期限切れは無いものとして扱う）（#188）
//*  2026/10/22  玄人 幸道         認可要求の dpop_jkt を code に紐付ける（#311 の段階 4）
//*  2026/11/03  玄人 幸道         列の幅を超える値は、引かずに「無い」とする（Oracle で 500 になっていた。#331）
//*  2026/11/04  玄人 幸道         消せた 1 つだけが引き換える（同時に引き換えると、複数にトークンが出ていた。#332）
//*  2026/11/12  玄人 幸道         見つからない request_uri のコメントを、Controller が先に断る形に合わせた（#362）
//*  2026/11/18  玄人 幸道         預けた Request Object の値を、文字列でなければ無いのと同じに読む（例外にしない。#377）
//*  2026/11/18  玄人 幸道         預けた Request Object を、日付の形の文字列を日付に変えずに読む（#403）
//*  2026/11/23  玄人 幸道         引き換えたコードを消さずに使用済みの印を立て、再利用されたら、そのコードから出したトークンを失効させる。コードに認可の ID を持たせる（RFC 6749 §4.1.2。#421）
//**********************************************************************************

using MultiPurposeAuthSite.Co;
using MultiPurposeAuthSite.Data;
using MultiPurposeAuthSite.Extensions.Sts;
using MultiPurposeAuthSite.Log;

using System;
using System.Data;
using System.Linq;
using System.Collections.Generic;
using System.Collections.Concurrent;
using System.Collections.Specialized;
using System.Security.Claims;

using Dapper;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;

using Touryo.Infrastructure.Framework.Authentication;

namespace MultiPurposeAuthSite.TokenProviders
{
    /// <summary>AccessTokenのpayloadを一時保存する。</summary>
    public class AuthorizationCodeProvider
    {
        /// <summary>
        /// AuthenticationCodes
        /// ConcurrentDictionaryは、.NET 4.0の新しいスレッドセーフなHashtable
        /// </summary>
        private static ConcurrentDictionary<string, CodeEntry>
                    AuthenticationCodes = new ConcurrentDictionary<string, CodeEntry>(StringComparer.Ordinal);

        /// <summary>メモリ ストアの 1 件（値と作成時刻）（#188）</summary>
        private class CodeEntry
        {
            /// <summary>値</summary>
            public string Value = "";
            /// <summary>作成時刻</summary>
            public DateTime CreatedDate = DateTime.MinValue;
            /// <summary>引き換えた時刻（null なら未使用）（#421）</summary>
            public DateTime? UsedDate = null;
        }

        /// <summary>
        /// **これより古い認可コードは、無いものとして扱う**（#188）
        /// </summary>
        /// <remarks>
        /// RFC 6749 §4.1.2 は短命（10 分以内を推奨）を求めている。
        /// 以前は CreatedDate を書くだけで読んでおらず、事実上の無期限だった。
        ///
        /// **DBMS では SELECT の条件に入れる**ので、期限切れの行は「見つからない」になり、
        /// これまでの「存在しない code」と同じ経路（空を返す）に合流する。
        /// ※ SQL Server の CreatedDate は smalldatetime（分の精度）。
        /// </remarks>
        private static DateTime ExpireLimit
        {
            get { return DateTime.Now - Config.OAuth2AuthorizationCodeExpireTimeSpanFromSeconds; }
        }

        /// <summary>メモリ ストアの期限内の行に、使用済みの印を立てる（#421）</summary>
        /// <param name="code">認可コード</param>
        /// <param name="reused">既に使用済みだったか（再利用）</param>
        /// <returns>値（無い・期限切れなら空。**再利用でも値を返す**：失効させる認可の ID を読むため）</returns>
        /// <remarks>
        /// **印を立てられた 1 つだけが引き換える**（#332）。**以前は行を消していた**ので、再利用に気付けなかった。
        /// **行は期限まで残す**（`SweepIfNeeded` が、作成時刻で消す）。
        /// </remarks>
        private static string MarkAsUsedInMemory(string code, out bool reused)
        {
            reused = false;

            if (!AuthorizationCodeProvider.AuthenticationCodes.TryGetValue(code, out CodeEntry entry)
                || entry.CreatedDate < AuthorizationCodeProvider.ExpireLimit)
            {
                return "";
            }

            lock (entry)
            {
                if (entry.UsedDate == null)
                {
                    entry.UsedDate = DateTime.Now;
                }
                else
                {
                    reused = true;
                }
            }

            return entry.Value;
        }

        /// <summary>メモリ ストアから、期限内の値を読む（期限切れは消す）（#188）</summary>
        /// <param name="code">認可コード</param>
        /// <returns>値（無い・期限切れなら空。**使用済みでも返す**：引き換えの前の確かめ（PKCE・DPoP）を通し、`Receive` で再利用に気付くため。#421）</returns>
        private static string GetFromMemory(string code)
        {
            CodeEntry entry = null;

            if (!AuthorizationCodeProvider.AuthenticationCodes.TryGetValue(code, out entry))
            {
                return "";
            }

            if (entry.CreatedDate < AuthorizationCodeProvider.ExpireLimit)
            {
                // 期限切れ。参照した時点で消す。
                AuthorizationCodeProvider.AuthenticationCodes.TryRemove(code, out CodeEntry _);
                return "";
            }

            return entry.Value;
        }


        #region 掃除（期限切れの行）

        /// <summary>前回まとめて消した時刻</summary>
        private static DateTime LastSweep = DateTime.MinValue;

        /// <summary>まとめて消す間隔</summary>
        /// <remarks>
        /// **常駐の仕組み（バッチ・タイマ）を増やさず、書き込みのついでに消す**（#188 の案 4）。
        /// 参照時にも期限切れは消えるが、**一度も参照されない行は残る**ため。
        /// 間隔を空けるのは、書き込みのたびに全件を走査しないため。
        /// </remarks>
        private static readonly TimeSpan SweepInterval = TimeSpan.FromMinutes(10);

        /// <summary>間隔を過ぎていたら、期限切れの行をまとめて消す</summary>
        private static void SweepIfNeeded()
        {
            DateTime now = DateTime.Now;

            lock (AuthorizationCodeProvider.SweepLock)
            {
                if (now - AuthorizationCodeProvider.LastSweep < AuthorizationCodeProvider.SweepInterval)
                {
                    return;
                }

                AuthorizationCodeProvider.LastSweep = now;
            }

            DateTime limit = AuthorizationCodeProvider.ExpireLimit;

            switch (Config.UserStoreType)
            {
                case EnumUserStoreType.Memory:

                    foreach (KeyValuePair<string, CodeEntry> kv in AuthorizationCodeProvider.AuthenticationCodes)
                    {
                        if (kv.Value.CreatedDate < limit)
                        {
                            AuthorizationCodeProvider.AuthenticationCodes.TryRemove(kv.Key, out CodeEntry _);
                        }
                    }

                    break;

                case EnumUserStoreType.SqlServer:
                case EnumUserStoreType.ODPManagedDriver:
                case EnumUserStoreType.PostgreSQL: // DMBMS

                    using (IDbConnection cnn = DataAccess.CreateConnection())
                    {
                        cnn.Open();

                        switch (Config.UserStoreType)
                        {
                            case EnumUserStoreType.SqlServer:

                                cnn.Execute(
                                    "DELETE FROM [AuthenticationCodeDictionary] WHERE [CreatedDate] <= @Limit",
                                    new { Limit = limit });

                                break;

                            case EnumUserStoreType.ODPManagedDriver:

                                cnn.Execute(
                                    "DELETE FROM \"AuthenticationCodeDictionary\" WHERE \"CreatedDate\" <= :Limit",
                                    new { Limit = limit });

                                break;

                            case EnumUserStoreType.PostgreSQL:

                                cnn.Execute(
                                    "DELETE FROM \"authenticationcodedictionary\" WHERE \"createddate\" <= @Limit",
                                    new { Limit = limit });

                                break;
                        }
                    }

                    break;
            }
        }

        /// <summary>掃除の間隔を測るための錠</summary>
        private static readonly object SweepLock = new object();

        #endregion

        #region Create

        /// <summary>
        /// 認可コードに紐付ける値（redirect_uri / code_challenge / code_challenge_method）の出どころを決める。
        /// </summary>
        /// <param name="queryString">認可リクエストのクエリ文字列</param>
        /// <returns>値を読む NameValueCollection</returns>
        /// <remarks>
        /// request_uri（JAR / PAR）で認可した場合、これらの値は署名付きの Request Object の中にあり、
        /// クエリ文字列には無い。クエリ文字列から読むと null が保存され、
        /// redirect_uri の照合（#186）が素通りになり、PKCE も検証できなくなっていた（#197）。
        /// RFC 9101 5 : Request Object を使うときは、その中の値だけを使う（クエリ文字列の同名の値は使わない）。
        ///
        /// Request Object が見つからないときは、Controller も同じくクエリ文字列の値で処理を続ける
        /// （その後の ValidateAuthZReqParam で弾かれる）。ここもクエリ文字列に戻して、扱いを揃える。
        ///
        /// ※ Request Object は Controller でも読んでいる（RequestObjectProvider.Get）。
        ///    ここで読み直せるのは、Get が消費しない（削除しない）ため。
        ///    **ワンタイム化は、読む回数を減らすのではなく、認可応答を作り終えた時点で消すことで実現した**
        ///    （CmnEndpoints.ConsumeRequestObject。#188 の段階 2）。
        /// </remarks>
        private static NameValueCollection GetAuthorizationRequestParams(NameValueCollection queryString)
        {
            string request_uri = queryString[OAuth2AndOIDCConst.request_uri];

            if (string.IsNullOrEmpty(request_uri))
            {
                // クエリ文字列の経路
                return queryString;
            }

            string requestObjectPayloadString = RequestObjectProvider.Get(
                request_uri.Replace(OAuth2AndOIDCConst.UrnRequestUriBase, ""));

            if (string.IsNullOrEmpty(requestObjectPayloadString))
            {
                // 見つからない request_uri（**Controller が先に断る**ので、通常は来ない。#362。
                //   以前は Controller もクエリ文字列の値で続けていた）
                return queryString;
            }

            //  **日付の形の文字列を、日付に変えずに読む**（#403。以前は既定の読み方で、日付の形の値が書式の変わった文字列になっていた）。
            JObject requestObjectPayload = MultiPurposeAuthSite.Util.Sts.JwtUtil.TryParseObjectAsIs(requestObjectPayloadString);

            if (requestObjectPayload == null)
            {
                return queryString;
            }

            // Request Object の値だけを使う（入っていなければ null のまま）。
            //   **文字列でなければ、無いのと同じに扱う**（#377）。**以前は `(string)` で読み、配列・オブジェクトだと例外（500）になった。**
            //   **PAR・`/ros` は、文字列でないものを預からない**（`CmnRequestObjectEndpoint.AreAuthZParamsWellTyped`）ので、ここは念のための守り。
            NameValueCollection ret = new NameValueCollection();
            ret[OAuth2AndOIDCConst.redirect_uri] = AuthorizationCodeProvider.StringOrNull(requestObjectPayload, OAuth2AndOIDCConst.redirect_uri);
            ret[OAuth2AndOIDCConst.code_challenge] = AuthorizationCodeProvider.StringOrNull(requestObjectPayload, OAuth2AndOIDCConst.code_challenge);
            ret[OAuth2AndOIDCConst.code_challenge_method] = AuthorizationCodeProvider.StringOrNull(requestObjectPayload, OAuth2AndOIDCConst.code_challenge_method);

            // **DPoP の鍵の申告も、Request Object の中から読む**（#311 の段階 4）。
            //   **ここに足し忘れると、JAR / PAR の経路だけ縛りが外れる**（#197 と同じ落ち方）。
            ret[OAuth2AndOIDCConst.dpop_jkt] = AuthorizationCodeProvider.StringOrNull(requestObjectPayload, OAuth2AndOIDCConst.dpop_jkt);

            return ret;
        }

        /// <summary>payload の値が JSON の文字列なら、その値（無い・文字列でなければ null。#377）</summary>
        /// <param name="payload">預けた Request Object の payload</param>
        /// <param name="name">名前</param>
        /// <returns>文字列か null</returns>
        /// <remarks>
        /// **`Date` も文字列として読む**（念のため）。**預けた中身は、日付に変えない読み方で読む**（#403）ので、今は `Date` は来ない。
        /// </remarks>
        private static string StringOrNull(JObject payload, string name)
        {
            JToken value = payload[name];

            return (value != null && (value.Type == JTokenType.String || value.Type == JTokenType.Date)) ? (string)value : null;
        }

        /// <summary>CreateAuthenticationCode</summary>
        /// <param name="identity">ClaimsIdentity</param>
        /// <returns>code</returns>
        public static string Create(ClaimsIdentity identity, NameValueCollection queryString)
        {
            string code = Guid.NewGuid().ToString("n") + Guid.NewGuid().ToString("n");

            Dictionary<string, string> temp = new Dictionary<string, string>();

            // 有効期限が無効なtokenのペイロードだけ作成
            //  **認可の ID を決めて、payload に書く**（#421）。
            //    **payload は access_token と refresh_token に引き継がれる**ので、
            //    **このコードから出したトークンは、更新したものも含めて、同じ値を持つ。**
            //    **コードが再利用されたら、この値を失効させる**（RFC 6749 §4.1.2。`Receive`）。
            string access_token_payload = CmnAccessToken.CreatePayloadForCode(
                identity, DateTimeOffset.Now, Guid.NewGuid().ToString("N"));
            temp.Add(Const.AuthZCodeAccessTokenPayload, access_token_payload);

            // redirect_uri 対応
            // 認可リクエストのredirect_uriをcodeに紐付ける（#186）。
            // Tokenリクエストでの照合は、CheckClientIdAndRedirectUriが行う。
            // - RFC 6749 4.1.3 : 認可リクエストに含めた場合、Tokenリクエストでも必須
            // - OIDC Core 3.1.3.1 : OIDCでは必須
            // ※ 認可リクエストに指定が無い場合（事前登録のみ）はnullが入り、照合はスキップされる。
            //    Device AuthZ / CIBAは空のqueryStringを渡すので、この経路に入る。
            // ※ request_uri（JAR / PAR）の経路では、値を Request Object から読む（#197）。
            NameValueCollection authZReq = AuthorizationCodeProvider.GetAuthorizationRequestParams(queryString);

            temp.Add(OAuth2AndOIDCConst.redirect_uri, authZReq[OAuth2AndOIDCConst.redirect_uri]);

            // OAuth PKCE 対応
            temp.Add(OAuth2AndOIDCConst.code_challenge, authZReq[OAuth2AndOIDCConst.code_challenge]);
            temp.Add(OAuth2AndOIDCConst.code_challenge_method, authZReq[OAuth2AndOIDCConst.code_challenge_method]);

            // DPoP 対応
            //   **認可要求で申告された鍵の指紋を、コードに紐付ける**（RFC 9449 §10。#311 の段階 4）。
            //   **`/token` での照合は GetDPoPJkt を読む側が行う**（`CmnEndpoints`）。
            //   **指定が無ければ null が入り、照合はスキップされる**（PKCE と同じ扱い）。
            temp.Add(OAuth2AndOIDCConst.dpop_jkt, authZReq[OAuth2AndOIDCConst.dpop_jkt]);

            // 新しいCodeのticketをストアに保存
            string jsonString = JsonConvert.SerializeObject(temp);

            // 期限切れの行を、間隔を空けてまとめて消す（#188 の案 4）
            AuthorizationCodeProvider.SweepIfNeeded();

            switch (Config.UserStoreType)
            {
                case EnumUserStoreType.Memory:
                    AuthorizationCodeProvider.AuthenticationCodes[code] =
                        new CodeEntry { Value = jsonString, CreatedDate = DateTime.Now };
                    break;

                case EnumUserStoreType.SqlServer:
                case EnumUserStoreType.ODPManagedDriver:
                case EnumUserStoreType.PostgreSQL: // DMBMS

                    using (IDbConnection cnn = DataAccess.CreateConnection())
                    {
                        cnn.Open();

                        switch (Config.UserStoreType)
                        {
                            case EnumUserStoreType.SqlServer:

                                cnn.Execute(
                                    "INSERT INTO [AuthenticationCodeDictionary] ([Key], [Value], [CreatedDate]) VALUES (@Key, @Value, @CreatedDate)",
                                    new { Key = code, Value = jsonString, CreatedDate = DateTime.Now });

                                break;

                            case EnumUserStoreType.ODPManagedDriver:

                                cnn.Execute(
                                    "INSERT INTO \"AuthenticationCodeDictionary\" (\"Key\", \"Value\", \"CreatedDate\") VALUES (:Key, :Value, :CreatedDate)",
                                    new { Key = code, Value = jsonString, CreatedDate = DateTime.Now });

                                break;

                            case EnumUserStoreType.PostgreSQL:

                                cnn.Execute(
                                    "INSERT INTO \"authenticationcodedictionary\" (\"key\", \"value\", \"createddate\") VALUES (@Key, @Value, @CreatedDate)",
                                    new { Key = code, Value = jsonString, CreatedDate = DateTime.Now });

                                break;
                        }
                    }

                    break;
            }

            return code;
        }

        #endregion

        #region Receive

        #region Receive

        /// <summary>Receive（引き換える。**1 回だけ**）</summary>
        /// <param name="code">string</param>
        /// <param name="client_id">string</param>
        /// <param name="redirect_uri">string</param>
        /// <returns>PayloadForCode（存在しない・期限切れ・使用済み・別のクライアントのものなら空）</returns>
        /// <remarks>
        /// **使用済みの印（`UsedDate`）を、条件付きで立てられた 1 つだけが引き換える**（#332）。
        /// **以前は行を消していた**ので、**2 回目は存在しないコードと見分けられなかった**（#421）。
        /// **行は、コードの期限まで残す**（`SweepIfNeeded` が作成時刻で消す）。
        ///
        /// **使用済みのコードが、同じクライアントから再び出されたら、そのコードから出したトークンを失効させる**
        /// （RFC 6749 §4.1.2 の SHOULD。`RevocationProvider.RevokeAuthorization`）。**応答は、これまでどおり空**（呼び出し元が `invalid_grant` にする）。
        /// - **同時に来た 2 つの引き換えも、負けた側は再利用と同じに扱う**（refresh_token と同じ。#332）
        /// - **別のクライアントが出したら、失効させない**（そのクライアントに出したコードではない）
        /// - **PKCE・DPoP の確かめは、この前に済んでいる**（`code_verifier` の誤った要求は、ここまで来ずに断られ、失効させない）
        /// </remarks>
        public static string Receive(string code, string client_id, string redirect_uri)
        {
            string value = "";
            bool reused = false;

            //  **列の幅（64）を超える値は、引くまでもなく「無い」**（#331。Oracle は例外にする）。
            if (!MultiPurposeAuthSite.Data.CmnStore.IsSearchable(code, 64))
            {
                return value;
            }

            switch (Config.UserStoreType)
            {
                case EnumUserStoreType.Memory:
                    value = AuthorizationCodeProvider.MarkAsUsedInMemory(code, out reused);
                    break;

                case EnumUserStoreType.SqlServer:
                case EnumUserStoreType.ODPManagedDriver:
                case EnumUserStoreType.PostgreSQL: // DMBMS

                    using (IDbConnection cnn = DataAccess.CreateConnection())
                    {
                        cnn.Open();

                        int updated = 0;
                        DateTime now = DateTime.Now;
                        DateTime limit = AuthorizationCodeProvider.ExpireLimit;

                        switch (Config.UserStoreType)
                        {
                            case EnumUserStoreType.SqlServer:

                                //  **同じ行の更新が重なると、SQL Server はデッドロックの犠牲を選ぶ**（#332）。やり直す。
                                updated = DataAccess.RetryWriteOnDeadlock(() => cnn.Execute(
                                    "UPDATE [AuthenticationCodeDictionary] SET [UsedDate] = @Now"
                                    + " WHERE [Key] = @Key AND [UsedDate] IS NULL AND [CreatedDate] > @Limit",
                                    new { Key = code, Now = now, Limit = limit }));

                                value = cnn.ExecuteScalar<string>(
                                    "SELECT [Value] FROM [AuthenticationCodeDictionary]"
                                    + " WHERE [Key] = @Key AND [CreatedDate] > @Limit",
                                    new { Key = code, Limit = limit });

                                break;

                            case EnumUserStoreType.ODPManagedDriver:

                                updated = cnn.Execute(
                                    "UPDATE \"AuthenticationCodeDictionary\" SET \"UsedDate\" = :Now"
                                    + " WHERE \"Key\" = :Key AND \"UsedDate\" IS NULL AND \"CreatedDate\" > :Limit",
                                    new { Key = code, Now = now, Limit = limit });

                                value = cnn.ExecuteScalar<string>(
                                    "SELECT \"Value\" FROM \"AuthenticationCodeDictionary\""
                                    + " WHERE \"Key\" = :Key AND \"CreatedDate\" > :Limit",
                                    new { Key = code, Limit = limit });

                                break;

                            case EnumUserStoreType.PostgreSQL:

                                updated = cnn.Execute(
                                    "UPDATE \"authenticationcodedictionary\" SET \"useddate\" = @Now"
                                    + " WHERE \"key\" = @Key AND \"useddate\" IS NULL AND \"createddate\" > @Limit",
                                    new { Key = code, Now = now, Limit = limit });

                                value = cnn.ExecuteScalar<string>(
                                    "SELECT \"value\" FROM \"authenticationcodedictionary\""
                                    + " WHERE \"key\" = @Key AND \"createddate\" > @Limit",
                                    new { Key = code, Limit = limit });

                                break;
                        }

                        //  **印を立てられた 1 つだけが引き換える**（#332）。
                        //    **device_code・auth_req_id も、最後はここで内部の認可コードを引き換える**ので、同じく 1 回になる。
                        //    **立てられず、行が在れば、使用済み**（#421）。
                        if (updated != 1)
                        {
                            reused = !string.IsNullOrEmpty(value);
                        }
                    }

                    break;
            }

            // 存在しない、または期限切れのcodeでは空になる（#185）。
            if (string.IsNullOrEmpty(value)) return "";

            JObject jobj = (JObject)JsonConvert.DeserializeObject(value);

            if (reused)
            {
                AuthorizationCodeProvider.RevokeIfSameClient(client_id, jobj);
                return "";
            }

            return AuthorizationCodeProvider.CheckClientIdAndRedirectUri(client_id, redirect_uri, jobj);
        }

        /// <summary>使用済みのコードが、そのコードを出したクライアントから再び出されたら、そのコードから出したトークンを失効させる（#421）</summary>
        /// <param name="client_id">認証したクライアント</param>
        /// <param name="jobj">コードの行の値</param>
        /// <remarks>
        /// **RFC 6749 §4.1.2**：「If an authorization code is used more than once, the authorization server MUST deny the request
        /// and SHOULD revoke (when possible) all tokens previously issued based on that authorization code.」
        /// **認可の ID を持たないコード**（この変更の前に作ったもの）**は、失効させられない**（従来どおり）。
        /// </remarks>
        private static void RevokeIfSameClient(string client_id, JObject jobj)
        {
            JObject payload = (JObject)JsonConvert.DeserializeObject((string)jobj[Const.AuthZCodeAccessTokenPayload]);

            if (payload == null || client_id != (string)payload[OAuth2AndOIDCConst.aud])
            {
                return;
            }

            RevocationProvider.RevokeAuthorization((string)payload[Const.AuthorizationIdClaim]);

            Logging.MyOperationTrace(string.Format(
                "The authorization code issued to {0} was used more than once. The tokens issued from it were revoked.",
                client_id));
        }

        #endregion

        #region ReceiveChallenge

        /// <summary>ReceiveChallenge</summary>
        /// <param name="code">string</param>
        /// <param name="client_id">string</param>
        /// <param name="redirect_uri">string</param>
        /// <param name="code_challenge_method">string</param>
        /// <param name="code_challenge">string</param>
        public static void ReceiveChallenge(
            string code, string client_id, string redirect_uri,
            out string code_challenge_method, out string code_challenge)
        {
            string value = "";
            code_challenge_method = "";
            code_challenge = "";

            //  **列の幅（64）を超える値は、引くまでもなく「無い」**（#331。Oracle は例外にする）。
            if (!MultiPurposeAuthSite.Data.CmnStore.IsSearchable(code, 64))
            {
                return;
            }

            switch (Config.UserStoreType)
            {
                case EnumUserStoreType.Memory:
                    value = AuthorizationCodeProvider.GetFromMemory(code);
                    break;

                case EnumUserStoreType.SqlServer:
                case EnumUserStoreType.ODPManagedDriver:
                case EnumUserStoreType.PostgreSQL: // DMBMS

                    using (IDbConnection cnn = DataAccess.CreateConnection())
                    {
                        cnn.Open();

                        switch (Config.UserStoreType)
                        {
                            case EnumUserStoreType.SqlServer:

                                value = cnn.ExecuteScalar<string>(
                                  "SELECT [Value] FROM [AuthenticationCodeDictionary]"
                                  + " WHERE [Key] = @Key AND [CreatedDate] > @Limit",
                                  new { Key = code, Limit = AuthorizationCodeProvider.ExpireLimit });

                                //cnn.Execute(
                                //    "DELETE FROM [AuthenticationCodeDictionary] WHERE [Key] = @Key", new { Key = code });

                                break;

                            case EnumUserStoreType.ODPManagedDriver:

                                value = cnn.ExecuteScalar<string>(
                                    "SELECT \"Value\" FROM \"AuthenticationCodeDictionary\""
                                    + " WHERE \"Key\" = :Key AND \"CreatedDate\" > :Limit",
                                    new { Key = code, Limit = AuthorizationCodeProvider.ExpireLimit });

                                //cnn.Execute(
                                //    "DELETE FROM \"AuthenticationCodeDictionary\" WHERE \"Key\" = :Key", new { Key = code });

                                break;

                            case EnumUserStoreType.PostgreSQL:

                                value = cnn.ExecuteScalar<string>(
                                    "SELECT \"value\" FROM \"authenticationcodedictionary\""
                                    + " WHERE \"key\" = @Key AND \"createddate\" > @Limit",
                                    new { Key = code, Limit = AuthorizationCodeProvider.ExpireLimit });

                                //cnn.Execute(
                                //    "DELETE FROM \"authenticationcodedictionary\" WHERE \"key\" = @Key", new { Key = code });

                                break;
                        }
                    }

                    break;
            }

            // 存在しないcodeでは空になる（#185）。out引数は空のままで返す。
            if (string.IsNullOrEmpty(value)) return;

            JObject jobj = (JObject)JsonConvert.DeserializeObject(value);
            string payload = AuthorizationCodeProvider.CheckClientIdAndRedirectUri(client_id, redirect_uri, jobj);

            if (!string.IsNullOrEmpty(payload))
            {
                code_challenge_method = (string)jobj[OAuth2AndOIDCConst.code_challenge_method];
                code_challenge = (string)jobj[OAuth2AndOIDCConst.code_challenge];
            }
        }

        /// <summary>CheckRedirectUri</summary>
        /// <param name="client_id">string</param>
        /// <param name="redirect_uri">string</param>
        /// <param name="payload">JObject</param>
        /// <returns>payload</returns>
        private static string CheckClientIdAndRedirectUri(string client_id, string redirect_uri, JObject jobj)
        {
            // payload
            JObject payload = (JObject)JsonConvert.
                DeserializeObject((string)jobj[Const.AuthZCodeAccessTokenPayload]);

            // client_idチェック
            if (client_id == (string)payload[OAuth2AndOIDCConst.aud])
            {
                // client_id 一致

                // 空文字列で標準化
                redirect_uri = redirect_uri ?? "";

                string _redirect_uri =
                    (string)jobj[OAuth2AndOIDCConst.redirect_uri] ?? "";

                // redirect_uriチェック
                if (string.IsNullOrEmpty(_redirect_uri)) return payload.ToString(); // 認可リクエスト時、指定無し
                else if (_redirect_uri == redirect_uri) return payload.ToString(); // 認可リクエスト指定と一致
                else return ""; // 認可リクエスト指定と不一致
            }
            else
            {
                return ""; // client_id 不正
            }
        }

        #endregion

        #endregion

        #region Hybrid Flow対応

        /// <summary>GetAccessTokenPayload</summary>
        /// <param name="code">code</param>
        /// <returns>Jwt AccessTokenのPayload部</returns>
        public static string GetAccessTokenPayload(string code)
        {
            string value = "";

            //  **列の幅（64）を超える値は、引くまでもなく「無い」**（#331。Oracle は例外にする）。
            if (!MultiPurposeAuthSite.Data.CmnStore.IsSearchable(code, 64))
            {
                return value;
            }

            switch (Config.UserStoreType)
            {
                case EnumUserStoreType.Memory:
                    value = AuthorizationCodeProvider.GetFromMemory(code);
                    break;

                case EnumUserStoreType.SqlServer:
                case EnumUserStoreType.ODPManagedDriver:
                case EnumUserStoreType.PostgreSQL: // DMBMS

                    using (IDbConnection cnn = DataAccess.CreateConnection())
                    {
                        cnn.Open();

                        switch (Config.UserStoreType)
                        {
                            case EnumUserStoreType.SqlServer:

                                value = cnn.ExecuteScalar<string>(
                                  "SELECT [Value] FROM [AuthenticationCodeDictionary]"
                                  + " WHERE [Key] = @Key AND [CreatedDate] > @Limit",
                                  new { Key = code, Limit = AuthorizationCodeProvider.ExpireLimit });
                                break;

                            case EnumUserStoreType.ODPManagedDriver:

                                value = cnn.ExecuteScalar<string>(
                                    "SELECT \"Value\" FROM \"AuthenticationCodeDictionary\""
                                    + " WHERE \"Key\" = :Key AND \"CreatedDate\" > :Limit",
                                    new { Key = code, Limit = AuthorizationCodeProvider.ExpireLimit });
                                break;

                            case EnumUserStoreType.PostgreSQL:

                                value = cnn.ExecuteScalar<string>(
                                    "SELECT \"value\" FROM \"authenticationcodedictionary\""
                                    + " WHERE \"key\" = @Key AND \"createddate\" > @Limit",
                                    new { Key = code, Limit = AuthorizationCodeProvider.ExpireLimit });
                                break;
                        }
                    }

                    break;
            }

            // 存在しないcodeでは空になる（#185）。
            if (string.IsNullOrEmpty(value)) return "";

            Dictionary<string, string> temp = JsonConvert.DeserializeObject<Dictionary<string, string>>(value);

            return temp[Const.AuthZCodeAccessTokenPayload];
        }

        #endregion

        #region DPoP（#311 の段階 4）

        /// <summary>このコードに紐付いた DPoP の鍵の指紋（RFC 9449 §10）</summary>
        /// <param name="code">code</param>
        /// <returns>`dpop_jkt`（申告が無ければ空）</returns>
        /// <remarks>
        /// **消費しない**（`Receive` と違う） — **照合して断るときに、コードを消費してはいけない。**
        /// **断られた後、同じコードでやり直せる**ようにする（段階 1 の `/token` と同じ考え）。
        ///
        /// **古いコード（この機能より前に作られた行）には、この項目が無い** —
        /// **無ければ空**を返す（**照合はスキップされる**）。
        /// </remarks>
        public static string GetDPoPJkt(string code)
        {
            string value = "";

            //  **列の幅（64）を超える値は、引くまでもなく「無い」**（#331。Oracle は例外にする）。
            if (!MultiPurposeAuthSite.Data.CmnStore.IsSearchable(code, 64))
            {
                return value;
            }

            switch (Config.UserStoreType)
            {
                case EnumUserStoreType.Memory:
                    value = AuthorizationCodeProvider.GetFromMemory(code);
                    break;

                case EnumUserStoreType.SqlServer:
                case EnumUserStoreType.ODPManagedDriver:
                case EnumUserStoreType.PostgreSQL: // DMBMS

                    using (IDbConnection cnn = DataAccess.CreateConnection())
                    {
                        cnn.Open();

                        switch (Config.UserStoreType)
                        {
                            case EnumUserStoreType.SqlServer:

                                value = cnn.ExecuteScalar<string>(
                                  "SELECT [Value] FROM [AuthenticationCodeDictionary]"
                                  + " WHERE [Key] = @Key AND [CreatedDate] > @Limit",
                                  new { Key = code, Limit = AuthorizationCodeProvider.ExpireLimit });
                                break;

                            case EnumUserStoreType.ODPManagedDriver:

                                value = cnn.ExecuteScalar<string>(
                                    "SELECT \"Value\" FROM \"AuthenticationCodeDictionary\""
                                    + " WHERE \"Key\" = :Key AND \"CreatedDate\" > :Limit",
                                    new { Key = code, Limit = AuthorizationCodeProvider.ExpireLimit });
                                break;

                            case EnumUserStoreType.PostgreSQL:

                                value = cnn.ExecuteScalar<string>(
                                    "SELECT \"value\" FROM \"authenticationcodedictionary\""
                                    + " WHERE \"key\" = @Key AND \"createddate\" > @Limit",
                                    new { Key = code, Limit = AuthorizationCodeProvider.ExpireLimit });
                                break;
                        }
                    }

                    break;
            }

            // 存在しないcodeでは空になる（#185）。
            if (string.IsNullOrEmpty(value)) return "";

            Dictionary<string, string> temp =
                JsonConvert.DeserializeObject<Dictionary<string, string>>(value);

            if (temp == null
                || !temp.TryGetValue(OAuth2AndOIDCConst.dpop_jkt, out string jkt)
                || string.IsNullOrEmpty(jkt))
            {
                return "";
            }

            return jkt;
        }

        #endregion
    }
}