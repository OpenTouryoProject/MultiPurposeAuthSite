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
//**********************************************************************************

using MultiPurposeAuthSite.Co;
using MultiPurposeAuthSite.Data;
using MultiPurposeAuthSite.Extensions.Sts;

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
        private static ConcurrentDictionary<string, string>
                    AuthenticationCodes = new ConcurrentDictionary<string, string>(StringComparer.Ordinal);

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
        ///    ワンタイム化（ANALYSIS-IdP.md の C-11）するときは、読む回数を 1 回にまとめること。
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
                // 見つからない request_uri（Controller と同じく、クエリ文字列の値で続ける）
                return queryString;
            }

            JObject requestObjectPayload = (JObject)JsonConvert.DeserializeObject(requestObjectPayloadString);

            if (requestObjectPayload == null)
            {
                return queryString;
            }

            // Request Object の値だけを使う（入っていなければ null のまま）。
            NameValueCollection ret = new NameValueCollection();
            ret[OAuth2AndOIDCConst.redirect_uri] = (string)requestObjectPayload[OAuth2AndOIDCConst.redirect_uri];
            ret[OAuth2AndOIDCConst.code_challenge] = (string)requestObjectPayload[OAuth2AndOIDCConst.code_challenge];
            ret[OAuth2AndOIDCConst.code_challenge_method] = (string)requestObjectPayload[OAuth2AndOIDCConst.code_challenge_method];

            return ret;
        }

        /// <summary>CreateAuthenticationCode</summary>
        /// <param name="identity">ClaimsIdentity</param>
        /// <returns>code</returns>
        public static string Create(ClaimsIdentity identity, NameValueCollection queryString)
        {
            string code = Guid.NewGuid().ToString("n") + Guid.NewGuid().ToString("n");

            Dictionary<string, string> temp = new Dictionary<string, string>();

            // 有効期限が無効なtokenのペイロードだけ作成
            string access_token_payload = CmnAccessToken.CreatePayloadForCode(identity, DateTimeOffset.Now);
            temp.Add("access_token_payload", access_token_payload);

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

            // 新しいCodeのticketをストアに保存
            string jsonString = JsonConvert.SerializeObject(temp);

            switch (Config.UserStoreType)
            {
                case EnumUserStoreType.Memory:
                    AuthorizationCodeProvider.AuthenticationCodes[code] = jsonString;
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

        /// <summary>Receive</summary>
        /// <param name="code">string</param>
        /// <param name="client_id">string</param>
        /// <param name="redirect_uri">string</param>
        /// <returns>PayloadForCode</returns>
        public static string Receive(string code, string client_id, string redirect_uri)
        {
            string value = "";

            switch (Config.UserStoreType)
            {
                case EnumUserStoreType.Memory:
                    if (AuthorizationCodeProvider.AuthenticationCodes.TryRemove(code, out value)) { }
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
                                    "SELECT [Value] FROM [AuthenticationCodeDictionary] WHERE [Key] = @Key", new { Key = code });

                                cnn.Execute(
                                    "DELETE FROM [AuthenticationCodeDictionary] WHERE [Key] = @Key", new { Key = code });

                                break;

                            case EnumUserStoreType.ODPManagedDriver:

                                value = cnn.ExecuteScalar<string>(
                                    "SELECT \"Value\" FROM \"AuthenticationCodeDictionary\" WHERE \"Key\" = :Key", new { Key = code });

                                cnn.Execute(
                                    "DELETE FROM \"AuthenticationCodeDictionary\" WHERE \"Key\" = :Key", new { Key = code });

                                break;

                            case EnumUserStoreType.PostgreSQL:

                                value = cnn.ExecuteScalar<string>(
                                    "SELECT \"value\" FROM \"authenticationcodedictionary\" WHERE \"key\" = @Key", new { Key = code });

                                cnn.Execute(
                                    "DELETE FROM \"authenticationcodedictionary\" WHERE \"key\" = @Key", new { Key = code });

                                break;
                        }
                    }

                    break;
            }

            // 存在しない、または使用済みのcodeでは空になる（#185）。
            if (string.IsNullOrEmpty(value)) return "";

            JObject jobj = (JObject)JsonConvert.DeserializeObject(value);
            return AuthorizationCodeProvider.CheckClientIdAndRedirectUri(client_id, redirect_uri, jobj);
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

            switch (Config.UserStoreType)
            {
                case EnumUserStoreType.Memory:
                    if (AuthorizationCodeProvider.AuthenticationCodes.TryGetValue(code, out value)) { }
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
                                  "SELECT [Value] FROM [AuthenticationCodeDictionary] WHERE [Key] = @Key", new { Key = code });

                                //cnn.Execute(
                                //    "DELETE FROM [AuthenticationCodeDictionary] WHERE [Key] = @Key", new { Key = code });

                                break;

                            case EnumUserStoreType.ODPManagedDriver:

                                value = cnn.ExecuteScalar<string>(
                                    "SELECT \"Value\" FROM \"AuthenticationCodeDictionary\" WHERE \"Key\" = :Key", new { Key = code });

                                //cnn.Execute(
                                //    "DELETE FROM \"AuthenticationCodeDictionary\" WHERE \"Key\" = :Key", new { Key = code });

                                break;

                            case EnumUserStoreType.PostgreSQL:

                                value = cnn.ExecuteScalar<string>(
                                    "SELECT \"value\" FROM \"authenticationcodedictionary\" WHERE \"key\" = @Key", new { Key = code });

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
                DeserializeObject((string)jobj["access_token_payload"]);

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

            switch (Config.UserStoreType)
            {
                case EnumUserStoreType.Memory:
                    AuthorizationCodeProvider.AuthenticationCodes.TryGetValue(code, out value);
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
                                  "SELECT [Value] FROM [AuthenticationCodeDictionary] WHERE [Key] = @Key", new { Key = code });
                                break;

                            case EnumUserStoreType.ODPManagedDriver:

                                value = cnn.ExecuteScalar<string>(
                                    "SELECT \"Value\" FROM \"AuthenticationCodeDictionary\" WHERE \"Key\" = :Key", new { Key = code });
                                break;

                            case EnumUserStoreType.PostgreSQL:

                                value = cnn.ExecuteScalar<string>(
                                    "SELECT \"value\" FROM \"authenticationcodedictionary\" WHERE \"key\" = @Key", new { Key = code });
                                break;
                        }
                    }

                    break;
            }

            // 存在しないcodeでは空になる（#185）。
            if (string.IsNullOrEmpty(value)) return "";

            Dictionary<string, string> temp = JsonConvert.DeserializeObject<Dictionary<string, string>>(value);

            return temp["access_token_payload"];
        }

        #endregion
    }
}