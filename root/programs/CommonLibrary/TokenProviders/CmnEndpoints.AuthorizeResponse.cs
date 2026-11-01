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
//* クラス名        ：CmnEndpoints
//* クラス日本語名  ：CmnEndpoints（ライブラリ）の 認可エンドポイント（応答の組み立て）
//*
//* 作成日時        ：－
//* 作成者          ：－
//* 更新履歴        ：－
//*
//*  日時        更新者            内容
//*  ----------  ----------------  -------------------------------------------------
//*  2026/10/29  玄人 幸道         新規（CmnEndpoints.cs から partial に分割。#294）
//*  2026/10/29  玄人 幸道         ログの文言を経路に合わせ、using を整理した（#294）
//*  2026/10/31  玄人 幸道         認可ログの User Account は、利用者名で引く（GetClientIdByUserName。#294）
//**********************************************************************************

using MultiPurposeAuthSite.Co;
using MultiPurposeAuthSite.Util;
using MultiPurposeAuthSite.Log;
using MultiPurposeAuthSite.Extensions.Sts;
using MultiPurposeAuthSite.Util.Sts;

using System;
using System.Collections.Generic;
using System.Collections.Specialized;
using System.Security.Claims;

using Newtonsoft.Json;
using Newtonsoft.Json.Linq;

using Touryo.Infrastructure.Framework.Authentication;
using Touryo.Infrastructure.Public.Str;

namespace MultiPurposeAuthSite.TokenProviders
{
    /// <summary>CmnEndpoints（認可エンドポイント（応答の組み立て））</summary>
    public partial class CmnEndpoints
    {
        #region AuthZ(N)Endpoint

        #region Create Response

        #region ConsumeRequestObject

        /// <summary>
        /// 認可応答を作り終えた Request Object を消す（ワンタイム化）（#188 の段階 2）
        /// </summary>
        /// <param name="queryString">認可リクエストのクエリ文字列（request_uri が在れば消す）</param>
        /// <remarks>
        /// **1 回の認可の中では、同じ request_uri を何度も読む。**
        /// 同意画面（Controller）、コードの生成（AuthorizationCodeProvider）と続くため、
        /// **最初の読み取りで消すと、その認可自体が壊れる。**
        /// そこで**認可応答を作り終えた時点**（ここ）で消し、
        /// **2 回目の認可要求には使えない**ようにする。
        ///
        /// 消し忘れても期限で無効になる（#188 の段階 1）。ここは**使い回しを断つ**ためのもの。
        /// </remarks>
        private static void ConsumeRequestObject(NameValueCollection queryString)
        {
            if (queryString == null)
            {
                return;
            }

            string request_uri = queryString[OAuth2AndOIDCConst.request_uri];

            if (string.IsNullOrEmpty(request_uri))
            {
                return;
            }

            RequestObjectProvider.Delete(
                request_uri.Replace(OAuth2AndOIDCConst.UrnRequestUriBase, ""));
        }

        #endregion

        #region CreateCodeInAuthZNRes

        /// <summary>CreateCodeInAuthZNRes</summary>
        /// <param name="identity">ClaimsIdentity</param>
        /// <param name="queryString">NameValueCollection</param>
        /// <param name="client_id">string</param>
        /// <param name="state">string</param>
        /// <param name="scopes">string</param>
        /// <param name="claims">JObject</param>
        /// <param name="nonce">string</param>
        /// <returns>code</returns>
        public static string CreateCodeInAuthZNRes(
            ClaimsIdentity identity, NameValueCollection queryString,
            string client_id, string state, IEnumerable<string> scopes, JObject claims, string nonce)
        {
            // ClaimsIdentityに、その他、所定のClaimを追加する。
            // scopes_supported に無いスコープと、クライアントに許されていないスコープは発行しない（#198）
            Helper.AddClaim(identity, client_id, Helper.FilterSupportedScopes(scopes, client_id), claims, nonce);

            // Codeの生成
            string code = AuthorizationCodeProvider.Create(identity, queryString);

            // オペレーション・トレース・ログ出力
            string name = Helper.GetInstance().GetClientName(client_id);
            Logging.MyOperationTrace(string.Format(
                "{0}({1}) passed the authorization endpoint of Authorization Code by {2}({3}).",
                client_id, name,                                                        // Client Account
                Helper.GetInstance().GetClientIdByUserName(identity.Name), identity.Name)); // User Account

            // 使い終わった Request Object を消す（ワンタイム化。#188 の段階 2）
            CmnEndpoints.ConsumeRequestObject(queryString);

            return code;
        }

        #endregion

        #region CreateAuthZRes4ImplicitFlow

        /// <summary>CreateAuthZRes4ImplicitFlow</summary>
        /// <param name="identity">ClaimsIdentity</param>
        /// <param name="queryString">NameValueCollection</param>
        /// <param name="response_type">string</param>
        /// <param name="client_id">string</param>
        /// <param name="state">string</param>
        /// <param name="scopes">IEnumerable(string)</param>
        /// <param name="claims">JObject</param>
        /// <param name="nonce">string</param>
        /// <param name="access_token">out string</param>
        /// <param name="id_token">out string</param>
        public static void CreateAuthZRes4ImplicitFlow(
            ClaimsIdentity identity, NameValueCollection queryString, string response_type,
            string client_id, string state, IEnumerable<string> scopes, JObject claims, string nonce,
            out string access_token, out string id_token)
        {
            string jwkString = "";

            access_token = ""; // 初期化
            id_token = "";     // 初期化

            if (Config.EnableImplicitGrantType)
            {
                #region CheckClientMode

                // このフローが認められるか？
                Dictionary<string, string> err = new Dictionary<string, string>();
                if (CmnEndpoints.CheckClientMode(client_id,
                    ClientModePolicy.Flow.Implicit, ClientModePolicy.Proof.None,
                    out OAuth2AndOIDCEnum.ClientMode _, out jwkString, out err))
                {
                    // 継続可
                }
                else
                {
                    // 継続不可
                    // err設定済み
                    return;
                }

                #endregion

                #region Token発行

                // ClaimsIdentityに、その他、所定のClaimを追加する。
                // scopes_supported に無いスコープと、クライアントに許されていないスコープは発行しない（#198）
                Helper.AddClaim(identity, client_id, Helper.FilterSupportedScopes(scopes, client_id), claims, nonce);

                // **登録された署名 alg**（#129 の段階 2）
                string signingAlg = Helper.GetInstance().GetIdTokenSignedResponseAlg(client_id);

                // AccessTokenの生成
                access_token = CmnAccessToken.CreateFromClaims(
                	client_id, identity.Name, identity.Claims,
                    DateTimeOffset.Now.AddMinutes(Config.OAuth2AccessTokenExpireTimeSpanFromMinutes.TotalMinutes), signingAlg);

                JObject jObj = (JObject)JsonConvert.DeserializeObject(
                    CustomEncode.ByteToString(CustomEncode.FromBase64UrlString(
                        access_token.Split('.')[1]), CustomEncode.us_ascii));

                // id_token
                if (response_type.IndexOf(OAuth2AndOIDCConst.IDToken) != -1)
                {
                    JArray jAry = (JArray)jObj[OAuth2AndOIDCConst.scopes];
                    foreach (string s in jAry)
                    {
                        if (s == OAuth2AndOIDCConst.Scope_Openid)
                        {
                            // **access_token に揃える**（#129 の段階 2）。
                            //   **鍵は alg から引く**（#129 の段階 3。pfx の引数は JWE のときだけ使う）。
                            id_token = CmnIdToken.ChangeToIdTokenFromAccessToken(
                                access_token, "", state, // c_hash, は Implicit Flow で生成不可
                                HashClaimType.AtHash | HashClaimType.SHash,
                                CmnServerParams.RsaPfxFilePath, CmnServerParams.RsaPfxPassword, jwkString, signingAlg);
                        }
                    }
                }

                // オペレーション・トレース・ログ出力
                string name = Helper.GetInstance().GetClientName(client_id);
                Logging.MyOperationTrace(string.Format(
                    "{0}({1}) passed the authorization endpoint of Implicit by {2}({3}).",
                    client_id, name,                                                        // Client Account
                    Helper.GetInstance().GetClientIdByUserName(identity.Name), identity.Name)); // User Account

                // 使い終わった Request Object を消す（ワンタイム化。#188 の段階 2）
                CmnEndpoints.ConsumeRequestObject(queryString);

                #endregion
            }
        }

        #endregion

        #region CreateAuthNRes4HybridFlow

        /// <summary>CreateAuthNRes4HybridFlow</summary>
        /// <param name="identity">ClaimsIdentity</param>
        /// <param name="queryString">NameValueCollection</param>
        /// <param name="client_id">string</param>
        /// <param name="state">string</param>
        /// <param name="scopes">IEnumerable(string)</param>
        /// <param name="claims">JObject</param>
        /// <param name="nonce">string</param>
        /// <param name="access_token">out string</param>
        /// <param name="id_token">out string</param>
        /// <returns></returns>
        public static string CreateAuthNRes4HybridFlow(
            ClaimsIdentity identity, NameValueCollection queryString,
            string client_id, string state, IEnumerable<string> scopes, JObject claims, string nonce,
            out string access_token, out string id_token)
        {
            string code = "";
            string jwkString = "";

            access_token = ""; // 初期化
            id_token = "";     // 初期化

            #region CheckClientMode

            // ★ 未実装
            // TokenBinding を実装するなら、証明（ClientModePolicy.Proof）の 1 つとして扱う。
            //   いまは証明なし（Proof.None）で判定する（#224）。

            // このフローが認められるか？（経路 × 証明 → ClientModePolicy の表で引く。#224）
            Dictionary<string, string> err = new Dictionary<string, string>();
            if (CmnEndpoints.CheckClientMode(client_id,
                ClientModePolicy.Flow.Hybrid, ClientModePolicy.Proof.None,
                out OAuth2AndOIDCEnum.ClientMode clientMode, out jwkString, out err))
            {
                // 継続可
            }
            else
            {
                // 継続不可
                return "";
            }

            #endregion

            #region Token発行

            // ClaimsIdentityに、その他、所定のClaimを追加する。
            // scopes_supported に無いスコープと、クライアントに許されていないスコープは発行しない（#198）
            Helper.AddClaim(identity, client_id, Helper.FilterSupportedScopes(scopes, client_id), claims, nonce);

            // Codeの生成
            code = AuthorizationCodeProvider.Create(identity, queryString);

            string tokenPayload = AuthorizationCodeProvider.GetAccessTokenPayload(code);

            // ★ 必要に応じて、scopeを調整する。

            // access_token
            // **クレームは、登録された種別（clientMode）で書く**（#220）。
            //   経路や証明（ClientModePolicy の表。#224）は、トークンの名乗りには使わない。
            access_token = CmnAccessToken.ProtectFromPayload(
            	client_id, tokenPayload,
                DateTimeOffset.Now.Add(Config.OAuth2AccessTokenExpireTimeSpanFromMinutes),
                null, clientMode, out string aud, out string sub,
                // **登録された署名 alg で署名する**（#129 の段階 2）
                Helper.GetInstance().GetIdTokenSignedResponseAlg(client_id));

            // Client認証のclient_idとToken類のaudをチェック
            if (client_id != aud) { throw new Exception("[client_id != aud]"); }

            JObject jObj = (JObject)JsonConvert.DeserializeObject(
                            CustomEncode.ByteToString(CustomEncode.FromBase64UrlString(
                                access_token.Split('.')[1]), CustomEncode.us_ascii));

            // id_token
            JArray jAry = (JArray)jObj[OAuth2AndOIDCConst.scopes];
            foreach (string s in jAry)
            {
                if (s == OAuth2AndOIDCConst.Scope_Openid)
                {
                    // **access_token に揃える**（#129 の段階 2）。
                    //   **鍵は alg から引く**（#129 の段階 3。pfx の引数は JWE のときだけ使う）。
                    string signingAlg = Helper.GetInstance().GetIdTokenSignedResponseAlg(client_id);

                    id_token = CmnIdToken.ChangeToIdTokenFromAccessToken(
                        access_token, code, state, // at_hash, c_hash, s_hash
                        HashClaimType.AtHash | HashClaimType.CHash | HashClaimType.SHash,
                        CmnServerParams.RsaPfxFilePath, CmnServerParams.RsaPfxPassword, jwkString, signingAlg);
                }
            }

            // オペレーション・トレース・ログ出力
            string name = Helper.GetInstance().GetClientName(client_id);
            Logging.MyOperationTrace(string.Format(
                "{0}({1}) passed the authorization endpoint of Hybrid by {2}({3}).",
                client_id, name,                                         // Client Account
                PPIDExtension.GetUserNameFromSub(client_id, sub), sub)); // User Account (PPID化により...)

            // 使い終わった Request Object を消す（ワンタイム化。#188 の段階 2）
            CmnEndpoints.ConsumeRequestObject(queryString);

            #endregion

            return code;
        }

        #endregion

        #endregion

        #endregion
    }
}