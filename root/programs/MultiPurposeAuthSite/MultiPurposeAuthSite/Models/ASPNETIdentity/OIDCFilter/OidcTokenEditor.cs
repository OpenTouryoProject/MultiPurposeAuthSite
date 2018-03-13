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
//* クラス名        ：OidcTokenEditor
//* クラス日本語名  ：OIDC用のtoken編集処理クラス
//*
//* 作成日時        ：－
//* 作成者          ：－
//* 更新履歴        ：－
//*
//*  日時        更新者            内容
//*  ----------  ----------------  -------------------------------------------------
//*  2018/02/05  西野 大介         新規
//**********************************************************************************

using System;
using System.Linq;
using System.Collections.Generic;
using System.Security.Claims;
using System.Security.Cryptography.X509Certificates;

using Microsoft.Owin.Security;

using Newtonsoft.Json;
using Newtonsoft.Json.Linq;

using Touryo.Infrastructure.Public.Str;
using Touryo.Infrastructure.Public.Util;
using Touryo.Infrastructure.Public.Security;

namespace MultiPurposeAuthSite.Models.ASPNETIdentity.OIDCFilter
{
    /// <summary>OIDC用のtoken編集処理クラス</summary>
    /// <remarks>
    /// ・OIDC対応（AccessTokenからIdTokenを生成）
    ///   書き換えで対応するので、AccessTokenからIdTokenを生成する拡張メソッドを新設した。
    ///   
    /// ・Hybrid Flow対応（access_token_payloadを処理）
    ///   codeのフローをtokenのフローに変更するため、tokenをcodeプロバイダを使用して生成する必要があった。
    ///   この際、OAuthAuthorizationServerHandler経由でのAuthorizationCodeProviderの呼び出しが実装できなかったため、
    ///   （ApplicationUserから、ticketを生成する）抜け道を準備したが、今度は、
    ///   AccessTokenFormatJwtから、ApplicationUserManagerにアクセスできなかったため、この拡張メソッドを新設した。
    ///   また、ticketのシリアライズしたものはサイズが大き過ぎたため、access_tokenのpayloadを使用することとした。
    /// </remarks>
    public class OidcTokenEditor
    {
        #region AccessToken

        /// <summary>
        /// CreateAccessTokenPayload
        ///   Hybrid Flow対応（access_token_payloadを処理）
        /// </summary>
        /// <param name="ticket">AuthenticationTicket</param>
        /// <returns>Jwt AccessTokenのPayload部</returns>
        /// <remarks>
        /// Hybrid Flow対応なので、scopeを制限してもイイ。
        /// </remarks>
        public static string CreateAccessTokenPayload(AuthenticationTicket ticket)
        {
            // チェック
            if (ticket == null)
            {
                throw new ArgumentNullException("ticket");
            }

            Dictionary<string, object> authTokenClaimSet = new Dictionary<string, object>();
            List<string> scopes = new List<string>();
            List<string> roles = new List<string>();

            foreach (Claim c in ticket.Identity.Claims)
            {
                if (c.Type == ASPNETIdentityConst.Claim_Issuer)
                {
                    authTokenClaimSet.Add("iss", c.Value);
                }
                else if (c.Type == ASPNETIdentityConst.Claim_Audience)
                {
                    authTokenClaimSet.Add("aud", c.Value);
                }
                else if (c.Type == ASPNETIdentityConst.Claim_Nonce)
                {
                    authTokenClaimSet.Add("nonce", c.Value);
                }
                else if (c.Type == ASPNETIdentityConst.Claim_Scope)
                {
                    scopes.Add(c.Value);
                }
                else if (c.Type == "http://schemas.microsoft.com/ws/2008/06/identity/claims/role")
                {
                    roles.Add(c.Value);
                }
            }

            // Resource Owner認証の場合、Resource Ownerの名称
            authTokenClaimSet.Add("sub", ticket.Identity.Name);

            #region authTokenClaimSet.Add("exp", ・・・

            // ticketの値を使用(これは、codeのexpっぽい。300秒になっているのでNG。)
            //authTokenClaimSet.Add("exp", ticket.Properties.ExpiresUtc.Value.ToUnixTimeSeconds().ToString());

            // この時点では空にしておく。
            authTokenClaimSet.Add("exp", "");

            #endregion

            authTokenClaimSet.Add("nbf", DateTimeOffset.Now.ToUnixTimeSeconds().ToString());
            authTokenClaimSet.Add("iat", ticket.Properties.IssuedUtc.Value.ToUnixTimeSeconds().ToString());
            authTokenClaimSet.Add("jti", Guid.NewGuid().ToString("N"));

            // ★ Hybrid Flow対応なので、scopeを制限してもイイ。
            authTokenClaimSet.Add("scopes", scopes);

            // scope値によって、返す値を変更する。
            // ココでは返さない（別途ユーザ取得処理を実装してもイイ）。

            return JsonConvert.SerializeObject(authTokenClaimSet);
        }

        /// <summary>
        /// ProtectFromPayload
        ///   Hybrid Flow対応（access_token_payloadを処理）
        /// </summary>
        /// <param name="access_token_payload">AccessTokenのPayload</param>
        /// <param name="customExp">Hybrid Flowのtokenに対応したexp</param>
        /// <returns></returns>
        public static string ProtectFromPayload(string access_token_payload, ulong customExp)
        {
            string json = "";
            string jwt = "";

            // ticketの値を使用(これは、codeのexpっぽい。300秒になっているのでNG。)
            //authTokenClaimSet.Add("exp", ticket.Properties.ExpiresUtc.Value.ToUnixTimeSeconds().ToString());
            //authTokenClaimSet.Add("exp", DateTimeOffset.Now.AddSeconds(customExp).ToUnixTimeSeconds().ToString());

            #region JSON編集

            // access_token_payloadのDictionary化
            Dictionary<string, object> dic =
                JsonConvert.DeserializeObject<Dictionary<string, object>>(access_token_payload);

            // ★ customExpの値を使用する。
            dic["exp"] = DateTimeOffset.Now.AddSeconds(customExp).ToUnixTimeSeconds().ToString();
            // ★ Hybrid Flow対応なので、scopeを制限してもイイ。
            dic["scopes"] = dic["scopes"];

            json = JsonConvert.SerializeObject(dic);

            #endregion

            #region JWT化

            JWT_RS256 jwtRS256 = null;

            // 署名
            jwtRS256 = new JWT_RS256(ASPNETIdentityConfig.OAuthJWT_pfx, ASPNETIdentityConfig.OAuthJWTPassword,
                X509KeyStorageFlags.Exportable | X509KeyStorageFlags.MachineKeySet);

            jwt = jwtRS256.Create(json);

            // 検証
            jwtRS256 = new JWT_RS256(ASPNETIdentityConfig.OAuthJWT_cer, ASPNETIdentityConfig.OAuthJWTPassword,
                X509KeyStorageFlags.Exportable | X509KeyStorageFlags.MachineKeySet);

            if (jwtRS256.Verify(jwt))
            {
                return jwt; // 検証できた。
            }
            else
            {
                return ""; // 検証できなかった。
            }

            #endregion
        }

        #endregion

        #region IdToken

        /// <summary>
        /// ChangeToIdTokenFromAccessToken
        ///   OIDC対応（AccessTokenからIdTokenを生成）
        /// </summary>
        /// <param name="access_token">string</param>
        /// <param name="code">string</param>
        /// <param name="HashClaimType">HashClaimType</param>
        /// <returns>IdToken</returns>
        /// <remarks>
        /// OIDC対応
        /// </remarks>

        public static string ChangeToIdTokenFromAccessToken(string access_token, string code, HashClaimType hct)
        {
            if (access_token.Contains("."))
            {
                string[] temp = access_token.Split('.');
                string json = CustomEncode.ByteToString(CustomEncode.FromBase64UrlString(temp[1]), CustomEncode.UTF_8);
                Dictionary<string, object> authTokenClaimSet = JsonConvert.DeserializeObject<Dictionary<string, object>>(json);

                // ・access_tokenがJWTで、payloadに"nonce" and "scope=openidクレームが存在する場合、
                if (authTokenClaimSet.ContainsKey("nonce")
                    && authTokenClaimSet.ContainsKey("scopes"))
                {
                    JArray scopes = (JArray)authTokenClaimSet["scopes"];

                    // ・OpenID Connect : response_type=codeに対応する。
                    if (scopes.Any(x => x.ToString() == ASPNETIdentityConst.Scope_Openid))
                    {
                        //・payloadからscopeを削除する。
                        authTokenClaimSet.Remove("scopes");

                        //・payloadにat_hash, c_hashを追加する。
                        switch (hct)
                        {
                            case HashClaimType.None:
                                break;

                            case HashClaimType.AtHash:
                                // at_hash
                                authTokenClaimSet.Add(
                                    "at_hash",
                                    OidcTokenEditor.CreateHash(access_token));
                                break;

                            case HashClaimType.CHash:
                                // c_hash
                                authTokenClaimSet.Add(
                                    "c_hash",
                                    OidcTokenEditor.CreateHash(code));
                                break;

                            case HashClaimType.Both:
                                // at_hash, c_hash
                                authTokenClaimSet.Add(
                                    "at_hash",
                                    OidcTokenEditor.CreateHash(access_token));
                                authTokenClaimSet.Add(
                                    "c_hash",
                                    OidcTokenEditor.CreateHash(code));
                                break;
                        }

                        //・編集したpayloadを再度JWTとして署名する。
                        string newPayload = JsonConvert.SerializeObject(authTokenClaimSet);
                        JWT_RS256 jwtRS256 = null;

                        // 署名
                        jwtRS256 = new JWT_RS256(ASPNETIdentityConfig.OAuthJWT_pfx, ASPNETIdentityConfig.OAuthJWTPassword,
                            X509KeyStorageFlags.Exportable | X509KeyStorageFlags.MachineKeySet);

                        string id_token = jwtRS256.Create(newPayload);

                        // 検証
                        jwtRS256 = new JWT_RS256(ASPNETIdentityConfig.OAuthJWT_cer, ASPNETIdentityConfig.OAuthJWTPassword,
                            X509KeyStorageFlags.Exportable | X509KeyStorageFlags.MachineKeySet);

                        if (jwtRS256.Verify(id_token))
                        {
                            // 検証できた。
                            return id_token;
                        }
                        else
                        {
                            // 検証できなかった。
                        }
                    }
                    else
                    {
                        // OIDCでない。
                    }
                }
                else
                {
                    // OIDCでない。
                }
            }
            else
            {
                // JWTでない。
            }

            return "";
        }

        /// <summary>
        /// SHA256でat_hash, c_hashを作成。
        /// （現時点でRS256固定になっているので）
        /// </summary>
        /// <returns>hash</returns>
        public static string CreateHash(string input)
        {
            // ID Token の JOSE Header にある alg Header Parameterのアルゴリズムで使用されるハッシュアルゴリズムを用い、
            // input(access_token や code) のASCII オクテット列からハッシュ値を求め、左半分を base64url エンコードした値。
            return CustomEncode.ToBase64UrlString(
                PubCmnFunction.ShortenByteArray(
                    GetHash.GetHashBytes(
                        CustomEncode.StringToByte(input, CustomEncode.us_ascii),
                        EnumHashAlgorithm.SHA256Managed), (256 / 2)));
        }

        #endregion
    }
}