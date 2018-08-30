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

using Touryo.Infrastructure.Framework.Authentication;
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
        public static string CreateAccessTokenPayloadFromAuthenticationTicket(AuthenticationTicket ticket)
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
                if (c.Type == OAuth2AndOIDCConst.Claim_Issuer)
                {
                    authTokenClaimSet.Add(OAuth2AndOIDCConst.iss, c.Value);
                }
                else if (c.Type == OAuth2AndOIDCConst.Claim_Audience)
                {
                    authTokenClaimSet.Add(OAuth2AndOIDCConst.aud, c.Value);
                }
                else if (c.Type == OAuth2AndOIDCConst.Claim_Nonce)
                {
                    authTokenClaimSet.Add(OAuth2AndOIDCConst.nonce, c.Value);
                }
                else if (c.Type == OAuth2AndOIDCConst.Claim_Scopes)
                {
                    scopes.Add(c.Value);
                }
                else if (c.Type == "http://schemas.microsoft.com/ws/2008/06/identity/claims/role")
                {
                    roles.Add(c.Value);
                }
            }

            // Resource Owner認証の場合、Resource Ownerの名称
            authTokenClaimSet.Add(OAuth2AndOIDCConst.sub, ticket.Identity.Name);

            #region authTokenClaimSet.Add(OAuth2AndOIDCConst.exp, ・・・

            // ticketの値を使用(これは、codeのexpっぽい。300秒になっているのでNG。)
            //authTokenClaimSet.Add(OAuth2AndOIDCConst.exp, ticket.Properties.ExpiresUtc.Value.ToUnixTimeSeconds().ToString());

            // この時点では空にしておく。
            authTokenClaimSet.Add(OAuth2AndOIDCConst.exp, "");

            #endregion

            authTokenClaimSet.Add(OAuth2AndOIDCConst.nbf, DateTimeOffset.Now.ToUnixTimeSeconds().ToString());
            authTokenClaimSet.Add(OAuth2AndOIDCConst.iat, ticket.Properties.IssuedUtc.Value.ToUnixTimeSeconds().ToString());
            authTokenClaimSet.Add(OAuth2AndOIDCConst.jti, Guid.NewGuid().ToString("N"));

            // ★ Hybrid Flow対応なので、scopeを制限してもイイ。
            authTokenClaimSet.Add(OAuth2AndOIDCConst.scopes, scopes);

            // scope値によって、返す値を変更する。
            // ココでは返さない（別途ユーザ取得処理を実装してもイイ）。

            return JsonConvert.SerializeObject(authTokenClaimSet);
        }

        /// <summary>
        /// ProtectFromAccessTokenPayload
        ///   Hybrid Flow対応（access_token_payloadを処理）
        /// </summary>
        /// <param name="access_token_payload">AccessTokenのPayload</param>
        /// <param name="customExp">Hybrid Flowのtokenに対応したexp</param>
        /// <returns>IdToken</returns>
        public static string ProtectFromAccessTokenPayload(string access_token_payload, ulong customExp)
        {
            string json = "";
            //string jws = "";

            // ticketの値を使用(これは、codeのexpっぽい。300秒になっているのでNG。)
            //authTokenClaimSet.Add(OAuth2AndOIDCConst.exp, ticket.Properties.ExpiresUtc.Value.ToUnixTimeSeconds().ToString());
            //authTokenClaimSet.Add(OAuth2AndOIDCConst.exp, DateTimeOffset.Now.AddSeconds(customExp).ToUnixTimeSeconds().ToString());

            #region JSON編集

            // access_token_payloadのDictionary化
            Dictionary<string, object> payload =
                JsonConvert.DeserializeObject<Dictionary<string, object>>(access_token_payload);

            // ★ customExpの値を使用する。
            payload[OAuth2AndOIDCConst.exp] = DateTimeOffset.Now.AddSeconds(customExp).ToUnixTimeSeconds().ToString();
            // ★ Hybrid Flow対応なので、scopeを制限してもイイ。
            payload[OAuth2AndOIDCConst.scopes] = payload[OAuth2AndOIDCConst.scopes];

            json = JsonConvert.SerializeObject(payload);

            #endregion

            #region JWS化

            JWS_RS256_X509 jwsRS256 = null;

            // 署名
            jwsRS256 = new JWS_RS256_X509(ASPNETIdentityConfig.OAuth2JWT_pfx, ASPNETIdentityConfig.OAuth2JWTPassword,
                X509KeyStorageFlags.Exportable | X509KeyStorageFlags.MachineKeySet);

            // JWSHeaderのセット
            // kid : https://openid-foundation-japan.github.io/rfc7638.ja.html#Example
            Dictionary<string, string> jwk =
                JsonConvert.DeserializeObject<Dictionary<string, string>>(
                    RS256_KeyConverter.X509PfxToJwkPublicKey(ASPNETIdentityConfig.OAuth2JWT_pfx, ASPNETIdentityConfig.OAuth2JWTPassword));

            jwsRS256.JWSHeader.kid = jwk[JwtConst.kid];
            jwsRS256.JWSHeader.jku = ASPNETIdentityConfig.OAuth2AuthorizationServerEndpointsRootURI + OAuth2AndOIDCParams.JwkSetUri;

            return jwsRS256.Create(json);

            //// 検証
            //jwsRS256 = new JWS_RS256_X509(OAuth2AndOIDCParams.RS256Cer, ASPNETIdentityConfig.OAuth2JWTPassword,
            //    X509KeyStorageFlags.Exportable | X509KeyStorageFlags.MachineKeySet);

            //if (jwsRS256.Verify(jws))
            //{
            //    return jws; // 検証できた。
            //}
            //else
            //{
            //    return ""; // 検証できなかった。
            //}

            #endregion
        }

        #endregion
    }
}