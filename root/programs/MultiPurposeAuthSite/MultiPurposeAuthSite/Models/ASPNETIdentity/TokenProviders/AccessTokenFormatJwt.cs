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
//* クラス名        ：AccessTokenFormatJwt
//* クラス日本語名  ：Access TokenのJWTカスタマイズクラス
//*
//* 作成日時        ：－
//* 作成者          ：－
//* 更新履歴        ：－
//*
//*  日時        更新者            内容
//*  ----------  ----------------  -------------------------------------------------
//*  2017/04/24  西野 大介         新規
//**********************************************************************************

using System;
using System.Web;
using System.Linq;
using System.Collections.Generic;
using System.Security.Claims;
using System.Security.Cryptography.X509Certificates;

using Microsoft.Owin.Security;
using Microsoft.AspNet.Identity;
using Microsoft.AspNet.Identity.Owin;

using Newtonsoft.Json;
using Newtonsoft.Json.Linq;

using MultiPurposeAuthSite.Models.ASPNETIdentity.Manager;
using MultiPurposeAuthSite.Models.ASPNETIdentity.Entity;
using MultiPurposeAuthSite.Models.ASPNETIdentity.OAuth2Extension;

using Touryo.Infrastructure.Framework.Authentication;
using Touryo.Infrastructure.Public.IO;
using Touryo.Infrastructure.Public.Str;
using Touryo.Infrastructure.Public.Security;

namespace MultiPurposeAuthSite.Models.ASPNETIdentity.TokenProviders
{
    /// <summary>AccessTokenFormatJwt</summary>
    public class AccessTokenFormatJwt: ISecureDataFormat<AuthenticationTicket>
    {
        /// <summary>constructor</summary>
        public AccessTokenFormatJwt() { }

        /// <summary>Protect</summary>
        /// <param name="ticket">AuthenticationTicket</param>
        /// <returns>JWT文字列</returns>
        public string Protect(AuthenticationTicket ticket)
        {
            string json = "";
            //string jws = "";
            
            // チェック
            if (ticket == null)
            {
                throw new ArgumentNullException("ticket");
            }

            ApplicationUserManager userManager
                = HttpContext.Current.GetOwinContext().GetUserManager<ApplicationUserManager>();

            ApplicationUser user = null;

            if (ticket.Identity.Name == null)
            {
                // Client認証の場合、
                user = null;
            }
            else
            {
                // Resource Owner認証の場合、
                user = userManager.FindByName(ticket.Identity.Name); // 同期版でOK。
            }

            #region ClaimSetの生成

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

            if (ticket.Identity.Name == null)
            {
                // Client認証の場合、aud（client_id）に対応するClient名称
                authTokenClaimSet.Add(OAuth2AndOIDCConst.sub, 
                    OAuth2Helper.GetInstance().GetClientName((string)authTokenClaimSet[OAuth2AndOIDCConst.aud]));
            }
            else
            {
                // Resource Owner認証の場合、Resource Ownerの名称
                authTokenClaimSet.Add(OAuth2AndOIDCConst.sub, ticket.Identity.Name);
            }

            authTokenClaimSet.Add(OAuth2AndOIDCConst.exp, ticket.Properties.ExpiresUtc.Value.ToUnixTimeSeconds().ToString());
            authTokenClaimSet.Add(OAuth2AndOIDCConst.nbf, DateTimeOffset.Now.ToUnixTimeSeconds().ToString());
            authTokenClaimSet.Add(OAuth2AndOIDCConst.iat, ticket.Properties.IssuedUtc.Value.ToUnixTimeSeconds().ToString());
            authTokenClaimSet.Add(OAuth2AndOIDCConst.jti, Guid.NewGuid().ToString("N"));

            authTokenClaimSet.Add(OAuth2AndOIDCConst.scopes, scopes);

            // scope値によって、返す値を変更する。
            foreach (string scope in scopes)
            {
                if (user != null)
                {
                    // user == null では NG な Resource（Resource Owner の Resource）
                    switch (scope.ToLower())
                    {
                        #region OpenID Connect

                        case OAuth2AndOIDCConst.Scope_Profile:
                            // ・・・
                            break;
                        case OAuth2AndOIDCConst.Scope_Email:
                            authTokenClaimSet.Add(OAuth2AndOIDCConst.Scope_Email, user.Email);
                            authTokenClaimSet.Add(OAuth2AndOIDCConst.email_verified, user.EmailConfirmed.ToString());
                            break;
                        case OAuth2AndOIDCConst.Scope_Phone:
                            authTokenClaimSet.Add(OAuth2AndOIDCConst.phone_number, user.PhoneNumber);
                            authTokenClaimSet.Add(OAuth2AndOIDCConst.phone_number_verified, user.PhoneNumberConfirmed.ToString());
                            break;
                        case OAuth2AndOIDCConst.Scope_Address:
                            // ・・・
                            break;

                        #endregion

                        #region Else

                        case OAuth2AndOIDCConst.Scope_UserID:
                            authTokenClaimSet.Add(OAuth2AndOIDCConst.Scope_UserID, user.Id);
                            break;
                        case OAuth2AndOIDCConst.Scope_Roles:
                            authTokenClaimSet.Add(
                                OAuth2AndOIDCConst.Scope_Roles,
                                userManager.GetRolesAsync(user.Id).Result);
                            break;

                            #endregion
                    }
                }
                else
                {
                    // user == null でも OK な Resource
                }
            }
            
            json = JsonConvert.SerializeObject(authTokenClaimSet);

            #endregion

            #region JWS化

            JWS_RS256_X509 jwsRS256 = null;

            // JWT_RS256_X509
            jwsRS256 = new JWS_RS256_X509(ASPNETIdentityConfig.OAuth2JWT_pfx, ASPNETIdentityConfig.OAuth2JWTPassword,
                X509KeyStorageFlags.Exportable | X509KeyStorageFlags.MachineKeySet);

            // JWSHeaderのセット
            // kid : https://openid-foundation-japan.github.io/rfc7638.ja.html#Example
            Dictionary<string, string> jwk =
                JsonConvert.DeserializeObject<Dictionary<string, string>>(
                    RS256_KeyConverter.X509PfxToJwkPublicKey(ASPNETIdentityConfig.OAuth2JWT_pfx, ASPNETIdentityConfig.OAuth2JWTPassword));

            jwsRS256.JWSHeader.kid = jwk[JwtConst.kid];
            jwsRS256.JWSHeader.jku = ASPNETIdentityConfig.OAuth2AuthorizationServerEndpointsRootURI + OAuth2AndOIDCParams.JwkSetUri;

            // 署名
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

        /// <summary>Unprotect</summary>
        /// <param name="jwt">JWT文字列</param>
        /// <returns>AuthenticationTicket</returns>
        public AuthenticationTicket Unprotect(string jwt)
        {
            // 空のケースあり。
            if (string.IsNullOrEmpty(jwt))
            {
                return null;
            }

            // 検証
            JWS_RS256 jwsRS256 = null;

            // 証明書を使用するか、Jwkを使用するか判定
            Dictionary<string, string> header = JsonConvert.DeserializeObject<Dictionary<string, string>>(
                CustomEncode.ByteToString(CustomEncode.FromBase64UrlString(jwt.Split('.')[0]),CustomEncode.UTF_8));

            if (header.Keys.Any(s => s == JwtConst.kid))
            {
                if (string.IsNullOrEmpty(header[JwtConst.kid]))
                {
                    // 証明書を使用
                    jwsRS256 = new JWS_RS256_X509(OAuth2AndOIDCParams.RS256Cer, "");
                }
                else
                {
                    JwkSet jwkSetObject = JwkSet.LoadJwkSet(OAuth2AndOIDCParams.JwkSetFilePath);
                    JObject jwkObject = JwkSet.GetJwkObject(jwkSetObject, header[JwtConst.kid]);

                    if (jwkObject == null)
                    {
                        // 証明書を使用
                        jwsRS256 = new JWS_RS256_X509(OAuth2AndOIDCParams.RS256Cer, "");
                    }
                    else
                    {
                        // Jwkを使用
                        jwsRS256 = new JWS_RS256_Param(
                            RS256_KeyConverter.JwkToProvider(jwkObject).ExportParameters(false));
                    }
                }
            }

            if (jwsRS256.Verify(jwt))
            {
                // 検証できた。

                // デシリアライズ、
                string[] temp = jwt.Split('.');
                string json = CustomEncode.ByteToString(CustomEncode.FromBase64UrlString(temp[1]), CustomEncode.UTF_8);
                Dictionary<string, object> authTokenClaimSet = JsonConvert.DeserializeObject<Dictionary<string, object>>(json);

                // 以下の検証処理
                //  ★ "iss": accounts.google.com的な,
                //  ★ "aud": client_id（クライアント識別子）
                //  ★ "sub": ユーザーの一意識別子（uname, email）
                //  ★ "exp": JWT の有効期限（Unix時間）
                //  ☆ "jti": JWT のID（OAuth Token Revocation）

                DateTime? datetime = OAuth2RevocationProvider.GetInstance().Get((string)authTokenClaimSet[OAuth2AndOIDCConst.jti]);

                if (datetime == null)
                {
                    // authToken.iss, authToken.expの検証
                    if ((string)authTokenClaimSet[OAuth2AndOIDCConst.iss] == ASPNETIdentityConfig.OAuth2IssuerId
                        && OAuth2Helper.GetInstance().GetClientSecret((string)authTokenClaimSet[OAuth2AndOIDCConst.aud]) != null
                        && long.Parse((string)authTokenClaimSet[OAuth2AndOIDCConst.exp]) >= DateTimeOffset.Now.ToUnixTimeSeconds())
                    {
                        // authToken.subの検証
                        // ApplicationUser を取得する。
                        ApplicationUserManager userManager
                        = HttpContext.Current.GetOwinContext().GetUserManager<ApplicationUserManager>();
                        ApplicationUser user = userManager.FindByName((string)authTokenClaimSet[OAuth2AndOIDCConst.sub]); // 同期版でOK。

                        if (user != null)
                        {
                            // User Accountの場合

                            // ユーザーに対応するClaimsIdentityを生成し、
                            ClaimsIdentity identity = userManager.CreateIdentity(user, DefaultAuthenticationTypes.ExternalBearer);

                            // aud、scopes、nonceなどのClaimを追加する。
                            List<string> scopes = new List<string>();
                            foreach (string s in (JArray)authTokenClaimSet[OAuth2AndOIDCConst.scopes])
                            {
                                scopes.Add(s);
                            }

                            OAuth2Helper.AddClaim(identity,
                                (string)authTokenClaimSet[OAuth2AndOIDCConst.aud], "", scopes,　(string)authTokenClaimSet[OAuth2AndOIDCConst.nonce]);

                            // その他、所定のClaimを追加する。
                            identity.AddClaim(new Claim(OAuth2AndOIDCConst.Claim_ExpirationTime, (string)authTokenClaimSet[OAuth2AndOIDCConst.exp]));
                            identity.AddClaim(new Claim(OAuth2AndOIDCConst.Claim_NotBefore, (string)authTokenClaimSet[OAuth2AndOIDCConst.nbf]));
                            identity.AddClaim(new Claim(OAuth2AndOIDCConst.Claim_IssuedAt, (string)authTokenClaimSet[OAuth2AndOIDCConst.iat]));
                            identity.AddClaim(new Claim(OAuth2AndOIDCConst.Claim_JwtId, (string)authTokenClaimSet[OAuth2AndOIDCConst.jti]));
                            
                            // AuthenticationPropertiesの生成
                            AuthenticationProperties prop = new AuthenticationProperties();
                            prop.IssuedUtc = DateTimeOffset.FromUnixTimeSeconds(long.Parse((string)authTokenClaimSet[OAuth2AndOIDCConst.iat]));
                            prop.ExpiresUtc = DateTimeOffset.FromUnixTimeSeconds(long.Parse((string)authTokenClaimSet[OAuth2AndOIDCConst.exp]));

                            AuthenticationTicket auth = new AuthenticationTicket(identity, prop);

                            // 認証結果を返す。
                            return auth;
                        }
                        else
                        {
                            // Client Accountの場合

                            // ClaimとStoreのAudience(aud)に対応するSubject(sub)が一致するかを確認し、一致する場合のみ、認証する。
                            // ※ でないと、UserStoreから削除されたUser Accountが、Client Accountに化けることになる。
                            if ((string)authTokenClaimSet[OAuth2AndOIDCConst.sub] == OAuth2Helper.GetInstance().GetClientName((string)authTokenClaimSet[OAuth2AndOIDCConst.aud]))
                            {
                                // ClaimsIdentityを生成し、
                                ClaimsIdentity identity = new ClaimsIdentity(DefaultAuthenticationTypes.ExternalBearer);

                                // sub（client_idに対応するclient_name）Claimを設定する。
                                identity.AddClaim(new Claim(ClaimTypes.Name, (string)authTokenClaimSet[OAuth2AndOIDCConst.sub]));

                                // aud、scopes、nonceなどのClaimを追加する。
                                List<string> scopes = new List<string>();
                                foreach (string s in (JArray)authTokenClaimSet[OAuth2AndOIDCConst.scopes])
                                {
                                    scopes.Add(s);
                                }

                                OAuth2Helper.AddClaim(identity,
                                    (string)authTokenClaimSet[OAuth2AndOIDCConst.aud], "", scopes, (string)authTokenClaimSet[OAuth2AndOIDCConst.nonce]);

                                // その他、所定のClaimを追加する。
                                identity.AddClaim(new Claim(OAuth2AndOIDCConst.Claim_ExpirationTime, (string)authTokenClaimSet[OAuth2AndOIDCConst.exp]));
                                identity.AddClaim(new Claim(OAuth2AndOIDCConst.Claim_NotBefore, (string)authTokenClaimSet[OAuth2AndOIDCConst.nbf]));
                                identity.AddClaim(new Claim(OAuth2AndOIDCConst.Claim_IssuedAt, (string)authTokenClaimSet[OAuth2AndOIDCConst.iat]));
                                identity.AddClaim(new Claim(OAuth2AndOIDCConst.Claim_JwtId, (string)authTokenClaimSet[OAuth2AndOIDCConst.jti]));

                                // AuthenticationPropertiesの生成
                                AuthenticationProperties prop = new AuthenticationProperties();
                                prop.IssuedUtc = DateTimeOffset.FromUnixTimeSeconds(long.Parse((string)authTokenClaimSet[OAuth2AndOIDCConst.iat]));
                                prop.ExpiresUtc = DateTimeOffset.FromUnixTimeSeconds(long.Parse((string)authTokenClaimSet[OAuth2AndOIDCConst.exp]));

                                AuthenticationTicket auth = new AuthenticationTicket(identity, prop);

                                // 認証結果を返す。
                                return auth;
                            }
                        }
                    }
                    else
                    {
                        // クレーム検証の失敗
                    }
                }
                else
                {
                    // 取り消し済み
                }
            }
            else
            {
                // JWT署名検証の失敗
            }
            
            // 検証、認証ナドナド、できなかった。
            return null;
        }
    }
}