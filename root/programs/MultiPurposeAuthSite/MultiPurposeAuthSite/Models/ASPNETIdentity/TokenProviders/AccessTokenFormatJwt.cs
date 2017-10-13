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
using System.Security.Claims;
using System.Collections.Generic;
using System.Security.Cryptography.X509Certificates;

using Microsoft.Owin.Security;
using Microsoft.Owin.Security.OAuth;
using Microsoft.AspNet.Identity;
using Microsoft.AspNet.Identity.Owin;

using Newtonsoft.Json;
using Newtonsoft.Json.Linq;

using MultiPurposeAuthSite.Models.ASPNETIdentity.Manager;
using MultiPurposeAuthSite.Models.ASPNETIdentity.Entity;
using MultiPurposeAuthSite.Models.ASPNETIdentity.OAuth2Extension;

using Touryo.Infrastructure.Public.Str;
using Touryo.Infrastructure.Public.Security;

namespace MultiPurposeAuthSite.Models.ASPNETIdentity.TokenProviders
{
    /// <summary>AccessTokenFormatJwt</summary>
    public class AccessTokenFormatJwt: ISecureDataFormat<AuthenticationTicket>
    {
        /// <summary>constructor</summary>
        /// <param name="oAuthIssuerId">oAuthIssuerId</param>
        public AccessTokenFormatJwt()
        {
        }

        /// <summary>Protect</summary>
        /// <param name="ticket">AuthenticationTicket</param>
        /// <returns>JWT文字列</returns>
        public string Protect(AuthenticationTicket ticket)
        {
            string json = "";
            string jwt = "";
            
            // チェック
            if (ticket == null)
            {
                throw new ArgumentNullException("ticket");
            }

            ApplicationUserManager userManager
                = HttpContext.Current.GetOwinContext().GetUserManager<ApplicationUserManager>();
            ApplicationUser user = userManager.FindByName(ticket.Identity.Name); // 同期版でOK。

            #region ClaimSetの生成

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

            authTokenClaimSet.Add("sub", ticket.Identity.Name);
            authTokenClaimSet.Add("iat", ticket.Properties.IssuedUtc.Value.ToUnixTimeSeconds().ToString());
            authTokenClaimSet.Add("exp", ticket.Properties.ExpiresUtc.Value.ToUnixTimeSeconds().ToString());

            // scope値によって、返す値を変更する。
            foreach (string scope in scopes)
            {
                switch (scope.ToLower())
                {
                    #region OpenID Connect
                    case ASPNETIdentityConst.Scope_Profile:
                        // ・・・
                        break;
                    case ASPNETIdentityConst.Scope_Email:
                        authTokenClaimSet.Add("email", user.Email);
                        authTokenClaimSet.Add("email_verified", user.EmailConfirmed.ToString());
                        break;
                    case ASPNETIdentityConst.Scope_Phone:
                        authTokenClaimSet.Add("phone_number", user.PhoneNumber);
                        authTokenClaimSet.Add("phone_number_verified", user.PhoneNumberConfirmed.ToString());
                        break;
                    case ASPNETIdentityConst.Scope_Address:
                        // ・・・
                        break;
                    #endregion

                    #region Else

                    case ASPNETIdentityConst.Scope_Userid:
                        authTokenClaimSet.Add(ASPNETIdentityConst.Scope_Userid, user.Id);
                        break;
                    case ASPNETIdentityConst.Scope_Roles:
                        authTokenClaimSet.Add(ASPNETIdentityConst.Scope_Roles, roles);
                        break;

                    #endregion

                }
            }

            authTokenClaimSet.Add("scopes", scopes);
            
            json = JsonConvert.SerializeObject(authTokenClaimSet);

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

        /// <summary>Unprotect</summary>
        /// <param name="jwt">JWT文字列</param>
        /// <returns>AuthenticationTicket</returns>
        public AuthenticationTicket Unprotect(string jwt)
        {
            // 検証
            JWT_RS256 jwtRS256 = new JWT_RS256(ASPNETIdentityConfig.OAuthJWT_cer, ASPNETIdentityConfig.OAuthJWTPassword);
            if (jwtRS256.Verify(jwt))
            {
                // 検証できた。

                // デシリアライズ、
                string[] temp = jwt.Split('.');
                string json = CustomEncode.ByteToString(CustomEncode.FromBase64UrlString(temp[1]), CustomEncode.UTF_8);
                Dictionary<string, object> authTokenClaimSet = JsonConvert.DeserializeObject<Dictionary<string, object>>(json);

                // 以下の検証処理
                //  ★ "iss":"accounts.google.com",
                //  ★ "aud":"クライアント識別子.apps.googleusercontent.com",
                //  ★ "sub":"ユーザーの一意識別子",
                //  ★ "exp":JWT の有効期限（Unix時間）
                //  ☆ "nonce":Implicitで必須

                // authToken.iss, authToken.expの検証
                if ((string)authTokenClaimSet["iss"] == ASPNETIdentityConfig.OAuthIssuerId
                    && OAuth2ProviderHelper.GetInstance().GetClientSecret((string)authTokenClaimSet["aud"]) != null
                    && long.Parse((string)authTokenClaimSet["exp"]) >= DateTimeOffset.Now.ToUnixTimeSeconds())
                {
                    // authToken.subの検証
                    // ApplicationUser を取得する。
                    ApplicationUserManager userManager
                    = HttpContext.Current.GetOwinContext().GetUserManager<ApplicationUserManager>();
                    ApplicationUser user = userManager.FindByName((string)authTokenClaimSet["sub"]); // 同期版でOK。

                    if (user != null)
                    {
                        // User Accountの場合

                        // ユーザーに対応するClaimsIdentityを生成する。
                        ClaimsIdentity identity = userManager.CreateIdentity(user, DefaultAuthenticationTypes.ExternalBearer);

                        // ClaimsIdentityに、その他、所定のClaimを追加する。
                        List<string> scopes = new List<string>();
                        foreach (string s in (JArray)authTokenClaimSet["scopes"])
                        {
                            scopes.Add(s);
                        }
                        OAuth2ProviderHelper.AddClaim(identity,
                            (string)authTokenClaimSet["aud"],
                            "", (string)authTokenClaimSet["nonce"], scopes);

                        // AuthenticationPropertiesの生成
                        AuthenticationProperties prop = new AuthenticationProperties();

                        // AuthenticationTicketに格納不要
                        //prop.IssuedUtc = DateTimeOffset.FromUnixTimeSeconds(long.Parse((string)authTokenClaimSet["iat"]));
                        //prop.ExpiresUtc = DateTimeOffset.FromUnixTimeSeconds(long.Parse((string)authTokenClaimSet["exp"]));

                        AuthenticationTicket auth = new AuthenticationTicket(identity, prop);

                        // 認証結果を返す。
                        return auth;
                    }
                    else
                    {
                        // Client Accountの場合

                        // ClaimとStoreのAudienceに対応するSubjectが一致するかを確認し、一致する場合のみ、認証する。
                        // でないと、UserStoreから削除されたUser Accountが、Client Accountに化けることになる。
                        if ((string)authTokenClaimSet["sub"] == OAuth2ProviderHelper.GetInstance().GetClientName((string)authTokenClaimSet["aud"]))
                        {
                            // ClaimsIdentityを生成し、
                            ClaimsIdentity identity = new ClaimsIdentity(OAuthDefaults.AuthenticationType);

                            // ClaimsIdentityに、client_idに対応するclient_nameを設定する。
                            identity.AddClaim(new Claim(ClaimTypes.Name, (string)authTokenClaimSet["sub"]));

                            // ClaimsIdentityに、その他、所定のClaimを追加する。
                            List<string> scopes = new List<string>();
                            foreach (string s in (JArray)authTokenClaimSet["scopes"])
                            {
                                scopes.Add(s);
                            }

                            OAuth2ProviderHelper.AddClaim(identity,
                                (string)authTokenClaimSet["aud"],
                                "", (string)authTokenClaimSet["nonce"], scopes);

                            // AuthenticationPropertiesの生成
                            AuthenticationProperties prop = new AuthenticationProperties();

                            // AuthenticationTicketに格納不要
                            //prop.IssuedUtc = DateTimeOffset.FromUnixTimeSeconds(long.Parse((string)authTokenClaimSet["iat"]));
                            //prop.ExpiresUtc = DateTimeOffset.FromUnixTimeSeconds(long.Parse((string)authTokenClaimSet["exp"]));

                            AuthenticationTicket auth = new AuthenticationTicket(identity, prop);

                            // 認証結果を返す。
                            return auth;
                        }
                    }
                }
            }
            
            // 検証、認証ナドナド、できなかった。
            return null;
        }
    }
}