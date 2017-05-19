﻿//**********************************************************************************
//* Copyright (C) 2007,2016 Hitachi Solutions,Ltd.
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

using Microsoft.Owin.Security;
using Microsoft.Owin.Security.OAuth;
using Microsoft.AspNet.Identity;
using Microsoft.AspNet.Identity.Owin;

using Newtonsoft.Json;

using MultiPurposeAuthSite.Models.ASPNETIdentity.Manager;
using MultiPurposeAuthSite.Models.ASPNETIdentity.Entity;
using MultiPurposeAuthSite.Models.ASPNETIdentity.TokensClaimSet;

using Touryo.Infrastructure.Public.Str;
using Touryo.Infrastructure.Public.Util.JWT;

namespace MultiPurposeAuthSite.Models.ASPNETIdentity.TokenProviders
{
    /// <summary>AccessTokenFormatJwt</summary>
    public class AccessTokenFormatJwt: ISecureDataFormat<AuthenticationTicket>
    {
        ///// <summary>IssuerId</summary>
        //private readonly string _oAuthIssuerId = string.Empty;

        /// <summary>constructor</summary>
        /// <param name="oAuthIssuerId">oAuthIssuerId</param>
        public AccessTokenFormatJwt(string oAuthIssuerId)
        {
            //this._oAuthIssuerId = oAuthIssuerId;
        }

        /// <summary>Protect</summary>
        /// <param name="data">AuthenticationTicket</param>
        /// <returns>JWT文字列</returns>
        public string Protect(AuthenticationTicket data)
        {
            string json = "";
            string jwt = "";

            // OpenID Connect - マイクロソフト系技術情報 Wiki > IDトークン（クレーム）
            // - クレームセット
            //   https://techinfoofmicrosofttech.osscons.jp/index.php?OpenID%20Connect#h586dfab
            // - 例 > Google
            //   https://techinfoofmicrosofttech.osscons.jp/index.php?OpenID%20Connect#jaec1c75
            //{
            //  ★ "iss":"accounts.google.com",
            //  ★ "aud":"クライアント識別子.apps.googleusercontent.com",
            //  ★ "sub":"ユーザーの一意識別子",
            //  ★ "iat":JWT の発行日時（Unix時間）,
            //  ★ "exp":JWT の有効期限（Unix時間）
            //  ☆ "nonce":Implicitで必須
            //  "email":"・・・・",
            //  "email_verified":"true",
            //  "azp":"認可した対象者のID.apps.googleusercontent.com",
            //  "at_hash":"・・・", ← Hybrid Flowの追加クレーム
            //}

            // チェック
            if (data == null)
            {
                throw new ArgumentNullException("data");
            }

            AuthenticationTokensClaimSet authToken = new AuthenticationTokensClaimSet();

            authToken.Issuer = "";
            authToken.Audience = "";
            authToken.Subject = data.Identity.Name;
            authToken.IssuedAt = data.Properties.IssuedUtc.Value.ToUnixTimeSeconds().ToString();
            authToken.ExpirationTime = data.Properties.ExpiresUtc.Value.ToUnixTimeSeconds().ToString();
            authToken.Nonce = ""; // 拡張した（nonce代替）。
            authToken.Email = data.Identity.Name;

            List<string> roles = new List<string>();
            List<string> scopes = new List<string>();

            foreach (Claim c in data.Identity.Claims)
            {
                if (c.Type == ASPNETIdentityConst.Claim_Issuer)
                {
                    authToken.Issuer = c.Value;
                }
                else if (c.Type == ASPNETIdentityConst.Claim_Audience)
                {
                    authToken.Audience = c.Value;
                }
                else if (c.Type == ASPNETIdentityConst.Claim_Nonce)
                {
                    authToken.Nonce = c.Value;
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

            authToken.Roles = roles.ToArray();
            authToken.Scopes = scopes.ToArray();

            json = JsonConvert.SerializeObject(authToken);
            
            JWT_RS256 jwtRS256 = null;

            // 署名
            jwtRS256 = new JWT_RS256(ASPNETIdentityConfig.OAuthJWT_pfx, ASPNETIdentityConfig.OAuthJWTPassword);
            jwt = jwtRS256.Create(json);

            // 検証
            jwtRS256 = new JWT_RS256(ASPNETIdentityConfig.OAuthJWT_cer, ASPNETIdentityConfig.OAuthJWTPassword);
            if (jwtRS256.Verify(jwt))
            {
                return jwt; // 検証できた。
            }
            else
            {
                return ""; // 検証できなかった。
            }
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
                AuthenticationTokensClaimSet authToken = JsonConvert.DeserializeObject<AuthenticationTokensClaimSet>(json);

                // 以下の検証処理
                //  ★ "iss":"accounts.google.com",
                //  ★ "aud":"クライアント識別子.apps.googleusercontent.com",
                //  ★ "sub":"ユーザーの一意識別子",
                //  ★ "exp":JWT の有効期限（Unix時間）
                //  ☆ "nonce":Implicitで必須

                // authToken.iss, authToken.expの検証
                if (authToken.Issuer == ASPNETIdentityConfig.OAuthIssuerId
                    && OAuthProviderHelper.GetInstance().GetClientSecret(authToken.Audience) != null
                    && long.Parse(authToken.ExpirationTime) >= DateTimeOffset.Now.ToUnixTimeSeconds())
                {
                    // authToken.subの検証
                    // ApplicationUser を取得する。
                    ApplicationUserManager userManager
                    = HttpContext.Current.GetOwinContext().GetUserManager<ApplicationUserManager>();
                    ApplicationUser user = userManager.FindByName(authToken.Subject); // 同期版でOK。

                    if (user != null)
                    {
                        // User Accountの場合

                        // ユーザーに対応するClaimsIdentityを生成する。
                        ClaimsIdentity identity = userManager.CreateIdentity(user, DefaultAuthenticationTypes.ExternalBearer);

                        // ClaimsIdentityに、その他、所定のClaimを追加する。
                        OAuthProviderHelper.AddClaim(identity, authToken.Audience, authToken.Nonce, authToken.Scopes);

                        // AuthenticationPropertiesの生成
                        AuthenticationProperties prop = new AuthenticationProperties();

                        // 不要
                        //prop.IssuedUtc = DateTimeOffset.FromUnixTimeSeconds(long.Parse(authToken.iat));
                        //prop.ExpiresUtc = DateTimeOffset.FromUnixTimeSeconds(long.Parse(authToken.exp));

                        AuthenticationTicket auth = new AuthenticationTicket(identity, prop);

                        // 認証結果を返す。
                        return auth;
                    }
                    else
                    {
                        // Client Accountの場合

                        // ClaimとStoreのAudienceに対応するSubjectが一致するかを確認し、一致する場合のみ、認証する。
                        // でないと、UserStoreから削除されたUser Accountが、Client Accountに化けることになる。
                        if (authToken.Subject == OAuthProviderHelper.GetInstance().GetClientName(authToken.Audience))
                        {
                            // ClaimsIdentityを生成し、
                            ClaimsIdentity identity = new ClaimsIdentity(OAuthDefaults.AuthenticationType);

                            // ClaimsIdentityに、client_idに対応するclient_nameを設定する。
                            identity.AddClaim(new Claim(ClaimTypes.Name, authToken.Subject));

                            // ClaimsIdentityに、その他、所定のClaimを追加する。
                            OAuthProviderHelper.AddClaim(identity, authToken.Audience, authToken.Nonce, authToken.Scopes);

                            // AuthenticationPropertiesの生成
                            AuthenticationProperties prop = new AuthenticationProperties();

                            // 不要
                            //prop.IssuedUtc = DateTimeOffset.FromUnixTimeSeconds(long.Parse(authToken.iat));
                            //prop.ExpiresUtc = DateTimeOffset.FromUnixTimeSeconds(long.Parse(authToken.exp));

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