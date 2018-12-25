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

using MultiPurposeAuthSite.Co;
using MultiPurposeAuthSite.Entity;
#if NETFX
using MultiPurposeAuthSite.Manager;
#else
#endif
using MultiPurposeAuthSite.Extensions.OAuth2;

using System;
using System.Web;
using System.Linq;
using System.Collections.Generic;
using System.Security.Claims;

using Microsoft.Owin.Security;
using Microsoft.AspNet.Identity;
using Microsoft.AspNet.Identity.Owin;

using Newtonsoft.Json;
using Newtonsoft.Json.Linq;

using Touryo.Infrastructure.Framework.Authentication;
using Touryo.Infrastructure.Public.IO;
using Touryo.Infrastructure.Public.Str;
using Touryo.Infrastructure.Public.Security;

namespace MultiPurposeAuthSite.TokenProviders
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
            // チェック
            if (ticket == null)
            {
                throw new ArgumentNullException("ticket");
            }

            return CmnAccessToken.Protect(ticket.Identity.Name, ticket.Identity.Claims, 
                ticket.Properties.ExpiresUtc.Value, ticket.Properties.IssuedUtc.Value);
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
                    JObject jwkObject = null;

                    if (ResourceLoader.Exists(OAuth2AndOIDCParams.JwkSetFilePath, false))
                    {
                        JwkSet jwkSetObject = JwkSet.LoadJwkSet(OAuth2AndOIDCParams.JwkSetFilePath);
                        jwkObject = JwkSet.GetJwkObject(jwkSetObject, header[JwtConst.kid]);
                    }

                    if (jwkObject == null)
                    {
                        // 証明書を使用
                        jwsRS256 = new JWS_RS256_X509(OAuth2AndOIDCParams.RS256Cer, "");
                    }
                    else
                    {
                        // Jwkを使用
                        jwsRS256 = new JWS_RS256_Param(
                            RsaPublicKeyConverter.JwkToProvider(jwkObject).ExportParameters(false));
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

                DateTime? datetime = RevocationProvider.GetInstance().Get((string)authTokenClaimSet[OAuth2AndOIDCConst.jti]);

                if (datetime == null)
                {
                    // authToken.iss, authToken.expの検証
                    if ((string)authTokenClaimSet[OAuth2AndOIDCConst.iss] == Config.OAuth2IssuerId
                        && Helper.GetInstance().GetClientSecret((string)authTokenClaimSet[OAuth2AndOIDCConst.aud]) != null
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

                            // もろもろのClaimの設定
                            Helper.AddClaim(identity,
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
                            if ((string)authTokenClaimSet[OAuth2AndOIDCConst.sub] == Helper.GetInstance().GetClientName((string)authTokenClaimSet[OAuth2AndOIDCConst.aud]))
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

                                Helper.AddClaim(identity,
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