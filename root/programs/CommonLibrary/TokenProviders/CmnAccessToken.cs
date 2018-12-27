﻿//**********************************************************************************
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
//* クラス名        ：CmnAccessToken
//* クラス日本語名  ：CmnAccessToken
//*
//* 作成日時        ：－
//* 作成者          ：－
//* 更新履歴        ：－
//*
//*  日時        更新者            内容
//*  ----------  ----------------  -------------------------------------------------
//*  2018/12/25  西野 大介         新規
//**********************************************************************************

using MultiPurposeAuthSite.Co;
#if NETFX
using MultiPurposeAuthSite.Entity;
#else
using MultiPurposeAuthSite;
#endif
using MultiPurposeAuthSite.Data;
using MultiPurposeAuthSite.Extensions.OAuth2;

using System;
using System.Linq;
using System.Collections.Generic;
using System.Security.Claims;
using System.Security.Cryptography.X509Certificates;

using Newtonsoft.Json;
using Newtonsoft.Json.Linq;

using Touryo.Infrastructure.Framework.Authentication;
using Touryo.Infrastructure.Public.IO;
using Touryo.Infrastructure.Public.Str;
using Touryo.Infrastructure.Public.Security;

namespace MultiPurposeAuthSite.TokenProviders
{
    /// <summary>CmnAccessToken</summary>
    public class CmnAccessToken
    {
        #region Create

        #region Claims経由

        /// <summary>CreateFromClaims</summary>
        /// <param name="userName">string</param>
        /// <param name="claims">IEnumerable(Claim)</param>
        /// <param name="ExpiresUtc">DateTimeOffset</param>
        /// <param name="IssuedUtc">DateTimeOffset</param>
        /// <returns>JWT文字列</returns>
        public static string CreateFromClaims(
            string userName, IEnumerable<Claim> claims, DateTimeOffset expiresUtc, DateTimeOffset issuedUtc)
        {
            string json = "";

            #region ClaimSetの生成
            
            Dictionary<string, object> authTokenClaimSet = new Dictionary<string, object>();
            List<string> scopes = new List<string>();
            List<string> roles = new List<string>();

            foreach (Claim claim in claims)
            {
                if (claim.Type == OAuth2AndOIDCConst.Claim_Issuer)
                {
                    authTokenClaimSet.Add(OAuth2AndOIDCConst.iss, claim.Value);
                }
                else if (claim.Type == OAuth2AndOIDCConst.Claim_Audience)
                {
                    authTokenClaimSet.Add(OAuth2AndOIDCConst.aud, claim.Value);
                }
                else if (claim.Type == OAuth2AndOIDCConst.Claim_Nonce)
                {
                    authTokenClaimSet.Add(OAuth2AndOIDCConst.nonce, claim.Value);
                }
                else if (claim.Type == OAuth2AndOIDCConst.Claim_Scopes)
                {
                    scopes.Add(claim.Value);
                }
                else if (claim.Type == "http://schemas.microsoft.com/ws/2008/06/identity/claims/role")
                {
                    roles.Add(claim.Value);
                }
            }

            string sub = "";
            ApplicationUser user = null;
            if (!string.IsNullOrEmpty(userName))
            {
                sub = userName;
                user = CmnUserStore.FindByName(userName);
            }
            else
            {
                sub = Helper.GetInstance().GetClientName((string)authTokenClaimSet[OAuth2AndOIDCConst.aud]);
            }

            authTokenClaimSet.Add(OAuth2AndOIDCConst.sub, userName);

            authTokenClaimSet.Add(OAuth2AndOIDCConst.exp, expiresUtc.ToUnixTimeSeconds().ToString());
            authTokenClaimSet.Add(OAuth2AndOIDCConst.nbf, DateTimeOffset.Now.ToUnixTimeSeconds().ToString());
            authTokenClaimSet.Add(OAuth2AndOIDCConst.iat, issuedUtc.ToUnixTimeSeconds().ToString());
            authTokenClaimSet.Add(OAuth2AndOIDCConst.jti, Guid.NewGuid().ToString("N"));

            authTokenClaimSet.Add(OAuth2AndOIDCConst.scopes, scopes);

            // scope値によって、返す値を変更する。
            foreach (string scope in scopes)
            {
                if (user != null)
                {
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
                                OAuth2AndOIDCConst.Scope_Roles, CmnUserStore.GetRoles(user));
                            break;

                            #endregion
                    }
                }
            }

            json = JsonConvert.SerializeObject(authTokenClaimSet);

            #endregion

            #region JWS化

            JWS_RS256_X509 jwsRS256 = null;

            // JWT_RS256_X509
            jwsRS256 = new JWS_RS256_X509(Config.OAuth2JWT_pfx, Config.OAuth2JWTPassword,
                X509KeyStorageFlags.Exportable | X509KeyStorageFlags.MachineKeySet);

            // JWSHeaderのセット
            // kid : https://openid-foundation-japan.github.io/rfc7638.ja.html#Example
            Dictionary<string, string> jwk =
                JsonConvert.DeserializeObject<Dictionary<string, string>>(
                    RsaPublicKeyConverter.X509PfxToJwk(Config.OAuth2JWT_pfx, Config.OAuth2JWTPassword));

            jwsRS256.JWSHeader.kid = jwk[JwtConst.kid];
            jwsRS256.JWSHeader.jku = Config.OAuth2AuthorizationServerEndpointsRootURI + OAuth2AndOIDCParams.JwkSetUri;

            // 署名
            return jwsRS256.Create(json);

            #endregion
        }

        #endregion

        #region Code経由

        /// <summary>CreatePayloadForCode</summary>
        /// <param name="identity">ClaimsIdentity</param>
        /// <param name="issuedUtc">DateTimeOffset</param>
        /// <returns>Jwt AccessTokenのPayload部</returns>
        public static string CreatePayloadForCode(ClaimsIdentity identity, DateTimeOffset issuedUtc)
        {
            // チェック
            if (identity == null || issuedUtc == null)
            {
                throw new ArgumentNullException();
            }

            Dictionary<string, object> authTokenClaimSet = new Dictionary<string, object>();
            List<string> scopes = new List<string>();
            List<string> roles = new List<string>();

            foreach (Claim c in identity.Claims)
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

            authTokenClaimSet.Add(OAuth2AndOIDCConst.sub, identity.Name);
            authTokenClaimSet.Add(OAuth2AndOIDCConst.scopes, scopes);

            // この時点では空にしておく。
            authTokenClaimSet.Add(OAuth2AndOIDCConst.exp, "");

            authTokenClaimSet.Add(OAuth2AndOIDCConst.nbf, DateTimeOffset.Now.ToUnixTimeSeconds().ToString());
            authTokenClaimSet.Add(OAuth2AndOIDCConst.iat, issuedUtc.ToUnixTimeSeconds().ToString());
            authTokenClaimSet.Add(OAuth2AndOIDCConst.jti, Guid.NewGuid().ToString("N"));

            return JsonConvert.SerializeObject(authTokenClaimSet);
        }

        /// <summary>ProtectFromPayloadForCode</summary>
        /// <param name="access_token_payload">AccessTokenのPayload</param>
        /// <param name="expiresUtc">DateTimeOffset</param>
        /// <returns>AccessToken</returns>
        public static string ProtectFromPayloadForCode(string access_token_payload, DateTimeOffset expiresUtc)
        {
            string json = "";

            #region JSON編集

            // access_token_payloadのDictionary化
            Dictionary<string, object> payload =
                JsonConvert.DeserializeObject<Dictionary<string, object>>(access_token_payload);

            payload[OAuth2AndOIDCConst.exp] = expiresUtc.ToUnixTimeSeconds().ToString();
            payload[OAuth2AndOIDCConst.scopes] = payload[OAuth2AndOIDCConst.scopes];

            json = JsonConvert.SerializeObject(payload);

            #endregion

            #region JWS化

            JWS_RS256_X509 jwsRS256 = null;

            // 署名
            jwsRS256 = new JWS_RS256_X509(Config.OAuth2JWT_pfx, Config.OAuth2JWTPassword,
                X509KeyStorageFlags.Exportable | X509KeyStorageFlags.MachineKeySet);

            // JWSHeaderのセット
            // kid : https://openid-foundation-japan.github.io/rfc7638.ja.html#Example
            Dictionary<string, string> jwk =
                JsonConvert.DeserializeObject<Dictionary<string, string>>(
                    RsaPublicKeyConverter.X509PfxToJwk(Config.OAuth2JWT_pfx, Config.OAuth2JWTPassword));

            jwsRS256.JWSHeader.kid = jwk[JwtConst.kid];
            jwsRS256.JWSHeader.jku = Config.OAuth2AuthorizationServerEndpointsRootURI + OAuth2AndOIDCParams.JwkSetUri;

            return jwsRS256.Create(json);

            #endregion
        }

        #endregion

        #endregion

        #region Verify

        /// <summary>Verify</summary>
        /// <param name="jwt">string</param>
        /// <param name="identity">ClaimsIdentity</param>
        /// <returns>検証結果</returns>
        public static bool VerifyAccessToken(string jwt, out ClaimsIdentity identity)
        {
            identity = new ClaimsIdentity();

            if (!string.IsNullOrEmpty(jwt))
            {
                // 検証
                JWS_RS256 jwsRS256 = null;

                // 証明書を使用するか、Jwkを使用するか判定
                Dictionary<string, string> header = JsonConvert.DeserializeObject<Dictionary<string, string>>(
                    CustomEncode.ByteToString(CustomEncode.FromBase64UrlString(jwt.Split('.')[0]), CustomEncode.UTF_8));

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

                    DateTime? datetime = RevocationProvider.Get((string)authTokenClaimSet[OAuth2AndOIDCConst.jti]);

                    if (datetime == null)
                    {
                        // authToken.iss, authToken.expの検証
                        if ((string)authTokenClaimSet[OAuth2AndOIDCConst.iss] == Config.OAuth2IssuerId
                            && Helper.GetInstance().GetClientSecret((string)authTokenClaimSet[OAuth2AndOIDCConst.aud]) != null
                            && long.Parse((string)authTokenClaimSet[OAuth2AndOIDCConst.exp]) >= DateTimeOffset.Now.ToUnixTimeSeconds())
                        {
                            // authToken.subの検証
                            // ApplicationUser を取得する。
                            ApplicationUser user = CmnUserStore.FindByName((string)authTokenClaimSet[OAuth2AndOIDCConst.sub]); // 同期版でOK。

                            if (user != null)
                            {
                                // User Accountの場合
                                CmnAccessToken.AddClaims(authTokenClaimSet, identity);
                                return true;
                            }
                            else
                            {
                                // Client Accountの場合

                                // ClaimとStoreのAudience(aud)に対応するSubject(sub)が一致するかを確認し、一致する場合のみ、認証する。
                                // ※ でないと、UserStoreから削除されたUser Accountが、Client Accountに化けることになる。
                                if ((string)authTokenClaimSet[OAuth2AndOIDCConst.sub]
                                    == Helper.GetInstance().GetClientName((string)authTokenClaimSet[OAuth2AndOIDCConst.aud]))
                                {
                                    CmnAccessToken.AddClaims(authTokenClaimSet, identity);
                                    return true;
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
            }
            else
            {
                // 引数に問題
            }

            return false;
        }

        /// <summary>AddClaims</summary>
        /// <param name="authTokenClaimSet"></param>
        /// <param name="identity"></param>
        private static void AddClaims(
            Dictionary<string, object> authTokenClaimSet,
            ClaimsIdentity identity)
        {
            // sub（client_idに対応するclient_name）Claimを設定する。
            identity.AddClaim(new Claim(ClaimTypes.Name, (string)authTokenClaimSet[OAuth2AndOIDCConst.sub]));

            // aud、scopes、nonceなどのClaimを追加する。
            List<string> scopes = new List<string>();
            foreach (string s in (JArray)authTokenClaimSet[OAuth2AndOIDCConst.scopes])
            {
                scopes.Add(s);
            }

            // もろもろのClaimの設定
            Helper.AddClaim(identity,
                (string)authTokenClaimSet[OAuth2AndOIDCConst.aud], "", scopes, (string)authTokenClaimSet[OAuth2AndOIDCConst.nonce]);

            // その他、所定のClaimを追加する。
            identity.AddClaim(new Claim(OAuth2AndOIDCConst.Claim_ExpirationTime, (string)authTokenClaimSet[OAuth2AndOIDCConst.exp]));
            identity.AddClaim(new Claim(OAuth2AndOIDCConst.Claim_NotBefore, (string)authTokenClaimSet[OAuth2AndOIDCConst.nbf]));
            identity.AddClaim(new Claim(OAuth2AndOIDCConst.Claim_IssuedAt, (string)authTokenClaimSet[OAuth2AndOIDCConst.iat]));
            identity.AddClaim(new Claim(OAuth2AndOIDCConst.Claim_JwtId, (string)authTokenClaimSet[OAuth2AndOIDCConst.jti]));
        }

        #endregion
    }
}
