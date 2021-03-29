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
//*  2019/06/20  西野 大介         IssuedTokenProvider対応
//*  2020/01/07  西野 大介         PPID対応実施
//*  2020/03/17  西野 大介         CIBA対応実施 (ES256)
//*  2020/12/21  西野 大介         ClientMode追加対応実施
//**********************************************************************************

using MultiPurposeAuthSite.Co;

#if NETFX
using MultiPurposeAuthSite.Entity;
#else
using MultiPurposeAuthSite;
#endif
using MultiPurposeAuthSite.Util;
using MultiPurposeAuthSite.Extensions.Sts;

using System;
using System.Linq;
using System.Collections.Generic;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

using Newtonsoft.Json;
using Newtonsoft.Json.Linq;

using Touryo.Infrastructure.Framework.Authentication;
using Touryo.Infrastructure.Public.IO;
using Touryo.Infrastructure.Public.Str;
using Touryo.Infrastructure.Public.Security.Jwt;
using Touryo.Infrastructure.Public.FastReflection;

namespace MultiPurposeAuthSite.TokenProviders
{
    /// <summary>CmnAccessToken</summary>
    public class CmnAccessToken
    {
        /// <summary>S256</summary>
        static string S256 = "#S256";
        /// <summary>S512</summary>
        static string S512 = "#S512";

        #region Create

        #region Claims経由

        /// <summary>CreateFromClaims</summary>
        /// <param name="clientId">string</param>
        /// <param name="userName">string</param>
        /// <param name="claims">IEnumerable(Claim)</param>
        /// <param name="ExpiresUtc">DateTimeOffset</param>
        /// <returns>JWT文字列</returns>
        public static string CreateFromClaims(
            string clientId, string userName,
            IEnumerable<Claim> identityClaims, DateTimeOffset expiresUtc)
        {
            string jti = Guid.NewGuid().ToString("N");
            string json = "";
            string audience = "";

            #region ClaimSetの生成

            Dictionary<string, object> tokenClaimSet = new Dictionary<string, object>();
            List<string> scopes = new List<string>();
            string auth_time = null;
            string claims = null;

            // カスタムクレームは含めない。
            //bool haveRoles = false;
            //List<string> roles = new List<string>();

            foreach (Claim c in identityClaims)
            {
                if (c.Type == OAuth2AndOIDCConst.UrnIssuerClaim)
                {
                    tokenClaimSet.Add(OAuth2AndOIDCConst.iss, c.Value);
                }
                else if (c.Type == OAuth2AndOIDCConst.UrnAudienceClaim)
                {
                    audience = c.Value;
                    tokenClaimSet.Add(OAuth2AndOIDCConst.aud, c.Value);
                }
                else if (c.Type == OAuth2AndOIDCConst.UrnScopesClaim)
                {
                    scopes.Add(c.Value);
                }
                else if (c.Type == OAuth2AndOIDCConst.UrnNonceClaim)
                {
                    tokenClaimSet.Add(OAuth2AndOIDCConst.nonce, c.Value);
                }
                else if (c.Type == OAuth2AndOIDCConst.UrnAuthTimeClaim)
                {
                    auth_time = c.Value;
                }
            }
            
            // PPID対応
            ApplicationUser user = null;
            string sub = PPIDExtension.GetSubForOIDC(
                (string)tokenClaimSet[OAuth2AndOIDCConst.aud], userName, out user);

            // sub
            tokenClaimSet.Add(OAuth2AndOIDCConst.sub, sub);

            // scopes
            tokenClaimSet.Add(OAuth2AndOIDCConst.scopes, scopes);

            // auth_time
            if (!string.IsNullOrEmpty(auth_time))
                tokenClaimSet.Add(OAuth2AndOIDCConst.auth_time, auth_time);

            // claims
            if (!string.IsNullOrEmpty(claims))
            {
                JObject _claims = JObject.Parse(claims);
                // claimsからid_tokeの内容を削除する。
                tokenClaimSet.Remove(OAuth2AndOIDCConst.claims_id_token);
                tokenClaimSet.Add(OAuth2AndOIDCConst.claims, _claims);
            }

            tokenClaimSet.Add(OAuth2AndOIDCConst.jti, jti);
            tokenClaimSet.Add(OAuth2AndOIDCConst.exp, expiresUtc.ToUnixTimeSeconds().ToString());
            tokenClaimSet.Add(OAuth2AndOIDCConst.nbf, DateTimeOffset.Now.ToUnixTimeSeconds().ToString());
            tokenClaimSet.Add(OAuth2AndOIDCConst.iat, DateTimeOffset.Now.ToUnixTimeSeconds().ToString());

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
                            tokenClaimSet.Add(OAuth2AndOIDCConst.Scope_Email, user.Email);
                            tokenClaimSet.Add(OAuth2AndOIDCConst.email_verified, user.EmailConfirmed.ToString());
                            break;
                        case OAuth2AndOIDCConst.Scope_Phone:
                            tokenClaimSet.Add(OAuth2AndOIDCConst.phone_number, user.PhoneNumber);
                            tokenClaimSet.Add(OAuth2AndOIDCConst.phone_number_verified, user.PhoneNumberConfirmed.ToString());
                            break;
                        case OAuth2AndOIDCConst.Scope_Address:
                            // ・・・
                            break;

                        #endregion

                        #region Else

                        case OAuth2AndOIDCConst.Scope_UserID:
                            tokenClaimSet.Add(OAuth2AndOIDCConst.Scope_UserID, user.Id);
                            break;

                        #endregion
                    }
                }
            }

            json = JsonConvert.SerializeObject(tokenClaimSet);

            #endregion

            #region JWS化

            JWS_RS256_X509 jwsRS256 = null;

            // JWT_RS256_X509
            jwsRS256 = new JWS_RS256_X509(Config.RsaPfxFilePath, Config.RsaPfxPassword);

            // 鍵変換
            RsaPublicKeyConverter rpkc = new RsaPublicKeyConverter(JWS_RSA.RS._256);

            // JWSHeaderのセット
            // kid : https://openid-foundation-japan.github.io/rfc7638.ja.html#Example
            Dictionary<string, string> jwk =
                JsonConvert.DeserializeObject<Dictionary<string, string>>(
                    rpkc.X509PfxToJwk(Config.RsaPfxFilePath, Config.RsaPfxPassword));

            jwsRS256.JWSHeader.kid = jwk[JwtConst.kid];
            jwsRS256.JWSHeader.jku = Config.OAuth2AuthorizationServerEndpointsRootURI + OAuth2AndOIDCParams.JwkSetUri;

            // ここでストアに登録
            IssuedTokenProvider.Create(jti, json, clientId, audience);

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

            Dictionary<string, object> tokenClaimSet = new Dictionary<string, object>();
            List<string> scopes = new List<string>();
            string auth_time = null;
            string claims = null;

            // カスタムクレームは含めない。
            //bool haveRoles = false;
            //List<string> roles = new List<string>();

            foreach (Claim c in identity.Claims)
            {
                if (c.Type == OAuth2AndOIDCConst.UrnIssuerClaim)
                {
                    tokenClaimSet.Add(OAuth2AndOIDCConst.iss, c.Value);
                }
                else if (c.Type == OAuth2AndOIDCConst.UrnAudienceClaim)
                {
                    tokenClaimSet.Add(OAuth2AndOIDCConst.aud, c.Value);
                }
                else if (c.Type == OAuth2AndOIDCConst.UrnScopesClaim)
                {
                    scopes.Add(c.Value);
                }
                else if (c.Type == OAuth2AndOIDCConst.UrnNonceClaim)
                {
                    tokenClaimSet.Add(OAuth2AndOIDCConst.nonce, c.Value);
                }
                else if (c.Type == OAuth2AndOIDCConst.UrnAuthTimeClaim)
                {
                    auth_time = c.Value;
                }
                else if (c.Type == OAuth2AndOIDCConst.UrnClaimsClaim)
                {
                    claims = c.Value;
                }
            }

            // PPID対応
            ApplicationUser user = null;
            string sub = PPIDExtension.GetSubForOIDC(
                (string)tokenClaimSet[OAuth2AndOIDCConst.aud], identity.Name, out user);

            // sub
            tokenClaimSet.Add(OAuth2AndOIDCConst.sub, sub);

            // scopes
            tokenClaimSet.Add(OAuth2AndOIDCConst.scopes, scopes);

            // auth_time
            if(!string.IsNullOrEmpty(auth_time))
                tokenClaimSet.Add(OAuth2AndOIDCConst.auth_time, auth_time);

            // claims
            if (!string.IsNullOrEmpty(claims)) tokenClaimSet.Add(
                OAuth2AndOIDCConst.claims, JObject.Parse(claims));

            // この時点では空にしておく。
            tokenClaimSet.Add(OAuth2AndOIDCConst.exp, "");
            tokenClaimSet.Add(OAuth2AndOIDCConst.nbf, "");
            tokenClaimSet.Add(OAuth2AndOIDCConst.iat, "");
            tokenClaimSet.Add(OAuth2AndOIDCConst.jti, "");

            return JsonConvert.SerializeObject(tokenClaimSet);
        }

        #endregion

        #region ProtectFromPayload

        /// <summary>ProtectFromPayload</summary>
        /// <param name="clientId">string</param>
        /// <param name="access_token_payload">AccessTokenのPayload</param>
        /// <param name="expiresUtc">DateTimeOffset</param>
        /// <param name="x509">X509Certificate2</param>
        /// <param name="permittedLevel">OAuth2AndOIDCEnum.ClientMode</param>
        /// <param name="audience">out string</param>
        /// <param name="subject">out string</param>
        /// <param name="alg">string</param>
        /// <returns>AccessToken</returns>
        public static string ProtectFromPayload(
            string clientId, string access_token_payload,
            DateTimeOffset expiresUtc, X509Certificate2 x509,
            OAuth2AndOIDCEnum.ClientMode permittedLevel,
            out string audience, out string subject, string alg = JwtConst.RS256)
        {
            string jti = Guid.NewGuid().ToString("N");
            string json = "";
            //string audience = "";

            #region JSON編集

            // access_token_payload の JObject化
            JObject payload = (JObject)JsonConvert.DeserializeObject(access_token_payload);

            // 読取
            audience = (string)payload[OAuth2AndOIDCConst.aud];
            subject = (string)payload[OAuth2AndOIDCConst.sub];
            
            //// claimsからid_tokeの内容を削除する。 -> 消すとCmnIdToken側で取得不可
            //JObject claims = (JObject)payload[OAuth2AndOIDCConst.claims];
            //if (claims != null)
            //{
                
            //    claims.Remove(OAuth2AndOIDCConst.claims_id_token);
            //    payload[OAuth2AndOIDCConst.claims] = claims;
            //}

            // 書込１
            payload[OAuth2AndOIDCConst.jti] = jti;
            payload[OAuth2AndOIDCConst.exp] = expiresUtc.ToUnixTimeSeconds().ToString();
            payload[OAuth2AndOIDCConst.nbf] = DateTimeOffset.Now.ToUnixTimeSeconds().ToString();
            payload[OAuth2AndOIDCConst.iat] = DateTimeOffset.Now.ToUnixTimeSeconds().ToString();
            
            // 書込２
            // - cnf
            if (x509 != null)
            {
                JObject dic = new JObject();
                string key = OAuth2AndOIDCConst.x5t;
                string val = x509.Thumbprint;

                if (x509.SignatureAlgorithm.FriendlyName == "sha256RSA")
                {
                    key += CmnAccessToken.S256;
                }
                else if (x509.SignatureAlgorithm.FriendlyName == "sha512RSA")
                {
                    key += CmnAccessToken.S512;
                }

                dic.Add(key, val);
                payload[OAuth2AndOIDCConst.cnf] = dic;
            }

            if (permittedLevel == OAuth2AndOIDCEnum.ClientMode.normal)
            {
                // ...
            }
            else if (permittedLevel == OAuth2AndOIDCEnum.ClientMode.device)
            {
                // - device
                payload["device"] = permittedLevel.ToStringByEmit();
            }
            else // fapi1, fapi2, fapi_ciba
            {
                // - fapi
                payload[OAuth2AndOIDCConst.fapi] = permittedLevel.ToStringByEmit();
            }

            json = JsonConvert.SerializeObject(payload);

            #endregion

            #region JWS化

            if (alg == JwtConst.ES256)
            {
                JWS_ES256_X509 jwsES256 = null;

                // 署名
                jwsES256 = new JWS_ES256_X509(Config.EcdsaPfxFilePath, Config.EcdsaPfxPassword);

                // 鍵変換
                EccPublicKeyConverter epkc = new EccPublicKeyConverter(JWS_ECDSA.ES._256);

                // JWSHeaderのセット
                Dictionary<string, string> jwk =
                    JsonConvert.DeserializeObject<Dictionary<string, string>>(
                        epkc.X509PfxToJwk(Config.EcdsaPfxFilePath, Config.EcdsaPfxPassword, HashAlgorithmName.SHA256));

                jwsES256.JWSHeader.kid = jwk[JwtConst.kid];
                jwsES256.JWSHeader.jku = Config.OAuth2AuthorizationServerEndpointsRootURI + OAuth2AndOIDCParams.JwkSetUri;

                // ここでストアに登録
                if (!string.IsNullOrEmpty(clientId))
                    // ... clientIdがnullのケースは、
                    // IntrospectTokenから処理共通化のために利用されるケース。
                    IssuedTokenProvider.Create(jti, json, clientId, audience);

                // 署名
                return jwsES256.Create(json);
            }
            else // 既定 は RS256
            {
                JWS_RS256_X509 jwsRS256 = null;

                // 署名
                jwsRS256 = new JWS_RS256_X509(Config.RsaPfxFilePath, Config.RsaPfxPassword);

                // 鍵変換
                RsaPublicKeyConverter rpkc = new RsaPublicKeyConverter(JWS_RSA.RS._256);

                // JWSHeaderのセット
                Dictionary<string, string> jwk =
                    JsonConvert.DeserializeObject<Dictionary<string, string>>(
                        rpkc.X509PfxToJwk(Config.RsaPfxFilePath, Config.RsaPfxPassword));

                jwsRS256.JWSHeader.kid = jwk[JwtConst.kid];
                jwsRS256.JWSHeader.jku = Config.OAuth2AuthorizationServerEndpointsRootURI + OAuth2AndOIDCParams.JwkSetUri;

                // ここでストアに登録
                if (!string.IsNullOrEmpty(clientId))
                    // ... clientIdがnullのケースは、
                    // IntrospectTokenから処理共通化のために利用されるケース。
                    IssuedTokenProvider.Create(jti, json, clientId, audience);

                // 署名
                return jwsRS256.Create(json);
            }

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
            JObject claims = null;
            return CmnAccessToken.VerifyAccessToken(jwt, out claims, out identity);
        }
        
        /// <summary>Verify</summary>
        /// <param name="jwt">string</param>
        /// <param name="claims">out JObject</param>
        /// <param name="identity">out ClaimsIdentity</param>
        /// <returns>検証結果</returns>
        public static bool VerifyAccessToken(string jwt, out JObject claims, out ClaimsIdentity identity)
        {
            claims = null; // = new JObject();
            // JObjectのnull対策は内包するCollectionの型自体が変わるので上手く行かない。
            // ≒ OAuth2EndpointController.GetUserClaimsでのnullチェックは必要。

            identity = new ClaimsIdentity();

            if (!string.IsNullOrEmpty(jwt))
            {
                // 検証
                JWS jws = null;
                
                // 証明書を使用するか、Jwkを使用するか判定
                Dictionary<string, string> header = JsonConvert.DeserializeObject<Dictionary<string, string>>(
                    CustomEncode.ByteToString(CustomEncode.FromBase64UrlString(jwt.Split('.')[0]), CustomEncode.UTF_8));

                if (header.Keys.Any(s => s == JwtConst.kid))
                {
                    string alg = header[JwtConst.alg];

                    if (string.IsNullOrEmpty(header[JwtConst.kid]))
                    {
                        // 証明書を使用
                        if (alg == JwtConst.ES256)
                        {
                            // ES256
                            jws = new JWS_ES256_X509(CmnClientParams.EcdsaCerFilePath, "");
                        }
                        else
                        {
                            // RS256
                            jws = new JWS_RS256_X509(CmnClientParams.RsaCerFilePath, "");
                        }
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
                            jws = new JWS_RS256_X509(CmnClientParams.RsaCerFilePath, "");
                        }
                        else
                        {
                            // Jwkを使用
                            if ((string)jwkObject[JwtConst.alg] == JwtConst.ES256)
                            {
                                // ES256
                                EccPublicKeyConverter epkc = new EccPublicKeyConverter(JWS_ECDSA.ES._256);
                                jws = new JWS_ES256_Param(epkc.JwkToParam(jwkObject), false);
                            }
                            else
                            {
                                // RS256
                                RsaPublicKeyConverter rpkc = new RsaPublicKeyConverter(JWS_RSA.RS._256);
                                jws = new JWS_RS256_Param(
                                    rpkc.JwkToProvider(jwkObject).ExportParameters(false));
                            }
                        }
                    }
                }

                if (jws.Verify(jwt))
                {
                    // 検証できた。

                    // デシリアライズ、
                    string[] temp = jwt.Split('.');
                    string json = CustomEncode.ByteToString(CustomEncode.FromBase64UrlString(temp[1]), CustomEncode.UTF_8);
                    Dictionary<string, object> tokenClaimSet = JsonConvert.DeserializeObject<Dictionary<string, object>>(json);

                    DateTime? datetime = RevocationProvider.Get((string)tokenClaimSet[OAuth2AndOIDCConst.jti]);

                    if (datetime == null)
                    {
                        // iss, expの検証
                        if ((string)tokenClaimSet[OAuth2AndOIDCConst.iss] == Config.IssuerId
                            && Helper.GetInstance().GetClientSecret((string)tokenClaimSet[OAuth2AndOIDCConst.aud]) != null
                            && CmnJwtToken.VerifyExp((string)tokenClaimSet[OAuth2AndOIDCConst.exp]))
                        {
                            // claims
                            if(tokenClaimSet.ContainsKey(OAuth2AndOIDCConst.claims))
                                claims = (JObject)tokenClaimSet[OAuth2AndOIDCConst.claims];

                            // subの検証
                            // ApplicationUser を取得する。
                            string subjectTypes = "";
                            ApplicationUser user = PPIDExtension.GetUserFromSub(
                                (string)tokenClaimSet[OAuth2AndOIDCConst.aud],
                                (string)tokenClaimSet[OAuth2AndOIDCConst.sub],
                                out subjectTypes);
                            //CmnUserStore.FindByName((string)tokenClaimSet[OAuth2AndOIDCConst.sub]); // 同期版でOK。

                            if (subjectTypes == OAuth2AndOIDCEnum.SubjectTypes.pairwise.ToStringByEmit())
                            {
                                // PPIDの場合
                                CmnAccessToken.AddClaims(tokenClaimSet, identity);
                                return true;
                            }
                            else
                            {
                                if (user != null)
                                {
                                    // User Accountの場合
                                    CmnAccessToken.AddClaims(tokenClaimSet, identity);
                                    return true;
                                }
                                else
                                {
                                    // Client Accountの場合

                                    // ClaimとStoreのAudience(aud)に対応するSubject(sub)が一致するかを確認し、一致する場合のみ、認証する。
                                    // ※ でないと、UserStoreから削除されたUser Accountが、Client Accountに化けることになる。
                                    if ((string)tokenClaimSet[OAuth2AndOIDCConst.sub]
                                        == Helper.GetInstance().GetClientName((string)tokenClaimSet[OAuth2AndOIDCConst.aud]))
                                    {
                                        CmnAccessToken.AddClaims(tokenClaimSet, identity);
                                        return true;
                                    }
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

        #endregion

        #region private

        #region AddClaims

        /// <summary>AddClaims</summary>
        /// <param name="tokenClaimSet">Dictionary(string, object)</param>
        /// <param name="identity">ClaimsIdentity</param>
        private static void AddClaims(Dictionary<string, object> tokenClaimSet, ClaimsIdentity identity)
        {
            // 予約Claimを追加
            identity.AddClaim(new Claim(ClaimTypes.Name, (string)tokenClaimSet[OAuth2AndOIDCConst.sub]));
            identity.AddClaim(new Claim(OAuth2AndOIDCConst.UrnExpirationTimeClaim, (string)tokenClaimSet[OAuth2AndOIDCConst.exp]));
            identity.AddClaim(new Claim(OAuth2AndOIDCConst.UrnNotBeforeClaim, (string)tokenClaimSet[OAuth2AndOIDCConst.nbf]));
            identity.AddClaim(new Claim(OAuth2AndOIDCConst.UrnIssuedAtClaim, (string)tokenClaimSet[OAuth2AndOIDCConst.iat]));
            identity.AddClaim(new Claim(OAuth2AndOIDCConst.UrnJwtIdClaim, (string)tokenClaimSet[OAuth2AndOIDCConst.jti]));

            // 基本Claimを追加
            // scopes
            List<string> scopes = new List<string>();
            foreach (string s in (JArray)tokenClaimSet[OAuth2AndOIDCConst.scopes])
            {
                scopes.Add(s);
            }
            Helper.AddClaim(identity,
                (string)tokenClaimSet[OAuth2AndOIDCConst.aud], "", scopes, null, (string)tokenClaimSet[OAuth2AndOIDCConst.nonce]);

            // 拡張Claimを追加
            // - cnf
            if (tokenClaimSet.ContainsKey(OAuth2AndOIDCConst.cnf))
            {
                JObject cnf = (JObject)tokenClaimSet[OAuth2AndOIDCConst.cnf];

                if(cnf.ContainsKey(OAuth2AndOIDCConst.x5t + CmnAccessToken.S256))
                    identity.AddClaim(new Claim(OAuth2AndOIDCConst.UrnCnfX5tClaim + CmnAccessToken.S256,
                        (string)cnf[OAuth2AndOIDCConst.x5t + CmnAccessToken.S256]));
                else if(cnf.ContainsKey(OAuth2AndOIDCConst.x5t + CmnAccessToken.S512))
                    identity.AddClaim(new Claim(OAuth2AndOIDCConst.UrnCnfX5tClaim + CmnAccessToken.S512,
                        (string)cnf[OAuth2AndOIDCConst.x5t + CmnAccessToken.S512]));
            }
            
            //// - fapi
            //if (tokenClaimSet.ContainsKey(OAuth2AndOIDCConst.fapi))
            //{
            //    identity.AddClaim(new Claim(OAuth2AndOIDCConst.Claim_FApi, (string)tokenClaimSet[OAuth2AndOIDCConst.fapi]));
            //}
        }

        #endregion

        #endregion
    }
}
