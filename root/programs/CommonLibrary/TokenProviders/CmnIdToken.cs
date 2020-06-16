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
//* クラス名        ：CmnIdToken
//* クラス日本語名  ：CmnIdToken
//*
//* 作成日時        ：－
//* 作成者          ：－
//* 更新履歴        ：－
//*
//*  日時        更新者            内容
//*  ----------  ----------------  -------------------------------------------------
//*  2019/02/12  西野 大介         新規
//*  2020/01/08  西野 大介         #126（Feedback）対応実施
//*  2020/03/17  西野 大介         CIBA対応実施 (ES256)
//**********************************************************************************

using MultiPurposeAuthSite.Co;
using MultiPurposeAuthSite.Data;

#if NETCORE
//using MultiPurposeAuthSite;
#else
using MultiPurposeAuthSite.Entity;
#endif

using System;
using System.Linq;
using System.Collections.Generic;
using System.Security.Cryptography.X509Certificates;

using Newtonsoft.Json;
using Newtonsoft.Json.Linq;

using Touryo.Infrastructure.Framework.Authentication;
using Touryo.Infrastructure.Public.Str;
using Touryo.Infrastructure.Public.Util;
using Touryo.Infrastructure.Public.Security;
using Touryo.Infrastructure.Public.Security.Jwt;


namespace MultiPurposeAuthSite.TokenProviders
{
    /// <summary>CmnIdToken</summary>
    public class CmnIdToken
    {
        /// <summary>
        /// ChangeToIdTokenFromAccessToken
        ///   OIDC対応（AccessTokenからIdTokenを生成）
        /// </summary>
        /// <param name="access_token">string</param>
        /// <param name="code">string</param>
        /// <param name="state">string</param>
        /// <param name="hct">HashClaimType</param>
        /// <param name="pfxFilePath">string</param>
        /// <param name="pfxPassword">string</param>
        /// <param name="cerJwkString">string</param>
        /// <param name="alg">string</param>
        /// <returns>id_token</returns>
        public static string ChangeToIdTokenFromAccessToken(
            string access_token, string code, string state, HashClaimType hct,
            string pfxFilePath, string pfxPassword, string cerJwkString, string alg = JwtConst.RS256)
        {
            if (access_token.Contains("."))
            {
                string[] temp = access_token.Split('.');
                string json = CustomEncode.ByteToString(CustomEncode.FromBase64UrlString(temp[1]), CustomEncode.UTF_8);
                JObject tokenClaimSet = (JObject)JsonConvert.DeserializeObject(json);

                // ・access_tokenがJWTで、payloadに"nonce" and "scope=openidクレームが存在する場合、
                if (tokenClaimSet.ContainsKey(OAuth2AndOIDCConst.nonce)
                    && tokenClaimSet.ContainsKey(OAuth2AndOIDCConst.scopes))
                {
                    JArray scopes = (JArray)tokenClaimSet[OAuth2AndOIDCConst.scopes];

                    // ・OpenID Connect : response_type=codeに対応する。
                    if (scopes.Any(x => x.ToString() == OAuth2AndOIDCConst.Scope_Openid))
                    {
                        // claimsクレームを退避
                        JObject claims = (JObject)tokenClaimSet[OAuth2AndOIDCConst.claims];

                        // IdTokenから不要なクレームを削除する。
                        List<string> keys = new List<string>();
                        foreach (KeyValuePair<string, JToken> item in tokenClaimSet)
                        {
                            if ("iss sub aud client_id exp iat nonce auth_time".IndexOf(item.Key) == -1)
                            {
                                keys.Add(item.Key);
                            }
                        }

                        foreach (string key in keys)
                        {
                            tokenClaimSet.Remove(key);
                        }

                        //・expをIdToken用のexpに差し替える。
                        tokenClaimSet[OAuth2AndOIDCConst.exp] = DateTimeOffset.Now.AddMinutes(
                            Config.OidcIdTokenExpireTimeSpanFromMinutes.TotalMinutes).ToUnixTimeSeconds().ToString();

                        if (claims != null)
                        {
                            // claims > id_tokenクレームの内容を格納
                            foreach (KeyValuePair<string, JToken> item in claims)
                            {
                                if (item.Key == OAuth2AndOIDCConst.claims_userinfo)
                                {
                                    // ...
                                }
                                else if (item.Key == OAuth2AndOIDCConst.claims_id_token)
                                {
                                    // id_tokenに追加する値
                                    // - auth_timeクレーム
                                    //   max_age対応もあるので、対応済み。
                                    // - acrクレーム
                                    //   ...未サポート...
                                    // - その他
                                    //   任意の実装を追加可能
                                    ApplicationUser user = CmnUserStore.FindByName((string)tokenClaimSet[OAuth2AndOIDCConst.sub]);
                                }
                            }
                        }

                        //Co.Config.;

                        //・payloadにat_hash, c_hash, s_hashを追加する。

                        if (hct.HasFlag(HashClaimType.AtHash))
                        {
                            // at_hash
                            tokenClaimSet.Add(
                                OAuth2AndOIDCConst.at_hash,
                                IdToken.CreateHash(access_token));
                        }

                        if (hct.HasFlag(HashClaimType.CHash))
                        {
                            // c_hash
                            tokenClaimSet.Add(
                                OAuth2AndOIDCConst.c_hash,
                                IdToken.CreateHash(code));
                        }

                        if (hct.HasFlag(HashClaimType.SHash))
                        {
                            // s_hash
                            if (!string.IsNullOrEmpty(state))
                            {
                                tokenClaimSet.Add(
                                    OAuth2AndOIDCConst.s_hash,
                                    IdToken.CreateHash(state));
                            }
                        }

                        //・編集したpayloadを再度JWTとして署名する。
                        string newPayload = JsonConvert.SerializeObject(tokenClaimSet);

                        // 署名
                        if (string.IsNullOrEmpty(cerJwkString))
                        {
                            // 通常

                            // ヘッダ ... access_tokenと同じ
                            JWS_Header jwsHeader =
                                JsonConvert.DeserializeObject<JWS_Header>(
                                    CustomEncode.ByteToString(CustomEncode.FromBase64UrlString(temp[0]), CustomEncode.UTF_8));

                            // JWS
                            JWS jws = null;
                            if (alg == JwtConst.ES256)
                            {
                                // ES256
                                jws = new JWS_ES256_X509(pfxFilePath, pfxPassword);

                                if (!string.IsNullOrEmpty(jwsHeader.jku)
                                && !string.IsNullOrEmpty(jwsHeader.kid))
                                {
                                    ((JWS_ES256)jws).JWSHeader.jku = jwsHeader.jku;
                                    ((JWS_ES256)jws).JWSHeader.kid = jwsHeader.kid;
                                }
                            }
                            else
                            {
                                // RS256
                                jws = new JWS_RS256_X509(pfxFilePath, pfxPassword);

                                if (!string.IsNullOrEmpty(jwsHeader.jku)
                                && !string.IsNullOrEmpty(jwsHeader.kid))
                                {
                                    ((JWS_RS256)jws).JWSHeader.jku = jwsHeader.jku;
                                    ((JWS_RS256)jws).JWSHeader.kid = jwsHeader.kid;
                                }
                            }

                            // Create
                            return jws.Create(newPayload);
                        }
                        else
                        {
                            // FAPI2
#if NET45 || NET46
                            throw new NotSupportedException("FAPI2 is not supported in this dotnet version.");
#else
                            // JWE(RsaOaepAesGcm)
                            RsaPublicKeyConverter rpkc = new RsaPublicKeyConverter(JWS_RSA.RS._256);
                            JWE_RsaOaepAesGcm_Param jweRsaOaep = new JWE_RsaOaepAesGcm_Param(
                                EnumASymmetricAlgorithm.RsaCng, rpkc.JwkToParam(cerJwkString));

                            // JWS(ES256)
                            JWS_ES256_X509 jwsES256 = new JWS_ES256_X509(pfxFilePath, pfxPassword);
                            // X509KeyStorageFlags.Exportable | X509KeyStorageFlags.MachineKeySet);
                            // ECDSAは、MachineKeySetに入らない & ExportableはDigitalSignECDsaX509の既定値に指定。

                            // ヘッダ ... access_tokenと同じではない。

                            // JWSHeaderのセット
                            Dictionary<string, string> jwk =
                                JsonConvert.DeserializeObject<Dictionary<string, string>>(cerJwkString);

                            jwsES256.JWSHeader.kid = jwk[JwtConst.kid];
                            jwsES256.JWSHeader.jku = Config.OAuth2AuthorizationServerEndpointsRootURI + OAuth2AndOIDCParams.JwkSetUri;

                            // Create
                            // Nested JWT : JWSをJWEで暗号化する。
                            return jweRsaOaep.Create(jwsES256.Create(newPayload));
#endif
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
    }
}
