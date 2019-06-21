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
//**********************************************************************************

using MultiPurposeAuthSite.Co;

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
        /// <returns>id_token</returns>
        public static string ChangeToIdTokenFromAccessToken(
            string access_token, string code, string state, HashClaimType hct,
            string pfxFilePath, string pfxPassword, string cerJwkString)
        {
            if (access_token.Contains("."))
            {
                string[] temp = access_token.Split('.');
                string json = CustomEncode.ByteToString(CustomEncode.FromBase64UrlString(temp[1]), CustomEncode.UTF_8);
                JObject authTokenClaimSet = (JObject)JsonConvert.DeserializeObject(json);

                // ・access_tokenがJWTで、payloadに"nonce" and "scope=openidクレームが存在する場合、
                if (authTokenClaimSet.ContainsKey(OAuth2AndOIDCConst.nonce)
                    && authTokenClaimSet.ContainsKey(OAuth2AndOIDCConst.scopes))
                {
                    JArray scopes = (JArray)authTokenClaimSet[OAuth2AndOIDCConst.scopes];

                    // ・OpenID Connect : response_type=codeに対応する。
                    if (scopes.Any(x => x.ToString() == OAuth2AndOIDCConst.Scope_Openid))
                    {
                        // claimsクレームを退避
                        JObject claims = (JObject)authTokenClaimSet[OAuth2AndOIDCConst.claims];

                        // IdTokenから不要なクレームを削除する。
                        List<string> keys = new List<string>();
                        foreach (KeyValuePair<string, JToken> item in authTokenClaimSet)
                        {
                            if ("iss sub aud client_id exp iat nonce".IndexOf(item.Key) == -1)
                            {
                                keys.Add(item.Key);
                            }
                        }
                        foreach (string key in keys)
                        {
                            authTokenClaimSet.Remove(key);
                        }

                        //・expをIdToken用のexpに差し替える。
                        authTokenClaimSet[OAuth2AndOIDCConst.exp] = DateTimeOffset.Now.AddMinutes(
                            Config.OidcIdTokenExpireTimeSpanFromMinutes.TotalMinutes).ToUnixTimeSeconds().ToString();

                        if (claims != null)
                        {
                            // claims > id_tokenクレームの内容を格納
                            // - auth_timeクレーム
                            //   ...未サポート...
                            // - acrクレーム
                            //   ...未サポート...
                        }

                        //Co.Config.;

                        //・payloadにat_hash, c_hash, s_hashを追加する。

                        if (hct.HasFlag(HashClaimType.AtHash))
                        {
                            // at_hash
                            authTokenClaimSet.Add(
                                OAuth2AndOIDCConst.at_hash,
                                IdToken.CreateHash(access_token));
                        }

                        if (hct.HasFlag(HashClaimType.CHash))
                        {
                            // c_hash
                            authTokenClaimSet.Add(
                                OAuth2AndOIDCConst.c_hash,
                                IdToken.CreateHash(code));
                        }

                        if (hct.HasFlag(HashClaimType.SHash))
                        {
                            // s_hash
                            authTokenClaimSet.Add(
                                OAuth2AndOIDCConst.s_hash,
                                IdToken.CreateHash(state));
                        }

                        //・編集したpayloadを再度JWTとして署名する。
                        string newPayload = JsonConvert.SerializeObject(authTokenClaimSet);

                        // 署名
                        if (string.IsNullOrEmpty(cerJwkString))
                        {
                            // 通常

                            // JWS(RS256)
                            JWS_RS256_X509 jwsRS256 = new JWS_RS256_X509(pfxFilePath, pfxPassword);

                            // ヘッダ ... access_tokenと同じ
                            JWS_Header jwsHeader =
                                JsonConvert.DeserializeObject<JWS_Header>(
                                    CustomEncode.ByteToString(CustomEncode.FromBase64UrlString(temp[0]), CustomEncode.UTF_8));

                            if (!string.IsNullOrEmpty(jwsHeader.jku)
                                && !string.IsNullOrEmpty(jwsHeader.kid))
                            {
                                jwsRS256.JWSHeader.jku = jwsHeader.jku;
                                jwsRS256.JWSHeader.kid = jwsHeader.kid;
                            }

                            // Create
                            return jwsRS256.Create(newPayload);
                        }
                        else
                        {
                            // FAPI2
#if NET45 || NET46
                            throw new NotSupportedException("FAPI2 is not supported in this dotnet version.");
#else
                            // JWE(RsaOaepAesGcm)
                            JWE_RsaOaepAesGcm_Param jweRsaOaep = new JWE_RsaOaepAesGcm_Param(
                                EnumASymmetricAlgorithm.RsaCng, RsaPublicKeyConverter.JwkToParam(cerJwkString));

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
