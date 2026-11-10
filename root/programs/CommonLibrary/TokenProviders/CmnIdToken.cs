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
//*  2026/09/07  玄人 幸道         nonce無しでもid_tokenを発行するよう修正（#183）
//*  2026/09/07  玄人 幸道         JWTの数値・真偽値クレームの型を修正（#184）
//*  2026/10/02  玄人 幸道         RS384 / RS512 でも署名できるようにした（#129 の段階 2）
//*  2026/10/15  玄人 幸道         ヘッダにjkuを入れないようにした（#302）
//*  2026/10/21  玄人 幸道         sid クレームを残すようにした（#310 の段階 1）
//*  2026/11/10  玄人 幸道         FAPI2（JWE）の中の JWS の kid を、署名した鍵の kid にした（#352）
//*  2026/11/10  玄人 幸道         FAPI2（JWE）の中の JWS を、登録の id_token_signed_response_alg で署名するようにした（#355）
//**********************************************************************************

using MultiPurposeAuthSite.Co;
using MultiPurposeAuthSite.Data;
using MultiPurposeAuthSite.Util.Sts;

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
        /// <param name="cerJwkString">string（**クライアントの暗号化の鍵**。空でなければ JWE（FAPI2）にする）</param>
        /// <param name="alg">署名アルゴリズム（既定は RS256。#129 の段階 2。**JWE のときは `SigningAlgForEncrypted` の値を渡す**。#355）</param>
        /// <returns>id_token</returns>
        /// <remarks>
        /// **署名の鍵は、どちらの形でも `SigningKeys` の表から引く**（#129 の段階 3・#352）。
        /// **以前は pfx のパスとパスワードを引数で受けていた**が、JWS では使わず、
        /// JWE では受けた鍵と別の鍵の `kid` をヘッダに入れていた（#352）。引数を消して、鍵と `kid` の出どころを 1 つにした。
        /// </remarks>
        public static string ChangeToIdTokenFromAccessToken(
            string access_token, string code, string state, HashClaimType hct,
            string cerJwkString, string alg = JwtConst.RS256)
        {
            if (access_token.Contains("."))
            {
                string[] temp = access_token.Split('.');
                string json = CustomEncode.ByteToString(CustomEncode.FromBase64UrlString(temp[1]), CustomEncode.UTF_8);
                JObject tokenClaimSet = (JObject)JsonConvert.DeserializeObject(json);

                // ・access_tokenがJWTで、payloadに"scope=openid"クレームが存在する場合、
                //   nonceは、Authorization Codeフローでは任意（OIDC Core 3.1.2.1）なので条件にしない。
                if (tokenClaimSet.ContainsKey(OAuth2AndOIDCConst.scopes))
                {
                    JArray scopes = (JArray)tokenClaimSet[OAuth2AndOIDCConst.scopes];

                    // ・OpenID Connect : response_type=codeに対応する。
                    if (scopes.Any(x => x.ToString() == OAuth2AndOIDCConst.Scope_Openid))
                    {
                        // claimsクレームを退避
                        JObject claims = (JObject)tokenClaimSet[OAuth2AndOIDCConst.claims];

                        // IdTokenから不要なクレームを削除する。
                        //   **sid は残す**（#310 の段階 1。OIDC Core §2）。
                        //   **access_token 経由で運ばれてくる**ので、ここで落とすと id_token に出ない。
                        List<string> keys = new List<string>();
                        foreach (KeyValuePair<string, JToken> item in tokenClaimSet)
                        {
                            if ("iss sub aud client_id exp iat nonce auth_time sid".IndexOf(item.Key) == -1)
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
                            Config.OidcIdTokenExpireTimeSpanFromMinutes.TotalMinutes).ToUnixTimeSeconds();

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

                            // JWS（**鍵は SigningKeys の表が持つ**。#129 の段階 3 / D-9）
                            SigningKeys.Entry key = SigningKeys.Of(alg);

                            if (key == null)
                            {
                                // 扱わない alg（入口の CheckClientMode で弾いてある）。
                                return "";
                            }

                            JWS jws = key.CreateJwsFromPfx();

                            // **kid は access_token から写す**（鍵が同じなので同じ値になる）。
                            //   **`jku` は写さない**（#302。もう付けていない。RFC 9068 / D-10）。
                            if (!string.IsNullOrEmpty(jwsHeader.kid))
                            {
                                CmnIdToken.SetKid(jws, key, jwsHeader.kid);
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

                            // JWS（**alg は呼び出し元が決める**。`SigningAlgForEncrypted`。#355）
                            //   **登録の `id_token_signed_response_alg` が在れば、それで署名する**（OIDC Registration 1.0 §2）。
                            //   **以前は登録にかかわらず ES256 の固定**で、access_token（登録の alg）と食い違っていた（#355）。
                            //   **鍵と kid は、access_token と同じく SigningKeys の表から引く**（#352）。
                            //   **kid は、署名した鍵（jwks_uri に載る鍵）のもの**（OIDC Core 1.0 §10.1、RFC 7515 §4.1.4）。
                            //   以前は、暗号化に使うクライアントの鍵（cerJwkString）の kid を入れていたので、
                            //   **kid で jwks_uri から鍵を引く RP が、署名を確かめられなかった**（#352）。
                            SigningKeys.Entry key = SigningKeys.Of(alg);

                            if (key == null)
                            {
                                // 扱わない alg（入口の CheckClientMode で弾いてある）。
                                return "";
                            }

                            JWS jws = key.CreateJwsFromPfx();

                            //  **`jku` は入れない**（#302）。**鍵は `kid` で引く。**
                            CmnIdToken.SetKid(jws, key, (string)key.JwkFromPfx()[JwtConst.kid]);

                            // Create
                            // Nested JWT : JWSをJWEで暗号化する。
                            return jweRsaOaep.Create(jws.Create(newPayload));
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

        /// <summary>暗号化した id_token（fapi2 の Nested JWT）の中の JWS の alg を決める（#355）</summary>
        /// <param name="client_id">client_id</param>
        /// <returns>alg</returns>
        /// <remarks>
        /// | 登録の `id_token_signed_response_alg` | 中の JWS の alg |
        /// |---|---|
        /// | 在る | **登録の値**（access_token と同じ。OIDC Registration 1.0 §2） |
        /// | 無い | **`ES256`**（従来どおり） |
        ///
        /// **登録が無いときに、暗号化しない側の既定（`RS256`）に倒さない。**
        /// **FAPI 2.0 Security Profile §5.4.1 は PS256・ES256・EdDSA を求め、RS256 は入らない。**
        /// **そのため、登録の無い fapi2 のクライアントでは、access_token（RS256）と食い違ったまま**である（`CONFIGURATION.md`）。
        /// </remarks>
        public static string SigningAlgForEncrypted(string client_id)
        {
            return Helper.GetInstance().GetRegisteredIdTokenSignedResponseAlg(client_id) ?? JwtConst.ES256;
        }

        /// <summary>JWS のヘッダに kid を入れる</summary>
        /// <param name="jws">JWS（`SigningKeys.Entry.CreateJwsFromPfx` で作ったもの）</param>
        /// <param name="key">SigningKeys.Entry</param>
        /// <param name="kid">kid</param>
        private static void SetKid(JWS jws, SigningKeys.Entry key, string kid)
        {
            if (key.IsRsa)
            {
                ((JWS_RSA)jws).JWSHeader.kid = kid;
            }
            else
            {
                ((JWS_ECDSA)jws).JWSHeader.kid = kid;
            }
        }
    }
}
