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
//*  2026/09/07  玄人 幸道         JWTの数値・真偽値クレームの型を修正（#184）
//*  2026/09/07  玄人 幸道         nonceをstateから捏造しないよう修正（#191）
//*  2026/09/07  玄人 幸道         不正な入力での未処理例外を修正（#185）
//*  2026/09/22  玄人 幸道         ProtectFromPayload の引数名を permittedLevel から clientMode に（#224）
//*  2026/09/23  玄人 幸道         cnf を RFC 8705 の形式で書き、提示された証明書と照合する口を追加
//*  2026/09/25  玄人 幸道         profile / address のクレームを、設定の対応付けから返す（#230）
//*  2026/09/27  玄人 幸道         署名検証の鍵選択を切り出し、署名だけを検証する口を追加（#232）
//*  2026/10/02  玄人 幸道         受ける alg を自分が発行する 2 つに固定（C-8）（#129 の段階 1）
//*  2026/10/02  玄人 幸道         RS384 / RS512 を発行・検証できるようにした（#129 の段階 2）
//*  2026/10/02  玄人 幸道         署名する鍵の選択を SelectJwsForSigning に切り出した（#129 の段階 2）
//*  2026/10/02  玄人 幸道         alg と鍵の対応を SigningKeys の表に寄せた（#129 の段階 3 / D-9）
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

        #region SelectJwsForSigning

        /// <summary>署名に使う JWS を選ぶ（kid / jku まで入れて返す）</summary>
        /// <param name="alg">alg（SupportedAlgs のいずれか）</param>
        /// <returns>JWS</returns>
        /// <remarks>
        /// **鍵は `SigningKeys` の表が持つ**（#129 の段階 3 / D-9）。
        /// **`RS256` / `RS384` / `RS512` は同じ RSA の鍵**で、**ダイジェストだけが違う。**
        /// **`ES256` / `ES384` / `ES512` は曲線が alg に紐づく**ので、**鍵が 3 本に分かれる。**
        ///
        /// **`kid` は鍵から作る**（RFC 7638）。
        /// RSA は kty / n / e から作るので **`RS256` / `RS384` / `RS512` で同じ値**になり、
        /// EC は crv / kty / x / y から作るので **曲線ごとに違う値**になる。
        /// ＝ **RP は `jwkcerts` に載っている鍵で、そのまま検証できる**
        /// （どのダイジェストかは、ヘッダの alg が伝える）。
        ///
        /// **既知でない alg では null を返す。** 入口（`CmnEndpoints.CheckClientMode`）で
        /// 弾いてあるので、ここへは来ない。
        /// </remarks>
        private static JWS SelectJwsForSigning(string alg)
        {
            SigningKeys.Entry key = SigningKeys.Of(alg);

            if (key == null)
            {
                return null;
            }

            JWS jws = key.CreateJwsFromPfx();

            // JWSHeaderのセット
            // kid : https://openid-foundation-japan.github.io/rfc7638.ja.html#Example
            JObject jwk = key.JwkFromPfx();
            string kid = (string)jwk[JwtConst.kid];
            string jku = Config.OAuth2AuthorizationServerEndpointsRootURI + OAuth2AndOIDCParams.JwkSetUri;

            if (key.IsRsa)
            {
                ((JWS_RSA)jws).JWSHeader.kid = kid;
                ((JWS_RSA)jws).JWSHeader.jku = jku;
            }
            else
            {
                ((JWS_ECDSA)jws).JWSHeader.kid = kid;
                ((JWS_ECDSA)jws).JWSHeader.jku = jku;
            }

            return jws;
        }

        #endregion

        #region Claims経由

        /// <summary>CreateFromClaims</summary>
        /// <param name="clientId">string</param>
        /// <param name="userName">string</param>
        /// <param name="claims">IEnumerable(Claim)</param>
        /// <param name="ExpiresUtc">DateTimeOffset</param>
        /// <param name="alg">署名アルゴリズム（既定は RS256。#129 の段階 2）</param>
        /// <returns>JWT文字列</returns>
        public static string CreateFromClaims(
            string clientId, string userName,
            IEnumerable<Claim> identityClaims, DateTimeOffset expiresUtc,
            string alg = JwtConst.RS256)
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
            // exp/nbf/iat は NumericDate（RFC 7519 2章）＝JSONの数値。文字列にしない。
            tokenClaimSet.Add(OAuth2AndOIDCConst.exp, expiresUtc.ToUnixTimeSeconds());
            tokenClaimSet.Add(OAuth2AndOIDCConst.nbf, DateTimeOffset.Now.ToUnixTimeSeconds());
            tokenClaimSet.Add(OAuth2AndOIDCConst.iat, DateTimeOffset.Now.ToUnixTimeSeconds());

            // scope値によって、返す値を変更する。
            foreach (string scope in scopes)
            {
                if (user != null)
                {
                    switch (scope.ToLower())
                    {
                        #region OpenID Connect

                        case OAuth2AndOIDCConst.Scope_Profile:
                            // **返す項目は設定で決まる**（#230。UserClaims）。
                            UserClaims.AddClaims(tokenClaimSet, user, OAuth2AndOIDCConst.Scope_Profile);
                            break;
                        case OAuth2AndOIDCConst.Scope_Email:
                            tokenClaimSet.Add(OAuth2AndOIDCConst.Scope_Email, user.Email);
                            tokenClaimSet.Add(OAuth2AndOIDCConst.email_verified, user.EmailConfirmed);
                            break;
                        case OAuth2AndOIDCConst.Scope_Phone:
                            tokenClaimSet.Add(OAuth2AndOIDCConst.phone_number, user.PhoneNumber);
                            tokenClaimSet.Add(OAuth2AndOIDCConst.phone_number_verified, user.PhoneNumberConfirmed);
                            break;
                        case OAuth2AndOIDCConst.Scope_Address:
                            // **返す項目は設定で決まる**（#230。UserClaims）。
                            UserClaims.AddClaims(tokenClaimSet, user, OAuth2AndOIDCConst.Scope_Address);
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

            // **登録された alg で署名する**（#129 の段階 2）。鍵の選択は SelectJwsForSigning が持つ。
            JWS jws = CmnAccessToken.SelectJwsForSigning(alg);

            // ここでストアに登録
            IssuedTokenProvider.Create(jti, json, clientId, audience);

            // 署名
            return jws.Create(json);

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
            if (identity == null)// || issuedUtc == null)
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
        /// <param name="clientMode">クライアントに登録された ClientMode（クレームに書く。#220 / #224）</param>
        /// <param name="audience">out string</param>
        /// <param name="subject">out string</param>
        /// <param name="alg">string</param>
        /// <returns>AccessToken</returns>
        public static string ProtectFromPayload(
            string clientId, string access_token_payload,
            DateTimeOffset expiresUtc, X509Certificate2 x509,
            OAuth2AndOIDCEnum.ClientMode clientMode,
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
            // exp/nbf/iat は NumericDate（RFC 7519 2章）＝JSONの数値。文字列にしない。
            payload[OAuth2AndOIDCConst.exp] = expiresUtc.ToUnixTimeSeconds();
            payload[OAuth2AndOIDCConst.nbf] = DateTimeOffset.Now.ToUnixTimeSeconds();
            payload[OAuth2AndOIDCConst.iat] = DateTimeOffset.Now.ToUnixTimeSeconds();
            
            // 書込２
            // - cnf
            if (x509 != null)
            {
                // **RFC 8705 3.1 : cnf の x5t#S256 は、証明書（DER）の SHA-256 を BASE64URL したもの。**
                //   以前は SHA-1 のサムプリント（16 進）を入れ、キーの #S256 / #S512 も
                //   **証明書の署名アルゴリズム**で選んでいた。どちらも仕様と違い、
                //   RFC のとおりに照合するリソース サーバとは紐づけが一致しない。
                JObject dic = new JObject();
                dic.Add(OAuth2AndOIDCConst.x5t + CmnAccessToken.S256,
                    CmnAccessToken.ComputeCertificateThumbprint(x509));

                payload[OAuth2AndOIDCConst.cnf] = dic;
            }

            if (clientMode == OAuth2AndOIDCEnum.ClientMode.normal)
            {
                // ...
            }
            else if (clientMode == OAuth2AndOIDCEnum.ClientMode.device)
            {
                // - device
                payload["device"] = clientMode.ToStringByEmit();
            }
            else // fapi1, fapi2, fapi_ciba
            {
                // - fapi
                payload[OAuth2AndOIDCConst.fapi] = clientMode.ToStringByEmit();
            }

            json = JsonConvert.SerializeObject(payload);

            #endregion

            #region JWS化

            // **登録された alg で署名する**（#129 の段階 2）。鍵の選択は SelectJwsForSigning が持つ。
            JWS jws = CmnAccessToken.SelectJwsForSigning(alg);

            // ここでストアに登録
            if (!string.IsNullOrEmpty(clientId))
                // ... clientIdがnullのケースは、
                // IntrospectTokenから処理共通化のために利用されるケース。
                IssuedTokenProvider.Create(jti, json, clientId, audience);

            // 署名
            return jws.Create(json);

            #endregion
        }

        #endregion

        #endregion

        #region Verify

        /// <summary>JWT の署名を検証する鍵（JWS）を選ぶ（#232 で切り出し）</summary>
        /// <param name="jwt">JWS（コンパクト形式）</param>
        /// <returns>JWS（決まらなければ null ＝ 検証失敗）</returns>
        /// <remarks>
        /// **ここで検証するのは「この認可サーバが発行したトークン」だけ**である
        /// （access_token / id_token / id_token_hint）。相手の OP が発行したものは通らない。
        ///
        /// **受ける alg を、自分が発行するものに固定する**（C-8。#129 の段階 1）。
        ///
        /// | ヘッダの alg | |
        /// |---|---|
        /// | `SigningKeys.SupportedAlgs` のいずれか | **受ける**（この認可サーバが発行しうる） |
        /// | それ以外（`none` / `HS256` / `PS256` など） | **即、検証失敗**（null を返す） |
        ///
        /// **以前は、知らない alg を RS256 として扱っていた。**
        /// 署名は自分の公開鍵で確かめるので偽造はできなかったが、
        /// **サーバが期待する alg を決めていなかった**（アルゴリズム混同の温床）。
        /// **alg の選択肢を増やす前に、受ける範囲を決めておく**（#129 の段階 2 以降）。
        ///
        /// **鍵は、alg に対応するものを選ぶ。**
        ///
        /// | ヘッダ | 使う鍵 |
        /// |---|---|
        /// | `kid` が空 | **自分の証明書**（alg に対応する方。RSA / ECDSA） |
        /// | `kid` が在る | **JWK Set の、その kid**。**JWK の alg がヘッダと一致すること** |
        /// | `kid` が JWK Set に無い | **自分の証明書**（alg に対応する方）に落とす |
        ///
        /// **kid を引けないときに証明書へ落とすのは、従来どおり**である
        /// （`JwkSet.json` を置いていない配備でも、自分の鍵で検証できる）。
        /// **以前は、そこで必ず RSA を選んでいた**ので、
        /// **ES256 で発行したトークンが検証できなかった。**
        /// </remarks>
        private static JWS SelectJws(string jwt)
        {
            JWS jws = null;

            // 証明書を使用するか、Jwkを使用するか判定
            // ヘッダの解析は、JWTでない文字列を渡されても例外にしない（#185）。
            Dictionary<string, string> header = null;
            try
            {
                string[] segments = jwt.Split('.');
                if (segments.Length == 3)
                {
                    header = JsonConvert.DeserializeObject<Dictionary<string, string>>(
                        CustomEncode.ByteToString(CustomEncode.FromBase64UrlString(segments[0]), CustomEncode.UTF_8));
                }
            }
            catch
            {
                // Base64Url、JSONとして壊れている ＝ 検証失敗として扱う。
                header = null;
            }

            if (header != null
                && header.ContainsKey(JwtConst.kid)
                && header.ContainsKey(JwtConst.alg))
            {
                string alg = header[JwtConst.alg];

                // **自分が発行する alg だけを受ける**（C-8。#129 の段階 1）。
                //   **一覧は 1 か所で持つ**（#129 の段階 2 で RS384 / RS512 を足した）。
                //   **それ以外の alg のトークンは、自分が発行したものではない。**
                if (!CmnAccessToken.IsSupportedAlg(alg))
                {
                    return null;
                }

                if (string.IsNullOrEmpty(header[JwtConst.kid]))
                {
                    // 証明書を使用（alg に対応する鍵）
                    jws = CmnAccessToken.SelectJwsFromCertificate(alg);
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
                        // kid を引けなかった（JwkSet.json が無い、または載っていない kid）。
                        //   **証明書に落とす**（従来どおり）。**ただし alg に対応する鍵を選ぶ。**
                        jws = CmnAccessToken.SelectJwsFromCertificate(alg);
                    }
                    else if (!CmnAccessToken.IsSameKeyType(jwkObject, alg))
                    {
                        // **JWK の鍵の種類と、ヘッダの alg が食い違っている。**
                        //   どちらを信じるかという話にしないため、受けない。
                        return null;
                    }
                    else
                    {
                        // Jwkを使用（鍵の作り方は SigningKeys の表が持つ）
                        jws = SigningKeys.Of(alg).CreateJwsFromJwk(jwkObject);
                    }
                }
            }

            return jws;
        }

        /// <summary>自分の証明書から、alg に対応する JWS を作る（C-8。#129 の段階 1）</summary>
        /// <param name="alg">ヘッダの alg（SupportedAlgs のいずれか）</param>
        /// <returns>JWS</returns>
        /// <remarks>
        /// **呼ぶ前に alg を確かめてあること**（`SelectJws` が `SupportedAlgs` に限っている）。
        /// **公開鍵（.cer）で検証する。** 署名に使う秘密鍵（.pfx）は、ここでは要らない。
        /// **鍵は `SigningKeys` の表が持つ**（#129 の段階 3 / D-9）。
        /// </remarks>
        private static JWS SelectJwsFromCertificate(string alg)
        {
            SigningKeys.Entry key = SigningKeys.Of(alg);

            return (key == null) ? null : key.CreateJwsFromCer();
        }

        /// <summary>この認可サーバが署名に使う alg（#129 の段階 1〜3）</summary>
        /// <remarks>
        /// **一覧は `SigningKeys` の表が持つ**（#129 の段階 3 / D-9）。
        /// **発行（`SelectJwsForSigning`）・検証（`SelectJws`）・広告（Discovery の
        /// `*_signing_alg_values_supported`）・`jwkcerts` の生成が、同じ表を見る。**
        ///
        /// **増やすときは表に 1 行足す。** ただし **E2E の `RT-129.2`（受けない alg の一覧）も直すこと**
        /// （黙って広がらないようにするため）。
        /// **`PS256` は #129 の段階 4**（上流に `JWS_PS*` が無い。OpenTouryoProject/OpenTouryo#596）。
        /// </remarks>
        public static string[] SupportedAlgs
        {
            get { return SigningKeys.SupportedAlgs; }
        }

        /// <summary>この認可サーバが署名に使う alg かどうか</summary>
        /// <param name="alg">alg</param>
        /// <returns>使うなら true</returns>
        public static bool IsSupportedAlg(string alg)
        {
            return SigningKeys.IsSupported(alg);
        }

        /// <summary>JWK の鍵が、alg に合っているか（#129 の段階 2・3）</summary>
        /// <param name="jwkObject">JWK</param>
        /// <param name="alg">ヘッダの alg</param>
        /// <returns>合っていれば true</returns>
        /// <remarks>
        /// **以前は JWK の `alg` と完全一致を求めていた**（C-8）。
        /// **同じ鍵で RS256 / RS384 / RS512 を使えるようにした**ので、
        /// **一致ではなく「鍵が合っているか」で見る**（RFC 7517 の `alg` は「用途」で、任意）。
        ///
        /// | alg | 要る kty | 要る crv |
        /// |---|---|---|
        /// | `RS256` / `RS384` / `RS512` | `RSA` | （無し。**1 本の鍵で 3 つ**） |
        /// | `ES256` | `EC` | `P-256` |
        /// | `ES384` | `EC` | `P-384` |
        /// | `ES512` | `EC` | `P-521` |
        ///
        /// **`crv` まで見るのは、EC が alg と曲線で対応するから**である（JWA）。
        /// **`kty` だけでは、P-256 の鍵で `ES512` のトークンを受けてしまう**（#129 の段階 3）。
        /// </remarks>
        private static bool IsSameKeyType(JObject jwkObject, string alg)
        {
            SigningKeys.Entry key = SigningKeys.Of(alg);

            if (key == null)
            {
                return false;
            }

            if ((string)jwkObject[JwtConst.kty] != key.Kty)
            {
                return false;
            }

            // RSA は曲線を持たない（1 本の鍵で RS256 / RS384 / RS512）。
            return key.Crv == null
                || (string)jwkObject[JwtConst.crv] == key.Crv;
        }

        /// <summary>JWT の署名だけを検証する（#232）</summary>
        /// <param name="jwt">JWS（コンパクト形式）</param>
        /// <returns>この認可サーバの鍵で署名されていれば true</returns>
        /// <remarks>
        /// **id_token_hint の検証に使う**（RP-Initiated Logout 1.0 §2）。
        /// そちらは **exp が切れていても受ける**（SHOULD）ため、
        /// 期限・失効まで見る VerifyAccessToken は使えない。
        /// **iss や aud の確認は、呼び出し側が行う。**
        /// </remarks>
        public static bool VerifySignature(string jwt)
        {
            if (string.IsNullOrEmpty(jwt))
            {
                return false;
            }

            JWS jws = CmnAccessToken.SelectJws(jwt);

            return jws != null && jws.Verify(jwt);
        }

        /// <summary>Verify</summary>
        /// <param name="jwt">string</param>
        /// <param name="identity">ClaimsIdentity</param>
        /// <returns>検証結果</returns>
        public static bool VerifyAccessToken(string jwt, out ClaimsIdentity identity)
        {
            JObject claims = null;
            return CmnAccessToken.VerifyAccessToken(jwt, out claims, out identity);
        }
        
        /// <summary>証明書（DER）の SHA-256 を BASE64URL した値（RFC 8705 3.1 の x5t#S256）</summary>
        /// <param name="x509">クライアント証明書</param>
        /// <returns>BASE64URL の文字列</returns>
        private static string ComputeCertificateThumbprint(X509Certificate2 x509)
        {
            using (SHA256 sha256 = SHA256.Create())
            {
                return CustomEncode.ToBase64UrlString(sha256.ComputeHash(x509.RawData));
            }
        }

        /// <summary>
        /// トークンの cnf（証明書への紐づけ）と、提示されたクライアント証明書を照合する（RFC 8705 3）
        /// </summary>
        /// <param name="identity">VerifyAccessToken が返した ClaimsIdentity</param>
        /// <param name="x509">TLS で提示されたクライアント証明書（無ければ null）</param>
        /// <returns>使ってよければ true</returns>
        /// <remarks>
        /// **証明書に紐づけたトークン（sender-constrained）は、その証明書を提示した要求でしか使えない。**
        /// RFC 8705 3 は、保護されたリソースに照合を求めている。
        /// 紐づいていないトークン（cnf 無し）は、これまでどおり bearer として扱う。
        ///
        /// **紐づいているのに証明書が無い要求は拒否する。** 以前は照合しておらず、
        /// 漏えいしたトークンを証明書なしで使えた。
        /// </remarks>
        public static bool VerifyCertificateBinding(ClaimsIdentity identity, X509Certificate2 x509)
        {
            if (identity == null)
            {
                return false;
            }

            Claim cnf = identity.Claims.FirstOrDefault(
                x => x.Type.StartsWith(OAuth2AndOIDCConst.UrnCnfX5tClaim));

            if (cnf == null)
            {
                // 紐づいていないトークン
                return true;
            }

            if (x509 == null)
            {
                // 紐づいているのに、証明書が提示されていない
                return false;
            }

            string expected = "";

            if (cnf.Type == OAuth2AndOIDCConst.UrnCnfX5tClaim + CmnAccessToken.S256)
            {
                expected = CmnAccessToken.ComputeCertificateThumbprint(x509);
            }
            else
            {
                // 未知の方式（#S512 など）は、照合できないので通さない
                return false;
            }

            return string.Equals(cnf.Value, expected, StringComparison.Ordinal);
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
                // 検証（鍵の選択は SelectJws に切り出した。#232）
                JWS jws = CmnAccessToken.SelectJws(jwt);

                // jwsが決まらなかった場合（kid無し、ヘッダ破損など）は検証失敗（#185）。
                if (jws != null && jws.Verify(jwt))
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
                            // CmnJwtToken.VerifyExpはstring引数のみ。expは数値になったのでToStringで渡す
                            // （文字列で発行された過去のTokenも、そのまま通る）。
                            && CmnJwtToken.VerifyExp(tokenClaimSet[OAuth2AndOIDCConst.exp].ToString()))
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
            // exp/nbf/iatは数値。Claimの値はstringなのでToStringで変換する。
            identity.AddClaim(new Claim(OAuth2AndOIDCConst.UrnExpirationTimeClaim, tokenClaimSet[OAuth2AndOIDCConst.exp].ToString()));
            identity.AddClaim(new Claim(OAuth2AndOIDCConst.UrnNotBeforeClaim, tokenClaimSet[OAuth2AndOIDCConst.nbf].ToString()));
            identity.AddClaim(new Claim(OAuth2AndOIDCConst.UrnIssuedAtClaim, tokenClaimSet[OAuth2AndOIDCConst.iat].ToString()));
            identity.AddClaim(new Claim(OAuth2AndOIDCConst.UrnJwtIdClaim, (string)tokenClaimSet[OAuth2AndOIDCConst.jti]));

            // 基本Claimを追加
            // scopes
            List<string> scopes = new List<string>();
            foreach (string s in (JArray)tokenClaimSet[OAuth2AndOIDCConst.scopes])
            {
                scopes.Add(s);
            }
            // nonceは、認可リクエストで指定されなかった場合、Tokenに含まれない（#191）。
            tokenClaimSet.TryGetValue(OAuth2AndOIDCConst.nonce, out object nonce);

            Helper.AddClaim(identity,
                (string)tokenClaimSet[OAuth2AndOIDCConst.aud], scopes, null, (string)nonce);

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
