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
//* クラス日本語名  ：CmnAccessToken の 作る（Claims・認可コード・預けた payload から）
//*
//* 作成日時        ：－
//* 作成者          ：－
//* 更新履歴        ：－
//*
//*  日時        更新者            内容
//*  ----------  ----------------  -------------------------------------------------
//*  2026/10/31  玄人 幸道         新規（CmnAccessToken.cs から partial に分割。#294）
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
using System.Collections.Generic;
using System.Security.Claims;
using System.Security.Cryptography.X509Certificates;

using Newtonsoft.Json;
using Newtonsoft.Json.Linq;

using Touryo.Infrastructure.Framework.Authentication;
using Touryo.Infrastructure.Public.Security.Jwt;
using Touryo.Infrastructure.Public.FastReflection;

namespace MultiPurposeAuthSite.TokenProviders
{
    /// <summary>CmnAccessToken（作る（Claims・認可コード・預けた payload から））</summary>
    public partial class CmnAccessToken
    {
        #region Create

        #region Claims経由

        /// <summary>CreateFromClaims</summary>
        /// <param name="clientId">string</param>
        /// <param name="userName">string</param>
        /// <param name="claims">IEnumerable(Claim)</param>
        /// <param name="ExpiresUtc">DateTimeOffset</param>
        /// <param name="alg">署名アルゴリズム（既定は RS256。#129 の段階 2）</param>
        /// <param name="jkt">DPoP の鍵の指紋（#311 の段階 1。無ければ空）</param>
        /// <returns>JWT文字列</returns>
        public static string CreateFromClaims(
            string clientId, string userName,
            IEnumerable<Claim> identityClaims, DateTimeOffset expiresUtc,
            string alg = JwtConst.RS256, string jkt = null)
        {
            string jti = Guid.NewGuid().ToString("N");
            string json = "";
            string audience = "";

            #region ClaimSetの生成

            Dictionary<string, object> tokenClaimSet = new Dictionary<string, object>();
            List<string> scopes = new List<string>();
            string auth_time = null;
            string claims = null;
            string sid = null;

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
                else if (c.Type == Const.UrnSidClaim)
                {
                    //  **sid（OP のセッションの識別子。#310 の段階 1）**
                    sid = c.Value;
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

            // sid（#310 の段階 1）
            //   **id_token に出すためには、ここ（access_token）を通る必要が在る**
            //   （`CmnIdToken.ChangeToIdTokenFromAccessToken` が access_token の
            //   クレーム集合から id_token を作るため）。
            //   **クライアントごとに別の値**なので、**RP 同士の突き合わせには使えない。**
            if (!string.IsNullOrEmpty(sid))
                tokenClaimSet.Add(Const.Sid, sid);

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
                    }
                }
            }

            //  **DPoP の鍵に縛る**（#311 の段階 1）。
            //    **この経路は mTLS の `cnf` を書いていない**（証明書を受けていない経路である）。
            //    **DPoP は証明が在れば書ける**ので、ここで足す。
            if (!string.IsNullOrEmpty(jkt))
            {
                Dictionary<string, object> cnf = new Dictionary<string, object>();
                cnf.Add(OAuth2AndOIDCConst.jkt, jkt);

                tokenClaimSet.Add(OAuth2AndOIDCConst.cnf, cnf);
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
            string sid = null;

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
                else if (c.Type == Const.UrnSidClaim)
                {
                    //  **sid（OP のセッションの識別子。#310 の段階 1）**
                    sid = c.Value;
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

            // sid（#310 の段階 1）
            if (!string.IsNullOrEmpty(sid))
                tokenClaimSet.Add(Const.Sid, sid);

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
        /// <param name="jkt">DPoP の鍵の指紋（#311 の段階 1。無ければ空）</param>
        /// <returns>AccessToken</returns>
        public static string ProtectFromPayload(
            string clientId, string access_token_payload,
            DateTimeOffset expiresUtc, X509Certificate2 x509,
            OAuth2AndOIDCEnum.ClientMode clientMode,
            out string audience, out string subject, string alg = JwtConst.RS256,
            string jkt = null)
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
            CmnAccessToken.WriteCnf(payload, x509, jkt);

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

            // - sid（#310 の段階 1）
            //   **refresh_token で作り直すときに、同じ sid を引き継ぐ**ため。
            //   **ここで戻さないと、作り直した id_token から sid が消える**
            //   （**RP から見ると、同じセッションが別物に見える**）。
            if (tokenClaimSet.TryGetValue(Const.Sid, out object sid))
            {
                if (!string.IsNullOrEmpty((string)sid))
                {
                    identity.AddClaim(new Claim(Const.UrnSidClaim, (string)sid));
                }
            }

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

                //  **DPoP の縛り**（#311 の段階 2）。
                //    **mTLS と排他ではない**（両方書かれていることが在る）ので、
                //    **`else if` で繋がない。**
                if (cnf.ContainsKey(OAuth2AndOIDCConst.jkt))
                    identity.AddClaim(new Claim(Const.UrnCnfJktClaim, (string)cnf[OAuth2AndOIDCConst.jkt]));
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
