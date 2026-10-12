//**********************************************************************************
//* Copyright (C) 2026 Hitachi Solutions,Ltd.
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
//* クラス名        ：DiscoveryJwks
//* クラス日本語名  ：discovery → jwks_uri → kid で、相手の署名鍵を引く（汎用）
//*
//* 作成日時        ：－
//* 作成者          ：－
//* 更新履歴        ：－
//*
//*  日時        更新者            内容
//*  ----------  ----------------  -------------------------------------------------
//*  2026/10/13  玄人 幸道         新規（#289 の段階 2。IdFederationJwks から汎用部分を分けた）
//**********************************************************************************

using MultiPurposeAuthSite.Log;

using System;
using System.Collections.Generic;
using System.Threading.Tasks;

using Newtonsoft.Json;
using Newtonsoft.Json.Linq;

using Touryo.Infrastructure.Framework.Authentication;
using Touryo.Infrastructure.Public.Security.Jwt;
using Touryo.Infrastructure.Public.Str;

namespace MultiPurposeAuthSite.Extensions.Sts
{
    /// <summary>
    /// **discovery → `jwks_uri` → `kid`** で、相手（OP）の署名鍵を引く（#289 の段階 2）。
    /// </summary>
    /// <remarks>
    /// **ここは「相手が誰か」を知らない。** **呼び出し側が、口と期待する Issuer を渡す。**
    ///
    /// | | |
    /// |---|---|
    /// | **この型** | **protocol と HTTP とキャッシュ**（discovery を読み、`jwks_uri` を読み、`kid` で引く） |
    /// | **呼び出し側** | **設定の読み方**（どの URL か、どの Issuer を期待するか） |
    ///
    /// **ID 連携（OIDC）が使っている**（`IdFederationJwks`）。
    /// **他にも「相手の鍵を `kid` で引く」場面は在る**
    /// （`request_object` / `client_assertion` の検証、将来の複数 OP）ので、**分けてある。**
    ///
    /// **期待する Issuer を必ず受け取る。**
    /// **discovery の `issuer` がそれと一致しなければ、鍵を使わない**
    /// （**どこから引いた鍵かを、期待する Issuer に結び付けるため**。
    /// **この確認が無いと、設定の URL を差し替えられた配備で、別の発行者の鍵を信じてしまう**）。
    ///
    /// **引けなければ null を返す。** **例外にしない。**
    /// **呼び出し側が別の手段（設定の証明書など）に倒せるようにする**ためである。
    /// **落ちる方向には倒さない** — **トークンの検証そのものは、呼び出し側が必ず行う。**
    ///
    /// **取得は `OAuth2AndOIDCClient.GetJwkSetAsync`** で行う。
    /// **名前は JwkSet だが、中身は「URL を GET して本文を返す」だけ**であり、
    /// **ID 連携の `/token` や `/userinfo` と同じ `HttpClient`**（TLS・プロキシの扱いが揃う）。
    /// </remarks>
    public static class DiscoveryJwks
    {
        #region 定数

        /// <summary>discovery の口（OIDC Discovery 4.1 / RFC 8414 3）</summary>
        public const string WellKnown = "/.well-known/openid-configuration";

        /// <summary>
        /// 取り直しの下限（**これより短い間隔では取りに行かない**）。
        /// </summary>
        /// <remarks>
        /// **`kid` が引けないたびに取りに行くと、相手を叩き続けられる**
        /// （`kid` を偽ったトークンを投げれば、いくらでも起こせる）。
        /// **下限を置く**ことで、**取得は 1 分に 1 回まで**になる。
        /// </remarks>
        private static readonly TimeSpan MinRefetchInterval = TimeSpan.FromMinutes(1);

        #endregion

        #region キャッシュ

        /// <summary>取得した JWK Set（鍵は discovery の URL）</summary>
        private static readonly Dictionary<string, Entry> _cache = new Dictionary<string, Entry>();

        /// <summary>_cache の排他</summary>
        private static readonly object _lock = new object();

        /// <summary>キャッシュの 1 件</summary>
        private class Entry
        {
            /// <summary>JWK Set（`keys` の配列を持つ JSON）</summary>
            public JObject JwkSet { get; set; }

            /// <summary>取得した時刻（UTC）</summary>
            public DateTime FetchedAt { get; set; }
        }

        #endregion

        #region public

        /// <summary>
        /// `kid` に対応する RSA の署名鍵を、discovery から引く。
        /// </summary>
        /// <param name="discoveryUrl">相手の discovery の URL</param>
        /// <param name="expectedIssuer">
        /// **期待する Issuer。** **discovery の `issuer` がこれと一致しなければ、鍵を使わない。**
        /// </param>
        /// <param name="kid">トークンのヘッダの `kid`</param>
        /// <returns>検証鍵（引けなければ null）</returns>
        /// <remarks>
        /// **RSA（`RS256`）だけを返す。**
        /// **EC（`ES*`）は FAPI2（JWE）の経路で使う**ので、ここでは扱わない。
        /// </remarks>
        public static async Task<JWS> GetRsaKeyAsync(
            string discoveryUrl, string expectedIssuer, string kid)
        {
            if (string.IsNullOrEmpty(discoveryUrl)
                || string.IsNullOrEmpty(expectedIssuer)
                || string.IsNullOrEmpty(kid))
            {
                return null;
            }

            //  **まずキャッシュから引く。**
            JObject jwk = DiscoveryJwks.PickFromCache(discoveryUrl, kid, out bool canRefetch);

            if (jwk == null && canRefetch)
            {
                //  **引けなければ取り直す**（鍵のロールオーバー）。
                await DiscoveryJwks.FetchAsync(discoveryUrl, expectedIssuer);
                jwk = DiscoveryJwks.PickFromCache(discoveryUrl, kid, out bool dummy);
            }

            if (jwk == null)
            {
                return null;
            }

            try
            {
                RsaPublicKeyConverter rpkc = new RsaPublicKeyConverter();
                return new JWS_RS256_Param(rpkc.JwkToParam(jwk));
            }
            catch (Exception ex)
            {
                Logging.MyOperationTrace(string.Format(
                    "The JWK of the kid could not be read. ({0})", ex.GetType().Name));

                return null;
            }
        }

        /// <summary>
        /// JWT のヘッダから `kid` を読む。
        /// </summary>
        /// <param name="jwt">JWT（JWS）</param>
        /// <returns>kid（読めなければ空）</returns>
        /// <remarks>
        /// **署名を検証する前に読む値**である。
        /// **鍵を選ぶためだけに使い、他の判断には使わない。**
        /// </remarks>
        public static string KidOf(string jwt)
        {
            if (string.IsNullOrEmpty(jwt))
            {
                return "";
            }

            try
            {
                string[] parts = jwt.Split('.');

                if (parts.Length < 2)
                {
                    return "";
                }

                JWS_Header header = JsonConvert.DeserializeObject<JWS_Header>(
                    CustomEncode.ByteToString(
                        CustomEncode.FromBase64UrlString(parts[0]), CustomEncode.UTF_8));

                return (header == null) ? "" : (header.kid ?? "");
            }
            catch (Exception)
            {
                // **読めない JWT は、ここでは扱わない**（検証は呼び出し側が行う）。
                return "";
            }
        }

        /// <summary>
        /// URL の基底から、discovery の URL を組み立てる。
        /// </summary>
        /// <param name="anyEndpointUrl">
        /// 相手の口の URL（`authorize` / `token` など。**基底だけを使う**）
        /// </param>
        /// <returns>discovery の URL（組み立てられなければ空）</returns>
        /// <remarks>
        /// **`iss` から組み立てる形は、ここでは採らない。**
        /// **`iss` が URL でない配備がある**ためである（呼び出し側の `remarks`）。
        /// </remarks>
        public static string DiscoveryUrlOf(string anyEndpointUrl)
        {
            if (string.IsNullOrEmpty(anyEndpointUrl))
            {
                return "";
            }

            try
            {
                Uri uri = new Uri(anyEndpointUrl);

                return uri.GetLeftPart(UriPartial.Authority) + DiscoveryJwks.WellKnown;
            }
            catch (UriFormatException)
            {
                return "";
            }
        }

        #endregion

        #region private

        /// <summary>キャッシュから `kid` の JWK を引く</summary>
        /// <param name="discoveryUrl">discovery の URL</param>
        /// <param name="kid">kid</param>
        /// <param name="canRefetch">取り直してよいか（下限を過ぎているか）</param>
        /// <returns>JWK（無ければ null）</returns>
        private static JObject PickFromCache(string discoveryUrl, string kid, out bool canRefetch)
        {
            canRefetch = true;

            lock (DiscoveryJwks._lock)
            {
                Entry entry = null;

                if (!DiscoveryJwks._cache.TryGetValue(discoveryUrl, out entry))
                {
                    return null;
                }

                canRefetch = (DateTime.UtcNow - entry.FetchedAt) > DiscoveryJwks.MinRefetchInterval;

                return DiscoveryJwks.PickRsaKey(entry.JwkSet, kid);
            }
        }

        /// <summary>JWK Set から `kid` の RSA 鍵を探す</summary>
        /// <param name="jwkSet">JWK Set</param>
        /// <param name="kid">kid</param>
        /// <returns>JWK（無ければ null）</returns>
        private static JObject PickRsaKey(JObject jwkSet, string kid)
        {
            if (jwkSet == null)
            {
                return null;
            }

            JToken keys = jwkSet[JwtConst.keys];

            if (!(keys is JArray))
            {
                return null;
            }

            foreach (JToken key in (JArray)keys)
            {
                JObject jwk = key as JObject;

                if (jwk == null)
                {
                    continue;
                }

                if ((string)jwk[JwtConst.kid] == kid
                    && (string)jwk[JwtConst.kty] == JwtConst.RSA)
                {
                    return jwk;
                }
            }

            return null;
        }

        /// <summary>discovery を読み、`jwks_uri` から JWK Set を取ってキャッシュする</summary>
        /// <param name="discoveryUrl">discovery の URL</param>
        /// <param name="expectedIssuer">期待する Issuer</param>
        /// <returns>Task</returns>
        /// <remarks>
        /// **失敗しても例外にしない。** **呼び出し側が別の手段に倒せるようにする。**
        /// **理由はログに残す**（#253 と同じ方針。**鍵そのものは出さない**）。
        /// </remarks>
        private static async Task FetchAsync(string discoveryUrl, string expectedIssuer)
        {
            string jwksUri = "";

            try
            {
                string discovery = await OAuth2AndOIDCClient.GetJwkSetAsync(new Uri(discoveryUrl));

                if (string.IsNullOrEmpty(discovery))
                {
                    Logging.MyOperationTrace(
                        "The discovery document could not be read. (empty response)");

                    return;
                }

                JObject jobj = (JObject)JsonConvert.DeserializeObject(discovery);

                //  **名前は直に書く**（`TokenProviders/CmnEndpoints` の組み立て側も同じ）。
                string issuer = (string)jobj["issuer"];

                if (issuer != expectedIssuer)
                {
                    //  **期待する Issuer と違う。** **その鍵は使わない。**
                    Logging.MyOperationTrace(
                        "The discovery issuer did not match the expected issuer.");

                    return;
                }

                jwksUri = (string)jobj["jwks_uri"];

                if (string.IsNullOrEmpty(jwksUri))
                {
                    Logging.MyOperationTrace("The discovery document had no jwks_uri.");

                    return;
                }
            }
            catch (Exception ex)
            {
                Logging.MyOperationTrace(string.Format(
                    "The discovery document could not be read. ({0})", ex.GetType().Name));

                return;
            }

            try
            {
                string jwkSet = await OAuth2AndOIDCClient.GetJwkSetAsync(new Uri(jwksUri));

                if (string.IsNullOrEmpty(jwkSet))
                {
                    Logging.MyOperationTrace("The JWK Set could not be read. (empty response)");

                    return;
                }

                JObject jobj = (JObject)JsonConvert.DeserializeObject(jwkSet);

                lock (DiscoveryJwks._lock)
                {
                    DiscoveryJwks._cache[discoveryUrl] = new Entry()
                    {
                        JwkSet = jobj,
                        FetchedAt = DateTime.UtcNow
                    };
                }

                Logging.MyOperationTrace("The JWK Set was read from the discovery document.");
            }
            catch (Exception ex)
            {
                Logging.MyOperationTrace(string.Format(
                    "The JWK Set could not be read. ({0})", ex.GetType().Name));
            }
        }

        #endregion
    }
}
