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
//* クラス名        ：IdFederationJwks
//* クラス日本語名  ：上流 OP の署名鍵を、discovery の jwks_uri から引く
//*
//* 作成日時        ：－
//* 作成者          ：－
//* 更新履歴        ：－
//*
//*  日時        更新者            内容
//*  ----------  ----------------  -------------------------------------------------
//*  2026/10/12  玄人 幸道         新規（#289 の段階 2）
//**********************************************************************************

using MultiPurposeAuthSite.Co;
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
    /// 上流 OP の署名鍵を、discovery（`jwks_uri`）から引く（#289 の段階 2）。
    /// </summary>
    /// <remarks>
    /// **段階 1 は、上流の証明書を設定で与える形**だった（`IdFederationOidcCerFilePath`）。
    /// **鍵のロールオーバーに追随できない**ので、**`kid` で引ける形にする。**
    ///
    /// | 段階 | 鍵の出どころ | ロールオーバー |
    /// |---|---|---|
    /// | 1 | **設定の `.cer`**（1 本） | **追随できない**（置き直す） |
    /// | **2（ここ）** | **上流の discovery → `jwks_uri` → `kid`** | **追随する**（`kid` が引けなければ取り直す） |
    ///
    /// **設定キーは増やしていない。**
    ///
    /// | | |
    /// |---|---|
    /// | discovery の在り処 | **`IdFederationAuthorizeEndpoint` の基底**（`https://host/authorize` → `https://host`） |
    /// | **期待する Issuer** | **`SpRp_Isser`**（`CmnClientParams.Isser`）。**discovery の `issuer` がこれと一致しなければ、鍵を使わない** |
    ///
    /// **`iss` そのものから引かない。** **この製品の `IssuerId` は論理名**であり
    /// （雛形は `https://ssoauth.opentouryo.com`）、**待ち受けている URL とは別**だからである
    /// （実測 : 開発・E2E の上流は `https://localhost:44301`）。
    /// **「`iss` を URL として引く」形は、`IssuerId` を URL にできる配備でしか成り立たない。**
    ///
    /// **引けなければ null を返す。** **呼び出し側は、段階 1（設定の `.cer`）に倒す。**
    /// **落ちる方向には倒さない** — **`id_token` の検証そのものは、呼び出し側が必ず行う。**
    ///
    /// **取得は `OAuth2AndOIDCClient.GetJwkSetAsync`** で行う。
    /// **名前は JwkSet だが、中身は「URL を GET して本文を返す」だけ**であり、
    /// **ID 連携の `/token` や `/userinfo` と同じ `HttpClient`**（TLS・プロキシの扱いが揃う）。
    /// </remarks>
    public static class IdFederationJwks
    {
        #region 定数

        /// <summary>discovery の口（RFC 8414 / OIDC Discovery 4.1）</summary>
        private const string WellKnown = "/.well-known/openid-configuration";

        /// <summary>
        /// 取り直しの下限（**これより短い間隔では取りに行かない**）。
        /// </summary>
        /// <remarks>
        /// **`kid` が引けないたびに取りに行くと、上流を叩き続けられる**
        /// （`kid` を偽った `id_token` を投げれば、いくらでも起こせる）。
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
        /// `id_token` の `kid` に対応する上流の鍵を返す。
        /// </summary>
        /// <param name="idToken">上流から受け取った `id_token`</param>
        /// <returns>検証鍵（引けなければ null）</returns>
        /// <remarks>
        /// **RSA（`RS256`）だけを返す。**
        /// **この製品が出す `id_token` は `RS256`** であり、
        /// **EC（`ES*`）は FAPI2（JWE）の経路で使う**ので、ここでは扱わない。
        /// </remarks>
        public static async Task<JWS> GetKeyAsync(string idToken)
        {
            string discoveryUrl = IdFederationJwks.DiscoveryUrl();

            if (string.IsNullOrEmpty(discoveryUrl)
                || string.IsNullOrEmpty(CmnClientParams.Isser))
            {
                // **引く先が分からない。**
                return null;
            }

            string kid = IdFederationJwks.KidOf(idToken);

            if (string.IsNullOrEmpty(kid))
            {
                // **`kid` が無い `id_token` は、ここでは扱えない**（設定の `.cer` に倒す）。
                return null;
            }

            //  **まずキャッシュから引く。**
            JObject jwk = IdFederationJwks.PickFromCache(discoveryUrl, kid, out bool canRefetch);

            if (jwk == null && canRefetch)
            {
                //  **引けなければ取り直す**（鍵のロールオーバー）。
                await IdFederationJwks.FetchAsync(discoveryUrl);
                jwk = IdFederationJwks.PickFromCache(discoveryUrl, kid, out bool dummy);
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
                    "The ID federation could not read the upstream JWK. (kid is in the set, {0})",
                    ex.GetType().Name));

                return null;
            }
        }

        #endregion

        #region private

        /// <summary>discovery の URL（`IdFederationAuthorizeEndpoint` の基底 ＋ well-known）</summary>
        /// <returns>URL（組み立てられなければ空）</returns>
        private static string DiscoveryUrl()
        {
            string authorize = Config.IdFederationAuthorizeEndpoint;

            if (string.IsNullOrEmpty(authorize))
            {
                return "";
            }

            try
            {
                Uri uri = new Uri(authorize);

                return uri.GetLeftPart(UriPartial.Authority) + IdFederationJwks.WellKnown;
            }
            catch (UriFormatException)
            {
                return "";
            }
        }

        /// <summary>`id_token` のヘッダから `kid` を読む</summary>
        /// <param name="idToken">id_token</param>
        /// <returns>kid（読めなければ空）</returns>
        /// <remarks>
        /// **署名を検証する前に読む値**である。
        /// **鍵を選ぶためだけに使い、他の判断には使わない。**
        /// </remarks>
        private static string KidOf(string idToken)
        {
            if (string.IsNullOrEmpty(idToken))
            {
                return "";
            }

            try
            {
                string[] parts = idToken.Split('.');

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
                // **読めない `id_token` は、ここでは扱わない**（検証は呼び出し側が行う）。
                return "";
            }
        }

        /// <summary>キャッシュから `kid` の JWK を引く</summary>
        /// <param name="discoveryUrl">discovery の URL</param>
        /// <param name="kid">kid</param>
        /// <param name="canRefetch">取り直してよいか（下限を過ぎているか）</param>
        /// <returns>JWK（無ければ null）</returns>
        private static JObject PickFromCache(string discoveryUrl, string kid, out bool canRefetch)
        {
            canRefetch = true;

            lock (IdFederationJwks._lock)
            {
                Entry entry = null;

                if (!IdFederationJwks._cache.TryGetValue(discoveryUrl, out entry))
                {
                    return null;
                }

                canRefetch = (DateTime.UtcNow - entry.FetchedAt) > IdFederationJwks.MinRefetchInterval;

                return IdFederationJwks.PickRsaKey(entry.JwkSet, kid);
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
        /// <returns>Task</returns>
        /// <remarks>
        /// **`issuer` が `SpRp_Isser` と一致しなければ、鍵を使わない。**
        /// **「どこから引いた鍵か」を、期待する Issuer に結び付けるため**である
        /// （**この確認が無いと、設定の URL を差し替えられた配備で、別の発行者の鍵を信じてしまう**）。
        ///
        /// **失敗しても例外にしない。** **呼び出し側が段階 1 に倒せるようにする。**
        /// **理由はログに残す**（#253 と同じ方針。**値は URL までで、鍵は出さない**）。
        /// </remarks>
        private static async Task FetchAsync(string discoveryUrl)
        {
            string jwksUri = "";

            try
            {
                string discovery = await OAuth2AndOIDCClient.GetJwkSetAsync(new Uri(discoveryUrl));

                if (string.IsNullOrEmpty(discovery))
                {
                    Logging.MyOperationTrace(
                        "The ID federation could not read the upstream discovery. (empty response)");

                    return;
                }

                JObject jobj = (JObject)JsonConvert.DeserializeObject(discovery);

                //  **名前は直に書く**（`CmnEndpoints` の discovery の組み立て側も同じ）。
                string issuer = (string)jobj["issuer"];

                if (issuer != CmnClientParams.Isser)
                {
                    //  **期待する Issuer と違う。** **その鍵は使わない。**
                    Logging.MyOperationTrace(
                        "The upstream discovery issuer did not match the expected issuer.");

                    return;
                }

                jwksUri = (string)jobj["jwks_uri"];

                if (string.IsNullOrEmpty(jwksUri))
                {
                    Logging.MyOperationTrace(
                        "The upstream discovery had no jwks_uri.");

                    return;
                }
            }
            catch (Exception ex)
            {
                Logging.MyOperationTrace(string.Format(
                    "The ID federation could not read the upstream discovery. ({0})",
                    ex.GetType().Name));

                return;
            }

            try
            {
                string jwkSet = await OAuth2AndOIDCClient.GetJwkSetAsync(new Uri(jwksUri));

                if (string.IsNullOrEmpty(jwkSet))
                {
                    Logging.MyOperationTrace(
                        "The ID federation could not read the upstream JWK Set. (empty response)");

                    return;
                }

                JObject jobj = (JObject)JsonConvert.DeserializeObject(jwkSet);

                lock (IdFederationJwks._lock)
                {
                    IdFederationJwks._cache[discoveryUrl] = new Entry()
                    {
                        JwkSet = jobj,
                        FetchedAt = DateTime.UtcNow
                    };
                }

                Logging.MyOperationTrace(
                    "The ID federation read the upstream JWK Set from the discovery.");
            }
            catch (Exception ex)
            {
                Logging.MyOperationTrace(string.Format(
                    "The ID federation could not read the upstream JWK Set. ({0})",
                    ex.GetType().Name));
            }
        }

        #endregion
    }
}
