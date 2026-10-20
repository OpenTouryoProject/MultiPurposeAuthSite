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
//*  2026/10/13  玄人 幸道         JWK SetのURLから直に引く口を足した（#290）
//*  2026/10/21  玄人 幸道         同期で読む口と、背景で補充する口を足した（#309 の段階 1）
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

        /// <summary>取得中の URL（**同じ URL へ何本も取りに行かない**）</summary>
        /// <remarks>
        /// **背景の補充は、外から起こせる**（**`kid` を偽った要求を並べる**）ので、
        /// **同時に走る本数を 1 本に抑える**（#309 の段階 1）。
        /// </remarks>
        private static readonly HashSet<string> _fetching = new HashSet<string>();

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

            return DiscoveryJwks.ToJws(jwk);
        }

        /// <summary>
        /// `kid` に対応する RSA の署名鍵を、JWK Set の URL から直に引く。
        /// </summary>
        /// <param name="jwkSetUrl">相手の JWK Set の URL</param>
        /// <param name="kid">トークンのヘッダの `kid`</param>
        /// <returns>検証鍵（引けなければ null）</returns>
        /// <remarks>
        /// **discovery を読まない。** **`issuer` の照合も無い。**
        /// **信頼の根拠は、この URL を設定した人である。**
        /// **`issuer` と結び付けたいなら `GetRsaKeyAsync`（discovery 経由）を使う。**
        ///
        /// **キャッシュと取り直しの下限は、discovery 経由と同じ**（鍵は URL）。
        /// </remarks>
        public static async Task<JWS> GetRsaKeyFromJwkSetAsync(string jwkSetUrl, string kid)
        {
            if (string.IsNullOrEmpty(jwkSetUrl) || string.IsNullOrEmpty(kid))
            {
                return null;
            }

            JObject jwk = DiscoveryJwks.PickFromCache(jwkSetUrl, kid, out bool canRefetch);

            if (jwk == null && canRefetch)
            {
                //  **引けなければ取り直す**（鍵のロールオーバー）。
                await DiscoveryJwks.FetchJwkSetAsync(jwkSetUrl);
                jwk = DiscoveryJwks.PickFromCache(jwkSetUrl, kid, out bool dummy);
            }

            return DiscoveryJwks.ToJws(jwk);
        }

        /// <summary>
        /// **キャッシュに在る JWK を、同期で引く**（**取りに行かない**）。
        /// </summary>
        /// <param name="jwkSetUrl">相手の JWK Set の URL</param>
        /// <param name="kid">JWS のヘッダの `kid`（**空なら、在る鍵を順に返す**）</param>
        /// <param name="max">返す本数の上限（**`kid` が空のとき**）</param>
        /// <returns>JWK（JSON）の並び。**無ければ空の配列**</returns>
        /// <remarks>
        /// **同期の経路から呼ぶための口**である（#309 の段階 1）。
        ///
        /// **クライアント認証は `static bool` の鎖**で、
        /// **`/token` / `/par` / `/ciba_authz` / `/revoke` / `/introspect` の
        /// 全部から同期で呼ばれる。** **そこで `await` を待つと、net48 で止まる** —
        /// **継続が `AspNetSynchronizationContext` へ Post され、
        /// その順番を握っているのは待っている自分**だからである。
        /// **だから、ここでは取りに行かない。**
        ///
        /// | 取りに行くのは | |
        /// |---|---|
        /// | **`RefillInBackground`** | **要求の外**（**待たない**。その 1 本は断る） |
        /// | **`WarmUpAsync`** | **登録のとき**（**あちらの口は async**） |
        ///
        /// **`kty` で絞らない。** **返した JWK は `JwtAssertion.Verify` に渡す** —
        /// **あちらが `kty` を見て RSA / EC を選ぶ**ので、**ES256 も通る。**
        /// （**`PickRsaKey` は discovery の経路のもの**で、**あちらは RSA しか使わない。**）
        /// </remarks>
        public static string[] PickJwksFromCache(string jwkSetUrl, string kid, int max)
        {
            List<string> ret = new List<string>();

            if (string.IsNullOrEmpty(jwkSetUrl))
            {
                return ret.ToArray();
            }

            lock (DiscoveryJwks._lock)
            {
                if (!DiscoveryJwks._cache.TryGetValue(jwkSetUrl, out Entry entry)
                    || entry.JwkSet == null)
                {
                    return ret.ToArray();
                }

                JToken keys = entry.JwkSet[JwtConst.keys];

                if (!(keys is JArray))
                {
                    return ret.ToArray();
                }

                foreach (JToken key in (JArray)keys)
                {
                    JObject jwk = key as JObject;

                    if (jwk == null)
                    {
                        continue;
                    }

                    if (!string.IsNullOrEmpty(kid))
                    {
                        //  **`kid` が在るなら、その 1 本だけ。**
                        if ((string)jwk[JwtConst.kid] == kid)
                        {
                            ret.Add(jwk.ToString());
                            break;
                        }

                        continue;
                    }

                    //  **`kid` の無い JWS**（RFC 7515 §4.1.4 は任意）。
                    //    **在る鍵を順に試す**ことになるので、**本数に上限を置く。**
                    ret.Add(jwk.ToString());

                    if (max <= ret.Count)
                    {
                        break;
                    }
                }
            }

            return ret.ToArray();
        }

        /// <summary>**キャッシュに鍵が在るか**（登録の検査で使う）</summary>
        /// <param name="jwkSetUrl">相手の JWK Set の URL</param>
        /// <returns>1 本でも在れば true</returns>
        /// <remarks>
        /// **`ClientRegistrationProvider.Validate` が見る**（#309 の段階 1 の決め (B)）。
        /// **取れない URL は、登録のその場で断る** —
        /// **後から黙って `private_key_jwt` が通らなくなるより良い。**
        /// </remarks>
        public static bool HasKeysInCache(string jwkSetUrl)
        {
            return 0 < DiscoveryJwks.PickJwksFromCache(jwkSetUrl, "", 1).Length;
        }

        /// <summary>**要求の外で、キャッシュを補充する**（**待たない**）</summary>
        /// <param name="jwkSetUrl">相手の JWK Set の URL</param>
        /// <remarks>
        /// **同期の経路で「鍵が無い」と分かったときに呼ぶ**（#309 の段階 1 の決め (C)(1)）。
        /// **ここで待たないので、その 1 本には間に合わない** — **断って、次の試行で通す。**
        ///
        /// | 見るもの | なぜ |
        /// |---|---|
        /// | **取り直しの下限**（`MinRefetchInterval`） | **`kid` を偽った要求を並べれば、外から取得を起こせる** |
        /// | **取得中の印**（`_fetching`） | **同時に来た要求が、同じ URL へ何本も取りに行かないため**（#305 と同じ考え方） |
        ///
        /// **`Task.Run` で投げる** — **同期コンテキストを持たないスレッドで走る**ので、
        /// **呼び出し側の文脈を塞がない。** **例外は `FetchJwkSetAsync` が飲む。**
        /// </remarks>
        public static void RefillInBackground(string jwkSetUrl)
        {
            if (string.IsNullOrEmpty(jwkSetUrl))
            {
                return;
            }

            lock (DiscoveryJwks._lock)
            {
                if (DiscoveryJwks._fetching.Contains(jwkSetUrl))
                {
                    //  **既に取りに行っている。**
                    return;
                }

                if (DiscoveryJwks._cache.TryGetValue(jwkSetUrl, out Entry entry)
                    && (DateTime.UtcNow - entry.FetchedAt) <= DiscoveryJwks.MinRefetchInterval)
                {
                    //  **下限の内側**（**取り直さない**）。
                    return;
                }

                DiscoveryJwks._fetching.Add(jwkSetUrl);
            }

            Task.Run(async () =>
            {
                try
                {
                    await DiscoveryJwks.FetchJwkSetAsync(jwkSetUrl);
                }
                finally
                {
                    lock (DiscoveryJwks._lock)
                    {
                        DiscoveryJwks._fetching.Remove(jwkSetUrl);
                    }
                }
            });
        }

        /// <summary>**取りに行って、キャッシュへ入れる**（**登録のときに使う**）</summary>
        /// <param name="jwkSetUrl">相手の JWK Set の URL</param>
        /// <returns>**鍵が 1 本でも載ったなら true**</returns>
        /// <remarks>
        /// **登録の口は async なので、ここは待てる**
        /// （`OAuth2ResourceServerController.Register` / `UpdateClient`。#309 の段階 1）。
        ///
        /// **取り直しの下限を見ない**（**毎回、取りに行く**）。
        ///
        /// | | |
        /// |---|---|
        /// | **下限を置いているのは背景の補充**（`RefillInBackground`） | **あれは外から起こせる**（`kid` を偽った要求を並べる） |
        /// | **ここは認可が要る** | **専用 scope のトークンが必要**で、**レート制限も掛かっている**（#305 の段階 3） |
        /// | **毎回取る利点** | **鍵を入れ替えた相手が、`PUT` でその場で反映できる**（**待たされない**） |
        ///
        /// **何もしなくても、最大で下限ぶん**（1 分）**で追随する** —
        /// **背景の補充が、そこで取り直す**ためである。
        /// </remarks>
        public static async Task<bool> WarmUpAsync(string jwkSetUrl)
        {
            if (string.IsNullOrEmpty(jwkSetUrl))
            {
                return false;
            }

            await DiscoveryJwks.FetchJwkSetAsync(jwkSetUrl);

            return DiscoveryJwks.HasKeysInCache(jwkSetUrl);
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

        /// <summary>JWK から検証鍵（RSA）を作る</summary>
        /// <param name="jwk">JWK（null なら null を返す）</param>
        /// <returns>JWS（作れなければ null）</returns>
        private static JWS ToJws(JObject jwk)
        {
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

        /// <summary>JWK Set を取ってキャッシュする（URL を直に指している場合）</summary>
        /// <param name="jwkSetUrl">JWK Set の URL</param>
        /// <returns>Task</returns>
        /// <remarks>**失敗しても例外にしない。** **理由はログに残す**（#253 と同じ方針）。</remarks>
        private static async Task FetchJwkSetAsync(string jwkSetUrl)
        {
            try
            {
                string jwkSet = await OAuth2AndOIDCClient.GetJwkSetAsync(new Uri(jwkSetUrl));

                if (string.IsNullOrEmpty(jwkSet))
                {
                    Logging.MyOperationTrace("The JWK Set could not be read. (empty response)");

                    return;
                }

                JObject jobj = (JObject)JsonConvert.DeserializeObject(jwkSet);

                lock (DiscoveryJwks._lock)
                {
                    DiscoveryJwks._cache[jwkSetUrl] = new Entry()
                    {
                        JwkSet = jobj,
                        FetchedAt = DateTime.UtcNow
                    };
                }

                Logging.MyOperationTrace("The JWK Set was read from the configured URL.");
            }
            catch (Exception ex)
            {
                Logging.MyOperationTrace(string.Format(
                    "The JWK Set could not be read. ({0})", ex.GetType().Name));
            }
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
