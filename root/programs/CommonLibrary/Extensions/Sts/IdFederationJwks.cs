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
//* クラス日本語名  ：ID 連携（OIDC）の上流の署名鍵を、設定から決めて引く
//*
//* 作成日時        ：－
//* 作成者          ：－
//* 更新履歴        ：－
//*
//*  日時        更新者            内容
//*  ----------  ----------------  -------------------------------------------------
//*  2026/10/12  玄人 幸道         新規（#289 の段階 2）
//*  2026/10/13  玄人 幸道         汎用部分を DiscoveryJwks に分けた（#289 の段階 2）
//*  2026/10/13  玄人 幸道         discoveryのURLを設定で与えられるようにした（#289 の段階 2）
//*  2026/10/13  玄人 幸道         上流のJWK SetのURLを直に指せるようにした（#290）
//*  2026/10/13  玄人 幸道         上流n件から読めるようにした（#292 の段階 1）
//*  2026/10/22  玄人 幸道         鍵の取得を Open棟梁 の RemoteJwkSetStore に移した（#294）
//**********************************************************************************

using MultiPurposeAuthSite.Co;
using MultiPurposeAuthSite.Log;

using System.Threading.Tasks;

using Newtonsoft.Json.Linq;

using Touryo.Infrastructure.Framework.Authentication;
using Touryo.Infrastructure.Public.Security.Jwt;

namespace MultiPurposeAuthSite.Extensions.Sts
{
    /// <summary>
    /// ID 連携（OIDC）の上流の署名鍵を、**設定から決めて**引く（#289 の段階 2）。
    /// </summary>
    /// <remarks>
    /// **この型は「設定の読み方」だけを持つ。**
    /// **protocol と HTTP とキャッシュは `RemoteJwkSetStore`（Open棟梁）**に在る。
    ///
    /// | | この配備での決め方 |
    /// |---|---|
    /// | **上流の JWK Set** | **設定の `IdFederationJwkSetUri`**（書いてあれば、discovery を読まない。#290） |
    /// | **discovery の在り処** | **設定の `IdFederationOidcDiscoveryUrl`** → **`IdFederationAuthorizeEndpoint` の基底**（`https://host/authorize` → `https://host/.well-known/openid-configuration`） |
    /// | **期待する Issuer** | **上流の登録の `issuer`**（#292 の段階 1。**登録が無ければ `SpRp_Isser`**） |
    ///
    /// **設定を先に見る**（SAML2 側の `IdFederationSaml2MetadataUrl` と対称）。
    /// **組み立てでは足りない配備がある** — **パスの下に discovery を置く OP**
    /// （`https://host/tenant/v2.0/.well-known/openid-configuration`）には、**基底だけでは当たらない。**
    ///
    /// **`iss` そのものから引かない。** **この製品の `IssuerId` は論理名**であり
    /// （雛形は `https://ssoauth.opentouryo.com`）、**待ち受けている URL とは別**だからである
    /// （実測 : 開発・E2E の上流は `https://localhost:44301`）。
    /// **「`iss` を URL として引く」形は、`IssuerId` を URL にできる配備でしか成り立たない。**
    ///
    /// **引けなければ null を返す。**
    /// **呼び出し側は、設定の `.cer`（#289 の段階 1。`IdFederationOidcCerFilePath`）に倒す。**
    ///
    /// | 順 | 鍵の出どころ | ロールオーバー |
    /// |---|---|---|
    /// | 1 | **ここ**（discovery → `jwks_uri` → `kid`） | **追随する** |
    /// | 2 | 設定の `.cer`（段階 1） | **追随しない**（置き直す） |
    /// | 3 | 渡さない（従来どおり） | － |
    /// </remarks>
    public static class IdFederationJwks
    {
        /// <summary>
        /// `id_token` の `kid` に対応する上流の鍵を返す。
        /// </summary>
        /// <param name="idToken">上流から受け取った `id_token`</param>
        /// <returns>検証鍵（引けなければ null）</returns>
        public static async Task<JWS> GetKeyAsync(string idToken)
        {
            //  **上流を指定しない呼び出しは、既定の上流**（従来どおり。#292 の段階 1）。
            return await IdFederationJwks.GetKeyAsync(
                idToken,
                IdFederationUpstreams.GetOrDefault("", IdFederationUpstream.Oidc));
        }

        /// <summary>
        /// `id_token` の `kid` に対応する、**その上流**の鍵を返す（#292 の段階 1）。
        /// </summary>
        /// <param name="idToken">上流から受け取った `id_token`</param>
        /// <param name="upstream">上流の登録（null なら引けない）</param>
        /// <returns>検証鍵（引けなければ null）</returns>
        public static async Task<JWS> GetKeyAsync(string idToken, IdFederationUpstream upstream)
        {
            if (upstream == null || string.IsNullOrEmpty(upstream.Issuer))
            {
                //  **期待する Issuer が無ければ引かない**（照合できない相手を信じない）。
                return null;
            }

            string kid = JwtReader.TryReadKid(idToken);
            JObject jwk = null;

            if (!string.IsNullOrEmpty(upstream.JwkSetUri))
            {
                // 専用設定から引く
                jwk = await RemoteJwkSetStore.GetJwkAsync(upstream.JwkSetUri, kid);
            }
            else
            {
                // Discovery経由で引く
                jwk = await RemoteJwkSetStore.GetJwkByDiscoveryAsync(
                    IdFederationJwks.DiscoveryUrl(upstream), upstream.Issuer, kid);
            }

            if (jwk == null)
            {
                //  **理由を残す**（#253。**鍵そのものは出さない**）。
                Logging.MyOperationTrace("The key of the upstream id_token was not found.");
                return null;
            }

            //  **上流の id_token は RS256 で検証する**（設定の証明書に倒す経路と同じ）。
            //    **鍵の種類が合わなければ null**（`JwsFactory.CreateFromJwk` が見る）。
            return JwsFactory.CreateFromJwk(JwtConst.RS256, jwk);
        }

        /// <summary>
        /// 上流の discovery の URL を決める（設定 → 口の基底から組み立て）。
        /// </summary>
        /// <returns>URL（決まらなければ空）</returns>
        public static string DiscoveryUrl()
        {
            return IdFederationJwks.DiscoveryUrl(
                IdFederationUpstreams.GetOrDefault("", IdFederationUpstream.Oidc));
        }

        /// <summary>
        /// **その上流**の discovery の URL を決める（設定 → 口の基底から組み立て）。
        /// </summary>
        /// <param name="upstream">上流の登録</param>
        /// <returns>URL（決まらなければ空）</returns>
        public static string DiscoveryUrl(IdFederationUpstream upstream)
        {
            if (upstream == null)
            {
                return "";
            }

            if (!string.IsNullOrEmpty(upstream.DiscoveryUrl))
            {
                // 専用設定から引く
                return upstream.DiscoveryUrl;
            }
            else
            {
                // 口の基底から組み立てる
                return RemoteJwkSetStore.DiscoveryUrlOf(upstream.AuthorizeEndpoint);
            }
        }
    }
}
