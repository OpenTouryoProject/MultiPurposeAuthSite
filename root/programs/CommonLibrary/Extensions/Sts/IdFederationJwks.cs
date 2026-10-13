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
//**********************************************************************************

using MultiPurposeAuthSite.Co;

using System.Threading.Tasks;

using Touryo.Infrastructure.Framework.Authentication;
using Touryo.Infrastructure.Public.Security.Jwt;

namespace MultiPurposeAuthSite.Extensions.Sts
{
    /// <summary>
    /// ID 連携（OIDC）の上流の署名鍵を、**設定から決めて**引く（#289 の段階 2）。
    /// </summary>
    /// <remarks>
    /// **この型は「設定の読み方」だけを持つ。**
    /// **protocol と HTTP とキャッシュは `DiscoveryJwks`（汎用）**に在る。
    ///
    /// | | この配備での決め方 |
    /// |---|---|
    /// | **上流の JWK Set** | **設定の `IdFederationJwkSetUri`**（書いてあれば、discovery を読まない。#290） |
    /// | **discovery の在り処** | **設定の `IdFederationOidcDiscoveryUrl`** → **`IdFederationAuthorizeEndpoint` の基底**（`https://host/authorize` → `https://host/.well-known/openid-configuration`） |
    /// | **期待する Issuer** | **`SpRp_Isser`**（`CmnClientParams.Isser`。Open棟梁 のクライアント役の設定 ＝ **相手の Issuer**） |
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
            string kid = DiscoveryJwks.KidOf(idToken);

            if (!string.IsNullOrEmpty(Config.IdFederationJwkSetUri))
            {
                // 専用設定から引く
                return await DiscoveryJwks.GetRsaKeyFromJwkSetAsync(
                    Config.IdFederationJwkSetUri, kid);
            }
            else
            {
                // Discovery経由で引く
                return await DiscoveryJwks.GetRsaKeyAsync(
                    IdFederationJwks.DiscoveryUrl(), CmnClientParams.Isser, kid);
            }
        }

        /// <summary>
        /// 上流の discovery の URL を決める（設定 → 口の基底から組み立て）。
        /// </summary>
        /// <returns>URL（決まらなければ空）</returns>
        public static string DiscoveryUrl()
        {
            if (!string.IsNullOrEmpty(Config.IdFederationOidcDiscoveryUrl))
            {
                // 専用設定から引く
                return Config.IdFederationOidcDiscoveryUrl;
            }
            else
            {
                // Discovery経由で引く
                return DiscoveryJwks.DiscoveryUrlOf(Config.IdFederationAuthorizeEndpoint);
            }
        }
    }
}
