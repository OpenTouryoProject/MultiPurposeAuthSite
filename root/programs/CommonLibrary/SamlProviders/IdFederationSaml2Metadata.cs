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
//* クラス名        ：IdFederationSaml2Metadata
//* クラス日本語名  ：ID 連携（SAML2）の上流の口と鍵を、設定から決めて引く
//*
//* 作成日時        ：－
//* 作成者          ：－
//* 更新履歴        ：－
//*
//*  日時        更新者            内容
//*  ----------  ----------------  -------------------------------------------------
//*  2026/10/13  玄人 幸道         新規（#291。CmnSamlMetadata から設定の読み方を分けた）
//**********************************************************************************

using MultiPurposeAuthSite.Co;

using System.Security.Cryptography;
using System.Threading.Tasks;

namespace MultiPurposeAuthSite.SamlProviders
{
    /// <summary>
    /// ID 連携（SAML2）の上流の口と鍵を、**設定から決めて**引く（#291）。
    /// </summary>
    /// <remarks>
    /// **この型は「設定の読み方」だけを持つ。**
    /// **取得と解析とキャッシュは `CmnSamlMetadata`（汎用）**に在る。
    ///
    /// **OIDC 側と同じ分け方**である（#289 の段階 2）。
    ///
    /// | | 汎用 | 設定の読み方 |
    /// |---|---|---|
    /// | OIDC | `Extensions.Sts.DiscoveryJwks` | `Extensions.Sts.IdFederationJwks` |
    /// | **SAML2** | **`CmnSamlMetadata`** | **この型** |
    ///
    /// | | この配備での決め方 |
    /// |---|---|
    /// | **メタデータの在り処** | **`IdFederationSaml2MetadataUrl`**（**SAML2 には既知のパスが無い**ので、組み立てはしない） |
    /// | **期待する EntityID** | **`IdFederationSaml2IssuerId`**（一致しなければ、メタデータの値を使わない） |
    /// | 倒れ先 | **`IdFederationSaml2RequestEndpoint`（口）** と **`IdFederationSaml2CerFilePath`（鍵）** |
    ///
    /// **両アプリの `AccountController` に同文で置かない**ため、`CommonLibrary` に在る
    /// （**OIDC の ID 連携が両アプリに同文で在る**のと、同じ重複を増やさない。#286 の段階 1）。
    /// </remarks>
    public static class IdFederationSaml2Metadata
    {
        /// <summary>
        /// 上流の SSO の口を決める（メタデータ → 設定）。
        /// </summary>
        /// <returns>SSO の URL（分からなければ空）</returns>
        /// <remarks>
        /// **メタデータの `entityID` が `IdFederationSaml2IssuerId` と一致しなければ、
        /// メタデータの値は使わない**（`CmnSamlMetadata.GetAsync` が照合する）。
        /// </remarks>
        public static async Task<string> GetSsoUrlAsync()
        {
            CmnSamlMetadata.Metadata metadata = await CmnSamlMetadata.GetAsync(
                Config.IdFederationSaml2MetadataUrl, Config.IdFederationSaml2IssuerId);

            if (metadata != null && !string.IsNullOrEmpty(metadata.SsoRedirectLocation))
            {
                return metadata.SsoRedirectLocation;
            }

            return Config.IdFederationSaml2RequestEndpoint;
        }

        /// <summary>
        /// 上流の署名を検証する鍵を決める（メタデータ → 設定）。
        /// </summary>
        /// <returns>RSA（分からなければ null）</returns>
        /// <remarks>
        /// **メタデータから引けなければ、設定の `.cer` を読む**（従来どおり）。
        /// **どちらも無ければ null** — **検証は成立しない**（`CmnSaml2Response` が理由を返す）。
        /// </remarks>
        public static async Task<RSA> GetSigningKeyAsync()
        {
            CmnSamlMetadata.Metadata metadata = await CmnSamlMetadata.GetAsync(
                Config.IdFederationSaml2MetadataUrl, Config.IdFederationSaml2IssuerId);

            RSA rsa = CmnSamlMetadata.FirstSigningKey(metadata);

            if (rsa != null)
            {
                return rsa;
            }

            //  **設定の `.cer` を読む**（読み込みは `CmnSaml2Response` の 1 か所に寄せてある）。
            return CmnSaml2Response.RsaFromCerFile(Config.IdFederationSaml2CerFilePath);
        }
    }
}
