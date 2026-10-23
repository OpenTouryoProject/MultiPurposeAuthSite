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
//*  2026/10/13  玄人 幸道         上流n件から読めるようにした（#292 の段階 1）
//*  2026/10/14  玄人 幸道         鍵を全部集める版を足した（#292 の段階 3）
//*  2026/10/22  玄人 幸道         メタデータの取得を Open棟梁 の SAML2Metadata に移した（#294）
//**********************************************************************************

using MultiPurposeAuthSite.Co;

using System.Collections.Generic;
using System.Security.Cryptography;
using System.Threading.Tasks;

using Touryo.Infrastructure.Framework.Authentication;

namespace MultiPurposeAuthSite.SamlProviders
{
    /// <summary>
    /// ID 連携（SAML2）の上流の口と鍵を、**設定から決めて**引く（#291）。
    /// </summary>
    /// <remarks>
    /// **この型は「設定の読み方」だけを持つ。**
    /// **取得と解析とキャッシュは `SAML2Metadata`（Open棟梁）**に在る。
    ///
    /// **OIDC 側と同じ分け方**である（#289 の段階 2）。
    ///
    /// | | 汎用 | 設定の読み方 |
    /// |---|---|---|
    /// | OIDC | `RemoteJwkSetStore`（Open棟梁） | `Extensions.Sts.IdFederationJwks` |
    /// | **SAML2** | **`SAML2Metadata`**（Open棟梁） | **この型** |
    ///
    /// | | この配備での決め方 |
    /// |---|---|
    /// | **メタデータの在り処** | **上流の登録の `metadata_url`**（**SAML2 には既知のパスが無い**ので、組み立てはしない） |
    /// | **期待する EntityID** | **上流の登録の `issuer`**（一致しなければ、メタデータの値を使わない） |
    /// | 倒れ先 | **`sso_endpoint`（口）** と **`cer_file_path`（鍵）** |
    ///
    /// **上流の登録は n 件**（#292 の段階 1。`IdFederationUpstreams`）。
    /// **登録が無ければ、従来の単数キーから 1 件が組み立てられる。**
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
        /// メタデータの値は使わない**（`SAML2Metadata.GetAsync` が照合する）。
        /// </remarks>
        public static async Task<string> GetSsoUrlAsync()
        {
            //  **上流を指定しない呼び出しは、既定の上流**（従来どおり。#292 の段階 1）。
            return await IdFederationSaml2Metadata.GetSsoUrlAsync(
                IdFederationUpstreams.GetOrDefault("", IdFederationUpstream.Saml2));
        }

        /// <summary>
        /// **その上流**の SSO の口を決める（メタデータ → 設定。#292 の段階 1）。
        /// </summary>
        /// <param name="upstream">上流の登録</param>
        /// <returns>SSO の URL（分からなければ空）</returns>
        public static async Task<string> GetSsoUrlAsync(IdFederationUpstream upstream)
        {
            if (upstream == null)
            {
                return "";
            }

            SAML2Metadata metadata = await SAML2Metadata.GetAsync(
                upstream.MetadataUrl, upstream.Issuer);

            if (metadata != null && !string.IsNullOrEmpty(metadata.SsoRedirectLocation))
            {
                return metadata.SsoRedirectLocation;
            }

            return upstream.SsoEndpoint;
        }

        /// <summary>
        /// 上流の署名を検証する鍵を決める（メタデータ → 設定）。
        /// </summary>
        /// <returns>RSA（分からなければ null）</returns>
        /// <remarks>
        /// **メタデータから引けなければ、設定の `.cer` を読む**（従来どおり）。
        /// **どちらも無ければ null** — **検証は成立しない**（`SAML2Client.VerifyResponseWithReason` が理由を返す）。
        /// </remarks>
        public static async Task<RSA> GetSigningKeyAsync()
        {
            //  **上流を指定しない呼び出しは、既定の上流**（従来どおり。#292 の段階 1）。
            return await IdFederationSaml2Metadata.GetSigningKeyAsync(
                IdFederationUpstreams.GetOrDefault("", IdFederationUpstream.Saml2));
        }

        /// <summary>
        /// **その上流**の署名を検証する鍵を、**全部**集める（#292 の段階 3）。
        /// </summary>
        /// <param name="upstream">上流の登録</param>
        /// <returns>RSA の列（1 本も無ければ空）</returns>
        /// <remarks>
        /// **順は メタデータの並び → 設定の `.cer`** である。
        ///
        /// **ロールオーバー中は、メタデータに 2 本以上並ぶ。**
        /// **SAML2 の署名には `kid` に当たるものが無い**ので、**受け取る側は全部試す**
        /// （`SAML2Client.VerifyResponseWithReason`）。
        ///
        /// **設定の `.cer` は、いつでも最後の受け皿**である
        /// （**メタデータが引けない配備**のため。#291）。
        /// </remarks>
        public static async Task<List<RSA>> GetSigningKeysAsync(IdFederationUpstream upstream)
        {
            List<RSA> keys = new List<RSA>();

            if (upstream == null)
            {
                return keys;
            }

            SAML2Metadata metadata = await SAML2Metadata.GetAsync(
                upstream.MetadataUrl, upstream.Issuer);

            if (metadata != null)
            {
                keys.AddRange(metadata.GetSigningKeys());
            }

            //  **設定の `.cer` も足す**（**メタデータから引けた鍵の後ろ**）。
            RSA fromFile = CmnSaml2Response.RsaFromCerFile(upstream.CerFilePath);

            if (fromFile != null)
            {
                keys.Add(fromFile);
            }

            return keys;
        }

        /// <summary>
        /// **その上流**の署名を検証する鍵を決める（メタデータ → 設定。#292 の段階 1）。
        /// </summary>
        /// <param name="upstream">上流の登録</param>
        /// <returns>RSA（分からなければ null）</returns>
        public static async Task<RSA> GetSigningKeyAsync(IdFederationUpstream upstream)
        {
            if (upstream == null)
            {
                return null;
            }

            SAML2Metadata metadata = await SAML2Metadata.GetAsync(
                upstream.MetadataUrl, upstream.Issuer);

            RSA rsa = (metadata == null) ? null : metadata.GetFirstSigningKey();

            if (rsa != null)
            {
                return rsa;
            }

            //  **設定の `.cer` を読む**（読み込みは `CmnSaml2Response` の 1 か所に寄せてある）。
            return CmnSaml2Response.RsaFromCerFile(upstream.CerFilePath);
        }
    }
}
