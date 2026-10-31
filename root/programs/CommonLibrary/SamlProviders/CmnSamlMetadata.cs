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
//* クラス名        ：CmnSamlMetadata
//* クラス日本語名  ：この配備の SAML2 のメタデータを作る
//*
//* 作成日時        ：－
//* 作成者          ：－
//* 更新履歴        ：－
//*
//*  日時        更新者            内容
//*  ----------  ----------------  -------------------------------------------------
//*  2026/10/13  玄人 幸道         新規（#291）
//*  2026/10/14  玄人 幸道         この配備のメタデータを作る処理を、両アプリから寄せた（#292 の段階 3）
//**********************************************************************************

using MultiPurposeAuthSite.Co;
using MultiPurposeAuthSite.Log;

using System;
using System.Xml;

using Touryo.Infrastructure.Framework.Authentication;
using Touryo.Infrastructure.Public.Security;

/// <summary>MultiPurposeAuthSite.SamlProviders</summary>
namespace MultiPurposeAuthSite.SamlProviders
{
    /// <summary>
    /// この配備の SAML2 のメタデータ（`EntityDescriptor`）を作る（#292 の段階 3）。
    /// </summary>
    /// <remarks>
    /// **相手のメタデータを読むのは Open棟梁 の `SAML2Metadata`**（取得・解析・キャッシュ。#294）。
    /// **設定の読み方（どの URL か、どの EntityID を期待するか）は `IdFederationSaml2Metadata`** に在る。
    ///
    /// | | 汎用 | 設定の読み方 |
    /// |---|---|---|
    /// | OIDC | `RemoteJwkSetStore`（Open棟梁） | `TokenProviders.IdFederationJwks` |
    /// | **SAML2** | **`SAML2Metadata`（Open棟梁）** | **`IdFederationSaml2Metadata`** |
    /// </remarks>
    public static class CmnSamlMetadata
    {
        /// <summary>
        /// この配備の `/samlmetadata` を作る。
        /// </summary>
        /// <returns>メタデータ（XmlDocument）</returns>
        /// <remarks>
        /// **両アプリの `/samlmetadata` が、これを呼ぶ**
        /// （**同じ組み立てが 2 か所に在った**ので 1 か所にした。#292 の段階 3）。
        ///
        /// **署名証明書は 1 本だけでは足りない。**
        /// **鍵を替えた瞬間に、キャッシュを持つ SP が検証できなくなる**ためで、
        /// **`PreviousSigningCerFilePaths` に書いた分を並べて広告する。**
        ///
        /// | 広告する順 | 出どころ |
        /// |---|---|
        /// | 1 本目 | **いま署名に使っている鍵の証明書**（`SpRp_RsaCerFilePath`） |
        /// | 2 本目以降 | **`PreviousSigningCerFilePaths`**（空白かカンマ区切り。`SAML2Bindings.AppendSigningCertificates`） |
        ///
        /// **読めない証明書は、黙って飛ばされる**（**メタデータが出せなくなる方が困る**ため）。
        /// **Open棟梁 はログを出さず、並べた本数を返す**ので、
        /// **設定に書いた本数と比べてログを残す**（Open棟梁 #634 の補足 3-6）。
        /// </remarks>
        public static XmlDocument CreateForThisDeployment()
        {
            string saml2RequestEndpoint =
                Config.OAuth2AuthorizationServerEndpointsRootURI + Config.Saml2RequestEndpoint;

            XmlDocument metadata = SAML2Bindings.CreateMetadata(
                CmnServerParams.IssuerId,
                PrivacyEnhancedMail.GetBase64StringFromPemFilePath(
                    CmnClientParams.RsaCerFilePath,
                    PrivacyEnhancedMail.RFC7468Label.Certificate),
                new SAML2Enum.NameIDFormat[]
                {
                    SAML2Enum.NameIDFormat.Unspecified,
                    SAML2Enum.NameIDFormat.EmailAddress,
                    SAML2Enum.NameIDFormat.Persistent//,
                    //SAML2Enum.NameIDFormat.Transient
                },
                saml2RequestEndpoint,
                saml2RequestEndpoint);

            int added = SAML2Bindings.AppendSigningCertificates(metadata);
            int written = CmnSamlMetadata.CountOf(CmnServerParams.PreviousSigningCerFilePaths);

            if (added < written)
            {
                //  **読めない 1 本で、メタデータ全体を落とさない。** **理由は残す**（#253）。
                Logging.MyOperationTrace(string.Format(
                    "Some previous signing certificates could not be read. (configured: {0}, advertised: {1})",
                    written, added));
            }
            else if (0 < added)
            {
                Logging.MyOperationTrace(string.Format(
                    "The SAML2 metadata advertises previous signing certificates. (count: {0})",
                    added));
            }

            return metadata;
        }

        /// <summary>設定に書かれた証明書の本数</summary>
        /// <param name="paths">`PreviousSigningCerFilePaths`（空白・カンマ・タブ区切り）</param>
        /// <returns>本数</returns>
        /// <remarks>**区切りは `SAML2Bindings.AppendSigningCertificates` と同じ。**</remarks>
        private static int CountOf(string paths)
        {
            return string.IsNullOrEmpty(paths) ? 0 : paths.Split(
                new char[] { ' ', ',', '\t' }, StringSplitOptions.RemoveEmptyEntries).Length;
        }
    }
}
