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
//* クラス日本語名  ：SAML2 のメタデータを読む（汎用）
//*
//* 作成日時        ：－
//* 作成者          ：－
//* 更新履歴        ：－
//*
//*  日時        更新者            内容
//*  ----------  ----------------  -------------------------------------------------
//*  2026/10/13  玄人 幸道         新規（#291）
//*  2026/10/13  玄人 幸道         設定の読み方をIdFederationSaml2Metadataへ分けた（#291）
//**********************************************************************************

using MultiPurposeAuthSite.Log;

using System;
using System.Collections.Generic;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Threading.Tasks;
using System.Xml;

using Touryo.Infrastructure.Framework.Authentication;

/// <summary>MultiPurposeAuthSite.SamlProviders</summary>
namespace MultiPurposeAuthSite.SamlProviders
{
    /// <summary>
    /// SAML2 のメタデータ（`EntityDescriptor`）を読む（#291）。
    /// </summary>
    /// <remarks>
    /// **ここは「相手が誰か」を知らない。** **呼び出し側が、URL と期待する EntityID を渡す。**
    /// **OIDC 側の `Extensions.Sts.DiscoveryJwks` と同じ作り**である（#289 の段階 2）。
    ///
    /// | | |
    /// |---|---|
    /// | **この型** | **取得と解析とキャッシュ**（`entityID` / SSO の口 / 署名用の証明書） |
    /// | **呼び出し側** | **設定の読み方**（どの URL か、どの EntityID を期待するか）。**`IdFederationSaml2Metadata`** |
    ///
    /// | | 汎用 | 設定の読み方 |
    /// |---|---|---|
    /// | OIDC | `Extensions.Sts.DiscoveryJwks` | `Extensions.Sts.IdFederationJwks` |
    /// | **SAML2** | **この型** | **`IdFederationSaml2Metadata`** |
    ///
    /// **期待する EntityID を必ず受け取る。**
    /// **メタデータの `entityID` がそれと一致しなければ、何も返さない**
    /// （**どこから引いた値かを、期待する相手に結び付けるため**。
    /// **この確認が無いと、設定の URL を差し替えられた配備で、別の相手の口と鍵を信じてしまう**）。
    ///
    /// > **メタデータは署名されていない**（実測。`SAML2Bindings.CreateMetadata` は署名しない）。
    /// > **信頼の根拠は TLS と、この `entityID` の照合だけ**である。
    /// > **署名されたメタデータを検証する形は、まだ無い**（その鍵をどこから得るかを決める必要がある）。
    ///
    /// **引けなければ null を返す。** **例外にしない。**
    /// **呼び出し側が設定の値（従来の形）に倒せるようにする**ためである。
    ///
    /// **取得は `OAuth2AndOIDCClient.GetJwkSetAsync`** で行う。
    /// **名前は JwkSet だが、中身は「URL を GET して本文を返す」だけ**であり、
    /// **ID 連携の他の口と同じ `HttpClient`**（TLS・プロキシの扱いが揃う）。
    /// </remarks>
    public static class CmnSamlMetadata
    {
        #region 定数

        /// <summary>md（metadata）</summary>
        private const string UrnMetadata = "urn:oasis:names:tc:SAML:2.0:metadata";

        /// <summary>ds（XML 署名）</summary>
        private const string UrnDSig = "http://www.w3.org/2000/09/xmldsig#";

        /// <summary>HTTP-Redirect の Binding</summary>
        private const string BindingRedirect = "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect";

        /// <summary>HTTP-POST の Binding</summary>
        private const string BindingPost = "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST";

        /// <summary>
        /// 取り直しの下限（**これより短い間隔では取りに行かない**）。
        /// </summary>
        /// <remarks>
        /// **引けないたびに取りに行くと、相手を叩き続けられる。**
        /// **OIDC 側（`DiscoveryJwks`）と同じ下限**にしてある。
        /// </remarks>
        private static readonly TimeSpan MinRefetchInterval = TimeSpan.FromMinutes(1);

        #endregion

        #region 結果

        /// <summary>メタデータから読み取った値（#291）</summary>
        public class Metadata
        {
            /// <summary>entityID</summary>
            public string EntityId { get; set; }

            /// <summary>SingleSignOnService（HTTP-Redirect）の Location（無ければ空）</summary>
            public string SsoRedirectLocation { get; set; }

            /// <summary>SingleSignOnService（HTTP-POST）の Location（無ければ空）</summary>
            public string SsoPostLocation { get; set; }

            /// <summary>
            /// 署名用の証明書（`KeyDescriptor use="signing"`。base64。**複数あり得る**）
            /// </summary>
            /// <remarks>
            /// **鍵のロールオーバー中は 2 本並ぶ**（新旧）ので、**配列で持つ。**
            /// </remarks>
            public List<string> SigningCertificates { get; set; }

            /// <summary>取得した時刻（UTC）</summary>
            public DateTime FetchedAt { get; set; }
        }

        #endregion

        #region キャッシュ

        /// <summary>取得したメタデータ（鍵はメタデータの URL）</summary>
        private static readonly Dictionary<string, Metadata> _cache = new Dictionary<string, Metadata>();

        /// <summary>_cache の排他</summary>
        private static readonly object _lock = new object();

        #endregion

        #region public

        /// <summary>
        /// メタデータを読む（キャッシュを使う）。
        /// </summary>
        /// <param name="metadataUrl">相手のメタデータの URL</param>
        /// <param name="expectedEntityId">
        /// **期待する EntityID。** **メタデータの `entityID` がこれと一致しなければ、何も返さない。**
        /// </param>
        /// <returns>メタデータ（引けなければ null）</returns>
        public static async Task<Metadata> GetAsync(string metadataUrl, string expectedEntityId)
        {
            if (string.IsNullOrEmpty(metadataUrl) || string.IsNullOrEmpty(expectedEntityId))
            {
                return null;
            }

            Metadata cached = null;
            bool canRefetch = true;

            lock (CmnSamlMetadata._lock)
            {
                if (CmnSamlMetadata._cache.TryGetValue(metadataUrl, out cached))
                {
                    canRefetch = (DateTime.UtcNow - cached.FetchedAt)
                        > CmnSamlMetadata.MinRefetchInterval;
                }
            }

            if (cached != null)
            {
                return cached;
            }

            if (!canRefetch)
            {
                return null;
            }

            return await CmnSamlMetadata.FetchAsync(metadataUrl, expectedEntityId);
        }

        /// <summary>
        /// 署名用の証明書から、検証鍵（RSA）を作る。
        /// </summary>
        /// <param name="metadata">`GetAsync` の戻り</param>
        /// <returns>RSA（作れなければ null）</returns>
        /// <remarks>
        /// **最初の 1 本だけを使う。**
        /// **ロールオーバー中に 2 本並ぶ**ことはあるが、
        /// **どちらで検証するかを選ぶ仕組み（`KeyInfo` の照合）は、まだ無い。**
        /// </remarks>
        public static RSA FirstSigningKey(Metadata metadata)
        {
            if (metadata == null
                || metadata.SigningCertificates == null
                || metadata.SigningCertificates.Count == 0)
            {
                return null;
            }

            try
            {
                byte[] der = Convert.FromBase64String(metadata.SigningCertificates[0]);

                //  **証明書の読み込みはターゲットで分ける**（`CmnSaml2Response` と同じ）。
                //    `new X509Certificate2(byte[])` は net10.0 で旧形式（SYSLIB0057）、
                //    `X509CertificateLoader` は net48 に無い。
#if NETFX
                X509Certificate2 x509 = new X509Certificate2(der);
#else
                X509Certificate2 x509 = X509CertificateLoader.LoadCertificate(der);
#endif
                return x509.GetRSAPublicKey();
            }
            catch (Exception ex)
            {
                Logging.MyOperationTrace(string.Format(
                    "The signing certificate in the metadata could not be read. ({0})",
                    ex.GetType().Name));

                return null;
            }
        }

        /// <summary>
        /// URL の基底から、この製品のメタデータの URL を組み立てる。
        /// </summary>
        /// <param name="anyEndpointUrl">相手の口の URL（SSO など。**基底だけを使う**）</param>
        /// <param name="metadataPath">メタデータのパス（この製品は `/samlmetadata`）</param>
        /// <returns>URL（組み立てられなければ空）</returns>
        /// <remarks>
        /// **SAML2 には、メタデータの既知のパスが無い**（OIDC の `/.well-known/…` に当たるものが無い）。
        /// **したがって、他の実装では使えない** — **同じ製品を上流に置く配備のための補助**である。
        /// **他の実装が相手なら、URL を設定で与えること。**
        /// </remarks>
        public static string MetadataUrlOf(string anyEndpointUrl, string metadataPath)
        {
            if (string.IsNullOrEmpty(anyEndpointUrl) || string.IsNullOrEmpty(metadataPath))
            {
                return "";
            }

            try
            {
                Uri uri = new Uri(anyEndpointUrl);

                return uri.GetLeftPart(UriPartial.Authority) + metadataPath;
            }
            catch (UriFormatException)
            {
                return "";
            }
        }

        #endregion

        #region private

        /// <summary>メタデータを取って解析し、キャッシュする</summary>
        /// <param name="metadataUrl">メタデータの URL</param>
        /// <param name="expectedEntityId">期待する EntityID</param>
        /// <returns>メタデータ（引けなければ null）</returns>
        /// <remarks>
        /// **失敗しても例外にしない。** **理由はログに残す**（#253 と同じ方針）。
        /// </remarks>
        private static async Task<Metadata> FetchAsync(string metadataUrl, string expectedEntityId)
        {
            string xml = "";

            try
            {
                xml = await OAuth2AndOIDCClient.GetJwkSetAsync(new Uri(metadataUrl));
            }
            catch (Exception ex)
            {
                Logging.MyOperationTrace(string.Format(
                    "The SAML2 metadata could not be read. ({0})", ex.GetType().Name));

                return null;
            }

            if (string.IsNullOrEmpty(xml))
            {
                Logging.MyOperationTrace("The SAML2 metadata could not be read. (empty response)");

                return null;
            }

            Metadata metadata = CmnSamlMetadata.Parse(xml);

            if (metadata == null)
            {
                Logging.MyOperationTrace("The SAML2 metadata could not be parsed.");

                return null;
            }

            if (metadata.EntityId != expectedEntityId)
            {
                //  **期待する EntityID と違う。** **その値は使わない。**
                Logging.MyOperationTrace(
                    "The SAML2 metadata entityID did not match the expected entityID.");

                return null;
            }

            lock (CmnSamlMetadata._lock)
            {
                CmnSamlMetadata._cache[metadataUrl] = metadata;
            }

            Logging.MyOperationTrace(string.Format(
                "The SAML2 metadata was read. (sso: {0}, signing certificates: {1})",
                string.IsNullOrEmpty(metadata.SsoRedirectLocation) ? "(none)" : "found",
                metadata.SigningCertificates.Count));

            return metadata;
        }

        /// <summary>メタデータの XML を解析する</summary>
        /// <param name="xml">メタデータの XML</param>
        /// <returns>メタデータ（読めなければ null）</returns>
        private static Metadata Parse(string xml)
        {
            try
            {
                XmlDocument doc = new XmlDocument();
                doc.PreserveWhitespace = false;
                doc.LoadXml(xml);

                XmlNamespaceManager ns = new XmlNamespaceManager(doc.NameTable);
                ns.AddNamespace("md", CmnSamlMetadata.UrnMetadata);
                ns.AddNamespace("ds", CmnSamlMetadata.UrnDSig);

                XmlNode entity = doc.SelectSingleNode("/md:EntityDescriptor", ns);

                if (entity == null)
                {
                    return null;
                }

                Metadata ret = new Metadata()
                {
                    EntityId = CmnSamlMetadata.Attr(entity, "entityID"),
                    SsoRedirectLocation = CmnSamlMetadata.SsoLocation(
                        doc, ns, CmnSamlMetadata.BindingRedirect),
                    SsoPostLocation = CmnSamlMetadata.SsoLocation(
                        doc, ns, CmnSamlMetadata.BindingPost),
                    SigningCertificates = new List<string>(),
                    FetchedAt = DateTime.UtcNow
                };

                //  **`use="signing"` だけを採る**（暗号化用の鍵は使わない）。
                //    **`use` が無い `KeyDescriptor` は、どちらにも使える**（Metadata 2.4.1.1）ので採る。
                XmlNodeList keys = doc.SelectNodes(
                    "/md:EntityDescriptor/md:IDPSSODescriptor/md:KeyDescriptor", ns);

                if (keys != null)
                {
                    foreach (XmlNode key in keys)
                    {
                        string use = CmnSamlMetadata.Attr(key, "use");

                        if (use != "" && use != "signing")
                        {
                            continue;
                        }

                        XmlNode cer = key.SelectSingleNode(
                            "ds:KeyInfo/ds:X509Data/ds:X509Certificate", ns);

                        if (cer == null || string.IsNullOrEmpty(cer.InnerText))
                        {
                            continue;
                        }

                        //  **PEM の本体だけを採る**（改行・空白は落とす）。
                        ret.SigningCertificates.Add(
                            cer.InnerText.Replace("\r", "").Replace("\n", "").Replace(" ", "").Trim());
                    }
                }

                return string.IsNullOrEmpty(ret.EntityId) ? null : ret;
            }
            catch (Exception)
            {
                return null;
            }
        }

        /// <summary>SingleSignOnService の Location を読む</summary>
        /// <param name="doc">メタデータ</param>
        /// <param name="ns">XmlNamespaceManager</param>
        /// <param name="binding">Binding</param>
        /// <returns>Location（無ければ空）</returns>
        private static string SsoLocation(XmlDocument doc, XmlNamespaceManager ns, string binding)
        {
            XmlNode node = doc.SelectSingleNode(
                "/md:EntityDescriptor/md:IDPSSODescriptor"
                + "/md:SingleSignOnService[@Binding='" + binding + "']", ns);

            return (node == null) ? "" : CmnSamlMetadata.Attr(node, "Location");
        }

        /// <summary>属性値を読む（無ければ空）</summary>
        /// <param name="node">XmlNode</param>
        /// <param name="name">属性の名前</param>
        /// <returns>値</returns>
        private static string Attr(XmlNode node, string name)
        {
            if (node == null || node.Attributes == null)
            {
                return "";
            }

            XmlNode attr = node.Attributes[name];

            return (attr == null) ? "" : attr.Value;
        }

        #endregion
    }
}
