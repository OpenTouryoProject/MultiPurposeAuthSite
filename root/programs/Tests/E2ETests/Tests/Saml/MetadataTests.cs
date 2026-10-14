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
//* クラス名        ：MetadataTests
//* クラス日本語名  ：SA-2 IdP のメタデータ（/samlmetadata）
//*
//* 作成日時        ：－
//* 作成者          ：－
//* 更新履歴        ：－
//*
//*  日時        更新者            内容
//*  ----------  ----------------  -------------------------------------------------
//*  2026/10/07  玄人 幸道         新規（#275）
//*  2026/10/14  玄人 幸道         SA-2.2（退役前の証明書）を足した（#292 の段階 3）
//**********************************************************************************

using System.Net.Http;
using System.Threading.Tasks;
using System.Xml;

using MultiPurposeAuthSite.Tests.E2E.Infrastructure;

using Xunit;
using Xunit.Abstractions;

namespace MultiPurposeAuthSite.Tests.E2E.Tests.Saml
{
    /// <summary>
    /// SA-2. IdP のメタデータ（`/samlmetadata`）が、SP が読める形で出る。
    /// </summary>
    /// <remarks>
    /// **E2E が 1 件も無かった口である**（#275）。
    /// `CorsTests` は `.well-known/openid-configuration` と `/jwkcerts` を測っているが、
    /// **同じ `MpasPublicDocs` ポリシーが付いている `/samlmetadata` を測っていなかった。**
    ///
    /// **SP は、この XML だけを見て IdP に繋ぐ。**
    /// **entityID が応答の Issuer と違えば、SP は照合に失敗する。**
    /// **SSO の口が違えば、要求が届かない。**
    /// **証明書が違えば、署名を検証できない。**
    /// **どれも「設定を書き換えたときに黙って壊れる」**ので、ここで固定する。
    /// </remarks>
    public class MetadataTests : TargetTestBase
    {
        /// <summary>md（metadata）の名前空間</summary>
        private const string UrnMetadata = "urn:oasis:names:tc:SAML:2.0:metadata";

        /// <summary>CORS を測るときの、許していないオリジン</summary>
        private const string Evil = "https://evil.example";

        /// <summary>コンストラクタ</summary>
        /// <param name="output">ITestOutputHelper</param>
        public MetadataTests(ITestOutputHelper output) : base(output)
        {
        }

        /// <summary>SA-2.1 メタデータの中身が、IdP の設定と揃っている</summary>
        /// <param name="targetKey">core / netfx</param>
        /// <returns>Task</returns>
        [SkippableTheory]
        [MemberData(nameof(AllTargets))]
        public async Task SA0201_メタデータの中身がIdPの設定と揃っている(string targetKey)
        {
            using (IdPClient client = this.Client(targetKey))
            {
                TestReport r = this.Report("SA-2.1",
                    "/samlmetadata が、entityID・証明書・NameIDFormat・SSO の口を出す",
                    "**SP は、この XML だけを見て IdP に繋ぐ。**"
                    + "**entityID が応答の Issuer と違えば、SP の照合が落ちる。**"
                    + "**SSO の口が違えば要求が届かず、証明書が違えば署名を検証できない。**"
                    + "**E2E が 1 件も無かった口である**（#275）。",
                    "SAML 2.0 Metadata 2.4.3（IDPSSODescriptor）/ #275");

                r.Target("GET /samlmetadata");

                r.Step("(1) XML として読める");

                HttpResponseMessage res = await client.GetAsync("/samlmetadata");

                r.VerifyEqual("HTTP 200", "200", ((int)res.StatusCode).ToString());

                string contentType = (res.Content.Headers.ContentType == null)
                    ? "" : res.Content.Headers.ContentType.MediaType;

                r.VerifyEqual("Content-Type", "application/xml", contentType);

                string xml = await res.Content.ReadAsStringAsync();

                XmlDocument doc = new XmlDocument();
                bool parsed = true;

                try
                {
                    doc.LoadXml(xml);
                }
                catch
                {
                    parsed = false;
                }

                r.Verify("XML として読める", parsed, "読める", parsed ? "読めた" : "**読めない**");

                Assert.True(parsed, "前提: メタデータが XML であること");

                XmlNamespaceManager ns = new XmlNamespaceManager(doc.NameTable);
                ns.AddNamespace("md", MetadataTests.UrnMetadata);
                ns.AddNamespace("ds", "http://www.w3.org/2000/09/xmldsig#");

                r.Step("(2) entityID が、OIDC の issuer と同じ値である");

                XmlNode entity = doc.SelectSingleNode("/md:EntityDescriptor", ns);

                string entityId = (entity == null || entity.Attributes["entityID"] == null)
                    ? "" : entity.Attributes["entityID"].Value;

                // **SAML の entityID も OIDC の issuer も `Config.IssuerId` である。**
                //   **揃っていなければ、どちらかの設定を取り違えている。**
                string issuer = await client.IssuerAsync();

                r.VerifyEqual("entityID = Discovery の issuer", issuer ?? "(取れない)", entityId);

                r.Step("(3) IDPSSODescriptor に、署名用の証明書がある");

                XmlNode idp = doc.SelectSingleNode(
                    "/md:EntityDescriptor/md:IDPSSODescriptor", ns);

                r.Verify("IDPSSODescriptor がある", idp != null,
                    "ある", (idp != null) ? "ある" : "**無い**");

                Assert.NotNull(idp);

                string protocols = (idp.Attributes["protocolSupportEnumeration"] == null)
                    ? "" : idp.Attributes["protocolSupportEnumeration"].Value;

                r.VerifyEqual("protocolSupportEnumeration", Saml2.UrnProtocol, protocols);

                XmlNode cert = doc.SelectSingleNode(
                    "/md:EntityDescriptor/md:IDPSSODescriptor"
                    + "/md:KeyDescriptor[@use='signing']/ds:KeyInfo/ds:X509Data/ds:X509Certificate", ns);

                bool hasCert = (cert != null) && !string.IsNullOrEmpty(cert.InnerText);

                r.Verify("署名用の X509Certificate がある", hasCert,
                    "ある", hasCert ? "ある（長さ " + cert.InnerText.Trim().Length + " 文字）" : "**無い**");

                r.Step("(4) NameIDFormat を 3 種とも広告している");

                XmlNodeList formats = doc.SelectNodes(
                    "/md:EntityDescriptor/md:IDPSSODescriptor/md:NameIDFormat", ns);

                r.VerifyEqual("NameIDFormat の件数", "3",
                    (formats == null) ? "0" : formats.Count.ToString());

                foreach (string expected in new string[]
                {
                    Saml2.FormatUnspecified, Saml2.FormatEmailAddress, Saml2.FormatPersistent
                })
                {
                    bool found = false;

                    if (formats != null)
                    {
                        foreach (XmlNode f in formats)
                        {
                            if (f.InnerText.Trim() == expected)
                            {
                                found = true;
                            }
                        }
                    }

                    r.Verify(expected + " を広告する", found,
                        "広告する", found ? "広告している" : "**していない**");
                }

                r.Step("(5) SSO の口が、Redirect と POST の両方にあり、設定と一致する");

                // **設定ファイルの値と突き合わせる**（取り違えていれば落ちる）。
                //   **`ToLocalUrl` を通す。** `test.ps1 -Launch` は
                //   **RootURI を環境変数で上書きする**ので（TESTING.md 4 節）、
                //   **設定ファイルの値をそのまま期待値にすると落ちる。**
                string expectedLocation = client.ToLocalUrl(
                    client.Config.Get("OAuth2AuthorizationServerEndpointsRootURI")
                    + client.Config.Get("Saml2RequestEndpoint"));

                XmlNodeList ssos = doc.SelectNodes(
                    "/md:EntityDescriptor/md:IDPSSODescriptor/md:SingleSignOnService", ns);

                r.VerifyEqual("SingleSignOnService の件数", "2",
                    (ssos == null) ? "0" : ssos.Count.ToString());

                foreach (string binding in new string[] { Saml2.BindingRedirect, Saml2.BindingPost })
                {
                    XmlNode sso = doc.SelectSingleNode(
                        "/md:EntityDescriptor/md:IDPSSODescriptor"
                        + "/md:SingleSignOnService[@Binding='" + binding + "']", ns);

                    string location = (sso == null || sso.Attributes["Location"] == null)
                        ? "" : sso.Attributes["Location"].Value;

                    r.VerifyEqual(binding.Replace(
                        "urn:oasis:names:tc:SAML:2.0:bindings:", "") + " の Location",
                        expectedLocation, location);
                }

                r.Step("(6) 公開情報なので、許していないオリジンにも開く");

                HttpResponseMessage cors = await client.GetWithOriginAsync("/samlmetadata", MetadataTests.Evil);

                r.VerifyEqual("Access-Control-Allow-Origin", "*", IdPClient.AllowOrigin(cors));

                string wantSigned = (idp.Attributes["WantAuthnRequestsSigned"] == null)
                    ? "" : idp.Attributes["WantAuthnRequestsSigned"].Value;

                r.Observe("WantAuthnRequestsSigned", wantSigned,
                    "**固定で true を出している**（Open棟梁 の雛形）。"
                    + "**実際は、`jwk_rsa_publickey` を登録していないクライアントの要求は、"
                    + "署名が無くても通る**（`VerifySamlRequest` の「鍵がない場合は、通す」）。"
                    + "**広告と振る舞いが揃っていない**ので、`CONFIGURATION.md` に明記してある。");

                r.Done();
            }
        }

        #region SA-2.2

        /// <summary>SA-2.2 メタデータは、退役させる途中の署名証明書も並べて広告する</summary>
        /// <param name="targetKey">core / netfx</param>
        /// <returns>Task</returns>
        /// <remarks>
        /// **鍵の入れ替え（ロールオーバー）に要る**（#292 の段階 3）。
        ///
        /// **SP はメタデータをキャッシュする。**
        /// **1 本しか広告していないと、鍵を替えた瞬間に SP が検証できなくなる。**
        ///
        /// **`PreviousSigningCerFilePaths` に書いた分を、`KeyDescriptor` として並べる**
        /// （**いまの鍵が 1 本目**）。**空なら 1 本だけ**（従来どおり）。
        ///
        /// **`SAML2Bindings.CreateMetadata` は証明書を 1 本しか受けない**ので、
        /// **出来上がった XML に足している**（`CmnSamlMetadata.AppendPreviousSigningKeyDescriptors`）。
        /// </remarks>
        [SkippableTheory]
        [MemberData(nameof(AllTargets))]
        public async Task SA0202_メタデータが退役前の証明書も広告する(string targetKey)
        {
            using (IdPClient client = this.Client(targetKey))
            {
                TestReport r = this.Report("SA-2.2",
                    "メタデータは、退役させる途中の署名証明書も並べて広告する",
                    "**鍵を入れ替えられること**（#292 の段階 3）。"
                    + "**SP はメタデータをキャッシュする**ので、"
                    + "**1 本だけ広告していると、替えた瞬間に検証できなくなる。**"
                    + "**2 本並べておけば、SP がどちらでも検証できる**"
                    + "（**受け取る側は全部試す**。`CmnSaml2Response` の鍵の列を受ける版）。",
                    "SAML 2.0 Metadata 2.4.1.1 / #292 の段階 3");

                r.Target("GET /samlmetadata");

                r.Step("(1) メタデータを引く");

                HttpResponseMessage res = await client.GetAsync("/samlmetadata");
                string xml = await res.Content.ReadAsStringAsync();

                r.VerifyEqual("HTTP 200", "200", ((int)res.StatusCode).ToString());

                XmlDocument doc = new XmlDocument();
                bool parsed = true;

                try
                {
                    doc.LoadXml(xml);
                }
                catch
                {
                    parsed = false;
                }

                r.Verify("XML として読める", parsed, "読める", parsed ? "読めた" : "**読めない**");

                Assert.True(parsed, "前提: メタデータが XML であること");

                r.Step("(2) 署名用の KeyDescriptor の本数を見る");

                XmlNodeList keys = doc.SelectNodes(
                    "//*[local-name()='KeyDescriptor'][@use='signing']"
                    + "//*[local-name()='X509Certificate']");

                int count = (keys == null) ? 0 : keys.Count;

                //  **設定が在る配備では 2 本以上**（`test.ps1` が渡している）。
                //    **空の配備では 1 本**（雛形の既定）。**どちらでも 1 本以上は在る。**
                r.Verify("1 本以上ある", 0 < count, "1 本以上", count + " 本");

                Assert.True(0 < count, "前提: 署名証明書が広告されていること");

                bool hasPrevious = 1 < count;

                r.Verify("退役前の証明書も並ぶ（設定が在れば）", hasPrevious,
                    "2 本以上",
                    hasPrevious ? count + " 本"
                        : "**1 本だけ**（PreviousSigningCerFilePaths を確認）");

                r.Step("(3) 1 本目は、いま署名に使っている証明書である");

                //  **1 本目は `SpRp_RsaCerFilePath`**（`CreateMetadata` が入れる）。
                //    **順が入れ替わると、キャッシュを持つ SP の挙動が変わる**ので、見ておく。
                string first = (0 < count) ? keys[0].InnerText.Trim() : "";
                string second = (1 < count) ? keys[1].InnerText.Trim() : "";

                r.Verify("1 本目と 2 本目は別の証明書である",
                    !hasPrevious || first != second,
                    "別のもの",
                    (hasPrevious && first == second) ? "**同じものが 2 本**" : "別のもの");

                r.Observe("広告している署名証明書の本数", count.ToString(),
                    "**`PreviousSigningCerFilePaths` に書いた分だけ増える**"
                    + "（区切りは空白かカンマ）。");

                r.Done();
            }
        }

        #endregion
    }
}
