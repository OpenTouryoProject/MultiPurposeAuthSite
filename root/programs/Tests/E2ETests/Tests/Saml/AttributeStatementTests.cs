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
//* クラス名        ：AttributeStatementTests
//* クラス日本語名  ：SA-7 アサーションの AttributeStatement
//*
//* 作成日時        ：－
//* 作成者          ：－
//* 更新履歴        ：－
//*
//*  日時        更新者            内容
//*  ----------  ----------------  -------------------------------------------------
//*  2026/10/12  玄人 幸道         新規（#286 の段階 4）
//**********************************************************************************

using System.Collections.Generic;
using System.Net.Http;
using System.Threading.Tasks;

using MultiPurposeAuthSite.Tests.E2E.Infrastructure;

using Xunit;
using Xunit.Abstractions;

namespace MultiPurposeAuthSite.Tests.E2E.Tests.Saml
{
    /// <summary>
    /// SA-7. アサーションが、メアドと利用者名を属性で返す（#286 の段階 4）。
    /// </summary>
    /// <remarks>
    /// **段階 3 までは `NameID` だけだった。**
    /// **`NameIDFormat=emailAddress` の `NameID` をメアドとして扱う**ことで ID 連携を通していたので、
    ///
    /// | | 段階 3 まで | 段階 4 |
    /// |---|---|---|
    /// | メアド | **`emailAddress` の `NameID` だけ** | **属性（`mail`）** → `NameID` |
    /// | 新規作成時の名前 | メアドの `@` より前 | **属性（`uid`）** → メアドの `@` より前 |
    /// | 検証済みのメアドか | **言う方法が無い** | **属性（`email_verified`）** |
    ///
    /// **`Persistent`（PPID）の `NameID` を返す配備とも連携できる**ようになった（`SA-7.2`）。
    ///
    /// **名前は Open棟梁 の `SAML2Const` が持つ**（出す側と読む側（`SAML2Attributes`）で同じものを使う）。
    /// **ここでは、出てきた XML の名前を直に書いて測る**（製品側の定数を参照しない。
    /// **定数ごと変わってしまったら、テストが気付かない**ため）。
    /// </remarks>
    public class AttributeStatementTests : TargetTestBase
    {
        #region 測る名前（XML に出る値を直に書く）

        /// <summary>メアド（X.500/LDAP の mail）</summary>
        private const string NameEmail = "urn:oid:0.9.2342.19200300.100.1.3";

        /// <summary>利用者名（X.500/LDAP の uid）</summary>
        private const string NameUserName = "urn:oid:0.9.2342.19200300.100.1.1";

        /// <summary>メアドが検証済みか</summary>
        private const string NameEmailVerified = "email_verified";

        /// <summary>NameFormat（uri）</summary>
        private const string NameFormatUri = "urn:oasis:names:tc:SAML:2.0:attrname-format:uri";

        /// <summary>NameFormat（basic）</summary>
        private const string NameFormatBasic = "urn:oasis:names:tc:SAML:2.0:attrname-format:basic";

        #endregion

        /// <summary>コンストラクタ</summary>
        /// <param name="output">ITestOutputHelper</param>
        public AttributeStatementTests(ITestOutputHelper output) : base(output)
        {
        }

        /// <summary>SA-7.1 アサーションが、メアド・利用者名・email_verified を属性で返す</summary>
        /// <param name="targetKey">core / netfx</param>
        /// <returns>Task</returns>
        [SkippableTheory]
        [MemberData(nameof(AllTargets))]
        public async Task SA0701_アサーションが属性でメアドと利用者名を返す(string targetKey)
        {
            using (IdPClient client = await this.SignedInClientAsync(targetKey))
            {
                TestReport r = this.Report("SA-7.1",
                    "アサーションが、メアド・利用者名・email_verified を属性で返す",
                    "**`NameID` だけでは、メアドと利用者名を運べない**（#286 の段階 4）。"
                    + "**OIDC 側のクレームに 1 対 1 で対応させた属性**を出す"
                    + "（`mail` ⇔ `email`、`uid` ⇔ `preferred_username`、"
                    + "`email_verified` ⇔ `email_verified`）。"
                    + "**`urn:oid:…` は X.500/LDAP Attribute Profile** であり、"
                    + "**他の IdP（Shibboleth / ADFS など）とも合う。**",
                    "SAML Core 2.7.3.1 / SAML V2.0 prof-attr-x500 / #286 の段階 4");

                r.Target("GET /saml2request（NameIDPolicy=emailAddress。POST Binding）");

                Saml2Response res = await this.RequestAsync(
                    client, r, KnownClients.TestClient_21, Saml2.FormatEmailAddress);

                r.Verify("AttributeStatement がある",
                    res.Attributes != null && res.Attributes.Count != 0,
                    "ある",
                    (res.Attributes == null || res.Attributes.Count == 0)
                        ? "**無い**" : "ある（" + res.Attributes.Count + " 件）");

                Assert.True(res.Attributes != null && res.Attributes.Count != 0,
                    "前提: 属性が返ること");

                r.VerifyEqual("メアドの属性（mail）が、サインインした利用者のメアド",
                    "一致",
                    (res.Attribute(AttributeStatementTests.NameEmail)
                        == TestEnv.TestUserEmail(targetKey)) ? "一致" : "**不一致**");

                r.VerifyEqual("利用者名の属性（uid）が、サインインした利用者名",
                    "一致",
                    (res.Attribute(AttributeStatementTests.NameUserName)
                        == TestEnv.TestUserName(targetKey)) ? "一致" : "**不一致**");

                string verified = res.Attribute(AttributeStatementTests.NameEmailVerified);

                //  **種データの利用者は「確認済み」である**ので、`true` になる。
                //    **`user.EmailConfirmed` がそのまま出ている**ことを測る
                //    （**言い値ではない** — 上流が知っている状態である）。
                r.VerifyEqual("email_verified の属性（種データの利用者は確認済み）",
                    "true", string.IsNullOrEmpty(verified) ? "（無し）" : verified);

                r.Step("(2) 名前の付け方（FriendlyName / NameFormat）");

                string friendlyName = "";
                string nameFormat = "";

                r.Verify("メアドの属性に FriendlyName と NameFormat がある",
                    Saml2.TryReadAttributeNames(
                        res.Xml, AttributeStatementTests.NameEmail,
                        out friendlyName, out nameFormat),
                    "ある", "ある");

                r.VerifyEqual("メアドの FriendlyName", "mail", friendlyName);
                r.VerifyEqual("メアドの NameFormat",
                    AttributeStatementTests.NameFormatUri, nameFormat);

                Saml2.TryReadAttributeNames(
                    res.Xml, AttributeStatementTests.NameUserName,
                    out friendlyName, out nameFormat);

                r.VerifyEqual("利用者名の FriendlyName", "uid", friendlyName);
                r.VerifyEqual("利用者名の NameFormat",
                    AttributeStatementTests.NameFormatUri, nameFormat);

                Saml2.TryReadAttributeNames(
                    res.Xml, AttributeStatementTests.NameEmailVerified,
                    out friendlyName, out nameFormat);

                r.VerifyEqual("email_verified の NameFormat（標準の属性ではないので basic）",
                    AttributeStatementTests.NameFormatBasic, nameFormat);

                r.Observe("属性の件数", res.Attributes.Count.ToString(),
                    "**3 件**（`mail` / `email_verified` / `uid`）。"
                    + "**この E2E は `Name` だけを鍵にする**ので、"
                    + "**製品側（`FriendlyName` も鍵に入れる）より少ない。**");

                r.Note("**署名は応答の全体に対して行う**ので、"
                    + "**属性も署名の対象に入っている**（`SA-1.*` が署名を測っている）。");

                r.Done();
            }
        }

        /// <summary>SA-7.2 persistent の NameID でも、属性でメアドが分かる</summary>
        /// <param name="targetKey">core / netfx</param>
        /// <returns>Task</returns>
        [SkippableTheory]
        [MemberData(nameof(AllTargets))]
        public async Task SA0702_persistentでも属性でメアドが分かる(string targetKey)
        {
            using (IdPClient client = await this.SignedInClientAsync(targetKey))
            {
                TestReport r = this.Report("SA-7.2",
                    "NameIDPolicy=persistent でも、属性でメアドと利用者名が分かる",
                    "**これが段階 4 の目的である。**"
                    + "**`Persistent`（PPID）の `NameID` はメアドではない**ので、"
                    + "**段階 3 までは、その配備と ID 連携できなかった**"
                    + "（`NameID` をメアドとして扱っていた）。"
                    + "**属性が在れば、`NameID` が何であっても利用者を引ける。**",
                    "SAML Core 8.3.7 / #286 の段階 4");

                r.Target("GET /saml2request（NameIDPolicy=persistent。POST Binding）");

                Saml2Response res = await this.RequestAsync(
                    client, r, KnownClients.TestClient_21, Saml2.FormatPersistent);

                r.VerifyEqual("NameID の Format が echo される",
                    Saml2.FormatPersistent, res.NameIdFormat);

                r.Verify("NameID はメアドではない（PPID）",
                    !string.IsNullOrEmpty(res.NameId) && !res.NameId.Contains("@"),
                    "@ を含まない",
                    string.IsNullOrEmpty(res.NameId)
                        ? "**無い**"
                        : (res.NameId.Contains("@") ? "**@ を含む**" : "含まない（値は伏せる）"));

                r.VerifyEqual("それでも、属性のメアドは利用者のメアドである",
                    "一致",
                    (res.Attribute(AttributeStatementTests.NameEmail)
                        == TestEnv.TestUserEmail(targetKey)) ? "一致" : "**不一致**");

                r.VerifyEqual("属性の利用者名も取れる",
                    "一致",
                    (res.Attribute(AttributeStatementTests.NameUserName)
                        == TestEnv.TestUserName(targetKey)) ? "一致" : "**不一致**");

                r.Note("**下流（SP）側の口は、属性 → `NameID` の順でメアドを決める**"
                    + "（`IDFederationAssertionConsumerService`）。"
                    + "**この要求の形でも ID 連携が成立する**という意味である。"
                    + "**ただし、下流が送る要求は `emailAddress` のまま**なので"
                    + "（#286 の決め事）、**`SA-6.*` はそちらを測っている。**");

                r.Done();
            }
        }

        #region 補助

        /// <summary>
        /// 要求を組み立てて送り、応答（POST Binding）を読む。
        /// </summary>
        /// <param name="client">IdPClient</param>
        /// <param name="r">TestReport</param>
        /// <param name="clientName">種データのクライアント名</param>
        /// <param name="nameIdFormat">NameIDPolicy の Format</param>
        /// <returns>Saml2Response</returns>
        /// <remarks>
        /// **`SA-3` の補助と同じ形**である（`NameIdFormatTests`）。
        /// **`TestClient_21` は `jwk_rsa_publickey` を持たない**ので、署名の無い要求が通る。
        /// </remarks>
        private async Task<Saml2Response> RequestAsync(
            IdPClient client, TestReport r, string clientName, string nameIdFormat)
        {
            string clientId = KnownClients.SeededClientId(clientName);

            Skip.If(string.IsNullOrEmpty(clientId),
                clientName + " の client_id が分かりません（種データ）。");

            string id = Saml2.NewId();

            string xml = Saml2.BuildAuthnRequest(
                id, "http://" + clientId, nameIdFormat, Saml2.BindingPost);

            HttpResponseMessage res = await client.GetAsync(
                "/saml2request?" + Saml2.ToRedirectQuery(xml));

            r.VerifyEqual("HTTP 200（自動送信フォーム）", "200", ((int)res.StatusCode).ToString());

            string form = await res.Content.ReadAsStringAsync();
            Dictionary<string, string> hidden = Html.HiddenInputs(form);

            Assert.True(hidden.ContainsKey("SAMLResponse"), "前提: 応答が返ること");

            Saml2Response decoded = Saml2.ReadResponse(
                Saml2.FromPostValue(hidden["SAMLResponse"]));

            Assert.NotNull(decoded);

            r.VerifyEqual("StatusCode", Saml2.StatusSuccess, decoded.StatusCode);
            r.VerifyEqual("InResponseTo（送った要求の ID）", id, decoded.InResponseTo);

            return decoded;
        }

        #endregion
    }
}
