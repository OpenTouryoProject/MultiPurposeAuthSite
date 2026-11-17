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
//* クラス名        ：Saml2AudienceEntityIdTests
//* クラス日本語名  ：RT-389 SAML2 の応答の Audience は SP の entityID（SAML Profiles §4.1.4.2）
//*
//* 作成日時        ：－
//* 作成者          ：－
//* 更新履歴        ：－
//*
//*  日時        更新者            内容
//*  ----------  ----------------  -------------------------------------------------
//*  2026/11/17  玄人 幸道         新規（#389）
//**********************************************************************************

using System.Collections.Generic;
using System.Net.Http;
using System.Threading.Tasks;

using MultiPurposeAuthSite.Tests.E2E.Infrastructure;

using Xunit;
using Xunit.Abstractions;

namespace MultiPurposeAuthSite.Tests.E2E.Tests.Issues
{
    /// <summary>
    /// RT-389. **SAML2 の応答の `Audience` は、SP の entityID（要求の `Issuer`）**（SAML Profiles §4.1.4.2）。
    /// </summary>
    /// <remarks>
    /// **以前は ACS の URL を入れていた**（Open棟梁 の `audience` を受けない版）。**仕様どおりの SP（`Audience` を entityID と照合する SP）とは通らなかった。**
    /// **`Recipient`（`SubjectConfirmationData`）は、従来どおり ACS の URL**（SAML Profiles §4.1.4.2 の Recipient）。
    ///
    /// | | 測ること |
    /// |---|---|
    /// | **`RT-389.1`** | **POST Binding の応答で、`Audience` が要求の `Issuer` と一致し、ACS の URL ではない。`Recipient` は ACS の URL** |
    /// | **`RT-389.2`** | **Redirect Binding の応答で、同じこと**（`CreateRedirectResponse` に `audience` を渡す分岐） |
    ///
    /// - **entityID は、要求の `Issuer` そのもの**（`http://` ＋ client_id）。IdP が client_id を引くために外す `http://` は、`Audience` では外さない
    /// - **自己テストの SP 役が entityID で照合する**ことは、`WebSsoBindingTests`（画面の「✓ 自分の entityID」）が測る
    /// - `TestClient_21` は `jwk_rsa_publickey` を持たないので、署名の無い要求が通る（`NameIdFormatTests` と同じ）
    /// </remarks>
    public class Saml2AudienceEntityIdTests : TargetTestBase
    {
        /// <summary>コンストラクタ</summary>
        /// <param name="output">ITestOutputHelper</param>
        public Saml2AudienceEntityIdTests(ITestOutputHelper output) : base(output)
        {
        }

        #region RT-389.1

        /// <summary>RT-389.1 SAML2 の応答の Audience は、要求の Issuer（SP の entityID）</summary>
        /// <param name="targetKey">core / netfx</param>
        /// <returns>Task</returns>
        [SkippableTheory]
        [MemberData(nameof(AllTargets))]
        public async Task RT38901_SAML2の応答のAudienceはSPのentityID(string targetKey)
        {
            using (IdPClient client = await this.SignedInClientAsync(targetKey))
            {
                TestReport r = this.Report("RT-389.1",
                    "**SAML2 の応答の Audience は、要求の Issuer（SP の entityID）と一致し、ACS の URL ではない。Recipient は ACS の URL**",
                    "**SAML Profiles §4.1.4.2 は、bearer の確認を持つアサーションの AudienceRestriction に、SP の一意の識別子（entityID）を入れることを求める。**"
                    + "**以前は ACS の URL を入れていた**ので、Audience を entityID と照合する SP とは通らなかった。",
                    "SAML Profiles §4.1.4.2 / #389");

                string clientId = KnownClients.SeededClientId(KnownClients.TestClient_21);

                Assert.False(string.IsNullOrEmpty(clientId),
                    "前提: " + KnownClients.TestClient_21 + " の client_id が分かること（種データ）");

                string issuer = "http://" + clientId;
                string id = Saml2.NewId();

                r.Target("GET /saml2request（client_name=" + KnownClients.TestClient_21 + "。Issuer=http://＋client_id。POST Binding で受ける）");

                string xml = Saml2.BuildAuthnRequest(id, issuer, Saml2.FormatUnspecified, Saml2.BindingPost);

                HttpResponseMessage res = await client.GetAsync("/saml2request?" + Saml2.ToRedirectQuery(xml));

                r.VerifyEqual("HTTP 200（自動送信フォーム）", "200", ((int)res.StatusCode).ToString());

                Dictionary<string, string> hidden = Html.HiddenInputs(await res.Content.ReadAsStringAsync());

                Assert.True(hidden.ContainsKey("SAMLResponse"), "前提: 応答が返ること");

                Saml2Response decoded = Saml2.ReadResponse(Saml2.FromPostValue(hidden["SAMLResponse"]));

                Assert.NotNull(decoded);

                r.VerifyEqual("StatusCode", Saml2.StatusSuccess, decoded.StatusCode);
                r.VerifyEqual("Audience は、要求の Issuer（SP の entityID）", issuer, decoded.Audience ?? "（無い）");
                r.Verify("Audience は ACS の URL ではない", decoded.Audience != decoded.Recipient,
                    "ACS の URL と違う", decoded.Audience != decoded.Recipient ? "違う" : "**ACS の URL と同じ**");
                r.Verify("Recipient（ACS の URL）は在る", !string.IsNullOrEmpty(decoded.Recipient),
                    "在る", string.IsNullOrEmpty(decoded.Recipient) ? "**無い**" : decoded.Recipient);

                r.Done();
            }
        }

        #endregion

        #region RT-389.2

        /// <summary>RT-389.2 Redirect Binding の応答でも、Audience は要求の Issuer（SP の entityID）</summary>
        /// <param name="targetKey">core / netfx</param>
        /// <returns>Task</returns>
        [SkippableTheory]
        [MemberData(nameof(AllTargets))]
        public async Task RT38902_Redirectの応答でもAudienceはSPのentityID(string targetKey)
        {
            using (IdPClient client = await this.SignedInClientAsync(targetKey))
            {
                TestReport r = this.Report("RT-389.2",
                    "**Redirect Binding の応答でも、Audience は要求の Issuer（SP の entityID）と一致し、ACS の URL ではない**",
                    "**SAML Profiles §4.1.4.2 は、AudienceRestriction に SP の entityID を求める。**"
                    + "**Binding ごとに応答を作る関数が分かれている**（CreateRedirectResponse・CreatePostResponse）ので、両方を測る（RT-389.1 は POST）。",
                    "SAML Profiles §4.1.4.2 / #389");

                string clientId = KnownClients.SeededClientId(KnownClients.TestClient_21);

                Assert.False(string.IsNullOrEmpty(clientId),
                    "前提: " + KnownClients.TestClient_21 + " の client_id が分かること（種データ）");

                string issuer = "http://" + clientId;

                r.Target("GET /saml2request（client_name=" + KnownClients.TestClient_21 + "。Issuer=http://＋client_id。Redirect Binding で受ける）");

                string xml = Saml2.BuildAuthnRequest(Saml2.NewId(), issuer, Saml2.FormatUnspecified, Saml2.BindingRedirect);

                HttpResponseMessage res = await client.GetAsync("/saml2request?" + Saml2.ToRedirectQuery(xml));

                bool redirected = (res.Headers.Location != null);

                r.Verify("SP（ACS）へリダイレクトで返る", redirected,
                    "リダイレクトする", redirected ? "リダイレクトした" : "**しなかった**（HTTP " + (int)res.StatusCode + "）");

                Assert.True(redirected, "前提: 応答が SP へ返ること");

                Saml2Response decoded = Saml2.ReadResponse(Saml2.FromRedirectQuery(res.Headers.Location.ToString()));

                Assert.NotNull(decoded);

                r.VerifyEqual("StatusCode", Saml2.StatusSuccess, decoded.StatusCode);
                r.VerifyEqual("Audience は、要求の Issuer（SP の entityID）", issuer, decoded.Audience ?? "（無い）");
                r.Verify("Audience は ACS の URL ではない", decoded.Audience != decoded.Recipient,
                    "ACS の URL と違う", decoded.Audience != decoded.Recipient ? "違う" : "**ACS の URL と同じ**");

                r.Done();
            }
        }

        #endregion
    }
}
