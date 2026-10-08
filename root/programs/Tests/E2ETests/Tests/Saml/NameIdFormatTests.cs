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
//* クラス名        ：NameIdFormatTests
//* クラス日本語名  ：SA-3 NameIDPolicy の値ごとの NameID
//*
//* 作成日時        ：－
//* 作成者          ：－
//* 更新履歴        ：－
//*
//*  日時        更新者            内容
//*  ----------  ----------------  -------------------------------------------------
//*  2026/10/07  玄人 幸道         新規（#275）
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
    /// SA-3. `NameIDPolicy` の値に従って、`NameID` の中身が変わる。
    /// </summary>
    /// <remarks>
    /// **自己テストのボタンは 4 つとも `Unspecified` 固定**なので、
    /// **`EmailAddress` / `Persistent` を踏んでいなかった**（#275）。
    /// **メタデータは 3 種を広告している**（`SA-2.1`）のに、**2 種が未測定**だった。
    ///
    /// | `NameIDPolicy` | `NameID` | 実装 |
    /// |---|---|---|
    /// | `Unspecified` | `sub`（`subject_types` に従う。既定は `public` ＝ 利用者 ID） | `PPIDExtension.GetSubForOIDC` |
    /// | `EmailAddress` | 利用者のメアド | `user.Email` |
    /// | `Persistent` | **RP ごとに違う値**（PPID） | `GeneratePPIDByUserID(iss, user.Id)` |
    ///
    /// **`Persistent` は `subject_types` に依らず、必ず PPID になる。**
    ///
    /// **`NameID` は利用者を指す値**なので、**報告に値そのものを出さない。**
    /// **長さ・形・一致／不一致だけを出す。**
    /// </remarks>
    public class NameIdFormatTests : TargetTestBase
    {
        /// <summary>コンストラクタ</summary>
        /// <param name="output">ITestOutputHelper</param>
        public NameIdFormatTests(ITestOutputHelper output) : base(output)
        {
        }

        /// <summary>SA-3.1 Unspecified は、sub（既定は利用者 ID）を返す</summary>
        /// <param name="targetKey">core / netfx</param>
        /// <returns>Task</returns>
        [SkippableTheory]
        [MemberData(nameof(AllTargets))]
        public async Task SA0301_UnspecifiedはsubをNameIDにする(string targetKey)
        {
            using (IdPClient client = await this.SignedInClientAsync(targetKey))
            {
                TestReport r = this.Report("SA-3.1",
                    "NameIDPolicy=unspecified は、sub（既定は利用者 ID）を NameID にする",
                    "**`NameIDPolicy` の値で `NameID` の中身が変わる**"
                    + "（`PPIDExtension.GetSubForSAML2`）。"
                    + "**自己テストのボタンは `unspecified` 固定**なので、"
                    + "**ここだけが従来の E2E と重なる**（他の 2 種は未測定だった）。",
                    "SAML Core 2.2.2 / 8.3 / #275");

                r.Target("GET /saml2request（NameIDPolicy=unspecified）");

                Saml2Response res = await this.RequestAsync(
                    client, r, KnownClients.TestClient_21, Saml2.FormatUnspecified);

                r.VerifyEqual("NameID の Format が echo される",
                    Saml2.FormatUnspecified, res.NameIdFormat);

                r.Verify("NameID がある", !string.IsNullOrEmpty(res.NameId),
                    "ある",
                    string.IsNullOrEmpty(res.NameId)
                        ? "**無い**" : "ある（長さ " + res.NameId.Length + " 文字。値は伏せる）");

                r.Verify("メアドではない（既定は public ＝ 利用者 ID）",
                    !res.NameId.Contains("@"),
                    "@ を含まない", res.NameId.Contains("@") ? "**@ を含む**" : "含まない");

                r.Done();
            }
        }

        /// <summary>SA-3.2 EmailAddress は、メアドを返す</summary>
        /// <param name="targetKey">core / netfx</param>
        /// <returns>Task</returns>
        [SkippableTheory]
        [MemberData(nameof(AllTargets))]
        public async Task SA0302_EmailAddressはメアドをNameIDにする(string targetKey)
        {
            using (IdPClient client = await this.SignedInClientAsync(targetKey))
            {
                TestReport r = this.Report("SA-3.2",
                    "NameIDPolicy=emailAddress は、利用者のメアドを NameID にする",
                    "**メタデータは広告しているのに、E2E が踏んでいなかった**（#275）。"
                    + "**`user.Email` をそのまま入れる**（`GetSubForSAML2`）。"
                    + "**利用者名とメアドは #151 の段階 3 で分かれている**ので、"
                    + "**`unspecified` とは必ず違う値になる。**",
                    "SAML Core 8.3.2 / #275");

                r.Target("GET /saml2request（NameIDPolicy=emailAddress）");

                Saml2Response res = await this.RequestAsync(
                    client, r, KnownClients.TestClient_21, Saml2.FormatEmailAddress);

                r.VerifyEqual("NameID の Format が echo される",
                    Saml2.FormatEmailAddress, res.NameIdFormat);

                r.Verify("NameID がメアドの形である",
                    !string.IsNullOrEmpty(res.NameId) && res.NameId.Contains("@"),
                    "@ を含む",
                    string.IsNullOrEmpty(res.NameId)
                        ? "**無い**"
                        : (res.NameId.Contains("@") ? "@ を含む（値は伏せる）" : "**@ を含まない**"));

                r.Note("**メアドを NameID にすると、RP に利用者のメアドが渡る。**"
                    + "**pairwise（PPID）を使っていても、この指定で素のメアドが出る**ので、"
                    + "**配備のときに意識すること。**");

                r.Done();
            }
        }

        /// <summary>SA-3.3 Persistent は、RP ごとに違う PPID を返す</summary>
        /// <param name="targetKey">core / netfx</param>
        /// <returns>Task</returns>
        [SkippableTheory]
        [MemberData(nameof(AllTargets))]
        public async Task SA0303_PersistentはRPごとに違うPPIDをNameIDにする(string targetKey)
        {
            using (IdPClient client = await this.SignedInClientAsync(targetKey))
            {
                TestReport r = this.Report("SA-3.3",
                    "NameIDPolicy=persistent は、RP ごとに違う PPID を NameID にする",
                    "**`persistent` は `subject_types` に依らず、必ず PPID になる**"
                    + "（`GeneratePPIDByUserID(iss, user.Id)`）。"
                    + "**同じ利用者でも、RP が違えば値が違う**ので、"
                    + "**RP 同士が突き合わせられない**（OIDC の pairwise と同じ狙い）。"
                    + "**2 つのクライアントで比べる**ことで、それを測る。",
                    "SAML Core 8.3.7 / #275");

                r.Target("GET /saml2request（NameIDPolicy=persistent を 2 つの RP で）");

                r.Step("(1) RP その 1（TestClient_21）");

                Saml2Response one = await this.RequestAsync(
                    client, r, KnownClients.TestClient_21, Saml2.FormatPersistent);

                r.VerifyEqual("NameID の Format が echo される",
                    Saml2.FormatPersistent, one.NameIdFormat);

                r.Verify("NameID がある", !string.IsNullOrEmpty(one.NameId),
                    "ある",
                    string.IsNullOrEmpty(one.NameId)
                        ? "**無い**" : "ある（長さ " + one.NameId.Length + " 文字。値は伏せる）");

                r.Step("(2) RP その 2（TestClient_22）");

                Saml2Response two = await this.RequestAsync(
                    client, r, KnownClients.TestClient_22, Saml2.FormatPersistent);

                r.Verify("NameID がある", !string.IsNullOrEmpty(two.NameId),
                    "ある",
                    string.IsNullOrEmpty(two.NameId)
                        ? "**無い**" : "ある（長さ " + two.NameId.Length + " 文字。値は伏せる）");

                r.Step("(3) 2 つの RP で、値が違う");

                r.Verify("RP ごとに違う値になる", one.NameId != two.NameId,
                    "違う", (one.NameId != two.NameId) ? "違う" : "**同じ**（突き合わせられる）");

                Assert.NotEqual(one.NameId, two.NameId);

                r.Step("(4) unspecified とも違う");

                Saml2Response plain = await this.RequestAsync(
                    client, r, KnownClients.TestClient_21, Saml2.FormatUnspecified);

                r.Verify("同じ RP でも、unspecified とは違う値になる",
                    one.NameId != plain.NameId,
                    "違う", (one.NameId != plain.NameId) ? "違う" : "**同じ**");

                r.Note("**`subject_types` を書いていないクライアントでも、"
                    + "`persistent` を指定すれば PPID になる。**"
                    + "**OIDC 側の既定（public。#151 の段階 4）とは別の話である。**");

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
        /// **`TestClient_21` / `TestClient_22` は `jwk_rsa_publickey` を持たない**ので、
        /// **署名の無い要求が通る**（`VerifySamlRequest` の「鍵がない場合は、通す」）。
        /// **ACS URL は指定しない**（登録値が使われる）。
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

            r.Verify("SAMLResponse がある", hidden.ContainsKey("SAMLResponse"),
                "ある", hidden.ContainsKey("SAMLResponse") ? "ある" : "**無い**");

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
