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
//* クラス名        ：ErrorResponseTests
//* クラス日本語名  ：SA-5 SAML2 の異常系
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
    /// SA-5. SAML2 の異常系。
    /// </summary>
    /// <remarks>
    /// **異常系の E2E が 1 件も無かった**（#275）。
    /// **OAuth 側は #245 で足してある**ので、方針を揃える。
    ///
    /// | | 期待 |
    /// |---|---|
    /// | `SA-5.1` | **ACS URL が登録値と違う** → **登録値へ `Requester`**（#276 の (1)） |
    /// | `SA-5.2` | **未登録の `Issuer`** → **エラー画面**（返す先が決まらない） |
    /// | `SA-5.3` | **壊れた `SAMLRequest`** → **エラー画面。500 にしない** |
    /// | `SA-5.4` | **鍵を登録したクライアントの、署名の無い要求** → `Requester` |
    ///
    /// **要求は自前で組み立てる**（`Infrastructure/Saml2`）。
    /// **自己テストのボタンは、どれも正しい値しか送らない**ので、ここは測れない。
    ///
    /// **署名は付けない。**
    /// **`TestClient_21` は `jwk_rsa_publickey` を持たない**ので、署名の無い要求が通る。
    /// **`TestClient` は持っている**ので、同じ要求が `SA-5.4` で落ちる。
    /// </remarks>
    public class ErrorResponseTests : TargetTestBase
    {
        /// <summary>コンストラクタ</summary>
        /// <param name="output">ITestOutputHelper</param>
        public ErrorResponseTests(ITestOutputHelper output) : base(output)
        {
        }

        /// <summary>SA-5.1 ACS URL が登録値と違えば、登録値へエラー応答を返す</summary>
        /// <param name="targetKey">core / netfx</param>
        /// <returns>Task</returns>
        [SkippableTheory]
        [MemberData(nameof(AllTargets))]
        public async Task SA0501_ACSURLが登録値と違えば登録値へエラー応答(string targetKey)
        {
            using (IdPClient client = await this.SignedInClientAsync(targetKey))
            {
                TestReport r = this.Report("SA-5.1",
                    "AssertionConsumerServiceURL が登録値と違えば、登録値へ Requester を返す",
                    "**要求に書かれた ACS URL をそのまま使うと、"
                    + "任意の URL へアサーションを飛ばせられる。**"
                    + "**事前登録の値と完全一致するか、省略されているときだけ通す。**"
                    + "**以前は `CreateSamlResponse` が `null` を返していたが、"
                    + "呼び出し側が `== HttpRedirect` で分岐していたため、"
                    + "`null` が POST 側に落ち、`action` も `SAMLResponse` も空の"
                    + "自動送信フォームが返っていた**（#276 の (1)）。",
                    "SAML Core 3.2.1 / Web SSO Profile 4.1.4.1 / #276");

                string id = Saml2.NewId();
                string clientId = KnownClients.SeededClientId(KnownClients.TestClient_21);

                r.Target("GET /saml2request（AssertionConsumerServiceURL を登録値と違う値にする）");

                r.Step("(1) 登録値と違う ACS URL で、要求を送る");

                string xml = Saml2.BuildAuthnRequest(
                    id, "http://" + clientId,
                    Saml2.FormatUnspecified, Saml2.BindingPost,
                    acsUrl: "https://attacker.e2e.example/acs");

                HttpResponseMessage res = await this.SendRedirectAsync(client, xml);

                r.VerifyEqual("HTTP 200（自動送信フォーム）", "200", ((int)res.StatusCode).ToString());

                string form = await res.Content.ReadAsStringAsync();
                string action = Html.FormAttribute(form, "action");
                Dictionary<string, string> hidden = Html.HiddenInputs(form);

                r.Step("(2) 返す先は、要求の値ではなく登録値である");

                r.VerifyEqual("フォームの action", KnownClients.Saml2AcsUrl, action ?? "(無し)");

                r.Verify("要求に書いた URL へは返さない",
                    action != null && !action.Contains("attacker.e2e.example"),
                    "返さない",
                    (action != null && action.Contains("attacker.e2e.example"))
                        ? "**要求の URL へ返している**" : "返していない");

                r.Step("(3) StatusCode は Requester である");

                r.Verify("SAMLResponse がある（空のフォームではない）",
                    hidden.ContainsKey("SAMLResponse")
                        && !string.IsNullOrEmpty(hidden["SAMLResponse"]),
                    "ある",
                    hidden.ContainsKey("SAMLResponse")
                        ? (string.IsNullOrEmpty(hidden["SAMLResponse"])
                            ? "**空**（#276 で直した形）" : "ある")
                        : "**無い**");

                Assert.True(hidden.ContainsKey("SAMLResponse")
                    && !string.IsNullOrEmpty(hidden["SAMLResponse"]),
                    "前提: 応答が返ること（空のフォームでないこと）");

                Saml2Response decoded = Saml2.ReadResponse(
                    Saml2.FromPostValue(hidden["SAMLResponse"]));

                r.Verify("応答を読める", decoded != null,
                    "読める", (decoded != null) ? "読めた" : "**読めない**");

                Assert.NotNull(decoded);

                r.VerifyEqual("StatusCode", Saml2.StatusRequester, decoded.StatusCode);

                r.VerifyEqual("Destination（応答の宛先）", KnownClients.Saml2AcsUrl, decoded.Destination);

                r.VerifyEqual("InResponseTo（送った要求の ID）", id, decoded.InResponseTo);

                r.Observe("エラー応答に Assertion が入るか", decoded.HasAssertion ? "入る" : "入らない",
                    "**いまの実装は、エラー応答にも Assertion を組み込む**"
                    + "（`CreateSamlResponse` が `CreateResponse` と `CreateAssertion` を"
                    + "常に呼ぶため）。**仕様としては、エラー応答にアサーションは要らない。**"
                    + "**直すなら別 Issue**（この Issue の範囲では、返す先と StatusCode を測る）。");

                r.Done();
            }
        }

        /// <summary>SA-5.2 未登録の Issuer には、応答せずエラー画面を返す</summary>
        /// <param name="targetKey">core / netfx</param>
        /// <returns>Task</returns>
        [SkippableTheory]
        [MemberData(nameof(AllTargets))]
        public async Task SA0502_未登録のIssuerにはエラー画面(string targetKey)
        {
            using (IdPClient client = await this.SignedInClientAsync(targetKey))
            {
                TestReport r = this.Report("SA-5.2",
                    "未登録の Issuer には、応答せずエラー画面を返す",
                    "**応答を返す先は、事前登録の ACS URL だけ**である。"
                    + "**登録が無ければ、返す先が決まらない**ので、"
                    + "**要求に書かれた URL へは返さない**（SAML Core 3.2.1）。"
                    + "**以前は `action` が空の自動送信フォームが返っていた**（#276 の (1)）。",
                    "SAML Core 3.2.1 / #276");

                r.Target("GET /saml2request（Issuer を未登録の値にする）");

                r.Step("(1) 未登録の Issuer で、要求を送る");

                string xml = Saml2.BuildAuthnRequest(
                    Saml2.NewId(), "http://e2e0notregistered00000000000000",
                    Saml2.FormatUnspecified, Saml2.BindingPost,
                    acsUrl: "https://attacker.e2e.example/acs");

                HttpResponseMessage res = await this.SendRedirectAsync(client, xml);

                await this.VerifyErrorScreenAsync(r, res);

                r.Done();
            }
        }

        /// <summary>SA-5.3 壊れた SAMLRequest でも 500 にしない</summary>
        /// <param name="targetKey">core / netfx</param>
        /// <returns>Task</returns>
        [SkippableTheory]
        [MemberData(nameof(AllTargets))]
        public async Task SA0503_壊れたSAMLRequestでも500にしない(string targetKey)
        {
            using (IdPClient client = await this.SignedInClientAsync(targetKey))
            {
                TestReport r = this.Report("SA-5.3",
                    "壊れた SAMLRequest を送っても、500 にしない",
                    "**外から任意の文字列が来る口である。**"
                    + "**base64 でない・XML でない・AuthnRequest でない**ものが来ても、"
                    + "**サーバの例外を見せない。**"
                    + "**#241 と同じ観点**（JWT でない値・`iss` の無い JWT で 500 にしない）。",
                    "#241 と同じ観点 / #275");

                r.Target("GET /saml2request（SAMLRequest を壊す）");

                int n = 0;

                foreach (string broken in new string[]
                {
                    "not-base64-at-all",                                  // base64 でない
                    "YWJjZGVm",                                           // base64 だが XML でない
                    "PGhlbGxvLz4=",                                       // XML だが AuthnRequest でない
                })
                {
                    n++;
                    r.Step("(" + n + ") SAMLRequest = （壊れた値 " + n + "）");

                    HttpResponseMessage res = await client.GetAsync(
                        "/saml2request?SAMLRequest=" + System.Uri.EscapeDataString(broken));

                    await this.VerifyErrorScreenAsync(r, res);
                }

                r.Note("**net48 版は `customErrors` が例外を 302 に変える**ので、"
                    + "**500 でないことだけでは足りない**（#272 で踏んだ）。"
                    + "**エラー画面が開くことまで見る。**");

                r.Done();
            }
        }

        /// <summary>SA-5.4 鍵を登録したクライアントの、署名の無い要求を断る</summary>
        /// <param name="targetKey">core / netfx</param>
        /// <returns>Task</returns>
        [SkippableTheory]
        [MemberData(nameof(AllTargets))]
        public async Task SA0504_鍵を登録したクライアントの署名の無い要求を断る(string targetKey)
        {
            using (IdPClient client = await this.SignedInClientAsync(targetKey))
            {
                TestReport r = this.Report("SA-5.4",
                    "鍵を登録したクライアントの、署名の無い要求は断る",
                    "**`jwk_rsa_publickey` を登録していれば、署名を検証する。**"
                    + "**登録していなければ、署名の無い要求も通す**"
                    + "（`VerifySamlRequest` の「鍵がない場合は、通す」）。"
                    + "**`AuthnRequest` の署名は SAML では任意**で、"
                    + "**応答が事前登録の ACS URL にしか飛ばない**ことで守っている。"
                    + "**登録した場合に、それが効いていること**をここで測る。",
                    "SAML Core 3.4 / Web SSO Profile / #275");

                ClientRegistration reg = Flows.Registration(client, KnownClients.TestClient);

                string id = Saml2.NewId();

                r.Target("GET /saml2request（TestClient は jwk_rsa_publickey を登録している）");

                r.Step("(1) 署名を付けずに要求を送る");

                string xml = Saml2.BuildAuthnRequest(
                    id, "http://" + reg.ClientId,
                    Saml2.FormatUnspecified, Saml2.BindingPost);

                HttpResponseMessage res = await this.SendRedirectAsync(client, xml);

                r.VerifyEqual("HTTP 200（自動送信フォーム）", "200", ((int)res.StatusCode).ToString());

                string form = await res.Content.ReadAsStringAsync();
                Dictionary<string, string> hidden = Html.HiddenInputs(form);

                r.Verify("SAMLResponse がある", hidden.ContainsKey("SAMLResponse"),
                    "ある", hidden.ContainsKey("SAMLResponse") ? "ある" : "**無い**");

                Assert.True(hidden.ContainsKey("SAMLResponse"), "前提: 応答が返ること");

                Saml2Response decoded = Saml2.ReadResponse(
                    Saml2.FromPostValue(hidden["SAMLResponse"]));

                Assert.NotNull(decoded);

                r.Step("(2) StatusCode は Requester である（署名を検証できない）");

                r.VerifyEqual("StatusCode", Saml2.StatusRequester, decoded.StatusCode);

                r.Note("**`TestClient_21` は鍵を登録していない**ので、"
                    + "**同じ要求が `SA-3.*` では通る。** 差は登録だけである。");

                r.Done();
            }
        }

        #region 補助

        /// <summary>Redirect Binding で /saml2request に要求を送る</summary>
        /// <param name="client">IdPClient</param>
        /// <param name="xml">AuthnRequest の XML</param>
        /// <returns>HttpResponseMessage</returns>
        private Task<HttpResponseMessage> SendRedirectAsync(IdPClient client, string xml)
        {
            return client.GetAsync("/saml2request?" + Saml2.ToRedirectQuery(xml));
        }

        /// <summary>エラー画面が返ることを確かめる</summary>
        /// <param name="r">TestReport</param>
        /// <param name="res">HttpResponseMessage</param>
        /// <returns>Task</returns>
        private async Task VerifyErrorScreenAsync(TestReport r, HttpResponseMessage res)
        {
            int status = (int)res.StatusCode;

            r.Verify("500 にしない", status != 500,
                "500 でない", (status == 500) ? "**500**" : "HTTP " + status);

            string body = System.Net.WebUtility.HtmlDecode(
                await res.Content.ReadAsStringAsync());

            r.Verify("エラー画面が開く", body.Contains("エラーが発生しました"),
                "エラー画面", body.Contains("エラーが発生しました") ? "エラー画面" : "**別の画面**");

            // **空の自動送信フォームを返していないこと**（#276 の (1) で直した形）。
            Dictionary<string, string> hidden = Html.HiddenInputs(body);

            bool emptyForm = hidden.ContainsKey("SAMLResponse")
                && string.IsNullOrEmpty(hidden["SAMLResponse"]);

            r.Verify("空の自動送信フォームではない", !emptyForm,
                "違う", emptyForm ? "**空のフォーム**（直す前の形）" : "違う");

            Assert.NotEqual(500, status);
        }

        #endregion
    }
}
