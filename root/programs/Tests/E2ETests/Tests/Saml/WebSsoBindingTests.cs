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
//* クラス名        ：WebSsoBindingTests
//* クラス日本語名  ：SA-1 Web Browser SSO の 4 通りのバインディング
//*
//* 作成日時        ：－
//* 作成者          ：－
//* 更新履歴        ：－
//*
//*  日時        更新者            内容
//*  ----------  ----------------  -------------------------------------------------
//*  2026/10/07  玄人 幸道         新規（#275）
//**********************************************************************************

using System;
using System.Collections.Generic;
using System.Net.Http;
using System.Threading.Tasks;

using MultiPurposeAuthSite.Tests.E2E.Infrastructure;

using Xunit;
using Xunit.Abstractions;

namespace MultiPurposeAuthSite.Tests.E2E.Tests.Saml
{
    /// <summary>
    /// SA-1. SP-initiated Web Browser SSO が、**4 通りのバインディングすべて**で成立する。
    /// </summary>
    /// <remarks>
    /// **要求と応答で、それぞれ Redirect / POST が選べる**ので 4 通りある
    /// （SAML 2.0 Bindings 3.4 / 3.5）。
    ///
    /// | | 要求 | 応答 |
    /// |---|---|---|
    /// | `SA-1.1` | Redirect | Redirect |
    /// | `SA-1.2` | Redirect | POST |
    /// | `SA-1.3` | POST | Redirect |
    /// | `SA-1.4` | **POST** | **POST** |
    ///
    /// **`SA-1.4` は、#246 の項目 2 でボタンを足したのに、テストが無かった組み合わせ**である
    /// （`RT-246.4` / `.5` / `.7` が残りの 3 つ）。
    ///
    /// **`RT-246.*` とは観点が違う。**
    /// あちらは**自己テストの画面が目視できる形になっていること**（#246 の項目 3）。
    /// **こちらは、SP が受け取った応答が、照合をすべて通ること**である。
    ///
    /// **照合は #276 で足した。**
    /// `Audience` / `Recipient` / `InResponseTo` / `RelayState` のそれぞれに ✓ が出る。
    /// **「照合していない」と出たら、期待値が渡っていない**ということなので、落とす。
    /// </remarks>
    public class WebSsoBindingTests : TargetTestBase
    {
        /// <summary>コンストラクタ</summary>
        /// <param name="output">ITestOutputHelper</param>
        public WebSsoBindingTests(ITestOutputHelper output) : base(output)
        {
        }

        /// <summary>SA-1.1 Redirect 要求 → Redirect 応答</summary>
        /// <param name="targetKey">core / netfx</param>
        /// <returns>Task</returns>
        [SkippableTheory]
        [MemberData(nameof(AllTargets))]
        public async Task SA0101_Redirect要求とRedirect応答で成立する(string targetKey)
        {
            await this.RunAsync(targetKey, "SA-1.1", "Saml2RedirectRedirectBinding",
                requestViaPost: false, responseViaRedirect: true);
        }

        /// <summary>SA-1.2 Redirect 要求 → POST 応答</summary>
        /// <param name="targetKey">core / netfx</param>
        /// <returns>Task</returns>
        [SkippableTheory]
        [MemberData(nameof(AllTargets))]
        public async Task SA0102_Redirect要求とPost応答で成立する(string targetKey)
        {
            await this.RunAsync(targetKey, "SA-1.2", "Saml2RedirectPostBinding",
                requestViaPost: false, responseViaRedirect: false);
        }

        /// <summary>SA-1.3 POST 要求 → Redirect 応答</summary>
        /// <param name="targetKey">core / netfx</param>
        /// <returns>Task</returns>
        [SkippableTheory]
        [MemberData(nameof(AllTargets))]
        public async Task SA0103_Post要求とRedirect応答で成立する(string targetKey)
        {
            await this.RunAsync(targetKey, "SA-1.3", "Saml2PostRedirectBinding",
                requestViaPost: true, responseViaRedirect: true);
        }

        /// <summary>SA-1.4 POST 要求 → POST 応答（テストが無かった組み合わせ）</summary>
        /// <param name="targetKey">core / netfx</param>
        /// <returns>Task</returns>
        [SkippableTheory]
        [MemberData(nameof(AllTargets))]
        public async Task SA0104_Post要求とPost応答で成立する(string targetKey)
        {
            await this.RunAsync(targetKey, "SA-1.4", "Saml2PostPostBinding",
                requestViaPost: true, responseViaRedirect: false);
        }

        #region 本体

        /// <summary>1 つの組み合わせを通す</summary>
        /// <param name="targetKey">core / netfx</param>
        /// <param name="id">識別子</param>
        /// <param name="submitButton">自己テストのボタン（submit. を除く）</param>
        /// <param name="requestViaPost">要求を POST（自動送信フォーム）で送るか</param>
        /// <param name="responseViaRedirect">応答を Redirect（GET）で受けるか</param>
        /// <returns>Task</returns>
        private async Task RunAsync(
            string targetKey, string id, string submitButton,
            bool requestViaPost, bool responseViaRedirect)
        {
            using (IdPClient client = await this.SignedInClientAsync(targetKey))
            {
                TestReport r = this.Report(id,
                    "SP-initiated Web Browser SSO が成立する（要求 "
                    + (requestViaPost ? "POST" : "Redirect") + " / 応答 "
                    + (responseViaRedirect ? "Redirect" : "POST") + "）",
                    "**要求と応答で、それぞれ Redirect / POST が選べる**ので 4 通りある。"
                    + "**署名の対象が違う** — Redirect はクエリ文字列、POST は XML の中。"
                    + "**SP 側の照合（Audience / Recipient / InResponseTo / RelayState）が"
                    + "すべて通ること**を見る（#276 で足した）。",
                    "SAML 2.0 Core / Bindings 3.4・3.5 / Web SSO Profile / #275");

                r.Target("POST /Home/Saml2OAuth2Starters に submit." + submitButton);

                r.Step("(1) 自己テストのボタンを押す（要求を組み立てて IdP へ）");

                HttpResponseMessage started = await client.StartSelfTestAsync(submitButton, "normal");

                HttpResponseMessage idp;

                if (requestViaPost)
                {
                    r.VerifyEqual("要求の自動送信フォームが返る（HTTP 200）",
                        "200", ((int)started.StatusCode).ToString());

                    string form = await started.Content.ReadAsStringAsync();
                    string action = Html.FormAttribute(form, "action");
                    Dictionary<string, string> hidden = Html.HiddenInputs(form);

                    r.Verify("フォームに SAMLRequest がある", hidden.ContainsKey("SAMLRequest"),
                        "ある", hidden.ContainsKey("SAMLRequest") ? "ある（値は伏せる）" : "**無い**");

                    Assert.True(hidden.ContainsKey("SAMLRequest"), "前提: 要求のフォームが返ること");

                    idp = await client.PostFormAsync(client.ToLocalUrl(action), hidden);
                }
                else
                {
                    bool redirected = (started.Headers.Location != null);

                    r.Verify("IdP のエンドポイントへ送られる", redirected,
                        "リダイレクトする", redirected ? "リダイレクトした" : "**しなかった**");

                    Assert.True(redirected, "前提: 要求が組み立てられること");

                    idp = await client.GetAsync(
                        client.ToLocalUrl(started.Headers.Location.ToString()));
                }

                r.Step("(2) IdP が応答（アサーション）を返す");

                HttpResponseMessage acs;

                if (responseViaRedirect)
                {
                    bool toAcs = (idp.Headers.Location != null);

                    r.Verify("SP（ACS）へリダイレクトで返る", toAcs,
                        "リダイレクトする",
                        toAcs ? "リダイレクトした" : "**しなかった**（HTTP " + (int)idp.StatusCode + "）");

                    Assert.True(toAcs, "前提: 応答が SP へ返ること");

                    string location = idp.Headers.Location.ToString();

                    // **Redirect Binding の応答は、クエリ文字列に署名が付く**（Bindings 3.4.4.1）。
                    r.Verify("応答のクエリ文字列に SigAlg と Signature が付く",
                        !string.IsNullOrEmpty(Saml2.QueryValue(location, "SigAlg"))
                            && !string.IsNullOrEmpty(Saml2.QueryValue(location, "Signature")),
                        "両方ある",
                        (!string.IsNullOrEmpty(Saml2.QueryValue(location, "SigAlg"))
                            && !string.IsNullOrEmpty(Saml2.QueryValue(location, "Signature")))
                            ? "両方ある（値は伏せる）" : "**足りない**");

                    Saml2Response decoded = Saml2.ReadResponse(Saml2.FromRedirectQuery(location));

                    this.VerifyResponseXml(r, decoded, expectXmlSignature: false);

                    acs = await client.GetAsync(client.ToLocalUrl(location));
                }
                else
                {
                    string form = await idp.Content.ReadAsStringAsync();
                    string action = Html.FormAttribute(form, "action");
                    Dictionary<string, string> hidden = Html.HiddenInputs(form);

                    r.Verify("自動送信フォームで返る（action は SP）", !string.IsNullOrEmpty(action),
                        "フォームがある", string.IsNullOrEmpty(action) ? "**無い**" : action);

                    r.Verify("フォームに SAMLResponse がある", hidden.ContainsKey("SAMLResponse"),
                        "ある", hidden.ContainsKey("SAMLResponse") ? "ある（値は伏せる）" : "**無い**");

                    Assert.True(hidden.ContainsKey("SAMLResponse"), "前提: 応答のフォームが返ること");

                    Saml2Response decoded = Saml2.ReadResponse(
                        Saml2.FromPostValue(hidden["SAMLResponse"]));

                    this.VerifyResponseXml(r, decoded, expectXmlSignature: true);

                    acs = await client.PostFormAsync(client.ToLocalUrl(action), hidden);
                }

                r.Step("(3) SP の照合が、すべて通る");

                r.VerifyEqual("HTTP 200（結果の画面）", "200", ((int)acs.StatusCode).ToString());

                // **net10.0 版の Razor は非 ASCII を数値文字参照で出す**ので、戻してから判定する。
                string html = System.Net.WebUtility.HtmlDecode(
                    await acs.Content.ReadAsStringAsync());

                bool normal = html.Contains("NORMAL_END") && !html.Contains("ABNORMAL_END");

                r.Verify("判定は NORMAL_END", normal, "NORMAL_END",
                    normal ? "NORMAL_END"
                           : (html.Contains("ABNORMAL_END") ? "**ABNORMAL_END**" : "**判定が無い**"));

                // **「照合していない」が出たら落とす**（期待値が渡っていない＝ #276 が効いていない）。
                r.Verify("照合していない項目が無い",
                    !html.Contains("（照合していない）"),
                    "全部照合する",
                    html.Contains("（照合していない）")
                        ? "**照合していない項目がある**（期待値が渡っていない）" : "全部照合した");

                foreach (string expected in new string[]
                {
                    "✓ 検証できた",            // 署名
                    "✓ 一致",                  // Issuer
                    "✓ 自分の ACS URL",        // Audience / Recipient
                    "✓ 送った要求の ID と一致", // InResponseTo
                    "✓ 期限内",                // NotOnOrAfter
                })
                {
                    r.Verify("画面に「" + expected + "」が出る", html.Contains(expected),
                        "出る", html.Contains(expected) ? "出ている" : "**出ていない**");
                }

                r.Verify("RelayState が送った state と一致する",
                    html.Contains("送った state と一致"),
                    "一致", html.Contains("送った state と一致") ? "一致" : "**一致しない**");

                Assert.True(normal, "SP の照合がすべて通ること");

                r.Note("**NameID と XML は画面に出ているが、ここでは値を報告しない**"
                    + "（利用者を指す値のため）。**有無と照合の結果だけを見る。**");

                r.Done();
            }
        }

        /// <summary>応答の XML を直接読んで確かめる</summary>
        /// <param name="r">TestReport</param>
        /// <param name="res">Saml2Response（null 可）</param>
        /// <param name="expectXmlSignature">XML の中に署名があるはずか</param>
        private void VerifyResponseXml(TestReport r, Saml2Response res, bool expectXmlSignature)
        {
            r.Verify("応答の XML を復号して読める", res != null,
                "読める", (res != null) ? "読めた" : "**読めない**");

            Assert.NotNull(res);

            r.Verify("StatusCode は Success", res.IsSuccess,
                "Success", res.IsSuccess ? "Success" : "**" + res.StatusCode + "**");

            r.Verify("Assertion を含む", res.HasAssertion,
                "含む", res.HasAssertion ? "含む" : "**含まない**");

            r.Verify("NameID がある", !string.IsNullOrEmpty(res.NameId),
                "ある", string.IsNullOrEmpty(res.NameId) ? "**無い**" : "ある（値は伏せる）");

            r.Verify("Conditions に NotOnOrAfter がある",
                !string.IsNullOrEmpty(res.NotOnOrAfter),
                "ある", string.IsNullOrEmpty(res.NotOnOrAfter) ? "**無い**" : res.NotOnOrAfter);

            // **有効期限の幅を測る**（#276 の (3) の回帰）。
            //   **`CreateAssertion` の引数は秒**で、
            //   **設定（`Saml2AssertionExpireTimeSpanFromMinutes`）は分**である。
            //   **分 → 秒 なので × 60**。雛形の 30 分が 1800 秒になる。
            //   **かけ忘れていた頃は 30 秒**、**× 3600 にすれば 30 時間**になるので、
            //   **幅を見ればどちらにも気付ける。**
            DateTime notOnOrAfter;
            bool parsed = DateTime.TryParse(
                res.NotOnOrAfter, System.Globalization.CultureInfo.InvariantCulture,
                System.Globalization.DateTimeStyles.AdjustToUniversal
                    | System.Globalization.DateTimeStyles.AssumeUniversal,
                out notOnOrAfter);

            r.Verify("NotOnOrAfter を時刻として読める", parsed,
                "読める", parsed ? "読めた" : "**読めない**");

            Assert.True(parsed, "前提: NotOnOrAfter が時刻であること");

            double minutes = (notOnOrAfter - DateTime.UtcNow).TotalMinutes;

            // **雛形の設定は 30 分。** 往復の時間を見て幅を持たせる。
            r.Verify("有効期限の幅が 25〜35 分（雛形の 30 分）",
                25.0 <= minutes && minutes <= 35.0,
                "25〜35 分",
                minutes.ToString("0.0") + " 分"
                    + ((minutes < 1.0) ? "（**秒になっている**）"
                        : ((minutes > 120.0) ? "（**時間になっている**）" : "")));

            if (expectXmlSignature)
            {
                // **POST Binding は、署名が XML の中に在る。**
                r.Verify("XML の中に署名がある", res.HasSignature,
                    "ある", res.HasSignature ? "ある（値は伏せる）" : "**無い**");
            }
            else
            {
                // **Redirect Binding は、署名がクエリ文字列に付く**ので XML には無い。
                r.Observe("XML の中の署名", res.HasSignature ? "ある" : "無い",
                    "**Redirect Binding では、署名は XML ではなくクエリ文字列に付く**"
                    + "（SAML 2.0 Bindings 3.4.4.1）。無いのが正しい。");
            }
        }

        #endregion
    }
}
