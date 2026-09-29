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
//* クラス名        ：Saml2AssertionTests
//* クラス日本語名  ：RT-246 自己テストが SAML2 のアサーションを画面に出す
//*
//* 作成日時        ：－
//* 作成者          ：－
//* 更新履歴        ：－
//*
//*  日時        更新者            内容
//*  ----------  ----------------  -------------------------------------------------
//*  2026/09/28  玄人 幸道         新規（#246 の項目 3）
//*  2026/09/28  玄人 幸道         4 つ目のバインディングの組み合わせ（RT-246.7）を追加（#246 の項目 2）
//**********************************************************************************

using System.Collections.Generic;
using System.Net.Http;
using System.Text.RegularExpressions;
using System.Threading.Tasks;

using MultiPurposeAuthSite.Tests.E2E.Infrastructure;

using Xunit;
using Xunit.Abstractions;

namespace MultiPurposeAuthSite.Tests.E2E.Tests.Issues
{
    /// <summary>
    /// RT-246. 自己テストが、SAML2 の応答（アサーション）を画面に出す。
    /// </summary>
    /// <remarks>
    /// **#246 の項目 3 で「最も手薄」とした箇所。**
    /// SP 側（`AccountController.AssertionConsumerService`）は応答を検証していたが、
    /// **結果を `?ret=認証完了（nameId=…）` / `?ret=認証失敗` という URL に載せるだけ**で、
    /// **どこで落ちたのかが分からず、読み取った属性も、アサーションの XML も捨てていた。**
    ///
    /// ここで測るのは **SAML の適合性ではなく、自己テストが目視できる形になっていること**である
    /// （`#246` の方針。SAML の異常系は、この実装の役割分担では E2E の担当でない）。
    ///
    /// | 見るもの | なぜ |
    /// |---|---|
    /// | 判定（NORMAL_END / ABNORMAL_END）と理由 | 以前は URL の文字列だけだった |
    /// | 署名の検証と Issuer の一致を、**別々に**出す | どちらで落ちたかが分かるように |
    /// | アサーションの XML（`Assertion` と `Signature`） | **実値を目視する**ため |
    /// | 属性（`Audience`・`NotOnOrAfter`・`AuthnContextClassRef` など） | 捨てていた |
    /// | Redirect Binding（GET）と POST Binding の**両方** | 署名の対象が違う（クエリ文字列 / XML の中） |
    ///
    /// **画面（Razor）は実行時コンパイル**なので、ビルドでは誤りが出ない。ここで一度開く。
    /// </remarks>
    public class Saml2AssertionTests : TargetTestBase
    {
        /// <summary>コンストラクタ</summary>
        /// <param name="output">ITestOutputHelper</param>
        public Saml2AssertionTests(ITestOutputHelper output) : base(output)
        {
        }

        /// <summary>RT-246.4 Redirect Binding（GET）でアサーションを画面に出す</summary>
        /// <param name="targetKey">core / netfx</param>
        /// <returns>Task</returns>
        [SkippableTheory]
        [MemberData(nameof(AllTargets))]
        public async Task RT24604_SAMLのアサーションを画面に出す_Redirect(string targetKey)
        {
            using (IdPClient client = await this.SignedInClientAsync(targetKey))
            {
                TestReport r = this.Report("RT-246.4",
                    "自己テストが、Redirect Binding（GET）で受け取ったアサーションを画面に出す",
                    "**#246 の項目 3 で「最も手薄」とした箇所。**"
                    + "検証はしていたが、**結果を `?ret=認証完了（nameId=…）` という URL に載せるだけ**で、"
                    + "**署名の検証で落ちたのか Issuer の不一致で落ちたのかが分からず、"
                    + "読み取った属性も、アサーションの XML も捨てていた。**"
                    + "**画面（Razor）は実行時コンパイル**なので、ビルドでは分からない。",
                    "SAML 2.0 Core / Bindings（HTTP-Redirect）/ #246 の項目 3");

                r.Target("POST /Home/Saml2OAuth2Starters に submit.Saml2RedirectRedirectBinding");

                string html = await Saml2AssertionTests.RunSelfTestAsync(
                    r, client, "Saml2RedirectRedirectBinding", redirectToAcs: true);

                // **Redirect Binding は、署名がクエリ文字列に付く**ので、XML に署名の要素は無い。
                Saml2AssertionTests.VerifyScreen(r, html, "Redirect（GET", expectXmlSignature: false);

                r.Note("**Redirect Binding は、クエリ文字列そのものが署名の対象**である"
                    + "（`SigAlg` が `RSAwithSHA1` のときだけ検証する。従来どおり）。");

                r.Done();
            }
        }

        /// <summary>RT-246.5 POST Binding でアサーションを画面に出す</summary>
        /// <param name="targetKey">core / netfx</param>
        /// <returns>Task</returns>
        [SkippableTheory]
        [MemberData(nameof(AllTargets))]
        public async Task RT24605_SAMLのアサーションを画面に出す_Post(string targetKey)
        {
            using (IdPClient client = await this.SignedInClientAsync(targetKey))
            {
                TestReport r = this.Report("RT-246.5",
                    "自己テストが、POST Binding で受け取ったアサーションを画面に出す",
                    "**署名の対象が Redirect Binding と違う**（クエリ文字列ではなく XML の中）。"
                    + "**自動送信フォームで戻る経路**も、同じ画面で見えるようにする（#246 の項目 3）。",
                    "SAML 2.0 Bindings（HTTP-POST）/ #246 の項目 3");

                r.Target("POST /Home/Saml2OAuth2Starters に submit.Saml2RedirectPostBinding");

                string html = await Saml2AssertionTests.RunSelfTestAsync(
                    r, client, "Saml2RedirectPostBinding", redirectToAcs: false);

                Saml2AssertionTests.VerifyScreen(r, html, "POST（署名は XML の中）", expectXmlSignature: true);

                r.Note("**IdP は自動送信フォーム（`PostBinding` 画面）で返す。**"
                    + "テストは、そのフォームの hidden をそのまま POST している。");

                r.Done();
            }
        }

        /// <summary>RT-246.7 Post & Redirect Binding（4 つ目の組み合わせ）</summary>
        /// <param name="targetKey">core / netfx</param>
        /// <returns>Task</returns>
        [SkippableTheory]
        [MemberData(nameof(AllTargets))]
        public async Task RT24607_SAMLの4つ目の組み合わせが通る(string targetKey)
        {
            using (IdPClient client = await this.SignedInClientAsync(targetKey))
            {
                TestReport r = this.Report("RT-246.7",
                    "自己テストが、要求を POST・応答を Redirect で受ける組み合わせも試せる",
                    "**バインディングの組み合わせは 4 通りあるが、ボタンは 3 つだけだった**"
                    + "（Redirect-Redirect / Redirect-Post / Post-Post）。"
                    + "**要求を POST で送り、応答を Redirect で受ける**組み合わせが抜けていた（#246 の項目 2）。"
                    + "`ProtocolBinding` が応答の受け取り方を決めるので、指定を変えるだけで足りる。",
                    "SAML 2.0 Bindings（HTTP-POST / HTTP-Redirect）/ #246 の項目 2");

                r.Target("POST /Home/Saml2OAuth2Starters に submit.Saml2PostRedirectBinding");

                string html = await Saml2AssertionTests.RunSelfTestAsync(
                    r, client, "Saml2PostRedirectBinding",
                    redirectToAcs: true, requestViaPost: true);

                Saml2AssertionTests.VerifyScreen(r, html, "Redirect（GET", expectXmlSignature: false);

                r.Note("**要求は POST、応答は Redirect。** 応答の署名はクエリ文字列に付くので、"
                    + "XML には署名の要素が無い（`RT-246.4` と同じ）。");

                r.Done();
            }
        }

        #region 補助

        /// <summary>自己テストの SAML ボタンを押し、SP の結果画面の HTML を返す</summary>
        /// <param name="r">TestReport</param>
        /// <param name="client">IdPClient</param>
        /// <param name="submitButton">submit. を除いたボタン名</param>
        /// <param name="redirectToAcs">IdP が ACS へリダイレクトで返すか（Redirect Binding）</param>
        /// <param name="requestViaPost">要求を POST（自動送信フォーム）で送るか</param>
        /// <returns>結果画面の HTML（実体参照は戻したもの）</returns>
        /// <remarks>
        /// **絶対 URL は必ず `ToLocalUrl` を通す。**
        /// 構成ファイルのルート URI（44300）のままだと、net48 版（44302）の測定で別のサイトを叩く。
        /// </remarks>
        private static async Task<string> RunSelfTestAsync(
            TestReport r, IdPClient client, string submitButton, bool redirectToAcs,
            bool requestViaPost = false)
        {
            r.Step("(1) 自己テストの SAML ボタンを押す（要求を組み立てて IdP へ）");

            HttpResponseMessage started = await client.StartSelfTestAsync(submitButton, "normal");

            HttpResponseMessage idp;

            if (requestViaPost)
            {
                // **要求を POST で送る経路。** 画面が自動送信フォームを返す。
                r.VerifyEqual("要求の自動送信フォームが返る（HTTP 200）",
                    "200", ((int)started.StatusCode).ToString());

                string requestForm = await started.Content.ReadAsStringAsync();
                string requestAction = Html.FormAttribute(requestForm, "action");

                r.Verify("フォームの action が IdP のエンドポイントである",
                    !string.IsNullOrEmpty(requestAction),
                    "action あり", string.IsNullOrEmpty(requestAction) ? "**無い**" : requestAction);

                Assert.False(string.IsNullOrEmpty(requestAction), "前提: 要求のフォームが返ること");

                Dictionary<string, string> requestHidden = Html.HiddenInputs(requestForm);

                r.Verify("フォームに SAMLRequest がある", requestHidden.ContainsKey("SAMLRequest"),
                    "ある", requestHidden.ContainsKey("SAMLRequest") ? "ある（値は伏せる）" : "**無い**");

                r.Step("(2) IdP が応答（アサーション）を返す");

                idp = await client.PostFormAsync(client.ToLocalUrl(requestAction), requestHidden);
            }
            else
            {
                bool redirected = (started.Headers.Location != null);

                r.Verify("IdP のエンドポイントへ送られる", redirected,
                    "リダイレクトする", redirected ? "リダイレクトした" : "**しなかった**");

                Assert.True(redirected, "前提: SAML の要求が組み立てられること");

                r.Step("(2) IdP が応答（アサーション）を返す");

                idp = await client.GetAsync(
                    client.ToLocalUrl(started.Headers.Location.ToString()));
            }

            HttpResponseMessage acs;

            if (redirectToAcs)
            {
                bool toAcs = (idp.Headers.Location != null);

                r.Verify("SP（AssertionConsumerService）へリダイレクトで返る", toAcs,
                    "リダイレクトする", toAcs ? "リダイレクトした" : "**しなかった**（" + (int)idp.StatusCode + "）");

                Assert.True(toAcs, "前提: 応答が SP へ返ること");

                acs = await client.GetAsync(client.ToLocalUrl(idp.Headers.Location.ToString()));
            }
            else
            {
                string form = await idp.Content.ReadAsStringAsync();
                string action = Html.FormAttribute(form, "action");

                r.Verify("自動送信フォームで返る（action は SP）", !string.IsNullOrEmpty(action),
                    "フォームがある", string.IsNullOrEmpty(action) ? "**無い**" : action);

                Assert.False(string.IsNullOrEmpty(action), "前提: 自動送信フォームが返ること");

                Dictionary<string, string> hidden = Html.HiddenInputs(form);

                r.Verify("フォームに SAMLResponse がある", hidden.ContainsKey("SAMLResponse"),
                    "ある", hidden.ContainsKey("SAMLResponse") ? "ある（値は伏せる）" : "**無い**");

                acs = await client.PostFormAsync(client.ToLocalUrl(action), hidden);
            }

            r.Step("(3) SP の結果画面を確かめる");

            r.VerifyEqual("HTTP 200（結果の画面）", "200", ((int)acs.StatusCode).ToString());

            // **net10.0 版の Razor は非 ASCII を数値文字参照で出す**ので、戻してから判定する。
            //   XML も `&lt;` で埋め込まれているため、ここで戻すと要素名で確かめられる。
            return System.Net.WebUtility.HtmlDecode(await acs.Content.ReadAsStringAsync());
        }

        /// <summary>結果画面の中身を確かめる</summary>
        /// <param name="r">TestReport</param>
        /// <param name="html">結果画面（実体参照は戻したもの）</param>
        /// <param name="binding">画面に出るバインディングの文字列（前方一致）</param>
        /// <param name="expectXmlSignature">XML の中に署名（SignatureValue）があるはずか</param>
        /// <remarks>**アサーションは利用者名を含むので、実測値には出さない**（有無だけを報告する）。</remarks>
        private static void VerifyScreen(
            TestReport r, string html, string binding, bool expectXmlSignature)
        {
            bool notError = !html.Contains("エラーが発生しました");

            r.Verify("エラー画面ではない", notError,
                "結果の画面", notError ? "結果の画面" : "**エラー画面**");

            Assert.True(notError, "前提: 結果の画面が開くこと（Razor は実行時コンパイル）");

            bool normal = html.Contains("NORMAL_END") && !html.Contains("ABNORMAL_END");

            r.Verify("判定は NORMAL_END", normal, "NORMAL_END",
                normal ? "NORMAL_END"
                       : (html.Contains("ABNORMAL_END") ? "**ABNORMAL_END**" : "**判定が出ていない**"));

            r.Verify("署名を検証できたことが出る", html.Contains("✓ 検証できた"),
                "✓ 検証できた", html.Contains("✓ 検証できた") ? "✓ 検証できた" : "**出ていない**");

            r.Verify("Issuer の一致が出る", html.Contains("✓ 一致"),
                "✓ 一致", html.Contains("✓ 一致") ? "✓ 一致" : "**出ていない**");

            r.Verify("バインディングが出る（" + binding + "…）", html.Contains(binding),
                binding + "…", html.Contains(binding) ? "出ている" : "**出ていない**");

            // **XML は利用者名を含むので、要素の有無だけを見る。**
            bool hasAssertion = Regex.IsMatch(html, "<[A-Za-z0-9]*:?Assertion");
            bool hasSignature = html.Contains("SignatureValue");

            r.Verify("アサーションの XML が画面に出る", hasAssertion,
                "Assertion 要素がある", hasAssertion ? "ある（中身は伏せる）" : "**無い**");

            if (expectXmlSignature)
            {
                // POST Binding : 署名は XML の中にある。
                r.Verify("署名の要素も XML に出る", hasSignature,
                    "SignatureValue がある", hasSignature ? "ある（値は伏せる）" : "**無い**");
            }
            else
            {
                // **Redirect Binding : 署名はクエリ文字列に付く**ので、XML には無いのが正しい。
                r.Verify("SigAlg が画面に出る（署名はクエリ文字列に付く）",
                    html.Contains("rsa-sha1"),
                    "SigAlg が出る", html.Contains("rsa-sha1") ? "出ている" : "**出ていない**");

                r.Observe("XML の中の署名", hasSignature ? "ある" : "無い",
                    "**Redirect Binding では、署名は XML ではなくクエリ文字列に付く**"
                    + "（SAML 2.0 Bindings 3.4.4.1）。無いのが正しい。");
            }

            bool hasNameId = html.Contains("NameID / NameIDFormat");

            r.Verify("属性（NameID / NameIDFormat など）が表になって出る", hasNameId,
                "表に出る", hasNameId ? "出ている" : "**出ていない**");

            r.Verify("RelayState が送った state と一致する", html.Contains("送った state と一致"),
                "一致", html.Contains("送った state と一致") ? "一致" : "**一致しない（または照合していない）**");
        }

        #endregion
    }
}
