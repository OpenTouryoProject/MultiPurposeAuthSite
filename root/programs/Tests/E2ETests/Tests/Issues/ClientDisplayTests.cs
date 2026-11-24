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
//* クラス名        ：ClientDisplayTests
//* クラス日本語名  ：RT-427 承認の画面に、クライアントのロゴ・ポリシー・利用規約を出す（OIDC Registration 1.0 §2）
//*
//* 作成日時        ：－
//* 作成者          ：－
//* 更新履歴        ：－
//*
//*  日時        更新者            内容
//*  ----------  ----------------  -------------------------------------------------
//*  2026/11/24  玄人 幸道         新規（#427）
//**********************************************************************************

using System;
using System.Collections.Generic;
using System.Net;
using System.Net.Http;
using System.Threading.Tasks;

using MultiPurposeAuthSite.Tests.E2E.Infrastructure;

using Xunit;
using Xunit.Abstractions;

namespace MultiPurposeAuthSite.Tests.E2E.Tests.Issues
{
    /// <summary>
    /// RT-427. **承認の画面（同意・サインイン）に、クライアントのロゴ・ポリシー・利用規約を出す**。
    /// </summary>
    /// <remarks>
    /// **OIDC Registration 1.0 §2**：`logo_uri` は「承認の間に利用者へ出すべき（SHOULD）」、`policy_uri`・`tos_uri` は「与えられたら出すべき（SHOULD）」。
    /// **以前は 3 つとも登録で受けて保存するだけで、どの画面にも出していなかった。**
    /// **`client_name` は出さない**（画面・動的登録の登録の名前は、登録した利用者の利用者名のため。`ClientDisplay` の remarks）。
    ///
    /// | | 登録 | 測ること |
    /// |---|---|---|
    /// | **`RT-427.1`** | `TestClient_48`（3 つとも https） | **同意の画面に、ロゴ・2 つのリンクが出る**（リンクは `noopener noreferrer`） |
    /// | **`RT-427.2`** | `TestClient_48` | **認可の要求から来たサインインの画面にも出る**（同意を記録した後は同意の画面が出ないため）。**`ReturnUrl` が無い・認可の口でない・登録の無い `client_id` のサインインの画面には出ない** |
    /// | **`RT-427.3`** | `TestClient_49`（`http:`・`javascript:`・`data:`） | **https でない値は出さない**（出すものが無いので、枠ごと出ない） |
    ///
    /// **E2E は HTML だけを見る**（URL は取りに行かない。画像は利用者のブラウザが取りに行く）。
    /// </remarks>
    public class ClientDisplayTests : TargetTestBase
    {
        /// <summary>登録した logo_uri</summary>
        private const string LogoUri = "https://rp.e2e.example/logo.png";

        /// <summary>登録した policy_uri</summary>
        private const string PolicyUri = "https://rp.e2e.example/policy";

        /// <summary>登録した tos_uri</summary>
        private const string TosUri = "https://rp.e2e.example/tos";

        /// <summary>constructor</summary>
        /// <param name="output">ITestOutputHelper</param>
        public ClientDisplayTests(ITestOutputHelper output) : base(output) { }

        #region RT-427.1

        /// <summary>RT-427.1 同意の画面に、クライアントのロゴ・ポリシー・利用規約が出る</summary>
        /// <param name="targetKey">core / netfx</param>
        /// <returns>Task</returns>
        [SkippableTheory]
        [MemberData(nameof(AllTargets))]
        public async Task RT42701_同意の画面にクライアントのロゴとリンクが出る(string targetKey)
        {
            using (IdPClient client = await this.SignedInClientAsync(targetKey))
            {
                TestReport r = this.Report("RT-427.1",
                    "**同意の画面に、クライアントのロゴ（`logo_uri`）・ポリシー（`policy_uri`）・利用規約（`tos_uri`）が出る**",
                    "**以前は、3 つとも登録で受けて保存するだけで、どの画面にも出していなかった。**"
                    + "**OIDC Registration 1.0 §2 は、承認の間に利用者へ出すことを求める（SHOULD）。**"
                    + "**外へのリンクは、開いた先から元の画面を触らせない（`noopener`）・参照元を渡さない（`noreferrer`）。**",
                    "OIDC Registration 1.0 §2 / #427");

                ClientRegistration reg = Flows.InjectedRegistration(client, KnownClients.TestClient_48);

                r.Target("GET /authorize（prompt=consent。client_name=" + KnownClients.TestClient_48
                    + "。logo_uri・policy_uri・tos_uri は https）");

                r.Step("(1) prompt=consent で認可を要求し、同意の画面を開く");

                AuthZResponse authz = await client.AuthorizeAsync(
                    ClientDisplayTests.Parameters(reg, "state-rt42701", "consent"));

                r.Verify("同意の画面が出る", authz.NeedsConsent,
                    "同意の画面", authz.NeedsConsent ? "同意の画面" : "**" + authz.ToString() + "**");

                ClientDisplayTests.VerifyShown(r, ClientDisplayTests.Decode(authz.Body));

                r.Done();
            }
        }

        #endregion

        #region RT-427.2

        /// <summary>RT-427.2 認可の要求から来たサインインの画面にも出る</summary>
        /// <param name="targetKey">core / netfx</param>
        /// <returns>Task</returns>
        [SkippableTheory]
        [MemberData(nameof(AllTargets))]
        public async Task RT42702_認可の要求から来たサインインの画面にも出る(string targetKey)
        {
            using (IdPClient client = this.Client(targetKey))
            {
                TestReport r = this.Report("RT-427.2",
                    "**認可の要求から来たサインインの画面にも、クライアントのロゴ・ポリシー・利用規約が出る。認可の要求から来ていないサインインの画面には出ない**",
                    "**MPAS は同意を記録した後は同意の画面を出さない**ので、同意の画面だけでは 2 回目以降の認可で出ない。"
                    + "**サインインの画面は、戻り先（`ReturnUrl`）が認可の口で、登録のある `client_id` を持つときだけ出す**"
                    + "（適合性テストの `oidcc-registration-logo-uri` などもサインインの画面で写す）。",
                    "OIDC Registration 1.0 §2 / #427");

                ClientRegistration reg = Flows.InjectedRegistration(client, KnownClients.TestClient_48);

                r.Target("サインインしていない状態で GET /authorize（client_name=" + KnownClients.TestClient_48 + "）");

                r.Step("(1) サインインしていない状態で認可を要求し、サインインの画面へ送られる");

                AuthZResponse authz = await client.AuthorizeAsync(
                    ClientDisplayTests.Parameters(reg, "state-rt42702", null));

                bool toLogin = authz.Redirected && (authz.Location ?? "").Contains("/Account/Login");

                r.Verify("サインインの画面へ送られる", toLogin,
                    "/Account/Login", authz.Location ?? authz.ToString());

                Assert.True(toLogin, "前提: サインインの画面へ送られること");

                r.Step("(2) サインインの画面を開く");

                HttpResponseMessage login = await client.GetAsync(client.ToLocalUrl(authz.Location));

                r.VerifyEqual("HTTP 200（サインインの画面）", "200", ((int)login.StatusCode).ToString());

                ClientDisplayTests.VerifyShown(r,
                    ClientDisplayTests.Decode(await login.Content.ReadAsStringAsync()));

                r.Step("(3) 対照：認可の要求から来ていないサインインの画面（ReturnUrl 無し）");

                HttpResponseMessage plain = await client.GetAsync("/Account/Login");
                string plainHtml = ClientDisplayTests.Decode(await plain.Content.ReadAsStringAsync());

                r.Verify("クライアントの情報を出さない", !plainHtml.Contains("id=\"client-display\""),
                    "出さない", plainHtml.Contains("id=\"client-display\"") ? "**出した**" : "出さない");

                foreach (KeyValuePair<string, string> other in new Dictionary<string, string>()
                {
                    { "(4) 対照：ReturnUrl が認可の口でない（client_id は登録のあるもの）", "/Manage/Index?client_id=" + reg.ClientId },
                    { "(5) 対照：ReturnUrl の client_id に登録が無い", "/authorize?client_id=e2e-unknown-427&response_type=code" }
                })
                {
                    r.Step(other.Key);

                    HttpResponseMessage res = await client.GetAsync(
                        "/Account/Login?ReturnUrl=" + Uri.EscapeDataString(other.Value));
                    string html = ClientDisplayTests.Decode(await res.Content.ReadAsStringAsync());

                    r.VerifyEqual("HTTP 200（サインインの画面）", "200", ((int)res.StatusCode).ToString());
                    r.Verify("クライアントの情報を出さない", !html.Contains("id=\"client-display\""),
                        "出さない", html.Contains("id=\"client-display\"") ? "**出した**" : "出さない");
                }

                r.Done();
            }
        }

        #endregion

        #region RT-427.3

        /// <summary>RT-427.3 https でない logo_uri・policy_uri・tos_uri は出さない</summary>
        /// <param name="targetKey">core / netfx</param>
        /// <returns>Task</returns>
        [SkippableTheory]
        [MemberData(nameof(AllTargets))]
        public async Task RT42703_httpsでない値は出さない(string targetKey)
        {
            using (IdPClient client = await this.SignedInClientAsync(targetKey))
            {
                TestReport r = this.Report("RT-427.3",
                    "**https でない `logo_uri`・`policy_uri`・`tos_uri`（`http:`・`javascript:`・`data:`）は、同意の画面に出さない**",
                    "**登録（動的登録・管理画面・構成ファイル）は、絶対 URI であることしか確かめていない**ので、`javascript:` なども入る。"
                    + "**画面に出す側で、https の絶対 URI だけに絞る**（#427 で決めた。登録の振る舞いは変えない）。",
                    "OIDC Registration 1.0 §2 / #427");

                ClientRegistration reg = Flows.InjectedRegistration(client, KnownClients.TestClient_49);

                r.Target("GET /authorize（prompt=consent。client_name=" + KnownClients.TestClient_49
                    + "。logo_uri=http:、policy_uri=javascript:、tos_uri=data:）");

                r.Step("(1) prompt=consent で認可を要求し、同意の画面を開く");

                AuthZResponse authz = await client.AuthorizeAsync(
                    ClientDisplayTests.Parameters(reg, "state-rt42703", "consent"));

                r.Verify("同意の画面が出る", authz.NeedsConsent,
                    "同意の画面", authz.NeedsConsent ? "同意の画面" : "**" + authz.ToString() + "**");

                string html = ClientDisplayTests.Decode(authz.Body);

                r.Verify("出すものが無いので、枠ごと出さない", !html.Contains("id=\"client-display\""),
                    "出さない", html.Contains("id=\"client-display\"") ? "**出した**" : "出さない");

                foreach (KeyValuePair<string, string> item in new Dictionary<string, string>()
                {
                    { "ロゴ（http:）", "id=\"client-logo\"" },
                    { "ポリシー（javascript:）", "id=\"client-policy\"" },
                    { "利用規約（data:）", "id=\"client-tos\"" },
                    { "javascript: の値", "javascript:alert(427)" },
                    { "data: の値", "data:text/html,tos" },
                    { "http: の値", "http://rp.e2e.example/logo.png" }
                })
                {
                    r.Verify(item.Key + "を出さない", !html.Contains(item.Value),
                        "出さない", html.Contains(item.Value) ? "**出した**" : "出さない");
                }

                r.Done();
            }
        }

        #endregion

        #region 部品

        /// <summary>認可コードの要求のパラメタ</summary>
        /// <param name="reg">クライアント</param>
        /// <param name="state">state</param>
        /// <param name="prompt">prompt（null なら付けない）</param>
        /// <returns>パラメタ</returns>
        private static Dictionary<string, string> Parameters(ClientRegistration reg, string state, string prompt)
        {
            Dictionary<string, string> q = new Dictionary<string, string>()
            {
                { "response_type", "code" },
                { "client_id", reg.ClientId },
                { "redirect_uri", reg.RedirectUri },
                { "scope", "openid" },
                { "state", state },
                { "nonce", "nonce-" + state }
            };

            if (prompt != null)
            {
                q.Add("prompt", prompt);
            }

            return q;
        }

        /// <summary>HTML の数値文字参照を戻す（net10.0 版の Razor は非 ASCII を数値文字参照で出す）</summary>
        /// <param name="html">HTML</param>
        /// <returns>戻した HTML</returns>
        private static string Decode(string html)
        {
            return WebUtility.HtmlDecode(html ?? "");
        }

        /// <summary>ロゴ・2 つのリンクが出ていることを確かめる</summary>
        /// <param name="r">TestReport</param>
        /// <param name="html">画面の HTML（戻したもの）</param>
        private static void VerifyShown(TestReport r, string html)
        {
            r.Verify("ロゴが出る（img の src が登録した logo_uri）",
                html.Contains("id=\"client-logo\" src=\"" + ClientDisplayTests.LogoUri + "\""),
                ClientDisplayTests.LogoUri, html.Contains(ClientDisplayTests.LogoUri) ? "出る" : "**出ない**");

            //  **ロゴの画像も、参照元を渡さない**（サインインの画面の URL は、`state` などを含む ReturnUrl を持つ。別モデルのレビューの指摘）。
            r.Verify("ロゴの画像は参照元を渡さない（referrerpolicy=\"no-referrer\"）",
                html.Contains("referrerpolicy=\"no-referrer\""),
                "no-referrer", html.Contains("referrerpolicy=\"no-referrer\"") ? "付いている" : "**付いていない**");

            r.Verify("ポリシーへのリンクが出る（noopener noreferrer）",
                html.Contains("id=\"client-policy\" href=\"" + ClientDisplayTests.PolicyUri + "\" target=\"_blank\" rel=\"noopener noreferrer\""),
                ClientDisplayTests.PolicyUri, html.Contains(ClientDisplayTests.PolicyUri) ? "出る" : "**出ない**");

            r.Verify("利用規約へのリンクが出る（noopener noreferrer）",
                html.Contains("id=\"client-tos\" href=\"" + ClientDisplayTests.TosUri + "\" target=\"_blank\" rel=\"noopener noreferrer\""),
                ClientDisplayTests.TosUri, html.Contains(ClientDisplayTests.TosUri) ? "出る" : "**出ない**");
        }

        #endregion
    }
}
