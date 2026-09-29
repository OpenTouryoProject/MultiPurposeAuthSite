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
//* クラス名        ：MaxAgeTests
//* クラス日本語名  ：RT-247 max_age を超えたときの応答
//*
//* 作成日時        ：－
//* 作成者          ：－
//* 更新履歴        ：－
//*
//*  日時        更新者            内容
//*  ----------  ----------------  -------------------------------------------------
//*  2026/09/28  玄人 幸道         新規（#247）
//*  2026/09/29  玄人 幸道         自己テスト経由の経路（手順 4・5）を追加（#247）
//*  2026/09/29  玄人 幸道         秒単位の判定に合わせ、サインインから 1 秒以上ずらす（#247）
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
    /// RT-247. `max_age` を超えたときに、再認証するか、仕様どおりのエラーを `redirect_uri` へ返す。
    /// </summary>
    /// <remarks>
    /// **以前は、再認証もエラー応答もせず、文面の無いエラー画面になっていた**
    /// （`ANALYSIS-IdP.md` の A-12）。
    /// `CheckAuthTime` が false になると `ValidateAuthZReqParam` を通らないため、
    /// **`valid_redirect_uri` も `err` も空のまま**「ここまで来たらエラー」に落ちていた。
    ///
    /// | 状況 | あるべき応答 | 根拠 |
    /// |---|---|---|
    /// | `max_age` を超えている | **再認証する** | OIDC Core §3.1.2.1 |
    /// | 同上 かつ `prompt=none` | `redirect_uri` へ `login_required` | OIDC Core §3.1.2.6 |
    /// | `max_age` が数値でない | `redirect_uri` へ `invalid_request` | RFC 6749 §4.1.2.1 |
    ///
    /// **検証の順序を入れ替えた**（先に要求を検証し、`redirect_uri` を確定させてから `max_age` を見る）。
    /// **繰り返しを防ぐ印**（`re_auth_at` の Cookie）も入れた。`max_age=0` は再認証の直後でも
    /// 経過時間が 0 を超えるため、印が無いと延々と送り返すことになる。
    /// </remarks>
    public class MaxAgeTests : TargetTestBase
    {
        /// <summary>コンストラクタ</summary>
        /// <param name="output">ITestOutputHelper</param>
        public MaxAgeTests(ITestOutputHelper output) : base(output)
        {
        }

        /// <summary>RT-247.1 max_age を超えていれば再認証へ送る</summary>
        /// <param name="targetKey">core / netfx</param>
        /// <returns>Task</returns>
        [SkippableTheory]
        [MemberData(nameof(AllTargets))]
        public async Task RT24701_max_ageを超えていれば再認証へ送る(string targetKey)
        {
            using (IdPClient client = await this.SignedInClientAsync(targetKey))
            {
                ClientRegistration reg = Flows.Registration(client, KnownClients.TestClient);

                TestReport r = this.Report("RT-247.1",
                    "max_age を超えていれば、エラー画面ではなく再認証へ送る",
                    "**以前は、文面の無いエラー画面だった**（`ANALYSIS-IdP.md` の A-12）。"
                    + "OIDC Core §3.1.2.1 は「経過が `max_age` を超えていれば、"
                    + "**利用者を再認証しなければならない**」としている。"
                    + "**サインイン画面へ送る**（サインアウトして同じ URL に戻すので、認証が要る）。",
                    "OIDC Core §3.1.2.1 / #247");

                r.Target("client_name=" + KnownClients.TestClient + " / max_age=0");

                Dictionary<string, string> form =
                    MaxAgeTests.Parameters(reg, "state-rt2471", maxAge: "0");

                // **秒単位で判定する**ので、サインインから 1 秒以上ずらす（#247）。
                //   `auth_time` も `max_age` も秒単位で、**同じ秒のうちは超過にならない**。
                //   ブラウザで手で操作すれば必ず 1 秒以上経つが、テストは速いので待つ。
                await Task.Delay(1500);

                r.Step("(1) max_age=0（毎回、再認証）で認可リクエストを送る");

                AuthZResponse authz = await client.AuthorizeAsync(form);

                r.Verify("エラー画面ではなく、リダイレクトで返る", authz.Redirected,
                    "リダイレクトする",
                    authz.Redirected ? authz.RedirectTo : "**リダイレクトしない**（" + authz.ToString() + "）");

                Assert.True(authz.Redirected, "前提: リダイレクトで返ること");

                r.Verify("認可コードは発行されない", string.IsNullOrEmpty(authz.Code),
                    "code なし", string.IsNullOrEmpty(authz.Code) ? "なし" : "**発行された**");

                r.Step("(2) その先が、サインイン画面（再認証）であることを確かめる");

                // **一度サインアウトさせ、同じ URL に戻す**ので、その次で認証が要求される。
                HttpResponseMessage again = await client.GetAsync(
                    client.ToLocalUrl(authz.Location));

                string toLogin = (again.Headers.Location == null)
                    ? "" : again.Headers.Location.ToString();

                r.Verify("サインイン画面へ送られる", toLogin.Contains("/Account/Login"),
                    "/Account/Login へ",
                    string.IsNullOrEmpty(toLogin)
                        ? "**移らない**（HTTP " + (int)again.StatusCode + " / "
                            + Html.Describe(await again.Content.ReadAsStringAsync()) + "）"
                        : toLogin);

                r.Step("(3) 再認証すると先へ進む（繰り返しにならない）");

                await client.SignInAsync(force: true);

                // **ここでは待たない。** 再認証の直後（同じ秒）は超過にならないのが期待。
                AuthZResponse after = await client.AuthorizeAsync(form);

                r.Verify("同意画面まで進む（再びサインインへ送られない）", after.NeedsConsent,
                    "同意画面", after.NeedsConsent ? "同意画面" : "**進まない**（" + after.ToString() + "）");

                // **秒単位で判定する**ので、手順 3 のサインインから 1 秒以上ずらす（#247）。
                await Task.Delay(1500);

                r.Step("(4) OIDC のボタンは prompt=none を送るので login_required になる");

                HttpResponseMessage oidc = await client.StartSelfTestAsync(
                    "AuthorizationCode_OIDC", "normal", maxAge: "0");

                string oidcUrl = (oidc.Headers.Location == null)
                    ? "" : client.ToLocalUrl(oidc.Headers.Location.ToString());

                r.Verify("prompt=none が付く（同意画面を飛ばすため）",
                    oidcUrl.Contains("prompt=none"),
                    "prompt=none", oidcUrl.Contains("prompt=none") ? "付いている" : "**付いていない**");

                AuthZResponse viaOidc = await IdPClient.ToAuthZResponseAsync(
                    await client.GetAsync(oidcUrl));

                r.VerifyEqual("login_required が返る（エラー画面ではない）",
                    "login_required", viaOidc.Error ?? "（無し）");

                r.Step("(5) 自己テストのボタン（max_age=0）でも、再認証へ送られることを確かめる");

                // **ブラウザで踏む経路**（starters → /authorize）。
                //   **OIDC のボタンは prompt=none を送る**ので、再認証ではなく login_required になる（手順 4）。
                //   再認証を見るのは、prompt を付けない方のボタン（#247 で実測して分かった）。
                //   **この手順は最後に置く。** 再認証を求めると印（re_auth_at）が残り、
                //   その後の要求は「一度求めた」と見て通るため、順序が意味を持つ。
                HttpResponseMessage started = await client.StartSelfTestAsync(
                    "AuthorizationCode", "normal", maxAge: "0");

                string selfTestUrl = (started.Headers.Location == null)
                    ? "" : client.ToLocalUrl(started.Headers.Location.ToString());

                r.Verify("自己テストが max_age=0 を乗せる", selfTestUrl.Contains("max_age=0"),
                    "max_age=0", string.IsNullOrEmpty(selfTestUrl) ? "**URL が無い**" : selfTestUrl);

                r.Verify("prompt は付かない（このボタンは付けない）",
                    !selfTestUrl.Contains("prompt="),
                    "prompt なし", selfTestUrl.Contains("prompt=") ? "**付いている**" : "付いていない");

                HttpResponseMessage viaSelfTest = await client.GetAsync(selfTestUrl);

                string next = (viaSelfTest.Headers.Location == null)
                    ? "" : viaSelfTest.Headers.Location.ToString();

                r.Verify("自己テスト経由でも、リダイレクトで返る（同じ URL へ）",
                    next.Contains("/authorize"),
                    "/authorize へ",
                    string.IsNullOrEmpty(next)
                        ? "**移らない**（HTTP " + (int)viaSelfTest.StatusCode + " / "
                            + Html.Describe(await viaSelfTest.Content.ReadAsStringAsync()) + "）"
                        : next);

                r.Note("**画面で prompt を選べば、このボタンの prompt=none を上書きできる**（#247 で直した）。"
                    + "**選択と実際が食い違っていた**（`max_age` を選んでも prompt=none のままだった）。");

                r.Note("**再認証を求めた時刻を Cookie（`re_auth_at`）に残している**（#247）。"
                    + "`max_age=0` は再認証の直後でも経過が 0 を超えるため、"
                    + "印が無いと「送る → 認証する → また超過」で戻り続ける。"
                    + "**この手順 (3) が、その繰り返しが起きないことを押さえている。**");

                r.Done();
            }
        }

        /// <summary>RT-247.2 prompt=none なら login_required を返す</summary>
        /// <param name="targetKey">core / netfx</param>
        /// <returns>Task</returns>
        [SkippableTheory]
        [MemberData(nameof(AllTargets))]
        public async Task RT24702_promptがnoneならlogin_requiredを返す(string targetKey)
        {
            using (IdPClient client = await this.SignedInClientAsync(targetKey))
            {
                ClientRegistration reg = Flows.Registration(client, KnownClients.TestClient);

                TestReport r = this.Report("RT-247.2",
                    "max_age を超えていて prompt=none なら、redirect_uri へ login_required を返す",
                    "**UI を出せない指定**（`prompt=none`）で再認証が必要になったときは、"
                    + "**エラーを `redirect_uri` へ返す**のが仕様（OIDC Core §3.1.2.6）。"
                    + "**以前はエラー画面**で、RP はエラーの理由を受け取れなかった。",
                    "OIDC Core §3.1.2.6（login_required）/ #247");

                r.Target("client_name=" + KnownClients.TestClient + " / max_age=0 & prompt=none");

                // **秒単位で判定する**ので、サインインから 1 秒以上ずらす（#247）。
                //   `auth_time` も `max_age` も秒単位で、**同じ秒のうちは超過にならない**。
                //   ブラウザで手で操作すれば必ず 1 秒以上経つが、テストは速いので待つ。
                await Task.Delay(1500);

                r.Step("max_age=0 と prompt=none を付けて認可リクエストを送る");

                Dictionary<string, string> form =
                    MaxAgeTests.Parameters(reg, "state-rt2472", maxAge: "0");
                form["prompt"] = "none";

                AuthZResponse authz = await client.AuthorizeAsync(form);

                r.Verify("エラー画面ではなく、リダイレクトで返る", authz.Redirected,
                    "リダイレクトする",
                    authz.Redirected ? authz.RedirectTo : "**リダイレクトしない**（" + authz.ToString() + "）");

                bool toRp = !string.IsNullOrEmpty(authz.Location)
                    && authz.Location.StartsWith(reg.RedirectUri);

                r.Verify("redirect_uri へ返る", toRp,
                    "登録した redirect_uri へ",
                    string.IsNullOrEmpty(authz.Location) ? "**移らない**" : authz.Location);

                r.VerifyEqual("エラーは login_required", "login_required", authz.Error ?? "（無し）");

                r.VerifyEqual("state が返る", "state-rt2472", authz.State ?? "（無し）");

                r.Verify("認可コードは発行されない", string.IsNullOrEmpty(authz.Code),
                    "code なし", string.IsNullOrEmpty(authz.Code) ? "なし" : "**発行された**");

                r.Done();
            }
        }

        /// <summary>RT-247.3 max_age が数値でなければ invalid_request</summary>
        /// <param name="targetKey">core / netfx</param>
        /// <returns>Task</returns>
        [SkippableTheory]
        [MemberData(nameof(AllTargets))]
        public async Task RT24703_max_ageが数値でなければinvalid_request(string targetKey)
        {
            using (IdPClient client = await this.SignedInClientAsync(targetKey))
            {
                ClientRegistration reg = Flows.Registration(client, KnownClients.TestClient);

                TestReport r = this.Report("RT-247.3",
                    "max_age が数値でなければ、redirect_uri へ invalid_request を返す",
                    "`max_age` は**0 以上の整数**（OIDC Core §3.1.2.1）。"
                    + "**以前は、数値でない値でもエラー画面**になっていた"
                    + "（`CheckAuthTime` が false を返し、そのまま落ちていた）。"
                    + "**不正なパラメタは `invalid_request` として `redirect_uri` へ返す**"
                    + "（RFC 6749 §4.1.2.1）。",
                    "RFC 6749 §4.1.2.1 / OIDC Core §3.1.2.1 / #247");

                r.Target("client_name=" + KnownClients.TestClient + " / max_age=abc");

                r.Step("max_age=abc（数値でない）で認可リクエストを送る");

                AuthZResponse authz = await client.AuthorizeAsync(
                    MaxAgeTests.Parameters(reg, "state-rt2473", maxAge: "abc"));

                r.Verify("エラー画面ではなく、redirect_uri へ返る", authz.Redirected,
                    "リダイレクトする",
                    authz.Redirected ? authz.RedirectTo : "**リダイレクトしない**（" + authz.ToString() + "）");

                r.VerifyEqual("エラーは invalid_request", "invalid_request", authz.Error ?? "（無し）");

                r.Verify("認可コードは発行されない", string.IsNullOrEmpty(authz.Code),
                    "code なし", string.IsNullOrEmpty(authz.Code) ? "なし" : "**発行された**");

                r.Step("（対照）負の値でも同じであることを確かめる");

                AuthZResponse minus = await client.AuthorizeAsync(
                    MaxAgeTests.Parameters(reg, "state-rt2473m", maxAge: "-1"));

                r.VerifyEqual("max_age=-1 も invalid_request",
                    "invalid_request", minus.Error ?? "（無し）");

                r.Done();
            }
        }

        #region 補助

        /// <summary>認可リクエストのパラメタ（OIDC の認可コード）</summary>
        /// <param name="reg">クライアントの登録</param>
        /// <param name="state">state</param>
        /// <param name="maxAge">max_age</param>
        /// <returns>パラメタ</returns>
        private static Dictionary<string, string> Parameters(
            ClientRegistration reg, string state, string maxAge)
        {
            return new Dictionary<string, string>()
            {
                { "client_id", reg.ClientId },
                { "response_type", "code" },
                { "redirect_uri", reg.RedirectUri },
                { "scope", "openid email" },
                { "state", state },
                { "nonce", "nonce-" + state },
                { "max_age", maxAge }
            };
        }

        #endregion
    }
}
