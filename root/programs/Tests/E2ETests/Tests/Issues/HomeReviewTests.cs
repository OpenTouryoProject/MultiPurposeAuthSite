//**********************************************************************************
//* Copyright (C) 2017 Hitachi Solutions,Ltd.
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
//* クラス名        ：HomeReviewTests
//* クラス日本語名  ：RT-294.81 〜 .85 HomeController.*.cs のレビューで見つけた不具合
//*
//* 作成日時        ：－
//* 作成者          ：－
//* 更新履歴        ：－
//*
//*  日時        更新者            内容
//*  ----------  ----------------  -------------------------------------------------
//*  2026/10/31  玄人 幸道         新規（#294）
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
    /// RT-294.81 〜 .85 `HomeController.*.cs`（自己テスト）のレビューで見つけた不具合（#294）。
    /// </summary>
    /// <remarks>
    /// | | 確かめること |
    /// |---|---|
    /// | `RT-294.81` | **自己テストの POST は、AntiForgery トークンが無ければ動かない** |
    /// | `RT-294.82` | **Device AuthZ のポーリングの間隔を、画面から短くできない**（C-56） |
    /// | `RT-294.83` | **自己テストの ROPC は、管理者ではなくテスト利用者でトークンを取る**（C-56） |
    /// | `RT-294.84` | **SPA 向けの PKCE で、response_mode が 2 つ載らない** |
    /// | `RT-294.85` | **画面から来る値は URL 符号化され、別のパラメタを差し込めない** |
    ///
    /// **`IsLockedDownTestEndpoints` で閉じたこと**（C-56）は、**通しでは測れない**（通しは自己テストを開けて回す）。
    /// </remarks>
    public class HomeReviewTests : TargetTestBase
    {
        /// <summary>AntiForgery トークン（画面の hidden）</summary>
        private static readonly Regex TokenRegex = new Regex(
            "name=\"__RequestVerificationToken\"[^>]*value=\"(?<value>[^\"]*)\"", RegexOptions.IgnoreCase);

        /// <summary>ポーリングの結果の画面の「N 秒 × M 回」</summary>
        private static readonly Regex PollRegex = new Regex("(?<sec>\\d+) 秒 × (?<count>\\d+) 回");

        /// <summary>結果の画面が JS に埋める access_token</summary>
        private static readonly Regex AccessTokenRegex = new Regex("token = '(?<value>[^']*)'");

        /// <summary>コンストラクタ</summary>
        /// <param name="output">ITestOutputHelper</param>
        public HomeReviewTests(ITestOutputHelper output) : base(output) { }

        #region RT-294.81

        /// <summary>RT-294.81 自己テストの POST は、AntiForgery トークンが無ければ動かない</summary>
        /// <param name="targetKey">core / netfx</param>
        /// <returns>Task</returns>
        [SkippableTheory]
        [MemberData(nameof(AllTargets))]
        public async Task RT29481_自己テストのPOSTはAntiForgeryトークンが無ければ動かない(string targetKey)
        {
            using (IdPClient client = this.Client(targetKey))
            {
                TestReport r = this.Report("RT-294.81",
                    "/Home/Saml2OAuth2Starters・/Home/DeviceAuthZResponse : AntiForgery トークンの無い POST では動かない",
                    "**画面はトークンを出していたが、アクションが確かめていなかった**（`[ValidateAntiForgeryToken]` が無かった）。"
                    + "**#294 で `/device_verify` に付けたのと同じ種類の抜け**である。",
                    "OWASP CSRF Prevention / #294");

                r.Step("(1) トークンを付けずに、自己テストの開始（認可コード フロー）を送る");

                HttpResponseMessage start = await client.PostFormAsync("/Home/Saml2OAuth2Starters",
                    new Dictionary<string, string>()
                    {
                        { "ClientType", "normal" },
                        { "ClarifyRedirectUri", "true" },
                        { "submit.AuthorizationCode", "AuthorizationCode" }
                    });

                string location = (start.Headers.Location == null) ? "" : start.Headers.Location.ToString();

                r.Verify("**認可エンドポイントへ送られない**", !location.Contains("/authorize"),
                    "送られない", string.IsNullOrEmpty(location) ? "HTTP " + (int)start.StatusCode : "**" + location + "**");

                r.Step("(2) トークンを付けずに、Device AuthZ のポーリングを送る");

                HttpResponseMessage poll = await client.PostFormAsync("/Home/DeviceAuthZResponse",
                    new Dictionary<string, string>()
                    {
                        { "client_id", "dummy" },
                        { "device_code", "dummy" },
                        { "interval", "5" }
                    });

                string body = await poll.Content.ReadAsStringAsync();

                r.Verify("**ポーリングしない**（結果の画面が出ない）", !PollRegex.IsMatch(body),
                    "出ない", PollRegex.IsMatch(body) ? "**出た**" : "HTTP " + (int)poll.StatusCode);

                r.Done();
            }
        }

        #endregion

        #region RT-294.82

        /// <summary>RT-294.82 Device AuthZ のポーリングの間隔を、画面から短くできない</summary>
        /// <param name="targetKey">core / netfx</param>
        /// <returns>Task</returns>
        [SkippableTheory]
        [MemberData(nameof(AllTargets))]
        public async Task RT29482_DeviceAuthZのポーリングの間隔を画面から短くできない(string targetKey)
        {
            using (IdPClient client = this.Client(targetKey))
            {
                TestReport r = this.Report("RT-294.82",
                    "/Home/DeviceAuthZResponse : interval を 1 にして送っても、設定値より短い間隔では問い合わせない",
                    "**interval は画面（hidden）から戻ってくる値**なので、"
                    + "**以前は 1 秒にすれば、60 秒で 60 回、サーバに自分の /token を問い合わせさせられた**（C-56）。",
                    "RFC 8628 §3.5 / #294");

                r.Step("(1) 自己テストの Device AuthZ を始めて、画面（AntiForgery トークン）を得る");

                HttpResponseMessage started = await client.StartSelfTestAsync("DeviceAuthZGrant", "device");
                string html = await started.Content.ReadAsStringAsync();

                Match token = TokenRegex.Match(html);
                Match clientId = new Regex("name=\"client_id\"[^>]*value=\"(?<value>[^\"]*)\"").Match(html);

                Assert.True(token.Success && clientId.Success, "前提: Device AuthZ の画面が出ること");

                r.Step("(2) interval=1・存在しない device_code で、ポーリングを送る（1 回目で終わる）");

                HttpResponseMessage poll = await client.PostFormAsync("/Home/DeviceAuthZResponse",
                    new Dictionary<string, string>()
                    {
                        { "client_id", clientId.Groups["value"].Value },
                        { "device_code", "rt29482-not-a-device-code" },
                        { "interval", "1" },
                        { "__RequestVerificationToken", token.Groups["value"].Value }
                    });

                string body = await poll.Content.ReadAsStringAsync();
                Match m = PollRegex.Match(body);

                Assert.True(m.Success, "前提: ポーリングの結果の画面が出ること（HTTP " + (int)poll.StatusCode + "）");

                int seconds = int.Parse(m.Groups["sec"].Value);

                r.Verify("**間隔は 1 秒にならない**（設定値で頭を押さえる）", 1 < seconds,
                    "1 秒より長い", seconds + " 秒");

                r.Observe("問い合わせた回数", m.Groups["count"].Value + " 回",
                    "存在しない device_code なので、1 回目で終わる。");

                r.Done();
            }
        }

        #endregion

        #region RT-294.83

        /// <summary>RT-294.83 自己テストの ROPC は、管理者ではなくテスト利用者でトークンを取る</summary>
        /// <param name="targetKey">core / netfx</param>
        /// <returns>Task</returns>
        [SkippableTheory]
        [MemberData(nameof(AllTargets))]
        public async Task RT29483_自己テストのROPCはテスト利用者でトークンを取る(string targetKey)
        {
            using (IdPClient client = this.Client(targetKey))
            {
                TestReport r = this.Report("RT-294.83",
                    "/Home/Saml2OAuth2Starters の ROPC : 取ったトークンの sub はテスト利用者",
                    "**以前は管理者（AdministratorUID / AdministratorPWD）でトークンを取り、画面に出していた。**"
                    + "**この POST は匿名で受ける**ので、自己テストの口が開いている間は、"
                    + "**ログインしていない人にも管理者のトークンを見せていた**（C-56）。",
                    "RFC 6749 §4.3 / #294");

                r.Step("(1) ログインせずに、自己テストの ROPC を押す");

                HttpResponseMessage res = await client.StartSelfTestAsync("ResourceOwnerPasswordCredentialsFlow", "normal");
                string html = await res.Content.ReadAsStringAsync();

                Match m = AccessTokenRegex.Match(html);
                string accessToken = m.Success ? m.Groups["value"].Value : "";

                Assert.False(string.IsNullOrEmpty(accessToken), "前提: access_token が返ること（HTTP " + (int)res.StatusCode + "）");

                string sub = Jwt.Payload(accessToken).GetProperty("sub").GetString();

                r.Step("(2) テスト利用者（2 人目）で、同じクライアントから ROPC を直接送り、sub を比べる");

                //   **sub は利用者名ではなく ID** なので、同じ利用者のトークンを取って比べる。
                ClientRegistration reg = Flows.Registration(client, KnownClients.TestClient);

                JsonResponse direct = await client.TokenAsync(new Dictionary<string, string>()
                {
                    { "grant_type", "password" },
                    { "username", TestEnv.SecondUserName(targetKey) },
                    { "password", client.Config.Get("TestUserPWD") },
                    { "scope", "profile" },
                    { "client_id", reg.ClientId },
                    { "client_secret", reg.ClientSecret }
                });

                Assert.False(string.IsNullOrEmpty(direct.AccessToken), "前提: テスト利用者の ROPC が通ること");

                string expected = Jwt.Payload(direct.AccessToken).GetProperty("sub").GetString();

                r.VerifyEqual("**sub はテスト利用者**（" + TestEnv.SecondUserName(targetKey) + "）", expected, sub);

                r.Done();
            }
        }

        #endregion

        #region RT-294.84

        /// <summary>RT-294.84 SPA 向けの PKCE で、response_mode が 2 つ載らない</summary>
        /// <param name="targetKey">core / netfx</param>
        /// <returns>Task</returns>
        [SkippableTheory]
        [MemberData(nameof(AllTargets))]
        public async Task RT29484_SPA向けのPKCEでresponse_modeが2つ載らない(string targetKey)
        {
            using (IdPClient client = this.Client(targetKey))
            {
                TestReport r = this.Report("RT-294.84",
                    "自己テストの PKCE（SPA 向け）: 画面で response_mode を選んでいても、response_mode は fragment の 1 つだけ",
                    "**以前は `&response_mode=fragment` を後から足していた**ので、"
                    + "**画面で選んでいると response_mode が 2 つ載った**（RFC 6749 §3.1 : 同じパラメタを 2 回含めてはならない）。",
                    "RFC 6749 §3.1 / #294");

                r.Step("(1) response_mode=query を選んで、PKCE（S256・SPA 向け）を始める");

                HttpResponseMessage started = await client.StartSelfTestAsync(
                    "PKCE_S256_4SPA", "normal", responseMode: "query");

                Assert.True(started.Headers.Location != null, "前提: 認可エンドポイントへ送られること");

                string url = started.Headers.Location.OriginalString;
                int count = Regex.Matches(url, "[?&]response_mode=").Count;

                r.VerifyEqual("**response_mode は 1 つ**", "1", count.ToString());
                r.Verify("その値は fragment", url.Contains("response_mode=fragment"),
                    "response_mode=fragment", url);

                r.Done();
            }
        }

        #endregion

        #region RT-294.85

        /// <summary>RT-294.85 画面から来る値は URL 符号化され、別のパラメタを差し込めない</summary>
        /// <param name="targetKey">core / netfx</param>
        /// <returns>Task</returns>
        [SkippableTheory]
        [MemberData(nameof(AllTargets))]
        public async Task RT29485_画面から来る値はURL符号化される(string targetKey)
        {
            using (IdPClient client = this.Client(targetKey))
            {
                TestReport r = this.Report("RT-294.85",
                    "自己テストの開始 : prompt に `&` を含めても、別のパラメタにならない（URL 符号化される）",
                    "**以前は画面から来る値（prompt・max_age・response_mode）を符号化せずに連結していた**ので、"
                    + "**`&` を入れると別のパラメタを差し込めた**（自分への要求なので、影響は自己テストの中だけ）。"
                    + "scope・response_type の空白も、そのまま載っていた。",
                    "RFC 6749 Appendix B / RFC 3986 §2.1 / #294");

                r.Step("(1) prompt に `none&rt29485=injected` を入れて、認可コード フローを始める");

                HttpResponseMessage started = await client.StartSelfTestAsync(
                    "AuthorizationCode", "normal", prompt: "none&rt29485=injected");

                Assert.True(started.Headers.Location != null, "前提: 認可エンドポイントへ送られること");

                string url = started.Headers.Location.OriginalString;

                r.Verify("**別のパラメタにならない**", !url.Contains("&rt29485="),
                    "&rt29485= が無い", url.Contains("&rt29485=") ? "**ある**" : "無い");
                r.Verify("prompt の値として符号化されている", url.Contains("prompt=none%26rt29485%3Dinjected"),
                    "prompt=none%26rt29485%3Dinjected", url);
                r.Verify("scope の空白も符号化されている", !url.Contains(" "),
                    "空白が無い", url.Contains(" ") ? "**ある**" : "無い");

                r.Done();
            }
        }

        #endregion
    }
}
