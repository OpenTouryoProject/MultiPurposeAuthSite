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
//* クラス名        ：AccountFlowTests
//* クラス日本語名  ：RT-294.26 〜 .40 メールを使う流れ・失敗の口・自己テスト（AccountController.*.cs の E2E の拡充）
//*
//* 作成日時        ：－
//* 作成者          ：－
//* 更新履歴        ：－
//*
//*  日時        更新者            内容
//*  ----------  ----------------  -------------------------------------------------
//*  2026/10/29  玄人 幸道         新規（#294）
//*  2026/10/30  玄人 幸道         認証デバイスの口を叩くトークンを、認証デバイスのクライアントで取る（#294）
//*  2026/10/30  玄人 幸道         RT-294.38 は自己テストの OIDC の経路で通す（UserInfo が openid の無いトークンを断るようにしたため。#294）
//**********************************************************************************

using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Text.RegularExpressions;
using System.Threading.Tasks;

using MultiPurposeAuthSite.Tests.E2E.Infrastructure;

using Xunit;
using Xunit.Abstractions;

namespace MultiPurposeAuthSite.Tests.E2E.Tests.Issues
{
    /// <summary>
    /// RT-294.26 〜 .40 メールを使う流れ・失敗の口・自己テスト（#294）。
    /// </summary>
    /// <remarks>
    /// **カバレッジ（test.ps1 -Coverage）で、`AccountController` の通っていない所を見て足した。**
    ///
    /// | ケース | 通していなかった理由 |
    /// |---|---|
    /// | RT-294.26 メアドの確認の流れ | **確認のリンクはメールでしか届かない** |
    /// | RT-294.27 パスワードのリセットの流れ | **リセットのリンクはメールでしか届かない** |
    /// | RT-294.28 確認待ちの利用者のサインイン | **確認待ちの利用者でサインインするテストが無かった**（C-33） |
    /// | RT-294.29 コードの 2FA（Email）の成功 | **コードはメールでしか届かない** |
    /// | RT-294.30 外部ログインの戻りの失敗 | **外部プロバイダを動かせない**（失敗の口だけは叩ける。出口は版で違う） |
    /// | RT-294.31 ID 連携の受け口の失敗 | **失敗の口を叩いていなかった** |
    /// | RT-294.32 利用者名の重複でサインアップ | **利用者の作成が失敗する経路**（`AddErrors`）を通していなかった |
    /// | RT-294.33 パラメタ無し・code 違いの確認とリセット | **RT-294.6 / .7 は「利用者が居ない」経路だけ** |
    /// | RT-294.34 リセットのメールの絞り | **画面は変えない**ので、**送信箱でしか数えられない**（C-31） |
    /// | RT-294.35 2FA の途中でない要求（コードの口） | **RT-294.10 は TOTP・回復コードの GET だけ** |
    /// | RT-294.36 2FA のコードの送信の失敗 | **送信の失敗の経路**（#214 の catch）を通していなかった |
    /// | RT-294.37 パスワードのロックアウト | **RT-294.11 は TOTP のロックアウトだけ** |
    /// | RT-294.38 自己テストの結果画面のボタン | **自己テストは結果画面までしか通していなかった** |
    /// | RT-294.39 自己テストの受け口の JARM | **Implicit の受け口は 1 度も叩いていなかった**（叩いたら 500 だった。直した） |
    /// | RT-294.40 プッシュの 2FA の成功 | **RT-213.1 は `/2fa_result` の失敗の口だけ** |
    ///
    /// **メールは送信箱（`MailOutbox`）、プッシュ通知は `FcmOutbox` から読む**（test.ps1 -Launch が、サイトごとに渡す）。
    /// </remarks>
    public class AccountFlowTests : TargetTestBase
    {
        /// <summary>エラー画面の見出し（Views/Shared/Error.cshtml。両アプリ共通）</summary>
        private const string ErrorHeading = "<h2 class=\"text-danger\">";

        /// <summary>外部ログインの失敗の画面の見出し（Views/Account/ExternalLoginFailure.cshtml。両アプリ共通）</summary>
        private const string FailureHeading = "<h3 class=\"text-danger\">";

        /// <summary>ロックアウトの画面の印（Views/Shared/Lockout.cshtml。両アプリ共通。エラー画面には無い）</summary>
        private const string LockoutMarker = "<hgroup>";

        /// <summary>認証サイトが、IsDebug のときに送信を失敗させるドメイン（CmnEmail.FailureDomainForTest）</summary>
        private const string MailFailureDomain = "e2e-mail-failure.invalid";

        /// <summary>メールを待つ長さ</summary>
        private static readonly TimeSpan MailTimeout = TimeSpan.FromSeconds(15);

        /// <summary>コンストラクタ</summary>
        /// <param name="output">ITestOutputHelper</param>
        public AccountFlowTests(ITestOutputHelper output) : base(output)
        {
        }

        /// <summary>RT-294.26 サインアップして、メールの確認のリンクを踏むと、サインインできるようになる</summary>
        /// <param name="targetKey">core / netfx</param>
        /// <returns>Task</returns>
        [SkippableTheory]
        [MemberData(nameof(AllTargets))]
        public async Task RT29426_メアドの確認のリンクを踏むとサインインできる(string targetKey)
        {
            using (IdPClient client = this.Client(targetKey))
            {
                MailOutbox.SkipIfUnavailable(client.Target);

                string userName = AccountFlowTests.UniqueName();
                string email = userName + "@example.com";

                TestReport r = this.Report("RT-294.26",
                    "サインアップして、メールの確認のリンクを踏むと、サインインできるようになる",
                    "**確認のリンクはメールでしか届かない**ので、**この流れは E2E で 1 度も通していなかった**"
                    + "（カバレッジで `EmailConfirmation` が通っていなかった）。"
                    + "**メールの送信箱（`MailOutbox`）から読む。**",
                    "#294（E2E の拡充）");

                r.Target("利用者名 = " + userName);

                try
                {
                    r.Step("(1) サインアップする");

                    Assert.True(await AccountFlowTests.RegisterAsync(client, userName, email), "前提: サインアップできること");

                    r.Verify("確認の前は、サインインできない",
                        !await client.TrySignInAsync(userName, client.Config.Get("TestUserPWD")),
                        "できない", "**できた**");

                    r.Step("(2) 送信箱から、確認のメールを読む");

                    MailOutbox.Message mail = await MailOutbox.WaitForAsync(
                        client.Target, email, "EmailConfirmation", MailTimeout);

                    r.Verify("確認のメールが届く", mail != null, "届く", mail == null ? "**届かない**" : "届いた");
                    Assert.NotNull(mail);

                    string link = MailOutbox.FindUrl(mail, "/Account/EmailConfirmation");
                    Assert.False(string.IsNullOrEmpty(link), "前提: 本文に確認のリンクが在ること");

                    r.Step("(3) リンクを踏む（約款を出す配備なら、同意して送る）");

                    HttpResponseMessage page = await client.GetAsync(client.ToLocalUrl(link));
                    string body = await page.Content.ReadAsStringAsync();

                    if (Html.HasField(body, "AcceptedAgreement"))
                    {
                        Dictionary<string, string> form = Html.HiddenInputs(body);
                        form["AcceptedAgreement"] = "true";

                        page = await client.PostFormAsync("/Account/EmailConfirmation", form);
                        body = await page.Content.ReadAsStringAsync();
                    }

                    r.VerifyEqual("HTTP 200", "200", ((int)page.StatusCode).ToString());
                    r.Verify("**エラー画面にならない**（確認が通る）", !body.Contains(ErrorHeading),
                        "確認の画面", Html.Describe(body));

                    r.Step("(4) サインインする");

                    r.Verify("**確認の後は、サインインできる**",
                        await client.TrySignInAsync(userName, client.Config.Get("TestUserPWD")),
                        "できる", "**できない**");
                }
                finally
                {
                    await AccountFlowTests.CleanUpAsync(this, targetKey, userName);
                }

                r.Done();
            }
        }

        /// <summary>RT-294.27 パスワードの失念のメールのリンクから、パスワードをリセットできる</summary>
        /// <param name="targetKey">core / netfx</param>
        /// <returns>Task</returns>
        [SkippableTheory]
        [MemberData(nameof(AllTargets))]
        public async Task RT29427_パスワードをリセットできる(string targetKey)
        {
            using (IdPClient admin = this.Client(targetKey))
            {
                MailOutbox.SkipIfUnavailable(admin.Target);

                string userName = AccountFlowTests.UniqueName();
                string email = userName + "@example.com";
                string oldPassword = admin.Config.Get("TestUserPWD");
                string newPassword = oldPassword + "9";

                TestReport r = this.Report("RT-294.27",
                    "パスワードの失念のメールのリンクから、パスワードをリセットできる",
                    "**リセットのリンクはメールでしか届かない**ので、**この流れは E2E で 1 度も通していなかった。**"
                    + "**正しい code のときは、画面に利用者のメアドが出る**（C-30 の裏返し）。",
                    "#294（E2E の拡充）");

                r.Target("利用者名 = " + userName + "（管理画面から作る。メアドは確認済み）");

                try
                {
                    await AccountFlowTests.CreateUserAsync(admin, userName, email);

                    using (IdPClient client = this.Client(targetKey))
                    {
                        r.Step("(1) パスワードの失念を送る");

                        await AccountFlowTests.PostForgotPasswordAsync(client, email);

                        r.Step("(2) 送信箱から、リセットのメールを読む");

                        MailOutbox.Message mail = await MailOutbox.WaitForAsync(
                            client.Target, email, "ResetPassword", MailTimeout);

                        r.Verify("リセットのメールが届く", mail != null, "届く", mail == null ? "**届かない**" : "届いた");
                        Assert.NotNull(mail);

                        string link = MailOutbox.FindUrl(mail, "/Account/ResetPassword");
                        Assert.False(string.IsNullOrEmpty(link), "前提: 本文にリセットのリンクが在ること");

                        r.Step("(3) リンクを踏む");

                        HttpResponseMessage page = await client.GetAsync(client.ToLocalUrl(link));
                        string body = await page.Content.ReadAsStringAsync();

                        r.Verify("**リセットの画面が開く**（正しい code）",
                            Html.HasField(body, "Password") && !body.Contains(ErrorHeading),
                            "入力欄が在る", Html.Describe(body));

                        r.Verify("**画面に利用者のメアドが出る**（正しい code のときだけ。C-30）",
                            WebUtility.HtmlDecode(body).Contains(email), "出る", "**出ない**");

                        r.Step("(4) 新しいパスワードを送る");

                        Dictionary<string, string> form = Html.HiddenInputs(body);
                        form["Email"] = email;
                        form["Password"] = newPassword;
                        form["ConfirmPassword"] = newPassword;

                        HttpResponseMessage reset = await client.PostFormAsync(
                            AccountFlowTests.ActionOf(client, body, "/Account/ResetPassword"), form);
                        string resetBody = await reset.Content.ReadAsStringAsync();

                        r.Verify("**完了の画面になる**（入力欄もエラーも無い）",
                            reset.StatusCode == HttpStatusCode.OK && !Html.HasField(resetBody, "ConfirmPassword")
                                && !resetBody.Contains(ErrorHeading),
                            "完了の画面", Html.Describe(resetBody));
                    }

                    using (IdPClient after = this.Client(targetKey))
                    {
                        r.Step("(5) 新しいパスワードでサインインする");

                        r.Verify("**新しいパスワードで入れる**",
                            await after.TrySignInAsync(userName, newPassword), "入れる", "**入れない**");
                    }

                    using (IdPClient before = this.Client(targetKey))
                    {
                        r.Verify("**古いパスワードでは入れない**",
                            !await before.TrySignInAsync(userName, oldPassword), "入れない", "**入れた**");
                    }
                }
                finally
                {
                    await AccountFlowTests.CleanUpAsync(this, targetKey, userName);
                }

                r.Done();
            }
        }

        /// <summary>RT-294.28 確認待ちの利用者は、パスワードが合っても違っても、サインインできない</summary>
        /// <param name="targetKey">core / netfx</param>
        /// <returns>Task</returns>
        [SkippableTheory]
        [MemberData(nameof(AllTargets))]
        public async Task RT29428_確認待ちの利用者はサインインできない(string targetKey)
        {
            using (IdPClient client = this.Client(targetKey))
            {
                string userName = AccountFlowTests.UniqueName();
                string email = userName + "@example.com";
                string password = client.Config.Get("TestUserPWD");

                TestReport r = this.Report("RT-294.28",
                    "確認待ちの利用者は、パスワードが合っても違っても、サインインできない（画面にエラーが出る）",
                    "**確認待ちの利用者でサインインするテストが無かった**（C-33 の経路）。"
                    + "**パスワードが合えば確認のメールを送り直し、違えば利用者が居ないときと同じ応答にする。**",
                    "#294（E2E の拡充 / C-33）");

                r.Target("利用者名 = " + userName + "（サインアップしただけ。確認待ち）");

                try
                {
                    Assert.True(await AccountFlowTests.RegisterAsync(client, userName, email), "前提: サインアップできること");

                    foreach (KeyValuePair<string, string> c in new Dictionary<string, string>()
                    {
                        { "正しいパスワード", password },
                        { "違うパスワード", password + "x" }
                    })
                    {
                        r.Step(c.Key + "でサインインする");

                        HttpResponseMessage post = await AccountFlowTests.PostLoginAsync(client, userName, c.Value);
                        string body = await post.Content.ReadAsStringAsync();

                        r.Verify(c.Key + " : **サインインしない**（画面を出し直し、エラーを出す）",
                            post.StatusCode == HttpStatusCode.OK && Html.HasValidationError(body),
                            "画面＋エラー", "HTTP " + (int)post.StatusCode + " / " + Html.Describe(body));
                    }
                }
                finally
                {
                    await AccountFlowTests.CleanUpAsync(this, targetKey, userName);
                }

                r.Done();
            }
        }

        /// <summary>RT-294.29 コードの 2FA（Email）で、メールのコードを入れるとサインインできる</summary>
        /// <param name="targetKey">core / netfx</param>
        /// <returns>Task</returns>
        [SkippableTheory]
        [MemberData(nameof(AllTargets))]
        public async Task RT29429_メールのコードで2FAを通る(string targetKey)
        {
            using (IdPClient admin = this.Client(targetKey))
            {
                MailOutbox.SkipIfUnavailable(admin.Target);

                string userName = AccountFlowTests.UniqueName();
                string email = userName + "@example.com";

                TestReport r = this.Report("RT-294.29",
                    "コードの 2FA（Email）で、メールのコードを入れるとサインインでき、戻り先へ戻る",
                    "**コードはメールでしか届かない**ので、**コードの 2FA が成功する経路は E2E で通していなかった**"
                    + "（RT-294.13 は、間違ったコードの経路だけ）。",
                    "#294（E2E の拡充）");

                r.Target("利用者名 = " + userName + "（2FA を有効にした使い捨ての利用者）");

                try
                {
                    await AccountFlowTests.CreateUserAsync(admin, userName, email);

                    using (IdPClient user = this.Client(targetKey))
                    {
                        Assert.True(await user.TrySignInAsync(userName, user.Config.Get("TestUserPWD")),
                            "前提: 作った利用者でサインインできること");

                        await AccountFlowTests.EnableTwoFactorAsync(user);
                    }

                    using (IdPClient client = this.Client(targetKey))
                    {
                        string returnUrl = new Uri(client.Target.Url("/Manage/Index")).AbsolutePath;

                        r.Step("(1) パスワードでサインインし、手段に Email を選ぶ");

                        HttpResponseMessage sent = await AccountFlowTests.SelectEmailProviderAsync(client, userName, returnUrl);

                        Assert.True(sent.Headers.Location != null && sent.Headers.Location.ToString().Contains("/Account/VerifyCode"),
                            "前提: コードの入力画面へ送られること");

                        r.Step("(2) 送信箱から、コードを読む");

                        MailOutbox.Message mail = await MailOutbox.WaitForAsync(client.Target, email, null, MailTimeout);
                        string code = (mail == null) ? null : MailOutbox.FindCode(mail);

                        r.Verify("コードのメールが届く", !string.IsNullOrEmpty(code), "届く", mail == null ? "**届かない**" : "届いた");
                        Assert.False(string.IsNullOrEmpty(code), "前提: コードを読めること");

                        r.Step("(3) コードを入れる");

                        HttpResponseMessage verify = await client.GetAsync(AccountFlowTests.Resolve(client, sent.Headers.Location));
                        string verifyBody = await verify.Content.ReadAsStringAsync();

                        Dictionary<string, string> form = Html.HiddenInputs(verifyBody);
                        form["Code"] = code;

                        HttpResponseMessage ok = await client.PostFormAsync(
                            AccountFlowTests.ActionOf(client, verifyBody, "/Account/VerifyCode"), form);

                        string location = (ok.Headers.Location == null) ? null : ok.Headers.Location.ToString();

                        r.Verify("**戻り先へリダイレクトする**（サインインできた）",
                            location != null && location.Split('?')[0].EndsWith(returnUrl, StringComparison.OrdinalIgnoreCase),
                            returnUrl, location ?? ("HTTP " + (int)ok.StatusCode));

                        bool authTime = client.CookieNames.Any(n => n.EndsWith("auth_time", StringComparison.Ordinal));

                        r.Verify("`auth_time` の Cookie が書かれている（セッションの初期化）",
                            authTime, "在る", authTime ? "在る" : "**無い**");
                    }
                }
                finally
                {
                    await AccountFlowTests.CleanUpAsync(this, targetKey, userName);
                }

                r.Done();
            }
        }

        /// <summary>RT-294.30 外部ログインの戻りの口は、失敗を 500 にせず、サインインもしない</summary>
        /// <param name="targetKey">core / netfx</param>
        /// <returns>Task</returns>
        [SkippableTheory]
        [MemberData(nameof(AllTargets))]
        public async Task RT29430_外部ログインの戻りの失敗は500にしない(string targetKey)
        {
            using (IdPClient client = this.Client(targetKey))
            {
                TestReport r = this.Report("RT-294.30",
                    "外部ログインの戻りの口（ExternalLoginCallback）は、失敗を 500 にせず、サインインもしない",
                    "**外部プロバイダ（Google など）は E2E で動かせない**ので、**この口は 1 度も叩いていなかった。**"
                    + "**失敗の口だけは叩ける**（プロバイダのエラー、外部ログインの Cookie が無い）。",
                    "#294（E2E の拡充）");

                foreach (string path in new string[] {
                    "/Account/ExternalLoginCallback?remoteError=access_denied",
                    "/Account/ExternalLoginCallback" })
                {
                    r.Step("GET " + path);

                    HttpResponseMessage res = await client.GetAsync(path);
                    string body = await res.Content.ReadAsStringAsync();
                    string location = (res.Headers.Location == null) ? "" : res.Headers.Location.ToString();

                    //  **出口は版で違う**（net10.0 : サインイン画面へ戻す、net48 : 失敗の画面）。
                    //    どちらも「500 にせず、サインインしない」ので、どちらでもよい。
                    bool toLogin = location.Contains("/Account/Login");
                    bool failureView = res.StatusCode == HttpStatusCode.OK && body.Contains(FailureHeading);

                    r.Verify(path + " : **サインイン画面へ戻すか、失敗の画面を出す**（500 にしない）",
                        toLogin || failureView,
                        "/Account/Login へ / 失敗の画面",
                        string.IsNullOrEmpty(location) ? "HTTP " + (int)res.StatusCode + " / " + Html.Describe(body) : location);
                }

                HttpResponseMessage manage = await client.GetAsync("/Manage/Index");

                r.Verify("**サインインしていない**（保護された画面は開かない）",
                    manage.StatusCode != HttpStatusCode.OK, "開かない", "HTTP " + (int)manage.StatusCode);

                r.Done();
            }
        }

        /// <summary>RT-294.31 ID 連携の受け口は、連携を始めていない要求をエラー画面で断る（500 にしない）</summary>
        /// <param name="targetKey">core / netfx</param>
        /// <returns>Task</returns>
        [SkippableTheory]
        [MemberData(nameof(AllTargets))]
        public async Task RT29431_ID連携の受け口は始めていない要求を断る(string targetKey)
        {
            using (IdPClient client = this.Client(targetKey))
            {
                TestReport r = this.Report("RT-294.31",
                    "ID 連携の受け口（OIDC の Redirect エンドポイント・SAML2 の ACS）は、連携を始めていない要求をエラー画面で断る",
                    "**受け口の失敗の経路を叩いていなかった。**"
                    + "**連携を始めた記録（セッションの state・上流）が無ければ、上流の応答を受け取らない。**",
                    "#294（E2E の拡充）/ #253");

                foreach (string path in new string[] {
                    "/Account/IDFederationRedirectEndPoint?code=dummy&state=dummy",
                    "/Account/IDFederationRedirectEndPoint?error=access_denied&state=dummy",
                    "/Account/IDFederationAssertionConsumerService?SAMLResponse=dummy&RelayState=dummy" })
                {
                    r.Step("GET " + path);

                    HttpResponseMessage res = await client.GetAsync(path);
                    string body = await res.Content.ReadAsStringAsync();

                    r.VerifyEqual(path + " : HTTP 200（500 にならない）", "200", ((int)res.StatusCode).ToString());

                    r.Verify(path + " : **エラー画面になる**（サインインしない）",
                        body.Contains(ErrorHeading), "エラー画面", Html.Describe(body));
                }

                HttpResponseMessage manage = await client.GetAsync("/Manage/Index");

                r.Verify("**サインインしていない**（保護された画面は開かない）",
                    manage.StatusCode != HttpStatusCode.OK, "開かない", "HTTP " + (int)manage.StatusCode);

                r.Done();
            }
        }

        /// <summary>RT-294.32 使われている利用者名でサインアップすると、画面にエラーを出し、作らない</summary>
        /// <param name="targetKey">core / netfx</param>
        /// <returns>Task</returns>
        [SkippableTheory]
        [MemberData(nameof(AllTargets))]
        public async Task RT29432_使われている利用者名ではサインアップできない(string targetKey)
        {
            using (IdPClient client = this.Client(targetKey))
            {
                string userName = AccountFlowTests.UniqueName();
                string email = userName + "@example.com";
                string otherEmail = AccountFlowTests.UniqueName() + "@example.com";

                TestReport r = this.Report("RT-294.32",
                    "既に使われている利用者名でサインアップすると、画面にエラーを出し、利用者を作らない",
                    "**利用者の作成（`CreateAsync`）が失敗する経路を通していなかった**（`AddErrors` が 1 度も通っていなかった）。"
                    + "**確認待ちのメアドの登録し直し（RT-294.4）とは別の経路である**（利用者名の重複は、作成で断られる）。",
                    "#294（E2E の拡充）");

                r.Target("利用者名 = " + userName + "（サインアップ済み）に、別のメアドでもう一度");

                try
                {
                    Assert.True(await AccountFlowTests.RegisterAsync(client, userName, email), "前提: サインアップできること");

                    using (IdPClient other = this.Client(targetKey))
                    {
                        r.Step("同じ利用者名・別のメアドでサインアップする");

                        HttpResponseMessage post = await AccountFlowTests.PostRegisterAsync(other, userName, otherEmail);
                        string body = await post.Content.ReadAsStringAsync();

                        r.Verify("**サインアップの画面を出し直し、エラーを出す**",
                            post.StatusCode == HttpStatusCode.OK && Html.HasField(body, "ConfirmPassword")
                                && Html.HasValidationError(body),
                            "画面＋エラー", "HTTP " + (int)post.StatusCode + " / " + Html.Describe(body));
                    }

                    using (IdPClient admin = this.Client(targetKey))
                    {
                        await admin.SignInAsAdministratorAsync();
                        string index = await UsersAdmin.SkipIfLockedDownAsync(admin);

                        r.VerifyEqual("**先の利用者のメアドは変わらない**", email,
                            UsersAdmin.FindEmail(index, userName));

                        r.Verify("**別のメアドの利用者は作られない**",
                            !WebUtility.HtmlDecode(index).Contains(otherEmail), "居ない", "**居る**");
                    }
                }
                finally
                {
                    await AccountFlowTests.CleanUpAsync(this, targetKey, userName);
                }

                r.Done();
            }
        }

        /// <summary>RT-294.33 メアドの確認・リセットは、パラメタが無い・code が違えば、通さない</summary>
        /// <param name="targetKey">core / netfx</param>
        /// <returns>Task</returns>
        [SkippableTheory]
        [MemberData(nameof(AllTargets))]
        public async Task RT29433_パラメタが無いかcodeが違えば確認もリセットも通さない(string targetKey)
        {
            using (IdPClient admin = this.Client(targetKey))
            {
                string userName = AccountFlowTests.UniqueName();
                string email = userName + "@example.com";
                string password = admin.Config.Get("TestUserPWD");
                string newPassword = password + "9";

                TestReport r = this.Report("RT-294.33",
                    "メアドの確認・パスワードのリセットは、パラメタが無い・code が違えば、通さない（パスワードは変わらない）",
                    "**RT-294.6 / .7 は「利用者が居ない」経路だけ**で、"
                    + "**パラメタが無い・code が違う・入力が合わない経路は通していなかった。**",
                    "#294（E2E の拡充）");

                r.Target("利用者名 = " + userName + "（管理画面から作る。メアドは確認済み）");

                try
                {
                    string userId = await AccountFlowTests.CreateUserAsync(admin, userName, email);

                    using (IdPClient client = this.Client(targetKey))
                    {
                        foreach (string path in new string[] {
                            "/Account/EmailConfirmation",
                            "/Account/EmailConfirmation?userId=" + Uri.EscapeDataString(userId) + "&code=bogus",
                            "/Account/ResetPassword" })
                        {
                            r.Step("GET " + path);

                            HttpResponseMessage res = await client.GetAsync(path);
                            string body = await res.Content.ReadAsStringAsync();

                            r.VerifyEqual(path + " : HTTP 200（500 にならない）", "200", ((int)res.StatusCode).ToString());
                            r.Verify(path + " : **エラー画面になる**", body.Contains(ErrorHeading), "エラー画面", Html.Describe(body));
                        }

                        HttpResponseMessage page = await client.GetAsync("/Account/ForgotPassword");
                        string token = Html.Antiforgery(await page.Content.ReadAsStringAsync());

                        foreach (KeyValuePair<string, string[]> c in new Dictionary<string, string[]>()
                        {
                            { "code が違う", new string[] { "bogus", newPassword } },
                            { "確認の入力が合わない", new string[] { "bogus", newPassword + "x" } }
                        })
                        {
                            r.Step("POST /Account/ResetPassword（" + c.Key + "）");

                            HttpResponseMessage post = await client.PostFormAsync("/Account/ResetPassword",
                                new Dictionary<string, string>()
                                {
                                    { "__RequestVerificationToken", token },
                                    { "UserId", userId },
                                    { "Email", email },
                                    { "Code", c.Value[0] },
                                    { "Password", newPassword },
                                    { "ConfirmPassword", c.Value[1] }
                                });
                            string body = await post.Content.ReadAsStringAsync();

                            r.Verify(c.Key + " : **リセットの画面を出し直し、エラーを出す**",
                                post.StatusCode == HttpStatusCode.OK && Html.HasField(body, "ConfirmPassword")
                                    && Html.HasValidationError(body),
                                "画面＋エラー", "HTTP " + (int)post.StatusCode + " / " + Html.Describe(body));
                        }
                    }

                    using (IdPClient after = this.Client(targetKey))
                    {
                        r.Verify("**パスワードは変わらない**（元のパスワードで入れる）",
                            await after.TrySignInAsync(userName, password), "入れる", "**入れない**");
                    }
                }
                finally
                {
                    await AccountFlowTests.CleanUpAsync(this, targetKey, userName);
                }

                r.Done();
            }
        }

        /// <summary>RT-294.34 パスワードの失念を続けて送っても、リセットのメールは 1 通だけ</summary>
        /// <param name="targetKey">core / netfx</param>
        /// <returns>Task</returns>
        [SkippableTheory]
        [MemberData(nameof(AllTargets))]
        public async Task RT29434_リセットのメールは続けて送らない(string targetKey)
        {
            using (IdPClient admin = this.Client(targetKey))
            {
                MailOutbox.SkipIfUnavailable(admin.Target);

                Skip.If(AccountFlowTests.SettingOf(admin, "MailResendIntervalSeconds", 0) <= 0,
                    "MailResendIntervalSeconds が設定されていません（絞らない配備）。");

                string userName = AccountFlowTests.UniqueName();
                string email = userName + "@example.com";

                TestReport r = this.Report("RT-294.34",
                    "パスワードの失念を続けて送っても、リセットのメールは 1 通だけ（画面は同じ）",
                    "**`MailResendIntervalSeconds` の絞り（C-31）を、パスワードの失念で確かめていなかった**"
                    + "（`SendConfirmEmailForPasswordReset` の絞りの分岐が通っていなかった）。"
                    + "**画面は変えない**ので、**数えられるのは送信箱だけ**である。",
                    "#294（E2E の拡充 / C-31）");

                r.Target("利用者名 = " + userName + "（管理画面から作る）");

                try
                {
                    await AccountFlowTests.CreateUserAsync(admin, userName, email);

                    for (int i = 1; i <= 2; i++)
                    {
                        using (IdPClient client = this.Client(targetKey))
                        {
                            r.Step("(" + i + ") パスワードの失念を送る");

                            HttpResponseMessage post = await AccountFlowTests.PostForgotPasswordAsync(client, email);
                            string body = await post.Content.ReadAsStringAsync();

                            r.Verify("(" + i + ") **確認の画面になる**（入力欄もエラーも無い）",
                                post.StatusCode == HttpStatusCode.OK && !Html.HasField(body, "Email")
                                    && !body.Contains(ErrorHeading),
                                "確認の画面", Html.Describe(body));
                        }

                        if (i == 1)
                        {
                            Assert.NotNull(await MailOutbox.WaitForAsync(
                                admin.Target, email, "/Account/ResetPassword", MailTimeout));
                        }
                    }

                    //  **送信は要求から切り離してある**ので、2 通目が来るなら来るだけの間を置いてから数える。
                    await Task.Delay(TimeSpan.FromSeconds(3));

                    int count = MailOutbox.Count(admin.Target, email, "/Account/ResetPassword");

                    r.VerifyEqual("**リセットのメールは 1 通だけ**", "1", count.ToString());
                }
                finally
                {
                    await AccountFlowTests.CleanUpAsync(this, targetKey, userName);
                }

                r.Done();
            }
        }

        /// <summary>RT-294.35 2FA の途中でなければ、コードの 2FA の口は通さない</summary>
        /// <param name="targetKey">core / netfx</param>
        /// <returns>Task</returns>
        [SkippableTheory]
        [MemberData(nameof(AllTargets))]
        public async Task RT29435_2FAの途中でなければコードの口は通さない(string targetKey)
        {
            using (IdPClient client = this.Client(targetKey))
            {
                TestReport r = this.Report("RT-294.35",
                    "2FA の途中でなければ、コードの 2FA の口（手段の選択・コードの入力・プッシュの状態）は通さない",
                    "**RT-294.10 は TOTP・回復コードの画面（GET）だけ**で、"
                    + "**コードの 2FA の口と、POST・プッシュの状態の口は、2FA の途中でない要求を通していなかった。**",
                    "#294（E2E の拡充）");

                r.Target("サインインしていないブラウザ");

                foreach (string path in new string[] {
                    "/Account/SendCode?rememberMe=false",
                    "/Account/VerifyCode?provider=Email&rememberMe=false&rememberBrowser=false" })
                {
                    r.Step("GET " + path);

                    HttpResponseMessage res = await client.GetAsync(path);
                    string body = await res.Content.ReadAsStringAsync();

                    r.VerifyEqual(path + " : HTTP 200", "200", ((int)res.StatusCode).ToString());
                    r.Verify(path + " : **エラー画面になる**", body.Contains(ErrorHeading), "エラー画面", Html.Describe(body));
                }

                HttpResponseMessage login = await client.GetAsync("/Account/Login");
                string token = Html.Antiforgery(await login.Content.ReadAsStringAsync());

                r.Step("POST /Account/SendCode");

                HttpResponseMessage send = await client.PostFormAsync("/Account/SendCode", new Dictionary<string, string>()
                {
                    { "__RequestVerificationToken", token },
                    { "SelectedProvider", "Email" },
                    { "ReturnUrl", "" },
                    { "RememberMe", "false" }
                });
                string sendBody = await send.Content.ReadAsStringAsync();

                r.Verify("POST /Account/SendCode : **エラー画面になる**（コードを送らない）",
                    send.StatusCode == HttpStatusCode.OK && sendBody.Contains(ErrorHeading),
                    "エラー画面", "HTTP " + (int)send.StatusCode + " / " + Html.Describe(sendBody));

                r.Step("POST /Account/VerifyCode");

                HttpResponseMessage verify = await client.PostFormAsync("/Account/VerifyCode", new Dictionary<string, string>()
                {
                    { "__RequestVerificationToken", token },
                    { "Provider", "Email" },
                    { "Code", "123456" },
                    { "ReturnUrl", "" },
                    { "RememberMe", "false" },
                    { "RememberBrowser", "false" }
                });

                r.Verify("POST /Account/VerifyCode : **リダイレクトしない**（サインインしない）",
                    verify.StatusCode == HttpStatusCode.OK, "HTTP 200",
                    "HTTP " + (int)verify.StatusCode + " " + verify.Headers.Location);

                r.Step("GET /Account/TwoFactorPushStatus");

                HttpResponseMessage push = await client.GetAsync(
                    "/Account/TwoFactorPushStatus?rememberMe=false&rememberBrowser=false");
                string pushBody = (await push.Content.ReadAsStringAsync()).Replace(" ", "");

                r.Verify("GET /Account/TwoFactorPushStatus : **承認されていない**（`approved` が false）",
                    push.StatusCode == HttpStatusCode.OK && pushBody.Contains("\"approved\":false"),
                    "{\"approved\":false}", "HTTP " + (int)push.StatusCode + " / " + pushBody);

                if (targetKey == TestEnv.CoreKey)
                {
                    //  **TOTP・回復コードは、net10.0 版だけ**（RT-294.10 と同じ）。
                    foreach (KeyValuePair<string, Dictionary<string, string>> c in new Dictionary<string, Dictionary<string, string>>()
                    {
                        { "/Account/LoginWithTwoFactorAuthenticator?rememberMe=false",
                            new Dictionary<string, string>() { { "TwoFactorCode", "000000" }, { "RememberMachine", "false" } } },
                        { "/Account/LoginWithTwoFactorAuthenticatorRecoveryCode",
                            new Dictionary<string, string>() { { "RecoveryCode", "bogus-code" } } }
                    })
                    {
                        r.Step("POST " + c.Key);

                        c.Value["__RequestVerificationToken"] = token;

                        HttpResponseMessage res = await client.PostFormAsync(c.Key, c.Value);
                        string body = await res.Content.ReadAsStringAsync();

                        r.Verify("POST " + c.Key + " : **エラー画面になる**",
                            res.StatusCode == HttpStatusCode.OK && body.Contains(ErrorHeading) && !body.Contains(LockoutMarker),
                            "エラー画面", "HTTP " + (int)res.StatusCode + " / " + Html.Describe(body));
                    }
                }

                HttpResponseMessage manage = await client.GetAsync("/Manage/Index");

                r.Verify("**サインインしていない**（保護された画面は開かない）",
                    manage.StatusCode != HttpStatusCode.OK, "開かない", "HTTP " + (int)manage.StatusCode);

                r.Done();
            }
        }

        /// <summary>RT-294.36 2FA のコードのメールが送れなければ、手段の選択の画面に文言を出す</summary>
        /// <param name="targetKey">core / netfx</param>
        /// <returns>Task</returns>
        [SkippableTheory]
        [MemberData(nameof(AllTargets))]
        public async Task RT29436_2FAのコードを送れなければ選び直しになる(string targetKey)
        {
            using (IdPClient admin = this.Client(targetKey))
            {
                string userName = AccountFlowTests.UniqueName();

                //  **このドメイン宛ては、IsDebug のサイトが送信を失敗させる**（RT-294.14 と同じ）。
                string email = userName + "@" + MailFailureDomain;

                TestReport r = this.Report("RT-294.36",
                    "2FA のコードのメールが送れなければ、手段の選択の画面を出し直し、文言を出す（500 にしない）",
                    "**コードの送信に失敗する経路（#214 の catch）を通していなかった。**"
                    + "**送信の失敗は、IsDebug のサイトが特定のドメイン宛てで起こす**（RT-294.14 と同じ）。",
                    "#294（E2E の拡充）/ #214");

                r.Target("利用者名 = " + userName + " / メアド = 送信が失敗するドメイン（" + MailFailureDomain + "）");

                try
                {
                    await AccountFlowTests.CreateUserAsync(admin, userName, email);

                    using (IdPClient user = this.Client(targetKey))
                    {
                        Assert.True(await user.TrySignInAsync(userName, user.Config.Get("TestUserPWD")),
                            "前提: 作った利用者でサインインできること");

                        await AccountFlowTests.EnableTwoFactorAsync(user);
                    }

                    using (IdPClient client = this.Client(targetKey))
                    {
                        r.Step("パスワードでサインインし、手段に Email を選ぶ");

                        HttpResponseMessage sent = await AccountFlowTests.SelectEmailProviderAsync(client, userName, null);
                        string body = await sent.Content.ReadAsStringAsync();

                        r.Verify("**手段の選択の画面を出し直し、文言を出す**（コードの入力へ進まない）",
                            sent.StatusCode == HttpStatusCode.OK && Html.HasField(body, "SelectedProvider")
                                && Html.HasValidationError(body),
                            "画面＋文言", "HTTP " + (int)sent.StatusCode + " " + sent.Headers.Location + " / " + Html.Describe(body));
                    }
                }
                finally
                {
                    await AccountFlowTests.CleanUpAsync(this, targetKey, userName);
                }

                r.Done();
            }
        }

        /// <summary>RT-294.37 パスワードを続けて間違えると、ロックアウトの画面になる（確認済み・確認待ちとも）</summary>
        /// <param name="targetKey">core / netfx</param>
        /// <returns>Task</returns>
        [SkippableTheory]
        [MemberData(nameof(AllTargets))]
        public async Task RT29437_パスワードを続けて間違えるとロックアウトになる(string targetKey)
        {
            using (IdPClient admin = this.Client(targetKey))
            {
                //  **上限は配備で違う**（test.ps1 -Launch は 20 回にしている。共用の利用者で、わざと間違えるケースがあるため）。
                int max = AccountFlowTests.SettingOf(admin, "MaxFailedAccessAttemptsBeforeLockout", 0);

                Skip.If(max <= 0 || 50 < max,
                    "MaxFailedAccessAttemptsBeforeLockout が " + max + " で、測れません（0 は数えない配備）。");

                string confirmed = AccountFlowTests.UniqueName();
                string pending = AccountFlowTests.UniqueName();
                string password = admin.Config.Get("TestUserPWD");

                TestReport r = this.Report("RT-294.37",
                    "パスワードを続けて間違えると、ロックアウトの画面になり、正しいパスワードでも入れない（確認済み・確認待ちとも）",
                    "**パスワードのサインインでロックアウトする経路を通していなかった**（RT-294.11 は TOTP）。"
                    + "**確認待ちの利用者は、別の経路で失敗を数える**（C-33。`AccessFailedAsync`）。"
                    + "**確認待ちは、上限に達した次の要求でロックアウトの画面になる**（確認済みは、達した要求で）。",
                    "#294（E2E の拡充 / C-33）");

                r.Target("利用者名 = " + confirmed + "（確認済み）/ " + pending + "（確認待ち）");

                try
                {
                    await AccountFlowTests.CreateUserAsync(admin, confirmed, confirmed + "@example.com");

                    using (IdPClient signup = this.Client(targetKey))
                    {
                        Assert.True(await AccountFlowTests.RegisterAsync(signup, pending, pending + "@example.com"),
                            "前提: サインアップできること");
                    }

                    foreach (KeyValuePair<string, string> c in new Dictionary<string, string>()
                    {
                        { "確認済み", confirmed },
                        { "確認待ち", pending }
                    })
                    {
                        using (IdPClient client = this.Client(targetKey))
                        {
                            r.Step(c.Key + " : ロックアウトするまで、違うパスワードを送る（上限 " + max + " 回 ＋ 1）");

                            int tries = 0;
                            bool lockedOut = false;
                            string last = null;

                            while (tries <= max && !lockedOut)
                            {
                                tries++;

                                HttpResponseMessage post = await AccountFlowTests.PostLoginAsync(client, c.Value, password + "x");
                                string body = await post.Content.ReadAsStringAsync();

                                Assert.True(post.StatusCode == HttpStatusCode.OK,
                                    "前提: 違うパスワードでは画面が返ること（HTTP " + (int)post.StatusCode + "）");

                                lockedOut = body.Contains(LockoutMarker);
                                last = body;
                            }

                            Skip.IfNot(lockedOut,
                                c.Key + " : " + (max + 1) + " 回間違えてもロックアウトしません（UserLockoutEnabledByDefault を確認）: "
                                + Html.ErrorSummary(last) + " / " + Html.Describe(last));

                            r.Verify(c.Key + " : **ロックアウトの画面になる**", lockedOut,
                                "ロックアウトの画面", "ロックアウトの画面（" + tries + " 回目）");

                            HttpResponseMessage right = await AccountFlowTests.PostLoginAsync(client, c.Value, password);
                            string rightBody = await right.Content.ReadAsStringAsync();

                            r.Verify(c.Key + " : **正しいパスワードでも、ロックアウトの画面になる**",
                                right.StatusCode == HttpStatusCode.OK && rightBody.Contains(LockoutMarker),
                                "ロックアウトの画面", "HTTP " + (int)right.StatusCode + " " + right.Headers.Location + " / " + Html.Describe(rightBody));
                        }
                    }
                }
                finally
                {
                    await AccountFlowTests.CleanUpAsync(this, targetKey, confirmed);
                    await AccountFlowTests.CleanUpAsync(this, targetKey, pending);
                }

                r.Done();
            }
        }

        /// <summary>RT-294.38 自己テストの結果画面のボタン（UserInfo・更新・取り消し・照会）が動く</summary>
        /// <param name="targetKey">core / netfx</param>
        /// <returns>Task</returns>
        [SkippableTheory]
        [MemberData(nameof(AllTargets))]
        public async Task RT29438_自己テストの結果画面のボタンが動く(string targetKey)
        {
            using (IdPClient client = this.Client(targetKey))
            {
                TestReport r = this.Report("RT-294.38",
                    "自己テストの結果画面のボタン（UserInfo・リフレッシュ・照会・取り消し）が動き、取り消したトークンは照会で無効になる",
                    "**自己テストは結果画面までしか通していなかった**（`OAuth2AuthorizationCodeGrantClient2` が 1 度も通っていなかった）。"
                    + "**画面のボタンは、トークン・UserInfo・照会・取り消しの各エンドポイントを、サイト自身が叩く。**",
                    "#294（E2E の拡充）");

                await client.SignInAsync();

                r.Target("自己テスト : Authorization Code Flow → 結果画面のボタン");

                r.Step("(1) 自己テストを通し、結果画面まで進む");

                //  **OIDC の経路で通す**（#294）。**UserInfo ボタンは、openid の無いトークンでは 403 になる**
                //    （OAuth2 の経路の `SelfTestScopes` には openid が無い）。
                HttpResponseMessage starter = await client.StartSelfTestAsync("AuthorizationCode_OIDC", "normal");
                string authorizeUrl = (starter.Headers.Location == null) ? null : starter.Headers.Location.OriginalString;

                Skip.If(string.IsNullOrEmpty(authorizeUrl),
                    "自己テストが認可リクエストへ飛びません（HTTP " + (int)starter.StatusCode + "。IsLockedDownTestEndpoints を確認）。");

                AuthZResponse authz = await client.AuthorizeAndGrantAsync(client.ToLocalUrl(authorizeUrl));
                Assert.False(string.IsNullOrEmpty(authz.Code), "前提: 認可コードが返ること（" + authz.ToString() + "）");

                HttpResponseMessage screen = await client.GetAsync(authz.Location);
                string html = await screen.Content.ReadAsStringAsync();

                string accessToken = Html.FieldValue(html, "AccessToken");
                string refreshToken = Html.FieldValue(html, "RefreshToken");

                Assert.False(string.IsNullOrEmpty(accessToken), "前提: 結果画面に access_token が出ること");
                Assert.False(string.IsNullOrEmpty(refreshToken), "前提: 結果画面に refresh_token が出ること");

                //  **ボタンを押す**（画面の値をそのまま送る。応答は画面の Response 欄に出る）。
                Func<string, Task<string>> press = async (button) =>
                {
                    r.Step("「" + button + "」を押す");

                    HttpResponseMessage res = await client.PostFormAsync("/Account/OAuth2AuthorizationCodeGrantClient2",
                        new Dictionary<string, string>()
                        {
                            { "__RequestVerificationToken", Html.Antiforgery(html) },
                            { "ClientId", Html.FieldValue(html, "ClientId") },
                            { "State", Html.FieldValue(html, "State") },
                            { "Code", Html.FieldValue(html, "Code") },
                            { "AccessToken", Html.FieldValue(html, "AccessToken") },
                            { "IdToken", Html.FieldValue(html, "IdToken") ?? "" },
                            { "RefreshToken", Html.FieldValue(html, "RefreshToken") },
                            { "submit." + button, button }
                        });

                    html = await res.Content.ReadAsStringAsync();

                    Assert.True(res.StatusCode == HttpStatusCode.OK && !html.Contains(ErrorHeading),
                        "前提: 結果画面が返ること（HTTP " + (int)res.StatusCode + " / " + Html.Describe(html) + "）");

                    return AccountFlowTests.TextAreaValue(html, "Response").Replace(" ", "").Replace("\r", "").Replace("\n", "");
                };

                string userInfo = await press("GetUserClaims");
                r.Verify("UserInfo : **`sub` が返る**", userInfo.Contains("\"sub\""), "sub あり", AccountFlowTests.Brief(userInfo));

                string introspected = await press("IntrospectAccess");
                r.Verify("照会（access_token）: **有効**", introspected.Contains("\"active\":true"),
                    "active=true", AccountFlowTests.Brief(introspected));

                string refreshed = await press("Refresh");
                string newAccessToken = Html.FieldValue(html, "AccessToken");

                r.Verify("リフレッシュ : **新しい access_token が画面に出る**",
                    refreshed.Contains("access_token") && !string.IsNullOrEmpty(newAccessToken) && newAccessToken != accessToken,
                    "新しい access_token", AccountFlowTests.Brief(refreshed));

                string introspectedRefresh = await press("IntrospectRefresh");
                r.Verify("照会（refresh_token）: **有効**", introspectedRefresh.Contains("\"active\":true"),
                    "active=true", AccountFlowTests.Brief(introspectedRefresh));

                await press("RevokeAccess");
                string revokedAccess = await press("IntrospectAccess");
                r.Verify("**取り消した access_token は、照会で無効**", revokedAccess.Contains("\"active\":false"),
                    "active=false", AccountFlowTests.Brief(revokedAccess));

                await press("RevokeRefresh");
                string revokedRefresh = await press("IntrospectRefresh");
                r.Verify("**取り消した refresh_token は、照会で無効**", revokedRefresh.Contains("\"active\":false"),
                    "active=false", AccountFlowTests.Brief(revokedRefresh));

                r.Done();
            }
        }

        /// <summary>RT-294.39 自己テストの受け口は、検証できない JARM をエラー画面で断る（500 にしない）</summary>
        /// <param name="targetKey">core / netfx</param>
        /// <returns>Task</returns>
        [SkippableTheory]
        [MemberData(nameof(AllTargets))]
        public async Task RT29439_自己テストのImplicitの受け口は検証できないJARMを断る(string targetKey)
        {
            using (IdPClient client = this.Client(targetKey))
            {
                TestReport r = this.Report("RT-294.39",
                    "自己テストの受け口は、fragment・form_post の値を画面に出し、検証できない JARM はエラー画面で断る（500 にしない）",
                    "**自己テストの Implicit の受け口（`OAuth2ImplicitGrantClient`）を 1 度も叩いていなかった。**"
                    + "**叩いたら、自己テストを始めていない要求の JARM で 500 になった**（net48 版は 302）。"
                    + "**JARM の検証に失敗したら先へ進めない**（#294 の B7）。",
                    "#294（E2E の拡充 / B7）");

                r.Target("サインインしていないブラウザから、受け口を直接叩く");

                r.Step("(1) 値なし（fragment で返る場合。値は画面のスクリプトが読む）");

                HttpResponseMessage fragment = await client.GetAsync("/Account/OAuth2ImplicitGrantClient");
                string fragmentBody = await fragment.Content.ReadAsStringAsync();

                Skip.If(fragment.StatusCode == HttpStatusCode.OK && fragmentBody.Contains(ErrorHeading),
                    "自己テストの受け口が閉じています（IsLockedDownTestEndpoints）。");

                r.VerifyEqual("値なし : HTTP 200（画面を出す）", "200", ((int)fragment.StatusCode).ToString());

                r.Step("(2) state ＋ 値（form_post・query で返る場合）");

                HttpResponseMessage posted = await client.GetAsync(
                    "/Account/OAuth2ImplicitGrantClient?state=e2e-state-294&token_type=Bearer&expires_in=60");
                string postedBody = WebUtility.HtmlDecode(await posted.Content.ReadAsStringAsync());

                r.Verify("state あり : **受け取った値を画面に出す**",
                    posted.StatusCode == HttpStatusCode.OK && !postedBody.Contains(ErrorHeading) && postedBody.Contains("e2e-state-294"),
                    "画面に state", "HTTP " + (int)posted.StatusCode + " / " + Html.Describe(postedBody));

                //  **自己テストを始めていない要求**なので、その回の client_id が無い（JARM の aud を決められない）。
                //    **以前は ResponseObject.Verify が例外を投げ、net10.0 版は 500、net48 版は 302 だった**（#294）。
                foreach (string path in new string[] {
                    "/Account/OAuth2ImplicitGrantClient?response=not.a.jwt",
                    "/Account/OAuth2AuthorizationCodeGrantClient?response=not.a.jwt" })
                {
                    r.Step("(3) 検証できない JARM : GET " + path);

                    HttpResponseMessage jarm = await client.GetAsync(path);
                    string jarmBody = await jarm.Content.ReadAsStringAsync();

                    r.Verify(path + " : **エラー画面になる**（値を使わない。500 にしない）",
                        jarm.StatusCode == HttpStatusCode.OK && jarmBody.Contains(ErrorHeading),
                        "エラー画面", "HTTP " + (int)jarm.StatusCode + " / " + Html.Describe(jarmBody));
                }

                r.Done();
            }
        }

        /// <summary>RT-294.40 プッシュの 2FA（MobileApp）で、端末が承認するとブラウザのサインインが完了する</summary>
        /// <param name="targetKey">core / netfx</param>
        /// <returns>Task</returns>
        [SkippableTheory]
        [MemberData(nameof(AllTargets))]
        public async Task RT29440_プッシュの2FAで端末が承認するとサインインできる(string targetKey)
        {
            using (IdPClient admin = this.Client(targetKey))
            {
                FcmOutbox.SkipIfUnavailable(admin.Target);

                string userName = AccountFlowTests.UniqueName();
                string email = userName + "@example.com";
                string deviceToken = "e2e-device-" + Guid.NewGuid().ToString("N");

                TestReport r = this.Report("RT-294.40",
                    "プッシュの 2FA（MobileApp）で、端末が承認すると、待っているブラウザのサインインが完了する",
                    "**プッシュの 2FA の成功の経路を、E2E で通していなかった**（RT-213.1 は `/2fa_result` の失敗の口だけ）。"
                    + "**端末の役は、送信箱（`FcmOutbox`）を読んで `/2fa_result` を叩くテストがする。**",
                    "#294（E2E の拡充）/ #213");

                r.Target("利用者名 = " + userName + "（2FA を有効にし、端末を登録した使い捨ての利用者）");

                try
                {
                    await AccountFlowTests.CreateUserAsync(admin, userName, email);

                    string accessToken;

                    using (IdPClient user = this.Client(targetKey))
                    {
                        Assert.True(await user.TrySignInAsync(userName, user.Config.Get("TestUserPWD")),
                            "前提: 作った利用者でサインインできること");

                        //  **端末の登録は、2FA を有効にする前に**（有効にした後のサインインは 2FA を求められる）。
                        //  **認証デバイスのクライアントでトークンを取る**（#294。この口は、それ以外のクライアントのトークンを断る）。
                        JsonResponse token = await Flows.RunAuthenticationDeviceFlowAsync(user);
                        accessToken = token.AccessToken;

                        Assert.False(string.IsNullOrEmpty(accessToken), "前提: 利用者の access_token が取れること");

                        JsonResponse registered = await user.SetDeviceTokenAsync(accessToken, deviceToken);
                        Assert.True(registered.StatusCode == HttpStatusCode.OK,
                            "前提: 端末を登録できること（HTTP " + (int)registered.StatusCode + "）");

                        await AccountFlowTests.EnableTwoFactorAsync(user);
                    }

                    using (IdPClient client = this.Client(targetKey))
                    {
                        string returnUrl = new Uri(client.Target.Url("/Manage/Index")).AbsolutePath;

                        r.Step("(1) パスワードでサインインし、手段に MobileApp を選ぶ");

                        HttpResponseMessage login = await AccountFlowTests.PostLoginAsync(
                            client, userName, client.Config.Get("TestUserPWD"), returnUrl);

                        Assert.True(login.Headers.Location != null && login.Headers.Location.ToString().Contains("/Account/SendCode"),
                            "前提: 2FA の手段の選択へ送られること");

                        HttpResponseMessage send = await client.GetAsync(AccountFlowTests.Resolve(client, login.Headers.Location));
                        string sendBody = await send.Content.ReadAsStringAsync();

                        bool offered = AccountFlowTests.ProviderOptions(sendBody).Contains("MobileApp");

                        r.Verify("**端末を登録した利用者には、手段に MobileApp が出る**", offered, "出る", "**出ない**");

                        Dictionary<string, string> sendForm = Html.HiddenInputs(sendBody);
                        sendForm["SelectedProvider"] = "MobileApp";

                        HttpResponseMessage sent = await client.PostFormAsync(
                            AccountFlowTests.ActionOf(client, sendBody, "/Account/SendCode"), sendForm);

                        Assert.True(sent.Headers.Location != null && sent.Headers.Location.ToString().Contains("/Account/VerifyCode"),
                            "前提: コードの入力画面へ送られること");

                        r.Step("(2) 端末の役 : 送信箱から、プッシュ通知のコードを読む");

                        FcmOutbox.Message push = await FcmOutbox.WaitForTokenAsync(client.Target, deviceToken, MailTimeout);
                        string code = null;

                        if (push != null)
                        {
                            push.Data.TryGetValue("code", out code);
                        }

                        r.Verify("**登録した端末へ、コードのプッシュ通知が届く**", !string.IsNullOrEmpty(code),
                            "届く", push == null ? "**届かない**" : "届いたがコードが無い");
                        Assert.False(string.IsNullOrEmpty(code), "前提: コードを読めること");

                        string status = "/Account/TwoFactorPushStatus?returnUrl=" + Uri.EscapeDataString(returnUrl)
                            + "&rememberMe=false&rememberBrowser=false";

                        string before = (await client.GetStringAsync(status)).Replace(" ", "");

                        r.Verify("承認の前 : **`approved` は false**", before.Contains("\"approved\":false"),
                            "approved=false", before);

                        r.Step("(3) 端末の役 : `/2fa_result` で承認する");

                        JsonResponse approved = await client.TwoFactorPushResultAsync(accessToken, code);
                        Assert.True(approved.StatusCode == HttpStatusCode.OK,
                            "前提: 承認を受け付けること（HTTP " + (int)approved.StatusCode + "）");

                        r.Step("(4) ブラウザの役 : 承認の状態を問い合わせる");

                        string after = (await client.GetStringAsync(status)).Replace(" ", "").Replace("\\/", "/");

                        r.Verify("承認の後 : **`approved` が true で、戻り先が返る**",
                            after.Contains("\"approved\":true") && after.Contains(returnUrl),
                            "approved=true ＋ " + returnUrl, after);

                        HttpResponseMessage manage = await client.GetAsync("/Manage/Index");

                        r.Verify("**サインインが完了している**（保護された画面が開く）",
                            manage.StatusCode == HttpStatusCode.OK, "HTTP 200", "HTTP " + (int)manage.StatusCode);
                    }
                }
                finally
                {
                    await AccountFlowTests.CleanUpAsync(this, targetKey, userName);
                }

                r.Done();
            }
        }

        #region 補助

        /// <summary>この配備の設定値（環境変数が構成ファイルより強い。AuthFailureLockoutTests と同じ）</summary>
        /// <param name="client">IdPClient</param>
        /// <param name="key">設定キー</param>
        /// <param name="fallback">読めなかったときの値</param>
        /// <returns>値</returns>
        private static int SettingOf(IdPClient client, string key, int fallback)
        {
            string value = Environment.GetEnvironmentVariable(key);

            if (string.IsNullOrEmpty(value))
            {
                value = client.Config.Get(key);
            }

            int parsed = 0;
            return int.TryParse(value ?? "", out parsed) ? parsed : fallback;
        }

        /// <summary>管理画面から利用者を作る（メアドは確認済み）</summary>
        /// <param name="admin">IdPClient（中で管理者としてサインインする）</param>
        /// <param name="userName">利用者名</param>
        /// <param name="email">メアド</param>
        /// <returns>利用者の ID</returns>
        private static async Task<string> CreateUserAsync(IdPClient admin, string userName, string email)
        {
            await admin.SignInAsAdministratorAsync();
            await UsersAdmin.SkipIfLockedDownAsync(admin);

            HttpResponseMessage created = await UsersAdmin.CreateAsync(admin, userName, email, "User");
            Assert.True(created.StatusCode == HttpStatusCode.Found || created.StatusCode == HttpStatusCode.Redirect,
                "前提: 利用者を作れること");

            HttpResponseMessage index = await UsersAdmin.IndexAsync(admin);
            string userId = UsersAdmin.FindId(await index.Content.ReadAsStringAsync(), userName);

            Assert.False(string.IsNullOrEmpty(userId), "前提: 作った利用者が一覧に出ること");

            return userId;
        }

        /// <summary>2FA を有効にする（管理画面のボタン）</summary>
        /// <param name="user">利用者でサインインした IdPClient</param>
        /// <returns>Task</returns>
        private static async Task EnableTwoFactorAsync(IdPClient user)
        {
            HttpResponseMessage index = await user.GetAsync("/Manage/Index");
            string indexBody = await index.Content.ReadAsStringAsync();

            HttpResponseMessage enabled = await user.PostFormAsync("/Manage/EnableTwoFactorAuthentication",
                new Dictionary<string, string>() { { "__RequestVerificationToken", Html.Antiforgery(indexBody) } });

            Skip.IfNot(enabled.StatusCode == HttpStatusCode.Found || enabled.StatusCode == HttpStatusCode.Redirect,
                "2FA を有効にできません（CanEdit2FA / EnableEditingOfUserAttribute を確認）。");
        }

        /// <summary>2FA の手段の選択画面に出ている選択肢</summary>
        /// <param name="body">画面の本文</param>
        /// <returns>選択肢の値</returns>
        private static List<string> ProviderOptions(string body)
        {
            return Regex.Matches(body, "<option\\b[^>]*\\bvalue=\"(?<v>[^\"]*)\"", RegexOptions.IgnoreCase)
                .Cast<Match>()
                .Select(m => WebUtility.HtmlDecode(m.Groups["v"].Value))
                .ToList();
        }

        /// <summary>textarea の中身（無ければ空）</summary>
        /// <param name="body">画面の本文</param>
        /// <param name="name">name</param>
        /// <returns>中身（HTML の文字参照は戻す）</returns>
        private static string TextAreaValue(string body, string name)
        {
            Match m = Regex.Match(body,
                "<textarea\\b[^>]*\\bname=\"" + Regex.Escape(name) + "\"[^>]*>(?<v>.*?)</textarea>",
                RegexOptions.IgnoreCase | RegexOptions.Singleline);

            return m.Success ? WebUtility.HtmlDecode(m.Groups["v"].Value) : "";
        }

        /// <summary>応答を、報告に出せる長さに縮める（トークンの値は出さない）</summary>
        /// <param name="response">応答</param>
        /// <returns>先頭の 80 文字（JWT は伏せる）</returns>
        private static string Brief(string response)
        {
            string squashed = Regex.Replace(response ?? "", "ey[A-Za-z0-9_\\-]+\\.[A-Za-z0-9_\\-\\.]+", "(JWT)");
            return (squashed.Length <= 80) ? squashed : squashed.Substring(0, 80) + "…";
        }

        /// <summary>パスワードでサインインし、2FA の手段に Email を選んで送る</summary>
        /// <param name="client">IdPClient（新しいもの）</param>
        /// <param name="userName">利用者名</param>
        /// <param name="returnUrl">戻り先（null なら付けない）</param>
        /// <returns>SendCode の POST の応答</returns>
        private static async Task<HttpResponseMessage> SelectEmailProviderAsync(
            IdPClient client, string userName, string returnUrl)
        {
            HttpResponseMessage login = await AccountFlowTests.PostLoginAsync(
                client, userName, client.Config.Get("TestUserPWD"), returnUrl);

            Assert.True(login.Headers.Location != null && login.Headers.Location.ToString().Contains("/Account/SendCode"),
                "前提: 2FA の手段の選択へ送られること");

            HttpResponseMessage send = await client.GetAsync(AccountFlowTests.Resolve(client, login.Headers.Location));
            string sendBody = await send.Content.ReadAsStringAsync();

            //  **Email の手段の名前は、版で違う**（net10.0 版は "Email"、net48 版はリソースの文言）。画面の選択肢から拾う。
            string provider = AccountFlowTests.ProviderOptions(sendBody)
                .FirstOrDefault(v => v.Contains("Email") || v.Contains("電子メール"));

            Skip.If(provider == null, "2FA の手段に Email が出ません。");

            Dictionary<string, string> form = Html.HiddenInputs(sendBody);
            form["SelectedProvider"] = provider;

            return await client.PostFormAsync(AccountFlowTests.ActionOf(client, sendBody, "/Account/SendCode"), form);
        }

        /// <summary>パスワードの失念を送る（画面を開いて送る）</summary>
        /// <param name="client">IdPClient</param>
        /// <param name="email">メアド</param>
        /// <returns>応答</returns>
        private static async Task<HttpResponseMessage> PostForgotPasswordAsync(IdPClient client, string email)
        {
            HttpResponseMessage get = await client.GetAsync("/Account/ForgotPassword");
            string getBody = await get.Content.ReadAsStringAsync();

            return await client.PostFormAsync("/Account/ForgotPassword", new Dictionary<string, string>()
            {
                { "__RequestVerificationToken", Html.Antiforgery(getBody) },
                { "Email", email }
            });
        }

        /// <summary>この回だけの利用者名を作る</summary>
        /// <returns>利用者名</returns>
        private static string UniqueName()
        {
            return "e2e_rt294_flow_" + Guid.NewGuid().ToString("N").Substring(0, 8);
        }

        /// <summary>サインアップする（画面を開いて送る）</summary>
        /// <param name="client">IdPClient</param>
        /// <param name="userName">利用者名</param>
        /// <param name="email">メアド</param>
        /// <returns>サインアップできたか（メアド検証の画面になったか）</returns>
        private static async Task<bool> RegisterAsync(IdPClient client, string userName, string email)
        {
            HttpResponseMessage post = await AccountFlowTests.PostRegisterAsync(client, userName, email);
            string body = await post.Content.ReadAsStringAsync();

            return post.StatusCode == HttpStatusCode.OK && !Html.HasField(body, "ConfirmPassword");
        }

        /// <summary>サインアップを送る（画面を開いて送る）</summary>
        /// <param name="client">IdPClient</param>
        /// <param name="userName">利用者名</param>
        /// <param name="email">メアド</param>
        /// <returns>応答</returns>
        private static async Task<HttpResponseMessage> PostRegisterAsync(IdPClient client, string userName, string email)
        {
            HttpResponseMessage get = await client.GetAsync("/Account/Register");
            string formBody = await get.Content.ReadAsStringAsync();

            Skip.IfNot(get.StatusCode == HttpStatusCode.OK && Html.HasField(formBody, "ConfirmPassword"),
                "サインアップ画面が開きません（EnableSignupProcess を確認）。");

            string password = client.Config.Get("TestUserPWD");

            return await client.PostFormAsync("/Account/Register", new Dictionary<string, string>()
            {
                { "__RequestVerificationToken", Html.Antiforgery(formBody) },
                { "Name", userName },
                { "Email", email },
                { "Password", password },
                { "ConfirmPassword", password }
            });
        }

        /// <summary>サインイン画面からサインインを送る</summary>
        /// <param name="client">IdPClient</param>
        /// <param name="userName">利用者名</param>
        /// <param name="password">パスワード</param>
        /// <param name="returnUrl">戻り先（null なら付けない）</param>
        /// <returns>応答</returns>
        private static async Task<HttpResponseMessage> PostLoginAsync(
            IdPClient client, string userName, string password, string returnUrl = null)
        {
            HttpResponseMessage get = await client.GetAsync("/Account/Login");
            string loginBody = await get.Content.ReadAsStringAsync();

            return await client.PostFormAsync("/Account/Login", new Dictionary<string, string>()
            {
                { "__RequestVerificationToken", Html.Antiforgery(loginBody) },
                { "Email", userName },
                { "Password", password },
                { "RememberMe", "false" },
                { "ReturnUrl", returnUrl },
                { "submitButtonName", "normal_signin" }
            });
        }

        /// <summary>画面の最初のフォームの送り先（無ければ既定の口）</summary>
        /// <param name="client">IdPClient</param>
        /// <param name="body">画面の本文</param>
        /// <param name="fallback">既定の口</param>
        /// <returns>送り先</returns>
        private static string ActionOf(IdPClient client, string body, string fallback)
        {
            string action = WebUtility.HtmlDecode(Html.FormAttribute(body, "action") ?? "");

            return string.IsNullOrEmpty(action)
                ? fallback : AccountFlowTests.Resolve(client, new Uri(action, UriKind.RelativeOrAbsolute));
        }

        /// <summary>相対 URL を、絶対 URL にする</summary>
        /// <param name="client">IdPClient</param>
        /// <param name="location">URL</param>
        /// <returns>絶対 URL</returns>
        private static string Resolve(IdPClient client, Uri location)
        {
            return location.IsAbsoluteUri
                ? location.AbsoluteUri
                : new Uri(new Uri(client.Target.BaseUrl), location).AbsoluteUri;
        }

        /// <summary>後片付け : 管理画面から削除する</summary>
        /// <param name="test">テスト</param>
        /// <param name="targetKey">対象</param>
        /// <param name="userName">利用者名</param>
        /// <returns>Task</returns>
        private static async Task CleanUpAsync(AccountFlowTests test, string targetKey, string userName)
        {
            using (IdPClient admin = test.Client(targetKey))
            {
                await admin.SignInAsAdministratorAsync();
                await UsersAdmin.DeleteByUserNameAsync(admin, userName);
            }
        }

        #endregion
    }
}
