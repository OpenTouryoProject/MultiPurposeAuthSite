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
//* クラス名        ：TwoFactorTests
//* クラス日本語名  ：RT-294.8 〜 .13 2 要素認証（TOTP・回復コード・コード）
//*
//* 作成日時        ：－
//* 作成者          ：－
//* 更新履歴        ：－
//*
//*  日時        更新者            内容
//*  ----------  ----------------  -------------------------------------------------
//*  2026/10/28  玄人 幸道         新規（#294）
//**********************************************************************************

using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Security.Cryptography;
using System.Text.RegularExpressions;
using System.Threading.Tasks;

using MultiPurposeAuthSite.Tests.E2E.Infrastructure;

using Xunit;
using Xunit.Abstractions;

namespace MultiPurposeAuthSite.Tests.E2E.Tests.Issues
{
    /// <summary>
    /// RT-294.8 〜 .13 2 要素認証（#294）。
    /// </summary>
    /// <remarks>
    /// **`AccountController.TwoFactor.cs` のレビューで見つけた穴を、直した形で押さえる。**
    /// **2FA の画面は、それまで E2E で 1 度も通していなかった。**
    ///
    /// **TOTP（認証アプリ）は net10.0 版にしかない**ので、TOTP を使うケースは `CoreOnly` である。
    /// **認証アプリの役は、テストが RFC 6238 で計算して務める**（共有鍵は登録画面の `otpauth://` から取る）。
    ///
    /// | ケース | 以前の振る舞い |
    /// |---|---|
    /// | RT-294.8 TOTP でサインイン | **セッションを初期化していなかった**（`auth_time` と OP のセッションの Cookie が書かれない）。**1 回間違えると戻り先を失った** |
    /// | RT-294.9 回復コードでサインイン | **同上** |
    /// | RT-294.10 2FA の途中でない TOTP・回復コードの画面 | **誰でも開けた** |
    /// | RT-294.11 TOTP を続けて間違える | **ロックアウトが 404**（`RedirectToAction("Lockout")` のアクションが無い） |
    /// | RT-294.12 画面に出していない手段を選ぶ | **知らない値は TOTP として扱っていた** |
    /// | RT-294.13 コードの 2FA で間違える | **文言が出なかった**（net10.0 版）。**ブラウザ記憶が既定で入っていた**（両版） |
    /// </remarks>
    public class TwoFactorTests : TargetTestBase
    {
        /// <summary>エラー画面・ロックアウトの画面の見出し（両方とも同じ形）</summary>
        private const string DangerHeading = "<h2 class=\"text-danger\">";

        /// <summary>ロックアウトの画面だけにある要素（Views/Shared/Lockout.cshtml）</summary>
        private const string LockoutMarker = "<hgroup>";

        /// <summary>TOTP（認証アプリ）の手段の名前（ASP.NET Core Identity の既定）</summary>
        private const string AuthenticatorProvider = "Authenticator";

        /// <summary>Email の手段を、画面の選択肢から拾うことを表す（名前は版で違う）</summary>
        private const string EmailProvider = "(Email)";

        /// <summary>コンストラクタ</summary>
        /// <param name="output">ITestOutputHelper</param>
        public TwoFactorTests(ITestOutputHelper output) : base(output)
        {
        }

        /// <summary>RT-294.8 TOTP でサインインすると、セッションが初期化され、1 回間違えても戻り先へ戻る</summary>
        /// <param name="targetKey">core</param>
        /// <returns>Task</returns>
        [SkippableTheory]
        [MemberData(nameof(CoreOnly))]
        public async Task RT29408_TOTPでサインインするとセッションが初期化される(string targetKey)
        {
            using (IdPClient admin = this.Client(targetKey))
            {
                string userName = TwoFactorTests.UniqueName();

                TestReport r = this.Report("RT-294.8",
                    "TOTP でサインインすると、セッションが初期化され、1 回間違えても戻り先へ戻る",
                    "**パスワード・コードの 2FA・プッシュ承認は、サインインの後にセッションを初期化する**"
                    + "（セッション ID の切り替え、`auth_time` と OP のセッション（#310 の `sid`）の Cookie）。"
                    + "**TOTP の 2 か所だけ、それを呼んでいなかった。**"
                    + "**また、1 回間違えると画面を出し直すときに戻り先を渡さず、認可要求の続きに戻れなかった。**",
                    "#294（AccountController.TwoFactor.cs のレビュー 1・4）");

                r.Target("利用者名 = " + userName + "（TOTP を有効にした使い捨ての利用者）");

                try
                {
                    r.Step("(1) 利用者を作り、認証アプリを登録して 2FA を有効にする");

                    TotpUser totp = await TwoFactorTests.PrepareTotpUserAsync(admin, targetKey, userName, this);

                    using (IdPClient client = this.Client(targetKey))
                    {
                        string returnUrl = TwoFactorTests.LocalPath(client, "/Manage/Index");

                        r.Step("(2) パスワードでサインインし、手段に認証アプリを選ぶ");

                        string totpUrl = await TwoFactorTests.StartTwoFactorAsync(
                            client, userName, returnUrl, AuthenticatorProvider);

                        r.Verify("TOTP の入力画面へ送られる",
                            (totpUrl ?? "").Contains("/Account/LoginWithTwoFactorAuthenticator"),
                            "LoginWithTwoFactorAuthenticator", totpUrl ?? "**送られない**");

                        HttpResponseMessage page = await client.GetAsync(totpUrl);
                        string pageBody = await page.Content.ReadAsStringAsync();

                        r.Step("(3) まず、間違ったコードを送る");

                        HttpResponseMessage wrong = await TwoFactorTests.PostTotpAsync(
                            client, pageBody, "000000");
                        string wrongBody = await wrong.Content.ReadAsStringAsync();

                        r.VerifyEqual("HTTP 200（再表示）", "200", ((int)wrong.StatusCode).ToString());

                        r.Verify("エラーが出ている",
                            Html.HasValidationError(wrongBody),
                            "出ている", Html.HasValidationError(wrongBody) ? "出ている" : "**出ていない**");

                        string action = WebUtility.HtmlDecode(Html.FormAttribute(wrongBody, "action") ?? "");

                        r.Verify("**再表示のフォームが、戻り先を持っている**",
                            WebUtility.UrlDecode(action).Contains("returnUrl=" + returnUrl),
                            "returnUrl=" + returnUrl, action);

                        r.Step("(4) 正しいコードを送る（再表示されたフォームから）");

                        HttpResponseMessage ok = await TwoFactorTests.PostTotpAsync(
                            client, wrongBody, totp.CodeForNextStep());

                        r.Verify("**戻り先へリダイレクトする**",
                            TwoFactorTests.IsRedirectTo(ok, returnUrl),
                            returnUrl, TwoFactorTests.Describe(ok));

                        TwoFactorTests.VerifySessionInitialized(r, client);

                        HttpResponseMessage manage = await client.GetAsync("/Manage/Index");

                        r.VerifyEqual("保護された画面が開く", "200", ((int)manage.StatusCode).ToString());
                    }
                }
                finally
                {
                    await TwoFactorTests.CleanUpAsync(admin, userName);
                }

                r.Done();
            }
        }

        /// <summary>RT-294.9 回復コードでサインインしても、セッションが初期化される</summary>
        /// <param name="targetKey">core</param>
        /// <returns>Task</returns>
        [SkippableTheory]
        [MemberData(nameof(CoreOnly))]
        public async Task RT29409_回復コードでサインインするとセッションが初期化される(string targetKey)
        {
            using (IdPClient admin = this.Client(targetKey))
            {
                string userName = TwoFactorTests.UniqueName();

                TestReport r = this.Report("RT-294.9",
                    "回復コードでサインインしても、セッションが初期化され、戻り先へ戻る",
                    "**RT-294.8 と同じ穴が、回復コードの口にもあった。**",
                    "#294（AccountController.TwoFactor.cs のレビュー 1）");

                r.Target("利用者名 = " + userName);

                try
                {
                    r.Step("(1) 利用者を作り、認証アプリを登録して 2FA を有効にする（回復コードも受け取る）");

                    TotpUser totp = await TwoFactorTests.PrepareTotpUserAsync(admin, targetKey, userName, this);

                    Assert.True(0 < totp.RecoveryCodes.Count, "前提: 回復コードを受け取れること");

                    using (IdPClient client = this.Client(targetKey))
                    {
                        string returnUrl = TwoFactorTests.LocalPath(client, "/Manage/Index");

                        r.Step("(2) パスワードでサインインし、認証アプリを選んだ後、回復コードの画面へ");

                        await TwoFactorTests.StartTwoFactorAsync(client, userName, returnUrl, AuthenticatorProvider);

                        string recoveryUrl = "/Account/LoginWithTwoFactorAuthenticatorRecoveryCode?returnUrl="
                            + WebUtility.UrlEncode(returnUrl);

                        HttpResponseMessage page = await client.GetAsync(recoveryUrl);
                        string pageBody = await page.Content.ReadAsStringAsync();

                        r.Verify("回復コードの入力画面が開く",
                            Html.HasField(pageBody, "RecoveryCode"),
                            "入力欄が在る", Html.Describe(pageBody));

                        r.Step("(3) 回復コードを送る");

                        HttpResponseMessage ok = await TwoFactorTests.PostFormFromAsync(client, pageBody,
                            new Dictionary<string, string>() { { "RecoveryCode", totp.RecoveryCodes[0] } },
                            recoveryUrl);

                        r.Verify("**戻り先へリダイレクトする**",
                            TwoFactorTests.IsRedirectTo(ok, returnUrl),
                            returnUrl, TwoFactorTests.Describe(ok));

                        TwoFactorTests.VerifySessionInitialized(r, client);
                    }
                }
                finally
                {
                    await TwoFactorTests.CleanUpAsync(admin, userName);
                }

                r.Done();
            }
        }

        /// <summary>RT-294.10 2FA の途中でなければ、TOTP・回復コードの画面は開かない</summary>
        /// <param name="targetKey">core</param>
        /// <returns>Task</returns>
        [SkippableTheory]
        [MemberData(nameof(CoreOnly))]
        public async Task RT29410_2FAの途中でなければTOTPの画面は開かない(string targetKey)
        {
            using (IdPClient client = this.Client(targetKey))
            {
                TestReport r = this.Report("RT-294.10",
                    "2FA の途中でなければ、TOTP・回復コードの画面はエラー画面になる",
                    "**コードの 2FA（SendCode / VerifyCode）は、パスワードを通った後でなければエラー画面を返す。**"
                    + "**TOTP・回復コードの画面だけ、確かめるコードがコメントアウトされていて、誰でも開けた。**",
                    "#294（AccountController.TwoFactor.cs のレビュー 5）");

                r.Target("サインインしていないブラウザ");

                foreach (string path in new string[] {
                    "/Account/LoginWithTwoFactorAuthenticator?rememberMe=false",
                    "/Account/LoginWithTwoFactorAuthenticatorRecoveryCode" })
                {
                    r.Step("GET " + path);

                    HttpResponseMessage res = await client.GetAsync(path);
                    string body = await res.Content.ReadAsStringAsync();

                    r.VerifyEqual(path + " : HTTP 200", "200", ((int)res.StatusCode).ToString());

                    r.Verify(path + " : **エラー画面になる**（入力画面を出さない）",
                        body.Contains(DangerHeading) && !body.Contains(LockoutMarker),
                        "エラー画面", Html.Describe(body));
                }

                r.Done();
            }
        }

        /// <summary>RT-294.11 TOTP を続けて間違えると、ロックアウトの画面になる（404 にならない）</summary>
        /// <param name="targetKey">core</param>
        /// <returns>Task</returns>
        [SkippableTheory]
        [MemberData(nameof(CoreOnly))]
        public async Task RT29411_TOTPを続けて間違えるとロックアウトの画面になる(string targetKey)
        {
            using (IdPClient admin = this.Client(targetKey))
            {
                string userName = TwoFactorTests.UniqueName();

                TestReport r = this.Report("RT-294.11",
                    "TOTP を続けて間違えると、ロックアウトの画面になる（404 にならない）",
                    "**`Lockout` はアクションではなく画面である**（`Views/Shared/Lockout.cshtml`）。"
                    + "**TOTP・回復コードの 2 か所だけ `RedirectToAction(\"Lockout\")` で、行き先が 404 だった。**",
                    "#294（AccountController.TwoFactor.cs のレビュー 3）");

                r.Target("利用者名 = " + userName + "（ロックアウトさせるので、専用に作る）");

                try
                {
                    await TwoFactorTests.PrepareTotpUserAsync(admin, targetKey, userName, this);

                    using (IdPClient client = this.Client(targetKey))
                    {
                        r.Step("(1) パスワードでサインインし、認証アプリを選ぶ");

                        string totpUrl = await TwoFactorTests.StartTwoFactorAsync(
                            client, userName, TwoFactorTests.LocalPath(client, "/Manage/Index"), AuthenticatorProvider);

                        HttpResponseMessage page = await client.GetAsync(totpUrl);
                        string body = await page.Content.ReadAsStringAsync();

                        r.Step("(2) ロックアウトするまで、間違ったコードを送る（上限 20 回）");

                        HttpResponseMessage last = null;
                        int tries = 0;
                        bool lockedOut = false;

                        while (tries < 20)
                        {
                            tries++;
                            last = await TwoFactorTests.PostTotpAsync(client, body, "000000");
                            string lastBody = await last.Content.ReadAsStringAsync();

                            if (last.StatusCode != HttpStatusCode.OK || lastBody.Contains(LockoutMarker))
                            {
                                lockedOut = lastBody.Contains(LockoutMarker);
                                break;
                            }

                            body = lastBody;
                        }

                        Skip.If(!lockedOut && last != null && last.StatusCode == HttpStatusCode.OK,
                            "20 回間違えてもロックアウトしません（UserLockoutEnabledByDefault / MaxFailedAccessAttemptsBeforeLockout を確認）。");

                        r.VerifyEqual("HTTP 200（404 にならない）", "200", ((int)last.StatusCode).ToString());

                        r.Verify("**ロックアウトの画面になる**",
                            lockedOut, "ロックアウトの画面", lockedOut ? "ロックアウトの画面（" + tries + " 回目）" : TwoFactorTests.Describe(last));
                    }
                }
                finally
                {
                    await TwoFactorTests.CleanUpAsync(admin, userName);
                }

                r.Done();
            }
        }

        /// <summary>RT-294.12 画面に出していない手段を選ぶと、送らずに選び直しになる</summary>
        /// <param name="targetKey">core</param>
        /// <returns>Task</returns>
        [SkippableTheory]
        [MemberData(nameof(CoreOnly))]
        public async Task RT29412_画面に出していない手段は選べない(string targetKey)
        {
            using (IdPClient admin = this.Client(targetKey))
            {
                string userName = TwoFactorTests.UniqueName();

                TestReport r = this.Report("RT-294.12",
                    "画面に出していない手段を選ぶと、送らずに選び直しになる",
                    "**選ばれた手段を、画面に出した選択肢と突き合わせていなかった。**"
                    + "**知らない値は TOTP として扱い、認証アプリを登録していない利用者も TOTP の画面へ送っていた。**",
                    "#294（AccountController.TwoFactor.cs のレビュー 9）");

                r.Target("利用者名 = " + userName + " / 手段 = \"Bogus\"");

                try
                {
                    await TwoFactorTests.PrepareTotpUserAsync(admin, targetKey, userName, this);

                    using (IdPClient client = this.Client(targetKey))
                    {
                        r.Step("パスワードでサインインし、存在しない手段を選ぶ");

                        HttpResponseMessage res = await TwoFactorTests.PostSendCodeAsync(
                            client, userName, TwoFactorTests.LocalPath(client, "/Manage/Index"), "Bogus");
                        string body = await res.Content.ReadAsStringAsync();

                        r.VerifyEqual("HTTP 200（選び直しの画面）", "200", ((int)res.StatusCode).ToString());

                        r.Verify("**手段の選択画面が、エラー付きで出し直される**",
                            Html.HasField(body, "SelectedProvider") && Html.HasValidationError(body),
                            "選択画面＋エラー", Html.Describe(body));
                    }
                }
                finally
                {
                    await TwoFactorTests.CleanUpAsync(admin, userName);
                }

                r.Done();
            }
        }

        /// <summary>RT-294.13 コードの 2FA で間違えると文言が出て、ブラウザ記憶は既定で入っていない</summary>
        /// <param name="targetKey">core / netfx</param>
        /// <returns>Task</returns>
        [SkippableTheory]
        [MemberData(nameof(AllTargets))]
        public async Task RT29413_コードの2FAで間違えると文言が出る(string targetKey)
        {
            using (IdPClient admin = this.Client(targetKey))
            {
                string userName = TwoFactorTests.UniqueName();

                TestReport r = this.Report("RT-294.13",
                    "コードの 2FA（Email）で間違えると文言が出て、ブラウザ記憶は既定で入っていない",
                    "**net10.0 版は、コードの誤り（`Failed`）で文言を出していなかった**（`IsNotAllowed` だけを見ていた）。"
                    + "**両版とも、ブラウザ記憶を常に入れた状態で画面を出していた**"
                    + "（既定のままだと、そのブラウザでは次から 2FA を飛ばした）。",
                    "#294（AccountController.TwoFactor.cs のレビュー 2・6）");

                r.Target("利用者名 = " + userName + "（2FA を有効にした使い捨ての利用者。手段は Email）");

                try
                {
                    r.Step("(1) 利用者を作り、2FA を有効にする");

                    await TwoFactorTests.PrepareTwoFactorUserAsync(admin, targetKey, userName, this);

                    using (IdPClient client = this.Client(targetKey))
                    {
                        r.Step("(2) パスワードでサインインし、手段に Email を選ぶ");

                        HttpResponseMessage sent = await TwoFactorTests.PostSendCodeAsync(
                            client, userName, TwoFactorTests.LocalPath(client, "/Manage/Index"), EmailProvider);

                        string location = (sent.Headers.Location == null) ? "" : sent.Headers.Location.ToString();

                        Skip.IfNot(location.Contains("/Account/VerifyCode"),
                            "コードを送れません（メールの送信の設定を確認）: " + TwoFactorTests.Describe(sent));

                        HttpResponseMessage page = await client.GetAsync(TwoFactorTests.Resolve(client, sent.Headers.Location));
                        string pageBody = await page.Content.ReadAsStringAsync();

                        r.Verify("**ブラウザ記憶のチェックボックスが、既定で入っていない**",
                            !TwoFactorTests.IsChecked(pageBody, "RememberBrowser"),
                            "入っていない",
                            TwoFactorTests.IsChecked(pageBody, "RememberBrowser") ? "**入っている**" : "入っていない");

                        r.Step("(3) 間違ったコードを送る");

                        HttpResponseMessage wrong = await TwoFactorTests.PostFormFromAsync(client, pageBody,
                            new Dictionary<string, string>() { { "Code", "000000" } });
                        string wrongBody = await wrong.Content.ReadAsStringAsync();

                        r.VerifyEqual("HTTP 200（再表示）", "200", ((int)wrong.StatusCode).ToString());

                        r.Verify("**エラーの文言が出る**",
                            Html.HasValidationError(wrongBody),
                            "出ている", Html.HasValidationError(wrongBody) ? "出ている" : "**出ていない**");
                    }
                }
                finally
                {
                    await TwoFactorTests.CleanUpAsync(admin, userName);
                }

                r.Done();
            }
        }

        #region 補助

        /// <summary>TOTP を有効にした利用者</summary>
        private sealed class TotpUser
        {
            /// <summary>共有鍵（Base32）</summary>
            public string Secret { get; set; }

            /// <summary>回復コード</summary>
            public List<string> RecoveryCodes { get; set; }

            /// <summary>
            /// 次の時間刻みのコード（登録で使った刻みと重ならないように、1 つ先を使う。
            /// 検証は前後 2 刻みまで受ける）
            /// </summary>
            /// <returns>6 桁のコード</returns>
            public string CodeForNextStep()
            {
                return Totp.Compute(this.Secret, DateTimeOffset.UtcNow.AddSeconds(30));
            }
        }

        /// <summary>この回だけの利用者名を作る</summary>
        /// <returns>利用者名</returns>
        private static string UniqueName()
        {
            return "e2e_rt294_2fa_" + Guid.NewGuid().ToString("N").Substring(0, 8);
        }

        /// <summary>利用者を作り、2FA を有効にする（手段は Email など、登録済みのもの）</summary>
        /// <param name="admin">管理者の IdPClient（中でサインインする）</param>
        /// <param name="targetKey">対象</param>
        /// <param name="userName">利用者名</param>
        /// <param name="test">テスト（Client を作るため）</param>
        /// <returns>Task</returns>
        private static async Task PrepareTwoFactorUserAsync(
            IdPClient admin, string targetKey, string userName, TwoFactorTests test)
        {
            await admin.SignInAsAdministratorAsync();
            await UsersAdmin.SkipIfLockedDownAsync(admin);

            //  **管理画面から作ると、メアドは確認済みになる**（そのままサインインでき、Email の手段も使える）。
            HttpResponseMessage created = await UsersAdmin.CreateAsync(
                admin, userName, userName + "@example.com", "User");

            Assert.True(created.StatusCode == HttpStatusCode.Found || created.StatusCode == HttpStatusCode.Redirect,
                "前提: 利用者を作れること");

            using (IdPClient user = test.Client(targetKey))
            {
                Assert.True(await user.TrySignInAsync(userName, user.Config.Get("TestUserPWD")),
                    "前提: 作った利用者でサインインできること");

                await TwoFactorTests.EnableTwoFactorAsync(user);
            }
        }

        /// <summary>利用者を作り、認証アプリを登録して 2FA を有効にする（net10.0 版だけ）</summary>
        /// <param name="admin">管理者の IdPClient（中でサインインする）</param>
        /// <param name="targetKey">対象</param>
        /// <param name="userName">利用者名</param>
        /// <param name="test">テスト（Client を作るため）</param>
        /// <returns>TotpUser</returns>
        private static async Task<TotpUser> PrepareTotpUserAsync(
            IdPClient admin, string targetKey, string userName, TwoFactorTests test)
        {
            await admin.SignInAsAdministratorAsync();
            await UsersAdmin.SkipIfLockedDownAsync(admin);

            HttpResponseMessage created = await UsersAdmin.CreateAsync(
                admin, userName, userName + "@example.com", "User");

            Assert.True(created.StatusCode == HttpStatusCode.Found || created.StatusCode == HttpStatusCode.Redirect,
                "前提: 利用者を作れること");

            using (IdPClient user = test.Client(targetKey))
            {
                Assert.True(await user.TrySignInAsync(userName, user.Config.Get("TestUserPWD")),
                    "前提: 作った利用者でサインインできること");

                //  **認証アプリの登録画面から、共有鍵を取る**（`otpauth://totp/...?secret=...`）。
                HttpResponseMessage get = await user.GetAsync("/Manage/EnableTwoFactorAuthenticator");
                string body = await get.Content.ReadAsStringAsync();

                Match secret = Regex.Match(WebUtility.HtmlDecode(body), "secret=(?<s>[A-Z2-7]+)");

                Skip.IfNot(get.StatusCode == HttpStatusCode.OK && secret.Success,
                    "認証アプリの登録画面が開きません（" + Html.Describe(body) + "）。");

                TotpUser totp = new TotpUser() { Secret = secret.Groups["s"].Value };

                HttpResponseMessage verified = await TwoFactorTests.PostFormFromAsync(user, body,
                    new Dictionary<string, string>() { { "Code", Totp.Compute(totp.Secret, DateTimeOffset.UtcNow) } },
                    "/Manage/EnableTwoFactorAuthenticator");

                Assert.True(verified.Headers.Location != null
                    && verified.Headers.Location.ToString().Contains("ShowTwoFactorAuthenticatorRecoveryCodes"),
                    "前提: 認証アプリを登録できること（" + TwoFactorTests.Describe(verified) + "）");

                HttpResponseMessage codes = await user.GetAsync(TwoFactorTests.Resolve(user, verified.Headers.Location));
                string codesBody = await codes.Content.ReadAsStringAsync();

                totp.RecoveryCodes = Regex.Matches(codesBody, "<code>(?<c>[^<]+)</code>")
                    .Cast<Match>().Select(m => m.Groups["c"].Value.Trim()).ToList();

                await TwoFactorTests.EnableTwoFactorAsync(user);

                return totp;
            }
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
                "2FA を有効にできません（CanEdit2FA / EnableEditingOfUserAttribute を確認）: "
                + TwoFactorTests.Describe(enabled));
        }

        /// <summary>パスワードでサインインし、2FA の手段を選んで送る</summary>
        /// <param name="client">IdPClient（新しいもの）</param>
        /// <param name="userName">利用者名</param>
        /// <param name="returnUrl">戻り先</param>
        /// <param name="provider">選ぶ手段</param>
        /// <returns>SendCode の POST の応答</returns>
        private static async Task<HttpResponseMessage> PostSendCodeAsync(
            IdPClient client, string userName, string returnUrl, string provider)
        {
            HttpResponseMessage get = await client.GetAsync("/Account/Login");
            string loginBody = await get.Content.ReadAsStringAsync();

            HttpResponseMessage post = await client.PostFormAsync("/Account/Login", new Dictionary<string, string>()
            {
                { "__RequestVerificationToken", Html.Antiforgery(loginBody) },
                { "Email", userName },
                { "Password", client.Config.Get("TestUserPWD") },
                { "RememberMe", "false" },
                { "ReturnUrl", returnUrl },
                { "submitButtonName", "normal_signin" }
            });

            Assert.True(post.Headers.Location != null && post.Headers.Location.ToString().Contains("/Account/SendCode"),
                "前提: パスワードの後に 2FA の手段の選択へ送られること（" + TwoFactorTests.Describe(post) + "）");

            HttpResponseMessage send = await client.GetAsync(TwoFactorTests.Resolve(client, post.Headers.Location));
            string sendBody = await send.Content.ReadAsStringAsync();

            //  **Email の手段の名前は、版で違う**（net10.0 版は "Email"、net48 版はリソースの "Email Code" / "電子メール コード"）。
            //    **画面の選択肢から拾う。**
            if (provider == EmailProvider)
            {
                provider = Regex.Matches(sendBody, "<option\\b[^>]*\\bvalue=\"(?<v>[^\"]*)\"", RegexOptions.IgnoreCase)
                    .Cast<Match>().Select(m => WebUtility.HtmlDecode(m.Groups["v"].Value))
                    .FirstOrDefault(v => v.Contains("Email") || v.Contains("電子メール"));

                Skip.If(provider == null, "2FA の手段に Email が出ません: " + Html.Describe(sendBody));
            }

            return await TwoFactorTests.PostFormFromAsync(client, sendBody,
                new Dictionary<string, string>() { { "SelectedProvider", provider } });
        }

        /// <summary>パスワードでサインインし、2FA の手段を選ぶ（行き先の URL を返す）</summary>
        /// <param name="client">IdPClient（新しいもの）</param>
        /// <param name="userName">利用者名</param>
        /// <param name="returnUrl">戻り先</param>
        /// <param name="provider">選ぶ手段</param>
        /// <returns>行き先の URL（リダイレクトしなければ null）</returns>
        private static async Task<string> StartTwoFactorAsync(
            IdPClient client, string userName, string returnUrl, string provider)
        {
            HttpResponseMessage res = await TwoFactorTests.PostSendCodeAsync(client, userName, returnUrl, provider);

            return (res.Headers.Location == null) ? null : TwoFactorTests.Resolve(client, res.Headers.Location);
        }

        /// <summary>TOTP の入力画面から、コードを送る</summary>
        /// <param name="client">IdPClient</param>
        /// <param name="formBody">入力画面の本文</param>
        /// <param name="code">コード</param>
        /// <returns>応答</returns>
        private static Task<HttpResponseMessage> PostTotpAsync(IdPClient client, string formBody, string code)
        {
            return TwoFactorTests.PostFormFromAsync(client, formBody,
                new Dictionary<string, string>() { { "TwoFactorCode", code }, { "RememberMachine", "false" } });
        }

        /// <summary>画面の最初のフォームを、hidden を引き継いで送る</summary>
        /// <param name="client">IdPClient</param>
        /// <param name="formBody">画面の本文</param>
        /// <param name="values">足す値（同じ名前は上書き）</param>
        /// <param name="pageUrl">画面の URL（フォームに action が無いとき、ブラウザと同じくここへ送る）</param>
        /// <returns>応答</returns>
        private static Task<HttpResponseMessage> PostFormFromAsync(
            IdPClient client, string formBody, Dictionary<string, string> values, string pageUrl = null)
        {
            Dictionary<string, string> form = Html.HiddenInputs(formBody);

            foreach (KeyValuePair<string, string> v in values)
            {
                form[v.Key] = v.Value;
            }

            //  **action が無ければ、開いた画面へ送る**（`<form method="post">` だけの画面がある）。
            string action = WebUtility.HtmlDecode(Html.FormAttribute(formBody, "action") ?? "");

            if (string.IsNullOrEmpty(action))
            {
                Assert.False(string.IsNullOrEmpty(pageUrl), "前提: action の無いフォームには、画面の URL を渡すこと");
                return client.PostFormAsync(pageUrl, form);
            }

            return client.PostFormAsync(TwoFactorTests.Resolve(client, new Uri(action, UriKind.RelativeOrAbsolute)), form);
        }

        /// <summary>サイトの中のパスを、パス ベースも含めた形にする</summary>
        /// <param name="client">IdPClient</param>
        /// <param name="path">/ 始まりのパス</param>
        /// <returns>パス</returns>
        private static string LocalPath(IdPClient client, string path)
        {
            return new Uri(client.Target.Url(path)).AbsolutePath;
        }

        /// <summary>リダイレクト先などの相対 URL を、絶対 URL にする</summary>
        /// <param name="client">IdPClient</param>
        /// <param name="location">URL</param>
        /// <returns>絶対 URL</returns>
        private static string Resolve(IdPClient client, Uri location)
        {
            return location.IsAbsoluteUri
                ? location.AbsoluteUri
                : new Uri(new Uri(client.Target.BaseUrl), location).AbsoluteUri;
        }

        /// <summary>戻り先へリダイレクトしたか</summary>
        /// <param name="res">応答</param>
        /// <param name="returnUrl">戻り先（パス）</param>
        /// <returns>そうなら true</returns>
        private static bool IsRedirectTo(HttpResponseMessage res, string returnUrl)
        {
            if (res.Headers.Location == null)
            {
                return false;
            }

            Uri location = res.Headers.Location;
            string path = location.IsAbsoluteUri ? location.AbsolutePath : location.OriginalString.Split('?')[0];

            return string.Equals(path, returnUrl, StringComparison.OrdinalIgnoreCase);
        }

        /// <summary>応答を 1 行で表す</summary>
        /// <param name="res">応答</param>
        /// <returns>文字列</returns>
        private static string Describe(HttpResponseMessage res)
        {
            if (res == null)
            {
                return "(応答なし)";
            }

            return "HTTP " + (int)res.StatusCode
                + ((res.Headers.Location == null) ? "" : " → " + res.Headers.Location);
        }

        /// <summary>チェックボックスが入っているか</summary>
        /// <param name="body">HTML</param>
        /// <param name="name">name</param>
        /// <returns>入っていれば true</returns>
        private static bool IsChecked(string body, string name)
        {
            foreach (Match m in Regex.Matches(body, "<input\\b[^>]*>", RegexOptions.IgnoreCase))
            {
                string tag = m.Value;

                if (Regex.IsMatch(tag, "type=\"checkbox\"", RegexOptions.IgnoreCase)
                    && Regex.IsMatch(tag, "name=\"" + name + "\"", RegexOptions.IgnoreCase))
                {
                    return Regex.IsMatch(tag, "\\bchecked\\b", RegexOptions.IgnoreCase);
                }
            }

            return false;
        }

        /// <summary>セッションの初期化で書かれる Cookie が在ることを確かめる</summary>
        /// <param name="r">TestReport</param>
        /// <param name="client">IdPClient</param>
        private static void VerifySessionInitialized(TestReport r, IdPClient client)
        {
            List<string> names = client.CookieNames.ToList();

            //  **名前には配備の接頭辞（CookieNamePrefix）が付くことがある**ので、末尾で見る。
            bool authTime = names.Any(n => n.EndsWith("auth_time", StringComparison.Ordinal));
            bool opSession = names.Any(n => n.EndsWith("op_session", StringComparison.Ordinal));

            r.Verify("**`auth_time` の Cookie が書かれている**（InitSessionAfterlogin）",
                authTime, "在る", authTime ? "在る" : "**無い**（" + string.Join(", ", names) + "）");

            r.Verify("**OP のセッションの Cookie が書かれている**（#310 の `sid` の元）",
                opSession, "在る", opSession ? "在る" : "**無い**（" + string.Join(", ", names) + "）");
        }

        /// <summary>後片付け : 管理画面から削除する</summary>
        /// <param name="admin">管理者の IdPClient</param>
        /// <param name="userName">利用者名</param>
        /// <returns>Task</returns>
        private static async Task CleanUpAsync(IdPClient admin, string userName)
        {
            await admin.SignInAsAdministratorAsync();
            await UsersAdmin.DeleteByUserNameAsync(admin, userName);
        }

        #endregion

        #region TOTP（RFC 6238）

        /// <summary>TOTP の計算（認証アプリの代わり）</summary>
        private static class Totp
        {
            /// <summary>6 桁のコードを計算する（SHA-1・30 秒）</summary>
            /// <param name="base32Secret">共有鍵（Base32）</param>
            /// <param name="at">時刻</param>
            /// <returns>6 桁のコード</returns>
            public static string Compute(string base32Secret, DateTimeOffset at)
            {
                byte[] key = Totp.FromBase32(base32Secret);
                long step = at.ToUnixTimeSeconds() / 30;

                byte[] counter = BitConverter.GetBytes(step);

                if (BitConverter.IsLittleEndian)
                {
                    Array.Reverse(counter);
                }

                byte[] hash;

                using (HMACSHA1 hmac = new HMACSHA1(key))
                {
                    hash = hmac.ComputeHash(counter);
                }

                int offset = hash[hash.Length - 1] & 0x0F;
                int binary = ((hash[offset] & 0x7F) << 24)
                    | (hash[offset + 1] << 16)
                    | (hash[offset + 2] << 8)
                    | hash[offset + 3];

                return (binary % 1000000).ToString("D6");
            }

            /// <summary>Base32 を復号する</summary>
            /// <param name="input">Base32</param>
            /// <returns>バイト列</returns>
            private static byte[] FromBase32(string input)
            {
                const string Alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

                List<byte> output = new List<byte>();
                int buffer = 0;
                int bits = 0;

                foreach (char c in input.TrimEnd('=').ToUpperInvariant())
                {
                    buffer = (buffer << 5) | Alphabet.IndexOf(c);
                    bits += 5;

                    if (8 <= bits)
                    {
                        output.Add((byte)((buffer >> (bits - 8)) & 0xFF));
                        bits -= 8;
                    }
                }

                return output.ToArray();
            }
        }

        #endregion
    }
}
