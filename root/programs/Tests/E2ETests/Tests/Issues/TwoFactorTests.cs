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
//*  2026/10/29  玄人 幸道         RT-294.60（登録画面を開いただけでは TOTP は登録されない）を足した（#294）
//*  2026/10/30  玄人 幸道         RT-294.63（再サインインで auth_time を新しくしない）・.64（2FA の無効化でパスワードを確かめる）・
//*                                .65（未確定の TOTP の鍵をほかの利用者に使わない）を足した（#294）
//*  2026/10/30  玄人 幸道         RT-294.66（登録済みの TOTP の鍵を出さない）・.67（回復コードの再発行とリセットで
//*                                パスワードを確かめる）を足した（#294）
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
    /// | RT-294.60 認証アプリの登録画面を開く | **開いただけで鍵を保存していた**（`ManageController.*.cs` のレビュー） |
    /// | RT-294.63 管理画面でサインインし直す | **auth_time を「いま」にしていた**（`max_age` の再認証が効かない。2 回目のレビュー） |
    /// | RT-294.64 2FA を無効にする | **パスワードを確かめていなかった**（2 回目のレビュー） |
    /// | RT-294.65 同じブラウザで別の利用者が登録画面を開く | **前の利用者が見た鍵を出していた**（2 回目のレビュー） |
    /// | RT-294.66 登録済みのときに登録画面を開く | **保存済みの鍵を何度でも出していた**（3 回目のレビュー） |
    /// | RT-294.67 回復コードの再発行・認証アプリのリセット | **パスワードを確かめていなかった**（3 回目のレビュー） |
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

        /// <summary>RT-294.60 認証アプリの登録画面を開いただけでは、TOTP は登録されない</summary>
        /// <param name="targetKey">core</param>
        /// <returns>Task</returns>
        [SkippableTheory]
        [MemberData(nameof(CoreOnly))]
        public async Task RT29460_登録画面を開いただけではTOTPは登録されない(string targetKey)
        {
            using (IdPClient admin = this.Client(targetKey))
            {
                string userName = TwoFactorTests.UniqueName();

                TestReport r = this.Report("RT-294.60",
                    "認証アプリの登録画面を開いただけでは、TOTP は登録されない（コードを確かめてから登録される）",
                    "**以前は登録画面（GET）を開いただけで、鍵を保存していた。**"
                    + "**そのため、コードを確かめていなくても、管理画面は TOTP を登録済みと出し、"
                    + "サインインの手段にも認証アプリが出ていた。**"
                    + "**鍵は TempData に置き、コードを確かめてから保存する**ようにした。"
                    + "**間違えて出し直すときは、同じ鍵を出す。**",
                    "#294（ManageController.*.cs のレビュー B10）");

                r.Target("利用者名 = " + userName + "（2FA を有効にした使い捨ての利用者）");

                try
                {
                    r.Step("(1) 利用者を作り、2FA を有効にする（認証アプリは、まだ登録しない）");

                    await admin.SignInAsAdministratorAsync();
                    await UsersAdmin.SkipIfLockedDownAsync(admin);

                    HttpResponseMessage created = await UsersAdmin.CreateAsync(
                        admin, userName, userName + "@example.com", "User");

                    Assert.True(created.StatusCode == HttpStatusCode.Found || created.StatusCode == HttpStatusCode.Redirect,
                        "前提: 利用者を作れること");

                    using (IdPClient user = this.Client(targetKey))
                    {
                        //  **2FA を有効にする前にサインインしておく**（有効にした後は、2FA を通さないと入れない）。
                        Assert.True(await user.TrySignInAsync(userName, user.Config.Get("TestUserPWD")),
                            "前提: 作った利用者でサインインできること");

                        await TwoFactorTests.EnableTwoFactorAsync(user);

                        r.Step("(2) 認証アプリの登録画面を開く");

                        HttpResponseMessage get = await user.GetAsync("/Manage/EnableTwoFactorAuthenticator");
                        string body = await get.Content.ReadAsStringAsync();
                        string secret = TwoFactorTests.SecretOf(body);

                        Skip.IfNot(get.StatusCode == HttpStatusCode.OK && secret != null,
                            "認証アプリの登録画面が開きません（" + Html.Describe(body) + "）。");

                        r.Step("(3) 管理画面と、サインインの手段を見る");

                        string index = await user.GetStringAsync("/Manage/Index");

                        r.Verify("管理画面は、TOTP を登録済みと出さない",
                            !(index ?? "").Contains("/Manage/ManageTwoFactorAuthenticator"),
                            "出さない",
                            (index ?? "").Contains("/Manage/ManageTwoFactorAuthenticator") ? "**出している**" : "出さない");

                        using (IdPClient other = this.Client(targetKey))
                        {
                            List<string> providers = await TwoFactorTests.ProvidersAsync(other, userName);

                            r.Observe("サインインの手段", string.Join(", ", providers), null);

                            r.Verify("サインインの手段に、認証アプリが出ない",
                                !providers.Contains(AuthenticatorProvider),
                                "出ない", providers.Contains(AuthenticatorProvider) ? "**出ている**" : "出ない");
                        }

                        r.Step("(4) 間違ったコードを送る");

                        HttpResponseMessage wrong = await TwoFactorTests.PostFormFromAsync(user, body,
                            new Dictionary<string, string>() { { "Code", "000000" } },
                            "/Manage/EnableTwoFactorAuthenticator");
                        string wrongBody = await wrong.Content.ReadAsStringAsync();

                        r.Verify("エラーの文言が出る",
                            Html.HasValidationError(wrongBody),
                            "出ている", Html.HasValidationError(wrongBody) ? "出ている" : "**出ていない**");

                        r.VerifyEqual("出し直した画面の鍵は、最初と同じ",
                            secret, TwoFactorTests.SecretOf(wrongBody) ?? "（無し）");

                        index = await user.GetStringAsync("/Manage/Index");

                        r.Verify("間違えた後も、管理画面は TOTP を登録済みと出さない",
                            !(index ?? "").Contains("/Manage/ManageTwoFactorAuthenticator"),
                            "出さない",
                            (index ?? "").Contains("/Manage/ManageTwoFactorAuthenticator") ? "**出している**" : "出さない");

                        r.Step("(5) 正しいコードを送る");

                        HttpResponseMessage verified = await TwoFactorTests.PostFormFromAsync(user, wrongBody,
                            new Dictionary<string, string>() { { "Code", Totp.Compute(secret, DateTimeOffset.UtcNow) } },
                            "/Manage/EnableTwoFactorAuthenticator");

                        r.Verify("回復コードの画面へ進む",
                            verified.Headers.Location != null
                                && verified.Headers.Location.ToString().Contains("ShowTwoFactorAuthenticatorRecoveryCodes"),
                            "ShowTwoFactorAuthenticatorRecoveryCodes", TwoFactorTests.Describe(verified));

                        index = await user.GetStringAsync("/Manage/Index");

                        r.Verify("管理画面は、TOTP を登録済みと出す",
                            (index ?? "").Contains("/Manage/ManageTwoFactorAuthenticator"),
                            "出す",
                            (index ?? "").Contains("/Manage/ManageTwoFactorAuthenticator") ? "出す" : "**出さない**");
                    }
                }
                finally
                {
                    await TwoFactorTests.CleanUpAsync(admin, userName);
                }

                r.Done();
            }
        }

        /// <summary>RT-294.63 管理画面でサインインし直しただけでは、auth_time は新しくならない</summary>
        /// <param name="targetKey">core / netfx</param>
        /// <returns>Task</returns>
        [SkippableTheory]
        [MemberData(nameof(AllTargets))]
        public async Task RT29463_管理画面の再サインインではauth_timeを新しくしない(string targetKey)
        {
            using (IdPClient admin = this.Client(targetKey))
            {
                string userName = TwoFactorTests.UniqueName();

                TestReport r = this.Report("RT-294.63",
                    "管理画面でサインインし直しただけでは、auth_time は新しくならない（max_age の再認証が効く）",
                    "**以前は、管理画面の操作のたびにサインインし直し、auth_time を「いま」にしていた。**"
                    + "**資格情報を確かめない操作（2FA の有効化など）でも新しくなる**ので、"
                    + "RP が `max_age` で求めた再認証が、行われないまま通っていた。"
                    + "**auth_time を書くのは、資格情報を確かめた所だけ**にした（パスワードの再確認など）。",
                    "OIDC Core §2 auth_time / §3.1.2.1 / #294（ManageController.*.cs の 2 回目のレビュー S1）");

                r.Target("利用者名 = " + userName + " / client_name=" + KnownClients.TestClient + " / max_age=2");

                try
                {
                    await admin.SignInAsAdministratorAsync();
                    await UsersAdmin.SkipIfLockedDownAsync(admin);

                    HttpResponseMessage created = await UsersAdmin.CreateAsync(
                        admin, userName, userName + "@example.com", "User");

                    Assert.True(created.StatusCode == HttpStatusCode.Found || created.StatusCode == HttpStatusCode.Redirect,
                        "前提: 利用者を作れること");

                    using (IdPClient user = this.Client(targetKey))
                    {
                        string password = user.Config.Get("TestUserPWD");
                        ClientRegistration reg = Flows.Registration(user, KnownClients.TestClient);

                        r.Step("(1) サインインし、2FA を有効にしておく（手順 2 で、パスワードを確かめて無効にするため）");

                        Assert.True(await user.TrySignInAsync(userName, password),
                            "前提: 作った利用者でサインインできること");

                        await TwoFactorTests.EnableTwoFactorAsync(user);

                        //  **秒単位で判定する**ので、max_age を超えるまで待つ（RT-247.1 と同じ）。
                        await Task.Delay(3000);

                        r.Step("(2) パスワードを確かめて 2FA を無効にし、すぐに max_age=2 で認可リクエストを送る");

                        HttpResponseMessage disabled = await TwoFactorTests.PostIndexFormAsync(
                            user, "/Manage/DisableTwoFactorAuthentication", password);

                        Assert.True(disabled.Headers.Location != null,
                            "前提: 2FA を無効にできること（" + TwoFactorTests.Describe(disabled) + "）");

                        AuthZResponse afterPassword = await user.AuthorizeAsync(
                            TwoFactorTests.AuthZParameters(reg, "state-rt29463-1", "2"));

                        bool wentOn = afterPassword.NeedsConsent || !string.IsNullOrEmpty(afterPassword.Code);

                        r.Verify("パスワードを確かめた直後は、再認証を求めない（先へ進む）", wentOn,
                            "同意画面 または 認可コード",
                            afterPassword.NeedsConsent ? "同意画面"
                                : (!string.IsNullOrEmpty(afterPassword.Code) ? "認可コード"
                                    : "**進まない**（" + afterPassword.ToString() + "）"));

                        await Task.Delay(3000);

                        r.Step("(3) 2FA を有効にし（サインインし直すだけで、資格情報は確かめない）、すぐに max_age=2 で送る");

                        await TwoFactorTests.EnableTwoFactorAsync(user);

                        AuthZResponse afterReSignIn = await user.AuthorizeAsync(
                            TwoFactorTests.AuthZParameters(reg, "state-rt29463-2", "2"));

                        bool reAuth = afterReSignIn.Redirected
                            && !afterReSignIn.NeedsConsent && string.IsNullOrEmpty(afterReSignIn.Code);

                        r.Verify("再認証を求める（同意画面にも、認可コードにも進まない）", reAuth,
                            "再認証へのリダイレクト",
                            reAuth ? afterReSignIn.RedirectTo
                                : (afterReSignIn.NeedsConsent ? "**同意画面へ進んだ**"
                                    : (!string.IsNullOrEmpty(afterReSignIn.Code) ? "**認可コードが出た**"
                                        : "**" + afterReSignIn.ToString() + "**")));
                    }
                }
                finally
                {
                    await TwoFactorTests.CleanUpAsync(admin, userName);
                }

                r.Done();
            }
        }

        /// <summary>RT-294.64 2FA の無効化と電話番号の削除は、パスワードを確かめる</summary>
        /// <param name="targetKey">core / netfx</param>
        /// <returns>Task</returns>
        [SkippableTheory]
        [MemberData(nameof(AllTargets))]
        public async Task RT29464_2FAの無効化はパスワードを確かめる(string targetKey)
        {
            using (IdPClient admin = this.Client(targetKey))
            {
                string userName = TwoFactorTests.UniqueName();

                TestReport r = this.Report("RT-294.64",
                    "2FA の無効化は、パスワードを確かめる（無い・間違いなら無効にしない）",
                    "**以前は、セッションさえあれば 2FA を無効にできた**（電話番号の削除・外部ログインの解除も同じ）。"
                    + "**パスワードの再確認を求める**ようにした。"
                    + "**電話番号の削除・外部ログインの解除も、同じ補助（`VerifyPasswordAsync`）で確かめる**"
                    + "（電話番号は SMS が、外部ログインは上流が要るので、E2E では 2FA の無効化で測る）。",
                    "#294（ManageController.*.cs の 2 回目のレビュー）");

                r.Target("利用者名 = " + userName + "（2FA を有効にした使い捨ての利用者）");

                try
                {
                    await admin.SignInAsAdministratorAsync();
                    await UsersAdmin.SkipIfLockedDownAsync(admin);

                    HttpResponseMessage created = await UsersAdmin.CreateAsync(
                        admin, userName, userName + "@example.com", "User");

                    Assert.True(created.StatusCode == HttpStatusCode.Found || created.StatusCode == HttpStatusCode.Redirect,
                        "前提: 利用者を作れること");

                    using (IdPClient user = this.Client(targetKey))
                    {
                        string password = user.Config.Get("TestUserPWD");

                        Assert.True(await user.TrySignInAsync(userName, password),
                            "前提: 作った利用者でサインインできること");

                        await TwoFactorTests.EnableTwoFactorAsync(user);

                        string index = await user.GetStringAsync("/Manage/Index");

                        r.Verify("無効化のフォームに、パスワードの入力欄がある",
                            TwoFactorTests.HasPasswordInput(index, "DisableTwoFactorAuthentication"),
                            "在る",
                            TwoFactorTests.HasPasswordInput(index, "DisableTwoFactorAuthentication") ? "在る" : "**無い**");

                        r.Step("(1) パスワードを送らずに無効にする");

                        await TwoFactorTests.PostIndexFormAsync(user, "/Manage/DisableTwoFactorAuthentication", null);

                        bool stillOn = TwoFactorTests.IsTwoFactorEnabled(await user.GetStringAsync("/Manage/Index"));

                        r.Verify("2FA は有効のまま", stillOn, "有効", stillOn ? "有効" : "**無効になった**");

                        r.Step("(2) 間違ったパスワードで無効にする");

                        await TwoFactorTests.PostIndexFormAsync(user, "/Manage/DisableTwoFactorAuthentication", password + "x");

                        stillOn = TwoFactorTests.IsTwoFactorEnabled(await user.GetStringAsync("/Manage/Index"));

                        r.Verify("2FA は有効のまま", stillOn, "有効", stillOn ? "有効" : "**無効になった**");

                        r.Step("(3) 正しいパスワードで無効にする");

                        await TwoFactorTests.PostIndexFormAsync(user, "/Manage/DisableTwoFactorAuthentication", password);

                        bool off = !TwoFactorTests.IsTwoFactorEnabled(await user.GetStringAsync("/Manage/Index"));

                        r.Verify("2FA が無効になる", off, "無効", off ? "無効" : "**有効のまま**");
                    }
                }
                finally
                {
                    await TwoFactorTests.CleanUpAsync(admin, userName);
                }

                r.Done();
            }
        }

        /// <summary>RT-294.65 認証アプリの未確定の鍵は、作った利用者にしか使われない</summary>
        /// <param name="targetKey">core</param>
        /// <returns>Task</returns>
        [SkippableTheory]
        [MemberData(nameof(CoreOnly))]
        public async Task RT29465_未確定のTOTPの鍵はほかの利用者に使われない(string targetKey)
        {
            using (IdPClient admin = this.Client(targetKey))
            {
                string userA = TwoFactorTests.UniqueName();
                string userB = TwoFactorTests.UniqueName();

                TestReport r = this.Report("RT-294.65",
                    "認証アプリの未確定の鍵は、同じブラウザで後からサインインした利用者に使われない",
                    "**未確定の鍵は TempData（Cookie）に置く**（RT-294.60）。**TempData はサインアウトしても残る**ので、"
                    + "**以前は、同じブラウザで後からサインインした利用者に、前の利用者が見た鍵を出していた**"
                    + "（そのまま登録すると、前の利用者がコードを作れる）。"
                    + "**鍵を利用者の id と組にして置き、id が合うときだけ使う**ようにした。",
                    "#294（ManageController.*.cs の 2 回目のレビュー）");

                r.Target("利用者名 = " + userA + " → " + userB + "（同じ IdPClient = 同じブラウザ）");

                try
                {
                    await admin.SignInAsAdministratorAsync();
                    await UsersAdmin.SkipIfLockedDownAsync(admin);

                    foreach (string name in new[] { userA, userB })
                    {
                        HttpResponseMessage created = await UsersAdmin.CreateAsync(
                            admin, name, name + "@example.com", "User");

                        Assert.True(created.StatusCode == HttpStatusCode.Found || created.StatusCode == HttpStatusCode.Redirect,
                            "前提: 利用者を作れること");
                    }

                    using (IdPClient browser = this.Client(targetKey))
                    {
                        string password = browser.Config.Get("TestUserPWD");

                        r.Step("(1) 利用者 A で、認証アプリの登録画面を開く（登録はしない）");

                        Assert.True(await browser.TrySignInAsync(userA, password), "前提: A でサインインできること");

                        string bodyA = await browser.GetStringAsync("/Manage/EnableTwoFactorAuthenticator");
                        string secretA = TwoFactorTests.SecretOf(bodyA);

                        Skip.If(secretA == null, "認証アプリの登録画面が開きません（" + Html.Describe(bodyA) + "）。");

                        r.Step("(2) 同じブラウザで利用者 B としてサインインし直し、登録画面を開く");

                        //  **サインアウトを挟んでも同じ**（TempData の Cookie は、サインアウトでは消えない）。
                        Assert.True(await browser.TrySignInAsync(userB, password), "前提: B でサインインできること");

                        string bodyB = await browser.GetStringAsync("/Manage/EnableTwoFactorAuthenticator");
                        string secretB = TwoFactorTests.SecretOf(bodyB);

                        r.Verify("B には、A に出した鍵を出さない",
                            secretB != null && secretB != secretA,
                            "別の鍵",
                            secretB == null ? "**鍵が無い**" : (secretB == secretA ? "**A と同じ鍵**" : "別の鍵"));

                        r.Step("(3) A の鍵で作ったコードを、B の登録に送る");

                        HttpResponseMessage posted = await TwoFactorTests.PostFormFromAsync(browser, bodyB,
                            new Dictionary<string, string>() { { "Code", Totp.Compute(secretA, DateTimeOffset.UtcNow) } },
                            "/Manage/EnableTwoFactorAuthenticator");

                        bool refused = posted.Headers.Location == null
                            || !posted.Headers.Location.ToString().Contains("ShowTwoFactorAuthenticatorRecoveryCodes");

                        r.Verify("登録されない", refused, "登録されない", refused ? "登録されない" : "**登録された**");
                    }
                }
                finally
                {
                    await TwoFactorTests.CleanUpAsync(admin, userA);
                    await TwoFactorTests.CleanUpAsync(admin, userB);
                }

                r.Done();
            }
        }

        /// <summary>RT-294.66 登録済みの認証アプリの鍵は、登録画面に出さない</summary>
        /// <param name="targetKey">core</param>
        /// <returns>Task</returns>
        [SkippableTheory]
        [MemberData(nameof(CoreOnly))]
        public async Task RT29466_登録済みのTOTPの鍵は出さない(string targetKey)
        {
            using (IdPClient admin = this.Client(targetKey))
            {
                string userName = TwoFactorTests.UniqueName();

                TestReport r = this.Report("RT-294.66",
                    "認証アプリを登録した後は、登録画面を開いても鍵を出さない（管理の画面へ戻す）",
                    "**以前は、登録済みの鍵を登録画面に何度でも出していた**（共有鍵と QR コード）。"
                    + "**セッションさえあれば、認証アプリと同じコードを作れるようになった。**"
                    + "**登録済みなら、登録画面は出さずに管理の画面へ戻す。** 登録し直すときは、リセットを通す。",
                    "#294（ManageController.*.cs の 3 回目のレビュー S1）");

                r.Target("利用者名 = " + userName + "（認証アプリを登録した使い捨ての利用者）");

                try
                {
                    using (IdPClient user = await this.TotpEnrolledClientAsync(admin, targetKey, userName))
                    {
                        r.Step("(1) 登録画面を開く（GET）");

                        HttpResponseMessage get = await user.GetAsync("/Manage/EnableTwoFactorAuthenticator");
                        string body = await get.Content.ReadAsStringAsync();

                        r.Verify("管理の画面へ戻す",
                            get.Headers.Location != null
                                && get.Headers.Location.ToString().Contains("ManageTwoFactorAuthenticator"),
                            "ManageTwoFactorAuthenticator へ", TwoFactorTests.Describe(get));

                        r.Verify("鍵を出さない", TwoFactorTests.SecretOf(body) == null,
                            "出さない", TwoFactorTests.SecretOf(body) == null ? "出さない" : "**出した**");

                        r.Step("(2) 登録の POST を直接送る");

                        string indexBody = await user.GetStringAsync("/Manage/Index");

                        HttpResponseMessage post = await user.PostFormAsync("/Manage/EnableTwoFactorAuthenticator",
                            new Dictionary<string, string>()
                            {
                                { "__RequestVerificationToken", Html.Antiforgery(indexBody) },
                                { "Code", "000000" }
                            });

                        r.Verify("受けずに、管理の画面へ戻す",
                            post.Headers.Location != null
                                && post.Headers.Location.ToString().Contains("ManageTwoFactorAuthenticator"),
                            "ManageTwoFactorAuthenticator へ", TwoFactorTests.Describe(post));
                    }
                }
                finally
                {
                    await TwoFactorTests.CleanUpAsync(admin, userName);
                }

                r.Done();
            }
        }

        /// <summary>RT-294.67 回復コードの再発行と、認証アプリのリセットは、パスワードを確かめる</summary>
        /// <param name="targetKey">core</param>
        /// <returns>Task</returns>
        [SkippableTheory]
        [MemberData(nameof(CoreOnly))]
        public async Task RT29467_回復コードの再発行とリセットはパスワードを確かめる(string targetKey)
        {
            using (IdPClient admin = this.Client(targetKey))
            {
                string userName = TwoFactorTests.UniqueName();

                TestReport r = this.Report("RT-294.67",
                    "回復コードの再発行と、認証アプリのリセットは、パスワードを確かめる（無い・間違いなら行わない）",
                    "**以前は、セッションさえあれば、新しい回復コードを画面に出せ、認証アプリを外せた。**"
                    + "**回復コードは、それだけで 2FA を通れる。**"
                    + "**どちらもパスワードを確かめる**ようにした。",
                    "#294（ManageController.*.cs の 3 回目のレビュー S2）");

                r.Target("利用者名 = " + userName + "（認証アプリを登録した使い捨ての利用者）");

                try
                {
                    using (IdPClient user = await this.TotpEnrolledClientAsync(admin, targetKey, userName))
                    {
                        string password = user.Config.Get("TestUserPWD");

                        r.Step("(1) 回復コードの再発行 : パスワード無し → 間違い → 正しい");

                        foreach (string wrong in new[] { null, password + "x" })
                        {
                            HttpResponseMessage refused = await TwoFactorTests.PostPageFormAsync(user,
                                "/Manage/GenerateTwoFactorAuthenticatorRecoveryCodes", wrong);
                            string refusedBody = await refused.Content.ReadAsStringAsync();

                            r.Verify(wrong == null ? "パスワード無しでは、回復コードを出さない" : "間違ったパスワードでは、回復コードを出さない",
                                !refusedBody.Contains("<code>"),
                                "出さない", refusedBody.Contains("<code>") ? "**出した**" : "出さない");
                        }

                        HttpResponseMessage generated = await TwoFactorTests.PostPageFormAsync(user,
                            "/Manage/GenerateTwoFactorAuthenticatorRecoveryCodes", password);
                        string generatedBody = await generated.Content.ReadAsStringAsync();

                        r.Verify("正しいパスワードなら、回復コードを出す", generatedBody.Contains("<code>"),
                            "出す", generatedBody.Contains("<code>") ? "出した" : "**出さない**（" + TwoFactorTests.Describe(generated) + "）");

                        r.Step("(2) 認証アプリのリセット : 間違い → 正しい");

                        await TwoFactorTests.PostPageFormAsync(user, "/Manage/ResetTwoFactorAuthenticator", password + "x");

                        string index = await user.GetStringAsync("/Manage/Index");

                        r.Verify("間違ったパスワードでは、認証アプリは登録済みのまま",
                            (index ?? "").Contains("/Manage/ManageTwoFactorAuthenticator"),
                            "登録済み", (index ?? "").Contains("/Manage/ManageTwoFactorAuthenticator") ? "登録済み" : "**外れた**");

                        await TwoFactorTests.PostPageFormAsync(user, "/Manage/ResetTwoFactorAuthenticator", password);

                        index = await user.GetStringAsync("/Manage/Index");

                        r.Verify("正しいパスワードなら、認証アプリが外れる",
                            !(index ?? "").Contains("/Manage/ManageTwoFactorAuthenticator"),
                            "外れる", !(index ?? "").Contains("/Manage/ManageTwoFactorAuthenticator") ? "外れた" : "**登録済みのまま**");
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

        /// <summary>利用者を作ってサインインし、認証アプリを登録した IdPClient を返す（net10.0 版だけ）</summary>
        /// <param name="admin">管理者の IdPClient（中でサインインする）</param>
        /// <param name="targetKey">対象</param>
        /// <param name="userName">利用者名</param>
        /// <returns>サインインしたままの IdPClient（呼ぶ側で Dispose する）</returns>
        private async Task<IdPClient> TotpEnrolledClientAsync(IdPClient admin, string targetKey, string userName)
        {
            await admin.SignInAsAdministratorAsync();
            await UsersAdmin.SkipIfLockedDownAsync(admin);

            HttpResponseMessage created = await UsersAdmin.CreateAsync(
                admin, userName, userName + "@example.com", "User");

            Assert.True(created.StatusCode == HttpStatusCode.Found || created.StatusCode == HttpStatusCode.Redirect,
                "前提: 利用者を作れること");

            IdPClient user = this.Client(targetKey);

            Assert.True(await user.TrySignInAsync(userName, user.Config.Get("TestUserPWD")),
                "前提: 作った利用者でサインインできること");

            await TwoFactorTests.EnableTwoFactorAsync(user);

            HttpResponseMessage get = await user.GetAsync("/Manage/EnableTwoFactorAuthenticator");
            string body = await get.Content.ReadAsStringAsync();
            string secret = TwoFactorTests.SecretOf(body);

            Skip.IfNot(get.StatusCode == HttpStatusCode.OK && secret != null,
                "認証アプリの登録画面が開きません（" + Html.Describe(body) + "）。");

            HttpResponseMessage verified = await TwoFactorTests.PostFormFromAsync(user, body,
                new Dictionary<string, string>() { { "Code", Totp.Compute(secret, DateTimeOffset.UtcNow) } },
                "/Manage/EnableTwoFactorAuthenticator");

            Assert.True(verified.Headers.Location != null
                && verified.Headers.Location.ToString().Contains("ShowTwoFactorAuthenticatorRecoveryCodes"),
                "前提: 認証アプリを登録できること（" + TwoFactorTests.Describe(verified) + "）");

            return user;
        }

        /// <summary>その画面を開き、トークンとパスワードを付けて、同じ URL へ POST する</summary>
        /// <param name="user">利用者でサインインした IdPClient</param>
        /// <param name="path">画面の URL（POST 先も同じ）</param>
        /// <param name="password">パスワード（null なら送らない）</param>
        /// <returns>応答</returns>
        private static async Task<HttpResponseMessage> PostPageFormAsync(IdPClient user, string path, string password)
        {
            string page = await user.GetStringAsync(path);

            Dictionary<string, string> form = new Dictionary<string, string>()
            {
                { "__RequestVerificationToken", Html.Antiforgery(page) }
            };

            if (password != null)
            {
                form["password"] = password;
            }

            return await user.PostFormAsync(path, form);
        }

        /// <summary>認可リクエストのパラメタ（max_age 付き。`MaxAgeTests` と同じ形）</summary>
        /// <param name="reg">ClientRegistration</param>
        /// <param name="state">state</param>
        /// <param name="maxAge">max_age</param>
        /// <returns>パラメタ</returns>
        private static Dictionary<string, string> AuthZParameters(ClientRegistration reg, string state, string maxAge)
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

        /// <summary>管理画面（Index）のボタンのフォームを、パスワードを付けて送る</summary>
        /// <param name="user">利用者でサインインした IdPClient</param>
        /// <param name="action">送り先</param>
        /// <param name="password">パスワード（null なら送らない）</param>
        /// <returns>応答</returns>
        private static async Task<HttpResponseMessage> PostIndexFormAsync(IdPClient user, string action, string password)
        {
            string indexBody = await user.GetStringAsync("/Manage/Index");

            Dictionary<string, string> form = new Dictionary<string, string>()
            {
                { "__RequestVerificationToken", Html.Antiforgery(indexBody) }
            };

            if (password != null)
            {
                form["password"] = password;
            }

            return await user.PostFormAsync(action, form);
        }

        /// <summary>管理画面が、2FA を有効と出しているか（無効化のフォームが在るか）</summary>
        /// <param name="index">管理画面の本文</param>
        /// <returns>有効なら true</returns>
        private static bool IsTwoFactorEnabled(string index)
        {
            return (index ?? "").Contains("DisableTwoFactorAuthentication");
        }

        /// <summary>そのフォームに、パスワードの入力欄が在るか</summary>
        /// <param name="body">画面の本文</param>
        /// <param name="action">フォームの送り先（の一部）</param>
        /// <returns>在れば true</returns>
        private static bool HasPasswordInput(string body, string action)
        {
            Match form = Regex.Match(body ?? "",
                "<form\\b[^>]*action=\"[^\"]*" + action + "[^\"]*\"[^>]*>(?<f>.*?)</form>",
                RegexOptions.IgnoreCase | RegexOptions.Singleline);

            return form.Success
                && Regex.IsMatch(form.Groups["f"].Value, "<input\\b[^>]*type=\"password\"[^>]*name=\"password\"",
                    RegexOptions.IgnoreCase);
        }

        /// <summary>認証アプリの登録画面から、共有鍵を取る（`otpauth://totp/...?secret=...`）</summary>
        /// <param name="body">画面の本文</param>
        /// <returns>共有鍵（Base32。無ければ null）</returns>
        private static string SecretOf(string body)
        {
            Match secret = Regex.Match(WebUtility.HtmlDecode(body ?? ""), "secret=(?<s>[A-Z2-7]+)");

            return secret.Success ? secret.Groups["s"].Value : null;
        }

        /// <summary>パスワードでサインインし、2FA の手段の選択肢を返す</summary>
        /// <param name="client">IdPClient（新しいもの）</param>
        /// <param name="userName">利用者名</param>
        /// <returns>選択肢の値</returns>
        private static async Task<List<string>> ProvidersAsync(IdPClient client, string userName)
        {
            HttpResponseMessage get = await client.GetAsync("/Account/Login");
            string loginBody = await get.Content.ReadAsStringAsync();

            HttpResponseMessage post = await client.PostFormAsync("/Account/Login", new Dictionary<string, string>()
            {
                { "__RequestVerificationToken", Html.Antiforgery(loginBody) },
                { "Email", userName },
                { "Password", client.Config.Get("TestUserPWD") },
                { "RememberMe", "false" },
                { "ReturnUrl", TwoFactorTests.LocalPath(client, "/Manage/Index") },
                { "submitButtonName", "normal_signin" }
            });

            Assert.True(post.Headers.Location != null && post.Headers.Location.ToString().Contains("/Account/SendCode"),
                "前提: パスワードの後に 2FA の手段の選択へ送られること（" + TwoFactorTests.Describe(post) + "）");

            HttpResponseMessage send = await client.GetAsync(TwoFactorTests.Resolve(client, post.Headers.Location));
            string sendBody = await send.Content.ReadAsStringAsync();

            return Regex.Matches(sendBody, "<option\\b[^>]*\\bvalue=\"(?<v>[^\"]*)\"", RegexOptions.IgnoreCase)
                .Cast<Match>().Select(m => WebUtility.HtmlDecode(m.Groups["v"].Value)).ToList();
        }

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
