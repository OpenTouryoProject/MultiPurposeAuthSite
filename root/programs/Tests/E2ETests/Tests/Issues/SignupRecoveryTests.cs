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
//* クラス名        ：SignupRecoveryTests
//* クラス日本語名  ：RT-294.4 〜 .7 サインアップの登録し直し・パスワードの失念・リセット
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
using System.Net;
using System.Net.Http;
using System.Threading.Tasks;

using MultiPurposeAuthSite.Tests.E2E.Infrastructure;

using Xunit;
using Xunit.Abstractions;

namespace MultiPurposeAuthSite.Tests.E2E.Tests.Issues
{
    /// <summary>
    /// RT-294.4 〜 .7 サインアップの登録し直し・パスワードの失念・リセット（#294）。
    /// </summary>
    /// <remarks>
    /// **`AccountController.SignUp.cs` のレビューで見つけた穴を、直した形で押さえる。**
    /// **どれも、それまで E2E で 1 度も踏んでいなかった経路である**
    /// （RT-257 はサインアップの入力の検証だけで、**登録し直し・失念・リセットは叩いていなかった**）。
    ///
    /// | ケース | 以前の振る舞い |
    /// |---|---|
    /// | RT-294.4 確認待ちのメアドで登録し直す | **古い利用者を消して、送られてきたパスワードで作り直していた** |
    /// | RT-294.5 居ないメアドでパスワードの失念 | **入力画面を出し直していた**（居れば確認画面。**画面の違いで存在が分かった**） |
    /// | RT-294.6 居ない利用者でメアド検証・リセット | **500**（null の利用者をそのまま渡していた） |
    /// | RT-294.7 code が合わないリセット画面 | **code を見ずに、利用者のメアドを画面に出していた** |
    ///
    /// **メールの中身は測れない**（`IsDebug` では送らずにデバッグ出力へ書くだけ）。
    /// **そのため、画面と利用者の一覧で判定する。**
    /// </remarks>
    public class SignupRecoveryTests : TargetTestBase
    {
        /// <summary>エラー画面の見出し（Views/Shared/Error.cshtml。両アプリ共通）</summary>
        private const string ErrorHeading = "<h2 class=\"text-danger\">";

        /// <summary>コンストラクタ</summary>
        /// <param name="output">ITestOutputHelper</param>
        public SignupRecoveryTests(ITestOutputHelper output) : base(output)
        {
        }

        /// <summary>RT-294.4 確認待ちのメアドで登録し直しても、既存の利用者は作り直されない</summary>
        /// <param name="targetKey">core / netfx</param>
        /// <returns>Task</returns>
        [SkippableTheory]
        [MemberData(nameof(AllTargets))]
        public async Task RT29404_確認待ちのメアドで登録し直しても作り直されない(string targetKey)
        {
            using (IdPClient client = this.Client(targetKey))
            {
                string first = SignupRecoveryTests.UniqueName();
                string second = SignupRecoveryTests.UniqueName();
                string email = first + "@example.com";

                TestReport r = this.Report("RT-294.4",
                    "確認待ちのメアドで登録し直しても、既存の利用者は作り直されない",
                    "**以前は、確認待ちの利用者を消して、送られてきたパスワードで作り直していた。**"
                    + "**他人が登録し直すとパスワードを差し替えられ**、"
                    + "**確認のメールは本人に届くので、本人が踏むと差し替えたパスワードのまま確認済みになった。**"
                    + "**作り直しをやめ、既存の利用者に確認のメールを送り直すだけにした**（画面は成功のときと同じ）。",
                    "#294（AccountController.SignUp.cs のレビュー 1・3・4）");

                r.Target("1 人目 = " + first + " / 2 人目 = " + second + " / メアドは同じ " + email);

                try
                {
                    r.Step("(1) 1 人目をサインアップする（メアドは確認待ちのまま）");

                    HttpResponseMessage post1 = await SignupRecoveryTests.RegisterAsync(client, first, email);
                    string body1 = await post1.Content.ReadAsStringAsync();

                    Assert.True(post1.StatusCode == HttpStatusCode.OK && !Html.HasField(body1, "ConfirmPassword"),
                        "前提: 1 人目をサインアップできること（" + Html.Describe(body1) + "）");

                    r.Step("(2) 同じメアドで、別の利用者名で登録し直す");

                    HttpResponseMessage post2 = await SignupRecoveryTests.RegisterAsync(client, second, email);
                    string body2 = await post2.Content.ReadAsStringAsync();

                    r.VerifyEqual("HTTP 200", "200", ((int)post2.StatusCode).ToString());

                    r.Verify("**成功のときと同じ画面**（メアド検証の画面。入力欄もエラーも無い）",
                        !Html.HasField(body2, "ConfirmPassword") && !Html.HasValidationError(body2),
                        "メアド検証の画面",
                        Html.HasField(body2, "ConfirmPassword")
                            ? "**サインアップ画面が再表示された**: " + Html.ErrorSummary(body2)
                            : (Html.HasValidationError(body2) ? "**エラーが出ている**" : "メアド検証の画面"));

                    r.Step("(3) 管理画面の一覧で、利用者を確かめる");

                    await client.SignInAsAdministratorAsync();
                    string index = await UsersAdmin.SkipIfLockedDownAsync(client);

                    string firstEmail = UsersAdmin.FindEmail(index, first);

                    r.Verify("**1 人目が残っている**（消して作り直していない）",
                        firstEmail == email,
                        "残っている（メアドも同じ）",
                        (firstEmail == null) ? "**消えている**" : "残っている（メアド = " + firstEmail + "）");

                    r.Verify("**2 人目は作られていない**",
                        UsersAdmin.FindId(index, second) == null,
                        "作られていない",
                        (UsersAdmin.FindId(index, second) == null) ? "作られていない" : "**作られている**（1 人目と差し替わった）");

                    r.Note("**パスワードは変わらない。** 忘れていれば、パスワードの失念から戻せる"
                        + "（確認前でもリセットできる）。**確認のメールは 1 人目に送り直される**（中身は測れない）。");
                }
                finally
                {
                    r.Step("(4) 後片付け : 管理画面から削除する");

                    await client.SignInAsAdministratorAsync();
                    await UsersAdmin.DeleteByUserNameAsync(client, first);
                    await UsersAdmin.DeleteByUserNameAsync(client, second);
                }

                r.Done();
            }
        }

        /// <summary>RT-294.5 パスワードの失念は、居ないメアドでも、居るメアドと同じ画面になる</summary>
        /// <param name="targetKey">core / netfx</param>
        /// <returns>Task</returns>
        [SkippableTheory]
        [MemberData(nameof(AllTargets))]
        public async Task RT29405_パスワードの失念は居ないメアドでも同じ画面になる(string targetKey)
        {
            using (IdPClient client = this.Client(targetKey))
            {
                string userName = SignupRecoveryTests.UniqueName();
                string email = userName + "@example.com";
                string unknown = SignupRecoveryTests.UniqueName() + "@example.com";

                TestReport r = this.Report("RT-294.5",
                    "パスワードの失念は、居ないメアドでも、居るメアドと同じ画面になる",
                    "**コメントには「ユーザーが存在しないことを（UI経由で）公開しない」と書いてあった**が、"
                    + "**居なければ入力画面を出し直し、居れば確認画面を出していた。**"
                    + "**画面の違いで、メアドが登録されているかが分かった。**"
                    + "**どちらも確認画面を返す**ように直した（メールは居るときだけ送る）。",
                    "#294（AccountController.SignUp.cs のレビュー 2）");

                r.Target("居るメアド = " + email + " / 居ないメアド = " + unknown);

                try
                {
                    r.Step("(1) 居る利用者を作る（サインアップ。確認待ちでもリセットできる）");

                    HttpResponseMessage reg = await SignupRecoveryTests.RegisterAsync(client, userName, email);
                    string regBody = await reg.Content.ReadAsStringAsync();

                    Assert.True(reg.StatusCode == HttpStatusCode.OK && !Html.HasField(regBody, "ConfirmPassword"),
                        "前提: サインアップできること（" + Html.Describe(regBody) + "）");

                    r.Step("(2) 居るメアドで、パスワードの失念を送る");

                    HttpResponseMessage known = await SignupRecoveryTests.ForgotPasswordAsync(client, email);
                    string knownBody = await known.Content.ReadAsStringAsync();

                    r.VerifyEqual("HTTP 200（居る）", "200", ((int)known.StatusCode).ToString());

                    r.Verify("確認画面になる（入力欄が無い）",
                        !Html.HasField(knownBody, "Email"),
                        "入力欄が無い", Html.HasField(knownBody, "Email") ? "**入力欄が在る**" : "入力欄が無い");

                    r.Step("(3) 居ないメアドで、パスワードの失念を送る");

                    HttpResponseMessage none = await SignupRecoveryTests.ForgotPasswordAsync(client, unknown);
                    string noneBody = await none.Content.ReadAsStringAsync();

                    r.VerifyEqual("HTTP 200（居ない）", "200", ((int)none.StatusCode).ToString());

                    r.Verify("**確認画面になる**（入力画面を出し直さない）",
                        !Html.HasField(noneBody, "Email"),
                        "入力欄が無い",
                        Html.HasField(noneBody, "Email") ? "**入力画面が出し直された**（存在が分かる）" : "入力欄が無い");

                    r.VerifyEqual("**居るときと同じ画面である**（題名・見出し・欄）",
                        SignupRecoveryTests.Shape(knownBody), SignupRecoveryTests.Shape(noneBody));
                }
                finally
                {
                    r.Step("(4) 後片付け : 管理画面から削除する");

                    await client.SignInAsAdministratorAsync();
                    await UsersAdmin.DeleteByUserNameAsync(client, userName);
                }

                r.Done();
            }
        }

        /// <summary>RT-294.6 利用者が居ないメアド検証・リセットは、500 にならずエラー画面になる</summary>
        /// <param name="targetKey">core / netfx</param>
        /// <returns>Task</returns>
        [SkippableTheory]
        [MemberData(nameof(AllTargets))]
        public async Task RT29406_利用者が居ないときはエラー画面になる(string targetKey)
        {
            using (IdPClient client = this.Client(targetKey))
            {
                string userId = Guid.NewGuid().ToString();

                TestReport r = this.Report("RT-294.6",
                    "利用者が居ないメアド検証・リセットは、500 にならずエラー画面になる",
                    "**メールのリンクは、利用者が消えた後にも踏まれる**（古いメール・書き換えた URL）。"
                    + "**以前は、引けなかった利用者（null）をそのまま Identity に渡し、500 になっていた。**"
                    + "**4 か所とも、エラー画面を返す**ように直した。",
                    "#294（AccountController.SignUp.cs のレビュー 5）");

                r.Target("userId = 新しい GUID（どの利用者でもない）");

                //  **POST の AntiForgery トークンは、サインアップ画面から取る**（画面ごとに分かれていない）。
                string form = await SignupRecoveryTests.GetRegisterAsync(client);
                string token = Html.Antiforgery(form);

                r.Step("(1) GET /Account/EmailConfirmation");

                await SignupRecoveryTests.VerifyErrorPageAsync(r, "GET /Account/EmailConfirmation",
                    await client.GetAsync("/Account/EmailConfirmation?userId=" + userId + "&code=dummy"));

                r.Step("(2) POST /Account/EmailConfirmation（約款に同意）");

                await SignupRecoveryTests.VerifyErrorPageAsync(r, "POST /Account/EmailConfirmation",
                    await client.PostFormAsync("/Account/EmailConfirmation", new Dictionary<string, string>()
                    {
                        { "__RequestVerificationToken", token },
                        { "UserId", userId },
                        { "Code", "dummy" },
                        { "Agreement", "" },
                        { "AcceptedAgreement", "true" }
                    }));

                r.Step("(3) GET /Account/ResetPassword");

                await SignupRecoveryTests.VerifyErrorPageAsync(r, "GET /Account/ResetPassword",
                    await client.GetAsync("/Account/ResetPassword?userId=" + userId + "&code=dummy"));

                r.Step("(4) POST /Account/ResetPassword");

                string password = client.Config.Get("TestUserPWD");

                await SignupRecoveryTests.VerifyErrorPageAsync(r, "POST /Account/ResetPassword",
                    await client.PostFormAsync("/Account/ResetPassword", new Dictionary<string, string>()
                    {
                        { "__RequestVerificationToken", token },
                        { "UserId", userId },
                        { "Email", "nobody@example.com" },
                        { "Password", password },
                        { "ConfirmPassword", password },
                        { "Code", "dummy" }
                    }));

                r.Note("**(2) は約款を出す配備（DisplayAgreementScreen）でだけ、利用者を引く枝に入る。**"
                    + "**出さない配備では、入口でエラー画面になる**（どちらでもエラー画面であることは同じ）。");

                r.Done();
            }
        }

        /// <summary>RT-294.7 リセット画面は、code が合わなければメアドを出さない</summary>
        /// <param name="targetKey">core / netfx</param>
        /// <returns>Task</returns>
        [SkippableTheory]
        [MemberData(nameof(AllTargets))]
        public async Task RT29407_リセット画面はcodeが合わなければメアドを出さない(string targetKey)
        {
            using (IdPClient client = this.Client(targetKey))
            {
                string userName = SignupRecoveryTests.UniqueName();
                string email = userName + "@example.com";

                TestReport r = this.Report("RT-294.7",
                    "リセット画面は、code が合わなければメアドを出さない（エラー画面になる）",
                    "**以前は code を確かめずに、userId の利用者のメアドを画面に出していた。**"
                    + "**userId が分かれば、code が何でもメアドが読めた。**"
                    + "**code を確かめてから画面を出す**ように直した（合わなければエラー画面）。",
                    "#294（AccountController.SignUp.cs のレビュー 6）");

                r.Target("利用者名 = " + userName + " / code = でたらめな値");

                try
                {
                    r.Step("(1) 利用者を作り、管理画面の一覧で id を引く");

                    HttpResponseMessage reg = await SignupRecoveryTests.RegisterAsync(client, userName, email);
                    string regBody = await reg.Content.ReadAsStringAsync();

                    Assert.True(reg.StatusCode == HttpStatusCode.OK && !Html.HasField(regBody, "ConfirmPassword"),
                        "前提: サインアップできること（" + Html.Describe(regBody) + "）");

                    await client.SignInAsAdministratorAsync();
                    string index = await UsersAdmin.SkipIfLockedDownAsync(client);
                    string userId = UsersAdmin.FindId(index, userName);

                    Assert.False(string.IsNullOrEmpty(userId), "前提: 一覧から id を引けること");

                    r.Step("(2) でたらめな code で、リセット画面を開く");

                    HttpResponseMessage get = await client.GetAsync(
                        "/Account/ResetPassword?userId=" + WebUtility.UrlEncode(userId) + "&code=dummy");
                    string body = await get.Content.ReadAsStringAsync();

                    r.VerifyEqual("HTTP 200（500 にならない）", "200", ((int)get.StatusCode).ToString());

                    r.Verify("**エラー画面になる**",
                        body.Contains(SignupRecoveryTests.ErrorHeading),
                        "エラー画面", body.Contains(SignupRecoveryTests.ErrorHeading) ? "エラー画面" : "**" + Html.Describe(body) + "**");

                    r.Verify("**メアドが画面に出ない**",
                        !WebUtility.HtmlDecode(body).Contains(email),
                        "出ない", WebUtility.HtmlDecode(body).Contains(email) ? "**出ている**" : "出ない");

                    r.Note("**正しい code での表示は測れない**（code はメールでしか届かない）。");
                }
                finally
                {
                    r.Step("(3) 後片付け : 管理画面から削除する");

                    await client.SignInAsAdministratorAsync();
                    await UsersAdmin.DeleteByUserNameAsync(client, userName);
                }

                r.Done();
            }
        }

        #region 補助

        /// <summary>この回だけの利用者名を作る（DB ストアでも衝突しない）</summary>
        /// <returns>利用者名</returns>
        private static string UniqueName()
        {
            return "e2e_rt294_" + Guid.NewGuid().ToString("N").Substring(0, 8);
        }

        /// <summary>サインアップ画面を開き、本文を返す（閉じていれば Skip）</summary>
        /// <param name="client">IdPClient</param>
        /// <returns>本文</returns>
        private static async Task<string> GetRegisterAsync(IdPClient client)
        {
            HttpResponseMessage get = await client.GetAsync("/Account/Register");
            string body = await get.Content.ReadAsStringAsync();

            // **サインアップが閉じていれば Error 画面になる**（EnableSignupProcess）。
            Skip.IfNot(get.StatusCode == HttpStatusCode.OK && Html.HasField(body, "ConfirmPassword"),
                "サインアップ画面が開きません（EnableSignupProcess を確認）。");

            return body;
        }

        /// <summary>サインアップする（画面を開いて送る）</summary>
        /// <param name="client">IdPClient</param>
        /// <param name="userName">利用者名</param>
        /// <param name="email">メアド</param>
        /// <returns>応答</returns>
        private static async Task<HttpResponseMessage> RegisterAsync(
            IdPClient client, string userName, string email)
        {
            string formBody = await SignupRecoveryTests.GetRegisterAsync(client);

            // **パスワードは構成ファイルの値を使う**（配備の方針を満たすため。値は出力しない）。
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

        /// <summary>パスワードの失念を送る（画面を開いて送る）</summary>
        /// <param name="client">IdPClient</param>
        /// <param name="email">メアド</param>
        /// <returns>応答</returns>
        private static async Task<HttpResponseMessage> ForgotPasswordAsync(IdPClient client, string email)
        {
            HttpResponseMessage get = await client.GetAsync("/Account/ForgotPassword");
            string formBody = await get.Content.ReadAsStringAsync();

            Assert.True(Html.HasField(formBody, "Email"), "前提: パスワードの失念の画面が開くこと");

            return await client.PostFormAsync("/Account/ForgotPassword", new Dictionary<string, string>()
            {
                { "__RequestVerificationToken", Html.Antiforgery(formBody) },
                { "Email", email }
            });
        }

        /// <summary>画面の形（題名・見出し・欄）。本文の長さは含めない</summary>
        /// <param name="body">HTML</param>
        /// <returns>形</returns>
        private static string Shape(string body)
        {
            string described = Html.Describe(body);
            int bytes = described.LastIndexOf(" / ");

            return (bytes < 0) ? described : described.Substring(0, bytes);
        }

        /// <summary>200 のエラー画面であることを確かめる</summary>
        /// <param name="r">TestReport</param>
        /// <param name="label">何を叩いたか</param>
        /// <param name="res">応答</param>
        /// <returns>Task</returns>
        private static async Task VerifyErrorPageAsync(TestReport r, string label, HttpResponseMessage res)
        {
            string body = await res.Content.ReadAsStringAsync();

            r.VerifyEqual(label + " : HTTP 200（500 にならない）", "200", ((int)res.StatusCode).ToString());

            r.Verify(label + " : エラー画面になる",
                body.Contains(SignupRecoveryTests.ErrorHeading),
                "エラー画面",
                body.Contains(SignupRecoveryTests.ErrorHeading) ? "エラー画面" : "**" + Html.Describe(body) + "**");
        }

        #endregion
    }
}
