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
//* クラス名        ：ManageUserAttributeTests
//* クラス日本語名  ：RT-277 管理画面での属性変更（利用者名・パスワード・メアド）
//*
//* 作成日時        ：－
//* 作成者          ：－
//* 更新履歴        ：－
//*
//*  日時        更新者            内容
//*  ----------  ----------------  -------------------------------------------------
//*  2026/10/10  玄人 幸道         新規（#277 の段階 7）
//**********************************************************************************

using System;
using System.Collections.Generic;
using System.Net;
using System.Net.Http;
using System.Threading.Tasks;

using MultiPurposeAuthSite.Tests.E2E.Infrastructure;

using Xunit;
using Xunit.Abstractions;

/// <summary>MultiPurposeAuthSite.Tests.E2E.Tests.Issues</summary>
namespace MultiPurposeAuthSite.Tests.E2E.Tests.Issues
{
    /// <summary>
    /// RT-277 管理画面での属性変更（`/Manage` の `ChangeUserName` / `ChangePassword` / `ChangeEmail`）。
    /// </summary>
    /// <remarks>
    /// **変えたら、その値で使えること**まで見る（#277 の段階 7）。
    /// **変わったと画面が言うだけでは足りない** — **サインインできて初めて、変わったと言える。**
    ///
    /// **使い捨ての利用者を、その都度ひとつ作る。**
    /// **テスト利用者（`super_tanaka`）を使ってはならない** —
    /// **他のテストが、その利用者名とパスワードでサインインする**ためである。
    /// **作成と削除は `/UsersAdmin`**（`RT-257.7` と同じ流儀）。
    ///
    /// **元に戻すところまでを 1 つのテストにする**（「往復」）。
    /// **戻せることも仕様**であり、**途中で落ちても後片付けで利用者ごと消える。**
    /// </remarks>
    public class ManageUserAttributeTests : TargetTestBase
    {
        /// <summary>コンストラクタ</summary>
        /// <param name="output">ITestOutputHelper</param>
        public ManageUserAttributeTests(ITestOutputHelper output) : base(output) { }

        #region RT-277.4

        /// <summary>RT-277.4 利用者名を変えると、新しい名前でサインインできる</summary>
        /// <param name="targetKey">core / netfx</param>
        /// <returns>Task</returns>
        [SkippableTheory]
        [MemberData(nameof(AllTargets))]
        public async Task RT27704_利用者名を変えると新しい名前でサインインできる(string targetKey)
        {
            using (IdPClient admin = await this.AdminClientAsync(targetKey))
            {
                string name1 = ManageUserAttributeTests.UniqueName();
                string name2 = name1 + "_renamed";
                string email = name1 + "@example.com";
                string password = admin.Config.Get("TestUserPWD");
                string current = name1;

                TestReport r = this.Report("RT-277.4",
                    "利用者名を変えると、新しい名前でサインインでき、古い名前では入れない",
                    "**利用者名の編集は、常に出せる**（#151 の段階 3）。"
                    + "**画面が「変えた」と言うだけでは足りない** — "
                    + "**新しい名前で入れて、古い名前では入れない**ことまで見る。"
                    + "**元に戻せること**も押さえる（#277 の段階 7）。",
                    "#151 の段階 3 / #277 / ManageController.ChangeUserName");

                r.Target("利用者 " + name1 + " を作り、" + name2 + " に変えて、戻す");

                await UsersAdmin.SkipIfLockedDownAsync(admin);

                try
                {
                    r.Step("(1) 使い捨ての利用者を作る");

                    HttpResponseMessage created = await UsersAdmin.CreateAsync(
                        admin, name1, email, "User");

                    Assert.True(ManageUserAttributeTests.IsRedirect(created),
                        "前提: 利用者を作れること");

                    bool signedIn = await this.TrySignInAsync(targetKey, name1, password);

                    r.Verify("作った利用者でサインインできる", signedIn,
                        "できる", signedIn ? "できる" : "**できない**");

                    Assert.True(signedIn, "前提: 作った利用者でサインインできること");

                    r.Step("(2) 利用者名を変える");

                    using (IdPClient user = this.Client(targetKey))
                    {
                        Assert.True(await user.TrySignInAsync(name1, password));

                        //  **`Password` も送る。** **`[Required(AllowEmptyStrings = true)]`** なので、
                        //    **項目ごと無いと検証に落ちて、画面が出し直されるだけになる。**
                        //    （`RequirePasswordInEditingUserNameAndEmail` が true の配備でも通るよう、
                        //      空ではなく実際のパスワードを送る）
                        HttpResponseMessage changed = await ManageUserAttributeTests.PostAsync(
                            user, "/Manage/ChangeUserName",
                            new Dictionary<string, string>()
                            {
                                { "UserNameForEdit", name2 },
                                { "Password", password }
                            });

                        r.Verify("管理画面へ戻る（変更の成功）",
                            ManageUserAttributeTests.IsRedirect(changed),
                            "リダイレクト", ((int)changed.StatusCode).ToString()
                                + (ManageUserAttributeTests.IsRedirect(changed) ? ""
                                    : "（再表示 : " + Html.ErrorSummary(
                                        await changed.Content.ReadAsStringAsync()) + "）"));

                        current = name2;

                        string form = await user.GetStringAsync("/Manage/ChangeUserName");

                        r.VerifyEqual("画面の値が新しい名前になる",
                            name2, Html.FieldValue(form, "UserNameForEdit") ?? "（無し）");
                    }

                    r.Step("(3) 新しい名前で入れて、古い名前では入れない");

                    bool withNew = await this.TrySignInAsync(targetKey, name2, password);
                    bool withOld = await this.TrySignInAsync(targetKey, name1, password);

                    r.Verify("新しい名前でサインインできる", withNew,
                        "できる", withNew ? "できる" : "**できない**");

                    r.Verify("古い名前ではサインインできない", !withOld,
                        "できない", withOld ? "**できてしまう**" : "できない");

                    r.Step("(4) 元に戻す");

                    using (IdPClient user = this.Client(targetKey))
                    {
                        Assert.True(await user.TrySignInAsync(name2, password));

                        await ManageUserAttributeTests.PostAsync(
                            user, "/Manage/ChangeUserName",
                            new Dictionary<string, string>()
                            {
                                { "UserNameForEdit", name1 },
                                { "Password", password }
                            });

                        current = name1;
                    }

                    bool restored = await this.TrySignInAsync(targetKey, name1, password);

                    r.Verify("元の名前に戻せる", restored,
                        "できる", restored ? "できる" : "**できない**");
                }
                finally
                {
                    await UsersAdmin.DeleteByUserNameAsync(admin, current);
                }

                r.Note("**メアドは変えていない。** 利用者名とメアドは別の項目である（#151 の段階 3）。");

                r.Done();
            }
        }

        #endregion

        #region RT-277.5

        /// <summary>RT-277.5 パスワードを変えると、新しいパスワードでサインインできる</summary>
        /// <param name="targetKey">core / netfx</param>
        /// <returns>Task</returns>
        [SkippableTheory]
        [MemberData(nameof(AllTargets))]
        public async Task RT27705_パスワードを変えると新しいパスワードでサインインできる(string targetKey)
        {
            using (IdPClient admin = await this.AdminClientAsync(targetKey))
            {
                string name = ManageUserAttributeTests.UniqueName();
                string email = name + "@example.com";
                string password1 = admin.Config.Get("TestUserPWD");

                // **新しいパスワードは、構成ファイルの値から作る。**
                //   リポジトリに資格情報そのものを置かないため（`TESTING.md` 9 節）。
                string password2 = password1 + "Zz9";

                TestReport r = this.Report("RT-277.5",
                    "パスワードを変えると、新しいパスワードで入れ、古いものでは入れない",
                    "**変更の後は再サインインが要る**（`ReSignInAsync`）。"
                    + "**画面が「変えた」と言うだけでは足りない** — "
                    + "**新しいパスワードで入れて、古いものでは入れない**ことまで見る。"
                    + "**元に戻せること**も押さえる（#277 の段階 7）。",
                    "#277 / ManageController.ChangePassword");

                r.Target("利用者 " + name + " のパスワードを変えて、戻す");

                await UsersAdmin.SkipIfLockedDownAsync(admin);

                try
                {
                    r.Step("(1) 使い捨ての利用者を作る");

                    Assert.True(ManageUserAttributeTests.IsRedirect(
                        await UsersAdmin.CreateAsync(admin, name, email, "User")),
                        "前提: 利用者を作れること");

                    r.Step("(2) パスワードを変える");

                    using (IdPClient user = this.Client(targetKey))
                    {
                        Assert.True(await user.TrySignInAsync(name, password1),
                            "前提: 作った利用者でサインインできること");

                        HttpResponseMessage changed = await ManageUserAttributeTests.PostAsync(
                            user, "/Manage/ChangePassword",
                            new Dictionary<string, string>()
                            {
                                { "OldPassword", password1 },
                                { "NewPassword", password2 },
                                { "ConfirmPassword", password2 }
                            });

                        r.Verify("管理画面へ戻る（変更の成功）",
                            ManageUserAttributeTests.IsRedirect(changed),
                            "リダイレクト", ((int)changed.StatusCode).ToString()
                                + (ManageUserAttributeTests.IsRedirect(changed) ? ""
                                    : "（再表示 : " + Html.ErrorSummary(
                                        await changed.Content.ReadAsStringAsync()) + "）"));
                    }

                    r.Step("(3) 新しいパスワードで入れて、古いものでは入れない");

                    bool withNew = await this.TrySignInAsync(targetKey, name, password2);
                    bool withOld = await this.TrySignInAsync(targetKey, name, password1);

                    r.Verify("新しいパスワードでサインインできる", withNew,
                        "できる", withNew ? "できる" : "**できない**");

                    r.Verify("古いパスワードではサインインできない", !withOld,
                        "できない", withOld ? "**できてしまう**" : "できない");

                    r.Step("(4) 元に戻す");

                    using (IdPClient user = this.Client(targetKey))
                    {
                        Assert.True(await user.TrySignInAsync(name, password2));

                        await ManageUserAttributeTests.PostAsync(
                            user, "/Manage/ChangePassword",
                            new Dictionary<string, string>()
                            {
                                { "OldPassword", password2 },
                                { "NewPassword", password1 },
                                { "ConfirmPassword", password1 }
                            });
                    }

                    bool restored = await this.TrySignInAsync(targetKey, name, password1);

                    r.Verify("元のパスワードに戻せる", restored,
                        "できる", restored ? "できる" : "**できない**");
                }
                finally
                {
                    await UsersAdmin.DeleteByUserNameAsync(admin, name);
                }

                r.Note("**値は出していない。** 新しいパスワードは構成ファイルの値から作っている"
                    + "（`TESTING.md` 9 節）。");

                r.Done();
            }
        }

        #endregion

        #region RT-277.6

        /// <summary>RT-277.6 メアドの変更は確認を挟む（その場では変わらない）</summary>
        /// <param name="targetKey">core / netfx</param>
        /// <returns>Task</returns>
        [SkippableTheory]
        [MemberData(nameof(AllTargets))]
        public async Task RT27706_メアドの変更は確認を挟む(string targetKey)
        {
            using (IdPClient admin = await this.AdminClientAsync(targetKey))
            {
                string name = ManageUserAttributeTests.UniqueName();
                string email1 = name + "@example.com";
                string email2 = name + "_new@example.com";
                string password = admin.Config.Get("TestUserPWD");

                TestReport r = this.Report("RT-277.6",
                    "メアドの変更は、確認メールを挟む（押しただけでは変わらない）",
                    "**メアドは、その場では変わらない。**"
                    + "**確認用の符号を作ってメールを送り、確認画面を返す**"
                    + "（`CustomizedConfirmationProvider` ＋ `VerifyEmailAddress`）。"
                    + "**他人のメアドを勝手に自分のものにできない**ための作りである。"
                    + "**E2E はメールを読めない**ので、**ここまでを測る**（#277 の段階 7）。",
                    "#277 / ManageController.ChangeEmail");

                r.Target("利用者 " + name + " のメアドを " + email2 + " に変えようとする");

                await UsersAdmin.SkipIfLockedDownAsync(admin);

                try
                {
                    r.Step("(1) 使い捨ての利用者を作る");

                    Assert.True(ManageUserAttributeTests.IsRedirect(
                        await UsersAdmin.CreateAsync(admin, name, email1, "User")),
                        "前提: 利用者を作れること");

                    using (IdPClient user = this.Client(targetKey))
                    {
                        Assert.True(await user.TrySignInAsync(name, password),
                            "前提: 作った利用者でサインインできること");

                        r.Step("(2) 管理画面に、いまのメアドが出ている");

                        string index = await user.GetStringAsync("/Manage/Index");

                        r.Verify("いまのメアドが出る", (index ?? "").Contains(email1),
                            email1, (index ?? "").Contains(email1) ? email1 : "**出ていない**");

                        r.Step("(3) メアドの変更を送る");

                        //  **`Password` も送る**（`[Required(AllowEmptyStrings = true)]`）。
                        HttpResponseMessage changed = await ManageUserAttributeTests.PostAsync(
                            user, "/Manage/ChangeEmail",
                            new Dictionary<string, string>()
                            {
                                { "Email", email2 },
                                { "ConfirmEmail", email2 },
                                { "Password", password }
                            });

                        string body = await changed.Content.ReadAsStringAsync();

                        r.VerifyEqual("HTTP 200（確認の画面）",
                            "200", ((int)changed.StatusCode).ToString());

                        //  **検証エラーの再表示と区別する。**
                        //    **どちらも HTTP 200** なので、**画面の中身で見分ける。**
                        //    **入力の画面なら `ConfirmEmail` の欄が在る**ので、
                        //    **それが無いことで「次の画面へ移った」と言える。**
                        //    （`Html.ErrorSummary` は診断用で、メニューの `<li>` まで拾うため
                        //      「エラーの有無」の判定には使えない）
                        r.Verify("入力の画面ではない（確認の画面に移っている）",
                            !Html.HasField(body, "ConfirmEmail"),
                            "ConfirmEmail の欄が無い",
                            Html.HasField(body, "ConfirmEmail")
                                ? "**入力の画面が出し直されている : "
                                    + Html.ErrorSummary(body) + "**" : "確認の画面");

                        r.Verify("その場で変わってはいない",
                            !ManageUserAttributeTests.IsRedirect(changed),
                            "管理画面へ戻らない",
                            ManageUserAttributeTests.IsRedirect(changed)
                                ? "**管理画面へ戻った（その場で変わった）**" : "戻らない");

                        r.Step("(4) この時点では、まだ変わっていない");

                        index = await user.GetStringAsync("/Manage/Index");

                        r.Verify("メアドは元のまま", (index ?? "").Contains(email1),
                            email1, (index ?? "").Contains(email1) ? email1 : "**変わっている**");

                        r.Verify("新しいメアドにはなっていない", !(index ?? "").Contains(email2),
                            "なっていない",
                            (index ?? "").Contains(email2) ? "**なっている**" : "なっていない");
                    }

                    r.Step("(5) 古いメアドのままサインインできる");

                    bool withOld = await this.TrySignInAsync(targetKey, email1, password);

                    r.Verify("古いメアドでサインインできる", withOld,
                        "できる", withOld ? "できる" : "**できない**");
                }
                finally
                {
                    await UsersAdmin.DeleteByUserNameAsync(admin, name);
                }

                r.Note("**確認の後（メールの符号を使った先）は測っていない。**"
                    + "**E2E はメールを読めない。** 測っているのは**「押しただけでは変わらない」**ところまで。");

                r.Done();
            }
        }

        #endregion

        #region 補助

        /// <summary>管理者でサインインした client を返す</summary>
        /// <param name="targetKey">core / netfx</param>
        /// <returns>IdPClient</returns>
        private async Task<IdPClient> AdminClientAsync(string targetKey)
        {
            IdPClient client = this.Client(targetKey);
            await client.SignInAsAdministratorAsync();

            return client;
        }

        /// <summary>新しい client で、サインインを試す</summary>
        /// <param name="targetKey">core / netfx</param>
        /// <param name="userName">利用者名（またはメアド）</param>
        /// <param name="password">パスワード</param>
        /// <returns>入れたら true</returns>
        /// <remarks>**毎回、新しい Cookie で試す**（前の状態を引きずらないため）。</remarks>
        private async Task<bool> TrySignInAsync(
            string targetKey, string userName, string password)
        {
            using (IdPClient client = this.Client(targetKey))
            {
                return await client.TrySignInAsync(userName, password);
            }
        }

        /// <summary>管理画面のフォームを送る（AntiForgeryToken は画面から取る）</summary>
        /// <param name="client">IdPClient</param>
        /// <param name="path">パス</param>
        /// <param name="values">送る値</param>
        /// <returns>応答</returns>
        private static async Task<HttpResponseMessage> PostAsync(
            IdPClient client, string path, Dictionary<string, string> values)
        {
            string html = await client.GetStringAsync(path);

            Assert.False(string.IsNullOrEmpty(html), "前提: " + path + " が開くこと");

            Dictionary<string, string> form = new Dictionary<string, string>(values)
            {
                { "__RequestVerificationToken", Html.Antiforgery(html) }
            };

            return await client.PostFormAsync(path, form);
        }

        /// <summary>リダイレクトか</summary>
        /// <param name="res">応答</param>
        /// <returns>リダイレクトなら true</returns>
        private static bool IsRedirect(HttpResponseMessage res)
        {
            return res.StatusCode == HttpStatusCode.Found
                || res.StatusCode == HttpStatusCode.Redirect
                || res.StatusCode == HttpStatusCode.SeeOther;
        }

        /// <summary>この回だけの利用者名を作る（DB ストアでも衝突しない）</summary>
        /// <returns>利用者名</returns>
        private static string UniqueName()
        {
            return "e2e_attr_" + Guid.NewGuid().ToString("N").Substring(0, 8);
        }

        #endregion
    }
}
