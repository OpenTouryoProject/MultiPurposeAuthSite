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
//* クラス名        ：UsersAdminTests
//* クラス日本語名  ：RT-257 利用者管理の画面（/UsersAdmin）
//*
//* 作成日時        ：－
//* 作成者          ：－
//* 更新履歴        ：－
//*
//*  日時        更新者            内容
//*  ----------  ----------------  -------------------------------------------------
//*  2026/10/02  玄人 幸道         新規（#257）
//**********************************************************************************

using System;
using System.Net;
using System.Net.Http;
using System.Threading.Tasks;

using MultiPurposeAuthSite.Tests.E2E.Infrastructure;

using Xunit;
using Xunit.Abstractions;

namespace MultiPurposeAuthSite.Tests.E2E.Tests.Issues
{
    /// <summary>
    /// RT-257.5 〜 .8 利用者管理の画面（#257）。
    /// </summary>
    /// <remarks>
    /// **この画面も、一度も叩いていなかった。**
    /// そのため **#151 の段階 3 で入れた不具合（検証エラーで HTTP 500）が、
    /// 目視まで出てこなかった。**
    ///
    /// | 当時の不具合 | 原因 |
    /// |---|---|
    /// | 作成の検証エラーで 500 | 再表示で `ViewBag.RoleId` を詰めていなかった |
    /// | 編集の検証エラーで 500 | 再表示で `RolesList` を詰めていなかった |
    ///
    /// **どちらも「ロールの選択肢が出たまま再表示されるか」で測れる。**
    ///
    /// **管理者でサインインする。** 画面は **`SystemAdmin` ロール**を要求するので、
    /// **雛形のテスト利用者（`User` / `Admin`）では開けない。**
    ///
    /// **net48 版と net10.0 版の両方で測る**（#258 で移植した。それまでは net48 版だけだった）。
    /// </remarks>
    public class UsersAdminTests : TargetTestBase
    {
        /// <summary>コンストラクタ</summary>
        /// <param name="output">ITestOutputHelper</param>
        public UsersAdminTests(ITestOutputHelper output) : base(output)
        {
        }

        /// <summary>RT-257.5 一覧に、利用者名とメアドが別の列で出る</summary>
        /// <param name="targetKey">core / netfx</param>
        /// <returns>Task</returns>
        [SkippableTheory]
        [MemberData(nameof(AllTargets))]
        public async Task RT25705_一覧に利用者名とメアドが別の列で出る(string targetKey)
        {
            using (IdPClient client = await this.AdminClientAsync(targetKey))
            {
                TestReport r = this.Report("RT-257.5",
                    "一覧が開き、利用者名とメアドが別の列で出る",
                    "**#151 の段階 3 で、利用者名とメアドは別の項目になった。**"
                    + "一覧は**利用者名しか出していなかった**ので、メアドの列を足した。"
                    + "**両方が、それぞれの列に出ている**ことを押さえる。",
                    "#151 の段階 3 / #257");

                r.Target("利用者 = " + TestEnv.TestUserName);

                r.Step("(1) 管理者で一覧を開く");

                string body = await UsersAdmin.SkipIfLockedDownAsync(client);

                r.Verify("一覧の画面が開く（検索の欄が在る）",
                    Html.HasField(body, "UserNameforSearch"),
                    "開く", Html.HasField(body, "UserNameforSearch") ? "開く" : "**開かない**");

                r.Step("(2) テスト利用者の行を読む");

                string email = UsersAdmin.FindEmail(body, TestEnv.TestUserName);

                r.Verify("テスト利用者の行が在る",
                    email != null, "在る", (email != null) ? "在る" : "**無い**");

                r.VerifyEqual("**メアドの列に、その利用者のメアドが出る**",
                    TestEnv.TestUserEmail, email ?? "（無し）");

                r.Note("**利用者名の列とメアドの列を、別に読んでいる。**"
                    + "**同じ値が両方に出ていた**のが、段階 3 より前の姿である"
                    + "（当時は「利用者名＝メアド」だった）。");

                r.Done();
            }
        }

        /// <summary>RT-257.6 作成の検証エラーで 500 にならない</summary>
        /// <param name="targetKey">core / netfx</param>
        /// <returns>Task</returns>
        [SkippableTheory]
        [MemberData(nameof(AllTargets))]
        public async Task RT25706_作成の検証エラーで500にならない(string targetKey)
        {
            using (IdPClient client = await this.AdminClientAsync(targetKey))
            {
                TestReport r = this.Report("RT-257.6",
                    "作成の検証エラーで 500 にならず、ロールの選択肢が出たまま再表示される",
                    "**ここが HTTP 500 になっていた**（#151 の段階 3）。"
                    + "**検証エラーの再表示で `ViewBag.RoleId` を詰めていなかった**ため、"
                    + "**ビューがロールの一覧を描こうとして落ちていた。**"
                    + "**選択肢が出たまま再表示される**ことが、直っている証拠になる。",
                    "#151 の段階 3（目視で見つかった不具合）/ #257");

                r.Target("利用者名 = \"bad@name\"（「@」は使えない）");

                await UsersAdmin.SkipIfLockedDownAsync(client);

                r.Step("利用者名に「@」を入れて作成する");

                HttpResponseMessage post = await UsersAdmin.CreateAsync(
                    client, "bad@name", UsersAdminTests.UniqueName() + "@example.com", null);
                string body = await post.Content.ReadAsStringAsync();

                r.VerifyEqual("**HTTP 200（500 にならない）**",
                    "200", ((int)post.StatusCode).ToString());

                r.Verify("作成の画面が再表示される（入力欄が在る）",
                    Html.HasField(body, "ConfirmPassword"),
                    "在る",
                    Html.HasField(body, "ConfirmPassword") ? "在る" : "**無い**（通ってしまった）");

                r.Verify("**ロールの選択肢が出ている**（ViewBag.RoleId を詰めている）",
                    Html.HasField(body, "SelectedRoles"),
                    "出ている",
                    Html.HasField(body, "SelectedRoles") ? "出ている" : "**出ていない**");

                r.Verify("エラーが出ている",
                    Html.HasValidationError(body),
                    "出ている", Html.HasValidationError(body) ? "出ている" : "**出ていない**");

                r.Done();
            }
        }

        /// <summary>RT-257.7 作成でき、編集画面に利用者名とメアドが別々に出る</summary>
        /// <param name="targetKey">core / netfx</param>
        /// <returns>Task</returns>
        [SkippableTheory]
        [MemberData(nameof(AllTargets))]
        public async Task RT25707_作成できて編集画面に別々に出る(string targetKey)
        {
            using (IdPClient client = await this.AdminClientAsync(targetKey))
            {
                string userName = UsersAdminTests.UniqueName();
                string email = userName + "@example.com";

                TestReport r = this.Report("RT-257.7",
                    "作成でき、編集画面に利用者名とメアドが別々に保存されている",
                    "**#151 の段階 3 で、作成・編集を 2 欄にした。**"
                    + "**入れた 2 つが、それぞれの項目として保存される**ことを押さえる"
                    + "（以前は「利用者名＝メアド」で、片方しか残らなかった）。",
                    "#151 の段階 3 / #257");

                r.Target("利用者名 = " + userName + " / メアド = " + email);

                await UsersAdmin.SkipIfLockedDownAsync(client);

                try
                {
                    r.Step("(1) 利用者名とメアドを入れて作成する（ロールも付ける）");

                    HttpResponseMessage post = await UsersAdmin.CreateAsync(
                        client, userName, email, Const.RoleUser);

                    r.Verify("一覧へリダイレクトする（作成の成功）",
                        post.StatusCode == HttpStatusCode.Found
                        || post.StatusCode == HttpStatusCode.Redirect,
                        "リダイレクト",
                        ((int)post.StatusCode).ToString()
                            + ((post.StatusCode == HttpStatusCode.OK)
                                ? "（再表示 : " + Html.ErrorSummary(
                                    await post.Content.ReadAsStringAsync()) + "）" : ""));

                    r.Step("(2) 一覧で、利用者名とメアドを読む");

                    HttpResponseMessage index = await UsersAdmin.IndexAsync(client);
                    string indexBody = await index.Content.ReadAsStringAsync();

                    string id = UsersAdmin.FindId(indexBody, userName);

                    r.Verify("一覧に出る", id != null, "出る", (id != null) ? "出る" : "**出ない**");

                    r.VerifyEqual("メアドの列が、入れたメアドである",
                        email, UsersAdmin.FindEmail(indexBody, userName) ?? "（無し）");

                    Assert.False(string.IsNullOrEmpty(id), "前提: 作った利用者の id を引けること");

                    r.Step("(3) 編集画面で、2 つの欄の値を読む");

                    HttpResponseMessage edit = await UsersAdmin.EditAsync(client, id);
                    string editBody = await edit.Content.ReadAsStringAsync();

                    r.VerifyEqual("HTTP 200", "200", ((int)edit.StatusCode).ToString());

                    r.Verify("利用者名の欄に、入れた利用者名が入っている",
                        Html.FieldValue(editBody, "Name") == userName,
                        userName, Html.FieldValue(editBody, "Name") ?? "（無し）");

                    r.Verify("メアドの欄に、入れたメアドが入っている",
                        Html.FieldValue(editBody, "Email") == email,
                        email, Html.FieldValue(editBody, "Email") ?? "（無し）");

                    r.Verify("ロールのチェックボックスが出ている",
                        Html.HasField(editBody, "SelectedRole"),
                        "出ている",
                        Html.HasField(editBody, "SelectedRole") ? "出ている" : "**出ていない**");
                }
                finally
                {
                    r.Step("(4) 後片付け : 作った利用者を削除する");

                    bool deleted = await UsersAdmin.DeleteByUserNameAsync(client, userName);

                    r.Verify("削除できた（DB ストアに残さない）",
                        deleted, "削除できた", deleted ? "削除できた" : "**削除できなかった**");
                }

                r.Note("**削除まで 1 つのテストで行う。** `mem` では再起動で消えるが、"
                    + "**DB ストアでは残る**ので、**次の回の一覧に積み上がる。**"
                    + "**削除そのものの確認**にもなっている。");

                r.Note("**ロールを 1 つ付けて作っている。** "
                    + "**net48 版は、ロールを選ばないと一覧へ戻らない**"
                    + "（`params string[]` に何も来ないと null になり、"
                    + "**利用者は作られるのに作成画面が再表示される**）。"
                    + "**net10.0 版は空の配列が来る**ので一覧へ戻る。"
                    + "**この非対称は #257 で作ったものではなく、元から在る。**");

                r.Done();
            }
        }

        /// <summary>RT-257.8 編集の検証エラーで 500 にならない</summary>
        /// <param name="targetKey">core / netfx</param>
        /// <returns>Task</returns>
        [SkippableTheory]
        [MemberData(nameof(AllTargets))]
        public async Task RT25708_編集の検証エラーで500にならない(string targetKey)
        {
            using (IdPClient client = await this.AdminClientAsync(targetKey))
            {
                string userName = UsersAdminTests.UniqueName();
                string email = userName + "@example.com";

                TestReport r = this.Report("RT-257.8",
                    "編集の検証エラーで 500 にならず、ロールのチェックボックスが出たまま再表示される",
                    "**作成と同じ不具合が、編集にも在った**（#151 の段階 3）。"
                    + "**再表示で `RolesList` を詰めていなかった**ため、ビューが落ちていた。"
                    + "**チェックボックスが出たまま再表示される**ことが、直っている証拠になる。",
                    "#151 の段階 3（目視で見つかった不具合）/ #257");

                r.Target("利用者名を \"bad@name\" に変えようとする");

                await UsersAdmin.SkipIfLockedDownAsync(client);

                try
                {
                    r.Step("(1) 測る対象の利用者を作る");

                    //   **ロールを 1 つ付けて作る。**
                    //   **net48 版は、ロールを選ばないと一覧へ戻らない**（下の RT-257.7 の注記）。
                    //   ここで見たいのは編集の方なので、**前提が揺れない形で作る。**
                    HttpResponseMessage created = await UsersAdmin.CreateAsync(
                        client, userName, email, Const.RoleUser);

                    Assert.True(created.StatusCode == HttpStatusCode.Found
                        || created.StatusCode == HttpStatusCode.Redirect,
                        "前提: 利用者を作れること（HTTP " + (int)created.StatusCode + "）");

                    HttpResponseMessage index = await UsersAdmin.IndexAsync(client);
                    string id = UsersAdmin.FindId(await index.Content.ReadAsStringAsync(), userName);

                    Assert.False(string.IsNullOrEmpty(id), "前提: 作った利用者の id を引けること");

                    r.Step("(2) 利用者名に「@」を入れて更新する");

                    HttpResponseMessage post = await UsersAdmin.EditAsync(
                        client, id, "bad@name", email, null);
                    string body = await post.Content.ReadAsStringAsync();

                    r.VerifyEqual("**HTTP 200（500 にならない）**",
                        "200", ((int)post.StatusCode).ToString());

                    r.Verify("**ロールのチェックボックスが出ている**（RolesList を詰めている）",
                        Html.HasField(body, "SelectedRole"),
                        "出ている",
                        Html.HasField(body, "SelectedRole") ? "出ている" : "**出ていない**");

                    r.Verify("エラーが出ている",
                        Html.HasValidationError(body),
                        "出ている", Html.HasValidationError(body) ? "出ている" : "**出ていない**");

                    r.Step("(3) 利用者名が変わっていない");

                    HttpResponseMessage edit = await UsersAdmin.EditAsync(client, id);
                    string editBody = await edit.Content.ReadAsStringAsync();

                    r.VerifyEqual("利用者名は元のまま",
                        userName, Html.FieldValue(editBody, "Name") ?? "（無し）");
                }
                finally
                {
                    r.Step("(4) 後片付け : 作った利用者を削除する");

                    bool deleted = await UsersAdmin.DeleteByUserNameAsync(client, userName);

                    r.Verify("削除できた（DB ストアに残さない）",
                        deleted, "削除できた", deleted ? "削除できた" : "**削除できなかった**");
                }

                r.Done();
            }
        }

        /// <summary>RT-257.9 管理画面は SystemAdmin でだけ開く</summary>
        /// <param name="targetKey">core / netfx</param>
        /// <returns>Task</returns>
        [SkippableTheory]
        [MemberData(nameof(AllTargets))]
        public async Task RT25709_管理画面はSystemAdminでだけ開く(string targetKey)
        {
            using (IdPClient admin = await this.AdminClientAsync(targetKey))
            using (IdPClient user = this.Client(targetKey))
            {
                string userName = UsersAdminTests.UniqueName();
                string email = userName + "@example.com";

                TestReport r = this.Report("RT-257.9",
                    "管理画面は SystemAdmin のときだけ開く（付与すると開き、無ければ開かない）",
                    "**これは認可の確認である。**"
                    + "**門番（`Authorize`）とメニューの出し分けは、どちらも `SystemAdmin` を見る**"
                    + "（`Admin` では開かない。雛形のテスト利用者は `User` / `Admin` しか持たない）。"
                    + "**付与の前後を 1 つのテストで通す**ので、"
                    + "**「誰でも開ける」退行と「誰も開けない」退行の両方**を捕まえられる。",
                    "#257 / #258（導線は EnableAdministrationOfUsersAndRoles でも出し分ける）");

                r.Target("使い捨ての利用者 = " + userName);

                await UsersAdmin.SkipIfLockedDownAsync(admin);

                try
                {
                    r.Step("(1) 管理者が、使い捨ての利用者を作る（ロールは User）");

                    HttpResponseMessage created = await UsersAdmin.CreateAsync(
                        admin, userName, email, Const.RoleUser);

                    Assert.True(created.StatusCode == HttpStatusCode.Found
                        || created.StatusCode == HttpStatusCode.Redirect,
                        "前提: 利用者を作れること（HTTP " + (int)created.StatusCode + "）");

                    HttpResponseMessage list = await UsersAdmin.IndexAsync(admin);
                    string id = UsersAdmin.FindId(await list.Content.ReadAsStringAsync(), userName);

                    Assert.False(string.IsNullOrEmpty(id), "前提: 作った利用者の id を引けること");

                    r.Step("(2) その利用者でサインインする（SystemAdmin は持っていない）");

                    await user.SignInAsync(userName);

                    HttpResponseMessage denied = await UsersAdmin.IndexAsync(user);
                    string deniedBody = await denied.Content.ReadAsStringAsync();

                    r.Verify("**一覧が開かない**",
                        !Html.HasField(deniedBody, "UserNameforSearch"),
                        "開かない",
                        Html.HasField(deniedBody, "UserNameforSearch")
                            ? "**開いてしまった**（誰でも見られる）" : "開かない");

                    r.Observe("断り方",
                        "HTTP " + (int)denied.StatusCode,
                        "**門番は例外を投げる**ので、エラー画面になる"
                        + "（401 / 403 ではない。そこは直していない）。");

                    HttpResponseMessage menu = await user.GetAsync("/Manage/Index");
                    string menuBody = await menu.Content.ReadAsStringAsync();

                    r.Verify("メニューに導線が出ない",
                        !menuBody.Contains("UsersAdmin Screen"),
                        "出ない",
                        menuBody.Contains("UsersAdmin Screen") ? "**出ている**" : "出ない");

                    r.Step("(3) 管理者が、その利用者に SystemAdmin を付ける");

                    HttpResponseMessage granted = await UsersAdmin.EditAsync(
                        admin, id, userName, email, Const.RoleSystemAdmin);

                    r.Verify("付与できた（一覧へリダイレクトする）",
                        granted.StatusCode == HttpStatusCode.Found
                        || granted.StatusCode == HttpStatusCode.Redirect,
                        "リダイレクト", ((int)granted.StatusCode).ToString());

                    r.Step("(4) 入り直して、開けるようになる");

                    await user.SignInAsync(userName, force: true);

                    HttpResponseMessage allowed = await UsersAdmin.IndexAsync(user);
                    string allowedBody = await allowed.Content.ReadAsStringAsync();

                    r.Verify("**一覧が開く**",
                        Html.HasField(allowedBody, "UserNameforSearch"),
                        "開く",
                        Html.HasField(allowedBody, "UserNameforSearch") ? "開く" : "**開かない**");

                    HttpResponseMessage menu2 = await user.GetAsync("/Manage/Index");
                    string menu2Body = await menu2.Content.ReadAsStringAsync();

                    r.Verify("メニューに導線が出る（UsersAdmin / RolesAdmin）",
                        menu2Body.Contains("UsersAdmin Screen")
                        && menu2Body.Contains("RolesAdmin Screen"),
                        "出る",
                        (menu2Body.Contains("UsersAdmin Screen")
                            && menu2Body.Contains("RolesAdmin Screen")) ? "出る" : "**出ない**");

                    r.Note("**入り直さないと効かない。** ロールは**サインインのときに Cookie のクレームへ入る**ので、"
                        + "**付与しただけでは、その人の今のセッションは変わらない。**"
                        + "テストが `force: true` で入り直しているのは、そのためである。");
                }
                finally
                {
                    r.Step("(5) 後片付け : 使い捨ての利用者を削除する");

                    bool deleted = await UsersAdmin.DeleteByUserNameAsync(admin, userName);

                    r.Verify("削除できた（SystemAdmin を持つ利用者を残さない）",
                        deleted, "削除できた", deleted ? "削除できた" : "**削除できなかった**");
                }

                r.Note("**種データの利用者には付与しない。** 戻し忘れると、"
                    + "**DB ストアで権限が残り続け、他のテストの前提が変わる。**"
                    + "**使い捨ての利用者なら、消せば終わる。**");

                r.Done();
            }
        }

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

        /// <summary>この回だけの利用者名を作る（DB ストアでも衝突しない）</summary>
        /// <returns>利用者名</returns>
        private static string UniqueName()
        {
            return "e2e_admin_" + Guid.NewGuid().ToString("N").Substring(0, 8);
        }

        /// <summary>画面で使うロール名</summary>
        private static class Const
        {
            /// <summary>一般利用者のロール（`Co.Const.Role_User` と同じ値）</summary>
            public const string RoleUser = "User";

            /// <summary>管理画面を開けるロール（`Co.Const.Role_SystemAdmin` と同じ値）</summary>
            public const string RoleSystemAdmin = "SystemAdmin";
        }

        #endregion
    }
}
