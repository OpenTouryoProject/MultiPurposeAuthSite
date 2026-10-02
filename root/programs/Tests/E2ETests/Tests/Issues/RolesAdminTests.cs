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
//* クラス名        ：RolesAdminTests
//* クラス日本語名  ：RT-257 ロール管理の画面（/RolesAdmin）
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
    /// RT-257.10 〜 .13 ロール管理の画面（#257）。
    /// </summary>
    /// <remarks>
    /// **利用者管理と同じ理由で測る。**
    /// **ビューの文字列（リソース）は、実行時に反射で探される**ので、
    /// **足し忘れても、ビルドでは分からない**（`root/CODING.md`）。
    /// **画面を 1 回叩けば分かる**ので、叩いておく。
    ///
    /// **#258 で net10.0 版へ移植したばかり**でもある（それまでは net48 版だけ）。
    /// 移植直後は、**退行しても誰も気付かない。**
    ///
    /// **管理者でサインインする**（`SystemAdmin` ロール）。
    /// **作ったロールは、同じテストの中で消す**（DB ストアでは残るため）。
    /// </remarks>
    public class RolesAdminTests : TargetTestBase
    {
        /// <summary>コンストラクタ</summary>
        /// <param name="output">ITestOutputHelper</param>
        public RolesAdminTests(ITestOutputHelper output) : base(output)
        {
        }

        /// <summary>RT-257.10 一覧が開き、種データのロールが出る</summary>
        /// <param name="targetKey">core / netfx</param>
        /// <returns>Task</returns>
        [SkippableTheory]
        [MemberData(nameof(AllTargets))]
        public async Task RT25710_一覧に種データのロールが出る(string targetKey)
        {
            using (IdPClient client = await this.AdminClientAsync(targetKey))
            {
                TestReport r = this.Report("RT-257.10",
                    "ロールの一覧が開き、種データの 3 つのロールが出る",
                    "**この画面も、一度も叩いていなかった。**"
                    + "**ビューの文字列は実行時に反射で探される**ので、"
                    + "**足し忘れはビルドでも E2E でも分からなかった**（`CODING.md`）。"
                    + "**#258 で net10.0 版へ移植したばかり**でもあり、"
                    + "**退行に気付く手段が無い**状態だった。",
                    "#257 / #258");

                r.Target("種データのロール : SystemAdmin / Admin / User");

                r.Step("管理者でロールの一覧を開く");

                string body = await RolesAdmin.SkipIfLockedDownAsync(client);

                r.Verify("SystemAdmin が出る",
                    RolesAdmin.Contains(body, "SystemAdmin"),
                    "出る", RolesAdmin.Contains(body, "SystemAdmin") ? "出る" : "**出ない**");

                r.Verify("Admin が出る",
                    RolesAdmin.Contains(body, "Admin"),
                    "出る", RolesAdmin.Contains(body, "Admin") ? "出る" : "**出ない**");

                r.Verify("User が出る",
                    RolesAdmin.Contains(body, "User"),
                    "出る", RolesAdmin.Contains(body, "User") ? "出る" : "**出ない**");

                r.Note("**行を読んで判定している**（ロール名の列と、編集のリンクの id）。"
                    + "**本文に文字列が在るかどうかでは見ていない**"
                    + "（メニューや他の語に含まれてしまう）。");

                r.Done();
            }
        }

        /// <summary>RT-257.11 ロールを作って、消せる</summary>
        /// <param name="targetKey">core / netfx</param>
        /// <returns>Task</returns>
        [SkippableTheory]
        [MemberData(nameof(AllTargets))]
        public async Task RT25711_ロールを作って消せる(string targetKey)
        {
            using (IdPClient client = await this.AdminClientAsync(targetKey))
            {
                string roleName = RolesAdminTests.UniqueName();

                TestReport r = this.Report("RT-257.11",
                    "ロールを作ると一覧に出て、削除すると消える",
                    "**ロールは、管理画面からしか作れない**（種データ以外）。"
                    + "**作成と削除は、利用者へのロール割り当ての前提**でもある。",
                    "#257");

                r.Target("ロール名 = " + roleName);

                await RolesAdmin.SkipIfLockedDownAsync(client);

                try
                {
                    r.Step("(1) ロールを作る");

                    HttpResponseMessage post = await RolesAdmin.CreateAsync(client, roleName);

                    r.Verify("一覧へリダイレクトする（作成の成功）",
                        post.StatusCode == HttpStatusCode.Found
                        || post.StatusCode == HttpStatusCode.Redirect,
                        "リダイレクト",
                        ((int)post.StatusCode).ToString()
                            + ((post.StatusCode == HttpStatusCode.OK)
                                ? "（再表示 : " + Html.ErrorSummary(
                                    await post.Content.ReadAsStringAsync()) + "）" : ""));

                    r.Step("(2) 一覧に出る");

                    HttpResponseMessage index = await RolesAdmin.IndexAsync(client);
                    string body = await index.Content.ReadAsStringAsync();

                    r.Verify("作ったロールが一覧に在る",
                        RolesAdmin.Contains(body, roleName),
                        "在る", RolesAdmin.Contains(body, roleName) ? "在る" : "**無い**");
                }
                finally
                {
                    r.Step("(3) 削除する（後片付けでもある）");

                    bool deleted = await RolesAdmin.DeleteByNameAsync(client, roleName);

                    r.Verify("削除できた", deleted,
                        "削除できた", deleted ? "削除できた" : "**削除できなかった**");
                }

                r.Step("(4) 一覧から消えている");

                HttpResponseMessage after = await RolesAdmin.IndexAsync(client);
                string afterBody = await after.Content.ReadAsStringAsync();

                r.Verify("一覧から消えている",
                    !RolesAdmin.Contains(afterBody, roleName),
                    "消えている",
                    RolesAdmin.Contains(afterBody, roleName) ? "**残っている**" : "消えている");

                r.Note("**削除まで 1 つのテストで行う。** `mem` では再起動で消えるが、"
                    + "**DB ストアでは残る。** 名前に `Guid` を混ぜて、回をまたいだ衝突も避けている。");

                r.Done();
            }
        }

        /// <summary>RT-257.12 詳細に、そのロールに属する利用者が出る</summary>
        /// <param name="targetKey">core / netfx</param>
        /// <returns>Task</returns>
        [SkippableTheory]
        [MemberData(nameof(AllTargets))]
        public async Task RT25712_詳細に属する利用者が出る(string targetKey)
        {
            using (IdPClient client = await this.AdminClientAsync(targetKey))
            {
                string roleName = RolesAdminTests.UniqueName();

                TestReport r = this.Report("RT-257.12",
                    "ロールの詳細に、そのロールに属する利用者が出る（属さなければ出ない）",
                    "**詳細は、全利用者を 1 人ずつ `IsInRole` で確かめて一覧する。**"
                    + "**0 人のときと 1 人以上のときで、画面の分岐が違う**"
                    + "（`ViewBag.UserCount`）。**両方を通す。**",
                    "#257");

                r.Target("既存のロール（User）と、作ったばかりのロール（" + roleName + "）");

                string index = await RolesAdmin.SkipIfLockedDownAsync(client);

                r.Step("(1) 種データのロール（User）の詳細を開く");

                string userRoleId = RolesAdmin.FindId(index, "User");

                Assert.False(string.IsNullOrEmpty(userRoleId), "前提: User ロールの id を引けること");

                HttpResponseMessage details = await RolesAdmin.DetailsAsync(client, userRoleId);
                string body = await details.Content.ReadAsStringAsync();

                r.VerifyEqual("HTTP 200", "200", ((int)details.StatusCode).ToString());

                r.Verify("**属している利用者が出る**（テスト利用者）",
                    body.Contains(TestEnv.TestUserName),
                    TestEnv.TestUserName + " が出る",
                    body.Contains(TestEnv.TestUserName) ? "出る" : "**出ない**");

                try
                {
                    r.Step("(2) 誰も属していないロールを作って、詳細を開く");

                    HttpResponseMessage created = await RolesAdmin.CreateAsync(client, roleName);

                    Assert.True(created.StatusCode == HttpStatusCode.Found
                        || created.StatusCode == HttpStatusCode.Redirect,
                        "前提: ロールを作れること（HTTP " + (int)created.StatusCode + "）");

                    HttpResponseMessage index2 = await RolesAdmin.IndexAsync(client);
                    string id = RolesAdmin.FindId(await index2.Content.ReadAsStringAsync(), roleName);

                    Assert.False(string.IsNullOrEmpty(id), "前提: 作ったロールの id を引けること");

                    HttpResponseMessage empty = await RolesAdmin.DetailsAsync(client, id);
                    string emptyBody = await empty.Content.ReadAsStringAsync();

                    r.VerifyEqual("HTTP 200（0 人でも落ちない）",
                        "200", ((int)empty.StatusCode).ToString());

                    r.Verify("属していない利用者は出ない",
                        !emptyBody.Contains(TestEnv.TestUserName),
                        "出ない",
                        emptyBody.Contains(TestEnv.TestUserName) ? "**出ている**" : "出ない");
                }
                finally
                {
                    r.Step("(3) 後片付け : 作ったロールを削除する");

                    bool deleted = await RolesAdmin.DeleteByNameAsync(client, roleName);

                    r.Verify("削除できた", deleted,
                        "削除できた", deleted ? "削除できた" : "**削除できなかった**");
                }

                r.Done();
            }
        }

        /// <summary>RT-257.13 作成の検証エラーで 500 にならない</summary>
        /// <param name="targetKey">core / netfx</param>
        /// <returns>Task</returns>
        [SkippableTheory]
        [MemberData(nameof(AllTargets))]
        public async Task RT25713_作成の検証エラーで500にならない(string targetKey)
        {
            using (IdPClient client = await this.AdminClientAsync(targetKey))
            {
                TestReport r = this.Report("RT-257.13",
                    "ロール名が空のとき、500 にならず、その欄のエラーとして再表示される",
                    "**利用者管理の作成・編集は、ここで 500 になっていた**（#151 の段階 3）。"
                    + "**同じ形の画面なので、こちらも押さえる。**"
                    + "ロール名は `[Required]` なので、**欄のエラーになる**のが正しい姿である。",
                    "#151 の段階 3（同じ性質の不具合）/ #257");

                r.Target("ロール名 = 空");

                await RolesAdmin.SkipIfLockedDownAsync(client);

                r.Step("ロール名を空で送る");

                HttpResponseMessage post = await RolesAdmin.CreateAsync(client, "");
                string body = await post.Content.ReadAsStringAsync();

                r.VerifyEqual("**HTTP 200（500 にならない）**",
                    "200", ((int)post.StatusCode).ToString());

                r.Verify("作成の画面が再表示される（入力欄が在る）",
                    Html.HasField(body, "Name"),
                    "在る", Html.HasField(body, "Name") ? "在る" : "**無い**（通ってしまった）");

                r.Verify("**ロール名の欄のエラーになる**",
                    Html.HasFieldError(body, "Name"),
                    "欄のエラー",
                    Html.HasFieldError(body, "Name") ? "欄のエラー" : "**欄のエラーではない**");

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

        /// <summary>この回だけのロール名を作る（DB ストアでも衝突しない）</summary>
        /// <returns>ロール名</returns>
        private static string UniqueName()
        {
            return "e2e_role_" + Guid.NewGuid().ToString("N").Substring(0, 8);
        }

        #endregion
    }
}
