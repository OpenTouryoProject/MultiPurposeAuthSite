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
//* クラス名        ：AdminCoverageTests
//* クラス日本語名  ：RT-324 E2E が一度も通っていなかった管理の画面
//*
//* 作成者          ：玄人 幸道
//* 更新履歴        ：
//*
//*  日時        更新者            内容
//*  ----------  ----------------  -------------------------------------------------
//*  2026/11/02  玄人 幸道         新規（#324）
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
    /// RT-324. **E2E が 1 行も通っていなかった管理の画面**（`Tests/COVERAGE.md` の一覧から）。
    /// </summary>
    /// <remarks>
    /// **作った利用者とロールは、同じテストの中で消す**（DB ストアでは残るため）。
    /// </remarks>
    // **UsersAdmin と同じ管理者で、同じ利用者・ロールを書く**ので並行させない。
    [Collection(UsersAdminTests.AdminScreenCollection)]
    public class AdminCoverageTests : TargetTestBase
    {
        /// <summary>コンストラクタ</summary>
        /// <param name="output">ITestOutputHelper</param>
        public AdminCoverageTests(ITestOutputHelper output) : base(output)
        {
        }

        /// <summary>RT-324.1 ロールの名前を変えられる</summary>
        /// <param name="targetKey">core / netfx</param>
        /// <returns>Task</returns>
        [SkippableTheory]
        [MemberData(nameof(AllTargets))]
        public async Task RT32401_ロールの名前を変えられる(string targetKey)
        {
            using (IdPClient client = await this.AdminClientAsync(targetKey))
            {
                string before = AdminCoverageTests.UniqueName("e2e_role");
                string after = AdminCoverageTests.UniqueName("e2e_role");

                TestReport r = this.Report("RT-324.1",
                    "ロールの編集で名前を変えると、一覧の名前が変わり、元の名前は無くなる",
                    "**編集の画面は、一度も通っていなかった**（`COVERAGE.md`）。",
                    "#324");

                r.Target("GET / POST /RolesAdmin/Edit/{id}");

                await RolesAdmin.SkipIfLockedDownAsync(client);

                try
                {
                    r.Step("(1) ロールを作る");

                    await RolesAdmin.CreateAsync(client, before);

                    string id = RolesAdmin.FindId(
                        await (await RolesAdmin.IndexAsync(client)).Content.ReadAsStringAsync(), before);

                    Assert.False(string.IsNullOrEmpty(id), "前提: 作ったロールの id を引けること");

                    r.Step("(2) 編集の画面を開く");

                    HttpResponseMessage get = await client.GetAsync("/RolesAdmin/Edit/" + id);
                    string html = await get.Content.ReadAsStringAsync();

                    r.VerifyEqual("編集の画面 : HTTP 200", "200", ((int)get.StatusCode).ToString());

                    r.Step("(3) 名前を変える");

                    HttpResponseMessage post = await client.PostFormAsync("/RolesAdmin/Edit/" + id,
                        new Dictionary<string, string>()
                        {
                            { "__RequestVerificationToken", Html.Antiforgery(html) },
                            { "Id", id },
                            { "Name", after }
                        });

                    r.VerifyEqual("更新 : 一覧へリダイレクトする", "302", ((int)post.StatusCode).ToString());

                    string index = await (await RolesAdmin.IndexAsync(client)).Content.ReadAsStringAsync();

                    r.Verify("一覧に新しい名前が出る", RolesAdmin.Contains(index, after),
                        "出る", RolesAdmin.Contains(index, after) ? "出る" : "**出ない**");

                    r.Verify("一覧に元の名前が出ない", !RolesAdmin.Contains(index, before),
                        "出ない", RolesAdmin.Contains(index, before) ? "**出る**" : "出ない");
                }
                finally
                {
                    await RolesAdmin.DeleteByNameAsync(client, before);
                    await RolesAdmin.DeleteByNameAsync(client, after);
                }
            }
        }

        /// <summary>RT-324.2 利用者を名前で絞り込める</summary>
        /// <param name="targetKey">core / netfx</param>
        /// <returns>Task</returns>
        [SkippableTheory]
        [MemberData(nameof(AllTargets))]
        public async Task RT32402_利用者を名前で絞り込める(string targetKey)
        {
            using (IdPClient client = await this.AdminClientAsync(targetKey))
            {
                string name = AdminCoverageTests.UniqueName("e2e_search");

                TestReport r = this.Report("RT-324.2",
                    "利用者の一覧を名前で絞り込むと、当たる利用者だけが出る",
                    "**絞り込みの口は、一度も通っていなかった**（`COVERAGE.md`）。",
                    "#324");

                r.Target("POST /UsersAdmin/List");

                await UsersAdmin.SkipIfLockedDownAsync(client);

                try
                {
                    r.Step("(1) 利用者を作る");

                    await UsersAdmin.CreateAsync(client, name, name + "@example.com", null);

                    r.Step("(2) その名前で絞り込む");

                    HttpResponseMessage post = await AdminCoverageTests.SearchAsync(client, name);
                    string body = await post.Content.ReadAsStringAsync();

                    r.VerifyEqual("HTTP 200", "200", ((int)post.StatusCode).ToString());

                    r.Verify("当たる利用者が出る", UsersAdmin.FindId(body, name) != null,
                        "出る", (UsersAdmin.FindId(body, name) != null) ? "出る" : "**出ない**");

                    string other = TestEnv.TestUserName(targetKey);

                    r.Verify("当たらない利用者は出ない", UsersAdmin.FindId(body, other) == null,
                        "出ない", (UsersAdmin.FindId(body, other) == null) ? "出ない" : "**出る**");
                }
                finally
                {
                    //  **検索の条件はセッションに残る**ので、空に戻す。
                    await AdminCoverageTests.SearchAsync(client, "");
                    await UsersAdmin.DeleteByUserNameAsync(client, name);
                }
            }
        }

        /// <summary>RT-324.3 利用者の詳細に、名前とロールが出る</summary>
        /// <param name="targetKey">core / netfx</param>
        /// <returns>Task</returns>
        [SkippableTheory]
        [MemberData(nameof(AllTargets))]
        public async Task RT32403_利用者の詳細に名前とロールが出る(string targetKey)
        {
            using (IdPClient client = await this.AdminClientAsync(targetKey))
            {
                string name = AdminCoverageTests.UniqueName("e2e_details");

                TestReport r = this.Report("RT-324.3",
                    "利用者の詳細に、利用者名と、付けたロールが出る",
                    "**詳細の画面は、一度も通っていなかった**（`COVERAGE.md`）。",
                    "#324");

                r.Target("GET /UsersAdmin/Details/{id}");

                await UsersAdmin.SkipIfLockedDownAsync(client);

                try
                {
                    r.Step("(1) ロール付きで利用者を作る");

                    await UsersAdmin.CreateAsync(client, name, name + "@example.com", "Admin");

                    string id = UsersAdmin.FindId(
                        await (await UsersAdmin.IndexAsync(client)).Content.ReadAsStringAsync(), name);

                    Assert.False(string.IsNullOrEmpty(id), "前提: 作った利用者の id を引けること");

                    r.Step("(2) 詳細を開く");

                    HttpResponseMessage get = await client.GetAsync("/UsersAdmin/Details/" + id);
                    string body = await get.Content.ReadAsStringAsync();

                    r.VerifyEqual("HTTP 200", "200", ((int)get.StatusCode).ToString());

                    r.Verify("利用者名が出る", body.Contains(name),
                        "出る", body.Contains(name) ? "出る" : "**出ない**");

                    r.Verify("ロールが出る", body.Contains("Admin"),
                        "出る", body.Contains("Admin") ? "出る" : "**出ない**");
                }
                finally
                {
                    await UsersAdmin.DeleteByUserNameAsync(client, name);
                }
            }
        }

        /// <summary>RT-324.4 属性データを消せる</summary>
        /// <param name="targetKey">core / netfx</param>
        /// <returns>Task</returns>
        [SkippableTheory]
        [MemberData(nameof(AllTargets))]
        public async Task RT32404_属性データを消せる(string targetKey)
        {
            using (IdPClient admin = await this.AdminClientAsync(targetKey))
            {
                string name = AdminCoverageTests.UniqueName("e2e_data");

                TestReport r = this.Report("RT-324.4",
                    "利用者が自分の属性データを消すと、管理画面の削除の口が消える",
                    "**削除の口は、一度も通っていなかった**（`COVERAGE.md`）。"
                    + "**使い捨ての利用者で測る**（テスト利用者の属性データを消さないため）。",
                    "#324");

                r.Target("POST /Manage/RemoveUnstructuredData");

                await UsersAdmin.SkipIfLockedDownAsync(admin);

                try
                {
                    r.Step("(1) 利用者を作り、属性データを入れる");

                    await UsersAdmin.CreateAsync(admin, name, name + "@example.com", null);

                    using (IdPClient user = this.Client(targetKey))
                    {
                        Assert.True(await user.TrySignInAsync(name, admin.Config.Get("TestUserPWD")),
                            "前提: 作った利用者でサインインできること");

                        string add = await user.GetStringAsync("/Manage/AddUnstructuredData");

                        Skip.If(string.IsNullOrEmpty(add) || !add.Contains("UnstructuredData1"),
                            "属性データの画面が閉じています（CanEditUnstructuredData）。");

                        await user.PostFormAsync("/Manage/AddUnstructuredData",
                            new Dictionary<string, string>()
                            {
                                { "__RequestVerificationToken", Html.Antiforgery(add) },
                                { "UnstructuredData1", "rt32404" },
                                { "UnstructuredData2", "rt32404" }
                            });

                        string before = await user.GetStringAsync("/Manage/Index");

                        r.Verify("削除の口が出る（前提）",
                            (before ?? "").Contains("RemoveUnstructuredData"),
                            "出る", (before ?? "").Contains("RemoveUnstructuredData") ? "出る" : "**出ない**");

                        r.Step("(2) 属性データを消す");

                        HttpResponseMessage post = await user.PostFormAsync("/Manage/RemoveUnstructuredData",
                            new Dictionary<string, string>()
                            {
                                { "__RequestVerificationToken", Html.Antiforgery(before) }
                            });

                        r.VerifyEqual("管理画面へリダイレクトする", "302", ((int)post.StatusCode).ToString());

                        string after = await user.GetStringAsync("/Manage/Index");

                        r.Verify("削除の口が消える", !(after ?? "").Contains("RemoveUnstructuredData"),
                            "消える", (after ?? "").Contains("RemoveUnstructuredData") ? "**消えない**" : "消える");
                    }
                }
                finally
                {
                    await UsersAdmin.DeleteByUserNameAsync(admin, name);
                }
            }
        }

        /// <summary>RT-324.5 自己テストの入口が、決まった response_type で認可エンドポイントへ送る</summary>
        /// <param name="targetKey">core / netfx</param>
        /// <returns>Task</returns>
        [SkippableTheory]
        [MemberData(nameof(AllTargets))]
        public async Task RT32405_自己テストの入口がresponse_typeを組み立てる(string targetKey)
        {
            using (IdPClient client = await this.AdminClientAsync(targetKey))
            {
                TestReport r = this.Report("RT-324.5",
                    "自己テストの入口（Implicit・Hybrid・PKCE plain）が、決まった response_type で /authorize へ送る",
                    "**これらの入口は、一度も通っていなかった**（`COVERAGE.md`）。"
                    + "**送るところまでを見る。** 認可の応答は `TC`・`EX` のテストが直接確かめている。",
                    "RFC 6749 §4.2.1 / OIDC Core 1.0 §3.2.2.1 / OIDC Core 1.0 §3.3.2.1 / RFC 7636 §4.3");

                r.Target("POST /Home/Saml2OAuth2Starters");

                string[][] starters = new string[][]
                {
                    new string[] { "Implicit", "token" },
                    new string[] { "Implicit_OIDC1", "id_token" },
                    new string[] { "Implicit_OIDC2", "id_token token" },
                    new string[] { "Hybrid_OIDC1", "code id_token" },
                    new string[] { "Hybrid_OIDC2", "code token" },
                    new string[] { "Hybrid_OIDC3", "code id_token token" },
                    new string[] { "PKCE_Plain", "code" }
                };

                foreach (string[] starter in starters)
                {
                    HttpResponseMessage res = await AdminCoverageTests.StartAsync(client, starter[0]);
                    string location = (res.Headers.Location == null) ? "" : res.Headers.Location.ToString();

                    r.Verify(starter[0] + " : /authorize へ送る", location.Contains("/authorize"),
                        "/authorize", string.IsNullOrEmpty(location) ? "HTTP " + (int)res.StatusCode : location.Split('?')[0]);

                    r.VerifyEqual(starter[0] + " : response_type", starter[1],
                        AdminCoverageTests.QueryValue(location, "response_type"));

                    if (starter[0] == "PKCE_Plain")
                    {
                        r.VerifyEqual(starter[0] + " : code_challenge_method", "plain",
                            AdminCoverageTests.QueryValue(location, "code_challenge_method"));
                    }
                }
            }
        }

        /// <summary>利用者の一覧を絞り込む</summary>
        /// <param name="client">IdPClient</param>
        /// <param name="name">条件</param>
        /// <returns>応答</returns>
        private static async Task<HttpResponseMessage> SearchAsync(IdPClient client, string name)
        {
            string index = await (await UsersAdmin.IndexAsync(client)).Content.ReadAsStringAsync();

            return await client.PostFormAsync("/UsersAdmin/List", new Dictionary<string, string>()
            {
                { "__RequestVerificationToken", Html.Antiforgery(index) },
                { "UserNameforSearch", name }
            });
        }

        /// <summary>自己テストの入口を叩く</summary>
        /// <param name="client">IdPClient</param>
        /// <param name="starter">入口の名前（submit.の後ろ）</param>
        /// <returns>応答</returns>
        private static async Task<HttpResponseMessage> StartAsync(IdPClient client, string starter)
        {
            string html = await client.GetStringAsync("/Home/Saml2OAuth2Starters");

            return await client.PostFormAsync("/Home/Saml2OAuth2Starters", new Dictionary<string, string>()
            {
                { "__RequestVerificationToken", Html.Antiforgery(html) },
                { "ClientType", "normal" },
                { "ClarifyRedirectUri", "true" },
                { "submit." + starter, starter }
            });
        }

        /// <summary>URL のクエリの値を引く（無ければ空）</summary>
        /// <param name="url">URL</param>
        /// <param name="name">名前</param>
        /// <returns>値</returns>
        private static string QueryValue(string url, string name)
        {
            int start = url.IndexOf('?');

            if (start >= 0)
            {
                foreach (string pair in url.Substring(start + 1).Split('&'))
                {
                    string[] kv = pair.Split(new char[] { '=' }, 2);

                    if (kv[0] == name && kv.Length == 2)
                    {
                        return WebUtility.UrlDecode(kv[1]);
                    }
                }
            }

            return "";
        }

        /// <summary>一意な名前</summary>
        /// <param name="prefix">接頭辞</param>
        /// <returns>名前</returns>
        private static string UniqueName(string prefix)
        {
            return prefix + "_" + Guid.NewGuid().ToString("N").Substring(0, 8);
        }

        /// <summary>管理者でサインインした IdPClient</summary>
        /// <param name="targetKey">core / netfx</param>
        /// <returns>IdPClient</returns>
        private async Task<IdPClient> AdminClientAsync(string targetKey)
        {
            IdPClient client = this.Client(targetKey);
            await client.SignInAsAdministratorAsync();

            return client;
        }
    }
}
