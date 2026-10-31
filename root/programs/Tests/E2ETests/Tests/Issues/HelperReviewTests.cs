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
//* クラス名        ：HelperReviewTests
//* クラス日本語名  ：RT-294.93 Util/Sts/Helper.*.cs のレビューで見つけた不具合
//*
//* 作成日時        ：－
//* 作成者          ：－
//* 更新履歴        ：－
//*
//*  日時        更新者            内容
//*  ----------  ----------------  -------------------------------------------------
//*  2026/10/31  玄人 幸道         新規（#294）
//**********************************************************************************

using System;
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
    /// RT-294.93 `Util/Sts/Helper.*.cs` のレビューで見つけた不具合（#294）。
    /// </summary>
    /// <remarks>
    /// | | 確かめること |
    /// |---|---|
    /// | `RT-294.93` | **クライアント名と大文字小文字だけ違う利用者は、自己テストで自分の登録を使う**（`GetClientIdByName`） |
    ///
    /// **管理者でサインインする**（使い捨ての利用者を作って消す）ので、管理画面のテストと同じコレクションに入れる。
    /// </remarks>
    [Collection(UsersAdminTests.AdminScreenCollection)]
    public class HelperReviewTests : TargetTestBase
    {
        /// <summary>認可要求の client_id</summary>
        private static readonly Regex ClientIdRegex = new Regex("[?&]client_id=(?<value>[^&]*)");

        /// <summary>コンストラクタ</summary>
        /// <param name="output">ITestOutputHelper</param>
        public HelperReviewTests(ITestOutputHelper output) : base(output) { }

        #region RT-294.93

        /// <summary>RT-294.93 クライアント名と大文字小文字だけ違う利用者は、自己テストで自分の登録を使う</summary>
        /// <param name="targetKey">core / netfx</param>
        /// <returns>Task</returns>
        [SkippableTheory]
        [MemberData(nameof(AllTargets))]
        public async Task RT29493_クライアント名と大文字小文字だけ違う利用者は自分の登録を使う(string targetKey)
        {
            using (IdPClient admin = this.Client(targetKey))
            using (IdPClient user = this.Client(targetKey))
            {
                await admin.SignInAsAdministratorAsync();

                // **構成ファイルのクライアント名（TestClient）と、大文字小文字だけが違う**。
                string name = KnownClients.TestClient.ToLowerInvariant();
                string password = admin.Config.Get("TestUserPWD");

                TestReport r = this.Report("RT-294.93",
                    "自己テスト（ログイン・ユーザの Client）: 利用者 " + name + " は、構成ファイルの "
                    + KnownClients.TestClient + " ではなく、自分の登録で認可要求を送る",
                    "**以前はクライアント名を大文字小文字を区別せずに、利用者名より先に照合していた**ので、"
                    + "**クライアント名と大文字小文字だけ違う利用者は、構成ファイルのクライアントで動いた**"
                    + "（認可の記録の「User Account」も、そのクライアントになった）。",
                    "#294（Helper.GetClientIdByName）");

                r.Target("使い捨ての利用者 = " + name);

                await UsersAdmin.SkipIfLockedDownAsync(admin);

                // **前の回が残していれば消す**（名前が固定なので）。
                await UsersAdmin.DeleteByUserNameAsync(admin, name);

                try
                {
                    r.Step("(1) 使い捨ての利用者を作り、サインインして、クライアントを 1 件登録する");

                    // **自分のクライアントの登録は Admin の画面**（`[Authorize(Roles = SystemAdminOrAdmin)]`）。
                    HttpResponseMessage created = await UsersAdmin.CreateAsync(admin, name, name + "@example.com", "Admin");

                    Assert.True(created.StatusCode == HttpStatusCode.Found || created.StatusCode == HttpStatusCode.Redirect,
                        "前提: 利用者を作れること");

                    Assert.True(await user.TrySignInAsync(name, password), "前提: 作った利用者でサインインできること");

                    string own = await ManageClientRegistration.RegisterAsync(user);

                    Assert.False(string.IsNullOrEmpty(own), "前提: クライアントを登録できること");

                    string configured = Flows.Registration(user, KnownClients.TestClient).ClientId;

                    r.Step("(2) 自己テストを「ログイン・ユーザの Client」で始める（認可コード フロー）");

                    HttpResponseMessage started = await user.StartSelfTestAsync("AuthorizationCode_OIDC", "");

                    Assert.True(started.Headers.Location != null, "前提: 認可エンドポイントへ送られること");

                    Match m = ClientIdRegex.Match(started.Headers.Location.OriginalString);

                    Assert.True(m.Success, "前提: 認可要求に client_id が載ること");

                    string sent = Uri.UnescapeDataString(m.Groups["value"].Value);

                    r.VerifyEqual("**client_id は、その人が登録したもの**", own, sent);
                    r.Verify("構成ファイルの " + KnownClients.TestClient + " ではない", sent != configured,
                        "違う", (sent == configured) ? "**同じ**" : "違う");
                }
                finally
                {
                    await UsersAdmin.DeleteByUserNameAsync(admin, name);
                }

                r.Done();
            }
        }

        #endregion
    }
}
