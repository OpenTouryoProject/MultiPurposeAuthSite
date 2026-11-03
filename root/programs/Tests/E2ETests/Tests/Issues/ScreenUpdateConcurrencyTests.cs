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
//* クラス名        ：ScreenUpdateConcurrencyTests
//* クラス日本語名  ：RT-331 画面からの更新は、同じ利用者の行の更新と重なっても失敗しない
//*
//* 作成日時        ：－
//* 作成者          ：－
//* 更新履歴        ：－
//*
//*  日時        更新者            内容
//*  ----------  ----------------  -------------------------------------------------
//*  2026/11/03  玄人 幸道         新規（#331）
//**********************************************************************************

using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Threading.Tasks;

using MultiPurposeAuthSite.Tests.E2E.Infrastructure;

using Xunit;
using Xunit.Abstractions;

namespace MultiPurposeAuthSite.Tests.E2E.Tests.Issues
{
    /// <summary>
    /// RT-331.7. **画面からの更新は、同じ利用者の行の更新と重なっても失敗しない**（#331）。
    /// </summary>
    /// <remarks>
    /// **利用者の行は楽観排他で書く**（#316）。**同じ利用者の行は、無関係な更新**（サインインの数え、別の端末など）**でも書き換わる。**
    /// **以前は、重なっただけで画面の保存が失敗した**（`RT-230.1` が、ときどき落ちた）。
    /// **読み直して、変えた項目だけを当て直す。**
    /// </remarks>
    public class ScreenUpdateConcurrencyTests : TargetTestBase
    {
        /// <summary>同時に送る数</summary>
        private const int Parallel = 5;

        /// <summary>コンストラクタ</summary>
        /// <param name="output">ITestOutputHelper</param>
        public ScreenUpdateConcurrencyTests(ITestOutputHelper output) : base(output)
        {
        }

        /// <summary>RT-331.7 非構造化データの保存を同時に送っても、どれも失敗しない</summary>
        /// <param name="targetKey">core / netfx</param>
        /// <returns>Task</returns>
        [SkippableTheory]
        [MemberData(nameof(AllTargets))]
        public async Task RT33107_画面からの保存を同時に送っても失敗しない(string targetKey)
        {
            using (IdPClient admin = this.Client(targetKey))
            {
                string userName = "e2e_rt331_screen_" + Guid.NewGuid().ToString("N").Substring(0, 8);

                TestReport r = this.Report("RT-331.7",
                    "同じ利用者の画面からの保存（非構造化データ）を同時に送っても、どれも失敗しない",
                    "**同時に送ると、利用者の行の更新が楽観排他で負ける要求が出る**（#316）。"
                    + "**負けた要求は、読み直して、変えた項目だけを当て直す**こと（以前は保存に失敗した）。"
                    + "**同じ項目なので、後から書いた方が残る。**",
                    "#331 / #316");

                r.Target("利用者名 = " + userName + "（使い捨ての利用者）/ POST /Manage/AddUnstructuredData");

                try
                {
                    r.Step("(1) 利用者を作り、サインインする");

                    await admin.SignInAsAdministratorAsync();
                    await UsersAdmin.SkipIfLockedDownAsync(admin);

                    HttpResponseMessage created = await UsersAdmin.CreateAsync(
                        admin, userName, userName + "@example.com", "User");

                    Assert.True(created.StatusCode == HttpStatusCode.Found || created.StatusCode == HttpStatusCode.Redirect,
                        "前提: 利用者を作れること");

                    //  **端末（セッション）を分ける。** 同じセッションの要求は、サイトが 1 本ずつ処理することがある。
                    List<IdPClient> users = new List<IdPClient>();

                    try
                    {
                        for (int i = 0; i < Parallel; i++)
                        {
                            IdPClient user = this.Client(targetKey);
                            users.Add(user);

                            Assert.True(await user.TrySignInAsync(userName, user.Config.Get("TestUserPWD")),
                                "前提: 作った利用者でサインインできること（" + (i + 1) + " 台目）");
                        }

                        r.Step("(2) " + Parallel + " 台の端末から、非構造化データの保存を同時に送る");

                        List<Task<bool>> saves = new List<Task<bool>>();

                        for (int i = 0; i < Parallel; i++)
                        {
                            saves.Add(users[i].SetUnstructuredDataAsync("e2e-" + i.ToString(), "e2e-" + i.ToString()));
                        }

                        bool[] results = await Task.WhenAll(saves);

                        int ok = results.Count(x => x);

                        r.VerifyEqual("**どれも保存できる**（競合で負けても、当て直す）",
                            Parallel.ToString() + " 件", ok.ToString() + " 件");
                    }
                    finally
                    {
                        foreach (IdPClient user in users)
                        {
                            user.Dispose();
                        }
                    }
                }
                finally
                {
                    await admin.SignInAsAdministratorAsync();
                    await UsersAdmin.DeleteByUserNameAsync(admin, userName);
                }

                r.Done();
            }
        }
    }
}
