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
//* クラス名        ：ContainerSignInTests
//* クラス日本語名  ：CN-2 コンテナでサインインできる（#284）
//*
//* 作成日時        ：－
//* 作成者          ：－
//* 更新履歴        ：－
//*
//*  日時        更新者            内容
//*  ----------  ----------------  -------------------------------------------------
//*  2026/10/08  玄人 幸道         新規（#284）
//**********************************************************************************

using System.Threading.Tasks;

using MultiPurposeAuthSite.Tests.E2E.Infrastructure;

using Xunit;
using Xunit.Abstractions;

namespace MultiPurposeAuthSite.Tests.E2E.Tests.Container
{
    /// <summary>
    /// CN-2. コンテナでサインインできること。
    /// </summary>
    /// <remarks>
    /// **ストアは `mem` 固定**（compose）。**種データは初回の `GET /Account/Login` で作られる**
    /// （`CreateData`。#210 / #264）。**作り直すたびに作り直される。**
    ///
    /// **接尾辞は付かない**（`super_tanaka`）。
    /// **コンテナは自分のストアを持つ**ので、分ける必要がない（#260 と同じ考え方）。
    /// </remarks>
    public class ContainerSignInTests : TargetTestBase
    {
        /// <summary>コンストラクタ</summary>
        /// <param name="output">ITestOutputHelper</param>
        public ContainerSignInTests(ITestOutputHelper output) : base(output)
        {
        }

        /// <summary>CN-2.1 種データの利用者でサインインできる</summary>
        /// <param name="containerKey">upstream / downstream</param>
        /// <returns>Task</returns>
        [SkippableTheory]
        [MemberData(nameof(ContainerTargets.BothContainers), MemberType = typeof(ContainerTargets))]
        public async Task CN0201_種データの利用者でサインインできる(string containerKey)
        {
            using (IdPClient client = ContainerTargets.Client(containerKey))
            {
                TestReport r = this.Report("CN-2.1",
                    "コンテナで、種データの利用者でサインインできる",
                    "**`mem` なので、作り直すたびに種データが作られる**（`CreateData`）。"
                    + "**サインインできることは、画面・ビュー・メールの雛形・"
                    + "DataProtection の鍵まで届いていることを意味する**"
                    + "（どれもマウントか設定で与えている）。",
                    "#250 の段階 2 / #264 / #284");

                r.Target(client.Target.DisplayName + "（" + client.Target.BaseUrl + "）");

                r.Step("(1) サインインする（利用者名は構成から。パスワードは出さない）");

                await client.SignInAsync();

                r.Verify("サインインできた", client.IsSignedIn,
                    "できる", client.IsSignedIn ? "できた" : "**できなかった**");

                Assert.True(client.IsSignedIn, "前提: サインインできること");

                r.Step("(2) 保護された画面が開く");

                bool signedIn = await IdFederation.IsSignedInAsync(client);

                r.Verify("`/Manage/Index` が開く", signedIn,
                    "開く", signedIn ? "開いた" : "**ログイン画面へ戻された**");

                r.Done();
            }
        }
    }
}
