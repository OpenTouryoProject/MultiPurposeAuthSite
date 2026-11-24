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
//* クラス名        ：LockedDownTests
//* クラス日本語名  ：RT-431 テスト用の口を閉じた配備では、どの経路から来ても開かない
//*
//* 作成日時        ：－
//* 作成者          ：－
//* 更新履歴        ：－
//*
//*  日時        更新者            内容
//*  ----------  ----------------  -------------------------------------------------
//*  2026/11/24  玄人 幸道         新規（#431）
//**********************************************************************************

using System;
using System.Collections.Generic;
using System.Net.Http;
using System.Threading.Tasks;

using MultiPurposeAuthSite.Tests.E2E.Infrastructure;

using Xunit;
using Xunit.Abstractions;

namespace MultiPurposeAuthSite.Tests.E2E.Tests.Issues
{
    /// <summary>
    /// RT-431. **`IsLockedDownTestEndpoints` を true にした配備では、テスト用の口は、
    /// 決めた経路からも既定の経路からも開かない。**
    /// </summary>
    /// <remarks>
    /// | | 測ること |
    /// |---|---|
    /// | **`RT-431.1`** | **`TestHybridFlow` は、決めた経路（net10.0 `/TestHybridFlowWebAPI`・net48 `/TestHybridFlow`）からも、既定の経路（net10.0 `/OAuth2ResourceServer/TestHybridFlow`・net48 `/api/OAuth2ResourceServer/TestHybridFlow`）からも 404** |
    /// | **`RT-431.2`** | **`TestResource`（#425）も、両方の経路から 404** |
    /// | **`RT-431.3`** | **Logout の受け口と受信箱（`/Account/BackChannelLogoutClient`・`BackChannelLogoutBox`・`FrontChannelLogoutClient`・`FrontChannelLogoutBox`）、`api/Values`（net10.0）も 404** |
    ///
    /// **以前は、`TestHybridFlow` を経路を張らないことでだけ閉じていた**ので、**既定の経路から動作に届いた**（#431）。
    ///
    /// **通しの E2E はテスト用の口を開けて起動する**（自己テスト・受信箱を使うテストがあるため）。
    /// **だから、閉じた設定で起動して測る** —
    /// **`test.ps1 -Launch -LockedDown -Filter "FullyQualifiedName~LockedDownTests"`。**
    ///
    /// **付けなければ、このクラスは走らない**（`test.ps1` が除外する。`ImplicitDisabledTests` と同じ流儀）。
    /// </remarks>
    public class LockedDownTests : TargetTestBase
    {
        /// <summary>コンストラクタ</summary>
        /// <param name="output">ITestOutputHelper</param>
        public LockedDownTests(ITestOutputHelper output) : base(output)
        {
        }

        /// <summary>測る対象 : `-LockedDown` で起動したときだけ</summary>
        public static IEnumerable<object[]> LockedDownTargets
        {
            get
            {
                if (Environment.GetEnvironmentVariable("MPAS_LOCKED_DOWN") == "true")
                {
                    yield return new object[] { TestEnv.CoreKey };
                    yield return new object[] { TestEnv.NetFxKey };
                }
            }
        }

        #region RT-431.1

        /// <summary>RT-431.1 TestHybridFlow は、どの経路からも 404</summary>
        /// <param name="targetKey">core / netfx</param>
        /// <returns>Task</returns>
        [SkippableTheory]
        [MemberData(nameof(LockedDownTargets))]
        public async Task RT43101_TestHybridFlowはどの経路からも404(string targetKey)
        {
            using (IdPClient client = this.Client(targetKey))
            {
                TestReport r = this.Report("RT-431.1",
                    "**`IsLockedDownTestEndpoints=true` の配備では、`TestHybridFlow` は、決めた経路からも既定の経路からも 404**",
                    "**本番の構成でテスト用の口を開かない**（`13_CONFIGURATION.md`「本番の確かめ方」）。"
                    + "**以前は経路を張らないことでだけ閉じていたので、既定の経路（`{controller}/{action}`）から動作に届いた**（#431）。",
                    "#431");

                bool netfx = targetKey == TestEnv.NetFxKey;

                foreach (string path in new string[]
                {
                    netfx ? "/TestHybridFlow" : "/TestHybridFlowWebAPI",
                    netfx ? "/api/OAuth2ResourceServer/TestHybridFlow" : "/OAuth2ResourceServer/TestHybridFlow"
                })
                {
                    r.Step("POST " + path + "（code=dummy）");

                    HttpResponseMessage res = await client.PostFormAsync(path,
                        new Dictionary<string, string>() { { "code", "dummy" } });

                    r.VerifyEqual(path + " は 404", "404", ((int)res.StatusCode).ToString());
                }

                r.Done();
            }
        }

        #endregion

        #region RT-431.2

        /// <summary>RT-431.2 TestResource は、どの経路からも 404</summary>
        /// <param name="targetKey">core / netfx</param>
        /// <returns>Task</returns>
        [SkippableTheory]
        [MemberData(nameof(LockedDownTargets))]
        public async Task RT43102_TestResourceはどの経路からも404(string targetKey)
        {
            using (IdPClient client = this.Client(targetKey))
            {
                TestReport r = this.Report("RT-431.2",
                    "**`IsLockedDownTestEndpoints=true` の配備では、`TestResource`（#425）は、決めた経路からも既定の経路からも 404**",
                    "**開いていれば、トークンが無い要求は 401 になる**ので、**404 なら口が閉じている**（#425 の設計。`Util.Test.TestResource`）。",
                    "#431 / #425");

                bool netfx = targetKey == TestEnv.NetFxKey;

                foreach (string path in new string[]
                {
                    "/TestResource",
                    netfx ? "/api/OAuth2ResourceServer/TestResource" : "/OAuth2ResourceServer/TestResource"
                })
                {
                    r.Step("GET " + path);

                    HttpResponseMessage res = await client.GetAsync(path);

                    r.VerifyEqual(path + " は 404", "404", ((int)res.StatusCode).ToString());
                }

                r.Done();
            }
        }

        #endregion

        #region RT-431.3

        /// <summary>RT-431.3 Logout の受け口と受信箱、api/Values も 404</summary>
        /// <param name="targetKey">core / netfx</param>
        /// <returns>Task</returns>
        [SkippableTheory]
        [MemberData(nameof(LockedDownTargets))]
        public async Task RT43103_Logoutの受け口と受信箱とValuesも404(string targetKey)
        {
            using (IdPClient client = this.Client(targetKey))
            {
                TestReport r = this.Report("RT-431.3",
                    "**`IsLockedDownTestEndpoints=true` の配備では、Logout の受け口と受信箱、`api/Values`（net10.0）も 404**",
                    "**受信箱が開いていれば、他人のログアウトの通知を読まれる**（`13_CONFIGURATION.md`「本番の確かめ方」。#310）。"
                    + "**これらは動作の中で閉じているかを確かめている**（#431 で、`TestHybridFlow` と比べて確かめた）。",
                    "#431 / #310");

                r.Step("POST /Account/BackChannelLogoutClient（logout_token=dummy。この口は POST だけ）");

                HttpResponseMessage backClient = await client.PostFormAsync("/Account/BackChannelLogoutClient",
                    new Dictionary<string, string>() { { "logout_token", "dummy" } });

                r.VerifyEqual("/Account/BackChannelLogoutClient は 404", "404", ((int)backClient.StatusCode).ToString());

                List<string> paths = new List<string>()
                {
                    "/Account/BackChannelLogoutBox",
                    "/Account/FrontChannelLogoutClient",
                    "/Account/FrontChannelLogoutBox"
                };

                if (targetKey != TestEnv.NetFxKey)
                {
                    //  **api/Values は net10.0 版だけに在る。**
                    paths.Add("/api/Values/Get");
                }

                foreach (string path in paths)
                {
                    r.Step("GET " + path);

                    HttpResponseMessage res = await client.GetAsync(path);

                    r.VerifyEqual(path + " は 404", "404", ((int)res.StatusCode).ToString());
                }

                r.Done();
            }
        }

        #endregion
    }
}
