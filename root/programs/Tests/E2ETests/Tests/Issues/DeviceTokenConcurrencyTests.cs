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
//* クラス名        ：DeviceTokenConcurrencyTests
//* クラス日本語名  ：RT-331 端末の登録は、同じ利用者の更新と重なっても失敗しない
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
using System.Threading.Tasks;

using MultiPurposeAuthSite.Tests.E2E.Infrastructure;
using MultiPurposeAuthSite.Tests.E2E.Tests.Extended;

using Xunit;
using Xunit.Abstractions;

namespace MultiPurposeAuthSite.Tests.E2E.Tests.Issues
{
    /// <summary>
    /// RT-331.4. **`/SetDeviceToken` は、同じ利用者の行の更新と重なっても失敗しない**（#331）。
    /// </summary>
    /// <remarks>
    /// **利用者の行は楽観排他で書く**（#316）。**競合で負けた要求は、以前は 500 を返した。**
    /// 端末は送り直さないので、**登録が残らず、プッシュ通知が届かなくなる。**
    ///
    /// **既定の利用者の行（端末の登録）を書く**ので、CIBA のテストと同じコレクションに入れる。
    /// </remarks>
    [Collection(CibaTests.DeviceCollection)]
    public class DeviceTokenConcurrencyTests : TargetTestBase
    {
        /// <summary>同時に送る数</summary>
        private const int Parallel = 10;

        /// <summary>コンストラクタ</summary>
        /// <param name="output">ITestOutputHelper</param>
        public DeviceTokenConcurrencyTests(ITestOutputHelper output) : base(output)
        {
        }

        /// <summary>RT-331.4 端末の登録を同時に送っても、どれも失敗しない</summary>
        /// <param name="targetKey">core / netfx</param>
        /// <returns>Task</returns>
        [SkippableTheory]
        [MemberData(nameof(AllTargets))]
        public async Task RT33104_端末の登録を同時に送っても失敗しない(string targetKey)
        {
            using (IdPClient client = await this.SignedInClientAsync(targetKey))
            {
                TestReport r = this.Report("RT-331.4",
                    "同じ利用者の端末の登録を同時に送っても、どれも失敗しない",
                    "**同じ利用者の行を同時に書くと、楽観排他で負ける要求が出る**（#316）。"
                    + "**負けた要求は、読み直して書き直し、200 を返す**こと（以前は 500）。",
                    "#331 / #316");

                r.Target("POST /SetDeviceToken（認証デバイス = " + KnownClients.AuthenticationDeviceWeb + "）");

                r.Step("(1) 認証デバイスのトークンを取る");

                JsonResponse device = await Flows.RunAuthenticationDeviceFlowAsync(client);

                Assert.False(string.IsNullOrEmpty(device.AccessToken), "前提: 認証デバイスの access_token が返ること");

                r.Step("(2) 同じトークンで、端末の登録を同時に " + Parallel + " 回送る");

                List<Task<JsonResponse>> requests = new List<Task<JsonResponse>>();

                for (int i = 0; i < Parallel; i++)
                {
                    requests.Add(client.SetDeviceTokenAsync(
                        device.AccessToken, "e2e-parallel-" + i.ToString() + "-" + Guid.NewGuid().ToString("N")));
                }

                JsonResponse[] results = await Task.WhenAll(requests);

                int ok = results.Count(x => x.StatusCode == HttpStatusCode.OK);

                r.VerifyEqual("**どれも 200**（競合で負けても、書き直す）",
                    Parallel.ToString() + " 件",
                    ok.ToString() + " 件"
                    + ((ok == Parallel) ? "" : "（ほか: "
                        + string.Join(", ", results.Where(x => x.StatusCode != HttpStatusCode.OK)
                            .Select(x => ((int)x.StatusCode).ToString())) + "）"));

                r.Done();
            }
        }
    }
}
