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
//* クラス名        ：CookieIsolationTests
//* クラス日本語名  ：CN-4 上流と下流の Cookie が衝突しない（#284）
//*
//* 作成日時        ：－
//* 作成者          ：－
//* 更新履歴        ：－
//*
//*  日時        更新者            内容
//*  ----------  ----------------  -------------------------------------------------
//*  2026/10/08  玄人 幸道         新規（#284）
//**********************************************************************************

using System;
using System.Collections.Generic;
using System.Linq;
using System.Net.Http;
using System.Threading.Tasks;

using MultiPurposeAuthSite.Tests.E2E.Infrastructure;

using Xunit;
using Xunit.Abstractions;

namespace MultiPurposeAuthSite.Tests.E2E.Tests.Container
{
    /// <summary>
    /// CN-4. 上流と下流の Cookie の名前が、1 つも衝突しないこと。
    /// </summary>
    /// <remarks>
    /// **Cookie のスコープにポートは入らない**（RFC 6265 §8.5）。
    /// **`localhost:44301`（上流）と `localhost:44303`（下流）は Cookie を共有する。**
    /// **名前が同じだと、後にサインインした側が相手を蹴り出す**（#250 の段階 4 で実測）。
    ///
    /// **名前は `CookieNamePrefix` で分けている**（#255）。**掛かっていないものが 1 つでもあると、
    /// そこだけが奪い合いになる** — #282 の AntiForgery が、まさにそれだった。
    ///
    /// **この形の欠陥は、2 つ建てないと出ない。**
    /// **ホストの core / netfx は同じ名前を使わない**ので、ここで測るしかない。
    /// </remarks>
    public class CookieIsolationTests : TargetTestBase
    {
        /// <summary>コンストラクタ</summary>
        /// <param name="output">ITestOutputHelper</param>
        public CookieIsolationTests(ITestOutputHelper output) : base(output)
        {
        }

        /// <summary>CN-4.1 上流と下流で、同じ名前の Cookie を発行しない</summary>
        /// <returns>Task</returns>
        [SkippableFact]
        public async Task CN0401_上流と下流で同じ名前のCookieを発行しない()
        {
            using (IdPClient up = ContainerTargets.Client(ContainerTargets.UpstreamKey))
            using (IdPClient down = ContainerTargets.Client(ContainerTargets.DownstreamKey))
            {
                TestReport r = this.Report("CN-4.1",
                    "上流コンテナと下流コンテナが、同じ名前の Cookie を発行しない",
                    "**Cookie のスコープにポートは入らない**（RFC 6265 §8.5）ので、"
                    + "**ポートを分けても Cookie は分かれない。** **名前で分けるしかない**（#255）。"
                    + "**掛かっていないものが 1 つでもあると、そこだけが奪い合いになる** — "
                    + "**#282 の AntiForgery がそれだった。**",
                    "RFC 6265 §8.5 / #250 の段階 4 / #255 / #282");

                r.Target("上流コンテナ ＋ 下流コンテナ");

                r.Step("(1) それぞれサインインして、発行された Cookie の名前を集める");

                HashSet<string> upNames = await CookieIsolationTests.CollectCookieNamesAsync(up);
                HashSet<string> downNames = await CookieIsolationTests.CollectCookieNamesAsync(down);

                r.Verify("上流が Cookie を発行する", 0 < upNames.Count,
                    "1 件以上", upNames.Count + " 件");

                r.Verify("下流が Cookie を発行する", 0 < downNames.Count,
                    "1 件以上", downNames.Count + " 件");

                Assert.True(0 < upNames.Count && 0 < downNames.Count,
                    "前提: 両方が Cookie を発行すること");

                r.Step("(2) 名前が 1 つも重なっていない");

                //  **分けられないと分かっているものを、あらかじめ除く。**
                //    `SessionTimeOut` は **Open棟梁 の定数**で、設定で分けられない
                //    （`CONFIGURATION.md` 11 節の `CookieNamePrefix`）。
                //    **雛形は `FxSessionTimeOutCheck` を `off` にしているので読まれない。**
                //    **ここを増やすと、測らない範囲が広がるので注意する。**
                string[] allowed = new string[] { "SessionTimeOut" };

                List<string> shared = upNames.Intersect(downNames, StringComparer.Ordinal)
                    .Where(x => !allowed.Contains(x, StringComparer.Ordinal))
                    .OrderBy(x => x, StringComparer.Ordinal).ToList();

                r.Verify("重なる名前が無い", shared.Count == 0,
                    "0 件",
                    (shared.Count == 0) ? "0 件"
                        : "**" + shared.Count + " 件 : " + string.Join(", ", shared) + "**");

                r.Note("**値は出さない。** 名前だけを見る（`TESTING.md` 9 節）。"
                    + "**`SessionTimeOut` だけは除いている** — "
                    + "**Open棟梁 の定数で、設定で分けられない**が、"
                    + "**雛形は `FxSessionTimeOutCheck` を `off` にしているので読まれない**"
                    + "（`CONFIGURATION.md` 11 節）。");

                r.Done();
            }
        }

        /// <summary>サインインまで通して、持っている Cookie の名前を集める</summary>
        /// <param name="client">IdPClient</param>
        /// <returns>Cookie の名前</returns>
        /// <remarks>
        /// **`CookieContainer` を見る**（`IdPClient.CookieNames`）。
        /// **`Set-Cookie` を拾い集めるのでは足りない** —
        /// **認証 Cookie はサインインの POST の応答で来る**ので、
        /// **その応答を観測していないと、いちばん大事なものが漏れる**（#284 で踏んだ）。
        ///
        /// **サインインまで通す。** 画面を 1 枚開くだけでは、認証 Cookie が出ない。
        /// </remarks>
        private static async Task<HashSet<string>> CollectCookieNamesAsync(IdPClient client)
        {
            await client.GetAsync("/Account/Login");
            await client.SignInAsync();
            await client.GetAsync("/Manage/Index");

            return new HashSet<string>(client.CookieNames, StringComparer.Ordinal);
        }
    }
}
