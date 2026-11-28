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
//* クラス名        ：SignInBeforeReadyTests
//* クラス日本語名  ：RT-440 画面の読み込みが終わる前に押しても、サインインできる
//*
//* 作成日時        ：－
//* 作成者          ：－
//* 更新履歴        ：－
//*
//*  日時        更新者            内容
//*  ----------  ----------------  -------------------------------------------------
//*  2026/11/28  玄人 幸道         新規（#440）
//**********************************************************************************

using System;
using System.Diagnostics;
using System.Threading.Tasks;

using Microsoft.Playwright;

using MultiPurposeAuthSite.Tests.E2E.Infrastructure;

using Xunit;
using Xunit.Abstractions;

/// <summary>MultiPurposeAuthSite.Tests.E2E.Tests.WebUI</summary>
namespace MultiPurposeAuthSite.Tests.E2E.Tests.WebUI
{
    /// <summary>
    /// RT-440 サインインの画面で、**jQuery の ready のハンドラが動く前に押しても**、サインインできる。
    /// </summary>
    /// <remarks>
    /// **サインインのボタンは `type="button"` で、送信するのは JavaScript のハンドラだけ**である。
    /// **以前は `$(function)` の中で付けていた。** **jQuery 3 は `$(function)` をタイマーで後から呼ぶ**ので、
    /// **それまでに押すと何も起きなかった**（適合性テストの自動操作のブラウザが、CI で 1 回目に 1〜2 割落ちていた。#440）。
    ///
    /// **ready が動くのを遅らせて、押した瞬間の状態を作る。**
    /// 文書の前に差し込むスクリプトで、jQuery が `window.jQuery` に入った時点で `jQuery.fn.ready` を包み、
    /// **ready のハンドラを <see cref="ReadyDelayMs"/> だけ遅らせる**（`$(function)` は `jQuery.fn.ready` を通る）。
    /// **直す前は、押しても画面が移らず、遅れの後にハンドラが付いても、押した後なので送られない。**
    ///
    /// **測るのは通常のサインインのボタンだけ**である。ID 連携のボタンは上流の IdP が要るので、ここでは押さない
    /// （同じ形に直した。`Login.cshtml`）。
    /// </remarks>
    public class SignInBeforeReadyTests : TargetTestBase
    {
        /// <summary>ready のハンドラを遅らせる時間（ミリ秒）</summary>
        private const int ReadyDelayMs = 5000;

        /// <summary>
        /// 文書の前に差し込むスクリプト。**jQuery の ready のハンドラを遅らせる**。
        /// **`window.__readyDelayed` で、差し込みが効いたかを確かめる**（効いていなければ、測れていない）。
        /// </summary>
        private const string DelayReadyScript = @"
(() => {
  let jq;
  Object.defineProperty(window, 'jQuery', {
    configurable: true,
    get() { return jq; },
    set(v) {
      jq = v;
      if (v && v.fn && v.fn.ready && !v.fn.__delayedReady) {
        const ready = v.fn.ready;
        v.fn.ready = function (fn) {
          const self = this;
          setTimeout(() => ready.call(self, fn), " + "READY_DELAY_MS" + @");
          return this;
        };
        v.fn.__delayedReady = true;
        window.__readyDelayed = true;
      }
    }
  });
})();";

        /// <summary>コンストラクタ</summary>
        /// <param name="output">ITestOutputHelper</param>
        public SignInBeforeReadyTests(ITestOutputHelper output) : base(output) { }

        #region RT-440.1

        /// <summary>RT-440.1 ready のハンドラが動く前に押しても、サインインの画面から移る</summary>
        /// <param name="targetKey">core / netfx</param>
        /// <returns>Task</returns>
        [SkippableTheory]
        [MemberData(nameof(AllTargets))]
        public async Task RT440_1_readyの前に押してもサインインできる(string targetKey)
        {
            // **対象が起動していなければ Skip する**（Client が確かめ、種データも作らせる）。
            using (IdPClient probe = this.Client(targetKey)) { }

            TargetInfo target = TestEnv.Target(targetKey);

            TestReport r = this.Report("RT-440.1",
                "サインインの画面で、jQuery の ready のハンドラが動く前にボタンを押しても、サインインできる",
                "**ボタンは `type=\"button\"` で、送信するのはハンドラだけ**である。"
                + "**ハンドラを `$(function)` の中で付けると、jQuery 3 はタイマーで後から呼ぶ**ので、"
                + "**それまでに押すと何も起きない**（適合性テストの自動操作のブラウザが落ちていた）。"
                + "**ready を遅らせて**、押した瞬間にハンドラが付いていない状態を作る。",
                "#440");

            using (WebUi.Session session = await WebUi.OpenAsync())
            await using (IBrowserContext context = await session.NewContextAsync(target))
            {
                await context.AddInitScriptAsync(
                    DelayReadyScript.Replace("READY_DELAY_MS", ReadyDelayMs.ToString()));

                IPage page = await context.NewPageAsync();

                r.Observe("使っているブラウザ", session.Channel);

                r.Target("GET /Account/Login → ボタン normal_signin（" + target.BaseUrl + "）");

                r.Step("(1) ready を " + ReadyDelayMs + " ミリ秒遅らせて、サインインの画面を開く");

                await WebUi.GotoAsync(page, target.Url("/Account/Login"));

                bool delayed = await page.EvaluateAsync<bool>("() => window.__readyDelayed === true");

                r.Verify("ready を遅らせる差し込みが効いている", delayed,
                    "効いている", delayed ? "効いている" : "**効いていない（測れていない）**");

                Assert.True(delayed, "前提: ready を遅らせる差し込みが効くこと");

                r.Step("(2) ready が動く前に、入力してボタンを押す");

                Stopwatch sw = Stopwatch.StartNew();

                await page.FillAsync("#Email", TestEnv.TestUserName(targetKey));
                await page.FillAsync("#Password", target.Config.Get("TestUserPWD"));
                await page.ClickAsync("#normal_signin");

                long clickedMs = sw.ElapsedMilliseconds;

                //  **押すまでが遅れより短くなければ、ハンドラが付いた後に押したことになり、測れていない。**
                r.Verify("ready が動く前に押した", clickedMs < ReadyDelayMs,
                    ReadyDelayMs + " ミリ秒より前", clickedMs + " ミリ秒");

                Assert.True(clickedMs < ReadyDelayMs, "前提: ready が動く前に押せること");

                //  **`WaitForURLAsync` を使わず、`page.Url` を見る**（`WebUi.SignInAsync` と同じ。#325）。
                //    **遅れの後も待つ**（直す前は、遅れの後にハンドラが付いても、押した後なので移らない）。
                DateTime deadline = DateTime.UtcNow.AddMilliseconds(ReadyDelayMs + 10000);

                while (page.Url.Contains("/Account/Login") && DateTime.UtcNow < deadline)
                {
                    await Task.Delay(100);
                }

                bool moved = !page.Url.Contains("/Account/Login");

                r.Verify("サインインの画面から移る", moved,
                    "移る", moved ? "移った" : "**移らない（押しても送られなかった）**");

                r.Observe("移った先", page.Url);

                r.Done();
            }
        }

        #endregion
    }
}
