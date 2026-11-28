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
//*  2026/11/28  玄人 幸道         ready のハンドラを時間で遅らせず、テストの間ずっと止めるようにした（通しの負荷で、遅れの後に押したことがあった。#440）
//**********************************************************************************

using System;
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
    /// **ready のハンドラを、テストの間ずっと止めて、押した瞬間の状態を作る。**
    /// 文書の前に差し込むスクリプトで、jQuery が `window.jQuery` に入った時点で `jQuery.fn.ready` を置き換え、
    /// **ready のハンドラを呼ばずに溜める**（`$(function)` は `jQuery.fn.ready` を通る）。
    /// **時間で遅らせない**（最初は 5 秒遅らせたが、通しの負荷で、入力して押すまでに 8.7 秒かかり、遅れの後に押したことがある）。
    /// **直す前は、押しても画面が移らない。**
    ///
    /// **測るのは通常のサインインのボタンだけ**である。ID 連携のボタンは上流の IdP が要るので、ここでは押さない
    /// （同じ形に直した。`Login.cshtml`）。
    /// </remarks>
    public class SignInBeforeReadyTests : TargetTestBase
    {
        /// <summary>押した後に、画面が移るのを待つ上限（秒）</summary>
        private const int WaitSeconds = 30;

        /// <summary>
        /// 文書の前に差し込むスクリプト。**jQuery の ready のハンドラを呼ばずに溜める**（`window.__heldReady`）。
        /// **`jQuery.fn.__heldReady` で、差し込みが効いたことを確かめる**（効いていなければ、測れていない）。
        /// </summary>
        private const string HoldReadyScript = @"
(() => {
  let jq;
  window.__heldReady = [];
  Object.defineProperty(window, 'jQuery', {
    configurable: true,
    get() { return jq; },
    set(v) {
      jq = v;
      if (v && v.fn && v.fn.ready && !v.fn.__heldReady) {
        v.fn.ready = function (fn) {
          window.__heldReady.push(fn);
          return this;
        };
        v.fn.__heldReady = true;
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
                + "**ready のハンドラを止めて**、押した瞬間にハンドラが付いていない状態を作る。",
                "#440");

            using (WebUi.Session session = await WebUi.OpenAsync())
            await using (IBrowserContext context = await session.NewContextAsync(target))
            {
                await context.AddInitScriptAsync(HoldReadyScript);

                IPage page = await context.NewPageAsync();

                r.Observe("使っているブラウザ", session.Channel);

                r.Target("GET /Account/Login → ボタン normal_signin（" + target.BaseUrl + "）");

                r.Step("(1) ready のハンドラを止めて、サインインの画面を開く");

                await WebUi.GotoAsync(page, target.Url("/Account/Login"));

                //  **前提は「jQuery の ready を止める差し込みが効いていること」**（溜まった数ではない）。
                //    **直した後の net48 版は、サインインの画面に ready のハンドラが 1 つも無い**ので、溜まる数は 0 になる
                //    （直す前は、Login.cshtml の 2 つが溜まった。net10.0 版は、ほかのスクリプトの分も溜まる）。
                bool hooked = await page.EvaluateAsync<bool>(
                    "() => !!(window.jQuery && window.jQuery.fn && window.jQuery.fn.__heldReady)");

                r.Verify("jQuery の ready を止める差し込みが効いている", hooked,
                    "効いている", hooked ? "効いている" : "**効いていない（測れていない）**");

                Assert.True(hooked, "前提: ready のハンドラを止める差し込みが効くこと");

                r.Observe("止めた ready のハンドラの数",
                    (await page.EvaluateAsync<int>("() => window.__heldReady.length")).ToString(),
                    "**直した後は、サインインのボタンは ready に頼らない**ので、0 でもよい");

                r.Step("(2) ready のハンドラが止まったまま、入力してボタンを押す");

                await page.FillAsync("#Email", TestEnv.TestUserName(targetKey));
                await page.FillAsync("#Password", target.Config.Get("TestUserPWD"));
                await page.ClickAsync("#normal_signin");

                //  **`WaitForURLAsync` を使わず、`page.Url` を見る**（`WebUi.SignInAsync` と同じ。#325）。
                //    **ready のハンドラは最後まで動かない**ので、待つ長さで結果は変わらない（上限は、遅い応答のため）。
                DateTime deadline = DateTime.UtcNow.AddSeconds(WaitSeconds);

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
