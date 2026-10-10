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
//* クラス名        ：RemoveWebAuthnRenderingTests
//* クラス日本語名  ：UI-1 チェックボックスが、入れたか外したか見て分かる
//*
//* 作成日時        ：－
//* 作成者          ：－
//* 更新履歴        ：－
//*
//*  日時        更新者            内容
//*  ----------  ----------------  -------------------------------------------------
//*  2026/10/10  玄人 幸道         新規（#277 の段階 7）
//**********************************************************************************

using System;
using System.Linq;
using System.Threading.Tasks;

using Microsoft.Playwright;

using MultiPurposeAuthSite.Tests.E2E.Infrastructure;

using Xunit;
using Xunit.Abstractions;

/// <summary>MultiPurposeAuthSite.Tests.E2E.Tests.WebUI</summary>
namespace MultiPurposeAuthSite.Tests.E2E.Tests.WebUI
{
    /// <summary>
    /// UI-1 WebAuthn の削除画面のチェックボックスが、**入れたか外したか見て分かる**。
    /// </summary>
    /// <remarks>
    /// **#277 の段階 6 で踏んだ不具合の回帰**である。
    ///
    /// **チェックボックスに `class="form-control"` が付いていた。**
    /// **Bootstrap 5 の `.form-control` は `appearance: none` を含む**ので、
    /// **チェックボックスに与えると、標準の描画が消える。**
    /// **入れても外しても同じ空の箱に見える**ため、
    /// **選んだつもりで選んでいなくても、画面からは分からなかった。**
    ///
    /// **この不具合は HttpClient では見えない。**
    /// **値は正しく往復していた**（選んだ分だけ送られ、選んだ分だけ消えていた）。
    /// **見えなかったのは「選べたかどうか」だけ**である。
    ///
    /// **だから、ここはブラウザで測る**（`Tests/WebUI`。`TESTING.md` 5 節）。
    ///
    /// **資格情報は種データが用意する**（`FIDO.TestCredentials`。`webauthn_tanaka` に 3 件）。
    /// **net10.0 版だけ**である（net48 版には WebAuthn の口が無い。#137）。
    /// </remarks>
    public class RemoveWebAuthnRenderingTests : TargetTestBase
    {
        /// <summary>コンストラクタ</summary>
        /// <param name="output">ITestOutputHelper</param>
        public RemoveWebAuthnRenderingTests(ITestOutputHelper output) : base(output) { }

        #region UI-1.1

        /// <summary>UI-1.1 チェックを入れたか外したかが、見て分かる</summary>
        /// <param name="targetKey">core / netfx</param>
        /// <returns>Task</returns>
        [SkippableTheory]
        [MemberData(nameof(CoreOnly))]
        public async Task UI0101_チェックの有無が見て分かる(string targetKey)
        {
            // **対象が起動していなければ Skip する**（Client が確かめ、種データも作らせる）。
            using (IdPClient probe = this.Client(targetKey)) { }

            TargetInfo target = TestEnv.Target(targetKey);

            TestReport r = this.Report("UI-1.1",
                "WebAuthn の削除画面で、チェックを入れたか外したかが見て分かる",
                "**`class=\"form-control\"` を付けると、Bootstrap 5 の `appearance: none` で"
                + "**標準の描画が消える**（#277 の段階 6 で踏んだ）。"
                + "**入れても外しても同じ空の箱**になり、**選べたかどうかが分からない。**"
                + "**値の往復は正しかった**ので、**HttpClient では見えない不具合**だった。",
                "#277 の段階 6 / Bootstrap 5 の .form-control");

            using (WebUi.Session session = await WebUi.OpenAsync())
            await using (IBrowserContext context = await session.NewContextAsync(target))
            {
                IPage page = await context.NewPageAsync();

                System.Collections.Generic.List<string> failures =
                    new System.Collections.Generic.List<string>();

                page.RequestFailed += (_, req) =>
                    failures.Add(req.Url + " : " + (req.Failure ?? "?"));

                r.Observe("使っているブラウザ", session.Channel);

                r.Target("GET /Manage/Index から「WebAuthn の削除」へ（" + target.BaseUrl + "）");

                r.Step("(1) サインインして、削除の画面を開く");

                try
                {
                    await WebUi.SignInAsync(page, target,
                        TestEnv.WebAuthnUserName(targetKey), target.Config.Get("TestUserPWD"));
                }
                catch (Exception e)
                {
                    r.Observe("通らなかった要求", string.Join(" / ", failures));
                    r.Verify("サインインの画面が開く", false, "開く",
                        "**" + e.Message.Replace('\n', ' ').Replace('\r', ' ') + "**");
                    throw;
                }

                await WebUi.GotoAsync(page, target.Url("/Manage/Index"));

                //  **一覧は POST でしか開かない**ので、管理画面のボタンを押す。
                await page.ClickAsync("form[action$='/Manage/RemoveWebAuthnData'] input[type=submit]");

                ILocator boxes = page.Locator("input[name='publicKeys']");
                int count = await boxes.CountAsync();

                r.Verify("チェックボックスが出ている", 0 < count,
                    "1 つ以上", count + " 個");

                Assert.True(0 < count, "前提: 種データの資格情報が出ていること");

                ILocator box = boxes.First;

                r.Step("(2) 入れる前と、入れた後を見比べる");

                byte[] before = await box.ScreenshotAsync();
                await box.CheckAsync();
                byte[] after = await box.ScreenshotAsync();

                bool visible = await box.IsVisibleAsync();

                r.Verify("チェックボックスが見えている", visible,
                    "見えている", visible ? "見えている" : "**見えていない**");

                //  **見た目が変わること**が、ここで測りたいことのすべてである。
                //    **原因を問わない**（appearance でも、大きさ 0 でも、色が同じでも落ちる）。
                bool changed = !before.SequenceEqual(after);

                r.Verify("入れた後の見た目が、入れる前と違う", changed,
                    "違う",
                    changed ? "違う（" + before.Length + " → " + after.Length + " バイト）"
                        : "**同じ（入れても外しても見分けが付かない）**");

                string appearance = await box.EvaluateAsync<string>(
                    "e => getComputedStyle(e).appearance");

                r.Observe("appearance", appearance,
                    "**`appearance: none` それ自体は不具合ではない。**"
                    + "**Bootstrap 5 の `.form-check-input` も `none` にしたうえで、"
                    + "印を自分で描いている**（**実測 : `none` のまま (2) は通る**）。"
                    + "**不具合だったのは `.form-control`** で、"
                    + "**標準の描画を消すだけで、代わりを描かなかった。**"
                    + "**だから「見た目が変わるか」を測る**（原因ではなく、結果を測る）。");

                r.Note("**選べること自体は HttpClient 側で測っている**（`RT-277.3`）。"
                    + "**ここで測るのは、選べたかどうかが画面から分かること**だけである。");

                r.Done();
            }
        }

        #endregion
    }
}
