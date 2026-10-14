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
//* クラス名        ：ManageWebAuthnTests
//* クラス日本語名  ：RT-277 WebAuthn の資格情報の削除（#277 の段階 6）
//*
//* 作成日時        ：－
//* 作成者          ：－
//* 更新履歴        ：－
//*
//*  日時        更新者            内容
//*  ----------  ----------------  -------------------------------------------------
//*  2026/10/10  玄人 幸道         新規（#277 の段階 7）
//**********************************************************************************

using System.Collections.Generic;
using System.Linq;
using System.Net.Http;
using System.Text.RegularExpressions;
using System.Threading.Tasks;

using MultiPurposeAuthSite.Tests.E2E.Infrastructure;

using Xunit;
using Xunit.Abstractions;

/// <summary>MultiPurposeAuthSite.Tests.E2E.Tests.Issues</summary>
namespace MultiPurposeAuthSite.Tests.E2E.Tests.Issues
{
    /// <summary>
    /// RT-277 WebAuthn の資格情報の削除（`/Manage/RemoveWebAuthnData`）。
    /// </summary>
    /// <remarks>
    /// **#277 の段階 6 で直した不具合の回帰**である。
    ///
    /// | 直したもの | |
    /// |---|---|
    /// | 受け口 | **`string` で受けていた**ので、**同名のチェックボックスの先頭 1 つしか届かなかった**（`ValueProviderResult.FirstValue`）。`string[]` にした |
    /// | 画面 | **`class="form-control"` が付いていた。** Bootstrap 5 の `.form-control` は `appearance: none` を付けるので、**チェックの印が描かれない。** `form-check-input` にした |
    ///
    /// **このテストが測るのは、前者（届く値と、消える件数）だけ**である。
    /// **後者（描画）は HttpClient では測れない。** **ブラウザが要る。**
    ///
    /// **資格情報を作れるのは認証器だけ**なので、**種データで用意している**
    /// （`FIDO.TestCredentials`。`webauthn_tanaka` に 3 件。#277 の段階 7）。
    /// **消した分は、次のサインインで作り直される**ので、繰り返し流せる。
    ///
    /// **net10.0 版だけ**である（net48 版には WebAuthn の口が無い。#137）。
    /// </remarks>
    public class ManageWebAuthnTests : TargetTestBase
    {
        /// <summary>コンストラクタ</summary>
        /// <param name="output">ITestOutputHelper</param>
        public ManageWebAuthnTests(ITestOutputHelper output) : base(output) { }

        #region RT-277.3

        /// <summary>RT-277.3 選んだ資格情報だけが、選んだ数だけ消える</summary>
        /// <param name="targetKey">core / netfx</param>
        /// <returns>Task</returns>
        [SkippableTheory]
        [MemberData(nameof(AllTargets))]
        public async Task RT27703_選んだ資格情報だけが選んだ数だけ消える(string targetKey)
        {
            Skip.If(targetKey == "netfx",
                "net48 版には WebAuthn の口が無い（#137）。");

            using (IdPClient client = await this.SignedInClientAsync(
                targetKey, TestEnv.WebAuthnUserName(targetKey)))
            {
                TestReport r = this.Report("RT-277.3",
                    "WebAuthn の資格情報は、選んだものだけが、選んだ数だけ消える",
                    "**画面は同じ名前のチェックボックスを並べる**ので、"
                    + "**選んだ数だけ同名の値が送られる**（`publicKeys=A&publicKeys=B`）。"
                    + "**`string` で受けると先頭の 1 つしか届かない**"
                    + "（`ValueProviderResult.FirstValue`）ので、"
                    + "**複数選んでも 1 件しか消えなかった**（#277 の段階 6）。"
                    + "**`string[]` で受けるように直した。**",
                    "#277 / ManageController.RemoveWebAuthnData");

                r.Target("POST /Manage/RemoveWebAuthnData（publicKeys を 2 つ送る）");

                r.Step("(1) 一覧を開く（種データが 3 件入っている）");

                List<string> before = await ManageWebAuthnTests.ListAsync(client);

                r.Observe("登録されている資格情報", before.Count + " 件",
                    "**種データが用意したもの**（`FIDO.TestCredentials`）。"
                    + "**認証器が無いと作れない**ので、E2E では作れない。");

                r.Verify("2 件以上ある（前提）", 2 <= before.Count,
                    "2 件以上", before.Count + " 件");

                Assert.True(2 <= before.Count, "前提: 種データの資格情報が 2 件以上あること");

                r.Step("(2) 2 つ選んで削除する");

                List<string> removing = before.Take(2).ToList();

                List<string> after = await ManageWebAuthnTests.RemoveAsync(client, removing);

                r.Observe("削除した値", string.Join(" , ", removing));

                r.Verify("選んだ数だけ減る",
                    after.Count == before.Count - removing.Count,
                    (before.Count - removing.Count) + " 件", after.Count + " 件");

                r.Verify("選んだものが消えている",
                    !removing.Any(x => after.Contains(x)),
                    "どれも残っていない",
                    removing.Any(x => after.Contains(x))
                        ? "**残っている : "
                            + string.Join(" , ", removing.Where(x => after.Contains(x))) + "**"
                        : "どれも残っていない");

                r.Verify("選んでいないものは残っている",
                    before.Except(removing).All(x => after.Contains(x)),
                    "残っている",
                    before.Except(removing).All(x => after.Contains(x))
                        ? "残っている" : "**消えた**");

                r.Note("**直す前は、ここで 1 件しか減らなかった。** "
                    + "**2 つ送っても、先頭の 1 つしか届いていなかった**ためである。");

                r.Note("**描画は測っていない。** "
                    + "**段階 6 のもう一方の不具合**（`class=\"form-control\"` で"
                    + "**チェックの印が描かれない**）は、**ブラウザでなければ見えない。**");

                r.Done();
            }
        }

        #endregion

        #region 道具

        /// <summary>資格情報の一覧を返す（画面から読む）</summary>
        /// <param name="client">IdPClient</param>
        /// <returns>PublicKeyId の一覧</returns>
        /// <remarks>
        /// **一覧は POST でしか開かない**（`/Manage/RemoveWebAuthnData` は `[HttpPost]`）。
        /// **管理画面のボタンと同じ経路**を通る。
        /// </remarks>
        private static Task<List<string>> ListAsync(IdPClient client)
        {
            return ManageWebAuthnTests.RemoveAsync(client, new List<string>());
        }

        /// <summary>選んだ資格情報を消して、残りの一覧を返す</summary>
        /// <param name="client">IdPClient</param>
        /// <param name="publicKeys">消す PublicKeyId（空なら一覧を開くだけ）</param>
        /// <returns>残っている PublicKeyId の一覧</returns>
        private static async Task<List<string>> RemoveAsync(
            IdPClient client, List<string> publicKeys)
        {
            string index = await client.GetStringAsync("/Manage/Index");

            Match token = Regex.Match(index ?? "",
                "name=\"__RequestVerificationToken\"[^>]*value=\"(?<value>[^\"]+)\"");

            Assert.True(token.Success, "前提: 管理画面から __RequestVerificationToken が取れること");

            // **同じ名前を複数送る**ので、辞書ではなく組の並びで渡す。
            List<KeyValuePair<string, string>> form = new List<KeyValuePair<string, string>>()
            {
                new KeyValuePair<string, string>(
                    "__RequestVerificationToken", token.Groups["value"].Value)
            };

            foreach (string key in publicKeys)
            {
                form.Add(new KeyValuePair<string, string>("publicKeys", key));
            }

            HttpResponseMessage res = await client.PostFormAsync(
                "/Manage/RemoveWebAuthnData", form);

            string html = await res.Content.ReadAsStringAsync();

            List<string> list = new List<string>();

            foreach (Match m in Regex.Matches(html ?? "",
                "name=\"publicKeys\"[^>]*value=\"(?<value>[^\"]*)\""))
            {
                list.Add(m.Groups["value"].Value);
            }

            return list;
        }

        #endregion
    }
}
