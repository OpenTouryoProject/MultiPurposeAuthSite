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
//* クラス名        ：JwkSetCacheTests
//* クラス日本語名  ：RT-303 /jwkcerts のキャッシュ（ETag / Cache-Control / 304）
//*
//* 作成日時        ：－
//* 作成者          ：－
//* 更新履歴        ：－
//*
//*  日時        更新者            内容
//*  ----------  ----------------  -------------------------------------------------
//*  2026/10/16  玄人 幸道         新規（#303。E-7）
//**********************************************************************************

using System;
using System.Collections.Generic;
using System.IO;
using System.Net;
using System.Net.Http;
using System.Threading.Tasks;

using MultiPurposeAuthSite.Tests.E2E.Infrastructure;

using Xunit;
using Xunit.Abstractions;

namespace MultiPurposeAuthSite.Tests.E2E.Tests.Issues
{
    /// <summary>
    /// RT-303. **`/jwkcerts` のキャッシュ**（#303。E-7）。
    /// </summary>
    /// <remarks>
    /// **この口は、トークンを検証する相手が必ず読む。**
    /// **内容は鍵を入れ替えるまで変わらない**のに、**要求ごとにファイルを開いて読んでいた。**
    ///
    /// | 見るもの | |
    /// |---|---|
    /// | `ETag` | **中身から作る**（同じ中身なら同じ値） |
    /// | `Cache-Control` | **`JwkSetCacheMaxAgeSeconds` が正なら `public, max-age=`**、0 なら `no-store` |
    /// | `304` | **`If-None-Match` が一致すれば、本文を送らない** |
    /// | **鍵の入れ替えに追随する** | **ファイルが変われば、次の要求で新しい中身が返る**（ここが一番大事） |
    ///
    /// **既定の通しは「キャッシュ有効」で回る**（`test.ps1` が `JwkSetCacheMaxAgeSeconds=300` を渡す）。
    /// **設定が 0 の配備でも通るように、`Cache-Control` の期待値は設定から決める。**
    /// </remarks>
    public class JwkSetCacheTests : TargetTestBase
    {
        /// <summary>コンストラクタ</summary>
        /// <param name="output">ITestOutputHelper</param>
        public JwkSetCacheTests(ITestOutputHelper output) : base(output)
        {
        }

        #region RT-303.1

        /// <summary>RT-303.1 /jwkcerts が ETag と Cache-Control を返し、304 を使える</summary>
        /// <param name="targetKey">core / netfx</param>
        /// <returns>Task</returns>
        [SkippableTheory]
        [MemberData(nameof(AllTargets))]
        public async Task RT30301_jwkcertsがETagとCacheControlを返す(string targetKey)
        {
            using (IdPClient client = this.Client(targetKey))
            {
                TestReport r = this.Report("RT-303.1",
                    "`/jwkcerts` が `ETag` と `Cache-Control` を返し、`304` を使える",
                    "**この口は、トークンを検証する相手が必ず読む。**"
                    + "**内容は鍵を入れ替えるまで変わらない**のに、"
                    + "**要求ごとにファイルを開いて読み、キャッシュの指示も付けていなかった**"
                    + "（`ANALYSIS-IdP.md` の E-7）。"
                    + "**持ち回らせることで、読む側の往復と、こちらのファイル読み出しを減らす。**",
                    "RFC 9110 §8.8.3（ETag）/ §13.1.2（If-None-Match）/ #303");

                r.Target("GET /jwkcerts");

                r.Step("(1) 1 回目の取得");

                HttpResponseMessage first = await client.GetAsync("/jwkcerts");
                string body = await first.Content.ReadAsStringAsync();

                r.Verify("HTTP 200", first.StatusCode == HttpStatusCode.OK,
                    "200", ((int)first.StatusCode).ToString());

                string etag = (first.Headers.ETag == null) ? null : first.Headers.ETag.ToString();

                r.Verify("`ETag` が付く", !string.IsNullOrEmpty(etag),
                    "付く", string.IsNullOrEmpty(etag) ? "**付かない**" : etag);

                string cacheControl = (first.Headers.CacheControl == null)
                    ? "" : first.Headers.CacheControl.ToString();

                //  **期待値は設定から決める**（`test.ps1` は 300 を渡す。既定の配備は 0）。
                int maxAge = JwkSetCacheTests.MaxAgeOf(client);

                if (0 < maxAge)
                {
                    bool ok = cacheControl.Contains("public")
                        && cacheControl.Contains("max-age=" + maxAge.ToString());

                    r.Verify("`Cache-Control` が `public, max-age=" + maxAge + "`", ok,
                        "public, max-age=" + maxAge, string.IsNullOrEmpty(cacheControl)
                            ? "**付かない**" : cacheControl);
                }
                else
                {
                    r.Verify("`Cache-Control` が `no-store`（キャッシュ無効の設定）",
                        cacheControl.Contains("no-store"),
                        "no-store", string.IsNullOrEmpty(cacheControl)
                            ? "**付かない**" : cacheControl);
                }

                r.Verify("本文が JWK Set である（`keys` が在る）",
                    0 <= (body ?? "").IndexOf("\"keys\""),
                    "keys あり", (0 <= (body ?? "").IndexOf("\"keys\"")) ? "あり" : "**無し**");

                r.Step("(2) 2 回目の取得（中身と `ETag` が変わらない）");

                HttpResponseMessage second = await client.GetAsync("/jwkcerts");
                string body2 = await second.Content.ReadAsStringAsync();
                string etag2 = (second.Headers.ETag == null) ? null : second.Headers.ETag.ToString();

                r.Verify("`ETag` が同じ", etag2 == etag, "同じ", (etag2 == etag) ? "同じ" : "**違う**");
                r.Verify("本文が同じ", body2 == body, "同じ", (body2 == body) ? "同じ" : "**違う**");

                r.Step("(3) `If-None-Match` を付けると `304`（本文なし）");

                HttpResponseMessage notModified = await client.GetAsync(
                    "/jwkcerts",
                    new Dictionary<string, string>() { { "If-None-Match", etag } });

                r.Verify("HTTP 304", notModified.StatusCode == HttpStatusCode.NotModified,
                    "304", ((int)notModified.StatusCode).ToString());

                string empty = await notModified.Content.ReadAsStringAsync();

                r.Verify("本文を送らない", string.IsNullOrEmpty(empty),
                    "空", string.IsNullOrEmpty(empty) ? "空" : "**本文が在る**");

                r.Note("**覚えているかどうかは、応答からは見えない。**"
                    + "**見えるのは `ETag` と `Cache-Control`、そして 304 である。**"
                    + "**ファイルの読み出しを減らしたことは、(4) の「追随する」側から裏を取る** — "
                    + "**覚えていなければ追随は自明で、覚えているからこそ測る価値がある。**");

                r.Done();
            }
        }

        #endregion

        #region RT-303.2

        /// <summary>RT-303.2 鍵の入れ替えに追随する（ファイルが変われば読み直す）</summary>
        /// <param name="targetKey">core / netfx</param>
        /// <returns>Task</returns>
        /// <remarks>
        /// **覚えたまま返し続けると、鍵を入れ替えても古い鍵を配る。**
        /// **出す側は新旧 2 本を広告する**作りにしてある（#291 / #292 の段階 3）が、
        /// **それも「読み直す」ことが前提**である。
        ///
        /// **`JwkSet.json` に空白を 1 つ足して戻す**（**中身の意味は変えない**）。
        /// **鍵は変わらない**ので、**並行して走る他のテストのトークン検証を壊さない。**
        /// </remarks>
        [SkippableTheory]
        [MemberData(nameof(AllTargets))]
        public async Task RT30302_鍵の入れ替えに追随する(string targetKey)
        {
            using (IdPClient client = this.Client(targetKey))
            {
                string path = client.Config.Get("JwkSetFilePath");

                Skip.If(string.IsNullOrEmpty(path) || !File.Exists(path),
                    "JwkSetFilePath（" + (path ?? "未設定") + "）が読めません。"
                    + "構成ファイルの絶対パスに JwkSet.json が在る配備でだけ測れます。");

                TestReport r = this.Report("RT-303.2",
                    "`JwkSet.json` が変われば、`/jwkcerts` は読み直す（鍵の入れ替えに追随する）",
                    "**覚えたまま返し続けると、鍵を入れ替えても古い鍵を配る。**"
                    + "**出す側が新旧 2 本を広告する**作り（#291 / #292 の段階 3）**も、"
                    + "読み直すことが前提**である。"
                    + "**ファイルの最終更新時刻と長さで、変わったかどうかだけを見る**（#303）。",
                    "#303 / E-7 / #292 の段階 3");

                r.Target("GET /jwkcerts（JwkSet.json を触って戻す）");

                string original = File.ReadAllText(path);

                try
                {
                    r.Step("(1) 触る前の `ETag`");

                    HttpResponseMessage before = await client.GetAsync("/jwkcerts");
                    string etagBefore = (before.Headers.ETag == null)
                        ? null : before.Headers.ETag.ToString();

                    r.Verify("`ETag` が取れる", !string.IsNullOrEmpty(etagBefore),
                        "取れる", string.IsNullOrEmpty(etagBefore) ? "**取れない**" : etagBefore);

                    r.Step("(2) `JwkSet.json` の末尾に空白を 1 つ足す（鍵は変えない）");

                    File.WriteAllText(path, original + " ");

                    HttpResponseMessage after = await client.GetAsync("/jwkcerts");
                    string etagAfter = (after.Headers.ETag == null)
                        ? null : after.Headers.ETag.ToString();
                    string bodyAfter = await after.Content.ReadAsStringAsync();

                    r.Verify("`ETag` が変わる（読み直した）", etagAfter != etagBefore,
                        "変わる", (etagAfter != etagBefore) ? "変わった" : "**変わらない（覚えたまま）**");

                    r.Verify("本文も新しい（末尾が変わっている）",
                        (bodyAfter ?? "").EndsWith(" "),
                        "新しい", (bodyAfter ?? "").EndsWith(" ") ? "新しい" : "**古いまま**");

                    r.Step("(3) 戻すと、`ETag` も元に戻る（中身から作っているため）");

                    File.WriteAllText(path, original);

                    HttpResponseMessage restored = await client.GetAsync("/jwkcerts");
                    string etagRestored = (restored.Headers.ETag == null)
                        ? null : restored.Headers.ETag.ToString();

                    r.Verify("`ETag` が 1 回目と同じ", etagRestored == etagBefore,
                        etagBefore, etagRestored);
                }
                finally
                {
                    //  **必ず戻す**（落ちた回でも、鍵の配布を壊さない）。
                    File.WriteAllText(path, original);
                }

                r.Done();
            }
        }

        #endregion

        #region 補助

        /// <summary>この配備の `JwkSetCacheMaxAgeSeconds`（未設定なら 0）</summary>
        /// <param name="client">IdPClient</param>
        /// <returns>秒数</returns>
        /// <remarks>
        /// **環境変数が構成ファイルより強い**（`FxContainerization`。`CONFIGURATION.md` 2 節）。
        /// **`test.ps1` は環境変数で渡す**ので、**そちらを先に見る** —
        /// **構成ファイルだけを見ると、通しの実際の設定と食い違う**（実測で踏んだ）。
        /// </remarks>
        private static int MaxAgeOf(IdPClient client)
        {
            string value = Environment.GetEnvironmentVariable("JwkSetCacheMaxAgeSeconds");

            if (string.IsNullOrEmpty(value))
            {
                value = client.Config.Get("JwkSetCacheMaxAgeSeconds");
            }

            int seconds = 0;
            return int.TryParse(value ?? "", out seconds) ? seconds : 0;
        }

        #endregion
    }
}
