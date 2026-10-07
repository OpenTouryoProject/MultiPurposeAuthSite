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
//* クラス名        ：ConsentScreenTests
//* クラス日本語名  ：RT-246 認可画面（同意）と、クライアント認証の方式の表示
//*
//* 作成日時        ：－
//* 作成者          ：－
//* 更新履歴        ：－
//*
//*  日時        更新者            内容
//*  ----------  ----------------  -------------------------------------------------
//*  2026/09/28  玄人 幸道         新規（#246 の項目 3）
//*  2026/10/06  玄人 幸道         RT-246.6を同意の記録の文面に合わせた（#272 の段階 2）
//**********************************************************************************

using System.Net.Http;
using System.Threading.Tasks;

using MultiPurposeAuthSite.Tests.E2E.Infrastructure;

using Xunit;
using Xunit.Abstractions;

namespace MultiPurposeAuthSite.Tests.E2E.Tests.Issues
{
    /// <summary>
    /// RT-246. 認可画面（同意）が「何を確かめる画面か」を出し、
    /// 結果画面が「トークン要求に使ったクライアント認証の方式」を出す。
    /// </summary>
    /// <remarks>
    /// **#246 の項目 3 の残り 2 つ。**
    ///
    /// | いままで | これから |
    /// |---|---|
    /// | 認可画面は押せるが、**何を確かめるのかが画面に書かれていない** | 要求のパラメタと、`prompt` / `max_age` の効き方を出す |
    /// | **どのクライアント認証で交換したのかが画面から分からない** | 結果画面に方式を出す |
    ///
    /// **`prompt` / `max_age` は、画面（starters）から選べるようにした**ので、
    /// **効き方を目視で確かめられる**（それまでは固定だった）。
    ///
    /// **自己テストのための表示は、`IsLockedDownTestEndpoints` が true の配置では出さない**
    /// （項目 4 の線引き。利用者に見せるものではない）。
    /// </remarks>
    public class ConsentScreenTests : TargetTestBase
    {
        /// <summary>コンストラクタ</summary>
        /// <param name="output">ITestOutputHelper</param>
        public ConsentScreenTests(ITestOutputHelper output) : base(output)
        {
        }

        /// <summary>RT-246.6 認可画面に、確かめる内容と prompt / max_age が出る</summary>
        /// <param name="targetKey">core / netfx</param>
        /// <returns>Task</returns>
        [SkippableTheory]
        [MemberData(nameof(AllTargets))]
        public async Task RT24606_認可画面に確かめる内容とpromptとmax_ageが出る(string targetKey)
        {
            using (IdPClient client = await this.SignedInClientAsync(targetKey))
            {
                TestReport r = this.Report("RT-246.6",
                    "認可画面（同意）が「何を確かめる画面か」を出し、結果画面がクライアント認証の方式を出す",
                    "**#246 の項目 3 の残り 2 つ。**"
                    + "認可画面は押せても**何を確かめるのかが書かれておらず**、"
                    + "**どのクライアント認証でトークンを交換したのかも画面から分からなかった。**"
                    + "`prompt` / `max_age` は固定だったので、**効き方を試せなかった。**"
                    + "**画面（Razor）は実行時コンパイル**なので、ビルドでは分からない。",
                    "OIDC Core §3.1.2.1（prompt / max_age）/ #246 の項目 3");

                r.Target("POST /Home/Saml2OAuth2Starters に submit.AuthorizationCode_OIDC"
                    + "（prompt=consent / max_age=60）");

                r.Step("(1) prompt と max_age を選んで、認可コード フロー（OIDC）を始める");

                HttpResponseMessage started = await client.StartSelfTestAsync(
                    "AuthorizationCode_OIDC", "normal", prompt: "consent", maxAge: "60");

                bool redirected = (started.Headers.Location != null);

                r.Verify("認可エンドポイントへ送られる", redirected,
                    "リダイレクトする", redirected ? "リダイレクトした" : "**しなかった**");

                Assert.True(redirected, "前提: 認可リクエストが組み立てられること");

                string authorizeUrl = client.ToLocalUrl(started.Headers.Location.ToString());

                r.Verify("要求に prompt が乗る", authorizeUrl.Contains("prompt=consent"),
                    "prompt=consent", authorizeUrl.Contains("prompt=consent") ? "乗っている" : "**乗っていない**");

                r.Verify("要求に max_age が乗る（選んだ値）", authorizeUrl.Contains("max_age=60"),
                    "max_age=60", authorizeUrl.Contains("max_age=60") ? "乗っている" : "**乗っていない**");

                r.Verify("max_age が二重にならない",
                    !authorizeUrl.Contains("max_age=600"),
                    "600 は付かない", authorizeUrl.Contains("max_age=600") ? "**付いている**" : "付いていない");

                r.Step("(2) 認可画面（同意）に、確かめる内容が出ていることを確かめる");

                HttpResponseMessage consent = await client.GetAsync(authorizeUrl);

                r.VerifyEqual("HTTP 200（認可画面）", "200", ((int)consent.StatusCode).ToString());

                // **net10.0 版の Razor は非 ASCII を数値文字参照で出す**ので、戻してから判定する。
                string html = System.Net.WebUtility.HtmlDecode(
                    await consent.Content.ReadAsStringAsync());

                r.Verify("「この画面で確かめること」が出る",
                    html.Contains("この画面で確かめること"),
                    "出る", html.Contains("この画面で確かめること") ? "出ている" : "**出ていない**");

                r.Verify("なぜこの画面が出たかが書かれている",
                    html.Contains("なぜこの画面が出たか"),
                    "書かれている", html.Contains("なぜこの画面が出たか") ? "書かれている" : "**書かれていない**");

                r.Verify("prompt の値が出る", html.Contains("consent"),
                    "consent", html.Contains("consent") ? "出ている" : "**出ていない**");

                r.Verify("max_age の値が出る", html.Contains("60"),
                    "60", html.Contains("60") ? "出ている" : "**出ていない**");

                // **「未対応」の記述は外した**（#272 の段階 2）。
                //   `login` / `consent` / `select_account` に対応したので、
                //   **画面には「記録が無いから出ている」ことを書いている。**
                r.Verify("同意を記録することが書かれている",
                    html.Contains("consent_required"),
                    "consent_required への言及",
                    html.Contains("consent_required") ? "書かれている" : "**書かれていない**");

                r.Verify("取り消しの場所が書かれている",
                    html.Contains("/Manage/ConsentGrants"),
                    "/Manage/ConsentGrants",
                    html.Contains("/Manage/ConsentGrants") ? "書かれている" : "**書かれていない**");

                r.Note("**以前は「prompt=consent は無視される」と書いていた**（同意を記録しなかったため、毎回この画面になっていた。C-3）。"
                    + "**#272 の段階 2 で記録するようになった**ので、"
                    + "**画面の文面も直した。解説を測るテストは、文面を変えると落ちる。**");

                r.Step("(3) 同意して、結果画面にクライアント認証の方式が出ることを確かめる");

                AuthZResponse authz = await client.AuthorizeAndGrantAsync(authorizeUrl);

                r.Verify("認可コードが返る", !string.IsNullOrEmpty(authz.Code),
                    "code あり",
                    string.IsNullOrEmpty(authz.Code) ? "**無し**（" + authz.ToString() + "）" : "あり");

                Assert.False(string.IsNullOrEmpty(authz.Code), "前提: 認可コードが返ること");

                HttpResponseMessage callback = await client.GetAsync(authz.Location);

                r.VerifyEqual("結果画面が開く（HTTP 200）", "200", ((int)callback.StatusCode).ToString());

                string result = System.Net.WebUtility.HtmlDecode(
                    await callback.Content.ReadAsStringAsync());

                bool notError = !result.Contains("エラーが発生しました");

                r.Verify("エラー画面ではない", notError,
                    "結果画面", notError ? "結果画面" : "**エラー画面**");

                r.Verify("クライアント認証の方式が出る",
                    result.Contains("クライアント認証（トークン要求）"),
                    "出る", result.Contains("クライアント認証（トークン要求）") ? "出ている" : "**出ていない**");

                r.Verify("この経路は client_secret_basic である",
                    result.Contains("client_secret_basic"),
                    "client_secret_basic",
                    result.Contains("client_secret_basic") ? "client_secret_basic" : "**違う**");

                r.Note("**PKCE の経路は `client_secret_post`**（Open棟梁 のクライアントの既定が違う）、"
                    + "**FAPI1 / FAPI2 は `private_key_jwt`** と出る。"
                    + "**どれを送ったのかが画面から分かるようになった**（#246 の項目 3）。");

                r.Done();
            }
        }
    }
}
