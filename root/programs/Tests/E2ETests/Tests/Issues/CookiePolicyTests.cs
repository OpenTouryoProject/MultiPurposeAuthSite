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
//* クラス名        ：CookiePolicyTests
//* クラス日本語名  ：RT-279 Cookie ポリシーが効いていること
//*
//* 作成日時        ：－
//* 作成者          ：－
//* 更新履歴        ：－
//*
//*  日時        更新者            内容
//*  ----------  ----------------  -------------------------------------------------
//*  2026/10/07  玄人 幸道         新規（#279）
//**********************************************************************************

using System.Collections.Generic;
using System.Linq;
using System.Net.Http;
using System.Threading.Tasks;

using MultiPurposeAuthSite.Tests.E2E.Infrastructure;

using Xunit;
using Xunit.Abstractions;

namespace MultiPurposeAuthSite.Tests.E2E.Tests.Issues
{
    /// <summary>
    /// RT-279. Cookie ポリシー（`CookiePolicyOptions`）が効いている。
    /// </summary>
    /// <remarks>
    /// **#279 で、`app.UseCookiePolicy()` から引数を外し、DI 側に一本化した。**
    ///
    /// | | |
    /// |---|---|
    /// | 以前 | `Configure` 側で `app.UseCookiePolicy(new CookiePolicyOptions(){…})`。**DI 側（`services.Configure<CookiePolicyOptions>`）は効いていなかった** |
    /// | これから | **`app.UseCookiePolicy()`（引数なし）。** 設定は DI 側に一本化 |
    ///
    /// **引数を渡す overload は、DI の設定を読まない。**
    /// **一本化し損なうと、`MinimumSameSitePolicy` の明示が失われる。**
    ///
    /// **実測**（`options.MinimumSameSitePolicy = SameSiteMode.None;` を外して測った）。
    ///
    /// | | `test_state` の Set-Cookie |
    /// |---|---|
    /// | 明示あり（いま） | **`samesite=none`** |
    /// | 明示なし | **`samesite` 属性ごと消える** |
    ///
    /// **「`Lax` に格上げされる」ではなく「属性が出なくなる」**のが、測った結果である。
    /// **属性が無ければブラウザ側の既定（Chrome は `Lax`）が適用される**ので、
    /// **結果として `None` ではなくなる。**
    ///
    /// **この実装は `None` を明示している**（`aspnet/Security#1822`）。
    /// **ID 連携の外部ログインや `response_mode=form_post` の戻りで、Cookie が送られなくなる**ため。
    ///
    /// **ブラウザを使わないと気付けない類の退行**なので、ここで固定する。
    /// **E2E は Cookie の属性をどこも見ていなかった。**
    ///
    /// **net10.0 版だけの話である**（net48 版は `Web.config` の `<httpCookies>`）。
    /// </remarks>
    public class CookiePolicyTests : TargetTestBase
    {
        /// <summary>コンストラクタ</summary>
        /// <param name="output">ITestOutputHelper</param>
        public CookiePolicyTests(ITestOutputHelper output) : base(output)
        {
        }

        /// <summary>RT-279.1 SameSite=None を宣言した Cookie が、格上げされない</summary>
        /// <param name="targetKey">core</param>
        /// <returns>Task</returns>
        [SkippableTheory]
        [MemberData(nameof(CoreOnly))]
        public async Task RT27901_SameSiteがNoneのCookieが格上げされない(string targetKey)
        {
            using (IdPClient client = await this.SignedInClientAsync(targetKey))
            {
                TestReport r = this.Report("RT-279.1",
                    "SameSite=None を宣言した Cookie が、Cookie ポリシーで格上げされない",
                    "**`app.UseCookiePolicy()` の引数を外し、DI 側に一本化した**（#279）。"
                    + "**引数を渡す overload は DI の設定を読まない**ので、"
                    + "**一本化し損なうと `MinimumSameSitePolicy` の明示が失われ、"
                    + "`samesite` 属性ごと出なくなる**（実測）。"
                    + "**属性が無ければブラウザ側の既定（Chrome は `Lax`）が適用される**ので、"
                    + "**ID 連携の外部ログインや `response_mode=form_post` の戻りで、"
                    + "Cookie が送られなくなる。**"
                    + "**ブラウザを使わないと気付けない**ので、ここで固定する。",
                    "#279（上流 Open棟梁 #541）");

                r.Target("POST /Home/Saml2OAuth2Starters（自己テストのパラメタ Cookie を出させる）");

                r.Step("(1) 自己テストのボタンを押して、Set-Cookie を受け取る");

                // **自己テストのパラメタ Cookie は SameSite=None を宣言している**
                //   （`HomeController` の `_cookieOptions`）。**格上げの有無がここで見える。**
                HttpResponseMessage res = await client.StartSelfTestAsync(
                    "Saml2RedirectRedirectBinding", "normal");

                IEnumerable<string> setCookies;

                if (!res.Headers.TryGetValues("Set-Cookie", out setCookies))
                {
                    setCookies = new string[0];
                }

                List<string> cookies = setCookies.ToList();

                r.Verify("Set-Cookie が返る", 0 < cookies.Count,
                    "1 件以上", cookies.Count + " 件");

                Assert.True(0 < cookies.Count, "前提: Set-Cookie が返ること");

                r.Step("(2) test_state の Cookie が SameSite=None のままである");

                // **値は出さない**（state はこの経路の照合に使う値）。属性だけを見る。
                string target = cookies.FirstOrDefault(
                    c => c.StartsWith("test_state=", System.StringComparison.OrdinalIgnoreCase));

                r.Verify("test_state の Set-Cookie がある", target != null,
                    "ある", (target != null) ? "ある" : "**無い**");

                Assert.NotNull(target);

                string attributes = target.Substring(target.IndexOf(';') + 1).ToLower();

                r.Verify("samesite=none である", attributes.Contains("samesite=none"),
                    "samesite=none",
                    attributes.Contains("samesite=lax")
                        ? "**samesite=lax**（格上げされている＝ DI の設定が効いていない）"
                        : (attributes.Contains("samesite=none")
                            ? "samesite=none" : "**samesite が無い**"));

                r.Step("(3) HttpOnly も効いている");

                r.Verify("httponly が付く", attributes.Contains("httponly"),
                    "httponly", attributes.Contains("httponly") ? "付く" : "**付かない**");

                r.Note("**`CookieSecurePolicy` は既定（空）のままなので、"
                    + "`Secure` 属性は各 Cookie の宣言に従う。**"
                    + "`always` にすると全部に付くが、**平文 HTTP では"
                    + "サインインできなくなる**ので既定では変えない（#279）。");

                r.Done();
            }
        }
    }
}
