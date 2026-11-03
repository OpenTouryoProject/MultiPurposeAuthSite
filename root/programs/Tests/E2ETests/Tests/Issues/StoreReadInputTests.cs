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
//* クラス名        ：StoreReadInputTests
//* クラス日本語名  ：RT-331 DB が受け付けない入力で利用者を引いても、500 にしない
//*
//* 作成日時        ：－
//* 作成者          ：－
//* 更新履歴        ：－
//*
//*  日時        更新者            内容
//*  ----------  ----------------  -------------------------------------------------
//*  2026/11/03  玄人 幸道         新規（#331）
//**********************************************************************************

using System.Collections.Generic;
using System.Net;
using System.Net.Http;
using System.Text.RegularExpressions;
using System.Threading.Tasks;

using MultiPurposeAuthSite.Tests.E2E.Infrastructure;
using MultiPurposeAuthSite.Tests.E2E.Tests.Extended;

using Xunit;
using Xunit.Abstractions;

namespace MultiPurposeAuthSite.Tests.E2E.Tests.Issues
{
    /// <summary>
    /// RT-331.3. **DB が受け付けない入力は、「居ない」と同じに扱う**（#331）。
    /// </summary>
    /// <remarks>
    /// **読み取りの失敗を握らなくなった**ので、外から来た値で DB が例外を投げると、
    /// **そのままでは 500 になる。** 例えば PostgreSQL は NUL 文字を受け付けない。
    /// </remarks>
    public class StoreReadInputTests : TargetTestBase
    {
        /// <summary>コンストラクタ</summary>
        /// <param name="output">ITestOutputHelper</param>
        public StoreReadInputTests(ITestOutputHelper output) : base(output)
        {
        }

        /// <summary>RT-331.3 DB が受け付けない利用者名でも、500 にしない</summary>
        /// <param name="targetKey">core / netfx</param>
        /// <returns>Task</returns>
        [SkippableTheory]
        [MemberData(nameof(AllTargets))]
        public async Task RT33103_DBが受け付けない利用者名でも500にしない(string targetKey)
        {
            using (IdPClient client = this.Client(targetKey))
            {
                TestReport r = this.Report("RT-331.3",
                    "DB が受け付けない利用者名でも、500 にしない",
                    "**NUL 文字を含む名前と、列の幅を大きく超える名前は、"
                    + "`/Account/Login` と `/token` で「居ない」と同じ結果になる**こと。",
                    "#331 / RFC 6749 §5.2");

                r.Target("POST /Account/Login、POST /token（grant_type=password）");

                ClientRegistration reg = Flows.Registration(client, KnownClients.MvcSample);

                string[] names = new string[]
                {
                    "e2e\0nul@example.com",
                    new string('a', 5000) + "@example.com"
                };

                string[] labels = new string[] { "NUL 文字", "5000 文字" };

                for (int i = 0; i < names.Length; i++)
                {
                    r.Step("(" + (i + 1) + ") " + labels[i] + " の利用者名");

                    HttpResponseMessage get = await client.GetAsync("/Account/Login");
                    string html = await get.Content.ReadAsStringAsync();

                    Match m = Regex.Match(html,
                        "name=\"__RequestVerificationToken\"[^>]*value=\"(?<value>[^\"]+)\"");

                    Assert.True(m.Success, "前提: サインイン画面を開けること");

                    HttpResponseMessage post = await client.PostFormAsync("/Account/Login",
                        new Dictionary<string, string>()
                        {
                            { "__RequestVerificationToken", m.Groups["value"].Value },
                            { "Email", names[i] },
                            { "Password", "e2e-no-such-password" },
                            { "RememberMe", "false" },
                            { "submitButtonName", "normal_signin" }
                        });

                    //  **net10.0 は、NUL 文字を含むフォームを読む前に 400 で断る**（ASP.NET Core のフォームの読み取り）。
                    r.Verify(labels[i] + "：サインインせず、画面を出し直すか、要求の誤りで返す",
                        post.StatusCode == HttpStatusCode.OK || post.StatusCode == HttpStatusCode.BadRequest,
                        "200 または 400", ((int)post.StatusCode).ToString());

                    JsonResponse token = await client.TokenAsync(new Dictionary<string, string>()
                    {
                        { "grant_type", "password" },
                        { "username", names[i] },
                        { "password", "e2e-no-such-password" },
                        { "scope", "email" },
                        { "client_id", reg.ClientId },
                        { "client_secret", reg.ClientSecret }
                    });

                    r.VerifyEqual(labels[i] + "：`/token` はトークンを出さず、要求の誤りで返す",
                        ((int)HttpStatusCode.BadRequest).ToString(), ((int)token.StatusCode).ToString());
                }

                r.Done();
            }
        }
    }
}
