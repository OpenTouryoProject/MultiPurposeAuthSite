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
//*  2026/11/03  玄人 幸道         RT-331.9（列の幅を超える値でトークンを引いても 500 にしない）を足した（#331）
//*  2026/11/03  玄人 幸道         RT-331.10（列の幅を超える値で画面から引いても 500 にしない）を足した（#331）
//**********************************************************************************

using System;
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

        /// <summary>RT-331.9 列の幅を超える値でトークンやコードを引いても、500 にしない</summary>
        /// <param name="targetKey">core / netfx</param>
        /// <returns>Task</returns>
        [SkippableTheory]
        [MemberData(nameof(AllTargets))]
        public async Task RT33109_列の幅を超える値でトークンを引いても500にしない(string targetKey)
        {
            using (IdPClient client = this.Client(targetKey))
            {
                TestReport r = this.Report("RT-331.9",
                    "DB の列の幅を超える値で、コード・トークン・クライアントを引いても 500 にしない",
                    "**`mem` には列の幅が無い。** DB では、幅を大きく超える値で引くと例外になることがある"
                    + "（Oracle は、利用者名で実際に起きた。`RT-331.3`）。"
                    + "**外から来た値で引く口は、「無い」と同じ結果になる**こと。",
                    "#331 / RFC 6749 §5.2 / RFC 7009 §2.2.1 / RFC 7662 §2.3");

                ClientRegistration reg = Flows.Registration(client, KnownClients.MvcSample);
                string longValue = new string('a', 5000);

                r.Target("/token・/revoke・/introspect・/authorize（値は 5000 文字）");

                List<KeyValuePair<string, Task<HttpResponseMessage>>> calls = new List<KeyValuePair<string, Task<HttpResponseMessage>>>()
                {
                    Post(client, "/token code", "/token", new Dictionary<string, string>()
                    {
                        { "grant_type", "authorization_code" }, { "code", longValue },
                        { "redirect_uri", reg.RedirectUri },
                        { "client_id", reg.ClientId }, { "client_secret", reg.ClientSecret }
                    }),
                    Post(client, "/token refresh_token", "/token", new Dictionary<string, string>()
                    {
                        { "grant_type", "refresh_token" }, { "refresh_token", longValue },
                        { "client_id", reg.ClientId }, { "client_secret", reg.ClientSecret }
                    }),
                    Post(client, "/token client_id", "/token", new Dictionary<string, string>()
                    {
                        { "grant_type", "client_credentials" },
                        { "client_id", longValue }, { "client_secret", "e2e-wrong-secret" }
                    }),
                    Post(client, "/token device_code", "/token", new Dictionary<string, string>()
                    {
                        { "grant_type", "urn:ietf:params:oauth:grant-type:device_code" }, { "device_code", longValue },
                        { "client_id", reg.ClientId }, { "client_secret", reg.ClientSecret }
                    }),
                    Post(client, "/token auth_req_id", "/token", new Dictionary<string, string>()
                    {
                        { "grant_type", "urn:openid:params:grant-type:ciba" }, { "auth_req_id", longValue },
                        { "client_id", reg.ClientId }, { "client_secret", reg.ClientSecret }
                    }),
                    Post(client, "/revoke token", "/revoke", new Dictionary<string, string>()
                    {
                        { "token", longValue },
                        { "client_id", reg.ClientId }, { "client_secret", reg.ClientSecret }
                    }),
                    Post(client, "/introspect token", "/introspect", new Dictionary<string, string>()
                    {
                        { "token", longValue },
                        { "client_id", reg.ClientId }, { "client_secret", reg.ClientSecret }
                    }),
                    new KeyValuePair<string, Task<HttpResponseMessage>>("/authorize request_uri",
                        client.GetAsync("/authorize?response_type=code&client_id=" + Uri.EscapeDataString(reg.ClientId)
                            + "&request_uri=" + Uri.EscapeDataString("urn:ietf:params:oauth:request_uri:" + longValue)))
                };

                //  **どの口が落ちたかを、まとめて出す**（1 つ目で止めると、残りが分からない）。
                List<string> statuses = new List<string>();
                List<string> errors = new List<string>();

                foreach (KeyValuePair<string, Task<HttpResponseMessage>> call in calls)
                {
                    HttpResponseMessage res = await call.Value;

                    statuses.Add(call.Key + "=" + (int)res.StatusCode);

                    if ((int)res.StatusCode >= 500)
                    {
                        errors.Add(call.Key);
                    }
                }

                r.Verify("**どの口も 500 にならない**（" + string.Join(", ", statuses) + "）",
                    errors.Count == 0,
                    "500 未満", (errors.Count == 0) ? "500 未満" : "**500**: " + string.Join(", ", errors));

                r.Done();
            }
        }

        /// <summary>RT-331.10 列の幅を超える値で、画面から同意・資格情報・管理の行を引いても 500 にしない</summary>
        /// <param name="targetKey">core / netfx</param>
        /// <returns>Task</returns>
        [SkippableTheory]
        [MemberData(nameof(AllTargets))]
        public async Task RT33110_列の幅を超える値で画面から引いても500にしない(string targetKey)
        {
            using (IdPClient client = await this.SignedInClientAsync(targetKey))
            using (IdPClient admin = this.Client(targetKey))
            {
                TestReport r = this.Report("RT-331.10",
                    "DB の列の幅を超える値で、画面から同意・資格情報・管理の行を引いても 500 にしない",
                    "**`RT-331.9` と同じ型を、サインインした利用者と管理者の画面で見る。**"
                    + "**外から来た値で引く口は、「無い」と同じ結果になる**こと。",
                    "#331");

                string longValue = new string('a', 5000);

                r.Target("/Manage/RevokeConsent・/Manage/RemoveWebAuthnData・/SoftwareStatementAdmin/Edit・/IdFederationAdmin/Edit（値は 5000 文字）");

                List<string> statuses = new List<string>();
                List<string> errors = new List<string>();

                string html = await (await client.GetAsync("/Manage/Index")).Content.ReadAsStringAsync();
                Match m = Regex.Match(html,
                    "name=\"__RequestVerificationToken\"[^>]*value=\"(?<value>[^\"]+)\"");

                Assert.True(m.Success, "前提: 管理画面を開けること");

                List<KeyValuePair<string, HttpResponseMessage>> calls = new List<KeyValuePair<string, HttpResponseMessage>>();

                calls.Add(new KeyValuePair<string, HttpResponseMessage>("RevokeConsent clientId",
                    await client.PostFormAsync("/Manage/RevokeConsent", new Dictionary<string, string>()
                    {
                        { "__RequestVerificationToken", m.Groups["value"].Value }, { "clientId", longValue }
                    })));

                //  **WebAuthn の削除の画面は net10.0 版だけに在る**（#137）。
                if (targetKey == TestEnv.CoreKey)
                {
                    calls.Add(new KeyValuePair<string, HttpResponseMessage>("RemoveWebAuthnData publicKeys",
                        await client.PostFormAsync("/Manage/RemoveWebAuthnData", new Dictionary<string, string>()
                        {
                            { "__RequestVerificationToken", m.Groups["value"].Value }, { "publicKeys", longValue }
                        })));
                }

                await admin.SignInAsAdministratorAsync();

                calls.Add(new KeyValuePair<string, HttpResponseMessage>("SoftwareStatementAdmin/Edit key",
                    await admin.GetAsync("/SoftwareStatementAdmin/Edit?key=" + longValue)));

                calls.Add(new KeyValuePair<string, HttpResponseMessage>("IdFederationAdmin/Edit key",
                    await admin.GetAsync("/IdFederationAdmin/Edit?key=" + longValue)));

                foreach (KeyValuePair<string, HttpResponseMessage> call in calls)
                {
                    statuses.Add(call.Key + "=" + (int)call.Value.StatusCode);

                    if ((int)call.Value.StatusCode >= 500)
                    {
                        errors.Add(call.Key);
                    }
                }

                r.Verify("**どの口も 500 にならない**（" + string.Join(", ", statuses) + "）",
                    errors.Count == 0,
                    "500 未満", (errors.Count == 0) ? "500 未満" : "**500**: " + string.Join(", ", errors));

                //  **net48 版は、例外をエラー画面への 302 にする**ので、状態コードだけでは見分けられない
                //    （修正前の `ora` で、取り消しは 302 のまま例外になっていた）。**取り消しは一覧へ戻ること**を見る。
                HttpResponseMessage revoked = calls[0].Value;
                string location = (revoked.Headers.Location == null) ? "" : revoked.Headers.Location.ToString();

                r.Verify("**同意の取り消しは、一覧の画面へ戻る**（エラー画面へ送らない）",
                    location.Contains("/Manage/ConsentGrants"),
                    "/Manage/ConsentGrants へ", string.IsNullOrEmpty(location)
                        ? "HTTP " + (int)revoked.StatusCode : location);

                r.Done();
            }
        }

        /// <summary>フォームを POST する（呼び出しを並べるため）</summary>
        /// <param name="client">IdPClient</param>
        /// <param name="label">名前</param>
        /// <param name="path">口</param>
        /// <param name="form">フォーム</param>
        /// <returns>名前と応答</returns>
        private static KeyValuePair<string, Task<HttpResponseMessage>> Post(
            IdPClient client, string label, string path, Dictionary<string, string> form)
        {
            return new KeyValuePair<string, Task<HttpResponseMessage>>(label, client.PostFormAsync(path, form));
        }
    }
}
