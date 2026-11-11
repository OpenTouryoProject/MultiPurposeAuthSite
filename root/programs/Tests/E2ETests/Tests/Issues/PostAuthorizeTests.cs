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
//* クラス名        ：PostAuthorizeTests
//* クラス日本語名  ：RT-359 POST の認可要求（OIDC Core 1.0 §3.1.2.1）
//*
//* 作成日時        ：－
//* 作成者          ：－
//* 更新履歴        ：－
//*
//*  日時        更新者            内容
//*  ----------  ----------------  -------------------------------------------------
//*  2026/11/11  玄人 幸道         新規（#359）
//**********************************************************************************

using System;
using System.Collections.Generic;
using System.Net;
using System.Net.Http;
using System.Threading.Tasks;

using MultiPurposeAuthSite.Tests.E2E.Infrastructure;

using Xunit;
using Xunit.Abstractions;

namespace MultiPurposeAuthSite.Tests.E2E.Tests.Issues
{
    /// <summary>
    /// RT-359 POST の認可要求（#359）。
    /// </summary>
    /// <remarks>
    /// **OIDC Core 1.0 §3.1.2.1 は、認可エンドポイントが GET と POST の両方を受けることを MUST としている。**
    /// **以前は `POST <認可の口>` が同意画面の送信の口で、RP からの POST の認可要求は、
    /// サインインの後にパラメタが落ちてエラー画面になった**（適合性テストの `oidcc-ensure-post-request-succeeds`）。
    ///
    /// **いまは、POST の認可要求をクエリに詰め替えて、GET の認可要求へ 303 で送り返す。**
    /// **同意画面の送信は `<認可の口>/consent` に移した。**
    /// </remarks>
    public class PostAuthorizeTests : TargetTestBase
    {
        /// <summary>コンストラクタ</summary>
        /// <param name="output">ITestOutputHelper</param>
        public PostAuthorizeTests(ITestOutputHelper output) : base(output)
        {
        }

        /// <summary>RT-359.1 未サインインの POST の認可要求は、サインインの後も元の要求で続く</summary>
        /// <param name="targetKey">core / netfx</param>
        /// <returns>Task</returns>
        [SkippableTheory]
        [MemberData(nameof(AllTargets))]
        public async Task RT35901_未サインインのPOSTの認可要求はサインインの後も続く(string targetKey)
        {
            using (IdPClient client = this.Client(targetKey))
            {
                ClientRegistration reg = Flows.Registration(client, KnownClients.MvcSample);

                TestReport r = this.Report("RT-359.1",
                    "未サインインで POST の認可要求を送ると、GET の認可要求へ送り返され、サインインの後も元の要求のパラメタで続く",
                    "**以前は、POST の口が同意画面の送信の口で、サインインの戻り先（ReturnUrl）にパラメタが残らず、"
                    + "サインインの後に `client_id not set` のエラー画面になった。**",
                    "OIDC Core 1.0 §3.1.2.1（認可エンドポイントは GET と POST を受ける）/ #359");

                r.Target("client_name=" + KnownClients.MvcSample + " / response_type=code / 未サインイン");

                r.Step("(1) POST /authorize（フォームの本文に client_id・redirect_uri・state など）");

                HttpResponseMessage post = await client.PostFormAsync("/authorize",
                    PostAuthorizeTests.CodeParameters(reg, "state-rt3591"));
                AuthZResponse redirected = await IdPClient.ToAuthZResponseAsync(post);

                r.VerifyEqual("**303 で送り返す**（次の要求を GET にする）", "303", ((int)post.StatusCode).ToString());

                r.Verify("**送り返す先は、GET の認可要求（同じパラメタ）**",
                    (redirected.RedirectTo ?? "").EndsWith("/authorize", StringComparison.Ordinal)
                        && redirected.Parameters.ContainsKey("client_id")
                        && redirected.Parameters["client_id"] == reg.ClientId
                        && redirected.Parameters.ContainsKey("state")
                        && redirected.Parameters["state"] == "state-rt3591",
                    "/authorize?client_id=…&state=state-rt3591", redirected.Location ?? "（Location 無し）");

                r.Step("(2) 送り返された GET の認可要求を開く（未サインインなので、サインイン画面へ）");

                HttpResponseMessage get = await client.GetAsync(redirected.Location);
                string login = (get.Headers.Location == null) ? "" : Uri.UnescapeDataString(get.Headers.Location.OriginalString);

                r.Verify("**サインイン画面の戻り先（ReturnUrl）に、元の要求のパラメタが残る**",
                    login.Contains("/Account/Login") && login.Contains("ReturnUrl")
                        && login.Contains(reg.ClientId) && login.Contains("state-rt3591"),
                    "ReturnUrl に client_id と state", string.IsNullOrEmpty(login) ? "HTTP " + (int)get.StatusCode : login.Split('?')[0]);

                r.Step("(3) サインインして、元の要求（送り返された GET）で続ける");

                await client.SignInAsync();
                AuthZResponse authz = await client.AuthorizeAndGrantAsync(redirected.Location);

                r.Verify("**認可コードが返る**", !string.IsNullOrEmpty(authz.Code),
                    "code あり", string.IsNullOrEmpty(authz.Code) ? "**無い**（" + authz.ToString() + "）" : "あり");

                r.VerifyEqual("state がそのまま返る", "state-rt3591", authz.State ?? "（無し）");

                r.Done();
            }
        }

        /// <summary>RT-359.2 サインイン済みの POST の認可要求は、認可コードまで進む</summary>
        /// <param name="targetKey">core / netfx</param>
        /// <returns>Task</returns>
        [SkippableTheory]
        [MemberData(nameof(AllTargets))]
        public async Task RT35902_サインイン済みのPOSTの認可要求は認可コードまで進む(string targetKey)
        {
            using (IdPClient client = await this.SignedInClientAsync(targetKey))
            {
                ClientRegistration reg = Flows.Registration(client, KnownClients.MvcSample);

                TestReport r = this.Report("RT-359.2",
                    "サインイン済みで POST の認可要求を送ると、GET と同じく認可コードまで進む",
                    "**以前は、POST の口が同意画面の送信の口で、偽造防止のトークンの無い要求として断られていた。**",
                    "OIDC Core 1.0 §3.1.2.1（認可エンドポイントは GET と POST を受ける）/ #359");

                r.Target("client_name=" + KnownClients.MvcSample + " / response_type=code / サインイン済み");

                r.Step("(1) POST /authorize（フォームの本文にパラメタ）");

                HttpResponseMessage post = await client.PostFormAsync("/authorize",
                    PostAuthorizeTests.CodeParameters(reg, "state-rt3592"));
                AuthZResponse redirected = await IdPClient.ToAuthZResponseAsync(post);

                r.VerifyEqual("**303 で送り返す**", "303", ((int)post.StatusCode).ToString());

                r.Step("(2) 送り返された GET の認可要求で続ける（同意画面が出たら許可する）");

                AuthZResponse authz = await client.AuthorizeAndGrantAsync(redirected.Location);

                r.Verify("**認可コードが返る**", !string.IsNullOrEmpty(authz.Code),
                    "code あり", string.IsNullOrEmpty(authz.Code) ? "**無い**（" + authz.ToString() + "）" : "あり");

                r.VerifyEqual("state がそのまま返る", "state-rt3592", authz.State ?? "（無し）");

                r.Done();
            }
        }

        /// <summary>RT-359.3 同じパラメタが 2 回来た POST の認可要求は、RP へ送らずエラー画面</summary>
        /// <param name="targetKey">core / netfx</param>
        /// <returns>Task</returns>
        [SkippableTheory]
        [MemberData(nameof(AllTargets))]
        public async Task RT35903_同じパラメタが2回来たPOSTの認可要求はエラー画面(string targetKey)
        {
            using (IdPClient client = await this.SignedInClientAsync(targetKey))
            {
                ClientRegistration reg = Flows.Registration(client, KnownClients.MvcSample);

                TestReport r = this.Report("RT-359.3",
                    "クエリとフォームの両方に同じパラメタ（state）がある POST の認可要求は、送り返さず、RP へも返さず、エラー画面になる",
                    "**どちらの値を使うかを決められない。** `redirect_uri` を確かめる前なので、RP へは返さない（オープン リダイレクトにしない）。",
                    "RFC 6749 §3.1（要求のパラメタを 2 回含めてはならない）/ #359");

                r.Target("client_name=" + KnownClients.MvcSample + " / state がクエリとフォームの両方");

                r.Step("(1) POST /authorize?state=…（フォームの本文にも state）");

                HttpResponseMessage post = await client.PostFormAsync("/authorize?state=state-rt3593-query",
                    PostAuthorizeTests.CodeParameters(reg, "state-rt3593-form"));
                AuthZResponse authz = await IdPClient.ToAuthZResponseAsync(post);

                r.Verify("**送り返さない・RP へ返さない**（Location が無い）",
                    string.IsNullOrEmpty(authz.Location),
                    "Location 無し", authz.Location ?? "無し");

                r.Verify("**エラー画面になる**", (authz.Body ?? "").Contains("text-danger"),
                    "エラー画面", Html.Describe(authz.Body));

                r.Done();
            }
        }

        /// <summary>RT-359.4 同意画面の「別のアカウント」は、認可の口へ戻す</summary>
        /// <param name="targetKey">core / netfx</param>
        /// <returns>Task</returns>
        [SkippableTheory]
        [MemberData(nameof(AllTargets))]
        public async Task RT35904_同意画面の別のアカウントは認可の口へ戻す(string targetKey)
        {
            using (IdPClient client = await this.SignedInClientAsync(targetKey))
            {
                ClientRegistration reg = Flows.InjectedRegistration(client, KnownClients.TestClient_19);

                TestReport r = this.Report("RT-359.4",
                    "同意画面で「別のアカウント」を押すと、サインアウトして、認可の口（同じ要求）へ戻る",
                    "**同意画面の送信の口を `<認可の口>/consent` に移したので、「同じ URL へ戻す」では、GET の無いその口へ戻って行き止まりになる。**"
                    + "戻る先は認可の口でなければならない。",
                    "#359（同意画面の送信の口を移した後の戻り先）");

                r.Target("client_name=" + KnownClients.TestClient_19 + "（同意画面が出る）");

                r.Step("(1) 同意画面を出す");

                AuthZResponse screen = await client.AuthorizeAsync(
                    PostAuthorizeTests.CodeParameters(reg, "state-rt3594"));

                Assert.True(screen.NeedsConsent, "前提: 同意画面が出ること（" + screen.ToString() + "）");

                r.Verify("**同意画面の送信先は、同意画面の送信の口**（`<認可の口>/consent`）",
                    IdPClient.ConsentFormUrl(screen).Contains("/authorize/consent?"),
                    "/authorize/consent?…", IdPClient.ConsentFormUrl(screen).Split('?')[0]);

                r.Step("(2) 「別のアカウント」（submit.Login）を押す");

                HttpResponseMessage post = await client.PostFormAsync(IdPClient.ConsentFormUrl(screen), new Dictionary<string, string>()
                {
                    { "__RequestVerificationToken", Html.Antiforgery(screen.Body) },
                    { "submit.Login", "Login" }
                });

                //  **ブラウザ経由で伝える先（Front-Channel Logout）が在れば、画面を挟む**（その画面の中に、進む先が書かれる）。
                string next = (post.Headers.Location == null)
                    ? await post.Content.ReadAsStringAsync()
                    : post.Headers.Location.OriginalString;

                r.Verify("**戻る先は、認可の口（同じ要求）**（`/consent` ではない）",
                    next != null && next.Contains("/authorize?") && !next.Contains("/authorize/consent") && next.Contains("state-rt3594"),
                    "/authorize?…state=state-rt3594", next == null ? "（無し）" : next.Split('?')[0]);

                r.Done();
            }
        }

        #region 補助

        /// <summary>code フローの要求</summary>
        /// <param name="reg">クライアント</param>
        /// <param name="state">state</param>
        /// <returns>パラメタ</returns>
        private static Dictionary<string, string> CodeParameters(ClientRegistration reg, string state)
        {
            return new Dictionary<string, string>()
            {
                { "client_id", reg.ClientId },
                { "response_type", "code" },
                { "redirect_uri", reg.RedirectUri },
                { "scope", "openid email" },
                { "state", state },
                { "nonce", "nonce-rt359" }
            };
        }

        #endregion
    }
}
