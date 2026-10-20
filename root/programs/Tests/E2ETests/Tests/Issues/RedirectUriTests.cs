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
//* クラス名        ：RedirectUriTests
//* クラス日本語名  ：RT-306 クライアントあたり複数 redirect_uri
//*
//* 作成日時        ：－
//* 作成者          ：－
//* 更新履歴        ：－
//*
//*  日時        更新者            内容
//*  ----------  ----------------  -------------------------------------------------
//*  2026/10/17  玄人 幸道         新規（#306）
//*  2026/10/20  玄人 幸道         コメントを1利用者nクライアントに合わせた（#307の段階5-a-1）
//**********************************************************************************

using System;
using System.Collections.Generic;
using System.Net;
using System.Threading.Tasks;

using MultiPurposeAuthSite.Tests.E2E.Infrastructure;

using Xunit;
using Xunit.Abstractions;

namespace MultiPurposeAuthSite.Tests.E2E.Tests.Issues
{
    /// <summary>
    /// RT-306. **クライアントあたり複数 `redirect_uri`**（#306）。
    /// </summary>
    /// <remarks>
    /// **以前は `redirect_uri_code` / `redirect_uri_token` が 1 本ずつ**だった。
    /// **開発と本番を 1 つの `client_id` で共存させられず**、
    /// **複数のプラットフォーム**（Web とモバイルのカスタム スキーム）**も扱えなかった。**
    ///
    /// **登録は空白区切りの 1 つの文字列**（設定ファイルでも DB の列でも同じ形）。
    ///
    /// | | 測ること |
    /// |---|---|
    /// | **`RT-306.1`** | **2 件登録して、どちらの `redirect_uri` でも認可コードが取れる** |
    /// | **`RT-306.2`** | **登録に無い `redirect_uri` は `invalid_request`** |
    /// | **`RT-306.3`** | **2 件登録のとき、`redirect_uri` の省略は `invalid_request`** |
    ///
    /// **「1 件登録なら省略できる」（下位互換）は、この一式では測らない** —
    /// **既存のケースの大半が、まさにその経路で回っている**
    /// （`Flows.AuthorizeCodeAsync` は `redirect_uri` を既定で送らない）。
    ///
    /// **使い捨ての利用者で測る。** **当時はクライアント登録が 1 人 1 件**で、
    /// **共用の利用者で登録すると、`RT-277.1` や `RT-305.4` と登録を奪い合った**
    /// （#305 の段階 2 で踏んだ。`TESTING.md`）。
    ///
    /// **#307 の段階 5-a-1 で 1 人 n 件になったが、使い捨てのままにしている** —
    /// **管理画面が扱うのは、その利用者の 1 件**だからである。
    /// </remarks>
    public class RedirectUriTests : TargetTestBase
    {
        /// <summary>コンストラクタ</summary>
        /// <param name="output">ITestOutputHelper</param>
        public RedirectUriTests(ITestOutputHelper output) : base(output)
        {
        }

        /// <summary>1 本目の折り返し先</summary>
        private const string UriA = "https://localhost:44300/e2e/rt306/a";

        /// <summary>2 本目の折り返し先</summary>
        private const string UriB = "https://localhost:44300/e2e/rt306/b";

        /// <summary>登録に無い折り返し先</summary>
        private const string UriUnregistered = "https://localhost:44300/e2e/rt306/c";

        #region RT-306.1

        /// <summary>RT-306.1 2 件登録すると、どちらでも認可コードが取れる</summary>
        /// <param name="targetKey">core / netfx</param>
        /// <returns>Task</returns>
        [SkippableTheory]
        [MemberData(nameof(AllTargets))]
        public async Task RT30601_2件登録するとどちらでも認可コードが取れる(string targetKey)
        {
            using (IdPClient admin = this.Client(targetKey))
            {
                TestReport r = this.Report("RT-306.1",
                    "`redirect_uri` を 2 件登録すると、どちらを指定しても認可コードが取れる",
                    "**以前は 1 本しか登録できなかった**（`ANALYSIS-IdP.md` の D-8）。"
                    + "**開発と本番を 1 つの `client_id` で共存させられず**、"
                    + "**Web とモバイルのような複数のプラットフォームも扱えなかった。**"
                    + "**登録は空白区切りの列挙**で、**要求の値は、そのいずれかと完全一致すればよい。**",
                    "RFC 6749 §3.1.2.2 / OIDC Core §3.1.2.1 / #306");

                r.Target("GET /authorize（使い捨ての利用者のクライアント登録。2 件登録）");

                await this.WithRegisteredClientAsync(admin, targetKey,
                    UriA + " " + UriB, async (client, reg) =>
                    {
                        r.Step("(1) 1 本目（" + UriA + "）で認可コードが取れる");

                        AuthZResponse a = await Flows.AuthorizeCodeAsync(
                            client, reg, "openid email", "state-a", "nonce-a", UriA);

                        r.Verify("1 本目で code が返る", !string.IsNullOrEmpty(a.Code),
                            "返る", string.IsNullOrEmpty(a.Code)
                                ? "**返らない（error=" + (a.Error ?? "なし") + "）**" : "返った");

                        r.VerifyEqual("折り返し先は 1 本目", "1",
                            ((a.Location ?? "").StartsWith(UriA) ? "1" : "0"));

                        r.Step("(2) 2 本目（" + UriB + "）でも認可コードが取れる");

                        AuthZResponse b = await Flows.AuthorizeCodeAsync(
                            client, reg, "openid email", "state-b", "nonce-b", UriB);

                        r.Verify("2 本目でも code が返る", !string.IsNullOrEmpty(b.Code),
                            "返る", string.IsNullOrEmpty(b.Code)
                                ? "**返らない（error=" + (b.Error ?? "なし") + "）**" : "返った");

                        r.VerifyEqual("折り返し先は 2 本目", "1",
                            ((b.Location ?? "").StartsWith(UriB) ? "1" : "0"));

                        r.Note("**区切りは空白である。** "
                            + "**URI に空白は入らない**（RFC 3986 §2）ので曖昧にならない。 "
                            + "**カンマは区切りにしていない** — "
                            + "**`sub-delims` に含まれるので URI に入り得る**（RFC 3986 §2.2）。");
                    });

                r.Done();
            }
        }

        #endregion

        #region RT-306.2

        /// <summary>RT-306.2 登録に無い redirect_uri は断られる</summary>
        /// <param name="targetKey">core / netfx</param>
        /// <returns>Task</returns>
        [SkippableTheory]
        [MemberData(nameof(AllTargets))]
        public async Task RT30602_登録に無いredirect_uriは断られる(string targetKey)
        {
            using (IdPClient admin = this.Client(targetKey))
            {
                TestReport r = this.Report("RT-306.2",
                    "登録に無い `redirect_uri` は `invalid_request` になる",
                    "**n 件になっても、照合は完全一致のままである。**"
                    + "**前方一致にはしていない** — "
                    + "**#263 で `StartsWith` をやめ、`ToLower()` 同士の比較もやめた**（C-10）。"
                    + "**登録の数が増えても、そこは変えていない。**",
                    "RFC 6749 §3.1.2.3（RFC 3986 §6.2.1 の単純文字列比較）/ #306");

                r.Target("GET /authorize（2 件登録のうち、どちらでもない値を送る）");

                await this.WithRegisteredClientAsync(admin, targetKey,
                    UriA + " " + UriB, async (client, reg) =>
                    {
                        r.Step("(1) 登録に無い " + UriUnregistered + " を送る");

                        AuthZResponse ng = await Flows.AuthorizeCodeAsync(
                            client, reg, "openid email", "state-ng", "nonce-ng", UriUnregistered);

                        r.Verify("code を返さない", string.IsNullOrEmpty(ng.Code),
                            "返さない", string.IsNullOrEmpty(ng.Code) ? "返さなかった" : "**返してしまった**");

                        r.Step("(2) 1 本目の接頭辞（末尾を削った値）も通らない");

                        AuthZResponse prefix = await Flows.AuthorizeCodeAsync(
                            client, reg, "openid email", "state-p", "nonce-p",
                            UriA.Substring(0, UriA.Length - 2));

                        r.Verify("接頭辞でも code を返さない", string.IsNullOrEmpty(prefix.Code),
                            "返さない", string.IsNullOrEmpty(prefix.Code)
                                ? "返さなかった" : "**返してしまった（前方一致になっている）**");

                        r.Note("**登録に無い折り返し先へは、応答を飛ばさない。** "
                            + "**飛ばせると、任意の URL に認可コードを渡せる**ことになる。");
                    });

                r.Done();
            }
        }

        #endregion

        #region RT-306.3

        /// <summary>RT-306.3 2 件登録のとき、redirect_uri の省略は断られる</summary>
        /// <param name="targetKey">core / netfx</param>
        /// <returns>Task</returns>
        [SkippableTheory]
        [MemberData(nameof(AllTargets))]
        public async Task RT30603_2件登録のとき省略は断られる(string targetKey)
        {
            using (IdPClient admin = this.Client(targetKey))
            {
                TestReport r = this.Report("RT-306.3",
                    "2 件以上登録しているとき、`redirect_uri` の省略は `invalid_request` になる",
                    "**1 本しか登録できなかった頃は、省略すると登録値がそのまま使われていた。**"
                    + "**n 件になると、どれを使うべきか決められない。**"
                    + "**RFC 6749 §3.1.2.3 は、複数登録しているなら要求に含めること**としている。"
                    + "**1 件だけの配備では、従来どおり省略できる** — "
                    + "**既存のケースの大半が、その経路で回っている。**",
                    "RFC 6749 §3.1.2.3 / #306");

                r.Target("GET /authorize（2 件登録。redirect_uri を送らない）");

                await this.WithRegisteredClientAsync(admin, targetKey,
                    UriA + " " + UriB, async (client, reg) =>
                    {
                        r.Step("(1) redirect_uri を送らない");

                        AuthZResponse omitted = await Flows.AuthorizeCodeAsync(
                            client, reg, "openid email", "state-o", "nonce-o", null);

                        r.Verify("code を返さない", string.IsNullOrEmpty(omitted.Code),
                            "返さない", string.IsNullOrEmpty(omitted.Code)
                                ? "返さなかった" : "**返してしまった（どれかを勝手に選んでいる）**");

                        r.Note("**1 件だけ登録している配備は、従来どおり省略できる。** "
                            + "**この分岐は件数で決まる** — **設定は増えていない。**");
                    });

                r.Done();
            }
        }

        #endregion

        #region 補助

        /// <summary>使い捨ての利用者を作り、指定の redirect_uri でクライアントを登録して渡す</summary>
        /// <param name="admin">管理者のクライアント</param>
        /// <param name="targetKey">core / netfx</param>
        /// <param name="redirectUriCode">登録する redirect_uri_code（空白区切り）</param>
        /// <param name="body">測る本体</param>
        /// <returns>Task</returns>
        /// <remarks>
        /// **管理画面が扱うのは、その利用者の 1 件**なので、**使い捨ての利用者で登録する**
        /// （**#307 の段階 5-a-1 より前は、DB 側も 1 人 1 件だった**）。
        /// **ロールは `Admin`** — **`/Manage/AddSaml2OAuth2Data` は
        /// `SystemAdmin` か `Admin` でなければ開かない**（#299 と同じ事情）。
        /// **終わったら利用者を消す**（登録も一緒に消える）。
        ///
        /// **インスタンス メソッドである。** **`Client` は `protected`** なので、
        /// **静的メソッドから型経由では呼べない**（`CS1540`。実測で踏んだ）。
        /// </remarks>
        private async Task WithRegisteredClientAsync(
            IdPClient admin, string targetKey,
            string redirectUriCode, Func<IdPClient, ClientRegistration, Task> body)
        {
            await admin.SignInAsAdministratorAsync();
            await UsersAdmin.SkipIfLockedDownAsync(admin);

            string name = "e2e_rt306_" + Guid.NewGuid().ToString("N").Substring(0, 8);
            string email = name + "@example.com";
            string password = admin.Config.Get("TestUserPWD");

            Assert.True(RedirectUriTests.IsRedirect(
                await UsersAdmin.CreateAsync(admin, name, email, "Admin")),
                "前提: 利用者を作れること");

            try
            {
                using (IdPClient client = this.Client(targetKey))
                {
                    Assert.True(await client.TrySignInAsync(name, password),
                        "前提: 使い捨ての利用者でサインインできること");

                    //  **登録の直前に redirect_uri_code を差し込む**（#306）。
                    (string ClientId, string ClientSecret) registered =
                        await ManageClientRegistration.RegisterWithSecretAsync(client,
                            new Dictionary<string, string>()
                            {
                                { "RedirectUriCode", redirectUriCode }
                            });

                    Assert.False(string.IsNullOrEmpty(registered.ClientId),
                        "前提: クライアントを登録できること");

                    ClientRegistration reg = new ClientRegistration()
                    {
                        ClientId = registered.ClientId,
                        ClientSecret = registered.ClientSecret,
                        RedirectUri = redirectUriCode
                    };

                    await body(client, reg);
                }
            }
            finally
            {
                await UsersAdmin.DeleteByUserNameAsync(admin, name);
            }
        }

        /// <summary>リダイレクトか（UsersAdmin の作成が成功したか）</summary>
        /// <param name="res">応答</param>
        /// <returns>リダイレクトなら true</returns>
        private static bool IsRedirect(System.Net.Http.HttpResponseMessage res)
        {
            return res.StatusCode == HttpStatusCode.Found
                || res.StatusCode == HttpStatusCode.Redirect
                || res.StatusCode == HttpStatusCode.SeeOther;
        }

        #endregion
    }
}
