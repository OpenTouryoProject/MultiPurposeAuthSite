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
//* クラス名        ：IdFederationTests
//* クラス日本語名  ：RT ID フェデレーション（#140 / #250 の段階 5）
//*
//* 作成日時        ：－
//* 作成者          ：－
//* 更新履歴        ：－
//*
//*  日時        更新者            内容
//*  ----------  ----------------  -------------------------------------------------
//*  2026/09/30  玄人 幸道         新規（#250 の段階 5 : ID フェデレーションを E2E で駆動する）
//**********************************************************************************

using System;
using System.Collections.Generic;
using System.Net;
using System.Net.Http;
using System.Text.RegularExpressions;
using System.Threading.Tasks;

using MultiPurposeAuthSite.Tests.E2E.Infrastructure;

using Xunit;
using Xunit.Abstractions;

namespace MultiPurposeAuthSite.Tests.E2E.Tests.Issues
{
    /// <summary>
    /// RT-140. ID フェデレーション（他の IdP へ委譲するサインイン）。
    /// </summary>
    /// <remarks>
    /// **この経路は、長いあいだ E2E で駆動していなかった**（`TESTING.md` 5 節）。
    /// **上流の IdP が要る**ためで、#250 の段階 2〜4 でコンテナとして建てられるようにした。
    ///
    /// **上流は `store/` のコンテナ**（既定 `https://localhost:44301`）で、
    /// **`test.ps1` の管理外**である。**建っていなければ Skip する**
    /// （DB ストアや IIS Express と同じ扱い）。
    ///
    /// **下流（テスト対象）は、`test.ps1` が上流を向くように起動する**
    /// （`OAuth2AndOidcClientID` / `IdFederationRedirectEndpoint` を差し込む）。
    ///
    /// **目視で見つかった欠陥は、どれもここで出るはずのものだった**（#250 の段階 4）。
    /// </remarks>
    public class IdFederationTests : TargetTestBase
    {
        /// <summary>コンストラクタ</summary>
        /// <param name="output">ITestOutputHelper</param>
        public IdFederationTests(ITestOutputHelper output) : base(output)
        {
        }

        #region 上流

        /// <summary>AntiForgery トークンを拾う</summary>
        private static readonly Regex AntiforgeryRegex = new Regex(
            "name=\"__RequestVerificationToken\"[^>]*value=\"(?<value>[^\"]+)\"",
            RegexOptions.IgnoreCase | RegexOptions.Compiled);

        /// <summary>上流の URL（スキーム＋ホスト＋ポート）</summary>
        /// <param name="client">IdPClient</param>
        /// <returns>上流の URL。分からなければ null</returns>
        /// <remarks>
        /// **構成ファイルの `IdFederationAuthorizeEndpoint` から引く。**
        /// **テストに URL を書かない**（`test.ps1` はここを上書きしないので、
        /// 構成ファイルの値が、そのままサイトの向き先である）。
        /// </remarks>
        private static string UpstreamOrigin(IdPClient client)
        {
            string endpoint = client.Config.Get("IdFederationAuthorizeEndpoint");

            if (string.IsNullOrEmpty(endpoint))
            {
                return null;
            }

            return new Uri(endpoint).GetLeftPart(UriPartial.Authority);
        }

        /// <summary>上流が起動していなければ Skip する</summary>
        /// <param name="client">IdPClient</param>
        /// <returns>上流の URL</returns>
        private static async Task<string> SkipIfUpstreamIsDownAsync(IdPClient client)
        {
            string origin = IdFederationTests.UpstreamOrigin(client);

            Skip.If(string.IsNullOrEmpty(origin),
                "IdFederationAuthorizeEndpoint が構成ファイルにありません。");

            bool up = false;

            try
            {
                HttpResponseMessage res = await client.GetAsync(
                    origin + "/.well-known/openid-configuration");

                up = res.IsSuccessStatusCode;
            }
            catch (HttpRequestException)
            {
                up = false;
            }
            catch (TaskCanceledException)
            {
                up = false;
            }

            Skip.IfNot(up,
                "上流の IdP（" + origin + "）が起動していません。"
                + "store\\1_DockerComposeUp.bat で建ててください（#250 の段階 5）。");

            return origin;
        }

        /// <summary>上流でサインインする（<c>prompt=none</c> の前提）</summary>
        /// <param name="client">IdPClient（Cookie は下流と同じ入れ物）</param>
        /// <param name="origin">上流の URL</param>
        /// <returns>サインインできたら true</returns>
        /// <remarks>
        /// **下流と同じ `IdPClient` を使う。** `CookieContainer` が 1 つなので、
        /// **ブラウザと同じ状態**（上流・下流の Cookie を同時に持つ）になる。
        /// </remarks>
        private static async Task<bool> SignInUpstreamAsync(IdPClient client, string origin)
        {
            HttpResponseMessage get = await client.GetAsync(origin + "/Account/Login");
            string html = await get.Content.ReadAsStringAsync();

            Match m = IdFederationTests.AntiforgeryRegex.Match(html);

            if (!m.Success)
            {
                return false;
            }

            HttpResponseMessage post = await client.PostFormAsync(
                origin + "/Account/Login",
                new Dictionary<string, string>()
                {
                    { "__RequestVerificationToken", m.Groups["value"].Value },
                    { "Email", TestEnv.TestUserName },
                    { "Password", client.Config.Get("TestUserPWD") },
                    { "RememberMe", "false" },
                    { "submitButtonName", "normal_signin" }
                });

            // 成功時はリダイレクト。失敗時はログイン画面を返す（HTTP 200）。
            return post.StatusCode == HttpStatusCode.Found
                || post.StatusCode == HttpStatusCode.Redirect
                || post.StatusCode == HttpStatusCode.SeeOther;
        }

        #endregion

        #region 連携の一巡

        /// <summary>ID 連携の結果</summary>
        private sealed class FederationResult
        {
            /// <summary>下流が上流へ送った認可要求の URL</summary>
            public string AuthorizeUrl { get; set; }

            /// <summary>上流の認可応答（form_post の自動送信フォーム）</summary>
            public HttpResponseMessage AuthorizeResponse { get; set; }

            /// <summary>自動送信フォームの hidden</summary>
            public Dictionary<string, string> Hidden { get; set; }

            /// <summary>下流の Redirect エンドポイントの応答</summary>
            public HttpResponseMessage Callback { get; set; }

            /// <summary>上流が認可応答を返したか（form_post になったか）</summary>
            public bool Authorized
            {
                get
                {
                    return this.Hidden != null && this.Hidden.ContainsKey("code");
                }
            }
        }

        /// <summary>下流の「ID連携でサインイン」を押して、最後まで流す</summary>
        /// <param name="client">IdPClient</param>
        /// <returns>FederationResult</returns>
        private static async Task<FederationResult> FederateAsync(IdPClient client)
        {
            FederationResult result = new FederationResult();

            // (1) 下流のログイン画面
            HttpResponseMessage login = await client.GetAsync("/Account/Login");
            string loginHtml = await login.Content.ReadAsStringAsync();

            Match m = IdFederationTests.AntiforgeryRegex.Match(loginHtml);

            Assert.True(m.Success, "前提: 下流のログイン画面から AntiForgery トークンを取れること");

            // (2) 「ID連携でサインイン」を押す（上流の /authorize へリダイレクトされる）
            HttpResponseMessage start = await client.PostFormAsync(
                "/Account/Login",
                new Dictionary<string, string>()
                {
                    { "__RequestVerificationToken", m.Groups["value"].Value },
                    { "Email", TestEnv.TestUserName },
                    { "Password", "" },
                    { "RememberMe", "false" },
                    { "submitButtonName", "id_federation_signin" }
                });

            if (start.Headers.Location == null)
            {
                return result;
            }

            result.AuthorizeUrl = start.Headers.Location.ToString();

            // (3) 上流の /authorize（prompt=none）
            result.AuthorizeResponse = await client.GetAsync(result.AuthorizeUrl);

            string authzHtml = await result.AuthorizeResponse.Content.ReadAsStringAsync();
            result.Hidden = Html.HiddenInputs(authzHtml);

            if (!result.Authorized)
            {
                return result;
            }

            // (4) 自動送信フォームを、下流の Redirect エンドポイントへ POST する
            string action = Html.FormAttribute(authzHtml, "action");

            Dictionary<string, string> form = new Dictionary<string, string>();

            foreach (KeyValuePair<string, string> item in result.Hidden)
            {
                form[item.Key] = item.Value;
            }

            result.Callback = await client.PostFormAsync(action, form);

            return result;
        }

        /// <summary>下流にサインインできているか</summary>
        /// <param name="client">IdPClient</param>
        /// <returns>サインインしていたら true</returns>
        /// <remarks>
        /// **保護された画面が開くかどうかで見る。**
        /// 未サインインなら、Cookie 認証がログイン画面へリダイレクトする。
        /// </remarks>
        private static async Task<bool> IsSignedInAsync(IdPClient client)
        {
            HttpResponseMessage res = await client.GetAsync("/Manage/Index");

            return res.StatusCode == HttpStatusCode.OK;
        }

        #endregion

        /// <summary>RT-140.4 ID 連携でサインインできる</summary>
        /// <param name="targetKey">core / netfx</param>
        /// <returns>Task</returns>
        [SkippableTheory]
        [MemberData(nameof(AllTargets))]
        public async Task RT14004_ID連携でサインインできる(string targetKey)
        {
            using (IdPClient client = this.Client(targetKey))
            {
                string upstream = await IdFederationTests.SkipIfUpstreamIsDownAsync(client);

                TestReport r = this.Report("RT-140.4",
                    "上流の IdP へ委譲して、下流にサインインできる",
                    "**下流は自分で認証せず、上流の認証結果を受け取る。**"
                    + "認可コード ＋ PKCE(S256) で `code` を受け、`/token`・`/userinfo` で"
                    + "利用者を特定し、**下流のアカウントに結び付けてサインインさせる。**"
                    + "**この経路は #140 の段階 3 で直したが、長く E2E で駆動できていなかった**（#250）。",
                    "OIDC Core §3.1 / #140 / #250 の段階 5");

                r.Target(client.Target.DisplayName + " ← 上流 " + upstream);

                r.Step("(1) 上流でサインインしておく（下流は prompt=none で委譲する）");

                bool upstreamSignedIn =
                    await IdFederationTests.SignInUpstreamAsync(client, upstream);

                r.Verify("上流にサインインできる", upstreamSignedIn,
                    "サインインする", upstreamSignedIn ? "サインインした" : "**できなかった**");

                Assert.True(upstreamSignedIn, "前提: 上流にサインインできること");

                r.Step("(2) 下流で「ID連携でサインイン」を押す");

                FederationResult fed = await IdFederationTests.FederateAsync(client);

                r.Verify("上流の認可エンドポイントへ送られる",
                    !string.IsNullOrEmpty(fed.AuthorizeUrl),
                    "上流へリダイレクト",
                    fed.AuthorizeUrl == null ? "**リダイレクトしない**" : fed.AuthorizeUrl);

                bool pkce = (fed.AuthorizeUrl ?? "").Contains("code_challenge_method=S256");

                r.Verify("PKCE(S256) を付けて要求する", pkce,
                    "code_challenge_method=S256", pkce ? "付いている" : "**付いていない**");

                bool promptNone = (fed.AuthorizeUrl ?? "").Contains("prompt=none");

                r.Verify("prompt=none で要求する（画面を出させない）", promptNone,
                    "prompt=none", promptNone ? "付いている" : "**付いていない**");

                r.Step("(3) 上流が認可応答（form_post）を返す");

                r.Verify("code が返る", fed.Authorized,
                    "code あり", fed.Authorized ? "あり（値は伏せる）" : "**無し**");

                Assert.True(fed.Authorized, "前提: 上流が認可コードを返すこと");

                r.Step("(4) 下流の Redirect エンドポイントへ渡す");

                bool signedIn = await IdFederationTests.IsSignedInAsync(client);

                r.Verify("下流にサインインできている", signedIn,
                    "保護された画面が開く",
                    signedIn ? "開いた" : "**ログイン画面へ戻された**");

                r.Done();
            }
        }

        /// <summary>RT-140.5 連携キーは (iss, sub)。二度目も同じ利用者になる</summary>
        /// <param name="targetKey">core / netfx</param>
        /// <returns>Task</returns>
        /// <remarks>
        /// **#140 の段階 3 で、連携キーを独自の `userid` から `(iss, sub)` へ移した。**
        /// **同じ上流・同じ利用者なら、何度連携しても同じ下流アカウントになる**
        /// （毎回新しいアカウントが作られない）ことを確かめる。
        /// </remarks>
        [SkippableTheory]
        [MemberData(nameof(AllTargets))]
        public async Task RT14005_二度目の連携でも同じ利用者になる(string targetKey)
        {
            string firstSub = null;

            for (int round = 1; round <= 2; round++)
            {
                // **毎回、新しい入れ物で始める**（Cookie を持ち越さない）。
                using (IdPClient client = this.Client(targetKey))
                {
                    string upstream = await IdFederationTests.SkipIfUpstreamIsDownAsync(client);

                    Assert.True(await IdFederationTests.SignInUpstreamAsync(client, upstream),
                        "前提: 上流にサインインできること（" + round + " 回目）");

                    FederationResult fed = await IdFederationTests.FederateAsync(client);

                    Assert.True(fed.Authorized,
                        "前提: 上流が認可コードを返すこと（" + round + " 回目）");

                    Assert.True(await IdFederationTests.IsSignedInAsync(client),
                        "前提: 下流にサインインできること（" + round + " 回目）");

                    // **下流の sub を、下流自身の /userinfo から引く。**
                    //   連携で作られた（または結び付いた）アカウントの識別子である。
                    //
                    //   **pairwise のクライアントを使う**（test.ps1 -Launch が差し込む）。
                    //   **既定（uname）の sub は利用者名**なので、
                    //   **別のアカウントが作られても同じ値になり、判定にならない。**
                    //   pairwise の sub は**利用者の ID から作る**ので、アカウントが違えば必ず違う。
                    ClientRegistration reg =
                        Flows.InjectedRegistration(client, KnownClients.TestClient_5);

                    // **RunAuthorizationCodeFlowAsync は使えない。**
                    //   あれはクライアント名から Registration を引くが、
                    //   **TestClient_5 は構成ファイルに無い**（差し込みなので InjectedRegistration）。
                    AuthZResponse authz = await Flows.AuthorizeCodeAsync(
                        client, reg, "openid email", "state-rt1405", "nonce-rt1405", reg.RedirectUri);

                    Assert.False(string.IsNullOrEmpty(authz.Code),
                        "前提: 下流で認可コードを取れること（" + round + " 回目）");

                    JsonResponse token = await Flows.ExchangeCodeAsync(
                        client, reg, authz.Code, reg.RedirectUri);

                    Assert.False(string.IsNullOrEmpty(token.AccessToken),
                        "前提: 下流でトークンを取れること（" + round + " 回目）");

                    JsonResponse userInfo = await client.UserInfoAsync(token.AccessToken);
                    string sub = userInfo.String("sub");

                    if (round == 1)
                    {
                        firstSub = sub;
                        continue;
                    }

                    TestReport r = this.Report("RT-140.5",
                        "二度目の ID 連携でも、同じ下流アカウントになる",
                        "**連携キーは `(iss, sub)` である**（#140 の段階 3。以前は独自の `userid`）。"
                        + "**同じ上流の同じ利用者なら、何度連携しても同じアカウント**に結び付く。"
                        + "毎回新しいアカウントが作られるなら、連携キーが効いていない。",
                        "OIDC Core §2（sub は Issuer 内で一意）/ #140 の段階 3");

                    r.Target(client.Target.DisplayName + " ← 上流 " + upstream);

                    r.Step("ID 連携を 2 回行い、下流の /userinfo が返す sub を比べる");

                    r.Verify("1 回目の sub が取れる", !string.IsNullOrEmpty(firstSub),
                        "sub あり", string.IsNullOrEmpty(firstSub) ? "**無し**" : "あり（値は伏せる）");

                    r.Verify("2 回目の sub が、1 回目と一致する",
                        !string.IsNullOrEmpty(sub) && sub == firstSub,
                        "一致する", (sub == firstSub) ? "一致した" : "**違う利用者になった**");

                    r.Done();
                }
            }
        }

        /// <summary>RT-140.6 上流にセッションが無ければ、連携は成立しない</summary>
        /// <param name="targetKey">core / netfx</param>
        /// <returns>Task</returns>
        /// <remarks>
        /// **下流は `prompt=none` で委譲する**ので、**上流が「黙って」認証できるときだけ通る。**
        ///
        /// **いまの上流は、セッションが無いとログイン画面を出す**（#254。OIDC Core §3.1.2.1 違反）。
        /// **#254 を直すと `login_required` が `redirect_uri` へ返る**が、
        /// **どちらでも「下流はサインインしない」**ので、この判定は変わらない。
        /// </remarks>
        [SkippableTheory]
        [MemberData(nameof(AllTargets))]
        public async Task RT14006_上流が未サインインなら連携は成立しない(string targetKey)
        {
            using (IdPClient client = this.Client(targetKey))
            {
                string upstream = await IdFederationTests.SkipIfUpstreamIsDownAsync(client);

                TestReport r = this.Report("RT-140.6",
                    "上流にセッションが無ければ、ID 連携は成立しない",
                    "**下流は prompt=none で委譲する。** 上流が黙って認証できないときに"
                    + "**勝手にサインインさせてしまっては、委譲の意味が無い。**"
                    + "**上流が画面を出すか login_required を返すかは #254 の論点**で、"
                    + "**どちらでも下流はサインインしない。**",
                    "OIDC Core §3.1.2.1 / §3.1.2.6 / #140 / #254");

                r.Target(client.Target.DisplayName + " ← 上流 " + upstream + "（未サインイン）");

                r.Step("上流にサインインせずに、下流で「ID連携でサインイン」を押す");

                FederationResult fed = await IdFederationTests.FederateAsync(client);

                r.Verify("上流の認可エンドポイントへは送られる",
                    !string.IsNullOrEmpty(fed.AuthorizeUrl),
                    "上流へリダイレクト",
                    fed.AuthorizeUrl == null ? "**リダイレクトしない**" : "リダイレクトした");

                r.Verify("認可コードは返らない", !fed.Authorized,
                    "code なし", fed.Authorized ? "**code が返った**" : "返らなかった");

                bool signedIn = await IdFederationTests.IsSignedInAsync(client);

                r.Verify("下流はサインインしない", !signedIn,
                    "サインインしない", signedIn ? "**サインインしてしまった**" : "しなかった");

                r.Done();
            }
        }

        /// <summary>RT-140.7 連携の認可応答にも iss が付く</summary>
        /// <param name="targetKey">core / netfx</param>
        /// <returns>Task</returns>
        /// <remarks>
        /// **#252 で form_post に `iss` を付けるようにした。**
        /// **ID 連携はまさに form_post を使う**ので、実経路でも付くことを確かめる。
        /// </remarks>
        [SkippableTheory]
        [MemberData(nameof(AllTargets))]
        public async Task RT14007_連携の認可応答にもissが付く(string targetKey)
        {
            using (IdPClient client = this.Client(targetKey))
            {
                string upstream = await IdFederationTests.SkipIfUpstreamIsDownAsync(client);

                TestReport r = this.Report("RT-140.7",
                    "ID 連携の認可応答（form_post）にも、iss が付く",
                    "**下流は認可応答の `iss` を照合する**（#140 の段階 3。Mix-Up 対策）。"
                    + "**上流が返さなければ、その照合は一度も働かない。**"
                    + "**form_post だけ `iss` が抜けていた**（#252）ので、実経路で確かめる。",
                    "RFC 9207 §2 / #252 / #140 の段階 3");

                r.Target(client.Target.DisplayName + " ← 上流 " + upstream);

                r.Step("(1) 上流の Discovery から issuer を読む");

                JsonResponse discovery = await client.GetJsonAsync(
                    upstream + "/.well-known/openid-configuration");

                Assert.True(discovery.IsJson, "前提: 上流の Discovery が JSON であること");

                string issuer = discovery.String("issuer");
                r.Note("上流の issuer = " + (issuer ?? "（無し）"));

                r.Step("(2) ID 連携を行い、認可応答の hidden を見る");

                Assert.True(await IdFederationTests.SignInUpstreamAsync(client, upstream),
                    "前提: 上流にサインインできること");

                FederationResult fed = await IdFederationTests.FederateAsync(client);

                Assert.True(fed.Authorized, "前提: 上流が認可コードを返すこと");

                string iss;
                fed.Hidden.TryGetValue("iss", out iss);

                r.VerifyEqual("iss が上流の issuer と一致する",
                    issuer ?? "（無し）", iss ?? "**無し**");

                r.Done();
            }
        }
    }
}
