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
//* クラス名        ：PostLogoutRedirectUrisTests
//* クラス日本語名  ：RT-426 ログアウト後の戻り先（post_logout_redirect_uri）を n 件登録できる
//*
//* 作成日時        ：－
//* 作成者          ：－
//* 更新履歴        ：－
//*
//*  日時        更新者            内容
//*  ----------  ----------------  -------------------------------------------------
//*  2026/11/25  玄人 幸道         新規（#426）
//**********************************************************************************

using System.Net.Http;
using System.Threading.Tasks;

using MultiPurposeAuthSite.Tests.E2E.Infrastructure;

using Xunit;
using Xunit.Abstractions;

namespace MultiPurposeAuthSite.Tests.E2E.Tests.Issues
{
    /// <summary>
    /// RT-426. **ログアウト後の戻り先（`post_logout_redirect_uri`）を n 件登録でき、どれかと完全一致すれば戻す。**
    /// </summary>
    /// <remarks>
    /// | | 測ること |
    /// |---|---|
    /// | **`RT-426.1`** | **2 件を登録したクライアントで、2 件目（記号）にも、1 件目（512 文字を超える URL）にも戻る。並べたままの値・前方一致・後ろに足した値には戻さない** |
    ///
    /// **RP-Initiated Logout 1.0 §3.1 の `post_logout_redirect_uris` は配列**である。
    /// **以前は 1 本だけ持てた**（#232）。**#426 で、動的登録の値を受けるため、`redirect_uri` と同じ形（空白区切りの n 件）にした。**
    /// **1 件目を 512 文字より長くしてある**ので、**DB の列を広げ忘れると、3 方言では保存できないか、2 件目が落ちる**（`mem` には幅が無い）。
    /// </remarks>
    public class PostLogoutRedirectUrisTests : TargetTestBase
    {
        /// <summary>コンストラクタ</summary>
        /// <param name="output">ITestOutputHelper</param>
        public PostLogoutRedirectUrisTests(ITestOutputHelper output) : base(output)
        {
        }

        /// <summary>サインインして、TestClient_50 の id_token を 1 つ取る</summary>
        /// <param name="client">IdPClient</param>
        /// <param name="reg">TestClient_50 の登録</param>
        /// <returns>id_token</returns>
        private static async Task<string> GetIdTokenAsync(IdPClient client, ClientRegistration reg)
        {
            await client.SignInAsync();

            AuthZResponse authz = await Flows.AuthorizeCodeAsync(
                client, reg, "openid email", "state1", "nonce1", reg.RedirectUri);

            Assert.False(string.IsNullOrEmpty(authz.Code),
                "前提: 認可コードが取得できること（" + authz.ToString() + "）");

            JsonResponse token = await Flows.ExchangeCodeAsync(
                client, reg, authz.Code, reg.RedirectUri);

            Assert.False(string.IsNullOrEmpty(token.IdToken),
                "前提: id_token が取得できること（" + token.ToString() + "）");

            return token.IdToken;
        }

        /// <summary>応答の Location から、OP が足した `state` を除いたもの（無ければ空）</summary>
        /// <param name="res">応答</param>
        /// <returns>Location（末尾の `?state=…` / `&amp;state=…` を除く）</returns>
        /// <remarks>**戻り先がクエリを持っていれば、`state` は `&amp;` でつながる**（`CmnLogoutEndpoint`）。</remarks>
        private static string LocationPathOf(HttpResponseMessage res)
        {
            string location = (res.Headers.Location == null) ? "" : res.Headers.Location.OriginalString;
            int q = location.LastIndexOf("state=");

            return (q < 1) ? location : location.Substring(0, q - 1);
        }

        #region RT-426.1

        /// <summary>RT-426.1 n 件の登録のどれかと完全一致すれば戻す</summary>
        /// <param name="targetKey">core / netfx</param>
        /// <returns>Task</returns>
        [SkippableTheory]
        [MemberData(nameof(AllTargets))]
        public async Task RT42601_登録したn件のどれかと完全一致すれば戻す(string targetKey)
        {
            using (IdPClient client = this.Client(targetKey))
            {
                TestReport r = this.Report("RT-426.1",
                    "**`post_logout_redirect_uri` を 2 件登録したクライアントで、2 件目（記号）にも 1 件目（512 文字を超える URL）にも戻る。どれとも完全一致しない値には戻さない**",
                    "**§3.1 の `post_logout_redirect_uris` は配列で、§3 は登録値と完全一致しなければ戻してはならない。**"
                    + "**以前は 1 本だけ持てた**（#232）。**#426 で `redirect_uri` と同じ空白区切りの n 件にした**（動的登録の値を受けるため）。"
                    + "**1 件目を 512 文字より長くしてある**ので、**列を広げ忘れると 3 方言では保存できないか、2 件目が落ちる。**",
                    "RP-Initiated Logout 1.0 §3.1 / §3 / #426");

                ClientRegistration reg = Flows.InjectedRegistration(client, KnownClients.TestClient_50);

                string second = KnownClients.PostLogoutRedirectUri(client);
                string first = KnownClients.TestClient50FirstPostLogoutRedirectUri;

                r.Target("GET /end_session（TestClient_50。登録は「512 文字を超える URL」と「test_self_logout」の 2 件）");

                r.Step("(1) 2 件目（記号。解決後の URL）を指定する");

                string idToken = await PostLogoutRedirectUrisTests.GetIdTokenAsync(client, reg);

                HttpResponseMessage res2 = await client.EndSessionAsync(idToken, null, second, "s426-2");

                r.VerifyEqual("HTTP 302", "302", ((int)res2.StatusCode).ToString());
                r.VerifyEqual("2 件目へ戻す", second, PostLogoutRedirectUrisTests.LocationPathOf(res2));

                r.Step("(2) 1 件目（512 文字を超える URL）を指定する");

                idToken = await PostLogoutRedirectUrisTests.GetIdTokenAsync(client, reg);

                HttpResponseMessage res1 = await client.EndSessionAsync(idToken, null, first, "s426-1");

                r.VerifyEqual("HTTP 302", "302", ((int)res1.StatusCode).ToString());
                r.VerifyEqual("1 件目へ戻す", first, PostLogoutRedirectUrisTests.LocationPathOf(res1));

                r.Step("(3) どれとも完全一致しない値を指定する（並べたまま・1 件目の前方・1 件目の後ろに足したもの）");

                idToken = await PostLogoutRedirectUrisTests.GetIdTokenAsync(client, reg);

                foreach (string[] c in new string[][]
                {
                    new string[] { "登録を並べたままの値", first + " " + second },
                    new string[] { "1 件目の前方（? より前）", "https://rp.e2e.example/logged_out" },
                    new string[] { "1 件目の後ろに足した値", first + "x" }
                })
                {
                    HttpResponseMessage res = await client.EndSessionAsync(idToken, null, c[1], "s426-x");

                    r.VerifyEqual(c[0] + " : HTTP 200（確認画面。リダイレクトしない）",
                        "200", ((int)res.StatusCode).ToString());
                }

                r.Verify("セッションは残っている（勝手にログアウトしない）",
                    await client.IsSessionAliveAsync(), "セッション有り", "セッション有り");

                r.Done();
            }
        }

        #endregion
    }
}
