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
//* クラス名        ：PairwiseTests
//* クラス日本語名  ：RT-140 subject_types = pairwise（PPID）の経路
//*
//* 作成日時        ：－
//* 作成者          ：－
//* 更新履歴        ：－
//*
//*  日時        更新者            内容
//*  ----------  ----------------  -------------------------------------------------
//*  2026/09/30  玄人 幸道         新規（#140 の段階 2）
//*  2026/10/03  玄人 幸道         テスト利用者をターゲットごとに引く（#260）
//**********************************************************************************

using System.Threading.Tasks;

using MultiPurposeAuthSite.Tests.E2E.Infrastructure;

using Xunit;
using Xunit.Abstractions;

namespace MultiPurposeAuthSite.Tests.E2E.Tests.Issues
{
    /// <summary>
    /// RT-140.2 / .3 `subject_types = pairwise`（PPID）の経路（#140 の段階 2）。
    /// </summary>
    /// <remarks>
    /// **PPID は「OP 以外が戻せない」ことが要件**で、一方向であることは求められていない。
    /// 以前は salted hash（一方向）だったため **OP 自身も戻せず**、
    /// `PPIDExtension.GetUserFromSub` が `pairwise` で null を返していた。
    ///
    /// その結果、**`subject_types=pairwise` のクライアントでは
    /// `/userinfo` がクレームを返さず（`sub` だけ）、`ciba_result` は 401 になっていた。**
    /// **機能が成立していなかった**ということ。
    ///
    /// **#140 の段階 2 で、OP だけが戻せる暗号化に変えた。**
    /// </remarks>
    public class PairwiseTests : TargetTestBase
    {
        /// <summary>コンストラクタ</summary>
        /// <param name="output">ITestOutputHelper</param>
        public PairwiseTests(ITestOutputHelper output) : base(output)
        {
        }

        /// <summary>RT-140.2 pairwise でも /userinfo がクレームを返す</summary>
        /// <param name="targetKey">core / netfx</param>
        /// <returns>Task</returns>
        [SkippableTheory]
        [MemberData(nameof(AllTargets))]
        public async Task RT14002_pairwiseでもuserinfoがクレームを返す(string targetKey)
        {
            using (IdPClient client = await this.SignedInClientAsync(targetKey))
            {
                // **TestClient_5 は構成ファイルに無い**（test.ps1 -Launch が差し込む）。
                ClientRegistration pairwise = Flows.InjectedRegistration(client, KnownClients.TestClient_5);

                TestReport r = this.Report("RT-140.2",
                    "subject_types=pairwise のクライアントでも、/userinfo が sub 以外のクレームを返す",
                    "**PPID は「OP 以外が戻せない」ことが要件**で、"
                    + "**一方向であることは求められていない。**"
                    + "以前は salted hash だったため **OP 自身も戻せず**、"
                    + "`GetUserFromSub` が null を返していた。"
                    + "**その結果 `/userinfo` は `sub` しか返さず、pairwise は機能していなかった**"
                    + "（#140 の段階 2）。",
                    "OIDC Core §8（Subject Identifier Types）/ §5.3（UserInfo Endpoint）/ #140 の段階 2");

                r.Target("client_name=" + KnownClients.TestClient_5 + "（subject_types=pairwise）");

                r.Step("(1) 認可コードを取ってトークンに交換する");

                AuthZResponse authz = await Flows.AuthorizeCodeAsync(
                    client, pairwise, scope: "openid email", redirectUri: pairwise.RedirectUri);

                Assert.False(string.IsNullOrEmpty(authz.Code), "前提: 認可コードが返ること");

                JsonResponse token = await Flows.ExchangeCodeAsync(
                    client, pairwise, authz.Code, redirectUri: pairwise.RedirectUri);

                r.Verify("access_token が返る", !string.IsNullOrEmpty(token.AccessToken),
                    "返る",
                    string.IsNullOrEmpty(token.AccessToken)
                        ? "**返らない**（" + token.ToString() + "）" : "返った");

                Assert.False(string.IsNullOrEmpty(token.AccessToken), "前提: access_token が返ること");

                r.Step("(2) sub が PPID になっている（利用者名でも UserId でもない）");

                string sub = Jwt.String(Jwt.Payload(token.AccessToken), "sub");

                r.Verify("sub が返る", !string.IsNullOrEmpty(sub),
                    "返る", string.IsNullOrEmpty(sub) ? "**返らない**" : "返った（値は伏せる）");

                r.Verify("sub が利用者名そのものではない",
                    sub != TestEnv.TestUserName(targetKey),
                    "利用者名ではない",
                    (sub == TestEnv.TestUserName(targetKey)) ? "**利用者名がそのまま出ている**" : "利用者名ではない");

                r.Step("(3) /userinfo を叩く");

                JsonResponse userinfo = await client.UserInfoAsync(token.AccessToken);

                r.VerifyEqual("HTTP 200", "200", ((int)userinfo.StatusCode).ToString());

                r.VerifyEqual("sub は access_token と同じ", sub, userinfo.String("sub") ?? "（無し）");

                r.Verify("**sub 以外のクレームが返る**（email）",
                    !string.IsNullOrEmpty(userinfo.String("email")),
                    "返る",
                    string.IsNullOrEmpty(userinfo.String("email"))
                        ? "**sub しか返らない**（PPID から利用者を引けていない）" : "返った");

                r.Note("**ここが段階 2 の要**。**以前はこの検証が通らなかった**"
                    + "（`GetUserFromSub` が null を返し、`user != null` の中だけで"
                    + "クレームを詰めているため、`sub` だけが返っていた）。");

                r.Done();
            }
        }

        /// <summary>RT-140.3 PPID はクライアントごとに違う</summary>
        /// <param name="targetKey">core / netfx</param>
        /// <returns>Task</returns>
        [SkippableTheory]
        [MemberData(nameof(AllTargets))]
        public async Task RT14003_PPIDはクライアントごとに違う(string targetKey)
        {
            using (IdPClient client = await this.SignedInClientAsync(targetKey))
            {
                ClientRegistration pairwise = Flows.InjectedRegistration(client, KnownClients.TestClient_5);
                ClientRegistration normal = Flows.Registration(client, KnownClients.TestClient);

                TestReport r = this.Report("RT-140.3",
                    "pairwise の sub は、同じ利用者でもクライアントごとに違い、毎回同じ値になる",
                    "**pairwise の目的は、RP 同士が sub を突き合わせても同じ人だと分からないこと。**"
                    + "同時に、**RP は sub を利用者の主キーとして保存する**ので、"
                    + "**同じ利用者・同じクライアントなら毎回同じ値**でなければならない"
                    + "（毎回変わると、RP から見て別人になる）。"
                    + "**暗号化に変えたので、この 2 つが両立しているかを測る**（#140 の段階 2）。",
                    "OIDC Core §8.1（Pairwise Identifier Algorithm）/ #140 の段階 2");

                r.Target("client_name=" + KnownClients.TestClient_5 + "（pairwise）と "
                    + KnownClients.TestClient + "（既定 = public）");

                r.Step("(1) pairwise のクライアントで 2 回、トークンを取る");

                string first = await PairwiseTests.SubOfAsync(client, pairwise);
                string second = await PairwiseTests.SubOfAsync(client, pairwise);

                r.Verify("2 回とも同じ sub（毎回変わらない）",
                    !string.IsNullOrEmpty(first) && first == second,
                    "同じ",
                    (first == second) ? "同じ" : "**違う**（RP から見て別人になってしまう）");

                r.Step("(2) 別のクライアントで取る");

                string other = await PairwiseTests.SubOfAsync(client, normal);

                r.Verify("別のクライアントでは違う sub",
                    !string.IsNullOrEmpty(other) && other != first,
                    "違う",
                    (other == first) ? "**同じ**（RP 同士で突き合わせられる）" : "違う");

                r.Note("**(2) の相手は subject_types の既定（public）**なので、"
                    + "**利用者 ID がそのまま sub になる。**"
                    + "**ここで見たいのは「突き合わせられないこと」**で、"
                    + "pairwise 同士の比較は、クライアントをもう 1 つ差し込まないと測れない。"
                    + "**既定が public であること自体は RT-151.2 が測る。**");

                r.Done();
            }
        }

        #region 補助

        /// <summary>認可コード フローを 1 往復して、access_token の sub を返す</summary>
        /// <param name="client">IdPClient</param>
        /// <param name="registration">クライアント</param>
        /// <returns>sub</returns>
        private static async Task<string> SubOfAsync(IdPClient client, ClientRegistration registration)
        {
            AuthZResponse authz = await Flows.AuthorizeCodeAsync(
                client, registration, scope: "openid email", redirectUri: registration.RedirectUri);

            Assert.False(string.IsNullOrEmpty(authz.Code), "前提: 認可コードが返ること");

            JsonResponse token = await Flows.ExchangeCodeAsync(
                client, registration, authz.Code, redirectUri: registration.RedirectUri);

            Assert.False(string.IsNullOrEmpty(token.AccessToken), "前提: access_token が返ること");

            return Jwt.String(Jwt.Payload(token.AccessToken), "sub");
        }

        #endregion
    }
}
