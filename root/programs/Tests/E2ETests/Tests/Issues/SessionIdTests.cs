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
//* クラス名        ：SessionIdTests
//* クラス日本語名  ：RT-310 sid（OP のセッションの識別子）
//*
//* 作成日時        ：－
//* 作成者          ：－
//* 更新履歴        ：－
//*
//*  日時        更新者            内容
//*  ----------  ----------------  -------------------------------------------------
//*  2026/10/21  玄人 幸道         新規（#310 の段階 1）
//**********************************************************************************

using System.Net.Http;
using System.Text.Json;
using System.Threading.Tasks;

using MultiPurposeAuthSite.Tests.E2E.Infrastructure;

using Xunit;
using Xunit.Abstractions;

namespace MultiPurposeAuthSite.Tests.E2E.Tests.Issues
{
    /// <summary>
    /// RT-310. **`sid`（OP のセッションの識別子）を `id_token` に出す**（#310 の段階 1）。
    /// </summary>
    /// <remarks>
    /// **ログアウトを他の RP へ伝えるには、「どのセッションか」を言う手段が要る**
    /// （Front-Channel / Back-Channel Logout。#310 の段階 2・3）。
    /// **段階 1 では、その手段（`sid`）と、伝える先の台帳（`SessionClient`）だけを入れた** —
    /// **Discovery は変えていない**（**できないことを広告しない**）。
    ///
    /// | | 測ること |
    /// |---|---|
    /// | **`RT-310.1`** | **`id_token` に `sid` が出る**。**同じセッション・同じ RP なら、2 回目も同じ値**（台帳から引けている）。**`refresh_token` で取り直しても同じ** |
    /// | **`RT-310.2`** | **RP ごとに別の値**（**`pairwise` の `sub` を分けた意味を消さない**） |
    /// | **`RT-310.3`** | **サインアウトして入り直すと変わる**（**セッションが終わっている**） |
    ///
    /// **`sid` の値そのものは意味を持たない**（guid）。**測るのは「同じか、違うか」だけ**である。
    /// </remarks>
    public class SessionIdTests : TargetTestBase
    {
        /// <summary>コンストラクタ</summary>
        /// <param name="output">ITestOutputHelper</param>
        public SessionIdTests(ITestOutputHelper output) : base(output)
        {
        }

        #region RT-310.1

        /// <summary>RT-310.1 id_token に sid が出て、同じセッションでは変わらない</summary>
        /// <param name="targetKey">core / netfx</param>
        /// <returns>Task</returns>
        [SkippableTheory]
        [MemberData(nameof(AllTargets))]
        public async Task RT31001_id_tokenにsidが出て同じセッションでは変わらない(string targetKey)
        {
            using (IdPClient client = await this.SignedInClientAsync(targetKey))
            {
                TestReport r = this.Report("RT-310.1",
                    "**`id_token` に `sid` が出る**（OIDC Core §2）。"
                    + "**同じセッション・同じ RP なら、2 回目も同じ値**で、"
                    + "**`refresh_token` で取り直しても同じ**",
                    "**`sid` は「どのセッションか」を言う手段**である"
                    + "（Front-Channel / Back-Channel Logout。#310 の段階 2・3）。"
                    + "**毎回違う値だと、ログアウトを伝える先と結び付かない** — "
                    + "**台帳（`SessionClient`）から引いていることを、ここで押さえる。**",
                    "OIDC Core §2 / #310 の段階 1");

                ClientRegistration reg = Flows.Registration(client, KnownClients.MvcSample);

                r.Target("client_name=" + KnownClients.MvcSample + "（認可コード フロー）");

                r.Step("(1) 1 回目の id_token に sid が出る");

                JsonResponse first = await Flows.RunAuthorizationCodeFlowAsync(
                    client, KnownClients.MvcSample, "openid email", "nonce-rt3101");

                string firstSid = SessionIdTests.SidOf(first.IdToken);

                Assert.False(string.IsNullOrEmpty(first.IdToken),
                    "前提: id_token が取得できること（" + first.ToString() + "）");

                r.Verify("id_token に sid が在る", !string.IsNullOrEmpty(firstSid),
                    "sid 有り", string.IsNullOrEmpty(firstSid) ? "**無い**" : "有り（値は出さない）");

                r.Step("(2) 2 回目の id_token も、同じ sid である");

                JsonResponse second = await Flows.RunAuthorizationCodeFlowAsync(
                    client, KnownClients.MvcSample, "openid email", "nonce-rt3101b");

                string secondSid = SessionIdTests.SidOf(second.IdToken);

                r.Verify("2 回目も同じ sid", (secondSid == firstSid) && !string.IsNullOrEmpty(secondSid),
                    "1 回目と同じ",
                    (secondSid == firstSid) ? "同じ" : "**違う**（台帳から引けていない）");

                r.Step("(3) refresh_token で取り直しても、同じ sid である");

                string refreshToken = second.RefreshToken;

                if (string.IsNullOrEmpty(refreshToken))
                {
                    r.Note("**この配備は `refresh_token` を返していない**ので、(3) は見送った"
                        + "（`EnableRefreshToken` が既定で有効なら測れる）。");
                }
                else
                {
                    JsonResponse refreshed = await Flows.RefreshAsync(client, reg, refreshToken);

                    string refreshedSid = SessionIdTests.SidOf(refreshed.IdToken);

                    r.Verify("取り直した id_token も同じ sid",
                        (refreshedSid == firstSid) && !string.IsNullOrEmpty(refreshedSid),
                        "1 回目と同じ",
                        string.IsNullOrEmpty(refreshedSid)
                            ? "**sid が消えた**（" + refreshed.ToString() + "）"
                            : ((refreshedSid == firstSid) ? "同じ" : "**違う**"));

                    r.Note("**`refresh_token` の経路は、access_token から ClaimsIdentity を"
                        + "組み直して作る**（`CmnAccessToken.AddClaims`）。"
                        + "**そこで `sid` を戻さないと、作り直した `id_token` から消える。**");
                }

                r.Note("**`access_token` にも `sid` が入る** — "
                    + "**`id_token` は access_token のクレーム集合から作られる**ためである"
                    + "（`CmnIdToken.ChangeToIdTokenFromAccessToken`）。"
                    + "**RP ごとに別の値**なので、**RP 同士の突き合わせには使えない。**");

                r.Done();
            }
        }

        #endregion

        #region RT-310.2

        /// <summary>RT-310.2 sid は RP ごとに別の値である</summary>
        /// <param name="targetKey">core / netfx</param>
        /// <returns>Task</returns>
        [SkippableTheory]
        [MemberData(nameof(AllTargets))]
        public async Task RT31002_sidはRPごとに別の値である(string targetKey)
        {
            using (IdPClient client = await this.SignedInClientAsync(targetKey))
            {
                TestReport r = this.Report("RT-310.2",
                    "**同じセッションでも、`sid` は RP ごとに別の値**になる",
                    "**セッション単位で 1 つにすると、`sub` を `pairwise` にしている配備で、"
                    + "2 つの RP が突き合わせたときに同じ利用者だと分かってしまう**"
                    + "（**`sub` を分けた意味が消える**）。"
                    + "**仕様が求めるのは「その RP に出した `id_token` の `sid` と、"
                    + "その RP へ送る `logout_token` の `sid` が同じこと」**なので、"
                    + "**RP ごとに別の値でよい。**",
                    "OIDC Back-Channel Logout 1.0 §2.4 / OIDC Core §8 / #310 の段階 1");

                r.Target("client_name=" + KnownClients.MvcSample
                    + " と " + KnownClients.TestClient + "（同じセッション）");

                r.Step("(1) 1 つ目の RP に id_token を発行する");

                JsonResponse one = await Flows.RunAuthorizationCodeFlowAsync(
                    client, KnownClients.MvcSample, "openid email", "nonce-rt3102a");

                string sidOne = SessionIdTests.SidOf(one.IdToken);

                Assert.False(string.IsNullOrEmpty(sidOne),
                    "前提: 1 つ目の id_token に sid が在ること（" + one.ToString() + "）");

                r.Step("(2) 2 つ目の RP にも id_token を発行する（同じセッション）");

                JsonResponse two = await Flows.RunAuthorizationCodeFlowAsync(
                    client, KnownClients.TestClient, "openid email", "nonce-rt3102b");

                string sidTwo = SessionIdTests.SidOf(two.IdToken);

                r.Verify("2 つ目の RP にも sid が在る", !string.IsNullOrEmpty(sidTwo),
                    "sid 有り", string.IsNullOrEmpty(sidTwo) ? "**無い**" : "有り");

                r.Verify("1 つ目と 2 つ目で、sid が違う",
                    !string.IsNullOrEmpty(sidTwo) && (sidOne != sidTwo),
                    "RP ごとに別の値",
                    (sidOne == sidTwo) ? "**同じ値だった**（RP 同士で突き合わせられる）" : "別の値");

                r.Note("**セッションそのものは 1 つである**（Cookie が持つ識別子は同じ）。"
                    + "**台帳（`SessionClient`）が、セッション × クライアントで 1 行**を持ち、"
                    + "**行ごとに別の `sid`** を記録している。"
                    + "**段階 2 では、この表からログアウトを伝える先を引く。**");

                r.Done();
            }
        }

        #endregion

        #region RT-310.3

        /// <summary>RT-310.3 サインアウトして入り直すと sid が変わる</summary>
        /// <param name="targetKey">core / netfx</param>
        /// <returns>Task</returns>
        [SkippableTheory]
        [MemberData(nameof(AllTargets))]
        public async Task RT31003_サインアウトして入り直すとsidが変わる(string targetKey)
        {
            using (IdPClient client = await this.SignedInClientAsync(targetKey))
            {
                TestReport r = this.Report("RT-310.3",
                    "**サインアウトして入り直すと、同じ RP でも `sid` が変わる**",
                    "**`sid` が指すのはセッションであって、利用者でもクライアントでもない。**"
                    + "**サインアウトでセッションが終わる**ので、"
                    + "**入り直した後は別のセッション ＝ 別の `sid`** でなければならない"
                    + "（**同じ値が返るなら、それはセッションを識別していない**）。",
                    "OIDC Core §2 / #310 の段階 1");

                r.Target("client_name=" + KnownClients.MvcSample + "（サインアウトを挟む）");

                r.Step("(1) サインアウトの前に id_token を取る");

                JsonResponse before = await Flows.RunAuthorizationCodeFlowAsync(
                    client, KnownClients.MvcSample, "openid email", "nonce-rt3103a");

                string sidBefore = SessionIdTests.SidOf(before.IdToken);

                Assert.False(string.IsNullOrEmpty(sidBefore),
                    "前提: id_token に sid が在ること（" + before.ToString() + "）");

                r.Step("(2) サインアウトする（/Account/LogOff）");

                HttpResponseMessage logOff = await client.GetAsync("/Account/LogOff");

                r.Verify("サインアウトできた（リダイレクトで返る）",
                    (int)logOff.StatusCode == 302,
                    "302", ((int)logOff.StatusCode).ToString());

                r.Step("(3) 入り直して、同じ RP に id_token を取る");

                await client.SignInAsync(force: true);

                JsonResponse after = await Flows.RunAuthorizationCodeFlowAsync(
                    client, KnownClients.MvcSample, "openid email", "nonce-rt3103b");

                string sidAfter = SessionIdTests.SidOf(after.IdToken);

                r.Verify("入り直した後も sid が在る", !string.IsNullOrEmpty(sidAfter),
                    "sid 有り", string.IsNullOrEmpty(sidAfter) ? "**無い**" : "有り");

                r.Verify("サインアウトの前後で、sid が違う",
                    !string.IsNullOrEmpty(sidAfter) && (sidBefore != sidAfter),
                    "別のセッション ＝ 別の値",
                    (sidBefore == sidAfter) ? "**同じ値だった**（セッションを識別していない）" : "別の値");

                r.Note("**サインアウトでは、台帳のその セッションの行も消している**"
                    + "（`SessionClientProvider.DeleteBySession`）。"
                    + "**消えたことは E2E では見えない**（**新しいセッションでは、どの行も引かれない**）。"
                    + "**SQL が通ることは、方言の通しで確かめている。**");

                r.Done();
            }
        }

        #endregion

        #region 私的なヘルパ

        /// <summary>id_token の sid（無ければ空）</summary>
        /// <param name="idToken">id_token</param>
        /// <returns>sid</returns>
        /// <remarks>**値そのものは意味を持たない**（guid）。**同じか違うかだけを見る。**</remarks>
        private static string SidOf(string idToken)
        {
            if (string.IsNullOrEmpty(idToken))
            {
                return "";
            }

            JsonElement payload = Jwt.Payload(idToken);

            return Jwt.String(payload, "sid") ?? "";
        }

        #endregion
    }
}
