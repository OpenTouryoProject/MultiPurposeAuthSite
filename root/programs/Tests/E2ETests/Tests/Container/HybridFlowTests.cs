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
//* クラス名        ：HybridFlowTests
//* クラス日本語名  ：CN-5 コンテナ 2 つでのハイブリッド IdP 構成（#284）
//*
//* 作成日時        ：－
//* 作成者          ：－
//* 更新履歴        ：－
//*
//*  日時        更新者            内容
//*  ----------  ----------------  -------------------------------------------------
//*  2026/10/08  玄人 幸道         新規（#284）
//**********************************************************************************

using System.Threading.Tasks;

using MultiPurposeAuthSite.Tests.E2E.Infrastructure;

using Xunit;
using Xunit.Abstractions;

namespace MultiPurposeAuthSite.Tests.E2E.Tests.Container
{
    /// <summary>
    /// CN-5. コンテナ 2 つ（下流 → 上流）で、ID 連携が一巡すること。
    /// </summary>
    /// <remarks>
    /// **#281 の目視の手順を、そのまま機械にしたもの**である。
    ///
    /// **`RT-140.*` とは目的が違う**（重複ではない）。
    ///
    /// | | 目的 |
    /// |---|---|
    /// | `RT-140.*`（`Tests/Issues`） | **ID 連携という機能が、net48 版 / net10.0 版の両方で動くこと** |
    /// | **`CN-5.*`（ここ）** | **コンテナ 2 つという配備で、一巡が通ること** |
    ///
    /// **手順の実装は `Infrastructure/IdFederation` に 1 つだけ置いてある**（#284）。
    /// **下流が違うだけ**で、押す順番は同じである。
    ///
    /// **ここが通るということは、次が全部効いているということである。**
    ///
    /// - **ブラウザが行く先と、サーバが呼ぶ先を分けた設定**
    ///   （`IdFederationAuthorizeEndpoint` ＝ ホストから届く URL /
    ///   `IdFederationTokenEndpoint` ＝ `http://upstream:8080`。#281）
    /// - **Cookie の名前が分かれている**（混ざると、途中で相手の状態を掴む）
    /// - **上流の `preferred_username` が下流へ渡っている**（#151 の段階 4）
    /// </remarks>
    public class HybridFlowTests : TargetTestBase
    {
        /// <summary>コンストラクタ</summary>
        /// <param name="output">ITestOutputHelper</param>
        public HybridFlowTests(ITestOutputHelper output) : base(output)
        {
        }

        /// <summary>CN-5.1 下流コンテナから上流コンテナへ委譲して、サインインできる</summary>
        /// <returns>Task</returns>
        [SkippableFact]
        public async Task CN0501_コンテナ2つでID連携できる()
        {
            using (IdPClient client = ContainerTargets.Client(ContainerTargets.DownstreamKey))
            {
                string upstream = await IdFederation.SkipIfUpstreamIsDownAsync(client);

                TestReport r = this.Report("CN-5.1",
                    "下流コンテナから上流コンテナへ委譲して、下流にサインインできる",
                    "**コンテナ 2 つだけでハイブリッド IdP 構成が取れること**（#281）。"
                    + "**ブラウザが行く先（`authorize`）とサーバが呼ぶ先（`token` / `userinfo`）を"
                    + "分けた設定が効いていなければ、`code` の後で止まる。**"
                    + "**どちらも「同じイメージの別の配備」**なので、"
                    + "**ここで出るのは配備の差である。**",
                    "OIDC Core §3.1 / #140 / #281 / #284");

                r.Target(client.Target.DisplayName + "（" + client.Target.BaseUrl
                    + "） ← 上流 " + upstream);

                r.Step("(1) 上流コンテナでサインインしておく（下流は prompt=none で委譲する）");

                bool upstreamSignedIn = await IdFederation.SignInUpstreamAsync(client, upstream);

                r.Verify("上流にサインインできる", upstreamSignedIn,
                    "サインインする", upstreamSignedIn ? "サインインした" : "**できなかった**");

                Assert.True(upstreamSignedIn, "前提: 上流にサインインできること");

                r.Step("(2) 下流コンテナで「ID連携でサインイン」を押す");

                FederationResult fed = await IdFederation.FederateAsync(
                    client, TestEnv.UpstreamUserName);

                r.Verify("上流の認可エンドポイントへ送られる",
                    !string.IsNullOrEmpty(fed.AuthorizeUrl),
                    "上流へリダイレクト",
                    (fed.AuthorizeUrl == null) ? "**リダイレクトしない**" : fed.AuthorizeUrl);

                bool promptNone = (fed.AuthorizeUrl ?? "").Contains("prompt=none");

                r.Verify("prompt=none で要求する（画面を出させない）", promptNone,
                    "prompt=none", promptNone ? "付いている" : "**付いていない**");

                r.Step("(3) 上流が認可応答（form_post）を返す");

                r.Verify("code が返る", fed.Authorized,
                    "code あり", fed.Authorized ? "あり（値は伏せる）" : "**無し**");

                Assert.True(fed.Authorized, "前提: 上流が認可コードを返すこと");

                r.Step("(4) 下流コンテナにサインインできている");

                bool signedIn = await IdFederation.IsSignedInAsync(client);

                r.Verify("保護された画面が開く", signedIn,
                    "開く", signedIn ? "開いた" : "**ログイン画面へ戻された**");

                r.Note("**`token` / `userinfo` はコンテナ内の宛先（`http://upstream:8080`）で呼ばれる**"
                    + "（#281）。**届いていなければ、この画面は開かない。**");

                r.Done();
            }
        }

        /// <summary>CN-5.2 二度目の連携でも同じ利用者になる</summary>
        /// <returns>Task</returns>
        /// <remarks>
        /// **連携キーは `(iss, sub)`**（#140 の段階 3）。
        /// **同じ上流・同じ利用者なら、何度連携しても同じ下流アカウントになる。**
        /// </remarks>
        [SkippableFact]
        public async Task CN0502_二度目の連携でも同じ利用者になる()
        {
            using (IdPClient client = ContainerTargets.Client(ContainerTargets.DownstreamKey))
            {
                string upstream = await IdFederation.SkipIfUpstreamIsDownAsync(client);

                TestReport r = this.Report("CN-5.2",
                    "コンテナ 2 つの構成でも、二度目の連携で同じ利用者になる",
                    "**連携キーは `(iss, sub)`**（#140 の段階 3）。"
                    + "**下流コンテナは `IssuerId` を上流と分けている**（#281）が、"
                    + "**連携キーに使うのは上流の `iss`** なので、分けても同じ利用者になる。"
                    + "**毎回新しいアカウントが作られないこと**を見る。",
                    "#140 の段階 3 / #281 / #284");

                r.Target(client.Target.DisplayName + " ← 上流 " + upstream);

                r.Step("(1) 上流でサインインして、1 回目の連携を通す");

                Assert.True(await IdFederation.SignInUpstreamAsync(client, upstream),
                    "前提: 上流にサインインできること");

                FederationResult first = await IdFederation.FederateAsync(
                    client, TestEnv.UpstreamUserName);

                Assert.True(first.Authorized, "前提: 上流が認可コードを返すこと（1 回目）");

                string firstName = await HybridFlowTests.SignedInUserNameAsync(client);

                r.Verify("1 回目でサインインできる", !string.IsNullOrEmpty(firstName),
                    "利用者名が読める",
                    string.IsNullOrEmpty(firstName) ? "**読めない**" : firstName);

                r.Step("(2) もう一度、同じ経路を通す");

                FederationResult second = await IdFederation.FederateAsync(
                    client, TestEnv.UpstreamUserName);

                Assert.True(second.Authorized, "前提: 上流が認可コードを返すこと（2 回目）");

                string secondName = await HybridFlowTests.SignedInUserNameAsync(client);

                r.Step("(3) 同じ利用者である");

                r.Verify("1 回目と 2 回目が同じ利用者", firstName == secondName,
                    firstName, secondName);

                r.Done();
            }
        }

        /// <summary>サインインしている利用者名を、画面から読む</summary>
        /// <param name="client">IdPClient</param>
        /// <returns>利用者名（読めなければ null）</returns>
        /// <remarks>
        /// **画面に出ている名前で見る。** **`sub` では見ない**
        /// （`subject_types` の既定が `public` になり、`sub` は利用者 ID である。#151 の段階 4）。
        /// </remarks>
        private static async Task<string> SignedInUserNameAsync(IdPClient client)
        {
            string html = await client.GetStringAsync("/Manage/Index");

            if (string.IsNullOrEmpty(html))
            {
                return null;
            }

            System.Text.RegularExpressions.Match m =
                System.Text.RegularExpressions.Regex.Match(
                    html, TestEnv.UpstreamUserName + "[A-Za-z0-9_@.]*");

            return m.Success ? m.Value : null;
        }
    }
}
