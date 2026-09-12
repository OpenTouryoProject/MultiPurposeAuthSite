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
//* クラス名        ：RedirectUriBindingTests
//* クラス日本語名  ：RT redirect_uriの照合の回帰（#186）
//*
//* 作成日時        ：－
//* 作成者          ：－
//* 更新履歴        ：－
//*
//*  日時        更新者            内容
//*  ----------  ----------------  -------------------------------------------------
//*  2026/09/08  玄人 幸道         新規（E2Eテスト基盤）
//*  2026/09/10  玄人 幸道         TestReportで記録を残すよう変更（RT-186）
//*  2026/09/13  玄人 幸道         Tests/Issues へ移動（RT-186）
//**********************************************************************************

using System.Threading.Tasks;

using MultiPurposeAuthSite.Tests.E2E.Infrastructure;

using Xunit;
using Xunit.Abstractions;

namespace MultiPurposeAuthSite.Tests.E2E.Tests.Issues
{
    /// <summary>
    /// RT-186. 認可リクエストの redirect_uri を認可コードに紐付け、
    /// トークン リクエストで照合していることを確認する。
    /// </summary>
    public class RedirectUriBindingTests : TargetTestBase
    {
        /// <summary>RT-186 の共通の根拠</summary>
        private const string Basis =
            "RFC 6749 §4.1.3（認可リクエストに含めたなら、トークン リクエストにも含め、"
            + "一致しなければならない）/ OIDC Core §3.1.3.1 / #186";

        /// <summary>コンストラクタ</summary>
        /// <param name="output">ITestOutputHelper</param>
        public RedirectUriBindingTests(ITestOutputHelper output) : base(output)
        {
        }

        /// <summary>RT-186.1 ケースA: 同じ redirect_uri なら成功する</summary>
        /// <param name="targetKey">core / netfx</param>
        /// <returns>Task</returns>
        [SkippableTheory]
        [MemberData(nameof(AllTargets))]
        public async Task RT186_01_同じredirect_uriなら成功する(string targetKey)
        {
            using (IdPClient client = await this.SignedInClientAsync(targetKey))
            {
                TestReport r = this.Report("RT-186.1",
                    "認可時と同じ redirect_uri なら成功する（ケース A）",
                    "**照合を足したことで、正当な交換まで弾いていないこと。**"
                    + "拒否のテスト（RT-186.2 / 186.3）だけでは、"
                    + "常に拒否する実装でも通ってしまう。",
                    Basis);

                ClientRegistration reg = Flows.Registration(client, KnownClients.MvcSample);

                r.Target("client_name=" + KnownClients.MvcSample
                    + " / redirect_uri = " + reg.RedirectUri);
                r.Step("(1) redirect_uri を指定して認可し、code を得る");
                r.Step("(2) 同じ redirect_uri でトークンに交換する");

                AuthZResponse authz = await Flows.AuthorizeCodeAsync(
                    client, reg, redirectUri: reg.RedirectUri);

                r.Verify("認可コードが発行される", !string.IsNullOrEmpty(authz.Code),
                    "code あり",
                    string.IsNullOrEmpty(authz.Code) ? authz.ToString() : "code あり");

                JsonResponse token = await Flows.ExchangeCodeAsync(
                    client, reg, authz.Code, reg.RedirectUri);

                r.Verify("エラーにならない", string.IsNullOrEmpty(token.Error),
                    "error なし", token.Error ?? "error なし");

                r.Verify("access_token が返る", !string.IsNullOrEmpty(token.AccessToken),
                    "access_token あり", token.AccessToken == null ? "なし" : "あり（値は伏せる）");

                r.Done();
            }
        }

        /// <summary>RT-186.2 ケースB: 違う redirect_uri は拒否される</summary>
        /// <param name="targetKey">core / netfx</param>
        /// <returns>Task</returns>
        [SkippableTheory]
        [MemberData(nameof(AllTargets))]
        public async Task RT186_02_違うredirect_uriは拒否される(string targetKey)
        {
            using (IdPClient client = await this.SignedInClientAsync(targetKey))
            {
                TestReport r = this.Report("RT-186.2",
                    "認可時と違う redirect_uri は拒否される（ケース B）",
                    "**これが本題。** code と redirect_uri が結び付いていないと、"
                    + "攻撃者が奪った code を自分の登録済み URI で交換できる余地が残る。"
                    + "多重防御の 1 枚。",
                    Basis);

                ClientRegistration reg = Flows.Registration(client, KnownClients.MvcSample);

                r.Target("client_name=" + KnownClients.MvcSample);
                r.Step("(1) 正しい redirect_uri で認可し、code を得る");
                r.Step("(2) https://attacker.example.com/callback を指定して交換する");

                AuthZResponse authz = await Flows.AuthorizeCodeAsync(
                    client, reg, redirectUri: reg.RedirectUri);

                Assert.False(string.IsNullOrEmpty(authz.Code), "前提: code が取得できること");

                JsonResponse token = await Flows.ExchangeCodeAsync(
                    client, reg, authz.Code, "https://attacker.example.com/callback");

                r.VerifyEqual("invalid_grant で拒否される", "invalid_grant", token.Error);

                r.Verify("トークンを発行しない", string.IsNullOrEmpty(token.AccessToken),
                    "access_token を返さない",
                    token.AccessToken == null ? "返さなかった" : "**返してしまった**");

                r.Done();
            }
        }

        /// <summary>RT-186.3 ケースC: redirect_uri の省略は拒否される</summary>
        /// <param name="targetKey">core / netfx</param>
        /// <returns>Task</returns>
        [SkippableTheory]
        [MemberData(nameof(AllTargets))]
        public async Task RT186_03_redirect_uriの省略は拒否される(string targetKey)
        {
            using (IdPClient client = await this.SignedInClientAsync(targetKey))
            {
                TestReport r = this.Report("RT-186.3",
                    "認可時に送った redirect_uri を、トークン時に省略すると拒否される（ケース C）",
                    "**省略を「一致」とみなしてはならない。**"
                    + "そう扱うと、RT-186.2 の照合を省略するだけで迂回できる。",
                    Basis);

                ClientRegistration reg = Flows.Registration(client, KnownClients.MvcSample);

                r.Target("client_name=" + KnownClients.MvcSample);
                r.Step("(1) 正しい redirect_uri で認可し、code を得る");
                r.Step("(2) redirect_uri を付けずに交換する");

                AuthZResponse authz = await Flows.AuthorizeCodeAsync(
                    client, reg, redirectUri: reg.RedirectUri);

                Assert.False(string.IsNullOrEmpty(authz.Code), "前提: code が取得できること");

                JsonResponse token = await Flows.ExchangeCodeAsync(
                    client, reg, authz.Code, null);

                r.VerifyEqual("invalid_grant で拒否される", "invalid_grant", token.Error);

                r.Verify("トークンを発行しない", string.IsNullOrEmpty(token.AccessToken),
                    "access_token を返さない",
                    token.AccessToken == null ? "返さなかった" : "**返してしまった**");

                r.Note("**この経路には穴が残っている。** `request_uri`（JAR）で認可した code は"
                    + "照合が効かない（#197 / RT-197.1）。");

                r.Done();
            }
        }

        /// <summary>RT-186.4 認可コードは再利用できない</summary>
        /// <param name="targetKey">core / netfx</param>
        /// <returns>Task</returns>
        [SkippableTheory]
        [MemberData(nameof(AllTargets))]
        public async Task RT186_04_認可コードは再利用できない(string targetKey)
        {
            using (IdPClient client = await this.SignedInClientAsync(targetKey))
            {
                TestReport r = this.Report("RT-186.4",
                    "認可コードは 1 回しか使えない",
                    "code は使い捨て。2 回目が通ると、"
                    + "盗まれた code が繰り返し使える。"
                    + "（TC-2.2 と同じ観点。こちらは #186 の修正で壊れていないことの確認）",
                    "RFC 6749 §4.1.2（code は 1 回限り）/ §10.5");

                ClientRegistration reg = Flows.Registration(client, KnownClients.MvcSample);

                r.Target("client_name=" + KnownClients.MvcSample);
                r.Step("(1) code を 1 つ取得し、トークンに交換する");
                r.Step("(2) 同じ code で、もう一度交換する");

                AuthZResponse authz = await Flows.AuthorizeCodeAsync(
                    client, reg, redirectUri: reg.RedirectUri);

                Assert.False(string.IsNullOrEmpty(authz.Code), "前提: code が取得できること");

                JsonResponse first = await Flows.ExchangeCodeAsync(
                    client, reg, authz.Code, reg.RedirectUri);

                r.Verify("1 回目は成功する", string.IsNullOrEmpty(first.Error),
                    "error なし", first.Error ?? "error なし");

                JsonResponse second = await Flows.ExchangeCodeAsync(
                    client, reg, authz.Code, reg.RedirectUri);

                r.Verify("2 回目は拒否される", !string.IsNullOrEmpty(second.Error),
                    "error が返る", "error = " + (second.Error ?? "なし"));

                r.Verify("2 回目でトークンを発行しない",
                    string.IsNullOrEmpty(second.AccessToken),
                    "access_token を返さない",
                    second.AccessToken == null ? "返さなかった" : "**返してしまった**");

                r.Done();
            }
        }
    }
}
