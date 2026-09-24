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
//* クラス名        ：LifetimeTests
//* クラス日本語名  ：RT 認可コード・refresh_token・Request Object の有効期限（#188）
//*
//* 作成日時        ：－
//* 作成者          ：－
//* 更新履歴        ：－
//*
//*  日時        更新者            内容
//*  ----------  ----------------  -------------------------------------------------
//*  2026/09/24  玄人 幸道         新規（#188 の段階 1 : 有効期限を実際に検証する）
//**********************************************************************************

using System;
using System.Collections.Generic;
using System.Threading.Tasks;

using MultiPurposeAuthSite.Tests.E2E.Infrastructure;

using Xunit;
using Xunit.Abstractions;

namespace MultiPurposeAuthSite.Tests.E2E.Tests.Issues
{
    /// <summary>
    /// RT-188. 認可コード / refresh_token / Request Object の**有効期限**。
    /// </summary>
    /// <remarks>
    /// **既定の寿命（認可コード 600 秒・Request Object 300 秒・refresh_token 14 日）を待つのは現実的でない。**
    /// そこで `test.ps1 -Launch -ShortLifetimes` が、寿命をごく短くしてサイトを起動する。
    /// **その起動でしかケースを作らない**（付けなければ Skip にもならない）。
    ///
    /// 寿命が短い状態では他のテストが落ちるので、**-Filter と併せて回す**
    ///   `.\2_RunAllTests.ps1 -Launch -ShortLifetimes -Filter "FullyQualifiedName~LifetimeTests"`
    ///
    /// 期限切れは「無かったこと」と同じ扱いにする。
    /// 存在しない code / token と同じ経路（`invalid_grant`）に合流する。
    /// </remarks>
    public class LifetimeTests : TargetTestBase
    {
        /// <summary>寿命（test.ps1 -ShortLifetimes が設定する秒数）より長く待つ</summary>
        private static readonly TimeSpan Wait = TimeSpan.FromSeconds(4);

        /// <summary>コンストラクタ</summary>
        /// <param name="output">ITestOutputHelper</param>
        public LifetimeTests(ITestOutputHelper output) : base(output)
        {
        }

        /// <summary>測る対象 : -ShortLifetimes で起動したときだけ</summary>
        public static IEnumerable<object[]> ShortLifetimeTargets
        {
            get
            {
                if (Environment.GetEnvironmentVariable("MPAS_SHORT_LIFETIMES") == "true")
                {
                    yield return new object[] { TestEnv.CoreKey };
                    yield return new object[] { TestEnv.NetFxKey };
                }
            }
        }

        /// <summary>RT-188.1 期限切れの認可コードは使えない</summary>
        /// <param name="targetKey">core / netfx</param>
        /// <returns>Task</returns>
        [SkippableTheory]
        [MemberData(nameof(ShortLifetimeTargets))]
        public async Task RT188_01_期限切れの認可コードは使えない(string targetKey)
        {
            using (IdPClient client = await this.SignedInClientAsync(targetKey))
            {
                ClientRegistration reg = Flows.Registration(client, KnownClients.TestClient);

                TestReport r = this.Report("RT-188.1",
                    "有効期限を過ぎた認可コードは、トークンに交換できない",
                    "**以前は、認可コードの有効期限を検証していなかった。**"
                    + "ストアに `CreatedDate` を書いてはいたが、**どこからも読んでいなかった**ため、"
                    + "いつまでも交換できた。RFC 6749 §4.1.2 は短命（10 分以内を推奨）を求めている。",
                    "RFC 6749 §4.1.2 / #188");

                r.Target(client.Target.DisplayName + " / client_name=" + KnownClients.TestClient);

                r.Step("(1) 認可コードを取る");

                AuthZResponse authz = await Flows.AuthorizeCodeAsync(client, reg, redirectUri: reg.RedirectUri);
                Assert.False(string.IsNullOrEmpty(authz.Code), "前提: code が取得できること");

                r.Step("(2) 寿命より長く待つ（" + (int)LifetimeTests.Wait.TotalSeconds + " 秒）");

                await Task.Delay(LifetimeTests.Wait);

                r.Step("(3) トークンに交換する");

                JsonResponse token = await Flows.ExchangeCodeAsync(client, reg, authz.Code, reg.RedirectUri);

                r.Verify("トークンを返さない", string.IsNullOrEmpty(token.AccessToken),
                    "返さない",
                    string.IsNullOrEmpty(token.AccessToken)
                        ? "返さなかった（error=" + (token.Error ?? "なし") + "）" : "**返してしまった**");

                r.VerifyEqual("エラーは invalid_grant", "invalid_grant", token.Error ?? "（無し）");

                r.Note("**期限切れは「無いもの」と同じ扱いにしている。**"
                    + "存在しない code と同じ経路に合流するので、有無を区別されない。");

                r.Done();
            }
        }

        /// <summary>RT-188.2 期限切れの refresh_token は使えない</summary>
        /// <param name="targetKey">core / netfx</param>
        /// <returns>Task</returns>
        [SkippableTheory]
        [MemberData(nameof(ShortLifetimeTargets))]
        public async Task RT188_02_期限切れのrefresh_tokenは使えない(string targetKey)
        {
            using (IdPClient client = await this.SignedInClientAsync(targetKey))
            {
                ClientRegistration reg = Flows.Registration(client, KnownClients.TestClient);

                TestReport r = this.Report("RT-188.2",
                    "有効期限を過ぎた refresh_token は、更新に使えない",
                    "**`OAuth2RefreshTokenExpireTimeSpanFromDays`（既定 14 日）は、"
                    + "定義だけで、どこからも参照されていなかった**（事実上の無期限）。"
                    + "本テストは 0 日（＝即座に期限切れ）で起動して測る。",
                    "OAuth 2.0 Security BCP §4.14 / #188");

                r.Target(client.Target.DisplayName + " / client_name=" + KnownClients.TestClient);

                r.Step("(1) 認可コードでトークンを取り、refresh_token を得る");

                AuthZResponse authz = await Flows.AuthorizeCodeAsync(client, reg, redirectUri: reg.RedirectUri);
                Assert.False(string.IsNullOrEmpty(authz.Code), "前提: code が取得できること");

                JsonResponse token = await Flows.ExchangeCodeAsync(client, reg, authz.Code, reg.RedirectUri);
                Assert.False(string.IsNullOrEmpty(token.RefreshToken), "前提: refresh_token が返ること");

                r.Step("(2) 寿命より長く待つ（" + (int)LifetimeTests.Wait.TotalSeconds + " 秒）");

                await Task.Delay(LifetimeTests.Wait);

                r.Step("(3) refresh_token で更新する");

                JsonResponse refreshed = await Flows.RefreshAsync(client, reg, token.RefreshToken);

                r.Verify("トークンを返さない", string.IsNullOrEmpty(refreshed.AccessToken),
                    "返さない",
                    string.IsNullOrEmpty(refreshed.AccessToken)
                        ? "返さなかった（error=" + (refreshed.Error ?? "なし") + "）" : "**返してしまった**");

                r.VerifyEqual("エラーは invalid_grant", "invalid_grant", refreshed.Error ?? "（無し）");

                r.Done();
            }
        }

        /// <summary>RT-188.3 期限切れの request_uri は使えない</summary>
        /// <param name="targetKey">core / netfx</param>
        /// <returns>Task</returns>
        [SkippableTheory]
        [MemberData(nameof(ShortLifetimeTargets))]
        public async Task RT188_03_期限切れのrequest_uriは使えない(string targetKey)
        {
            using (IdPClient client = await this.SignedInClientAsync(targetKey))
            {
                ClientRegistration reg = Flows.Registration(client, KnownClients.TestClient);

                TestReport r = this.Report("RT-188.3",
                    "有効期限を過ぎた request_uri は、認可要求に使えない",
                    "**Request Object も、`CreatedDate` を書くだけで読んでいなかった。**"
                    + "`/ros` の応答の `exp` は空文字で、いつまでも使えた。"
                    + "**使い切り（ワンタイム）にはしていない**（1 回の認可の中で複数回読むため。#229 で扱う）。",
                    "RFC 9101（JAR）/ #188");

                r.Target(client.Target.DisplayName + " / client_name=" + KnownClients.TestClient);

                r.Step("(1) Request Object を /ros に預け、request_uri と exp を得る");

                string requestUri = await RequestObjectBuilder.RegisterAsync(client,
                    RequestObjectBuilder.Create(client, reg.ClientId, new Dictionary<string, object>()
                    {
                        { "response_type", "code" },
                        { "redirect_uri", reg.RedirectUri },
                        { "scope", "openid email" },
                        { "state", "state-rt1883" },
                        { "nonce", "nonce-rt1883" }
                    }));

                Assert.False(string.IsNullOrEmpty(requestUri), "前提: /ros が request_uri を返すこと");

                r.Step("(2) 寿命より長く待つ（" + (int)LifetimeTests.Wait.TotalSeconds + " 秒）");

                await Task.Delay(LifetimeTests.Wait);

                r.Step("(3) その request_uri で認可要求を送る");

                AuthZResponse authz = await client.AuthorizeAsync(new Dictionary<string, string>()
                {
                    { "client_id", reg.ClientId },
                    { "request_uri", requestUri },
                    { "prompt", "none" }
                });

                r.Verify("認可コードを発行しない", string.IsNullOrEmpty(authz.Code),
                    "発行しない",
                    string.IsNullOrEmpty(authz.Code) ? "発行しなかった" : "**発行してしまった**");

                r.Observe("返り方",
                    "HTTP " + (int)authz.StatusCode + " / error=" + (authz.Error ?? "なし"),
                    "期限切れの request_uri は「無い」と同じ扱いになる。返し方は記録するだけで、判定しない。");

                r.Done();
            }
        }
    }
}
