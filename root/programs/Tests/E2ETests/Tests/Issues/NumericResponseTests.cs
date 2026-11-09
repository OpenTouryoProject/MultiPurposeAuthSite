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
//* クラス名        ：NumericResponseTests
//* クラス日本語名  ：RT-353 トークン応答と PAR の応答の expires_in は JSON の数値（#353）
//*
//* 作成日時        ：－
//* 作成者          ：－
//* 更新履歴        ：－
//*
//*  日時        更新者            内容
//*  ----------  ----------------  -------------------------------------------------
//*  2026/11/10  玄人 幸道         新規（#353）
//**********************************************************************************

using System.Collections.Generic;
using System.Text.Json;
using System.Threading.Tasks;

using MultiPurposeAuthSite.Tests.E2E.Infrastructure;

using Xunit;
using Xunit.Abstractions;

namespace MultiPurposeAuthSite.Tests.E2E.Tests.Issues
{
    /// <summary>
    /// RT-353. トークン応答と PAR の応答の `expires_in` は、JSON の数値で返る。
    /// </summary>
    /// <remarks>
    /// **以前は文字列（`"expires_in": "3600"`）で返していた**（応答の型が `Dictionary&lt;string, string&gt;` だったため）。
    /// 適合性テスト（#350）の `ValidateExpiresIn` で、トークンを取るすべてのモジュールが落ちて見つかった。
    /// **Device Authorization・CIBA の応答は、#294 で数値に直してある**（`RT-294.75` ほか）。同じ型の残りである。
    ///
    /// **E2E の `JsonResponse.String` は数値も文字列にして返す**ので、既存のテストでは見分けられなかった。
    /// ここでは **JSON の型（`KindOf`）** を見る。
    /// </remarks>
    public class NumericResponseTests : TargetTestBase
    {
        /// <summary>コンストラクタ</summary>
        /// <param name="output">ITestOutputHelper</param>
        public NumericResponseTests(ITestOutputHelper output) : base(output)
        {
        }

        /// <summary>RT-353.1 トークン応答の expires_in は JSON の数値</summary>
        /// <param name="targetKey">core / netfx</param>
        /// <returns>Task</returns>
        [SkippableTheory]
        [MemberData(nameof(AllTargets))]
        public async Task RT35301_トークン応答のexpires_inは数値(string targetKey)
        {
            using (IdPClient client = await this.SignedInClientAsync(targetKey))
            {
                ClientRegistration reg = Flows.Registration(client, KnownClients.MvcSample);

                TestReport r = this.Report("RT-353.1",
                    "トークン応答の expires_in は、JSON の数値で返る",
                    "**トークン応答の数値は JSON の数値で返す**（`\"3600\"` のような文字列にしない）。"
                    + "応答は 1 か所（`CreateAccessTokenResponse`）で作るので、"
                    + "**認可コード・refresh_token・client_credentials** の 3 つのグラントで確かめる。",
                    "RFC 6749 §5.1 / #353");

                r.Target("client_name=" + KnownClients.MvcSample);

                r.Step("(1) 認可コードを引き換える");

                JsonResponse code = await Flows.RunAuthorizationCodeFlowAsync(client);

                Assert.False(string.IsNullOrEmpty(code.AccessToken), "前提: access_token が返ること（" + code.ToString() + "）");

                NumericResponseTests.VerifyExpiresIn(r, "認可コード", code);

                r.Step("(2) refresh_token で更新する");

                Assert.False(string.IsNullOrEmpty(code.RefreshToken), "前提: refresh_token が返ること（" + code.ToString() + "）");

                JsonResponse refreshed = await client.TokenAsync(new Dictionary<string, string>()
                {
                    { "grant_type", "refresh_token" },
                    { "refresh_token", code.RefreshToken },
                    { "client_id", reg.ClientId },
                    { "client_secret", reg.ClientSecret }
                });

                Assert.False(string.IsNullOrEmpty(refreshed.AccessToken), "前提: 更新できること（" + refreshed.ToString() + "）");

                NumericResponseTests.VerifyExpiresIn(r, "refresh_token", refreshed);

                r.Step("(3) client_credentials でトークンを取る");

                JsonResponse cc = await client.TokenAsync(new Dictionary<string, string>()
                {
                    { "grant_type", "client_credentials" },
                    { "scope", "profile" },
                    { "client_id", reg.ClientId },
                    { "client_secret", reg.ClientSecret }
                });

                Assert.False(string.IsNullOrEmpty(cc.AccessToken), "前提: access_token が返ること（" + cc.ToString() + "）");

                NumericResponseTests.VerifyExpiresIn(r, "client_credentials", cc);

                r.Done();
            }
        }

        /// <summary>RT-353.2 PAR の応答の expires_in は JSON の数値</summary>
        /// <param name="targetKey">core / netfx</param>
        /// <returns>Task</returns>
        [SkippableTheory]
        [MemberData(nameof(AllTargets))]
        public async Task RT35302_PARの応答のexpires_inは数値(string targetKey)
        {
            using (IdPClient client = await this.SignedInClientAsync(targetKey))
            {
                ClientRegistration reg = Flows.Registration(client, KnownClients.TestClient);

                TestReport r = this.Report("RT-353.2",
                    "PAR の応答の expires_in は、JSON の数値で返る",
                    "**PAR の応答の `expires_in` は JSON の数値**（`request_uri` の有効期間の秒数）。",
                    "RFC 9126 §2.2 / #353");

                r.Target("client_name=" + KnownClients.TestClient + "（/par。client_secret_basic）");

                r.Step("(1) /par に認可要求を預ける");

                JsonResponse par = await client.PostJsonWithBasicAuthAsync("/par",
                    new Dictionary<string, string>()
                    {
                        { "response_type", "code" },
                        { "client_id", reg.ClientId },
                        { "redirect_uri", reg.RedirectUri },
                        { "scope", "openid email" },
                        { "state", "state-rt3532" },
                        { "nonce", "nonce-rt3532" }
                    }, reg.ClientId, reg.ClientSecret);

                Assert.False(string.IsNullOrEmpty(par.String("request_uri")), "前提: request_uri が返ること（" + par.ToString() + "）");

                NumericResponseTests.VerifyExpiresIn(r, "PAR", par);

                r.Done();
            }
        }

        /// <summary>expires_in が JSON の数値（正の整数）であることを確かめる</summary>
        /// <param name="r">TestReport</param>
        /// <param name="label">どの応答か</param>
        /// <param name="res">応答</param>
        private static void VerifyExpiresIn(TestReport r, string label, JsonResponse res)
        {
            r.VerifyEqual(label + "：expires_in は JSON の数値",
                JsonValueKind.Number.ToString(), res.KindOf("expires_in").ToString());

            long seconds;
            bool positive = long.TryParse(res.String("expires_in"), out seconds) && seconds > 0;

            r.Verify(label + "：expires_in は正の整数", positive,
                "1 以上の整数", "expires_in = " + (res.String("expires_in") ?? "なし"));
        }
    }
}
