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
//* クラス名        ：TokenClaimTests
//* クラス日本語名  ：RT トークンの値と型の回帰（#182 / #184）
//*
//* 作成日時        ：－
//* 作成者          ：－
//* 更新履歴        ：－
//*
//*  日時        更新者            内容
//*  ----------  ----------------  -------------------------------------------------
//*  2026/09/08  玄人 幸道         新規（E2Eテスト基盤）
//*  2026/09/10  玄人 幸道         TestReportで記録を残すよう変更（RT-182 / RT-184）
//*  2026/09/13  玄人 幸道         Tests/Issues へ移動（RT-182 / RT-184）
//**********************************************************************************

using System.Text.Json;
using System.Threading.Tasks;

using MultiPurposeAuthSite.Tests.E2E.Infrastructure;

using Xunit;
using Xunit.Abstractions;

namespace MultiPurposeAuthSite.Tests.E2E.Tests.Issues
{
    /// <summary>
    /// RT-182 / RT-184. トークンに載る値と型の回帰テスト。
    /// </summary>
    public class TokenClaimTests : TargetTestBase
    {
        /// <summary>コンストラクタ</summary>
        /// <param name="output">ITestOutputHelper</param>
        public TokenClaimTests(ITestOutputHelper output) : base(output)
        {
        }

        /// <summary>RT-182.1 expires_in が 0 にならない</summary>
        /// <param name="targetKey">core / netfx</param>
        /// <returns>Task</returns>
        [SkippableTheory]
        [MemberData(nameof(AllTargets))]
        public async Task RT182_01_expires_inが0でない(string targetKey)
        {
            using (IdPClient client = await this.SignedInClientAsync(targetKey))
            {
                TestReport r = this.Report("RT-182.1",
                    "expires_in が 0 にならない",
                    "expires_in は「トークンの有効期間の秒数」。"
                    + "0 だと RP は「即座に期限切れ」と解釈し、"
                    + "受け取った直後に再取得へ回るか、トークンを捨てる。",
                    "RFC 6749 §5.1（expires_in は有効期間の秒数）"
                    + " / 修正前は TimeSpan.Seconds（分内の秒）を返しており常に 0 だった（#182）");

                r.Target("client_name=" + KnownClients.MvcSample);
                r.Step("認可コード フローでトークンを取得し、expires_in を見る");

                JsonResponse token = await Flows.RunAuthorizationCodeFlowAsync(client);

                Assert.True(string.IsNullOrEmpty(token.Error), "前提: トークンが取得できること");

                string expiresIn = token.String("expires_in");
                int seconds = 0;
                bool parsed = int.TryParse(expiresIn, out seconds);

                r.Verify("expires_in が存在する", !string.IsNullOrEmpty(expiresIn),
                    "expires_in あり", expiresIn ?? "なし");

                r.Verify("expires_in が正の整数である", parsed && seconds > 0,
                    "1 以上の整数", "expires_in = " + (expiresIn ?? "なし"));

                r.Done();
            }
        }

        /// <summary>RT-184.1 JWTの時刻クレームが数値である</summary>
        /// <param name="targetKey">core / netfx</param>
        /// <returns>Task</returns>
        [SkippableTheory]
        [MemberData(nameof(AllTargets))]
        public async Task RT184_01_時刻クレームが数値である(string targetKey)
        {
            using (IdPClient client = await this.SignedInClientAsync(targetKey))
            {
                TestReport r = this.Report("RT-184.1",
                    "JWT の exp / nbf / iat が JSON の数値である",
                    "NumericDate は **JSON の数値**と定められている。"
                    + "文字列で入れると、仕様どおりに実装された RP のライブラリが"
                    + "型エラーで検証に失敗する。",
                    "RFC 7519 §2（NumericDate は JSON number）/ §4.1.4・4.1.5・4.1.6"
                    + " / 修正前は文字列だった（#184）");

                r.Target("client_name=" + KnownClients.MvcSample);
                r.Step("認可コード フローで access_token と id_token を取得し、型を見る");

                JsonResponse token = await Flows.RunAuthorizationCodeFlowAsync(client);

                Assert.True(string.IsNullOrEmpty(token.Error), "前提: トークンが取得できること");

                JsonElement accessToken = Jwt.Payload(token.AccessToken);
                JsonElement idToken = Jwt.Payload(token.IdToken);

                foreach (string claim in new string[] { "exp", "nbf", "iat" })
                {
                    if (Jwt.Has(accessToken, claim))
                    {
                        r.Verify("access_token の " + claim + " が数値である",
                            Jwt.KindOf(accessToken, claim) == JsonValueKind.Number,
                            "JSON の数値", claim + " の型 = " + Jwt.KindOf(accessToken, claim));
                    }

                    if (Jwt.Has(idToken, claim))
                    {
                        r.Verify("id_token の " + claim + " が数値である",
                            Jwt.KindOf(idToken, claim) == JsonValueKind.Number,
                            "JSON の数値", claim + " の型 = " + Jwt.KindOf(idToken, claim));
                    }
                }

                r.Done();
            }
        }

        /// <summary>RT-184.2 JWTの真偽値クレームが真偽値である</summary>
        /// <param name="targetKey">core / netfx</param>
        /// <returns>Task</returns>
        [SkippableTheory]
        [MemberData(nameof(AllTargets))]
        public async Task RT184_02_真偽値クレームが真偽値である(string targetKey)
        {
            using (IdPClient client = await this.SignedInClientAsync(targetKey))
            {
                TestReport r = this.Report("RT-184.2",
                    "access_token の email_verified / phone_number_verified が真偽値である",
                    "OIDC はこれらを boolean と定めている。"
                    + "文字列の \"true\" は、**JavaScript では \"false\" も真**になるため、"
                    + "RP 側で検証の意味が反転しうる。",
                    "OIDC Core §5.1（email_verified / phone_number_verified は boolean）"
                    + " / 修正前は文字列だった（#184）");

                r.Target("client_name=" + KnownClients.MvcSample + " / scope=openid email phone");
                r.Step("scope に email と phone を含めてトークンを取得し、型を見る");

                JsonResponse token = await Flows.RunAuthorizationCodeFlowAsync(
                    client, KnownClients.MvcSample, "openid email phone");

                Assert.True(string.IsNullOrEmpty(token.Error), "前提: トークンが取得できること");

                JsonElement accessToken = Jwt.Payload(token.AccessToken);
                int seen = 0;

                foreach (string claim in new string[] { "email_verified", "phone_number_verified" })
                {
                    if (!Jwt.Has(accessToken, claim))
                    {
                        continue;
                    }

                    seen++;
                    JsonValueKind kind = Jwt.KindOf(accessToken, claim);

                    r.Verify(claim + " が真偽値である",
                        kind == JsonValueKind.True || kind == JsonValueKind.False,
                        "boolean", claim + " の型 = " + kind);
                }

                if (seen == 0)
                {
                    r.Observe("対象のクレーム", "どちらも含まれていなかった",
                        "スコープの絞り込み次第で載らないことがある。その場合は型を確かめようがない。");
                }

                r.Done();
            }
        }

        /// <summary>RT-184.3 UserInfoの真偽値クレームが真偽値である</summary>
        /// <param name="targetKey">core / netfx</param>
        /// <returns>Task</returns>
        [SkippableTheory]
        [MemberData(nameof(AllTargets))]
        public async Task RT184_03_UserInfoの真偽値クレームが真偽値である(string targetKey)
        {
            using (IdPClient client = await this.SignedInClientAsync(targetKey))
            {
                TestReport r = this.Report("RT-184.3",
                    "UserInfo の email_verified / phone_number_verified が真偽値である",
                    "**JWT と UserInfo は別の経路**で組み立てられる。"
                    + "片方だけ直っている状態があり得るので、両方を見る。",
                    "OIDC Core §5.1 / §5.3.2（UserInfo の応答は JSON）"
                    + " / 修正前は文字列だった（#184）");

                r.Target("client_name=" + KnownClients.MvcSample + " / scope=openid email phone");
                r.Step("(1) scope に email と phone を含めてトークンを取得する");
                r.Step("(2) そのトークンで GET /userinfo を叩き、型を見る");

                JsonResponse token = await Flows.RunAuthorizationCodeFlowAsync(
                    client, KnownClients.MvcSample, "openid email phone");

                Assert.True(string.IsNullOrEmpty(token.Error), "前提: トークンが取得できること");

                JsonResponse userInfo = await client.UserInfoAsync(token.AccessToken);

                r.Verify("UserInfo が JSON を返す", userInfo.IsJson,
                    "JSON", userInfo.ToString());

                int seen = 0;

                foreach (string claim in new string[] { "email_verified", "phone_number_verified" })
                {
                    JsonValueKind kind = userInfo.KindOf(claim);

                    if (kind == JsonValueKind.Undefined)
                    {
                        continue;
                    }

                    seen++;

                    r.Verify(claim + " が真偽値である",
                        kind == JsonValueKind.True || kind == JsonValueKind.False,
                        "boolean", claim + " の型 = " + kind);
                }

                if (seen == 0)
                {
                    r.Observe("対象のクレーム", "どちらも含まれていなかった",
                        "スコープの絞り込み次第で載らないことがある。");
                }

                r.Done();
            }
        }
    }
}
