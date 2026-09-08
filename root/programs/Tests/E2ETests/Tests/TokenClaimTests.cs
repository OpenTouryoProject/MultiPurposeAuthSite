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
//* クラス日本語名  ：トークンの値と型の回帰テスト（#182 / #184）
//*
//* 作成日時        ：－
//* 作成者          ：－
//* 更新履歴        ：－
//*
//*  日時        更新者            内容
//*  ----------  ----------------  -------------------------------------------------
//*  2026/09/08  玄人 幸道         新規（E2Eテスト基盤）
//**********************************************************************************

using System.Text.Json;
using System.Threading.Tasks;

using MultiPurposeAuthSite.Tests.E2E.Infrastructure;

using Xunit;
using Xunit.Abstractions;

namespace MultiPurposeAuthSite.Tests.E2E.Tests
{
    /// <summary>
    /// トークンに載る値と型の回帰テスト。
    /// </summary>
    public class TokenClaimTests : TargetTestBase
    {
        /// <summary>コンストラクタ</summary>
        /// <param name="output">ITestOutputHelper</param>
        public TokenClaimTests(ITestOutputHelper output) : base(output)
        {
        }

        /// <summary>
        /// expires_in が 0 にならない（#182）。
        ///
        /// TimeSpan.Seconds（分内の秒＝0）を返していたため、常に 0 だった。
        /// RFC 6749 5.1 の expires_in は「有効期間の秒数」。
        /// </summary>
        /// <param name="targetKey">core / netfx</param>
        /// <returns>Task</returns>
        [SkippableTheory]
        [MemberData(nameof(AllTargets))]
        public async Task Issue182_expires_inが0でない(string targetKey)
        {
            using (IdPClient client = await this.SignedInClientAsync(targetKey))
            {
                JsonResponse token = await Flows.RunAuthorizationCodeFlowAsync(client);

                Assert.Null(token.Error);

                string expiresIn = token.String("expires_in");
                this.Output.WriteLine("expires_in = " + expiresIn);

                Assert.False(string.IsNullOrEmpty(expiresIn), "expires_in がありません。");
                Assert.True(int.Parse(expiresIn) > 0, "expires_in が 0 以下です: " + expiresIn);
            }
        }

        /// <summary>
        /// JWTの時刻クレームが数値である（#184）。
        ///
        /// RFC 7519 の NumericDate は JSON の数値。文字列で入れていた。
        /// </summary>
        /// <param name="targetKey">core / netfx</param>
        /// <returns>Task</returns>
        [SkippableTheory]
        [MemberData(nameof(AllTargets))]
        public async Task Issue184_時刻クレームが数値である(string targetKey)
        {
            using (IdPClient client = await this.SignedInClientAsync(targetKey))
            {
                JsonResponse token = await Flows.RunAuthorizationCodeFlowAsync(client);

                Assert.Null(token.Error);

                JsonElement accessToken = Jwt.Payload(token.AccessToken);
                JsonElement idToken = Jwt.Payload(token.IdToken);

                foreach (string claim in new string[] { "exp", "nbf", "iat" })
                {
                    if (Jwt.Has(accessToken, claim))
                    {
                        this.Output.WriteLine("access_token." + claim
                            + " = " + Jwt.KindOf(accessToken, claim));

                        Assert.Equal(JsonValueKind.Number, Jwt.KindOf(accessToken, claim));
                    }

                    if (Jwt.Has(idToken, claim))
                    {
                        this.Output.WriteLine("id_token." + claim
                            + " = " + Jwt.KindOf(idToken, claim));

                        Assert.Equal(JsonValueKind.Number, Jwt.KindOf(idToken, claim));
                    }
                }
            }
        }

        /// <summary>
        /// JWTの真偽値クレームが真偽値である（#184）。
        ///
        /// OIDC Core 5.1 の email_verified / phone_number_verified は boolean。
        /// </summary>
        /// <param name="targetKey">core / netfx</param>
        /// <returns>Task</returns>
        [SkippableTheory]
        [MemberData(nameof(AllTargets))]
        public async Task Issue184_真偽値クレームが真偽値である(string targetKey)
        {
            using (IdPClient client = await this.SignedInClientAsync(targetKey))
            {
                JsonResponse token = await Flows.RunAuthorizationCodeFlowAsync(
                    client, KnownClients.MvcSample, "openid email phone");

                Assert.Null(token.Error);

                JsonElement accessToken = Jwt.Payload(token.AccessToken);

                foreach (string claim in new string[] { "email_verified", "phone_number_verified" })
                {
                    if (!Jwt.Has(accessToken, claim))
                    {
                        continue;
                    }

                    JsonValueKind kind = Jwt.KindOf(accessToken, claim);
                    this.Output.WriteLine("access_token." + claim + " = " + kind);

                    Assert.True(kind == JsonValueKind.True || kind == JsonValueKind.False,
                        claim + " が真偽値ではありません: " + kind);
                }
            }
        }

        /// <summary>
        /// UserInfoの真偽値クレームが真偽値である（#184）。
        /// </summary>
        /// <param name="targetKey">core / netfx</param>
        /// <returns>Task</returns>
        [SkippableTheory]
        [MemberData(nameof(AllTargets))]
        public async Task Issue184_UserInfoの真偽値クレームが真偽値である(string targetKey)
        {
            using (IdPClient client = await this.SignedInClientAsync(targetKey))
            {
                JsonResponse token = await Flows.RunAuthorizationCodeFlowAsync(
                    client, KnownClients.MvcSample, "openid email phone");

                Assert.Null(token.Error);

                JsonResponse userInfo = await client.UserInfoAsync(token.AccessToken);

                Assert.True(userInfo.IsJson, "UserInfoの応答がJSONではありません: " + userInfo.ToString());

                foreach (string claim in new string[] { "email_verified", "phone_number_verified" })
                {
                    JsonValueKind kind = userInfo.KindOf(claim);

                    if (kind == JsonValueKind.Undefined)
                    {
                        continue;
                    }

                    this.Output.WriteLine("userinfo." + claim + " = " + kind);

                    Assert.True(kind == JsonValueKind.True || kind == JsonValueKind.False,
                        claim + " が真偽値ではありません: " + kind);
                }
            }
        }
    }
}
