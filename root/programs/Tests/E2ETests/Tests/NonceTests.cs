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
//* クラス名        ：NonceTests
//* クラス日本語名  ：nonceの扱いの回帰テスト（#183 / #190 / #191）
//*
//* 作成日時        ：－
//* 作成者          ：－
//* 更新履歴        ：－
//*
//*  日時        更新者            内容
//*  ----------  ----------------  -------------------------------------------------
//*  2026/09/08  玄人 幸道         新規（E2Eテスト基盤）
//**********************************************************************************

using System.Collections.Generic;
using System.Text.Json;
using System.Threading.Tasks;

using MultiPurposeAuthSite.Tests.E2E.Infrastructure;

using Xunit;
using Xunit.Abstractions;

namespace MultiPurposeAuthSite.Tests.E2E.Tests
{
    /// <summary>
    /// nonce の扱いの回帰テスト。
    ///
    /// - Authorization Code フローでは nonce は任意（OIDC Core 3.1.2.1）
    /// - Implicit / Hybrid フローでは必須（OIDC Core 3.2.2.1 / 3.3.2.1）
    /// - id_token の nonce は「認可リクエストで送られた値をそのまま」（OIDC Core 3.1.3.6）
    /// </summary>
    public class NonceTests : TargetTestBase
    {
        /// <summary>コンストラクタ</summary>
        /// <param name="output">ITestOutputHelper</param>
        public NonceTests(ITestOutputHelper output) : base(output)
        {
        }

        /// <summary>
        /// nonce なしの Authorization Code フローでも id_token が返る（#183）。
        /// </summary>
        /// <param name="targetKey">core / netfx</param>
        /// <returns>Task</returns>
        [SkippableTheory]
        [MemberData(nameof(AllTargets))]
        public async Task Issue183_nonceなしでもid_tokenが返る(string targetKey)
        {
            using (IdPClient client = await this.SignedInClientAsync(targetKey))
            {
                JsonResponse token = await Flows.RunAuthorizationCodeFlowAsync(
                    client, KnownClients.MvcSample, "openid email", null);

                this.Output.WriteLine(token.ToString());

                Assert.Null(token.Error);
                Assert.False(string.IsNullOrEmpty(token.IdToken), "id_token が返っていません。");
            }
        }

        /// <summary>
        /// nonce を送らなかったとき、id_token に nonce クレームを作らない（#191）。
        ///
        /// 以前は state を nonce として詰めていた。
        /// クライアントは nonce を送っていないので、検証しようがない値が入ることになる。
        /// </summary>
        /// <param name="targetKey">core / netfx</param>
        /// <returns>Task</returns>
        [SkippableTheory]
        [MemberData(nameof(AllTargets))]
        public async Task Issue191_nonceを送らなければnonceクレームは付かない(string targetKey)
        {
            using (IdPClient client = await this.SignedInClientAsync(targetKey))
            {
                JsonResponse token = await Flows.RunAuthorizationCodeFlowAsync(
                    client, KnownClients.MvcSample, "openid email", null);

                Assert.Null(token.Error);

                JsonElement idToken = Jwt.Payload(token.IdToken);

                this.Output.WriteLine("id_token.nonce = "
                    + (Jwt.Has(idToken, "nonce") ? Jwt.String(idToken, "nonce") : "(なし)"));

                Assert.False(Jwt.Has(idToken, "nonce"),
                    "nonce を送っていないのに id_token に nonce クレームがあります。");
            }
        }

        /// <summary>
        /// nonce を送ったときは、その値がそのまま id_token に載る（#191）。
        /// </summary>
        /// <param name="targetKey">core / netfx</param>
        /// <returns>Task</returns>
        [SkippableTheory]
        [MemberData(nameof(AllTargets))]
        public async Task Issue191_送ったnonceがそのままid_tokenに載る(string targetKey)
        {
            const string Nonce = "nonce-abc-123";

            using (IdPClient client = await this.SignedInClientAsync(targetKey))
            {
                JsonResponse token = await Flows.RunAuthorizationCodeFlowAsync(
                    client, KnownClients.MvcSample, "openid email", Nonce);

                Assert.Null(token.Error);

                JsonElement idToken = Jwt.Payload(token.IdToken);

                Assert.True(Jwt.Has(idToken, "nonce"), "id_token に nonce クレームがありません。");
                Assert.Equal(Nonce, Jwt.String(idToken, "nonce"));
            }
        }

        /// <summary>
        /// Implicit フローで nonce が無ければ invalid_request（#190）。
        /// </summary>
        /// <param name="targetKey">core / netfx</param>
        /// <returns>Task</returns>
        [SkippableTheory]
        [MemberData(nameof(AllTargets))]
        public async Task Issue190_Implicitでnonce無しは拒否される(string targetKey)
        {
            using (IdPClient client = await this.SignedInClientAsync(targetKey))
            {
                ClientRegistration registration = Flows.Registration(client, KnownClients.TestClient);

                Dictionary<string, string> q = new Dictionary<string, string>()
                {
                    { "response_type", "id_token token" },
                    { "client_id", registration.ClientId },
                    { "scope", "openid" },
                    { "redirect_uri", registration.RedirectUriToken },
                    { "state", "state1" },
                    { "prompt", "none" }

                    // nonce を送らない
                };

                AuthZResponse res = await client.AuthorizeAsync(q);

                this.Output.WriteLine(res.ToString());

                Assert.Equal("invalid_request", res.Error);
            }
        }

        /// <summary>
        /// Implicit フローで nonce があれば通る（#190 が過剰に弾いていないこと）。
        /// </summary>
        /// <param name="targetKey">core / netfx</param>
        /// <returns>Task</returns>
        [SkippableTheory]
        [MemberData(nameof(AllTargets))]
        public async Task Issue190_Implicitでnonce有りは通る(string targetKey)
        {
            using (IdPClient client = await this.SignedInClientAsync(targetKey))
            {
                ClientRegistration registration = Flows.Registration(client, KnownClients.TestClient);

                Dictionary<string, string> q = new Dictionary<string, string>()
                {
                    { "response_type", "id_token token" },
                    { "client_id", registration.ClientId },
                    { "scope", "openid" },
                    { "redirect_uri", registration.RedirectUriToken },
                    { "state", "state1" },
                    { "nonce", "nonce1" },
                    { "prompt", "none" }
                };

                AuthZResponse res = await client.AuthorizeAsync(q);

                this.Output.WriteLine(res.ToString());

                Assert.Null(res.Error);

                // Implicit はフラグメントで返す（OAuth 2.0 4.2.2）。
                Assert.Equal(ParameterLocation.Fragment, res.Where);
                Assert.False(string.IsNullOrEmpty(res.Get("id_token")), "id_token がありません。");
            }
        }
    }
}
