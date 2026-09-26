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
//* クラス名        ：ClientAssertionTests
//* クラス日本語名  ：RT-238 private_key_jwt のクライアント認証（client_assertion）（#238）
//*
//* 作成日時        ：－
//* 作成者          ：－
//* 更新履歴        ：－
//*
//*  日時        更新者            内容
//*  ----------  ----------------  -------------------------------------------------
//*  2026/09/25  玄人 幸道         新規（#238）
//**********************************************************************************

using System;
using System.Collections.Generic;
using System.Net.Http;
using System.Threading.Tasks;

using MultiPurposeAuthSite.Tests.E2E.Infrastructure;

using Xunit;
using Xunit.Abstractions;

namespace MultiPurposeAuthSite.Tests.E2E.Tests.Issues
{
    /// <summary>
    /// RT-238. `private_key_jwt` のクライアント認証（RFC 7523 §2.2）。
    /// </summary>
    /// <remarks>
    /// **仕様の名前は `client_assertion`**（＋ `client_assertion_type`）。
    /// `assertion` は **JWT Bearer グラント**（§2.1）のパラメタで、別物である。
    ///
    /// この実装は 3 つの口（`/token`・`/par`・`/ciba_authz`）で `assertion` を読んでいたため、
    /// **仕様に従うクライアントが private_key_jwt で認証できなかった**（#238）。
    /// **E2E に private_key_jwt の認証を測るテストが無かった**ので、気付けていなかった。
    ///
    /// **両方を受ける**（`client_assertion` を優先し、無ければ `assertion`）。
    /// Open棟梁 の既存のクライアントは `assertion` を送るため（OpenTouryo #592）。
    ///
    /// アサーションの `aud` は、**トークン エンドポイントの URL**でなければならない
    /// （`CmnEndpoints.ClientAuthentication` の実装。`/par` や `/ciba_authz` へ送るときも同じ）。
    /// </remarks>
    public class ClientAssertionTests : TargetTestBase
    {
        /// <summary>コンストラクタ</summary>
        /// <param name="output">ITestOutputHelper</param>
        public ClientAssertionTests(ITestOutputHelper output) : base(output)
        {
        }

        /// <summary>client_assertion（RS256 で署名した JWT）を作る</summary>
        /// <param name="client">IdPClient</param>
        /// <param name="clientId">client_id</param>
        /// <returns>JWS</returns>
        /// <remarks>
        /// RFC 7523 §3 : `iss` / `sub` はクライアントの識別子、`aud` は認可サーバ。
        /// **この実装は `aud` にトークン エンドポイントの URL を求める。**
        /// </remarks>
        private static string CreateClientAssertion(IdPClient client, string clientId)
        {
            long now = DateTimeOffset.UtcNow.ToUnixTimeSeconds();

            return JwsSigner.SignRS256(client, new Dictionary<string, object>()
            {
                { "iss", clientId },
                { "sub", clientId },
                { "aud", client.Target.BaseUrl + "/token" },
                { "jti", Guid.NewGuid().ToString("N") },
                { "iat", now },
                { "exp", now + 300 }
            });
        }

        /// <summary>RT-238.1 client_assertion で /par に預けられる</summary>
        /// <param name="targetKey">core / netfx</param>
        /// <returns>Task</returns>
        [SkippableTheory]
        [MemberData(nameof(AllTargets))]
        public async Task RT23801_client_assertionでparに預けられる(string targetKey)
        {
            using (IdPClient client = this.Client(targetKey))
            {
                ClientRegistration reg = Flows.Registration(client, KnownClients.TestClient2);

                TestReport r = this.Report("RT-238.1",
                    "RFC 7523 §2.2 の client_assertion で、private_key_jwt のクライアント認証が通る",
                    "**仕様の名前は `client_assertion`**（＋ `client_assertion_type`）。"
                    + "この実装は `assertion` だけを読んでいたため、"
                    + "**仕様に従うクライアントは private_key_jwt で認証できなかった**（#238）。"
                    + "Open棟梁 の PAR / CIBA のクライアント（OpenTouryo#592）は `client_assertion` を送る。",
                    "RFC 7523 §2.2 / RFC 9126 §2 / #238");

                r.Target("client_name=" + KnownClients.TestClient2 + "（fapi2。jwk_rsa_publickey を登録済み）");

                r.Step("(1) client_assertion（RS256）を作り、client_assertion_type を添えて POST /par");

                JsonResponse res = await client.PostJsonAsync("/par", new Dictionary<string, string>()
                {
                    { "client_id", reg.ClientId },
                    { "client_assertion", ClientAssertionTests.CreateClientAssertion(client, reg.ClientId) },
                    { "client_assertion_type", "urn:ietf:params:oauth:client-assertion-type:jwt-bearer" },
                    { "response_type", "code" },
                    { "scope", "openid" },
                    { "redirect_uri", reg.RedirectUri },
                    { "state", "state1" }
                });

                r.VerifyEqual("HTTP 201（RFC 9126 §2.2）", "201", ((int)res.StatusCode).ToString());

                string requestUri = res.String("request_uri");

                r.Verify("request_uri が返る", !string.IsNullOrEmpty(requestUri),
                    "request_uri あり", string.IsNullOrEmpty(requestUri) ? res.ToString() : "あり");

                r.Note("**client_secret は送っていない。** 署名したアサーションだけで認証している。");

                r.Done();
            }
        }

        /// <summary>RT-238.2 従来の assertion でも通る（後方互換）</summary>
        /// <param name="targetKey">core / netfx</param>
        /// <returns>Task</returns>
        [SkippableTheory]
        [MemberData(nameof(AllTargets))]
        public async Task RT23802_従来のassertionでも通る(string targetKey)
        {
            using (IdPClient client = this.Client(targetKey))
            {
                ClientRegistration reg = Flows.Registration(client, KnownClients.TestClient2);

                TestReport r = this.Report("RT-238.2",
                    "従来の名前（assertion）でも、private_key_jwt のクライアント認証が通る",
                    "**Open棟梁 の既存のクライアントは `assertion` を送る**"
                    + "（`GetAccessTokenByCodeAsync` の private_key_jwt）。"
                    + "名前を仕様に合わせるだけだと、**既存のクライアントが繋がらなくなる。**"
                    + "`client_assertion` を優先し、**無ければ `assertion` も読む。**",
                    "RFC 7523 §2.2 / #238");

                r.Target("client_name=" + KnownClients.TestClient2 + "（assertion という名前で送る）");

                r.Step("(1) assertion（従来の名前）で POST /par");

                JsonResponse res = await client.PostJsonAsync("/par", new Dictionary<string, string>()
                {
                    { "client_id", reg.ClientId },
                    { "assertion", ClientAssertionTests.CreateClientAssertion(client, reg.ClientId) },
                    { "response_type", "code" },
                    { "scope", "openid" },
                    { "redirect_uri", reg.RedirectUri },
                    { "state", "state1" }
                });

                r.VerifyEqual("HTTP 201", "201", ((int)res.StatusCode).ToString());

                r.Verify("request_uri が返る", !string.IsNullOrEmpty(res.String("request_uri")),
                    "request_uri あり", string.IsNullOrEmpty(res.String("request_uri")) ? res.ToString() : "あり");

                r.Done();
            }
        }

        /// <summary>RT-238.3 client_assertion_type が違えば断る</summary>
        /// <param name="targetKey">core / netfx</param>
        /// <returns>Task</returns>
        [SkippableTheory]
        [MemberData(nameof(AllTargets))]
        public async Task RT23803_client_assertion_typeが違えば断る(string targetKey)
        {
            using (IdPClient client = this.Client(targetKey))
            {
                ClientRegistration reg = Flows.Registration(client, KnownClients.TestClient2);

                TestReport r = this.Report("RT-238.3",
                    "client_assertion_type が仕様の値でなければ、クライアント認証を通さない",
                    "**RFC 7523 §2.2 は型を URN で定めている**"
                    + "（`urn:ietf:params:oauth:client-assertion-type:jwt-bearer`）。"
                    + "型が違うものを受け付けると、**別の種類のアサーションを取り違える**。"
                    + "**省略されていれば受ける**（この実装は従来、型を見ていなかったため）。",
                    "RFC 7523 §2.2 / #238");

                r.Target("client_name=" + KnownClients.TestClient2 + "（client_assertion_type だけ誤り）");

                r.Step("(1) client_assertion_type に別の URN を入れて POST /par");

                JsonResponse res = await client.PostJsonAsync("/par", new Dictionary<string, string>()
                {
                    { "client_id", reg.ClientId },
                    { "client_assertion", ClientAssertionTests.CreateClientAssertion(client, reg.ClientId) },
                    { "client_assertion_type", "urn:ietf:params:oauth:grant-type:jwt-bearer" },
                    { "response_type", "code" },
                    { "scope", "openid" },
                    { "redirect_uri", reg.RedirectUri },
                    { "state", "state1" }
                });

                r.VerifyEqual("HTTP 401", "401", ((int)res.StatusCode).ToString());

                r.VerifyEqual("エラーは invalid_client", "invalid_client", res.Error ?? "（無し）");

                r.Verify("request_uri は返らない", string.IsNullOrEmpty(res.String("request_uri")),
                    "返らない", string.IsNullOrEmpty(res.String("request_uri")) ? "返らなかった" : "**返した**");

                r.Note("**型が違うときは「アサーション無し」として扱う**ので、"
                    + "クライアント認証の失敗（invalid_client）になる。");

                r.Done();
            }
        }

        /// <summary>RT-238.4 /token でも client_assertion が通る</summary>
        /// <param name="targetKey">core / netfx</param>
        /// <returns>Task</returns>
        [SkippableTheory]
        [MemberData(nameof(AllTargets))]
        public async Task RT23804_tokenでもclient_assertionが通る(string targetKey)
        {
            using (IdPClient client = await this.SignedInClientAsync(targetKey))
            {
                ClientRegistration reg = Flows.Registration(client, KnownClients.TestClient2);

                TestReport r = this.Report("RT-238.4",
                    "トークン エンドポイントでも、client_assertion で認証してトークンを得られる",
                    "**FAPI 2.0 は、クライアント認証を private_key_jwt か mTLS に限っている。**"
                    + "fapi2 の登録は client_secret を通さない（`FA-2.1`）ので、"
                    + "**この経路が通らないと、fapi2 のクライアントはトークンを得られない。**",
                    "RFC 7523 §2.2 / FAPI 2.0 / #238");

                r.Target("client_name=" + KnownClients.TestClient2 + "（fapi2。JAR で認可し、private_key_jwt で交換）");

                r.Step("(1) FAPI2 の自己テストで、request_uri 経路の code を得る");

                HttpResponseMessage starter = await client.StartSelfTestAsync(
                    "AuthorizationCodeFAPI2", "fapi2");

                string location = (starter.Headers.Location == null)
                    ? null : starter.Headers.Location.OriginalString;

                Skip.If(string.IsNullOrEmpty(location),
                    "FAPI2 の自己テストが動かない（起動 URL の食い違い。RT-197.1 を見ること）。");

                AuthZResponse authz = await client.AuthorizeAndGrantAsync(client.ToLocalUrl(location));

                Assert.False(string.IsNullOrEmpty(authz.Code), "前提: code が発行されること");

                r.Step("(2) client_assertion を添えて、code をトークンに交換する");

                JsonResponse token = await client.TokenAsync(new Dictionary<string, string>()
                {
                    { "grant_type", "authorization_code" },
                    { "code", authz.Code },
                    { "client_assertion", ClientAssertionTests.CreateClientAssertion(client, reg.ClientId) },
                    { "client_assertion_type", "urn:ietf:params:oauth:client-assertion-type:jwt-bearer" },
                    { "redirect_uri", reg.RedirectUri }
                });

                r.Observe("応答", token.ToString(), "切り分け用（値は伏せられる）。");

                r.VerifyEqual("HTTP 200", "200", ((int)token.StatusCode).ToString());

                r.Verify("access_token が返る", !string.IsNullOrEmpty(token.AccessToken),
                    "access_token あり",
                    string.IsNullOrEmpty(token.AccessToken) ? token.ToString() : "あり（値は伏せる）");

                r.Note("**client_secret は送っていない**（fapi2 の登録は受け付けない）。"
                    + "`client_id` も送っていない（アサーションの `iss` から引く）。");

                r.Done();
            }
        }
    }
}
