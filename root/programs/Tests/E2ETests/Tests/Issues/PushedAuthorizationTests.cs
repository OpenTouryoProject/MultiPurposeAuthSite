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
//* クラス名        ：PushedAuthorizationTests
//* クラス日本語名  ：RT PAR（RFC 9126）の /par（#229）
//*
//* 作成日時        ：－
//* 作成者          ：－
//* 更新履歴        ：－
//*
//*  日時        更新者            内容
//*  ----------  ----------------  -------------------------------------------------
//*  2026/09/24  玄人 幸道         新規（#229 : PAR のエンドポイントを追加）
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
    /// RT-229. PAR（RFC 9126）の <c>/par</c>。
    /// </summary>
    /// <remarks>
    /// **独自の `/ros` とは別の口。** `/ros` は署名付き JWT を生の本文で受け、クライアント認証をしない
    /// （後方互換のため残している。`RT-197`）。
    /// `/par` は RFC のとおり、**フォーム形式＋クライアント認証**で受け、
    /// **`request_uri` と `expires_in`** を返す。
    ///
    /// 有効期限と使い切りは、#188 で入れた仕組みをそのまま使う（`RT-188.3` / `RT-188.4`）。
    /// </remarks>
    public class PushedAuthorizationTests : TargetTestBase
    {
        /// <summary>コンストラクタ</summary>
        /// <param name="output">ITestOutputHelper</param>
        public PushedAuthorizationTests(ITestOutputHelper output) : base(output)
        {
        }

        /// <summary>Discovery から PAR の口を引く</summary>
        /// <param name="client">IdPClient</param>
        /// <returns>URL（無ければ null）</returns>
        private static async Task<string> ParEndpointAsync(IdPClient client)
        {
            JsonResponse res = await client.GetJsonAsync("/.well-known/openid-configuration");
            Assert.True(res.IsJson, "前提: Discovery 文書が JSON であること");
            return res.String("pushed_authorization_request_endpoint");
        }

        /// <summary>認可リクエストのパラメタ（フォーム）</summary>
        /// <param name="reg">クライアント</param>
        /// <param name="state">state</param>
        /// <returns>フォーム</returns>
        private static Dictionary<string, string> Parameters(ClientRegistration reg, string state)
        {
            return new Dictionary<string, string>()
            {
                { "response_type", "code" },
                { "redirect_uri", reg.RedirectUri },
                { "scope", "openid email" },
                { "state", state },
                { "nonce", "nonce-" + state },
                { "prompt", "none" }
            };
        }

        /// <summary>RT-229.1 /par に預けた要求で認可できる</summary>
        /// <param name="targetKey">core / netfx</param>
        /// <returns>Task</returns>
        [SkippableTheory]
        [MemberData(nameof(AllTargets))]
        public async Task RT229_01_parに預けた要求で認可できる(string targetKey)
        {
            using (IdPClient client = await this.SignedInClientAsync(targetKey))
            {
                ClientRegistration reg = Flows.Registration(client, KnownClients.TestClient);

                TestReport r = this.Report("RT-229.1",
                    "/par に認可要求を預けると request_uri と expires_in が返り、その request_uri で認可できる",
                    "**PAR は、認可要求をブラウザ経由ではなく、先にサーバ同士で預ける仕組み。**"
                    + "URL に載らないので改ざんされず、長い要求も送れる。FAPI 2.0 は PAR を必須としている。"
                    + "独自の `/ros` と違い、**クライアント認証**を行い、応答は **`expires_in`**（秒）を返す。",
                    "RFC 9126 §2 / §2.2 / #229");

                r.Target(client.Target.DisplayName + " / client_name=" + KnownClients.TestClient);

                r.Step("(1) Discovery から pushed_authorization_request_endpoint を引く");

                string endpoint = await PushedAuthorizationTests.ParEndpointAsync(client);

                r.Verify("PAR の口が広告されている", !string.IsNullOrEmpty(endpoint),
                    "URL が載る", endpoint ?? "**無し**");

                Assert.False(string.IsNullOrEmpty(endpoint), "前提: PAR の口が広告されていること");

                r.Step("(2) client_secret_basic で認証し、認可要求を預ける");

                JsonResponse par = await client.PostJsonWithBasicAuthAsync(
                    client.ToLocalUrl(endpoint),
                    PushedAuthorizationTests.Parameters(reg, "state-rt2291"),
                    reg.ClientId, reg.ClientSecret);

                r.VerifyEqual("HTTP 201", "201", ((int)par.StatusCode).ToString());

                string requestUri = par.String("request_uri");

                r.Verify("request_uri が返る", !string.IsNullOrEmpty(requestUri),
                    "request_uri あり",
                    string.IsNullOrEmpty(requestUri) ? "**無し**（error=" + (par.Error ?? "なし") + "）" : "あり");

                r.Verify("expires_in（秒）が返る",
                    par.Json.TryGetProperty("expires_in", out JsonElement _),
                    "expires_in あり", par.String("expires_in") ?? "**無し**");

                Assert.False(string.IsNullOrEmpty(requestUri), "前提: request_uri が返ること");

                r.Step("(3) その request_uri で認可する");

                AuthZResponse authz = await client.AuthorizeAsync(new Dictionary<string, string>()
                {
                    { "client_id", reg.ClientId },
                    { "request_uri", requestUri }
                });

                r.Verify("認可コードが返る", !string.IsNullOrEmpty(authz.Code),
                    "code あり",
                    string.IsNullOrEmpty(authz.Code)
                        ? "**無し**（error=" + (authz.Error ?? "なし") + "）" : "あり（値は伏せる）");

                r.VerifyEqual("state がそのまま返る", "state-rt2291", authz.State ?? "（無し）");

                r.Done();
            }
        }

        /// <summary>RT-229.2 クライアント認証が要る</summary>
        /// <param name="targetKey">core / netfx</param>
        /// <returns>Task</returns>
        [SkippableTheory]
        [MemberData(nameof(AllTargets))]
        public async Task RT229_02_クライアント認証が要る(string targetKey)
        {
            using (IdPClient client = await this.SignedInClientAsync(targetKey))
            {
                ClientRegistration reg = Flows.Registration(client, KnownClients.TestClient);

                TestReport r = this.Report("RT-229.2",
                    "/par は、クライアント認証がなければ受け付けない",
                    "**これが独自の `/ros` との一番の違い。**"
                    + "`/ros` は Request Object の署名だけで受け付けるので、"
                    + "**登録済みの鍵を持たないクライアントでも、誰の要求かを主張できてしまう。**"
                    + "PAR は、トークン エンドポイントと同じクライアント認証を求めている（RFC 9126 §2）。",
                    "RFC 9126 §2 / §2.3 / #229");

                r.Target(client.Target.DisplayName + " / client_name=" + KnownClients.TestClient);

                string endpoint = await PushedAuthorizationTests.ParEndpointAsync(client);
                Assert.False(string.IsNullOrEmpty(endpoint), "前提: PAR の口が広告されていること");

                r.Step("(1) 資格情報を付けずに預ける");

                Dictionary<string, string> form =
                    PushedAuthorizationTests.Parameters(reg, "state-rt2292");
                form["client_id"] = reg.ClientId;

                JsonResponse none = await client.PostJsonAsync(client.ToLocalUrl(endpoint), form);

                r.VerifyEqual("HTTP 401", "401", ((int)none.StatusCode).ToString());
                r.VerifyEqual("エラーは invalid_client", "invalid_client", none.Error ?? "（無し）");
                r.Verify("request_uri を返さない", string.IsNullOrEmpty(none.String("request_uri")),
                    "返さない",
                    string.IsNullOrEmpty(none.String("request_uri")) ? "返さなかった" : "**返してしまった**");

                r.Step("(2) 誤った client_secret で預ける");

                JsonResponse wrong = await client.PostJsonWithBasicAuthAsync(
                    client.ToLocalUrl(endpoint),
                    PushedAuthorizationTests.Parameters(reg, "state-rt2292b"),
                    reg.ClientId, "wrong-secret");

                r.VerifyEqual("HTTP 401", "401", ((int)wrong.StatusCode).ToString());
                r.VerifyEqual("エラーは invalid_client", "invalid_client", wrong.Error ?? "（無し）");

                r.Done();
            }
        }

        /// <summary>RT-229.3 request（JAR）でも預けられる</summary>
        /// <param name="targetKey">core / netfx</param>
        /// <returns>Task</returns>
        [SkippableTheory]
        [MemberData(nameof(AllTargets))]
        public async Task RT229_03_requestのJARでも預けられる(string targetKey)
        {
            using (IdPClient client = await this.SignedInClientAsync(targetKey))
            {
                ClientRegistration reg = Flows.Registration(client, KnownClients.TestClient);

                TestReport r = this.Report("RT-229.3",
                    "/par は、フォームの request に署名付き Request Object（JAR）を入れる形でも受け付ける",
                    "**FAPI 2.0 の実運用では、PAR に JAR を入れて送る形が多い。**"
                    + "この実装は、`request` があればその中身を、無ければフォームの個別パラメタを預かる。"
                    + "**署名の検証に加えて、クライアント認証も行う**ので、"
                    + "`/ros`（署名だけ）より厳しい。",
                    "RFC 9126 §3 / RFC 9101 / #229");

                r.Target(client.Target.DisplayName + " / client_name=" + KnownClients.TestClient);

                string endpoint = await PushedAuthorizationTests.ParEndpointAsync(client);
                Assert.False(string.IsNullOrEmpty(endpoint), "前提: PAR の口が広告されていること");

                r.Step("(1) Request Object を作り、request に入れて預ける");

                string requestObject = RequestObjectBuilder.Create(
                    client, reg.ClientId, new Dictionary<string, object>()
                    {
                        { "response_type", "code" },
                        { "redirect_uri", reg.RedirectUri },
                        { "scope", "openid email" },
                        { "state", "state-rt2293" },
                        { "nonce", "nonce-rt2293" },
                        { "prompt", "none" }
                    });

                JsonResponse par = await client.PostJsonWithBasicAuthAsync(
                    client.ToLocalUrl(endpoint),
                    new Dictionary<string, string>() { { "request", requestObject } },
                    reg.ClientId, reg.ClientSecret);

                r.VerifyEqual("HTTP 201", "201", ((int)par.StatusCode).ToString());

                string requestUri = par.String("request_uri");

                r.Verify("request_uri が返る", !string.IsNullOrEmpty(requestUri),
                    "request_uri あり",
                    string.IsNullOrEmpty(requestUri) ? "**無し**（error=" + (par.Error ?? "なし") + "）" : "あり");

                Assert.False(string.IsNullOrEmpty(requestUri), "前提: request_uri が返ること");

                r.Step("(2) その request_uri で認可する");

                AuthZResponse authz = await client.AuthorizeAsync(new Dictionary<string, string>()
                {
                    { "client_id", reg.ClientId },
                    { "request_uri", requestUri }
                });

                r.Verify("認可コードが返る", !string.IsNullOrEmpty(authz.Code),
                    "code あり",
                    string.IsNullOrEmpty(authz.Code)
                        ? "**無し**（error=" + (authz.Error ?? "なし") + "）" : "あり（値は伏せる）");

                r.Done();
            }
        }

        /// <summary>RT-229.4 /par に request_uri は渡せない</summary>
        /// <param name="targetKey">core / netfx</param>
        /// <returns>Task</returns>
        [SkippableTheory]
        [MemberData(nameof(AllTargets))]
        public async Task RT229_04_parにrequest_uriは渡せない(string targetKey)
        {
            using (IdPClient client = await this.SignedInClientAsync(targetKey))
            {
                ClientRegistration reg = Flows.Registration(client, KnownClients.TestClient);

                TestReport r = this.Report("RT-229.4",
                    "/par に request_uri を渡すと invalid_request になる",
                    "**預ける口に、預けた結果を渡させない。**"
                    + "RFC 9126 §2.1 は、PAR の要求に `request_uri` を含めてはならないとしている"
                    + "（入れ子にすると、検証の前提が崩れる）。",
                    "RFC 9126 §2.1 / #229");

                r.Target(client.Target.DisplayName + " / client_name=" + KnownClients.TestClient);

                string endpoint = await PushedAuthorizationTests.ParEndpointAsync(client);
                Assert.False(string.IsNullOrEmpty(endpoint), "前提: PAR の口が広告されていること");

                r.Step("request_uri を付けて預ける");

                Dictionary<string, string> form =
                    PushedAuthorizationTests.Parameters(reg, "state-rt2294");
                form["request_uri"] = "urn:ietf:params:oauth:request_uri:dummy";

                JsonResponse par = await client.PostJsonWithBasicAuthAsync(
                    client.ToLocalUrl(endpoint), form, reg.ClientId, reg.ClientSecret);

                r.VerifyEqual("HTTP 400", "400", ((int)par.StatusCode).ToString());
                r.VerifyEqual("エラーは invalid_request", "invalid_request", par.Error ?? "（無し）");

                r.Done();
            }
        }
    }
}
