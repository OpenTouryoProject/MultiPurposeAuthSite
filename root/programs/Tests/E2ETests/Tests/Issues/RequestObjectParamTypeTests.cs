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
//* クラス名        ：RequestObjectParamTypeTests
//* クラス日本語名  ：RT-377 Request Object の中の、認可要求の値が文字列でなければ、預からない
//*
//* 作成日時        ：－
//* 作成者          ：－
//* 更新履歴        ：－
//*
//*  日時        更新者            内容
//*  ----------  ----------------  -------------------------------------------------
//*  2026/11/18  玄人 幸道         新規（#377）
//**********************************************************************************

using System.Collections.Generic;
using System.Threading.Tasks;

using MultiPurposeAuthSite.Tests.E2E.Infrastructure;

using Xunit;
using Xunit.Abstractions;

namespace MultiPurposeAuthSite.Tests.E2E.Tests.Issues
{
    /// <summary>
    /// RT-377. **Request Object の中の認可要求の値（`redirect_uri`・`state`・`nonce`・`dpop_jkt` など）が文字列でなければ、PAR・`/ros` は預からない**（`max_age` は整数も受ける）。
    /// </summary>
    /// <remarks>
    /// **預けた中身から、PAR・`/authorize`・`AuthorizationCodeProvider` がこれらを文字列として読む。**
    /// **以前は型を見ずに預かり、配列・オブジェクトだと、`nonce`・`prompt`・`response_mode` は PAR そのものが、
    /// `state`・`max_age`・`dpop_jkt` などはその `request_uri` で `/authorize` に行ったときに 500（net48 はエラー画面）になっていた**（#377）。
    /// **数値も断る**（以前は `"123"` として code に縛られ、引き換えられない code が出ていた）。
    ///
    /// | | 測ること |
    /// |---|---|
    /// | **`RT-377.1`** | **PAR**：値が配列・オブジェクト・数値なら 400 ＋ `invalid_request_object`（断る理由にその名前が出る）。文字列・整数の `max_age`・**日付の形の文字列**なら 201 |
    /// | **`RT-377.2`** | **`/ros`**：`dpop_jkt` が配列なら `request_uri` を返さない。文字列（日付の形を含む）なら返す |
    ///
    /// - **`/authorize` が 500 にならないこと**は、直接は測れない（文字列でない値を、もう預けられない）。
    ///   `AuthorizationCodeProvider` の読み方も、文字列でなければ無いのと同じに扱う形にした（念のための守り）
    /// </remarks>
    public class RequestObjectParamTypeTests : TargetTestBase
    {
        /// <summary>コンストラクタ</summary>
        /// <param name="output">ITestOutputHelper</param>
        public RequestObjectParamTypeTests(ITestOutputHelper output) : base(output)
        {
        }

        #region RT-377.1

        /// <summary>RT-377.1 PAR は、認可コードに縛る値が文字列でない Request Object を預からない</summary>
        /// <param name="targetKey">core / netfx</param>
        /// <returns>Task</returns>
        [SkippableTheory]
        [MemberData(nameof(AllTargets))]
        public async Task RT37701_PARは認可コードに縛る値が文字列でないRequestObjectを預からない(string targetKey)
        {
            using (IdPClient client = this.Client(targetKey))
            {
                TestReport r = this.Report("RT-377.1",
                    "PAR に預ける Request Object の中の認可要求の値（redirect_uri・code_challenge・code_challenge_method・dpop_jkt・nonce・prompt・response_mode・state・max_age）が文字列でなければ、400 ＋ invalid_request_object。文字列・整数の max_age なら 201",
                    "**これらは、預けた中身から文字列として読まれる。**"
                    + "**以前は型を見ずに預かり、配列・オブジェクトだと、PAR そのもの（nonce・prompt・response_mode）か /authorize（state・max_age・dpop_jkt など）が 500（net48 はエラー画面）になっていた。**"
                    + "**数値の dpop_jkt は、引き換えられない code を出していた**（dpop_jkt は鍵の指紋の文字列。RFC 9449 §10）。"
                    + "**max_age は秒数なので、整数も受ける**（OIDC Core 1.0 §3.1.2.1）。",
                    "RFC 9101 §7 / RFC 9449 §10 / OIDC Core 1.0 §3.1.2.1 / #377");

                ClientRegistration reg = Flows.Registration(client, KnownClients.TestClient);
                string endpoint = await RequestObjectParamTypeTests.ParEndpointAsync(client);

                r.Target("POST /par（client_name=" + KnownClients.TestClient + "。client_secret_basic。request に署名付き JWT）");

                r.Step("(1) 対照：文字列の dpop_jkt は 201");

                JsonResponse control = await RequestObjectParamTypeTests.ParAsync(client, reg, endpoint, "dpop_jkt", "e2e-rt3771-thumbprint");

                r.VerifyEqual("文字列の dpop_jkt : HTTP 201", "201", ((int)control.StatusCode).ToString());

                JsonResponse intMaxAge = await RequestObjectParamTypeTests.ParAsync(client, reg, endpoint, "max_age", 3600);

                r.VerifyEqual("整数の max_age : HTTP 201", "201", ((int)intMaxAge.StatusCode).ToString());

                //  **日付の形の文字列も文字列である**（既定の JSON の読み方は Date にする。OpenTouryo#662。別モデルのレビューの指摘）。
                foreach (string name in new string[] { "nonce", "state" })
                {
                    JsonResponse dateLike = await RequestObjectParamTypeTests.ParAsync(client, reg, endpoint, name, "2026-11-18T10:00:00Z");

                    r.VerifyEqual("日付の形の " + name + " : HTTP 201", "201", ((int)dateLike.StatusCode).ToString());
                }

                r.Step("(2) 文字列でない値を入れる");

                foreach (KeyValuePair<string, object[]> c in new Dictionary<string, object[]>()
                {
                    { "配列の dpop_jkt", new object[] { "dpop_jkt", new string[] { "x" } } },
                    { "オブジェクトの dpop_jkt", new object[] { "dpop_jkt", new Dictionary<string, object>() { { "a", "b" } } } },
                    { "数値の dpop_jkt", new object[] { "dpop_jkt", 123 } },
                    { "配列の redirect_uri", new object[] { "redirect_uri", new string[] { reg.RedirectUri } } },
                    { "オブジェクトの code_challenge", new object[] { "code_challenge", new Dictionary<string, object>() { { "a", "b" } } } },
                    { "数値の code_challenge_method", new object[] { "code_challenge_method", 256 } },
                    { "オブジェクトの nonce", new object[] { "nonce", new Dictionary<string, object>() { { "a", "b" } } } },
                    { "配列の prompt", new object[] { "prompt", new string[] { "login" } } },
                    { "配列の response_mode", new object[] { "response_mode", new string[] { "query" } } },
                    { "配列の state", new object[] { "state", new string[] { "s" } } },
                    { "配列の max_age", new object[] { "max_age", new string[] { "1" } } }
                })
                {
                    string name = (string)c.Value[0];
                    JsonResponse res = await RequestObjectParamTypeTests.ParAsync(client, reg, endpoint, name, c.Value[1]);

                    r.VerifyEqual(c.Key + " : HTTP 400", "400", ((int)res.StatusCode).ToString());
                    r.VerifyEqual(c.Key + " : invalid_request_object", "invalid_request_object", res.Error ?? "（無い）");

                    //  **署名・alg・ほかの値で先に断られたのではないこと**（理由がその値であること）。
                    string description = res.String("error_description") ?? "";
                    bool reason = description.Contains(name) && description.Contains("must be a string");

                    r.Verify(c.Key + " : 断る理由は " + name + " の型", reason,
                        name, reason ? name : "**" + description + "**");
                }

                r.Done();
            }
        }

        #endregion

        #region RT-377.2

        /// <summary>RT-377.2 /ros は、dpop_jkt が文字列でない Request Object を預からない</summary>
        /// <param name="targetKey">core / netfx</param>
        /// <returns>Task</returns>
        [SkippableTheory]
        [MemberData(nameof(AllTargets))]
        public async Task RT37702_rosはdpop_jktが文字列でないRequestObjectを預からない(string targetKey)
        {
            using (IdPClient client = this.Client(targetKey))
            {
                TestReport r = this.Report("RT-377.2",
                    "/ros : dpop_jkt が文字列でない Request Object を預からない（PAR と同じ扱い）。文字列なら預かる",
                    "**/ros も、預けた request_uri を /authorize で使う**ので、PAR と同じく型を確かめる。"
                    + "**以前は型を見ずに預かっていた**（#377）。",
                    "RFC 9101 §7 / RFC 9449 §10 / #377");

                ClientRegistration reg = Flows.Registration(client, KnownClients.Fapi2Client);

                r.Target("POST /ros（iss=" + KnownClients.Fapi2Client + "）");

                r.Step("(1) dpop_jkt を配列にした Request Object を預ける");

                string rejected = await RequestObjectBuilder.RegisterAsync(client,
                    await RequestObjectParamTypeTests.FapiRequestObjectAsync(client, reg, new string[] { "x" }));

                r.Verify("request_uri を返さない", string.IsNullOrEmpty(rejected),
                    "返さない", string.IsNullOrEmpty(rejected) ? "返さない" : "**返した**");

                r.Step("(2) 対照：文字列の dpop_jkt なら預かる（日付の形の文字列も）");

                foreach (string jkt in new string[] { "e2e-rt3772-thumbprint", "2026-11-18T10:00:00Z" })
                {
                    string accepted = await RequestObjectBuilder.RegisterAsync(client,
                        await RequestObjectParamTypeTests.FapiRequestObjectAsync(client, reg, jkt));

                    r.Verify("dpop_jkt=" + jkt + " : request_uri を返す", !string.IsNullOrEmpty(accepted),
                        "返す", string.IsNullOrEmpty(accepted) ? "**返さない**" : "返した");
                }

                r.Done();
            }
        }

        #endregion

        #region 補助

        /// <summary>Discovery が広告する PAR の口</summary>
        /// <param name="client">IdPClient</param>
        /// <returns>URL（ローカルの URL に直したもの）</returns>
        private static async Task<string> ParEndpointAsync(IdPClient client)
        {
            JsonResponse res = await client.GetJsonAsync("/.well-known/openid-configuration");
            string endpoint = res.String("pushed_authorization_request_endpoint");

            Assert.False(string.IsNullOrEmpty(endpoint), "前提: PAR の口が広告されていること");

            return client.ToLocalUrl(endpoint);
        }

        /// <summary>1 つの値を差し替えた Request Object を作って PAR に預ける</summary>
        /// <param name="client">IdPClient</param>
        /// <param name="reg">クライアント</param>
        /// <param name="endpoint">PAR の口</param>
        /// <param name="name">差し替える値の名前</param>
        /// <param name="value">値</param>
        /// <returns>応答</returns>
        private static async Task<JsonResponse> ParAsync(
            IdPClient client, ClientRegistration reg, string endpoint, string name, object value)
        {
            Dictionary<string, object> parameters = new Dictionary<string, object>()
            {
                { "response_type", "code" },
                { "redirect_uri", reg.RedirectUri },
                { "scope", "openid" },
                { "state", "state-rt3771" },
                { "nonce", "nonce-rt3771" }
            };

            parameters[name] = value;

            string requestObject = await RequestObjectBuilder.CreateAsync(client, reg.ClientId, parameters);

            return await client.PostJsonWithBasicAuthAsync(
                endpoint, new Dictionary<string, string>() { { "request", requestObject } }, reg.ClientId, reg.ClientSecret);
        }

        /// <summary>dpop_jkt を入れた FAPI の Request Object を作る（/ros 用）</summary>
        /// <param name="client">IdPClient</param>
        /// <param name="reg">クライアント</param>
        /// <param name="dpopJkt">dpop_jkt</param>
        /// <returns>JWS</returns>
        private static Task<string> FapiRequestObjectAsync(IdPClient client, ClientRegistration reg, object dpopJkt)
        {
            return RequestObjectBuilder.CreateFapiAsync(client, reg.ClientId, new Dictionary<string, object>()
            {
                { "response_type", "code" },
                { "scope", "openid" },
                { "redirect_uri", reg.RedirectUri },
                { "state", "state-rt3772" },
                { "nonce", "nonce-rt3772" },
                { "dpop_jkt", dpopJkt }
            });
        }

        #endregion
    }
}
