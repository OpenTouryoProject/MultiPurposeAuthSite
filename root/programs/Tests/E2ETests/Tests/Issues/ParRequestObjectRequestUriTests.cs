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
//* クラス名        ：ParRequestObjectRequestUriTests
//* クラス日本語名  ：RT-380 PAR の Request Object の中の request_uri を断る（RFC 9126 §2.1）
//*
//* 作成日時        ：－
//* 作成者          ：－
//* 更新履歴        ：－
//*
//*  日時        更新者            内容
//*  ----------  ----------------  -------------------------------------------------
//*  2026/11/17  玄人 幸道         新規（#380）
//**********************************************************************************

using System.Collections.Generic;
using System.Threading.Tasks;

using MultiPurposeAuthSite.Tests.E2E.Infrastructure;

using Xunit;
using Xunit.Abstractions;

namespace MultiPurposeAuthSite.Tests.E2E.Tests.Issues
{
    /// <summary>
    /// RT-380. **PAR に預ける Request Object（`request`）の中に `request_uri` が在れば、断る**（RFC 9126 §2.1・§3）。
    /// </summary>
    /// <remarks>
    /// **RFC 9126 §2.1 は、PAR の要求で `request_uri` を使うことを禁じる（MUST NOT）。Request Object で預ける形（§3）も PAR の要求である。**
    /// **以前は、フォームの `request_uri` だけを断り、Request Object の中は見ていなかった**
    /// （適合性テストの `par-authorization-request-containing-request_uri`：期待 400、実際 201）。
    ///
    /// | | 測ること |
    /// |---|---|
    /// | **`RT-380.1`** | **Request Object の中に `request_uri` が在れば（空文字も）`400` ＋ `invalid_request_object`**（RFC 9101 §7。理由が `request_uri` であることも確かめる）。**`request_uri` の無い Request Object は `201`。フォームの `request_uri` は従来どおり `invalid_request`** |
    /// </remarks>
    public class ParRequestObjectRequestUriTests : TargetTestBase
    {
        /// <summary>コンストラクタ</summary>
        /// <param name="output">ITestOutputHelper</param>
        public ParRequestObjectRequestUriTests(ITestOutputHelper output) : base(output)
        {
        }

        /// <summary>RT-380.1 PAR の Request Object の中の request_uri を断る</summary>
        /// <param name="targetKey">core / netfx</param>
        /// <returns>Task</returns>
        [SkippableTheory]
        [MemberData(nameof(AllTargets))]
        public async Task RT38001_PARのRequestObjectの中のrequest_uriを断る(string targetKey)
        {
            using (IdPClient client = this.Client(targetKey))
            {
                TestReport r = this.Report("RT-380.1",
                    "PAR に預ける Request Object の中に request_uri が在れば、400 ＋ invalid_request_object で断る。無ければ 201。フォームの request_uri は従来どおり invalid_request",
                    "**RFC 9126 は、PAR の要求で request_uri を使うことを禁じる。Request Object で預ける形も PAR の要求である。**"
                    + "**以前は、フォームの request_uri だけを断り、Request Object の中は見ていなかった**"
                    + "（適合性テストの par-authorization-request-containing-request_uri）。",
                    "RFC 9126 §2.1 / RFC 9126 §3 / RFC 9101 §7 / #380");

                ClientRegistration reg = Flows.Registration(client, KnownClients.TestClient);
                string endpoint = await ParRequestObjectRequestUriTests.ParEndpointAsync(client);

                r.Target("POST /par（client_name=" + KnownClients.TestClient + "。client_secret_basic。request に署名付き JWT）");

                r.Step("(1) 対照：request_uri の無い Request Object は 201");

                JsonResponse control = await ParRequestObjectRequestUriTests.ParAsync(client, reg, endpoint, null);

                r.VerifyEqual("request_uri 無し : HTTP 201", "201", ((int)control.StatusCode).ToString());

                r.Step("(2) Request Object の中に request_uri を入れる（値が在る・空文字）");

                foreach (KeyValuePair<string, string> c in new Dictionary<string, string>()
                {
                    { "中の request_uri", "urn:ietf:params:oauth:request_uri:e2e-rt3801" },
                    { "中の空の request_uri", "" }
                })
                {
                    JsonResponse inner = await ParRequestObjectRequestUriTests.ParAsync(client, reg, endpoint, c.Value);

                    r.VerifyEqual(c.Key + " : HTTP 400", "400", ((int)inner.StatusCode).ToString());
                    r.VerifyEqual(c.Key + " : invalid_request_object", "invalid_request_object", inner.Error ?? "（無い）");

                    //  **署名・alg で先に断られたのではないこと**（理由が request_uri であること）。
                    string description = inner.String("error_description") ?? "";

                    r.Verify(c.Key + " : 断る理由は request_uri", description.Contains("must not contain request_uri"),
                        "request_uri", description.Contains("must not contain request_uri") ? "request_uri" : "**" + description + "**");

                    r.Verify(c.Key + " : request_uri を返さない", string.IsNullOrEmpty(inner.String("request_uri")),
                        "返さない", string.IsNullOrEmpty(inner.String("request_uri")) ? "返さなかった" : "**返した**");
                }

                r.Step("(3) 対照：フォームの request_uri は、従来どおり invalid_request");

                JsonResponse form = await client.PostJsonWithBasicAuthAsync(endpoint, new Dictionary<string, string>()
                {
                    { "response_type", "code" },
                    { "redirect_uri", reg.RedirectUri },
                    { "scope", "openid" },
                    { "state", "state-rt3801-3" },
                    { "request_uri", "urn:ietf:params:oauth:request_uri:e2e-rt3801" }
                }, reg.ClientId, reg.ClientSecret);

                r.VerifyEqual("フォームの request_uri : HTTP 400", "400", ((int)form.StatusCode).ToString());
                r.VerifyEqual("フォームの request_uri : invalid_request", "invalid_request", form.Error ?? "（無い）");

                r.Done();
            }
        }

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

        /// <summary>Request Object を作って PAR に預ける</summary>
        /// <param name="client">IdPClient</param>
        /// <param name="reg">クライアント</param>
        /// <param name="endpoint">PAR の口</param>
        /// <param name="innerRequestUri">Request Object の中に入れる request_uri（null なら入れない）</param>
        /// <returns>応答</returns>
        private static async Task<JsonResponse> ParAsync(
            IdPClient client, ClientRegistration reg, string endpoint, string innerRequestUri)
        {
            Dictionary<string, object> parameters = new Dictionary<string, object>()
            {
                { "response_type", "code" },
                { "redirect_uri", reg.RedirectUri },
                { "scope", "openid" },
                { "state", "state-rt3801" },
                { "nonce", "nonce-rt3801" }
            };

            if (innerRequestUri != null)
            {
                parameters["request_uri"] = innerRequestUri;
            }

            string requestObject = await RequestObjectBuilder.CreateAsync(client, reg.ClientId, parameters);

            return await client.PostJsonWithBasicAuthAsync(
                endpoint, new Dictionary<string, string>() { { "request", requestObject } }, reg.ClientId, reg.ClientSecret);
        }

        #endregion
    }
}
