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
//* クラス名        ：RequestUriTests
//* クラス日本語名  ：RT-362 引けない request_uri を、黙って続けずに断る
//*
//* 作成日時        ：－
//* 作成者          ：－
//* 更新履歴        ：－
//*
//*  日時        更新者            内容
//*  ----------  ----------------  -------------------------------------------------
//*  2026/11/12  玄人 幸道         新規（#362）
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
    /// RT-362 引けない request_uri を、黙って続けずに断る（#362）。
    /// </summary>
    /// <remarks>
    /// **この OP は、自分が払い出した `urn:`（PAR・`/ros`）の request_uri だけを引く。**
    /// **以前は、引けない request_uri（外部の URL・存在しない `urn:`）でも、`request_uri` が無い要求としてクエリだけで続けていた**ので、
    /// **RP が Request Object に入れた `state`・`nonce` が応答から落ちた**（適合性テストの `oidcc-request-uri-signed-rs256`）。
    /// **外部の request_uri を取りに行く（OIDC Core 1.0 §6.2）のは、別の Issue で扱う。**
    /// </remarks>
    public class RequestUriTests : TargetTestBase
    {
        /// <summary>コンストラクタ</summary>
        /// <param name="output">ITestOutputHelper</param>
        public RequestUriTests(ITestOutputHelper output) : base(output)
        {
        }

        /// <summary>RT-362.1 外部の request_uri は、取りに行かずに request_uri_not_supported で断る</summary>
        /// <param name="targetKey">core / netfx</param>
        /// <returns>Task</returns>
        [SkippableTheory]
        [MemberData(nameof(AllTargets))]
        public async Task RT36201_外部のrequest_uriはrequest_uri_not_supportedで断る(string targetKey)
        {
            using (IdPClient client = await this.SignedInClientAsync(targetKey))
            {
                ClientRegistration reg = Flows.Registration(client, KnownClients.TestClient);

                TestReport r = this.Report("RT-362.1",
                    "外部の https の request_uri を付けた認可要求は、クエリだけで続けずに、request_uri_not_supported のエラー画面になる（RP へ返さない）",
                    "**この OP は外部の request_uri を取りに行かない。** 取りに行かないなら、黙って続けずに断る"
                    + "（以前は、クエリだけで認可を続け、Request Object の state・nonce が落ちていた）。"
                    + "**`redirect_uri` を照合する前なので、RP へは返さない。**",
                    "OIDC Core 1.0 §3.1.2.6（request_uri_not_supported）/ #362");

                r.Target("client_name=" + KnownClients.TestClient + " / request_uri=https://rp.example.com/request.jwt（外部の URL）");
                r.Step("GET /authorize に、クエリのパラメタと外部の request_uri を付けて送る");

                AuthZResponse res = await RequestUriTests.AuthorizeWithRequestUriAsync(
                    client, reg, "https://rp.example.com/request.jwt", "state-rt3621");

                RequestUriTests.VerifyRefused(r, res, "request_uri_not_supported");

                r.Done();
            }
        }

        /// <summary>RT-362.2 引けない urn: の request_uri は、invalid_request_uri で断る</summary>
        /// <param name="targetKey">core / netfx</param>
        /// <returns>Task</returns>
        [SkippableTheory]
        [MemberData(nameof(AllTargets))]
        public async Task RT36202_引けないurnのrequest_uriはinvalid_request_uriで断る(string targetKey)
        {
            using (IdPClient client = await this.SignedInClientAsync(targetKey))
            {
                ClientRegistration reg = Flows.Registration(client, KnownClients.TestClient);

                TestReport r = this.Report("RT-362.2",
                    "この OP の形（urn:）だが存在しない request_uri を付けた認可要求は、クエリだけで続けずに、invalid_request_uri のエラー画面になる（RP へ返さない）",
                    "**存在しない・期限切れ・使用済みの request_uri は、預けた要求を引けない。** 黙って続けずに断る"
                    + "（以前は、クエリだけで認可を続けていた）。**`redirect_uri` を照合する前なので、RP へは返さない。**",
                    "OIDC Core 1.0 §3.1.2.6（invalid_request_uri）/ #362");

                r.Target("client_name=" + KnownClients.TestClient + " / request_uri=（/ros で払い出した urn: の末尾を、存在しない値に替えたもの）");
                r.Step("(1) /ros に Request Object を預け、払い出された request_uri の形（urn:）を得る");

                string issued = await RequestObjectBuilder.RegisterAsync(client,
                    await RequestObjectBuilder.CreateAsync(client, reg.ClientId,
                        new Dictionary<string, object>()
                        {
                            { "response_type", "code" },
                            { "redirect_uri", reg.RedirectUri },
                            { "scope", "openid" },
                            { "state", "state-rt3622-ro" }
                        })) ?? "";

                Assert.True(issued.StartsWith("urn:", StringComparison.Ordinal) && issued.LastIndexOf(':') > 0,
                    "前提: 払い出された request_uri が urn: であること（" + issued + "）");

                string unknown = issued.Substring(0, issued.LastIndexOf(':') + 1) + "unknown" + Guid.NewGuid().ToString("N");

                r.Step("(2) GET /authorize に、クエリのパラメタと、存在しない urn: の request_uri を付けて送る");

                AuthZResponse res = await RequestUriTests.AuthorizeWithRequestUriAsync(client, reg, unknown, "state-rt3622");

                RequestUriTests.VerifyRefused(r, res, "invalid_request_uri");

                r.Done();
            }
        }

        /// <summary>RT-362.3 一度認可に使った request_uri は、invalid_request_uri で断る</summary>
        /// <param name="targetKey">core / netfx</param>
        /// <returns>Task</returns>
        [SkippableTheory]
        [MemberData(nameof(AllTargets))]
        public async Task RT36203_使用済みのrequest_uriはinvalid_request_uriで断る(string targetKey)
        {
            using (IdPClient client = await this.SignedInClientAsync(targetKey))
            {
                ClientRegistration reg = Flows.Registration(client, KnownClients.TestClient);

                TestReport r = this.Report("RT-362.3",
                    "一度認可に使った request_uri を、クエリのパラメタと一緒にもう一度送ると、クエリだけで続けずに、invalid_request_uri のエラー画面になる",
                    "**預けた要求は、認可応答を作り終えた時点で消している**（#188）。"
                    + "**消した後の request_uri は「引けない urn:」として断る**（以前は、クエリだけで認可を続けていた）。",
                    "OIDC Core 1.0 §3.1.2.6（invalid_request_uri）/ RFC 9126 §2.2（request_uri は一回限り）/ #362");

                r.Target("client_name=" + KnownClients.TestClient + " / request_uri=（/ros で払い出し、一度認可に使ったもの）");
                r.Step("(1) /ros に Request Object を預け、その request_uri で一度認可する");

                string issued = await RequestObjectBuilder.RegisterAsync(client,
                    await RequestObjectBuilder.CreateAsync(client, reg.ClientId,
                        new Dictionary<string, object>()
                        {
                            { "response_type", "code" },
                            { "redirect_uri", reg.RedirectUri },
                            { "scope", "openid" },
                            { "state", "state-rt3623-ro" }
                        })) ?? "";

                Assert.False(string.IsNullOrEmpty(issued), "前提: request_uri が払い出されること");

                AuthZResponse first = await RequestUriTests.AuthorizeWithRequestUriAsync(client, reg, issued, "state-rt3623-first");

                Assert.False(string.IsNullOrEmpty(first.Code), "前提: 1 回目は認可コードが返ること（" + first.ToString() + "）");

                r.Step("(2) 同じ request_uri を、クエリのパラメタと一緒にもう一度送る");

                AuthZResponse second = await RequestUriTests.AuthorizeWithRequestUriAsync(client, reg, issued, "state-rt3623-second");

                RequestUriTests.VerifyRefused(r, second, "invalid_request_uri");

                r.Done();
            }
        }

        #region 補助

        /// <summary>クエリのパラメタと request_uri を付けて認可要求を送る（同意画面が出たら許可する）</summary>
        /// <param name="client">IdPClient</param>
        /// <param name="reg">クライアント</param>
        /// <param name="requestUri">request_uri</param>
        /// <param name="state">state</param>
        /// <returns>AuthZResponse</returns>
        /// <remarks>
        /// **クエリだけでも成り立つ要求にする**（以前の「クエリだけで続ける」動きなら、code が返る）。
        /// </remarks>
        private static async Task<AuthZResponse> AuthorizeWithRequestUriAsync(
            IdPClient client, ClientRegistration reg, string requestUri, string state)
        {
            AuthZResponse res = await client.AuthorizeAsync(new Dictionary<string, string>()
            {
                { "response_type", "code" },
                { "client_id", reg.ClientId },
                { "scope", "openid" },
                { "redirect_uri", reg.RedirectUri },
                { "state", state },
                { "request_uri", requestUri }
            });

            return res.NeedsConsent ? await client.GrantConsentAsync(res) : res;
        }

        /// <summary>エラー画面で断ったことを確かめる</summary>
        /// <param name="r">TestReport</param>
        /// <param name="res">AuthZResponse</param>
        /// <param name="error">期待する error</param>
        private static void VerifyRefused(TestReport r, AuthZResponse res, string error)
        {
            r.Verify("**code を返さない**（クエリだけで続けない）", string.IsNullOrEmpty(res.Code),
                "code なし", string.IsNullOrEmpty(res.Code) ? "なし" : "**あり**（クエリだけで続けた）");

            r.Verify("**RP へ返さない**（Location が無い）", string.IsNullOrEmpty(res.Location),
                "Location なし", string.IsNullOrEmpty(res.Location) ? "なし" : res.Location.Split('?')[0]);

            r.Verify("**エラー画面に " + error + " が出る**",
                (res.Body ?? "").Contains("text-danger") && (res.Body ?? "").Contains(error),
                "エラー画面（" + error + "）", Html.Describe(res.Body));
        }

        #endregion
    }
}
