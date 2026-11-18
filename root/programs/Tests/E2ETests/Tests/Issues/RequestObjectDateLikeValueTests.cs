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
//* クラス名        ：RequestObjectDateLikeValueTests
//* クラス日本語名  ：RT-403 預けた Request Object の中の日付の形の文字列が、/authorize の応答で書き換わらない
//*
//* 作成日時        ：－
//* 作成者          ：－
//* 更新履歴        ：－
//*
//*  日時        更新者            内容
//*  ----------  ----------------  -------------------------------------------------
//*  2026/11/18  玄人 幸道         新規（#403）
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
    /// RT-403. **PAR・`/ros` に預けた Request Object の中の日付の形の文字列（`state` など）が、`/authorize` の応答で書き換わらない**。
    /// </summary>
    /// <remarks>
    /// **以前は、預かるときと `/authorize` で読み直すときに、既定の JSON の読み方で日付の形の文字列が `Date` になり、
    /// 応答の `state` が `2026-11-18T10:00:00Z` → `11/18/2026 10:00:00` に変わっていた**（両版。OpenTouryo#662。#403）。
    ///
    /// | | 測ること |
    /// |---|---|
    /// | **`RT-403.1`** | **PAR**・**`/ros`** に日付の形の `state`（UTC・時差付き）を預け、`prompt=none`（サインインしていない）で `/authorize` に行く。エラー応答の `state` が預けた値のまま |
    ///
    /// - **サインインしていない `prompt=none` のエラー応答**（`login_required`）で測る。応答の `state` を作る経路は、成功の応答と同じ預けた中身である
    /// </remarks>
    public class RequestObjectDateLikeValueTests : TargetTestBase
    {
        /// <summary>コンストラクタ</summary>
        /// <param name="output">ITestOutputHelper</param>
        public RequestObjectDateLikeValueTests(ITestOutputHelper output) : base(output)
        {
        }

        /// <summary>RT-403.1 預けた Request Object の日付の形の state が、/authorize の応答で書き換わらない</summary>
        /// <param name="targetKey">core / netfx</param>
        /// <returns>Task</returns>
        [SkippableTheory]
        [MemberData(nameof(AllTargets))]
        public async Task RT40301_預けたRequestObjectの日付の形のstateが応答で書き換わらない(string targetKey)
        {
            using (IdPClient client = this.Client(targetKey))
            {
                TestReport r = this.Report("RT-403.1",
                    "PAR・/ros に預けた Request Object の中の日付の形の state（UTC・時差付き）が、/authorize の応答（prompt=none の login_required）で預けた値のまま返る",
                    "**state は、受けた値をそのまま返す。**"
                    + "**以前は、日付の形の文字列が JSON の読み方で Date になり、書式の変わった文字列（11/18/2026 10:00:00）で返っていた**（OpenTouryo#662）。",
                    "RFC 6749 §4.1.2.1 / #403");

                ClientRegistration reg = Flows.Registration(client, KnownClients.TestClient);
                string endpoint = await RequestObjectDateLikeValueTests.ParEndpointAsync(client);

                r.Target("POST /par・POST /ros（client_name=" + KnownClients.TestClient + "）→ GET /authorize?request_uri=...");

                //  **時差は、手元の機械の時差（日本の +09:00）と違う値にする。** 既定の読み方は、時差付きの値を手元の時差に直してから書き戻すので、
                //  **手元と同じ時差では書き換わらず、直す前でも通ってしまう**（`/ros` の預かる側の読み方は、-03:00 で初めて落ちた）。
                foreach (string state in new string[] { "2026-11-18T10:00:00Z", "2026-11-18T10:00:00+05:30" })
                {
                    r.Step("PAR：state=" + state);

                    string ro = await RequestObjectBuilder.CreateAsync(client, reg.ClientId, RequestObjectDateLikeValueTests.Parameters(reg, state));
                    JsonResponse par = await client.PostJsonWithBasicAuthAsync(
                        endpoint, new Dictionary<string, string>() { { "request", ro } }, reg.ClientId, reg.ClientSecret);

                    r.VerifyEqual("PAR（" + state + "） : HTTP 201", "201", ((int)par.StatusCode).ToString());

                    string returned = await RequestObjectDateLikeValueTests.ReturnedStateAsync(client, reg, par.String("request_uri"));

                    r.VerifyEqual("PAR（" + state + "） : 応答の state", state, returned ?? "（無い）");
                }

                r.Step("/ros：state=2026-11-18T10:00:00-03:00");

                string rosState = "2026-11-18T10:00:00-03:00";
                string rosUri = await RequestObjectBuilder.RegisterAsync(client,
                    await RequestObjectBuilder.CreateAsync(client, reg.ClientId, RequestObjectDateLikeValueTests.Parameters(reg, rosState)));

                r.Verify("/ros : request_uri を返す", !string.IsNullOrEmpty(rosUri),
                    "返す", string.IsNullOrEmpty(rosUri) ? "**返さない**" : "返した");

                string rosReturned = await RequestObjectDateLikeValueTests.ReturnedStateAsync(client, reg, rosUri);

                r.VerifyEqual("/ros : 応答の state", rosState, rosReturned ?? "（無い）");

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

        /// <summary>認可要求のパラメタ（prompt=none）</summary>
        /// <param name="reg">クライアント</param>
        /// <param name="state">state</param>
        /// <returns>パラメタ</returns>
        private static Dictionary<string, object> Parameters(ClientRegistration reg, string state)
        {
            return new Dictionary<string, object>()
            {
                { "response_type", "code" },
                { "redirect_uri", reg.RedirectUri },
                { "scope", "openid" },
                { "state", state },
                { "nonce", "nonce-rt4031" },
                { "prompt", "none" }
            };
        }

        /// <summary>request_uri で /authorize に行き、リダイレクトの state を取る</summary>
        /// <param name="client">IdPClient</param>
        /// <param name="reg">クライアント</param>
        /// <param name="requestUri">request_uri</param>
        /// <returns>state（無ければ null）</returns>
        private static async Task<string> ReturnedStateAsync(IdPClient client, ClientRegistration reg, string requestUri)
        {
            if (string.IsNullOrEmpty(requestUri))
            {
                return null;
            }

            HttpResponseMessage res = await client.GetAsync(
                "/authorize?client_id=" + reg.ClientId + "&request_uri=" + Uri.EscapeDataString(requestUri));

            return (res.Headers.Location == null) ? null : Saml2.QueryValue(res.Headers.Location.OriginalString, "state");
        }

        #endregion
    }
}
