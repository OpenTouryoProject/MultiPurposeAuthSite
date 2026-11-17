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
//* クラス名        ：JarmNoStateTests
//* クラス日本語名  ：RT-378 state を送らない要求の JARM には、state を入れない（RFC 6749 §4.1.2・JARM §2.1.1）
//*
//* 作成日時        ：－
//* 作成者          ：－
//* 更新履歴        ：－
//*
//*  日時        更新者            内容
//*  ----------  ----------------  -------------------------------------------------
//*  2026/11/17  玄人 幸道         新規（#378）
//**********************************************************************************

using System.Collections.Generic;
using System.Threading.Tasks;

using MultiPurposeAuthSite.Tests.E2E.Infrastructure;

using Xunit;
using Xunit.Abstractions;

namespace MultiPurposeAuthSite.Tests.E2E.Tests.Issues
{
    /// <summary>
    /// RT-378. **`state` を送らない認可要求の JARM（`response` の JWT）には、`state` を入れない**（名前ごと省く）。
    /// </summary>
    /// <remarks>
    /// **`state` は要求に在ったときだけ返す文字列である**（RFC 6749 §4.1.2・§4.1.2.1）。
    /// **以前は、要求に無い `state` が `"state": null` として JWT に載っていた**（成功・エラーとも。
    /// 適合性テストの `ensure-authorization-request-without-state-success`・`state-only-outside-request-object-not-used`）。
    /// **クエリの応答では、値の無いパラメタは省かれていた**ので、JARM だけで起きていた。
    ///
    /// | | 測ること |
    /// |---|---|
    /// | **`RT-378.1`** | **`state` 無しの要求の JARM に `state` の名前が無い**（成功の応答・エラーの応答）。**`state` を送れば、その値が JWT に入る** |
    /// </remarks>
    public class JarmNoStateTests : TargetTestBase
    {
        /// <summary>コンストラクタ</summary>
        /// <param name="output">ITestOutputHelper</param>
        public JarmNoStateTests(ITestOutputHelper output) : base(output)
        {
        }

        /// <summary>RT-378.1 state を送らない要求の JARM には、state を入れない</summary>
        /// <param name="targetKey">core / netfx</param>
        /// <returns>Task</returns>
        [SkippableTheory]
        [MemberData(nameof(AllTargets))]
        public async Task RT37801_stateを送らない要求のJARMにstateを入れない(string targetKey)
        {
            using (IdPClient client = await this.SignedInClientAsync(targetKey))
            {
                TestReport r = this.Report("RT-378.1",
                    "state を送らない認可要求の JARM（response の JWT）には、成功・エラーとも state の名前を入れない。state を送れば、その値が入る",
                    "**state は要求に在ったときだけ返す文字列である。**"
                    + "**以前は、要求に無い state が \"state\": null として JWT に載り、型を確かめる RP（適合性テスト）が応答を断っていた。**"
                    + "**クエリの応答では値の無いパラメタを省いていたので、JARM だけで起きていた。**",
                    "RFC 6749 §4.1.2 / RFC 6749 §4.1.2.1 / JARM §2.1.1 / #378");

                ClientRegistration reg = Flows.Registration(client, KnownClients.MvcSample);

                r.Target("GET /authorize（client_name=" + KnownClients.MvcSample + "。response_mode=query.jwt）");

                r.Step("(1) state を送らずに要求する（成功の応答）");

                AuthZResponse success = await Flows.AuthorizeCodeAsync(
                    client, reg, "openid", state: null, redirectUri: reg.RedirectUri,
                    extra: new Dictionary<string, string>() { { "response_mode", "query.jwt" } });

                Assert.False(string.IsNullOrEmpty(success.Get("response")), "前提: JARM の response が返ること（" + success.ToString() + "）");

                AuthZResponse successJwt = success.Unwrap();

                r.Verify("成功 : code が在る", !string.IsNullOrEmpty(successJwt.Code),
                    "在る", string.IsNullOrEmpty(successJwt.Code) ? "**無い**" : "在る");
                JarmNoStateTests.VerifyNoState(r, "成功", successJwt);

                r.Step("(2) state を送らずに、エラーになる要求をする（prompt=none login。エラーの応答）");

                AuthZResponse error = await client.AuthorizeAsync(new Dictionary<string, string>()
                {
                    { "response_type", "code" },
                    { "client_id", reg.ClientId },
                    { "redirect_uri", reg.RedirectUri },
                    { "scope", "openid" },
                    { "prompt", "none login" },
                    { "response_mode", "query.jwt" }
                });

                Assert.False(string.IsNullOrEmpty(error.Get("response")), "前提: JARM の response が返ること（" + error.ToString() + "）");

                AuthZResponse errorJwt = error.Unwrap();

                r.Verify("エラー : error が在る", !string.IsNullOrEmpty(errorJwt.Error),
                    "在る", errorJwt.Error ?? "**無い**");
                JarmNoStateTests.VerifyNoState(r, "エラー", errorJwt);

                r.Step("(3) 対照：state を送れば、その値が JWT に入る");

                AuthZResponse withState = (await Flows.AuthorizeCodeAsync(
                    client, reg, "openid", state: "state-rt3781-3", redirectUri: reg.RedirectUri,
                    extra: new Dictionary<string, string>() { { "response_mode", "query.jwt" } })).Unwrap();

                r.VerifyEqual("state を送ったとき : state", "state-rt3781-3", withState.State ?? "（無い）");

                r.Done();
            }
        }

        #region 補助

        /// <summary>JWT の中に state の名前が無いことを確かめる（null も無いこととして扱わない）</summary>
        /// <param name="r">TestReport</param>
        /// <param name="label">どの応答か</param>
        /// <param name="unwrapped">Unwrap した応答</param>
        private static void VerifyNoState(TestReport r, string label, AuthZResponse unwrapped)
        {
            bool has = unwrapped.Parameters.ContainsKey("state");

            r.Verify(label + " : JWT に state の名前が無い（\"state\": null も出さない）", !has,
                "無い", has ? "**在る（" + (unwrapped.Get("state") ?? "null") + "）**" : "無い");
        }

        #endregion
    }
}
