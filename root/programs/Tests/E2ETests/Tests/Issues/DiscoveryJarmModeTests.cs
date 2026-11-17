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
//* クラス名        ：DiscoveryJarmModeTests
//* クラス日本語名  ：RT-379 Discovery の response_modes_supported に jwt を広告する（JARM §2.3.4）
//*
//* 作成日時        ：－
//* 作成者          ：－
//* 更新履歴        ：－
//*
//*  日時        更新者            内容
//*  ----------  ----------------  -------------------------------------------------
//*  2026/11/17  玄人 幸道         新規（#379）
//**********************************************************************************

using System.Collections.Generic;
using System.Threading.Tasks;

using MultiPurposeAuthSite.Tests.E2E.Infrastructure;

using Xunit;
using Xunit.Abstractions;

namespace MultiPurposeAuthSite.Tests.E2E.Tests.Issues
{
    /// <summary>
    /// RT-379. **Discovery の `response_modes_supported` に `jwt` を広告する**（JARM §2.3.4）。
    /// </summary>
    /// <remarks>
    /// **`jwt` は、応答の型の既定の置き場所で JARM にする短い形**（`code` は `query.jwt`）。
    /// **以前は受けていたのに広告していなかった**（`query.jwt`・`fragment.jwt`・`form_post.jwt` だけを広告。
    /// 適合性テストの `discovery-end-point-verification`）。
    ///
    /// | | 測ること |
    /// |---|---|
    /// | **`RT-379.1`** | **`response_modes_supported` に `jwt` が在る**（`*.jwt` も従来どおり）。**広告した `jwt` で要求すると、JARM（`response`）で返る** |
    /// </remarks>
    public class DiscoveryJarmModeTests : TargetTestBase
    {
        /// <summary>コンストラクタ</summary>
        /// <param name="output">ITestOutputHelper</param>
        public DiscoveryJarmModeTests(ITestOutputHelper output) : base(output)
        {
        }

        /// <summary>RT-379.1 response_modes_supported に jwt を広告し、受ける</summary>
        /// <param name="targetKey">core / netfx</param>
        /// <returns>Task</returns>
        [SkippableTheory]
        [MemberData(nameof(AllTargets))]
        public async Task RT37901_response_modes_supportedにjwtを広告する(string targetKey)
        {
            using (IdPClient client = await this.SignedInClientAsync(targetKey))
            {
                TestReport r = this.Report("RT-379.1",
                    "Discovery の response_modes_supported に jwt を広告し（*.jwt も従来どおり）、広告した jwt で要求すると JARM で返る",
                    "**jwt は、応答の型の既定の置き場所で JARM にする短い形である。**"
                    + "**以前は受けていたのに広告していなかった**（適合性テストの discovery-end-point-verification）。"
                    + "**広告と受け付けが一致していること**を、要求まで送って確かめる。",
                    "JARM §2.3.4 / OpenID Connect Discovery 1.0 §3 / #379");

                ClientRegistration reg = Flows.Registration(client, KnownClients.MvcSample);

                r.Target("GET /.well-known/openid-configuration・GET /authorize（client_name=" + KnownClients.MvcSample + "）");

                r.Step("(1) response_modes_supported を読む");

                JsonResponse discovery = await client.GetJsonAsync("/.well-known/openid-configuration");

                Assert.True(discovery.IsJson, "前提: Discovery 文書が JSON であること");

                foreach (string mode in new string[] { "jwt", "query.jwt", "fragment.jwt", "form_post.jwt" })
                {
                    bool has = discovery.ArrayContains("response_modes_supported", mode);

                    r.Verify("response_modes_supported に " + mode + " が在る", has,
                        "在る", has ? "在る" : "**無い**");
                }

                r.Step("(2) 広告した jwt で要求すると、JARM（response）で返る");

                AuthZResponse res = await Flows.AuthorizeCodeAsync(
                    client, reg, "openid", "state-rt3791", redirectUri: reg.RedirectUri,
                    extra: new Dictionary<string, string>() { { "response_mode", "jwt" } });

                bool isJarm = !string.IsNullOrEmpty(res.Get("response")) && string.IsNullOrEmpty(res.Code);

                r.Verify("response_mode=jwt : code を URL に直接載せず、response で返る", isJarm,
                    "response", isJarm ? "response" : "**" + res.ToString() + "**");

                AuthZResponse unwrapped = res.Unwrap();

                r.Verify("response_mode=jwt : response の中に code が在る", !string.IsNullOrEmpty(unwrapped.Code),
                    "在る", string.IsNullOrEmpty(unwrapped.Code) ? "**無い**" : "在る");

                r.Done();
            }
        }
    }
}
