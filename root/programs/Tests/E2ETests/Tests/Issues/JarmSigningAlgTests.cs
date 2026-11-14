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
//* クラス名        ：JarmSigningAlgTests
//* クラス日本語名  ：RT-370 JARM の署名 alg を登録（authorization_signed_response_alg）で選べる
//*
//* 作成日時        ：－
//* 作成者          ：－
//* 更新履歴        ：－
//*
//*  日時        更新者            内容
//*  ----------  ----------------  -------------------------------------------------
//*  2026/11/13  玄人 幸道         新規（#370）
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
    /// RT-370. **JARM の応答の署名 alg を、登録の `authorization_signed_response_alg` で選べる。**
    /// </summary>
    /// <remarks>
    /// **以前は JARM が RS256 に固定だった。**
    /// **FAPI は RS256 を認めない**（FAPI 1.0 Advanced §8.6、FAPI 2.0 Security Profile §5.4.1）ので、
    /// **FAPI 2.0 Message Signing の適合性テストは、JARM の alg で落ちていた**（#370）。
    /// **登録が無ければ RS256 のまま**（JARM §3 の既定。FAPI の登録も。Open棟梁 の RP 側の検証が、暗号化しない ES256 を受けないため）。
    ///
    /// | | 測ること |
    /// |---|---|
    /// | **`RT-370.5`** | **JARM は、登録の `authorization_signed_response_alg`（PS256）で署名され、登録が無ければ RS256**（JARM §3 の既定）。Discovery も選べる alg を広告する |
    /// </remarks>
    public class JarmSigningAlgTests : TargetTestBase
    {
        /// <summary>コンストラクタ</summary>
        /// <param name="output">ITestOutputHelper</param>
        public JarmSigningAlgTests(ITestOutputHelper output) : base(output)
        {
        }

        #region 補助

        /// <summary>JWT のヘッダの alg</summary>
        /// <param name="jwt">JWT</param>
        /// <returns>alg（読めなければ「（読めない）」）</returns>
        private static string AlgOf(string jwt)
        {
            if (string.IsNullOrEmpty(jwt))
            {
                return "（無い）";
            }

            return Jwt.String(Jwt.Header(jwt), "alg") ?? "（読めない）";
        }

        /// <summary>response_mode=query.jwt で認可コードを要求し、JARM の JWT を返す</summary>
        /// <param name="r">TestReport</param>
        /// <param name="client">IdPClient</param>
        /// <param name="reg">クライアント</param>
        /// <param name="state">state</param>
        /// <returns>JARM の JWT（無ければ null）</returns>
        private static async Task<string> JarmAsync(
            TestReport r, IdPClient client, ClientRegistration reg, string state)
        {
            Dictionary<string, string> extra = new Dictionary<string, string>()
            {
                { "response_mode", "query.jwt" }
            };

            AuthZResponse res = await Flows.AuthorizeCodeAsync(client, reg,
                state: state, redirectUri: reg.RedirectUri, extra: extra);

            string jwt = res.Get("response");

            r.Verify("response（JWT）が返る", !string.IsNullOrEmpty(jwt),
                "あり", string.IsNullOrEmpty(jwt) ? "**無い**（" + res.ToString() + "）" : "あり");

            return jwt;
        }

        /// <summary>JWT の alg と、JWKS での検証を確かめる</summary>
        /// <param name="r">TestReport</param>
        /// <param name="label">何の JWT か</param>
        /// <param name="jwt">JWT</param>
        /// <param name="expectedAlg">期待する alg</param>
        /// <param name="jwkSet">JWK Set</param>
        private static void VerifyAlg(TestReport r, string label, string jwt, string expectedAlg, JsonElement jwkSet)
        {
            r.VerifyEqual(label + " : alg", expectedAlg, JarmSigningAlgTests.AlgOf(jwt));

            if (!string.IsNullOrEmpty(jwt))
            {
                Jwks.Result sig = Jwks.Verify(jwt, jwkSet);
                r.Verify(label + " : 署名を JWKS で検証できる", sig.Verified, "検証できる", sig.Detail);
            }
        }

        #endregion

        #region RT-370.5

        /// <summary>RT-370.5 JARM は登録の authorization_signed_response_alg で署名され、登録が無ければ RS256</summary>
        /// <param name="targetKey">core / netfx</param>
        /// <returns>Task</returns>
        [SkippableTheory]
        [MemberData(nameof(AllTargets))]
        public async Task RT37005_JARMは登録のalgで署名され登録が無ければRS256(string targetKey)
        {
            using (IdPClient client = await this.SignedInClientAsync(targetKey))
            {
                TestReport r = this.Report("RT-370.5",
                    "JARM の応答は、登録の authorization_signed_response_alg（PS256）で署名され、登録が無ければ RS256 のまま。Discovery の authorization_signing_alg_values_supported も、選べる alg を広告する",
                    "**JARM §3 の authorization_signed_response_alg は、応答の署名 alg を選ぶ登録項目で、既定は RS256。**"
                    + "**以前は登録で選べず、RS256 に固定だった。**"
                    + "**鍵は id_token と同じ表（jwks_uri に載る）なので、RP は kid で引いて検証できる。**",
                    "JARM §3 / JARM §4 / #370");

                ClientRegistration normal = Flows.Registration(client, KnownClients.MvcSample);
                ClientRegistration registered = Flows.InjectedRegistration(client, KnownClients.TestClient_46);
                JsonElement jwkSet = await Flows.JwkSetAsync(client);

                r.Target("GET /authorize（response_mode=query.jwt。client_name=" + KnownClients.TestClient_46
                    + "（authorization_signed_response_alg=PS256）。対照は " + KnownClients.MvcSample + "（登録なし）");

                r.Step("(1) 登録が PS256");

                JarmSigningAlgTests.VerifyAlg(r, "PS256 の登録の JARM",
                    await JarmSigningAlgTests.JarmAsync(r, client, registered, "state-rt3705-1"), "PS256", jwkSet);

                r.Step("(2) 登録が無い（FAPI でない）");

                JarmSigningAlgTests.VerifyAlg(r, "登録の無い JARM",
                    await JarmSigningAlgTests.JarmAsync(r, client, normal, "state-rt3705-2"), "RS256", jwkSet);

                r.Step("(3) Discovery の広告");

                JsonResponse discovery = await client.GetJsonAsync("/.well-known/openid-configuration");

                foreach (string alg in new string[] { "RS256", "PS256", "ES256" })
                {
                    r.Verify("authorization_signing_alg_values_supported に " + alg + " が在る",
                        discovery.ArrayContains("authorization_signing_alg_values_supported", alg),
                        "在る", string.Join(" ", discovery.Strings("authorization_signing_alg_values_supported") ?? new string[0]));
                }

                r.Done();
            }
        }

        #endregion
    }
}
