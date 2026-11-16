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
//* クラス名        ：Fapi1JarmTests
//* クラス日本語名  ：RT-381 fapi1 の登録は、JARM の認可要求だけを受ける（FAPI 1.0 Advanced §5.2.2 の 2）
//*
//* 作成日時        ：－
//* 作成者          ：－
//* 更新履歴        ：－
//*
//*  日時        更新者            内容
//*  ----------  ----------------  -------------------------------------------------
//*  2026/11/17  玄人 幸道         新規（#381）
//**********************************************************************************

using System.Collections.Generic;
using System.Threading.Tasks;

using MultiPurposeAuthSite.Tests.E2E.Infrastructure;

using Xunit;
using Xunit.Abstractions;

namespace MultiPurposeAuthSite.Tests.E2E.Tests.Issues
{
    /// <summary>
    /// RT-381. **fapi1 の登録（`client_mode=fapi1`）は、JARM（`response_mode` が `jwt`・`*.jwt`）の認可要求だけを受ける**（FAPI 1.0 Advanced §5.2.2 の 2）。
    /// </summary>
    /// <remarks>
    /// **§5.2.2 の 2 は「`code id_token`、または `code` ＋ `response_mode=jwt`」を求める。**
    /// **MPAS は fapi1 の登録に Hybrid（`code id_token`）を許さない**（`ClientModePolicy`。`FA-1.4`）ので、**満たせる形は `code` ＋ JARM だけ**である。
    /// **以前は、fapi1 の登録の素の `code`（クエリ）に code を返していた**
    /// （適合性テストの `ensure-response-type-code-fails`・`ensure-response-mode-query`）。
    ///
    /// | | 測ること |
    /// |---|---|
    /// | **`RT-381.1`** | **fapi1 の登録で JARM でない要求（`response_mode` 無し・`query`）は `invalid_request`**（クエリは RP へ返す。PAR は `400`）。**JARM（`jwt`・`query.jwt`・`fragment.jwt`・大文字の `JWT`）なら code を返す。fapi1 でない登録は従来どおり** |
    /// </remarks>
    public class Fapi1JarmTests : TargetTestBase
    {
        /// <summary>コンストラクタ</summary>
        /// <param name="output">ITestOutputHelper</param>
        public Fapi1JarmTests(ITestOutputHelper output) : base(output)
        {
        }

        /// <summary>RT-381.1 fapi1 の登録は、JARM の認可要求だけを受ける</summary>
        /// <param name="targetKey">core / netfx</param>
        /// <returns>Task</returns>
        [SkippableTheory]
        [MemberData(nameof(AllTargets))]
        public async Task RT38101_fapi1の登録はJARMの認可要求だけを受ける(string targetKey)
        {
            using (IdPClient client = await this.SignedInClientAsync(targetKey))
            {
                TestReport r = this.Report("RT-381.1",
                    "fapi1 の登録は、JARM でない認可要求（response_mode 無し・query）を invalid_request で断り（クエリ・PAR とも）、JARM の要求には code を返す。fapi1 でない登録は従来どおり",
                    "**FAPI 1.0 Advanced は、認可サーバが「code id_token、または code と response_mode=jwt の組」を求めることを求める。**"
                    + "**MPAS は fapi1 に Hybrid を許さないので、code ＋ JARM だけを受ける。**"
                    + "**以前は fapi1 の素の code（クエリ）に code を返していた**（適合性テストの ensure-response-type-code-fails・ensure-response-mode-query）。",
                    "FAPI 1.0 Advanced §5.2.2 / JARM §2.3 / #381");

                ClientRegistration fapi1 = Flows.Registration(client, KnownClients.Fapi1Client);
                ClientRegistration normal = Flows.Registration(client, KnownClients.MvcSample);

                r.Target("GET /authorize・POST /par（" + KnownClients.Fapi1Client + "（fapi1）・"
                    + KnownClients.MvcSample + "（normal））");

                r.Step("(1) fapi1・response_mode 無し（クエリ）は、invalid_request を RP へ返す");

                AuthZResponse noMode = await Flows.AuthorizeCodeAsync(
                    client, fapi1, "openid", "state-rt3811-1", redirectUri: fapi1.RedirectUri);

                Fapi1JarmTests.VerifyRejected(r, "response_mode 無し", noMode);

                r.Step("(2) fapi1・response_mode=query は、invalid_request を RP へ返す");

                AuthZResponse queryMode = await Flows.AuthorizeCodeAsync(
                    client, fapi1, "openid", "state-rt3811-2", redirectUri: fapi1.RedirectUri,
                    extra: new Dictionary<string, string>() { { "response_mode", "query" } });

                Fapi1JarmTests.VerifyRejected(r, "response_mode=query", queryMode);

                r.Step("(3) fapi1・JARM（jwt・query.jwt・fragment.jwt・大文字の JWT）は、code を返す");

                //  **大文字小文字は区別しない**（両版の TryResolveResponseMode と同じ。IsJarmResponseMode）。
                foreach (string mode in new string[] { "jwt", "query.jwt", "fragment.jwt", "JWT" })
                {
                    AuthZResponse jarm = await Flows.AuthorizeCodeAsync(
                        client, fapi1, "openid", "state-rt3811-3", redirectUri: fapi1.RedirectUri,
                        extra: new Dictionary<string, string>() { { "response_mode", mode } });

                    r.Verify("response_mode=" + mode + " : code を URL に直接載せず、JARM の response で返す",
                        string.IsNullOrEmpty(jarm.Code) && !string.IsNullOrEmpty(jarm.Get("response")),
                        "response",
                        !string.IsNullOrEmpty(jarm.Get("response")) ? "response"
                            : "**" + jarm.ToString() + "**");

                    AuthZResponse unwrapped = jarm.Unwrap();

                    r.Verify("response_mode=" + mode + " : response の中に code が在る",
                        unwrapped.Error == null && !string.IsNullOrEmpty(unwrapped.Code),
                        "code",
                        !string.IsNullOrEmpty(unwrapped.Code) ? "code"
                            : "**error=" + (unwrapped.Error ?? "なし") + "（" + (unwrapped.ErrorDescription ?? "") + "）**");
                }

                r.Step("(4) fapi1・response_mode 無し（PAR）は、400 ＋ invalid_request。jwt なら 201");

                JsonResponse parNoMode = await Fapi1JarmTests.ParAsync(client, fapi1, null);

                r.VerifyEqual("PAR・response_mode 無し : HTTP 400", "400", ((int)parNoMode.StatusCode).ToString());
                r.VerifyEqual("PAR・response_mode 無し : invalid_request", "invalid_request", parNoMode.Error ?? "（無い）");

                JsonResponse parJwt = await Fapi1JarmTests.ParAsync(client, fapi1, "jwt");

                r.VerifyEqual("PAR・response_mode=jwt : HTTP 201", "201", ((int)parJwt.StatusCode).ToString());

                r.Step("(5) 対照：fapi1 でない登録・response_mode 無しは、従来どおり code をクエリで返す");

                AuthZResponse normalRes = await Flows.AuthorizeCodeAsync(
                    client, normal, "openid", "state-rt3811-5", redirectUri: normal.RedirectUri);

                r.Verify("normal : code が返る",
                    normalRes.Error == null && !string.IsNullOrEmpty(normalRes.Code),
                    "code",
                    !string.IsNullOrEmpty(normalRes.Code) ? "code"
                        : "**error=" + (normalRes.Error ?? "なし") + "（" + (normalRes.ErrorDescription ?? "") + "）**");

                r.Note("**fapi1 の Hybrid（code id_token）は、この確かめより前に `ClientModePolicy` が `unauthorized_client` で断る**（`FA-1.4`）。");

                r.Done();
            }
        }

        #region 補助

        /// <summary>JARM でないとして invalid_request で断り、code を返さないことを確かめる</summary>
        /// <param name="r">TestReport</param>
        /// <param name="label">何の要求か</param>
        /// <param name="authz">AuthZResponse</param>
        private static void VerifyRejected(TestReport r, string label, AuthZResponse authz)
        {
            r.VerifyEqual(label + " : error", "invalid_request", authz.Error ?? "（無い）");

            bool isJarmReason = !string.IsNullOrEmpty(authz.ErrorDescription) && authz.ErrorDescription.Contains("JARM");

            r.Verify(label + " : 断る理由は JARM", isJarmReason,
                "JARM", isJarmReason ? "JARM" : "**" + (authz.ErrorDescription ?? "（無い）") + "**");

            r.Verify(label + " : code を返さない", string.IsNullOrEmpty(authz.Code),
                "返さない", string.IsNullOrEmpty(authz.Code) ? "返さなかった" : "**返した**");
        }

        /// <summary>fapi1 の登録（client_secret_basic）で PAR に預ける（S256 の PKCE と nonce は付ける）</summary>
        /// <param name="client">IdPClient</param>
        /// <param name="reg">クライアント</param>
        /// <param name="responseMode">response_mode（null なら付けない）</param>
        /// <returns>応答</returns>
        private static async Task<JsonResponse> ParAsync(IdPClient client, ClientRegistration reg, string responseMode)
        {
            JsonResponse discovery = await client.GetJsonAsync("/.well-known/openid-configuration");
            string endpoint = discovery.String("pushed_authorization_request_endpoint");

            Assert.False(string.IsNullOrEmpty(endpoint), "前提: PAR の口が広告されていること");

            Dictionary<string, string> form = new Dictionary<string, string>()
            {
                { "response_type", "code" },
                { "redirect_uri", reg.RedirectUri },
                { "scope", "openid" },
                { "state", "state-rt3811-4" },
                { "nonce", "nonce-rt3811-4" },
                { "code_challenge", "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM" },
                { "code_challenge_method", "S256" }
            };

            if (responseMode != null)
            {
                form["response_mode"] = responseMode;
            }

            return await client.PostJsonWithBasicAuthAsync(client.ToLocalUrl(endpoint), form, reg.ClientId, reg.ClientSecret);
        }

        #endregion
    }
}
