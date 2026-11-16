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
//* クラス名        ：Fapi1ParPkceTests
//* クラス日本語名  ：RT-383 fapi1 の登録の PAR では、S256 の PKCE を必須にする（FAPI 1.0 Advanced §5.2.2 の 18）
//*
//* 作成日時        ：－
//* 作成者          ：－
//* 更新履歴        ：－
//*
//*  日時        更新者            内容
//*  ----------  ----------------  -------------------------------------------------
//*  2026/11/16  玄人 幸道         新規（#383）
//**********************************************************************************

using System.Collections.Generic;
using System.Threading.Tasks;

using MultiPurposeAuthSite.Tests.E2E.Infrastructure;

using Xunit;
using Xunit.Abstractions;

namespace MultiPurposeAuthSite.Tests.E2E.Tests.Issues
{
    /// <summary>
    /// RT-383. **fapi1 の登録（`client_mode=fapi1`）の PAR では、S256 の PKCE を必須にする**（FAPI 1.0 Advanced §5.2.2 の 18）。
    /// </summary>
    /// <remarks>
    /// **以前は、fapi1 の登録の PAR が、PKCE 無し・plain の PKCE でも受けていた**
    /// （適合性テストの `fapi1-advanced-final-par-ensure-pkce-required`・`par-plain-pkce-rejected`）。
    /// **fapi1 の公開クライアントは `/token` で S256 以外を断っていた**（`ClientModePolicy`）が、
    /// **秘密や鍵で認証する fapi1 は、PKCE 無しでも code を引き換えられた。**
    ///
    /// | | 測ること |
    /// |---|---|
    /// | **`RT-383.1`** | **fapi1 の登録の `/par` は、S256 だけを受け、plain・方式の省略・PKCE 無しを `invalid_request` で断る**。S256 で預けた `request_uri` は、認可の口でも断られない |
    /// | **`RT-383.2`** | **PAR を使わない fapi1 の要求（`/authorize` のクエリ）は、従来どおり PKCE 無しでも断らない**（原典は PAR の要求だけ。#383 の決め） |
    /// </remarks>
    public class Fapi1ParPkceTests : TargetTestBase
    {
        /// <summary>code_verifier（RFC 7636 Appendix B）</summary>
        private const string Verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";

        /// <summary>Verifier の S256（RFC 7636 Appendix B）</summary>
        private const string Challenge = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";

        /// <summary>コンストラクタ</summary>
        /// <param name="output">ITestOutputHelper</param>
        public Fapi1ParPkceTests(ITestOutputHelper output) : base(output)
        {
        }

        #region RT-383.1

        /// <summary>RT-383.1 fapi1 の登録の PAR は、S256 の PKCE だけを受ける</summary>
        /// <param name="targetKey">core / netfx</param>
        /// <returns>Task</returns>
        [SkippableTheory]
        [MemberData(nameof(AllTargets))]
        public async Task RT38301_fapi1の登録のPARはS256のPKCEだけを受ける(string targetKey)
        {
            using (IdPClient client = this.Client(targetKey))
            {
                TestReport r = this.Report("RT-383.1",
                    "fapi1 の登録の /par は、S256 の PKCE だけを受け、plain・code_challenge_method の省略・PKCE 無しを invalid_request で断る",
                    "**FAPI 1.0 Advanced は、認可サーバに「PAR の要求には S256 の PKCE を求める」ことを求める。**"
                    + "**code_challenge_method を省くと plain の扱い**（RFC 7636 §4.3）なので、これも断る。"
                    + "**以前は fapi1 の登録の PAR が、PKCE 無し・plain でも受けていた**"
                    + "（適合性テストの par-ensure-pkce-required・par-plain-pkce-rejected）。",
                    "FAPI 1.0 Advanced §5.2.2 / RFC 7636 §4.3 / RFC 7636 §4.4.1 / #383");

                ClientRegistration reg = Flows.Registration(client, KnownClients.Fapi1Client);
                string endpoint = await Fapi1ParPkceTests.ParEndpointAsync(client);

                r.Target("POST /par（client_name=" + KnownClients.Fapi1Client + "。fapi1。client_secret_basic で認証する）");

                r.Step("(1) S256 で預ける（受ける）");

                JsonResponse s256 = await Fapi1ParPkceTests.ParAsync(client, reg, endpoint, "state-rt3831-1",
                    new Dictionary<string, string>()
                    {
                        { "code_challenge", Fapi1ParPkceTests.Challenge },
                        { "code_challenge_method", "S256" }
                    });

                r.VerifyEqual("S256 : HTTP 201", "201", ((int)s256.StatusCode).ToString());

                string requestUri = s256.String("request_uri");
                Assert.False(string.IsNullOrEmpty(requestUri), "前提: request_uri が返ること");

                r.Step("(1') その request_uri で認可の口へ行く（預けた要求を読み直しても断られない）");

                using (IdPClient user = await this.SignedInClientAsync(targetKey))
                {
                    AuthZResponse authz = await user.AuthorizeAsync(new Dictionary<string, string>()
                    {
                        { "client_id", reg.ClientId },
                        { "request_uri", requestUri }
                    });

                    r.Verify("認可の口で断られない（同意画面か code）",
                        authz.Error == null && (authz.NeedsConsent || !string.IsNullOrEmpty(authz.Code)),
                        "同意画面か code",
                        authz.NeedsConsent ? "同意画面"
                            : !string.IsNullOrEmpty(authz.Code) ? "code"
                            : "**error=" + (authz.Error ?? "なし") + "（" + (authz.ErrorDescription ?? "") + "）**");
                }

                r.Step("(2) plain で預ける");

                Fapi1ParPkceTests.VerifyRejected(r, "plain", await Fapi1ParPkceTests.ParAsync(
                    client, reg, endpoint, "state-rt3831-2",
                    new Dictionary<string, string>()
                    {
                        { "code_challenge", Fapi1ParPkceTests.Verifier },
                        { "code_challenge_method", "plain" }
                    }));

                r.Step("(3) code_challenge_method を省く（plain の扱い）");

                Fapi1ParPkceTests.VerifyRejected(r, "code_challenge_method の省略", await Fapi1ParPkceTests.ParAsync(
                    client, reg, endpoint, "state-rt3831-3",
                    new Dictionary<string, string>()
                    {
                        { "code_challenge", Fapi1ParPkceTests.Challenge }
                    }));

                r.Step("(4) PKCE を使わない");

                Fapi1ParPkceTests.VerifyRejected(r, "PKCE 無し", await Fapi1ParPkceTests.ParAsync(
                    client, reg, endpoint, "state-rt3831-4", null));

                r.Done();
            }
        }

        #endregion

        #region RT-383.2

        /// <summary>RT-383.2 PAR を使わない fapi1 の要求は、従来どおり PKCE 無しでも断らない</summary>
        /// <param name="targetKey">core / netfx</param>
        /// <returns>Task</returns>
        [SkippableTheory]
        [MemberData(nameof(AllTargets))]
        public async Task RT38302_PARを使わないfapi1の要求は従来どおり(string targetKey)
        {
            using (IdPClient client = await this.SignedInClientAsync(targetKey))
            {
                TestReport r = this.Report("RT-383.2",
                    "PAR を使わない fapi1 の登録の要求（/authorize のクエリ）は、従来どおり PKCE 無しでも断らない",
                    "**FAPI 1.0 Advanced §5.2.2 の 18 が S256 の PKCE を求めるのは、PAR の要求だけ。**"
                    + "**PAR を使わない fapi1 の RP を壊さない**（#383 の決め。fapi2 は #366 で全要求に必須）。",
                    "FAPI 1.0 Advanced §5.2.2 / #383");

                ClientRegistration reg = Flows.Registration(client, KnownClients.Fapi1Client);

                r.Target("GET /authorize（client_name=" + KnownClients.Fapi1Client + "。fapi1。PKCE 無し）");

                r.Step("(1) PKCE を付けずに、クエリで認可要求を送る");

                AuthZResponse authz = await Flows.AuthorizeCodeAsync(client, reg, redirectUri: reg.RedirectUri);

                r.Verify("code が返る（PKCE 無しで断らない）",
                    authz.Error == null && !string.IsNullOrEmpty(authz.Code),
                    "code",
                    !string.IsNullOrEmpty(authz.Code) ? "code"
                        : "**error=" + (authz.Error ?? "なし") + "（" + (authz.ErrorDescription ?? "") + "）**");

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
            Assert.True(res.IsJson, "前提: Discovery 文書が JSON であること");

            string endpoint = res.String("pushed_authorization_request_endpoint");
            Assert.False(string.IsNullOrEmpty(endpoint), "前提: PAR の口が広告されていること");

            return client.ToLocalUrl(endpoint);
        }

        /// <summary>fapi1 の登録（client_secret_basic）で、フォームのパラメタを PAR に預ける</summary>
        /// <param name="client">IdPClient</param>
        /// <param name="reg">クライアント</param>
        /// <param name="endpoint">PAR の口</param>
        /// <param name="state">state</param>
        /// <param name="pkce">PKCE のパラメタ（無ければ PKCE 無し）</param>
        /// <returns>応答</returns>
        private static Task<JsonResponse> ParAsync(
            IdPClient client, ClientRegistration reg, string endpoint, string state, IDictionary<string, string> pkce)
        {
            Dictionary<string, string> form = new Dictionary<string, string>()
            {
                { "response_type", "code" },
                { "redirect_uri", reg.RedirectUri },
                { "scope", "openid" },
                { "state", state },
                { "nonce", "nonce-" + state }
            };

            if (pkce != null)
            {
                foreach (KeyValuePair<string, string> p in pkce)
                {
                    form[p.Key] = p.Value;
                }
            }

            return client.PostJsonWithBasicAuthAsync(endpoint, form, reg.ClientId, reg.ClientSecret);
        }

        /// <summary>PAR が invalid_request で断り、request_uri を返さないことを確かめる</summary>
        /// <param name="r">TestReport</param>
        /// <param name="label">何の要求か</param>
        /// <param name="res">応答</param>
        private static void VerifyRejected(TestReport r, string label, JsonResponse res)
        {
            r.VerifyEqual(label + " : HTTP 400", "400", ((int)res.StatusCode).ToString());
            r.VerifyEqual(label + " : invalid_request", "invalid_request", res.Error ?? "（無い）");
            r.Verify(label + " : request_uri を返さない", string.IsNullOrEmpty(res.String("request_uri")),
                "返さない", string.IsNullOrEmpty(res.String("request_uri")) ? "返さなかった" : "**返した**");
        }

        #endregion
    }
}
