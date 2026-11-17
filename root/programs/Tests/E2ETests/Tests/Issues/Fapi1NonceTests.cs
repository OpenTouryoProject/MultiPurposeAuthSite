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
//* クラス名        ：Fapi1NonceTests
//* クラス日本語名  ：RT-382 fapi1 の登録の openid の認可要求では、nonce を必須にする（FAPI 1.0 Baseline §5.2.2.2 の 1）
//*
//* 作成日時        ：－
//* 作成者          ：－
//* 更新履歴        ：－
//*
//*  日時        更新者            内容
//*  ----------  ----------------  -------------------------------------------------
//*  2026/11/16  玄人 幸道         新規（#382）
//*  2026/11/17  玄人 幸道         fapi1 の要求を JARM にし、断る理由が nonce であることも確かめる（fapi1 は JARM の要求だけを受けるようになった。#381）
//**********************************************************************************

using System.Collections.Generic;
using System.Threading.Tasks;

using MultiPurposeAuthSite.Tests.E2E.Infrastructure;

using Xunit;
using Xunit.Abstractions;

namespace MultiPurposeAuthSite.Tests.E2E.Tests.Issues
{
    /// <summary>
    /// RT-382. **fapi1 の登録（`client_mode=fapi1`）の `openid` の認可要求では、`nonce` を必須にする**（FAPI 1.0 Baseline §5.2.2.2 の 1）。
    /// </summary>
    /// <remarks>
    /// **以前は、`nonce` を必須にしていたのは `id_token` を認可の口から返す `response_type` だけ**で（OIDC Core 1.0 §3.1.2.1・§3.3.2.1）、
    /// **fapi1 の登録の `response_type=code` は `nonce` 無しで通っていた**（適合性テストの `ensure-request-object-without-nonce-fails`）。
    ///
    /// | | 測ること |
    /// |---|---|
    /// | **`RT-382.1`** | **fapi1 の登録の `openid` の要求は、`nonce` が無ければ `invalid_request`**（クエリは RP へ返す。PAR は `400`）。`nonce` が在れば通る。**`openid` を含まない要求・fapi1 でない登録は従来どおり** |
    ///
    /// **fapi2 は `nonce` を求めない**（FAPI 2.0 Security Profile）ので、変えていない。
    ///
    /// **fapi1 の要求は JARM（`response_mode=jwt`）で送る**（fapi1 の登録は JARM の要求だけを受ける。#381）。
    /// **JARM を付けないと、`nonce` より先に JARM の確かめで断られる**ので、**断る理由が `nonce` であることも `error_description` で確かめる。**
    /// </remarks>
    public class Fapi1NonceTests : TargetTestBase
    {
        /// <summary>コンストラクタ</summary>
        /// <param name="output">ITestOutputHelper</param>
        public Fapi1NonceTests(ITestOutputHelper output) : base(output)
        {
        }

        /// <summary>RT-382.1 fapi1 の登録の openid の要求は、nonce が無ければ断る</summary>
        /// <param name="targetKey">core / netfx</param>
        /// <returns>Task</returns>
        [SkippableTheory]
        [MemberData(nameof(AllTargets))]
        public async Task RT38201_fapi1の登録のopenidの要求はnonceが無ければ断る(string targetKey)
        {
            using (IdPClient client = await this.SignedInClientAsync(targetKey))
            {
                TestReport r = this.Report("RT-382.1",
                    "fapi1 の登録の openid の認可要求は、nonce が無ければ invalid_request で断る（クエリ・PAR とも）。openid を含まない要求・fapi1 でない登録は従来どおり",
                    "**FAPI 1.0 Baseline は、openid を要求するクライアントに対して、認可サーバが nonce を求めることを求める。**"
                    + "**以前は response_type=code の fapi1 の要求が nonce 無しで通っていた**（適合性テストの ensure-request-object-without-nonce-fails）。"
                    + "**OIDC Core の Authorization Code フローでは nonce は任意**なので、fapi1 でない登録は変えない。",
                    "FAPI 1.0 Baseline §5.2.2.2 / OIDC Core 1.0 §3.1.2.1 / #382");

                ClientRegistration fapi1 = Flows.Registration(client, KnownClients.Fapi1Client);
                ClientRegistration normal = Flows.Registration(client, KnownClients.MvcSample);

                r.Target("GET /authorize・POST /par（" + KnownClients.Fapi1Client + "（fapi1）・"
                    + KnownClients.MvcSample + "（normal））");

                r.Step("(1) fapi1・openid・nonce 無し（クエリ）は、invalid_request を RP へ返す");

                AuthZResponse noNonce = (await Flows.AuthorizeCodeAsync(
                    client, fapi1, "openid", "state-rt3821-1", nonce: null, redirectUri: fapi1.RedirectUri,
                    extra: Flows.WithJarm())).Unwrap();

                r.VerifyEqual("error", "invalid_request", noNonce.Error ?? "（無い）");
                Fapi1NonceTests.VerifyReasonIsNonce(r, "クエリ", noNonce.ErrorDescription);
                r.Verify("code を返さない", string.IsNullOrEmpty(noNonce.Code),
                    "返さない", string.IsNullOrEmpty(noNonce.Code) ? "返さなかった" : "**返した**");

                r.Step("(2) 対照：fapi1・openid・nonce 在り（クエリ）は、code を返す");

                AuthZResponse withNonce = (await Flows.AuthorizeCodeAsync(
                    client, fapi1, "openid", "state-rt3821-2", "nonce-rt3821-2", fapi1.RedirectUri,
                    Flows.WithJarm())).Unwrap();

                Fapi1NonceTests.VerifyCode(r, "fapi1・nonce 在り", withNonce);

                r.Step("(3) fapi1・openid・nonce 無し（PAR）は、400 ＋ invalid_request");

                JsonResponse par = await Fapi1NonceTests.ParWithoutNonceAsync(client, fapi1);

                r.VerifyEqual("PAR : HTTP 400", "400", ((int)par.StatusCode).ToString());
                r.VerifyEqual("PAR : invalid_request", "invalid_request", par.Error ?? "（無い）");
                Fapi1NonceTests.VerifyReasonIsNonce(r, "PAR", par.String("error_description"));

                r.Step("(4) fapi1・openid を含まない要求は、nonce 無しでも nonce では断らない");

                AuthZResponse noOpenid = (await Flows.AuthorizeCodeAsync(
                    client, fapi1, "profile", "state-rt3821-4", nonce: null, redirectUri: fapi1.RedirectUri,
                    extra: Flows.WithJarm())).Unwrap();

                Fapi1NonceTests.VerifyCode(r, "fapi1・openid 無し", noOpenid);

                r.Step("(5) fapi1 でない登録・openid・nonce 無しは、従来どおり code を返す（OIDC Core では任意）");

                AuthZResponse normalNoNonce = await Flows.AuthorizeCodeAsync(
                    client, normal, "openid", "state-rt3821-5", nonce: null, redirectUri: normal.RedirectUri);

                Fapi1NonceTests.VerifyCode(r, "normal・nonce 無し", normalNoNonce);

                r.Done();
            }
        }

        #region 補助

        /// <summary>code が返ったことを確かめる</summary>
        /// <param name="r">TestReport</param>
        /// <param name="label">何の要求か</param>
        /// <param name="authz">AuthZResponse</param>
        private static void VerifyCode(TestReport r, string label, AuthZResponse authz)
        {
            r.Verify(label + " : code が返る",
                authz.Error == null && !string.IsNullOrEmpty(authz.Code),
                "code",
                !string.IsNullOrEmpty(authz.Code) ? "code"
                    : "**error=" + (authz.Error ?? "なし") + "（" + (authz.ErrorDescription ?? "") + "）**");
        }

        /// <summary>断る理由が nonce であることを確かめる（JARM の確かめで先に断られていないこと。#381）</summary>
        /// <param name="r">TestReport</param>
        /// <param name="label">どの経路か</param>
        /// <param name="description">error_description</param>
        private static void VerifyReasonIsNonce(TestReport r, string label, string description)
        {
            bool isNonce = !string.IsNullOrEmpty(description) && description.Contains("nonce");

            r.Verify(label + " : 断る理由は nonce", isNonce,
                "nonce", isNonce ? "nonce" : "**" + (description ?? "（無い）") + "**");
        }

        /// <summary>fapi1 の登録（client_secret_basic）で、nonce の無い要求を PAR に預ける（S256 の PKCE と JARM は付ける。#383・#381）</summary>
        /// <param name="client">IdPClient</param>
        /// <param name="reg">クライアント</param>
        /// <returns>応答</returns>
        private static async Task<JsonResponse> ParWithoutNonceAsync(IdPClient client, ClientRegistration reg)
        {
            JsonResponse discovery = await client.GetJsonAsync("/.well-known/openid-configuration");
            string endpoint = discovery.String("pushed_authorization_request_endpoint");

            Assert.False(string.IsNullOrEmpty(endpoint), "前提: PAR の口が広告されていること");

            return await client.PostJsonWithBasicAuthAsync(client.ToLocalUrl(endpoint), new Dictionary<string, string>()
            {
                { "response_type", "code" },
                { "redirect_uri", reg.RedirectUri },
                { "scope", "openid" },
                { "state", "state-rt3821-3" },
                { "response_mode", "jwt" },
                { "code_challenge", "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM" },
                { "code_challenge_method", "S256" }
            }, reg.ClientId, reg.ClientSecret);
        }

        #endregion
    }
}
