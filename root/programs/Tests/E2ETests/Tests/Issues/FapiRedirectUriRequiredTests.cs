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
//* クラス名        ：FapiRedirectUriRequiredTests
//* クラス日本語名  ：RT-422 FAPI の登録では、redirect_uri を省けない（FAPI 2.0 Security Profile §5.3.2.2 の 6・FAPI 1.0 Baseline §5.2.2 の 9）
//*
//* 作成日時        ：－
//* 作成者          ：－
//* 更新履歴        ：－
//*
//*  日時        更新者            内容
//*  ----------  ----------------  -------------------------------------------------
//*  2026/11/23  玄人 幸道         新規（#422）
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
    /// RT-422. **FAPI の登録では、`redirect_uri` を省けない**（登録が 1 件でも、RFC 6749 §3.1.2.3 の補いを使わせない）。
    /// </summary>
    /// <remarks>
    /// **以前は、`openid` の無い fapi2 の PAR の要求を、`redirect_uri` 無しで受け、認可コードまで出していた**
    /// （適合性テストの `fapi2-sp-plain-oauth` の `ensure-request-object-without-redirect-uri-fails`・`ensure-redirect-uri-in-authorization-request`）。
    /// **`openid` の要求は、以前から必須**（OIDC Core 1.0 §3.1.2.1）。
    ///
    /// | | 測ること |
    /// |---|---|
    /// | **`RT-422.1`** | **fapi2 の登録の `/par` は、`openid` の有無によらず、`redirect_uri` の無い要求を `invalid_request` で断る**（FAPI 2.0 Security Profile §5.3.2.2 の 6）。`redirect_uri` を付ければ受ける |
    /// | **`RT-422.2`** | **fapi1 の登録は、経路（クエリ・PAR）によらず、`openid` の無い要求でも `redirect_uri` を求める**（FAPI 1.0 Baseline §5.2.2 の 9。Advanced §5.2.2 が引き継ぐ） |
    /// | **`RT-422.3`** | **fapi2 の PAR を使わない要求と、normal の登録は、従来どおり省ける**（原典が PAR の要求に限るため。#422 の決め） |
    ///
    /// **測るクライアントは、どれも `redirect_uri` の登録が 1 件**（2 件以上なら、以前から省けない。`RT-306.3`）。
    /// </remarks>
    public class FapiRedirectUriRequiredTests : TargetTestBase
    {
        /// <summary>client_assertion_type（RFC 7523 §2.2）</summary>
        private const string JwtBearerAssertionType = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer";

        /// <summary>code_challenge（RFC 7636 Appendix B の S256。FAPI の PAR は S256 の PKCE を求める。#366・#383）</summary>
        private const string Challenge = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";

        /// <summary>openid の無い scope（OIDC を使わない要求）</summary>
        private const string PlainScope = "email";

        /// <summary>コンストラクタ</summary>
        /// <param name="output">ITestOutputHelper</param>
        public FapiRedirectUriRequiredTests(ITestOutputHelper output) : base(output)
        {
        }

        #region RT-422.1

        /// <summary>RT-422.1 fapi2 の登録の PAR は、redirect_uri の無い要求を断る</summary>
        /// <param name="targetKey">core / netfx</param>
        /// <returns>Task</returns>
        [SkippableTheory]
        [MemberData(nameof(AllTargets))]
        public async Task RT42201_fapi2の登録のPARはredirect_uriの無い要求を断る(string targetKey)
        {
            using (IdPClient client = this.Client(targetKey))
            {
                TestReport r = this.Report("RT-422.1",
                    "fapi2 の登録の /par は、openid の有無によらず、redirect_uri の無い要求を invalid_request で断る（付ければ受ける）",
                    "**FAPI 2.0 は、認可サーバに「PAR の要求には redirect_uri を求める」ことを求める**（openid の有無を問わない）。"
                    + "**以前は openid の無い要求を、登録の 1 件で補って受け、認可コードまで出していた**"
                    + "（適合性テストの fapi2-sp-plain-oauth）。openid の要求は、以前から OIDC Core で断っていた。",
                    "FAPI 2.0 Security Profile §5.3.2.2 / OIDC Core 1.0 §3.1.2.1 / #422");

                ClientRegistration reg = Flows.InjectedRegistration(client, KnownClients.TestClient_32);
                string endpoint = await FapiRedirectUriRequiredTests.ParEndpointAsync(client);
                string issuer = await client.IssuerAsync();

                r.Target("POST /par（client_name=" + KnownClients.TestClient_32 + "。fapi2。private_key_jwt で認証する。redirect_uri の登録は 1 件）");

                r.Step("(1) openid の無い要求に、redirect_uri を付けて預ける（受ける）");

                JsonResponse with = await FapiRedirectUriRequiredTests.Fapi2ParAsync(
                    client, reg, endpoint, issuer, FapiRedirectUriRequiredTests.PlainScope, reg.RedirectUri, "state-rt4221-1");

                r.VerifyEqual("redirect_uri あり : HTTP 201", "201", ((int)with.StatusCode).ToString());

                r.Step("(2) openid の無い要求から、redirect_uri を省く");

                FapiRedirectUriRequiredTests.VerifyRejected(r, "openid 無し・redirect_uri 無し",
                    await FapiRedirectUriRequiredTests.Fapi2ParAsync(
                        client, reg, endpoint, issuer, FapiRedirectUriRequiredTests.PlainScope, null, "state-rt4221-2"));

                r.Step("(3) openid の要求から、redirect_uri を省く（以前から断る）");

                FapiRedirectUriRequiredTests.VerifyRejected(r, "openid・redirect_uri 無し",
                    await FapiRedirectUriRequiredTests.Fapi2ParAsync(
                        client, reg, endpoint, issuer, "openid", null, "state-rt4221-3"));

                r.Done();
            }
        }

        #endregion

        #region RT-422.2

        /// <summary>RT-422.2 fapi1 の登録は、経路によらず redirect_uri を求める</summary>
        /// <param name="targetKey">core / netfx</param>
        /// <returns>Task</returns>
        [SkippableTheory]
        [MemberData(nameof(AllTargets))]
        public async Task RT42202_fapi1の登録は経路によらずredirect_uriを求める(string targetKey)
        {
            using (IdPClient client = await this.SignedInClientAsync(targetKey))
            {
                TestReport r = this.Report("RT-422.2",
                    "fapi1 の登録は、openid の無い要求でも、クエリ・PAR のどちらでも redirect_uri を求める（省くと invalid_request）",
                    "**FAPI 1.0 Baseline は、認可サーバに「認可要求に redirect_uri を求める」ことを求め、経路を限らない**（Advanced §5.2.2 が引き継ぐ）。"
                    + "**クエリでは、エラーを登録の redirect_uri へ返す**（登録が 1 件なので、返し先は決まる。RFC 6749 §4.1.2.1）。"
                    + "**PAR では、400 で断り、request_uri を返さない。**",
                    "FAPI 1.0 Baseline §5.2.2 / FAPI 1.0 Advanced §5.2.2 / RFC 6749 §4.1.2.1 / #422");

                ClientRegistration reg = Flows.Registration(client, KnownClients.Fapi1Client);

                r.Target("GET /authorize・POST /par（client_name=" + KnownClients.Fapi1Client + "。fapi1。client_secret_basic。redirect_uri の登録は 1 件）");

                r.Step("(1) クエリ：openid の無い要求に、redirect_uri を付ける（断らない）");

                //  **fapi1 は JARM の要求だけを受ける**（#381）。
                AuthZResponse with = (await Flows.AuthorizeCodeAsync(
                    client, reg, scope: FapiRedirectUriRequiredTests.PlainScope, nonce: null,
                    redirectUri: reg.RedirectUri, extra: Flows.WithJarm())).Unwrap();

                r.Verify("redirect_uri あり : code が返る",
                    with.Error == null && !string.IsNullOrEmpty(with.Code),
                    "code",
                    !string.IsNullOrEmpty(with.Code) ? "code"
                        : "**error=" + (with.Error ?? "なし") + "（" + (with.ErrorDescription ?? "") + "）**");

                r.Step("(2) クエリ：openid の無い要求から、redirect_uri を省く");

                AuthZResponse without = (await Flows.AuthorizeCodeAsync(
                    client, reg, scope: FapiRedirectUriRequiredTests.PlainScope, nonce: null,
                    redirectUri: null, extra: Flows.WithJarm())).Unwrap();

                r.Verify("redirect_uri 無し : code を出さない", string.IsNullOrEmpty(without.Code),
                    "出さない", string.IsNullOrEmpty(without.Code) ? "出さなかった" : "**出した**");

                r.VerifyEqual("redirect_uri 無し : RP へ invalid_request を返す", "invalid_request", without.Error ?? "（無し）");
                FapiRedirectUriRequiredTests.VerifyReason(r, "redirect_uri 無し", without.ErrorDescription);

                r.Step("(3) PAR：openid の無い要求から、redirect_uri を省く（S256 の PKCE と JARM は付ける。#383・#381）");

                string endpoint = await FapiRedirectUriRequiredTests.ParEndpointAsync(client);

                JsonResponse par = await client.PostJsonWithBasicAuthAsync(endpoint, new Dictionary<string, string>()
                {
                    { "response_type", "code" },
                    { "scope", FapiRedirectUriRequiredTests.PlainScope },
                    { "state", "state-rt4222-3" },
                    { "response_mode", "jwt" },
                    { "code_challenge", FapiRedirectUriRequiredTests.Challenge },
                    { "code_challenge_method", "S256" }
                }, reg.ClientId, reg.ClientSecret);

                FapiRedirectUriRequiredTests.VerifyRejected(r, "PAR・redirect_uri 無し", par);

                r.Done();
            }
        }

        #endregion

        #region RT-422.3

        /// <summary>RT-422.3 fapi2 の PAR を使わない要求と、normal の登録は、従来どおり省ける</summary>
        /// <remarks>
        /// **(1) は、PAR を必須にしていない fapi2 の登録（`FAPI2_Client`）の振る舞いを、変えていないことを確かめるもの**である。
        /// **FAPI 2.0 Security Profile §5.3.2.2 の 3（PAR を使わない認可要求を断る）は、登録の `require_pushed_authorization_requests`
        /// （またはサーバ全体の `RequirePushedAuthorizationRequests`）で強制する**（#346）。その登録では、PAR を使わない要求は
        /// `redirect_uri` を見る前に断られる。**§5.3.2.2 の 6 が PAR の要求に限るので、ここでは redirect_uri を求めない**（#422 の別モデルのレビュー）。
        /// </remarks>
        /// <param name="targetKey">core / netfx</param>
        /// <returns>Task</returns>
        [SkippableTheory]
        [MemberData(nameof(AllTargets))]
        public async Task RT42203_fapi2のPARを使わない要求とnormalは従来どおり省ける(string targetKey)
        {
            using (IdPClient client = await this.SignedInClientAsync(targetKey))
            {
                TestReport r = this.Report("RT-422.3",
                    "openid の無い要求で redirect_uri を省いても、fapi2 の PAR を使わない要求（クエリ）と normal の登録は、従来どおり断らない",
                    "**FAPI 2.0 Security Profile §5.3.2.2 の 6 が redirect_uri を求めるのは、PAR の要求だけ**（原典が経路を限るなら、その経路だけにする。#383 と同じ決め）。"
                    + "**normal の登録は、RFC 6749 §3.1.2.3 のとおり、登録が 1 件なら省ける。**",
                    "FAPI 2.0 Security Profile §5.3.2.2 / RFC 6749 §3.1.2.3 / #422");

                r.Target("GET /authorize（クエリ。openid の無い要求。redirect_uri 無し）");

                r.Step("(1) fapi2 の登録（" + KnownClients.Fapi2Client + "。PAR を必須にしていない）。S256 の PKCE を付ける（#366）");

                ClientRegistration fapi2 = Flows.Registration(client, KnownClients.Fapi2Client);

                AuthZResponse f2 = await Flows.AuthorizeCodeAsync(
                    client, fapi2, scope: FapiRedirectUriRequiredTests.PlainScope, nonce: null, redirectUri: null,
                    extra: new Dictionary<string, string>()
                    {
                        { "code_challenge", FapiRedirectUriRequiredTests.Challenge },
                        { "code_challenge_method", "S256" }
                    });

                r.Verify("fapi2・クエリ : code が返る（断らない）",
                    f2.Error == null && !string.IsNullOrEmpty(f2.Code),
                    "code",
                    !string.IsNullOrEmpty(f2.Code) ? "code"
                        : "**error=" + (f2.Error ?? "なし") + "（" + (f2.ErrorDescription ?? "") + "）**");

                r.Step("(2) normal の登録（" + KnownClients.TestClient + "）");

                ClientRegistration normal = Flows.Registration(client, KnownClients.TestClient);

                AuthZResponse n = await Flows.AuthorizeCodeAsync(
                    client, normal, scope: FapiRedirectUriRequiredTests.PlainScope, nonce: null, redirectUri: null);

                r.Verify("normal : code が返る（断らない）",
                    n.Error == null && !string.IsNullOrEmpty(n.Code),
                    "code",
                    !string.IsNullOrEmpty(n.Code) ? "code"
                        : "**error=" + (n.Error ?? "なし") + "（" + (n.ErrorDescription ?? "") + "）**");

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

        /// <summary>PS256 の client_assertion を作る（RFC 7523 §2.2。fapi2 の aud は issuer。#395・#398）</summary>
        /// <param name="client">IdPClient</param>
        /// <param name="clientId">client_id</param>
        /// <param name="issuer">issuer</param>
        /// <returns>client_assertion</returns>
        private static string ClientAssertion(IdPClient client, string clientId, string issuer)
        {
            long now = DateTimeOffset.UtcNow.ToUnixTimeSeconds();

            return JwsSigner.SignPS256(client, new Dictionary<string, object>()
            {
                { "iss", clientId },
                { "sub", clientId },
                { "aud", issuer },
                { "jti", Guid.NewGuid().ToString("N") },
                { "iat", now },
                { "exp", now + 300 }
            });
        }

        /// <summary>fapi2 の登録（private_key_jwt）で、request（JAR）を PAR に預ける（S256 の PKCE を付ける。#366）</summary>
        /// <param name="client">IdPClient</param>
        /// <param name="reg">クライアント</param>
        /// <param name="endpoint">PAR の口</param>
        /// <param name="issuer">issuer</param>
        /// <param name="scope">scope</param>
        /// <param name="redirectUri">redirect_uri（null なら入れない）</param>
        /// <param name="state">state</param>
        /// <returns>応答</returns>
        private static async Task<JsonResponse> Fapi2ParAsync(
            IdPClient client, ClientRegistration reg, string endpoint, string issuer,
            string scope, string redirectUri, string state)
        {
            Dictionary<string, object> parameters = new Dictionary<string, object>()
            {
                { "response_type", "code" },
                { "scope", scope },
                { "state", state },
                { "code_challenge", FapiRedirectUriRequiredTests.Challenge },
                { "code_challenge_method", "S256" }
            };

            if (redirectUri != null)
            {
                parameters["redirect_uri"] = redirectUri;
            }

            return await client.PostJsonAsync(endpoint, new Dictionary<string, string>()
            {
                { "request", await RequestObjectBuilder.CreateFapiAsync(client, reg.ClientId, parameters) },
                { "client_assertion_type", FapiRedirectUriRequiredTests.JwtBearerAssertionType },
                { "client_assertion", FapiRedirectUriRequiredTests.ClientAssertion(client, reg.ClientId, issuer) }
            });
        }

        /// <summary>PAR が invalid_request で断り、request_uri を返さないことを確かめる</summary>
        /// <param name="r">TestReport</param>
        /// <param name="label">何の要求か</param>
        /// <param name="res">応答</param>
        private static void VerifyRejected(TestReport r, string label, JsonResponse res)
        {
            r.VerifyEqual(label + " : HTTP 400", "400", ((int)res.StatusCode).ToString());
            r.VerifyEqual(label + " : invalid_request", "invalid_request", res.Error ?? "（無い）");
            FapiRedirectUriRequiredTests.VerifyReason(r, label, res.ErrorDescription);
            r.Verify(label + " : request_uri を返さない", string.IsNullOrEmpty(res.String("request_uri")),
                "返さない", string.IsNullOrEmpty(res.String("request_uri")) ? "返さなかった" : "**返した**");
        }

        /// <summary>断った理由が redirect_uri であることを確かめる</summary>
        /// <param name="r">TestReport</param>
        /// <param name="label">何の要求か</param>
        /// <param name="description">error_description</param>
        /// <remarks>
        /// **別の理由（PKCE・JARM・nonce など）で先に断られて「通った」ことにならないよう、理由まで見る**（QUALITY.md 4 節）。
        /// </remarks>
        private static void VerifyReason(TestReport r, string label, string description)
        {
            r.Verify(label + " : 理由が redirect_uri（error_description）",
                (description ?? "").IndexOf("redirect_uri", StringComparison.Ordinal) >= 0,
                "redirect_uri を含む", description ?? "（無い）");
        }

        #endregion
    }
}
