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
//* クラス名        ：PkceS256Tests
//* クラス日本語名  ：RT-366 FAPI 2.0 の登録では、S256 の PKCE を必須にする（FAPI 2.0 Security Profile §5.3.2.2）
//*
//* 作成日時        ：－
//* 作成者          ：－
//* 更新履歴        ：－
//*
//*  日時        更新者            内容
//*  ----------  ----------------  -------------------------------------------------
//*  2026/11/13  玄人 幸道         新規（#366）
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
    /// RT-366. **FAPI 2.0 の登録（`client_mode=fapi2`）では、S256 の PKCE を必須にする**（FAPI 2.0 Security Profile §5.3.2.2 の 5）。
    /// </summary>
    /// <remarks>
    /// **以前は、方式を絞るのはサーバ全体の `RequirePkceS256` だけで、それも `/token` で見ていた。**
    /// **PKCE を必須にするかも、登録の `require_pkce` だけで決まっていた。**
    /// そのため、**fapi2 の登録でも、plain の PKCE（や PKCE 無し）で預けた要求に `code` を出していた**
    /// （適合性テストの `fapi2-security-profile-final-par-plain-pkce-rejected`）。
    ///
    /// | | 測ること |
    /// |---|---|
    /// | **`RT-366.1`** | **fapi2 の登録の PAR は、S256 だけを受け、plain・方式の省略・PKCE 無しを `invalid_request` で断る**。S256 で預けた `request_uri` は、認可の口でも断られない |
    /// | **`RT-366.2`** | **fapi2 でない登録は、従来どおり plain・PKCE 無しを受ける**（既定の `RequirePkceS256=false`） |
    /// | **`RT-366.3`** | **PAR を使わない `/authorize`（クエリ）でも、fapi2 の登録の plain・省略・PKCE 無しを `invalid_request` で RP へ返す**。S256 なら code を出す |
    ///
    /// **`RequirePkceS256=true` の配備で、認可要求の時点で plain を断ること**は、E2E では測っていない（既定の配備では false）。
    /// </remarks>
    public class PkceS256Tests : TargetTestBase
    {
        /// <summary>client_assertion_type（RFC 7523 §2.2）</summary>
        private const string JwtBearerAssertionType = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer";

        /// <summary>code_verifier（RFC 7636 Appendix B）</summary>
        private const string Verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";

        /// <summary>Verifier の S256（RFC 7636 Appendix B）</summary>
        private const string Challenge = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";

        /// <summary>コンストラクタ</summary>
        /// <param name="output">ITestOutputHelper</param>
        public PkceS256Tests(ITestOutputHelper output) : base(output)
        {
        }

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

        /// <summary>認可要求のパラメタ（PKCE の部分は pkce で足す）</summary>
        /// <param name="reg">クライアント</param>
        /// <param name="state">state</param>
        /// <param name="pkce">code_challenge・code_challenge_method（無ければ PKCE 無し）</param>
        /// <returns>パラメタ</returns>
        private static Dictionary<string, object> Parameters(
            ClientRegistration reg, string state, IDictionary<string, string> pkce)
        {
            Dictionary<string, object> parameters = new Dictionary<string, object>()
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
                    parameters[p.Key] = p.Value;
                }
            }

            return parameters;
        }

        /// <summary>RS256 の client_assertion を作る（RFC 7523 §2.2。fapi2 の aud は issuer）</summary>
        /// <param name="client">IdPClient</param>
        /// <param name="clientId">client_id</param>
        /// <param name="issuer">issuer</param>
        /// <returns>client_assertion</returns>
        private static string ClientAssertion(IdPClient client, string clientId, string issuer)
        {
            long now = DateTimeOffset.UtcNow.ToUnixTimeSeconds();

            return JwsSigner.SignRS256(client, new Dictionary<string, object>()
            {
                { "iss", clientId },
                { "sub", clientId },
                { "aud", issuer },
                { "jti", Guid.NewGuid().ToString("N") },
                { "iat", now },
                { "exp", now + 300 }
            });
        }

        /// <summary>fapi2 の登録（private_key_jwt）で、request（JAR）を PAR に預ける</summary>
        /// <param name="client">IdPClient</param>
        /// <param name="reg">クライアント</param>
        /// <param name="endpoint">PAR の口</param>
        /// <param name="issuer">issuer</param>
        /// <param name="state">state</param>
        /// <param name="pkce">PKCE のパラメタ（無ければ PKCE 無し）</param>
        /// <returns>応答</returns>
        private static async Task<JsonResponse> Fapi2ParAsync(
            IdPClient client, ClientRegistration reg, string endpoint, string issuer,
            string state, IDictionary<string, string> pkce)
        {
            return await client.PostJsonAsync(endpoint, new Dictionary<string, string>()
            {
                { "request", await RequestObjectBuilder.CreateAsync(client, reg.ClientId,
                    PkceS256Tests.Parameters(reg, state, pkce)) },
                { "client_assertion_type", PkceS256Tests.JwtBearerAssertionType },
                { "client_assertion", PkceS256Tests.ClientAssertion(client, reg.ClientId, issuer) }
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
            r.Verify(label + " : request_uri を返さない", string.IsNullOrEmpty(res.String("request_uri")),
                "返さない", string.IsNullOrEmpty(res.String("request_uri")) ? "返さなかった" : "**返した**");
        }

        #endregion

        #region RT-366.1

        /// <summary>RT-366.1 fapi2 の登録の PAR は、S256 の PKCE だけを受ける</summary>
        /// <param name="targetKey">core / netfx</param>
        /// <returns>Task</returns>
        [SkippableTheory]
        [MemberData(nameof(AllTargets))]
        public async Task RT36601_fapi2の登録のPARはS256のPKCEだけを受ける(string targetKey)
        {
            using (IdPClient client = await this.SignedInClientAsync(targetKey))
            {
                TestReport r = this.Report("RT-366.1",
                    "fapi2 の登録の /par は、S256 の PKCE だけを受け、plain・code_challenge_method の省略・PKCE 無しを invalid_request で断る",
                    "**FAPI 2.0 は、認可サーバに「S256 の PKCE を必須にする」ことを求める。**"
                    + "**code_challenge_method を省くと plain の扱い**（RFC 7636 §4.3）なので、これも断る。"
                    + "**以前は plain で預けた要求にも code を出していた**（適合性テストの par-plain-pkce-rejected）。"
                    + "**S256 で預けた request_uri は、認可の口でも断られない**（Request Object の code_challenge_method を読む）。",
                    "FAPI 2.0 Security Profile §5.3.2.2 / RFC 7636 §4.3 / RFC 7636 §4.4.1 / #366");

                ClientRegistration reg = Flows.InjectedRegistration(client, KnownClients.TestClient_32);
                string endpoint = await PkceS256Tests.ParEndpointAsync(client);
                string issuer = await client.IssuerAsync();

                r.Target("POST /par（client_name=" + KnownClients.TestClient_32 + "。fapi2。private_key_jwt で認証する）");

                r.Step("(1) S256 で預ける（受ける）");

                JsonResponse s256 = await PkceS256Tests.Fapi2ParAsync(client, reg, endpoint, issuer, "state-rt3661-1",
                    new Dictionary<string, string>()
                    {
                        { "code_challenge", PkceS256Tests.Challenge },
                        { "code_challenge_method", "S256" }
                    });

                r.VerifyEqual("HTTP 201", "201", ((int)s256.StatusCode).ToString());

                string requestUri = s256.String("request_uri");
                Assert.False(string.IsNullOrEmpty(requestUri), "前提: request_uri が返ること");

                r.Step("(2) その request_uri で認可の口へ行く（断られない）");

                AuthZResponse authz = await client.AuthorizeAsync(new Dictionary<string, string>()
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

                r.Step("(3) plain で預ける");

                PkceS256Tests.VerifyRejected(r, "plain", await PkceS256Tests.Fapi2ParAsync(
                    client, reg, endpoint, issuer, "state-rt3661-3",
                    new Dictionary<string, string>()
                    {
                        { "code_challenge", PkceS256Tests.Verifier },
                        { "code_challenge_method", "plain" }
                    }));

                r.Step("(4) code_challenge_method を省く（plain の扱い）");

                PkceS256Tests.VerifyRejected(r, "code_challenge_method の省略", await PkceS256Tests.Fapi2ParAsync(
                    client, reg, endpoint, issuer, "state-rt3661-4",
                    new Dictionary<string, string>()
                    {
                        { "code_challenge", PkceS256Tests.Challenge }
                    }));

                r.Step("(5) PKCE を使わない");

                PkceS256Tests.VerifyRejected(r, "PKCE 無し", await PkceS256Tests.Fapi2ParAsync(
                    client, reg, endpoint, issuer, "state-rt3661-5", null));

                r.Done();
            }
        }

        #endregion

        #region RT-366.2

        /// <summary>RT-366.2 fapi2 でない登録は、従来どおり plain・PKCE 無しを受ける</summary>
        /// <param name="targetKey">core / netfx</param>
        /// <returns>Task</returns>
        [SkippableTheory]
        [MemberData(nameof(AllTargets))]
        public async Task RT36602_fapi2でない登録は従来どおりplainを受ける(string targetKey)
        {
            using (IdPClient client = this.Client(targetKey))
            {
                TestReport r = this.Report("RT-366.2",
                    "fapi2 でない登録の /par は、従来どおり plain の PKCE と PKCE 無しを受ける",
                    "**S256 に限るのは、fapi2 の登録と、サーバ全体の RequirePkceS256 だけ。**"
                    + "**既定の配備（RequirePkceS256=false）の normal の登録は、振る舞いを変えない**（RFC 7636 §4.2 は plain も定義している）。",
                    "RFC 7636 §4.2 / RFC 7636 §4.3 / #366");

                ClientRegistration reg = Flows.Registration(client, KnownClients.TestClient);
                string endpoint = await PkceS256Tests.ParEndpointAsync(client);

                r.Target("POST /par（client_name=" + KnownClients.TestClient + "。normal。client_secret_basic で認証する）");

                r.Step("(1) plain で預ける");

                Dictionary<string, string> plain = new Dictionary<string, string>()
                {
                    { "response_type", "code" },
                    { "redirect_uri", reg.RedirectUri },
                    { "scope", "openid" },
                    { "state", "state-rt3662-1" },
                    { "nonce", "nonce-rt3662-1" },
                    { "code_challenge", PkceS256Tests.Verifier },
                    { "code_challenge_method", "plain" }
                };

                JsonResponse resPlain = await client.PostJsonWithBasicAuthAsync(
                    endpoint, plain, reg.ClientId, reg.ClientSecret);

                r.VerifyEqual("plain : HTTP 201", "201", ((int)resPlain.StatusCode).ToString());

                r.Step("(2) PKCE を使わずに預ける");

                Dictionary<string, string> none = new Dictionary<string, string>()
                {
                    { "response_type", "code" },
                    { "redirect_uri", reg.RedirectUri },
                    { "scope", "openid" },
                    { "state", "state-rt3662-2" },
                    { "nonce", "nonce-rt3662-2" }
                };

                JsonResponse resNone = await client.PostJsonWithBasicAuthAsync(
                    endpoint, none, reg.ClientId, reg.ClientSecret);

                r.VerifyEqual("PKCE 無し : HTTP 201", "201", ((int)resNone.StatusCode).ToString());

                r.Done();
            }
        }

        #endregion

        #region RT-366.3

        /// <summary>RT-366.3 /authorize のクエリでも、fapi2 の登録は S256 の PKCE だけを受ける</summary>
        /// <param name="targetKey">core / netfx</param>
        /// <returns>Task</returns>
        [SkippableTheory]
        [MemberData(nameof(AllTargets))]
        public async Task RT36603_authorizeのクエリでもfapi2はS256だけを受ける(string targetKey)
        {
            using (IdPClient client = await this.SignedInClientAsync(targetKey))
            {
                TestReport r = this.Report("RT-366.3",
                    "PAR を使わない /authorize（クエリ）でも、fapi2 の登録の plain・code_challenge_method の省略・小文字の s256・PKCE 無しを invalid_request で断り、S256 なら code を出す",
                    "**判定は PAR と同じ所（認可要求の検証）にある。** 認可の口では、**クエリの code_challenge_method を読む。**"
                    + "**エラーは RP へリダイレクトで返す**（redirect_uri を照合した後の判定のため。RFC 6749 §4.1.2.1）。",
                    "FAPI 2.0 Security Profile §5.3.2.2 / RFC 7636 §4.2 / RFC 7636 §4.3 / RFC 7636 §4.4.1 / RFC 6749 §4.1.2.1 / #366");

                ClientRegistration reg = Flows.Registration(client, KnownClients.Fapi2Client);

                r.Target("GET /authorize（client_name=" + KnownClients.Fapi2Client + "。fapi2）");

                r.Step("(1) S256（code を出す）");

                AuthZResponse s256 = await Flows.AuthorizeCodeAsync(client, reg, redirectUri: reg.RedirectUri,
                    extra: new Dictionary<string, string>()
                    {
                        { "code_challenge", PkceS256Tests.Challenge },
                        { "code_challenge_method", "S256" }
                    });

                r.Verify("S256 : code が返る", !string.IsNullOrEmpty(s256.Code),
                    "code あり",
                    string.IsNullOrEmpty(s256.Code)
                        ? "**無し**（error=" + (s256.Error ?? "なし") + "）" : "あり（値は伏せる）");

                Dictionary<string, Dictionary<string, string>> cases = new Dictionary<string, Dictionary<string, string>>()
                {
                    { "plain", new Dictionary<string, string>()
                        {
                            { "code_challenge", PkceS256Tests.Verifier },
                            { "code_challenge_method", "plain" }
                        } },
                    { "code_challenge_method の省略", new Dictionary<string, string>()
                        {
                            { "code_challenge", PkceS256Tests.Challenge }
                        } },
                    //  **値は大文字小文字を区別する**（RFC 7636 §4.2 の S256。#366 の別モデルのレビュー）
                    { "小文字の s256", new Dictionary<string, string>()
                        {
                            { "code_challenge", PkceS256Tests.Challenge },
                            { "code_challenge_method", "s256" }
                        } },
                    { "PKCE 無し", new Dictionary<string, string>() }
                };

                int step = 2;

                foreach (KeyValuePair<string, Dictionary<string, string>> c in cases)
                {
                    r.Step("(" + step++ + ") " + c.Key);

                    AuthZResponse res = await Flows.AuthorizeCodeAsync(client, reg, redirectUri: reg.RedirectUri,
                        extra: c.Value);

                    r.Verify(c.Key + " : code を出さない", string.IsNullOrEmpty(res.Code),
                        "出さない", string.IsNullOrEmpty(res.Code) ? "出さなかった" : "**出した**");

                    r.VerifyEqual(c.Key + " : RP へ invalid_request を返す", "invalid_request", res.Error ?? "（無し）");
                }

                r.Done();
            }
        }

        #endregion
    }
}
