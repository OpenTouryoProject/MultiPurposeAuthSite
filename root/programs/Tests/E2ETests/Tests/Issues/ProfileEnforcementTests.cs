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
//* クラス名        ：ProfileEnforcementTests
//* クラス日本語名  ：RT FAPI の要件を、登録ごとに強制する（#346）
//*
//* 作成日時        ：－
//* 作成者          ：－
//* 更新履歴        ：－
//*
//*  日時        更新者            内容
//*  ----------  ----------------  -------------------------------------------------
//*  2026/11/09  玄人 幸道         新規（#346 の段階 2）
//**********************************************************************************

using System;
using System.Collections.Generic;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text.Json;
using System.Threading.Tasks;

using MultiPurposeAuthSite.Tests.E2E.Infrastructure;
using MultiPurposeAuthSite.Tests.E2E.Tests.Fapi;

using Xunit;
using Xunit.Abstractions;

namespace MultiPurposeAuthSite.Tests.E2E.Tests.Issues
{
    /// <summary>
    /// RT-346. **FAPI の要件を、登録ごとに強制する**（#346）。
    /// </summary>
    /// <remarks>
    /// **以前は、FAPI として登録したクライアントでも、PAR を使わない要求・署名の無い要求・
    /// 送信者に縛らないトークンが通った**（`ANALYSIS-IdP.md` の D-16）。
    /// **登録の 4 つの項目（標準のメタデータ）で、使わない要求を断れるようにした。**
    ///
    /// | | 登録 | 測ること |
    /// |---|---|---|
    /// | **`RT-346.1`** | （動的登録） | **4 つを立てて読み戻せる**（`ClientRegistrationTests` に置いた） |
    /// | **`RT-346.2`** | `require_pushed_authorization_requests` | **PAR で預けた要求だけが通る**（クエリ・`/ros` は断る） |
    /// | **`RT-346.3`** | `require_signed_request_object` | **署名付きの Request Object だけが通る**（クエリ・フォームだけの PAR は断る） |
    /// | **`RT-346.4`** | `dpop_bound_access_tokens` | **DPoP の証明の無いトークン要求を断る**（断られた code は、まだ使える） |
    /// | **`RT-346.5`** | `tls_client_certificate_bound_access_tokens` | **証明書の無いトークン要求を断り、在れば秘密の認証でも縛る**（net10.0 版だけ） |
    /// | **`RT-346.6`** | （Discovery） | **サーバ全体の 2 つの設定を広告する**（既定は false） |
    /// | **`RT-346.7`** | `tls_client_auth`（normal） | **client_credentials のトークンも、認証した証明書に縛られる**（以前は縛られなかった。net10.0 版だけ） |
    /// | **`RT-346.8`** | `tls_client_certificate_bound_access_tokens`（device） | **device_code の要求も、証明書が無ければ断り、在れば縛る**（net10.0 版だけ） |
    ///
    /// **サーバ全体の設定**（`RequirePushedAuthorizationRequests`・`RequireSignedRequestObject`）を
    /// **true にしたときに断ることは、E2E では測っていない**（`RequirePkce` と同じ。既定の通しでは、他のテストが落ちる）。
    /// 判定は登録と同じ式の OR である（`CmnEndpoints.ValidateAuthZReqParamCore`）。
    /// </remarks>
    public class ProfileEnforcementTests : TargetTestBase
    {
        /// <summary>コンストラクタ</summary>
        /// <param name="output">ITestOutputHelper</param>
        public ProfileEnforcementTests(ITestOutputHelper output) : base(output)
        {
        }

        #region 補助

        /// <summary>Discovery の値を読む</summary>
        /// <param name="client">IdPClient</param>
        /// <returns>JsonResponse</returns>
        private static async Task<JsonResponse> DiscoveryAsync(IdPClient client)
        {
            JsonResponse res = await client.GetJsonAsync("/.well-known/openid-configuration");
            Assert.True(res.IsJson, "前提: Discovery 文書が JSON であること");
            return res;
        }

        /// <summary>Discovery から口を引く（無ければ Skip）</summary>
        /// <param name="client">IdPClient</param>
        /// <param name="name">メタデータの名前</param>
        /// <returns>URL</returns>
        private static async Task<string> EndpointAsync(IdPClient client, string name)
        {
            string endpoint = (await ProfileEnforcementTests.DiscoveryAsync(client)).String(name);

            Skip.If(string.IsNullOrEmpty(endpoint), "Discovery が " + name + " を広告していません。");

            return endpoint;
        }

        /// <summary>認可要求のパラメタ（`prompt=none` は付けない。同意画面は AuthorizeAndGrantAsync が進める）</summary>
        /// <param name="reg">クライアント</param>
        /// <param name="state">state</param>
        /// <returns>パラメタ</returns>
        private static Dictionary<string, string> Parameters(ClientRegistration reg, string state)
        {
            return new Dictionary<string, string>()
            {
                { "response_type", "code" },
                { "redirect_uri", reg.RedirectUri },
                { "scope", "openid email" },
                { "state", state },
                { "nonce", "nonce-" + state }
            };
        }

        /// <summary>同じ中身を、Request Object のクレームにする</summary>
        /// <param name="reg">クライアント</param>
        /// <param name="state">state</param>
        /// <returns>クレーム</returns>
        private static Dictionary<string, object> Claims(ClientRegistration reg, string state)
        {
            Dictionary<string, object> claims = new Dictionary<string, object>();

            foreach (KeyValuePair<string, string> p in ProfileEnforcementTests.Parameters(reg, state))
            {
                claims.Add(p.Key, p.Value);
            }

            return claims;
        }

        /// <summary>クエリで認可要求を送る（同意画面には進まない）</summary>
        /// <param name="client">IdPClient</param>
        /// <param name="reg">クライアント</param>
        /// <param name="state">state</param>
        /// <returns>AuthZResponse</returns>
        private static Task<AuthZResponse> QueryAuthorizeAsync(
            IdPClient client, ClientRegistration reg, string state)
        {
            Dictionary<string, string> q = ProfileEnforcementTests.Parameters(reg, state);
            q["client_id"] = reg.ClientId;
            return client.AuthorizeAsync(q);
        }

        /// <summary>認可の応答を、報告に書ける形にする（code の値は出さない）</summary>
        /// <param name="authz">AuthZResponse</param>
        /// <returns>文字列</returns>
        private static string Outcome(AuthZResponse authz)
        {
            if (authz == null)
            {
                return "（応答なし）";
            }

            return !string.IsNullOrEmpty(authz.Code)
                ? "code あり（値は伏せる）"
                : "error=" + (authz.Error ?? "なし");
        }

        /// <summary>DPoP の証明を作る</summary>
        /// <param name="client">IdPClient</param>
        /// <param name="tokenEndpoint">広告された token_endpoint（htu）</param>
        /// <returns>証明</returns>
        private static string DPoPProof(IdPClient client, string tokenEndpoint)
        {
            return JwsSigner.SignDPoP(client, new Dictionary<string, object>()
            {
                { "jti", Guid.NewGuid().ToString("N") },
                { "htm", "POST" },
                { "htu", tokenEndpoint },
                { "iat", DateTimeOffset.UtcNow.ToUnixTimeSeconds() }
            });
        }

        /// <summary>access_token の cnf の値を読む</summary>
        /// <param name="accessToken">access_token</param>
        /// <param name="name">`jkt` / `x5t#S256`</param>
        /// <returns>値（無ければ空）</returns>
        private static string CnfOf(string accessToken, string name)
        {
            if (string.IsNullOrEmpty(accessToken))
            {
                return "";
            }

            JsonElement payload = Jwt.Payload(accessToken);

            if (payload.ValueKind == JsonValueKind.Object
                && payload.TryGetProperty("cnf", out JsonElement cnf)
                && cnf.ValueKind == JsonValueKind.Object
                && cnf.TryGetProperty(name, out JsonElement value)
                && value.ValueKind == JsonValueKind.String)
            {
                return value.GetString() ?? "";
            }

            return "";
        }

        #endregion

        #region RT-346.2 PAR

        /// <summary>RT-346.2 PAR を必須にした登録は、PAR で預けた要求だけが通る</summary>
        /// <param name="targetKey">core / netfx</param>
        /// <returns>Task</returns>
        [SkippableTheory]
        [MemberData(nameof(AllTargets))]
        public async Task RT34602_PARを必須にした登録はPARで預けた要求だけが通る(string targetKey)
        {
            using (IdPClient client = await this.SignedInClientAsync(targetKey))
            {
                ClientRegistration reg = Flows.InjectedRegistration(client, KnownClients.TestClient_37);

                TestReport r = this.Report("RT-346.2",
                    "`require_pushed_authorization_requests` の登録は、PAR で預けた `request_uri` の無い認可要求を `invalid_request` で断る",
                    "**FAPI 2.0 は、PAR 以外の認可要求を断ることを求める。**"
                    + "**`/ros`（独自の口）で預けた `request_uri` も、PAR ではないので断る**"
                    + "（経路は、預けた中身にサーバが付けた印で見分ける）。"
                    + "**`redirect_uri` を確かめた後に断るので、エラーは RP へ返る。**",
                    "RFC 9126 §4・§6 / FAPI 2.0 Security Profile 5.3.2.2 の 3 / #346");

                r.Target("client_name=" + KnownClients.TestClient_37 + "（require_pushed_authorization_requests=true）");

                r.Step("(1) クエリで認可要求を送る");

                AuthZResponse query = await ProfileEnforcementTests.QueryAuthorizeAsync(client, reg, "state-rt3462a");

                r.VerifyEqual("invalid_request で断られる（RP へ返る）", "invalid_request", query.Error ?? "（無し）");

                r.Verify("code は返らない", string.IsNullOrEmpty(query.Code),
                    "返らない", ProfileEnforcementTests.Outcome(query));

                r.Step("(2) /ros で署名付きの Request Object を預け、その request_uri で送る");

                string rosUrl = await RequestObjectBuilder.BuildAuthorizeUrlAsync(
                    client, reg.ClientId, ProfileEnforcementTests.Claims(reg, "state-rt3462b"));

                Assert.False(string.IsNullOrEmpty(rosUrl), "前提: /ros に預けられること");

                AuthZResponse ros = await client.AuthorizeAsync(new Dictionary<string, string>()
                {
                    { "client_id", reg.ClientId },
                    { "request_uri", ProfileEnforcementTests.RequestUriOf(rosUrl) }
                });

                r.VerifyEqual("/ros の request_uri も invalid_request で断られる（PAR ではない）",
                    "invalid_request", ros.Error ?? "（無し）");

                r.Step("(3) PAR に預け、その request_uri で送る");

                string parEndpoint = await ProfileEnforcementTests.EndpointAsync(
                    client, "pushed_authorization_request_endpoint");

                JsonResponse par = await client.PostJsonWithBasicAuthAsync(
                    client.ToLocalUrl(parEndpoint),
                    ProfileEnforcementTests.Parameters(reg, "state-rt3462c"),
                    reg.ClientId, reg.ClientSecret);

                r.VerifyEqual("PAR は HTTP 201", "201", ((int)par.StatusCode).ToString());

                string requestUri = par.String("request_uri");

                Assert.False(string.IsNullOrEmpty(requestUri),
                    "前提: request_uri が返ること（error=" + (par.Error ?? "なし") + "）");

                AuthZResponse pushed = await client.AuthorizeAndGrantAsync(new Dictionary<string, string>()
                {
                    { "client_id", reg.ClientId },
                    { "request_uri", requestUri }
                });

                r.Verify("認可コードが返る", !string.IsNullOrEmpty(pushed.Code),
                    "code あり", ProfileEnforcementTests.Outcome(pushed));

                r.VerifyEqual("state がそのまま返る", "state-rt3462c", pushed.State ?? "（無し）");

                r.Done();
            }
        }

        /// <summary>/authorize の URL から request_uri を取り出す</summary>
        /// <param name="url">BuildAuthorizeUrlAsync が返した URL</param>
        /// <returns>request_uri</returns>
        /// <remarks>**エンコードせずに連結されている**（`RequestObjectBuilder` の注記）。</remarks>
        private static string RequestUriOf(string url)
        {
            const string key = "request_uri=";
            int i = url.IndexOf(key, StringComparison.Ordinal);
            return (i < 0) ? "" : url.Substring(i + key.Length);
        }

        #endregion

        #region RT-346.3 署名付きの Request Object

        /// <summary>RT-346.3 署名付きの Request Object を必須にした登録は、それで送られた要求だけが通る</summary>
        /// <param name="targetKey">core / netfx</param>
        /// <returns>Task</returns>
        [SkippableTheory]
        [MemberData(nameof(AllTargets))]
        public async Task RT34603_署名付きのRequestObjectを必須にした登録はそれだけが通る(string targetKey)
        {
            using (IdPClient client = await this.SignedInClientAsync(targetKey))
            {
                ClientRegistration reg = Flows.InjectedRegistration(client, KnownClients.TestClient_38);

                TestReport r = this.Report("RT-346.3",
                    "`require_signed_request_object` の登録は、署名付きの Request Object で送られていない認可要求を断る",
                    "**FAPI 1.0 Advanced は、署名付きの Request Object を求める。**"
                    + "**この実装は `request` パラメタを受けない**ので、**署名付きの Request Object は `/ros` か PAR の `request` で預ける。**"
                    + "**フォームのパラメタだけの PAR は、PAR の口で `invalid_request`（400）で断る**（RFC 9126 §2.3）。",
                    "RFC 9101 §10.5 / RFC 9126 §2.3 / FAPI 1.0 Advanced 5.2.2 の 1 / #346");

                r.Target("client_name=" + KnownClients.TestClient_38 + "（require_signed_request_object=true）");

                r.Step("(1) クエリで認可要求を送る");

                AuthZResponse query = await ProfileEnforcementTests.QueryAuthorizeAsync(client, reg, "state-rt3463a");

                r.VerifyEqual("invalid_request で断られる（RP へ返る）", "invalid_request", query.Error ?? "（無し）");

                r.Step("(2) フォームのパラメタだけで PAR に預ける");

                string parEndpoint = await ProfileEnforcementTests.EndpointAsync(
                    client, "pushed_authorization_request_endpoint");

                JsonResponse form = await client.PostJsonWithBasicAuthAsync(
                    client.ToLocalUrl(parEndpoint),
                    ProfileEnforcementTests.Parameters(reg, "state-rt3463b"),
                    reg.ClientId, reg.ClientSecret);

                r.VerifyEqual("HTTP 400 ＋ invalid_request", "400 invalid_request",
                    ((int)form.StatusCode).ToString() + " " + (form.Error ?? "（無し）"));

                r.Verify("request_uri を返さない", string.IsNullOrEmpty(form.String("request_uri")),
                    "返さない", string.IsNullOrEmpty(form.String("request_uri")) ? "返さなかった" : "**返した**");

                r.Step("(3) PAR の request に署名付きの Request Object を入れて預け、その request_uri で送る");

                string requestObject = await RequestObjectBuilder.CreateAsync(
                    client, reg.ClientId, ProfileEnforcementTests.Claims(reg, "state-rt3463c"));

                JsonResponse jar = await client.PostJsonWithBasicAuthAsync(
                    client.ToLocalUrl(parEndpoint),
                    new Dictionary<string, string>() { { "request", requestObject } },
                    reg.ClientId, reg.ClientSecret);

                r.VerifyEqual("PAR は HTTP 201", "201", ((int)jar.StatusCode).ToString());

                string requestUri = jar.String("request_uri");

                Assert.False(string.IsNullOrEmpty(requestUri),
                    "前提: request_uri が返ること（error=" + (jar.Error ?? "なし") + "）");

                AuthZResponse viaPar = await client.AuthorizeAndGrantAsync(new Dictionary<string, string>()
                {
                    { "client_id", reg.ClientId },
                    { "request_uri", requestUri }
                });

                r.Verify("認可コードが返る", !string.IsNullOrEmpty(viaPar.Code),
                    "code あり", ProfileEnforcementTests.Outcome(viaPar));

                r.Step("(4) /ros に署名付きの Request Object を預け、その request_uri で送る");

                string rosUrl = await RequestObjectBuilder.BuildAuthorizeUrlAsync(
                    client, reg.ClientId, ProfileEnforcementTests.Claims(reg, "state-rt3463d"));

                Assert.False(string.IsNullOrEmpty(rosUrl), "前提: /ros に預けられること");

                AuthZResponse viaRos = await client.AuthorizeAndGrantAsync(client.ToLocalUrl(rosUrl));

                r.Verify("認可コードが返る", !string.IsNullOrEmpty(viaRos.Code),
                    "code あり", ProfileEnforcementTests.Outcome(viaRos));

                r.Done();
            }
        }

        #endregion

        #region RT-346.4 DPoP

        /// <summary>RT-346.4 DPoP を必須にした登録は、証明の無いトークン要求を断る</summary>
        /// <param name="targetKey">core / netfx</param>
        /// <returns>Task</returns>
        [SkippableTheory]
        [MemberData(nameof(AllTargets))]
        public async Task RT34604_DPoPを必須にした登録は証明の無いトークン要求を断る(string targetKey)
        {
            using (IdPClient client = await this.SignedInClientAsync(targetKey))
            {
                ClientRegistration reg = Flows.InjectedRegistration(client, KnownClients.TestClient_39);

                TestReport r = this.Report("RT-346.4",
                    "`dpop_bound_access_tokens` の登録は、DPoP の証明の無いトークン要求を `invalid_request` で断る",
                    "**RFC 9449 §5.2 は、証明の無いトークン要求を断ることを求める（MUST）が、エラー コードを決めていない。**"
                    + "**`invalid_dpop_proof` は「証明が在って通らない」ときのコード**なので使わず、`invalid_request` にした。"
                    + "**code を消費する前に断る**ので、**断られた code は、証明を添えればまだ使える。**",
                    "RFC 9449 §5.2 / FAPI 2.0 Security Profile 5.3.2.1 の 4・5 / #346");

                r.Target("client_name=" + KnownClients.TestClient_39 + "（dpop_bound_access_tokens=true）");

                string tokenEndpoint = await ProfileEnforcementTests.EndpointAsync(client, "token_endpoint");

                r.Step("(1) client_credentials を、証明なしで要求する");

                Dictionary<string, string> cc = new Dictionary<string, string>()
                {
                    { "grant_type", "client_credentials" },
                    { "client_id", reg.ClientId },
                    { "client_secret", reg.ClientSecret }
                };

                JsonResponse noProof = await client.PostJsonAsync(client.ToLocalUrl(tokenEndpoint), cc);

                r.VerifyEqual("HTTP 400 ＋ invalid_request", "400 invalid_request",
                    ((int)noProof.StatusCode).ToString() + " " + (noProof.Error ?? "（無し）"));

                r.Step("(2) 同じ要求に、証明を添える");

                JsonResponse withProof = await client.PostJsonAsync(client.ToLocalUrl(tokenEndpoint), cc,
                    new Dictionary<string, string>() { { "DPoP", ProfileEnforcementTests.DPoPProof(client, tokenEndpoint) } });

                r.VerifyEqual("HTTP 200", "200", ((int)withProof.StatusCode).ToString());
                r.VerifyEqual("token_type は DPoP", "DPoP", withProof.String("token_type") ?? "（無し）");

                r.Step("(3) 認可コードを取り、証明なしで交換する");

                AuthZResponse authz = await Flows.AuthorizeCodeAsync(client, reg, redirectUri: reg.RedirectUri);

                Assert.False(string.IsNullOrEmpty(authz.Code),
                    "前提: 認可コードが取得できること（error=" + (authz.Error ?? "なし") + "）");

                Dictionary<string, string> code = new Dictionary<string, string>()
                {
                    { "grant_type", "authorization_code" },
                    { "code", authz.Code },
                    { "client_id", reg.ClientId },
                    { "client_secret", reg.ClientSecret },
                    { "redirect_uri", reg.RedirectUri }
                };

                JsonResponse codeNoProof = await client.PostJsonAsync(client.ToLocalUrl(tokenEndpoint), code);

                r.VerifyEqual("HTTP 400 ＋ invalid_request", "400 invalid_request",
                    ((int)codeNoProof.StatusCode).ToString() + " " + (codeNoProof.Error ?? "（無し）"));

                r.Step("(4) 同じ code を、証明を添えて交換する");

                JsonResponse codeWithProof = await client.PostJsonAsync(client.ToLocalUrl(tokenEndpoint), code,
                    new Dictionary<string, string>() { { "DPoP", ProfileEnforcementTests.DPoPProof(client, tokenEndpoint) } });

                r.VerifyEqual("HTTP 200（断られた code は消費されていない）", "200",
                    ((int)codeWithProof.StatusCode).ToString());

                r.Verify("access_token に cnf.jkt が入る",
                    !string.IsNullOrEmpty(ProfileEnforcementTests.CnfOf(codeWithProof.AccessToken, "jkt")),
                    "入る", string.IsNullOrEmpty(ProfileEnforcementTests.CnfOf(codeWithProof.AccessToken, "jkt"))
                        ? "**無い**" : "入る");

                r.Done();
            }
        }

        #endregion

        #region RT-346.5 MTLS

        /// <summary>RT-346.5 クライアント証明書を必須にした登録は、証明書の無いトークン要求を断り、在れば縛る</summary>
        /// <param name="targetKey">core（-NetFxMtls のときは netfx も）</param>
        /// <returns>Task</returns>
        [SkippableTheory]
        [MemberData(nameof(MtlsTests.MtlsTargets), MemberType = typeof(MtlsTests))]
        public async Task RT34605_証明書を必須にした登録は証明書の無いトークン要求を断る(string targetKey)
        {
            using (IdPClient client = this.Client(targetKey))
            {
                MtlsTests.SkipIfNoMtls(client.Target);
                ClientRegistration reg = Flows.InjectedRegistration(client, KnownClients.TestClient_40);

                TestReport r = this.Report("RT-346.5",
                    "`tls_client_certificate_bound_access_tokens` の登録は、クライアント証明書の無いトークン要求を `invalid_request` で断り、"
                    + "在れば、秘密で認証していても、その証明書でトークンを縛る",
                    "**RFC 8705 §3.4 は「エラーにするか、縛らないトークンを出すかはサーバが決める」としている。この実装は断る。**"
                    + "**縛るのは、認証の方法によらない**（RFC 8705 §3）。"
                    + "**以前は、証明書で認証した登録（`tls_client_auth`）のときだけ縛っていた**（秘密で認証すると、証明書を捨てていた）。",
                    "RFC 8705 §3・§3.1・§3.4 / FAPI 2.0 Security Profile 5.3.2.1 の 4・5 / #346");

                r.Target("client_name=" + KnownClients.TestClient_40 + "（tls_client_certificate_bound_access_tokens=true。認証は client_secret）");

                Dictionary<string, string> cc = new Dictionary<string, string>()
                {
                    { "grant_type", "client_credentials" },
                    { "client_id", reg.ClientId },
                    { "client_secret", reg.ClientSecret }
                };

                r.Step("(1) client_credentials を、証明書なしで要求する");

                JsonResponse noCert = await client.TokenWithCertificateAsync(cc, null);

                r.VerifyEqual("HTTP 400 ＋ invalid_request", "400 invalid_request",
                    ((int)noCert.StatusCode).ToString() + " " + (noCert.Error ?? "（無し）"));

                r.Step("(2) 同じ要求に、クライアント証明書を添える");

                using (X509Certificate2 cert = TestCertificate.ForTarget(client.Target, KnownClients.MtlsSubjectDn))
                {
                    JsonResponse withCert = await client.TokenWithCertificateAsync(cc, cert);

                    r.VerifyEqual("HTTP 200", "200", ((int)withCert.StatusCode).ToString());

                    string thumbprint = ProfileEnforcementTests.CnfOf(withCert.AccessToken, "x5t#S256");
                    string expected = Base64Url.Encode(SHA256.HashData(cert.RawData));

                    r.Verify("access_token の cnf の x5t#S256 は、提示した証明書の SHA-256（BASE64URL）",
                        thumbprint == expected,
                        "一致",
                        string.IsNullOrEmpty(thumbprint) ? "**無し**" : (thumbprint == expected ? "一致" : "**別の値**"));
                }

                r.Done();
            }
        }

        #endregion

        #region RT-346.7 tls_client_auth の client_credentials

        /// <summary>RT-346.7 tls_client_auth の client_credentials のトークンは、証明書に縛られる</summary>
        /// <param name="targetKey">core（-NetFxMtls のときは netfx も）</param>
        /// <returns>Task</returns>
        [SkippableTheory]
        [MemberData(nameof(MtlsTests.MtlsTargets), MemberType = typeof(MtlsTests))]
        public async Task RT34607_tls_client_authのclient_credentialsは証明書に縛られる(string targetKey)
        {
            using (IdPClient client = this.Client(targetKey))
            {
                MtlsTests.SkipIfNoMtls(client.Target);
                ClientRegistration reg = Flows.InjectedRegistration(client, KnownClients.TestClient_42);

                TestReport r = this.Report("RT-346.7",
                    "`tls_client_auth` で認証した client_credentials のトークンは、その証明書に縛られる（`cnf.x5t#S256`）",
                    "**以前は、client_credentials・ROPC・JWT Bearer のトークンを証明書に縛っていなかった**"
                    + "（トークンを作る `CreateFromClaims` が、証明書を受けていなかった）。"
                    + "**認可コード・refresh_token は縛っていた**ので、グラントによって振る舞いが違った。"
                    + "**#346 で、必須にした登録の縛りを足すときに見つけて、揃えた。**",
                    "RFC 8705 §3・§3.1 / #346");

                r.Target("client_name=" + KnownClients.TestClient_42 + "（normal。token_endpoint_auth_method=tls_client_auth）");

                using (X509Certificate2 cert = TestCertificate.ForTarget(client.Target, KnownClients.MtlsSubjectDn))
                {
                    r.Step("(1) 証明書で認証して、client_credentials でトークンを取る");

                    JsonResponse token = await client.TokenWithCertificateAsync(new Dictionary<string, string>()
                    {
                        { "grant_type", "client_credentials" },
                        { "client_id", reg.ClientId }
                    }, cert);

                    r.VerifyEqual("HTTP 200", "200", ((int)token.StatusCode).ToString());

                    string thumbprint = ProfileEnforcementTests.CnfOf(token.AccessToken, "x5t#S256");
                    string expected = Base64Url.Encode(SHA256.HashData(cert.RawData));

                    r.Verify("access_token の cnf の x5t#S256 は、認証した証明書の SHA-256（BASE64URL）",
                        thumbprint == expected,
                        "一致",
                        string.IsNullOrEmpty(thumbprint) ? "**無し**" : (thumbprint == expected ? "一致" : "**別の値**"));
                }

                r.Note("**ROPC も同じ関数で作る**ので、同じ直し方で縛られる（E2E は client_credentials だけで測る）。"
                    + "**JWT Bearer はクライアント認証を通らない**ので、`tls_client_auth` の登録でも縛らない（証明書を必須にした登録だけ）。");

                r.Done();
            }
        }

        #endregion

        #region RT-346.8 device_code

        /// <summary>RT-346.8 証明書を必須にした device の登録は、device_code の要求でも証明書を求め、縛る</summary>
        /// <param name="targetKey">core（-NetFxMtls のときは netfx も）</param>
        /// <returns>Task</returns>
        [SkippableTheory]
        [MemberData(nameof(MtlsTests.MtlsTargets), MemberType = typeof(MtlsTests))]
        public async Task RT34608_証明書を必須にしたdeviceの登録はdevice_codeでも縛る(string targetKey)
        {
            using (IdPClient client = await this.SignedInClientAsync(targetKey))
            {
                MtlsTests.SkipIfNoMtls(client.Target);
                ClientRegistration reg = Flows.InjectedRegistration(client, KnownClients.TestClient_43);

                TestReport r = this.Report("RT-346.8",
                    "`tls_client_certificate_bound_access_tokens` の device の登録は、device_code の要求でも、証明書が無ければ断り、在ればトークンを縛る",
                    "**device_code のグラントだけ、トークンを作るときに証明書を渡していなかった**（`ProtectFromPayload` に null）。"
                    + "**証明書を求めるのに、縛らない**ことになっていた（#346 のレビューで見つかった）。"
                    + "**断られた device_code は、まだ使える**（消費する前に断る）。",
                    "RFC 8705 §3・§3.1・§3.4 / RFC 8628 §3.4 / #346");

                r.Target("client_name=" + KnownClients.TestClient_43 + "（device。tls_client_certificate_bound_access_tokens=true。認証は client_secret）");

                r.Step("(1) 機器 : device_code と user_code を得て、ユーザが許可する");

                JsonResponse start = await client.DeviceAuthorizationAsync(new Dictionary<string, string>()
                {
                    { "client_id", reg.ClientId },
                    { "client_secret", reg.ClientSecret },
                    { "scope", "openid email" }
                });

                string deviceCode = start.String("device_code");
                string userCode = start.String("user_code");

                Assert.False(string.IsNullOrEmpty(deviceCode) || string.IsNullOrEmpty(userCode),
                    "前提: device_code と user_code が発行されること（error=" + (start.Error ?? "なし") + "）");

                Assert.True(await client.SubmitDeviceUserCodeAsync(userCode, true), "前提: 検証画面が承認を受け付けること");

                Dictionary<string, string> poll = new Dictionary<string, string>()
                {
                    { "grant_type", "urn:ietf:params:oauth:grant-type:device_code" },
                    { "device_code", deviceCode },
                    { "client_id", reg.ClientId },
                    { "client_secret", reg.ClientSecret }
                };

                r.Step("(2) 機器 : 証明書なしでトークンを要求する");

                JsonResponse noCert = await client.TokenWithCertificateAsync(poll, null);

                r.VerifyEqual("HTTP 400 ＋ invalid_request", "400 invalid_request",
                    ((int)noCert.StatusCode).ToString() + " " + (noCert.Error ?? "（無し）"));

                r.Step("(3) 機器 : 同じ device_code で、証明書を添えて要求する");

                using (X509Certificate2 cert = TestCertificate.ForTarget(client.Target, KnownClients.MtlsSubjectDn))
                {
                    JsonResponse withCert = await client.TokenWithCertificateAsync(poll, cert);

                    r.VerifyEqual("HTTP 200（断られた device_code は消費されていない）", "200",
                        ((int)withCert.StatusCode).ToString());

                    string thumbprint = ProfileEnforcementTests.CnfOf(withCert.AccessToken, "x5t#S256");
                    string expected = Base64Url.Encode(SHA256.HashData(cert.RawData));

                    r.Verify("access_token の cnf の x5t#S256 は、提示した証明書の SHA-256（BASE64URL）",
                        thumbprint == expected,
                        "一致",
                        string.IsNullOrEmpty(thumbprint) ? "**無し**" : (thumbprint == expected ? "一致" : "**別の値**"));
                }

                r.Done();
            }
        }

        #endregion

        #region RT-346.6 Discovery

        /// <summary>RT-346.6 サーバ全体の 2 つの設定を Discovery に出す</summary>
        /// <param name="targetKey">core / netfx</param>
        /// <returns>Task</returns>
        [SkippableTheory]
        [MemberData(nameof(AllTargets))]
        public async Task RT34606_サーバ全体の設定をDiscoveryに出す(string targetKey)
        {
            using (IdPClient client = this.Client(targetKey))
            {
                TestReport r = this.Report("RT-346.6",
                    "Discovery の `require_pushed_authorization_requests`・`require_signed_request_object` は、サーバ全体の設定の値（既定は false）",
                    "**どちらも AS のメタデータとして標準に在る**（RFC 9126 §5・RFC 9101 §10.5）。"
                    + "**以前は `require_pushed_authorization_requests` を false に固定し、`require_signed_request_object` は出していなかった。**"
                    + "**登録ごとの必須は、ここには出ない**（Discovery にクライアント別の項目は無い）。",
                    "RFC 9126 §5 / RFC 9101 §10.5 / RFC 8414 §2 / #346");

                r.Target("GET /.well-known/openid-configuration（既定の配備）");

                JsonResponse discovery = await ProfileEnforcementTests.DiscoveryAsync(client);

                foreach (string name in new string[] { "require_pushed_authorization_requests", "require_signed_request_object" })
                {
                    string actual = "（無い）";

                    if (discovery.Json.TryGetProperty(name, out JsonElement value))
                    {
                        actual = value.ValueKind == JsonValueKind.True ? "true"
                            : (value.ValueKind == JsonValueKind.False ? "false" : value.GetRawText());
                    }

                    r.VerifyEqual(name + " は false（真偽値。既定の配備）", "false", actual);
                }

                r.Note("**true にした配備は、E2E では測っていない**（既定の通しの他のテストが落ちる）。"
                    + "**値は `Config.RequirePushedAuthorizationRequests`・`Config.RequireSignedRequestObject` をそのまま出している。**");

                r.Done();
            }
        }

        #endregion
    }
}
