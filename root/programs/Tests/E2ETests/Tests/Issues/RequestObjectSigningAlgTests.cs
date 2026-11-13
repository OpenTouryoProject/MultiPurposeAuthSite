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
//* クラス名        ：RequestObjectSigningAlgTests
//* クラス日本語名  ：RT-370 Request Object を RS256・PS256・ES256 で検証し、FAPI の登録は PS256・ES256 に限る
//*
//* 作成日時        ：－
//* 作成者          ：－
//* 更新履歴        ：－
//*
//*  日時        更新者            内容
//*  ----------  ----------------  -------------------------------------------------
//*  2026/11/13  玄人 幸道         新規（#370）
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
    /// RT-370. **Request Object を、登録の鍵とヘッダの alg（RS256・PS256・ES256）で検証する。FAPI の登録は PS256・ES256 に限る。**
    /// </summary>
    /// <remarks>
    /// **以前は、登録の RSA 公開鍵による RS256 しか検証できなかった。**
    /// **FAPI は RS256 を認めない**（FAPI 1.0 Advanced §8.6、FAPI 2.0 Security Profile §5.4.1）ので、
    /// **FAPI 2.0 Message Signing・FAPI 1.0 Advanced の適合性テストは、ES256 の Request Object を PAR に渡した所で止まっていた**（#370）。
    ///
    /// | | 測ること |
    /// |---|---|
    /// | **`RT-370.1`** | **FAPI でない登録は、RS256・PS256（RSA の鍵）と ES256（EC の鍵）の Request Object を預かる**。Discovery も 3 つを広告する |
    /// | **`RT-370.2`** | **FAPI の登録（fapi1・fapi2）は、RS256 の Request Object を預からず、PS256・ES256 なら預かる** |
    /// | **`RT-370.3`** | **alg に合う鍵が登録されていなければ預からない**（RSA の鍵だけの登録に ES256）。**alg が none も預からない** |
    /// | **`RT-370.4`** | **PAR では、FAPI の登録の RS256 を `invalid_request_object` で断り、PS256 なら預かる** |
    /// </remarks>
    public class RequestObjectSigningAlgTests : TargetTestBase
    {
        /// <summary>client_assertion_type（RFC 7523 §2.2）</summary>
        private const string JwtBearerAssertionType = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer";

        /// <summary>code_challenge（RFC 7636 Appendix B の S256。fapi2 の PAR は S256 の PKCE を求める。#366）</summary>
        private const string Challenge = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";

        /// <summary>コンストラクタ</summary>
        /// <param name="output">ITestOutputHelper</param>
        public RequestObjectSigningAlgTests(ITestOutputHelper output) : base(output)
        {
        }

        #region 補助

        /// <summary>認可要求のパラメタ（S256 の PKCE を含む）</summary>
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
                { "nonce", "nonce-" + state },
                { "code_challenge", RequestObjectSigningAlgTests.Challenge },
                { "code_challenge_method", "S256" }
            };
        }

        /// <summary>Request Object を作って /ros に預ける</summary>
        /// <param name="client">IdPClient</param>
        /// <param name="reg">クライアント（iss）</param>
        /// <param name="alg">RS256・PS256・ES256</param>
        /// <param name="state">state</param>
        /// <returns>応答</returns>
        private static async Task<JsonResponse> RosAsync(
            IdPClient client, ClientRegistration reg, string alg, string state)
        {
            string requestObject = await RequestObjectBuilder.CreateAsync(
                client, reg.ClientId, RequestObjectSigningAlgTests.Parameters(reg, state), alg);

            return await client.PostTextAsync(RequestObjectBuilder.RegistrationPath, requestObject);
        }

        /// <summary>預かった（request_uri が返った）ことを確かめる</summary>
        /// <param name="r">TestReport</param>
        /// <param name="label">何の要求か</param>
        /// <param name="res">応答</param>
        private static void VerifyAccepted(TestReport r, string label, JsonResponse res)
        {
            string requestUri = res.IsJson ? res.String("request_uri") : null;

            r.Verify(label + " : request_uri が返る", !string.IsNullOrEmpty(requestUri),
                "返る", !string.IsNullOrEmpty(requestUri) ? "返った"
                    : "**返らない**（HTTP " + (int)res.StatusCode + " / error=" + (res.Error ?? "-") + "）");
        }

        /// <summary>預からなかった（request_uri が返らない）ことを確かめる</summary>
        /// <param name="r">TestReport</param>
        /// <param name="label">何の要求か</param>
        /// <param name="res">応答</param>
        private static void VerifyRejected(TestReport r, string label, JsonResponse res)
        {
            string requestUri = res.IsJson ? res.String("request_uri") : null;

            r.Verify(label + " : request_uri を返さない", string.IsNullOrEmpty(requestUri),
                "返さない", string.IsNullOrEmpty(requestUri) ? "返さなかった" : "**返した**");
            r.VerifyEqual(label + " : HTTP 400", "400", ((int)res.StatusCode).ToString());
        }

        /// <summary>署名した JWT から、alg が none の署名の無い JWT を作る（RFC 7519 §6.1）</summary>
        /// <param name="signed">署名した JWT（payload を借りる）</param>
        /// <returns>`{"alg":"none"}.payload.`</returns>
        private static string Unsigned(string signed)
        {
            string header = Base64Url.Encode(System.Text.Encoding.UTF8.GetBytes("{\"alg\":\"none\"}"));

            return header + "." + signed.Split('.')[1] + ".";
        }

        /// <summary>RS256 の client_assertion を作る（RFC 7523 §2.2。fapi2 の aud は issuer）</summary>
        /// <param name="client">IdPClient</param>
        /// <param name="clientId">client_id</param>
        /// <param name="issuer">issuer</param>
        /// <returns>client_assertion</returns>
        /// <remarks>**client_assertion の alg は、この Issue では変えていない**（RS256 のまま受ける）。</remarks>
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

        #endregion

        #region RT-370.1

        /// <summary>RT-370.1 FAPI でない登録は、RS256・PS256・ES256 の Request Object を預かる</summary>
        /// <param name="targetKey">core / netfx</param>
        /// <returns>Task</returns>
        [SkippableTheory]
        [MemberData(nameof(AllTargets))]
        public async Task RT37001_FAPIでない登録はRS256とPS256とES256のRequestObjectを預かる(string targetKey)
        {
            using (IdPClient client = this.Client(targetKey))
            {
                TestReport r = this.Report("RT-370.1",
                    "FAPI でない登録の /ros は、RS256・PS256（登録の RSA の鍵）と ES256（登録の EC の鍵）の Request Object を預かる。Discovery の request_object_signing_alg_values_supported も 3 つを広告する",
                    "**検証鍵は、ヘッダの alg と登録の鍵から作る**（RS256・PS256 は RSA、ES256 は EC）。"
                    + "**以前は登録の RSA の鍵による RS256 しか検証できず、ES256 の Request Object を断っていた**（適合性テストの FAPI 2.0 Message Signing・FAPI 1.0 Advanced）。"
                    + "**既存の RS256 の RP は変わらない。**",
                    "RFC 9101 §6.2 / RFC 7518 §3.1 / OIDC Discovery 1.0 §3 / #370");

                ClientRegistration reg = Flows.Registration(client, KnownClients.TestClient);

                r.Target("POST /ros（client_name=" + KnownClients.TestClient + "。RSA と EC の鍵を登録している）");

                foreach (string alg in new string[] { "RS256", "PS256", "ES256" })
                {
                    r.Step(alg);

                    RequestObjectSigningAlgTests.VerifyAccepted(r, alg,
                        await RequestObjectSigningAlgTests.RosAsync(client, reg, alg, "state-rt3701-" + alg));
                }

                r.Step("Discovery の広告");

                JsonResponse discovery = await client.GetJsonAsync("/.well-known/openid-configuration");

                foreach (string alg in new string[] { "RS256", "PS256", "ES256" })
                {
                    r.Verify("request_object_signing_alg_values_supported に " + alg + " が在る",
                        discovery.ArrayContains("request_object_signing_alg_values_supported", alg),
                        "在る", string.Join(" ", discovery.Strings("request_object_signing_alg_values_supported") ?? new string[0]));
                }

                r.Done();
            }
        }

        #endregion

        #region RT-370.2

        /// <summary>RT-370.2 FAPI の登録は、RS256 の Request Object を預からず、PS256・ES256 なら預かる</summary>
        /// <param name="targetKey">core / netfx</param>
        /// <returns>Task</returns>
        [SkippableTheory]
        [MemberData(nameof(AllTargets))]
        public async Task RT37002_FAPIの登録はRS256のRequestObjectを預からない(string targetKey)
        {
            using (IdPClient client = this.Client(targetKey))
            {
                TestReport r = this.Report("RT-370.2",
                    "FAPI の登録（fapi1・fapi2）の /ros は、RS256 の Request Object を預からず、PS256・ES256 なら預かる",
                    "**FAPI 1.0 Advanced は PS256 か ES256 を使い、RS256（RSASSA-PKCS1-v1_5）を使わないことを、"
                    + "FAPI 2.0 は PS256・ES256・EdDSA を使うことを求める。**"
                    + "**登録の request_object_signing_alg が無くても、FAPI の登録はこの 2 つに限る。**",
                    "FAPI 1.0 Advanced §8.6 / FAPI 2.0 Security Profile §5.4.1 / #370");

                ClientRegistration fapi2 = Flows.Registration(client, KnownClients.Fapi2Client);
                ClientRegistration fapi1 = Flows.Registration(client, KnownClients.Fapi1Client);

                r.Target("POST /ros（client_name=" + KnownClients.Fapi2Client + "（fapi2。RSA と EC の鍵）・"
                    + KnownClients.Fapi1Client + "（fapi1。RSA の鍵）");

                r.Step("(1) fapi2");

                RequestObjectSigningAlgTests.VerifyRejected(r, "fapi2 の RS256",
                    await RequestObjectSigningAlgTests.RosAsync(client, fapi2, "RS256", "state-rt3702-1"));
                RequestObjectSigningAlgTests.VerifyAccepted(r, "fapi2 の PS256",
                    await RequestObjectSigningAlgTests.RosAsync(client, fapi2, "PS256", "state-rt3702-2"));
                RequestObjectSigningAlgTests.VerifyAccepted(r, "fapi2 の ES256",
                    await RequestObjectSigningAlgTests.RosAsync(client, fapi2, "ES256", "state-rt3702-3"));

                r.Step("(2) fapi1");

                RequestObjectSigningAlgTests.VerifyRejected(r, "fapi1 の RS256",
                    await RequestObjectSigningAlgTests.RosAsync(client, fapi1, "RS256", "state-rt3702-4"));
                RequestObjectSigningAlgTests.VerifyAccepted(r, "fapi1 の PS256",
                    await RequestObjectSigningAlgTests.RosAsync(client, fapi1, "PS256", "state-rt3702-5"));

                r.Done();
            }
        }

        #endregion

        #region RT-370.3

        /// <summary>RT-370.3 alg に合う鍵が登録されていなければ、Request Object を預からない</summary>
        /// <param name="targetKey">core / netfx</param>
        /// <returns>Task</returns>
        [SkippableTheory]
        [MemberData(nameof(AllTargets))]
        public async Task RT37003_algに合う鍵が登録されていなければ預からない(string targetKey)
        {
            using (IdPClient client = this.Client(targetKey))
            {
                TestReport r = this.Report("RT-370.3",
                    "RSA の鍵だけを登録したクライアントの、ES256 の Request Object を預からない。alg が none の Request Object も預からない",
                    "**ヘッダの alg と鍵の種類が食い違えば、検証しない**（アルゴリズムの取り違えを防ぐ）。"
                    + "**EC の鍵を登録していないので、ES256 の署名を確かめる鍵が無い。**"
                    + "**none は扱う alg の一覧に無いので、鍵を選ぶ前に断る。**",
                    "RFC 8725 §3.1 / RFC 8725 §2.1 / RFC 9101 §6.2 / #370");

                ClientRegistration reg = Flows.Registration(client, KnownClients.Fapi1Client);

                r.Target("POST /ros（client_name=" + KnownClients.Fapi1Client + "（RSA の鍵だけ）。ES256 で署名する）");

                RequestObjectSigningAlgTests.VerifyRejected(r, "ES256",
                    await RequestObjectSigningAlgTests.RosAsync(client, reg, "ES256", "state-rt3703-1"));

                r.Step("alg が none（署名の無い JWT）");

                ClientRegistration normal = Flows.Registration(client, KnownClients.TestClient);
                string unsigned = RequestObjectSigningAlgTests.Unsigned(
                    await RequestObjectBuilder.CreateAsync(client, normal.ClientId,
                        RequestObjectSigningAlgTests.Parameters(normal, "state-rt3703-2"), "RS256"));

                RequestObjectSigningAlgTests.VerifyRejected(r, "none",
                    await client.PostTextAsync(RequestObjectBuilder.RegistrationPath, unsigned));

                r.Done();
            }
        }

        #endregion

        #region RT-370.4

        /// <summary>RT-370.4 PAR では、FAPI の登録の RS256 を invalid_request_object で断る</summary>
        /// <param name="targetKey">core / netfx</param>
        /// <returns>Task</returns>
        [SkippableTheory]
        [MemberData(nameof(AllTargets))]
        public async Task RT37004_PARはFAPIの登録のRS256をinvalid_request_objectで断る(string targetKey)
        {
            using (IdPClient client = this.Client(targetKey))
            {
                TestReport r = this.Report("RT-370.4",
                    "fapi2 の登録の /par は、RS256 の request を 400 ＋ invalid_request_object で断り、PS256 なら預かる",
                    "**Request Object が受けられない alg なら invalid_request_object**（RFC 9101 §7。PAR の口の誤りは 400。RFC 9126 §2.3）。"
                    + "**FAPI の登録は RS256 を受けない**（RT-370.2 と同じ判定を PAR でも行う）。",
                    "RFC 9101 §7 / RFC 9126 §2.3 / FAPI 2.0 Security Profile §5.4.1 / #370");

                ClientRegistration reg = Flows.InjectedRegistration(client, KnownClients.TestClient_32);
                string issuer = await client.IssuerAsync();

                JsonResponse discovery = await client.GetJsonAsync("/.well-known/openid-configuration");
                string endpoint = discovery.String("pushed_authorization_request_endpoint");
                Assert.False(string.IsNullOrEmpty(endpoint), "前提: PAR の口が広告されていること");
                endpoint = client.ToLocalUrl(endpoint);

                r.Target("POST /par（client_name=" + KnownClients.TestClient_32 + "。fapi2。private_key_jwt で認証する）");

                foreach (string alg in new string[] { "RS256", "PS256" })
                {
                    r.Step(alg);

                    JsonResponse res = await client.PostJsonAsync(endpoint, new Dictionary<string, string>()
                    {
                        { "request", await RequestObjectBuilder.CreateAsync(client, reg.ClientId,
                            RequestObjectSigningAlgTests.Parameters(reg, "state-rt3704-" + alg), alg) },
                        { "client_assertion_type", RequestObjectSigningAlgTests.JwtBearerAssertionType },
                        { "client_assertion", RequestObjectSigningAlgTests.ClientAssertion(client, reg.ClientId, issuer) }
                    });

                    if (alg == "RS256")
                    {
                        r.VerifyEqual("RS256 : HTTP 400", "400", ((int)res.StatusCode).ToString());
                        r.VerifyEqual("RS256 : invalid_request_object", "invalid_request_object", res.Error ?? "（無い）");
                    }
                    else
                    {
                        r.VerifyEqual("PS256 : HTTP 201", "201", ((int)res.StatusCode).ToString());
                        RequestObjectSigningAlgTests.VerifyAccepted(r, "PS256", res);
                    }
                }

                r.Done();
            }
        }

        #endregion
    }
}
