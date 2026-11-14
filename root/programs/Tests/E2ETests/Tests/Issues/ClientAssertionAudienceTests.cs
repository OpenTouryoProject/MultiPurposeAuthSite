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
//* クラス名        ：ClientAssertionAudienceTests
//* クラス日本語名  ：RT-371 client_assertion の aud に、受けた口（CIBA・PAR）の URL を受ける（CIBA Core 1.0 §7.1・RFC 9126 §2）
//*
//* 作成日時        ：－
//* 作成者          ：－
//* 更新履歴        ：－
//*
//*  日時        更新者            内容
//*  ----------  ----------------  -------------------------------------------------
//*  2026/11/14  玄人 幸道         新規（#371）
//**********************************************************************************

using System;
using System.Collections.Generic;
using System.Threading.Tasks;

using MultiPurposeAuthSite.Tests.E2E.Infrastructure;
using MultiPurposeAuthSite.Tests.E2E.Tests.Extended;

using Xunit;
using Xunit.Abstractions;

namespace MultiPurposeAuthSite.Tests.E2E.Tests.Issues
{
    /// <summary>
    /// RT-371. **`client_assertion` の `aud` に、受けた口（CIBA・PAR）の URL を受ける**（CIBA Core 1.0 §7.1・RFC 9126 §2）。
    /// </summary>
    /// <remarks>
    /// **以前は、どの口でも、トークン エンドポイントの URL と issuer だけを受けていた**ので、
    /// **`aud` に CIBA の口・PAR の口の URL を書いた RP は `invalid_client` で断られた**
    /// （適合性テストの `fapi-ciba-id1` の大半と、`fapi1-advanced-final-par-test-pushed-authorization-url-as-audience-…`）。
    ///
    /// | | 測ること |
    /// |---|---|
    /// | **`RT-371.1`** | **`/ciba_authz` は、CIBA の口の URL を受ける。** PAR の口の URL は受けない |
    /// | **`RT-371.2`** | **`/par` は、PAR の口の URL を受ける。** CIBA の口の URL は受けない。**`/revoke` は PAR の口の URL を受けない** |
    /// | **`RT-371.3`** | **fapi2 の登録は、`/par` でも issuer だけ**（PAR の口の URL も受けない。#323） |
    ///
    /// **足すのは、その口の URL だけ**（クライアント認証の JWT の `jti` は使用済みとして記録していないので、
    /// **ある口に宛てたアサーションを、別の口で使えないようにする**）。
    /// **口の URL は、テストの側では `BaseUrl` ＋ 口のパスで作る**（`RT-294.54` のトークン エンドポイントと同じ）。
    /// **配列の `aud` は、この Issue では変えない**（`RT-294.54`）。
    ///
    /// **`RT-371.1` は利用者の端末を登録する**ので、CIBA のほかのテストと同じコレクションで、順に回す
    /// （並行に回すと、端末の登録を上書きし合う）。
    /// </remarks>
    [Collection(CibaTests.DeviceCollection)]
    public class ClientAssertionAudienceTests : TargetTestBase
    {
        /// <summary>client_assertion_type（RFC 7523 §2.2）</summary>
        private const string JwtBearerAssertionType = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer";

        /// <summary>PKCE の code_challenge（S256。値は RFC 7636 付録 B）</summary>
        private const string CodeChallenge = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";

        /// <summary>コンストラクタ</summary>
        /// <param name="output">ITestOutputHelper</param>
        public ClientAssertionAudienceTests(ITestOutputHelper output) : base(output)
        {
        }

        #region RT-371.1

        /// <summary>RT-371.1 /ciba_authz は、client_assertion の aud に CIBA の口の URL を受ける</summary>
        /// <param name="targetKey">core / netfx</param>
        /// <returns>Task</returns>
        [SkippableTheory]
        [MemberData(nameof(AllTargets))]
        public async Task RT37101_ciba_authzはaudにCIBAの口のURLを受ける(string targetKey)
        {
            using (IdPClient client = await this.SignedInClientAsync(targetKey))
            {
                FcmOutbox.SkipIfUnavailable(client.Target);

                TestReport r = this.Report("RT-371.1",
                    "**/ciba_authz は、client_assertion の aud に CIBA の口（Backchannel Authentication Endpoint）の URL を受ける。PAR の口の URL は受けない**",
                    "**CIBA Core 1.0 §7.1 は、OP が issuer・トークン エンドポイントの URL・CIBA の口の URL を aud として受けることを求める（MUST）。**"
                    + "**以前は、トークン エンドポイントの URL と issuer だけを受けていた**ので、CIBA の口の URL を書いた RP は invalid_client で断られた。"
                    + "**足すのはその口の URL だけ**（ほかの口に宛てたアサーションは受けない）。",
                    "CIBA Core 1.0 §7.1 / #371");

                ClientRegistration reg = Flows.InjectedRegistration(client, KnownClients.TestClient4_4);
                string cibaUrl = client.Target.BaseUrl + "/ciba_authz";
                string parUrl = client.Target.BaseUrl + "/par";

                r.Target("POST /ciba_authz（client_name=" + KnownClients.TestClient4_4
                    + "。fapi_ciba。private_key_jwt（ES256）で認証する）");

                (string AccessToken, string DeviceToken) device = await CibaTests.RegisterDeviceAsync(r, client);

                r.Step("(1) aud = CIBA の口の URL（通る）");

                JsonResponse accepted = await ClientAssertionAudienceTests.CibaAuthorizeAsync(
                    client, reg, targetKey, cibaUrl);

                string authReqId = accepted.String("auth_req_id");

                r.Verify("auth_req_id が返る（認証が通る）", !string.IsNullOrEmpty(authReqId),
                    "あり", string.IsNullOrEmpty(authReqId) ? "**無い**（" + accepted.ToString() + "）" : "あり");

                if (!string.IsNullOrEmpty(authReqId))
                {
                    // **後始末**（利用者は拒否する。端末の登録は、同じコレクションの次のテストが上書きする）。
                    await CibaTests.ReceivePushAsync(r, client, authReqId, device.DeviceToken);
                    await client.CibaPushResultAsync(device.AccessToken, authReqId, "false");
                }

                r.Step("(2) aud = PAR の口の URL（ほかの口の URL は受けない）");

                JsonResponse rejected = await ClientAssertionAudienceTests.CibaAuthorizeAsync(
                    client, reg, targetKey, parUrl);

                r.VerifyEqual("HTTP 401", "401", ((int)rejected.StatusCode).ToString());
                r.VerifyEqual("invalid_client", "invalid_client", rejected.Error ?? "（無い）");

                r.Done();
            }
        }

        #endregion

        #region RT-371.2

        /// <summary>RT-371.2 /par は、client_assertion の aud に PAR の口の URL を受ける</summary>
        /// <param name="targetKey">core / netfx</param>
        /// <returns>Task</returns>
        [SkippableTheory]
        [MemberData(nameof(AllTargets))]
        public async Task RT37102_parはaudにPARの口のURLを受ける(string targetKey)
        {
            using (IdPClient client = this.Client(targetKey))
            {
                TestReport r = this.Report("RT-371.2",
                    "**/par は、client_assertion の aud に PAR の口の URL を受ける。CIBA の口の URL は受けない。/revoke は PAR の口の URL を受けない**",
                    "**RFC 9126 §2 は、認可サーバが issuer・トークン エンドポイントの URL・PAR の口の URL を aud として受けることを求める（MUST）。**"
                    + "**以前は、トークン エンドポイントの URL と issuer だけを受けていた**ので、PAR の口の URL を書いた RP は invalid_client で断られた。"
                    + "**足すのはその口の URL だけ**（ほかの口に宛てたアサーションは受けない）。",
                    "RFC 9126 §2 / #371");

                ClientRegistration reg = Flows.InjectedRegistration(client, KnownClients.TestClient_24);
                string parUrl = client.Target.BaseUrl + "/par";
                string cibaUrl = client.Target.BaseUrl + "/ciba_authz";

                r.Target("POST /par・POST /revoke（client_name=" + KnownClients.TestClient_24
                    + "。normal。private_key_jwt（RS256）で認証する）");

                r.Step("(1) /par に aud = PAR の口の URL（通る）");

                JsonResponse accepted = await ClientAssertionAudienceTests.ParAsync(client, reg, parUrl, "state-rt3712-1");

                r.VerifyEqual("HTTP 201（RFC 9126 §2.2）", "201", ((int)accepted.StatusCode).ToString());
                r.Verify("request_uri が返る", !string.IsNullOrEmpty(accepted.String("request_uri")),
                    "あり", string.IsNullOrEmpty(accepted.String("request_uri")) ? "**無い**（" + accepted.ToString() + "）" : "あり");

                r.Step("(2) /par に aud = CIBA の口の URL（ほかの口の URL は受けない）");

                JsonResponse otherEndpoint = await ClientAssertionAudienceTests.ParAsync(client, reg, cibaUrl, "state-rt3712-2");

                r.VerifyEqual("HTTP 401", "401", ((int)otherEndpoint.StatusCode).ToString());
                r.VerifyEqual("invalid_client", "invalid_client", otherEndpoint.Error ?? "（無い）");

                r.Step("(3) /revoke に aud = PAR の口の URL（PAR の口でしか受けない）");

                JsonResponse revoke = await client.RevokeAsync(new Dictionary<string, string>()
                {
                    { "token", "not-a-token" },
                    { "client_assertion_type", ClientAssertionAudienceTests.JwtBearerAssertionType },
                    { "client_assertion", ClientAssertionAudienceTests.ClientAssertionRS256(client, reg.ClientId, parUrl) }
                });

                r.VerifyEqual("invalid_client", "invalid_client", revoke.Error ?? "（無い）");

                r.Step("(4) 対照：/revoke に aud = トークン エンドポイントの URL（同じクライアント・同じ鍵で通る）");

                JsonResponse control = await client.RevokeAsync(new Dictionary<string, string>()
                {
                    { "token", "not-a-token" },
                    { "client_assertion_type", ClientAssertionAudienceTests.JwtBearerAssertionType },
                    { "client_assertion", ClientAssertionAudienceTests.ClientAssertionRS256(
                        client, reg.ClientId, client.Target.BaseUrl + "/token") }
                });

                r.VerifyEqual("認証が通る（HTTP 200）", "200", ((int)control.StatusCode).ToString());

                r.Done();
            }
        }

        #endregion

        #region RT-371.3

        /// <summary>RT-371.3 fapi2 の登録は、/par でも aud に issuer だけを受ける</summary>
        /// <param name="targetKey">core / netfx</param>
        /// <returns>Task</returns>
        [SkippableTheory]
        [MemberData(nameof(AllTargets))]
        public async Task RT37103_fapi2の登録はparでもaudにissuerだけを受ける(string targetKey)
        {
            using (IdPClient client = this.Client(targetKey))
            {
                TestReport r = this.Report("RT-371.3",
                    "**fapi2 の登録は、/par でも client_assertion の aud に issuer だけを受ける（PAR の口の URL は受けない）**",
                    "**FAPI 2.0 Security Profile §5.3.2.1 は、issuer だけを文字列で受けることを求める**（RFC 9126 §2 より狭い）。"
                    + "**口の URL を足したのは fapi2 以外の登録**で、fapi2 は口によらず issuer だけ（RT-323.1）。",
                    "FAPI 2.0 Security Profile §5.3.2.1 / #323 / #371");

                ClientRegistration reg = Flows.Registration(client, KnownClients.Fapi2Client);
                string issuer = await client.IssuerAsync();

                r.Target("POST /par（client_name=" + KnownClients.Fapi2Client + "。fapi2。private_key_jwt（RS256）で認証する）");

                r.Step("(1) aud = issuer（通る）");

                JsonResponse accepted = await ClientAssertionAudienceTests.ParAsync(client, reg, issuer, "state-rt3713-1");

                r.VerifyEqual("HTTP 201", "201", ((int)accepted.StatusCode).ToString());

                r.Step("(2) aud = PAR の口の URL（fapi2 は受けない）");

                JsonResponse rejected = await ClientAssertionAudienceTests.ParAsync(
                    client, reg, client.Target.BaseUrl + "/par", "state-rt3713-2");

                r.VerifyEqual("HTTP 401", "401", ((int)rejected.StatusCode).ToString());
                r.VerifyEqual("invalid_client", "invalid_client", rejected.Error ?? "（無い）");

                r.Done();
            }
        }

        #endregion

        #region 補助

        /// <summary>client_assertion（ES256）で POST /ciba_authz する</summary>
        /// <param name="client">IdPClient</param>
        /// <param name="reg">クライアント（fapi_ciba。private_key_jwt）</param>
        /// <param name="targetKey">core / netfx</param>
        /// <param name="aud">client_assertion の aud</param>
        /// <returns>JsonResponse</returns>
        private static async Task<JsonResponse> CibaAuthorizeAsync(
            IdPClient client, ClientRegistration reg, string targetKey, string aud)
        {
            string request = await RequestObjectBuilder.CreateCibaAsync(client, reg.ClientId,
                new Dictionary<string, object>()
                {
                    { "login_hint", TestEnv.TestUserName(targetKey) },
                    { "binding_message", "E2E-" + Guid.NewGuid().ToString("N").Substring(0, 8) }
                });

            long now = DateTimeOffset.UtcNow.ToUnixTimeSeconds();

            string assertion = JwsSigner.SignES256(client, new Dictionary<string, object>()
            {
                { "iss", reg.ClientId },
                { "sub", reg.ClientId },
                { "aud", aud },
                { "jti", Guid.NewGuid().ToString("N") },
                { "iat", now },
                { "exp", now + 300 }
            });

            return await client.CibaAuthorizeAsync(new Dictionary<string, string>()
            {
                { "request", request },
                { "client_assertion_type", ClientAssertionAudienceTests.JwtBearerAssertionType },
                { "client_assertion", assertion }
            });
        }

        /// <summary>client_assertion（RS256）で POST /par する</summary>
        /// <param name="client">IdPClient</param>
        /// <param name="reg">クライアント（private_key_jwt）</param>
        /// <param name="aud">client_assertion の aud</param>
        /// <param name="state">state</param>
        /// <returns>JsonResponse</returns>
        private static Task<JsonResponse> ParAsync(
            IdPClient client, ClientRegistration reg, string aud, string state)
        {
            return client.PostJsonAsync("/par", new Dictionary<string, string>()
            {
                { "client_id", reg.ClientId },
                { "client_assertion_type", ClientAssertionAudienceTests.JwtBearerAssertionType },
                { "client_assertion", ClientAssertionAudienceTests.ClientAssertionRS256(client, reg.ClientId, aud) },
                { "response_type", "code" },
                { "scope", "openid" },
                { "redirect_uri", reg.RedirectUri },
                { "state", state },
                //  **fapi2 の登録は、S256 の PKCE 無しの PAR を断る**（#366）。ほかの登録にも同じ値を送る。
                { "code_challenge", ClientAssertionAudienceTests.CodeChallenge },
                { "code_challenge_method", "S256" }
            });
        }

        /// <summary>RS256 の client_assertion を作る（RFC 7523 §2.2）</summary>
        /// <param name="client">IdPClient</param>
        /// <param name="clientId">client_id</param>
        /// <param name="aud">aud</param>
        /// <returns>client_assertion</returns>
        private static string ClientAssertionRS256(IdPClient client, string clientId, string aud)
        {
            long now = DateTimeOffset.UtcNow.ToUnixTimeSeconds();

            return JwsSigner.SignRS256(client, new Dictionary<string, object>()
            {
                { "iss", clientId },
                { "sub", clientId },
                { "aud", aud },
                { "jti", Guid.NewGuid().ToString("N") },
                { "iat", now },
                { "exp", now + 300 }
            });
        }

        #endregion
    }
}
