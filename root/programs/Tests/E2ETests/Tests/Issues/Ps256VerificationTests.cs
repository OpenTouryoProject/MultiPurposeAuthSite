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
//* クラス名        ：Ps256VerificationTests
//* クラス日本語名  ：RT-395 client_assertion と CIBA の署名した要求で PS256 を受け、FAPI の登録・CIBA は RS256 を断る（FAPI 1.0 Advanced §8.6）
//*
//* 作成日時        ：－
//* 作成者          ：－
//* 更新履歴        ：－
//*
//*  日時        更新者            内容
//*  ----------  ----------------  -------------------------------------------------
//*  2026/11/15  玄人 幸道         新規（#395）
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
    /// RT-395. **`client_assertion` と CIBA の署名した要求で PS256 を受け、FAPI の登録・CIBA は RS256 を断る**（FAPI 1.0 Advanced §8.6）。
    /// </summary>
    /// <remarks>
    /// **以前は、`client_assertion` は RS256・ES256、CIBA の要求は ES256 だけを受けていた**
    /// （JWK を受ける版の `JwtAssertion.Verify`・`RequestObject.VerifyCiba` が、鍵の種類で alg を決めていた）。
    /// **検証鍵 `JWS` を受ける版（OpenTouryo#664）に替え、ヘッダの alg と登録の鍵から検証鍵を作るようにした。**
    ///
    /// | | 測ること |
    /// |---|---|
    /// | **`RT-395.1`** | **`client_assertion`**：FAPI でない登録・fapi2 の登録とも **PS256 で通る**。**fapi2 の登録の RS256 は `invalid_client`**。広告に PS256 が在る |
    /// | **`RT-395.2`** | **CIBA の署名した要求**：**PS256（RSA の鍵）でも ES256（EC の鍵）でも受け付ける**（`auth_req_id` が返る）。**RS256 は断る**。広告は PS256・ES256 |
    ///
    /// **`RT-395.2` は利用者の端末を登録する**ので、CIBA のほかのテストと同じコレクションで、順に回す。
    /// </remarks>
    [Collection(CibaTests.DeviceCollection)]
    public class Ps256VerificationTests : TargetTestBase
    {
        /// <summary>client_assertion_type（RFC 7523 §2.2）</summary>
        private const string JwtBearerAssertionType = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer";

        /// <summary>コンストラクタ</summary>
        /// <param name="output">ITestOutputHelper</param>
        public Ps256VerificationTests(ITestOutputHelper output) : base(output)
        {
        }

        #region RT-395.1

        /// <summary>RT-395.1 client_assertion で PS256 を受け、fapi2 の登録の RS256 は断る</summary>
        /// <param name="targetKey">core / netfx</param>
        /// <returns>Task</returns>
        [SkippableTheory]
        [MemberData(nameof(AllTargets))]
        public async Task RT39501_client_assertionでPS256を受けfapi2の登録のRS256は断る(string targetKey)
        {
            using (IdPClient client = this.Client(targetKey))
            {
                TestReport r = this.Report("RT-395.1",
                    "**client_assertion は PS256 でも通る（FAPI でない登録・fapi2 の登録）。fapi2 の登録の RS256 は invalid_client。Discovery は PS256 を広告する**",
                    "**FAPI 1.0 Advanced §8.6 は、クライアントも認可サーバも PS256 か ES256 を使うことを求める**（FAPI 2.0 Security Profile §5.4.1 も同じ）。"
                    + "**以前は RS256・ES256 だけを受け**、PS256 の FAPI のクライアントは認証できなかった。**FAPI の登録は RS256 を断る**（Request Object と同じ。#370）。",
                    "FAPI 1.0 Advanced §8.6 / FAPI 2.0 Security Profile §5.4.1 / RFC 7523 §2.2 / #395");

                string issuer = await client.IssuerAsync();
                ClientRegistration normal = Flows.InjectedRegistration(client, KnownClients.TestClient_24);
                ClientRegistration fapi2 = Flows.Registration(client, KnownClients.Fapi2Client);

                r.Target("POST /revoke（client_name=" + KnownClients.TestClient_24 + "（normal）・"
                    + KnownClients.Fapi2Client + "（fapi2）。private_key_jwt で認証する）");

                r.Step("(1) FAPI でない登録 : PS256 のアサーション");

                JsonResponse normalPs256 = await Ps256VerificationTests.RevokeAsync(client,
                    JwsSigner.SignPS256(client, Ps256VerificationTests.AssertionPayload(normal.ClientId, client.Target.BaseUrl + "/token")));

                r.VerifyEqual("認証が通る（HTTP 200）", "200", ((int)normalPs256.StatusCode).ToString());

                r.Step("(2) fapi2 の登録 : PS256 のアサーション（aud は issuer）");

                JsonResponse fapiPs256 = await Ps256VerificationTests.RevokeAsync(client,
                    JwsSigner.SignPS256(client, Ps256VerificationTests.AssertionPayload(fapi2.ClientId, issuer)));

                r.VerifyEqual("認証が通る（HTTP 200）", "200", ((int)fapiPs256.StatusCode).ToString());

                r.Step("(3) fapi2 の登録 : RS256 のアサーション（FAPI は RS256 を認めない）");

                JsonResponse fapiRs256 = await Ps256VerificationTests.RevokeAsync(client,
                    JwsSigner.SignRS256(client, Ps256VerificationTests.AssertionPayload(fapi2.ClientId, issuer)));

                r.VerifyEqual("invalid_client", "invalid_client", fapiRs256.Error ?? "（無い）");

                r.Step("(4) Discovery の広告");

                JsonResponse discovery = await client.GetJsonAsync("/.well-known/openid-configuration");

                r.Verify("token_endpoint_auth_signing_alg_values_supported に PS256 が在る",
                    discovery.ArrayContains("token_endpoint_auth_signing_alg_values_supported", "PS256"),
                    "在る", string.Join(" ", discovery.Strings("token_endpoint_auth_signing_alg_values_supported") ?? new string[0]));

                r.Done();
            }
        }

        #endregion

        #region RT-395.2

        /// <summary>RT-395.2 CIBA の署名した要求で PS256 を受け、RS256 は断る</summary>
        /// <param name="targetKey">core / netfx</param>
        /// <returns>Task</returns>
        [SkippableTheory]
        [MemberData(nameof(AllTargets))]
        public async Task RT39502_CIBAの署名した要求でPS256を受けRS256は断る(string targetKey)
        {
            using (IdPClient client = await this.SignedInClientAsync(targetKey))
            {
                FcmOutbox.SkipIfUnavailable(client.Target);

                TestReport r = this.Report("RT-395.2",
                    "**CIBA の署名した要求（request）は、PS256（RSA の鍵）でも ES256（EC の鍵）でも受け付け（auth_req_id が返る）、RS256 は断る。Discovery は PS256・ES256 を広告する**",
                    "**FAPI-CIBA ID1 §7.10 は、PS256 か ES256 を求める**（§7.6 は FAPI 1.0 Advanced §8.6 に従うとする）。"
                    + "**以前は ES256 だけを受けていた**（使っていた版の `RequestObject.VerifyCiba` が ES256 に固定）。"
                    + "**検証鍵は、ヘッダの alg と登録の鍵（PS256 は RSA、ES256 は EC）で決める。**",
                    "FAPI-CIBA ID1 §7.10 / CIBA Core 1.0 §7.1.1 / #395");

                ClientRegistration reg = Flows.InjectedRegistration(client, KnownClients.TestClient4_5);
                string issuer = await client.IssuerAsync();

                r.Target("POST /ciba_authz（client_name=" + KnownClients.TestClient4_5
                    + "。fapi_ciba。RSA と ECDSA の公開鍵を登録。Basic で認証する）");

                (string AccessToken, string DeviceToken) device = await CibaTests.RegisterDeviceAsync(r, client);

                r.Step("(1) PS256 で署名した要求（受け付ける）");

                JsonResponse ps256 = await client.CibaAuthorizeWithBasicAuthAsync(
                    new Dictionary<string, string>()
                    {
                        { "request", JwsSigner.SignPS256(client, Ps256VerificationTests.CibaPayload(reg.ClientId, issuer, targetKey)) }
                    },
                    reg.ClientId, reg.ClientSecret);

                string authReqId = ps256.String("auth_req_id");

                r.Verify("auth_req_id が返る", !string.IsNullOrEmpty(authReqId),
                    "あり", string.IsNullOrEmpty(authReqId) ? "**無い**（" + ps256.ToString() + "）" : "あり");

                if (!string.IsNullOrEmpty(authReqId))
                {
                    // **後始末**（利用者は拒否する。端末の登録は、同じコレクションの次のテストが上書きする）。
                    await CibaTests.ReceivePushAsync(r, client, authReqId, device.DeviceToken);
                    await client.CibaPushResultAsync(device.AccessToken, authReqId, "false");
                }

                r.Step("(2) ES256 で署名した要求（同じクライアント。EC の鍵で検証する）");

                JsonResponse es256 = await client.CibaAuthorizeWithBasicAuthAsync(
                    new Dictionary<string, string>()
                    {
                        { "request", JwsSigner.SignES256(client, Ps256VerificationTests.CibaPayload(reg.ClientId, issuer, targetKey)) }
                    },
                    reg.ClientId, reg.ClientSecret);

                string esAuthReqId = es256.String("auth_req_id");

                r.Verify("auth_req_id が返る", !string.IsNullOrEmpty(esAuthReqId),
                    "あり", string.IsNullOrEmpty(esAuthReqId) ? "**無い**（" + es256.ToString() + "）" : "あり");

                if (!string.IsNullOrEmpty(esAuthReqId))
                {
                    await CibaTests.ReceivePushAsync(r, client, esAuthReqId, device.DeviceToken);
                    await client.CibaPushResultAsync(device.AccessToken, esAuthReqId, "false");
                }

                r.Step("(3) RS256 で署名した要求（FAPI-CIBA は RS256 を認めない）");

                JsonResponse rs256 = await client.CibaAuthorizeWithBasicAuthAsync(
                    new Dictionary<string, string>()
                    {
                        { "request", JwsSigner.SignRS256(client, Ps256VerificationTests.CibaPayload(reg.ClientId, issuer, targetKey)) }
                    },
                    reg.ClientId, reg.ClientSecret);

                r.Verify("auth_req_id を返さない", string.IsNullOrEmpty(rs256.String("auth_req_id")),
                    "返さない", string.IsNullOrEmpty(rs256.String("auth_req_id")) ? "返さなかった" : "**返した**");
                r.VerifyEqual("invalid_request", "invalid_request", rs256.Error ?? "（無い）");

                r.Step("(4) Discovery の広告");

                JsonResponse discovery = await client.GetJsonAsync("/.well-known/openid-configuration");

                r.VerifyEqual("backchannel_authentication_request_signing_alg_values_supported",
                    "PS256 ES256",
                    string.Join(" ", discovery.Strings("backchannel_authentication_request_signing_alg_values_supported") ?? new string[0]));

                r.Done();
            }
        }

        #endregion

        #region 補助

        /// <summary>client_assertion のペイロード（RFC 7523 §3）</summary>
        /// <param name="clientId">client_id（iss・sub）</param>
        /// <param name="aud">aud</param>
        /// <returns>ペイロード</returns>
        private static Dictionary<string, object> AssertionPayload(string clientId, string aud)
        {
            long now = DateTimeOffset.UtcNow.ToUnixTimeSeconds();

            return new Dictionary<string, object>()
            {
                { "iss", clientId },
                { "sub", clientId },
                { "aud", aud },
                { "jti", Guid.NewGuid().ToString("N") },
                { "iat", now },
                { "exp", now + 300 }
            };
        }

        /// <summary>client_assertion で POST /revoke する（認証が通れば 200）</summary>
        /// <param name="client">IdPClient</param>
        /// <param name="assertion">client_assertion</param>
        /// <returns>JsonResponse</returns>
        private static Task<JsonResponse> RevokeAsync(IdPClient client, string assertion)
        {
            return client.RevokeAsync(new Dictionary<string, string>()
            {
                { "token", "not-a-token" },
                { "client_assertion_type", Ps256VerificationTests.JwtBearerAssertionType },
                { "client_assertion", assertion }
            });
        }

        /// <summary>CIBA の署名した要求のペイロード（CIBA Core 1.0 §7.1.1。poll なので client_notification_token は入れない）</summary>
        /// <param name="clientId">client_id（iss）</param>
        /// <param name="issuer">OP の Issuer Identifier（aud）</param>
        /// <param name="targetKey">core / netfx（login_hint の利用者）</param>
        /// <returns>ペイロード</returns>
        private static Dictionary<string, object> CibaPayload(string clientId, string issuer, string targetKey)
        {
            long now = DateTimeOffset.UtcNow.ToUnixTimeSeconds();

            return new Dictionary<string, object>()
            {
                { "iss", clientId },
                { "aud", issuer },
                { "iat", now },
                { "nbf", now },
                { "exp", now + 600 },
                { "jti", Guid.NewGuid().ToString("N") },
                { "scope", "openid" },
                { "login_hint", TestEnv.TestUserName(targetKey) },
                { "binding_message", "E2E-" + Guid.NewGuid().ToString("N").Substring(0, 8) }
            };
        }

        #endregion
    }
}
