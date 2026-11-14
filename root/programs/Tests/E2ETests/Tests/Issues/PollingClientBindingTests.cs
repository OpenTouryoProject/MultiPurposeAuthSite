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
//* クラス名        ：PollingClientBindingTests
//* クラス日本語名  ：RT-387 CIBA・Device のトークン要求は、auth_req_id・device_code を出したクライアントと照合する（CIBA Core 1.0 §11・RFC 6749 §5.2）
//*
//* 作成日時        ：－
//* 作成者          ：－
//* 更新履歴        ：－
//*
//*  日時        更新者            内容
//*  ----------  ----------------  -------------------------------------------------
//*  2026/11/14  玄人 幸道         新規（#387）
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
    /// RT-387. **CIBA・Device のトークン要求は、`auth_req_id`・`device_code` を出したクライアントと照合する**
    /// （CIBA Core 1.0 §11・RFC 8628 §3.5・RFC 6749 §5.2）。
    /// </summary>
    /// <remarks>
    /// **以前は照合する前に、状態（`authorization_pending` など）を返し、ポーリングの時刻を書き換え、
    /// 承認済みなら記録と認可コードを消していた**（適合性テストの `fapi-ciba-id1-ensure-wrong-auth-req-id-in-token-endpoint-request`）。
    ///
    /// | | 測ること |
    /// |---|---|
    /// | **`RT-387.1`** | **CIBA**：別のクライアントは、承認の前も後も `invalid_grant`。**その後も、正規のクライアントは `authorization_pending`（`slow_down` でない）を受け、承認の後にトークンを受け取れる** |
    /// | **`RT-387.2`** | **Device**：同じことを `device_code` で |
    ///
    /// **正規のクライアントが `slow_down` を受けないこと**で、**別のクライアントの要求が、ポーリングの時刻を書き換えていない**ことを確かめる
    /// （書き換えると、直後の正規の要求が間隔を守っていないとみなされる）。
    /// **利用者の端末を登録する**ので、CIBA のほかのテストと同じコレクションで、順に回す。
    /// </remarks>
    [Collection(CibaTests.DeviceCollection)]
    public class PollingClientBindingTests : TargetTestBase
    {
        /// <summary>client_assertion_type（RFC 7523 §2.2）</summary>
        private const string JwtBearerAssertionType = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer";

        /// <summary>CIBA の grant_type</summary>
        private const string CibaGrantType = "urn:openid:params:grant-type:ciba";

        /// <summary>Device の grant_type</summary>
        private const string DeviceGrantType = "urn:ietf:params:oauth:grant-type:device_code";

        /// <summary>コンストラクタ</summary>
        /// <param name="output">ITestOutputHelper</param>
        public PollingClientBindingTests(ITestOutputHelper output) : base(output)
        {
        }

        #region RT-387.1

        /// <summary>RT-387.1 CIBA の別のクライアントは invalid_grant で、正規のクライアントは影響を受けない</summary>
        /// <param name="targetKey">core / netfx</param>
        /// <returns>Task</returns>
        [SkippableTheory]
        [MemberData(nameof(AllTargets))]
        public async Task RT38701_CIBAの別のクライアントはinvalid_grantで正規のクライアントは影響を受けない(string targetKey)
        {
            using (IdPClient client = await this.SignedInClientAsync(targetKey))
            {
                FcmOutbox.SkipIfUnavailable(client.Target);

                TestReport r = this.Report("RT-387.1",
                    "**CIBA のトークン要求で、別のクライアントに出した auth_req_id は、承認の前も後も invalid_grant。正規のクライアントは影響を受けない**",
                    "**CIBA Core 1.0 §11 は、別のクライアントに出した auth_req_id に invalid_grant を求める（MUST）。**"
                    + "**以前は照合する前に、状態を返し、ポーリングの時刻を書き換え、承認済みなら記録と認可コードを消していた**ので、"
                    + "auth_req_id を知る別のクライアントが先に引くと、正規のクライアントが結果を受け取れなかった。",
                    "CIBA Core 1.0 §11 / #387");

                ClientRegistration owner = Flows.Registration(client, KnownClients.FapiCibaClient);
                ClientRegistration other = Flows.InjectedRegistration(client, KnownClients.TestClient4_4);

                r.Target("auth_req_id を出したクライアント=" + KnownClients.FapiCibaClient
                    + "（client_secret）/ 別のクライアント=" + KnownClients.TestClient4_4 + "（fapi_ciba。private_key_jwt）");

                r.Step("(1) 利用者 : 認証デバイスを登録し、" + KnownClients.FapiCibaClient + " が CIBA を始める");

                (string AccessToken, string DeviceToken) device = await CibaTests.RegisterDeviceAsync(r, client);

                JsonResponse start = await CibaTests.StartAsync(
                    client, owner, "E2E-" + Guid.NewGuid().ToString("N").Substring(0, 8));
                string authReqId = start.String("auth_req_id");

                Assert.False(string.IsNullOrEmpty(authReqId), "前提: auth_req_id が返ること（" + start.ToString() + "）");

                await CibaTests.ReceivePushAsync(r, client, authReqId, device.DeviceToken);

                r.Step("(2) 承認の前に、別のクライアントが、その auth_req_id でトークンを要求する");

                JsonResponse otherPending = await PollingClientBindingTests.CibaTokenByOtherAsync(client, other, authReqId);

                r.VerifyEqual("invalid_grant（authorization_pending を返さない）", "invalid_grant", otherPending.Error ?? "（無い）");

                r.Step("(3) 続けて、正規のクライアントがポーリングする");

                JsonResponse ownerPending = await CibaTests.PollAsync(client, owner, authReqId);

                r.VerifyEqual("authorization_pending（slow_down にならない ＝ 別のクライアントの要求は、ポーリングの時刻を書き換えていない）",
                    "authorization_pending", ownerPending.Error ?? "（無い）");

                r.Step("(4) 利用者 : 認証デバイスで許可する");

                JsonResponse answer = await client.CibaPushResultAsync(device.AccessToken, authReqId, "true");

                Assert.Equal(200, (int)answer.StatusCode);

                r.Step("(5) 承認の後に、別のクライアントが、その auth_req_id でトークンを要求する");

                JsonResponse otherGranted = await PollingClientBindingTests.CibaTokenByOtherAsync(client, other, authReqId);

                r.VerifyEqual("invalid_grant", "invalid_grant", otherGranted.Error ?? "（無い）");
                r.Verify("トークンを出さない", string.IsNullOrEmpty(otherGranted.AccessToken),
                    "返さない", string.IsNullOrEmpty(otherGranted.AccessToken) ? "返さなかった" : "**返した**");

                r.Step("(6) 正規のクライアントがポーリングする（記録と認可コードが残っている）");

                JsonResponse ownerGranted = await CibaTests.PollAsync(client, owner, authReqId);

                r.Verify("access_token が返る", !string.IsNullOrEmpty(ownerGranted.AccessToken),
                    "あり", string.IsNullOrEmpty(ownerGranted.AccessToken)
                        ? "**無い**（" + ownerGranted.ToString() + "）" : "あり（値は伏せる）");

                r.Done();
            }
        }

        #endregion

        #region RT-387.2

        /// <summary>RT-387.2 Device の別のクライアントは invalid_grant で、正規のクライアントは影響を受けない</summary>
        /// <param name="targetKey">core / netfx</param>
        /// <returns>Task</returns>
        [SkippableTheory]
        [MemberData(nameof(AllTargets))]
        public async Task RT38702_Deviceの別のクライアントはinvalid_grantで正規のクライアントは影響を受けない(string targetKey)
        {
            using (IdPClient client = await this.SignedInClientAsync(targetKey))
            {
                TestReport r = this.Report("RT-387.2",
                    "**Device のトークン要求で、別のクライアントに出した device_code は、承認の前も後も invalid_grant。正規のクライアントは影響を受けない**",
                    "**RFC 8628 §3.5 は RFC 6749 §5.2 のエラーを使い、§5.2 の invalid_grant は「issued to another client」を含む。**"
                    + "**以前は CIBA と同じく、照合する前に、状態を返し、ポーリングの時刻を書き換え、承認済みなら記録と認可コードを消していた。**",
                    "RFC 8628 §3.5 / RFC 6749 §5.2 / #387");

                ClientRegistration owner = Flows.Registration(client, KnownClients.DeviceClient);
                ClientRegistration other = Flows.Registration(client, KnownClients.MvcSample);

                r.Target("device_code を出したクライアント=" + KnownClients.DeviceClient
                    + " / 別のクライアント=" + KnownClients.MvcSample + "（normal。client_secret）");

                r.Step("(1) 機器 : " + KnownClients.DeviceClient + " が POST /device_authz で device_code を得る");

                JsonResponse start = await DeviceAuthorizationTests.StartAsync(client, owner.ClientId);
                string deviceCode = start.String("device_code");
                string userCode = start.String("user_code");

                Assert.False(string.IsNullOrEmpty(deviceCode) || string.IsNullOrEmpty(userCode),
                    "前提: device_code と user_code が発行されること（" + start.ToString() + "）");

                r.Step("(2) 承認の前に、別のクライアントが、その device_code でトークンを要求する");

                JsonResponse otherPending = await PollingClientBindingTests.DeviceTokenByOtherAsync(client, other, deviceCode);

                r.VerifyEqual("invalid_grant（authorization_pending を返さない）", "invalid_grant", otherPending.Error ?? "（無い）");

                r.Step("(3) 続けて、正規のクライアントがポーリングする");

                JsonResponse ownerPending = await DeviceAuthorizationTests.PollAsync(client, owner.ClientId, deviceCode);

                r.VerifyEqual("authorization_pending（slow_down にならない ＝ 別のクライアントの要求は、ポーリングの時刻を書き換えていない）",
                    "authorization_pending", ownerPending.Error ?? "（無い）");

                r.Step("(4) 利用者 : user_code を入力して許可する");

                bool accepted = await client.SubmitDeviceUserCodeAsync(userCode, true);

                Assert.True(accepted, "前提: 検証画面が承認を受け付けること");

                r.Step("(5) 承認の後に、別のクライアントが、その device_code でトークンを要求する");

                JsonResponse otherGranted = await PollingClientBindingTests.DeviceTokenByOtherAsync(client, other, deviceCode);

                r.VerifyEqual("invalid_grant", "invalid_grant", otherGranted.Error ?? "（無い）");
                r.Verify("トークンを出さない", string.IsNullOrEmpty(otherGranted.AccessToken),
                    "返さない", string.IsNullOrEmpty(otherGranted.AccessToken) ? "返さなかった" : "**返した**");

                r.Step("(6) 正規のクライアントがポーリングする（記録と認可コードが残っている）");

                JsonResponse ownerGranted = await DeviceAuthorizationTests.PollAsync(client, owner.ClientId, deviceCode);

                r.Verify("access_token が返る", !string.IsNullOrEmpty(ownerGranted.AccessToken),
                    "あり", string.IsNullOrEmpty(ownerGranted.AccessToken)
                        ? "**無い**（" + ownerGranted.ToString() + "）" : "あり（値は伏せる）");

                r.Done();
            }
        }

        #endregion

        #region 補助

        /// <summary>別のクライアント（private_key_jwt。ES256）で、CIBA のトークンを要求する</summary>
        /// <param name="client">IdPClient</param>
        /// <param name="other">別のクライアント</param>
        /// <param name="authReqId">auth_req_id</param>
        /// <returns>JsonResponse</returns>
        private static Task<JsonResponse> CibaTokenByOtherAsync(IdPClient client, ClientRegistration other, string authReqId)
        {
            long now = DateTimeOffset.UtcNow.ToUnixTimeSeconds();

            string assertion = JwsSigner.SignES256(client, new Dictionary<string, object>()
            {
                { "iss", other.ClientId },
                { "sub", other.ClientId },
                { "aud", client.Target.BaseUrl + "/token" },
                { "jti", Guid.NewGuid().ToString("N") },
                { "iat", now },
                { "exp", now + 300 }
            });

            return client.TokenAsync(new Dictionary<string, string>()
            {
                { "grant_type", PollingClientBindingTests.CibaGrantType },
                { "auth_req_id", authReqId },
                { "client_assertion_type", PollingClientBindingTests.JwtBearerAssertionType },
                { "client_assertion", assertion }
            });
        }

        /// <summary>別のクライアント（client_secret）で、Device のトークンを要求する</summary>
        /// <param name="client">IdPClient</param>
        /// <param name="other">別のクライアント</param>
        /// <param name="deviceCode">device_code</param>
        /// <returns>JsonResponse</returns>
        private static Task<JsonResponse> DeviceTokenByOtherAsync(IdPClient client, ClientRegistration other, string deviceCode)
        {
            return client.TokenAsync(new Dictionary<string, string>()
            {
                { "grant_type", PollingClientBindingTests.DeviceGrantType },
                { "device_code", deviceCode },
                { "client_id", other.ClientId },
                { "client_secret", other.ClientSecret }
            });
        }

        #endregion
    }
}
