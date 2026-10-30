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
//* クラス名        ：OAuth2EndpointReviewTests
//* クラス日本語名  ：RT-294.73 〜 .79 OAuth2EndpointController.*.cs のレビューで見つけた不具合
//*
//* 作成日時        ：－
//* 作成者          ：－
//* 更新履歴        ：－
//*
//*  日時        更新者            内容
//*  ----------  ----------------  -------------------------------------------------
//*  2026/10/30  玄人 幸道         新規（#294）
//*  2026/10/30  玄人 幸道         RT-294.79（/par は同じ名前のパラメタを断る）を足した・既定の利用者の行を書くので CIBA と同じコレクションに入れた（#294）
//**********************************************************************************

using System;
using System.Collections.Generic;
using System.Net;
using System.Net.Http;
using System.Text.Json;
using System.Threading.Tasks;

using MultiPurposeAuthSite.Tests.E2E.Infrastructure;
using MultiPurposeAuthSite.Tests.E2E.Tests.Extended;

using Xunit;
using Xunit.Abstractions;

namespace MultiPurposeAuthSite.Tests.E2E.Tests.Issues
{
    /// <summary>
    /// RT-294.73 〜 .79 `OAuth2EndpointController.*.cs` のレビューで見つけた不具合（#294）。
    /// </summary>
    /// <remarks>
    /// | | 確かめること |
    /// |---|---|
    /// | `RT-294.73` | **認証デバイス用の口は、認証デバイスのクライアントのトークンだけを受ける**（C-55） |
    /// | `RT-294.74` | **`/token` の `grant_type` の誤りを、RFC 6749 §5.2 のコードで返す** |
    /// | `RT-294.75` | **`/device_authz` の `expires_in` / `interval` は JSON の数値** |
    /// | `RT-294.76` | **CIBA の `requested_expiry` を検証し、上限で頭を打つ。応答の数値も見る** |
    /// | `RT-294.77` | **デバイス認可で `private_key_jwt` が通る** |
    /// | `RT-294.78` | **`/revoke`・`/introspect` は、クライアント認証を `token` の有無より先に行う** |
    /// | `RT-294.79` | **`/par` は、同じ名前のパラメタが 2 回来たら断る** |
    ///
    /// **既定の利用者の行（端末の登録）を書く**（`RT-294.73` / `.76`）ので、CIBA のテストと同じコレクションに入れる
    /// （並行すると、プッシュの宛先を上書きし合う）。
    /// </remarks>
    [Collection(CibaTests.DeviceCollection)]
    public class OAuth2EndpointReviewTests : TargetTestBase
    {
        /// <summary>コンストラクタ</summary>
        /// <param name="output">ITestOutputHelper</param>
        public OAuth2EndpointReviewTests(ITestOutputHelper output) : base(output) { }

        #region RT-294.73

        /// <summary>RT-294.73 認証デバイス用の口は、認証デバイスのクライアントのトークンだけを受ける</summary>
        /// <param name="targetKey">core / netfx</param>
        /// <returns>Task</returns>
        [SkippableTheory]
        [MemberData(nameof(AllTargets))]
        public async Task RT29473_認証デバイスの口は認証デバイスのトークンだけを受ける(string targetKey)
        {
            using (IdPClient client = await this.SignedInClientAsync(targetKey))
            {
                TestReport r = this.Report("RT-294.73",
                    "/SetDeviceToken・/ciba_result・/2fa_result は、認証デバイスのクライアントに発行したトークンだけを受ける",
                    "**以前はトークンの発行先を見ておらず、利用者が同意したどの RP のトークンでも通った。**"
                    + "**RP が、利用者の端末の登録を差し替え、CIBA の要求を「許可」し、2FA のプッシュ承認を記録できた。**"
                    + "**`AuthenticationDeviceClientIds`（既定は同梱の AuthenticationDevice_Web）に挙げたクライアントだけ**を受ける。",
                    "#294（ANALYSIS-IdP.md の C-55）");

                r.Target("RP = " + KnownClients.MvcSample + " / 認証デバイス = " + KnownClients.AuthenticationDeviceWeb);

                r.Step("(1) 同じ利用者で、RP のトークンと、認証デバイスのトークンを取る");

                JsonResponse rp = await Flows.RunAuthorizationCodeFlowAsync(client, KnownClients.MvcSample);
                JsonResponse device = await Flows.RunAuthenticationDeviceFlowAsync(client);

                Assert.False(string.IsNullOrEmpty(rp.AccessToken), "前提: RP の access_token が返ること");
                Assert.False(string.IsNullOrEmpty(device.AccessToken), "前提: 認証デバイスの access_token が返ること");

                r.Step("(2) RP のトークンで、3 つの口を叩く");

                JsonResponse setByRp = await client.SetDeviceTokenAsync(rp.AccessToken, "e2e-rp-" + Guid.NewGuid().ToString("N"));
                JsonResponse cibaByRp = await client.CibaPushResultAsync(rp.AccessToken, "dummy", "true");
                JsonResponse twoFaByRp = await client.TwoFactorPushResultAsync(rp.AccessToken, "000000");

                OAuth2EndpointReviewTests.VerifyRejected(r, "/SetDeviceToken", setByRp);
                OAuth2EndpointReviewTests.VerifyRejected(r, "/ciba_result", cibaByRp);
                OAuth2EndpointReviewTests.VerifyRejected(r, "/2fa_result", twoFaByRp);

                r.Step("(3) 認証デバイスのトークンなら、通る（対照）");

                JsonResponse setByDevice = await client.SetDeviceTokenAsync(
                    device.AccessToken, "e2e-device-" + Guid.NewGuid().ToString("N"));

                r.VerifyEqual("/SetDeviceToken : HTTP 200（端末を登録できる）", "200", ((int)setByDevice.StatusCode).ToString());

                //  **トークンは受け、要求の中身で断る**（auth_req_id / code が合わない）ので 400。
                JsonResponse cibaByDevice = await client.CibaPushResultAsync(device.AccessToken, "dummy", "true");
                JsonResponse twoFaByDevice = await client.TwoFactorPushResultAsync(device.AccessToken, "000000");

                r.VerifyEqual("/ciba_result : トークンは受ける（合わない auth_req_id なので 400）",
                    "400", ((int)cibaByDevice.StatusCode).ToString());
                r.VerifyEqual("/2fa_result : トークンは受ける（合わないコードなので 400）",
                    "400", ((int)twoFaByDevice.StatusCode).ToString());

                r.Done();
            }
        }

        /// <summary>RP のトークンが断られたか（401 ＋ NG ＋ invalid_token）</summary>
        /// <param name="r">TestReport</param>
        /// <param name="path">口</param>
        /// <param name="res">応答</param>
        private static void VerifyRejected(TestReport r, string path, JsonResponse res)
        {
            string www = res.Header("WWW-Authenticate") ?? "";

            r.Verify(path + " : **RP のトークンは 401 で断る**",
                res.StatusCode == HttpStatusCode.Unauthorized && www.Contains("invalid_token"),
                "401 / invalid_token",
                (int)res.StatusCode + " / " + (string.IsNullOrEmpty(www) ? "WWW-Authenticate なし" : www));
        }

        #endregion

        #region RT-294.74

        /// <summary>RT-294.74 /token の grant_type の誤りを RFC 6749 §5.2 のコードで返す</summary>
        /// <param name="targetKey">core / netfx</param>
        /// <returns>Task</returns>
        [SkippableTheory]
        [MemberData(nameof(AllTargets))]
        public async Task RT29474_grant_typeの誤りをRFCのコードで返す(string targetKey)
        {
            using (IdPClient client = this.Client(targetKey))
            {
                TestReport r = this.Report("RT-294.74",
                    "/token : grant_type が無ければ invalid_request、未知・大文字小文字の違う値なら unsupported_grant_type",
                    "**以前はどちらも invalid_grant だった**（RFC 6749 §5.2 では、invalid_grant は「グラントそのものが無効」）。"
                    + "**grant_type は大文字小文字を区別する値**なので、`AUTHORIZATION_CODE` も知らない値として扱う"
                    + "（以前は ToLower で通していた）。`RT-196.3` は HTTP ステータスだけを判定し、値は記録していた。",
                    "RFC 6749 §5.2 / #294");

                ClientRegistration reg = Flows.Registration(client, KnownClients.MvcSample);

                r.Target("client_name=" + KnownClients.MvcSample);

                r.Step("(1) grant_type を付けずに送る");

                JsonResponse none = await client.TokenAsync(new Dictionary<string, string>()
                {
                    { "client_id", reg.ClientId },
                    { "client_secret", reg.ClientSecret }
                });

                r.VerifyEqual("invalid_request", "invalid_request", none.Error);

                r.Step("(2) 未知の grant_type を送る");

                JsonResponse unknown = await client.TokenAsync(new Dictionary<string, string>()
                {
                    { "grant_type", "urn:example:unknown" },
                    { "client_id", reg.ClientId },
                    { "client_secret", reg.ClientSecret }
                });

                r.VerifyEqual("unsupported_grant_type", "unsupported_grant_type", unknown.Error);

                r.Step("(3) 大文字の grant_type（AUTHORIZATION_CODE）を送る");

                JsonResponse upper = await client.TokenAsync(new Dictionary<string, string>()
                {
                    { "grant_type", "AUTHORIZATION_CODE" },
                    { "code", "dummy" },
                    { "client_id", reg.ClientId },
                    { "client_secret", reg.ClientSecret }
                });

                r.VerifyEqual("unsupported_grant_type（大文字小文字まで比べる）", "unsupported_grant_type", upper.Error);

                r.Done();
            }
        }

        #endregion

        #region RT-294.75

        /// <summary>RT-294.75 /device_authz の expires_in / interval は JSON の数値</summary>
        /// <param name="targetKey">core / netfx</param>
        /// <returns>Task</returns>
        [SkippableTheory]
        [MemberData(nameof(AllTargets))]
        public async Task RT29475_device_authzのexpires_inとintervalは数値(string targetKey)
        {
            using (IdPClient client = this.Client(targetKey))
            {
                TestReport r = this.Report("RT-294.75",
                    "/device_authz の expires_in / interval は、JSON の数値で返る",
                    "**以前は文字列（\"1800\"）だった。** RFC 8628 §3.2 は数値を求めている。"
                    + "**型に厳しいクライアントは、文字列を読めない。** `EX-4.1` は型を記録するだけだった。",
                    "RFC 8628 §3.2 / #294");

                ClientRegistration reg = Flows.Registration(client, KnownClients.TestClient3);

                r.Target("client_name=" + KnownClients.TestClient3);

                JsonResponse res = await client.DeviceAuthorizationAsync(new Dictionary<string, string>()
                {
                    { "client_id", reg.ClientId },
                    { "scope", "openid" }
                });

                r.VerifyEqual("HTTP 200", "200", ((int)res.StatusCode).ToString());
                r.VerifyEqual("expires_in は数値", JsonValueKind.Number.ToString(), res.KindOf("expires_in").ToString());
                r.VerifyEqual("interval は数値", JsonValueKind.Number.ToString(), res.KindOf("interval").ToString());

                r.Done();
            }
        }

        #endregion

        #region RT-294.76

        /// <summary>RT-294.76 CIBA の requested_expiry を検証し、上限で頭を打つ</summary>
        /// <param name="targetKey">core / netfx</param>
        /// <returns>Task</returns>
        [SkippableTheory]
        [MemberData(nameof(AllTargets))]
        public async Task RT29476_CIBAのrequested_expiryを検証し上限で頭を打つ(string targetKey)
        {
            using (IdPClient client = await this.SignedInClientAsync(targetKey))
            {
                FcmOutbox.SkipIfUnavailable(client.Target);

                TestReport r = this.Report("RT-294.76",
                    "CIBA : requested_expiry が正の整数でなければ invalid_request、大きすぎれば設定の上限で返す",
                    "**以前は検証も上限も無かった。** 読めない値は `int.TryParse` が 0 にして、"
                    + "**要求は作った瞬間に期限が切れた。** 大きな値なら、**待ちの要求をいくらでも長く残せた。**"
                    + "**応答の expires_in / interval も、JSON の数値で返す**（以前は文字列）。",
                    "CIBA Core §7.1 / §7.3 / #294");

                ClientRegistration reg = Flows.Registration(client, KnownClients.TestClient4);
                int max = int.Parse(client.Config.Get("CibaExpireTimeSpanFromSeconds"));

                r.Target("client_name=" + KnownClients.TestClient4 + " / 上限（CibaExpireTimeSpanFromSeconds）= " + max);

                r.Step("(1) 認証デバイスを登録する（宛先が無いと access_denied になるため）");

                await CibaTests.RegisterDeviceAsync(r, client);

                r.Step("(2) requested_expiry に数値でない値を送る");

                JsonResponse bad = await OAuth2EndpointReviewTests.StartCibaAsync(client, reg, "abc");

                r.VerifyEqual("invalid_request", "invalid_request", bad.Error);

                r.Step("(3) requested_expiry に上限より大きな値を送る");

                JsonResponse big = await OAuth2EndpointReviewTests.StartCibaAsync(client, reg, (max * 100).ToString());

                r.VerifyEqual("HTTP 200", "200", ((int)big.StatusCode).ToString());
                r.VerifyEqual("expires_in は数値", JsonValueKind.Number.ToString(), big.KindOf("expires_in").ToString());
                r.VerifyEqual("interval は数値", JsonValueKind.Number.ToString(), big.KindOf("interval").ToString());

                long expiresIn = (big.KindOf("expires_in") == JsonValueKind.Number)
                    ? big.Json.GetProperty("expires_in").GetInt64() : -1;

                r.VerifyEqual("**expires_in は上限で頭を打つ**", max.ToString(), expiresIn.ToString());

                r.Done();
            }
        }

        /// <summary>requested_expiry を付けて、CIBA の認証リクエストを送る</summary>
        /// <param name="client">IdPClient</param>
        /// <param name="reg">CIBA のクライアント</param>
        /// <param name="requestedExpiry">requested_expiry</param>
        /// <returns>JsonResponse</returns>
        private static async Task<JsonResponse> StartCibaAsync(
            IdPClient client, ClientRegistration reg, string requestedExpiry)
        {
            string requestUri = await RequestObjectBuilder.RegisterAsync(client,
                await RequestObjectBuilder.CreateCibaAsync(client, reg.ClientId, new Dictionary<string, object>()
                {
                    { "login_hint", TestEnv.TestUserName(client.Target.Key) },
                    { "binding_message", "E2E-" + Guid.NewGuid().ToString("N").Substring(0, 8) },
                    { "requested_expiry", requestedExpiry }
                }));

            Assert.False(string.IsNullOrEmpty(requestUri), "前提: /ros が CIBA の要求を受け付けること");

            return await client.CibaAuthorizeWithBasicAuthAsync(new Dictionary<string, string>()
            {
                { "request_uri", requestUri }
            }, reg.ClientId, reg.ClientSecret);
        }

        #endregion

        #region RT-294.77

        /// <summary>RT-294.77 デバイス認可で private_key_jwt が通る</summary>
        /// <param name="targetKey">core / netfx</param>
        /// <returns>Task</returns>
        [SkippableTheory]
        [MemberData(nameof(AllTargets))]
        public async Task RT29477_デバイス認可でprivate_key_jwtが通る(string targetKey)
        {
            using (IdPClient client = this.Client(targetKey))
            {
                TestReport r = this.Report("RT-294.77",
                    "/device_authz を、private_key_jwt（client_assertion）のクライアント認証で通せる",
                    "**以前は RFC 8628 の口（/device_authz と /token）が client_assertion を読んでおらず、**"
                    + "**private_key_jwt で登録したクライアントは、デバイス フローを使えなかった**"
                    + "（動的登録は、その組み合わせを登録の時点で断っていた）。",
                    "RFC 8628 §3.1 / RFC 7523 / #294");

                ClientRegistration reg = Flows.InjectedRegistration(client, KnownClients.TestClient_24);

                r.Target("client_name=" + KnownClients.TestClient_24 + "（private_key_jwt）");

                long now = DateTimeOffset.UtcNow.ToUnixTimeSeconds();

                string assertion = JwsSigner.SignRS256(client, new Dictionary<string, object>()
                {
                    { "iss", reg.ClientId },
                    { "sub", reg.ClientId },
                    { "aud", client.Target.BaseUrl + "/token" },
                    { "jti", Guid.NewGuid().ToString("N") },
                    { "iat", now },
                    { "exp", now + 300 }
                });

                JsonResponse res = await client.DeviceAuthorizationAsync(new Dictionary<string, string>()
                {
                    { "scope", "openid" },
                    { "client_assertion_type", "urn:ietf:params:oauth:client-assertion-type:jwt-bearer" },
                    { "client_assertion", assertion }
                });

                r.VerifyEqual("HTTP 200（以前は 401 / invalid_client）", "200", ((int)res.StatusCode).ToString());

                r.Verify("device_code が返る", !string.IsNullOrEmpty(res.String("device_code")),
                    "あり", string.IsNullOrEmpty(res.String("device_code")) ? "**なし**（" + (res.Error ?? "-") + "）" : "あり");

                r.Done();
            }
        }

        #endregion

        #region RT-294.78

        /// <summary>RT-294.78 /revoke・/introspect は、クライアント認証を token の有無より先に行う</summary>
        /// <param name="targetKey">core / netfx</param>
        /// <returns>Task</returns>
        [SkippableTheory]
        [MemberData(nameof(AllTargets))]
        public async Task RT29478_revokeとintrospectは認証を先に行う(string targetKey)
        {
            using (IdPClient client = this.Client(targetKey))
            {
                TestReport r = this.Report("RT-294.78",
                    "/revoke・/introspect : 資格情報も token も無ければ 401（認証の失敗）、資格情報が正しく token が無ければ 400",
                    "**以前は token の有無を先に見ていた**ので、**認証していない要求にも 400 を返していた**"
                    + "（RFC 6749 §5.2 : クライアント認証の失敗は 401）。",
                    "RFC 7009 §2.1 / RFC 7662 §2.1 / RFC 6749 §5.2 / #294");

                ClientRegistration reg = Flows.Registration(client, KnownClients.MvcSample);

                r.Target("client_name=" + KnownClients.MvcSample);

                Dictionary<string, string> empty = new Dictionary<string, string>() { { "token_type_hint", "access_token" } };

                r.Step("(1) 資格情報も token も付けずに送る");

                JsonResponse revokeNone = await client.RevokeAsync(empty);
                JsonResponse introspectNone = await client.IntrospectAsync(empty);

                r.VerifyEqual("/revoke : 401", "401", ((int)revokeNone.StatusCode).ToString());
                r.VerifyEqual("/introspect : 401", "401", ((int)introspectNone.StatusCode).ToString());

                r.Step("(2) 資格情報だけを付けて送る（token なし）");

                JsonResponse revokeNoToken = await client.RevokeWithBasicAuthAsync(empty, reg.ClientId, reg.ClientSecret);
                JsonResponse introspectNoToken = await client.IntrospectWithBasicAuthAsync(empty, reg.ClientId, reg.ClientSecret);

                r.VerifyEqual("/revoke : 400 / invalid_request", "400 / invalid_request",
                    (int)revokeNoToken.StatusCode + " / " + revokeNoToken.Error);
                r.VerifyEqual("/introspect : 400 / invalid_request", "400 / invalid_request",
                    (int)introspectNoToken.StatusCode + " / " + introspectNoToken.Error);

                r.Done();
            }
        }

        #endregion

        #region RT-294.79

        /// <summary>RT-294.79 /par は、同じ名前のパラメタが 2 回来たら断る</summary>
        /// <param name="targetKey">core / netfx</param>
        /// <returns>Task</returns>
        [SkippableTheory]
        [MemberData(nameof(AllTargets))]
        public async Task RT29479_parは同じ名前のパラメタを断る(string targetKey)
        {
            using (IdPClient client = this.Client(targetKey))
            {
                TestReport r = this.Report("RT-294.79",
                    "/par : 同じ名前のパラメタが 2 回来たら invalid_request で断る（1 回なら受ける）",
                    "**以前はカンマでつないだ 1 つの値として受けていた**"
                    + "（例 : scope を 2 回送ると \"openid,email\"）。"
                    + "**認可要求のパラメタは、1 回までしか含めてはならない。**",
                    "RFC 6749 §3.1 / RFC 9126 §2.1 / #294");

                ClientRegistration reg = Flows.Registration(client, KnownClients.TestClient);

                r.Target("client_name=" + KnownClients.TestClient);

                r.Step("(1) scope を 2 回送る");

                HttpResponseMessage dup = await client.PostFormAsync("/par", new List<KeyValuePair<string, string>>()
                {
                    new KeyValuePair<string, string>("response_type", "code"),
                    new KeyValuePair<string, string>("client_id", reg.ClientId),
                    new KeyValuePair<string, string>("client_secret", reg.ClientSecret),
                    new KeyValuePair<string, string>("redirect_uri", reg.RedirectUri),
                    new KeyValuePair<string, string>("scope", "openid"),
                    new KeyValuePair<string, string>("scope", "email"),
                    new KeyValuePair<string, string>("state", "state-rt29479")
                });

                JsonResponse dupRes = await IdPClient.ToJsonResponseAsync(dup);

                r.VerifyEqual("400 / invalid_request", "400 / invalid_request",
                    (int)dupRes.StatusCode + " / " + dupRes.Error);

                r.Step("(2) 対照 : 1 回なら受ける");

                JsonResponse once = await client.PostJsonWithBasicAuthAsync("/par",
                    new Dictionary<string, string>()
                    {
                        { "response_type", "code" },
                        { "client_id", reg.ClientId },
                        { "redirect_uri", reg.RedirectUri },
                        { "scope", "openid email" },
                        { "state", "state-rt29479" }
                    }, reg.ClientId, reg.ClientSecret);

                r.VerifyEqual("201（request_uri が返る）", "201", ((int)once.StatusCode).ToString());

                r.Done();
            }
        }

        #endregion
    }
}
