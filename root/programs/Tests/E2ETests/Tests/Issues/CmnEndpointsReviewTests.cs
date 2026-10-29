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
//* クラス名        ：CmnEndpointsReviewTests
//* クラス日本語名  ：RT-294.41 〜 .59 CmnEndpoints.*.cs のレビューで見つけた不具合
//*
//* 作成日時        ：－
//* 作成者          ：－
//* 更新履歴        ：－
//*
//*  日時        更新者            内容
//*  ----------  ----------------  -------------------------------------------------
//*  2026/10/29  玄人 幸道         新規（#294）
//*  2026/10/29  玄人 幸道         RT-294.50 〜 .57 を追加し、.41（登録種別）と .49（none）を見直した（#294）
//*  2026/10/29  玄人 幸道         RT-294.58 / .59 を追加し、.51 で invalid_grant を見る（#294）
//**********************************************************************************

using System;
using System.Collections.Generic;
using System.Text;
using System.Text.Json;
using System.Threading.Tasks;

using MultiPurposeAuthSite.Tests.E2E.Infrastructure;
using MultiPurposeAuthSite.Tests.E2E.Tests.Extended;

using Xunit;
using Xunit.Abstractions;

namespace MultiPurposeAuthSite.Tests.E2E.Tests.Issues
{
    /// <summary>
    /// RT-294.41 〜 .59 `CmnEndpoints.*.cs` のレビュー（3 回）で見つけた不具合（#294）。
    /// </summary>
    /// <remarks>
    /// | ケース | 以前の振る舞い |
    /// |---|---|
    /// | RT-294.41 Device グラントの refresh_token | **作って保存するだけで、応答に入れていなかった** |
    /// | RT-294.42 DPoP で縛ったトークンの照会 | **`cnf.jkt` を返していなかった**（mTLS の `x5t#S256` だけ返していた） |
    /// | RT-294.43 CIBA を private_key_jwt で通す | **`/ciba_authz` は受けるのに、`/token` は `client_assertion` を読まなかった** |
    /// | RT-294.44 CIBA の知らない auth_req_id | **仕様に無い `not_found` を error に入れていた** |
    /// | RT-294.45 JWT Bearer の壊れた assertion | **HTTP 500** |
    /// | RT-294.46 scope を省いたトークン要求 | **HTTP 500**（client_credentials / password / JWT Bearer） |
    /// | RT-294.47 CIBA の壊れた request | **HTTP 500**（payload が配列・`iss` が文字列でない） |
    /// | RT-294.48 他のクライアントの refresh_token | **消費してから断っていた**（持ち主が次に使うと、一族ごと失効した） |
    /// | RT-294.49 Discovery の一覧 | **revoke / introspect の認証方法を、秘密の 2 つしか広告していなかった** |
    /// | RT-294.50 client_credentials の sub | **ClientName と同じ名前の利用者が居ると、その利用者の sub になった**（S3） |
    /// | RT-294.51 PKCE と private_key_jwt の併用 | **code_verifier が在ると client_assertion を無視し、fapi2 が通らなかった**（N1） |
    /// | RT-294.52 PKCE だけの引き換え | **認証の方法を明示したクライアントでも、PKCE だけで引き換えられた**（C-40） |
    /// | RT-294.53 scope を省いた認可要求 | **HTTP 500**（N2） |
    /// | RT-294.54 client_assertion の aud | **トークン エンドポイントの URL しか受けなかった**（issuer を断った。配列は 500。N4） |
    /// | RT-294.55 登録の grant_types（Implicit / Hybrid） | **認可エンドポイントで見ず、同意の後で server_error になった** |
    /// | RT-294.56 poll の CIBA | **client_notification_token と binding_message を必須にしていた**（N5） |
    /// | RT-294.57 PAR の Request Object の client_id | **iss だけを照合し、中の client_id は照合していなかった**（C-41） |
    /// | RT-294.58 合わない code_verifier | **invalid_client で返していた**（RFC 7636 §4.6 は invalid_grant。F1） |
    /// | RT-294.59 /ros の Request Object の client_id | **署名（iss）だけを確かめ、中の client_id は照合していなかった**（F5） |
    ///
    /// **`client_registration` 専用トークンの `expires_in`** は、`RT-307.5` に足した。
    ///
    /// **CIBA の利用者の端末を登録するテストがある**ので、**EX-8 と同じコレクションに入れる**
    /// （既定の利用者の端末の登録を奪い合わないため）。
    /// </remarks>
    [Collection(CibaTests.DeviceCollection)]
    public class CmnEndpointsReviewTests : TargetTestBase
    {
        /// <summary>Device Authorization Grant の grant_type</summary>
        private const string DeviceGrantType = "urn:ietf:params:oauth:grant-type:device_code";

        /// <summary>CIBA の grant_type</summary>
        private const string CibaGrantType = "urn:openid:params:grant-type:ciba";

        /// <summary>client_assertion_type（RFC 7523 §2.2）</summary>
        private const string JwtBearerAssertionType = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer";

        /// <summary>コンストラクタ</summary>
        /// <param name="output">ITestOutputHelper</param>
        public CmnEndpointsReviewTests(ITestOutputHelper output) : base(output)
        {
        }

        #region RT-294.41

        /// <summary>RT-294.41 Device グラントで refresh_token が返る</summary>
        /// <param name="targetKey">core / netfx</param>
        /// <returns>Task</returns>
        [SkippableTheory]
        [MemberData(nameof(AllTargets))]
        public async Task RT29441_Deviceグラントでrefresh_tokenが返る(string targetKey)
        {
            using (IdPClient client = await this.SignedInClientAsync(targetKey))
            {
                await Flows.SkipIfGrantTypeNotSupportedAsync(client, DeviceGrantType);
                await Flows.SkipIfGrantTypeNotSupportedAsync(client, "refresh_token");

                TestReport r = this.Report("RT-294.41",
                    "**normal の登録のクライアントは、Device グラントでも refresh_token を受け取り、それで更新できる**",
                    "**以前は refresh_token を作って保存するだけで、応答に入れていなかった**"
                    + "（**使われない行が溜まり、機器は期限が切れるたびに利用者の承認からやり直していた**）。"
                    + "**device の登録には、従来どおり発行しない**（ClientModePolicy の表。EX-4.3）。",
                    "RFC 8628 §3.5 / RFC 6749 §5.1 / #294");

                ClientRegistration reg = Flows.Registration(client, KnownClients.TestClient);

                r.Target("client_name=" + KnownClients.TestClient + "（normal。コンフィデンシャル）");

                r.Step("(1) 機器 : POST /device_authz");

                JsonResponse start = await client.DeviceAuthorizationAsync(new Dictionary<string, string>()
                {
                    { "client_id", reg.ClientId },
                    { "client_secret", reg.ClientSecret },
                    { "scope", "profile email" }
                });

                string deviceCode = start.String("device_code");
                string userCode = start.String("user_code");

                Assert.False(string.IsNullOrEmpty(deviceCode) || string.IsNullOrEmpty(userCode),
                    "前提: device_code と user_code が発行されること（" + start.ToString() + "）");

                r.Step("(2) 利用者 : /device_verify で許可する");

                bool accepted = await client.SubmitDeviceUserCodeAsync(userCode, true);

                Assert.True(accepted, "前提: 検証画面が承認を受け付けること");

                r.Step("(3) 機器 : grant_type=device_code でトークンを取る");

                JsonResponse token = await client.TokenAsync(new Dictionary<string, string>()
                {
                    { "grant_type", DeviceGrantType },
                    { "device_code", deviceCode },
                    { "client_id", reg.ClientId },
                    { "client_secret", reg.ClientSecret }
                });

                r.Verify("access_token が返る", !string.IsNullOrEmpty(token.AccessToken),
                    "あり", string.IsNullOrEmpty(token.AccessToken) ? "**無い**（" + token.ToString() + "）" : "あり");

                r.Verify("refresh_token が返る", !string.IsNullOrEmpty(token.RefreshToken),
                    "あり", string.IsNullOrEmpty(token.RefreshToken) ? "**無い**" : "あり（値は伏せる）");

                if (!string.IsNullOrEmpty(token.AccessToken))
                {
                    //  **登録された種別で書く**（N6。#294）。**以前は device を固定で書いていた。**
                    JsonElement payload = Jwt.Payload(token.AccessToken);

                    r.Verify("normal の登録のトークンは device を名乗らない",
                        !payload.TryGetProperty("device", out JsonElement _),
                        "device クレーム無し",
                        payload.TryGetProperty("device", out JsonElement d) ? "**device=" + d.ToString() + "**" : "無し");
                }

                if (!string.IsNullOrEmpty(token.RefreshToken))
                {
                    r.Step("(4) その refresh_token で更新できる");

                    JsonResponse refreshed = await Flows.RefreshAsync(client, reg, token.RefreshToken);

                    r.Verify("更新で access_token が返る", !string.IsNullOrEmpty(refreshed.AccessToken),
                        "あり", string.IsNullOrEmpty(refreshed.AccessToken)
                            ? "**無い**（" + refreshed.ToString() + "）" : "あり");
                }

                r.Done();
            }
        }

        #endregion

        #region RT-294.42

        /// <summary>RT-294.42 DPoP で縛ったトークンを照会すると cnf.jkt が返る</summary>
        /// <param name="targetKey">core / netfx</param>
        /// <returns>Task</returns>
        [SkippableTheory]
        [MemberData(nameof(AllTargets))]
        public async Task RT29442_DPoPで縛ったトークンの照会でcnfのjktが返る(string targetKey)
        {
            using (IdPClient client = await this.SignedInClientAsync(targetKey))
            {
                TestReport r = this.Report("RT-294.42",
                    "**DPoP で縛ったトークンを /introspect で照会すると、`cnf` の中に `jkt` が返る**",
                    "**リソース サーバは照会の `cnf.jkt` を見て、証明の鍵と突き合わせる**（RFC 9449 §6.2）。"
                    + "**以前は `jkt` を返していなかった**ので、"
                    + "**照会で確かめるリソース サーバは、縛りに気付けなかった**（mTLS の `x5t#S256` だけ入っていた）。",
                    "RFC 7662 §2.2 / RFC 7800 §3.1 / RFC 9449 §6.2 / #294");

                ClientRegistration reg = Flows.Registration(client, KnownClients.TestClient);
                string tokenEndpoint = await CmnEndpointsReviewTests.TokenEndpointAsync(client);
                string expectedJkt = JwsSigner.DPoPJkt(client);

                r.Target("POST /introspect（DPoP で縛った access_token）");

                r.Step("(1) 証明を添えて、認可コードを交換する");

                AuthZResponse authz = await Flows.AuthorizeCodeAsync(
                    client, reg, "openid email", "state1", "nonce-rt29442", reg.RedirectUri);

                Assert.False(string.IsNullOrEmpty(authz.Code),
                    "前提: 認可コードが取得できること（" + authz.ToString() + "）");

                JsonResponse token = await client.PostJsonAsync(
                    client.ToLocalUrl(tokenEndpoint),
                    new Dictionary<string, string>()
                    {
                        { "grant_type", "authorization_code" },
                        { "code", authz.Code },
                        { "client_id", reg.ClientId },
                        { "client_secret", reg.ClientSecret },
                        { "redirect_uri", reg.RedirectUri }
                    },
                    new Dictionary<string, string>()
                    {
                        { "DPoP", CmnEndpointsReviewTests.DPoPProof(client, tokenEndpoint) }
                    });

                Assert.Equal("DPoP", token.String("token_type"));
                Assert.False(string.IsNullOrEmpty(token.AccessToken), "前提: access_token が返ること");

                r.Step("(2) 発行先の資格情報で照会する");

                JsonResponse res = await Flows.IntrospectAsync(client, reg, token.AccessToken, "access_token");

                r.VerifyEqual("active が true", "true", (res.String("active") ?? "なし").ToLower());

                string jkt = null;

                if (res.Json.ValueKind == JsonValueKind.Object
                    && res.Json.TryGetProperty("cnf", out JsonElement cnf)
                    && cnf.ValueKind == JsonValueKind.Object
                    && cnf.TryGetProperty("jkt", out JsonElement jktElement))
                {
                    jkt = jktElement.GetString();
                }

                r.VerifyEqual("cnf.jkt が、証明の鍵の指紋と一致する", expectedJkt, jkt ?? "（無い）");

                r.Done();
            }
        }

        #endregion

        #region RT-294.43

        /// <summary>RT-294.43 CIBA を private_key_jwt で最後まで通せる</summary>
        /// <param name="targetKey">core / netfx</param>
        /// <returns>Task</returns>
        [SkippableTheory]
        [MemberData(nameof(AllTargets))]
        public async Task RT29443_CIBAをprivate_key_jwtで最後まで通せる(string targetKey)
        {
            using (IdPClient client = await this.SignedInClientAsync(targetKey))
            {
                FcmOutbox.SkipIfUnavailable(client.Target);

                TestReport r = this.Report("RT-294.43",
                    "**CIBA を、`/ciba_authz` から `/token` まで `client_assertion`（private_key_jwt）で通せる**",
                    "**FAPI-CIBA は、クライアント認証に private_key_jwt か mTLS を求める。**"
                    + "**以前は `/ciba_authz` は `client_assertion` を受けるのに、`/token` は読まなかった**ので、"
                    + "**利用者が承認した後で `invalid_client` になっていた。**",
                    "CIBA Core §7.1 / §10.1 / RFC 7523 §2.2 / #294");

                ClientRegistration reg = Flows.InjectedRegistration(client, KnownClients.TestClient4_4);
                string bindingMessage = "E2E-" + Guid.NewGuid().ToString("N").Substring(0, 8);

                r.Target("client_name=" + KnownClients.TestClient4_4
                    + "（fapi_ciba。token_endpoint_auth_method=private_key_jwt）");

                r.Step("(1) 利用者 : 認証デバイスを登録する");

                (string AccessToken, string DeviceToken) device = await CibaTests.RegisterDeviceAsync(r, client);

                r.Step("(2) クライアント : client_assertion で POST /ciba_authz");

                string request = await RequestObjectBuilder.CreateCibaAsync(client, reg.ClientId,
                    new Dictionary<string, object>()
                    {
                        { "login_hint", TestEnv.TestUserName(targetKey) },
                        { "binding_message", bindingMessage }
                    });

                JsonResponse start = await client.CibaAuthorizeAsync(new Dictionary<string, string>()
                {
                    { "request", request },
                    { "client_assertion_type", JwtBearerAssertionType },
                    { "client_assertion", CmnEndpointsReviewTests.ClientAssertionES256(client, reg.ClientId) }
                });

                string authReqId = start.String("auth_req_id");

                Assert.False(string.IsNullOrEmpty(authReqId),
                    "前提: auth_req_id が返ること（" + start.ToString() + "）");

                r.Step("(3) 利用者 : 認証デバイスで許可する");

                await CibaTests.ReceivePushAsync(r, client, authReqId, device.DeviceToken);

                JsonResponse answer = await client.CibaPushResultAsync(device.AccessToken, authReqId, "true");

                Assert.Equal(200, (int)answer.StatusCode);

                r.Step("(4) クライアント : client_assertion で POST /token");

                JsonResponse granted = await client.TokenAsync(new Dictionary<string, string>()
                {
                    { "grant_type", CibaGrantType },
                    { "auth_req_id", authReqId },
                    { "client_assertion_type", JwtBearerAssertionType },
                    { "client_assertion", CmnEndpointsReviewTests.ClientAssertionES256(client, reg.ClientId) }
                });

                r.Verify("access_token が返る", !string.IsNullOrEmpty(granted.AccessToken),
                    "あり", string.IsNullOrEmpty(granted.AccessToken)
                        ? "**無い**（" + granted.ToString() + "）" : "あり（値は伏せる）");

                r.Done();
            }
        }

        #endregion

        #region RT-294.44

        /// <summary>RT-294.44 CIBA の知らない auth_req_id は invalid_grant</summary>
        /// <param name="targetKey">core / netfx</param>
        /// <returns>Task</returns>
        [SkippableTheory]
        [MemberData(nameof(AllTargets))]
        public async Task RT29444_CIBAの知らないauth_req_idはinvalid_grant(string targetKey)
        {
            using (IdPClient client = this.Client(targetKey))
            {
                await Flows.SkipIfGrantTypeNotSupportedAsync(client, CibaGrantType);

                TestReport r = this.Report("RT-294.44",
                    "**発行していない auth_req_id でポーリングすると、`invalid_grant` が返る**",
                    "**以前は内部の状態名（`not_found`）を、そのまま error に入れていた**"
                    + "（仕様に無い値で、RP は意味を読めない）。"
                    + "**Device グラントは #199 で直してあった**ので、それに揃えた。",
                    "CIBA Core §11 / RFC 6749 §5.2 / #294");

                ClientRegistration reg = Flows.Registration(client, KnownClients.TestClient4);

                r.Target("POST /token（grant_type=ciba、発行していない auth_req_id）");

                JsonResponse res = await client.TokenAsync(new Dictionary<string, string>()
                {
                    { "grant_type", CibaGrantType },
                    { "auth_req_id", "e2e-" + Guid.NewGuid().ToString("N") },
                    { "client_id", reg.ClientId },
                    { "client_secret", reg.ClientSecret }
                });

                r.VerifyEqual("HTTP 400", "400", ((int)res.StatusCode).ToString());
                r.VerifyEqual("error が invalid_grant", "invalid_grant", res.Error ?? "（無い）");

                r.Done();
            }
        }

        #endregion

        #region RT-294.45

        /// <summary>RT-294.45 JWT Bearer の壊れた assertion で 500 にしない</summary>
        /// <param name="targetKey">core / netfx</param>
        /// <returns>Task</returns>
        [SkippableTheory]
        [MemberData(nameof(AllTargets))]
        public async Task RT29445_JWTBearerの壊れたassertionで500にしない(string targetKey)
        {
            using (IdPClient client = this.Client(targetKey))
            {
                await Flows.SkipIfGrantTypeNotSupportedAsync(client, JwtBearerAssertion.GrantType);

                TestReport r = this.Report("RT-294.45",
                    "**JWT Bearer グラントに壊れた assertion を渡しても、HTTP 500 にしない**",
                    "**以前は `Split('.')[1]`・`dic[iss]`・登録の無い鍵の復号を、確かめずに行っていた**ので、"
                    + "**外から来た値で 500 に落とせた**（他の口は #241 で直してあった）。",
                    "RFC 7523 §3.1 / RFC 6749 §5.2 / #241 / #294");

                r.Target("POST /token（grant_type=jwt-bearer）");

                r.Step("(1) JWT でない値");

                JsonResponse notJwt = await CmnEndpointsReviewTests.JwtBearerAsync(client, "not-a-jwt", "profile");

                CmnEndpointsReviewTests.VerifyClientError(r, notJwt);

                r.Step("(2) iss が文字列でない JWT");

                string objectIss = JwsSigner.SignRS256(client, new Dictionary<string, object>()
                {
                    { "iss", new Dictionary<string, object>() { { "a", "b" } } },
                    { "sub", "e2e" },
                    { "aud", client.Target.Url("/token") },
                    { "exp", DateTimeOffset.UtcNow.ToUnixTimeSeconds() + 300 }
                });

                JsonResponse notString = await CmnEndpointsReviewTests.JwtBearerAsync(client, objectIss, "profile");

                CmnEndpointsReviewTests.VerifyClientError(r, notString);

                r.Step("(3) 登録されていない iss");

                string unknownIss = JwtBearerAssertion.Create(client, "e2e-unknown-" + Guid.NewGuid().ToString("N"));

                JsonResponse unknown = await CmnEndpointsReviewTests.JwtBearerAsync(client, unknownIss, "profile");

                CmnEndpointsReviewTests.VerifyClientError(r, unknown);

                r.Done();
            }
        }

        #endregion

        #region RT-294.46

        /// <summary>RT-294.46 scope を省いてもトークンが取れる</summary>
        /// <param name="targetKey">core / netfx</param>
        /// <returns>Task</returns>
        [SkippableTheory]
        [MemberData(nameof(AllTargets))]
        public async Task RT29446_scopeを省いてもトークンが取れる(string targetKey)
        {
            using (IdPClient client = this.Client(targetKey))
            {
                TestReport r = this.Report("RT-294.46",
                    "**scope を省いたトークン要求でも、HTTP 500 にしない**（client_credentials / password / JWT Bearer）",
                    "**scope は OPTIONAL である**（RFC 6749 §4.3.2 / §4.4.2）。"
                    + "**以前は null の `Split` で 500 になっていた**（client_credentials は、上の方では null を守っていた）。",
                    "RFC 6749 §3.3 / §4.3.2 / §4.4.2 / RFC 7523 §2.1 / #294");

                ClientRegistration reg = Flows.Registration(client, KnownClients.MvcSample);

                r.Target("POST /token（scope を送らない）");

                if (await CmnEndpointsReviewTests.SupportsGrantTypeAsync(client, "client_credentials"))
                {
                    r.Step("client_credentials");

                    JsonResponse cc = await client.TokenAsync(new Dictionary<string, string>()
                    {
                        { "grant_type", "client_credentials" },
                        { "client_id", reg.ClientId },
                        { "client_secret", reg.ClientSecret }
                    });

                    CmnEndpointsReviewTests.VerifyIssued(r, cc);
                }

                if (await CmnEndpointsReviewTests.SupportsGrantTypeAsync(client, "password"))
                {
                    r.Step("password");

                    // テスト ユーザは、サインイン画面への初回アクセスで作られる。
                    await client.GetAsync("/Account/Login");

                    JsonResponse ropc = await client.TokenAsync(new Dictionary<string, string>()
                    {
                        { "grant_type", "password" },
                        { "username", TestEnv.TestUserName(targetKey) },
                        { "password", client.Config.Get("TestUserPWD") },
                        { "client_id", reg.ClientId },
                        { "client_secret", reg.ClientSecret }
                    });

                    CmnEndpointsReviewTests.VerifyIssued(r, ropc);
                }

                if (await CmnEndpointsReviewTests.SupportsGrantTypeAsync(client, JwtBearerAssertion.GrantType))
                {
                    r.Step("JWT Bearer（assertion にも scope を入れない）");

                    ClientRegistration test = Flows.Registration(client, KnownClients.TestClient);

                    string assertion = JwtBearerAssertion.Create(client, test.ClientId,
                        new Dictionary<string, object>() { { "scope", null } });

                    JsonResponse bearer = await CmnEndpointsReviewTests.JwtBearerAsync(client, assertion, null);

                    CmnEndpointsReviewTests.VerifyIssued(r, bearer);
                }

                r.Done();
            }
        }

        #endregion

        #region RT-294.47

        /// <summary>RT-294.47 CIBA の壊れた request で 500 にしない</summary>
        /// <param name="targetKey">core / netfx</param>
        /// <returns>Task</returns>
        [SkippableTheory]
        [MemberData(nameof(AllTargets))]
        public async Task RT29447_CIBAの壊れたrequestで500にしない(string targetKey)
        {
            using (IdPClient client = this.Client(targetKey))
            {
                await Flows.SkipIfGrantTypeNotSupportedAsync(client, CibaGrantType);

                TestReport r = this.Report("RT-294.47",
                    "**CIBA の request が、payload がオブジェクトでない・iss が文字列でない JWT でも、HTTP 400 で返す**",
                    "**以前は Base64URL の復号だけを守っていて、その後の JSON の読み取りで 500 になっていた。**",
                    "CIBA Core §13 / RFC 6749 §5.2 / #241 / #294");

                ClientRegistration reg = Flows.Registration(client, KnownClients.TestClient4);

                r.Target("POST /ciba_authz（client_secret_basic で認証し、壊れた request を送る）");

                r.Step("(1) payload が配列の JWT");

                JsonResponse array = await client.CibaAuthorizeWithBasicAuthAsync(
                    new Dictionary<string, string>()
                    {
                        { "request", CmnEndpointsReviewTests.UnsignedJwt("[1]") }
                    }, reg.ClientId, reg.ClientSecret);

                r.VerifyEqual("HTTP 400", "400", ((int)array.StatusCode).ToString());

                r.Step("(2) iss がオブジェクトの JWT");

                JsonResponse objectIss = await client.CibaAuthorizeWithBasicAuthAsync(
                    new Dictionary<string, string>()
                    {
                        { "request", CmnEndpointsReviewTests.UnsignedJwt("{\"iss\":{\"a\":1}}") }
                    }, reg.ClientId, reg.ClientSecret);

                r.VerifyEqual("HTTP 400", "400", ((int)objectIss.StatusCode).ToString());

                r.Done();
            }
        }

        #endregion

        #region RT-294.48

        /// <summary>RT-294.48 他のクライアントの refresh_token は、消費せずに断る</summary>
        /// <param name="targetKey">core / netfx</param>
        /// <returns>Task</returns>
        [SkippableTheory]
        [MemberData(nameof(AllTargets))]
        public async Task RT29448_他のクライアントのrefresh_tokenは消費せずに断る(string targetKey)
        {
            using (IdPClient client = await this.SignedInClientAsync(targetKey))
            {
                await Flows.SkipIfGrantTypeNotSupportedAsync(client, "refresh_token");

                TestReport r = this.Report("RT-294.48",
                    "**他のクライアントが出した refresh_token は、消費せずに断る**（持ち主はその後も使える）",
                    "**以前は消費（ローテーション）してから、発行先が違うと断っていた。**"
                    + "**持ち主が次に使うと「使用済みの再提示」と見なされ、一族ごと失効した**（#188 の段階 3）。",
                    "RFC 6749 §6 / RFC 9700 §4.14 / #294");

                ClientRegistration owner = Flows.Registration(client, KnownClients.MvcSample);
                ClientRegistration other = Flows.Registration(client, KnownClients.TestClient);

                r.Target("POST /token（grant_type=refresh_token）");

                r.Step("(1) 持ち主（" + KnownClients.MvcSample + "）が refresh_token を得る");

                JsonResponse token = await Flows.RunAuthorizationCodeFlowAsync(client);

                Skip.If(string.IsNullOrEmpty(token.RefreshToken), "この配備は refresh_token を返しません。");

                r.Step("(2) 他のクライアント（" + KnownClients.TestClient + "）が出す");

                JsonResponse stolen = await Flows.RefreshAsync(client, other, token.RefreshToken);

                r.VerifyEqual("error が invalid_grant", "invalid_grant", stolen.Error ?? "（無い）");

                r.Step("(3) 持ち主は、その後も更新できる");

                JsonResponse refreshed = await Flows.RefreshAsync(client, owner, token.RefreshToken);

                r.Verify("access_token が返る", !string.IsNullOrEmpty(refreshed.AccessToken),
                    "あり", string.IsNullOrEmpty(refreshed.AccessToken)
                        ? "**無い**（" + refreshed.ToString() + "）" : "あり");

                r.Done();
            }
        }

        #endregion

        #region RT-294.49

        /// <summary>RT-294.49 Discovery が受け付ける認証方法・alg を広告する</summary>
        /// <param name="targetKey">core / netfx</param>
        /// <returns>Task</returns>
        [SkippableTheory]
        [MemberData(nameof(AllTargets))]
        public async Task RT29449_Discoveryが受け付ける認証方法を広告する(string targetKey)
        {
            using (IdPClient client = this.Client(targetKey))
            {
                TestReport r = this.Report("RT-294.49",
                    "**revoke / introspect の認証方法は、トークン エンドポイントと同じ一覧を広告する**",
                    "**#239 から、revoke / introspect も private_key_jwt と mTLS で通る**のに、"
                    + "**広告は秘密の 2 つのままだった**（広告を見て方法を選ぶ RP は、使えないと判断する）。"
                    + "**一覧は 1 か所（`TokenEndpointAuthMethods`）から作る。**",
                    "RFC 8414 §2 / RFC 7009 §2.1 / RFC 7662 §2.1 / #294");

                r.Target("GET /.well-known/openid-configuration");

                JsonResponse res = await client.GetJsonAsync("/.well-known/openid-configuration");

                string[] token = res.Strings("token_endpoint_auth_methods_supported") ?? new string[0];

                r.Verify("token_endpoint_auth_methods_supported に none（パブリック）が在る",
                    Array.IndexOf(token, "none") >= 0, "在る", string.Join(" ", token));

                //  **revoke / introspect は認証を要する**ので、**none を除いた一覧**である（#294）。
                string expected = string.Join(" ", Array.FindAll(token, x => x != "none"));

                foreach (string name in new string[] {
                    "revocation_endpoint_auth_methods_supported",
                    "introspection_endpoint_auth_methods_supported" })
                {
                    string[] methods = res.Strings(name) ?? new string[0];

                    r.VerifyEqual(name + " が token_endpoint_auth_methods_supported から none を除いたもの",
                        expected, string.Join(" ", methods));
                }

                r.Verify("request_object_signing_alg_values_supported に RS256 が在る",
                    res.ArrayContains("request_object_signing_alg_values_supported", "RS256"),
                    "在る", string.Join(" ", res.Strings("request_object_signing_alg_values_supported") ?? new string[0]));

                r.Done();
            }
        }

        #endregion

        #region RT-294.50

        /// <summary>RT-294.50 client_credentials の sub は、同じ名前の利用者に結び付かない</summary>
        /// <param name="targetKey">core / netfx</param>
        /// <returns>Task</returns>
        [SkippableTheory]
        [MemberData(nameof(AllTargets))]
        public async Task RT29450_client_credentialsのsubは同じ名前の利用者に結び付かない(string targetKey)
        {
            using (IdPClient admin = await this.AdminClientAsync(targetKey))
            {
                await Flows.SkipIfGrantTypeNotSupportedAsync(admin, "client_credentials");
                await UsersAdmin.SkipIfLockedDownAsync(admin);

                TestReport r = this.Report("RT-294.50",
                    "**client_credentials のトークンは、クライアントと同じ名前の利用者が居ても、その利用者に結び付かない**",
                    "**以前は ClientName と同じ名前の利用者を引き、居ればその利用者の sub にしていた。**"
                    + "**ClientName はラベル**（登録の時点の所有者の利用者名）なので、"
                    + "**名前を付け替えた後に同じ名前を取った別の利用者に、トークンが結び付いた**（S3）。"
                    + "**client_credentials は資源所有者の居ないトークン**である。",
                    "RFC 6749 §4.4 / #294");

                ClientRegistration reg = Flows.InjectedRegistration(admin, KnownClients.TestClient_33);
                string email = "rt29450-" + Guid.NewGuid().ToString("N").Substring(0, 8) + "@example.invalid";

                r.Target("client_name=" + KnownClients.TestClient_33 + "（同じ名前の利用者を、管理画面で作る）");

                try
                {
                    r.Step("(1) 管理者 : クライアントと同じ名前の利用者を作る");

                    await UsersAdmin.CreateAsync(admin, KnownClients.TestClient_33, email, null);

                    string body = await UsersAdmin.SkipIfLockedDownAsync(admin);

                    Assert.False(string.IsNullOrEmpty(UsersAdmin.FindId(body, KnownClients.TestClient_33)),
                        "前提: 同じ名前の利用者が作られること");

                    r.Step("(2) クライアント : client_credentials でトークンを取る");

                    JsonResponse token = await admin.TokenAsync(new Dictionary<string, string>()
                    {
                        { "grant_type", "client_credentials" },
                        { "scope", "email" },
                        { "client_id", reg.ClientId },
                        { "client_secret", reg.ClientSecret }
                    });

                    Assert.False(string.IsNullOrEmpty(token.AccessToken),
                        "前提: トークンが取れること（" + token.ToString() + "）");

                    r.VerifyEqual("sub はクライアント名", KnownClients.TestClient_33,
                        Jwt.String(Jwt.Payload(token.AccessToken), "sub") ?? "（無い）");

                    r.Step("(3) /userinfo は、その利用者のメアドを返さない");

                    JsonResponse userinfo = await admin.UserInfoAsync(token.AccessToken);

                    r.Verify("利用者のメアドを返さない", userinfo.String("email") != email,
                        "返さない", userinfo.String("email") == email ? "**返した**" : "返さない");
                }
                finally
                {
                    await UsersAdmin.DeleteByUserNameAsync(admin, KnownClients.TestClient_33);
                }

                r.Done();
            }
        }

        #endregion

        #region RT-294.51

        /// <summary>RT-294.51 PKCE と private_key_jwt を併用して、fapi2 の認可コードを引き換えられる</summary>
        /// <param name="targetKey">core / netfx</param>
        /// <returns>Task</returns>
        [SkippableTheory]
        [MemberData(nameof(AllTargets))]
        public async Task RT29451_PKCEとprivate_key_jwtを併用できる(string targetKey)
        {
            using (IdPClient client = await this.SignedInClientAsync(targetKey))
            {
                TestReport r = this.Report("RT-294.51",
                    "**fapi2 のクライアントが、PKCE と client_assertion（private_key_jwt）を併用して、認可コードを引き換えられる**",
                    "**FAPI 2.0 は、PKCE と、private_key_jwt か mTLS の両方を求める。**"
                    + "**以前は code_verifier が在ると、client_assertion を見ずに PKCE だけで認証した**ので、"
                    + "**証明が PKCE になり、fapi2 の登録は通らなかった**（N1）。",
                    "FAPI 2.0 Security Profile §5.3.2.1 / RFC 7636 / RFC 7523 §2.2 / #294");

                ClientRegistration reg = Flows.InjectedRegistration(client, KnownClients.TestClient_32);

                r.Target("client_name=" + KnownClients.TestClient_32 + "（fapi2。token_endpoint_auth_method=private_key_jwt）");

                r.Step("(1) PKCE（S256）で認可コードを取る");

                AuthZResponse authz = await Flows.AuthorizeCodeAsync(
                    client, reg, redirectUri: reg.RedirectUri, extra: CmnEndpointsReviewTests.Pkce());

                Assert.False(string.IsNullOrEmpty(authz.Code),
                    "前提: 認可コードが取得できること（" + authz.ToString() + "）");

                r.Step("(2) code_verifier と client_assertion を送って交換する");

                JsonResponse token = await client.TokenAsync(new Dictionary<string, string>()
                {
                    { "grant_type", "authorization_code" },
                    { "code", authz.Code },
                    { "code_verifier", CmnEndpointsReviewTests.Verifier },
                    { "redirect_uri", reg.RedirectUri },
                    { "client_assertion_type", JwtBearerAssertionType },
                    { "client_assertion", CmnEndpointsReviewTests.ClientAssertionRS256(client, reg.ClientId, null) }
                });

                r.Verify("access_token が返る", !string.IsNullOrEmpty(token.AccessToken),
                    "あり", string.IsNullOrEmpty(token.AccessToken) ? "**無い**（" + token.ToString() + "）" : "あり");

                r.Step("(3) 違う code_verifier では、client_assertion が正しくても通らない");

                AuthZResponse authz2 = await Flows.AuthorizeCodeAsync(
                    client, reg, redirectUri: reg.RedirectUri, extra: CmnEndpointsReviewTests.Pkce());

                Assert.False(string.IsNullOrEmpty(authz2.Code), "前提: 認可コードが取得できること");

                JsonResponse wrong = await client.TokenAsync(new Dictionary<string, string>()
                {
                    { "grant_type", "authorization_code" },
                    { "code", authz2.Code },
                    { "code_verifier", CmnEndpointsReviewTests.Verifier + "x" },
                    { "redirect_uri", reg.RedirectUri },
                    { "client_assertion_type", JwtBearerAssertionType },
                    { "client_assertion", CmnEndpointsReviewTests.ClientAssertionRS256(client, reg.ClientId, null) }
                });

                r.Verify("access_token を返さない", string.IsNullOrEmpty(wrong.AccessToken),
                    "返さない", string.IsNullOrEmpty(wrong.AccessToken) ? "返さない（error=" + (wrong.Error ?? "なし") + "）" : "**返した**");

                r.VerifyEqual("error は invalid_grant（RFC 7636 §4.6。F1）", "invalid_grant", wrong.Error ?? "（無い）");

                r.Done();
            }
        }

        #endregion

        #region RT-294.52

        /// <summary>RT-294.52 PKCE だけの引き換えは、登録で認証の方法を明示していないクライアントだけ</summary>
        /// <param name="targetKey">core / netfx</param>
        /// <returns>Task</returns>
        [SkippableTheory]
        [MemberData(nameof(AllTargets))]
        public async Task RT29452_PKCEだけの引き換えは明示していないクライアントだけ(string targetKey)
        {
            using (IdPClient client = await this.SignedInClientAsync(targetKey))
            {
                TestReport r = this.Report("RT-294.52",
                    "**認証の方法を明示したクライアントは、PKCE だけでは認可コードを引き換えられない**"
                    + "（`none` を明示したクライアントは引き換えられ、秘密では認証できない）",
                    "**RFC 6749 §4.1.3 は、コンフィデンシャル クライアントの認証を MUST としている。**"
                    + "**以前は code_verifier が在り client_secret が無ければ、登録に関わらず PKCE だけで通した**（C-40）。"
                    + "**登録が空のクライアントは、従来どおり PKCE だけで通す**（既定の挙動を変えない）。",
                    "RFC 6749 §4.1.3 / RFC 7591 §2（token_endpoint_auth_method）/ #294");

                ClientRegistration secretBasic = Flows.InjectedRegistration(client, KnownClients.TestClient_30);
                ClientRegistration none = Flows.InjectedRegistration(client, KnownClients.TestClient_31);

                r.Target(KnownClients.TestClient_30 + "（client_secret_basic を明示）／"
                    + KnownClients.TestClient_31 + "（none を明示）");

                r.Step("(1) client_secret_basic を明示したクライアント : PKCE だけでは通らない");

                JsonResponse pkceOnly = await CmnEndpointsReviewTests.ExchangeWithPkceAsync(client, secretBasic, false);

                r.VerifyEqual("invalid_client", "invalid_client", pkceOnly.Error ?? "（無い）");

                r.Step("(2) 同じクライアント : client_secret ＋ PKCE なら通る");

                JsonResponse withSecret = await CmnEndpointsReviewTests.ExchangeWithPkceAsync(client, secretBasic, true);

                r.Verify("access_token が返る", !string.IsNullOrEmpty(withSecret.AccessToken),
                    "あり", string.IsNullOrEmpty(withSecret.AccessToken) ? "**無い**（" + withSecret.ToString() + "）" : "あり");

                r.Step("(3) none を明示したクライアント : PKCE だけで通る");

                JsonResponse publicPkce = await CmnEndpointsReviewTests.ExchangeWithPkceAsync(client, none, false);

                r.Verify("access_token が返る", !string.IsNullOrEmpty(publicPkce.AccessToken),
                    "あり", string.IsNullOrEmpty(publicPkce.AccessToken) ? "**無い**（" + publicPkce.ToString() + "）" : "あり");

                r.Step("(4) none を明示したクライアント : 秘密では認証できない");

                JsonResponse publicSecret = await CmnEndpointsReviewTests.ExchangeWithPkceAsync(client, none, true);

                r.VerifyEqual("invalid_client", "invalid_client", publicSecret.Error ?? "（無い）");

                r.Done();
            }
        }

        #endregion

        #region RT-294.53

        /// <summary>RT-294.53 scope を省いた認可要求で 500 にしない</summary>
        /// <param name="targetKey">core / netfx</param>
        /// <returns>Task</returns>
        [SkippableTheory]
        [MemberData(nameof(AllTargets))]
        public async Task RT29453_scopeを省いた認可要求で500にしない(string targetKey)
        {
            using (IdPClient client = await this.SignedInClientAsync(targetKey))
            {
                TestReport r = this.Report("RT-294.53",
                    "**scope を省いた認可要求（OAuth 2.0 の code）でも、HTTP 500 にしない**",
                    "**scope は省略できる**（RFC 6749 §3.3）。**以前は null の `Split` で 500 になっていた**（N2）。",
                    "RFC 6749 §3.3 / §4.1.1 / #294");

                ClientRegistration reg = Flows.Registration(client, KnownClients.TestClient);

                r.Target("GET /authorize（response_type=code。scope を送らない）");

                AuthZResponse authz = await Flows.AuthorizeCodeAsync(
                    client, reg, scope: null, nonce: null, redirectUri: reg.RedirectUri);

                r.Verify("HTTP 500 にならない", (int)authz.StatusCode != 500,
                    "500 以外", ((int)authz.StatusCode).ToString());

                r.Verify("code が返る", !string.IsNullOrEmpty(authz.Code),
                    "あり", string.IsNullOrEmpty(authz.Code) ? "**無い**（" + authz.ToString() + "）" : "あり");

                r.Done();
            }
        }

        #endregion

        #region RT-294.54

        /// <summary>RT-294.54 client_assertion の aud に issuer を受ける</summary>
        /// <param name="targetKey">core / netfx</param>
        /// <returns>Task</returns>
        [SkippableTheory]
        [MemberData(nameof(AllTargets))]
        public async Task RT29454_client_assertionのaudにissuerを受ける(string targetKey)
        {
            using (IdPClient client = this.Client(targetKey))
            {
                TestReport r = this.Report("RT-294.54",
                    "**client_assertion の aud は、トークン エンドポイントの URL のほか、issuer でもよい**"
                    + "（配列は、500 にせず invalid_client で断る）",
                    "**FAPI 2.0 は、issuer を aud として受けることを求める**（RFC 7523 §3 も issuer を認める）。"
                    + "**以前はトークン エンドポイントの URL との完全一致だけ**だったので、"
                    + "**issuer を入れる FAPI 2.0 のクライアントは invalid_client になった**（N4）。"
                    + "**配列の aud は、上流（`JwtAssertion.Verify`）が文字列として読むので受けられない**"
                    + "（**以前は HTTP 500** だった）。",
                    "RFC 7523 §3 / FAPI 2.0 Security Profile §5.3.2.1 / RFC 7519 §4.1.3 / #294");

                ClientRegistration reg = Flows.InjectedRegistration(client, KnownClients.TestClient_24);
                string issuer = await client.IssuerAsync();

                r.Target("POST /revoke（client_name=" + KnownClients.TestClient_24 + "。private_key_jwt で認証する）");

                foreach (KeyValuePair<string, object> aud in new Dictionary<string, object>()
                {
                    { "issuer", issuer },
                    { "トークン エンドポイント", client.Target.BaseUrl + "/token" }
                })
                {
                    r.Step("aud = " + aud.Key);

                    JsonResponse res = await CmnEndpointsReviewTests.RevokeWithAssertionAsync(client, reg, aud.Value);

                    r.VerifyEqual("認証が通る（HTTP 200）", "200", ((int)res.StatusCode).ToString());
                }

                foreach (KeyValuePair<string, object> aud in new Dictionary<string, object>()
                {
                    { "他の値", "https://other.example" },
                    { "[issuer]（配列）", new string[] { issuer } }
                })
                {
                    r.Step("aud = " + aud.Key);

                    JsonResponse res = await CmnEndpointsReviewTests.RevokeWithAssertionAsync(client, reg, aud.Value);

                    r.VerifyEqual("invalid_client（500 にしない）", "invalid_client", res.Error ?? "（無い）");
                }

                r.Done();
            }
        }

        #endregion

        #region RT-294.55

        /// <summary>RT-294.55 登録の grant_types に implicit が無ければ、Hybrid は同意の前に断る</summary>
        /// <param name="targetKey">core / netfx</param>
        /// <returns>Task</returns>
        [SkippableTheory]
        [MemberData(nameof(AllTargets))]
        public async Task RT29455_grant_typesにimplicitが無ければHybridは同意の前に断る(string targetKey)
        {
            using (IdPClient client = await this.SignedInClientAsync(targetKey))
            {
                TestReport r = this.Report("RT-294.55",
                    "**登録の grant_types に implicit が無いクライアントの Hybrid（code id_token）の要求は、"
                    + "同意の前に unauthorized_client で断る**",
                    "**認可エンドポイントで発行する経路は、発行の時点（`CheckClientMode`）で grant_types を見ていた**が、"
                    + "**要求の検査では見ていなかった**ので、**利用者に同意させた後で server_error になっていた。**"
                    + "**動的登録は組み合わせを揃えるが、構成ファイル・画面の登録は揃っているとは限らない。**"
                    + "**code は従来どおり /token で見る**（#307 の段階 1。`RT-307.7`）。",
                    "RFC 7591 §2（grant_types）/ RFC 6749 §4.1.2.1 / #294");

                ClientRegistration reg = Flows.InjectedRegistration(client, KnownClients.TestClient_34);

                r.Target("client_name=" + KnownClients.TestClient_34 + "（grant_types=client_credentials）/ response_type=code id_token");

                AuthZResponse authz = await client.AuthorizeAsync(new Dictionary<string, string>()
                {
                    { "response_type", "code id_token" },
                    { "client_id", reg.ClientId },
                    { "scope", "openid" },
                    { "state", "state-rt29455" },
                    { "nonce", "nonce-rt29455" },
                    { "redirect_uri", reg.RedirectUriToken }
                });

                r.Verify("同意画面を出さない", !authz.NeedsConsent,
                    "出さない", authz.NeedsConsent ? "**出した**" : "出さない");

                r.VerifyEqual("unauthorized_client", "unauthorized_client", authz.Error ?? "（無い）");

                r.Done();
            }
        }

        #endregion

        #region RT-294.56

        /// <summary>RT-294.56 poll の CIBA は、client_notification_token も binding_message も要らない</summary>
        /// <param name="targetKey">core / netfx</param>
        /// <returns>Task</returns>
        [SkippableTheory]
        [MemberData(nameof(AllTargets))]
        public async Task RT29456_pollのCIBAはclient_notification_tokenを要らない(string targetKey)
        {
            using (IdPClient client = await this.SignedInClientAsync(targetKey))
            {
                FcmOutbox.SkipIfUnavailable(client.Target);

                TestReport r = this.Report("RT-294.56",
                    "**poll の CIBA は、client_notification_token も binding_message も無い request で受け付ける**",
                    "**client_notification_token は ping / push のときだけ REQUIRED、binding_message は OPTIONAL**（CIBA Core §7.1）。"
                    + "**この実装は poll だけを扱う**のに、**以前は両方を必須にしていた**ので、"
                    + "**標準の poll のクライアントは invalid_request で断られた**（N5）。",
                    "CIBA Core §7.1 / #294");

                ClientRegistration reg = Flows.Registration(client, KnownClients.TestClient4);
                long now = DateTimeOffset.UtcNow.ToUnixTimeSeconds();

                r.Target("POST /ciba_authz（client_name=" + KnownClients.TestClient4 + "。request に 2 つを入れない）");

                (string AccessToken, string DeviceToken) device = await CibaTests.RegisterDeviceAsync(r, client);

                string request = JwsSigner.SignES256(client, new Dictionary<string, object>()
                {
                    { "iss", reg.ClientId },
                    { "aud", await client.IssuerAsync() },
                    { "iat", now },
                    { "nbf", now },
                    { "exp", now + 600 },
                    { "jti", Guid.NewGuid().ToString("N") },
                    { "scope", "openid" },
                    { "login_hint", TestEnv.TestUserName(targetKey) }
                });

                JsonResponse start = await client.CibaAuthorizeWithBasicAuthAsync(
                    new Dictionary<string, string>() { { "request", request } },
                    reg.ClientId, reg.ClientSecret);

                string authReqId = start.String("auth_req_id");

                r.Verify("auth_req_id が返る", !string.IsNullOrEmpty(authReqId),
                    "あり", string.IsNullOrEmpty(authReqId) ? "**無い**（" + start.ToString() + "）" : "あり");

                if (!string.IsNullOrEmpty(authReqId))
                {
                    // **後始末**（利用者は拒否する。端末の登録は、同じコレクションの次のテストが上書きする）。
                    await CibaTests.ReceivePushAsync(r, client, authReqId, device.DeviceToken);
                    await client.CibaPushResultAsync(device.AccessToken, authReqId, "false");
                }

                r.Done();
            }
        }

        #endregion

        #region RT-294.57

        /// <summary>RT-294.57 PAR の Request Object の client_id は、認証したクライアントであること</summary>
        /// <param name="targetKey">core / netfx</param>
        /// <returns>Task</returns>
        [SkippableTheory]
        [MemberData(nameof(AllTargets))]
        public async Task RT29457_PARのRequestObjectのclient_idを照合する(string targetKey)
        {
            using (IdPClient client = this.Client(targetKey))
            {
                TestReport r = this.Report("RT-294.57",
                    "**PAR に預ける Request Object の client_id が、認証したクライアントと違えば、invalid_request_object で断る**",
                    "**RFC 9126 §2.1 は、Request Object の client_id が認証したクライアントであることを求める。**"
                    + "**以前は iss だけを照合し、検証と保存は中の client_id で行っていた**ので、"
                    + "**別のクライアントの名義で、預けた要求を作れた**（C-41）。",
                    "RFC 9126 §2.1 / RFC 9101 §6.3 / #294");

                ClientRegistration reg = Flows.Registration(client, KnownClients.TestClient2);
                ClientRegistration other = Flows.Registration(client, KnownClients.TestClient);

                r.Target("POST /par（client_name=" + KnownClients.TestClient2 + "。request の client_id だけを他のクライアントにする）");

                string request = RequestObjectBuilder.Create(client, reg.ClientId, new Dictionary<string, object>()
                {
                    { "client_id", other.ClientId },
                    { "response_type", "code" },
                    { "scope", "openid" },
                    { "redirect_uri", other.RedirectUri },
                    { "state", "state-rt29457" },
                    { "nonce", "nonce-rt29457" }
                });

                JsonResponse res = await client.PostJsonAsync("/par", new Dictionary<string, string>()
                {
                    { "request", request },
                    { "client_assertion_type", JwtBearerAssertionType },
                    { "client_assertion", CmnEndpointsReviewTests.ClientAssertionRS256(client, reg.ClientId, null) }
                });

                r.VerifyEqual("invalid_request_object", "invalid_request_object", res.Error ?? "（無い）");

                r.Verify("request_uri を返さない", string.IsNullOrEmpty(res.String("request_uri")),
                    "返さない", string.IsNullOrEmpty(res.String("request_uri")) ? "返さない" : "**返した**");

                r.Done();
            }
        }

        #endregion

        #region RT-294.58

        /// <summary>RT-294.58 合わない code_verifier は invalid_grant</summary>
        /// <param name="targetKey">core / netfx</param>
        /// <returns>Task</returns>
        [SkippableTheory]
        [MemberData(nameof(AllTargets))]
        public async Task RT29458_合わないcode_verifierはinvalid_grant(string targetKey)
        {
            using (IdPClient client = await this.SignedInClientAsync(targetKey))
            {
                TestReport r = this.Report("RT-294.58",
                    "**code_verifier が合わなければ、invalid_grant で断る**（PKCE だけでも、client_secret と併せても）",
                    "**RFC 7636 §4.6 は、code_verifier の不一致を invalid_grant とする。**"
                    + "**以前は invalid_client で返していた**ので、"
                    + "**クライアントは「資格情報が違う」のか「code_verifier が違う」のかを区別できなかった**（F1）。",
                    "RFC 7636 §4.6 / RFC 6749 §5.2 / #294");

                ClientRegistration secretBasic = Flows.InjectedRegistration(client, KnownClients.TestClient_30);
                ClientRegistration none = Flows.InjectedRegistration(client, KnownClients.TestClient_31);

                r.Target("POST /token（grant_type=authorization_code。code_verifier を 1 文字変える）");

                r.Step("(1) PKCE だけ（" + KnownClients.TestClient_31 + "。none）");

                JsonResponse pkceOnly = await CmnEndpointsReviewTests.ExchangeWithPkceAsync(
                    client, none, false, CmnEndpointsReviewTests.Verifier + "x");

                r.VerifyEqual("invalid_grant", "invalid_grant", pkceOnly.Error ?? "（無い）");

                r.Step("(2) client_secret ＋ PKCE（" + KnownClients.TestClient_30 + "。client_secret_basic）");

                JsonResponse withSecret = await CmnEndpointsReviewTests.ExchangeWithPkceAsync(
                    client, secretBasic, true, CmnEndpointsReviewTests.Verifier + "x");

                r.VerifyEqual("invalid_grant", "invalid_grant", withSecret.Error ?? "（無い）");

                r.Step("(3) 秘密が違えば、従来どおり invalid_client");

                JsonResponse badSecret = await CmnEndpointsReviewTests.ExchangeWithPkceAsync(
                    client, new ClientRegistration()
                    {
                        ClientId = secretBasic.ClientId,
                        ClientSecret = "wrong-" + Guid.NewGuid().ToString("N"),
                        RedirectUri = secretBasic.RedirectUri,
                        RedirectUriToken = secretBasic.RedirectUriToken
                    }, true, CmnEndpointsReviewTests.Verifier);

                r.VerifyEqual("invalid_client", "invalid_client", badSecret.Error ?? "（無い）");

                r.Done();
            }
        }

        #endregion

        #region RT-294.59

        /// <summary>RT-294.59 /ros の Request Object の client_id は、署名したクライアントであること</summary>
        /// <param name="targetKey">core / netfx</param>
        /// <returns>Task</returns>
        [SkippableTheory]
        [MemberData(nameof(AllTargets))]
        public async Task RT29459_rosのRequestObjectのclient_idを照合する(string targetKey)
        {
            using (IdPClient client = this.Client(targetKey))
            {
                TestReport r = this.Report("RT-294.59",
                    "**/ros に預ける Request Object の client_id が、署名したクライアント（iss）と違えば、預からない**",
                    "**RFC 9101 §6.3 は、Request Object の client_id が要求したクライアントであることを求める。**"
                    + "**以前は署名（iss）だけを確かめていた**ので、**自分の鍵で署名した Request Object を、"
                    + "別のクライアントの名義で預けられた**（PAR は C-41 で直した。F5）。",
                    "RFC 9101 §6.3 / #294");

                ClientRegistration reg = Flows.Registration(client, KnownClients.TestClient2);
                ClientRegistration other = Flows.Registration(client, KnownClients.TestClient);

                r.Target("POST /ros（iss=" + KnownClients.TestClient2 + "。client_id だけを他のクライアントにする）");

                r.Step("(1) client_id が他のクライアント");

                string mismatched = RequestObjectBuilder.Create(client, reg.ClientId, new Dictionary<string, object>()
                {
                    { "client_id", other.ClientId },
                    { "response_type", "code" },
                    { "scope", "openid" },
                    { "redirect_uri", other.RedirectUri },
                    { "state", "state-rt29459" },
                    { "nonce", "nonce-rt29459" }
                });

                string rejected = await RequestObjectBuilder.RegisterAsync(client, mismatched);

                r.Verify("request_uri を返さない", string.IsNullOrEmpty(rejected),
                    "返さない", string.IsNullOrEmpty(rejected) ? "返さない" : "**返した**");

                r.Step("(2) client_id が署名したクライアント（従来どおり預かる）");

                string matched = RequestObjectBuilder.Create(client, reg.ClientId, new Dictionary<string, object>()
                {
                    { "response_type", "code" },
                    { "scope", "openid" },
                    { "redirect_uri", reg.RedirectUri },
                    { "state", "state-rt29459" },
                    { "nonce", "nonce-rt29459" }
                });

                string accepted = await RequestObjectBuilder.RegisterAsync(client, matched);

                r.Verify("request_uri を返す", !string.IsNullOrEmpty(accepted),
                    "返す", string.IsNullOrEmpty(accepted) ? "**返さない**" : "返した");

                r.Done();
            }
        }

        #endregion

        #region 補助

        /// <summary>管理者でサインインした client を作る</summary>
        /// <param name="targetKey">core / netfx</param>
        /// <returns>IdPClient</returns>
        private async Task<IdPClient> AdminClientAsync(string targetKey)
        {
            IdPClient client = this.Client(targetKey);
            await client.SignInAsAdministratorAsync();

            return client;
        }

        /// <summary>RFC 7636 附録 B の例</summary>
        private const string Verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";

        /// <summary>RFC 7636 附録 B の例（SHA256(verifier) を BASE64URL したもの）</summary>
        private const string Challenge = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";

        /// <summary>PKCE（S256）の認可リクエストのパラメタ</summary>
        /// <returns>パラメタ</returns>
        private static Dictionary<string, string> Pkce()
        {
            return new Dictionary<string, string>()
            {
                { "code_challenge", CmnEndpointsReviewTests.Challenge },
                { "code_challenge_method", "S256" }
            };
        }

        /// <summary>PKCE で認可コードを取り、交換する</summary>
        /// <param name="client">IdPClient</param>
        /// <param name="reg">クライアント</param>
        /// <param name="withSecret">client_secret も送るか</param>
        /// <param name="verifier">送る code_verifier（null なら正しいもの）</param>
        /// <returns>トークン応答</returns>
        private static async Task<JsonResponse> ExchangeWithPkceAsync(
            IdPClient client, ClientRegistration reg, bool withSecret, string verifier = null)
        {
            AuthZResponse authz = await Flows.AuthorizeCodeAsync(
                client, reg, redirectUri: reg.RedirectUri, extra: CmnEndpointsReviewTests.Pkce());

            Assert.False(string.IsNullOrEmpty(authz.Code),
                "前提: 認可コードが取得できること（" + authz.ToString() + "）");

            return await client.TokenAsync(new Dictionary<string, string>()
            {
                { "grant_type", "authorization_code" },
                { "code", authz.Code },
                { "client_id", reg.ClientId },
                { "client_secret", withSecret ? reg.ClientSecret : null },
                { "code_verifier", verifier ?? CmnEndpointsReviewTests.Verifier },
                { "redirect_uri", reg.RedirectUri }
            });
        }

        /// <summary>client_assertion で認証して /revoke を叩く（認証が通れば 200）</summary>
        /// <param name="client">IdPClient</param>
        /// <param name="reg">クライアント</param>
        /// <param name="aud">client_assertion の aud</param>
        /// <returns>JsonResponse</returns>
        private static Task<JsonResponse> RevokeWithAssertionAsync(
            IdPClient client, ClientRegistration reg, object aud)
        {
            return client.RevokeAsync(new Dictionary<string, string>()
            {
                { "token", "not-a-token" },
                { "client_assertion_type", JwtBearerAssertionType },
                { "client_assertion", CmnEndpointsReviewTests.ClientAssertionRS256(client, reg.ClientId, aud) }
            });
        }

        /// <summary>RS256 の client_assertion を作る（RFC 7523 §2.2）</summary>
        /// <param name="client">IdPClient</param>
        /// <param name="clientId">client_id</param>
        /// <param name="aud">aud（null ならトークン エンドポイントの URL）</param>
        /// <returns>client_assertion</returns>
        private static string ClientAssertionRS256(IdPClient client, string clientId, object aud)
        {
            long now = DateTimeOffset.UtcNow.ToUnixTimeSeconds();

            return JwsSigner.SignRS256(client, new Dictionary<string, object>()
            {
                { "iss", clientId },
                { "sub", clientId },
                { "aud", aud ?? (client.Target.BaseUrl + "/token") },
                { "jti", Guid.NewGuid().ToString("N") },
                { "iat", now },
                { "exp", now + 300 }
            });
        }

        /// <summary>Discovery が広告する token_endpoint（DPoP の `htu`）</summary>
        /// <param name="client">IdPClient</param>
        /// <returns>token_endpoint</returns>
        private static async Task<string> TokenEndpointAsync(IdPClient client)
        {
            JsonResponse res = await client.GetJsonAsync("/.well-known/openid-configuration");

            string endpoint = res.String("token_endpoint");

            Skip.If(string.IsNullOrEmpty(endpoint), "Discovery が token_endpoint を広告していません。");

            return endpoint;
        }

        /// <summary>`/token` 宛ての DPoP の証明を作る</summary>
        /// <param name="client">IdPClient</param>
        /// <param name="htu">token_endpoint</param>
        /// <returns>証明</returns>
        private static string DPoPProof(IdPClient client, string htu)
        {
            return JwsSigner.SignDPoP(client, new Dictionary<string, object>()
            {
                { "jti", Guid.NewGuid().ToString("N") },
                { "htm", "POST" },
                { "htu", htu },
                { "iat", DateTimeOffset.UtcNow.ToUnixTimeSeconds() }
            });
        }

        /// <summary>ES256 の client_assertion を作る（RFC 7523 §2.2）</summary>
        /// <param name="client">IdPClient</param>
        /// <param name="clientId">client_id</param>
        /// <returns>client_assertion</returns>
        private static string ClientAssertionES256(IdPClient client, string clientId)
        {
            long now = DateTimeOffset.UtcNow.ToUnixTimeSeconds();

            return JwsSigner.SignES256(client, new Dictionary<string, object>()
            {
                { "iss", clientId },
                { "sub", clientId },
                { "aud", client.Target.BaseUrl + "/token" },
                { "jti", Guid.NewGuid().ToString("N") },
                { "iat", now },
                { "exp", now + 300 }
            });
        }

        /// <summary>署名の無い（壊れた）JWT を作る</summary>
        /// <param name="payloadJson">payload の JSON</param>
        /// <returns>JWT の形の文字列</returns>
        private static string UnsignedJwt(string payloadJson)
        {
            return Base64Url.Encode(Encoding.UTF8.GetBytes("{\"alg\":\"ES256\"}"))
                + "." + Base64Url.Encode(Encoding.UTF8.GetBytes(payloadJson))
                + ".c2ln";
        }

        /// <summary>JWT Bearer グラントを要求する</summary>
        /// <param name="client">IdPClient</param>
        /// <param name="assertion">assertion</param>
        /// <param name="scope">scope（null なら送らない）</param>
        /// <returns>JsonResponse</returns>
        private static Task<JsonResponse> JwtBearerAsync(IdPClient client, string assertion, string scope)
        {
            return client.TokenAsync(new Dictionary<string, string>()
            {
                { "grant_type", JwtBearerAssertion.GrantType },
                { "assertion", assertion },
                { "scope", scope }
            });
        }

        /// <summary>この配備が、その grant_type を広告しているか</summary>
        /// <param name="client">IdPClient</param>
        /// <param name="grantType">grant_type</param>
        /// <returns>広告していれば true</returns>
        private static async Task<bool> SupportsGrantTypeAsync(IdPClient client, string grantType)
        {
            JsonResponse res = await client.GetJsonAsync("/.well-known/openid-configuration");

            return res.ArrayContains("grant_types_supported", grantType);
        }

        /// <summary>クライアントの誤りとして断られたこと（500 でないこと）を確かめる</summary>
        /// <param name="r">TestReport</param>
        /// <param name="res">応答</param>
        private static void VerifyClientError(TestReport r, JsonResponse res)
        {
            int status = (int)res.StatusCode;

            r.Verify("HTTP 400 か 401（500 にしない）", status == 400 || status == 401,
                "400 / 401", status.ToString());

            r.Verify("error が返る", !string.IsNullOrEmpty(res.Error),
                "あり", res.Error ?? "**無い**");
        }

        /// <summary>トークンが発行されたことを確かめる</summary>
        /// <param name="r">TestReport</param>
        /// <param name="res">応答</param>
        private static void VerifyIssued(TestReport r, JsonResponse res)
        {
            r.VerifyEqual("HTTP 200", "200", ((int)res.StatusCode).ToString());

            r.Verify("access_token が返る", !string.IsNullOrEmpty(res.AccessToken),
                "あり", string.IsNullOrEmpty(res.AccessToken) ? "**無い**（" + res.ToString() + "）" : "あり");
        }

        #endregion
    }
}
