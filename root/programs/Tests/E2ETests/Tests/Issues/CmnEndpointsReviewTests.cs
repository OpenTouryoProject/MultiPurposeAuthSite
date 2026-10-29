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
//* クラス日本語名  ：RT-294.41 〜 .49 CmnEndpoints.*.cs のレビューで見つけた不具合
//*
//* 作成日時        ：－
//* 作成者          ：－
//* 更新履歴        ：－
//*
//*  日時        更新者            内容
//*  ----------  ----------------  -------------------------------------------------
//*  2026/10/29  玄人 幸道         新規（#294）
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
    /// RT-294.41 〜 .49 `CmnEndpoints.*.cs` のレビューで見つけた不具合（#294）。
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

                foreach (string name in new string[] {
                    "revocation_endpoint_auth_methods_supported",
                    "introspection_endpoint_auth_methods_supported" })
                {
                    string[] methods = res.Strings(name) ?? new string[0];

                    r.VerifyEqual(name + " が token_endpoint_auth_methods_supported と同じ",
                        string.Join(" ", token), string.Join(" ", methods));
                }

                r.Verify("request_object_signing_alg_values_supported に RS256 が在る",
                    res.ArrayContains("request_object_signing_alg_values_supported", "RS256"),
                    "在る", string.Join(" ", res.Strings("request_object_signing_alg_values_supported") ?? new string[0]));

                r.Done();
            }
        }

        #endregion

        #region 補助

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
