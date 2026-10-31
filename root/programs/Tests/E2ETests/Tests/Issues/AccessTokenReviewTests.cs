//**********************************************************************************
//* Copyright (C) 2017 Hitachi Solutions,Ltd.
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
//* クラス名        ：AccessTokenReviewTests
//* クラス日本語名  ：RT-294.87 〜 .92 CmnAccessToken.*.cs のレビューで見つけた不具合
//*
//* 作成日時        ：－
//* 作成者          ：－
//* 更新履歴        ：－
//*
//*  日時        更新者            内容
//*  ----------  ----------------  -------------------------------------------------
//*  2026/10/31  玄人 幸道         新規（#294）
//*  2026/10/31  玄人 幸道         RT-294.91 / .92（claims の id_token がオブジェクトでなくても 500 にしない・/ros の claims）を足した（#294）
//**********************************************************************************

using System;
using System.Collections.Generic;
using System.Net;
using System.Net.Http;
using System.Text.Json;
using System.Threading.Tasks;

using MultiPurposeAuthSite.Tests.E2E.Infrastructure;

using Xunit;
using Xunit.Abstractions;

namespace MultiPurposeAuthSite.Tests.E2E.Tests.Issues
{
    /// <summary>
    /// RT-294.87 〜 .92 `CmnAccessToken.*.cs` のレビューで見つけた不具合（#294）。
    /// </summary>
    /// <remarks>
    /// | | 確かめること |
    /// |---|---|
    /// | `RT-294.87` | **pairwise のクライアントでも、消された利用者の access_token は通らない**（C-57） |
    /// | `RT-294.88` | **`auth_time` は JSON の数値**（OIDC Core §2） |
    /// | `RT-294.89` | **Implicit でも `claims` パラメタが access_token に載る**（OIDC Core 5.5。PAR で渡す） |
    /// | `RT-294.90` | **`/par` は、JSON のオブジェクトでない `claims` を断る**（以前は `/authorize` で 500） |
    /// | `RT-294.91` | **`claims` の `id_token` がオブジェクトでなくても、認可は 500 にならない**（`AddAuthTimeClaim`） |
    /// | `RT-294.92` | **`/ros` は、`claims` がオブジェクトでない Request Object を預からない**（PAR と同じ扱い） |
    ///
    /// **`RT-294.87` は管理者でサインインする**（使い捨ての利用者を作って消す）ので、管理画面のテストと同じコレクションに入れる。
    /// </remarks>
    [Collection(UsersAdminTests.AdminScreenCollection)]
    public class AccessTokenReviewTests : TargetTestBase
    {
        /// <summary>コンストラクタ</summary>
        /// <param name="output">ITestOutputHelper</param>
        public AccessTokenReviewTests(ITestOutputHelper output) : base(output) { }

        #region RT-294.87

        /// <summary>RT-294.87 pairwise のクライアントでも、消された利用者の access_token は通らない</summary>
        /// <param name="targetKey">core / netfx</param>
        /// <returns>Task</returns>
        [SkippableTheory]
        [MemberData(nameof(AllTargets))]
        public async Task RT29487_pairwiseでも消された利用者のaccess_tokenは通らない(string targetKey)
        {
            using (IdPClient admin = await this.AdminClientAsync(targetKey))
            using (IdPClient user = this.Client(targetKey))
            {
                string name = "e2e_rt_" + Guid.NewGuid().ToString("N").Substring(0, 8);
                string password = admin.Config.Get("TestUserPWD");

                TestReport r = this.Report("RT-294.87",
                    "pairwise のクライアント : 利用者を消したら、その人の access_token は /userinfo で通らない",
                    "**以前は pairwise なら、利用者が居るかを確かめずに access_token を受けていた**ので、"
                    + "**利用者を消しても、その人の access_token が期限まで通った**（public のクライアントでは落ちていた）。"
                    + "**C-54（refresh_token）と同じ種類の抜け**である（C-57）。",
                    "OIDC Core §8.1 / #294（CmnAccessToken.VerifyAccessToken。ANALYSIS-IdP.md の C-57）");

                r.Target("使い捨ての利用者 = " + name + " / client_name=" + KnownClients.TestClient_5 + "（subject_types=pairwise）");

                await UsersAdmin.SkipIfLockedDownAsync(admin);

                bool deleted = false;

                try
                {
                    r.Step("(1) 使い捨ての利用者を作り、pairwise のクライアントで access_token を得る");

                    HttpResponseMessage created = await UsersAdmin.CreateAsync(admin, name, name + "@example.com", "User");

                    Assert.True(created.StatusCode == HttpStatusCode.Found || created.StatusCode == HttpStatusCode.Redirect,
                        "前提: 利用者を作れること");

                    Assert.True(await user.TrySignInAsync(name, password), "前提: 作った利用者でサインインできること");

                    ClientRegistration pairwise = Flows.InjectedRegistration(user, KnownClients.TestClient_5);

                    AuthZResponse authz = await Flows.AuthorizeCodeAsync(
                        user, pairwise, scope: "openid email", redirectUri: pairwise.RedirectUri);

                    Assert.False(string.IsNullOrEmpty(authz.Code), "前提: 認可コードが返ること");

                    JsonResponse token = await Flows.ExchangeCodeAsync(
                        user, pairwise, authz.Code, redirectUri: pairwise.RedirectUri);

                    Assert.False(string.IsNullOrEmpty(token.AccessToken), "前提: access_token が返ること");

                    JsonResponse before = await user.UserInfoAsync(token.AccessToken);

                    r.VerifyEqual("消す前は /userinfo が通る", "200", ((int)before.StatusCode).ToString());

                    r.Step("(2) 管理者が、その利用者を消す");

                    deleted = await UsersAdmin.DeleteByUserNameAsync(admin, name);

                    Assert.True(deleted, "前提: 利用者を消せること");

                    r.Step("(3) 消された利用者の access_token で /userinfo を叩く");

                    JsonResponse after = await user.UserInfoAsync(token.AccessToken);

                    r.VerifyEqual("**401 で断る**", "401", ((int)after.StatusCode).ToString());
                }
                finally
                {
                    if (!deleted)
                    {
                        await UsersAdmin.DeleteByUserNameAsync(admin, name);
                    }
                }

                r.Done();
            }
        }

        #endregion

        #region RT-294.88

        /// <summary>RT-294.88 auth_time は JSON の数値</summary>
        /// <param name="targetKey">core / netfx</param>
        /// <returns>Task</returns>
        [SkippableTheory]
        [MemberData(nameof(AllTargets))]
        public async Task RT29488_auth_timeはJSONの数値(string targetKey)
        {
            using (IdPClient client = await this.SignedInClientAsync(targetKey))
            {
                TestReport r = this.Report("RT-294.88",
                    "max_age を付けた認可コード フロー : id_token と access_token の auth_time は JSON の数値",
                    "**以前は W3C 形式の文字列（`2026-10-31T…Z`）で載せていた**"
                    + "（`AccountController.AddAuthTimeClaim` が W3C で渡すものを、そのまま入れていた）。"
                    + "**OIDC Core §2 は auth_time を、エポックからの秒数（JSON の数値）と定めている。**"
                    + "**厳密な RP は max_age の照合で読めない。**",
                    "OIDC Core §2 / RFC 7519 §2（NumericDate）/ #294");

                ClientRegistration reg = Flows.Registration(client, KnownClients.MvcSample);

                r.Target("client_name=" + KnownClients.MvcSample + " / max_age=600");

                r.Step("(1) max_age=600 を付けて、認可コード フローを通す");

                AuthZResponse authz = await Flows.AuthorizeCodeAsync(
                    client, reg, "openid email", "state1", "nonce1", reg.RedirectUri,
                    new Dictionary<string, string>() { { "max_age", "600" } });

                Assert.False(string.IsNullOrEmpty(authz.Code), "前提: 認可コードが返ること（" + authz.ToString() + "）");

                JsonResponse token = await Flows.ExchangeCodeAsync(client, reg, authz.Code, reg.RedirectUri);

                Assert.False(string.IsNullOrEmpty(token.IdToken), "前提: id_token が返ること");

                JsonElement idToken = Jwt.Payload(token.IdToken);
                JsonElement accessToken = Jwt.Payload(token.AccessToken);

                r.VerifyEqual("**id_token の auth_time は数値**", "Number", Jwt.KindOf(idToken, "auth_time").ToString());
                r.VerifyEqual("access_token の auth_time も数値", "Number", Jwt.KindOf(accessToken, "auth_time").ToString());

                r.Done();
            }
        }

        #endregion

        #region RT-294.89

        /// <summary>RT-294.89 Implicit でも claims パラメタが access_token に載る</summary>
        /// <param name="targetKey">core / netfx</param>
        /// <returns>Task</returns>
        [SkippableTheory]
        [MemberData(nameof(AllTargets))]
        public async Task RT29489_Implicitでもclaimsパラメタがaccess_tokenに載る(string targetKey)
        {
            using (IdPClient client = await this.SignedInClientAsync(targetKey))
            {
                // **Implicit は雛形の既定で無効**（#220）。有効な環境でだけ測る。
                await Flows.SkipIfGrantTypeNotSupportedAsync(client, "implicit");

                TestReport r = this.Report("RT-294.89",
                    "Implicit（id_token token）: claims パラメタが access_token に載る",
                    "**以前は Claims 経由の作り方（`CreateFromClaims`）が claims を拾っていなかった**ので、"
                    + "**Implicit / Hybrid で要求された claims が access_token に載らず、/userinfo で効かなかった**"
                    + "（認可コード フローの `CreatePayloadForCode` は拾っていた）。",
                    "OIDC Core §5.5 / #294");

                ClientRegistration reg = Flows.Registration(client, KnownClients.TestClient);

                r.Target("client_name=" + KnownClients.TestClient + " / response_type=id_token token");

                // **claims は Request Object（PAR を含む）でだけ受ける**（`claims_parameter_supported` は false）。
                JsonResponse discovery = await client.GetJsonAsync("/.well-known/openid-configuration");
                string endpoint = discovery.String("pushed_authorization_request_endpoint");

                Skip.If(string.IsNullOrEmpty(endpoint), "PAR の口が広告されていません。");

                r.Step("(1) claims（userinfo の email）を付けた Implicit の要求を、PAR に預ける");

                JsonResponse par = await client.PostJsonWithBasicAuthAsync(
                    client.ToLocalUrl(endpoint),
                    new Dictionary<string, string>()
                    {
                        { "response_type", "id_token token" },
                        { "client_id", reg.ClientId },
                        { "scope", "openid" },
                        { "redirect_uri", reg.RedirectUriToken },
                        { "state", "state1" },
                        { "nonce", "nonce1" },
                        { "claims", "{\"userinfo\":{\"email\":null}}" }
                    },
                    reg.ClientId, reg.ClientSecret);

                string requestUri = par.String("request_uri");

                Assert.False(string.IsNullOrEmpty(requestUri), "前提: request_uri が返ること（" + par.ToString() + "）");

                r.Step("(2) その request_uri で認可する");

                AuthZResponse res = await client.AuthorizeAndGrantAsync(new Dictionary<string, string>()
                {
                    { "client_id", reg.ClientId },
                    { "request_uri", requestUri }
                });

                string accessToken = res.Get("access_token");

                Assert.False(string.IsNullOrEmpty(accessToken), "前提: access_token が返ること（" + res.ToString() + "）");

                JsonElement payload = Jwt.Payload(accessToken);

                r.VerifyEqual("**access_token に claims が載る**", "Object", Jwt.KindOf(payload, "claims").ToString());

                r.Done();
            }
        }

        #endregion

        #region RT-294.90

        /// <summary>RT-294.90 /par は、JSON のオブジェクトでない claims を断る</summary>
        /// <param name="targetKey">core / netfx</param>
        /// <returns>Task</returns>
        [SkippableTheory]
        [MemberData(nameof(AllTargets))]
        public async Task RT29490_parはJSONのオブジェクトでないclaimsを断る(string targetKey)
        {
            using (IdPClient client = await this.SignedInClientAsync(targetKey))
            {
                TestReport r = this.Report("RT-294.90",
                    "/par : claims が JSON のオブジェクトでなければ、invalid_request で断る（500 にしない）",
                    "**以前は claims を文字列のまま預けていた**ので、"
                    + "**/authorize で `(JObject)` の変換に失敗して 500 になった**（正しい JSON でも同じだった。RT-294.89）。"
                    + "**いまは JSON のオブジェクトとして預け、読めなければ PAR の時点で断る。**",
                    "RFC 9126 §2.1 / §2.3 / OIDC Core §5.5 / #294");

                JsonResponse discovery = await client.GetJsonAsync("/.well-known/openid-configuration");
                string endpoint = discovery.String("pushed_authorization_request_endpoint");

                Skip.If(string.IsNullOrEmpty(endpoint), "PAR の口が広告されていません。");

                ClientRegistration reg = Flows.Registration(client, KnownClients.TestClient);

                r.Target("client_name=" + KnownClients.TestClient + " / claims=not-a-json");

                r.Step("(1) JSON でない claims を付けて、PAR に預ける");

                JsonResponse par = await client.PostJsonWithBasicAuthAsync(
                    client.ToLocalUrl(endpoint),
                    new Dictionary<string, string>()
                    {
                        { "response_type", "code" },
                        { "client_id", reg.ClientId },
                        { "scope", "openid" },
                        { "redirect_uri", reg.RedirectUri },
                        { "state", "state1" },
                        { "nonce", "nonce1" },
                        { "claims", "not-a-json" }
                    },
                    reg.ClientId, reg.ClientSecret);

                r.VerifyEqual("**HTTP 400**", "400", ((int)par.StatusCode).ToString());
                r.VerifyEqual("invalid_request", "invalid_request", par.Error);

                r.Done();
            }
        }

        #endregion

        #region RT-294.91

        /// <summary>RT-294.91 claims の id_token がオブジェクトでなくても 500 にしない</summary>
        /// <param name="targetKey">core / netfx</param>
        /// <returns>Task</returns>
        [SkippableTheory]
        [MemberData(nameof(AllTargets))]
        public async Task RT29491_claimsのid_tokenがオブジェクトでなくても500にしない(string targetKey)
        {
            using (IdPClient client = await this.SignedInClientAsync(targetKey))
            {
                TestReport r = this.Report("RT-294.91",
                    "PAR の claims が {\"id_token\":null} でも、認可は 500 にならず code を返す",
                    "**auth_time を載せるかの判定（`AddAuthTimeClaim`）が、claims の id_token を `(JObject)` で読んでいた**ので、"
                    + "**オブジェクトでないと 500 になった**（RT-294.89 で PAR の claims を受けるようにしたので、誰でも届く）。"
                    + "**いまは、オブジェクトでなければ auth_time の要求は無いものとして扱う。**",
                    "OIDC Core §5.5 / #294");

                JsonResponse discovery = await client.GetJsonAsync("/.well-known/openid-configuration");
                string endpoint = discovery.String("pushed_authorization_request_endpoint");

                Skip.If(string.IsNullOrEmpty(endpoint), "PAR の口が広告されていません。");

                ClientRegistration reg = Flows.Registration(client, KnownClients.TestClient);

                r.Target("client_name=" + KnownClients.TestClient + " / claims={\"id_token\":null}");

                r.Step("(1) claims={\"id_token\":null} の認可コードの要求を、PAR に預ける");

                JsonResponse par = await client.PostJsonWithBasicAuthAsync(
                    client.ToLocalUrl(endpoint),
                    new Dictionary<string, string>()
                    {
                        { "response_type", "code" },
                        { "client_id", reg.ClientId },
                        { "scope", "openid" },
                        { "redirect_uri", reg.RedirectUri },
                        { "state", "state1" },
                        { "nonce", "nonce1" },
                        { "claims", "{\"id_token\":null}" }
                    },
                    reg.ClientId, reg.ClientSecret);

                string requestUri = par.String("request_uri");

                Assert.False(string.IsNullOrEmpty(requestUri), "前提: request_uri が返ること（" + par.ToString() + "）");

                r.Step("(2) その request_uri で認可する");

                AuthZResponse authz = await client.AuthorizeAndGrantAsync(new Dictionary<string, string>()
                {
                    { "client_id", reg.ClientId },
                    { "request_uri", requestUri }
                });

                r.Verify("**500 にならず、code を返す**", !string.IsNullOrEmpty(authz.Code),
                    "code が返る", string.IsNullOrEmpty(authz.Code) ? "**" + authz.ToString() + "**" : "code が返った");

                r.Done();
            }
        }

        #endregion

        #region RT-294.92

        /// <summary>RT-294.92 /ros は、claims が JSON のオブジェクトでない Request Object を預からない</summary>
        /// <param name="targetKey">core / netfx</param>
        /// <returns>Task</returns>
        [SkippableTheory]
        [MemberData(nameof(AllTargets))]
        public async Task RT29492_rosはclaimsがオブジェクトでないRequestObjectを預からない(string targetKey)
        {
            using (IdPClient client = this.Client(targetKey))
            {
                TestReport r = this.Report("RT-294.92",
                    "/ros : claims が JSON のオブジェクトでない Request Object を預からない（PAR と同じ扱い）",
                    "**以前は預かり、/authorize で黙って無視していた**（その前は `(JObject)` の変換で 500）。"
                    + "**PAR のフォーム（RT-294.90）と扱いを揃えた。**",
                    "OIDC Core §5.5 / RFC 9101 §6.3 / #294");

                ClientRegistration reg = Flows.Registration(client, KnownClients.TestClient2);

                r.Target("POST /ros（iss=" + KnownClients.TestClient2 + " / claims=\"not-an-object\"）");

                r.Step("(1) claims を文字列にした Request Object を預ける");

                string bad = RequestObjectBuilder.Create(client, reg.ClientId, new Dictionary<string, object>()
                {
                    { "response_type", "code" },
                    { "scope", "openid" },
                    { "redirect_uri", reg.RedirectUri },
                    { "state", "state-rt29492" },
                    { "nonce", "nonce-rt29492" },
                    { "claims", "not-an-object" }
                });

                string rejected = await RequestObjectBuilder.RegisterAsync(client, bad);

                r.Verify("**request_uri を返さない**", string.IsNullOrEmpty(rejected),
                    "返さない", string.IsNullOrEmpty(rejected) ? "返さない" : "**返した**");

                r.Step("(2) claims をオブジェクトにすれば預かる（対照）");

                string good = RequestObjectBuilder.Create(client, reg.ClientId, new Dictionary<string, object>()
                {
                    { "response_type", "code" },
                    { "scope", "openid" },
                    { "redirect_uri", reg.RedirectUri },
                    { "state", "state-rt29492" },
                    { "nonce", "nonce-rt29492" },
                    { "claims", new Dictionary<string, object>() { { "userinfo", new Dictionary<string, object>() { { "email", null } } } } }
                });

                string accepted = await RequestObjectBuilder.RegisterAsync(client, good);

                r.Verify("request_uri を返す", !string.IsNullOrEmpty(accepted),
                    "返す", string.IsNullOrEmpty(accepted) ? "**返さない**" : "返した");

                r.Done();
            }
        }

        #endregion

        #region 共通

        /// <summary>管理者でサインインした IdPClient</summary>
        /// <param name="targetKey">core / netfx</param>
        /// <returns>IdPClient</returns>
        private async Task<IdPClient> AdminClientAsync(string targetKey)
        {
            IdPClient client = this.Client(targetKey);
            await client.SignInAsAdministratorAsync();

            return client;
        }

        #endregion
    }
}
