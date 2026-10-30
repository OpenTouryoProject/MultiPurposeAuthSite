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
//* クラス名        ：AuthorizeReviewTests
//* クラス日本語名  ：RT-294.15 〜 .22 認可エンドポイント（AccountController.Authorize.cs のレビュー）
//*
//* 作成日時        ：－
//* 作成者          ：－
//* 更新履歴        ：－
//*
//*  日時        更新者            内容
//*  ----------  ----------------  -------------------------------------------------
//*  2026/10/28  玄人 幸道         新規（#294）
//**********************************************************************************

using System;
using System.Collections.Generic;
using System.Net;
using System.Net.Http;
using System.Text.Json;
using System.Text.RegularExpressions;
using System.Threading.Tasks;

using MultiPurposeAuthSite.Tests.E2E.Infrastructure;

using Xunit;
using Xunit.Abstractions;

namespace MultiPurposeAuthSite.Tests.E2E.Tests.Issues
{
    /// <summary>
    /// RT-294.15 〜 .22 認可エンドポイント（#294）。
    /// </summary>
    /// <remarks>
    /// **`AccountController.Authorize.cs` のレビューで見つけた穴を、直した形で押さえる。**
    ///
    /// | ケース | 以前の振る舞い |
    /// |---|---|
    /// | RT-294.15 `/device_verify` を AntiForgery トークン無しで送る | **承認された**（トークンを検証していなかった） |
    /// | RT-294.16 同意の無い Hybrid | **同意を確かめずにトークンを発行した** |
    /// | RT-294.17 `auth_time` の Cookie を書き換える | **`max_age` の再認証を飛ばせた** |
    /// | RT-294.18 再認証の印の Cookie を書き換える | **`prompt=login` の再認証を飛ばせた** |
    /// | RT-294.19 Hybrid のエラーを JARM で返す | **JARM で返さなかった**（エラーは常に query の平文） |
    /// | RT-294.20 Hybrid に `response_mode=query` | **`error` が空のまま返った** |
    /// | RT-294.21 Request Object と違う `client_id` | **確かめずに上書きした** |
    /// | RT-294.22 同意画面のボタンを送らない POST | **画面の値を組まずに画面を返した** |
    ///
    /// **`TestClient_19` には、どのテストも「許可」を押さない**（同意の記録を残さないため。#272 の段階 2）。
    /// </remarks>
    public class AuthorizeReviewTests : TargetTestBase
    {
        /// <summary>コンストラクタ</summary>
        /// <param name="output">ITestOutputHelper</param>
        public AuthorizeReviewTests(ITestOutputHelper output) : base(output)
        {
        }

        /// <summary>RT-294.15 /device_verify は、AntiForgery トークンが無ければ承認しない</summary>
        /// <param name="targetKey">core / netfx</param>
        /// <returns>Task</returns>
        [SkippableTheory]
        [MemberData(nameof(AllTargets))]
        public async Task RT29415_device_verifyはトークンが無ければ承認しない(string targetKey)
        {
            using (IdPClient client = await this.SignedInClientAsync(targetKey))
            {
                ClientRegistration reg = Flows.Registration(client, KnownClients.TestClient3);

                TestReport r = this.Report("RT-294.15",
                    "/device_verify は、AntiForgery トークンが無ければ承認しない",
                    "**画面はトークンを埋めていたが、アクションが検証していなかった。**"
                    + "**認証の Cookie は `SameSite=None`** なので、**別のサイトからの POST にも Cookie が付く。**"
                    + "**利用者が意図しない `user_code` の承認を送らせられた。**",
                    "#294（AccountController.Authorize.cs のレビュー S1）/ RFC 8628 §5.4");

                r.Target("client_name=" + KnownClients.TestClient3);

                r.Step("(1) 機器 : デバイス認可を始める");

                JsonResponse start = await client.DeviceAuthorizationAsync(new Dictionary<string, string>()
                {
                    { "client_id", reg.ClientId },
                    { "scope", "profile email" }
                });

                string deviceCode = start.String("device_code");
                string userCode = start.String("user_code");

                Assert.False(string.IsNullOrEmpty(deviceCode) || string.IsNullOrEmpty(userCode),
                    "前提: device_code と user_code が発行されること");

                r.Step("(2) サインイン済みの利用者のブラウザから、トークン無しで承認を送る");

                HttpResponseMessage post = await client.PostFormAsync("/device_verify", new Dictionary<string, string>()
                {
                    { "user_code", userCode },
                    { "allow", "Allow" }
                });
                string body = await post.Content.ReadAsStringAsync();

                r.Verify("**承認されない**（\"Accepted.\" を出さない）",
                    !body.Contains("Accepted."),
                    "承認されない", body.Contains("Accepted.") ? "**承認された**" : "HTTP " + (int)post.StatusCode);

                r.Step("(3) 機器 : トークンを要求する");

                JsonResponse poll = await client.TokenAsync(new Dictionary<string, string>()
                {
                    { "grant_type", "urn:ietf:params:oauth:grant-type:device_code" },
                    { "device_code", deviceCode },
                    { "client_id", reg.ClientId }
                });

                r.VerifyEqual("**まだ authorization_pending**（承認は通っていない）",
                    "authorization_pending", poll.Error ?? "（error 無し）");

                r.Verify("トークンを発行しない", string.IsNullOrEmpty(poll.AccessToken),
                    "access_token を返さない", poll.AccessToken == null ? "返さなかった" : "**返した**");

                r.Done();
            }
        }

        /// <summary>RT-294.16 同意の無い Hybrid は、同意を求める（prompt=none なら consent_required）</summary>
        /// <param name="targetKey">core / netfx</param>
        /// <returns>Task</returns>
        [SkippableTheory]
        [MemberData(nameof(AllTargets))]
        public async Task RT29416_同意の無いHybridは同意を求める(string targetKey)
        {
            using (IdPClient client = await this.SignedInClientAsync(targetKey))
            {
                ClientRegistration reg = Flows.InjectedRegistration(client, KnownClients.TestClient_19);

                TestReport r = this.Report("RT-294.16",
                    "同意の記録が無いクライアントの Hybrid は、同意を求める（prompt=none なら consent_required）",
                    "**同意の判定は、code の分岐の中にしか無かった。**"
                    + "**Implicit と Hybrid は、サインインしていれば同意を確かめずにトークンを発行した**"
                    + "（#272 の `consent_required` も効いていなかった）。**3 つのフローで共通にした。**",
                    "#294（AccountController.Authorize.cs のレビュー S2）/ OIDC Core §3.1.2.6");

                r.Target("client_name=" + KnownClients.TestClient_19 + "（同意の記録が無い）/ response_type=code id_token");

                r.Step("(1) prompt=none で要求する");

                AuthZResponse none = await client.AuthorizeAsync(
                    AuthorizeReviewTests.HybridParameters(reg, "state-rt29416a", "none", null));

                r.VerifyEqual("**consent_required が返る**", "consent_required", none.Error ?? "（error 無し）");

                r.Verify("code も id_token も返さない",
                    string.IsNullOrEmpty(none.Code) && string.IsNullOrEmpty(none.Get("id_token")),
                    "返さない", string.IsNullOrEmpty(none.Code) ? "返さない" : "**返した**");

                r.Verify("**フラグメントで返る**（トークンを含む応答の形）",
                    none.Where == ParameterLocation.Fragment,
                    "Fragment", none.Where.ToString());

                r.Step("(2) prompt を付けずに要求する");

                AuthZResponse screen = await client.AuthorizeAsync(
                    AuthorizeReviewTests.HybridParameters(reg, "state-rt29416b", null, null));

                r.Verify("**同意画面が出る**（トークンを返さない）",
                    screen.NeedsConsent && string.IsNullOrEmpty(screen.Code),
                    "同意画面", screen.NeedsConsent ? "同意画面" : "**" + screen.ToString() + "**");

                r.Note("**「許可」は押さない**（`TestClient_19` に同意の記録を残さない）。");

                r.Done();
            }
        }

        /// <summary>RT-294.17 auth_time の Cookie を書き換えても、max_age の再認証は飛ばせない</summary>
        /// <param name="targetKey">core / netfx</param>
        /// <returns>Task</returns>
        [SkippableTheory]
        [MemberData(nameof(AllTargets))]
        public async Task RT29417_auth_timeのCookieを書き換えても再認証は飛ばせない(string targetKey)
        {
            using (IdPClient client = await this.SignedInClientAsync(targetKey))
            {
                ClientRegistration reg = Flows.Registration(client, KnownClients.TestClient);

                TestReport r = this.Report("RT-294.17",
                    "auth_time の Cookie を書き換えても、max_age の再認証は飛ばせない",
                    "**`max_age` の判定と id_token の `auth_time` は、平文の Cookie を読んでいた。**"
                    + "**ブラウザ側で書き換えると、再認証を飛ばし、偽の時刻を RP に保証した。**"
                    + "**値を改ざんできない形で包む**ようにした（DataProtection / MachineKey）。",
                    "#294（AccountController.Authorize.cs のレビュー S3）/ OIDC Core §3.1.2.1");

                r.Target("client_name=" + KnownClients.TestClient + " / max_age=1");

                await Flows.EnsureConsentAsync(client, reg);

                r.Step("(1) サインインから 2 秒待ち、auth_time の Cookie を「いま」の平文に書き換える");

                await Task.Delay(TimeSpan.FromSeconds(2));

                client.OverwriteCookie("auth_time", DateTime.UtcNow.ToString("yyyy-MM-ddTHH:mm:ssZ"));

                r.Step("(2) max_age=1 で要求する");

                Dictionary<string, string> q = AuthorizeReviewTests.CodeParameters(reg, "state-rt29417");
                q["max_age"] = "1";

                AuthZResponse authz = await client.AuthorizeAsync(q);

                r.Verify("**認可コードは発行されない**（書き換えた時刻を信じない）",
                    string.IsNullOrEmpty(authz.Code),
                    "code なし", string.IsNullOrEmpty(authz.Code) ? "なし" : "**発行された**");

                r.Verify("**再認証の経路へ送られる**（同じ URL へ戻される）",
                    !string.IsNullOrEmpty(authz.Location) && authz.Location.Contains("/authorize"),
                    "/authorize へ戻る", authz.Location ?? authz.ToString());

                r.Done();
            }
        }

        /// <summary>RT-294.18 再認証の印の Cookie を書き換えても、prompt=login の再認証は飛ばせない</summary>
        /// <param name="targetKey">core / netfx</param>
        /// <returns>Task</returns>
        [SkippableTheory]
        [MemberData(nameof(AllTargets))]
        public async Task RT29418_再認証の印を書き換えてもprompt_loginは飛ばせない(string targetKey)
        {
            using (IdPClient client = await this.SignedInClientAsync(targetKey))
            {
                ClientRegistration reg = Flows.Registration(client, KnownClients.TestClient);

                TestReport r = this.Report("RT-294.18",
                    "再認証の印の Cookie を書き換えても、prompt=login の再認証は飛ばせない",
                    "**`prompt=login` の印は、平文の Cookie が有るか無いかしか見ていなかった。**"
                    + "**ブラウザ側で置くだけで、再認証を飛ばせた。**"
                    + "**印は改ざんできない形で包み、再認証を求めた要求に結び付けた。**",
                    "#294（AccountController.Authorize.cs のレビュー S3）/ OIDC Core §3.1.2.1");

                r.Target("client_name=" + KnownClients.TestClient + " / prompt=login");

                await Flows.EnsureConsentAsync(client, reg);

                r.Step("(1) 再認証の印の Cookie を、平文で置く");

                client.OverwriteCookie("re_auth_at", DateTime.UtcNow.ToString("yyyy-MM-ddTHH:mm:ssZ"));

                r.Step("(2) prompt=login で要求する");

                Dictionary<string, string> q = AuthorizeReviewTests.CodeParameters(reg, "state-rt29418");
                q["prompt"] = "login";

                AuthZResponse authz = await client.AuthorizeAsync(q);

                r.Verify("**認可コードは発行されない**（置いた印を信じない）",
                    string.IsNullOrEmpty(authz.Code),
                    "code なし", string.IsNullOrEmpty(authz.Code) ? "なし" : "**発行された**");

                r.Verify("**再認証の経路へ送られる**（同じ URL へ戻される）",
                    !string.IsNullOrEmpty(authz.Location) && authz.Location.Contains("/authorize"),
                    "/authorize へ戻る", authz.Location ?? authz.ToString());

                r.Done();
            }
        }

        /// <summary>RT-294.19 Hybrid のエラーを JARM で求めると、iss・aud・exp の入った JWT で返る</summary>
        /// <param name="targetKey">core / netfx</param>
        /// <returns>Task</returns>
        [SkippableTheory]
        [MemberData(nameof(AllTargets))]
        public async Task RT29419_HybridのエラーはJARMで返る(string targetKey)
        {
            using (IdPClient client = await this.SignedInClientAsync(targetKey))
            {
                ClientRegistration reg = Flows.InjectedRegistration(client, KnownClients.TestClient_19);

                TestReport r = this.Report("RT-294.19",
                    "Hybrid のエラーを JARM（fragment.jwt）で求めると、iss・aud・exp の入った JWT で返る",
                    "**エラーは、response_mode に関係なく query の平文で返していた。**"
                    + "**また、Implicit の JARM は aud / exp / iss を入れていなかった**（JARM §2.1 では必須）。"
                    + "**応答の組み立てを 1 か所にまとめ、エラーも response_mode に従うようにした。**",
                    "#294（AccountController.Authorize.cs のレビュー 4・6）/ JARM §2.1 / §2.3");

                r.Target("client_name=" + KnownClients.TestClient_19 + " / response_type=code id_token / response_mode=fragment.jwt / prompt=none");

                AuthZResponse authz = await client.AuthorizeAsync(
                    AuthorizeReviewTests.HybridParameters(reg, "state-rt29419", "none", "fragment.jwt"));

                string response = authz.Get("response");

                r.Verify("**フラグメントに response（JWT）が返る**",
                    authz.Where == ParameterLocation.Fragment && !string.IsNullOrEmpty(response),
                    "Fragment ＋ response", authz.ToString());

                Assert.False(string.IsNullOrEmpty(response), "前提: response が返ること");

                JsonElement payload = Jwt.Payload(response);

                r.VerifyEqual("error は consent_required", "consent_required", Jwt.String(payload, "error") ?? "（無し）");
                r.Verify("**iss が入る**", !string.IsNullOrEmpty(Jwt.String(payload, "iss")), "あり", Jwt.String(payload, "iss") ?? "**無し**");
                r.VerifyEqual("**aud は client_id**", reg.ClientId, Jwt.String(payload, "aud") ?? "（無し）");
                r.Verify("**exp が数値で入る**", Jwt.KindOf(payload, "exp") == JsonValueKind.Number,
                    "Number", Jwt.KindOf(payload, "exp").ToString());

                r.Done();
            }
        }

        /// <summary>RT-294.20 Hybrid に response_mode=query は使えない（invalid_request が返る）</summary>
        /// <param name="targetKey">core / netfx</param>
        /// <returns>Task</returns>
        [SkippableTheory]
        [MemberData(nameof(AllTargets))]
        public async Task RT29420_Hybridにresponse_modeのqueryは使えない(string targetKey)
        {
            using (IdPClient client = await this.SignedInClientAsync(targetKey))
            {
                ClientRegistration reg = Flows.Registration(client, KnownClients.TestClient);

                TestReport r = this.Report("RT-294.20",
                    "Hybrid に response_mode=query は使えない（invalid_request が、フラグメントで返る）",
                    "**トークンを含む応答に query は使わない**（OAuth 2.0 Multiple Response Types §5）。"
                    + "**以前は、発行した後で応答を作れず、`error` が空のまま RP へ返っていた。**",
                    "#294（AccountController.Authorize.cs のレビュー 6）");

                r.Target("client_name=" + KnownClients.TestClient + " / response_type=code id_token / response_mode=query");

                await Flows.EnsureConsentAsync(client, reg);

                AuthZResponse authz = await client.AuthorizeAsync(
                    AuthorizeReviewTests.HybridParameters(reg, "state-rt29420", null, "query"));

                r.VerifyEqual("**invalid_request が返る**（error が空でない）", "invalid_request", authz.Error ?? "（error 無し）");

                r.Verify("**フラグメントで返る**（その response_type の既定の形）",
                    authz.Where == ParameterLocation.Fragment,
                    "Fragment", authz.Where.ToString());

                r.Verify("code も id_token も返さない",
                    string.IsNullOrEmpty(authz.Code) && string.IsNullOrEmpty(authz.Get("id_token")),
                    "返さない", string.IsNullOrEmpty(authz.Code) ? "返さない" : "**返した**");

                r.Done();
            }
        }

        /// <summary>RT-294.21 Request Object と違う client_id を付けると、断る</summary>
        /// <param name="targetKey">core / netfx</param>
        /// <returns>Task</returns>
        [SkippableTheory]
        [MemberData(nameof(AllTargets))]
        public async Task RT29421_RequestObjectと違うclient_idは断る(string targetKey)
        {
            using (IdPClient client = await this.SignedInClientAsync(targetKey))
            {
                ClientRegistration reg = Flows.Registration(client, KnownClients.TestClient);
                ClientRegistration other = Flows.Registration(client, KnownClients.TestClient1);

                TestReport r = this.Report("RT-294.21",
                    "request_uri（PAR）の Request Object と違う client_id を付けると、断る",
                    "**クエリの client_id を、Request Object の値で確かめずに上書きしていた**"
                    + "（RFC 9126 §4 / RFC 9101 §5 は一致を求める）。",
                    "#294（AccountController.Authorize.cs のレビュー 8）");

                r.Target("PAR は " + KnownClients.TestClient + " / 認可要求の client_id は " + KnownClients.TestClient1);

                JsonResponse discovery = await client.GetJsonAsync("/.well-known/openid-configuration");
                string endpoint = discovery.String("pushed_authorization_request_endpoint");

                Skip.If(string.IsNullOrEmpty(endpoint), "PAR の口が広告されていません。");

                r.Step("(1) TestClient で、認可要求を預ける");

                JsonResponse par = await client.PostJsonWithBasicAuthAsync(
                    client.ToLocalUrl(endpoint),
                    AuthorizeReviewTests.CodeParameters(reg, "state-rt29421"),
                    reg.ClientId, reg.ClientSecret);

                string requestUri = par.String("request_uri");

                Assert.False(string.IsNullOrEmpty(requestUri), "前提: request_uri が返ること");

                r.Step("(2) 別のクライアントの client_id と、その request_uri で認可する");

                AuthZResponse authz = await client.AuthorizeAsync(new Dictionary<string, string>()
                {
                    { "client_id", other.ClientId },
                    { "request_uri", requestUri }
                });

                r.Verify("**認可コードは発行されない**",
                    string.IsNullOrEmpty(authz.Code),
                    "code なし", string.IsNullOrEmpty(authz.Code) ? "なし" : "**発行された**");

                r.Verify("**RP へ送らず、エラー画面になる**（どちらの redirect_uri も信じない）",
                    authz.Where == ParameterLocation.None && (authz.Body ?? "").Contains("text-danger"),
                    "エラー画面", authz.ToString());

                r.Done();
            }
        }

        /// <summary>RT-294.22 同意画面のボタンを送らない POST は、invalid_request を返す</summary>
        /// <param name="targetKey">core / netfx</param>
        /// <returns>Task</returns>
        [SkippableTheory]
        [MemberData(nameof(AllTargets))]
        public async Task RT29422_同意画面のボタンが無いPOSTはinvalid_request(string targetKey)
        {
            using (IdPClient client = await this.SignedInClientAsync(targetKey))
            {
                ClientRegistration reg = Flows.InjectedRegistration(client, KnownClients.TestClient_19);

                TestReport r = this.Report("RT-294.22",
                    "同意画面のボタン（許可・拒否・別のアカウント）を送らない POST は、invalid_request を RP へ返す",
                    "**以前は画面を出し直していたが、画面の値（ViewBag）を組まずに返していた。**",
                    "#294（AccountController.Authorize.cs のレビュー 7）");

                r.Target("client_name=" + KnownClients.TestClient_19 + "（同意画面が出る）");

                r.Step("(1) 同意画面を出す");

                AuthZResponse screen = await client.AuthorizeAsync(
                    AuthorizeReviewTests.CodeParameters(reg, "state-rt29422"));

                Assert.True(screen.NeedsConsent, "前提: 同意画面が出ること（" + screen.ToString() + "）");

                r.Step("(2) ボタンを付けずに POST する（トークンだけを送る）");

                HttpResponseMessage post = await client.PostFormAsync(screen.RequestUrl, new Dictionary<string, string>()
                {
                    { "__RequestVerificationToken", Html.Antiforgery(screen.Body) }
                });

                AuthZResponse authz = await IdPClient.ToAuthZResponseAsync(post);

                r.VerifyEqual("**invalid_request を RP へ返す**", "invalid_request", authz.Error ?? "（error 無し: " + authz.ToString() + "）");

                r.VerifyEqual("state がそのまま返る", "state-rt29422", authz.State ?? "（無し）");

                r.Done();
            }
        }

        #region 補助

        /// <summary>code フローの要求</summary>
        /// <param name="reg">クライアント</param>
        /// <param name="state">state</param>
        /// <returns>パラメタ</returns>
        private static Dictionary<string, string> CodeParameters(ClientRegistration reg, string state)
        {
            return new Dictionary<string, string>()
            {
                { "client_id", reg.ClientId },
                { "response_type", "code" },
                { "redirect_uri", reg.RedirectUri },
                { "scope", "openid email" },
                { "state", state },
                { "nonce", "nonce-" + state }
            };
        }

        /// <summary>Hybrid（code id_token）の要求</summary>
        /// <param name="reg">クライアント</param>
        /// <param name="state">state</param>
        /// <param name="prompt">prompt（null なら付けない）</param>
        /// <param name="responseMode">response_mode（null なら付けない）</param>
        /// <returns>パラメタ</returns>
        private static Dictionary<string, string> HybridParameters(
            ClientRegistration reg, string state, string prompt, string responseMode)
        {
            Dictionary<string, string> q = new Dictionary<string, string>()
            {
                { "client_id", reg.ClientId },
                { "response_type", "code id_token" },
                //  **トークンを含む応答は、トークン用の redirect_uri へ返す**（HybridFlowTests と同じ）。
                { "redirect_uri", reg.RedirectUriToken },
                { "scope", "openid" },
                { "state", state },
                { "nonce", "nonce-" + state }
            };

            if (prompt != null) q["prompt"] = prompt;
            if (responseMode != null) q["response_mode"] = responseMode;

            return q;
        }

        #endregion
    }
}
