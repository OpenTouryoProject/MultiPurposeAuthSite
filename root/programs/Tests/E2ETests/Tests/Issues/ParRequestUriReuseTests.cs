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
//* クラス名        ：ParRequestUriReuseTests
//* クラス日本語名  ：RT-413 PAR の request_uri を、認可を終える前に使い回す
//*
//* 作成日時        ：－
//* 作成者          ：－
//* 更新履歴        ：－
//*
//*  日時        更新者            内容
//*  ----------  ----------------  -------------------------------------------------
//*  2026/11/21  玄人 幸道         新規（#413）
//*  2026/11/21  玄人 幸道         RT-413.2 の拒否の後の返り方を検証に上げ、RT-420.1〜.3 を足した（#420）
//**********************************************************************************

using System;
using System.Collections.Generic;
using System.Net.Http;
using System.Threading.Tasks;

using MultiPurposeAuthSite.Tests.E2E.Infrastructure;

using Xunit;
using Xunit.Abstractions;

namespace MultiPurposeAuthSite.Tests.E2E.Tests.Issues
{
    /// <summary>
    /// RT-413 PAR の request_uri を、認可を終える前に使い回す（#413）。
    /// RT-420 redirect_uri へエラーを返した後の request_uri（#420）。
    /// </summary>
    /// <remarks>
    /// **預けた要求は、認可の応答を作り終えた時点で消す**（`CmnEndpoints.AuthorizeResponse`。#188 の段階 2）。
    /// **#420 から、`redirect_uri` へエラーを返した時点（拒否・`prompt=none` のエラーなど）でも消す。**
    /// **それまで（サインインの画面へ送る・RP へ返さないエラー画面）は、何度読んでも消えない。**
    /// **E2E は、認可要求の前にサインインしておく**ので、**サインインの前に始まる PAR の認可**は、ほかのテストでは通っていない。
    /// 適合性テストの `par-ensure-reused-request-uri-prior-to-auth-completion-succeeds` は同じ観点だが、
    /// **ブラウザの操作が 1 回目と 2 回目の訪問を区別できず、自動では回せない**（`container/CTS/README.md`）。ここで補う。
    /// **クライアントは `TestClient`（client_secret_basic）にした。** 預ける・読む・消す処理は、登録の種別を問わず同じである。
    /// </remarks>
    public class ParRequestUriReuseTests : TargetTestBase
    {
        /// <summary>コンストラクタ</summary>
        /// <param name="output">ITestOutputHelper</param>
        public ParRequestUriReuseTests(ITestOutputHelper output) : base(output)
        {
        }

        /// <summary>RT-413.1 サインインの前に同じ request_uri を 2 回送り、2 回目でサインインすると認可できる</summary>
        /// <param name="targetKey">core / netfx</param>
        /// <returns>Task</returns>
        [SkippableTheory]
        [MemberData(nameof(AllTargets))]
        public async Task RT41301_サインインの前に使い回したrequest_uriで認可できる(string targetKey)
        {
            using (IdPClient client = this.Client(targetKey))
            {
                ClientRegistration reg = Flows.Registration(client, KnownClients.TestClient);

                TestReport r = this.Report("RT-413.1",
                    "PAR の request_uri の認可要求を、サインインしないまま 2 回送り、2 回目でサインインすると、認可コードが返ってトークンに引き換えられる。その後は同じ request_uri を使えない",
                    "**request_uri の使い切りは、認可を終えた時点で効かせる。** サインインの画面を出しただけで使い切りにすると、"
                    + "**利用者がサインインの画面を開き直したり、ブラウザが URL を先読みしたりしただけで、認可できなくなる。**"
                    + "**一方で、認可を終えた後は使えない**（RT-188.4 と同じ）。",
                    "FAPI 2.0 Security Profile §5.3.2.2 NOTE 3 / RFC 9126 §4 / #413");

                r.Target(client.Target.DisplayName + " / client_name=" + KnownClients.TestClient + " / **サインインしていない**クライアント");

                r.Step("(1) PAR に認可要求を預け、request_uri を受け取る");

                string requestUri = await ParRequestUriReuseTests.PushAsync(client, reg, "state-rt4131");

                r.Step("(2) サインインしないまま、その request_uri で認可要求を送り、サインインの画面を開く（サインインはしない）");

                AuthZResponse first = await ParRequestUriReuseTests.AuthorizeAsync(client, reg, requestUri);

                ParRequestUriReuseTests.VerifyToSignIn(r, "1 回目", first);

                HttpResponseMessage signInPage = await client.GetAsync(first.Location);
                string signInHtml = await signInPage.Content.ReadAsStringAsync();

                r.Verify("1 回目 : サインインの画面が開く", Html.HasField(signInHtml, "Password"),
                    "パスワードの欄がある画面", "HTTP " + (int)signInPage.StatusCode + " / " + Html.Describe(signInHtml));

                r.Step("(3) 同じ request_uri で認可要求をもう一度送り、今度はサインインの画面からサインインする（ReturnUrl で認可要求へ戻る）");

                AuthZResponse second = await ParRequestUriReuseTests.AuthorizeAsync(client, reg, requestUri);

                ParRequestUriReuseTests.VerifyToSignIn(r, "2 回目", second);

                Assert.True(second.Redirected, "前提: 2 回目もサインインの画面へ送られること（" + second.ToString() + "）");

                string back = await client.SignInViaSignInPageAsync(second);

                r.Verify("サインインの後、預けた要求の認可要求へ戻る", back.Contains("request_uri="),
                    "request_uri を持つ認可要求へ戻る", back.Split('?')[0]);

                AuthZResponse authz = await IdPClient.ToAuthZResponseAsync(await client.GetAsync(back));

                r.Verify("同意の画面が出る（prompt=consent を預けた）", authz.NeedsConsent,
                    "同意の画面", authz.NeedsConsent ? "出た" : "**出なかった**（" + authz.ToString() + "）");

                Assert.True(authz.NeedsConsent, "前提: 同意の画面が出ること");

                AuthZResponse granted = await client.GrantConsentAsync(authz);

                r.Verify("認可コードが返る", !string.IsNullOrEmpty(granted.Code),
                    "code あり",
                    string.IsNullOrEmpty(granted.Code)
                        ? "**無し**（error=" + (granted.Error ?? "なし") + "）" : "あり（値は伏せる）");

                r.VerifyEqual("預けた state が返る", "state-rt4131", granted.State ?? "（無し）");

                Assert.False(string.IsNullOrEmpty(granted.Code), "前提: 認可コードが返ること");

                r.Step("(4) 認可コードをトークンに引き換える");

                JsonResponse token = await Flows.ExchangeCodeAsync(client, reg, granted.Code, reg.RedirectUri);

                r.VerifyEqual("トークンの応答 : HTTP 200", "200", ((int)token.StatusCode).ToString());

                r.Verify("access_token が返る", !string.IsNullOrEmpty(token.AccessToken),
                    "access_token あり",
                    string.IsNullOrEmpty(token.AccessToken)
                        ? "**無し**（error=" + (token.Error ?? "なし") + "）" : "あり（値は伏せる）");

                r.Step("(5) 認可を終えた後に、同じ request_uri をもう一度送る");

                AuthZResponse after = await ParRequestUriReuseTests.AuthorizeAsync(client, reg, requestUri);

                r.Verify("認可を終えた後は、認可コードを返さない", string.IsNullOrEmpty(after.Code),
                    "code 無し", string.IsNullOrEmpty(after.Code) ? "無し" : "**返してしまった**");

                r.Observe("認可を終えた後の返り方",
                    ParRequestUriReuseTests.Describe(after),
                    "消した後は「存在しない request_uri」と同じ扱いになる（RT-362.3）。返し方は記録するだけで、判定しない。");

                r.Done();
            }
        }

        /// <summary>RT-413.2 PAR の要求を同意の画面で拒否すると access_denied。その後の request_uri の扱いを残す</summary>
        /// <param name="targetKey">core / netfx</param>
        /// <returns>Task</returns>
        [SkippableTheory]
        [MemberData(nameof(AllTargets))]
        public async Task RT41302_PARの要求を拒否するとaccess_denied(string targetKey)
        {
            using (IdPClient client = await this.SignedInClientAsync(targetKey))
            {
                ClientRegistration reg = Flows.Registration(client, KnownClients.TestClient);

                TestReport r = this.Report("RT-413.2",
                    "PAR に預けた要求を同意の画面で拒否すると、redirect_uri へ access_denied を返す。その後に同じ request_uri を送ると、invalid_request_uri のエラー画面になる",
                    "**PAR で預けた要求でも、拒否は access_denied で返す**（RT-272.6 は、預けない要求で測っている）。"
                    + "**拒否も認可の結果なので、RP へ返した時点で request_uri を使い切る**（#420）。"
                    + "**以前は成功の応答を作ったときだけ消しており、拒否の後も、期限まで同じ request_uri でやり直せた**（#413 で観測した）。",
                    "RFC 6749 §4.1.2.1（access_denied）/ RFC 9126 §4・§7.3 / #413 / #420");

                r.Target(client.Target.DisplayName + " / client_name=" + KnownClients.TestClient + " / prompt=consent を預けて同意の画面を出す");

                r.Step("(1) PAR に認可要求を預け、request_uri を受け取る");

                string requestUri = await ParRequestUriReuseTests.PushAsync(client, reg, "state-rt4132");

                r.Step("(2) その request_uri で認可要求を送り、同意の画面で「拒否」を押す");

                AuthZResponse authz = await ParRequestUriReuseTests.AuthorizeAsync(client, reg, requestUri);

                r.Verify("同意の画面が出る", authz.NeedsConsent,
                    "同意の画面", authz.NeedsConsent ? "出た" : "**出なかった**（" + authz.ToString() + "）");

                Assert.True(authz.NeedsConsent, "前提: 同意の画面が出ること");

                AuthZResponse denied = await client.DenyConsentAsync(authz);

                r.Verify("リダイレクトで返る", denied.Redirected,
                    "リダイレクトする",
                    denied.Redirected ? denied.RedirectTo : "**リダイレクトしない**（" + denied.ToString() + "）");

                r.VerifyEqual("エラーは access_denied", "access_denied", denied.Error ?? "（無し）");

                r.VerifyEqual("預けた state が返る", "state-rt4132", denied.State ?? "（無し）");

                r.Verify("認可コードは発行されない", string.IsNullOrEmpty(denied.Code),
                    "code なし", string.IsNullOrEmpty(denied.Code) ? "なし" : "**発行された**");

                r.Step("(3) 拒否した後に、同じ request_uri をもう一度送る");

                AuthZResponse again = await ParRequestUriReuseTests.AuthorizeAsync(client, reg, requestUri);

                ParRequestUriReuseTests.VerifyRefused(r, "拒否した後", again);

                r.Done();
            }
        }

        /// <summary>RT-420.1 redirect_uri へエラー（login_required）を返した後は、同じ request_uri を使えない</summary>
        /// <param name="targetKey">core / netfx</param>
        /// <returns>Task</returns>
        [SkippableTheory]
        [MemberData(nameof(AllTargets))]
        public async Task RT42001_エラーを返した後のrequest_uriは使えない(string targetKey)
        {
            using (IdPClient client = this.Client(targetKey))
            {
                ClientRegistration reg = Flows.Registration(client, KnownClients.TestClient);

                TestReport r = this.Report("RT-420.1",
                    "PAR に prompt=none を預け、サインインしていない状態で認可要求を送ると、redirect_uri へ login_required を返す。その後に同じ request_uri を送ると、invalid_request_uri のエラー画面になる",
                    "**拒否に限らず、redirect_uri へエラーを返した時点で、その認可は終わっている**ので、request_uri を使い切る。"
                    + "**RP がやり直すなら、預け直す**（クライアントは request_uri を 1 回だけ使う。RFC 9126 §4 の MUST）。",
                    "RFC 9126 §4・§7.3 / FAPI 2.0 Security Profile §5.3.2.2 NOTE 3 / OIDC Core 1.0 §3.1.2.6（login_required）/ #420");

                r.Target(client.Target.DisplayName + " / client_name=" + KnownClients.TestClient + " / **サインインしていない**クライアント / prompt=none を預ける");

                r.Step("(1) PAR に prompt=none の認可要求を預け、request_uri を受け取る");

                string requestUri = await ParRequestUriReuseTests.PushAsync(client, reg, "state-rt4201", "none");

                r.Step("(2) サインインしないまま、その request_uri で認可要求を送る");

                AuthZResponse first = await ParRequestUriReuseTests.AuthorizeAsync(client, reg, requestUri);

                r.Verify("redirect_uri へ返る", first.Redirected && (first.Location ?? "").StartsWith(reg.RedirectUri, StringComparison.Ordinal),
                    "redirect_uri へのリダイレクト", ParRequestUriReuseTests.Describe(first));

                r.VerifyEqual("エラーは login_required", "login_required", first.Error ?? "（無し）");

                r.Step("(3) 同じ request_uri をもう一度送る");

                AuthZResponse again = await ParRequestUriReuseTests.AuthorizeAsync(client, reg, requestUri);

                ParRequestUriReuseTests.VerifyRefused(r, "エラーを返した後", again);

                r.Done();
            }
        }

        /// <summary>RT-420.3 /ros で預けた request_uri も、redirect_uri へエラーを返した後は使えない</summary>
        /// <param name="targetKey">core / netfx</param>
        /// <returns>Task</returns>
        [SkippableTheory]
        [MemberData(nameof(AllTargets))]
        public async Task RT42003_rosで預けたrequest_uriもエラーの後は使えない(string targetKey)
        {
            using (IdPClient client = this.Client(targetKey))
            {
                ClientRegistration reg = Flows.Registration(client, KnownClients.TestClient);

                TestReport r = this.Report("RT-420.3",
                    "/ros に prompt=none の Request Object を預け、サインインしていない状態で認可要求を送ると、redirect_uri へ login_required を返す。その後に同じ request_uri を送ると、invalid_request_uri のエラー画面になる",
                    "**`/ros`（この OP の独自の口）で預けた request_uri も、PAR と同じ預け先・同じ消し方**なので、エラーを返した時点で使い切る（#420）。",
                    "RFC 9126 §4・§7.3 / RFC 9101 §5.2 / #420");

                r.Target(client.Target.DisplayName + " / client_name=" + KnownClients.TestClient + " / **サインインしていない**クライアント / /ros に prompt=none を預ける");

                r.Step("(1) /ros に prompt=none の Request Object を預け、request_uri を受け取る");

                string requestUri = await RequestObjectBuilder.RegisterAsync(client,
                    await RequestObjectBuilder.CreateAsync(client, reg.ClientId,
                        new Dictionary<string, object>()
                        {
                            { "response_type", "code" },
                            { "redirect_uri", reg.RedirectUri },
                            { "scope", "openid" },
                            { "state", "state-rt4203" },
                            { "nonce", "nonce-rt4203" },
                            { "prompt", "none" }
                        })) ?? "";

                Assert.False(string.IsNullOrEmpty(requestUri), "前提: request_uri が払い出されること");

                r.Step("(2) サインインしないまま、その request_uri で認可要求を送る");

                AuthZResponse first = await ParRequestUriReuseTests.AuthorizeAsync(client, reg, requestUri);

                r.Verify("redirect_uri へ返る", first.Redirected && (first.Location ?? "").StartsWith(reg.RedirectUri, StringComparison.Ordinal),
                    "redirect_uri へのリダイレクト", ParRequestUriReuseTests.Describe(first));

                r.VerifyEqual("エラーは login_required", "login_required", first.Error ?? "（無し）");

                r.Step("(3) 同じ request_uri をもう一度送る");

                AuthZResponse again = await ParRequestUriReuseTests.AuthorizeAsync(client, reg, requestUri);

                ParRequestUriReuseTests.VerifyRefused(r, "エラーを返した後", again);

                r.Done();
            }
        }

        /// <summary>RT-420.2 エラー画面で止めたときは、request_uri を消さない</summary>
        /// <param name="targetKey">core / netfx</param>
        /// <returns>Task</returns>
        [SkippableTheory]
        [MemberData(nameof(AllTargets))]
        public async Task RT42002_エラー画面で止めたときはrequest_uriを消さない(string targetKey)
        {
            using (IdPClient client = await this.SignedInClientAsync(targetKey))
            {
                ClientRegistration reg = Flows.Registration(client, KnownClients.TestClient);
                ClientRegistration other = Flows.Registration(client, KnownClients.Fapi1Client);

                TestReport r = this.Report("RT-420.2",
                    "PAR に預けた要求の request_uri を、別のクライアントの client_id で送るとエラー画面になるが、request_uri は消えず、正しい client_id で送り直すと認可を続けられる",
                    "**エラー画面で止めるときは、RP へ何も返していない**（どちらの redirect_uri も信じない。RT-294.21）。"
                    + "**ここで消すと、要求を取り違えただけで、正しいクライアントの認可まで終わってしまう。**"
                    + "**消すのは、redirect_uri へ結果を返したときだけ**（#420）。",
                    "RFC 9126 §4 / #420");

                r.Target("PAR は " + KnownClients.TestClient + " / 1 回目の client_id は " + KnownClients.Fapi1Client);

                r.Step("(1) PAR に認可要求を預け、request_uri を受け取る");

                string requestUri = await ParRequestUriReuseTests.PushAsync(client, reg, "state-rt4202");

                r.Step("(2) 別のクライアントの client_id と、その request_uri で認可要求を送る");

                AuthZResponse mismatch = await client.AuthorizeAsync(new Dictionary<string, string>()
                {
                    { "client_id", other.ClientId },
                    { "request_uri", requestUri }
                });

                r.Verify("エラー画面になる（RP へ返さない）",
                    !mismatch.Redirected && (mismatch.Body ?? "").Contains("text-danger"),
                    "エラー画面", ParRequestUriReuseTests.Describe(mismatch));

                r.Step("(3) 正しい client_id で、同じ request_uri をもう一度送る");

                AuthZResponse again = await ParRequestUriReuseTests.AuthorizeAsync(client, reg, requestUri);

                r.Verify("同意の画面が出る（request_uri は消えていない）", again.NeedsConsent,
                    "同意の画面", ParRequestUriReuseTests.Describe(again));

                r.Done();
            }
        }

        #region 補助

        /// <summary>PAR に認可要求を預け、request_uri を返す（既定は prompt=consent で同意の画面を出させる）</summary>
        /// <param name="client">IdPClient</param>
        /// <param name="reg">クライアント</param>
        /// <param name="state">state</param>
        /// <param name="prompt">prompt</param>
        /// <returns>request_uri</returns>
        private static async Task<string> PushAsync(IdPClient client, ClientRegistration reg, string state, string prompt = "consent")
        {
            JsonResponse discovery = await client.GetJsonAsync("/.well-known/openid-configuration");
            string endpoint = discovery.String("pushed_authorization_request_endpoint");

            Assert.False(string.IsNullOrEmpty(endpoint), "前提: PAR の口が広告されていること");

            JsonResponse par = await client.PostJsonWithBasicAuthAsync(
                client.ToLocalUrl(endpoint),
                new Dictionary<string, string>()
                {
                    { "response_type", "code" },
                    { "redirect_uri", reg.RedirectUri },
                    { "scope", "openid email" },
                    { "state", state },
                    { "nonce", "nonce-" + state },
                    //  **既定は、同意の記録があっても同意の画面を出させる**（許可・拒否を自分で押すため）。
                    { "prompt", prompt }
                },
                reg.ClientId, reg.ClientSecret);

            string requestUri = par.String("request_uri");

            Assert.False(string.IsNullOrEmpty(requestUri),
                "前提: request_uri が返ること（HTTP " + (int)par.StatusCode + " / error=" + (par.Error ?? "なし") + "）");

            return requestUri;
        }

        /// <summary>request_uri だけで認可要求を送る（同意の画面が出ても押さない）</summary>
        /// <param name="client">IdPClient</param>
        /// <param name="reg">クライアント</param>
        /// <param name="requestUri">request_uri</param>
        /// <returns>AuthZResponse</returns>
        private static Task<AuthZResponse> AuthorizeAsync(IdPClient client, ClientRegistration reg, string requestUri)
        {
            return client.AuthorizeAsync(new Dictionary<string, string>()
            {
                { "client_id", reg.ClientId },
                { "request_uri", requestUri }
            });
        }

        /// <summary>サインインの画面へ送られたこと（request_uri を断っていないこと）を確かめる</summary>
        /// <param name="r">TestReport</param>
        /// <param name="label">何回目か</param>
        /// <param name="res">AuthZResponse</param>
        private static void VerifyToSignIn(TestReport r, string label, AuthZResponse res)
        {
            string to = res.Location ?? "";

            r.Verify(label + " : サインインの画面へ送られる（request_uri を断らない）",
                to.IndexOf("/Account/Login", StringComparison.OrdinalIgnoreCase) >= 0,
                "/Account/Login へのリダイレクト",
                string.IsNullOrEmpty(to) ? "**リダイレクトしない**（" + ParRequestUriReuseTests.Describe(res) + "）" : to.Split('?')[0]);

            r.Verify(label + " : 認可コードもエラーも返さない", string.IsNullOrEmpty(res.Code) && string.IsNullOrEmpty(res.Error),
                "code・error 無し",
                "code=" + (string.IsNullOrEmpty(res.Code) ? "無し" : "あり") + " / error=" + (res.Error ?? "無し"));
        }

        /// <summary>使い切った request_uri を、invalid_request_uri のエラー画面で断ったことを確かめる（RT-362.3 と同じ判定）</summary>
        /// <param name="r">TestReport</param>
        /// <param name="label">いつの要求か</param>
        /// <param name="res">AuthZResponse</param>
        private static void VerifyRefused(TestReport r, string label, AuthZResponse res)
        {
            r.Verify(label + " : 認可コードを返さない", string.IsNullOrEmpty(res.Code),
                "code 無し", string.IsNullOrEmpty(res.Code) ? "無し" : "**返してしまった**");

            r.Verify(label + " : 同意の画面を出さない（request_uri を使い切っている）", !res.NeedsConsent,
                "同意の画面を出さない", ParRequestUriReuseTests.Describe(res));

            r.Verify(label + " : invalid_request_uri のエラー画面になる（RP へ返さない）",
                !res.Redirected && (res.Body ?? "").Contains("text-danger") && (res.Body ?? "").Contains("invalid_request_uri"),
                "エラー画面（invalid_request_uri）", ParRequestUriReuseTests.Describe(res));
        }

        /// <summary>返り方を 1 行にする（値は伏せる）</summary>
        /// <param name="res">AuthZResponse</param>
        /// <returns>説明</returns>
        private static string Describe(AuthZResponse res)
        {
            if (res.NeedsConsent)
            {
                return "HTTP " + (int)res.StatusCode + " / 同意の画面（まだ使える）";
            }

            if (res.Redirected)
            {
                return "HTTP " + (int)res.StatusCode + " / " + res.Location.Split('?')[0]
                    + " / code=" + (string.IsNullOrEmpty(res.Code) ? "無し" : "あり")
                    + " / error=" + (res.Error ?? "無し");
            }

            return "HTTP " + (int)res.StatusCode + " / " + Html.Describe(res.Body);
        }

        #endregion
    }
}
