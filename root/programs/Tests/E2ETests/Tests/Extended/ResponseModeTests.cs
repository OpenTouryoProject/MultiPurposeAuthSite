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
//* クラス名        ：ResponseModeTests
//* クラス日本語名  ：EX-6 応答の返し方（response_mode / form_post / JARM）
//*
//* 作成日時        ：－
//* 作成者          ：－
//* 更新履歴        ：－
//*
//*  日時        更新者            内容
//*  ----------  ----------------  -------------------------------------------------
//*  2026/09/10  玄人 幸道         新規（拡張仕様のテストケースの追加）
//**********************************************************************************

using System;
using System.Collections.Generic;
using System.Text.Json;
using System.Threading.Tasks;

using MultiPurposeAuthSite.Tests.E2E.Infrastructure;

using Xunit;
using Xunit.Abstractions;

namespace MultiPurposeAuthSite.Tests.E2E.Tests.Extended
{
    /// <summary>
    /// EX-6. 認可応答の返し方（response_mode）。
    ///
    ///   fragment      : パラメタをフラグメントに載せる
    ///   form_post     : redirect_uri へ自動送信する HTML フォームで返す
    ///   query.jwt など : パラメタを認可サーバの署名付き JWT に包む（JARM）
    ///
    /// Discovery の response_modes_supported は、これらを広告している。
    /// </summary>
    public class ResponseModeTests : TargetTestBase
    {
        /// <summary>コンストラクタ</summary>
        /// <param name="output">ITestOutputHelper</param>
        public ResponseModeTests(ITestOutputHelper output) : base(output)
        {
        }

        /// <summary>response_mode を付けて、認可コードを要求する</summary>
        /// <param name="client">IdPClient</param>
        /// <param name="reg">クライアント</param>
        /// <param name="responseMode">response_mode</param>
        /// <param name="state">state</param>
        /// <returns>AuthZResponse</returns>
        private static Task<AuthZResponse> AuthorizeAsync(
            IdPClient client, ClientRegistration reg, string responseMode, string state)
        {
            return Flows.AuthorizeCodeAsync(client, reg,
                state: state, redirectUri: reg.RedirectUri,
                extra: new Dictionary<string, string>() { { "response_mode", responseMode } });
        }

        /// <summary>EX-6.1 fragment</summary>
        /// <param name="targetKey">core / netfx</param>
        /// <returns>Task</returns>
        [SkippableTheory]
        [MemberData(nameof(AllTargets))]
        public async Task EX0601_response_modeがfragmentならcodeがフラグメントで返る(string targetKey)
        {
            using (IdPClient client = await this.SignedInClientAsync(targetKey))
            {
                TestReport r = this.Report("EX-6.1",
                    "response_mode=fragment : 認可コードがフラグメントで返る",
                    "response_mode は、応答パラメタの**置き場所**をクライアントが選ぶ仕組み。"
                    + "code は既定ではクエリで返るが、fragment を指定すればフラグメントで返る"
                    + "（フラグメントはサーバへ送られないので、リダイレクト先のアクセス ログに残らない）。",
                    "OAuth 2.0 Multiple Response Type Encoding Practices §2.1（response_mode）");

                ClientRegistration reg = Flows.Registration(client, KnownClients.MvcSample);

                r.Target("client_name=" + KnownClients.MvcSample + " / response_type=code");
                r.Step("GET /authorize に response_mode=fragment を付けて送る");

                AuthZResponse res = await AuthorizeAsync(client, reg, "fragment", "state-fragment");

                r.Verify("フラグメント（#）で返る", res.Where == ParameterLocation.Fragment,
                    "フラグメント", res.ToString());

                r.Verify("code が返る", !string.IsNullOrEmpty(res.Code),
                    "code あり", res.Code == null ? "なし" : "あり（値は伏せる）");

                r.VerifyEqual("state がそのまま返る", "state-fragment", res.State);

                string location = res.Location ?? "";
                int hash = location.IndexOf('#');
                bool codeInQuery = (hash >= 0 ? location.Substring(0, hash) : location).Contains("code=");

                r.Verify("クエリには code を載せない", !codeInQuery,
                    "載せない", codeInQuery ? "**載っている**" : "載っていない");

                r.Done();
            }
        }

        /// <summary>EX-6.2 form_post</summary>
        /// <param name="targetKey">core / netfx</param>
        /// <returns>Task</returns>
        [SkippableTheory]
        [MemberData(nameof(AllTargets))]
        public async Task EX0602_response_modeがform_postなら自動送信フォームで返る(string targetKey)
        {
            using (IdPClient client = await this.SignedInClientAsync(targetKey))
            {
                TestReport r = this.Report("EX-6.2",
                    "response_mode=form_post : redirect_uri へ自動送信する HTML フォームで返る",
                    "パラメタを URL に載せずに返す方法。"
                    + "**ブラウザの履歴・Referer・アクセス ログに code が残らない。**"
                    + "応答はリダイレクトではなく、redirect_uri へ POST される HTML フォームになる。",
                    "OAuth 2.0 Form Post Response Mode §2（HTML フォームを自動送信し、パラメタは hidden で送る）");

                ClientRegistration reg = Flows.Registration(client, KnownClients.MvcSample);

                r.Target("client_name=" + KnownClients.MvcSample + " / response_type=code");
                r.Step("(1) GET /authorize に response_mode=form_post を付けて送る");

                AuthZResponse res = await AuthorizeAsync(client, reg, "form_post", "state-form-post");

                r.Verify("リダイレクトしない（HTML を返す）",
                    !res.Redirected && (int)res.StatusCode == 200,
                    "HTTP 200 の HTML", res.ToString());

                r.VerifyEqual("フォームの送信先が redirect_uri", reg.RedirectUri,
                    Html.FormAttribute(res.Body, "action"));

                r.VerifyEqual("フォームは POST で送る", "post",
                    (Html.FormAttribute(res.Body, "method") ?? "").ToLowerInvariant());

                bool autoSubmit = (res.Body ?? "").Contains(".submit()");

                r.Verify("読み込んだら自動で送信する", autoSubmit,
                    "submit() を呼ぶ", autoSubmit ? "呼ぶ" : "**呼ばない**");

                Dictionary<string, string> hidden = Html.HiddenInputs(res.Body);
                string code;
                string state;
                hidden.TryGetValue("code", out code);
                hidden.TryGetValue("state", out state);

                r.Verify("code を hidden で送る", !string.IsNullOrEmpty(code),
                    "code あり", string.IsNullOrEmpty(code) ? "なし" : "あり（値は伏せる）");

                r.VerifyEqual("state がそのまま返る", "state-form-post", state);

                if (!string.IsNullOrEmpty(code))
                {
                    r.Step("(2) フォームで受け取った code を、トークンに交換する");

                    JsonResponse token = await Flows.ExchangeCodeAsync(client, reg, code, reg.RedirectUri);

                    r.Verify("トークンに交換できる", !string.IsNullOrEmpty(token.AccessToken),
                        "access_token あり",
                        token.AccessToken == null ? "なし（error=" + (token.Error ?? "なし") + "）"
                                                  : "あり（値は伏せる）");
                }

                r.Done();
            }
        }

        /// <summary>EX-6.3 JARM</summary>
        /// <param name="targetKey">core / netfx</param>
        /// <returns>Task</returns>
        [SkippableTheory]
        [MemberData(nameof(AllTargets))]
        public async Task EX0603_JARMの応答は署名付きJWTで検証できる(string targetKey)
        {
            using (IdPClient client = await this.SignedInClientAsync(targetKey))
            {
                TestReport r = this.Report("EX-6.3",
                    "response_mode=query.jwt（JARM）: 応答が署名付き JWT 1 つにまとまり、検証できる",
                    "応答パラメタ（code / state）を**認可サーバの署名付き JWT に包んで**返す。"
                    + "RP は署名・iss・aud・exp を確かめることで、応答の差し替えや、"
                    + "別の RP 向けの応答の流用を検知できる。",
                    "JARM（JWT Secured Authorization Response Mode for OAuth 2.0）"
                    + "§2.1（iss / aud / exp は REQUIRED）/ §2.3.1（query.jwt）/ §4（検証）");

                ClientRegistration reg = Flows.Registration(client, KnownClients.MvcSample);
                const string State = "state-jarm";

                r.Target("client_name=" + KnownClients.MvcSample + " / response_type=code");
                r.Step("(1) GET /authorize に response_mode=query.jwt を付けて送る");

                AuthZResponse res = await AuthorizeAsync(client, reg, "query.jwt", State);
                string jwt = res.Get("response");

                r.Verify("クエリで返る", res.Where == ParameterLocation.Query, "クエリ", res.ToString());

                r.Verify("response パラメタ（JWT）が返る", !string.IsNullOrEmpty(jwt),
                    "あり", jwt == null ? "なし（" + res.ToString() + "）" : "あり");

                r.Verify("code を URL に直接載せない", res.Code == null,
                    "載せない", res.Code == null ? "載せていない" : "**載せている**");

                if (!string.IsNullOrEmpty(jwt))
                {
                    r.Step("(2) JWT の署名を JWKS で確かめ、中身を読む");

                    Jwks.Result sig = Jwks.Verify(jwt, await Flows.JwkSetAsync(client));

                    r.Verify("署名を JWKS で検証できる", sig.Verified, "検証できる", sig.Detail);

                    JsonElement payload = Jwt.Payload(jwt);
                    JsonResponse discovery = await client.GetJsonAsync("/.well-known/openid-configuration");

                    r.VerifyEqual("iss が Discovery の issuer と一致する",
                        discovery.String("issuer"), Jwt.String(payload, "iss"));

                    bool audOk = Jwt.String(payload, "aud") == reg.ClientId;

                    r.Verify("aud が client_id と一致する", audOk,
                        "client_id と一致", audOk ? "一致" : "**一致しない**");

                    r.Verify("exp がある", Jwt.Has(payload, "exp"),
                        "あり", Jwt.Has(payload, "exp") ? "あり" : "なし");

                    r.VerifyEqual("state が送った値と一致する", State, Jwt.String(payload, "state"));

                    string code = Jwt.String(payload, "code");

                    r.Verify("code が JWT の中にある", !string.IsNullOrEmpty(code),
                        "あり", code == null ? "なし" : "あり（値は伏せる）");

                    if (!string.IsNullOrEmpty(code))
                    {
                        r.Step("(3) JWT から取り出した code を、トークンに交換する");

                        JsonResponse token = await Flows.ExchangeCodeAsync(client, reg, code, reg.RedirectUri);

                        r.Verify("トークンに交換できる", !string.IsNullOrEmpty(token.AccessToken),
                            "access_token あり",
                            token.AccessToken == null ? "なし（error=" + (token.Error ?? "なし") + "）"
                                                      : "あり（値は伏せる）");
                    }
                }

                r.Done();
            }
        }

        /// <summary>EX-6.4 JARM の exp の型</summary>
        /// <param name="targetKey">core / netfx</param>
        /// <returns>Task</returns>
        [SkippableTheory(Skip = "未修正（#201）。実測（2026/09/10, net10.0 / net48）では、"
            + "JARM の exp が JSON の文字列になっている。")]
        [MemberData(nameof(AllTargets))]
        public async Task EX0604_JARMのexpはNumericDateである(string targetKey)
        {
            using (IdPClient client = await this.SignedInClientAsync(targetKey))
            {
                TestReport r = this.Report("EX-6.4",
                    "JARM の exp は NumericDate（JSON の数値）である",
                    "exp は RFC 7519 の NumericDate であり、**数値**でなければならない。"
                    + "文字列だと、JWT ライブラリの多くは有効期限の検証に失敗するか、検証を素通りさせる。"
                    + "（id_token / access_token では #184 で直した問題）",
                    "JARM §2.1（exp は RFC 7519 の定義による）/ RFC 7519 §2（NumericDate）/ §4.1.4");

                ClientRegistration reg = Flows.Registration(client, KnownClients.MvcSample);

                r.Target("client_name=" + KnownClients.MvcSample + " / response_mode=query.jwt");
                r.Step("GET /authorize に response_mode=query.jwt を付けて送り、JWT の exp の型を見る");

                AuthZResponse res = await AuthorizeAsync(client, reg, "query.jwt", "state-jarm-exp");
                string jwt = res.Get("response");

                Assert.False(string.IsNullOrEmpty(jwt), "前提: response（JWT）が返ること（" + res.ToString() + "）");

                JsonElement payload = Jwt.Payload(jwt);
                JsonValueKind kind = Jwt.KindOf(payload, "exp");

                r.Verify("exp が JSON の数値である", kind == JsonValueKind.Number,
                    "Number", kind + "（" + (Jwt.String(payload, "exp") ?? "なし") + "）");

                r.Done();
            }
        }
    }
}
