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
//* クラス名        ：AuthorizationCodeFlowTests
//* クラス日本語名  ：TC-2 認可コード フロー
//*
//* 作成日時        ：－
//* 作成者          ：－
//* 更新履歴        ：－
//*
//*  日時        更新者            内容
//*  ----------  ----------------  -------------------------------------------------
//*  2026/09/09  玄人 幸道         新規（基本テストケースの追加）
//**********************************************************************************

using System.Collections.Generic;
using System.Threading.Tasks;

using MultiPurposeAuthSite.Tests.E2E.Infrastructure;

using Xunit;
using Xunit.Abstractions;

namespace MultiPurposeAuthSite.Tests.E2E.Tests.Basic
{
    /// <summary>
    /// TC-2. 認可コード フロー（Authorization Code Grant）。
    /// </summary>
    public class AuthorizationCodeFlowTests : TargetTestBase
    {
        /// <summary>コンストラクタ</summary>
        /// <param name="output">ITestOutputHelper</param>
        public AuthorizationCodeFlowTests(ITestOutputHelper output) : base(output)
        {
        }

        /// <summary>TC-2.1 正常系</summary>
        /// <param name="targetKey">core / netfx</param>
        /// <returns>Task</returns>
        [SkippableTheory]
        [MemberData(nameof(AllTargets))]
        public async Task TC0201_認可コードからトークンを取得できる(string targetKey)
        {
            using (IdPClient client = await this.SignedInClientAsync(targetKey))
            {
                TestReport r = this.Report("TC-2.1",
                    "認可コードを取得し、トークンに交換できる",
                    "認可エンドポイントで code を得て、トークン エンドポイントで "
                    + "access_token（と refresh_token）に交換できること。フローの骨格。",
                    "RFC 6749 §4.1（Authorization Code Grant）");

                ClientRegistration reg = Flows.Registration(client, KnownClients.MvcSample);

                r.Target("client_name=" + KnownClients.MvcSample + "（コンフィデンシャル）");
                r.Step("(1) GET /authorize?response_type=code&scope=openid email …（サインイン済み）");

                AuthZResponse authz = await Flows.AuthorizeCodeAsync(
                    client, reg, redirectUri: reg.RedirectUri);

                r.Verify("認可コードが発行される", !string.IsNullOrEmpty(authz.Code),
                    "code が返る",
                    string.IsNullOrEmpty(authz.Code) ? "code なし（" + authz.ToString() + "）" : "code あり");

                r.Verify("認可コードはクエリ文字列で返る",
                    authz.Where == ParameterLocation.Query,
                    "クエリ（?）で返す", "返却位置 = " + authz.Where);

                r.Step("(2) POST /token に grant_type=authorization_code と code を送る");

                JsonResponse token = await Flows.ExchangeCodeAsync(
                    client, reg, authz.Code, reg.RedirectUri);

                r.Verify("エラーにならない", string.IsNullOrEmpty(token.Error),
                    "error なし", token.Error ?? "error なし");

                r.Verify("access_token が返る", !string.IsNullOrEmpty(token.AccessToken),
                    "access_token あり", token.AccessToken == null ? "なし" : "あり（値は伏せる）");

                r.Verify("refresh_token が返る", !string.IsNullOrEmpty(token.RefreshToken),
                    "refresh_token あり", token.RefreshToken == null ? "なし" : "あり（値は伏せる）");

                r.Verify("token_type が Bearer である",
                    string.Equals(token.String("token_type"), "Bearer",
                        System.StringComparison.OrdinalIgnoreCase),
                    "Bearer", "token_type = " + (token.String("token_type") ?? "なし"));

                r.Done();
            }
        }

        /// <summary>TC-2.2 認可コードの使い捨て</summary>
        /// <param name="targetKey">core / netfx</param>
        /// <returns>Task</returns>
        [SkippableTheory]
        [MemberData(nameof(AllTargets))]
        public async Task TC0202_認可コードは1回しか使えない(string targetKey)
        {
            using (IdPClient client = await this.SignedInClientAsync(targetKey))
            {
                TestReport r = this.Report("TC-2.2",
                    "使用済みの認可コードが再利用できない",
                    "同じ code での 2 回目のトークン要求が拒否されること。"
                    + "**1 回目で発行済みのトークンを失効させるかは SHOULD** なので、"
                    + "そちらは観測にとどめる。",
                    "RFC 6749 §4.1.2（code は 1 回限り）/ §10.5（再利用時は"
                    + "発行済みトークンを取り消す SHOULD）");

                ClientRegistration reg = Flows.Registration(client, KnownClients.MvcSample);

                r.Target("client_name=" + KnownClients.MvcSample);
                r.Step("(1) code を 1 つ取得し、トークンに交換する");

                AuthZResponse authz = await Flows.AuthorizeCodeAsync(
                    client, reg, redirectUri: reg.RedirectUri);

                Assert.False(string.IsNullOrEmpty(authz.Code), "前提: code が取得できること");

                JsonResponse first = await Flows.ExchangeCodeAsync(
                    client, reg, authz.Code, reg.RedirectUri);

                r.Verify("1 回目は成功する", string.IsNullOrEmpty(first.Error),
                    "error なし", first.Error ?? "error なし");

                r.Step("(2) 同じ code で、もう一度トークン要求を送る");

                JsonResponse second = await Flows.ExchangeCodeAsync(
                    client, reg, authz.Code, reg.RedirectUri);

                r.Verify("2 回目は拒否される", !string.IsNullOrEmpty(second.Error),
                    "error が返る", "error = " + (second.Error ?? "なし"));

                r.Verify("2 回目でトークンを発行しない", string.IsNullOrEmpty(second.AccessToken),
                    "access_token を返さない",
                    second.AccessToken == null ? "返さなかった" : "**返してしまった**");

                r.Observe("エラー コード", second.Error ?? "なし",
                    "RFC 6749 §5.2 は invalid_grant を求める。");

                r.Step("(3) 1 回目に発行されたトークンがまだ使えるかを見る");

                JsonResponse userInfo = await client.UserInfoAsync(first.AccessToken);

                r.Observe("再利用検知後、1 回目のトークンが失効しているか",
                    string.IsNullOrEmpty(userInfo.Error) && userInfo.IsJson
                        ? "まだ使える（/userinfo が応答した）"
                        : "使えない（error=" + (userInfo.Error ?? "不明") + "）",
                    "RFC 6749 §10.5 は SHOULD であって MUST ではない。"
                    + "使えるままでも仕様違反ではないが、推奨からは外れる。");

                r.Done();
            }
        }

        /// <summary>TC-2.3 クライアント認証</summary>
        /// <param name="targetKey">core / netfx</param>
        /// <returns>Task</returns>
        [SkippableTheory]
        [MemberData(nameof(AllTargets))]
        public async Task TC0203_不正なクライアント資格情報が拒否される(string targetKey)
        {
            using (IdPClient client = await this.SignedInClientAsync(targetKey))
            {
                TestReport r = this.Report("TC-2.3",
                    "不正な client_id / client_secret のトークン要求が拒否される",
                    "コンフィデンシャル クライアントは、トークン エンドポイントで"
                    + "認証されなければならない。誤った資格情報でトークンが出てはならない。",
                    "RFC 6749 §4.1.3 / §5.2（invalid_client）");

                ClientRegistration reg = Flows.Registration(client, KnownClients.MvcSample);

                r.Target("client_name=" + KnownClients.MvcSample);

                // (1) client_secret が誤り
                r.Step("(1) 正しい code に、誤った client_secret を添えて送る");

                AuthZResponse a1 = await Flows.AuthorizeCodeAsync(
                    client, reg, redirectUri: reg.RedirectUri);
                Assert.False(string.IsNullOrEmpty(a1.Code), "前提: code が取得できること");

                Dictionary<string, string> wrongSecret = new Dictionary<string, string>()
                {
                    { "grant_type", "authorization_code" },
                    { "code", a1.Code },
                    { "client_id", reg.ClientId },
                    { "client_secret", "WRONG-SECRET-WRONG-SECRET-WRONG-SECRET" },
                    { "redirect_uri", reg.RedirectUri }
                };

                JsonResponse t1 = await client.TokenAsync(wrongSecret);

                r.Verify("誤った client_secret ではトークンを発行しない",
                    string.IsNullOrEmpty(t1.AccessToken),
                    "access_token を返さない",
                    t1.AccessToken == null ? "返さなかった（error=" + (t1.Error ?? "なし") + "）"
                                           : "**返してしまった**");

                // (2) client_id が存在しない
                r.Step("(2) 存在しない client_id で送る");

                AuthZResponse a2 = await Flows.AuthorizeCodeAsync(
                    client, reg, redirectUri: reg.RedirectUri);
                Assert.False(string.IsNullOrEmpty(a2.Code), "前提: code が取得できること");

                Dictionary<string, string> unknownClient = new Dictionary<string, string>()
                {
                    { "grant_type", "authorization_code" },
                    { "code", a2.Code },
                    { "client_id", "deadbeefdeadbeefdeadbeefdeadbeef" },
                    { "client_secret", reg.ClientSecret },
                    { "redirect_uri", reg.RedirectUri }
                };

                JsonResponse t2 = await client.TokenAsync(unknownClient);

                r.Verify("存在しない client_id ではトークンを発行しない",
                    string.IsNullOrEmpty(t2.AccessToken),
                    "access_token を返さない",
                    t2.AccessToken == null ? "返さなかった（error=" + (t2.Error ?? "なし") + "）"
                                           : "**返してしまった**");

                r.Observe("エラー コード",
                    "誤った secret = " + (t1.Error ?? "なし")
                    + " / 未知の client_id = " + (t2.Error ?? "なし"),
                    "RFC 6749 §5.2 はクライアント認証の失敗に invalid_client を求める。");

                r.Done();
            }
        }

        /// <summary>TC-2.4 PKCE の検証</summary>
        /// <param name="targetKey">core / netfx</param>
        /// <returns>Task</returns>
        [SkippableTheory]
        [MemberData(nameof(AllTargets))]
        public async Task TC0204_PKCEのcode_verifier不一致が拒否される(string targetKey)
        {
            // RFC 7636 附録 B の例。SHA256(verifier) を BASE64URL したものが challenge。
            const string Verifier  = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
            const string Challenge = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";
            const string WrongVerifier = "WRONG-VERIFIER-WRONG-VERIFIER-WRONG-VERIFIER";

            using (IdPClient client = await this.SignedInClientAsync(targetKey))
            {
                TestReport r = this.Report("TC-2.4",
                    "PKCE の code_verifier が一致しないとトークンを発行しない",
                    "code_challenge を伴って得た code は、"
                    + "**対応する code_verifier を示せた要求にだけ**交換されること。"
                    + "一致しない要求でトークンが出ると、PKCE が意味を成さない。",
                    "RFC 7636 §4.6（検証失敗は invalid_grant）");

                ClientRegistration reg = Flows.Registration(client, KnownClients.MvcSample);

                r.Target("client_name=" + KnownClients.MvcSample);
                r.Step("(1) code_challenge_method=S256, code_challenge=" + Challenge + " で認可");

                Dictionary<string, string> pkce = new Dictionary<string, string>()
                {
                    { "code_challenge", Challenge },
                    { "code_challenge_method", "S256" }
                };

                AuthZResponse authz = await Flows.AuthorizeCodeAsync(
                    client, reg, redirectUri: reg.RedirectUri, extra: pkce);

                r.Verify("認可コードが発行される", !string.IsNullOrEmpty(authz.Code),
                    "code が返る",
                    string.IsNullOrEmpty(authz.Code) ? "code なし" : "code あり");

                r.Step("(2) 誤った code_verifier でトークン要求を送る");

                Dictionary<string, string> wrong = new Dictionary<string, string>()
                {
                    { "grant_type", "authorization_code" },
                    { "code", authz.Code },
                    { "client_id", reg.ClientId },
                    { "code_verifier", WrongVerifier },
                    { "redirect_uri", reg.RedirectUri }
                };

                JsonResponse bad = await client.TokenAsync(wrong);

                r.Verify("誤った code_verifier ではトークンを発行しない",
                    string.IsNullOrEmpty(bad.AccessToken),
                    "access_token を返さない",
                    bad.AccessToken == null ? "返さなかった（error=" + (bad.Error ?? "なし") + "）"
                                            : "**返してしまった**");

                r.Step("(3) 正しい code_verifier で、別の code を交換する（対照）");

                AuthZResponse authz2 = await Flows.AuthorizeCodeAsync(
                    client, reg, redirectUri: reg.RedirectUri, extra: pkce);

                Dictionary<string, string> good = new Dictionary<string, string>()
                {
                    { "grant_type", "authorization_code" },
                    { "code", authz2.Code },
                    { "client_id", reg.ClientId },
                    { "code_verifier", Verifier },
                    { "redirect_uri", reg.RedirectUri }
                };

                JsonResponse ok = await client.TokenAsync(good);

                r.Observe("正しい code_verifier のときの結果",
                    string.IsNullOrEmpty(ok.Error)
                        ? "トークンが発行された"
                        : "拒否された（error=" + ok.Error + "）",
                    "**ここが拒否されると、PKCE を使うパブリック クライアントが動かない。**"
                    + "この実装は PKCE の扱いが OAuth 2.1 と噛み合っていない"
                    + "（ANALYSIS-IdP.md の C-7）。安全側の失敗ではあるが、機能はしない。");

                r.Done();
            }
        }
    }
}
