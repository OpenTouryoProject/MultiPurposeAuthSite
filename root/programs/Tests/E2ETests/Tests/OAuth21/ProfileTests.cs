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
//* クラス名        ：ProfileTests
//* クラス日本語名  ：21 OAuth 2.1 で許されない経路の抑止（#222）
//*
//* 作成日時        ：－
//* 作成者          ：－
//* 更新履歴        ：－
//*
//*  日時        更新者            内容
//*  ----------  ----------------  -------------------------------------------------
//*  2026/09/19  玄人 幸道         新規（#222 : 許されない経路が抑止されること）
//**********************************************************************************

using System.Collections.Generic;
using System.Net;
using System.Threading.Tasks;

using MultiPurposeAuthSite.Tests.E2E.Infrastructure;

using Xunit;
using Xunit.Abstractions;

namespace MultiPurposeAuthSite.Tests.E2E.Tests.OAuth21
{
    /// <summary>
    /// 21-1〜2. **OAuth 2.1 が許さない経路が、実際に抑止されること**を測る。
    /// </summary>
    /// <remarks>
    /// **サーバ全体の設定は変えない。** `-Launch` は Implicit / ROPC を有効にして起動しており
    /// （#220）、`RequirePkce` / `RequirePkceS256` も false のままである。
    ///
    /// **締めるのはクライアント単位の登録**（`oauth2_oidc_mode` / `require_pkce`）。
    /// そのため「**サーバは開いているのに、このクライアントでは塞がる**」という
    /// 対照の効いた形で測れる。
    ///
    /// **サーバ全体の設定（`RequirePkce` など）を true にしたときの挙動は測れない。**
    /// 設定ファイルを変えて起動し直す必要があるため（CONFIGURATION.md 11 節）。
    /// </remarks>
    public class ProfileTests : TargetTestBase
    {
        /// <summary>RFC 7636 附録 B の例</summary>
        private const string Verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";

        /// <summary>RFC 7636 附録 B の例（SHA256(verifier) を BASE64URL したもの）</summary>
        private const string Challenge = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";

        /// <summary>コンストラクタ</summary>
        /// <param name="output">ITestOutputHelper</param>
        public ProfileTests(ITestOutputHelper output) : base(output)
        {
        }

        /// <summary>21-1.1 締めたクライアントでは、許されない経路が塞がる</summary>
        /// <param name="targetKey">core / netfx</param>
        /// <returns>Task</returns>
        [SkippableTheory]
        [MemberData(nameof(AllTargets))]
        public async Task OA2101_締めたクライアントでは許されない経路が塞がる(string targetKey)
        {
            using (IdPClient client = await this.SignedInClientAsync(targetKey))
            {
                Flows.SkipIfClientNotRegistered(client, KnownClients.TestClient6);

                TestReport r = this.Report("21-1.1",
                    "OAuth 2.1 が許さない経路（Implicit / ROPC / PKCE 無し）が、締めた登録では塞がる",
                    "**サーバ全体は開いたままで測る。** -Launch は Implicit / ROPC を有効にし、"
                    + "RequirePkce も false のまま。**塞いでいるのはクライアントの登録**であることを、"
                    + "対照（normal 登録は通る）と並べて確かめる（#222）。",
                    "OAuth 2.1 draft §2.1.2 / §4.1.1 / #222");

                ClientRegistration fapi1 = Flows.Registration(client, KnownClients.TestClient1);
                ClientRegistration pkceOnly = Flows.Registration(client, KnownClients.TestClient6);
                ClientRegistration normal = Flows.Registration(client, KnownClients.MvcSample);

                r.Target("fapi1=" + KnownClients.TestClient1
                    + " / require_pkce=" + KnownClients.TestClient6
                    + " / 対照=" + KnownClients.MvcSample);

                r.Step("(1) 対照 : normal 登録は、PKCE 無しでも ROPC でも通る");

                AuthZResponse controlAuthz = await Flows.AuthorizeCodeAsync(
                    client, normal, redirectUri: normal.RedirectUri);

                r.Verify("対照は PKCE 無しで認可コードが返る",
                    !string.IsNullOrEmpty(controlAuthz.Code),
                    "code あり",
                    string.IsNullOrEmpty(controlAuthz.Code)
                        ? "**返らなかった**（error=" + (controlAuthz.Error ?? "なし") + "）" : "あり");

                JsonResponse controlRopc = await client.TokenAsync(new Dictionary<string, string>()
                {
                    { "grant_type", "password" },
                    { "username", TestEnv.TestUserName },
                    { "password", client.Config.Get("TestUserPWD") },
                    { "scope", "email profile" },
                    { "client_id", normal.ClientId },
                    { "client_secret", normal.ClientSecret }
                });

                r.Verify("対照は ROPC が通る（＝サーバ全体では有効）",
                    !string.IsNullOrEmpty(controlRopc.AccessToken),
                    "トークンが返る",
                    string.IsNullOrEmpty(controlRopc.AccessToken)
                        ? "**返らなかった**（error=" + (controlRopc.Error ?? "なし") + "）" : "返った");

                r.Step("(2) PKCE 無しの認可 : require_pkce のクライアントでは塞がる");

                AuthZResponse withoutPkce = await Flows.AuthorizeCodeAsync(
                    client, pkceOnly, redirectUri: pkceOnly.RedirectUri);

                r.Verify("認可コードを発行しない",
                    string.IsNullOrEmpty(withoutPkce.Code),
                    "code を返さない",
                    string.IsNullOrEmpty(withoutPkce.Code) ? "返さなかった" : "**返してしまった**");

                r.Verify("エラーは invalid_request",
                    withoutPkce.Error == "invalid_request",
                    "invalid_request", withoutPkce.Error ?? "（無し）");

                r.Step("(3) ROPC : fapi1 のクライアントでは塞がる");

                JsonResponse ropc = await client.TokenAsync(new Dictionary<string, string>()
                {
                    { "grant_type", "password" },
                    { "username", TestEnv.TestUserName },
                    { "password", client.Config.Get("TestUserPWD") },
                    { "scope", "email profile" },
                    { "client_id", fapi1.ClientId },
                    { "client_secret", fapi1.ClientSecret }
                });

                r.Verify("ROPC は拒否される",
                    string.IsNullOrEmpty(ropc.AccessToken),
                    "トークンを返さない",
                    string.IsNullOrEmpty(ropc.AccessToken)
                        ? "返さなかった（error=" + (ropc.Error ?? "なし") + "）" : "**返してしまった**");

                r.Step("(4) Implicit : fapi1 のクライアントでは塞がる");

                AuthZResponse implicitRes = await client.AuthorizeAsync(
                    new Dictionary<string, string>()
                    {
                        { "response_type", "token" },
                        { "client_id", fapi1.ClientId },
                        { "scope", "profile" },
                        { "state", "state1" },
                        { "redirect_uri", fapi1.RedirectUriToken },
                        { "prompt", "none" }
                    });

                r.Verify("access_token を返さない",
                    string.IsNullOrEmpty(implicitRes.Get("access_token")),
                    "返さない",
                    string.IsNullOrEmpty(implicitRes.Get("access_token"))
                        ? "返さなかった（error=" + (implicitRes.Error ?? "なし") + "）" : "**返してしまった**");

                r.Note("**(1) との対比が要点。** 同じサーバ・同じ設定で、"
                    + "**登録の違いだけで経路が塞がっている**。"
                    + "移行では、締められるクライアントから順に登録を変えていける（#221）。");

                r.Done();
            }
        }

        /// <summary>21-2.1 アクセス トークンはヘッダでのみ受け付ける</summary>
        /// <param name="targetKey">core / netfx</param>
        /// <returns>Task</returns>
        [SkippableTheory]
        [MemberData(nameof(AllTargets))]
        public async Task OA2102_アクセストークンはヘッダでのみ受け付ける(string targetKey)
        {
            using (IdPClient client = await this.SignedInClientAsync(targetKey))
            {
                TestReport r = this.Report("21-2.1",
                    "アクセス トークンは Authorization ヘッダでのみ受け付ける（クエリ文字列では受けない）",
                    "**OAuth 2.1 は、URI クエリ文字列でのトークン送信を禁止している**"
                    + "（RFC 6750 §2.3 の form-encoded / URI query は廃止）。"
                    + "**URL はログ・Referer・履歴に残る**ため。"
                    + "`ANALYSIS-IdP.md` の D-12 で「ヘッダのみ（要再確認）」としていた項目を、実際に測る。",
                    "OAuth 2.1 draft §4.3 / RFC 6750 §2.3 / #222");

                ClientRegistration reg = Flows.Registration(client, KnownClients.MvcSample);

                r.Target("client_name=" + KnownClients.MvcSample + " / エンドポイント : /userinfo");

                r.Step("(1) トークンを取得する");

                AuthZResponse authz = await Flows.AuthorizeCodeAsync(
                    client, reg, redirectUri: reg.RedirectUri);

                Assert.False(string.IsNullOrEmpty(authz.Code), "前提: code が取得できること");

                JsonResponse token = await client.TokenAsync(new Dictionary<string, string>()
                {
                    { "grant_type", "authorization_code" },
                    { "code", authz.Code },
                    { "client_id", reg.ClientId },
                    { "client_secret", reg.ClientSecret },
                    { "redirect_uri", reg.RedirectUri }
                });

                Assert.False(string.IsNullOrEmpty(token.AccessToken), "前提: トークンが取得できること");

                r.Step("(2) 対照 : Authorization ヘッダで /userinfo を呼ぶ");

                JsonResponse byHeader = await client.UserInfoAsync(token.AccessToken);

                r.Verify("ヘッダなら答える",
                    byHeader.StatusCode == HttpStatusCode.OK,
                    "200", ((int)byHeader.StatusCode).ToString());

                r.Step("(3) クエリ文字列（?access_token=...）で /userinfo を呼ぶ");

                r.Note("**要求 URL はここに出さない**（トークンを含むため）。");

                JsonResponse byQuery = await client.GetJsonAsync(
                    "/userinfo?access_token=" + token.AccessToken);

                r.Verify("クエリ文字列では答えない",
                    byQuery.StatusCode != HttpStatusCode.OK,
                    "200 以外", ((int)byQuery.StatusCode).ToString());

                r.Verify("401 を返す",
                    byQuery.StatusCode == HttpStatusCode.Unauthorized,
                    "401", ((int)byQuery.StatusCode).ToString());

                r.Done();
            }
        }
    }
}
