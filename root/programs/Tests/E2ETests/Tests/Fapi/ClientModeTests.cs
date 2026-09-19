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
//* クラス名        ：ClientModeTests
//* クラス日本語名  ：FA ClientMode（oauth2_oidc_mode）ごとに通る経路（#222）
//*
//* 作成日時        ：－
//* 作成者          ：－
//* 更新履歴        ：－
//*
//*  日時        更新者            内容
//*  ----------  ----------------  -------------------------------------------------
//*  2026/09/19  玄人 幸道         新規（#222 : ClientMode 経路の E2E 整備）
//**********************************************************************************

using System.Collections.Generic;
using System.Threading.Tasks;

using MultiPurposeAuthSite.Tests.E2E.Infrastructure;

using Xunit;
using Xunit.Abstractions;

namespace MultiPurposeAuthSite.Tests.E2E.Tests.Fapi
{
    /// <summary>
    /// FA-1〜3. クライアント登録の <c>oauth2_oidc_mode</c> によって、
    /// **どの経路が通り、どの経路が塞がるか**を測る。
    /// </summary>
    /// <remarks>
    /// **判定は CmnEndpoints.CheckClientMode が行う。**
    /// 「clientMode &lt;= permittedLevel」で、permittedLevel は
    /// **クライアント認証の強度**で決まる（client_secret なら normal、PKCE の S256 なら fapi1、
    /// x509 なら fapi2）。**登録が上位のクライアントほど、通る経路が狭い。**
    ///
    /// **本クラスは、今の振る舞いを記録する。** 望ましくないと考える点は
    /// 「観測」として書き、合否には影響させない。
    /// </remarks>
    public class ClientModeTests : TargetTestBase
    {
        /// <summary>RFC 7636 附録 B の例</summary>
        private const string Verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";

        /// <summary>RFC 7636 附録 B の例（SHA256(verifier) を BASE64URL したもの）</summary>
        private const string Challenge = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";

        /// <summary>コンストラクタ</summary>
        /// <param name="output">ITestOutputHelper</param>
        public ClientModeTests(ITestOutputHelper output) : base(output)
        {
        }

        #region 補助

        /// <summary>PKCE（S256）の認可リクエストのパラメタ</summary>
        private static Dictionary<string, string> Pkce()
        {
            return new Dictionary<string, string>()
            {
                { "code_challenge", ClientModeTests.Challenge },
                { "code_challenge_method", "S256" }
            };
        }

        /// <summary>認可コードを取り、client_secret で交換する（PKCE 無し）</summary>
        /// <param name="client">IdPClient</param>
        /// <param name="reg">ClientRegistration</param>
        /// <returns>JsonResponse（認可で失敗したら null）</returns>
        private static async Task<JsonResponse> CodeWithSecretAsync(
            IdPClient client, ClientRegistration reg)
        {
            AuthZResponse authz = await Flows.AuthorizeCodeAsync(
                client, reg, redirectUri: reg.RedirectUri);

            if (string.IsNullOrEmpty(authz.Code))
            {
                return null;
            }

            return await client.TokenAsync(new Dictionary<string, string>()
            {
                { "grant_type", "authorization_code" },
                { "code", authz.Code },
                { "client_id", reg.ClientId },
                { "client_secret", reg.ClientSecret },
                { "redirect_uri", reg.RedirectUri }
            });
        }

        /// <summary>認可コードを取り、PKCE（S256）で交換する（client_secret 無し）</summary>
        /// <param name="client">IdPClient</param>
        /// <param name="reg">ClientRegistration</param>
        /// <returns>JsonResponse（認可で失敗したら null）</returns>
        private static async Task<JsonResponse> CodeWithPkceAsync(
            IdPClient client, ClientRegistration reg)
        {
            AuthZResponse authz = await Flows.AuthorizeCodeAsync(
                client, reg, redirectUri: reg.RedirectUri, extra: ClientModeTests.Pkce());

            if (string.IsNullOrEmpty(authz.Code))
            {
                return null;
            }

            return await client.TokenAsync(new Dictionary<string, string>()
            {
                { "grant_type", "authorization_code" },
                { "code", authz.Code },
                { "client_id", reg.ClientId },
                { "code_verifier", ClientModeTests.Verifier },
                { "redirect_uri", reg.RedirectUri }
            });
        }

        /// <summary>結果の表現（トークンの値は出さない）</summary>
        /// <param name="token">JsonResponse</param>
        /// <returns>文字列</returns>
        private static string Outcome(JsonResponse token)
        {
            if (token == null)
            {
                return "認可エンドポイントで失敗";
            }

            return string.IsNullOrEmpty(token.AccessToken)
                ? "拒否（error=" + (token.Error ?? "なし") + "）"
                : "トークンが返った";
        }

        #endregion

        #region FA-1 fapi1

        /// <summary>FA-1.1 fapi1 は PKCE の経路だけを通す</summary>
        /// <param name="targetKey">core / netfx</param>
        /// <returns>Task</returns>
        [SkippableTheory]
        [MemberData(nameof(AllTargets))]
        public async Task FA0101_fapi1はPKCEの経路だけを通す(string targetKey)
        {
            using (IdPClient client = await this.SignedInClientAsync(targetKey))
            {
                TestReport r = this.Report("FA-1.1",
                    "oauth2_oidc_mode=fapi1 のクライアントは、PKCE(S256) の認可コードだけが通る",
                    "**登録が上位のクライアントほど、通る経路が狭い。**"
                    + "CheckClientMode は「clientMode <= permittedLevel」で判定し、"
                    + "permittedLevel は**クライアント認証の強度**で決まる。"
                    + "client_secret では normal 止まりなので、fapi1 の登録は通らない。"
                    + "**PKCE の S256 を使うと permittedLevel が fapi1 に上がり、そこだけが通る。**",
                    "FAPI 1.0 Advanced / #222");

                ClientRegistration reg = Flows.Registration(client, KnownClients.TestClient1);
                ClientRegistration normal = Flows.Registration(client, KnownClients.MvcSample);

                r.Target("client_name=" + KnownClients.TestClient1 + "（fapi1 登録）");

                r.Step("(1) 対照 : normal 登録のクライアントは、client_secret で通る");

                JsonResponse control = await ClientModeTests.CodeWithSecretAsync(client, normal);

                r.Verify("対照（normal）は通る",
                    control != null && !string.IsNullOrEmpty(control.AccessToken),
                    "トークンが返る", ClientModeTests.Outcome(control));

                r.Step("(2) fapi1 ＋ client_secret（PKCE 無し）");

                JsonResponse withSecret = await ClientModeTests.CodeWithSecretAsync(client, reg);

                r.Verify("client_secret だけでは通らない",
                    withSecret != null && string.IsNullOrEmpty(withSecret.AccessToken),
                    "拒否される", ClientModeTests.Outcome(withSecret));

                r.Verify("エラーは unsupported_grant_type",
                    withSecret != null && withSecret.Error == "unsupported_grant_type",
                    "unsupported_grant_type",
                    withSecret == null ? "（認可で失敗）" : (withSecret.Error ?? "（無し）"));

                r.Step("(3) fapi1 ＋ PKCE(S256)（client_secret 無し）");

                JsonResponse withPkce = await ClientModeTests.CodeWithPkceAsync(client, reg);

                r.Verify("PKCE(S256) なら通る",
                    withPkce != null && !string.IsNullOrEmpty(withPkce.AccessToken),
                    "トークンが返る", ClientModeTests.Outcome(withPkce));

                r.Step("(4) fapi1 ＋ ROPC / client_credentials");

                JsonResponse ropc = await client.TokenAsync(new Dictionary<string, string>()
                {
                    { "grant_type", "password" },
                    { "username", TestEnv.TestUserName },
                    { "password", client.Config.Get("TestUserPWD") },
                    { "scope", "email profile" },
                    { "client_id", reg.ClientId },
                    { "client_secret", reg.ClientSecret }
                });

                r.Verify("ROPC は通らない",
                    string.IsNullOrEmpty(ropc.AccessToken),
                    "拒否される", ClientModeTests.Outcome(ropc));

                JsonResponse cc = await client.TokenAsync(new Dictionary<string, string>()
                {
                    { "grant_type", "client_credentials" },
                    { "scope", "profile" },
                    { "client_id", reg.ClientId },
                    { "client_secret", reg.ClientSecret }
                });

                r.Verify("client_credentials は通らない",
                    string.IsNullOrEmpty(cc.AccessToken),
                    "拒否される", ClientModeTests.Outcome(cc));

                r.Note("**ROPC / client_credentials は、サーバ全体では有効**"
                    + "（-Launch は Implicit / ROPC を有効にして起動する。#220）。"
                    + "**塞いでいるのは、このクライアントの登録**であることが、(1) の対照で分かる。");

                r.Done();
            }
        }

        /// <summary>FA-1.2 fapi1 は使えない refresh_token を発行する</summary>
        /// <param name="targetKey">core / netfx</param>
        /// <returns>Task</returns>
        [SkippableTheory]
        [MemberData(nameof(AllTargets))]
        public async Task FA0102_fapi1は使えないrefresh_tokenを発行する(string targetKey)
        {
            using (IdPClient client = await this.SignedInClientAsync(targetKey))
            {
                TestReport r = this.Report("FA-1.2",
                    "fapi1 のクライアントは refresh_token を受け取るが、それを使うと拒否される",
                    "**受け取ったのに必ず失敗する資格情報を渡している。**"
                    + "refresh_token の経路は permittedLevel=normal で判定するため、"
                    + "fapi1 の登録は通らない。**発行しない、あるいは経路を通す、のどちらかが筋。**"
                    + "本テストは**現状を記録する**もので、望ましさは判定しない（#222）。",
                    "RFC 6749 §6 / #222");

                ClientRegistration reg = Flows.Registration(client, KnownClients.TestClient1);
                ClientRegistration normal = Flows.Registration(client, KnownClients.MvcSample);

                r.Target("client_name=" + KnownClients.TestClient1 + "（fapi1 登録）");

                r.Step("(1) 対照 : normal 登録では、refresh_token で更新できる");

                JsonResponse controlToken = await ClientModeTests.CodeWithSecretAsync(client, normal);
                Assert.False(controlToken == null || string.IsNullOrEmpty(controlToken.RefreshToken),
                    "前提: 対照の refresh_token が取得できること");

                JsonResponse controlRefresh = await client.TokenAsync(new Dictionary<string, string>()
                {
                    { "grant_type", "refresh_token" },
                    { "refresh_token", controlToken.RefreshToken },
                    { "client_id", normal.ClientId },
                    { "client_secret", normal.ClientSecret }
                });

                r.Verify("対照（normal）は更新できる",
                    !string.IsNullOrEmpty(controlRefresh.AccessToken),
                    "トークンが返る", ClientModeTests.Outcome(controlRefresh));

                r.Step("(2) fapi1 で PKCE(S256) のトークンを取る");

                JsonResponse token = await ClientModeTests.CodeWithPkceAsync(client, reg);
                Assert.False(token == null || string.IsNullOrEmpty(token.AccessToken),
                    "前提: fapi1 で PKCE のトークンが取得できること");

                r.Verify("refresh_token が発行される",
                    !string.IsNullOrEmpty(token.RefreshToken),
                    "発行される",
                    string.IsNullOrEmpty(token.RefreshToken) ? "発行されない" : "発行される（値は伏せる）");

                r.Step("(3) その refresh_token で更新を試みる");

                JsonResponse refreshed = await client.TokenAsync(new Dictionary<string, string>()
                {
                    { "grant_type", "refresh_token" },
                    { "refresh_token", token.RefreshToken },
                    { "client_id", reg.ClientId },
                    { "client_secret", reg.ClientSecret }
                });

                r.Verify("更新は拒否される",
                    string.IsNullOrEmpty(refreshed.AccessToken),
                    "拒否される", ClientModeTests.Outcome(refreshed));

                r.Note("**望ましくない。** 使えない資格情報を渡している。"
                    + "直すなら「fapi1 では refresh_token を発行しない」か"
                    + "「refresh_token の経路を登録種別で判定し直す」のどちらか（#222 の 3）。");

                r.Done();
            }
        }

        #endregion

        #region FA-2 fapi2

        /// <summary>FA-2.1 fapi2 は client_secret / PKCE の経路を通さない</summary>
        /// <param name="targetKey">core / netfx</param>
        /// <returns>Task</returns>
        [SkippableTheory]
        [MemberData(nameof(AllTargets))]
        public async Task FA0201_fapi2はclient_secretもPKCEも通さない(string targetKey)
        {
            using (IdPClient client = await this.SignedInClientAsync(targetKey))
            {
                TestReport r = this.Report("FA-2.1",
                    "oauth2_oidc_mode=fapi2 のクライアントは、client_secret でも PKCE でも通らない",
                    "**fapi2 に達するのは x509（mTLS）だけ。**"
                    + "PKCE の S256 で上がるのは fapi1 までなので、**平文の経路は全滅する**。"
                    + "FAPI2 のクライアントは、Request Object（JAR）＋ 証明書で使う想定"
                    + "（`RT-197` が request_uri 経路を測っている）。",
                    "FAPI 2.0 / #222");

                ClientRegistration reg = Flows.Registration(client, KnownClients.TestClient2);

                r.Target("client_name=" + KnownClients.TestClient2 + "（fapi2 登録）");

                r.Step("(1) client_secret（PKCE 無し）");

                JsonResponse withSecret = await ClientModeTests.CodeWithSecretAsync(client, reg);

                r.Verify("client_secret では通らない",
                    withSecret != null && string.IsNullOrEmpty(withSecret.AccessToken),
                    "拒否される", ClientModeTests.Outcome(withSecret));

                r.Step("(2) PKCE(S256)（client_secret 無し）");

                JsonResponse withPkce = await ClientModeTests.CodeWithPkceAsync(client, reg);

                r.Verify("PKCE(S256) でも通らない",
                    withPkce != null && string.IsNullOrEmpty(withPkce.AccessToken),
                    "拒否される", ClientModeTests.Outcome(withPkce));

                r.Verify("エラーは unsupported_grant_type",
                    withPkce != null && withPkce.Error == "unsupported_grant_type",
                    "unsupported_grant_type",
                    withPkce == null ? "（認可で失敗）" : (withPkce.Error ?? "（無し）"));

                r.Note("**これは設計どおり。** fapi2 の登録は、証明書（x509）を伴う経路でだけ通る。"
                    + "本 E2E は mTLS を張らないので、**通る側は測っていない**。");

                r.Done();
            }
        }

        #endregion

        #region FA-3 device

        /// <summary>FA-3.1 device は PKCE の経路を通る（例外措置）</summary>
        /// <param name="targetKey">core / netfx</param>
        /// <returns>Task</returns>
        [SkippableTheory]
        [MemberData(nameof(AllTargets))]
        public async Task FA0301_deviceはPKCEの経路を通る(string targetKey)
        {
            using (IdPClient client = await this.SignedInClientAsync(targetKey))
            {
                TestReport r = this.Report("FA-3.1",
                    "oauth2_oidc_mode=device のクライアントは、PKCE(S256) の認可コードが通る",
                    "**CheckClientMode には、device のための例外措置がある。**"
                    + "device は fapi2 より大きい値なので、本来は「permittedLevel と一致」が要るが、"
                    + "**clientMode=device かつ permittedLevel=fapi1（＝PKCE の S256）のときだけ通す**"
                    + "と書かれている（LIR 用）。**その例外が効いていることを測る。**",
                    "RFC 8628（Device Authorization Grant）/ #222");

                ClientRegistration reg = Flows.Registration(client, KnownClients.TestClient3);

                r.Target("client_name=" + KnownClients.TestClient3
                    + "（device 登録。client_secret を持たないパブリック クライアント）");

                r.Step("PKCE(S256) で認可コードを取り、交換する");

                JsonResponse token = await ClientModeTests.CodeWithPkceAsync(client, reg);

                r.Verify("トークンが返る",
                    token != null && !string.IsNullOrEmpty(token.AccessToken),
                    "トークンが返る", ClientModeTests.Outcome(token));

                r.Note("**例外措置が無ければ、ここは通らない**（device > fapi2 なので一致判定になる）。"
                    + "`permittedLevel` を作り直すときは、この経路を壊さないこと（#222 の 3）。");

                r.Note("**refresh_token は使えない。** 更新の経路は client_secret による認証を求めるので、"
                    + "client_secret を持たないこのクライアントは、そもそも要求を組み立てられない。");

                r.Done();
            }
        }

        #endregion
    }
}
