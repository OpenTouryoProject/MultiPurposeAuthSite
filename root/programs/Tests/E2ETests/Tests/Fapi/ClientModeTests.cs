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
//*  2026/09/22  玄人 幸道         FA-4.1（Device AuthZ グラントは normal と device にだけ許す）を追加（#224）
//*  2026/09/22  玄人 幸道         FA-1.3（client_secret と PKCE の併用）・FA-1.4（Hybrid）を追加（#224 の段階 0）
//*  2026/09/22  玄人 幸道         観点の文面を、ClientModePolicy の表に合わせた（#224 の段階 1。判定は変えていない）
//*  2026/09/22  玄人 幸道         拒否のエラー コードを unauthorized_client に、FA-1.2 を「発行しない」に、
//*                                FA-1.4 を認可エンドポイントでの拒否に改めた（#224 の段階 2）
//*  2026/09/22  玄人 幸道         FA-2.1 の注記を、mTLS の通る側（FA-6.1）に合わせた（#226）
//*  2026/09/26  玄人 幸道         FA-1.2 を、refresh_token を「非対称の証明でだけ使える」に改めた（#239 の段階 3）
//**********************************************************************************

using System.Collections.Generic;
using System.Threading.Tasks;

using MultiPurposeAuthSite.Tests.E2E.Infrastructure;

using Xunit;
using Xunit.Abstractions;

namespace MultiPurposeAuthSite.Tests.E2E.Tests.Fapi
{
    /// <summary>
    /// FA-1〜4. クライアント登録の <c>oauth2_oidc_mode</c> によって、
    /// **どの経路が通り、どの経路が塞がるか**を測る。
    /// </summary>
    /// <remarks>
    /// **判定は CmnEndpoints.CheckClientMode が、ClientModePolicy の表で行う（#224）。**
    /// 表は「経路 × その要求で何を証明したか（client_secret / PKCE の S256 / x509 など）」から、
    /// 通す登録種別を引く。**登録が上位のクライアントほど、通る経路が狭い。**
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
                    + "CheckClientMode は ClientModePolicy の表（経路 × 何を証明したか）で判定する。"
                    + "認可コードを client_secret で取る行は normal だけを通すので、fapi1 の登録は通らない。"
                    + "**PKCE の S256 で取る行は fapi1 も通すので、そこだけが通る。**",
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

                r.Verify("エラーは unauthorized_client",
                    withSecret != null && withSecret.Error == "unauthorized_client",
                    "unauthorized_client",
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

        /// <summary>FA-1.2 fapi1 には refresh_token を発行しない</summary>
        /// <param name="targetKey">core / netfx</param>
        /// <returns>Task</returns>
        [SkippableTheory]
        [MemberData(nameof(AllTargets))]
        public async Task FA0102_fapi1のrefresh_tokenは非対称の証明でだけ使える(string targetKey)
        {
            using (IdPClient client = await this.SignedInClientAsync(targetKey))
            {
                TestReport r = this.Report("FA-1.2",
                    "fapi1 の refresh_token は、非対称の証明でだけ使える",
                    "**使えない資格情報は渡さない**（#224 の段階 2）という原則は変わらない。"
                    + "変わったのは前提で、**#239 の段階 3 で refresh_token の行を証明ごとに分けた**"
                    + "（`private_key_jwt` / mTLS なら fapi1 / fapi2 も通す。`client_secret` では通さない）。"
                    + "**FAPI は refresh token を禁じていない**ので、"
                    + "以前のように「fapi1 には発行しない」では、期限が切れるたびに認可からやり直しになる。",
                    "RFC 6749 §5.1 / §6 / FAPI 1.0 Advanced / #224 / #239");

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

                r.Verify("refresh_token が発行される（#239 の段階 3 で開いた）",
                    !string.IsNullOrEmpty(token.RefreshToken),
                    "発行される",
                    string.IsNullOrEmpty(token.RefreshToken) ? "**発行されない**" : "発行された（値は伏せる）");

                Assert.False(string.IsNullOrEmpty(token.RefreshToken),
                    "前提: fapi1 に refresh_token が発行されること");

                r.Step("(3) client_secret で更新しようとする（fapi1 には認めない証明）");

                JsonResponse bySecret = await client.TokenAsync(new Dictionary<string, string>()
                {
                    { "grant_type", "refresh_token" },
                    { "refresh_token", token.RefreshToken },
                    { "client_id", reg.ClientId },
                    { "client_secret", reg.ClientSecret }
                });

                r.Verify("client_secret では更新できない",
                    string.IsNullOrEmpty(bySecret.AccessToken),
                    "トークンを返さない", ClientModeTests.Outcome(bySecret));

                r.VerifyEqual("エラーは unauthorized_client",
                    "unauthorized_client", bySecret.Error ?? "（無し）");

                r.Note("**(1) の対照で、サーバ全体では refresh_token が有効**であることが分かる。"
                    + "fapi1 が更新できないのは**証明の種類**によるもので、登録種別そのものではない"
                    + "（`private_key_jwt` / mTLS なら通る。`RT-239.5` が fapi2 で測っている）。");

                r.Done();
            }
        }

        /// <summary>FA-1.3 fapi1 は client_secret と PKCE の併用を通さない</summary>
        /// <param name="targetKey">core / netfx</param>
        /// <returns>Task</returns>
        [SkippableTheory]
        [MemberData(nameof(AllTargets))]
        public async Task FA0103_fapi1はclient_secretとPKCEの併用を通さない(string targetKey)
        {
            using (IdPClient client = await this.SignedInClientAsync(targetKey))
            {
                TestReport r = this.Report("FA-1.3",
                    "fapi1 のクライアントが client_secret と PKCE(S256) を両方送ると、拒否される",
                    "**表の「認可コード × client_secret と PKCE の併用」の行は、normal だけを通す。**"
                    + "fapi1 を通すのは、client_secret を送らない「PKCE の S256」の行だけ"
                    + "（併用の経路では PKCE は検証だけ行い、判定には使わない。#220）。"
                    + "FAPI 1.0 Advanced は client_secret を認めていないので、拒否は設計どおり（#224）。",
                    "FAPI 1.0 Advanced §5.2.2 / RFC 7636 / #224");

                ClientRegistration reg = Flows.Registration(client, KnownClients.TestClient1);

                r.Target("client_name=" + KnownClients.TestClient1 + "（fapi1 登録。client_secret 登録あり）");
                r.Step("PKCE(S256) で認可コードを取り、client_secret と code_verifier の両方を送って交換する");

                AuthZResponse authz = await Flows.AuthorizeCodeAsync(
                    client, reg, redirectUri: reg.RedirectUri, extra: ClientModeTests.Pkce());

                Assert.False(string.IsNullOrEmpty(authz.Code), "前提: code が取得できること");

                JsonResponse token = await client.TokenAsync(new Dictionary<string, string>()
                {
                    { "grant_type", "authorization_code" },
                    { "code", authz.Code },
                    { "client_id", reg.ClientId },
                    { "client_secret", reg.ClientSecret },
                    { "code_verifier", ClientModeTests.Verifier },
                    { "redirect_uri", reg.RedirectUri }
                });

                r.Verify("トークンを返さない",
                    string.IsNullOrEmpty(token.AccessToken),
                    "拒否される", ClientModeTests.Outcome(token));

                r.Verify("エラーは unauthorized_client",
                    token.Error == "unauthorized_client",
                    "unauthorized_client", token.Error ?? "（無し）");

                r.Note("**設計どおり**（#224 の段階 2 で、拒否のままとすることにした）。"
                    + "FAPI 1.0 Advanced は client_secret によるクライアント認証を認めていない"
                    + "（private_key_jwt か mTLS）。"
                    + "同じクライアントが client_secret を送らなければ通る（FA-1.1）のは、PKCE の S256 の行による。");

                r.Done();
            }
        }

        /// <summary>FA-1.4 fapi1 は Hybrid フローを通さない</summary>
        /// <param name="targetKey">core / netfx</param>
        /// <returns>Task</returns>
        [SkippableTheory]
        [MemberData(nameof(AllTargets))]
        public async Task FA0104_fapi1はHybridフローを通さない(string targetKey)
        {
            using (IdPClient client = await this.SignedInClientAsync(targetKey))
            {
                TestReport r = this.Report("FA-1.4",
                    "fapi1 のクライアントは、Hybrid フロー（code id_token）で code も id_token も受け取らず、unauthorized_client が RP へ返る",
                    "**表の Hybrid の行は normal だけを通す。**"
                    + "以前はトークンを作る時点で拒否し、error=access_denied を返していた（#224 の段階 0 で記録）。"
                    + "段階 2 で、**要求を検証する時点**（redirect_uri を確かめた直後）で判定し、"
                    + "unauthorized_client を RP へリダイレクトで返すようにした。",
                    "RFC 6749 §4.2.2.1 / OIDC Core §3.3 / FAPI 1.0 Advanced / #224");

                ClientRegistration reg = Flows.Registration(client, KnownClients.TestClient1);
                ClientRegistration normal = Flows.Registration(client, KnownClients.TestClient);

                r.Target("client_name=" + KnownClients.TestClient1 + "（fapi1 登録）/ 対照="
                    + KnownClients.TestClient + "（normal 登録）");

                r.Step("(1) 対照 : normal 登録のクライアントは、Hybrid で code と id_token を受け取る");

                AuthZResponse control = await ClientModeTests.HybridAsync(client, normal);

                r.Verify("対照（normal）は code を受け取る",
                    !string.IsNullOrEmpty(control.Code),
                    "code あり",
                    string.IsNullOrEmpty(control.Code)
                        ? "**無し**（error=" + (control.Error ?? "なし") + "）" : "あり（値は伏せる）");

                r.Step("(2) fapi1 登録のクライアントで、同じ要求を送る");

                AuthZResponse res = await ClientModeTests.HybridAsync(client, reg);

                r.Verify("code を受け取らない",
                    string.IsNullOrEmpty(res.Code),
                    "code 無し",
                    string.IsNullOrEmpty(res.Code) ? "無し" : "**あり**");

                r.Verify("id_token を受け取らない",
                    string.IsNullOrEmpty(res.Get("id_token")),
                    "id_token 無し",
                    string.IsNullOrEmpty(res.Get("id_token")) ? "無し" : "**あり**");

                r.Verify("RP へリダイレクトで返す",
                    res.Redirected,
                    "リダイレクト",
                    res.Redirected ? "リダイレクト" : "**画面**（HTTP " + (int)res.StatusCode + "）");

                r.VerifyEqual("エラーは unauthorized_client", "unauthorized_client", res.Error ?? "（無し）");

                r.Done();
            }
        }

        /// <summary>Hybrid（code id_token）の認可リクエストを送る</summary>
        /// <param name="client">IdPClient</param>
        /// <param name="reg">ClientRegistration</param>
        /// <returns>AuthZResponse</returns>
        private static Task<AuthZResponse> HybridAsync(IdPClient client, ClientRegistration reg)
        {
            return client.AuthorizeAsync(new Dictionary<string, string>()
            {
                { "response_type", "code id_token" },
                { "client_id", reg.ClientId },
                { "scope", "openid" },
                { "redirect_uri", reg.RedirectUriToken },
                { "state", "state-fa14" },
                { "nonce", "nonce-fa14" },
                { "prompt", "none" }
            });
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

                r.Verify("エラーは unauthorized_client",
                    withPkce != null && withPkce.Error == "unauthorized_client",
                    "unauthorized_client",
                    withPkce == null ? "（認可で失敗）" : (withPkce.Error ?? "（無し）"));

                r.Note("**これは設計どおり。** fapi2 の登録は、証明書（x509）を伴う経路でだけ通る。"
                    + "**通る側は FA-6.1 で測る**（net10.0 版のみ。net48 版は手動。#226）。");

                r.Done();
            }
        }

        #endregion

        #region FA-3 device

        /// <summary>FA-3.1 device は PKCE の経路を通る（以前の例外措置。今は表の 1 行）</summary>
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
                    "**表の「認可コード × PKCE の S256」の行は、device も通す**（LIR 用）。"
                    + "以前の大小比較では device は fapi2 より大きい値で、この経路は例外措置として"
                    + "ハードコードされていた（#224 の段階 1 で表に置き換えた）。**その行が効いていることを測る。**",
                    "RFC 8628（Device Authorization Grant）/ #222");

                ClientRegistration reg = Flows.Registration(client, KnownClients.TestClient3);

                r.Target("client_name=" + KnownClients.TestClient3
                    + "（device 登録。client_secret を持たないパブリック クライアント）");

                r.Step("PKCE(S256) で認可コードを取り、交換する");

                JsonResponse token = await ClientModeTests.CodeWithPkceAsync(client, reg);

                r.Verify("トークンが返る",
                    token != null && !string.IsNullOrEmpty(token.AccessToken),
                    "トークンが返る", ClientModeTests.Outcome(token));

                r.Note("**表のこの行から device を外すと、ここは通らない。**"
                    + "表を書き換えるときは、この経路を壊さないこと（#224）。");

                r.Verify("refresh_token は発行されない",
                    token == null || string.IsNullOrEmpty(token.RefreshToken),
                    "発行されない",
                    token == null || string.IsNullOrEmpty(token.RefreshToken)
                        ? "発行されない" : "**発行された**（値は伏せる）");

                r.Note("**refresh_token の経路は normal の登録だけ**なので、device の登録には発行しない"
                    + "（#224 の段階 2。以前は発行していたが、使えなかった）。");

                r.Done();
            }
        }

        #endregion

        #region FA-4 Device AuthZ グラント

        /// <summary>FA-4.1 Device AuthZ グラントは normal と device の登録にだけ許す</summary>
        /// <param name="targetKey">core / netfx</param>
        /// <returns>Task</returns>
        [SkippableTheory]
        [MemberData(nameof(AllTargets))]
        public async Task FA0401_DeviceAuthZはnormalとdeviceの登録にだけ許す(string targetKey)
        {
            using (IdPClient client = await this.SignedInClientAsync(targetKey))
            {
                TestReport r = this.Report("FA-4.1",
                    "Device AuthZ グラントは、登録種別が normal と device のクライアントにだけ許す",
                    "**このグラントは client_secret（またはパブリック）で通る。**"
                    + "fapi1 / fapi2 / fapi_ciba の登録は、より強いクライアント認証"
                    + "（PKCE / private_key_jwt / mTLS）を求めているので、この経路を使わせてはならない。"
                    + "**以前は登録種別を判定しておらず、client_secret だけでトークンが出ていた**（#224）。",
                    "RFC 8628 / RFC 6749 §5.2（unauthorized_client）/ #224");

                r.Target("device=" + KnownClients.TestClient3 + " / normal=" + KnownClients.MvcSample
                    + " / fapi1=" + KnownClients.TestClient1 + " / fapi2=" + KnownClients.TestClient2
                    + " / fapi_ciba=" + KnownClients.TestClient4);

                r.Step("(1) 対照 : device / normal の登録は、開始できる");

                foreach (string name in new string[] { KnownClients.TestClient3, KnownClients.MvcSample })
                {
                    JsonResponse start = await ClientModeTests.StartDeviceAuthZAsync(
                        client, Flows.Registration(client, name));

                    r.Verify(name + " は device_code を得る",
                        !string.IsNullOrEmpty(start.String("device_code")),
                        "device_code あり",
                        string.IsNullOrEmpty(start.String("device_code"))
                            ? "**得られなかった**（" + (int)start.StatusCode + " / " + (start.Error ?? "なし") + "）"
                            : "あり（値は伏せる）");
                }

                r.Step("(2) fapi1 / fapi2 / fapi_ciba の登録は、開始の時点で拒否される");

                foreach (string name in new string[]
                    { KnownClients.TestClient1, KnownClients.TestClient2, KnownClients.TestClient4 })
                {
                    JsonResponse start = await ClientModeTests.StartDeviceAuthZAsync(
                        client, Flows.Registration(client, name));

                    r.Verify(name + " は unauthorized_client（400）",
                        start.StatusCode == System.Net.HttpStatusCode.BadRequest
                            && start.Error == "unauthorized_client",
                        "400 / unauthorized_client",
                        (int)start.StatusCode + " / " + (start.Error ?? "（無し）"));
                }

                r.Note("**client_secret は正しいものを送っている。** 拒否の理由は認証の失敗ではなく、"
                    + "**登録種別がこのグラントを許さないこと**（だから invalid_client ではなく unauthorized_client）。");

                r.Note("**トークン発行（/token）側でも同じ判定をしている**が、開始で弾かれるため到達できず、"
                    + "この E2E では単独で測っていない。");

                r.Done();
            }
        }

        /// <summary>Device AuthZ を開始する（機密クライアントは client_secret も送る）</summary>
        /// <param name="client">IdPClient</param>
        /// <param name="reg">ClientRegistration</param>
        /// <returns>JsonResponse</returns>
        private static Task<JsonResponse> StartDeviceAuthZAsync(IdPClient client, ClientRegistration reg)
        {
            Dictionary<string, string> form = new Dictionary<string, string>()
            {
                { "client_id", reg.ClientId },
                { "scope", "profile email" }
            };

            if (!string.IsNullOrEmpty(reg.ClientSecret))
            {
                form["client_secret"] = reg.ClientSecret;
            }

            return client.DeviceAuthorizationAsync(form);
        }

        #endregion
    }
}
