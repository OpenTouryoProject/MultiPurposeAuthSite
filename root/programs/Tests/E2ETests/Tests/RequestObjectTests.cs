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
//* クラス名        ：RequestObjectTests
//* クラス日本語名  ：RT Request Object（request_uri）経路の実測（#197）
//*
//* 作成日時        ：－
//* 作成者          ：－
//* 更新履歴        ：－
//*
//*  日時        更新者            内容
//*  ----------  ----------------  -------------------------------------------------
//*  2026/09/08  玄人 幸道         新規（E2Eテスト基盤）
//*  2026/09/09  玄人 幸道         redirect_uriの実測結果を#197として起票
//*  2026/09/10  玄人 幸道         TestReportで記録を残すよう変更（RT-197）
//**********************************************************************************

using System.Collections.Generic;
using System.Net.Http;
using System.Threading.Tasks;

using MultiPurposeAuthSite.Tests.E2E.Infrastructure;

using Xunit;
using Xunit.Abstractions;

namespace MultiPurposeAuthSite.Tests.E2E.Tests
{
    /// <summary>
    /// RT-197. Request Object（request_uri）を使う認可リクエストの実測。
    ///
    /// JAR（RFC 9101）では、認可パラメタをクエリ文字列ではなく署名付き JWT に入れ、
    /// PAR で登録して request_uri で参照する。
    ///
    /// 一方 AuthorizationCodeProvider.Create は、認可コードに紐付ける
    /// redirect_uri / code_challenge / code_challenge_method を
    /// **クエリ文字列から**読んでいる。request_uri 経路では、これらは
    /// クエリ文字列に無いため null になる。
    ///
    /// 測った結果は #197 に記録した。
    /// </summary>
    public class RequestObjectTests : TargetTestBase
    {
        /// <summary>コンストラクタ</summary>
        /// <param name="output">ITestOutputHelper</param>
        public RequestObjectTests(ITestOutputHelper output) : base(output)
        {
        }

        #region アプリ同梱の自己テスト（FAPI2）

        /// <summary>RT-197.1 FAPI2 の自己テストが request_uri を組み立てる</summary>
        /// <param name="targetKey">core / netfx</param>
        /// <returns>Task</returns>
        [SkippableTheory]
        [MemberData(nameof(AllTargets))]
        public async Task RT197_01_FAPI2の自己テストがrequest_uriを組み立てる(string targetKey)
        {
            using (IdPClient client = await this.SignedInClientAsync(targetKey))
            {
                TestReport r = this.Report("RT-197.1",
                    "FAPI2 の自己テストが、PAR 登録から request_uri の認可リクエストまで到達する",
                    "**以降のテストの前提。** アプリ同梱の自己テストが、"
                    + "Request Object を作って PAR（`/ros`）へ登録し、"
                    + "`request_uri` 付きの認可リクエストを組み立てられること。"
                    + "ここで止まる場合、原因は経路の不備ではなく"
                    + "**起動 URL の食い違い**であることが多い。",
                    "RFC 9101（JAR）/ RFC 9126（PAR。ただしこの実装の `/ros` は独自仕様）");

                r.Target("client_name=" + KnownClients.TestClient2 + "（oauth2_oidc_mode=fapi2）");
                r.Step("POST /Home/Saml2OAuth2Starters に submit.AuthorizationCodeFAPI2 を送る");

                HttpResponseMessage starter = await client.StartSelfTestAsync(
                    "AuthorizationCodeFAPI2", "fapi2");

                string location = (starter.Headers.Location == null)
                    ? null : starter.Headers.Location.OriginalString;

                r.Verify("リダイレクトする", !string.IsNullOrEmpty(location),
                    "Location ヘッダあり",
                    string.IsNullOrEmpty(location)
                        ? "HTTP " + (int)starter.StatusCode + " / Location なし"
                          + "（PAR への登録に失敗した可能性）"
                        : "HTTP " + (int)starter.StatusCode);

                r.Verify("リダイレクト先に request_uri が付く",
                    location.Contains("request_uri="),
                    "request_uri= を含む",
                    "Location = " + location);

                r.Done();
            }
        }

        /// <summary>RT-197.2 FAPI2 クライアントは client_secret のトークン要求を拒否する</summary>
        /// <param name="targetKey">core / netfx</param>
        /// <returns>Task</returns>
        [SkippableTheory]
        [MemberData(nameof(AllTargets))]
        public async Task RT197_02_FAPI2クライアントはclient_secretのトークン要求を拒否する(string targetKey)
        {
            using (IdPClient client = await this.SignedInClientAsync(targetKey))
            {
                TestReport r = this.Report("RT-197.2",
                    "FAPI2 クライアントは、client_secret だけのトークン要求を受け付けない",
                    "`oauth2_oidc_mode=fapi2` のクライアントは、より強いクライアント認証"
                    + "（mTLS / private_key_jwt）を要求する。"
                    + "**この性質のため、FAPI2 の経路では redirect_uri の照合まで到達しない。**"
                    + "照合そのものは RT-197.4 で、normal モードのクライアントを使って測る。",
                    "FAPI 2.0 Security Profile（クライアント認証は mTLS または"
                    + " private_key_jwt）/ RFC 6749 §5.2");

                ClientRegistration reg = Flows.Registration(client, KnownClients.TestClient2);

                r.Target("client_name=" + KnownClients.TestClient2);
                r.Step("(1) FAPI2 の自己テストで request_uri 経路の code を得る");
                r.Step("(2) client_secret を添えてトークンに交換する");

                AuthZResponse authz = await this.RunFAPI2SelfTestAsync(client);

                r.Verify("request_uri 経路で認可コードが発行される",
                    !string.IsNullOrEmpty(authz.Code),
                    "code あり",
                    string.IsNullOrEmpty(authz.Code) ? authz.ToString() : "code あり");

                JsonResponse token = await Flows.ExchangeCodeAsync(
                    client, reg, authz.Code, reg.RedirectUri);

                r.Verify("トークンを発行しない", string.IsNullOrEmpty(token.AccessToken),
                    "access_token を返さない",
                    token.AccessToken == null ? "返さなかった" : "**返してしまった**");

                r.VerifyEqual("unsupported_grant_type で拒否される",
                    "unsupported_grant_type", token.Error);

                r.Done();
            }
        }

        #endregion

        #region 自前で組み立てた Request Object（normal モードのクライアント）

        /// <summary>RT-197.3 request_uri の認可リクエストで認可コードが発行される</summary>
        /// <param name="targetKey">core / netfx</param>
        /// <returns>Task</returns>
        [SkippableTheory]
        [MemberData(nameof(AllTargets))]
        public async Task RT197_03_request_uriの認可リクエストで認可コードが発行される(string targetKey)
        {
            using (IdPClient client = await this.SignedInClientAsync(targetKey))
            {
                TestReport r = this.Report("RT-197.3",
                    "自前で署名した Request Object でも、認可コードが発行される",
                    "**RT-197.4 / 197.5 の前提。** 実装側の JWS クラスを使わず、"
                    + "テスト側で RS256 の署名を作って PAR に登録し、認可まで通せること。"
                    + "normal モードのクライアントを使うのは、"
                    + "FAPI2 だとクライアント認証で先に弾かれる（RT-197.2）ため。",
                    "RFC 9101 §4（Request Object の署名）/ OIDC Core §6.2（request_uri）");

                ClientRegistration reg = Flows.Registration(client, KnownClients.TestClient);

                r.Target("client_name=" + KnownClients.TestClient
                    + "（jwk_rsa_publickey 登録済み、oauth2_oidc_mode 指定なし）");
                r.Step("(1) SpRp_RsaPfxFilePath の秘密鍵で Request Object に署名する");
                r.Step("(2) POST /ros に登録して request_uri を得る");
                r.Step("(3) GET /authorize?request_uri=… で認可する");

                AuthZResponse authz = await this.AuthorizeViaRequestUriAsync(
                    client, reg, reg.RedirectUri);

                r.Verify("認可コードが発行される", !string.IsNullOrEmpty(authz.Code),
                    "code あり",
                    string.IsNullOrEmpty(authz.Code) ? authz.ToString() : "code あり");

                r.Done();
            }
        }

        /// <summary>RT-197.4 request_uri 経路で同じ redirect_uri なら成功する</summary>
        /// <param name="targetKey">core / netfx</param>
        /// <returns>Task</returns>
        [SkippableTheory]
        [MemberData(nameof(AllTargets))]
        public async Task RT197_04_request_uri経路で同じredirect_uriなら成功する(string targetKey)
        {
            using (IdPClient client = await this.SignedInClientAsync(targetKey))
            {
                TestReport r = this.Report("RT-197.4",
                    "request_uri 経路でも、同じ redirect_uri ならトークンが取得できる",
                    "**RT-197.5 の対照。** この経路が機能していること自体を先に示す。"
                    + "これが通らなければ、RT-197.5 の結果は"
                    + "「照合が効いていない」ではなく「経路が壊れている」になる。",
                    "RFC 6749 §4.1.3 / OIDC Core §3.1.3.1");

                ClientRegistration reg = Flows.Registration(client, KnownClients.TestClient);

                r.Target("client_name=" + KnownClients.TestClient);
                r.Step("(1) Request Object に redirect_uri を入れて認可する");
                r.Step("(2) 同じ redirect_uri でトークンに交換する");

                AuthZResponse authz = await this.AuthorizeViaRequestUriAsync(
                    client, reg, reg.RedirectUri);

                Assert.False(string.IsNullOrEmpty(authz.Code), "前提: code が取得できること");

                JsonResponse token = await Flows.ExchangeCodeAsync(
                    client, reg, authz.Code, reg.RedirectUri);

                r.Verify("エラーにならない", string.IsNullOrEmpty(token.Error),
                    "error なし", token.Error ?? "error なし");

                r.Verify("access_token が返る", !string.IsNullOrEmpty(token.AccessToken),
                    "access_token あり", token.AccessToken == null ? "なし" : "あり（値は伏せる）");

                r.Done();
            }
        }

        /// <summary>RT-197.5 request_uri 経路でも redirect_uri が照合される</summary>
        /// <param name="targetKey">core / netfx</param>
        /// <returns>Task</returns>
        [SkippableTheory(Skip = "未修正（#197）。実測（2026/09/09, net10.0）では、"
            + "誤った redirect_uri を送ってもトークンが発行される。")]
        [MemberData(nameof(AllTargets))]
        public async Task RT197_05_request_uri経路でもredirect_uriが照合される(string targetKey)
        {
            using (IdPClient client = await this.SignedInClientAsync(targetKey))
            {
                TestReport r = this.Report("RT-197.5",
                    "request_uri 経路でも、redirect_uri が認可コードに紐付いている",
                    "Request Object には redirect_uri が入っている。"
                    + "**クエリ文字列で渡したときと扱いが変わってはならない。**"
                    + "`AuthorizationCodeProvider.Create` がクエリ文字列だけを読むため、"
                    + "この経路では null が保存され、照合が素通りになる。"
                    + "#186 の対応が及んでいない箇所。",
                    "RFC 6749 §4.1.3 / OIDC Core §3.1.3.1 / #197");

                ClientRegistration reg = Flows.Registration(client, KnownClients.TestClient);

                r.Target("client_name=" + KnownClients.TestClient);
                r.Step("(1) Request Object に正しい redirect_uri を入れて認可する");
                r.Step("(2) https://attacker.example.com/callback を指定して交換する");

                AuthZResponse authz = await this.AuthorizeViaRequestUriAsync(
                    client, reg, reg.RedirectUri);

                Assert.False(string.IsNullOrEmpty(authz.Code), "前提: code が取得できること");

                JsonResponse token = await Flows.ExchangeCodeAsync(
                    client, reg, authz.Code, "https://attacker.example.com/callback");

                r.Verify("トークンを発行しない", string.IsNullOrEmpty(token.AccessToken),
                    "access_token を返さない",
                    token.AccessToken == null ? "返さなかった" : "**返してしまった**");

                r.VerifyEqual("invalid_grant で拒否される", "invalid_grant", token.Error);

                r.Done();
            }
        }

        /// <summary>RT-197.6 request_uri 経路の PKCE の実測</summary>
        /// <param name="targetKey">core / netfx</param>
        /// <returns>Task</returns>
        [SkippableTheory]
        [MemberData(nameof(AllTargets))]
        public async Task RT197_06_request_uri経路のPKCEの実測(string targetKey)
        {
            // RFC 7636 附録 B の例。
            const string Verifier  = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
            const string Challenge = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";

            using (IdPClient client = await this.SignedInClientAsync(targetKey))
            {
                TestReport r = this.Report("RT-197.6",
                    "request_uri 経路の PKCE が、どう振る舞うかを測る",
                    "`code_challenge` も redirect_uri と同じ理由で記録されない。"
                    + "ただし**向きが逆で、素通りではなく拒否になる**"
                    + "（`code_verifier` を示しても `invalid_client`）。"
                    + "安全側に倒れてはいるが、"
                    + "**`request_uri` ＋ PKCE のパブリック クライアントは機能しない。**"
                    + "ここで必ず満たすべきなのは「誤った検証子でトークンが出ないこと」だけ。",
                    "RFC 7636 §4.6 / RFC 9101 / #197");

                ClientRegistration reg = Flows.Registration(client, KnownClients.TestClient);

                Dictionary<string, object> extra = new Dictionary<string, object>()
                {
                    { "code_challenge", Challenge },
                    { "code_challenge_method", "S256" }
                };

                r.Target("client_name=" + KnownClients.TestClient);
                r.Step("(1) Request Object に code_challenge（S256）を入れて認可する");

                AuthZResponse authz = await this.AuthorizeViaRequestUriAsync(
                    client, reg, reg.RedirectUri, extra);

                r.Verify("認可コードが発行される", !string.IsNullOrEmpty(authz.Code),
                    "code あり",
                    string.IsNullOrEmpty(authz.Code) ? authz.ToString() : "code あり");

                r.Step("(2) 正しい code_verifier で交換する（client_secret は送らない）");

                Dictionary<string, string> form = new Dictionary<string, string>()
                {
                    { "grant_type", "authorization_code" },
                    { "code", authz.Code },
                    { "client_id", reg.ClientId },
                    { "code_verifier", Verifier },
                    { "redirect_uri", reg.RedirectUri }
                };

                JsonResponse token = await client.TokenAsync(form);

                r.Observe("正しい code_verifier のときの結果",
                    string.IsNullOrEmpty(token.Error)
                        ? "トークンが発行された"
                        : "拒否された（error=" + token.Error + "）",
                    "**拒否されるのが現状。** code_challenge が記録されていないため、"
                    + "PKCE 分岐がクライアントを認証できず invalid_client になる。"
                    + "安全側の失敗だが、この組み合わせは機能しない。");

                r.Step("(3) 誤った code_verifier で交換する（別の code を取り直す）");

                AuthZResponse authz2 = await this.AuthorizeViaRequestUriAsync(
                    client, reg, reg.RedirectUri, extra);

                form["code"] = authz2.Code;
                form["code_verifier"] = "WRONG-VERIFIER-WRONG-VERIFIER-WRONG-VERIFIER";

                JsonResponse token2 = await client.TokenAsync(form);

                r.Verify("誤った code_verifier ではトークンを発行しない",
                    string.IsNullOrEmpty(token2.AccessToken),
                    "access_token を返さない",
                    token2.AccessToken == null
                        ? "返さなかった（error=" + (token2.Error ?? "なし") + "）"
                        : "**返してしまった**");

                r.Done();
            }
        }

        #endregion

        #region ヘルパ

        /// <summary>
        /// Request Object を自前で組み立てて登録し、認可リクエストを送る。
        /// </summary>
        /// <param name="client">IdPClient</param>
        /// <param name="registration">クライアント</param>
        /// <param name="redirectUri">Request Object に入れる redirect_uri</param>
        /// <param name="extra">Request Object に追加するパラメタ</param>
        /// <returns>AuthZResponse</returns>
        private async Task<AuthZResponse> AuthorizeViaRequestUriAsync(
            IdPClient client, ClientRegistration registration, string redirectUri,
            IDictionary<string, object> extra = null)
        {
            Dictionary<string, object> parameters = new Dictionary<string, object>()
            {
                { "response_type", "code" },
                { "redirect_uri", redirectUri },
                { "scope", "openid email" },
                { "state", "state1" },
                { "nonce", "nonce1" },

                // 同意画面を挟まない。
                { "prompt", "none" }
            };

            if (extra != null)
            {
                foreach (KeyValuePair<string, object> p in extra)
                {
                    parameters[p.Key] = p.Value;
                }
            }

            string url = await RequestObjectBuilder.BuildAuthorizeUrlAsync(
                client, registration.ClientId, parameters);

            Assert.False(string.IsNullOrEmpty(url),
                "Request Object を PARエンドポイント（" + RequestObjectBuilder.RegistrationPath
                + "）に登録できませんでした。");

            AuthZResponse authz = await client.AuthorizeAndGrantAsync(url);

            if (!authz.Redirected)
            {
                // 何の画面が返ったのかを残す（原因の切り分けに要る）。
                this.Output.WriteLine("HTML応答: " + Html.Describe(authz.Body));
            }

            return authz;
        }

        /// <summary>
        /// アプリ同梱の FAPI2 自己テストを起動し、request_uri の認可リクエストを送る。
        /// </summary>
        /// <param name="client">IdPClient</param>
        /// <returns>AuthZResponse</returns>
        private async Task<AuthZResponse> RunFAPI2SelfTestAsync(IdPClient client)
        {
            HttpResponseMessage starter = await client.StartSelfTestAsync(
                "AuthorizationCodeFAPI2", "fapi2");

            string location = (starter.Headers.Location == null)
                ? null : starter.Headers.Location.OriginalString;

            Assert.False(string.IsNullOrEmpty(location),
                "FAPI2 スターターがリダイレクトしませんでした。");

            // スターターは構成ファイルのエンドポイントURLを返すので、
            // 実際に待ち受けているURLへ読み替える。
            string authorizeUrl = client.ToLocalUrl(location);

            // Request Object に prompt=none が入っていないので、同意画面が出る。
            AuthZResponse authz = await client.AuthorizeAndGrantAsync(authorizeUrl);

            if (!authz.Redirected)
            {
                this.Output.WriteLine("HTML応答: " + Html.Describe(authz.Body));
            }

            return authz;
        }

        #endregion
    }
}
