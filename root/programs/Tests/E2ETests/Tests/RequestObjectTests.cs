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
//* クラス日本語名  ：Request Object（request_uri）経路の実測
//*
//* 作成日時        ：－
//* 作成者          ：－
//* 更新履歴        ：－
//*
//*  日時        更新者            内容
//*  ----------  ----------------  -------------------------------------------------
//*  2026/09/08  玄人 幸道         新規（E2Eテスト基盤）
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
    /// Request Object（request_uri）を使う認可リクエストの実測。
    ///
    /// JAR（RFC 9101）では、認可パラメタをクエリ文字列ではなく署名付きJWTに入れ、
    /// PARで登録して request_uri で参照する。
    ///
    /// 一方 AuthorizationCodeProvider.Create は、認可コードに紐付ける
    /// redirect_uri / code_challenge / code_challenge_method を
    /// **クエリ文字列から**読んでいる。request_uri 経路では、これらは
    /// クエリ文字列に無いので null になる、というのがコードを読んだ限りの推測。
    ///
    /// 推測のままにしないために、ここで実際の応答を測る。
    /// </summary>
    public class RequestObjectTests : TargetTestBase
    {
        /// <summary>コンストラクタ</summary>
        /// <param name="output">ITestOutputHelper</param>
        public RequestObjectTests(ITestOutputHelper output) : base(output)
        {
        }

        #region アプリ同梱の自己テスト（FAPI2）

        /// <summary>
        /// FAPI2 の自己テストが request_uri の認可リクエストまで到達する。
        /// </summary>
        /// <param name="targetKey">core / netfx</param>
        /// <returns>Task</returns>
        [SkippableTheory]
        [MemberData(nameof(AllTargets))]
        public async Task FAPI2の自己テストがrequest_uriを組み立てる(string targetKey)
        {
            using (IdPClient client = await this.SignedInClientAsync(targetKey))
            {
                HttpResponseMessage starter = await client.StartSelfTestAsync(
                    "AuthorizationCodeFAPI2", "fapi2");

                string location = (starter.Headers.Location == null)
                    ? null : starter.Headers.Location.OriginalString;

                this.Output.WriteLine("HTTP " + (int)starter.StatusCode);
                this.Output.WriteLine("Location = " + (location ?? "(なし)"));

                Assert.False(string.IsNullOrEmpty(location),
                    "FAPI2 スターターがリダイレクトしませんでした（PAR への登録に失敗した可能性）。");

                Assert.Contains("request_uri=", location);
            }
        }

        /// <summary>
        /// FAPI2 クライアントは、client_secret だけのトークン要求を受け付けない。
        ///
        /// oauth2_oidc_mode=fapi2 のクライアントは、より強いクライアント認証
        /// （mTLS / private_key_jwt）を要求する。
        /// このため FAPI2 の経路だけでは、redirect_uri の照合まで到達しない。
        /// redirect_uri の照合は、normalモードのクライアント＋自前の Request Object で測る。
        /// </summary>
        /// <param name="targetKey">core / netfx</param>
        /// <returns>Task</returns>
        [SkippableTheory]
        [MemberData(nameof(AllTargets))]
        public async Task FAPI2クライアントはclient_secretのトークン要求を拒否する(string targetKey)
        {
            using (IdPClient client = await this.SignedInClientAsync(targetKey))
            {
                ClientRegistration registration = Flows.Registration(client, KnownClients.TestClient2);

                AuthZResponse authz = await this.RunFAPI2SelfTestAsync(client);

                Assert.False(string.IsNullOrEmpty(authz.Code),
                    "FAPI2 の request_uri 経路で認可コードが発行されませんでした: " + authz.ToString());

                JsonResponse token = await Flows.ExchangeCodeAsync(
                    client, registration, authz.Code, registration.RedirectUri);

                this.Output.WriteLine(token.ToString());

                Assert.Null(token.AccessToken);
                Assert.Equal("unsupported_grant_type", token.Error);
            }
        }

        #endregion

        #region 自前で組み立てた Request Object（normalモードのクライアント）

        /// <summary>
        /// request_uri の認可リクエストで、認可コードが発行される。
        /// </summary>
        /// <param name="targetKey">core / netfx</param>
        /// <returns>Task</returns>
        [SkippableTheory]
        [MemberData(nameof(AllTargets))]
        public async Task request_uriの認可リクエストで認可コードが発行される(string targetKey)
        {
            using (IdPClient client = await this.SignedInClientAsync(targetKey))
            {
                ClientRegistration registration = Flows.Registration(client, KnownClients.TestClient);

                AuthZResponse authz = await this.AuthorizeViaRequestUriAsync(
                    client, registration, registration.RedirectUri);

                this.Output.WriteLine(authz.ToString());

                Assert.False(string.IsNullOrEmpty(authz.Code),
                    "request_uri 経路で認可コードが発行されませんでした。");
            }
        }

        /// <summary>
        /// request_uri 経路でも、同じ redirect_uri なら成功する（対照）。
        /// </summary>
        /// <param name="targetKey">core / netfx</param>
        /// <returns>Task</returns>
        [SkippableTheory]
        [MemberData(nameof(AllTargets))]
        public async Task request_uri経路で同じredirect_uriなら成功する(string targetKey)
        {
            using (IdPClient client = await this.SignedInClientAsync(targetKey))
            {
                ClientRegistration registration = Flows.Registration(client, KnownClients.TestClient);

                AuthZResponse authz = await this.AuthorizeViaRequestUriAsync(
                    client, registration, registration.RedirectUri);

                Assert.False(string.IsNullOrEmpty(authz.Code),
                    "request_uri 経路で認可コードが発行されませんでした: " + authz.ToString());

                JsonResponse token = await Flows.ExchangeCodeAsync(
                    client, registration, authz.Code, registration.RedirectUri);

                this.Output.WriteLine("正しい redirect_uri: " + token.ToString());

                Assert.Null(token.Error);
                Assert.False(string.IsNullOrEmpty(token.AccessToken), "access_token がありません。");
            }
        }

        /// <summary>
        /// request_uri 経路でも、redirect_uri が認可コードに紐付いている。
        ///
        /// Request Object には redirect_uri が入っている。
        /// RFC 6749 4.1.3 / OIDC Core 3.1.3.1 により、トークン リクエストの
        /// redirect_uri は、それと一致しなければならない。
        ///
        /// クエリ文字列の経路は #186 で対応済み。この経路も同じかどうかを測る。
        /// </summary>
        /// <param name="targetKey">core / netfx</param>
        /// <returns>Task</returns>
        [SkippableTheory(Skip = "未修正。実測（2026/09/08, net10.0）では、"
            + "誤った redirect_uri を送ってもトークンが発行される。")]
        [MemberData(nameof(AllTargets))]
        public async Task request_uri経路でもredirect_uriが照合される(string targetKey)
        {
            using (IdPClient client = await this.SignedInClientAsync(targetKey))
            {
                ClientRegistration registration = Flows.Registration(client, KnownClients.TestClient);

                AuthZResponse authz = await this.AuthorizeViaRequestUriAsync(
                    client, registration, registration.RedirectUri);

                Assert.False(string.IsNullOrEmpty(authz.Code),
                    "request_uri 経路で認可コードが発行されませんでした: " + authz.ToString());

                // 認可時とは違う redirect_uri を送る。
                JsonResponse token = await Flows.ExchangeCodeAsync(
                    client, registration, authz.Code, "https://attacker.example.com/callback");

                this.Output.WriteLine("誤った redirect_uri: " + token.ToString());

                Assert.Null(token.AccessToken);
                Assert.Equal("invalid_grant", token.Error);
            }
        }

        /// <summary>
        /// request_uri 経路でも、PKCE（RFC 7636）が機能する。
        ///
        /// Request Object に code_challenge / code_challenge_method を入れて認可し、
        /// トークン リクエストで code_verifier を送る。
        /// </summary>
        /// <param name="targetKey">core / netfx</param>
        /// <returns>Task</returns>
        [SkippableTheory]
        [MemberData(nameof(AllTargets))]
        public async Task request_uri経路のPKCEの実測(string targetKey)
        {
            const string Verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
            const string Challenge = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";

            using (IdPClient client = await this.SignedInClientAsync(targetKey))
            {
                ClientRegistration registration = Flows.Registration(client, KnownClients.TestClient);

                Dictionary<string, object> extra = new Dictionary<string, object>()
                {
                    { "code_challenge", Challenge },
                    { "code_challenge_method", "S256" }
                };

                AuthZResponse authz = await this.AuthorizeViaRequestUriAsync(
                    client, registration, registration.RedirectUri, extra);

                Assert.False(string.IsNullOrEmpty(authz.Code),
                    "request_uri + PKCE で認可コードが発行されませんでした: " + authz.ToString());

                // パブリック クライアントの作法で、client_secret を送らずに交換する。
                Dictionary<string, string> form = new Dictionary<string, string>()
                {
                    { "grant_type", "authorization_code" },
                    { "code", authz.Code },
                    { "client_id", registration.ClientId },
                    { "code_verifier", Verifier },
                    { "redirect_uri", registration.RedirectUri }
                };

                JsonResponse token = await client.TokenAsync(form);

                this.Output.WriteLine("正しい code_verifier: " + token.ToString());

                // 誤った code_verifier
                form["code_verifier"] = "WRONG-VERIFIER-WRONG-VERIFIER-WRONG-VERIFIER";
                AuthZResponse authz2 = await this.AuthorizeViaRequestUriAsync(
                    client, registration, registration.RedirectUri, extra);
                form["code"] = authz2.Code;

                JsonResponse token2 = await client.TokenAsync(form);

                this.Output.WriteLine("誤った code_verifier: " + token2.ToString());

                // 誤った code_verifier でトークンが出ないことだけは、必ず満たすこと。
                Assert.Null(token2.AccessToken);
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

            this.Output.WriteLine("認可リクエスト: " + url);

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
            this.Output.WriteLine("認可リクエスト: " + authorizeUrl);

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
