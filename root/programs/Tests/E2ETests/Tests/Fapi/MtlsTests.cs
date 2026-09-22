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
//* クラス名        ：MtlsTests
//* クラス日本語名  ：FA mTLS（クライアント証明書）で認証する経路（#226）
//*
//* 作成日時        ：－
//* 作成者          ：－
//* 更新履歴        ：－
//*
//*  日時        更新者            内容
//*  ----------  ----------------  -------------------------------------------------
//*  2026/09/22  玄人 幸道         新規（#226 : mTLS の経路を E2E で確かめる）
//*  2026/09/23  玄人 幸道         -NetFxMtls のとき、net48 版でも回す（#226）
//**********************************************************************************

using System;
using System.Collections.Generic;
using System.Security.Cryptography.X509Certificates;
using System.Text.Json;
using System.Threading.Tasks;

using MultiPurposeAuthSite.Tests.E2E.Infrastructure;

using Xunit;
using Xunit.Abstractions;

namespace MultiPurposeAuthSite.Tests.E2E.Tests.Fapi
{
    /// <summary>
    /// FA-6. mTLS（クライアント証明書。RFC 8705 の tls_client_auth）で認証する経路。
    /// </summary>
    /// <remarks>
    /// **既定では net10.0 版だけを測る。** サーバにクライアント証明書を受け付けさせるため、
    /// test.ps1 -Launch が、テスト専用のフック（Tests/MtlsTestHook）を net10.0 版にだけ読ませる
    /// （アプリのコードは変えない）。証明書はその場で作る自己署名のもので、ストアには入れない。
    ///
    /// **net48 版（IIS Express）は、準備だけを手動で行い、-NetFxMtls を付けて回す**（TESTING.md）。
    /// IIS は自己署名の証明書をアプリより前で 403.16 として断るため、テスト用 CA を
    /// コンピューターの信頼されたルートに入れ（管理者権限）、その CA が発行した証明書を CurrentUser\My に置く。
    /// -NetFxMtls を付けなければ、net48 版のケースは作らない（Skip にもしない）。
    ///
    /// クライアントは、TestClient2（fapi2）を写して Subject をテスト専用の値にした TestClient2_2 / TestClient2_3
    /// （雛形の TestClient1 / TestClient2 は同じ Subject を共有しているので使わない）。
    /// </remarks>
    public class MtlsTests : TargetTestBase
    {
        /// <summary>コンストラクタ</summary>
        /// <param name="output">ITestOutputHelper</param>
        public MtlsTests(ITestOutputHelper output) : base(output)
        {
        }

        /// <summary>Subject が一致しない証明書の Subject（net48 版では、これもテスト用 CA が発行したものを用意する）</summary>
        public const string OtherSubjectDn = "CN=mpas-e2e-mtls-other";

        /// <summary>
        /// 測る対象 : net10.0 版と、-NetFxMtls のときだけ net48 版
        /// </summary>
        /// <remarks>
        /// net48 版は準備（テスト用 CA）が要るので、既定ではケースを作らない。
        /// **作ってから Skip にすると、毎回の通しに Skip が並び、他の Skip が見えにくくなる**（TESTING.md 5 節）。
        /// </remarks>
        public static IEnumerable<object[]> MtlsTargets
        {
            get
            {
                yield return new object[] { TestEnv.CoreKey };

                if (Environment.GetEnvironmentVariable("MPAS_NETFX_MTLS") == "true")
                {
                    yield return new object[] { TestEnv.NetFxKey };
                }
            }
        }

        #region 補助

        /// <summary>対象のサイトがクライアント証明書を受け付けていなければ Skip する</summary>
        /// <param name="target">テスト対象</param>
        private static void SkipIfNoMtls(TargetInfo target)
        {
            string key = target.Key == TestEnv.NetFxKey ? "MPAS_NETFX_MTLS" : "MPAS_CORE_MTLS";

            Skip.If(Environment.GetEnvironmentVariable(key) != "true",
                target.DisplayName + " がクライアント証明書を受け付けていません"
                + "（test.ps1 -Launch のときだけ受け付けさせる。net48 版は -NetFxMtls も要る。#226）。");
        }

        /// <summary>認可コードを取り、クライアント証明書を添えて交換する（client_secret なし）</summary>
        /// <param name="client">IdPClient</param>
        /// <param name="reg">ClientRegistration</param>
        /// <param name="certificate">クライアント証明書（null なら添えない）</param>
        /// <returns>トークン応答</returns>
        private static async Task<JsonResponse> CodeWithCertificateAsync(
            IdPClient client, ClientRegistration reg, X509Certificate2 certificate)
        {
            AuthZResponse authz = await Flows.AuthorizeCodeAsync(client, reg, redirectUri: reg.RedirectUri);

            Assert.False(string.IsNullOrEmpty(authz.Code),
                "前提: 認可コードが取得できること（error=" + (authz.Error ?? "なし") + "）");

            return await client.TokenWithCertificateAsync(new Dictionary<string, string>()
            {
                { "grant_type", "authorization_code" },
                { "code", authz.Code },
                { "client_id", reg.ClientId },
                { "redirect_uri", reg.RedirectUri }
            }, certificate);
        }

        /// <summary>結果の表現（トークンの値は出さない）</summary>
        /// <param name="token">JsonResponse</param>
        /// <returns>文字列</returns>
        private static string Outcome(JsonResponse token)
        {
            return string.IsNullOrEmpty(token.AccessToken)
                ? "拒否（HTTP " + (int)token.StatusCode + " / error=" + (token.Error ?? "なし") + "）"
                : "トークンが返った";
        }

        #endregion

        /// <summary>FA-6.1 fapi2 は mTLS の認可コードで通る</summary>
        /// <param name="targetKey">core（-NetFxMtls のときは netfx も）</param>
        /// <returns>Task</returns>
        [SkippableTheory]
        [MemberData(nameof(MtlsTargets))]
        public async Task FA0601_fapi2はmTLSの認可コードで通る(string targetKey)
        {
            using (IdPClient client = await this.SignedInClientAsync(targetKey))
            {
                MtlsTests.SkipIfNoMtls(client.Target);
                ClientRegistration reg = Flows.InjectedRegistration(client, KnownClients.TestClient2_2);

                TestReport r = this.Report("FA-6.1",
                    "oauth2_oidc_mode=fapi2 のクライアントは、mTLS（Subject が一致する証明書）の認可コードで通る",
                    "**fapi2 を通すのは、ClientModePolicy の表の「認可コード × mTLS」の行だけ。**"
                    + "FA-2.1 は client_secret / PKCE では通らないことを測っており、"
                    + "本テストは**その対照（通る側）**。"
                    + "net48 版は -NetFxMtls のときだけ（TESTING.md）。",
                    "RFC 8705 §2.1（tls_client_auth）/ FAPI 2.0 / #226");

                r.Target("client_name=" + KnownClients.TestClient2_2
                    + "（TestClient2 の写し。Subject をテスト専用の値にしたもの。test.ps1 が差し込む）");

                r.Step("認可コードを取り、Subject が一致する自己署名の証明書を添えて交換する（client_secret は送らない）");

                using (X509Certificate2 cert = TestCertificate.ForTarget(client.Target, KnownClients.MtlsSubjectDn))
                {
                    JsonResponse token = await MtlsTests.CodeWithCertificateAsync(client, reg, cert);

                    r.Verify("トークンが返る",
                        !string.IsNullOrEmpty(token.AccessToken),
                        "トークンが返る", MtlsTests.Outcome(token));

                    Assert.False(string.IsNullOrEmpty(token.AccessToken), "前提: トークンが返ること");

                    JsonElement claims = Jwt.Payload(token.AccessToken);

                    r.VerifyEqual("fapi クレームは登録どおり fapi2", "fapi2", Jwt.String(claims, "fapi") ?? "（無し）");

                    r.Verify("アクセス トークンに cnf が載る（証明書に紐づく）",
                        Jwt.Has(claims, "cnf"),
                        "cnf あり", Jwt.Has(claims, "cnf") ? "cnf あり" : "**無し**");

                    r.Verify("refresh_token は発行されない",
                        string.IsNullOrEmpty(token.RefreshToken),
                        "発行されない",
                        string.IsNullOrEmpty(token.RefreshToken) ? "発行されない" : "**発行された**（値は伏せる）");

                    r.Note("**refresh_token の経路は normal の登録だけ**なので、fapi2 には発行しない（#224 の段階 2）。");
                }

                r.Done();
            }
        }

        /// <summary>FA-6.2 証明書が無い・Subject が違うなら invalid_client</summary>
        /// <param name="targetKey">core（-NetFxMtls のときは netfx も）</param>
        /// <returns>Task</returns>
        [SkippableTheory]
        [MemberData(nameof(MtlsTargets))]
        public async Task FA0602_証明書が無いかSubjectが違うならinvalid_client(string targetKey)
        {
            using (IdPClient client = await this.SignedInClientAsync(targetKey))
            {
                MtlsTests.SkipIfNoMtls(client.Target);
                ClientRegistration reg = Flows.InjectedRegistration(client, KnownClients.TestClient2_2);

                TestReport r = this.Report("FA-6.2",
                    "mTLS のクライアントは、証明書が無い・Subject が一致しないと invalid_client（401）になる",
                    "**クライアント認証は、証明書の Subject と登録の tls_client_auth_subject_dn の一致で行う。**"
                    + "client_secret を送らず、証明書も一致しなければ、認証に失敗する（RFC 6749 §5.2 : invalid_client）。",
                    "RFC 8705 §2.1 / RFC 6749 §5.2 / #226");

                r.Target("client_name=" + KnownClients.TestClient2_2);

                r.Step("(1) 証明書を添えずに交換する");

                JsonResponse none = await MtlsTests.CodeWithCertificateAsync(client, reg, null);

                r.Verify("トークンを返さない", string.IsNullOrEmpty(none.AccessToken),
                    "返さない", MtlsTests.Outcome(none));
                r.VerifyEqual("HTTP 401", "401", ((int)none.StatusCode).ToString());
                r.VerifyEqual("エラーは invalid_client", "invalid_client", none.Error ?? "（無し）");

                r.Step("(2) Subject が違う証明書を添えて交換する");

                using (X509Certificate2 other = TestCertificate.ForTarget(client.Target, MtlsTests.OtherSubjectDn))
                {
                    JsonResponse mismatch = await MtlsTests.CodeWithCertificateAsync(client, reg, other);

                    r.Verify("トークンを返さない", string.IsNullOrEmpty(mismatch.AccessToken),
                        "返さない", MtlsTests.Outcome(mismatch));
                    r.VerifyEqual("HTTP 401", "401", ((int)mismatch.StatusCode).ToString());
                    r.VerifyEqual("エラーは invalid_client", "invalid_client", mismatch.Error ?? "（無し）");
                }

                r.Done();
            }
        }

        /// <summary>FA-6.3 登録種別が既知でない値なら、証明書が一致しても通さない</summary>
        /// <param name="targetKey">core（-NetFxMtls のときは netfx も）</param>
        /// <returns>Task</returns>
        [SkippableTheory]
        [MemberData(nameof(MtlsTargets))]
        public async Task FA0603_登録種別が既知でない値なら証明書が一致しても通さない(string targetKey)
        {
            using (IdPClient client = await this.SignedInClientAsync(targetKey))
            {
                MtlsTests.SkipIfNoMtls(client.Target);
                ClientRegistration reg = Flows.InjectedRegistration(client, KnownClients.TestClient2_3);

                TestReport r = this.Report("FA-6.3",
                    "oauth2_oidc_mode が既知でない値（fapi_1）のクライアントは、Subject が一致する証明書でも通らない",
                    "**既知でない登録値は、不正な登録として拒否する**（#224 の段階 2 の E）。"
                    + "以前は fapi2 とみなしていたので、**この経路（認可コード × mTLS）では通っていた**。"
                    + "FA-5.2（CIBA）は以前の扱いでも拒否されるため区別できず、違いが出るのはここだけ。",
                    "#224 / #226");

                r.Target("client_name=" + KnownClients.TestClient2_3
                    + "（TestClient2_2 と同じ Subject。登録種別だけ fapi_1＝書き間違い。test.ps1 が差し込む）");

                r.Step("(1) 認可リクエストを送る");

                AuthZResponse authz = await Flows.AuthorizeCodeAsync(client, reg, redirectUri: reg.RedirectUri);

                r.Verify("認可コードを発行しない", string.IsNullOrEmpty(authz.Code),
                    "発行しない", string.IsNullOrEmpty(authz.Code) ? "発行しない" : "**発行した**");
                r.VerifyEqual("エラーは unauthorized_client", "unauthorized_client", authz.Error ?? "（無し）");

                r.Step("(2) 証明書で認証できることを、トークン エンドポイント（client_credentials）で確かめる");

                using (X509Certificate2 cert = TestCertificate.ForTarget(client.Target, KnownClients.MtlsSubjectDn))
                {
                    JsonResponse cc = await client.TokenWithCertificateAsync(new Dictionary<string, string>()
                    {
                        { "grant_type", "client_credentials" },
                        { "client_id", reg.ClientId },
                        { "scope", "profile" }
                    }, cert);

                    r.Verify("トークンを返さない", string.IsNullOrEmpty(cc.AccessToken),
                        "返さない", MtlsTests.Outcome(cc));

                    // invalid_client ではない ＝ 証明書による認証は通り、その後の登録種別の判定で断られた
                    r.VerifyEqual("エラーは unauthorized_client（認証は通っている）",
                        "unauthorized_client", cc.Error ?? "（無し）");

                    r.Verify("説明は「登録値が不正」",
                        (cc.ErrorDescription ?? "").Contains("is invalid"),
                        "The mode of this client (…) is invalid.", cc.ErrorDescription ?? "（無し）");
                }

                r.Done();
            }
        }
    }
}
