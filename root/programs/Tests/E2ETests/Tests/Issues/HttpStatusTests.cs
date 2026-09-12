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
//* クラス名        ：HttpStatusTests
//* クラス日本語名  ：RT エラー応答の HTTP ステータスの回帰（#196）
//*
//* 作成日時        ：－
//* 作成者          ：－
//* 更新履歴        ：－
//*
//*  日時        更新者            内容
//*  ----------  ----------------  -------------------------------------------------
//*  2026/09/11  玄人 幸道         新規（#196 の 1 つ目 : /token）
//*  2026/09/11  玄人 幸道         /userinfo（RT-196.5 〜 196.7）を追加（#196 の 2 つ目）
//*  2026/09/11  玄人 幸道         /revoke（RT-196.8 〜 196.10）を追加（#196 の 3 つ目）
//*  2026/09/11  玄人 幸道         /introspect（RT-196.11 〜 196.13）を追加（#196 の 4 つ目）
//*  2026/09/11  玄人 幸道         /device_authz（RT-196.14 〜 196.15）を追加（#196 の 5 つ目）
//*  2026/09/11  玄人 幸道         /ciba_authz（RT-196.16 〜 196.18）を追加（#196 の 6 つ目）
//*  2026/09/12  玄人 幸道         /SetDeviceToken・/ciba_result（RT-196.19 〜 196.20）を追加（#196 の 7 つ目）
//**********************************************************************************

using System.Collections.Generic;
using System.Net;
using System.Text.Json;
using System.Threading.Tasks;

using MultiPurposeAuthSite.Tests.E2E.Infrastructure;

using Xunit;
using Xunit.Abstractions;

namespace MultiPurposeAuthSite.Tests.E2E.Tests
{
    /// <summary>
    /// RT-196. エラー応答の HTTP ステータス（#196）。
    ///
    /// 以前は、どのエンドポイントもエラーを HTTP 200 で返していた。
    /// エンドポイントごとに分けて直しているので、テストも分けて足していく。
    ///
    ///   RT-196.1 〜 196.4 : /token（RFC 6749 §5.2 : エラーは 400、invalid_client は 401）
    ///   RT-196.5 〜 196.7 : /userinfo（RFC 6750 §3 : 401 と WWW-Authenticate: Bearer）
    ///   RT-196.8 〜 196.10 : /revoke（RFC 7009 §2.2.1 : エラーは /token と同じ。成功と無効なトークンは 200）
    ///   RT-196.11 〜 196.13 : /introspect（RFC 7662 §2.3 : 認証の失敗は 401。active=false は 200）
    ///   RT-196.14 〜 196.15 : /device_authz（RFC 8628 §3.1 : クライアント認証は /token と同じ。失敗は 401）
    ///   RT-196.16 〜 196.18 : /ciba_authz（CIBA Core §13 : invalid_client は 401、それ以外は 400。成功の経路は EX-8）
    ///   RT-196.19 〜 196.20 : /SetDeviceToken・/ciba_result（本文は OK / NG のまま。トークンの不備は 401、パラメタの不備は 400）
    ///
    /// /token・/revoke・/introspect・/device_authz では、**本文（error / error_description の JSON）が変わっていないこと**も併せて見る。
    /// ステータスだけ直して本文が壊れると、既存のクライアントが error を読めなくなる。
    /// /userinfo は RFC 6750 に合わせて本文も変えた（無効なトークンは invalid_token、トークン無しは本文なし）。
    /// /ciba_authz は CIBA Core §13 に合わせてエラー コードも変えた（空・server_error だった経路を、正しいコードに）。
    /// </summary>
    public class HttpStatusTests : TargetTestBase
    {
        /// <summary>コンストラクタ</summary>
        /// <param name="output">ITestOutputHelper</param>
        public HttpStatusTests(ITestOutputHelper output) : base(output)
        {
        }

        /// <summary>HTTP ステータスと、本文の error を確かめる</summary>
        /// <param name="r">TestReport</param>
        /// <param name="label">何の要求か</param>
        /// <param name="res">応答</param>
        /// <param name="status">期待する HTTP ステータス</param>
        /// <param name="error">期待する error（null なら値は見ない）</param>
        private static void VerifyError(
            TestReport r, string label, JsonResponse res, int status, string error)
        {
            r.VerifyEqual(label + " : HTTP " + status + " で返る",
                status.ToString(), ((int)res.StatusCode).ToString());

            r.Verify(label + " : 本文は error を含む JSON のまま", res.IsJson && !string.IsNullOrEmpty(res.Error),
                "error を含む JSON", res.ToString());

            if (error != null)
            {
                r.VerifyEqual(label + " : error", error, res.Error);
            }
        }

        /// <summary>WWW-Authenticate が Bearer 方式を示すかを確かめる</summary>
        /// <param name="r">TestReport</param>
        /// <param name="label">何の要求か</param>
        /// <param name="res">応答</param>
        /// <returns>WWW-Authenticate の値（無ければ null）</returns>
        private static string VerifyBearerChallenge(TestReport r, string label, JsonResponse res)
        {
            string challenge = res.Header("WWW-Authenticate");

            r.Verify(label + " : WWW-Authenticate が Bearer 方式を示す",
                challenge != null && challenge.TrimStart().StartsWith("Bearer", System.StringComparison.OrdinalIgnoreCase),
                "Bearer ...", challenge ?? "（無し）");

            return challenge;
        }

        /// <summary>無効なトークンへの /userinfo の応答を確かめる（RFC 6750 §3.1）</summary>
        /// <param name="r">TestReport</param>
        /// <param name="label">何の要求か</param>
        /// <param name="res">応答</param>
        private static void VerifyInvalidToken(TestReport r, string label, JsonResponse res)
        {
            VerifyError(r, label, res, 401, "invalid_token");

            string challenge = VerifyBearerChallenge(r, label, res);

            r.Verify(label + " : WWW-Authenticate に error=\"invalid_token\" が付く",
                challenge != null && challenge.Contains("error=\"invalid_token\""),
                "error=\"invalid_token\"", challenge ?? "（無し）");
        }

        /// <summary>CIBA の認証リクエスト（ES256）を /ros に登録し、request_uri を返す</summary>
        /// <param name="client">IdPClient</param>
        /// <param name="reg">CIBA のクライアント</param>
        /// <param name="overrides">既定の値を上書きするクレーム</param>
        /// <returns>request_uri</returns>
        private static async Task<string> RegisterCibaRequestAsync(
            IdPClient client, ClientRegistration reg, IDictionary<string, object> overrides)
        {
            string requestUri = await RequestObjectBuilder.RegisterAsync(
                client, RequestObjectBuilder.CreateCiba(client, reg.ClientId, overrides));

            Assert.False(string.IsNullOrEmpty(requestUri),
                "前提: /ros が、ES256 で署名した CIBA の要求を受け付けること");

            return requestUri;
        }

        /// <summary>"NG" で答えるエンドポイント（/SetDeviceToken・/ciba_result）の失敗を確かめる</summary>
        /// <param name="r">TestReport</param>
        /// <param name="label">何の要求か</param>
        /// <param name="res">応答</param>
        /// <param name="status">期待する HTTP ステータス</param>
        /// <param name="bearerError">401 のときに期待する WWW-Authenticate の error（トークンが無い場合は null）</param>
        private static void VerifyNG(TestReport r, string label, JsonResponse res, int status, string bearerError)
        {
            r.VerifyEqual(label + " : HTTP " + status + " で返る", status.ToString(), ((int)res.StatusCode).ToString());

            r.VerifyEqual(label + " : 本文は NG のまま", "NG", res.Text);

            if (status != 401)
            {
                return;
            }

            string challenge = VerifyBearerChallenge(r, label, res);

            if (bearerError == null)
            {
                r.Verify(label + " : WWW-Authenticate にエラー コードを付けない",
                    challenge != null && !challenge.Contains("error="),
                    "error= なし", challenge ?? "（無し）");
            }
            else
            {
                r.Verify(label + " : WWW-Authenticate に error=\"" + bearerError + "\" が付く",
                    challenge != null && challenge.Contains("error=\"" + bearerError + "\""),
                    "error=\"" + bearerError + "\"", challenge ?? "（無し）");
            }
        }

        /// <summary>RT-196.1 クライアント認証の失敗（フォーム）</summary>
        /// <param name="targetKey">core / netfx</param>
        /// <returns>Task</returns>
        [SkippableTheory]
        [MemberData(nameof(AllTargets))]
        public async Task RT196_01_tokenでクライアント認証の失敗は401(string targetKey)
        {
            using (IdPClient client = this.Client(targetKey))
            {
                TestReport r = this.Report("RT-196.1",
                    "/token : クライアント認証の失敗（client_secret_post）は HTTP 401",
                    "invalid_client は、要求の中身ではなく**誰が要求したか**の失敗。"
                    + "400 と区別されていれば、クライアントは「資格情報を見直す」と判断できる。",
                    "RFC 6749 §5.2（invalid_client は 401 を返してよい）/ #196");

                ClientRegistration reg = Flows.Registration(client, KnownClients.MvcSample);

                r.Target("client_name=" + KnownClients.MvcSample + "（client_secret だけを誤らせる）");
                r.Step("POST /token に grant_type=client_credentials と誤った client_secret をフォームで送る");

                JsonResponse res = await client.TokenAsync(new Dictionary<string, string>()
                {
                    { "grant_type", "client_credentials" },
                    { "scope", "profile" },
                    { "client_id", reg.ClientId },
                    { "client_secret", "WRONG-SECRET-WRONG-SECRET" }
                });

                VerifyError(r, "誤った client_secret", res, 401, "invalid_client");

                r.Observe("WWW-Authenticate", res.Header("WWW-Authenticate") ?? "（無し）",
                    "フォームで認証を試みた場合は任意。付けると、受け付ける認証方式をクライアントに示せる。");

                r.Done();
            }
        }

        /// <summary>RT-196.2 クライアント認証の失敗（Authorization ヘッダ）</summary>
        /// <param name="targetKey">core / netfx</param>
        /// <returns>Task</returns>
        [SkippableTheory]
        [MemberData(nameof(AllTargets))]
        public async Task RT196_02_tokenでBasic認証の失敗は401とWWW_Authenticate(string targetKey)
        {
            using (IdPClient client = this.Client(targetKey))
            {
                TestReport r = this.Report("RT-196.2",
                    "/token : Authorization ヘッダでの認証の失敗は、HTTP 401 と WWW-Authenticate",
                    "Authorization ヘッダ（client_secret_basic）で認証を試みたクライアントには、"
                    + "**401 と、同じ方式の WWW-Authenticate を必ず返す**。"
                    + "HTTP 認証の約束事であり、ここを外すと汎用の HTTP クライアントが認証の失敗と認識できない。",
                    "RFC 6749 §5.2（Authorization ヘッダで認証した場合は 401 と WWW-Authenticate が MUST）"
                    + " / §2.3.1 / #196");

                ClientRegistration reg = Flows.Registration(client, KnownClients.MvcSample);

                r.Target("client_name=" + KnownClients.MvcSample + "（Basic 認証の client_secret だけを誤らせる）");
                r.Step("POST /token に grant_type=client_credentials を送り、"
                    + "client_id と誤った client_secret を Authorization: Basic で渡す");

                JsonResponse res = await client.TokenWithBasicAuthAsync(new Dictionary<string, string>()
                {
                    { "grant_type", "client_credentials" },
                    { "scope", "profile" }
                }, reg.ClientId, "WRONG-SECRET-WRONG-SECRET");

                VerifyError(r, "誤った client_secret（Basic）", res, 401, "invalid_client");

                string challenge = res.Header("WWW-Authenticate");

                r.Verify("WWW-Authenticate が Basic 方式を示す",
                    challenge != null && challenge.TrimStart().StartsWith("Basic", System.StringComparison.OrdinalIgnoreCase),
                    "Basic ...", challenge ?? "（無し）");

                r.Done();
            }
        }

        /// <summary>RT-196.3 それ以外のエラー</summary>
        /// <param name="targetKey">core / netfx</param>
        /// <returns>Task</returns>
        [SkippableTheory]
        [MemberData(nameof(AllTargets))]
        public async Task RT196_03_tokenでそれ以外のエラーは400(string targetKey)
        {
            using (IdPClient client = this.Client(targetKey))
            {
                TestReport r = this.Report("RT-196.3",
                    "/token : クライアント認証以外のエラーは HTTP 400",
                    "要求の中身の誤り（無効な refresh_token、grant_type の欠落・未知の値）は 400。"
                    + "**正しく認証したクライアントの要求は、401 にしない**（資格情報の問題と取り違えさせない）。",
                    "RFC 6749 §5.2（エラーは 400）/ #196");

                ClientRegistration reg = Flows.Registration(client, KnownClients.MvcSample);

                r.Target("client_name=" + KnownClients.MvcSample + "（資格情報は正しい）");

                r.Step("(1) 存在しない refresh_token で更新する");

                JsonResponse badGrant = await client.TokenAsync(new Dictionary<string, string>()
                {
                    { "grant_type", "refresh_token" },
                    { "refresh_token", "NOT-A-REAL-TOKEN" },
                    { "client_id", reg.ClientId },
                    { "client_secret", reg.ClientSecret }
                });

                VerifyError(r, "存在しない refresh_token", badGrant, 400, "invalid_grant");

                r.Step("(2) grant_type を付けずに送る");

                JsonResponse noGrant = await client.TokenAsync(new Dictionary<string, string>()
                {
                    { "client_id", reg.ClientId },
                    { "client_secret", reg.ClientSecret }
                });

                VerifyError(r, "grant_type なし", noGrant, 400, null);

                r.Step("(3) 未知の grant_type を送る");

                JsonResponse unknown = await client.TokenAsync(new Dictionary<string, string>()
                {
                    { "grant_type", "urn:example:unknown" },
                    { "client_id", reg.ClientId },
                    { "client_secret", reg.ClientSecret }
                });

                VerifyError(r, "未知の grant_type", unknown, 400, null);

                r.Observe("error の値（grant_type なし / 未知）",
                    (noGrant.Error ?? "なし") + " / " + (unknown.Error ?? "なし"),
                    "RFC 6749 §5.2 では、欠落は invalid_request、未知の値は unsupported_grant_type が相当する。"
                    + "本 Issue（HTTP ステータス）の範囲外なので、値は判定しない。");

                r.Done();
            }
        }

        /// <summary>RT-196.4 成功は 200（対照）</summary>
        /// <param name="targetKey">core / netfx</param>
        /// <returns>Task</returns>
        [SkippableTheory]
        [MemberData(nameof(AllTargets))]
        public async Task RT196_04_tokenの成功は200のまま(string targetKey)
        {
            using (IdPClient client = this.Client(targetKey))
            {
                TestReport r = this.Report("RT-196.4",
                    "/token : 成功は HTTP 200 のまま（対照）",
                    "**RT-196.1 〜 196.3 の対照。** エラーの返し方を変えたことで、"
                    + "成功の応答まで変わっていないことを確かめる（Basic 認証の成功も含む）。",
                    "RFC 6749 §5.1（成功は 200）/ #196");

                ClientRegistration reg = Flows.Registration(client, KnownClients.MvcSample);

                r.Target("client_name=" + KnownClients.MvcSample);
                r.Step("(1) client_secret_post（フォーム）で client_credentials を送る");

                JsonResponse post = await client.TokenAsync(new Dictionary<string, string>()
                {
                    { "grant_type", "client_credentials" },
                    { "scope", "profile" },
                    { "client_id", reg.ClientId },
                    { "client_secret", reg.ClientSecret }
                });

                r.VerifyEqual("フォーム : HTTP 200", "200", ((int)post.StatusCode).ToString());
                r.Verify("フォーム : access_token が返る", !string.IsNullOrEmpty(post.AccessToken),
                    "access_token あり", post.AccessToken == null ? "なし（" + post.ToString() + "）" : "あり（値は伏せる）");

                r.Step("(2) client_secret_basic（Authorization ヘッダ）で同じ要求を送る");

                JsonResponse basic = await client.TokenWithBasicAuthAsync(new Dictionary<string, string>()
                {
                    { "grant_type", "client_credentials" },
                    { "scope", "profile" }
                }, reg.ClientId, reg.ClientSecret);

                r.VerifyEqual("Basic : HTTP 200", "200", ((int)basic.StatusCode).ToString());
                r.Verify("Basic : access_token が返る", !string.IsNullOrEmpty(basic.AccessToken),
                    "access_token あり", basic.AccessToken == null ? "なし（" + basic.ToString() + "）" : "あり（値は伏せる）");

                r.Done();
            }
        }

        /// <summary>RT-196.5 /userinfo にトークン無し</summary>
        /// <param name="targetKey">core / netfx</param>
        /// <returns>Task</returns>
        [SkippableTheory]
        [MemberData(nameof(AllTargets))]
        public async Task RT196_05_userinfoでトークン無しは401とBearerの要求(string targetKey)
        {
            using (IdPClient client = this.Client(targetKey))
            {
                TestReport r = this.Report("RT-196.5",
                    "/userinfo : Bearer トークンの無い要求は、HTTP 401 と WWW-Authenticate: Bearer（エラー コードなし）",
                    "トークンを付け忘れた（または別の方式で認証しようとした）クライアントに、"
                    + "**Bearer トークンが要ることを、HTTP の約束事で伝える。**"
                    + "認証情報が無いだけなので、エラー コードは付けない。",
                    "RFC 6750 §3 / §3.1（認証情報の無い要求にはエラー情報を含めない）/ OIDC Core §5.3.3 / #196");

                r.Target(client.Target.DisplayName);
                r.Step("(1) Authorization ヘッダを付けずに GET /userinfo を送る");

                JsonResponse none = await client.UserInfoWithAuthorizationAsync(null);

                r.VerifyEqual("ヘッダ無し : HTTP 401 で返る", "401", ((int)none.StatusCode).ToString());

                string challenge = VerifyBearerChallenge(r, "ヘッダ無し", none);

                r.Verify("ヘッダ無し : WWW-Authenticate にエラー コードを付けない",
                    challenge != null && !challenge.Contains("error="),
                    "error= なし", challenge ?? "（無し）");

                r.Verify("ヘッダ無し : 本文に、エラー情報もユーザ情報も含めない",
                    string.IsNullOrEmpty(none.Error) && none.KindOf("sub") == JsonValueKind.Undefined,
                    "error なし・sub なし", none.ToString());

                r.Step("(2) Bearer ではなく Basic 方式の Authorization ヘッダで GET /userinfo を送る");

                JsonResponse basic = await client.UserInfoWithAuthorizationAsync(
                    "Basic " + System.Convert.ToBase64String(System.Text.Encoding.ASCII.GetBytes("user:password")));

                r.VerifyEqual("Basic 方式 : HTTP 401 で返る", "401", ((int)basic.StatusCode).ToString());

                VerifyBearerChallenge(r, "Basic 方式", basic);

                r.Step("(3) 観測 : 方式だけで値の無い Authorization ヘッダ（Bearer のみ）で GET /userinfo を送る");

                JsonResponse empty = await client.UserInfoWithAuthorizationAsync("Bearer");

                r.Observe("値の無い Bearer", "HTTP " + (int)empty.StatusCode,
                    "Open棟梁 の AuthenticationHeader.GetCredentials は、方式の後ろの値を確かめずに読む。"
                    + "値が無いと例外になり、HTTP 500 になり得る（#196 の範囲外）。");

                r.Done();
            }
        }

        /// <summary>RT-196.6 /userinfo に無効なトークン</summary>
        /// <param name="targetKey">core / netfx</param>
        /// <returns>Task</returns>
        [SkippableTheory]
        [MemberData(nameof(AllTargets))]
        public async Task RT196_06_userinfoで無効なトークンは401とinvalid_token(string targetKey)
        {
            using (IdPClient client = await this.SignedInClientAsync(targetKey))
            {
                TestReport r = this.Report("RT-196.6",
                    "/userinfo : 無効なトークンは、HTTP 401 と error=\"invalid_token\"",
                    "壊れた・改竄された・失効したトークンは、**クライアントが取り直すべき**トークン。"
                    + "401 と invalid_token で伝えれば、クライアントは refresh_token での更新や再認可に進める。"
                    + "以前は invalid_request（400 に当たるコード）を HTTP 200 で返していた。",
                    "RFC 6750 §3.1（invalid_token は 401）/ OIDC Core §5.3.3 / #196");

                ClientRegistration reg = Flows.Registration(client, KnownClients.MvcSample);

                r.Target("client_name=" + KnownClients.MvcSample);
                r.Step("(1) 認可コード フローで access_token を得る");

                JsonResponse token = await Flows.RunAuthorizationCodeFlowAsync(client);

                Assert.False(string.IsNullOrEmpty(token.AccessToken), "前提: access_token が返ること");

                r.Step("(2) JWT でない文字列を Bearer トークンとして送る");

                VerifyInvalidToken(r, "JWT でない文字列", await client.UserInfoAsync("NOT-A-REAL-TOKEN"));

                r.Step("(3) ペイロードを書き換えた（署名はそのままの）トークンを送る");

                VerifyInvalidToken(r, "改竄したトークン", await client.UserInfoAsync(Jwks.Tamper(token.AccessToken)));

                r.Step("(4) トークンを失効させてから送る");

                JsonResponse revoke = await Flows.RevokeAsync(client, reg, token.AccessToken, "access_token");

                Assert.True(string.IsNullOrEmpty(revoke.Error), "前提: 失効に成功すること（" + revoke.ToString() + "）");

                VerifyInvalidToken(r, "失効させたトークン", await client.UserInfoAsync(token.AccessToken));

                r.Done();
            }
        }

        /// <summary>RT-196.7 成功は 200（対照）</summary>
        /// <param name="targetKey">core / netfx</param>
        /// <returns>Task</returns>
        [SkippableTheory]
        [MemberData(nameof(AllTargets))]
        public async Task RT196_07_userinfoの成功は200のまま(string targetKey)
        {
            using (IdPClient client = await this.SignedInClientAsync(targetKey))
            {
                TestReport r = this.Report("RT-196.7",
                    "/userinfo : 有効なトークンでの成功は HTTP 200 のまま（対照）",
                    "**RT-196.5 / 196.6 の対照。** エラーの返し方を変えたことで、"
                    + "成功の応答（ユーザ情報の JSON）まで変わっていないことを確かめる。",
                    "OIDC Core §5.3.2（成功は 200 と JSON）/ #196");

                r.Target("client_name=" + KnownClients.MvcSample + " / scope=openid email");
                r.Step("(1) 認可コード フローで access_token を得て、GET /userinfo を送る");

                JsonResponse token = await Flows.RunAuthorizationCodeFlowAsync(client);

                Assert.False(string.IsNullOrEmpty(token.AccessToken), "前提: access_token が返ること");

                JsonResponse res = await client.UserInfoAsync(token.AccessToken);

                r.VerifyEqual("HTTP 200", "200", ((int)res.StatusCode).ToString());

                r.VerifyEqual("sub がテスト ユーザである", TestEnv.TestUserName, res.String("sub"));

                r.Verify("WWW-Authenticate を付けない", res.Header("WWW-Authenticate") == null,
                    "（無し）", res.Header("WWW-Authenticate") ?? "（無し）");

                r.Done();
            }
        }

        /// <summary>RT-196.8 /revoke のクライアント認証の失敗</summary>
        /// <param name="targetKey">core / netfx</param>
        /// <returns>Task</returns>
        [SkippableTheory]
        [MemberData(nameof(AllTargets))]
        public async Task RT196_08_revokeでクライアント認証の失敗は401(string targetKey)
        {
            using (IdPClient client = this.Client(targetKey))
            {
                TestReport r = this.Report("RT-196.8",
                    "/revoke : クライアント認証の失敗は HTTP 401（Authorization ヘッダなら WWW-Authenticate: Basic も）",
                    "失効も、トークン エンドポイントと同じくクライアントを認証してから行う。"
                    + "**認証の失敗は、要求の中身の誤り（400）と区別して 401 で返す。**",
                    "RFC 7009 §2.2.1（エラーは RFC 6749 §5.2 のとおり）/ RFC 6749 §5.2 / #196");

                ClientRegistration reg = Flows.Registration(client, KnownClients.MvcSample);

                r.Target("client_name=" + KnownClients.MvcSample + "（client_secret だけを誤らせる）");
                r.Step("(1) POST /revoke に token と、誤った client_secret をフォームで送る");

                JsonResponse post = await client.RevokeAsync(new Dictionary<string, string>()
                {
                    { "token", "NOT-A-REAL-TOKEN" },
                    { "client_id", reg.ClientId },
                    { "client_secret", "WRONG-SECRET-WRONG-SECRET" }
                });

                VerifyError(r, "誤った client_secret（フォーム）", post, 401, "invalid_client");

                r.Step("(2) 同じ要求を、client_id と誤った client_secret を Authorization: Basic で渡して送る");

                JsonResponse basic = await client.RevokeWithBasicAuthAsync(new Dictionary<string, string>()
                {
                    { "token", "NOT-A-REAL-TOKEN" }
                }, reg.ClientId, "WRONG-SECRET-WRONG-SECRET");

                VerifyError(r, "誤った client_secret（Basic）", basic, 401, "invalid_client");

                string challenge = basic.Header("WWW-Authenticate");

                r.Verify("Basic : WWW-Authenticate が Basic 方式を示す",
                    challenge != null && challenge.TrimStart().StartsWith("Basic", System.StringComparison.OrdinalIgnoreCase),
                    "Basic ...", challenge ?? "（無し）");

                r.Done();
            }
        }

        /// <summary>RT-196.9 /revoke のそれ以外のエラー</summary>
        /// <param name="targetKey">core / netfx</param>
        /// <returns>Task</returns>
        [SkippableTheory]
        [MemberData(nameof(AllTargets))]
        public async Task RT196_09_revokeでそれ以外のエラーは400(string targetKey)
        {
            using (IdPClient client = await this.SignedInClientAsync(targetKey))
            {
                TestReport r = this.Report("RT-196.9",
                    "/revoke : クライアント認証以外のエラーは HTTP 400",
                    "token の欠落（invalid_request）や、他のクライアントのトークンの失効要求（invalid_grant）は、"
                    + "**正しく認証したクライアントの要求の誤り**なので 400。401 にしない。",
                    "RFC 7009 §2.1 / §2.2.1 / RFC 6749 §5.2 / #196");

                ClientRegistration reg = Flows.Registration(client, KnownClients.MvcSample);
                ClientRegistration other = Flows.Registration(client, KnownClients.TestClient);

                Assert.False(string.IsNullOrEmpty(other.ClientSecret),
                    "前提: " + KnownClients.TestClient + " に client_secret が登録されていること");

                r.Target("発行先 client_name=" + KnownClients.MvcSample
                    + " / 失効を要求する側 client_name=" + KnownClients.TestClient);

                r.Step("(1) token を付けずに POST /revoke を送る（資格情報は正しい）");

                JsonResponse missing = await client.RevokeAsync(new Dictionary<string, string>()
                {
                    { "client_id", reg.ClientId },
                    { "client_secret", reg.ClientSecret }
                });

                VerifyError(r, "token なし", missing, 400, "invalid_request");

                r.Step("(2) " + KnownClients.MvcSample + " の access_token の失効を、"
                    + KnownClients.TestClient + " の資格情報で要求する");

                JsonResponse token = await Flows.RunAuthorizationCodeFlowAsync(client);

                Assert.False(string.IsNullOrEmpty(token.AccessToken), "前提: access_token が返ること");

                JsonResponse stolen = await Flows.RevokeAsync(client, other, token.AccessToken, "access_token");

                VerifyError(r, "他のクライアントのトークン", stolen, 400, "invalid_grant");

                r.Done();
            }
        }

        /// <summary>RT-196.10 /revoke の成功は 200（対照）</summary>
        /// <param name="targetKey">core / netfx</param>
        /// <returns>Task</returns>
        [SkippableTheory]
        [MemberData(nameof(AllTargets))]
        public async Task RT196_10_revokeの成功は200のまま(string targetKey)
        {
            using (IdPClient client = await this.SignedInClientAsync(targetKey))
            {
                TestReport r = this.Report("RT-196.10",
                    "/revoke : 成功は HTTP 200 のまま（Authorization ヘッダでの認証を含む）",
                    "**RT-196.8 / 196.9 の対照。** エラーの返し方を変えたことで、成功の応答まで変わっていないことを確かめる。"
                    + "フォームでの失効と、無効なトークンの失効が 200 であることは EX-2.1 / EX-2.5 が見ているので、"
                    + "ここでは Authorization ヘッダ（client_secret_basic）での失効を見る。",
                    "RFC 7009 §2.2（成功は 200）/ #196");

                ClientRegistration reg = Flows.Registration(client, KnownClients.MvcSample);

                r.Target("client_name=" + KnownClients.MvcSample);
                r.Step("(1) 認可コード フローで access_token を得る");

                JsonResponse token = await Flows.RunAuthorizationCodeFlowAsync(client);

                Assert.False(string.IsNullOrEmpty(token.AccessToken), "前提: access_token が返ること");

                r.Step("(2) POST /revoke に token を送り、client_id と client_secret は Authorization: Basic で渡す");

                JsonResponse revoke = await client.RevokeWithBasicAuthAsync(new Dictionary<string, string>()
                {
                    { "token", token.AccessToken },
                    { "token_type_hint", "access_token" }
                }, reg.ClientId, reg.ClientSecret);

                r.VerifyEqual("HTTP 200", "200", ((int)revoke.StatusCode).ToString());

                r.Verify("error を返さない", string.IsNullOrEmpty(revoke.Error),
                    "error なし", revoke.Error == null ? "error なし" : "error=" + revoke.Error);

                r.Step("(3) 同じ access_token で /userinfo を叩く");

                JsonResponse after = await client.UserInfoAsync(token.AccessToken);

                r.VerifyEqual("失効している（/userinfo が 401 を返す）", "401", ((int)after.StatusCode).ToString());

                r.Done();
            }
        }

        /// <summary>RT-196.11 /introspect のクライアント認証の失敗</summary>
        /// <param name="targetKey">core / netfx</param>
        /// <returns>Task</returns>
        [SkippableTheory]
        [MemberData(nameof(AllTargets))]
        public async Task RT196_11_introspectでクライアント認証の失敗は401(string targetKey)
        {
            using (IdPClient client = this.Client(targetKey))
            {
                TestReport r = this.Report("RT-196.11",
                    "/introspect : クライアント認証の失敗は HTTP 401（Authorization ヘッダなら WWW-Authenticate: Basic も）",
                    "イントロスペクションは、トークンの中身（ユーザ・範囲）を明かす口。"
                    + "**認証できない問い合わせ元には、401 で断る。**"
                    + "資格情報を付けない問い合わせも、認証の失敗として扱う。",
                    "RFC 7662 §2.3（認証に失敗したら RFC 6749 §5.2 のとおり 401）/ §2.1 / #196");

                ClientRegistration reg = Flows.Registration(client, KnownClients.MvcSample);

                r.Target("client_name=" + KnownClients.MvcSample + "（client_secret だけを誤らせる）");
                r.Step("(1) POST /introspect に token と、誤った client_secret をフォームで送る");

                JsonResponse post = await client.IntrospectAsync(new Dictionary<string, string>()
                {
                    { "token", "NOT-A-REAL-TOKEN" },
                    { "client_id", reg.ClientId },
                    { "client_secret", "WRONG-SECRET-WRONG-SECRET" }
                });

                VerifyError(r, "誤った client_secret（フォーム）", post, 401, "invalid_client");

                r.Step("(2) 同じ要求を、client_id と誤った client_secret を Authorization: Basic で渡して送る");

                JsonResponse basic = await client.IntrospectWithBasicAuthAsync(new Dictionary<string, string>()
                {
                    { "token", "NOT-A-REAL-TOKEN" }
                }, reg.ClientId, "WRONG-SECRET-WRONG-SECRET");

                VerifyError(r, "誤った client_secret（Basic）", basic, 401, "invalid_client");

                string challenge = basic.Header("WWW-Authenticate");

                r.Verify("Basic : WWW-Authenticate が Basic 方式を示す",
                    challenge != null && challenge.TrimStart().StartsWith("Basic", System.StringComparison.OrdinalIgnoreCase),
                    "Basic ...", challenge ?? "（無し）");

                r.Step("(3) 資格情報を何も付けずに送る");

                JsonResponse none = await client.IntrospectAsync(new Dictionary<string, string>()
                {
                    { "token", "NOT-A-REAL-TOKEN" }
                });

                VerifyError(r, "資格情報なし", none, 401, "invalid_client");

                r.Done();
            }
        }

        /// <summary>RT-196.12 /introspect のそれ以外のエラー</summary>
        /// <param name="targetKey">core / netfx</param>
        /// <returns>Task</returns>
        [SkippableTheory]
        [MemberData(nameof(AllTargets))]
        public async Task RT196_12_introspectでtokenが無ければ400(string targetKey)
        {
            using (IdPClient client = this.Client(targetKey))
            {
                TestReport r = this.Report("RT-196.12",
                    "/introspect : token の無い問い合わせは HTTP 400",
                    "token は必須のパラメタ。欠けているのは要求の誤りなので 400（invalid_request）。"
                    + "**正しく認証したクライアントの要求は、401 にしない。**",
                    "RFC 7662 §2.1（token は REQUIRED）/ RFC 6749 §5.2 / #196");

                ClientRegistration reg = Flows.Registration(client, KnownClients.MvcSample);

                r.Target("client_name=" + KnownClients.MvcSample + "（資格情報は正しい）");
                r.Step("token を付けずに POST /introspect を送る");

                JsonResponse missing = await client.IntrospectAsync(new Dictionary<string, string>()
                {
                    { "client_id", reg.ClientId },
                    { "client_secret", reg.ClientSecret }
                });

                VerifyError(r, "token なし", missing, 400, "invalid_request");

                r.Done();
            }
        }

        /// <summary>RT-196.13 /introspect の答えは 200（対照）</summary>
        /// <param name="targetKey">core / netfx</param>
        /// <returns>Task</returns>
        [SkippableTheory]
        [MemberData(nameof(AllTargets))]
        public async Task RT196_13_introspectの答えはactiveによらず200(string targetKey)
        {
            using (IdPClient client = await this.SignedInClientAsync(targetKey))
            {
                TestReport r = this.Report("RT-196.13",
                    "/introspect : 問い合わせへの答えは、active=true でも active=false でも HTTP 200（対照）",
                    "**RT-196.11 / 196.12 の対照。** 使えないトークンについての「使えない」（active=false）は、"
                    + "エラーではなく正常な答え。**4xx にしてはならない。**"
                    + "あわせて、Authorization ヘッダ（client_secret_basic）での問い合わせを見る。",
                    "RFC 7662 §2.2（active=false も正常な応答）/ §2.3 / #196");

                ClientRegistration reg = Flows.Registration(client, KnownClients.MvcSample);

                r.Target("client_name=" + KnownClients.MvcSample);
                r.Step("(1) 認可コード フローで access_token を得る");

                JsonResponse token = await Flows.RunAuthorizationCodeFlowAsync(client);

                Assert.False(string.IsNullOrEmpty(token.AccessToken), "前提: access_token が返ること");

                r.Step("(2) その access_token を、Authorization: Basic で認証して問い合わせる");

                JsonResponse active = await client.IntrospectWithBasicAuthAsync(new Dictionary<string, string>()
                {
                    { "token", token.AccessToken },
                    { "token_type_hint", "access_token" }
                }, reg.ClientId, reg.ClientSecret);

                r.VerifyEqual("有効なトークン : HTTP 200", "200", ((int)active.StatusCode).ToString());

                r.Verify("有効なトークン : active が true", active.KindOf("active") == JsonValueKind.True,
                    "active=true", "active の型 = " + active.KindOf("active"));

                r.Step("(3) 存在しないトークンを、同じく問い合わせる");

                JsonResponse inactive = await client.IntrospectWithBasicAuthAsync(new Dictionary<string, string>()
                {
                    { "token", "NOT-A-REAL-TOKEN" }
                }, reg.ClientId, reg.ClientSecret);

                r.VerifyEqual("無効なトークン : HTTP 200（エラーにしない）", "200", ((int)inactive.StatusCode).ToString());

                r.Verify("無効なトークン : active が false", inactive.KindOf("active") == JsonValueKind.False,
                    "active=false", "active の型 = " + inactive.KindOf("active"));

                r.Done();
            }
        }

        /// <summary>RT-196.14 /device_authz のクライアント認証の失敗</summary>
        /// <param name="targetKey">core / netfx</param>
        /// <returns>Task</returns>
        [SkippableTheory]
        [MemberData(nameof(AllTargets))]
        public async Task RT196_14_device_authzでクライアント認証の失敗は401(string targetKey)
        {
            using (IdPClient client = this.Client(targetKey))
            {
                TestReport r = this.Report("RT-196.14",
                    "/device_authz : クライアント認証の失敗は HTTP 401（Authorization ヘッダなら WWW-Authenticate: Basic も）",
                    "デバイス認可エンドポイントのクライアント認証は、トークン エンドポイントと同じ。"
                    + "**登録されていない client_id や、誤った資格情報は 401 で断る。**"
                    + "パブリック クライアントは client_id だけで識別する（#193）。",
                    "RFC 8628 §3.1（クライアント認証は RFC 6749 §3.2.1 のとおり）/ RFC 6749 §5.2 / #196");

                ClientRegistration reg = Flows.Registration(client, KnownClients.MvcSample);

                r.Target("登録されていない client_id / client_name=" + KnownClients.MvcSample
                    + "（コンフィデンシャル。client_secret だけを誤らせる）");

                r.Step("(1) POST /device_authz に、登録されていない client_id をフォームで送る");

                JsonResponse unknown = await client.DeviceAuthorizationAsync(new Dictionary<string, string>()
                {
                    { "client_id", "00000000000000000000000000000000" },
                    { "scope", "profile email" }
                });

                VerifyError(r, "登録されていない client_id", unknown, 401, "invalid_client");

                r.Step("(2) コンフィデンシャル クライアントの client_id と誤った client_secret を、Authorization: Basic で渡して送る");

                JsonResponse basic = await client.DeviceAuthorizationWithBasicAuthAsync(new Dictionary<string, string>()
                {
                    { "scope", "profile email" }
                }, reg.ClientId, "WRONG-SECRET-WRONG-SECRET");

                VerifyError(r, "誤った client_secret（Basic）", basic, 401, "invalid_client");

                string challenge = basic.Header("WWW-Authenticate");

                r.Verify("Basic : WWW-Authenticate が Basic 方式を示す",
                    challenge != null && challenge.TrimStart().StartsWith("Basic", System.StringComparison.OrdinalIgnoreCase),
                    "Basic ...", challenge ?? "（無し）");

                r.Verify("device_code を発行しない",
                    unknown.KindOf("device_code") == JsonValueKind.Undefined
                    && basic.KindOf("device_code") == JsonValueKind.Undefined,
                    "どちらも device_code を返さない", "（1）" + unknown.ToString() + " /（2）" + basic.ToString());

                r.Done();
            }
        }

        /// <summary>RT-196.15 /device_authz の成功は 200（対照）</summary>
        /// <param name="targetKey">core / netfx</param>
        /// <returns>Task</returns>
        [SkippableTheory]
        [MemberData(nameof(AllTargets))]
        public async Task RT196_15_device_authzの成功は200のまま(string targetKey)
        {
            using (IdPClient client = this.Client(targetKey))
            {
                TestReport r = this.Report("RT-196.15",
                    "/device_authz : 成功は HTTP 200 のまま（対照）",
                    "**RT-196.14 の対照。** エラーの返し方を変えたことで、"
                    + "成功の応答（device_code / user_code の JSON）まで変わっていないことを確かめる。",
                    "RFC 8628 §3.2（成功は 200 と JSON）/ #196");

                ClientRegistration reg = Flows.Registration(client, KnownClients.TestClient3);

                r.Target("client_name=" + KnownClients.TestClient3 + "（device モード、client_secret なし）");
                r.Step("POST /device_authz に client_id と scope を送る");

                JsonResponse res = await client.DeviceAuthorizationAsync(new Dictionary<string, string>()
                {
                    { "client_id", reg.ClientId },
                    { "scope", "profile email" }
                });

                r.VerifyEqual("HTTP 200", "200", ((int)res.StatusCode).ToString());

                r.Verify("device_code が返る", res.KindOf("device_code") != JsonValueKind.Undefined,
                    "device_code あり", res.KindOf("device_code") != JsonValueKind.Undefined ? "あり（値は伏せる）" : res.ToString());

                r.Verify("error を返さない", string.IsNullOrEmpty(res.Error),
                    "error なし", res.Error == null ? "error なし" : "error=" + res.Error);

                r.Done();
            }
        }

        /// <summary>RT-196.16 /ciba_authz の request_uri の不備</summary>
        /// <param name="targetKey">core / netfx</param>
        /// <returns>Task</returns>
        [SkippableTheory]
        [MemberData(nameof(AllTargets))]
        public async Task RT196_16_ciba_authzでrequest_uriの不備は400(string targetKey)
        {
            using (IdPClient client = this.Client(targetKey))
            {
                TestReport r = this.Report("RT-196.16",
                    "/ciba_authz : request_uri が無い・存在しない要求は、HTTP 400 と invalid_request",
                    "CIBA の認証リクエストは、事前に /ros へ登録した Request Object を request_uri で指す。"
                    + "**指していない・指す先が無い要求は、要求の誤りとして 400 で返す。**",
                    "CIBA Core §13（invalid_request は 400）/ #196");

                r.Target(client.Target.DisplayName);
                r.Step("(1) request_uri を付けずに POST /ciba_authz を送る");

                JsonResponse none = await client.CibaAuthorizeAsync(new Dictionary<string, string>());

                VerifyError(r, "request_uri なし", none, 400, "invalid_request");

                r.Step("(2) 登録されていない request_uri を送る");

                JsonResponse unknown = await client.CibaAuthorizeAsync(new Dictionary<string, string>()
                {
                    { "request_uri", RequestObjectBuilder.RequestUriPrefix + "00000000000000000000000000000000" }
                });

                VerifyError(r, "存在しない request_uri", unknown, 400, "invalid_request");

                r.Done();
            }
        }

        /// <summary>RT-196.17 /ciba_authz の認証リクエストの中身の誤り</summary>
        /// <param name="targetKey">core / netfx</param>
        /// <returns>Task</returns>
        [SkippableTheory]
        [MemberData(nameof(AllTargets))]
        public async Task RT196_17_ciba_authzで要求の中身の誤りは400とCIBAのコード(string targetKey)
        {
            using (IdPClient client = this.Client(targetKey))
            {
                TestReport r = this.Report("RT-196.17",
                    "/ciba_authz : 認証リクエストの中身の誤りは、HTTP 400 と CIBA Core §13 のエラー コード",
                    "以前は、これらの誤りで error が**空文字列**のまま返っていた（コードが無いと、クライアントは原因を判断できない）。"
                    + "CIBA Core §13 のコードを返し、HTTP ステータスはコードから決める（invalid_client 以外は 400）。",
                    "CIBA Core §7.1 / §13 / #196");

                ClientRegistration reg = Flows.Registration(client, KnownClients.TestClient4);
                long now = System.DateTimeOffset.UtcNow.ToUnixTimeSeconds();

                r.Target("client_name=" + KnownClients.TestClient4 + "（fapi_ciba。要求は ES256 で署名して /ros に登録する）");

                r.Step("(1) scope に openid が無い要求");

                string noOpenid = await RegisterCibaRequestAsync(client, reg,
                    new Dictionary<string, object>() { { "scope", "profile" } });

                VerifyError(r, "openid なし", await client.CibaAuthorizeAsync(
                    new Dictionary<string, string>() { { "request_uri", noOpenid } }), 400, "invalid_scope");

                r.Step("(2) nbf が未来の要求（まだ有効になっていない）");

                string notYet = await RegisterCibaRequestAsync(client, reg,
                    new Dictionary<string, object>() { { "nbf", now + 600 } });

                VerifyError(r, "nbf が未来", await client.CibaAuthorizeAsync(
                    new Dictionary<string, string>() { { "request_uri", notYet } }), 400, "invalid_request");

                r.Step("(3) exp が過去の要求（期限切れ）");

                string expired = await RegisterCibaRequestAsync(client, reg,
                    new Dictionary<string, object>() { { "exp", now - 600 } });

                VerifyError(r, "exp が過去", await client.CibaAuthorizeAsync(
                    new Dictionary<string, string>() { { "request_uri", expired } }), 400, "invalid_request");

                r.Done();
            }
        }

        /// <summary>RT-196.18 /ciba_authz のユーザ不明</summary>
        /// <param name="targetKey">core / netfx</param>
        /// <returns>Task</returns>
        [SkippableTheory]
        [MemberData(nameof(AllTargets))]
        public async Task RT196_18_ciba_authzでユーザが見つからなければ400とunknown_user_id(string targetKey)
        {
            using (IdPClient client = this.Client(targetKey))
            {
                TestReport r = this.Report("RT-196.18",
                    "/ciba_authz : login_hint のユーザが見つからない要求は、HTTP 400 と unknown_user_id",
                    "CIBA では、認証を求める相手（ユーザ）を login_hint などで指す。"
                    + "**見つからないなら、それを unknown_user_id で伝える。**以前は error が空のまま返っていた。",
                    "CIBA Core §13（unknown_user_id は 400）/ #196");

                ClientRegistration reg = Flows.Registration(client, KnownClients.TestClient4);

                r.Target("client_name=" + KnownClients.TestClient4 + " / login_hint = 存在しないユーザ");
                r.Step("login_hint に存在しないユーザを入れた要求を /ros に登録し、その request_uri を送る");

                string requestUri = await RegisterCibaRequestAsync(client, reg,
                    new Dictionary<string, object>() { { "login_hint", "unknown-user@example.invalid" } });

                VerifyError(r, "ユーザ不明", await client.CibaAuthorizeAsync(
                    new Dictionary<string, string>() { { "request_uri", requestUri } }), 400, "unknown_user_id");

                r.Note("成功経路（見つかったユーザへのプッシュ通知）は FCM に送るので、E2E では測らない。");

                r.Done();
            }
        }

        /// <summary>RT-196.19 /SetDeviceToken の失敗</summary>
        /// <param name="targetKey">core / netfx</param>
        /// <returns>Task</returns>
        [SkippableTheory]
        [MemberData(nameof(AllTargets))]
        public async Task RT196_19_SetDeviceTokenの失敗は400と401(string targetKey)
        {
            using (IdPClient client = this.Client(targetKey))
            {
                TestReport r = this.Report("RT-196.19",
                    "/SetDeviceToken : 失敗は本文 NG のまま、パラメタの不備は HTTP 400、トークンの不備は 401",
                    "認証デバイスを登録する口。以前は失敗でも HTTP 200 と NG だった。"
                    + "**本文（OK / NG）は認証デバイス（authentication_device）が見ているので変えず、ステータスだけを直す。**"
                    + "トークンの不備には、Bearer トークンが要ることを WWW-Authenticate で示す。",
                    "RFC 6750 §3 / #196");

                r.Target(client.Target.DisplayName);
                r.Note("成功（200 と OK）は EX-8 で見る。ここで登録すると、並行して動く CIBA のテストの宛先を書き換えてしまう。");

                r.Step("(1) device_token を付けずに送る");

                VerifyNG(r, "device_token なし", await client.SetDeviceTokenAsync("NOT-A-REAL-TOKEN", null), 400, null);

                r.Step("(2) Authorization ヘッダを付けずに送る");

                VerifyNG(r, "トークンなし", await client.SetDeviceTokenAsync(null, "e2e-device-token"), 401, null);

                r.Step("(3) 無効なトークンで送る");

                VerifyNG(r, "無効なトークン",
                    await client.SetDeviceTokenAsync("NOT-A-REAL-TOKEN", "e2e-device-token"), 401, "invalid_token");

                r.Done();
            }
        }

        /// <summary>RT-196.20 /ciba_result の失敗</summary>
        /// <param name="targetKey">core / netfx</param>
        /// <returns>Task</returns>
        [SkippableTheory]
        [MemberData(nameof(AllTargets))]
        public async Task RT196_20_ciba_resultの失敗は400と401(string targetKey)
        {
            using (IdPClient client = await this.SignedInClientAsync(targetKey))
            {
                TestReport r = this.Report("RT-196.20",
                    "/ciba_result : 失敗は本文 NG のまま、トークンの不備は HTTP 401、パラメタの不備は 400",
                    "認証デバイスが、CIBA の要求に「許可 / 拒否」を返す口。以前は失敗でも HTTP 200 と NG だった。"
                    + "本文（OK / NG）は変えず、ステータスだけを直す。",
                    "RFC 6750 §3 / #196");

                r.Target(client.Target.DisplayName + " / ユーザのトークンは認可コード フローで得る");
                r.Note("成功（200 と OK）は EX-8 で見る。ここで返答すると、並行して動く CIBA のテストの要求に結果を書き込んでしまう。");

                r.Step("(1) Authorization ヘッダを付けずに送る");

                VerifyNG(r, "トークンなし", await client.CibaPushResultAsync(null, "dummy", "true"), 401, null);

                r.Step("(2) 無効なトークンで送る");

                VerifyNG(r, "無効なトークン",
                    await client.CibaPushResultAsync("NOT-A-REAL-TOKEN", "dummy", "true"), 401, "invalid_token");

                JsonResponse token = await Flows.RunAuthorizationCodeFlowAsync(client);

                Assert.False(string.IsNullOrEmpty(token.AccessToken), "前提: access_token が返ること");

                r.Step("(3) ユーザの有効なトークンで、auth_req_id を付けずに送る");

                VerifyNG(r, "auth_req_id なし", await client.CibaPushResultAsync(token.AccessToken, null, "true"), 400, null);

                r.Step("(4) result が真偽値でない値で送る");

                VerifyNG(r, "result が不正", await client.CibaPushResultAsync(token.AccessToken, "dummy", "maybe"), 400, null);

                r.Done();
            }
        }
    }
}
