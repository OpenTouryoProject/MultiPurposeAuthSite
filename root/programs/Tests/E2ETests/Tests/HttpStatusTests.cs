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
//**********************************************************************************

using System.Collections.Generic;
using System.Net;
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
    ///
    /// **本文（error / error_description の JSON）が変わっていないこと**も併せて見る。
    /// ステータスだけ直して本文が壊れると、既存のクライアントが error を読めなくなる。
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
    }
}
