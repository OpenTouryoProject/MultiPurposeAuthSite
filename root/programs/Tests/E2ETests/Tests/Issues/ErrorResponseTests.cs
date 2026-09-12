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
//* クラス名        ：ErrorResponseTests
//* クラス日本語名  ：RT エラー応答の回帰（#185 / #187）
//*
//* 作成日時        ：－
//* 作成者          ：－
//* 更新履歴        ：－
//*
//*  日時        更新者            内容
//*  ----------  ----------------  -------------------------------------------------
//*  2026/09/08  玄人 幸道         新規（E2Eテスト基盤）
//*  2026/09/10  玄人 幸道         TestReportで記録を残すよう変更（RT-185 / RT-187）
//*  2026/09/11  玄人 幸道         RT-185.1 の注記を、#196（/token の 400 / 401）の対応に合わせる
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
    /// RT-185 / RT-187. エラー応答の回帰テスト。
    /// </summary>
    public class ErrorResponseTests : TargetTestBase
    {
        /// <summary>コンストラクタ</summary>
        /// <param name="output">ITestOutputHelper</param>
        public ErrorResponseTests(ITestOutputHelper output) : base(output)
        {
        }

        #region RT-185 トークン エンドポイント

        /// <summary>RT-185.1 不正な入力でも JSON のエラーを返す</summary>
        /// <param name="targetKey">core / netfx</param>
        /// <returns>Task</returns>
        [SkippableTheory]
        [MemberData(nameof(AllTargets))]
        public async Task RT185_01_不正な入力でもJSONのエラーを返す(string targetKey)
        {
            using (IdPClient client = await this.SignedInClientAsync(targetKey))
            {
                TestReport r = this.Report("RT-185.1",
                    "トークン エンドポイントに不正な入力を送っても、JSON のエラー応答になる",
                    "**未処理の例外（HTTP 500 や HTML のエラー画面）にしない。**"
                    + "RP はエラーを JSON として解釈する。HTML が返ると解析に失敗し、"
                    + "何が悪かったのかを利用者に伝えられない。"
                    + "加えて、例外のスタック トレースが外に出る恐れがある。",
                    "RFC 6749 §5.2（エラー応答は error を含む JSON）/ #185");

                ClientRegistration reg = Flows.Registration(client, KnownClients.MvcSample);

                r.Target("client_name=" + KnownClients.MvcSample);

                List<KeyValuePair<string, Dictionary<string, string>>> cases =
                    new List<KeyValuePair<string, Dictionary<string, string>>>()
                {
                    new KeyValuePair<string, Dictionary<string, string>>(
                        "grant_type が空",
                        new Dictionary<string, string>()),

                    new KeyValuePair<string, Dictionary<string, string>>(
                        "grant_type が未知",
                        new Dictionary<string, string>() { { "grant_type", "urn:example:bogus" } }),

                    new KeyValuePair<string, Dictionary<string, string>>(
                        "code が存在しない（PKCE 経路）",
                        new Dictionary<string, string>()
                        {
                            { "grant_type", "authorization_code" },
                            { "code", "NOT-A-REAL-CODE" },
                            { "code_verifier", "x" },
                            { "client_id", reg.ClientId }
                        }),

                    new KeyValuePair<string, Dictionary<string, string>>(
                        "code が存在しない（client_secret 経路）",
                        new Dictionary<string, string>()
                        {
                            { "grant_type", "authorization_code" },
                            { "code", "NOT-A-REAL-CODE" },
                            { "client_id", reg.ClientId },
                            { "client_secret", reg.ClientSecret }
                        }),

                    new KeyValuePair<string, Dictionary<string, string>>(
                        "refresh_token が存在しない",
                        new Dictionary<string, string>()
                        {
                            { "grant_type", "refresh_token" },
                            { "refresh_token", "NOT-A-REAL-TOKEN" },
                            { "client_id", reg.ClientId },
                            { "client_secret", reg.ClientSecret }
                        })
                };

                r.Step("POST /token に、次の 5 通りの不正な入力を順に送る："
                    + string.Join(" / ", cases.ConvertAll(c => c.Key)));

                foreach (KeyValuePair<string, Dictionary<string, string>> c in cases)
                {
                    JsonResponse res = await client.TokenAsync(c.Value);

                    r.Verify(c.Key + " で HTTP 500 にならない",
                        res.StatusCode != HttpStatusCode.InternalServerError,
                        "500 以外", "HTTP " + (int)res.StatusCode);

                    r.Verify(c.Key + " の応答が JSON である", res.IsJson,
                        "JSON", res.IsJson ? "JSON" : "非 JSON（" + (res.ContentType ?? "不明") + "）");

                    r.Verify(c.Key + " に error が含まれる",
                        !string.IsNullOrEmpty(res.Error),
                        "error あり", "error = " + (res.Error ?? "なし"));
                }

                r.Note("HTTP ステータスは、#196 で 400 / 401 に直した（RT-196.1 〜 196.4 で検証）。");

                r.Done();
            }
        }

        #endregion

        #region RT-187 認可エンドポイント

        /// <summary>RT-187.1 state に区切り文字があっても壊れない</summary>
        /// <param name="targetKey">core / netfx</param>
        /// <returns>Task</returns>
        [SkippableTheory]
        [MemberData(nameof(AllTargets))]
        public async Task RT187_01_stateに区切り文字があっても壊れない(string targetKey)
        {
            const string State = "a&b=c d";

            using (IdPClient client = await this.SignedInClientAsync(targetKey))
            {
                TestReport r = this.Report("RT-187.1",
                    "state に & や = や空白が含まれていても、そのまま往復する",
                    "**修正前は文字列連結でリダイレクト URL を組み立てていた。**"
                    + "state に区切り文字が入るとパラメタの境界が壊れ、"
                    + "後続のパラメタ（code など）まで読み違える。"
                    + "RP が state に構造化した値（JSON や URL）を入れると踏む。",
                    "RFC 3986 §2.2（予約文字はパーセント符号化する）"
                    + " / RFC 6749 §4.1.2（state はそのまま返す）/ #187");

                ClientRegistration reg = Flows.Registration(client, KnownClients.MvcSample);

                r.Target("client_name=" + KnownClients.MvcSample);
                r.Step("GET /authorize に state=\"" + State + "\" を付けて送る");

                AuthZResponse res = await Flows.AuthorizeCodeAsync(
                    client, reg, state: State, redirectUri: reg.RedirectUri);

                r.Verify("認可コードが発行される", !string.IsNullOrEmpty(res.Code),
                    "code あり", string.IsNullOrEmpty(res.Code) ? res.ToString() : "code あり");

                r.VerifyEqual("state が送信値と完全一致する", State, res.State);

                r.Done();
            }
        }

        /// <summary>RT-187.2 state を送らなければ返さない</summary>
        /// <param name="targetKey">core / netfx</param>
        /// <returns>Task</returns>
        [SkippableTheory]
        [MemberData(nameof(AllTargets))]
        public async Task RT187_02_stateを送らなければ返さない(string targetKey)
        {
            using (IdPClient client = await this.SignedInClientAsync(targetKey))
            {
                TestReport r = this.Report("RT-187.2",
                    "state を送らなければ、応答にも state を含めない",
                    "**送っていないものを返してはならない。**"
                    + "空の state を返すと、RP 側の照合処理が"
                    + "「空文字どうしで一致した」と誤判定しうる。",
                    "RFC 6749 §4.1.2（state は、あったときに返す）/ #187");

                ClientRegistration reg = Flows.Registration(client, KnownClients.MvcSample);

                r.Target("client_name=" + KnownClients.MvcSample);
                r.Step("GET /authorize を state 無しで送る");

                AuthZResponse res = await Flows.AuthorizeCodeAsync(
                    client, reg, state: null, redirectUri: reg.RedirectUri);

                r.Verify("認可コードが発行される", !string.IsNullOrEmpty(res.Code),
                    "code あり", string.IsNullOrEmpty(res.Code) ? res.ToString() : "code あり");

                r.Verify("応答に state が含まれない",
                    !res.Parameters.ContainsKey("state"),
                    "state なし",
                    res.Parameters.ContainsKey("state")
                        ? "**state=\"" + res.State + "\" が返った**" : "返らなかった");

                r.Done();
            }
        }

        /// <summary>RT-187.3 未知の response_type では認可コードを発行しない</summary>
        /// <param name="targetKey">core / netfx</param>
        /// <returns>Task</returns>
        [SkippableTheory]
        [MemberData(nameof(AllTargets))]
        public async Task RT187_03_未知のresponse_typeでは認可コードを発行しない(string targetKey)
        {
            using (IdPClient client = await this.SignedInClientAsync(targetKey))
            {
                TestReport r = this.Report("RT-187.3",
                    "未知の response_type では認可コードを発行しない",
                    "**どのフローを要求されたのか決まらない以上、何も発行してはならない。**"
                    + "エラーの返し方（リダイレクトか画面か）は RT-187.4 で別に見る。",
                    "RFC 6749 §3.1.1 / §4.1.2.1（unsupported_response_type）/ #187");

                ClientRegistration reg = Flows.Registration(client, KnownClients.MvcSample);

                r.Target("client_name=" + KnownClients.MvcSample);
                r.Step("GET /authorize に response_type=bogus を指定する");

                Dictionary<string, string> q = new Dictionary<string, string>()
                {
                    { "response_type", "bogus" },
                    { "client_id", reg.ClientId },
                    { "scope", "openid" },
                    { "state", "state1" },
                    { "redirect_uri", reg.RedirectUri },
                    { "prompt", "none" }
                };

                AuthZResponse res = await client.AuthorizeAsync(q);

                r.Verify("認可コードを発行しない", string.IsNullOrEmpty(res.Code),
                    "code を返さない",
                    string.IsNullOrEmpty(res.Code) ? "返さなかった" : "**返してしまった**");

                r.Observe("エラーの返し方",
                    res.Redirected
                        ? "リダイレクトして error=" + (res.Error ?? "なし")
                        : "リダイレクトせず HTTP " + (int)res.StatusCode + "（画面表示）",
                    "RFC 6749 §4.1.2.1 は、redirect_uri が妥当ならリダイレクトして"
                    + "error を返すことを求める。RT-187.4 を参照。");

                r.Done();
            }
        }

        /// <summary>RT-187.4 未知の response_type は unsupported_response_type でリダイレクトする</summary>
        /// <param name="targetKey">core / netfx</param>
        /// <returns>Task</returns>
        [SkippableTheory(Skip = "未修正。実測（2026/09/09, net10.0）では、"
            + "リダイレクトではなくエラー画面（HTTP 200）になる。")]
        [MemberData(nameof(AllTargets))]
        public async Task RT187_04_未知のresponse_typeはunsupported_response_typeでリダイレクトする(string targetKey)
        {
            using (IdPClient client = await this.SignedInClientAsync(targetKey))
            {
                TestReport r = this.Report("RT-187.4",
                    "未知の response_type を unsupported_response_type でリダイレクトする",
                    "client_id と redirect_uri が妥当なら、エラーは**リダイレクトで RP へ返す。**"
                    + "画面で止めると、RP は何が起きたのか分からない。"
                    + "ただし認可コードは発行されない（RT-187.3）ので、**安全側には倒れている。**",
                    "RFC 6749 §4.1.2.1（redirect_uri が妥当ならリダイレクトして error を返す）");

                ClientRegistration reg = Flows.Registration(client, KnownClients.MvcSample);

                r.Target("client_name=" + KnownClients.MvcSample);
                r.Step("GET /authorize に response_type=bogus を指定する（妥当な redirect_uri 付き）");

                Dictionary<string, string> q = new Dictionary<string, string>()
                {
                    { "response_type", "bogus" },
                    { "client_id", reg.ClientId },
                    { "scope", "openid" },
                    { "state", "state1" },
                    { "redirect_uri", reg.RedirectUri },
                    { "prompt", "none" }
                };

                AuthZResponse res = await client.AuthorizeAsync(q);

                r.VerifyEqual("unsupported_response_type が返る",
                    "unsupported_response_type", res.Error);

                r.Done();
            }
        }

        /// <summary>RT-187.5 不正な client_id ではリダイレクトしない</summary>
        /// <param name="targetKey">core / netfx</param>
        /// <returns>Task</returns>
        [SkippableTheory]
        [MemberData(nameof(AllTargets))]
        public async Task RT187_05_不正なclient_idではリダイレクトしない(string targetKey)
        {
            using (IdPClient client = await this.SignedInClientAsync(targetKey))
            {
                TestReport r = this.Report("RT-187.5",
                    "client_id が不正なときは、指定された redirect_uri へリダイレクトしない",
                    "**client_id が分からなければ、redirect_uri を検証できない。**"
                    + "検証できない URI へエラーを返すと、"
                    + "認可サーバがオープン リダイレクタになる。"
                    + "この場合は画面で知らせるのが正しい。",
                    "RFC 6749 §4.1.2.1（redirect_uri が不正・未検証なら"
                    + "リダイレクトせず、利用者に知らせる）/ #187");

                ClientRegistration reg = Flows.Registration(client, KnownClients.MvcSample);

                r.Target("client_name=" + KnownClients.MvcSample
                    + "（その redirect_uri を、存在しない client_id と組み合わせる）");
                r.Step("GET /authorize に client_id=deadbeef…（未登録）を指定する");

                Dictionary<string, string> q = new Dictionary<string, string>()
                {
                    { "response_type", "code" },
                    { "client_id", "deadbeefdeadbeefdeadbeefdeadbeef" },
                    { "scope", "openid" },
                    { "state", "state1" },
                    { "redirect_uri", reg.RedirectUri },
                    { "prompt", "none" }
                };

                AuthZResponse res = await client.AuthorizeAsync(q);

                r.Verify("認可コードを発行しない", string.IsNullOrEmpty(res.Code),
                    "code を返さない",
                    string.IsNullOrEmpty(res.Code) ? "返さなかった" : "**返してしまった**");

                r.Verify("指定された redirect_uri へリダイレクトしない",
                    res.RedirectTo != reg.RedirectUri,
                    "その URI へ飛ばさない",
                    "リダイレクト先 = " + (res.RedirectTo ?? "（リダイレクト無し）"));

                r.Done();
            }
        }

        #endregion
    }
}
