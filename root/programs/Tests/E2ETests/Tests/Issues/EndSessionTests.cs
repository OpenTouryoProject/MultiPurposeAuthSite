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
//* クラス名        ：EndSessionTests
//* クラス日本語名  ：RT-232 RP からのログアウト（RP-Initiated Logout）
//*
//* 作成日時        ：－
//* 作成者          ：－
//* 更新履歴        ：－
//*
//*  日時        更新者            内容
//*  ----------  ----------------  -------------------------------------------------
//*  2026/09/27  玄人 幸道         新規（#232）
//**********************************************************************************

using System.Collections.Generic;
using System.Net;
using System.Net.Http;
using System.Threading.Tasks;

using MultiPurposeAuthSite.Tests.E2E.Infrastructure;

using Xunit;
using Xunit.Abstractions;

namespace MultiPurposeAuthSite.Tests.E2E.Tests.Issues
{
    /// <summary>
    /// RT-232. RP からのログアウト（`end_session_endpoint`）。
    /// </summary>
    /// <remarks>
    /// **RP から SSO を解除する手段が無かった**（`ANALYSIS-IdP.md` D-1）。
    /// OpenID Connect RP-Initiated Logout 1.0 を実装した（#232）。
    ///
    /// | 見るもの | 根拠 |
    /// |---|---|
    /// | `end_session_endpoint` を Discovery に出す | §2.1（REQUIRED） |
    /// | **GET と POST の両方**を受ける | §2（MUST） |
    /// | `id_token_hint` は自分が発行したもので、`aud` が `client_id` と一致 | §2（MUST） |
    /// | `post_logout_redirect_uri` は**登録値と完全一致**でなければ戻さない | §3（MUST） |
    /// | **`id_token_hint` が無ければ戻さない** | §3（MUST） |
    /// | 検証できなければ**利用者に確認する** | §2（MUST）／§6 |
    /// | サインインしていなくても**エラーにしない** | §4（冪等） |
    ///
    /// **Front-Channel / Back-Channel Logout と Session Management は範囲外**（D-1 に残る）。
    ///
    /// `post_logout_redirect_uri` を登録したクライアントが要るので、
    /// **差し込みの仕組み（#224）で `TestClient_4` を用意する。**
    /// </remarks>
    public class EndSessionTests : TargetTestBase
    {
        /// <summary>コンストラクタ</summary>
        /// <param name="output">ITestOutputHelper</param>
        public EndSessionTests(ITestOutputHelper output) : base(output)
        {
        }

        /// <summary>id_token を 1 つ取る（TestClient_4 で認可コード フローを通す）</summary>
        /// <param name="client">IdPClient</param>
        /// <param name="r">TestReport</param>
        /// <returns>id_token</returns>
        private static async Task<string> GetIdTokenAsync(IdPClient client, TestReport r)
        {
            ClientRegistration reg = Flows.InjectedRegistration(client, KnownClients.TestClient_4);

            await client.SignInAsync();

            AuthZResponse authz = await Flows.AuthorizeCodeAsync(
                client, reg, "openid email", "state1", "nonce1", reg.RedirectUri);

            Assert.False(string.IsNullOrEmpty(authz.Code),
                "前提: 認可コードが取得できること（" + authz.ToString() + "）");

            JsonResponse token = await Flows.ExchangeCodeAsync(
                client, reg, authz.Code, reg.RedirectUri);

            Assert.False(string.IsNullOrEmpty(token.IdToken),
                "前提: id_token が取得できること（" + token.ToString() + "）");

            r.Note("**id_token は、`TestClient_4` に認可コード フローで発行したもの**を使う"
                + "（`scope=openid`）。このクライアントには `post_logout_redirect_uri` が登録されている。");

            return token.IdToken;
        }

        /// <summary>応答の Location（無ければ空）</summary>
        /// <param name="res">応答</param>
        /// <returns>Location</returns>
        private static string LocationOf(HttpResponseMessage res)
        {
            return (res.Headers.Location == null) ? "" : res.Headers.Location.ToString();
        }

        /// <summary>Location の「? より前」と、クエリ文字列の項目に分ける</summary>
        /// <param name="location">Location</param>
        /// <param name="query">クエリ文字列の項目</param>
        /// <returns>? より前</returns>
        private static string SplitLocation(string location, IDictionary<string, string> query)
        {
            int q = location.IndexOf('?');

            if (q < 0)
            {
                return location;
            }

            IdPClient.ParseInto(location.Substring(q + 1), query);

            return location.Substring(0, q);
        }

        /// <summary>RT-232.1 Discovery</summary>
        /// <param name="targetKey">core / netfx</param>
        /// <returns>Task</returns>
        [SkippableTheory]
        [MemberData(nameof(AllTargets))]
        public async Task RT23201_end_session_endpointをDiscoveryが広告する(string targetKey)
        {
            using (IdPClient client = this.Client(targetKey))
            {
                TestReport r = this.Report("RT-232.1",
                    "Discovery が end_session_endpoint を広告する",
                    "**RP は Discovery だけを見てログアウトの口を知る。**"
                    + "実装していても広告しなければ、RP からは使えない"
                    + "（実装も広告も無い状態だった。D-1）。",
                    "OpenID Connect RP-Initiated Logout 1.0 §2.1（REQUIRED）");

                r.Target("GET /.well-known/openid-configuration");
                r.Step("end_session_endpoint を読む");

                JsonResponse res = await client.GetJsonAsync("/.well-known/openid-configuration");

                Assert.True(res.IsJson, "前提: Discovery 文書が JSON であること");

                string endSession = res.String("end_session_endpoint");

                r.Verify("end_session_endpoint が有る", !string.IsNullOrEmpty(endSession),
                    "有り", string.IsNullOrEmpty(endSession) ? "**無し**" : endSession);

                r.Verify("https である", endSession != null && endSession.StartsWith("https://"),
                    "https://…", endSession ?? "なし");

                r.Observe("広告された URL", endSession ?? "なし",
                    "設定キー OAuth2EndSessionEndpoint（既定 /end_session）で決まる。");

                // **未実装のものは広告しない**（広告すると「できる」と読まれる）。
                r.Verify("Front-Channel Logout は広告しない",
                    string.IsNullOrEmpty(res.String("frontchannel_logout_supported")),
                    "広告なし",
                    string.IsNullOrEmpty(res.String("frontchannel_logout_supported"))
                        ? "広告なし" : "**広告あり**");

                r.Done();
            }
        }

        /// <summary>RT-232.2 GET でログアウトして RP へ戻る</summary>
        /// <param name="targetKey">core / netfx</param>
        /// <returns>Task</returns>
        [SkippableTheory]
        [MemberData(nameof(AllTargets))]
        public async Task RT23202_id_token_hintつきのGETでログアウトしRPへ戻る(string targetKey)
        {
            using (IdPClient client = this.Client(targetKey))
            {
                TestReport r = this.Report("RT-232.2",
                    "id_token_hint 付きの GET で、サインアウトして post_logout_redirect_uri へ戻る",
                    "**RP 主導のログアウトの本筋。**"
                    + "id_token_hint で要求元が確かめられるので、**確認画面を挟まずに**ログアウトし、"
                    + "登録された戻り先へ state を添えて返す。",
                    "RP-Initiated Logout 1.0 §2 / §3");

                string idToken = await EndSessionTests.GetIdTokenAsync(client, r);
                string registered = KnownClients.PostLogoutRedirectUri(client);

                r.Target("GET /end_session（id_token_hint ＋ post_logout_redirect_uri ＋ state）");

                r.Verify("前提: サインインしている", await client.IsSessionAliveAsync(),
                    "セッション有り", "セッション有り");

                r.Step("ログアウト要求を送る");

                HttpResponseMessage res = await client.EndSessionAsync(
                    idToken, null, registered, "logout-state-1");

                r.VerifyEqual("HTTP 302", "302", ((int)res.StatusCode).ToString());

                Dictionary<string, string> query = new Dictionary<string, string>();
                string location = EndSessionTests.SplitLocation(
                    EndSessionTests.LocationOf(res), query);

                r.VerifyEqual("登録された戻り先へ返す", registered, location);

                r.VerifyEqual("state をそのまま返す", "logout-state-1",
                    query.ContainsKey("state") ? query["state"] : "なし");

                r.Verify("iss は付けない（認可応答ではない）", !query.ContainsKey("iss"),
                    "iss なし", query.ContainsKey("iss") ? "**iss あり**" : "iss なし");

                r.Step("サインアウトされたことを確かめる");

                r.Verify("セッションが消えている", !await client.IsSessionAliveAsync(),
                    "サインインが要る画面が開けない", "サインインが要る画面が開けない");

                r.Done();
            }
        }

        /// <summary>RT-232.3 POST でも受ける</summary>
        /// <param name="targetKey">core / netfx</param>
        /// <returns>Task</returns>
        [SkippableTheory]
        [MemberData(nameof(AllTargets))]
        public async Task RT23203_POSTでもログアウトを受ける(string targetKey)
        {
            using (IdPClient client = this.Client(targetKey))
            {
                TestReport r = this.Report("RT-232.3",
                    "POST でもログアウト要求を受ける",
                    "**GET と POST の両方を受けることが MUST。**"
                    + "GET しか受けないと、id_token_hint が長い（URL 長の上限に当たる）ときに"
                    + "RP はログアウトできない。",
                    "RP-Initiated Logout 1.0 §2（MUST）");

                string idToken = await EndSessionTests.GetIdTokenAsync(client, r);
                string registered = KnownClients.PostLogoutRedirectUri(client);

                r.Target("POST /end_session（フォーム形式）");
                r.Step("ログアウト要求を送る");

                HttpResponseMessage res = await client.EndSessionPostAsync(
                    idToken, null, registered, "logout-state-2");

                r.VerifyEqual("HTTP 302", "302", ((int)res.StatusCode).ToString());

                Dictionary<string, string> query = new Dictionary<string, string>();
                string location = EndSessionTests.SplitLocation(
                    EndSessionTests.LocationOf(res), query);

                r.VerifyEqual("登録された戻り先へ返す", registered, location);

                r.VerifyEqual("state をそのまま返す", "logout-state-2",
                    query.ContainsKey("state") ? query["state"] : "なし");

                r.Verify("セッションが消えている", !await client.IsSessionAliveAsync(),
                    "サインインが要る画面が開けない", "サインインが要る画面が開けない");

                r.Done();
            }
        }

        /// <summary>RT-232.4 登録と一致しない戻り先</summary>
        /// <param name="targetKey">core / netfx</param>
        /// <returns>Task</returns>
        [SkippableTheory]
        [MemberData(nameof(AllTargets))]
        public async Task RT23204_登録と一致しないpost_logout_redirect_uriへは戻さない(string targetKey)
        {
            using (IdPClient client = this.Client(targetKey))
            {
                TestReport r = this.Report("RT-232.4",
                    "登録と完全一致しない post_logout_redirect_uri へは戻さない",
                    "**戻り先は、オープン リダイレクタになりうる。**"
                    + "登録値と完全一致しなければ戻してはならない（§3）。"
                    + "`redirect_uri` の照合は大文字小文字を無視するが（C-10）、"
                    + "**こちらは仕様が exactly match と書いているので、そのまま比較している。**",
                    "RP-Initiated Logout 1.0 §3（MUST）／§4");

                string idToken = await EndSessionTests.GetIdTokenAsync(client, r);

                r.Target("GET /end_session（登録と違う post_logout_redirect_uri）");

                r.Step("(1) 登録されていない URL を指定する");

                HttpResponseMessage other = await client.EndSessionAsync(
                    idToken, null, "https://evil.example.com/logged_out", "logout-state-3");

                r.VerifyEqual("HTTP 200（確認画面。リダイレクトしない）",
                    "200", ((int)other.StatusCode).ToString());

                r.Verify("その URL へは飛ばさない",
                    !EndSessionTests.LocationOf(other).Contains("evil.example.com"),
                    "Location に含まれない",
                    EndSessionTests.LocationOf(other) == "" ? "Location なし"
                                                            : EndSessionTests.LocationOf(other));

                r.Verify("セッションは残っている（勝手にログアウトしない）",
                    await client.IsSessionAliveAsync(),
                    "セッション有り", "セッション有り");

                r.Step("(2) 大文字小文字だけが違う URL を指定する");

                string registered = KnownClients.PostLogoutRedirectUri(client);

                HttpResponseMessage cased = await client.EndSessionAsync(
                    idToken, null, registered.ToUpperInvariant(), "logout-state-4");

                r.VerifyEqual("HTTP 200（完全一致でないので戻さない）",
                    "200", ((int)cased.StatusCode).ToString());

                r.Note("**完全一致にしている。** 大文字小文字を無視すると、"
                    + "登録と違う URL へ戻すことになる（§3 は exactly match）。");

                r.Done();
            }
        }

        /// <summary>RT-232.5 id_token_hint が無い</summary>
        /// <param name="targetKey">core / netfx</param>
        /// <returns>Task</returns>
        [SkippableTheory]
        [MemberData(nameof(AllTargets))]
        public async Task RT23205_id_token_hintが無ければ確認してからログアウトする(string targetKey)
        {
            using (IdPClient client = this.Client(targetKey))
            {
                TestReport r = this.Report("RT-232.5",
                    "id_token_hint が無ければ、利用者に確認してからログアウトする",
                    "**確認なしに応じると、誰でも他人をログアウトさせられる**（§6 : DoS の手段）。"
                    + "id_token_hint が無い要求は、要求元が確かめられないので"
                    + "**確認しなければならない**（§2 の MUST）。",
                    "RP-Initiated Logout 1.0 §2（MUST）／§6");

                await client.SignInAsync();

                r.Target("GET /end_session（パラメタ無し）");

                r.Step("(1) id_token_hint を付けずに要求する");

                HttpResponseMessage res = await client.EndSessionAsync();

                r.VerifyEqual("HTTP 200（確認画面）", "200", ((int)res.StatusCode).ToString());

                r.Verify("まだサインアウトしていない", await client.IsSessionAliveAsync(),
                    "セッション有り", "セッション有り");

                r.Step("(2) 確認画面で「はい」を押す");

                string html = await res.Content.ReadAsStringAsync();

                HttpResponseMessage confirmed = await client.ConfirmEndSessionAsync(html, true);

                r.VerifyEqual("HTTP 302（自サイトへ戻る）",
                    "302", ((int)confirmed.StatusCode).ToString());

                r.Verify("サインアウトされた", !await client.IsSessionAliveAsync(),
                    "セッション無し", "セッション無し");

                r.Done();
            }
        }

        /// <summary>RT-232.6 client_id が id_token の aud と違う</summary>
        /// <param name="targetKey">core / netfx</param>
        /// <returns>Task</returns>
        [SkippableTheory]
        [MemberData(nameof(AllTargets))]
        public async Task RT23206_client_idがid_tokenのaudと違えば断る(string targetKey)
        {
            using (IdPClient client = this.Client(targetKey))
            {
                TestReport r = this.Report("RT-232.6",
                    "client_id が id_token_hint の aud と一致しなければ、要求として扱わない",
                    "**両方来ているなら、一致を確かめることが MUST**（§2）。"
                    + "一致を見ないと、**他のクライアントに発行された id_token で**"
                    + "自分の戻り先へ戻させることができてしまう。",
                    "RP-Initiated Logout 1.0 §2（MUST）");

                string idToken = await EndSessionTests.GetIdTokenAsync(client, r);

                // 別のクライアント（構成ファイルに登録済み）の client_id を添える。
                ClientRegistration other = Flows.Registration(client, KnownClients.MvcSample);

                r.Target("GET /end_session（id_token_hint は TestClient_4、client_id は "
                    + KnownClients.MvcSample + "）");

                r.Step("食い違う client_id を添えて要求する");

                HttpResponseMessage res = await client.EndSessionAsync(
                    idToken, other.ClientId,
                    KnownClients.PostLogoutRedirectUri(client), "logout-state-5");

                r.VerifyEqual("HTTP 200（確認画面。リダイレクトしない）",
                    "200", ((int)res.StatusCode).ToString());

                r.Verify("セッションは残っている", await client.IsSessionAliveAsync(),
                    "セッション有り", "セッション有り");

                r.Step("壊れた id_token_hint も同じ扱いになることを確かめる");

                HttpResponseMessage broken = await client.EndSessionAsync(
                    "not-a-jwt", null, KnownClients.PostLogoutRedirectUri(client), "logout-state-6");

                r.VerifyEqual("HTTP 200（500 にしない）", "200", ((int)broken.StatusCode).ToString());

                r.Note("**JWT でない値でも 500 にしない**（#241 と同じ扱い）。"
                    + "id_token_hint は署名検証の前に payload を読む必要がある。");

                r.Done();
            }
        }

        /// <summary>RT-232.7 サインインしていない場合</summary>
        /// <param name="targetKey">core / netfx</param>
        /// <returns>Task</returns>
        [SkippableTheory]
        [MemberData(nameof(AllTargets))]
        public async Task RT23207_サインインしていなくてもエラーにしない(string targetKey)
        {
            using (IdPClient client = this.Client(targetKey))
            {
                TestReport r = this.Report("RT-232.7",
                    "サインインしていなくても、ログアウト要求はエラーにしない",
                    "**ログアウト要求は冪等である**（§4）。"
                    + "「その RP でログインしていない」ことは**エラーではない**と明記されている。"
                    + "RP は、OP 側の状態を知らずにログアウトを要求できる。",
                    "RP-Initiated Logout 1.0 §4");

                string idToken = await EndSessionTests.GetIdTokenAsync(client, r);
                string registered = KnownClients.PostLogoutRedirectUri(client);

                r.Target("GET /end_session（先にサインアウトしておく）");

                r.Step("(1) 先に自サイトからサインアウトする");

                await client.GetAsync("/Account/LogOff");

                r.Verify("サインアウトできた", !await client.IsSessionAliveAsync(),
                    "セッション無し", "セッション無し");

                r.Step("(2) その状態でログアウト要求を送る");

                HttpResponseMessage res = await client.EndSessionAsync(
                    idToken, null, registered, "logout-state-7");

                r.VerifyEqual("HTTP 302（エラーにしない）", "302", ((int)res.StatusCode).ToString());

                Dictionary<string, string> query = new Dictionary<string, string>();
                string location = EndSessionTests.SplitLocation(
                    EndSessionTests.LocationOf(res), query);

                r.VerifyEqual("登録された戻り先へ返す", registered, location);

                r.VerifyEqual("state をそのまま返す", "logout-state-7",
                    query.ContainsKey("state") ? query["state"] : "なし");

                r.Note("**確認画面は出さない。** 消すセッションが無いので、"
                    + "確認を求める意味が無い（§4 : エラーでもない）。");

                r.Done();
            }
        }

        /// <summary>RT-232.8 自己テストのボタン（Starters）</summary>
        /// <param name="targetKey">core / netfx</param>
        /// <returns>Task</returns>
        [SkippableTheory]
        [MemberData(nameof(AllTargets))]
        public async Task RT23208_自己テストのボタンから確認画面まで進める(string targetKey)
        {
            using (IdPClient client = this.Client(targetKey))
            {
                TestReport r = this.Report("RT-232.8",
                    "アプリ同梱の自己テスト（Starters）のボタンから、ログアウトを試せる",
                    "**手で試せる口を、他のフローと同じ場所に置く。**"
                    + "この画面は id_token を持たないので、**確認画面の経路**（§2 の MUST）を通る。"
                    + "`id_token_hint` 付きの経路は `RT-232.9` で見る。",
                    "RP-Initiated Logout 1.0 §2 ／ #232");

                await client.SignInAsync();

                JsonResponse discovery = await client.GetJsonAsync("/.well-known/openid-configuration");
                string endSession = discovery.String("end_session_endpoint");

                r.Target("POST /Home/Saml2OAuth2Starters に submit.EndSession を送る");

                r.Step("(1) ボタンを押す");

                HttpResponseMessage starter = await client.StartSelfTestAsync("EndSession");

                r.VerifyEqual("HTTP 302", "302", ((int)starter.StatusCode).ToString());

                string location = EndSessionTests.LocationOf(starter);

                r.VerifyEqual("Discovery が広告する end_session_endpoint へ飛ばす",
                    endSession, location);

                r.Step("(2) 飛び先（/end_session）を開く");

                HttpResponseMessage page = await client.GetAsync(location);

                r.VerifyEqual("HTTP 200（確認画面）", "200", ((int)page.StatusCode).ToString());

                r.Verify("まだサインアウトしていない", await client.IsSessionAliveAsync(),
                    "セッション有り", "セッション有り");

                r.Step("(3) 確認画面で「はい」を押す");

                HttpResponseMessage confirmed = await client.ConfirmEndSessionAsync(
                    await page.Content.ReadAsStringAsync(), true);

                r.VerifyEqual("HTTP 302", "302", ((int)confirmed.StatusCode).ToString());

                r.Verify("サインアウトされた", !await client.IsSessionAliveAsync(),
                    "セッション無し", "セッション無し");

                r.Done();
            }
        }

        /// <summary>RT-232.9 自己テストの結果画面のボタン</summary>
        /// <param name="targetKey">core / netfx</param>
        /// <returns>Task</returns>
        [SkippableTheory]
        [MemberData(nameof(AllTargets))]
        public async Task RT23209_認可コードの結果画面からid_token_hintつきでログアウトできる(string targetKey)
        {
            using (IdPClient client = this.Client(targetKey))
            {
                TestReport r = this.Report("RT-232.9",
                    "認可コード フローの結果画面から、id_token_hint 付きでログアウトできる",
                    "**取得した id_token をそのまま `id_token_hint` に使える**ことを、画面の側から確かめる。"
                    + "`RT-232.2` は要求の組み立てをテストが行うが、ここは**画面が出しているフォーム**を"
                    + "そのまま送る（自己テストの口が壊れていないこと）。",
                    "RP-Initiated Logout 1.0 §2 / §3 ／ #232");

                await client.SignInAsync();

                JsonResponse discovery = await client.GetJsonAsync("/.well-known/openid-configuration");
                string endSession = discovery.String("end_session_endpoint");

                r.Target("自己テスト : Authorization Code Flow (OIDC) → 結果画面の Sign out");

                r.Step("(1) 自己テストで認可コード フローを通し、結果画面まで進む");

                HttpResponseMessage starter = await client.StartSelfTestAsync(
                    "AuthorizationCode_OIDC", "normal");

                string authorizeUrl = EndSessionTests.LocationOf(starter);

                Assert.False(string.IsNullOrEmpty(authorizeUrl),
                    "前提: 自己テストが認可リクエストへ飛ぶこと（HTTP "
                    + (int)starter.StatusCode + "）");

                AuthZResponse authz = await client.AuthorizeAndGrantAsync(authorizeUrl);

                Assert.False(string.IsNullOrEmpty(authz.Code),
                    "前提: 認可コードが返ること（" + authz.ToString() + "）");

                // 結果画面（この画面が、コードをトークンに交換して表示する）。
                HttpResponseMessage screen = await client.GetAsync(authz.Location);
                string html = await screen.Content.ReadAsStringAsync();

                r.VerifyEqual("結果画面が開く（HTTP 200）", "200", ((int)screen.StatusCode).ToString());

                r.Step("(2) 画面が出しているログアウトのフォームを確かめる");

                r.Verify("フォームの宛先が end_session_endpoint である",
                    html.Contains(endSession),
                    "end_session の URL を含む",
                    html.Contains(endSession) ? "含む" : "**含まない**");

                bool hasIdTokenHint = System.Text.RegularExpressions.Regex.IsMatch(
                    html, "name=\"id_token_hint\"[^>]*value=\"ey[^\"]+\"");

                r.Verify("id_token_hint に id_token が入っている", hasIdTokenHint,
                    "JWT が入っている（値は伏せる）",
                    hasIdTokenHint ? "入っている" : "**空、または JWT でない**");

                // **画面が送る戻り先が、登録の定数（test_self_logout）の解決先と一致すること。**
                //   ここが合っていれば、雛形どおりに登録した配置では RP へ戻る
                //   （この配置の登録の有無に依らず確かめられる）。
                bool matchesRegistered = System.Text.RegularExpressions.Regex.IsMatch(
                    html, "name=\"post_logout_redirect_uri\"[^>]*value=\""
                        + System.Text.RegularExpressions.Regex.Escape(
                            KnownClients.PostLogoutRedirectUri(client)) + "\"");

                r.Verify("戻り先が test_self_logout の解決先と一致する", matchesRegistered,
                    KnownClients.PostLogoutRedirectUri(client),
                    matchesRegistered ? KnownClients.PostLogoutRedirectUri(client)
                                      : "**一致しない**");

                r.Step("(3) そのフォームを送る");

                HttpResponseMessage posted = await client.SubmitSelfTestLogoutAsync(html);

                if (posted.StatusCode == HttpStatusCode.Found
                    || posted.StatusCode == HttpStatusCode.Redirect)
                {
                    Dictionary<string, string> query = new Dictionary<string, string>();
                    string to = EndSessionTests.SplitLocation(
                        EndSessionTests.LocationOf(posted), query);

                    r.Observe("戻り先", to,
                        "**登録（post_logout_redirect_uri）が有る**ので、確認なしで RP へ戻った。");

                    r.Verify("state を返す", query.ContainsKey("state"),
                        "state あり", query.ContainsKey("state") ? "あり" : "**なし**");
                }
                else
                {
                    r.Observe("戻り先", "戻らない（HTTP " + (int)posted.StatusCode + " : 確認画面）",
                        "**この配置の TestClient には post_logout_redirect_uri の登録が無い**ため、"
                        + "RP へは戻さず確認画面になる（§3 の MUST）。"
                        + "雛形（`_appsettings.json` / `_app.config`）には `test_self_logout` を"
                        + "足したので、当て直せば戻るようになる。");

                    posted = await client.ConfirmEndSessionAsync(
                        await posted.Content.ReadAsStringAsync(), true);

                    r.VerifyEqual("確認すればログアウトする（HTTP 302）",
                        "302", ((int)posted.StatusCode).ToString());
                }

                r.Verify("サインアウトされた", !await client.IsSessionAliveAsync(),
                    "セッション無し", "セッション無し");

                r.Done();
            }
        }

        /// <summary>RT-232.10 openid が無いフローの結果画面</summary>
        /// <param name="targetKey">core / netfx</param>
        /// <returns>Task</returns>
        [SkippableTheory]
        [MemberData(nameof(AllTargets))]
        public async Task RT23210_openidが無いフローでは戻り先を送らず理由を出す(string targetKey)
        {
            using (IdPClient client = this.Client(targetKey))
            {
                TestReport r = this.Report("RT-232.10",
                    "openid が無いフローの結果画面は、戻り先を送らず、理由を表示する",
                    "**`scope` に `openid` が無ければ `id_token` は発行されない**"
                    + "（自己テストの `Test Authorization Code Flow` は `openid` を付けない）。"
                    + "`id_token_hint` を送れないので、**戻り先を送っても仕様上戻せない**（§3）。"
                    + "画面が戻り先を送ってしまうと、押すたびに"
                    + "`post_logout_redirect_uri requires id_token_hint.` になる。"
                    + "**送らずに、理由を画面に出す。**",
                    "RP-Initiated Logout 1.0 §2 / §3 ／ #232");

                await client.SignInAsync();

                r.Target("自己テスト : Authorization Code Flow（openid 無し）→ 結果画面");

                r.Step("(1) 自己テストを通し、結果画面まで進む");

                HttpResponseMessage starter = await client.StartSelfTestAsync(
                    "AuthorizationCode", "normal");

                string authorizeUrl = EndSessionTests.LocationOf(starter);

                Assert.False(string.IsNullOrEmpty(authorizeUrl),
                    "前提: 自己テストが認可リクエストへ飛ぶこと（HTTP "
                    + (int)starter.StatusCode + "）");

                AuthZResponse authz = await client.AuthorizeAndGrantAsync(authorizeUrl);

                Assert.False(string.IsNullOrEmpty(authz.Code),
                    "前提: 認可コードが返ること（" + authz.ToString() + "）");

                HttpResponseMessage screen = await client.GetAsync(authz.Location);
                string html = await screen.Content.ReadAsStringAsync();

                r.VerifyEqual("結果画面が開く（HTTP 200）", "200", ((int)screen.StatusCode).ToString());

                r.Step("(2) 画面が出しているものを確かめる");

                // **Razor は値が null の属性を出力しない**ので、value 属性そのものが消える。
                //   「空文字列で出る」ことを前提にせず、**JWT が載っていないこと**で見る。
                bool noIdToken = !System.Text.RegularExpressions.Regex.IsMatch(
                    html, "name=\"id_token_hint\"[^>]*value=\"ey");

                r.Verify("id_token_hint に id_token が載らない", noIdToken,
                    "JWT が無い", noIdToken ? "JWT が無い" : "**JWT が載っている**");

                bool noRedirectUri = !html.Contains("name=\"post_logout_redirect_uri\"");

                r.Verify("戻り先（post_logout_redirect_uri）を送らない", noRedirectUri,
                    "hidden が無い", noRedirectUri ? "hidden が無い" : "**hidden が有る**");

                bool hasReason = html.Contains("openid が無いフロー");

                r.Verify("理由を画面に出す", hasReason,
                    "「openid が無いフロー…」を表示",
                    hasReason ? "表示している" : "**表示していない**");

                r.Step("(3) それでもログアウトはできる（確認画面の経路）");

                HttpResponseMessage posted = await client.SubmitSelfTestLogoutAsync(html);

                r.VerifyEqual("HTTP 200（確認画面）", "200", ((int)posted.StatusCode).ToString());

                HttpResponseMessage confirmed = await client.ConfirmEndSessionAsync(
                    await posted.Content.ReadAsStringAsync(), true);

                r.VerifyEqual("確認すればログアウトする（HTTP 302）",
                    "302", ((int)confirmed.StatusCode).ToString());

                r.Verify("サインアウトされた", !await client.IsSessionAliveAsync(),
                    "セッション無し", "セッション無し");

                r.Note("**Razor の分岐は実行時にコンパイルされる**ので、"
                    + "この経路（id_token が無い側）も叩いておく。ビルドでは確かめられない。");

                r.Done();
            }
        }
    }
}
