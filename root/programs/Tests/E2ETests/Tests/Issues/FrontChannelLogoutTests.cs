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
//* クラス名        ：FrontChannelLogoutTests
//* クラス日本語名  ：RT-310 Front-Channel Logout（段階 3）
//*
//* 作成日時        ：－
//* 作成者          ：－
//* 更新履歴        ：－
//*
//*  日時        更新者            内容
//*  ----------  ----------------  -------------------------------------------------
//*  2026/10/21  玄人 幸道         新規（#310 の段階 3）
//**********************************************************************************

using System.Collections.Generic;
using System.Net;
using System.Net.Http;
using System.Text.RegularExpressions;
using System.Threading.Tasks;
using System.Web;

using MultiPurposeAuthSite.Tests.E2E.Infrastructure;

using Xunit;
using Xunit.Abstractions;

namespace MultiPurposeAuthSite.Tests.E2E.Tests.Issues
{
    /// <summary>
    /// RT-310. **Front-Channel Logout**（#310 の段階 3）。
    /// </summary>
    /// <remarks>
    /// **段階 2（Back-Channel）との違いは「誰が RP を叩くか」である。**
    ///
    /// | | 誰が叩くか | 届く相手 |
    /// |---|---|---|
    /// | **Back-Channel** | **OP のサーバ** | **受け口を持てる RP** |
    /// | **Front-Channel** | **利用者のブラウザ**（`iframe`） | **ブラウザの中だけで動く RP** も届く |
    ///
    /// | | 測ること |
    /// |---|---|
    /// | **`RT-310.7`** | **Discovery が `frontchannel_logout_supported` と `frontchannel_logout_session_supported` を広告する**（**`check_session_iframe` は出さない** — Session Management は見送り） |
    /// | **`RT-310.8`** | **`/end_session` が `iframe` の画面を返す**。**`iss` と `sid` が付く**。**その URL を叩くと RP に届く**。**登録が無い RP の `iframe` は無い**。**画面の後は、登録された戻り先へ進む** |
    /// | **`RT-310.9`** | **`/Account/Logout` でも画面が出る**。**登録が在る RP が 1 つも無ければ、画面は出ない**（**応答が変わらない**） |
    ///
    /// **E2E のクライアントは `iframe` を開かない**ので、
    /// **画面から URL を取り出して、自分で叩く**（**ブラウザの代わりをする**）。
    /// **叩かれたことは受信箱で見る**（`/Account/FrontChannelLogoutBox`。
    /// **`IsLockedDownTestEndpoints` で閉じる**ので、閉じている配備では Skip する）。
    /// </remarks>
    public class FrontChannelLogoutTests : TargetTestBase
    {
        /// <summary>受信箱を読む口</summary>
        private const string BoxPath = "/Account/FrontChannelLogoutBox";

        /// <summary>画面から iframe の src を拾う</summary>
        private static readonly Regex IframeRegex = new Regex(
            "<iframe[^>]*\\ssrc=\"(?<src>[^\"]+)\"", RegexOptions.IgnoreCase);

        /// <summary>画面から meta refresh の進む先を拾う</summary>
        private static readonly Regex RefreshRegex = new Regex(
            "http-equiv=\"refresh\"[^>]*content=\"[^\";]*;\\s*url=(?<url>[^\"]+)\"",
            RegexOptions.IgnoreCase);

        /// <summary>コンストラクタ</summary>
        /// <param name="output">ITestOutputHelper</param>
        public FrontChannelLogoutTests(ITestOutputHelper output) : base(output)
        {
        }

        #region RT-310.7

        /// <summary>RT-310.7 Discovery が Front-Channel Logout を広告する</summary>
        /// <param name="targetKey">core / netfx</param>
        /// <returns>Task</returns>
        [SkippableTheory]
        [MemberData(nameof(AllTargets))]
        public async Task RT31007_DiscoveryがFrontChannelLogoutを広告する(string targetKey)
        {
            using (IdPClient client = this.Client(targetKey))
            {
                TestReport r = this.Report("RT-310.7",
                    "**Discovery が `frontchannel_logout_supported` と "
                    + "`frontchannel_logout_session_supported` を広告する**",
                    "**RP は、どちらの伝え方に対応しているかを知る必要が在る。**"
                    + "**受け口を持てない RP**（ブラウザの中だけで動く RP）**は、"
                    + "Front-Channel しか使えない。**"
                    + "**`sid` を付けることも広告する** — "
                    + "**RP は `sid` で、どのセッションを閉じるかを決める。**",
                    "OIDC Front-Channel Logout 1.0 §3 / #310 の段階 3");

                r.Target("GET /.well-known/openid-configuration");

                r.Step("広告を読む");

                JsonResponse res = await client.GetJsonAsync("/.well-known/openid-configuration");

                r.VerifyEqual("frontchannel_logout_supported が true",
                    "true", FrontChannelLogoutTests.BoolOf(res, "frontchannel_logout_supported"));

                r.VerifyEqual("frontchannel_logout_session_supported が true",
                    "true",
                    FrontChannelLogoutTests.BoolOf(res, "frontchannel_logout_session_supported"));

                r.Step("段階 2 の広告も、そのまま在る");

                r.VerifyEqual("backchannel_logout_supported が true",
                    "true", FrontChannelLogoutTests.BoolOf(res, "backchannel_logout_supported"));

                r.Step("Session Management は見送ったので、広告しない");

                r.Verify("check_session_iframe は出ていない",
                    string.IsNullOrEmpty(res.String("check_session_iframe")),
                    "無い", string.IsNullOrEmpty(res.String("check_session_iframe"))
                        ? "無い" : "**出ている**（できないことを広告している）");

                r.Note("**Session Management（`check_session_iframe`）は見送った** — "
                    + "**third-party cookie を読む仕組み**で、"
                    + "**現代のブラウザでは効かなくなりつつある。**");

                r.Done();
            }
        }

        #endregion

        #region RT-310.8

        /// <summary>RT-310.8 /end_session が iframe の画面を返す</summary>
        /// <param name="targetKey">core / netfx</param>
        /// <returns>Task</returns>
        [SkippableTheory]
        [MemberData(nameof(AllTargets))]
        public async Task RT31008_end_sessionがiframeの画面を返す(string targetKey)
        {
            using (IdPClient client = this.Client(targetKey))
            {
                TestReport r = this.Report("RT-310.8",
                    "**`/end_session` が `iframe` の画面を返し、`iss` と `sid` を付けた URL で "
                    + "RP を叩ける**。**登録が無い RP の `iframe` は無い**。"
                    + "**画面の後は、登録された戻り先へ進む**",
                    "**受け口を持てない RP には、ブラウザ経由でしか伝えられない。**"
                    + "**`iframe` の URL に `iss` と `sid` が要る** — "
                    + "**Cookie が送られない文脈も在る**ので、"
                    + "**URL だけで「どの OP の・どのセッションか」が分からなければ、"
                    + "RP は閉じるセッションを決められない。**",
                    "OIDC Front-Channel Logout 1.0 §2 / #310 の段階 3");

                await FrontChannelLogoutTests.ClearBoxAsync(client, r);

                ClientRegistration notified = Flows.InjectedRegistration(
                    client, KnownClients.TestClient_28);
                ClientRegistration silent = Flows.Registration(
                    client, KnownClients.TestClient);

                string registeredIframe = KnownClients.FrontChannelLogoutUri(client);
                string registeredReturn = KnownClients.PostLogoutRedirectUri(client);

                r.Target("client_name=" + KnownClients.TestClient_28
                    + "（受け口を登録）と " + KnownClients.TestClient + "（登録なし）");

                r.Step("(1) 受け口を登録した RP に、トークンを発行する");

                await client.SignInAsync(force: true);

                string idToken = await FrontChannelLogoutTests.RunCodeFlowAsync(
                    client, notified, "nonce-rt3108a");

                Assert.False(string.IsNullOrEmpty(idToken),
                    "前提: id_token が取得できること");

                string sid = FrontChannelLogoutTests.ClaimOf(idToken, "sid");

                r.Verify("id_token に sid が在る（段階 1）", !string.IsNullOrEmpty(sid),
                    "sid 有り", string.IsNullOrEmpty(sid) ? "**無い**" : "有り（値は出さない）");

                r.Step("(2) 受け口を登録していない RP にも、トークンを発行する");

                string otherIdToken = await FrontChannelLogoutTests.RunCodeFlowAsync(
                    client, silent, "nonce-rt3108b");

                r.Verify("2 つ目の RP にもトークンが出た（台帳に 2 行）",
                    !string.IsNullOrEmpty(otherIdToken),
                    "出た", string.IsNullOrEmpty(otherIdToken) ? "**出ない**" : "出た");

                r.Step("(3) RP からのログアウト（/end_session）");

                HttpResponseMessage res = await client.EndSessionAsync(
                    idToken, null, registeredReturn, "fclogout-state-1");

                r.VerifyEqual("リダイレクトではなく、画面が返る（HTTP 200）",
                    "200", ((int)res.StatusCode).ToString());

                string html = await res.Content.ReadAsStringAsync();

                r.Verify("セッションが消えている", !await client.IsSessionAliveAsync(),
                    "サインインが要る画面が開けない", "サインインが要る画面が開けない");

                r.Step("(4) 画面に在る iframe");

                List<string> srcs = FrontChannelLogoutTests.IframeSrcs(html);

                r.VerifyEqual("iframe の数", "1", srcs.Count.ToString());

                if (srcs.Count == 0)
                {
                    r.Note("**iframe が無いので、中身は見ていない。**");
                    r.Done();
                    return;
                }

                string src = srcs[0];

                r.Verify("登録された frontchannel_logout_uri で始まる",
                    src.StartsWith(registeredIframe),
                    registeredIframe + " …",
                    src.StartsWith(registeredIframe) ? "そのとおり" : "**違う URL**");

                Dictionary<string, string> query = FrontChannelLogoutTests.QueryOf(src);

                r.Verify("iss が付いている",
                    query.ContainsKey("iss") && !string.IsNullOrEmpty(query["iss"]),
                    "付いている", query.ContainsKey("iss") ? "付いている" : "**無い**");

                r.Verify("sid は、その RP の id_token と同じ値",
                    query.ContainsKey("sid") && !string.IsNullOrEmpty(sid)
                        && (query["sid"] == sid),
                    "id_token と同じ",
                    (query.ContainsKey("sid") && query["sid"] == sid)
                        ? "同じ" : "**違う**（RP が照合できない）");

                r.Verify("登録していない RP の iframe は無い",
                    srcs.Count == 1,
                    "1 つだけ", srcs.Count.ToString() + " つ");

                r.Step("(5) 画面の後に進む先（meta refresh）");

                string continueUrl = FrontChannelLogoutTests.RefreshUrl(html);

                r.Verify("登録された post_logout_redirect_uri へ進む",
                    !string.IsNullOrEmpty(continueUrl)
                        && continueUrl.StartsWith(registeredReturn),
                    registeredReturn + " …", continueUrl ?? "**無い**");

                r.Verify("state も付いている",
                    !string.IsNullOrEmpty(continueUrl)
                        && continueUrl.Contains("fclogout-state-1"),
                    "付いている",
                    (continueUrl != null && continueUrl.Contains("fclogout-state-1"))
                        ? "付いている" : "**無い**");

                r.Step("(6) ブラウザの代わりに、その URL を叩く");

                HttpResponseMessage hit = await client.GetAsync(src);

                r.Verify("受け口が応える（2xx）", hit.IsSuccessStatusCode,
                    "2xx", ((int)hit.StatusCode).ToString());

                JsonResponse box = await client.GetJsonAsync(FrontChannelLogoutTests.BoxPath);
                string[] hits = box.Strings("frontchannel_hits");

                r.VerifyEqual("RP が受け取った回数", "1",
                    (hits == null) ? "0" : hits.Length.ToString());

                r.Verify("受け取った sid が、id_token と同じ",
                    hits != null && 0 < hits.Length && hits[hits.Length - 1].EndsWith("sid=" + sid),
                    "同じ",
                    (hits != null && 0 < hits.Length) ? "記録あり（値は出さない）" : "**記録なし**");

                r.Note("**E2E のクライアントは `iframe` を開かない**ので、"
                    + "**画面から URL を取り出して自分で叩いた**（ブラウザの代わり）。"
                    + "**本物の RP は、この要求で自分のセッションを閉じる。**");

                r.Note("**Back-Channel（段階 2）も同時に動く**（登録が在れば）。"
                    + "**この RP には `backchannel_logout_uri` を登録していない**ので、"
                    + "**ここで測っているのは Front-Channel だけ**である。");

                r.Done();
            }
        }

        #endregion

        #region RT-310.9

        /// <summary>RT-310.9 Logout でも画面が出る（登録が無ければ出ない）</summary>
        /// <param name="targetKey">core / netfx</param>
        /// <returns>Task</returns>
        [SkippableTheory]
        [MemberData(nameof(AllTargets))]
        public async Task RT31009_Logoutでも画面が出る(string targetKey)
        {
            using (IdPClient client = this.Client(targetKey))
            {
                TestReport r = this.Report("RT-310.9",
                    "**`/Account/Logout`（OP 主導のサインアウト）でも `iframe` の画面が出る**。"
                    + "**登録が在る RP が 1 つも無ければ、画面は出ない**",
                    "**伝えるのは「OP のセッションが終わるとき」である。**"
                    + "**RP から言われたときだけ伝えるのでは、足りない。**"
                    + "**一方で、登録している RP が 1 つも無い配備では、"
                    + "画面が増えてはならない** — **応答が変わると、既存の導線が壊れる。**",
                    "OIDC Front-Channel Logout 1.0 §2 / #310 の段階 3");

                await FrontChannelLogoutTests.ClearBoxAsync(client, r);

                ClientRegistration notified = Flows.InjectedRegistration(
                    client, KnownClients.TestClient_28);
                ClientRegistration silent = Flows.Registration(
                    client, KnownClients.TestClient);

                r.Target("GET /Account/Logout");

                r.Step("(1) 登録が無い RP だけのセッションでは、画面が出ない");

                await client.SignInAsync(force: true);

                string otherIdToken = await FrontChannelLogoutTests.RunCodeFlowAsync(
                    client, silent, "nonce-rt3109a");

                r.Verify("前提: トークンが出た（台帳に 1 行）",
                    !string.IsNullOrEmpty(otherIdToken),
                    "出た", string.IsNullOrEmpty(otherIdToken) ? "**出ない**" : "出た");

                HttpResponseMessage plain = await client.GetAsync("/Account/Logout");

                r.VerifyEqual("従来どおりリダイレクトで返る（HTTP 302）",
                    "302", ((int)plain.StatusCode).ToString());

                r.Step("(2) 登録が在る RP が居れば、画面が出る");

                await client.SignInAsync(force: true);

                string idToken = await FrontChannelLogoutTests.RunCodeFlowAsync(
                    client, notified, "nonce-rt3109b");

                string sid = FrontChannelLogoutTests.ClaimOf(idToken, "sid");

                r.Verify("前提: id_token に sid が在る", !string.IsNullOrEmpty(sid),
                    "sid 有り", string.IsNullOrEmpty(sid) ? "**無い**" : "有り");

                HttpResponseMessage res = await client.GetAsync("/Account/Logout");

                r.VerifyEqual("画面が返る（HTTP 200）",
                    "200", ((int)res.StatusCode).ToString());

                string html = await res.Content.ReadAsStringAsync();
                List<string> srcs = FrontChannelLogoutTests.IframeSrcs(html);

                r.VerifyEqual("iframe の数", "1", srcs.Count.ToString());

                if (0 < srcs.Count)
                {
                    Dictionary<string, string> query =
                        FrontChannelLogoutTests.QueryOf(srcs[0]);

                    r.Verify("sid は、その RP の id_token と同じ値",
                        query.ContainsKey("sid") && (query["sid"] == sid),
                        "id_token と同じ",
                        (query.ContainsKey("sid") && query["sid"] == sid) ? "同じ" : "**違う**");
                }

                r.Step("(3) 画面の後は Home へ進む（RP の指定が無いので）");

                string continueUrl = FrontChannelLogoutTests.RefreshUrl(html);

                r.Verify("進む先が在る", !string.IsNullOrEmpty(continueUrl),
                    "在る", continueUrl ?? "**無い**");

                r.Verify("セッションが消えている", !await client.IsSessionAliveAsync(),
                    "サインインが要る画面が開けない", "サインインが要る画面が開けない");

                r.Note("**同じ口を、サインアウトの 5 か所から呼んでいる**"
                    + "（`/Account/Logout` / `/end_session` / `prompt=login` の再認証 / "
                    + "`max_age` の再認証 / 別のアカウントでログイン）。"
                    + "**再認証の経路では、画面の後に同じ認可要求へ戻る**（測っていない）。");

                r.Done();
            }
        }

        #endregion

        #region 私的なヘルパ

        /// <summary>真偽値の広告を、小文字の綴りで引く</summary>
        /// <param name="res">JsonResponse</param>
        /// <param name="name">項目名</param>
        /// <returns>"true" / "false"（無ければ "なし"）</returns>
        private static string BoolOf(JsonResponse res, string name)
        {
            string value = res.String(name);

            return string.IsNullOrEmpty(value) ? "なし" : value.ToLower();
        }

        /// <summary>受信箱を空にする（閉じている配備では Skip）</summary>
        /// <param name="client">IdPClient</param>
        /// <param name="r">TestReport</param>
        /// <returns>Task</returns>
        private static async Task ClearBoxAsync(IdPClient client, TestReport r)
        {
            JsonResponse res = await client.GetJsonAsync(
                FrontChannelLogoutTests.BoxPath + "?clear=true");

            Skip.If(res.Strings("frontchannel_hits") == null,
                "自己テストの受け口が閉じています（IsLockedDownTestEndpoints）。");

            r.Note("**受信箱を空にしてから測る**（前のケースの記録が混ざらないように）。");
        }

        /// <summary>画面から iframe の src を並べる（HTML の実体参照は戻す）</summary>
        /// <param name="html">画面</param>
        /// <returns>src の一覧</returns>
        private static List<string> IframeSrcs(string html)
        {
            List<string> srcs = new List<string>();

            foreach (Match m in FrontChannelLogoutTests.IframeRegex.Matches(html ?? ""))
            {
                srcs.Add(HttpUtility.HtmlDecode(m.Groups["src"].Value));
            }

            return srcs;
        }

        /// <summary>画面から meta refresh の進む先を拾う（無ければ空）</summary>
        /// <param name="html">画面</param>
        /// <returns>URL</returns>
        private static string RefreshUrl(string html)
        {
            Match m = FrontChannelLogoutTests.RefreshRegex.Match(html ?? "");

            return m.Success ? HttpUtility.HtmlDecode(m.Groups["url"].Value) : "";
        }

        /// <summary>URL のクエリを辞書にする</summary>
        /// <param name="url">URL</param>
        /// <returns>クエリ</returns>
        private static Dictionary<string, string> QueryOf(string url)
        {
            Dictionary<string, string> query = new Dictionary<string, string>();

            int i = (url ?? "").IndexOf('?');

            if (i < 0)
            {
                return query;
            }

            foreach (string pair in url.Substring(i + 1).Split('&'))
            {
                string[] kv = pair.Split(new char[] { '=' }, 2);

                query[WebUtility.UrlDecode(kv[0])] =
                    (kv.Length == 2) ? WebUtility.UrlDecode(kv[1]) : "";
            }

            return query;
        }

        /// <summary>認可コード フローを通して id_token を返す</summary>
        /// <param name="client">IdPClient</param>
        /// <param name="registration">クライアント</param>
        /// <param name="nonce">nonce</param>
        /// <returns>id_token（取れなければ空）</returns>
        private static async Task<string> RunCodeFlowAsync(
            IdPClient client, ClientRegistration registration, string nonce)
        {
            AuthZResponse authz = await Flows.AuthorizeCodeAsync(
                client, registration, "openid email", "state1", nonce, registration.RedirectUri);

            if (string.IsNullOrEmpty(authz.Code))
            {
                return "";
            }

            JsonResponse token = await Flows.ExchangeCodeAsync(
                client, registration, authz.Code, registration.RedirectUri);

            return token.IdToken ?? "";
        }

        /// <summary>JWT のクレームを引く（無ければ空）</summary>
        /// <param name="jwt">JWT</param>
        /// <param name="name">クレーム名</param>
        /// <returns>値</returns>
        private static string ClaimOf(string jwt, string name)
        {
            if (string.IsNullOrEmpty(jwt))
            {
                return "";
            }

            return Jwt.String(Jwt.Payload(jwt), name) ?? "";
        }

        #endregion
    }
}
