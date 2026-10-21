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
//* クラス名        ：BackChannelLogoutTests
//* クラス日本語名  ：RT-310 Back-Channel Logout（段階 2）
//*
//* 作成日時        ：－
//* 作成者          ：－
//* 更新履歴        ：－
//*
//*  日時        更新者            内容
//*  ----------  ----------------  -------------------------------------------------
//*  2026/10/21  玄人 幸道         新規（#310 の段階 2）
//*  2026/10/21  玄人 幸道         Front-Channel Logout の広告に追随（#310 の段階 3）
//**********************************************************************************

using System.Collections.Generic;
using System.Net.Http;
using System.Text.Json;
using System.Threading.Tasks;

using MultiPurposeAuthSite.Tests.E2E.Infrastructure;

using Xunit;
using Xunit.Abstractions;

namespace MultiPurposeAuthSite.Tests.E2E.Tests.Issues
{
    /// <summary>
    /// RT-310. **Back-Channel Logout**（#310 の段階 2）。
    /// </summary>
    /// <remarks>
    /// **段階 1 で「どのセッションか」を言う手段（`sid`）と台帳を入れた**（`RT-310.1`〜`.3`）。
    /// **段階 2 は、そのセッションが触った RP へ、サインアウトを伝える。**
    ///
    /// | | 測ること |
    /// |---|---|
    /// | **`RT-310.4`** | **Discovery が `backchannel_logout_supported` を広告する**（`frontchannel_logout_supported` は**まだ出さない**） |
    /// | **`RT-310.5`** | **`/end_session` で、登録が在る RP に `logout_token` が届く**（中身も確かめる）。**登録が無い RP には届かない** |
    /// | **`RT-310.6`** | **同意画面を出しただけ・拒否された RP には伝えない**（段階 2 の冒頭で直した） |
    ///
    /// **受け口はサイト自身**である（`/Account/BackChannelLogoutClient`）。
    /// **E2E のクライアントは HTTP サーバを持たない**ので、
    /// **このサイトが自分の RP も兼ねる**（`test_self_code` と同じ考え方）。
    /// **受け取った `logout_token` は `/Account/BackChannelLogoutBox` で読める**
    /// （**どちらも `IsLockedDownTestEndpoints` で閉じる**ので、閉じている配備では Skip する）。
    ///
    /// **通知は背景で送られる**（**要求の経路では待たない**）ので、**届くまで待つ。**
    /// </remarks>
    public class BackChannelLogoutTests : TargetTestBase
    {
        /// <summary>events クレームの事象の型（Back-Channel Logout 1.0 §2.4）</summary>
        private const string BackChannelLogoutEvent
            = "http://schemas.openid.net/event/backchannel-logout";

        /// <summary>受信箱を読む口</summary>
        private const string BoxPath = "/Account/BackChannelLogoutBox";

        /// <summary>届くまで待つ回数（1 回 300ms）</summary>
        private const int WaitCount = 50;

        /// <summary>コンストラクタ</summary>
        /// <param name="output">ITestOutputHelper</param>
        public BackChannelLogoutTests(ITestOutputHelper output) : base(output)
        {
        }

        #region RT-310.4

        /// <summary>RT-310.4 Discovery が Back-Channel Logout を広告する</summary>
        /// <param name="targetKey">core / netfx</param>
        /// <returns>Task</returns>
        [SkippableTheory]
        [MemberData(nameof(AllTargets))]
        public async Task RT31004_DiscoveryがBackChannelLogoutを広告する(string targetKey)
        {
            using (IdPClient client = this.Client(targetKey))
            {
                TestReport r = this.Report("RT-310.4",
                    "**Discovery が `backchannel_logout_supported` と "
                    + "`backchannel_logout_session_supported` を広告する**",
                    "**RP は、OP が伝えてくれるかどうかを知る必要が在る。**"
                    + "**広告が無ければ、RP は `backchannel_logout_uri` を登録する理由が無い。**"
                    + "**`sid` を入れることも広告する** — "
                    + "**RP は `logout_token` の `sid` で、どのセッションを閉じるかを決める。**",
                    "OIDC Back-Channel Logout 1.0 §3 / #310 の段階 2");

                r.Target("GET /.well-known/openid-configuration");

                r.Step("広告を読む");

                JsonResponse res = await client.GetJsonAsync("/.well-known/openid-configuration");

                //  **真偽値は、JSON の綴りでは返らない**（`JsonElement.ToString()` は "True"）。
                //    **小文字に揃えて比べる**（**広告が無ければ "なし"**）。
                r.VerifyEqual("backchannel_logout_supported が true",
                    "true", BackChannelLogoutTests.BoolOf(res, "backchannel_logout_supported"));

                r.VerifyEqual("backchannel_logout_session_supported が true",
                    "true", BackChannelLogoutTests.BoolOf(res, "backchannel_logout_session_supported"));

                r.Verify("end_session_endpoint も在る（#232 のまま）",
                    !string.IsNullOrEmpty(res.String("end_session_endpoint")),
                    "在る", string.IsNullOrEmpty(res.String("end_session_endpoint"))
                        ? "**無い**" : "在る");

                r.Step("Front-Channel Logout も広告されている（段階 3 で入った）");

                //  **段階 2 の時点では「出ていない」ことを見ていた**（#310）。
                //    **段階 3 で実装したので、出ていることを見る**
                //    （**中身は `RT-310.7`** で測る）。
                r.Verify("frontchannel_logout_supported が出ている",
                    !string.IsNullOrEmpty(res.String("frontchannel_logout_supported")),
                    "出ている", string.IsNullOrEmpty(res.String("frontchannel_logout_supported"))
                        ? "**出ていない**" : "出ている");

                r.Note("**Session Management（`check_session_iframe`）は見送った**"
                    + "（third-party cookie を読む仕組みで、現代のブラウザでは効かなくなりつつある）。"
                    + "**広告しないので、RP は使おうとしない。**");

                r.Done();
            }
        }

        #endregion

        #region RT-310.5

        /// <summary>RT-310.5 /end_session で logout_token が届く</summary>
        /// <param name="targetKey">core / netfx</param>
        /// <returns>Task</returns>
        [SkippableTheory]
        [MemberData(nameof(AllTargets))]
        public async Task RT31005_end_sessionでlogout_tokenが届く(string targetKey)
        {
            using (IdPClient client = this.Client(targetKey))
            {
                TestReport r = this.Report("RT-310.5",
                    "**`/end_session` でサインアウトすると、`backchannel_logout_uri` を"
                    + "登録した RP に `logout_token` が POST される**（中身も確かめる）。"
                    + "**登録が無い RP には届かない**",
                    "**OP のセッションが終わっても、RP のセッションは残る。**"
                    + "**伝えなければ、RP では入ったままになる** — "
                    + "**これが D-1-2 の「他の RP へログアウトを伝えられない」である。**"
                    + "**`logout_token` は `id_token` と別のトークン**なので、"
                    + "**`events` が在り、`nonce` が無いことまで見る**"
                    + "（**`id_token` として受け取られると、RP でサインインに使われる恐れが在る**）。",
                    "OIDC Back-Channel Logout 1.0 §2.4 / §2.5 / #310 の段階 2");

                await BackChannelLogoutTests.ClearBoxAsync(client, r);

                ClientRegistration notified = Flows.InjectedRegistration(
                    client, KnownClients.TestClient_26);
                ClientRegistration silent = Flows.Registration(
                    client, KnownClients.TestClient);

                r.Target("client_name=" + KnownClients.TestClient_26
                    + "（受け口を登録）と " + KnownClients.TestClient + "（登録なし）");

                r.Step("(1) 受け口を登録した RP に、トークンを発行する");

                await client.SignInAsync(force: true);

                string idToken = await BackChannelLogoutTests.RunCodeFlowAsync(
                    client, notified, "nonce-rt3105a");

                Assert.False(string.IsNullOrEmpty(idToken),
                    "前提: id_token が取得できること");

                string sid = BackChannelLogoutTests.ClaimOf(idToken, "sid");

                r.Verify("id_token に sid が在る（段階 1）", !string.IsNullOrEmpty(sid),
                    "sid 有り", string.IsNullOrEmpty(sid) ? "**無い**" : "有り（値は出さない）");

                r.Step("(2) 受け口を登録していない RP にも、トークンを発行する");

                string otherIdToken = await BackChannelLogoutTests.RunCodeFlowAsync(
                    client, silent, "nonce-rt3105b");

                r.Verify("2 つ目の RP にもトークンが出た（台帳に 2 行）",
                    !string.IsNullOrEmpty(otherIdToken),
                    "出た", string.IsNullOrEmpty(otherIdToken) ? "**出ない**" : "出た");

                r.Step("(3) RP からのログアウト（/end_session）");

                HttpResponseMessage res = await client.EndSessionAsync(idToken, null, null, null);

                r.VerifyEqual("HTTP 302", "302", ((int)res.StatusCode).ToString());

                r.Verify("セッションが消えている", !await client.IsSessionAliveAsync(),
                    "サインインが要る画面が開けない", "サインインが要る画面が開けない");

                r.Step("(4) 受け口に logout_token が届く（背景で送られるので待つ）");

                List<string> tokens = await BackChannelLogoutTests.WaitForTokensAsync(client, 1);

                r.VerifyEqual("届いた logout_token の数", "1", tokens.Count.ToString());

                if (tokens.Count == 0)
                {
                    r.Note("**届かなかったので、中身は見ていない。**");
                    r.Done();
                    return;
                }

                string logoutToken = tokens[tokens.Count - 1];

                JsonElement header = Jwt.Header(logoutToken);
                JsonElement payload = Jwt.Payload(logoutToken);

                r.Step("(5) logout_token の中身");

                r.VerifyEqual("aud は、登録した RP の client_id",
                    notified.ClientId, Jwt.String(payload, "aud") ?? "なし");

                r.Verify("iss は、この OP である",
                    !string.IsNullOrEmpty(Jwt.String(payload, "iss")),
                    "在る", string.IsNullOrEmpty(Jwt.String(payload, "iss")) ? "**無い**" : "在る");

                r.Verify("sid は、その RP の id_token と同じ値",
                    !string.IsNullOrEmpty(sid) && (Jwt.String(payload, "sid") == sid),
                    "id_token と同じ",
                    (Jwt.String(payload, "sid") == sid) ? "同じ" : "**違う**（RP が照合できない）");

                r.Verify("sub も入っている（引けたので）",
                    !string.IsNullOrEmpty(Jwt.String(payload, "sub")),
                    "在る", string.IsNullOrEmpty(Jwt.String(payload, "sub"))
                        ? "**無い**（sid だけでも仕様は満たす）" : "在る");

                r.Verify("jti が在る（使い回しを RP が弾ける）",
                    !string.IsNullOrEmpty(Jwt.String(payload, "jti")),
                    "在る", string.IsNullOrEmpty(Jwt.String(payload, "jti")) ? "**無い**" : "在る");

                r.Verify("events に backchannel-logout が在る",
                    BackChannelLogoutTests.HasLogoutEvent(payload),
                    "在る", BackChannelLogoutTests.HasLogoutEvent(payload) ? "在る" : "**無い**");

                r.Verify("nonce は入っていない（MUST NOT）",
                    !Jwt.Has(payload, "nonce"),
                    "無い", Jwt.Has(payload, "nonce")
                        ? "**入っている**（id_token と見分けが付かない）" : "無い");

                r.VerifyEqual("typ ヘッダは logout+jwt",
                    "logout+jwt", Jwt.String(header, "typ") ?? "なし");

                r.Verify("kid が在る（id_token と同じ鍵で引ける）",
                    !string.IsNullOrEmpty(Jwt.String(header, "kid")),
                    "在る", string.IsNullOrEmpty(Jwt.String(header, "kid")) ? "**無い**" : "在る");

                r.Step("(6) 登録が無い RP には届いていない");

                bool toSilent = false;

                foreach (string t in tokens)
                {
                    if (Jwt.String(Jwt.Payload(t), "aud") == silent.ClientId)
                    {
                        toSilent = true;
                    }
                }

                r.Verify("登録していない RP 宛ての logout_token が無い", !toSilent,
                    "無い", toSilent ? "**在る**（登録の無い相手に伝えている）" : "無い");

                r.Note("**署名の検証は、ここでは行っていない。** "
                    + "**鍵は `id_token` と同じ**（`kid` も同じ引き方）なので、"
                    + "**`/jwkcerts` で検証できることは `RT-302.*` が押さえている。**");

                r.Note("**再送はしない**（仕様も求めていない）。"
                    + "**届かなかったことはログに残る**"
                    + "（`The back-channel logout notified n of m RPs.`）。");

                r.Done();
            }
        }

        #endregion

        #region RT-310.6

        /// <summary>RT-310.6 同意していない RP には伝えない</summary>
        /// <param name="targetKey">core / netfx</param>
        /// <returns>Task</returns>
        [SkippableTheory]
        [MemberData(nameof(AllTargets))]
        public async Task RT31006_同意していないRPには伝えない(string targetKey)
        {
            using (IdPClient client = this.Client(targetKey))
            {
                TestReport r = this.Report("RT-310.6",
                    "**同意画面を出しただけ・拒否された RP には、ログアウトを伝えない**",
                    "**伝える先は「トークンを発行した相手」である。**"
                    + "**段階 1 では、認可の口に入った時点で台帳に書いていた**ので、"
                    + "**同意画面を見せただけの相手・拒否された相手も、伝える先に残っていた** — "
                    + "**その RP に「この利用者が来た」ことを教えてしまう。**"
                    + "**段階 2 の冒頭で、台帳に書くのを「発行の直前」に移した。**",
                    "OIDC Back-Channel Logout 1.0 §2.5 / #310 の段階 2");

                await BackChannelLogoutTests.ClearBoxAsync(client, r);

                ClientRegistration granted = Flows.InjectedRegistration(
                    client, KnownClients.TestClient_26);
                ClientRegistration denied = Flows.InjectedRegistration(
                    client, KnownClients.TestClient_27);

                r.Target("client_name=" + KnownClients.TestClient_27
                    + "（受け口を登録。**同意しない**）");

                await client.SignInAsync(force: true);

                r.Step("(1) 拒否する RP の認可要求を出し、同意画面で「拒否」を押す");

                AuthZResponse authz = await client.AuthorizeAsync(
                    new Dictionary<string, string>()
                    {
                        { "response_type", "code" },
                        { "client_id", denied.ClientId },
                        { "scope", "openid email" },
                        { "state", "state-rt3106" },
                        { "nonce", "nonce-rt3106" },
                        { "redirect_uri", denied.RedirectUri }
                    });

                r.Verify("同意画面が出た", authz.NeedsConsent,
                    "出た", authz.NeedsConsent
                        ? "出た" : "**出ない**（このクライアントに同意が記録されている）");

                if (!authz.NeedsConsent)
                {
                    r.Note("**同意が記録されていると、この経路は測れない**"
                        + "（**このクライアントには、どのテストも「許可」を押さない**）。");
                    r.Done();
                    return;
                }

                AuthZResponse denyRes = await client.DenyConsentAsync(authz);

                r.VerifyEqual("access_denied が返る", "access_denied", denyRes.Error ?? "なし");

                r.Step("(2) 別の RP には、きちんと発行する（伝える先が 1 つ在る状態にする）");

                string idToken = await BackChannelLogoutTests.RunCodeFlowAsync(
                    client, granted, "nonce-rt3106b");

                Assert.False(string.IsNullOrEmpty(idToken),
                    "前提: id_token が取得できること");

                r.Step("(3) サインアウトして、届いた通知を見る");

                HttpResponseMessage res = await client.EndSessionAsync(idToken, null, null, null);

                r.VerifyEqual("HTTP 302", "302", ((int)res.StatusCode).ToString());

                List<string> tokens = await BackChannelLogoutTests.WaitForTokensAsync(client, 1);

                bool toGranted = false;
                bool toDenied = false;

                foreach (string t in tokens)
                {
                    string aud = Jwt.String(Jwt.Payload(t), "aud");

                    if (aud == granted.ClientId)
                    {
                        toGranted = true;
                    }

                    if (aud == denied.ClientId)
                    {
                        toDenied = true;
                    }
                }

                r.Verify("発行した RP には届く", toGranted,
                    "届く", toGranted ? "届く" : "**届かない**");

                r.Verify("拒否した RP には届かない", !toDenied,
                    "届かない",
                    toDenied ? "**届いた**（トークンを受けていない相手に伝えている）" : "届かない");

                r.Note("**同意画面を出した時点では、台帳に行が無い。** "
                    + "**`sid` も、そのとき初めて作られる**（`AddSidClaim` は発行の直前で呼ぶ）。");

                r.Done();
            }
        }

        #endregion

        #region 私的なヘルパ

        /// <summary>真偽値の広告を、小文字の綴りで引く</summary>
        /// <param name="res">JsonResponse</param>
        /// <param name="name">項目名</param>
        /// <returns>"true" / "false"（無ければ "なし"）</returns>
        /// <remarks>
        /// **`JsonResponse.String` は `JsonElement.ToString()` を返す**ので、
        /// **真偽値は "True" / "False"** になる（JSON の綴りではない）。
        /// </remarks>
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
                BackChannelLogoutTests.BoxPath + "?clear=true");

            Skip.If(res.Strings("logout_tokens") == null,
                "自己テストの受け口が閉じています（IsLockedDownTestEndpoints）。");

            r.Note("**受信箱を空にしてから測る**（前のケースの通知が混ざらないように）。");
        }

        /// <summary>届くまで待って、受信箱の中身を返す</summary>
        /// <param name="client">IdPClient</param>
        /// <param name="least">最低これだけ届くまで待つ</param>
        /// <returns>logout_token の一覧</returns>
        /// <remarks>
        /// **通知は背景で送られる**（**要求の経路では待たない**）ので、**応答の後に届く。**
        /// **待っても届かなければ、そのまま返す**（**件数で落ちる**）。
        /// </remarks>
        private static async Task<List<string>> WaitForTokensAsync(IdPClient client, int least)
        {
            List<string> tokens = new List<string>();

            for (int i = 0; i < BackChannelLogoutTests.WaitCount; i++)
            {
                JsonResponse res = await client.GetJsonAsync(BackChannelLogoutTests.BoxPath);
                string[] values = res.Strings("logout_tokens");

                tokens.Clear();

                if (values != null)
                {
                    tokens.AddRange(values);
                }

                if (least <= tokens.Count)
                {
                    return tokens;
                }

                await Task.Delay(300);
            }

            return tokens;
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

        /// <summary>events に backchannel-logout が在るか</summary>
        /// <param name="payload">logout_token の payload</param>
        /// <returns>在れば true</returns>
        /// <remarks>
        /// **値は空のオブジェクト**である（Back-Channel Logout 1.0 §2.4）。
        /// **キーが在ることだけを見る。**
        /// </remarks>
        private static bool HasLogoutEvent(JsonElement payload)
        {
            if (payload.ValueKind != JsonValueKind.Object)
            {
                return false;
            }

            if (!payload.TryGetProperty("events", out JsonElement events)
                || events.ValueKind != JsonValueKind.Object)
            {
                return false;
            }

            return events.TryGetProperty(
                BackChannelLogoutTests.BackChannelLogoutEvent, out JsonElement dummy);
        }

        #endregion
    }
}
