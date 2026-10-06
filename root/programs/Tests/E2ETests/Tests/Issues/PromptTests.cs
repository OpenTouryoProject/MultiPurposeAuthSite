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
//* クラス名        ：PromptTests
//* クラス日本語名  ：RT promptを空白区切りの集合として扱う（#272 の段階 1）
//*
//* 作成日時        ：－
//* 作成者          ：－
//* 更新履歴        ：－
//*
//*  日時        更新者            内容
//*  ----------  ----------------  -------------------------------------------------
//*  2026/10/06  玄人 幸道         新規（#272 の段階 1）
//*  2026/10/06  玄人 幸道         RT-272.8 / RT-272.9（prompt=login / select_account）を追加（#272）
//**********************************************************************************

using System.Collections.Generic;
using System.Net.Http;
using System.Threading.Tasks;

using MultiPurposeAuthSite.Tests.E2E.Infrastructure;

using Xunit;
using Xunit.Abstractions;

namespace MultiPurposeAuthSite.Tests.E2E.Tests.Issues
{
    /// <summary>
    /// RT-272. `prompt` を空白区切りの集合として扱う。
    /// </summary>
    /// <remarks>
    /// **`prompt` は空白区切りの集合**である（OIDC Core §3.1.2.1。**並びは意味を持たない**）。
    ///
    /// **以前は、同じ `/authorize` の中で照合規則が 2 つ混在していた。**
    ///
    /// | 書き方 | 問題 |
    /// |---|---|
    /// | `prompt.ToLower().Contains("none")` | **部分文字列**なので、**`prompt=nonexistent` でも true** |
    /// | `prompt.ToLower() == "none"` | **完全一致**なので、**`prompt=none login` で false** |
    ///
    /// その結果、**`prompt=none login` は「`login_required` の判定では none 扱い、
    /// 同意画面の判定では none でない」**という状態になっていた。
    ///
    /// **集合に揃えるだけでは、振る舞いが悪くなる。**
    /// 以前の `prompt=none login` は**同意画面を出していた**が、集合の判定に揃えると
    /// **同意を飛ばして code を発行する**ことになる。
    /// **仕様が `none` の併記をエラーとしている**ので（§3.1.2.1 :
    /// 「If this parameter contains none with any other value, an error is returned.」）、
    /// **そちらに合わせるのが、安全側でもある。**
    ///
    /// **段階 2（同意の永続化。D-6）は、この Issue の続き。**
    /// `prompt=login` / `consent` / `select_account` は、まだ処理していない。
    /// </remarks>
    public class PromptTests : TargetTestBase
    {
        /// <summary>コンストラクタ</summary>
        /// <param name="output">ITestOutputHelper</param>
        public PromptTests(ITestOutputHelper output) : base(output) { }

        /// <summary>認可リクエストのパラメタ</summary>
        /// <param name="reg">ClientRegistration</param>
        /// <param name="state">state</param>
        /// <param name="prompt">prompt（null なら付けない）</param>
        /// <returns>パラメタ</returns>
        private static Dictionary<string, string> Parameters(
            ClientRegistration reg, string state, string prompt)
        {
            Dictionary<string, string> form = new Dictionary<string, string>()
            {
                { "client_id", reg.ClientId },
                { "response_type", "code" },
                { "redirect_uri", reg.RedirectUri },
                { "scope", "openid email" },
                { "state", state },
                { "nonce", "nonce-" + state }
            };

            if (prompt != null)
            {
                form["prompt"] = prompt;
            }

            return form;
        }

        /// <summary>RT-272.1 prompt=none は他の値と併記できない</summary>
        /// <param name="targetKey">core / netfx</param>
        /// <returns>Task</returns>
        [SkippableTheory]
        [MemberData(nameof(AllTargets))]
        public async Task RT27201_promptのnoneは他の値と併記できない(string targetKey)
        {
            using (IdPClient client = await this.SignedInClientAsync(targetKey))
            {
                ClientRegistration reg = Flows.Registration(client, KnownClients.TestClient);

                TestReport r = this.Report("RT-272.1",
                    "prompt に none と他の値を併記したら、redirect_uri へ invalid_request を返す",
                    "**`prompt` は空白区切りの集合**（OIDC Core §3.1.2.1）。"
                    + "**`none` は他の値と併記できない**（仕様が「エラーを返す」としている）。"
                    + "**以前は照合が完全一致だった**ため、`prompt=none login` は "
                    + "**`none` と見なされないまま通っていた**（同意画面が出ていた）。"
                    + "**集合の判定に揃えるなら、ここをエラーにしないと"
                    + "「同意を飛ばして code を発行する」ことになる。**",
                    "OIDC Core §3.1.2.1 / #272 の段階 1");

                r.Target("client_name=" + KnownClients.TestClient + " / prompt=none login");

                r.Step("prompt に「none login」を指定して認可リクエストを送る");

                AuthZResponse authz = await client.AuthorizeAsync(
                    PromptTests.Parameters(reg, "state-rt2721", "none login"));

                r.Verify("エラー画面ではなく、リダイレクトで返る", authz.Redirected,
                    "リダイレクトする",
                    authz.Redirected ? authz.RedirectTo : "**リダイレクトしない**（" + authz.ToString() + "）");

                bool toRp = !string.IsNullOrEmpty(authz.Location)
                    && authz.Location.StartsWith(reg.RedirectUri);

                r.Verify("redirect_uri へ返る", toRp,
                    "登録した redirect_uri へ",
                    string.IsNullOrEmpty(authz.Location) ? "**移らない**" : authz.Location);

                r.VerifyEqual("エラーは invalid_request", "invalid_request", authz.Error ?? "（無し）");

                r.VerifyEqual("state が返る", "state-rt2721", authz.State ?? "（無し）");

                r.Verify("認可コードは発行されない", string.IsNullOrEmpty(authz.Code),
                    "code なし", string.IsNullOrEmpty(authz.Code) ? "なし" : "**発行された**");

                r.Note("**判定は `redirect_uri` を確かめた後**に置いてある"
                    + "（`ValidateAuthZReqParamCore`）。**でないとエラーを RP へ返せない**（#187）。");

                r.Done();
            }
        }

        /// <summary>RT-272.2 prompt=none だけなら従来どおり通る</summary>
        /// <param name="targetKey">core / netfx</param>
        /// <returns>Task</returns>
        [SkippableTheory]
        [MemberData(nameof(AllTargets))]
        public async Task RT27202_promptのnone単体は従来どおり通る(string targetKey)
        {
            using (IdPClient client = await this.SignedInClientAsync(targetKey))
            {
                ClientRegistration reg = Flows.Registration(client, KnownClients.TestClient);

                TestReport r = this.Report("RT-272.2",
                    "prompt=none だけなら、同意画面を出さずに認可コードを返す（従来どおり）",
                    "**集合の判定に替えても、単体の `none` の扱いは変えない。**"
                    + "**`prompt=none` で同意画面を飛ばすこと自体は、まだ直していない**"
                    + "（同意を記録していないので「以前に同意済みか」を判定できない。"
                    + "`ANALYSIS-IdP.md` の C-3 / D-6。**この Issue の段階 2**）。",
                    "OIDC Core §3.1.2.1 / #272 の段階 1");

                r.Target("client_name=" + KnownClients.TestClient + " / prompt=none");

                // **先に同意を記録する**（#272 の段階 2）。
                //   **記録が無ければ `consent_required`** になるので、
                //   **ここで測るのは「記録が在るときの `prompt=none`」**である。
                await Flows.EnsureConsentAsync(client, reg);

                r.Step("prompt=none を指定して認可リクエストを送る");

                AuthZResponse authz = await client.AuthorizeAsync(
                    PromptTests.Parameters(reg, "state-rt2722", "none"));

                r.Verify("認可コードが返る", !string.IsNullOrEmpty(authz.Code),
                    "code あり",
                    string.IsNullOrEmpty(authz.Code)
                        ? "**返らなかった**（error=" + (authz.Error ?? "なし") + "）" : "あり（値は伏せる）");

                r.VerifyEqual("state が返る", "state-rt2722", authz.State ?? "（無し）");

                r.Note("**`prompt=none` が同意画面を無条件に飛ばすのは、仕様どおりではない。**"
                    + "本来は「同意が必要なら `consent_required` を返す」。"
                    + "**段階 2 で同意を記録してから直す。**");

                r.Done();
            }
        }

        /// <summary>RT-272.3 none を含む別の語は none として扱わない</summary>
        /// <param name="targetKey">core / netfx</param>
        /// <returns>Task</returns>
        [SkippableTheory]
        [MemberData(nameof(AllTargets))]
        public async Task RT27203_noneを含む別の語はnoneとして扱わない(string targetKey)
        {
            using (IdPClient client = await this.SignedInClientAsync(targetKey))
            {
                // **TestClient_19 は、どのテストも同意を通していない**（#272 の段階 2）。
                //   **記録が在るクライアントでは、`none` 扱いかどうかを区別できない**
                //   （どちらでも同意画面を飛ばして code が返る）。
                ClientRegistration reg = Flows.InjectedRegistration(client, KnownClients.TestClient_19);

                TestReport r = this.Report("RT-272.3",
                    "prompt=nonexistent は none として扱わない（部分文字列で照合しない）",
                    "**以前は `Contains(\"none\")` で見ていた**ので、**`nonexistent` でも "
                    + "`none` と見なしていた**。"
                    + "**集合の要素として照合する**ようにしたので、一致しない。"
                    + "**既知でない値は、それ自身ではエラーにしない**"
                    + "（§3.1.2.1 は未知の値を `invalid_request` とはしていない）。",
                    "OIDC Core §3.1.2.1 / #272 の段階 1");

                r.Target("client_name=" + KnownClients.TestClient + " / prompt=nonexistent");

                r.Step("prompt=nonexistent を指定して認可リクエストを送る");

                AuthZResponse authz = await client.AuthorizeAsync(
                    PromptTests.Parameters(reg, "state-rt2723", "nonexistent"));

                r.Verify("invalid_request にはならない",
                    authz.Error != "invalid_request",
                    "invalid_request 以外",
                    authz.Error ?? "（エラー無し）");

                // **ここが歯。**
                //   **`none` 扱いになると同意画面を飛ばして code を返す**ので、
                //   **「同意画面で止まるか」で区別できる。**
                //   「invalid_request にならない」だけでは、旧挙動でも通ってしまう。
                r.Verify("同意画面で止まる（＝ none 扱いになっていない）",
                    authz.NeedsConsent,
                    "同意画面が返る",
                    authz.NeedsConsent ? "返った"
                        : "**返らなかった**（" + authz.ToString() + "）");

                r.Verify("認可コードは発行されない", string.IsNullOrEmpty(authz.Code),
                    "code なし", string.IsNullOrEmpty(authz.Code) ? "なし" : "**発行された**");

                r.Note("**`none` を含む語でも併記のエラーにならないこと**を見ている"
                    + "（`nonexistent` は `none` ではないので、単独の未知の値として扱う）。"
                    + "**`prompt=nonexistent none` なら併記のエラーになる。**");

                r.Done();
            }
        }
        /// <summary>RT-272.4 同意の記録が無ければ prompt=none は consent_required</summary>
        /// <param name="targetKey">core / netfx</param>
        /// <returns>Task</returns>
        [SkippableTheory]
        [MemberData(nameof(AllTargets))]
        public async Task RT27204_同意の記録が無ければpromptのnoneはconsent_required(string targetKey)
        {
            using (IdPClient client = await this.SignedInClientAsync(targetKey))
            {
                TestReport r = this.Report("RT-272.4",
                    "同意の記録が無いまま prompt=none で来たら、redirect_uri へ consent_required を返す",
                    "**これが C-3 そのものである。** 以前は**同意の記録を持っていなかった**ため、"
                    + "`prompt=none` は**同意画面を出さずに code を発行**していた。"
                    + "**セッションさえ生きていれば、どのクライアントも無音で認可を取得できた。**"
                    + "いまは**記録が無ければ UI が必要**と判断し、"
                    + "**UI を出せない指定なのでエラーを返す**（OIDC Core §3.1.2.6）。",
                    "OIDC Core §3.1.2.1 / §3.1.2.6（consent_required）/ #272 の段階 2 / C-3 / D-6");

                // **TestClient_19 は、どのテストも同意を通していない**（#272 の段階 2）。
                ClientRegistration reg = Flows.InjectedRegistration(client, KnownClients.TestClient_19);

                r.Target("client_name=" + KnownClients.TestClient_19 + "（同意の記録が無い）/ prompt=none");
                r.Step("prompt=none を指定して認可リクエストを送る");

                AuthZResponse authz = await client.AuthorizeAsync(
                    PromptTests.Parameters(reg, "state-rt2724", "none"));

                r.Verify("エラー画面ではなく、リダイレクトで返る", authz.Redirected,
                    "リダイレクトする",
                    authz.Redirected ? authz.RedirectTo : "**リダイレクトしない**（" + authz.ToString() + "）");

                bool toRp = !string.IsNullOrEmpty(authz.Location)
                    && authz.Location.StartsWith(reg.RedirectUri);

                r.Verify("redirect_uri へ返る", toRp,
                    "登録した redirect_uri へ",
                    string.IsNullOrEmpty(authz.Location) ? "**移らない**" : authz.Location);

                r.VerifyEqual("エラーは consent_required", "consent_required", authz.Error ?? "（無し）");

                r.VerifyEqual("state が返る", "state-rt2724", authz.State ?? "（無し）");

                r.Verify("認可コードは発行されない", string.IsNullOrEmpty(authz.Code),
                    "code なし", string.IsNullOrEmpty(authz.Code) ? "なし" : "**発行された**");

                r.Note("**このテストは「許可」を押さない。** 押すと記録が残り、"
                    + "**DB ストアでは 2 回目の実行から測れなくなる**（`TestClients` の表に注記してある）。");

                r.Done();
            }
        }

        /// <summary>RT-272.5 prompt=consent は記録が在っても同意画面を出す</summary>
        /// <param name="targetKey">core / netfx</param>
        /// <returns>Task</returns>
        [SkippableTheory]
        [MemberData(nameof(AllTargets))]
        public async Task RT27205_promptのconsentは記録が在っても同意画面を出す(string targetKey)
        {
            using (IdPClient client = await this.SignedInClientAsync(targetKey))
            {
                ClientRegistration reg = Flows.Registration(client, KnownClients.TestClient);

                TestReport r = this.Report("RT-272.5",
                    "prompt=consent は、同意済みでも同意画面を出す",
                    "**同意を記録すると「2 回目からは出ない」**ことになるが、"
                    + "**利用者が確かめ直したいときの口が要る。**"
                    + "§3.1.2.1 は `prompt=consent` を「同意を取り直せ」と定めている。",
                    "OIDC Core §3.1.2.1 / #272 の段階 2");

                r.Target("client_name=" + KnownClients.TestClient + " / prompt=consent");
                r.Step("(1) まず同意を記録する（記録が在る状態を作る）");

                await Flows.EnsureConsentAsync(client, reg);

                r.Step("(2) prompt を付けずに送ると、同意画面は出ない（記録が効いている）");

                AuthZResponse without = await client.AuthorizeAsync(
                    PromptTests.Parameters(reg, "state-rt2725a", null));

                r.Verify("同意画面は出ない", !without.NeedsConsent,
                    "出ない", without.NeedsConsent ? "**出た**" : "出なかった（code あり）");

                r.Step("(3) prompt=consent を付けると、同意画面が出る");

                AuthZResponse with = await client.AuthorizeAsync(
                    PromptTests.Parameters(reg, "state-rt2725b", "consent"));

                r.Verify("同意画面が出る", with.NeedsConsent,
                    "同意画面が返る",
                    with.NeedsConsent ? "返った" : "**返らなかった**（" + with.ToString() + "）");

                r.Note("**`prompt=none consent` は段階 1 で `invalid_request`** になる"
                    + "（`none` の併記）。**矛盾する指定は、そこで弾いている。**");

                r.Done();
            }
        }

        /// <summary>RT-272.6 同意画面で拒否すると access_denied</summary>
        /// <param name="targetKey">core / netfx</param>
        /// <returns>Task</returns>
        [SkippableTheory]
        [MemberData(nameof(AllTargets))]
        public async Task RT27206_同意画面で拒否するとaccess_denied(string targetKey)
        {
            using (IdPClient client = await this.SignedInClientAsync(targetKey))
            {
                ClientRegistration reg = Flows.Registration(client, KnownClients.TestClient);

                TestReport r = this.Report("RT-272.6",
                    "同意画面で「拒否」を押すと、redirect_uri へ access_denied を返す",
                    "**以前は認可画面に Deny ボタンが無く、利用者は拒否できなかった**"
                    + "（`ANALYSIS-IdP.md` の E-6）。**`access_denied` を返す経路も無かった。**"
                    + "**同意を記録するなら、拒否もできなければ筋が通らない。**",
                    "RFC 6749 §4.1.2.1（access_denied）/ E-6 / #272 の段階 2");

                r.Target("client_name=" + KnownClients.TestClient + " / prompt=consent で同意画面を出す");
                r.Step("(1) prompt=consent で同意画面を出す");

                AuthZResponse authz = await client.AuthorizeAsync(
                    PromptTests.Parameters(reg, "state-rt2726", "consent"));

                r.Verify("同意画面が出る", authz.NeedsConsent,
                    "同意画面が返る",
                    authz.NeedsConsent ? "返った" : "**返らなかった**（" + authz.ToString() + "）");

                Skip.If(!authz.NeedsConsent, "同意画面が出ないので、拒否を押せません。");

                r.Step("(2) 「拒否」を押す");

                AuthZResponse denied = await client.DenyConsentAsync(authz);

                r.Verify("リダイレクトで返る", denied.Redirected,
                    "リダイレクトする",
                    denied.Redirected ? denied.RedirectTo : "**リダイレクトしない**（" + denied.ToString() + "）");

                r.VerifyEqual("エラーは access_denied", "access_denied", denied.Error ?? "（無し）");

                r.Verify("認可コードは発行されない", string.IsNullOrEmpty(denied.Code),
                    "code なし", string.IsNullOrEmpty(denied.Code) ? "なし" : "**発行された**");

                r.Note("**拒否は記録しない。** 「拒否した」を覚えて次回以降自動で断ると、"
                    + "**利用者が気を変えられなくなる。**");

                r.Done();
            }
        }
        /// <summary>RT-272.7 管理画面から同意を取り消すと、prompt=none が通らなくなる</summary>
        /// <param name="targetKey">core / netfx</param>
        /// <returns>Task</returns>
        [SkippableTheory]
        [MemberData(nameof(AllTargets))]
        public async Task RT27207_管理画面から同意を取り消せる(string targetKey)
        {
            using (IdPClient client = await this.SignedInClientAsync(targetKey))
            {
                TestReport r = this.Report("RT-272.7",
                    "管理画面から同意を取り消すと、次の prompt=none が consent_required になる",
                    "**記録するなら、取り消せなければならない。**"
                    + "取り消さないと**記録が増えるだけ**になり、"
                    + "**利用者が「どのアプリに何を許したか」を解除できない。**"
                    + "**取り消しても、発行済みのトークンは失効しない**"
                    + "（そちらは `/revoke`（RFC 7009）の役目）。"
                    + "**効果は「次の認可で同意画面が出る」こと**である。",
                    "OIDC Core §3.1.2.6 / #272 の段階 2 / D-6");

                // **TestClient_20 は、この測定のためだけに在る**（取り消しが他のテストに響かないように）。
                ClientRegistration reg = Flows.InjectedRegistration(client, KnownClients.TestClient_20);

                r.Target("client_name=" + KnownClients.TestClient_20);
                r.Step("(1) 同意を記録する");

                await Flows.EnsureConsentAsync(client, reg);

                AuthZResponse before = await client.AuthorizeAsync(
                    PromptTests.Parameters(reg, "state-rt2727a", "none"));

                r.Verify("prompt=none で認可コードが返る（記録が効いている）",
                    !string.IsNullOrEmpty(before.Code),
                    "code あり",
                    string.IsNullOrEmpty(before.Code)
                        ? "**返らなかった**（error=" + (before.Error ?? "なし") + "）" : "あり（値は伏せる）");

                r.Step("(2) 管理画面の一覧に、このクライアントが出る");

                string list = null;
                int manageStatus = 0;

                HttpResponseMessage page = await client.GetAsync("/Manage/ConsentGrants");
                manageStatus = (int)page.StatusCode;

                if (page.IsSuccessStatusCode)
                {
                    list = await page.Content.ReadAsStringAsync();
                }

                r.Verify("一覧に client_name が出る",
                    list != null && list.Contains(KnownClients.TestClient_20),
                    "出る",
                    list == null
                        ? "**画面が出ない**（HTTP " + manageStatus + "）"
                        : (list.Contains(KnownClients.TestClient_20)
                            ? "出た" : "**一覧に無い**"));

                r.Step("(3) 管理画面から取り消す");

                bool revoked = await client.RevokeConsentAsync(reg.ClientId);

                r.Verify("取り消しが受け付けられる", revoked,
                    "受け付けられる", revoked ? "受け付けられた" : "**失敗した**");

                r.Step("(4) 取り消した後の prompt=none は consent_required");

                AuthZResponse after = await client.AuthorizeAsync(
                    PromptTests.Parameters(reg, "state-rt2727b", "none"));

                r.VerifyEqual("エラーは consent_required", "consent_required", after.Error ?? "（無し）");

                r.Verify("認可コードは発行されない", string.IsNullOrEmpty(after.Code),
                    "code なし", string.IsNullOrEmpty(after.Code) ? "なし" : "**発行された**");

                r.Note("**このテストは、終わった時点で記録を残さない。**"
                    + "**DB ストアでも 2 回目以降の実行で同じ結果になる。**");

                r.Done();
            }
        }
        /// <summary>RT-272.8 prompt=login は再認証を求める</summary>
        /// <param name="targetKey">core / netfx</param>
        /// <returns>Task</returns>
        [SkippableTheory]
        [MemberData(nameof(AllTargets))]
        public async Task RT27208_promptのloginは再認証を求める(string targetKey)
        {
            using (IdPClient client = await this.SignedInClientAsync(targetKey))
            {
                ClientRegistration reg = Flows.Registration(client, KnownClients.TestClient);

                TestReport r = this.Report("RT-272.8",
                    "prompt=login は、サインイン済みでも再認証を求める",
                    "**`prompt=login` は「利用者を認証し直せ」という指定**（OIDC Core §3.1.2.1）。"
                    + "**以前は未処理で、無視していた**（`ANALYSIS-IdP.md` の C-3）。"
                    + "**`max_age` の再認証と同じ経路**を使う — 印を残してサインアウトし、同じ URL に戻す。"
                    + "**印（`re_auth_at`）が無いと、戻ってきた要求にも `prompt=login` が付いているので"
                    + "永久に送り返すことになる。**",
                    "OIDC Core §3.1.2.1 / #272 の段階 2");

                // **同意を記録しておく。** prompt を付けなければ飛ぶ状態にしてから測る。
                await Flows.EnsureConsentAsync(client, reg);

                r.Target("client_name=" + KnownClients.TestClient + " / prompt=login");
                r.Step("(1) prompt=login を付けて認可リクエストを送る");

                AuthZResponse authz = await client.AuthorizeAsync(
                    PromptTests.Parameters(reg, "state-rt2728", "login"));

                r.Verify("認可コードは発行されない", string.IsNullOrEmpty(authz.Code),
                    "code なし", string.IsNullOrEmpty(authz.Code) ? "なし" : "**発行された**");

                r.Verify("同じ URL へ戻される（再認証の経路）",
                    !string.IsNullOrEmpty(authz.Location)
                        && authz.Location.Contains("/authorize"),
                    "/authorize へ戻る",
                    string.IsNullOrEmpty(authz.Location)
                        ? "**移らない**（" + authz.ToString() + "）" : authz.Location);

                Skip.If(string.IsNullOrEmpty(authz.Location), "戻り先が無いので、先に進めません。");

                r.Step("(2) 戻された先は、サインイン画面（サインアウトされている）");

                HttpResponseMessage again = await client.GetAsync(authz.Location);

                string toLogin = (again.Headers.Location == null)
                    ? "" : again.Headers.Location.ToString();

                r.Verify("サインイン画面へ送られる", toLogin.Contains("/Account/Login"),
                    "/Account/Login へ",
                    string.IsNullOrEmpty(toLogin)
                        ? "**移らない**（HTTP " + ((int)again.StatusCode) + "）" : toLogin);

                r.Step("(3) 再認証すると先へ進む（繰り返しにならない）");

                // **force が要る。** サーバ側はサインアウトしているが、
                //   **IdPClient は 「サインイン済み」の印を持っている**ので、
                //   **force 無しでは素通りする**（実測で踏んだ）。
                await client.SignInAsync(force: true);

                AuthZResponse after = await client.AuthorizeAsync(
                    PromptTests.Parameters(reg, "state-rt2728b", "login"));

                r.Verify("認可コードが返る（印が効いている）",
                    !string.IsNullOrEmpty(after.Code),
                    "code あり",
                    string.IsNullOrEmpty(after.Code)
                        ? "**返らなかった**（" + after.ToString() + "）" : "あり（値は伏せる）");

                r.Note("**印が無いと、ここで永久に送り返す。** `max_age=0` でも同じことが起きるので、"
                    + "**#247 で入れた印（`re_auth_at`）をそのまま使っている。**");

                r.Note("**`prompt=none login` は段階 1 で `invalid_request`** になる（`none` の併記）。"
                    + "**「UI を出せないのに再認証」にはならない。**");

                r.Done();
            }
        }

        /// <summary>RT-272.9 prompt=select_account は同意画面を出す</summary>
        /// <param name="targetKey">core / netfx</param>
        /// <returns>Task</returns>
        [SkippableTheory]
        [MemberData(nameof(AllTargets))]
        public async Task RT27209_promptのselect_accountは同意画面を出す(string targetKey)
        {
            using (IdPClient client = await this.SignedInClientAsync(targetKey))
            {
                ClientRegistration reg = Flows.Registration(client, KnownClients.TestClient);

                TestReport r = this.Report("RT-272.9",
                    "prompt=select_account は、同意済みでも同意画面を出す（アカウントを選べる画面へ）",
                    "**`prompt=select_account` は「アカウントを選ばせろ」という指定**（OIDC Core §3.1.2.1）。"
                    + "**以前は未処理で、無視していた**。"
                    + "**この実装はアカウントの一覧から選ぶ仕組みを持っていない**ので、"
                    + "**同意画面を出す**ところまでである"
                    + "（その画面に「別のアカウントでログイン」が在り、そこから切り替えられる）。",
                    "OIDC Core §3.1.2.1 / #272 の段階 2");

                await Flows.EnsureConsentAsync(client, reg);

                r.Target("client_name=" + KnownClients.TestClient + " / prompt=select_account");
                r.Step("(1) prompt を付けなければ、同意画面は出ない（記録が効いている）");

                AuthZResponse without = await client.AuthorizeAsync(
                    PromptTests.Parameters(reg, "state-rt2729a", null));

                r.Verify("同意画面は出ない", !without.NeedsConsent,
                    "出ない", without.NeedsConsent ? "**出た**" : "出なかった（code あり）");

                r.Step("(2) prompt=select_account を付けると、同意画面が出る");

                AuthZResponse with = await client.AuthorizeAsync(
                    PromptTests.Parameters(reg, "state-rt2729b", "select_account"));

                r.Verify("同意画面が出る", with.NeedsConsent,
                    "同意画面が返る",
                    with.NeedsConsent ? "返った" : "**返らなかった**（" + with.ToString() + "）");

                r.Step("(3) その画面から、別のアカウントへ切り替えられる");

                r.Verify("「別のアカウントでログイン」が在る",
                    with.NeedsConsent && !string.IsNullOrEmpty(with.Body)
                        && with.Body.Contains("submit.Login"),
                    "submit.Login が在る",
                    (with.NeedsConsent && !string.IsNullOrEmpty(with.Body)
                        && with.Body.Contains("submit.Login")) ? "在る" : "**無い**");

                r.Note("**アカウントの一覧から選ぶ仕組みは持っていない。** "
                    + "仕様（§3.1.2.1）は「選ばせろ」だが、**この実装は 1 利用者ずつのサインインしか持たない**。"
                    + "**`account_selection_required` を返す道もあった**が、"
                    + "**切り替えの口が画面に在るので、画面を出す方を選んだ。**");

                r.Done();
            }
        }
    }
}
