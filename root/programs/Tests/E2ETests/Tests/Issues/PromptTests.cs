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
//**********************************************************************************

using System.Collections.Generic;
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
                ClientRegistration reg = Flows.Registration(client, KnownClients.TestClient);

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
    }
}
