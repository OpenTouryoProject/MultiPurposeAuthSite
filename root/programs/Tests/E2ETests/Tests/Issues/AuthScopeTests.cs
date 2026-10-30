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
//* クラス名        ：AuthScopeTests
//* クラス日本語名  ：RT auth で同意画面を飛ばせるのは、登録に明記したクライアントだけ（#294）
//*
//* 作成日時        ：－
//* 作成者          ：－
//* 更新履歴        ：－
//*
//*  日時        更新者            内容
//*  ----------  ----------------  -------------------------------------------------
//*  2026/10/25  玄人 幸道         新規（#294）
//**********************************************************************************

using System.Collections.Generic;
using System.Threading.Tasks;

using MultiPurposeAuthSite.Tests.E2E.Infrastructure;

using Xunit;
using Xunit.Abstractions;

namespace MultiPurposeAuthSite.Tests.E2E.Tests.Issues
{
    /// <summary>
    /// RT-294. `auth` で同意画面を飛ばせるのは、登録に明記したクライアントだけ。
    /// </summary>
    /// <remarks>
    /// **`auth` は MPAS 独自の scope**で、**付けると同意画面を出さない**（認証だけに使う）。
    ///
    /// **以前は、要求に付けるだけで効いた。**
    /// **同意を求めるかを、要求する側（クライアント）が決めていた**ことになる。
    /// **いまは `client_registration` と同じく、登録に明記したクライアントにしか出さない**
    /// （Keycloak の「Consent Required」と同じ考え方。**決めるのは登録を管理する人**）。
    ///
    /// | クライアント | `scope=openid auth` ＋ `prompt=none` |
    /// |---|---|
    /// | `TestClient_29`（登録に `auth` を明記） | **同意画面を飛ばして code を返す** |
    /// | `TestClient_19`（登録に `scope` が無い） | **`consent_required`**（同意の記録も無い） |
    ///
    /// **どちらのクライアントにも、「許可」を押さない。**
    /// 押すと同意が記録され、**`auth` が効かなくても飛ばせてしまう**（DB ストアでは次の実行にも残る）。
    /// </remarks>
    public class AuthScopeTests : TargetTestBase
    {
        /// <summary>コンストラクタ</summary>
        /// <param name="output">ITestOutputHelper</param>
        public AuthScopeTests(ITestOutputHelper output) : base(output) { }

        /// <summary>認可リクエストのパラメタ（prompt=none）</summary>
        /// <param name="reg">ClientRegistration</param>
        /// <param name="state">state</param>
        /// <param name="scope">scope</param>
        /// <returns>パラメタ</returns>
        private static Dictionary<string, string> Parameters(
            ClientRegistration reg, string state, string scope)
        {
            return new Dictionary<string, string>()
            {
                { "client_id", reg.ClientId },
                { "response_type", "code" },
                { "redirect_uri", reg.RedirectUri },
                { "scope", scope },
                { "state", state },
                { "nonce", "nonce-" + state },
                // **UI を出せない指定にする。** 同意画面を飛ばしたかどうかが、code か consent_required かで分かる。
                { "prompt", "none" }
            };
        }

        /// <summary>RT-294.1 登録に auth が無ければ、同意画面を飛ばさない</summary>
        /// <param name="targetKey">core / netfx</param>
        /// <returns>Task</returns>
        [SkippableTheory]
        [MemberData(nameof(AllTargets))]
        public async Task RT29401_登録にauthが無ければ同意画面を飛ばさない(string targetKey)
        {
            using (IdPClient client = await this.SignedInClientAsync(targetKey))
            {
                TestReport r = this.Report("RT-294.1",
                    "登録に auth を明記していないクライアントは、scope=auth を付けても同意画面を飛ばせない",
                    "**以前は、要求に `auth` を付けるだけで同意画面を飛ばせた**"
                    + "（`AccountController.OAuth2Authorize` が、要求された scope をそのまま見ていた）。"
                    + "**同意を求めるかを、クライアントが決めていた**ことになる。"
                    + "**いまは、登録に明記したクライアントの要求だけを数える。**",
                    "OIDC Core §3.1.2.4 / §3.1.2.6（consent_required）/ #294");

                // **TestClient_19 は、どのテストも同意を通していない**（#272 の段階 2）。
                //   **登録に scope も無い**（＝ `auth` を明記していない）。
                ClientRegistration reg = Flows.InjectedRegistration(client, KnownClients.TestClient_19);

                r.Target("client_name=" + KnownClients.TestClient_19
                    + "（登録に auth が無い・同意の記録が無い）/ scope=openid auth / prompt=none");
                r.Step("scope=openid auth、prompt=none を指定して認可リクエストを送る");

                AuthZResponse authz = await client.AuthorizeAsync(
                    AuthScopeTests.Parameters(reg, "state-rtauth1", "openid auth"));

                // **ここが歯。** 以前は `auth` で同意画面を飛ばし、code を返していた。
                r.VerifyEqual("エラーは consent_required", "consent_required", authz.Error ?? "（無し）");

                r.Verify("認可コードは発行されない", string.IsNullOrEmpty(authz.Code),
                    "code なし", string.IsNullOrEmpty(authz.Code) ? "なし" : "**発行された**");

                r.Note("**このテストは「許可」を押さない。** 押すと記録が残り、"
                    + "**DB ストアでは 2 回目の実行から測れなくなる**（`TestClients` の表に注記してある）。");

                r.Done();
            }
        }

        /// <summary>RT-294.2 登録に auth を明記したクライアントは、同意画面を飛ばす</summary>
        /// <param name="targetKey">core / netfx</param>
        /// <returns>Task</returns>
        [SkippableTheory]
        [MemberData(nameof(AllTargets))]
        public async Task RT29402_登録にauthを明記すれば同意画面を飛ばす(string targetKey)
        {
            using (IdPClient client = await this.SignedInClientAsync(targetKey))
            {
                TestReport r = this.Report("RT-294.2",
                    "登録に auth を明記したクライアントは、同意画面を出さずに code を返し、scope を auth と openid に絞る",
                    "**`auth` の働きそのものは残す**（認証だけをしたいクライアント向け）。"
                    + "**登録で絞った結果、明記したクライアントで効かなくなっていない**ことを確かめる。"
                    + "**属性は渡さない**ので、`email` を一緒に要求しても発行されない（`FilterClaimAtAuth`）。",
                    "OIDC Core §3.1.2.4 / #294");

                // **TestClient_29 は、登録の scope に `openid auth` を明記してある**（#294）。
                //   **同意の記録は無い**（どのテストも「許可」を押さない）。
                ClientRegistration reg = Flows.InjectedRegistration(client, KnownClients.TestClient_29);

                r.Target("client_name=" + KnownClients.TestClient_29
                    + "（登録に auth を明記・同意の記録が無い）/ scope=openid auth email / prompt=none");
                r.Step("(1) scope=openid auth email、prompt=none を指定して認可リクエストを送る");

                AuthZResponse authz = await client.AuthorizeAsync(
                    AuthScopeTests.Parameters(reg, "state-rtauth2", "openid auth email"));

                r.Verify("認可コードが返る（同意画面を飛ばした）", !string.IsNullOrEmpty(authz.Code),
                    "code あり",
                    string.IsNullOrEmpty(authz.Code)
                        ? "**返らなかった**（error=" + (authz.Error ?? "なし") + "）" : "あり（値は伏せる）");

                Assert.False(string.IsNullOrEmpty(authz.Code),
                    "前提: 認可コードが返ること（" + authz.ToString() + "）");

                r.Step("(2) code をトークンに交換し、発行された scope を見る");

                JsonResponse token = await Flows.ExchangeCodeAsync(client, reg, authz.Code, reg.RedirectUri);

                Assert.False(string.IsNullOrEmpty(token.AccessToken),
                    "前提: トークンが発行されること（" + token.ToString() + "）");

                List<string> granted = Jwt.Strings(Jwt.Payload(token.AccessToken), "scopes");

                r.Verify("auth が発行される", granted.Contains("auth"),
                    "auth を含む", "発行 = [" + string.Join(", ", granted) + "]");

                r.Verify("email は発行されない（属性を渡さない）", !granted.Contains("email"),
                    "email を含まない", "発行 = [" + string.Join(", ", granted) + "]");

                r.Done();
            }
        }

        /// <summary>RT-294.3 auth は大文字小文字を区別する</summary>
        /// <param name="targetKey">core / netfx</param>
        /// <returns>Task</returns>
        [SkippableTheory]
        [MemberData(nameof(AllTargets))]
        public async Task RT29403_authは大文字小文字を区別する(string targetKey)
        {
            using (IdPClient client = await this.SignedInClientAsync(targetKey))
            {
                TestReport r = this.Report("RT-294.3",
                    "scope=AUTH は auth として扱わない（登録に auth を明記したクライアントでも、同意画面を飛ばさない）",
                    "**以前は小文字にしてから比べていた**ので、`AUTH` でも同意画面を飛ばした。"
                    + "**scope の値は case-sensitive**（RFC 6749 §3.3）。"
                    + "**`AUTH` は、この配備が扱わない別の scope** である。",
                    "RFC 6749 §3.3 / #294");

                ClientRegistration reg = Flows.InjectedRegistration(client, KnownClients.TestClient_29);

                r.Target("client_name=" + KnownClients.TestClient_29
                    + "（登録に auth を明記・同意の記録が無い）/ scope=openid AUTH / prompt=none");
                r.Step("scope=openid AUTH、prompt=none を指定して認可リクエストを送る");

                AuthZResponse authz = await client.AuthorizeAsync(
                    AuthScopeTests.Parameters(reg, "state-rtauth3", "openid AUTH"));

                r.VerifyEqual("エラーは consent_required", "consent_required", authz.Error ?? "（無し）");

                r.Verify("認可コードは発行されない", string.IsNullOrEmpty(authz.Code),
                    "code なし", string.IsNullOrEmpty(authz.Code) ? "なし" : "**発行された**");

                r.Done();
            }
        }
    }
}
