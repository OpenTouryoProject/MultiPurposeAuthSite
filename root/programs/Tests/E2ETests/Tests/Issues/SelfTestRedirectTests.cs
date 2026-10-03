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
//* クラス名        ：SelfTestRedirectTests
//* クラス日本語名  ：RT-C10 自己テスト用の折り返し先も、登録と突き合わせる
//*
//* 作成日時        ：－
//* 作成者          ：－
//* 更新履歴        ：－
//*
//*  日時        更新者            内容
//*  ----------  ----------------  -------------------------------------------------
//*  2026/10/04  玄人 幸道         新規（C-10）
//**********************************************************************************

using System.Threading.Tasks;

using MultiPurposeAuthSite.Tests.E2E.Infrastructure;

using Xunit;
using Xunit.Abstractions;

namespace MultiPurposeAuthSite.Tests.E2E.Tests.Issues
{
    /// <summary>
    /// RT-C10 管理画面の自己テストの折り返し先も、登録と突き合わせる（`ANALYSIS-IdP.md` の C-10）。
    /// </summary>
    /// <remarks>
    /// **`CheckRedirectUri` に、登録を確かめずに通す分岐が在った。**
    /// 管理画面の「トークンを取る」（`GetOAuth2Token`）の折り返し先と完全一致する `redirect_uri` は、
    /// **その client_id にその URI が登録されているかを見ずに通っていた。**
    /// **`IsLockedDownTestEndpoints` の対象外**なので、**本番配備でも閉じられなかった。**
    ///
    /// **直し方** : `test_self_code_manage` を記号として足し、
    /// **登録値として表せる**ようにして、**分岐を消した**（例外は無くなった）。
    ///
    /// | | |
    /// |---|---|
    /// | 消えたもの | 「この URL なら登録を確かめずに通す」分岐（`CmnEndpoints.CheckRedirectUri`） |
    /// | 足したもの | `Const.TestSelfCodeManage`（`GetRedirectUriFromConstr` が解決する） |
    /// | 画面 | 新規登録の `redirect_uri_code` の既定を、この記号にした |
    ///
    /// **識別子が `RT-C10` なのは、公開の Issue を持たない項目のため**である
    /// （`TESTING.md` 5 節。`ANALYSIS-IdP.md` の番号で辿る）。
    /// </remarks>
    public class SelfTestRedirectTests : TargetTestBase
    {
        /// <summary>コンストラクタ</summary>
        /// <param name="output">ITestOutputHelper</param>
        public SelfTestRedirectTests(ITestOutputHelper output) : base(output) { }

        /// <summary>RT-C10.1 自己テスト用の折り返し先も、登録と突き合わせる</summary>
        /// <param name="targetKey">core / netfx</param>
        /// <returns>Task</returns>
        [SkippableTheory]
        [MemberData(nameof(AllTargets))]
        public async Task RTC1001_自己テスト用の折り返し先も登録と突き合わせる(string targetKey)
        {
            using (IdPClient client = await this.SignedInClientAsync(targetKey))
            {
                TestReport r = this.Report("RT-C10.1",
                    "管理画面の自己テストの折り返し先は、登録されているクライアントでだけ使える",
                    "**`CheckRedirectUri` に、登録を確かめずに通す分岐が在った。**"
                    + "管理画面の「トークンを取る」の折り返し先と完全一致する `redirect_uri` は、"
                    + "**その client_id にその URI が登録されているかを見ずに通っていた。**"
                    + "**`IsLockedDownTestEndpoints` の対象外**なので、**本番でも閉じられなかった。**"
                    + "**`test_self_code_manage` を記号にして登録値で表せるようにし、分岐を消した。**"
                    + "**登録どおりの照合だけになり、例外は無くなった。**",
                    "RFC 6749 §3.1.2.3 / ANALYSIS-IdP.md の C-10");

                // **登録した側**（種データが作る。#264）。この値が registration.RedirectUri になる。
                ClientRegistration registered =
                    Flows.InjectedRegistration(client, KnownClients.TestClient_15);

                // **登録していない側**（構成ファイルの登録は test_self_code）。
                ClientRegistration notRegistered =
                    Flows.Registration(client, KnownClients.TestClient);

                string manageUri = registered.RedirectUri;

                r.Target("redirect_uri=" + manageUri
                    + "（管理画面の自己テストの折り返し先。`test_self_code_manage` が解決した値）");

                r.Verify("記号が解決できている（管理画面の口を指している）",
                    !string.IsNullOrEmpty(manageUri)
                        && manageUri != "test_self_code_manage"
                        && manageUri != notRegistered.RedirectUri,
                    "解決できている",
                    string.IsNullOrEmpty(manageUri) ? "**空**"
                        : (manageUri == "test_self_code_manage" ? "**記号のまま**"
                        : (manageUri == notRegistered.RedirectUri
                            ? "**test_self_code と同じ値**" : "解決できている")));

                Assert.NotEqual(notRegistered.RedirectUri, manageUri);

                r.Step("(1) 登録していないクライアントが、この折り返し先を指定する");

                AuthZResponse other = await Flows.AuthorizeCodeAsync(
                    client, notRegistered, redirectUri: manageUri, state: "state-rtc1001a");

                r.Observe("応答", other.ToString(),
                    "**redirect_uri が照合できないときは、その URI へエラーも返さない**"
                    + "（RFC 6749 §4.1.2.1。`TC-1.3` と同じ扱い）。");

                r.Verify("認可コードを発行しない", string.IsNullOrEmpty(other.Code),
                    "発行しない",
                    string.IsNullOrEmpty(other.Code) ? "発行しない" : "**発行した**");

                r.Verify("その URI へリダイレクトしない",
                    !(other.Redirected && (other.Location ?? "").StartsWith(manageUri)),
                    "送らない",
                    (other.Redirected && (other.Location ?? "").StartsWith(manageUri))
                        ? "**送ってしまった**" : "送らない");

                r.Step("(2) 登録しているクライアントが、同じ折り返し先を指定する");

                AuthZResponse mine = await Flows.AuthorizeCodeAsync(
                    client, registered, redirectUri: manageUri, state: "state-rtc1001b");

                r.Observe("応答", mine.ToString(),
                    "**登録値として表せるようにしたので、通常の照合で通る**（分岐は要らない）。");

                r.Verify("認可コードを発行する", !string.IsNullOrEmpty(mine.Code),
                    "発行する",
                    string.IsNullOrEmpty(mine.Code) ? "**発行しない**" : "発行する");

                r.Note("**(1) が、消した分岐そのものである。**"
                    + "分岐が在った間は、**登録済みのどのクライアントでもこの URI を宛先にできた。**");

                r.Note("**(2) は、消したことで機能が壊れていないことを見ている。**"
                    + "**管理画面の「トークンを取る」は、この記号を登録しておく必要がある**（新規登録の既定）。"
                    + "**動作確認の後は、自分の RP の折り返し先に書き換える。**");

                r.Done();
            }
        }
    }
}
