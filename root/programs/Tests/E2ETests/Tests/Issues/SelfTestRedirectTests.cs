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
//*  2026/10/09  玄人 幸道         記号（test_self_code_manage）を使わない形に建て直した
//**********************************************************************************

using System.Threading.Tasks;

using MultiPurposeAuthSite.Tests.E2E.Infrastructure;

using Xunit;
using Xunit.Abstractions;

namespace MultiPurposeAuthSite.Tests.E2E.Tests.Issues
{
    /// <summary>
    /// RT-C10 `redirect_uri` の照合に例外は無い（`ANALYSIS-IdP.md` の C-10）。
    /// </summary>
    /// <remarks>
    /// **`CheckRedirectUri` に、登録を確かめずに通す分岐が在った。**
    /// 管理画面の「トークンを取る」（`GetOAuth2Token`）の折り返し先と完全一致する `redirect_uri` は、
    /// **その client_id にその URI が登録されているかを見ずに通っていた。**
    /// **`IsLockedDownTestEndpoints` の対象外**なので、**本番配備でも閉じられなかった。**
    ///
    /// **直し方** : **分岐を消した**（例外は無くなった）。
    ///
    /// **その後、管理画面の「トークンを取る」自体が廃止された**ので、
    /// **記号（`test_self_code_manage`）も落とした。**
    /// **測る中身は変えていない。** **「他のクライアントに登録されている URI は、使えない」**ことである。
    /// **これが、消した分岐が許していたことである。**
    ///
    /// **`TC-1.3` との違い** : あちらは**誰にも登録されていない URI**（オープン リダイレクタ狙い）。
    /// **こちらは「登録はされているが、自分のものではない」URI** である。
    /// **消した分岐が通していたのは、こちらの形**だった。
    ///
    /// **識別子が `RT-C10` なのは、公開の Issue を持たない項目のため**である
    /// （`TESTING.md` 5 節。`ANALYSIS-IdP.md` の番号で辿る）。
    /// </remarks>
    public class SelfTestRedirectTests : TargetTestBase
    {
        /// <summary>コンストラクタ</summary>
        /// <param name="output">ITestOutputHelper</param>
        public SelfTestRedirectTests(ITestOutputHelper output) : base(output) { }

        /// <summary>RT-C10.1 他のクライアントに登録された折り返し先は使えない</summary>
        /// <param name="targetKey">core / netfx</param>
        /// <returns>Task</returns>
        [SkippableTheory]
        [MemberData(nameof(AllTargets))]
        public async Task RTC1001_他のクライアントに登録された折り返し先は使えない(string targetKey)
        {
            using (IdPClient client = await this.SignedInClientAsync(targetKey))
            {
                TestReport r = this.Report("RT-C10.1",
                    "登録された折り返し先は、登録したクライアントでだけ使える",
                    "**`CheckRedirectUri` に、登録を確かめずに通す分岐が在った。**"
                    + "管理画面の「トークンを取る」の折り返し先と完全一致する `redirect_uri` は、"
                    + "**その client_id にその URI が登録されているかを見ずに通っていた。**"
                    + "**`IsLockedDownTestEndpoints` の対象外**なので、**本番でも閉じられなかった。**"
                    + "**分岐を消し、登録どおりの照合だけになった。例外は無い。**"
                    + "**その画面は、その後に廃止された**（記号も落とした）が、**この性質は測り続ける。**",
                    "RFC 6749 §3.1.2.3 / ANALYSIS-IdP.md の C-10");

                // **この URI を登録している側**（種データが作る。#264）。
                ClientRegistration registered =
                    Flows.InjectedRegistration(client, KnownClients.TestClient_15);

                // **登録していない側**（構成ファイルの登録は test_self_code）。
                ClientRegistration notRegistered =
                    Flows.Registration(client, KnownClients.TestClient);

                string onlyHisUri = registered.RedirectUri;

                r.Target("redirect_uri=" + onlyHisUri
                    + "（TestClient_15 にだけ登録されている折り返し先）");

                r.Verify("片方にだけ登録された URI である",
                    !string.IsNullOrEmpty(onlyHisUri)
                        && onlyHisUri != notRegistered.RedirectUri,
                    "別の値",
                    string.IsNullOrEmpty(onlyHisUri) ? "**空**"
                        : (onlyHisUri == notRegistered.RedirectUri
                            ? "**TestClient と同じ値**" : "別の値"));

                Assert.NotEqual(notRegistered.RedirectUri, onlyHisUri);

                r.Step("(1) 登録していないクライアントが、この折り返し先を指定する");

                AuthZResponse other = await Flows.AuthorizeCodeAsync(
                    client, notRegistered, redirectUri: onlyHisUri, state: "state-rtc1001a");

                r.Observe("応答", other.ToString(),
                    "**redirect_uri が照合できないときは、その URI へエラーも返さない**"
                    + "（RFC 6749 §4.1.2.1。`TC-1.3` と同じ扱い）。");

                r.Verify("認可コードを発行しない", string.IsNullOrEmpty(other.Code),
                    "発行しない",
                    string.IsNullOrEmpty(other.Code) ? "発行しない" : "**発行した**");

                r.Verify("その URI へリダイレクトしない",
                    !(other.Redirected && (other.Location ?? "").StartsWith(onlyHisUri)),
                    "送らない",
                    (other.Redirected && (other.Location ?? "").StartsWith(onlyHisUri))
                        ? "**送ってしまった**" : "送らない");

                r.Step("(2) 登録しているクライアントが、同じ折り返し先を指定する");

                AuthZResponse mine = await Flows.AuthorizeCodeAsync(
                    client, registered, redirectUri: onlyHisUri, state: "state-rtc1001b");

                r.Observe("応答", mine.ToString(),
                    "**登録どおりなので、通常の照合で通る**（分岐は要らない）。");

                r.Verify("認可コードを発行する", !string.IsNullOrEmpty(mine.Code),
                    "発行する",
                    string.IsNullOrEmpty(mine.Code) ? "**発行しない**" : "発行する");

                r.Note("**(1) が、消した分岐そのものである。**"
                    + "分岐が在った間は、**登録済みのどのクライアントでもこの URI を宛先にできた。**");

                r.Note("**(2) は、消したことで普通の経路が壊れていないことを見ている。**"
                    + "**登録どおりの `redirect_uri` は、これまでどおり通る。**");

                r.Done();
            }
        }
    }
}
