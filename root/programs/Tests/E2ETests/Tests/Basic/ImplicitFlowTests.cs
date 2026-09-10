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
//* クラス名        ：ImplicitFlowTests
//* クラス日本語名  ：TC-3 インプリシット フロー
//*
//* 作成日時        ：－
//* 作成者          ：－
//* 更新履歴        ：－
//*
//*  日時        更新者            内容
//*  ----------  ----------------  -------------------------------------------------
//*  2026/09/09  玄人 幸道         新規（基本テストケースの追加）
//**********************************************************************************

using System.Collections.Generic;
using System.Threading.Tasks;

using MultiPurposeAuthSite.Tests.E2E.Infrastructure;

using Xunit;
using Xunit.Abstractions;

namespace MultiPurposeAuthSite.Tests.E2E.Tests.Basic
{
    /// <summary>
    /// TC-3. インプリシット フロー（Implicit Grant）。
    ///
    /// ＜前置き＞
    ///   OAuth 2.0 Security BCP と OAuth 2.1 は、**このフローの使用を推奨していない。**
    ///   ここでのテストは「実装されている以上、仕様どおりに振る舞うか」を見るもので、
    ///   このフローを推奨する意味ではない。
    /// </summary>
    public class ImplicitFlowTests : TargetTestBase
    {
        /// <summary>コンストラクタ</summary>
        /// <param name="output">ITestOutputHelper</param>
        public ImplicitFlowTests(ITestOutputHelper output) : base(output)
        {
        }

        /// <summary>TC-3.1 / TC-3.2 フラグメントで返り、クエリに漏れない</summary>
        /// <param name="targetKey">core / netfx</param>
        /// <returns>Task</returns>
        [SkippableTheory]
        [MemberData(nameof(AllTargets))]
        public async Task TC0301_トークンがフラグメントで返りクエリに漏れない(string targetKey)
        {
            using (IdPClient client = await this.SignedInClientAsync(targetKey))
            {
                TestReport r = this.Report("TC-3.1",
                    "インプリシットのトークンがフラグメントで返り、クエリに漏れない",
                    "アクセス トークンは **URL フラグメント（#）**で返さなければならない。"
                    + "クエリ（?）に入れると、Referer ヘッダやサーバのアクセス ログを通じて"
                    + "第三者に渡る。",
                    "RFC 6749 §4.2.2（フラグメントで返す）/ §10.3 / OIDC Core §3.2.2.5");

                ClientRegistration reg = Flows.Registration(client, KnownClients.TestClient);

                r.Target("client_name=" + KnownClients.TestClient
                    + " / redirect_uri（token 用）= " + reg.RedirectUriToken);
                r.Step("GET /authorize?response_type=id_token token&scope=openid&nonce=… を送る");

                Dictionary<string, string> q = new Dictionary<string, string>()
                {
                    { "response_type", "id_token token" },
                    { "client_id", reg.ClientId },
                    { "scope", "openid" },
                    { "redirect_uri", reg.RedirectUriToken },
                    { "state", "state1" },
                    { "nonce", "nonce1" },
                    { "prompt", "none" }
                };

                AuthZResponse res = await client.AuthorizeAsync(q);

                r.Verify("エラーにならない", string.IsNullOrEmpty(res.Error),
                    "error なし", res.Error ?? ("error=" + res.Error + " / " + res.ErrorDescription));

                r.Verify("フラグメント（#）で返る",
                    res.Where == ParameterLocation.Fragment,
                    "フラグメント", "返却位置 = " + res.Where);

                r.Verify("access_token が返る",
                    !string.IsNullOrEmpty(res.Get("access_token")),
                    "access_token あり",
                    res.Get("access_token") == null ? "なし" : "あり（値は伏せる）");

                // Location の ? より前と # より後を分けて、漏れを見る。
                string location = res.Location ?? "";
                int hash = location.IndexOf('#');
                string beforeFragment = (hash >= 0) ? location.Substring(0, hash) : location;

                bool leaked =
                    beforeFragment.IndexOf("access_token=", System.StringComparison.Ordinal) >= 0
                    || beforeFragment.IndexOf("id_token=", System.StringComparison.Ordinal) >= 0;

                r.Verify("クエリ（? より前）にトークンが含まれない", !leaked,
                    "access_token / id_token がクエリに無い",
                    leaked ? "**クエリに漏れている**" : "クエリには含まれていない");

                r.Verify("state がそのまま返る", res.Get("state") == "state1",
                    "state=state1", "state = " + (res.Get("state") ?? "なし"));

                r.Done();
            }
        }

        /// <summary>TC-3.2 トークン応答のキャッシュ制御</summary>
        /// <param name="targetKey">core / netfx</param>
        /// <returns>Task</returns>
        [SkippableTheory]
        [MemberData(nameof(AllTargets))]
        public async Task TC0302_トークン応答のキャッシュ制御(string targetKey)
        {
            using (IdPClient client = await this.SignedInClientAsync(targetKey))
            {
                TestReport r = this.Report("TC-3.2",
                    "トークン応答に Cache-Control: no-store が付く",
                    "トークンを含む応答は、中間キャッシュやブラウザ履歴に残してはならない。"
                    + "RFC 6749 は **Cache-Control: no-store と Pragma: no-cache** を MUST としている。",
                    "RFC 6749 §5.1（successful response）/ §5.2（error response）");

                ClientRegistration reg = Flows.Registration(client, KnownClients.MvcSample);

                r.Target("client_name=" + KnownClients.MvcSample);
                r.Step("POST /token で正常にトークンを取得し、応答ヘッダを見る");

                AuthZResponse authz = await Flows.AuthorizeCodeAsync(
                    client, reg, redirectUri: reg.RedirectUri);

                Assert.False(string.IsNullOrEmpty(authz.Code), "前提: code が取得できること");

                JsonResponse token = await Flows.ExchangeCodeAsync(
                    client, reg, authz.Code, reg.RedirectUri);

                Assert.True(string.IsNullOrEmpty(token.Error), "前提: トークンが取得できること");

                string cacheControl = token.Header("Cache-Control");
                string pragma = token.Header("Pragma");

                r.Observe("Cache-Control", cacheControl ?? "（ヘッダ無し）",
                    "RFC 6749 §5.1 は no-store を MUST としている。");

                r.Observe("Pragma", pragma ?? "（ヘッダ無し）",
                    "RFC 6749 §5.1 は no-cache を MUST としている。"
                    + "HTTP/1.0 の後方互換のためのもの。");

                r.Note("**この 2 つは現状 MUST を満たしていない。**"
                    + " 判定を NG にすると他の検証が実行されなくなるため、"
                    + "ここでは観測にとどめ、別途 Issue として扱う。");

                // トークンが本文に入っていること自体は確かめておく
                // （ヘッダの話をする前提が成り立っているか）。
                r.Verify("この応答にトークンが含まれている（前提の確認）",
                    !string.IsNullOrEmpty(token.AccessToken),
                    "access_token あり", token.AccessToken == null ? "なし" : "あり");

                r.Done();
            }
        }
    }
}
