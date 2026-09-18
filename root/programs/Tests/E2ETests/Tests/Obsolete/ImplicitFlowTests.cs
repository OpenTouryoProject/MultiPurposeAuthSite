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
//* クラス日本語名  ：TC Implicitフロー（OAuth 2.1 では廃止。#220）
//*
//* 作成日時        ：－
//* 作成者          ：－
//* 更新履歴        ：－
//*
//*  日時        更新者            内容
//*  ----------  ----------------  -------------------------------------------------
//*  2026/09/08  玄人 幸道         新規（E2Eテスト基盤）
//*  2026/09/18  玄人 幸道         #220 でファイルを分けた（元 : Tests/Basic）
//**********************************************************************************

using System.Collections.Generic;
using System.Text.Json;
using System.Threading.Tasks;

using MultiPurposeAuthSite.Tests.E2E.Infrastructure;

using Xunit;
using Xunit.Abstractions;

namespace MultiPurposeAuthSite.Tests.E2E.Tests.Obsolete
{
    /// <summary>
    /// TC-3. Implicit フロー。
    /// </summary>
    /// <remarks>
    /// **OAuth 2.1 では廃止されたフロー。** 雛形の既定でも無効にした（#220）。
    /// 有効にしている環境のために残してあり、無効なら Skip する。
    /// </remarks>
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
                // **Implicit は雛形の既定で無効**（#220）。有効な環境でだけ測る。
                await Flows.SkipIfGrantTypeNotSupportedAsync(client, "implicit");

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
    }
}
