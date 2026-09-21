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
//* クラス名        ：TokenResponseTests
//* クラス日本語名  ：TC トークン応答の共通の約束
//*
//* 作成日時        ：－
//* 作成者          ：－
//* 更新履歴        ：－
//*
//*  日時        更新者            内容
//*  ----------  ----------------  -------------------------------------------------
//*  2026/09/08  玄人 幸道         新規（E2Eテスト基盤）
//*  2026/09/18  玄人 幸道         #220 でファイルを分けた（元 : Basic/ImplicitFlowTests.cs）
//**********************************************************************************

using System.Collections.Generic;
using System.Text.Json;
using System.Threading.Tasks;

using MultiPurposeAuthSite.Tests.E2E.Infrastructure;

using Xunit;
using Xunit.Abstractions;

namespace MultiPurposeAuthSite.Tests.E2E.Tests.Basic
{
    /// <summary>
    /// TC-3.2 ほか。トークン応答そのものの約束（フローに依らない）。
    /// </summary>
    /// <remarks>
    /// **元は ImplicitFlowTests に同居していた**が、Implicit とは無関係なので分けた（#220）。
    /// </remarks>
    public class TokenResponseTests : TargetTestBase
    {
        /// <summary>コンストラクタ</summary>
        /// <param name="output">ITestOutputHelper</param>
        public TokenResponseTests(ITestOutputHelper output) : base(output)
        {
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

                // **値の完全一致では見ない。** net48 版は System.Web の Response.Cache を使うため、
                //   Cache-Control が "no-store, no-cache" になる（RFC の要求は no-store が在ること）。
                r.Verify("Cache-Control に no-store が付く",
                    cacheControl != null && cacheControl.Contains("no-store"),
                    "no-store を含む", cacheControl ?? "（ヘッダ無し）");

                r.Verify("Pragma に no-cache が付く",
                    pragma != null && pragma.Contains("no-cache"),
                    "no-cache を含む", pragma ?? "（ヘッダ無し）");

                r.Note("どちらも #218 で付けた。それ以前は、両系統ともヘッダが無かった。"
                    + "エラー応答（RFC 6749 §5.2）でも返るよう、アクションの入口で付けている。");

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
