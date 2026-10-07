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
//* クラス名        ：ResponseTypeOrderTests
//* クラス日本語名  ：RT-267 response_type を順不同の集合として扱う
//*
//* 作成日時        ：－
//* 作成者          ：－
//* 更新履歴        ：－
//*
//*  日時        更新者            内容
//*  ----------  ----------------  -------------------------------------------------
//*  2026/10/04  玄人 幸道         新規（#267）
//**********************************************************************************

using System;
using System.Collections.Generic;
using System.Threading.Tasks;

using MultiPurposeAuthSite.Tests.E2E.Infrastructure;

using Xunit;
using Xunit.Abstractions;

namespace MultiPurposeAuthSite.Tests.E2E.Tests.Issues
{
    /// <summary>
    /// RT-267 `response_type` の並びを変えても、同じ応答になる（#267）。
    /// </summary>
    /// <remarks>
    /// **`response_type` は順不同の空白区切り集合**である
    /// （OAuth 2.0 Multiple Response Type Encoding Practices §3。**並びは意味を持たない**）。
    ///
    /// **以前は文字列の完全一致で照合していた。**
    /// `OAuth2AndOIDCConst` の定数が固定の並び（`"code id_token token"` など）なので、
    /// **`id_token code token` と書く RP を `unsupported_response_type` で弾いていた。**
    ///
    /// **直し方** : `CmnEndpoints.NormalizeResponseType` を足し、
    /// **`ValidateAuthZReqParam` の入口で 1 回だけ掛ける**（`ref` で受けるので、
    /// 呼び出し元の変数も正規化された値になる）。
    /// **そのため、この後ろの照合（検証・`redirect_uri` の選択・応答の振り分け）は、
    /// 完全一致のままで正しくなる。**
    ///
    /// **大文字小文字の扱いは変えていない**（以前から `ToLower()` していた）。
    /// </remarks>
    public class ResponseTypeOrderTests : TargetTestBase
    {
        /// <summary>state（固定値。報告から追えるようにする）</summary>
        private const string State = "state-rt267";

        /// <summary>コンストラクタ</summary>
        /// <param name="output">ITestOutputHelper</param>
        public ResponseTypeOrderTests(ITestOutputHelper output) : base(output) { }

        /// <summary>RT-267.1 response_type の並びを変えても同じ応答になる</summary>
        /// <param name="targetKey">core / netfx</param>
        /// <returns>Task</returns>
        [SkippableTheory]
        [MemberData(nameof(AllTargets))]
        public async Task RT26701_response_typeの並びを変えても同じ応答になる(string targetKey)
        {
            using (IdPClient client = await this.SignedInClientAsync(targetKey))
            {
                TestReport r = this.Report("RT-267.1",
                    "response_type の並びを変えても、同じ応答になる",
                    "**`response_type` は順不同の空白区切り集合**である"
                    + "（OAuth 2.0 Multiple Response Type Encoding Practices §3。"
                    + "**並びは意味を持たない**）。"
                    + "**以前は文字列の完全一致で照合していた**ため、"
                    + "`OAuth2AndOIDCConst` の定数の並び（`code id_token token` など）でなければ"
                    + "**`unsupported_response_type` で弾いていた**（#267）。"
                    + "**`id_token code` と書く RP が通らない**という相互運用性の問題である。",
                    "OAuth 2.0 Multiple Response Type Encoding Practices §3 / OIDC Core §3.3 / #267");

                ClientRegistration reg = Flows.Registration(client, KnownClients.TestClient);

                r.Target("client_name=" + KnownClients.TestClient
                    + " / response_type の並びを入れ替えて送る");

                // **広告どおりの並び**と、**入れ替えた並び**の組。
                //   どちらも同じ集合なので、**同じ応答になる**のが正しい。
                string[][] pairs = new string[][]
                {
                    new string[] { "code id_token", "id_token code" },
                    new string[] { "id_token token", "token id_token" },
                    new string[] { "code token", "token code" },
                    new string[] { "code id_token token", "token id_token code" }
                };

                foreach (string[] pair in pairs)
                {
                    string advertised = pair[0];
                    string reordered = pair[1];

                    r.Step("(" + advertised + ") と、並べ替えた (" + reordered + ") を比べる");

                    string nonce = "nonce-" + Guid.NewGuid().ToString("N");

                    AuthZResponse a = await ResponseTypeOrderTests.AuthorizeAsync(
                        client, reg, advertised, nonce);
                    AuthZResponse b = await ResponseTypeOrderTests.AuthorizeAsync(
                        client, reg, reordered, nonce);

                    // **広告どおりの並びは、従来どおり通る**（測る前提）。
                    r.Verify("`" + advertised + "` は通る（前提）",
                        string.IsNullOrEmpty(a.Error),
                        "通る",
                        string.IsNullOrEmpty(a.Error)
                            ? "通る" : "**通らない**（" + a.Error + "）");

                    // **並べ替えても、同じ扱いになる。**
                    r.VerifyEqual("`" + reordered + "` のエラー（`" + advertised + "` と同じ）",
                        ResponseTypeOrderTests.Shown(a.Error),
                        ResponseTypeOrderTests.Shown(b.Error));

                    // **返る項目の有無が同じ**であること（値は毎回変わるので、有無で見る）。
                    r.VerifyEqual("`" + reordered + "` が返す項目（`" + advertised + "` と同じ）",
                        ResponseTypeOrderTests.Shape(a),
                        ResponseTypeOrderTests.Shape(b));
                }

                r.Note("**値そのものは比べていない。** code / id_token / access_token は毎回変わるため、"
                    + "**返る項目の有無**で比べている。"
                    + "**どの項目が返るかは `response_type` の集合で決まる**ので、これで十分である。");

                r.Note("**大文字小文字の扱いは変えていない。**"
                    + "**仕様では値は case-sensitive** だが、**以前から `ToLower()` していて "
                    + "`CODE` も通っていた。** **弾く範囲が変わるだけ**なので、寛容さを残した。");

                r.Done();
            }
        }

        /// <summary>認可要求を送る</summary>
        /// <param name="client">IdPClient</param>
        /// <param name="reg">クライアント</param>
        /// <param name="responseType">response_type</param>
        /// <param name="nonce">nonce</param>
        /// <returns>AuthZResponse</returns>
        private static Task<AuthZResponse> AuthorizeAsync(
            IdPClient client, ClientRegistration reg, string responseType, string nonce)
        {
            return client.AuthorizeAsync(new Dictionary<string, string>()
            {
                { "response_type", responseType },
                { "client_id", reg.ClientId },
                { "scope", "openid" },

                // **code を含む形も含めるので、token 用の折り返し先で揃える**
                //   （どちらの登録でも通る値。HybridFlowTests と同じ）。
                { "redirect_uri", reg.RedirectUriToken },
                { "state", ResponseTypeOrderTests.State },
                { "nonce", nonce },

                // 同意画面を挟まず、サインイン済みのセッションでそのまま認可させる。
                { "prompt", "none" }
            });
        }

        /// <summary>応答に、どの項目が返ったか（値は見ない）</summary>
        /// <param name="res">AuthZResponse</param>
        /// <returns>項目の並び</returns>
        private static string Shape(AuthZResponse res)
        {
            List<string> items = new List<string>();

            if (!string.IsNullOrEmpty(res.Code)) { items.Add("code"); }
            if (!string.IsNullOrEmpty(res.Get("id_token"))) { items.Add("id_token"); }
            if (!string.IsNullOrEmpty(res.Get("access_token"))) { items.Add("access_token"); }
            if (!string.IsNullOrEmpty(res.Get("token_type"))) { items.Add("token_type"); }

            return (items.Count == 0) ? "（無し）" : string.Join(" ", items);
        }

        /// <summary>報告に出す形（空なら「（無し）」）</summary>
        /// <param name="value">値</param>
        /// <returns>表示用</returns>
        private static string Shown(string value)
        {
            return string.IsNullOrEmpty(value) ? "（無し）" : value;
        }
    }
}
