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
//* クラス名        ：NonceTests
//* クラス日本語名  ：RT nonceの扱いの回帰（#183 / #190 / #191）
//*
//* 作成日時        ：－
//* 作成者          ：－
//* 更新履歴        ：－
//*
//*  日時        更新者            内容
//*  ----------  ----------------  -------------------------------------------------
//*  2026/09/08  玄人 幸道         新規（E2Eテスト基盤）
//*  2026/09/10  玄人 幸道         TestReportで記録を残すよう変更（RT-183 / 190 / 191）
//*  2026/09/13  玄人 幸道         Tests/Issues へ移動（RT-183 / RT-190 / RT-191）
//**********************************************************************************

using System.Collections.Generic;
using System.Text.Json;
using System.Threading.Tasks;

using MultiPurposeAuthSite.Tests.E2E.Infrastructure;

using Xunit;
using Xunit.Abstractions;

namespace MultiPurposeAuthSite.Tests.E2E.Tests.Issues
{
    /// <summary>
    /// RT-183 / RT-190 / RT-191. nonce の扱いの回帰テスト。
    /// </summary>
    public class NonceTests : TargetTestBase
    {
        /// <summary>コンストラクタ</summary>
        /// <param name="output">ITestOutputHelper</param>
        public NonceTests(ITestOutputHelper output) : base(output)
        {
        }

        /// <summary>RT-183.1 nonce なしでも id_token が返る</summary>
        /// <param name="targetKey">core / netfx</param>
        /// <returns>Task</returns>
        [SkippableTheory]
        [MemberData(nameof(AllTargets))]
        public async Task RT183_01_nonceなしでもid_tokenが返る(string targetKey)
        {
            using (IdPClient client = await this.SignedInClientAsync(targetKey))
            {
                TestReport r = this.Report("RT-183.1",
                    "nonce を送らない Authorization Code フローでも id_token が返る",
                    "**Authorization Code フローでは nonce は任意。**"
                    + "送らなかったことを理由に id_token を出さないのは、"
                    + "OIDC の認証そのものが成立しなくなる。",
                    "OIDC Core §3.1.2.1（Authorization Code フローの nonce は OPTIONAL）"
                    + " / #183");

                r.Target("client_name=" + KnownClients.MvcSample);
                r.Step("nonce を送らずに認可コード フローを通す");

                JsonResponse token = await Flows.RunAuthorizationCodeFlowAsync(
                    client, KnownClients.MvcSample, "openid email", null);

                r.Verify("エラーにならない", string.IsNullOrEmpty(token.Error),
                    "error なし", token.Error ?? "error なし");

                r.Verify("id_token が返る", !string.IsNullOrEmpty(token.IdToken),
                    "id_token あり", token.IdToken == null ? "なし" : "あり（値は伏せる）");

                r.Note("**当初 #183 は「nonce 無しだと id_token が返らない」と報告したが、"
                    + "これは誤検出だった**（呼び出し元まで追わずに判断した）。"
                    + "実際の欠陥は RT-191.1 の方である。");

                r.Done();
            }
        }

        /// <summary>RT-191.1 nonce を送らなければ nonce クレームは付かない</summary>
        /// <param name="targetKey">core / netfx</param>
        /// <returns>Task</returns>
        [SkippableTheory]
        [MemberData(nameof(AllTargets))]
        public async Task RT191_01_nonceを送らなければnonceクレームは付かない(string targetKey)
        {
            using (IdPClient client = await this.SignedInClientAsync(targetKey))
            {
                TestReport r = this.Report("RT-191.1",
                    "nonce を送らなかったとき、id_token に nonce クレームを作らない",
                    "**修正前は state の値を nonce として詰めていた。**"
                    + "クライアントは nonce を送っていないので、"
                    + "その値を検証しようがなく、リプレイ検知の役に立たない。"
                    + "さらに state は CSRF 対策の値であり、役割が違う。",
                    "OIDC Core §3.1.3.6（nonce は認可リクエストで送られた値をそのまま入れる）"
                    + " / #191");

                r.Target("client_name=" + KnownClients.MvcSample);
                r.Step("nonce を送らず、state だけを送って認可コード フローを通す");

                JsonResponse token = await Flows.RunAuthorizationCodeFlowAsync(
                    client, KnownClients.MvcSample, "openid email", null);

                Assert.True(string.IsNullOrEmpty(token.Error), "前提: トークンが取得できること");

                JsonElement idToken = Jwt.Payload(token.IdToken);

                r.Verify("id_token に nonce クレームが無い",
                    !Jwt.Has(idToken, "nonce"),
                    "nonce クレームなし",
                    Jwt.Has(idToken, "nonce")
                        ? "**nonce=\"" + Jwt.String(idToken, "nonce") + "\" が入っている**"
                        : "入っていない");

                r.Done();
            }
        }

        /// <summary>RT-191.2 送った nonce がそのまま id_token に載る</summary>
        /// <param name="targetKey">core / netfx</param>
        /// <returns>Task</returns>
        [SkippableTheory]
        [MemberData(nameof(AllTargets))]
        public async Task RT191_02_送ったnonceがそのままid_tokenに載る(string targetKey)
        {
            const string Nonce = "nonce-abc-123";

            using (IdPClient client = await this.SignedInClientAsync(targetKey))
            {
                TestReport r = this.Report("RT-191.2",
                    "認可リクエストで送った nonce が、そのまま id_token に載る",
                    "RP は、自分が送った値と一致することを確かめてリプレイを検知する。"
                    + "**値が変換されていては照合できない。**（RT-191.1 の対照）",
                    "OIDC Core §3.1.3.6 / §15.5.2（nonce の実装に関する注意）/ #191");

                r.Target("client_name=" + KnownClients.MvcSample);
                r.Step("nonce=\"" + Nonce + "\" を送って認可コード フローを通す");

                JsonResponse token = await Flows.RunAuthorizationCodeFlowAsync(
                    client, KnownClients.MvcSample, "openid email", Nonce);

                Assert.True(string.IsNullOrEmpty(token.Error), "前提: トークンが取得できること");

                JsonElement idToken = Jwt.Payload(token.IdToken);

                r.Verify("id_token に nonce クレームがある", Jwt.Has(idToken, "nonce"),
                    "nonce クレームあり", Jwt.Has(idToken, "nonce") ? "あり" : "なし");

                r.VerifyEqual("送った値と完全一致する", Nonce, Jwt.String(idToken, "nonce"));

                r.Done();
            }
        }

        /// <summary>RT-190.1 Implicit で nonce 無しは拒否される</summary>
        /// <param name="targetKey">core / netfx</param>
        /// <returns>Task</returns>
        [SkippableTheory]
        [MemberData(nameof(AllTargets))]
        public async Task RT190_01_Implicitでnonce無しは拒否される(string targetKey)
        {
            using (IdPClient client = await this.SignedInClientAsync(targetKey))
            {
                TestReport r = this.Report("RT-190.1",
                    "Implicit / Hybrid フローで nonce が無ければ拒否される",
                    "**このフローでは nonce は必須。**"
                    + "id_token がリダイレクトで直接返るため、"
                    + "nonce が無いと RP は**トークンの再送（リプレイ）を検知できない。**"
                    + "Authorization Code フロー（RT-183.1）とは要否が逆になる。",
                    "OIDC Core §3.2.2.1（Implicit の nonce は REQUIRED）"
                    + " / §3.3.2.1（Hybrid も REQUIRED）/ #190");

                ClientRegistration reg = Flows.Registration(client, KnownClients.TestClient);

                r.Target("client_name=" + KnownClients.TestClient
                    + " / response_type=id_token token");
                r.Step("GET /authorize を nonce 無しで送る");

                Dictionary<string, string> q = new Dictionary<string, string>()
                {
                    { "response_type", "id_token token" },
                    { "client_id", reg.ClientId },
                    { "scope", "openid" },
                    { "redirect_uri", reg.RedirectUriToken },
                    { "state", "state1" },
                    { "prompt", "none" }

                    // nonce を送らない
                };

                AuthZResponse res = await client.AuthorizeAsync(q);

                r.VerifyEqual("invalid_request で拒否される", "invalid_request", res.Error);

                r.Verify("トークンを発行しない",
                    string.IsNullOrEmpty(res.Get("id_token"))
                    && string.IsNullOrEmpty(res.Get("access_token")),
                    "id_token / access_token を返さない",
                    "params = [" + string.Join(", ", res.Parameters.Keys) + "]");

                r.Done();
            }
        }

        /// <summary>RT-190.2 Implicit で nonce 有りは通る</summary>
        /// <param name="targetKey">core / netfx</param>
        /// <returns>Task</returns>
        [SkippableTheory]
        [MemberData(nameof(AllTargets))]
        public async Task RT190_02_Implicitでnonce有りは通る(string targetKey)
        {
            using (IdPClient client = await this.SignedInClientAsync(targetKey))
            {
                TestReport r = this.Report("RT-190.2",
                    "Implicit フローで nonce があれば通る",
                    "**RT-190.1 の対照。** 必須チェックを足したことで、"
                    + "正当なリクエストまで弾いていないことを確かめる。"
                    + "「拒否する」だけのテストは、常に拒否する実装でも通ってしまう。",
                    "OIDC Core §3.2.2.1 / §3.2.2.5（Implicit はフラグメントで返す）/ #190");

                ClientRegistration reg = Flows.Registration(client, KnownClients.TestClient);

                r.Target("client_name=" + KnownClients.TestClient
                    + " / response_type=id_token token");
                r.Step("GET /authorize に nonce=nonce1 を付けて送る");

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
                    "error なし",
                    res.Error == null ? "error なし"
                                      : "error=" + res.Error + " / " + res.ErrorDescription);

                r.Verify("フラグメント（#）で返る",
                    res.Where == ParameterLocation.Fragment,
                    "フラグメント", "返却位置 = " + res.Where);

                r.Verify("id_token が返る", !string.IsNullOrEmpty(res.Get("id_token")),
                    "id_token あり", res.Get("id_token") == null ? "なし" : "あり（値は伏せる）");

                r.Done();
            }
        }
    }
}
