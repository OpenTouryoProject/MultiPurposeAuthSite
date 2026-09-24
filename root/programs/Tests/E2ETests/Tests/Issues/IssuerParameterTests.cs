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
//* クラス名        ：IssuerParameterTests
//* クラス日本語名  ：RT 認可応答の iss（RFC 9207）（#231）
//*
//* 作成日時        ：－
//* 作成者          ：－
//* 更新履歴        ：－
//*
//*  日時        更新者            内容
//*  ----------  ----------------  -------------------------------------------------
//*  2026/09/24  玄人 幸道         新規（#231 : 認可応答に iss を返す）
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
    /// RT-231. 認可応答の <c>iss</c>（RFC 9207）。
    /// </summary>
    /// <remarks>
    /// **どの認可サーバからの応答かを、RP が確かめられるようにする。**
    /// RP が複数の IdP を使う場合、応答を取り違えさせる攻撃（Mix-Up）が成り立つ。
    /// RFC 9207 は、認可応答に `iss`（発行者）を含めることを求めている。
    ///
    /// **成功にも失敗にも付ける**（同 §2）。
    /// **JARM（`*.jwt`）のときは付けない。** 署名された JWT の中の `iss` が同じ役目を果たすため。
    /// </remarks>
    public class IssuerParameterTests : TargetTestBase
    {
        /// <summary>コンストラクタ</summary>
        /// <param name="output">ITestOutputHelper</param>
        public IssuerParameterTests(ITestOutputHelper output) : base(output)
        {
        }

        /// <summary>Discovery の issuer を引く</summary>
        /// <param name="client">IdPClient</param>
        /// <returns>issuer</returns>
        private static async Task<string> IssuerAsync(IdPClient client)
        {
            JsonResponse res = await client.GetJsonAsync("/.well-known/openid-configuration");
            Assert.True(res.IsJson, "前提: Discovery 文書が JSON であること");
            return res.String("issuer");
        }

        /// <summary>RT-231.1 成功の認可応答に iss が付く</summary>
        /// <param name="targetKey">core / netfx</param>
        /// <returns>Task</returns>
        [SkippableTheory]
        [MemberData(nameof(AllTargets))]
        public async Task RT231_01_成功の認可応答にissが付く(string targetKey)
        {
            using (IdPClient client = await this.SignedInClientAsync(targetKey))
            {
                ClientRegistration reg = Flows.Registration(client, KnownClients.MvcSample);

                TestReport r = this.Report("RT-231.1",
                    "認可コードを返す応答に、iss（発行者）が付く",
                    "**RP が複数の IdP を使うとき、応答の取り違えを誘う攻撃（Mix-Up）がある。**"
                    + "RP は `iss` を見て、**自分が要求した IdP からの応答か**を確かめられる。"
                    + "以前は付けていなかったので、対策が RP 側任せだった。",
                    "RFC 9207 §2 / #231");

                r.Target(client.Target.DisplayName + " / client_name=" + KnownClients.MvcSample);

                r.Step("(1) Discovery の issuer を読む");

                string issuer = await IssuerParameterTests.IssuerAsync(client);
                r.Note("issuer = " + (issuer ?? "（無し）"));

                r.Step("(2) 認可コードを要求する");

                AuthZResponse authz = await Flows.AuthorizeCodeAsync(
                    client, reg, redirectUri: reg.RedirectUri);

                r.Verify("認可コードが返る", !string.IsNullOrEmpty(authz.Code),
                    "code あり", string.IsNullOrEmpty(authz.Code) ? "**無し**" : "あり（値は伏せる）");

                r.VerifyEqual("応答の iss が Discovery の issuer と一致する",
                    issuer ?? "（無し）", authz.Get("iss") ?? "（無し）");

                r.Done();
            }
        }

        /// <summary>RT-231.2 失敗の認可応答にも iss が付く</summary>
        /// <param name="targetKey">core / netfx</param>
        /// <returns>Task</returns>
        [SkippableTheory]
        [MemberData(nameof(AllTargets))]
        public async Task RT231_02_失敗の認可応答にもissが付く(string targetKey)
        {
            using (IdPClient client = await this.SignedInClientAsync(targetKey))
            {
                ClientRegistration reg = Flows.Registration(client, KnownClients.MvcSample);

                TestReport r = this.Report("RT-231.2",
                    "エラーを返す応答にも、iss が付く",
                    "**エラーも取り違えの対象になる。** RFC 9207 §2 は、"
                    + "**成功・失敗のどちらの認可応答にも** `iss` を含めることを求めている。"
                    + "エラーだけ付けないと、RP は「どの IdP が断ったのか」を確かめられない。",
                    "RFC 9207 §2 / RFC 6749 §4.1.2.1 / #231");

                r.Target(client.Target.DisplayName + " / client_name=" + KnownClients.MvcSample);

                r.Step("(1) Discovery の issuer を読む");

                string issuer = await IssuerParameterTests.IssuerAsync(client);

                r.Step("(2) 未知の response_type で認可を要求する（RP へエラーが返る）");

                AuthZResponse authz = await client.AuthorizeAsync(new Dictionary<string, string>()
                {
                    { "response_type", "unknown_type" },
                    { "client_id", reg.ClientId },
                    { "redirect_uri", reg.RedirectUri },
                    { "scope", "profile" },
                    { "state", "state-rt2312" }
                });

                r.Verify("RP へリダイレクトで返る", authz.Redirected,
                    "リダイレクト", authz.Redirected ? "リダイレクト" : "**画面**");

                r.VerifyEqual("エラーは unsupported_response_type",
                    "unsupported_response_type", authz.Error ?? "（無し）");

                r.VerifyEqual("エラー応答の iss が Discovery の issuer と一致する",
                    issuer ?? "（無し）", authz.Get("iss") ?? "（無し）");

                r.Done();
            }
        }

        /// <summary>RT-231.3 JARM では平文の iss を付けない（JWT の中に入る）</summary>
        /// <param name="targetKey">core / netfx</param>
        /// <returns>Task</returns>
        [SkippableTheory]
        [MemberData(nameof(AllTargets))]
        public async Task RT231_03_JARMでは平文のissを付けない(string targetKey)
        {
            using (IdPClient client = await this.SignedInClientAsync(targetKey))
            {
                ClientRegistration reg = Flows.Registration(client, KnownClients.MvcSample);

                TestReport r = this.Report("RT-231.3",
                    "JARM（response_mode=query.jwt）では、平文の iss を付けない（JWT の中に入っている）",
                    "**JARM は応答を認可サーバの署名付き JWT に包む。**"
                    + "その JWT に `iss` が入っており、**署名で守られている分だけ強い。**"
                    + "平文の `iss` を重ねて付ける必要はない。",
                    "JARM / RFC 9207 §2 / #231");

                r.Target(client.Target.DisplayName + " / client_name=" + KnownClients.MvcSample);

                r.Step("(1) Discovery の issuer を読む");

                string issuer = await IssuerParameterTests.IssuerAsync(client);

                r.Step("(2) response_mode=query.jwt で認可を要求する");

                AuthZResponse authz = await Flows.AuthorizeCodeAsync(
                    client, reg, state: "state-rt2313", redirectUri: reg.RedirectUri,
                    extra: new Dictionary<string, string>() { { "response_mode", "query.jwt" } });

                string response = authz.Get("response");

                r.Verify("response（JWT）が返る", !string.IsNullOrEmpty(response),
                    "response あり", string.IsNullOrEmpty(response) ? "**無し**" : "あり（値は伏せる）");

                Assert.False(string.IsNullOrEmpty(response), "前提: JARM の応答が返ること");

                r.Verify("平文の iss は付かない", string.IsNullOrEmpty(authz.Get("iss")),
                    "付かない",
                    string.IsNullOrEmpty(authz.Get("iss")) ? "付かなかった" : "**付いている**");

                JsonElement payload = Jwt.Payload(response);

                r.VerifyEqual("JWT の中の iss が Discovery の issuer と一致する",
                    issuer ?? "（無し）", Jwt.String(payload, "iss") ?? "（無し）");

                r.Done();
            }
        }

        /// <summary>RT-231.4 Discovery が iss の対応を広告する</summary>
        /// <param name="targetKey">core / netfx</param>
        /// <returns>Task</returns>
        [SkippableTheory]
        [MemberData(nameof(AllTargets))]
        public async Task RT231_04_Discoveryがissの対応を広告する(string targetKey)
        {
            using (IdPClient client = this.Client(targetKey))
            {
                TestReport r = this.Report("RT-231.4",
                    "Discovery が authorization_response_iss_parameter_supported: true を広告する",
                    "**RP は Discovery を見て、`iss` を確かめる処理を有効にする。**"
                    + "広告していなければ、対応していても使われない。",
                    "RFC 9207 §3 / #231");

                r.Target(client.Target.DisplayName);
                r.Step("GET /.well-known/openid-configuration");

                JsonResponse res = await client.GetJsonAsync("/.well-known/openid-configuration");
                Assert.True(res.IsJson, "前提: Discovery 文書が JSON であること");

                bool supported = res.Json.TryGetProperty(
                    "authorization_response_iss_parameter_supported", out JsonElement value)
                    && value.ValueKind == JsonValueKind.True;

                r.Verify("authorization_response_iss_parameter_supported が boolean の true",
                    supported, "true（boolean）",
                    res.Json.TryGetProperty("authorization_response_iss_parameter_supported", out JsonElement v)
                        ? v.ToString() : "**無し**");

                r.Done();
            }
        }
    }
}
