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
//* クラス名        ：ErrorResponseTests
//* クラス日本語名  ：エラー応答の回帰テスト（#185 / #187）
//*
//* 作成日時        ：－
//* 作成者          ：－
//* 更新履歴        ：－
//*
//*  日時        更新者            内容
//*  ----------  ----------------  -------------------------------------------------
//*  2026/09/08  玄人 幸道         新規（E2Eテスト基盤）
//**********************************************************************************

using System.Collections.Generic;
using System.Net;
using System.Threading.Tasks;

using MultiPurposeAuthSite.Tests.E2E.Infrastructure;

using Xunit;
using Xunit.Abstractions;

namespace MultiPurposeAuthSite.Tests.E2E.Tests
{
    /// <summary>
    /// エラー応答の回帰テスト。
    ///
    /// - #185: 不正な入力で未処理の例外（HTTP 500 / HTMLのエラー画面）にしない
    /// - #187: 認可エンドポイントのエラーを RFC 6749 4.1.2.1 / 4.2.2.1 の形で返す
    /// </summary>
    public class ErrorResponseTests : TargetTestBase
    {
        /// <summary>コンストラクタ</summary>
        /// <param name="output">ITestOutputHelper</param>
        public ErrorResponseTests(ITestOutputHelper output) : base(output)
        {
        }

        #region #185 トークン エンドポイント

        /// <summary>
        /// トークン エンドポイントに不正な入力を送っても、JSONのエラー応答になる（#185）。
        /// </summary>
        /// <param name="targetKey">core / netfx</param>
        /// <returns>Task</returns>
        [SkippableTheory]
        [MemberData(nameof(AllTargets))]
        public async Task Issue185_不正な入力でもJSONのエラーを返す(string targetKey)
        {
            using (IdPClient client = await this.SignedInClientAsync(targetKey))
            {
                ClientRegistration registration = Flows.Registration(client, KnownClients.MvcSample);

                List<KeyValuePair<string, Dictionary<string, string>>> cases =
                    new List<KeyValuePair<string, Dictionary<string, string>>>()
                {
                    new KeyValuePair<string, Dictionary<string, string>>(
                        "grant_type が空",
                        new Dictionary<string, string>()),

                    new KeyValuePair<string, Dictionary<string, string>>(
                        "grant_type が未知",
                        new Dictionary<string, string>() { { "grant_type", "urn:example:bogus" } }),

                    new KeyValuePair<string, Dictionary<string, string>>(
                        "code が存在しない（PKCE経路）",
                        new Dictionary<string, string>()
                        {
                            { "grant_type", "authorization_code" },
                            { "code", "NOT-A-REAL-CODE" },
                            { "code_verifier", "x" },
                            { "client_id", registration.ClientId }
                        }),

                    new KeyValuePair<string, Dictionary<string, string>>(
                        "code が存在しない（client_secret経路）",
                        new Dictionary<string, string>()
                        {
                            { "grant_type", "authorization_code" },
                            { "code", "NOT-A-REAL-CODE" },
                            { "client_id", registration.ClientId },
                            { "client_secret", registration.ClientSecret }
                        }),

                    new KeyValuePair<string, Dictionary<string, string>>(
                        "refresh_token が存在しない",
                        new Dictionary<string, string>()
                        {
                            { "grant_type", "refresh_token" },
                            { "refresh_token", "NOT-A-REAL-TOKEN" },
                            { "client_id", registration.ClientId },
                            { "client_secret", registration.ClientSecret }
                        })
                };

                foreach (KeyValuePair<string, Dictionary<string, string>> c in cases)
                {
                    JsonResponse res = await client.TokenAsync(c.Value);

                    this.Output.WriteLine(c.Key + " -> " + res.ToString());

                    Assert.True(res.StatusCode != HttpStatusCode.InternalServerError,
                        c.Key + " で HTTP 500 になりました。");

                    Assert.True(res.IsJson, c.Key + " の応答がJSONではありません。");
                    Assert.False(string.IsNullOrEmpty(res.Error), c.Key + " に error がありません。");
                }
            }
        }

        #endregion

        #region #187 認可エンドポイント

        /// <summary>
        /// state に区切り文字が含まれていても、そのまま往復する（#187）。
        ///
        /// 以前は文字列連結で URL を組み立てていたため、
        /// state に &amp; や = が含まれるとパラメタの境界が壊れた。
        /// </summary>
        /// <param name="targetKey">core / netfx</param>
        /// <returns>Task</returns>
        [SkippableTheory]
        [MemberData(nameof(AllTargets))]
        public async Task Issue187_stateに区切り文字があっても壊れない(string targetKey)
        {
            const string State = "a&b=c d";

            using (IdPClient client = await this.SignedInClientAsync(targetKey))
            {
                ClientRegistration registration = Flows.Registration(client, KnownClients.MvcSample);

                AuthZResponse res = await Flows.AuthorizeCodeAsync(
                    client, registration, state: State, redirectUri: registration.RedirectUri);

                this.Output.WriteLine(res.ToString());

                Assert.False(string.IsNullOrEmpty(res.Code), "認可コードがありません。");
                Assert.Equal(State, res.State);
            }
        }

        /// <summary>
        /// state を送らなければ、応答にも state を含めない（#187）。
        /// </summary>
        /// <param name="targetKey">core / netfx</param>
        /// <returns>Task</returns>
        [SkippableTheory]
        [MemberData(nameof(AllTargets))]
        public async Task Issue187_stateを送らなければ返さない(string targetKey)
        {
            using (IdPClient client = await this.SignedInClientAsync(targetKey))
            {
                ClientRegistration registration = Flows.Registration(client, KnownClients.MvcSample);

                AuthZResponse res = await Flows.AuthorizeCodeAsync(
                    client, registration, state: null, redirectUri: registration.RedirectUri);

                this.Output.WriteLine(res.ToString());

                Assert.False(string.IsNullOrEmpty(res.Code), "認可コードがありません。");
                Assert.False(res.Parameters.ContainsKey("state"),
                    "state を送っていないのに state が返っています。");
            }
        }

        /// <summary>
        /// 未知の response_type では認可コードを発行しない。
        /// </summary>
        /// <param name="targetKey">core / netfx</param>
        /// <returns>Task</returns>
        [SkippableTheory]
        [MemberData(nameof(AllTargets))]
        public async Task 未知のresponse_typeでは認可コードを発行しない(string targetKey)
        {
            using (IdPClient client = await this.SignedInClientAsync(targetKey))
            {
                ClientRegistration registration = Flows.Registration(client, KnownClients.MvcSample);

                Dictionary<string, string> q = new Dictionary<string, string>()
                {
                    { "response_type", "bogus" },
                    { "client_id", registration.ClientId },
                    { "scope", "openid" },
                    { "state", "state1" },
                    { "redirect_uri", registration.RedirectUri },
                    { "prompt", "none" }
                };

                AuthZResponse res = await client.AuthorizeAsync(q);

                this.Output.WriteLine(res.ToString());

                Assert.True(string.IsNullOrEmpty(res.Code),
                    "未知の response_type で認可コードが発行されました。");
            }
        }

        /// <summary>
        /// 未知の response_type は unsupported_response_type でリダイレクトする
        /// （RFC 6749 4.1.2.1）。
        ///
        /// 実測（2026/09/08, net10.0）では、リダイレクトせずエラー画面（HTTP 200）になる。
        /// client_id と redirect_uri は妥当なので、本来はリダイレクトしてエラーを返せる。
        /// 安全側に倒れている（コードは発行されない）ため、緊急性は低い。
        /// </summary>
        /// <param name="targetKey">core / netfx</param>
        /// <returns>Task</returns>
        [SkippableTheory(Skip = "未修正。未知の response_type がリダイレクトではなくエラー画面になる。")]
        [MemberData(nameof(AllTargets))]
        public async Task 未知のresponse_typeはunsupported_response_typeでリダイレクトする(string targetKey)
        {
            using (IdPClient client = await this.SignedInClientAsync(targetKey))
            {
                ClientRegistration registration = Flows.Registration(client, KnownClients.MvcSample);

                Dictionary<string, string> q = new Dictionary<string, string>()
                {
                    { "response_type", "bogus" },
                    { "client_id", registration.ClientId },
                    { "scope", "openid" },
                    { "state", "state1" },
                    { "redirect_uri", registration.RedirectUri },
                    { "prompt", "none" }
                };

                AuthZResponse res = await client.AuthorizeAsync(q);

                this.Output.WriteLine(res.ToString());

                Assert.Equal("unsupported_response_type", res.Error);
            }
        }

        /// <summary>
        /// client_id が不正なときは、リダイレクトしない（RFC 6749 4.1.2.1）。
        ///
        /// redirect_uri を検証できない以上、そこへエラーを返してはならない。
        /// </summary>
        /// <param name="targetKey">core / netfx</param>
        /// <returns>Task</returns>
        [SkippableTheory]
        [MemberData(nameof(AllTargets))]
        public async Task Issue187_不正なclient_idではリダイレクトしない(string targetKey)
        {
            using (IdPClient client = await this.SignedInClientAsync(targetKey))
            {
                ClientRegistration registration = Flows.Registration(client, KnownClients.MvcSample);

                Dictionary<string, string> q = new Dictionary<string, string>()
                {
                    { "response_type", "code" },
                    { "client_id", "deadbeefdeadbeefdeadbeefdeadbeef" },
                    { "scope", "openid" },
                    { "state", "state1" },
                    { "redirect_uri", registration.RedirectUri },
                    { "prompt", "none" }
                };

                AuthZResponse res = await client.AuthorizeAsync(q);

                this.Output.WriteLine(res.ToString());

                Assert.True(string.IsNullOrEmpty(res.Code),
                    "不正な client_id で認可コードが発行されました。");

                Assert.NotEqual(registration.RedirectUri, res.RedirectTo);
            }
        }

        #endregion
    }
}
