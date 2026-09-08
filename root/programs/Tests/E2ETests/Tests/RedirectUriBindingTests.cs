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
//* クラス名        ：RedirectUriBindingTests
//* クラス日本語名  ：redirect_uriの照合の回帰テスト（#186）
//*
//* 作成日時        ：－
//* 作成者          ：－
//* 更新履歴        ：－
//*
//*  日時        更新者            内容
//*  ----------  ----------------  -------------------------------------------------
//*  2026/09/08  玄人 幸道         新規（E2Eテスト基盤）
//**********************************************************************************

using System.Threading.Tasks;

using MultiPurposeAuthSite.Tests.E2E.Infrastructure;

using Xunit;
using Xunit.Abstractions;

namespace MultiPurposeAuthSite.Tests.E2E.Tests
{
    /// <summary>
    /// 認可リクエストの redirect_uri を認可コードに紐付け、
    /// トークン リクエストで照合していることを確認する（#186）。
    ///
    /// RFC 6749 4.1.3 / OIDC Core 3.1.3.1:
    ///   認可リクエストに redirect_uri が含まれていた場合、
    ///   トークン リクエストにも含めなければならず、両者は一致しなければならない。
    /// </summary>
    public class RedirectUriBindingTests : TargetTestBase
    {
        /// <summary>コンストラクタ</summary>
        /// <param name="output">ITestOutputHelper</param>
        public RedirectUriBindingTests(ITestOutputHelper output) : base(output)
        {
        }

        /// <summary>ケースA: 同じ redirect_uri を送れば成功する</summary>
        /// <param name="targetKey">core / netfx</param>
        /// <returns>Task</returns>
        [SkippableTheory]
        [MemberData(nameof(AllTargets))]
        public async Task Issue186_CaseA_同じredirect_uriなら成功する(string targetKey)
        {
            using (IdPClient client = await this.SignedInClientAsync(targetKey))
            {
                ClientRegistration registration = Flows.Registration(client, KnownClients.MvcSample);

                AuthZResponse authz = await Flows.AuthorizeCodeAsync(
                    client, registration, redirectUri: registration.RedirectUri);

                Assert.False(string.IsNullOrEmpty(authz.Code), "認可コードがありません: " + authz.ToString());

                JsonResponse token = await Flows.ExchangeCodeAsync(
                    client, registration, authz.Code, registration.RedirectUri);

                this.Output.WriteLine(token.ToString());

                Assert.Null(token.Error);
                Assert.False(string.IsNullOrEmpty(token.AccessToken), "access_token がありません。");
            }
        }

        /// <summary>ケースB: 違う redirect_uri を送れば拒否される</summary>
        /// <param name="targetKey">core / netfx</param>
        /// <returns>Task</returns>
        [SkippableTheory]
        [MemberData(nameof(AllTargets))]
        public async Task Issue186_CaseB_違うredirect_uriは拒否される(string targetKey)
        {
            using (IdPClient client = await this.SignedInClientAsync(targetKey))
            {
                ClientRegistration registration = Flows.Registration(client, KnownClients.MvcSample);

                AuthZResponse authz = await Flows.AuthorizeCodeAsync(
                    client, registration, redirectUri: registration.RedirectUri);

                Assert.False(string.IsNullOrEmpty(authz.Code), "認可コードがありません: " + authz.ToString());

                JsonResponse token = await Flows.ExchangeCodeAsync(
                    client, registration, authz.Code, "https://attacker.example.com/callback");

                this.Output.WriteLine(token.ToString());

                Assert.Equal("invalid_grant", token.Error);
                Assert.Null(token.AccessToken);
            }
        }

        /// <summary>ケースC: 認可時に送った redirect_uri をトークン時に省略すると拒否される</summary>
        /// <param name="targetKey">core / netfx</param>
        /// <returns>Task</returns>
        [SkippableTheory]
        [MemberData(nameof(AllTargets))]
        public async Task Issue186_CaseC_redirect_uriの省略は拒否される(string targetKey)
        {
            using (IdPClient client = await this.SignedInClientAsync(targetKey))
            {
                ClientRegistration registration = Flows.Registration(client, KnownClients.MvcSample);

                AuthZResponse authz = await Flows.AuthorizeCodeAsync(
                    client, registration, redirectUri: registration.RedirectUri);

                Assert.False(string.IsNullOrEmpty(authz.Code), "認可コードがありません: " + authz.ToString());

                // redirect_uri を送らない
                JsonResponse token = await Flows.ExchangeCodeAsync(
                    client, registration, authz.Code, null);

                this.Output.WriteLine(token.ToString());

                Assert.Equal("invalid_grant", token.Error);
                Assert.Null(token.AccessToken);
            }
        }

        /// <summary>認可コードは1回しか使えない（RFC 6749 4.1.2）</summary>
        /// <param name="targetKey">core / netfx</param>
        /// <returns>Task</returns>
        [SkippableTheory]
        [MemberData(nameof(AllTargets))]
        public async Task 認可コードは再利用できない(string targetKey)
        {
            using (IdPClient client = await this.SignedInClientAsync(targetKey))
            {
                ClientRegistration registration = Flows.Registration(client, KnownClients.MvcSample);

                AuthZResponse authz = await Flows.AuthorizeCodeAsync(
                    client, registration, redirectUri: registration.RedirectUri);

                Assert.False(string.IsNullOrEmpty(authz.Code), "認可コードがありません: " + authz.ToString());

                JsonResponse first = await Flows.ExchangeCodeAsync(
                    client, registration, authz.Code, registration.RedirectUri);

                Assert.Null(first.Error);

                JsonResponse second = await Flows.ExchangeCodeAsync(
                    client, registration, authz.Code, registration.RedirectUri);

                this.Output.WriteLine("2回目: " + second.ToString());

                Assert.NotNull(second.Error);
                Assert.Null(second.AccessToken);
            }
        }
    }
}
