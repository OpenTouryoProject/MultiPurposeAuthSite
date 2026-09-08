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
//* クラス名        ：SmokeTests
//* クラス日本語名  ：疎通確認（Discovery / サインイン / 認可コード フロー）
//*
//* 作成日時        ：－
//* 作成者          ：－
//* 更新履歴        ：－
//*
//*  日時        更新者            内容
//*  ----------  ----------------  -------------------------------------------------
//*  2026/09/08  玄人 幸道         新規（E2Eテスト基盤）
//**********************************************************************************

using System.Net;
using System.Text.Json;
using System.Threading.Tasks;

using MultiPurposeAuthSite.Tests.E2E.Infrastructure;

using Xunit;
using Xunit.Abstractions;

namespace MultiPurposeAuthSite.Tests.E2E.Tests
{
    /// <summary>
    /// テスト基盤そのものの疎通確認。
    /// ここが通らない場合、他のテストの失敗は基盤側の問題である可能性が高い。
    /// </summary>
    public class SmokeTests : TargetTestBase
    {
        /// <summary>コンストラクタ</summary>
        /// <param name="output">ITestOutputHelper</param>
        public SmokeTests(ITestOutputHelper output) : base(output)
        {
        }

        /// <summary>Discovery文書が取得でき、必須のメタデータが揃っている</summary>
        /// <param name="targetKey">core / netfx</param>
        /// <returns>Task</returns>
        [SkippableTheory]
        [MemberData(nameof(AllTargets))]
        public async Task Discovery文書が取得できる(string targetKey)
        {
            using (IdPClient client = this.Client(targetKey))
            {
                JsonResponse res = await client.GetJsonAsync("/.well-known/openid-configuration");

                Assert.Equal(HttpStatusCode.OK, res.StatusCode);
                Assert.True(res.IsJson, "Discovery文書がJSONではありません。");

                // OIDC Discovery 1.0 の必須メタデータ
                Assert.Equal(JsonValueKind.String, res.KindOf("issuer"));
                Assert.Equal(JsonValueKind.String, res.KindOf("authorization_endpoint"));
                Assert.Equal(JsonValueKind.String, res.KindOf("token_endpoint"));
                Assert.Equal(JsonValueKind.String, res.KindOf("jwks_uri"));

                this.Output.WriteLine("issuer = " + res.String("issuer"));
            }
        }

        /// <summary>Discovery文書のキー名に前後の空白が無い（#189 / A-9）</summary>
        /// <param name="targetKey">core / netfx</param>
        /// <returns>Task</returns>
        [SkippableTheory]
        [MemberData(nameof(AllTargets))]
        public async Task Discovery文書のキー名に空白が混じっていない(string targetKey)
        {
            using (IdPClient client = this.Client(targetKey))
            {
                JsonResponse res = await client.GetJsonAsync("/.well-known/openid-configuration");

                Assert.True(res.IsJson, "Discovery文書がJSONではありません。");

                foreach (JsonProperty p in res.Json.EnumerateObject())
                {
                    Assert.True(p.Name == p.Name.Trim(),
                        "キー名の前後に空白があります: \"" + p.Name + "\"");
                }
            }
        }

        /// <summary>JWK Setが取得できる</summary>
        /// <param name="targetKey">core / netfx</param>
        /// <returns>Task</returns>
        [SkippableTheory]
        [MemberData(nameof(AllTargets))]
        public async Task JWKSetが取得できる(string targetKey)
        {
            using (IdPClient client = this.Client(targetKey))
            {
                JsonResponse discovery = await client.GetJsonAsync("/.well-known/openid-configuration");
                Assert.True(discovery.IsJson, "Discovery文書がJSONではありません。");

                string jwksUri = discovery.String("jwks_uri");
                this.Output.WriteLine("jwks_uri = " + jwksUri);

                JsonResponse jwks = await client.GetJsonAsync(client.ToLocalUrl(jwksUri));

                Assert.Equal(HttpStatusCode.OK, jwks.StatusCode);
                Assert.True(jwks.IsJson, "JWK SetがJSONではありません。");
                Assert.Equal(JsonValueKind.Array, jwks.KindOf("keys"));
            }
        }

        /// <summary>テスト ユーザでサインインできる</summary>
        /// <param name="targetKey">core / netfx</param>
        /// <returns>Task</returns>
        [SkippableTheory]
        [MemberData(nameof(AllTargets))]
        public async Task サインインできる(string targetKey)
        {
            using (IdPClient client = await this.SignedInClientAsync(targetKey))
            {
                Assert.True(client.IsSignedIn);
            }
        }

        /// <summary>認可コード フローでトークンが取得できる</summary>
        /// <param name="targetKey">core / netfx</param>
        /// <returns>Task</returns>
        [SkippableTheory]
        [MemberData(nameof(AllTargets))]
        public async Task 認可コードフローでトークンが取得できる(string targetKey)
        {
            using (IdPClient client = await this.SignedInClientAsync(targetKey))
            {
                JsonResponse token = await Flows.RunAuthorizationCodeFlowAsync(client);

                this.Output.WriteLine(token.ToString());

                Assert.Equal(HttpStatusCode.OK, token.StatusCode);
                Assert.Null(token.Error);
                Assert.False(string.IsNullOrEmpty(token.AccessToken), "access_tokenがありません。");
                Assert.False(string.IsNullOrEmpty(token.IdToken), "id_tokenがありません。");
            }
        }
    }
}
