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
//* クラス日本語名  ：SM 疎通確認（Discovery / サインイン / 認可コード フロー）
//*
//* 作成日時        ：－
//* 作成者          ：－
//* 更新履歴        ：－
//*
//*  日時        更新者            内容
//*  ----------  ----------------  -------------------------------------------------
//*  2026/09/08  玄人 幸道         新規（E2Eテスト基盤）
//*  2026/09/10  玄人 幸道         TestReportで記録を残すよう変更（SM-1〜SM-5）
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
    /// SM. テスト基盤そのものの疎通確認。
    /// ここが通らない場合、他のテストの失敗は基盤側の問題である可能性が高い。
    /// </summary>
    public class SmokeTests : TargetTestBase
    {
        /// <summary>コンストラクタ</summary>
        /// <param name="output">ITestOutputHelper</param>
        public SmokeTests(ITestOutputHelper output) : base(output)
        {
        }

        /// <summary>SM-1 Discovery文書が取得でき、必須のメタデータが揃っている</summary>
        /// <param name="targetKey">core / netfx</param>
        /// <returns>Task</returns>
        [SkippableTheory]
        [MemberData(nameof(AllTargets))]
        public async Task SM01_Discovery文書が取得できる(string targetKey)
        {
            using (IdPClient client = this.Client(targetKey))
            {
                TestReport r = this.Report("SM-1",
                    "Discovery 文書が取得でき、必須のメタデータが揃っている",
                    "RP は、この 1 つの URL から各エンドポイントの位置を知る。"
                    + "ここが欠けると、RP は認可サーバに繋げない。",
                    "OIDC Discovery 1.0 §3（issuer / authorization_endpoint /"
                    + " token_endpoint / jwks_uri は REQUIRED）");

                r.Target(client.Target.DisplayName);
                r.Step("GET /.well-known/openid-configuration");

                JsonResponse res = await client.GetJsonAsync("/.well-known/openid-configuration");

                r.Verify("HTTP 200 が返る", res.StatusCode == HttpStatusCode.OK,
                    "200", "HTTP " + (int)res.StatusCode);

                r.Verify("JSON として解釈できる", res.IsJson,
                    "JSON", res.IsJson ? "JSON" : "非 JSON（" + (res.ContentType ?? "不明") + "）");

                foreach (string key in new string[] {
                    "issuer", "authorization_endpoint", "token_endpoint", "jwks_uri" })
                {
                    r.Verify("必須メタデータ " + key + " が文字列で存在する",
                        res.KindOf(key) == JsonValueKind.String,
                        "文字列", key + " の型 = " + res.KindOf(key));
                }

                r.Observe("issuer", res.String("issuer"),
                    "id_token の iss は、この値と完全一致しなければならない（SM-5 / TC-6.2）。");

                r.Done();
            }
        }

        /// <summary>SM-2 Discovery文書のキー名に前後の空白が無い（#189 の一部）</summary>
        /// <param name="targetKey">core / netfx</param>
        /// <returns>Task</returns>
        [SkippableTheory]
        [MemberData(nameof(AllTargets))]
        public async Task SM02_Discovery文書のキー名に空白が混じっていない(string targetKey)
        {
            using (IdPClient client = this.Client(targetKey))
            {
                TestReport r = this.Report("SM-2",
                    "Discovery 文書のキー名に前後の空白が無い",
                    "キー名に空白が混じると、RP はそのメタデータを**見つけられない。**"
                    + "JSON のキーは完全一致で引かれるため、目視では気付きにくい。",
                    "OIDC Discovery 1.0 §3（メタデータ名は仕様で定義された文字列）"
                    + " / #189 の一部として修正済み");

                r.Target(client.Target.DisplayName);
                r.Step("GET /.well-known/openid-configuration し、全キー名を調べる");

                JsonResponse res = await client.GetJsonAsync("/.well-known/openid-configuration");

                Assert.True(res.IsJson, "前提: Discovery 文書が JSON であること");

                int count = 0;
                string bad = null;

                foreach (JsonProperty p in res.Json.EnumerateObject())
                {
                    count++;

                    if (p.Name != p.Name.Trim() && bad == null)
                    {
                        bad = p.Name;
                    }
                }

                r.Verify("すべてのキー名に前後の空白が無い", bad == null,
                    "空白を含むキーが 0 件",
                    bad == null ? count + " 件すべて空白なし"
                                : "**\"" + bad + "\" に空白がある**（全 " + count + " 件中）");

                r.Done();
            }
        }

        /// <summary>SM-3 JWK Setが取得できる</summary>
        /// <param name="targetKey">core / netfx</param>
        /// <returns>Task</returns>
        [SkippableTheory]
        [MemberData(nameof(AllTargets))]
        public async Task SM03_JWKSetが取得できる(string targetKey)
        {
            using (IdPClient client = this.Client(targetKey))
            {
                TestReport r = this.Report("SM-3",
                    "Discovery の jwks_uri から JWK Set が取得できる",
                    "RP は、ここで公開される鍵だけで id_token の署名を検証する。"
                    + "取得できなければ、署名検証そのものが成立しない。",
                    "OIDC Core §10.1 / OIDC Discovery 1.0 §3（jwks_uri は REQUIRED）");

                r.Target(client.Target.DisplayName);
                r.Step("(1) Discovery 文書から jwks_uri を取り出す");

                JsonResponse discovery = await client.GetJsonAsync("/.well-known/openid-configuration");
                Assert.True(discovery.IsJson, "前提: Discovery 文書が JSON であること");

                string jwksUri = discovery.String("jwks_uri");
                r.Note("jwks_uri = " + (jwksUri ?? "なし"));

                r.Step("(2) その URL を GET する");

                JsonResponse jwks = await client.GetJsonAsync(client.ToLocalUrl(jwksUri));

                r.Verify("HTTP 200 が返る", jwks.StatusCode == HttpStatusCode.OK,
                    "200", "HTTP " + (int)jwks.StatusCode);

                r.Verify("keys が配列で存在する",
                    jwks.KindOf("keys") == JsonValueKind.Array,
                    "配列", "keys の型 = " + jwks.KindOf("keys"));

                r.Done();
            }
        }

        /// <summary>SM-4 テスト ユーザでサインインできる</summary>
        /// <param name="targetKey">core / netfx</param>
        /// <returns>Task</returns>
        [SkippableTheory]
        [MemberData(nameof(AllTargets))]
        public async Task SM04_サインインできる(string targetKey)
        {
            using (IdPClient client = this.Client(targetKey))
            {
                TestReport r = this.Report("SM-4",
                    "テスト ユーザでサインインできる",
                    "**他のテストの前提。** 認可エンドポイントを叩く前に、"
                    + "利用者が認証済みである必要がある。"
                    + "ここが落ちると、以降の失敗は認可の問題ではなく資格情報の問題。",
                    "このリポジトリの前提（UserStoreType=mem。"
                    + "テスト ユーザは初回アクセスで作られる）");

                r.Target("username=" + TestEnv.TestUserName
                    + "（パスワードは構成ファイルの TestUserPWD から読む）");
                r.Step("(1) GET /Account/Login して __RequestVerificationToken を取る");
                r.Step("(2) POST /Account/Login に資格情報を送る");

                await client.SignInAsync();

                r.Verify("サインインできた", client.IsSignedIn,
                    "リダイレクト（302）でセッションが確立する",
                    client.IsSignedIn ? "確立した" : "確立しなかった");

                r.Done();
            }
        }

        /// <summary>SM-5 認可コード フローでトークンが取得できる</summary>
        /// <param name="targetKey">core / netfx</param>
        /// <returns>Task</returns>
        [SkippableTheory]
        [MemberData(nameof(AllTargets))]
        public async Task SM05_認可コードフローでトークンが取得できる(string targetKey)
        {
            using (IdPClient client = await this.SignedInClientAsync(targetKey))
            {
                TestReport r = this.Report("SM-5",
                    "認可コード フローが端から端まで通る",
                    "**テスト基盤が正しく組めているかの確認。**"
                    + "ここが通らなければ、以降のテストの失敗は"
                    + "仕様への不適合ではなく基盤の問題である可能性が高い。",
                    "RFC 6749 §4.1 / OIDC Core §3.1");

                r.Target("client_name=" + KnownClients.MvcSample);
                r.Step("認可 → トークン交換までを通し、応答の形を見る");

                JsonResponse token = await Flows.RunAuthorizationCodeFlowAsync(client);

                r.Verify("HTTP 200 が返る", token.StatusCode == HttpStatusCode.OK,
                    "200", "HTTP " + (int)token.StatusCode);

                r.Verify("エラーにならない", string.IsNullOrEmpty(token.Error),
                    "error なし", token.Error ?? "error なし");

                r.Verify("access_token が返る", !string.IsNullOrEmpty(token.AccessToken),
                    "access_token あり", token.AccessToken == null ? "なし" : "あり（値は伏せる）");

                r.Verify("id_token が返る", !string.IsNullOrEmpty(token.IdToken),
                    "id_token あり", token.IdToken == null ? "なし" : "あり（値は伏せる）");

                r.Done();
            }
        }
    }
}
