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
//* クラス名        ：DiscoveryTests
//* クラス日本語名  ：RT Discovery 文書の項目と型（#189）
//*
//* 作成日時        ：－
//* 作成者          ：－
//* 更新履歴        ：－
//*
//*  日時        更新者            内容
//*  ----------  ----------------  -------------------------------------------------
//*  2026/09/24  玄人 幸道         新規（#189 の 2〜8 : 誤りの修正と、実装済みの項目の広告）
//**********************************************************************************

using System.Collections.Generic;
using System.Linq;
using System.Text.Json;
using System.Threading.Tasks;

using MultiPurposeAuthSite.Tests.E2E.Infrastructure;

using Xunit;
using Xunit.Abstractions;

namespace MultiPurposeAuthSite.Tests.E2E.Tests.Issues
{
    /// <summary>
    /// RT-189. Discovery 文書（<c>.well-known/openid-configuration</c>）の項目と型。
    /// </summary>
    /// <remarks>
    /// **Discovery は RP が最初に読む唯一の入口である。**
    /// キー名が仕様と違えば RP は見つけられず、型が違えば読む側が落ちる。
    /// どちらも**目視では気付きにくい**ので、ここで固定する。
    ///
    /// キー名の空白は `SM-2` が全数で見ている（#189 の 1）。
    /// </remarks>
    public class DiscoveryTests : TargetTestBase
    {
        /// <summary>コンストラクタ</summary>
        /// <param name="output">ITestOutputHelper</param>
        public DiscoveryTests(ITestOutputHelper output) : base(output)
        {
        }

        #region 補助

        /// <summary>Discovery 文書を取る</summary>
        /// <param name="client">IdPClient</param>
        /// <returns>JSON</returns>
        private static async Task<JsonElement> DiscoveryAsync(IdPClient client)
        {
            JsonResponse res = await client.GetJsonAsync("/.well-known/openid-configuration");
            Assert.True(res.IsJson, "前提: Discovery 文書が JSON であること");
            return res.Json;
        }

        /// <summary>値の種類を、読み手に分かる言葉にする</summary>
        /// <param name="json">Discovery 文書</param>
        /// <param name="name">キー</param>
        /// <returns>文字列</returns>
        private static string KindOf(JsonElement json, string name)
        {
            if (!json.TryGetProperty(name, out JsonElement value))
            {
                return "（無し）";
            }

            switch (value.ValueKind)
            {
                case JsonValueKind.Array:
                    return "配列 [" + string.Join(", ",
                        value.EnumerateArray().Select(x => x.ToString())) + "]";
                case JsonValueKind.True:
                case JsonValueKind.False:
                    return "boolean（" + value.ToString().ToLower() + "）";
                case JsonValueKind.String:
                    return "文字列（\"" + value.GetString() + "\"）";
                default:
                    return value.ValueKind.ToString();
            }
        }

        /// <summary>配列に、その値が入っているか</summary>
        /// <param name="json">Discovery 文書</param>
        /// <param name="name">キー</param>
        /// <param name="value">値</param>
        /// <returns>入っていれば true</returns>
        private static bool ArrayContains(JsonElement json, string name, string value)
        {
            return json.TryGetProperty(name, out JsonElement array)
                && array.ValueKind == JsonValueKind.Array
                && array.EnumerateArray().Any(x => x.ValueKind == JsonValueKind.String && x.GetString() == value);
        }

        #endregion

        /// <summary>RT-189.1 Device Authorization Grant を広告する</summary>
        /// <param name="targetKey">core / netfx</param>
        /// <returns>Task</returns>
        [SkippableTheory]
        [MemberData(nameof(AllTargets))]
        public async Task RT189_01_DeviceAuthorizationGrantを広告する(string targetKey)
        {
            using (IdPClient client = this.Client(targetKey))
            {
                TestReport r = this.Report("RT-189.1",
                    "Discovery が device_authorization_endpoint と device_code のグラントを広告する",
                    "**実装しているのに広告していなかった。**"
                    + "`/device_authz` を公開し、`device_code` のグラントも実装しているのに、"
                    + "Discovery は `Config.EnableDeviceAuthZGrantType` を一度も見ていなかった。"
                    + "RP は Discovery だけを見て設定するので、**使えるのに使えないと判断される。**",
                    "RFC 8628 §4 / #189 の 6・7");

                r.Target(client.Target.DisplayName);
                r.Step("GET /.well-known/openid-configuration");

                JsonElement json = await DiscoveryTests.DiscoveryAsync(client);

                string endpoint = json.TryGetProperty("device_authorization_endpoint", out JsonElement ep)
                    ? ep.GetString() : null;

                r.Verify("device_authorization_endpoint がある",
                    !string.IsNullOrEmpty(endpoint),
                    "URL が載る", endpoint ?? "**無し**");

                r.Verify("grant_types_supported に device_code が入る",
                    DiscoveryTests.ArrayContains(json,
                        "grant_types_supported", "urn:ietf:params:oauth:grant-type:device_code"),
                    "含まれる",
                    DiscoveryTests.KindOf(json, "grant_types_supported"));

                r.Step("広告された口が、実際に応答することを確かめる");

                JsonResponse res = await client.PostJsonAsync(
                    client.ToLocalUrl(endpoint), new Dictionary<string, string>());

                // 引数なしなので失敗するが、**その口が在ること**は分かる（404 ではない）。
                r.Verify("その URL は存在する（404 ではない）",
                    (int)res.StatusCode != 404,
                    "404 以外", "HTTP " + (int)res.StatusCode + " / error=" + (res.Error ?? "なし"));

                r.Done();
            }
        }

        /// <summary>RT-189.2 値の型が仕様どおり</summary>
        /// <param name="targetKey">core / netfx</param>
        /// <returns>Task</returns>
        [SkippableTheory]
        [MemberData(nameof(AllTargets))]
        public async Task RT189_02_値の型が仕様どおり(string targetKey)
        {
            using (IdPClient client = this.Client(targetKey))
            {
                TestReport r = this.Report("RT-189.2",
                    "Discovery の値が、仕様どおりの型（boolean / 配列）で返る",
                    "**素直に読む RP は、型が違うと落ちる。**"
                    + "boolean を文字列の \"false\" で返すと、多くの実装では**真**として読まれる。"
                    + "配列であるべき項目を文字列で返すと、解析でそのまま失敗する。",
                    "CIBA Core §4 / OIDC Discovery 1.0 §3 / #189 の 3・4");

                r.Target(client.Target.DisplayName);
                r.Step("GET /.well-known/openid-configuration");

                JsonElement json = await DiscoveryTests.DiscoveryAsync(client);

                r.Verify("backchannel_user_code_parameter_supported は boolean",
                    json.TryGetProperty("backchannel_user_code_parameter_supported", out JsonElement userCode)
                        && (userCode.ValueKind == JsonValueKind.True || userCode.ValueKind == JsonValueKind.False),
                    "boolean",
                    DiscoveryTests.KindOf(json, "backchannel_user_code_parameter_supported"));

                r.Verify("backchannel_authentication_request_signing_alg_values_supported は配列",
                    DiscoveryTests.ArrayContains(json,
                        "backchannel_authentication_request_signing_alg_values_supported", "ES256"),
                    "配列（ES256 を含む）",
                    DiscoveryTests.KindOf(json, "backchannel_authentication_request_signing_alg_values_supported"));

                r.Done();
            }
        }

        /// <summary>RT-189.3 mTLS の紐づけを、RFC の名前と型で広告する</summary>
        /// <param name="targetKey">core / netfx</param>
        /// <returns>Task</returns>
        [SkippableTheory]
        [MemberData(nameof(AllTargets))]
        public async Task RT189_03_mTLSの紐づけをRFCの名前で広告する(string targetKey)
        {
            using (IdPClient client = this.Client(targetKey))
            {
                TestReport r = this.Report("RT-189.3",
                    "mTLS の紐づけは tls_client_certificate_bound_access_tokens（boolean）で広告する",
                    "**以前は草案の名前（mutual_tls_sender_constrained_access_tokens）に、文字列の \"true\" を入れていた。**"
                    + "RFC 8705 §3.3 の名前で出さなければ、RP は**この IdP が紐づけに対応していない**と読む。"
                    + "紐づけそのものは `FA-6.4` で測っている。",
                    "RFC 8705 §3.3 / #189 の 2");

                r.Target(client.Target.DisplayName);
                r.Step("GET /.well-known/openid-configuration");

                JsonElement json = await DiscoveryTests.DiscoveryAsync(client);

                r.Verify("tls_client_certificate_bound_access_tokens が boolean の true",
                    json.TryGetProperty("tls_client_certificate_bound_access_tokens", out JsonElement bound)
                        && bound.ValueKind == JsonValueKind.True,
                    "true（boolean）",
                    DiscoveryTests.KindOf(json, "tls_client_certificate_bound_access_tokens"));

                r.Verify("草案の名前は載せない",
                    !json.TryGetProperty("mutual_tls_sender_constrained_access_tokens", out JsonElement _),
                    "無い",
                    DiscoveryTests.KindOf(json, "mutual_tls_sender_constrained_access_tokens"));

                r.Done();
            }
        }

        /// <summary>RT-189.4 暗号化と JARM は、対になる項目まで広告する</summary>
        /// <param name="targetKey">core / netfx</param>
        /// <returns>Task</returns>
        [SkippableTheory]
        [MemberData(nameof(AllTargets))]
        public async Task RT189_04_暗号化とJARMは対の項目まで広告する(string targetKey)
        {
            using (IdPClient client = this.Client(targetKey))
            {
                TestReport r = this.Report("RT-189.4",
                    "id_token の暗号化は alg と enc の対で、JARM は応答の署名アルゴリズムまで広告する",
                    "**片方だけでは使えない。** 暗号化は alg（鍵）と enc（本文）の両方が要り、"
                    + "`*.jwt` の response_mode を出すなら、RP は**何で検証するか**を知る必要がある。"
                    + "実装は JWE が RSA-OAEP ＋ A256GCM、JARM の署名が RS256。",
                    "OIDC Discovery 1.0 §3 / JARM §7 / #189 の 5・8");

                r.Target(client.Target.DisplayName);
                r.Step("GET /.well-known/openid-configuration");

                JsonElement json = await DiscoveryTests.DiscoveryAsync(client);

                Skip.If(!json.TryGetProperty("id_token_encryption_alg_values_supported", out JsonElement _),
                    "OpenID Connect が無効のため、id_token の項目が出ていません。");

                r.Verify("id_token_encryption_enc_values_supported がある（A256GCM）",
                    DiscoveryTests.ArrayContains(json, "id_token_encryption_enc_values_supported", "A256GCM"),
                    "配列（A256GCM を含む）",
                    DiscoveryTests.KindOf(json, "id_token_encryption_enc_values_supported"));

                r.Verify("response_modes_supported に *.jwt がある（JARM）",
                    DiscoveryTests.ArrayContains(json, "response_modes_supported", "query.jwt"),
                    "query.jwt を含む",
                    DiscoveryTests.KindOf(json, "response_modes_supported"));

                r.Verify("authorization_signing_alg_values_supported がある（RS256）",
                    DiscoveryTests.ArrayContains(json, "authorization_signing_alg_values_supported", "RS256"),
                    "配列（RS256 を含む）",
                    DiscoveryTests.KindOf(json, "authorization_signing_alg_values_supported"));

                r.Done();
            }
        }
    }
}
