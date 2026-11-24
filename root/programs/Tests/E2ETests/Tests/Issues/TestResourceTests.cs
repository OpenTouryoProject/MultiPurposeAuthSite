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
//* クラス名        ：TestResourceTests
//* クラス日本語名  ：テスト用の資源（/TestResource）の E2E テスト（#425）
//*
//* 作成日時        ：－
//* 作成者          ：－
//* 更新履歴        ：－
//*
//*  日時        更新者            内容
//*  ----------  ----------------  -------------------------------------------------
//*  2026/11/24  玄人 幸道         新規（#425）
//**********************************************************************************

using System;
using System.Collections.Generic;
using System.Linq;
using System.Net.Http;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Threading.Tasks;

using MultiPurposeAuthSite.Tests.E2E.Infrastructure;

using Xunit;
using Xunit.Abstractions;

namespace MultiPurposeAuthSite.Tests.E2E.Tests.Issues
{
    /// <summary>テスト用の資源（/TestResource）の E2E テスト（#425）</summary>
    /// <remarks>
    /// **適合性テストの FAPI 2.0 の `openid=plain_oauth`・client_credentials のプランは、最後に資源をトークンで呼び、200 を求める。**
    /// **`/userinfo` は `openid` の無いトークンを `403` で断る**（`RT-294.80`）ので、**`openid` を求めない資源 `/TestResource` を足した。**
    ///
    /// | ID | 測ること |
    /// |---|---|
    /// | **`RT-425.1`** | **`openid` の無い client_credentials のトークンで、`/TestResource` は 200（`client_id`・`scope`）。`/userinfo` は今までどおり 403。トークンが無い・壊れたトークンは 401** |
    /// | **`RT-425.2`** | **DPoP に縛ったトークンは、正しい証明でだけ使える**（`Bearer` で出す・証明なし・別の鍵・`ath`・`htu` が違えば 401） |
    ///
    /// **`IsLockedDownTestEndpoints` が true の配備で 404 になることは、E2E では測らない**（通しは口を開けた構成で回す）。
    /// </remarks>
    public class TestResourceTests : TargetTestBase
    {
        /// <summary>constructor</summary>
        /// <param name="output">ITestOutputHelper</param>
        public TestResourceTests(ITestOutputHelper output) : base(output) { }

        #region RT-425.1

        /// <summary>RT-425.1 openid の無いトークンで、/TestResource は 200、/userinfo は 403</summary>
        /// <param name="targetKey">core / netfx</param>
        /// <returns>Task</returns>
        [SkippableTheory]
        [MemberData(nameof(AllTargets))]
        public async Task RT42501_openidの無いトークンで資源は200でuserinfoは403(string targetKey)
        {
            using (IdPClient client = this.Client(targetKey))
            {
                TestReport r = this.Report("RT-425.1",
                    "**`openid` の無い client_credentials のトークンで、`/TestResource` は 200（`client_id`・`scope`）。`/userinfo` は今までどおり 403。トークンが無い・壊れたトークンは 401**",
                    "**適合性テストの FAPI 2.0 の `openid=plain_oauth`・client_credentials のプランが呼ぶ資源**（#425）。"
                    + "**`openid` を求めないところだけが `/userinfo` と違う**（OIDC Core 1.0 §5.3 は UserInfo に `openid` を求める）。"
                    + "**断り方は RFC 6750 §3**（トークンが無ければエラー コード無しの 401、壊れていれば `invalid_token`）。",
                    "RFC 6750 §3・§3.1 / #425");

                ClientRegistration reg = Flows.Registration(client, KnownClients.MvcSample);

                r.Target("GET /TestResource（client_name=" + KnownClients.MvcSample + "、client_credentials）");

                r.Step("(1) client_credentials（scope=profile）でトークンを取る");

                JsonResponse token = await client.TokenAsync(new Dictionary<string, string>()
                {
                    { "grant_type", "client_credentials" },
                    { "scope", "profile" },
                    { "client_id", reg.ClientId },
                    { "client_secret", reg.ClientSecret }
                });

                Assert.False(string.IsNullOrEmpty(token.AccessToken),
                    "前提: access_token が取れること（" + (token.Error ?? "") + "）");

                r.Step("(2) /TestResource を Bearer で呼ぶ");

                HttpResponseMessage ok = await client.GetAsync("/TestResource",
                    new Dictionary<string, string>() { { "Authorization", "Bearer " + token.AccessToken } });
                string body = await ok.Content.ReadAsStringAsync();

                r.VerifyEqual("200", "200", ((int)ok.StatusCode).ToString());
                r.VerifyEqual("client_id は、トークンを取ったクライアント", reg.ClientId, TestResourceTests.StringOf(body, "client_id"));
                r.Verify("scope に profile がある", (" " + TestResourceTests.StringOf(body, "scope") + " ").Contains(" profile "),
                    "profile を含む", TestResourceTests.StringOf(body, "scope"));
                r.Verify("scope に openid が無い（openid を求めない）", !(" " + TestResourceTests.StringOf(body, "scope") + " ").Contains(" openid "),
                    "openid を含まない", TestResourceTests.StringOf(body, "scope"));

                r.Step("(3) 同じトークンで /userinfo を呼ぶ（今までどおり断る）");

                JsonResponse userInfo = await client.UserInfoAsync(token.AccessToken);

                r.VerifyEqual("/userinfo は 403（insufficient_scope）", "403", ((int)userInfo.StatusCode).ToString());

                r.Step("(4) トークンを付けずに呼ぶ");

                HttpResponseMessage none = await client.GetAsync("/TestResource");

                r.VerifyEqual("401", "401", ((int)none.StatusCode).ToString());
                r.Verify("WWW-Authenticate が付く（RFC 6750 §3）", none.Headers.WwwAuthenticate.Any(),
                    "付く", none.Headers.WwwAuthenticate.Any() ? "付く" : "**付かない**");

                r.Step("(5) 壊れたトークンで呼ぶ");

                HttpResponseMessage broken = await client.GetAsync("/TestResource",
                    new Dictionary<string, string>() { { "Authorization", "Bearer " + token.AccessToken + "x" } });
                string brokenBody = await broken.Content.ReadAsStringAsync();

                r.VerifyEqual("401", "401", ((int)broken.StatusCode).ToString());
                r.VerifyEqual("invalid_token", "invalid_token", TestResourceTests.StringOf(brokenBody, "error"));

                r.Done();
            }
        }

        #endregion

        #region RT-425.2

        /// <summary>RT-425.2 DPoP に縛ったトークンは、正しい証明でだけ使える</summary>
        /// <param name="targetKey">core / netfx</param>
        /// <returns>Task</returns>
        [SkippableTheory]
        [MemberData(nameof(AllTargets))]
        public async Task RT42502_DPoPに縛ったトークンは正しい証明でだけ使える(string targetKey)
        {
            using (IdPClient client = this.Client(targetKey))
            {
                TestReport r = this.Report("RT-425.2",
                    "**DPoP に縛ったトークンは、`/TestResource` で、正しい証明でだけ使える**（`Bearer` で出す・証明なし・別の鍵・`ath` が別のトークン・`htu` が別の口は 401）",
                    "**資源の側の送信者の拘束**（RFC 9449 §7.1）。**照合は `/userinfo` と同じ製品の部品**（`CmnAccessToken.VerifyDPoPBinding`）で、"
                    + "**`htu` は、この口の URL**（`CmnDPoP.EndpointUriOf` に足した。#425）。",
                    "RFC 9449 §4.3・§7.1・§7.2 / #425");

                ClientRegistration reg = Flows.Registration(client, KnownClients.MvcSample);

                JsonResponse discovery = await client.GetJsonAsync("/.well-known/openid-configuration");
                string userInfoEndpoint = discovery.String("userinfo_endpoint");

                Assert.False(string.IsNullOrEmpty(userInfoEndpoint), "前提: Discovery が userinfo_endpoint を広告していること");

                //  **サーバは、設定のルート ＋ 口のパスで htu を作る**（`/userinfo` と同じルート）。
                string resource = userInfoEndpoint.Substring(0, userInfoEndpoint.LastIndexOf('/')) + "/TestResource";

                r.Target("GET /TestResource（DPoP に縛った client_credentials のトークン）");

                r.Step("(1) client_credentials で、DPoP の証明を添えてトークンを取る");

                JsonResponse token = await client.TokenWithDPoPAsync(new Dictionary<string, string>()
                {
                    { "grant_type", "client_credentials" },
                    { "scope", "profile" },
                    { "client_id", reg.ClientId },
                    { "client_secret", reg.ClientSecret }
                });

                Assert.False(string.IsNullOrEmpty(token.AccessToken),
                    "前提: access_token が取れること（" + (token.Error ?? "") + "）");
                Assert.Equal("DPoP", token.String("token_type"));

                string accessToken = token.AccessToken;

                r.Step("(2) Bearer で出す（証明なし）");

                HttpResponseMessage asBearer = await TestResourceTests.CallAsync(client, resource, "Bearer " + accessToken, null);

                r.VerifyEqual("401", "401", ((int)asBearer.StatusCode).ToString());

                r.Step("(3) DPoP スキームだが、証明が無い");

                HttpResponseMessage noProof = await TestResourceTests.CallAsync(client, resource, "DPoP " + accessToken, null);

                r.VerifyEqual("401", "401", ((int)noProof.StatusCode).ToString());

                r.Step("(4) 別の鍵（RSA）で署名した証明");

                HttpResponseMessage otherKey = await TestResourceTests.CallAsync(client, resource, "DPoP " + accessToken,
                    TestResourceTests.Proof(client, resource, accessToken, es256: false));

                r.VerifyEqual("401", "401", ((int)otherKey.StatusCode).ToString());

                r.Step("(5) ath が別のトークンの指紋");

                HttpResponseMessage otherAth = await TestResourceTests.CallAsync(client, resource, "DPoP " + accessToken,
                    TestResourceTests.Proof(client, resource, accessToken + "x"));

                r.VerifyEqual("401", "401", ((int)otherAth.StatusCode).ToString());

                r.Step("(6) htu が別の口（/userinfo への証明）");

                HttpResponseMessage otherHtu = await TestResourceTests.CallAsync(client, resource, "DPoP " + accessToken,
                    TestResourceTests.Proof(client, userInfoEndpoint, accessToken));

                r.VerifyEqual("401", "401", ((int)otherHtu.StatusCode).ToString());

                r.Step("(7) 正しい証明なら使える");

                HttpResponseMessage ok = await TestResourceTests.CallAsync(client, resource, "DPoP " + accessToken,
                    TestResourceTests.Proof(client, resource, accessToken));

                r.VerifyEqual("200", "200", ((int)ok.StatusCode).ToString());

                r.Done();
            }
        }

        #endregion

        #region 部品

        /// <summary>/TestResource を、ヘッダを指定して呼ぶ</summary>
        /// <param name="client">IdPClient</param>
        /// <param name="resource">口の URL（htu と同じ）</param>
        /// <param name="authorization">Authorization ヘッダの値</param>
        /// <param name="proof">DPoP ヘッダの値（null なら付けない）</param>
        /// <returns>応答</returns>
        private static Task<HttpResponseMessage> CallAsync(
            IdPClient client, string resource, string authorization, string proof)
        {
            Dictionary<string, string> headers = new Dictionary<string, string>()
            {
                { "Authorization", authorization }
            };

            if (proof != null)
            {
                headers.Add("DPoP", proof);
            }

            return client.GetAsync(client.ToLocalUrl(resource), headers);
        }

        /// <summary>DPoP の証明を作る（GET・ath 付き）</summary>
        /// <param name="client">IdPClient</param>
        /// <param name="htu">宛先</param>
        /// <param name="accessToken">ath の材料</param>
        /// <param name="es256">true なら ES256（トークンを縛った鍵）、false なら RS256（別の鍵）</param>
        /// <returns>証明</returns>
        private static string Proof(IdPClient client, string htu, string accessToken, bool es256 = true)
        {
            string ath;

            using (SHA256 sha256 = SHA256.Create())
            {
                ath = Base64Url.Encode(sha256.ComputeHash(Encoding.ASCII.GetBytes(accessToken)));
            }

            return JwsSigner.SignDPoP(client, new Dictionary<string, object>()
            {
                { "jti", Guid.NewGuid().ToString("N") },
                { "htm", "GET" },
                { "htu", htu },
                { "iat", DateTimeOffset.UtcNow.ToUnixTimeSeconds() },
                { "ath", ath }
            }, es256);
        }

        /// <summary>JSON の本文から文字列の値を読む（無ければ空）</summary>
        /// <param name="body">本文</param>
        /// <param name="name">名前</param>
        /// <returns>値</returns>
        private static string StringOf(string body, string name)
        {
            try
            {
                using (JsonDocument doc = JsonDocument.Parse(body))
                {
                    return doc.RootElement.TryGetProperty(name, out JsonElement value)
                        && value.ValueKind == JsonValueKind.String ? value.GetString() : "";
                }
            }
            catch (JsonException)
            {
                return "";
            }
        }

        #endregion
    }
}
