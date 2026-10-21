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
//* クラス名        ：DPoPResourceTests
//* クラス日本語名  ：RT-311 DPoP（RFC 9449）の段階 2（保護されたリソース）
//*
//* 作成日時        ：－
//* 作成者          ：－
//* 更新履歴        ：－
//*
//*  日時        更新者            内容
//*  ----------  ----------------  -------------------------------------------------
//*  2026/10/21  玄人 幸道         新規（#311 の段階 2）
//*  2026/10/21  玄人 幸道         Bearer ＋ 正しい証明のケースを追加（歯抜けで測り漏れが出た）
//**********************************************************************************

using System;
using System.Collections.Generic;
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
    /// <summary>
    /// RT-311. **DPoP の段階 2** — **保護されたリソースで照合する。**
    /// </summary>
    /// <remarks>
    /// **段階 1 では、縛った印（`cnf.jkt`）が付くだけ**だった。
    /// **段階 2 で、その印を見て拒む。**
    ///
    /// | | 測ること |
    /// |---|---|
    /// | **`RT-311.5`** | **縛ったトークンは、`Authorization: DPoP …` ＋ 証明（`ath` 付き）なら使える** |
    /// | **`RT-311.6`** | **出し方を変えると断られる**（`Bearer` で出す／証明なし／`ath` が違う／別の鍵／`htu` が別の口）。**正しい出し方なら、また使える** |
    /// | **`RT-311.7`** | **縛っていないトークンは、従来どおり `Bearer` で通る**（**既定の挙動を変えていない**） |
    ///
    /// **リソース側が足して見るのは 2 つ**である（RFC 9449 §7.1）。
    ///
    /// | | なぜ |
    /// |---|---|
    /// | **`ath` が、提示されたトークンの指紋と一致すること** | **別のトークンに付けた証明を使い回させない** |
    /// | **証明の鍵が、トークンの `cnf.jkt` と同じであること** | **これが「持ち主である」ことの確認** |
    /// </remarks>
    public class DPoPResourceTests : TargetTestBase
    {
        /// <summary>コンストラクタ</summary>
        /// <param name="output">ITestOutputHelper</param>
        public DPoPResourceTests(ITestOutputHelper output) : base(output)
        {
        }

        #region RT-311.5

        /// <summary>RT-311.5 縛ったトークンは、証明と一緒なら使える</summary>
        /// <param name="targetKey">core / netfx</param>
        /// <returns>Task</returns>
        [SkippableTheory]
        [MemberData(nameof(AllTargets))]
        public async Task RT31105_縛ったトークンは証明と一緒なら使える(string targetKey)
        {
            using (IdPClient client = await this.SignedInClientAsync(targetKey))
            {
                TestReport r = this.Report("RT-311.5",
                    "**`cnf.jkt` で縛ったトークンは、`Authorization: DPoP …` ＋ "
                    + "その鍵で署名した証明（`ath` 付き）を添えれば、`/userinfo` で使える**",
                    "**縛った結果が「使えなくなる」だけでは意味が無い。**"
                    + "**正しい持ち主は、これまでと同じことができなければならない。**"
                    + "**`ath` は、その証明がこのトークンのためのものだと示す**（§4.2） — "
                    + "**無ければ、別のトークンに付けた証明を使い回せる。**",
                    "RFC 9449 §7.1 / #311 の段階 2");

                string userInfoEndpoint = await DPoPResourceTests.EndpointAsync(client, "userinfo_endpoint");
                string accessToken = await DPoPResourceTests.BoundTokenAsync(client, r);

                r.Target("GET /userinfo（`Authorization: DPoP …` ＋ `DPoP` の証明）");

                r.Step("証明を添えて呼ぶ");

                HttpResponseMessage res = await DPoPResourceTests.UserInfoAsync(
                    client, userInfoEndpoint, "DPoP " + accessToken,
                    DPoPResourceTests.Proof(client, "GET", userInfoEndpoint, accessToken));

                r.VerifyEqual("HTTP 200", "200", ((int)res.StatusCode).ToString());

                string sub = await DPoPResourceTests.SubOf(res);

                r.Verify("sub が返る（利用者の情報が取れている）", !string.IsNullOrEmpty(sub),
                    "返る", string.IsNullOrEmpty(sub) ? "**無い**" : "返る（値は出さない）");

                r.Note("**`ath` は access_token の SHA-256 を BASE64URL したもの**（§4.2）。"
                    + "**`htm` は `GET`、`htu` は広告された `userinfo_endpoint`** である。");

                r.Done();
            }
        }

        #endregion

        #region RT-311.6

        /// <summary>RT-311.6 出し方を変えると断られる</summary>
        /// <param name="targetKey">core / netfx</param>
        /// <returns>Task</returns>
        [SkippableTheory]
        [MemberData(nameof(AllTargets))]
        public async Task RT31106_出し方を変えると断られる(string targetKey)
        {
            using (IdPClient client = await this.SignedInClientAsync(targetKey))
            {
                TestReport r = this.Report("RT-311.6",
                    "**縛ったトークンは、出し方を変えると断られる**"
                    + "（`Bearer` で出す／証明なし／`ath` が違う／別の鍵／`htu` が別の口）。"
                    + "**正しい出し方なら、また使える**",
                    "**縛りを「使う側の出し方」で外せてはいけない。**"
                    + "**`Bearer` で出せば通るなら、漏えいしたトークンはそのまま使える** — "
                    + "**縛った意味が無くなる。**"
                    + "**最後に正しい出し方で通ることまで見る** — "
                    + "**断りが「トークンを壊した」結果ではないことを、ここで押さえる。**",
                    "RFC 9449 §7.1 / #311 の段階 2");

                string userInfoEndpoint = await DPoPResourceTests.EndpointAsync(client, "userinfo_endpoint");
                string tokenEndpoint = await DPoPResourceTests.EndpointAsync(client, "token_endpoint");
                string accessToken = await DPoPResourceTests.BoundTokenAsync(client, r);

                r.Target("GET /userinfo（出し方を変える）");

                r.Step("(1) Bearer で出す（スキームを変える）");

                HttpResponseMessage asBearer = await DPoPResourceTests.UserInfoAsync(
                    client, userInfoEndpoint, "Bearer " + accessToken, null);

                r.VerifyEqual("401", "401", ((int)asBearer.StatusCode).ToString());

                r.Step("(1-b) Bearer で出すが、正しい証明を添える");

                //  **ここが歯抜けで見つかった測り漏れ**である（#311 の段階 2）。
                //    **証明を添えずに `Bearer` で出す**（(1)）のは、**証明が無いから落ちる。**
                //    **スキームを見ているかどうかは、証明を添えて初めて分かる。**
                HttpResponseMessage bearerWithProof = await DPoPResourceTests.UserInfoAsync(
                    client, userInfoEndpoint, "Bearer " + accessToken,
                    DPoPResourceTests.Proof(client, "GET", userInfoEndpoint, accessToken));

                r.VerifyEqual("401（スキームを見ている）", "401",
                    ((int)bearerWithProof.StatusCode).ToString());

                r.Step("(2) DPoP スキームだが、証明が無い");

                HttpResponseMessage noProof = await DPoPResourceTests.UserInfoAsync(
                    client, userInfoEndpoint, "DPoP " + accessToken, null);

                r.VerifyEqual("401", "401", ((int)noProof.StatusCode).ToString());

                r.Step("(3) ath が、別のトークンの指紋");

                HttpResponseMessage otherAth = await DPoPResourceTests.UserInfoAsync(
                    client, userInfoEndpoint, "DPoP " + accessToken,
                    DPoPResourceTests.Proof(client, "GET", userInfoEndpoint, accessToken + "x"));

                r.VerifyEqual("401", "401", ((int)otherAth.StatusCode).ToString());

                r.Step("(4) 別の鍵（RSA）で署名した証明");

                HttpResponseMessage otherKey = await DPoPResourceTests.UserInfoAsync(
                    client, userInfoEndpoint, "DPoP " + accessToken,
                    DPoPResourceTests.Proof(
                        client, "GET", userInfoEndpoint, accessToken, es256: false));

                r.VerifyEqual("401", "401", ((int)otherKey.StatusCode).ToString());

                r.Step("(5) htu が別の口（/token への証明）");

                HttpResponseMessage otherHtu = await DPoPResourceTests.UserInfoAsync(
                    client, userInfoEndpoint, "DPoP " + accessToken,
                    DPoPResourceTests.Proof(client, "GET", tokenEndpoint, accessToken));

                r.VerifyEqual("401", "401", ((int)otherHtu.StatusCode).ToString());

                r.Step("(6) 正しい出し方なら、また使える");

                HttpResponseMessage ok = await DPoPResourceTests.UserInfoAsync(
                    client, userInfoEndpoint, "DPoP " + accessToken,
                    DPoPResourceTests.Proof(client, "GET", userInfoEndpoint, accessToken));

                r.VerifyEqual("200", "200", ((int)ok.StatusCode).ToString());

                r.Note("**(4) は「鍵が違う」**のであって、**署名が壊れているのではない** — "
                    + "**証明そのものは正しく、`cnf.jkt` と合わない**だけである。");

                r.Note("**`WWW-Authenticate` のスキームは `Bearer` のまま**である"
                    + "（RFC 9449 §7.1 は `DPoP` を求めている）。"
                    + "**`DPoP-Nonce` を返す段階 4 で直す** — "
                    + "**チャレンジに `algs` と `nonce` を載せるのは、そこで要るため。**");

                r.Done();
            }
        }

        #endregion

        #region RT-311.7

        /// <summary>RT-311.7 縛っていないトークンは従来どおり</summary>
        /// <param name="targetKey">core / netfx</param>
        /// <returns>Task</returns>
        [SkippableTheory]
        [MemberData(nameof(AllTargets))]
        public async Task RT31107_縛っていないトークンは従来どおり(string targetKey)
        {
            using (IdPClient client = await this.SignedInClientAsync(targetKey))
            {
                TestReport r = this.Report("RT-311.7",
                    "**縛っていないトークンは、従来どおり `Bearer` で `/userinfo` が通る**",
                    "**段階 2 の約束は「縛ったものだけを縛る」**ことである。"
                    + "**DPoP を知らないクライアントが、照合を入れた途端に動かなくなってはならない。**",
                    "RFC 9449 §7.1 / #311 の段階 2");

                string userInfoEndpoint = await DPoPResourceTests.EndpointAsync(client, "userinfo_endpoint");

                r.Target("GET /userinfo（証明なしで取ったトークン）");

                r.Step("(1) 証明を添えずにトークンを取る");

                JsonResponse token = await Flows.RunAuthorizationCodeFlowAsync(
                    client, KnownClients.TestClient, "openid email", "nonce-rt3117");

                Assert.False(string.IsNullOrEmpty(token.AccessToken),
                    "前提: access_token が取得できること");

                r.VerifyEqual("token_type が bearer", "bearer",
                    (token.String("token_type") ?? "なし").ToLower());

                r.Step("(2) Bearer で /userinfo を呼ぶ");

                HttpResponseMessage res = await DPoPResourceTests.UserInfoAsync(
                    client, userInfoEndpoint, "Bearer " + token.AccessToken, null);

                r.VerifyEqual("HTTP 200", "200", ((int)res.StatusCode).ToString());

                r.Verify("sub が返る", !string.IsNullOrEmpty(await DPoPResourceTests.SubOf(res)),
                    "返る", "返る");

                r.Step("(3) 縛っていないトークンを DPoP スキームで出した場合");

                HttpResponseMessage asDPoP = await DPoPResourceTests.UserInfoAsync(
                    client, userInfoEndpoint, "DPoP " + token.AccessToken,
                    DPoPResourceTests.Proof(
                        client, "GET", userInfoEndpoint, token.AccessToken));

                r.Observe("応答", ((int)asDPoP.StatusCode).ToString(),
                    "**仕様は、この場合を明示していない。** "
                    + "**この実装は通す**（**縛っていないトークンは、縛りを見ない**）。"
                    + "**判定にはしていない。**");

                r.Done();
            }
        }

        #endregion

        #region 私的なヘルパ

        /// <summary>Discovery が広告する口の URL</summary>
        /// <param name="client">IdPClient</param>
        /// <param name="name">項目名（`userinfo_endpoint` など）</param>
        /// <returns>URL</returns>
        /// <remarks>
        /// **サーバは設定から `htu` を作る**ので、**広告された値と同じ**である。
        /// **叩く先は `ToLocalUrl` で読み替える**（開発では待ち受けが違うことが在る）。
        /// </remarks>
        private static async Task<string> EndpointAsync(IdPClient client, string name)
        {
            JsonResponse res = await client.GetJsonAsync("/.well-known/openid-configuration");

            string endpoint = res.String(name);

            Skip.If(string.IsNullOrEmpty(endpoint),
                "Discovery が " + name + " を広告していません。");

            return endpoint;
        }

        /// <summary>DPoP に縛られた access_token を取る</summary>
        /// <param name="client">IdPClient</param>
        /// <param name="r">TestReport</param>
        /// <returns>access_token</returns>
        private static async Task<string> BoundTokenAsync(IdPClient client, TestReport r)
        {
            ClientRegistration reg = Flows.Registration(client, KnownClients.TestClient);
            string tokenEndpoint = await DPoPResourceTests.EndpointAsync(client, "token_endpoint");

            AuthZResponse authz = await Flows.AuthorizeCodeAsync(
                client, reg, "openid email", "state1", "nonce-dpop-res", reg.RedirectUri);

            Assert.False(string.IsNullOrEmpty(authz.Code),
                "前提: 認可コードが取得できること（" + authz.ToString() + "）");

            JsonResponse token = await client.PostJsonAsync(
                client.ToLocalUrl(tokenEndpoint),
                new Dictionary<string, string>()
                {
                    { "grant_type", "authorization_code" },
                    { "code", authz.Code },
                    { "client_id", reg.ClientId },
                    { "client_secret", reg.ClientSecret },
                    { "redirect_uri", reg.RedirectUri }
                },
                new Dictionary<string, string>()
                {
                    { "DPoP", DPoPResourceTests.Proof(client, "POST", tokenEndpoint, null) }
                });

            Assert.Equal("DPoP", token.String("token_type"));
            Assert.False(string.IsNullOrEmpty(token.AccessToken),
                "前提: access_token が取得できること");

            r.Note("**トークンは、認可コードの `/token` に証明を添えて取ったもの**である"
                + "（段階 1。`token_type` は `DPoP`）。");

            return token.AccessToken;
        }

        /// <summary>`/userinfo` を、ヘッダを指定して呼ぶ</summary>
        /// <param name="client">IdPClient</param>
        /// <param name="userInfoEndpoint">広告された userinfo_endpoint</param>
        /// <param name="authorization">`Authorization` ヘッダの値</param>
        /// <param name="proof">`DPoP` ヘッダの値（null なら付けない）</param>
        /// <returns>応答</returns>
        private static Task<HttpResponseMessage> UserInfoAsync(
            IdPClient client, string userInfoEndpoint, string authorization, string proof)
        {
            Dictionary<string, string> headers = new Dictionary<string, string>()
            {
                { "Authorization", authorization }
            };

            if (!string.IsNullOrEmpty(proof))
            {
                headers.Add("DPoP", proof);
            }

            return client.GetAsync(client.ToLocalUrl(userInfoEndpoint), headers);
        }

        /// <summary>DPoP の証明を作る（`ath` 付き）</summary>
        /// <param name="client">IdPClient</param>
        /// <param name="htm">HTTP メソッド</param>
        /// <param name="htu">宛先</param>
        /// <param name="accessToken">`ath` の材料（null なら `ath` を入れない）</param>
        /// <param name="es256">true なら ES256（既定）、false なら RS256（**別の鍵**）</param>
        /// <returns>証明</returns>
        private static string Proof(
            IdPClient client, string htm, string htu, string accessToken, bool es256 = true)
        {
            Dictionary<string, object> payload = new Dictionary<string, object>()
            {
                { "jti", Guid.NewGuid().ToString("N") },
                { "htm", htm },
                { "htu", htu },
                { "iat", DateTimeOffset.UtcNow.ToUnixTimeSeconds() }
            };

            if (accessToken != null)
            {
                payload.Add("ath", DPoPResourceTests.Ath(accessToken));
            }

            return JwsSigner.SignDPoP(client, payload, es256);
        }

        /// <summary>`ath`（access_token の指紋。RFC 9449 §4.2）</summary>
        /// <param name="accessToken">access_token</param>
        /// <returns>BASE64URL(SHA-256(access_token))</returns>
        /// <remarks>**サーバと同じ計算を、テスト側でも独立に行う。**</remarks>
        private static string Ath(string accessToken)
        {
            using (SHA256 sha256 = SHA256.Create())
            {
                return Base64Url.Encode(
                    sha256.ComputeHash(Encoding.ASCII.GetBytes(accessToken)));
            }
        }

        /// <summary>応答の `sub`（無ければ空）</summary>
        /// <param name="res">応答</param>
        /// <returns>sub</returns>
        private static async Task<string> SubOf(HttpResponseMessage res)
        {
            string body = await res.Content.ReadAsStringAsync();

            try
            {
                using (JsonDocument doc = JsonDocument.Parse(body))
                {
                    return doc.RootElement.TryGetProperty("sub", out JsonElement sub)
                        ? (sub.GetString() ?? "") : "";
                }
            }
            catch
            {
                // JSON でない（エラーの本文など）。
                return "";
            }
        }

        #endregion
    }
}
