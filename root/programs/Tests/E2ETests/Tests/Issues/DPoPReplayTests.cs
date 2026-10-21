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
//* クラス名        ：DPoPReplayTests
//* クラス日本語名  ：RT-311 DPoP（RFC 9449）の段階 3（証明の使い回し）
//*
//* 作成日時        ：－
//* 作成者          ：－
//* 更新履歴        ：－
//*
//*  日時        更新者            内容
//*  ----------  ----------------  -------------------------------------------------
//*  2026/10/22  玄人 幸道         新規（#311 の段階 3）
//**********************************************************************************

using System;
using System.Collections.Generic;
using System.Net.Http;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

using MultiPurposeAuthSite.Tests.E2E.Infrastructure;

using Xunit;
using Xunit.Abstractions;

namespace MultiPurposeAuthSite.Tests.E2E.Tests.Issues
{
    /// <summary>
    /// RT-311. **DPoP の段階 3** — **一度使った証明を、二度と通さない。**
    /// </summary>
    /// <remarks>
    /// **段階 1・2 は、証明が「正しいこと」しか見ていなかった** —
    /// **正しい証明を横から写し取れば、そのまま通せた**（RFC 9449 §11.1）。
    ///
    /// | | 測ること |
    /// |---|---|
    /// | **`RT-311.8`** | **同じ証明は 2 回目で断られる**（`/userinfo` と `/token` の両方）。**新しい `jti` なら通る**。**壊れた証明の `jti` は焼かれない** |
    /// | **`RT-311.9`** | **台帳は鍵ごと**である（**別の鍵が同じ `jti` を使っても、互いを塞がない**） |
    ///
    /// **`RT-311.9` は「作りの選択」を測っている。**
    /// **`jti` だけを台帳の鍵にすると、`jti` の値はクライアントが決めるので、
    /// 先に使われた値は他の相手が使えなくなる** — **それだけで相手を塞げてしまう。**
    /// </remarks>
    public class DPoPReplayTests : TargetTestBase
    {
        /// <summary>コンストラクタ</summary>
        /// <param name="output">ITestOutputHelper</param>
        public DPoPReplayTests(ITestOutputHelper output) : base(output)
        {
        }

        #region RT-311.8

        /// <summary>RT-311.8 同じ証明は 2 回目で断られる</summary>
        /// <param name="targetKey">core / netfx</param>
        /// <returns>Task</returns>
        [SkippableTheory]
        [MemberData(nameof(AllTargets))]
        public async Task RT31108_同じ証明は2回目で断られる(string targetKey)
        {
            using (IdPClient client = await this.SignedInClientAsync(targetKey))
            {
                TestReport r = this.Report("RT-311.8",
                    "**一度使った証明は、二度と通らない**"
                    + "（`/userinfo` と `/token` の両方）。"
                    + "**新しい `jti` なら通る。** "
                    + "**検証に通らなかった証明の `jti` は、焼かれない**",
                    "**証明が「正しいこと」だけを見ていると、横から写し取った証明がそのまま通る**"
                    + "（RFC 9449 §11.1）。"
                    + "**縛りは「鍵を持っていること」の確認であって、"
                    + "「証明という文字列を持っていること」の確認ではない。**"
                    + "**焼くのは通った証明だけ**でなければならない — "
                    + "**壊した証明を投げるだけで相手の `jti` を使えなくできるなら、"
                    + "それは別の邪魔立てになる。**",
                    "RFC 9449 §11.1 / #311 の段階 3");

                string userInfoEndpoint = await DPoPReplayTests.EndpointAsync(client, "userinfo_endpoint");
                string tokenEndpoint = await DPoPReplayTests.EndpointAsync(client, "token_endpoint");
                string accessToken = await DPoPReplayTests.BoundTokenAsync(client);

                r.Target("GET /userinfo（同じ証明を 2 回）");

                string proof = DPoPReplayTests.Proof(
                    client, "GET", userInfoEndpoint, accessToken);

                r.Step("(1) 証明を添えて呼ぶ");

                HttpResponseMessage first = await DPoPReplayTests.UserInfoAsync(
                    client, userInfoEndpoint, "DPoP " + accessToken, proof);

                r.VerifyEqual("200", "200", ((int)first.StatusCode).ToString());

                r.Step("(2) **同じ証明をもう一度** 添えて呼ぶ");

                HttpResponseMessage again = await DPoPReplayTests.UserInfoAsync(
                    client, userInfoEndpoint, "DPoP " + accessToken, proof);

                r.VerifyEqual("401（使い回しは断る）", "401",
                    ((int)again.StatusCode).ToString());

                r.Step("(3) 新しい `jti` の証明なら、また使える");

                HttpResponseMessage fresh = await DPoPReplayTests.UserInfoAsync(
                    client, userInfoEndpoint, "DPoP " + accessToken,
                    DPoPReplayTests.Proof(client, "GET", userInfoEndpoint, accessToken));

                r.VerifyEqual("200", "200", ((int)fresh.StatusCode).ToString());

                r.Note("**(3) が通ることで、(2) の断りが「使い回し」に対するものだと分かる** — "
                    + "**トークンも鍵も壊れていない。**");

                r.Target("POST /token（同じ証明を 2 回）");

                ClientRegistration reg = Flows.Registration(client, KnownClients.TestClient);

                string tokenProof = DPoPReplayTests.Proof(client, "POST", tokenEndpoint, null);

                r.Step("(4) 認可コードを 2 本取り、同じ証明で 2 回 `/token` を叩く");

                JsonResponse okToken = await DPoPReplayTests.TokenAsync(
                    client, reg, tokenEndpoint, tokenProof);

                r.VerifyEqual("1 回目は 200", "200", ((int)okToken.StatusCode).ToString());

                r.VerifyEqual("1 回目の token_type は DPoP", "DPoP",
                    okToken.String("token_type") ?? "なし");

                JsonResponse deniedToken = await DPoPReplayTests.TokenAsync(
                    client, reg, tokenEndpoint, tokenProof);

                r.VerifyEqual("2 回目は invalid_dpop_proof",
                    "invalid_dpop_proof", deniedToken.Error ?? "なし");

                r.VerifyEqual("2 回目は 400", "400",
                    ((int)deniedToken.StatusCode).ToString());

                r.Note("**別の認可コードで叩いている** — "
                    + "**断りの理由はコードではなく、証明の使い回しである。**");

                r.Target("GET /userinfo（壊れた証明の `jti`）");

                r.Step("(5) 同じ `jti` で、まず壊れた証明（`htu` が別の口）を投げる");

                string sharedJti = Guid.NewGuid().ToString("N");

                HttpResponseMessage brokenRes = await DPoPReplayTests.UserInfoAsync(
                    client, userInfoEndpoint, "DPoP " + accessToken,
                    DPoPReplayTests.Proof(
                        client, "GET", tokenEndpoint, accessToken, jti: sharedJti));

                r.VerifyEqual("401（`htu` が合わない）", "401",
                    ((int)brokenRes.StatusCode).ToString());

                r.Step("(6) **同じ `jti`** で、正しい証明を投げる");

                HttpResponseMessage sameJtiRes = await DPoPReplayTests.UserInfoAsync(
                    client, userInfoEndpoint, "DPoP " + accessToken,
                    DPoPReplayTests.Proof(
                        client, "GET", userInfoEndpoint, accessToken, jti: sharedJti));

                r.VerifyEqual("200（焼けるのは通った証明だけ）", "200",
                    ((int)sameJtiRes.StatusCode).ToString());

                r.Note("**記録は、検証の最後に行っている** — "
                    + "**先に記録すると、壊した証明を投げるだけで相手の `jti` を奪える。**");

                r.Done();
            }
        }

        #endregion

        #region RT-311.9

        /// <summary>RT-311.9 台帳は鍵ごとである</summary>
        /// <param name="targetKey">core / netfx</param>
        /// <returns>Task</returns>
        [SkippableTheory]
        [MemberData(nameof(AllTargets))]
        public async Task RT31109_台帳は鍵ごとである(string targetKey)
        {
            using (IdPClient client = await this.SignedInClientAsync(targetKey))
            {
                TestReport r = this.Report("RT-311.9",
                    "**別の鍵が同じ `jti` を使っても、互いを塞がない**"
                    + "（**台帳は「鍵 × `jti`」で持つ**）",
                    "**`jti` の値はクライアントが決める。**"
                    + "**`jti` だけを台帳の鍵にすると、先に使われた値は他の相手が使えなくなる** — "
                    + "**よく使われる値を先に撃つだけで、相手の要求を断らせられる。**"
                    + "**RFC 9449 §11.1 も、証明の公開鍵と組にして持つことを挙げている。**",
                    "RFC 9449 §11.1 / #311 の段階 3");

                string userInfoEndpoint = await DPoPReplayTests.EndpointAsync(client, "userinfo_endpoint");

                r.Target("GET /userinfo（2 つの鍵が、同じ `jti` を使う）");

                r.Step("(1) 鍵の違う 2 本のトークンを取る（EC と RSA）");

                string ecToken = await DPoPReplayTests.BoundTokenAsync(client);
                string rsaToken = await DPoPReplayTests.BoundTokenAsync(client, es256: false);

                r.Verify("2 本とも取れた",
                    !string.IsNullOrEmpty(ecToken) && !string.IsNullOrEmpty(rsaToken),
                    "取れた", "取れた（値は出さない）");

                string sharedJti = Guid.NewGuid().ToString("N");

                r.Step("(2) EC の鍵で、その `jti` を使う");

                HttpResponseMessage ec = await DPoPReplayTests.UserInfoAsync(
                    client, userInfoEndpoint, "DPoP " + ecToken,
                    DPoPReplayTests.Proof(
                        client, "GET", userInfoEndpoint, ecToken, jti: sharedJti));

                r.VerifyEqual("200", "200", ((int)ec.StatusCode).ToString());

                r.Step("(3) **RSA の鍵で、同じ `jti`** を使う");

                HttpResponseMessage rsa = await DPoPReplayTests.UserInfoAsync(
                    client, userInfoEndpoint, "DPoP " + rsaToken,
                    DPoPReplayTests.Proof(
                        client, "GET", userInfoEndpoint, rsaToken,
                        es256: false, jti: sharedJti));

                r.VerifyEqual("200（鍵が違えば塞がらない）", "200",
                    ((int)rsa.StatusCode).ToString());

                r.Step("(4) EC の鍵で、その `jti` をもう一度");

                HttpResponseMessage ecAgain = await DPoPReplayTests.UserInfoAsync(
                    client, userInfoEndpoint, "DPoP " + ecToken,
                    DPoPReplayTests.Proof(
                        client, "GET", userInfoEndpoint, ecToken, jti: sharedJti));

                r.VerifyEqual("401（同じ鍵なら、やはり断る）", "401",
                    ((int)ecAgain.StatusCode).ToString());

                r.Note("**(3) と (4) を並べることで、"
                    + "台帳が効いていることと、鍵ごとに別であることが、同時に見える。**"
                    + "**`jti` だけを鍵にしていたら、(3) が 401 になる。**");

                r.Done();
            }
        }

        #endregion

        #region 私的なヘルパ

        /// <summary>Discovery が広告する口の URL</summary>
        /// <param name="client">IdPClient</param>
        /// <param name="name">項目名（`userinfo_endpoint` など）</param>
        /// <returns>URL</returns>
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
        /// <param name="es256">true なら EC（既定）、false なら RSA の鍵で縛る</param>
        /// <returns>access_token</returns>
        private static async Task<string> BoundTokenAsync(
            IdPClient client, bool es256 = true)
        {
            ClientRegistration reg = Flows.Registration(client, KnownClients.TestClient);
            string tokenEndpoint = await DPoPReplayTests.EndpointAsync(client, "token_endpoint");

            JsonResponse token = await DPoPReplayTests.TokenAsync(
                client, reg, tokenEndpoint,
                DPoPReplayTests.Proof(client, "POST", tokenEndpoint, null, es256));

            Assert.Equal("DPoP", token.String("token_type"));
            Assert.False(string.IsNullOrEmpty(token.AccessToken),
                "前提: access_token が取得できること");

            return token.AccessToken;
        }

        /// <summary>認可コードを取り、`/token` を証明付きで叩く</summary>
        /// <param name="client">IdPClient</param>
        /// <param name="reg">クライアントの登録</param>
        /// <param name="tokenEndpoint">広告された token_endpoint</param>
        /// <param name="proof">`DPoP` ヘッダの値</param>
        /// <returns>応答</returns>
        /// <remarks>
        /// **コードは呼ぶたびに取り直す** — **使い回しを測るのは証明の方**であり、
        /// **コードの使い回しで断られては、何を測ったのか分からない。**
        /// </remarks>
        private static async Task<JsonResponse> TokenAsync(
            IdPClient client, ClientRegistration reg, string tokenEndpoint, string proof)
        {
            AuthZResponse authz = await Flows.AuthorizeCodeAsync(
                client, reg, "openid email", "state1", "nonce-dpop-replay", reg.RedirectUri);

            Assert.False(string.IsNullOrEmpty(authz.Code),
                "前提: 認可コードが取得できること（" + authz.ToString() + "）");

            return await client.PostJsonAsync(
                client.ToLocalUrl(tokenEndpoint),
                new Dictionary<string, string>()
                {
                    { "grant_type", "authorization_code" },
                    { "code", authz.Code },
                    { "client_id", reg.ClientId },
                    { "client_secret", reg.ClientSecret },
                    { "redirect_uri", reg.RedirectUri }
                },
                new Dictionary<string, string>() { { "DPoP", proof } });
        }

        /// <summary>DPoP の証明を作る（`ath` 付き。`jti` も指定できる）</summary>
        /// <param name="client">IdPClient</param>
        /// <param name="htm">HTTP メソッド</param>
        /// <param name="htu">宛先</param>
        /// <param name="accessToken">`ath` の材料（null なら `ath` を入れない）</param>
        /// <param name="es256">true なら ES256（既定）、false なら RS256（**別の鍵**）</param>
        /// <param name="jti">`jti`（null なら新しい値）</param>
        /// <returns>証明</returns>
        /// <remarks>
        /// **`jti` を指定できるようにしている**のが、段階 2 のヘルパとの違いである
        /// （**使い回しを作るには、同じ `jti` を 2 回使う必要が在る**）。
        /// </remarks>
        private static string Proof(
            IdPClient client, string htm, string htu, string accessToken,
            bool es256 = true, string jti = null)
        {
            Dictionary<string, object> payload = new Dictionary<string, object>()
            {
                { "jti", jti ?? Guid.NewGuid().ToString("N") },
                { "htm", htm },
                { "htu", htu },
                { "iat", DateTimeOffset.UtcNow.ToUnixTimeSeconds() }
            };

            if (accessToken != null)
            {
                payload.Add("ath", DPoPReplayTests.Ath(accessToken));
            }

            return JwsSigner.SignDPoP(client, payload, es256);
        }

        /// <summary>`ath`（access_token の指紋。RFC 9449 §4.2）</summary>
        /// <param name="accessToken">access_token</param>
        /// <returns>BASE64URL(SHA-256(access_token))</returns>
        private static string Ath(string accessToken)
        {
            using (SHA256 sha256 = SHA256.Create())
            {
                return Base64Url.Encode(
                    sha256.ComputeHash(Encoding.ASCII.GetBytes(accessToken)));
            }
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

        #endregion
    }
}
