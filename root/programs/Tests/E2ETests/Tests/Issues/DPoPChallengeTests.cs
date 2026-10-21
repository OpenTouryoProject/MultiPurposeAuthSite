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
//* クラス名        ：DPoPChallengeTests
//* クラス日本語名  ：RT-311 DPoP（RFC 9449）の段階 4（チャレンジのスキーム）
//*
//* 作成日時        ：－
//* 作成者          ：－
//* 更新履歴        ：－
//*
//*  日時        更新者            内容
//*  ----------  ----------------  -------------------------------------------------
//*  2026/10/22  玄人 幸道         新規（#311 の段階 4）
//**********************************************************************************

using System;
using System.Collections.Generic;
using System.Linq;
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
    /// RT-311. **DPoP の段階 4** — **チャレンジを `DPoP` にし、`nonce` を要求できるようにする。**
    /// </summary>
    /// <remarks>
    /// | | 測ること |
    /// |---|---|
    /// | **`RT-311.12`** | **`DPoP` スキームで来た要求には、`WWW-Authenticate: DPoP` ＋ `algs` で答える**（§7.1） |
    ///
    /// **`nonce` の方は、要求する設定で起動しないと測れない**ので、
    /// **別のクラスに分けてある**（`DPoPNonceTests`。`RT-311.13` / `RT-311.14`）。
    /// **xUnit は「ケースが 0 件の Theory」を失敗として数える**ので、
    /// **クラスごと外せるようにしてある**（`test.ps1` の除外。`LifetimeTests` と同じ流儀）。
    /// </remarks>
    public class DPoPChallengeTests : TargetTestBase
    {
        /// <summary>コンストラクタ</summary>
        /// <param name="output">ITestOutputHelper</param>
        public DPoPChallengeTests(ITestOutputHelper output) : base(output)
        {
        }

        #region RT-311.12

        /// <summary>RT-311.12 チャレンジのスキームが DPoP になる</summary>
        /// <param name="targetKey">core / netfx</param>
        /// <returns>Task</returns>
        [SkippableTheory]
        [MemberData(nameof(AllTargets))]
        public async Task RT31112_チャレンジのスキームがDPoPになる(string targetKey)
        {
            using (IdPClient client = await this.SignedInClientAsync(targetKey))
            {
                TestReport r = this.Report("RT-311.12",
                    "**`DPoP` スキームで来た要求を断るときは、"
                    + "`WWW-Authenticate: DPoP` ＋ `algs` で答える**。"
                    + "**`Bearer` で来た要求には、従来どおり `Bearer`**",
                    "**チャレンジは「次はこう出せ」と伝えるもの**である。"
                    + "**`DPoP` で出した相手に `Bearer` と答えては、何を直せばよいか分からない**"
                    + "（RFC 9449 §7.1）。"
                    + "**`algs` は、証明の署名に使える alg** — "
                    + "**クライアントが鍵の種類を選べる。**"
                    + "**`Bearer` しか知らない相手に `DPoP` を突き付けない**のも、同じ理由である。",
                    "RFC 9449 §7.1 / #311 の段階 4");

                string userInfoEndpoint = await DPoPChallengeTests.EndpointAsync(client, "userinfo_endpoint");
                string accessToken = await DPoPChallengeTests.BoundTokenAsync(client);

                r.Target("GET /userinfo（断られたときのチャレンジ）");

                r.Step("(1) `DPoP` スキームで、証明を添えずに出す");

                HttpResponseMessage asDPoP = await DPoPChallengeTests.UserInfoAsync(
                    client, userInfoEndpoint, "DPoP " + accessToken, null);

                r.VerifyEqual("401", "401", ((int)asDPoP.StatusCode).ToString());

                string challenge = DPoPChallengeTests.HeaderOf(asDPoP, "WWW-Authenticate") ?? "";

                r.Verify("スキームが DPoP", challenge.StartsWith("DPoP ", StringComparison.Ordinal),
                    "DPoP", challenge.Split(' ')[0]);

                r.Verify("`algs` が在る", challenge.Contains("algs=\""),
                    "在る", challenge.Contains("algs=\"") ? "在る" : "**無い**");

                r.Verify("`algs` に ES256 が在る", challenge.Contains("ES256"),
                    "在る", challenge.Contains("ES256") ? "在る" : "**無い**");

                r.Step("(2) `Bearer` スキームで出す");

                HttpResponseMessage asBearer = await DPoPChallengeTests.UserInfoAsync(
                    client, userInfoEndpoint, "Bearer " + accessToken, null);

                r.VerifyEqual("401", "401", ((int)asBearer.StatusCode).ToString());

                string bearerChallenge = DPoPChallengeTests.HeaderOf(asBearer, "WWW-Authenticate") ?? "";

                r.Verify("スキームは Bearer のまま",
                    bearerChallenge.StartsWith("Bearer ", StringComparison.Ordinal),
                    "Bearer", bearerChallenge.Split(' ')[0]);

                r.Verify("`algs` は入らない", !bearerChallenge.Contains("algs=\""),
                    "入らない", bearerChallenge.Contains("algs=\"") ? "**入っている**" : "入らない");

                r.Observe("`DPoP-Nonce` ヘッダ（既定では要求しない）",
                    DPoPChallengeTests.HeaderOf(asDPoP, "DPoP-Nonce") == null ? "無し" : "在り",
                    "**nonce を要求する配備でだけ付く**（`RT-311.13` / `RT-311.14`）。");

                r.Note("**両方のスキームを並べて広告はしない。** "
                    + "**できるが、`Bearer` だけを知るクライアントが 2 つ目を読めるとは限らず、"
                    + "得るものが無い。**");

                r.Done();
            }
        }

        #endregion

        #region 私的なヘルパ

        /// <summary>Discovery が広告する口の URL</summary>
        /// <param name="client">IdPClient</param>
        /// <param name="name">項目名</param>
        /// <returns>URL</returns>
        private static async Task<string> EndpointAsync(IdPClient client, string name)
        {
            JsonResponse res = await client.GetJsonAsync("/.well-known/openid-configuration");

            string endpoint = res.String(name);

            Skip.If(string.IsNullOrEmpty(endpoint),
                "Discovery が " + name + " を広告していません。");

            return endpoint;
        }

        /// <summary>DPoP に縛られた access_token を取る（nonce が要るなら貰い直す）</summary>
        /// <param name="client">IdPClient</param>
        /// <returns>access_token</returns>
        /// <remarks>
        /// **nonce を要求する配備でも通るようにしてある** —
        /// **1 回断られてから、貰った値で出し直す**（**まともなクライアントの振る舞い**）。
        /// </remarks>
        private static async Task<string> BoundTokenAsync(IdPClient client)
        {
            ClientRegistration reg = Flows.Registration(client, KnownClients.TestClient);
            string tokenEndpoint = await DPoPChallengeTests.EndpointAsync(client, "token_endpoint");
            string code = await DPoPChallengeTests.CodeAsync(client, reg, "nonce-dpop-challenge");

            JsonResponse token = await DPoPChallengeTests.TokenAsync(
                client, reg, tokenEndpoint,
                code, DPoPChallengeTests.Proof(client, tokenEndpoint, null));

            if (token.Error == "use_dpop_nonce")
            {
                token = await DPoPChallengeTests.TokenAsync(
                    client, reg, tokenEndpoint, code,
                    DPoPChallengeTests.Proof(client, tokenEndpoint, token.Header("DPoP-Nonce")));
            }

            Assert.Equal("DPoP", token.String("token_type"));
            Assert.False(string.IsNullOrEmpty(token.AccessToken),
                "前提: access_token が取得できること");

            return token.AccessToken;
        }

        /// <summary>認可コードを取る</summary>
        /// <param name="client">IdPClient</param>
        /// <param name="reg">クライアントの登録</param>
        /// <param name="nonce">OIDC の nonce（DPoP の nonce とは別物）</param>
        /// <returns>code</returns>
        private static async Task<string> CodeAsync(
            IdPClient client, ClientRegistration reg, string nonce)
        {
            AuthZResponse authz = await Flows.AuthorizeCodeAsync(
                client, reg, "openid email", "state1", nonce, reg.RedirectUri);

            Assert.False(string.IsNullOrEmpty(authz.Code),
                "前提: 認可コードが取得できること（" + authz.ToString() + "）");

            return authz.Code;
        }

        /// <summary>code を引き換える</summary>
        /// <param name="client">IdPClient</param>
        /// <param name="reg">クライアントの登録</param>
        /// <param name="tokenEndpoint">広告された token_endpoint</param>
        /// <param name="code">code</param>
        /// <param name="proof">`DPoP` ヘッダの値</param>
        /// <returns>応答</returns>
        private static Task<JsonResponse> TokenAsync(
            IdPClient client, ClientRegistration reg,
            string tokenEndpoint, string code, string proof)
        {
            return client.PostJsonAsync(
                client.ToLocalUrl(tokenEndpoint),
                new Dictionary<string, string>()
                {
                    { "grant_type", "authorization_code" },
                    { "code", code },
                    { "client_id", reg.ClientId },
                    { "client_secret", reg.ClientSecret },
                    { "redirect_uri", reg.RedirectUri }
                },
                new Dictionary<string, string>() { { "DPoP", proof } });
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

        /// <summary>DPoP の証明を作る（`nonce` を入れられる）</summary>
        /// <param name="client">IdPClient</param>
        /// <param name="htu">宛先</param>
        /// <param name="nonce">`nonce`（null / 空なら入れない）</param>
        /// <param name="htm">HTTP メソッド（既定 POST）</param>
        /// <param name="accessToken">`ath` の材料（null なら入れない）</param>
        /// <returns>証明</returns>
        private static string Proof(
            IdPClient client, string htu, string nonce,
            string htm = "POST", string accessToken = null)
        {
            Dictionary<string, object> payload = new Dictionary<string, object>()
            {
                { "jti", Guid.NewGuid().ToString("N") },
                { "htm", htm },
                { "htu", htu },
                { "iat", DateTimeOffset.UtcNow.ToUnixTimeSeconds() }
            };

            if (!string.IsNullOrEmpty(nonce))
            {
                payload.Add("nonce", nonce);
            }

            if (accessToken != null)
            {
                payload.Add("ath", DPoPChallengeTests.Ath(accessToken));
            }

            return JwsSigner.SignDPoP(client, payload);
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

        /// <summary>応答ヘッダ（無ければ null）</summary>
        /// <param name="res">応答</param>
        /// <param name="name">ヘッダ名</param>
        /// <returns>値（複数は ", " で連結）</returns>
        private static string HeaderOf(HttpResponseMessage res, string name)
        {
            if (res.Headers.TryGetValues(name, out IEnumerable<string> values))
            {
                return string.Join(", ", values);
            }

            return null;
        }

        #endregion
    }
}
