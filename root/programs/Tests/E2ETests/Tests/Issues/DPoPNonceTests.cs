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
//* クラス名        ：DPoPNonceTests
//* クラス日本語名  ：RT-311 DPoP（RFC 9449）の段階 4（チャレンジと nonce）
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
    /// | **`RT-311.13`** | **`/token` で `nonce` を要求する**（`use_dpop_nonce` ＋ `DPoP-Nonce`。§8） |
    /// | **`RT-311.14`** | **保護されたリソースで `nonce` を要求する**（§9）。**`/token` の nonce は通らない** |
    ///
    /// **nonce は既定では要求しない**（**要求すると、nonce を知らないクライアントが全部止まる**）。
    /// **だから、要求する設定で起動して測る** —
    /// **`test.ps1 -Launch -DPoPNonce -Filter "FullyQualifiedName~DPoPNonceTests"`。**
    ///
    /// **付けなければ、このクラスは走らない**（`test.ps1` が除外する）。
    /// **xUnit は「ケースが 0 件の Theory」を失敗として数える**ので、
    /// **ケースを作らないのではなく、クラスごと外す**（`LifetimeTests` と同じ流儀）。
    ///
    /// **チャレンジのスキーム（`RT-311.12`）は、いつでも測れる**ので別のクラスに在る
    /// （`DPoPChallengeTests`）。
    /// </remarks>
    public class DPoPNonceTests : TargetTestBase
    {
        /// <summary>コンストラクタ</summary>
        /// <param name="output">ITestOutputHelper</param>
        public DPoPNonceTests(ITestOutputHelper output) : base(output)
        {
        }

        /// <summary>測る対象 : `-DPoPNonce` で起動したときだけ</summary>
        public static IEnumerable<object[]> NonceTargets
        {
            get
            {
                if (Environment.GetEnvironmentVariable("MPAS_DPOP_NONCE") == "true")
                {
                    yield return new object[] { TestEnv.CoreKey };
                    yield return new object[] { TestEnv.NetFxKey };
                }
            }
        }

        #region RT-311.13

        /// <summary>RT-311.13 /token が nonce を要求する</summary>
        /// <param name="targetKey">core / netfx</param>
        /// <returns>Task</returns>
        [SkippableTheory]
        [MemberData(nameof(NonceTargets))]
        public async Task RT31113_tokenがnonceを要求する(string targetKey)
        {
            using (IdPClient client = await this.SignedInClientAsync(targetKey))
            {
                TestReport r = this.Report("RT-311.13",
                    "**`nonce` を要求する配備では、`/token` は `use_dpop_nonce` で断り、"
                    + "`DPoP-Nonce` で値を渡す**。"
                    + "**その値を入れて出し直せば通る**（**code は消費されていない**）。"
                    + "**保護されたリソースの nonce は、ここでは通らない**",
                    "**`nonce` は「サーバが今出した値」を証明に入れさせる仕掛け**である"
                    + "（RFC 9449 §8） — **写し取った証明が、後から使えなくなる。**"
                    + "**断りで code を消費してしまうと、言われたとおり出し直しても通らない。**"
                    + "**`/token` と保護されたリソースの nonce は別物**（§9） — "
                    + "**混ぜると、片方で貰った値がもう片方で通ってしまう。**",
                    "RFC 9449 §8 / #311 の段階 4");

                ClientRegistration reg = Flows.Registration(client, KnownClients.TestClient);
                string tokenEndpoint = await DPoPNonceTests.EndpointAsync(client, "token_endpoint");
                string userInfoEndpoint = await DPoPNonceTests.EndpointAsync(client, "userinfo_endpoint");

                r.Target("POST /token（`nonce` を要求する配備）");

                r.Step("(1) nonce 無しの証明で出す");

                string code = await DPoPNonceTests.CodeAsync(client, reg, "nonce-rt31113");

                JsonResponse denied = await DPoPNonceTests.TokenAsync(
                    client, reg, tokenEndpoint, code,
                    DPoPNonceTests.Proof(client, tokenEndpoint, null));

                r.VerifyEqual("use_dpop_nonce", "use_dpop_nonce", denied.Error ?? "なし");

                r.VerifyEqual("400", "400", ((int)denied.StatusCode).ToString());

                string nonce = denied.Header("DPoP-Nonce");

                r.Verify("`DPoP-Nonce` が返る", !string.IsNullOrEmpty(nonce),
                    "返る", string.IsNullOrEmpty(nonce) ? "**無い**" : "返る（値は出さない）");

                r.Step("(2) 貰った nonce を入れて、**同じ code で**出し直す");

                JsonResponse ok = await DPoPNonceTests.TokenAsync(
                    client, reg, tokenEndpoint, code,
                    DPoPNonceTests.Proof(client, tokenEndpoint, nonce));

                r.VerifyEqual("200（code は消費されていない）", "200",
                    ((int)ok.StatusCode).ToString());

                r.VerifyEqual("token_type が DPoP", "DPoP", ok.String("token_type") ?? "なし");

                r.Step("(3) 保護されたリソースの nonce を、`/token` で使う");

                string rsNonce = await DPoPNonceTests.ResourceNonceAsync(
                    client, userInfoEndpoint, ok.AccessToken);

                Skip.If(string.IsNullOrEmpty(rsNonce),
                    "保護されたリソースが DPoP-Nonce を返していません。");

                string code2 = await DPoPNonceTests.CodeAsync(client, reg, "nonce-rt31113-3");

                JsonResponse wrongSpace = await DPoPNonceTests.TokenAsync(
                    client, reg, tokenEndpoint, code2,
                    DPoPNonceTests.Proof(client, tokenEndpoint, rsNonce));

                r.VerifyEqual("use_dpop_nonce（用途が別）", "use_dpop_nonce",
                    wrongSpace.Error ?? "なし");

                r.Note("**`nonce` は、鍵と「いまの時間帯」から計算している**（**台帳を持たない**）。"
                    + "**使える長さは 5〜10 分**であり、"
                    + "**切れたら `use_dpop_nonce` で貰い直す**（**1 往復増える**）。");

                r.Note("**成功応答には、新しい nonce を載せていない**"
                    + "（RFC 9449 は SHOULD）。**窓が切れたときに 1 往復増える。**");

                r.Done();
            }
        }

        #endregion

        #region RT-311.14

        /// <summary>RT-311.14 保護されたリソースが nonce を要求する</summary>
        /// <param name="targetKey">core / netfx</param>
        /// <returns>Task</returns>
        [SkippableTheory]
        [MemberData(nameof(NonceTargets))]
        public async Task RT31114_保護されたリソースがnonceを要求する(string targetKey)
        {
            using (IdPClient client = await this.SignedInClientAsync(targetKey))
            {
                TestReport r = this.Report("RT-311.14",
                    "**`nonce` を要求する配備では、保護されたリソースは "
                    + "`401` ＋ `WWW-Authenticate: DPoP error=\"use_dpop_nonce\"` ＋ `DPoP-Nonce` で答える**。"
                    + "**その値を入れれば通る**。**`/token` の nonce は通らない**",
                    "**保護されたリソースの断りは `401`**（**チャレンジである**。RFC 9449 §9） — "
                    + "**`/token` の `400` とは違う。**"
                    + "**同じ `use_dpop_nonce` でも、口によって状態が違う**ので、"
                    + "**口の側で決めている。**",
                    "RFC 9449 §9 / #311 の段階 4");

                string userInfoEndpoint = await DPoPNonceTests.EndpointAsync(client, "userinfo_endpoint");
                string tokenEndpoint = await DPoPNonceTests.EndpointAsync(client, "token_endpoint");
                string accessToken = await DPoPNonceTests.BoundTokenAsync(client);

                r.Target("GET /userinfo（`nonce` を要求する配備）");

                r.Step("(1) nonce 無しの証明で出す");

                HttpResponseMessage denied = await DPoPNonceTests.UserInfoAsync(
                    client, userInfoEndpoint, "DPoP " + accessToken,
                    DPoPNonceTests.Proof(client, userInfoEndpoint, null, "GET", accessToken));

                r.VerifyEqual("401（チャレンジである）", "401",
                    ((int)denied.StatusCode).ToString());

                string challenge = DPoPNonceTests.HeaderOf(denied, "WWW-Authenticate") ?? "";

                r.Verify("スキームが DPoP", challenge.StartsWith("DPoP ", StringComparison.Ordinal),
                    "DPoP", challenge.Split(' ')[0]);

                r.Verify("`error=\"use_dpop_nonce\"` が在る",
                    challenge.Contains("use_dpop_nonce"),
                    "在る", challenge.Contains("use_dpop_nonce") ? "在る" : "**無い**");

                string nonce = DPoPNonceTests.HeaderOf(denied, "DPoP-Nonce");

                r.Verify("`DPoP-Nonce` が返る", !string.IsNullOrEmpty(nonce),
                    "返る", string.IsNullOrEmpty(nonce) ? "**無い**" : "返る（値は出さない）");

                r.Step("(2) 貰った nonce を入れて出し直す");

                HttpResponseMessage ok = await DPoPNonceTests.UserInfoAsync(
                    client, userInfoEndpoint, "DPoP " + accessToken,
                    DPoPNonceTests.Proof(client, userInfoEndpoint, nonce, "GET", accessToken));

                r.VerifyEqual("200", "200", ((int)ok.StatusCode).ToString());

                r.Step("(3) `/token` の nonce を、保護されたリソースで使う");

                string asNonce = await DPoPNonceTests.TokenNonceAsync(client, tokenEndpoint);

                Skip.If(string.IsNullOrEmpty(asNonce), "`/token` が DPoP-Nonce を返していません。");

                HttpResponseMessage wrongSpace = await DPoPNonceTests.UserInfoAsync(
                    client, userInfoEndpoint, "DPoP " + accessToken,
                    DPoPNonceTests.Proof(client, userInfoEndpoint, asNonce, "GET", accessToken));

                r.VerifyEqual("401（用途が別）", "401", ((int)wrongSpace.StatusCode).ToString());

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
            string tokenEndpoint = await DPoPNonceTests.EndpointAsync(client, "token_endpoint");
            string code = await DPoPNonceTests.CodeAsync(client, reg, "nonce-dpop-challenge");

            JsonResponse token = await DPoPNonceTests.TokenAsync(
                client, reg, tokenEndpoint,
                code, DPoPNonceTests.Proof(client, tokenEndpoint, null));

            if (token.Error == "use_dpop_nonce")
            {
                token = await DPoPNonceTests.TokenAsync(
                    client, reg, tokenEndpoint, code,
                    DPoPNonceTests.Proof(client, tokenEndpoint, token.Header("DPoP-Nonce")));
            }

            Assert.Equal("DPoP", token.String("token_type"));
            Assert.False(string.IsNullOrEmpty(token.AccessToken),
                "前提: access_token が取得できること");

            return token.AccessToken;
        }

        /// <summary>`/token` が返す nonce（断られた応答から取る）</summary>
        /// <param name="client">IdPClient</param>
        /// <param name="tokenEndpoint">広告された token_endpoint</param>
        /// <returns>nonce（無ければ空）</returns>
        private static async Task<string> TokenNonceAsync(IdPClient client, string tokenEndpoint)
        {
            ClientRegistration reg = Flows.Registration(client, KnownClients.TestClient);

            JsonResponse denied = await DPoPNonceTests.TokenAsync(
                client, reg, tokenEndpoint, "not-a-code",
                DPoPNonceTests.Proof(client, tokenEndpoint, null));

            return denied.Header("DPoP-Nonce") ?? "";
        }

        /// <summary>保護されたリソースが返す nonce（断られた応答から取る）</summary>
        /// <param name="client">IdPClient</param>
        /// <param name="userInfoEndpoint">広告された userinfo_endpoint</param>
        /// <param name="accessToken">縛られた access_token</param>
        /// <returns>nonce（無ければ空）</returns>
        private static async Task<string> ResourceNonceAsync(
            IdPClient client, string userInfoEndpoint, string accessToken)
        {
            HttpResponseMessage denied = await DPoPNonceTests.UserInfoAsync(
                client, userInfoEndpoint, "DPoP " + accessToken,
                DPoPNonceTests.Proof(client, userInfoEndpoint, null, "GET", accessToken));

            return DPoPNonceTests.HeaderOf(denied, "DPoP-Nonce") ?? "";
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
                payload.Add("ath", DPoPNonceTests.Ath(accessToken));
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
