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
//* クラス名        ：DPoPParTests
//* クラス日本語名  ：RT-365 PAR の DPoP ヘッダの鍵に、認可コードを縛る（RFC 9449 §10.1）
//*
//* 作成日時        ：－
//* 作成者          ：－
//* 更新履歴        ：－
//*
//*  日時        更新者            内容
//*  ----------  ----------------  -------------------------------------------------
//*  2026/11/13  玄人 幸道         新規（#365）
//**********************************************************************************

using System;
using System.Collections.Generic;
using System.Text.Json;
using System.Threading.Tasks;

using MultiPurposeAuthSite.Tests.E2E.Infrastructure;

using Xunit;
using Xunit.Abstractions;

namespace MultiPurposeAuthSite.Tests.E2E.Tests.Issues
{
    /// <summary>
    /// RT-365. **PAR の `DPoP` ヘッダの鍵に、認可コードを縛る**（RFC 9449 §10.1）。
    /// </summary>
    /// <remarks>
    /// **PAR で `code` を鍵に縛る方法は 2 つある。** **サーバは両方を受けなければならない**（§10.1 の MUST）。
    ///
    /// | | 方法 | 以前 |
    /// |---|---|---|
    /// | (a) | **預ける要求に `dpop_jkt` を入れる** | **縛っていた**（#311 の段階 4。`RT-311.10`） |
    /// | (b) | **PAR の要求に `DPoP` ヘッダを付ける** | **見ていなかった**（#365） |
    ///
    /// | | 測ること |
    /// |---|---|
    /// | **`RT-365.1`** | **(b) で預けた `code` は、その鍵の証明でしか引き換えられない** |
    /// | **`RT-365.2`** | **(a) と (b) の両方が来て、指紋が違えば PAR で断る** |
    /// | **`RT-365.3`** | **PAR の証明も、`/token` と同じく確かめる**（`htu`・使い回し） |
    ///
    /// 適合性テスト（#350 の段階 4）の `ensure-mismatched-dpop-jkt-fails`・
    /// `ensure-token-endpoint-fails-with-mismatched-dpop-proof-jkt` に当たる。
    /// </remarks>
    public class DPoPParTests : TargetTestBase
    {
        /// <summary>コンストラクタ</summary>
        /// <param name="output">ITestOutputHelper</param>
        public DPoPParTests(ITestOutputHelper output) : base(output)
        {
        }

        #region RT-365.1

        /// <summary>RT-365.1 PAR の DPoP ヘッダの鍵に code が縛られる</summary>
        /// <param name="targetKey">core / netfx</param>
        /// <returns>Task</returns>
        [SkippableTheory]
        [MemberData(nameof(AllTargets))]
        public async Task RT36501_PARのDPoPヘッダの鍵にcodeが縛られる(string targetKey)
        {
            using (IdPClient client = await this.SignedInClientAsync(targetKey))
            {
                ClientRegistration reg = Flows.Registration(client, KnownClients.TestClient);

                //  **このテストは `prompt=none` を自分で送る**ので、先に同意を記録する（RT-229.1 と同じ）。
                await Flows.EnsureConsentAsync(client, reg);

                TestReport r = this.Report("RT-365.1",
                    "**PAR の要求に `DPoP` ヘッダを付けると、その `code` はその鍵の証明でしか引き換えられない**"
                    + "（別の鍵・証明なしは `invalid_grant`）。**ヘッダを付けない PAR は、従来どおり縛られない**",
                    "**§10.1 は、PAR の `DPoP` ヘッダの鍵の指紋を「`dpop_jkt` で渡されたもの」として扱えとしている** — "
                    + "**続くトークン要求は、同じ鍵の証明でなければ断る。**"
                    + "**以前はヘッダを見ておらず、`code` が鍵に縛られなかった**"
                    + "（**盗まれた `code` への備えの 1 つが効いていなかった**）。",
                    "RFC 9449 §10.1 / #365");

                string parEndpoint = await DPoPParTests.ParEndpointAsync(client);
                string tokenEndpoint = await DPoPParTests.TokenEndpointAsync(client);
                string ecJkt = JwsSigner.DPoPJkt(client);

                r.Target("POST /par（`DPoP` ヘッダ付き） → /authorize → POST /token");

                r.Step("(1) EC の鍵の証明を付けて PAR に預け、その code を EC の証明で引き換える");

                string code = await DPoPParTests.CodeViaParAsync(client, reg, parEndpoint,
                    DPoPParTests.Proof(client, parEndpoint), null, "state-rt3651-1");

                JsonResponse ok = await DPoPParTests.TokenAsync(client, reg, tokenEndpoint, code,
                    DPoPParTests.Proof(client, tokenEndpoint));

                r.VerifyEqual("HTTP 200", "200", ((int)ok.StatusCode).ToString());

                r.VerifyEqual("token_type が DPoP", "DPoP", ok.String("token_type") ?? "なし");

                r.VerifyEqual("cnf.jkt が PAR の証明の鍵の指紋と一致する",
                    "一致", (DPoPParTests.JktOf(ok.AccessToken) == ecJkt) ? "一致" : "**違う値**");

                r.Step("(2) EC の鍵の証明で預けた code を、**別の鍵（RSA）の証明**で引き換える");

                string code2 = await DPoPParTests.CodeViaParAsync(client, reg, parEndpoint,
                    DPoPParTests.Proof(client, parEndpoint), null, "state-rt3651-2");

                JsonResponse otherKey = await DPoPParTests.TokenAsync(client, reg, tokenEndpoint, code2,
                    DPoPParTests.Proof(client, tokenEndpoint, es256: false));

                r.VerifyEqual("invalid_grant", "invalid_grant", otherKey.Error ?? "なし");

                r.VerifyEqual("400", "400", ((int)otherKey.StatusCode).ToString());

                r.Step("(3) 同じ code を、**証明なし**で引き換える");

                JsonResponse noProof = await DPoPParTests.TokenAsync(client, reg, tokenEndpoint, code2, null);

                r.VerifyEqual("invalid_grant", "invalid_grant", noProof.Error ?? "なし");

                r.VerifyEqual("400", "400", ((int)noProof.StatusCode).ToString());

                r.Step("(4) **その code は、まだ使える**（EC の証明で引き換える）");

                JsonResponse retry = await DPoPParTests.TokenAsync(client, reg, tokenEndpoint, code2,
                    DPoPParTests.Proof(client, tokenEndpoint));

                r.VerifyEqual("HTTP 200（断りで消費していない）", "200", ((int)retry.StatusCode).ToString());

                r.Step("(5) `DPoP` ヘッダを付けない PAR の code は、従来どおり証明なしで引き換えられる");

                string plainCode = await DPoPParTests.CodeViaParAsync(client, reg, parEndpoint,
                    null, null, "state-rt3651-5");

                JsonResponse plain = await DPoPParTests.TokenAsync(client, reg, tokenEndpoint, plainCode, null);

                r.VerifyEqual("HTTP 200", "200", ((int)plain.StatusCode).ToString());

                r.VerifyEqual("token_type は bearer", "bearer",
                    (plain.String("token_type") ?? "なし").ToLower());

                r.Done();
            }
        }

        #endregion

        #region RT-365.2

        /// <summary>RT-365.2 dpop_jkt と DPoP ヘッダの鍵が違えば PAR で断る</summary>
        /// <param name="targetKey">core / netfx</param>
        /// <returns>Task</returns>
        [SkippableTheory]
        [MemberData(nameof(AllTargets))]
        public async Task RT36502_dpop_jktとDPoPヘッダの鍵が違えばPARで断る(string targetKey)
        {
            using (IdPClient client = await this.SignedInClientAsync(targetKey))
            {
                ClientRegistration reg = Flows.Registration(client, KnownClients.TestClient);

                await Flows.EnsureConsentAsync(client, reg);

                TestReport r = this.Report("RT-365.2",
                    "**PAR に `dpop_jkt` と `DPoP` ヘッダの両方が来て、指紋が違えば `400` ＋ `invalid_request` で断る。**"
                    + "**同じなら受け付け、その鍵に縛る**",
                    "**§10.1 は、`dpop_jkt` の指紋が `DPoP` ヘッダの公開鍵と合わなければ、要求を断れとしている**（MUST）。"
                    + "**エラー コードは決めていない。** **証明は正しく、要求が食い違っている**ので `invalid_request` にした"
                    + "（**証明が通らないときの `invalid_dpop_proof` と分ける**。RT-365.3）。",
                    "RFC 9449 §10.1 / #365");

                string parEndpoint = await DPoPParTests.ParEndpointAsync(client);
                string tokenEndpoint = await DPoPParTests.TokenEndpointAsync(client);

                r.Target("POST /par（`dpop_jkt` ＋ `DPoP` ヘッダ）");

                r.Step("(1) `dpop_jkt` に RSA の鍵の指紋、`DPoP` ヘッダに EC の鍵の証明を付けて預ける");

                JsonResponse mismatched = await DPoPParTests.ParAsync(client, reg, parEndpoint,
                    DPoPParTests.Proof(client, parEndpoint), JwsSigner.DPoPJkt(client, es256: false), "state-rt3652-1");

                r.VerifyEqual("HTTP 400", "400", ((int)mismatched.StatusCode).ToString());

                r.VerifyEqual("invalid_request", "invalid_request", mismatched.Error ?? "なし");

                r.Verify("request_uri を返さない", string.IsNullOrEmpty(mismatched.String("request_uri")),
                    "返さなかった",
                    string.IsNullOrEmpty(mismatched.String("request_uri")) ? "返さなかった" : "**返してしまった**");

                r.Step("(2) `dpop_jkt` も EC の鍵の指紋にして預け、その code を RSA の証明で引き換える");

                string code = await DPoPParTests.CodeViaParAsync(client, reg, parEndpoint,
                    DPoPParTests.Proof(client, parEndpoint), JwsSigner.DPoPJkt(client), "state-rt3652-2");

                JsonResponse otherKey = await DPoPParTests.TokenAsync(client, reg, tokenEndpoint, code,
                    DPoPParTests.Proof(client, tokenEndpoint, es256: false));

                r.VerifyEqual("invalid_grant（EC の鍵に縛られている）", "invalid_grant", otherKey.Error ?? "なし");

                r.Note("**`request`（JAR）の中の `dpop_jkt` も、同じ所で照合している**（預ける中身を作った後で見る）。"
                    + "**JAR の経路は測っていない。**");

                r.Done();
            }
        }

        #endregion

        #region RT-365.3

        /// <summary>RT-365.3 PAR の DPoP の証明も確かめる</summary>
        /// <param name="targetKey">core / netfx</param>
        /// <returns>Task</returns>
        [SkippableTheory]
        [MemberData(nameof(AllTargets))]
        public async Task RT36503_PARのDPoPの証明も確かめる(string targetKey)
        {
            using (IdPClient client = await this.SignedInClientAsync(targetKey))
            {
                ClientRegistration reg = Flows.Registration(client, KnownClients.TestClient);

                TestReport r = this.Report("RT-365.3",
                    "**PAR の `DPoP` ヘッダが通らなければ `400` ＋ `invalid_dpop_proof` で断る**"
                    + "（壊れた証明・宛先（`htu`）の違う証明・使い回した証明）。"
                    + "**ほかの理由で断った PAR では、証明を使い済みにしない**",
                    "**§10.1 は、PAR の証明を §4.3 のとおり確かめよとしている**（MUST）。"
                    + "**通らない証明を黙って捨てると、縛ったつもりのクライアントが縛られない**"
                    + "（`/token` で `invalid_dpop_proof` にしているのと同じ。§5）。"
                    + "**証明は一度しか通らない**（§11.1）ので、"
                    + "**別の理由で断る要求が証明を使い済みにすると、クライアントは作り直しを強いられる。**",
                    "RFC 9449 §10.1 / RFC 9449 §4.3 / #365");

                string parEndpoint = await DPoPParTests.ParEndpointAsync(client);
                string tokenEndpoint = await DPoPParTests.TokenEndpointAsync(client);

                r.Target("POST /par（`DPoP` ヘッダ）");

                r.Step("(1) JWT として読めない値を `DPoP` ヘッダに入れて預ける");

                JsonResponse broken = await DPoPParTests.ParAsync(client, reg, parEndpoint,
                    "not-a-dpop-proof", null, "state-rt3653-1");

                r.VerifyEqual("HTTP 400", "400", ((int)broken.StatusCode).ToString());

                r.VerifyEqual("invalid_dpop_proof", "invalid_dpop_proof", broken.Error ?? "なし");

                r.Step("(2) **`/token` 宛ての証明**（`htu` が違う）で預ける");

                JsonResponse wrongHtu = await DPoPParTests.ParAsync(client, reg, parEndpoint,
                    DPoPParTests.Proof(client, tokenEndpoint), null, "state-rt3653-2");

                r.VerifyEqual("HTTP 400", "400", ((int)wrongHtu.StatusCode).ToString());

                r.VerifyEqual("invalid_dpop_proof", "invalid_dpop_proof", wrongHtu.Error ?? "なし");

                r.Step("(3) 正しい証明で、**`request_uri` を付けた（断られる）PAR** を送り、同じ証明で正しい PAR を送る");

                string proof = DPoPParTests.Proof(client, parEndpoint);

                Dictionary<string, string> withRequestUri = DPoPParTests.Parameters(reg, null, "state-rt3653-3");
                withRequestUri["request_uri"] = "urn:ietf:params:oauth:request_uri:dummy";

                JsonResponse denied = await client.PostJsonAsync(client.ToLocalUrl(parEndpoint), withRequestUri,
                    new Dictionary<string, string>() { { "DPoP", proof } });

                r.VerifyEqual("先の PAR は invalid_request", "invalid_request", denied.Error ?? "なし");

                JsonResponse accepted = await DPoPParTests.ParAsync(client, reg, parEndpoint,
                    proof, null, "state-rt3653-3");

                r.VerifyEqual("同じ証明の PAR は HTTP 201（**先の断りで使い済みになっていない**）",
                    "201", ((int)accepted.StatusCode).ToString());

                r.Step("(4) その証明を、**もう一度**使って預ける");

                JsonResponse replayed = await DPoPParTests.ParAsync(client, reg, parEndpoint,
                    proof, null, "state-rt3653-4");

                r.VerifyEqual("HTTP 400", "400", ((int)replayed.StatusCode).ToString());

                r.VerifyEqual("invalid_dpop_proof（使い回し）", "invalid_dpop_proof", replayed.Error ?? "なし");

                r.Note("**`nonce` を要求する配備（`EnableDPoPNonce`）では、PAR の口も `use_dpop_nonce` ＋ `DPoP-Nonce` で答える**"
                    + "（`/token` と同じ用途の nonce）。**既定の配備では要求しないので、測っていない。**");

                r.Done();
            }
        }

        #endregion

        #region private

        /// <summary>Discovery が広告する PAR の口の URL（`htu` の期待値）</summary>
        /// <param name="client">IdPClient</param>
        /// <returns>URL</returns>
        private static async Task<string> ParEndpointAsync(IdPClient client)
        {
            JsonResponse res = await client.GetJsonAsync("/.well-known/openid-configuration");

            string endpoint = res.String("pushed_authorization_request_endpoint");

            Skip.If(string.IsNullOrEmpty(endpoint), "Discovery が pushed_authorization_request_endpoint を広告していません。");

            return endpoint;
        }

        /// <summary>Discovery が広告する `/token` の URL（`htu` の期待値）</summary>
        /// <param name="client">IdPClient</param>
        /// <returns>URL</returns>
        private static async Task<string> TokenEndpointAsync(IdPClient client)
        {
            JsonResponse res = await client.GetJsonAsync("/.well-known/openid-configuration");

            string endpoint = res.String("token_endpoint");

            Skip.If(string.IsNullOrEmpty(endpoint), "Discovery が token_endpoint を広告していません。");

            return endpoint;
        }

        /// <summary>PAR に預ける認可要求（client_secret_post）</summary>
        /// <param name="reg">クライアント</param>
        /// <param name="dpopJkt">`dpop_jkt`（null なら付けない）</param>
        /// <param name="state">state</param>
        /// <returns>フォーム</returns>
        private static Dictionary<string, string> Parameters(ClientRegistration reg, string dpopJkt, string state)
        {
            return new Dictionary<string, string>()
            {
                { "client_id", reg.ClientId },
                { "client_secret", reg.ClientSecret },
                { "response_type", "code" },
                { "redirect_uri", reg.RedirectUri },
                { "scope", "openid email" },
                { "state", state },
                { "nonce", "nonce-" + state },
                { "prompt", "none" },
                { "dpop_jkt", dpopJkt }
            };
        }

        /// <summary>PAR に預ける</summary>
        /// <param name="client">IdPClient</param>
        /// <param name="reg">クライアント</param>
        /// <param name="parEndpoint">広告された PAR の口</param>
        /// <param name="proof">`DPoP` ヘッダの値（null なら付けない）</param>
        /// <param name="dpopJkt">`dpop_jkt`（null なら付けない）</param>
        /// <param name="state">state</param>
        /// <returns>応答</returns>
        private static Task<JsonResponse> ParAsync(
            IdPClient client, ClientRegistration reg, string parEndpoint,
            string proof, string dpopJkt, string state)
        {
            return client.PostJsonAsync(client.ToLocalUrl(parEndpoint),
                DPoPParTests.Parameters(reg, dpopJkt, state),
                new Dictionary<string, string>() { { "DPoP", proof } });
        }

        /// <summary>PAR に預け、その request_uri で認可コードを取る</summary>
        /// <param name="client">IdPClient</param>
        /// <param name="reg">クライアント</param>
        /// <param name="parEndpoint">広告された PAR の口</param>
        /// <param name="proof">`DPoP` ヘッダの値（null なら付けない）</param>
        /// <param name="dpopJkt">`dpop_jkt`（null なら付けない）</param>
        /// <param name="state">state</param>
        /// <returns>code</returns>
        private static async Task<string> CodeViaParAsync(
            IdPClient client, ClientRegistration reg, string parEndpoint,
            string proof, string dpopJkt, string state)
        {
            JsonResponse par = await DPoPParTests.ParAsync(client, reg, parEndpoint, proof, dpopJkt, state);

            string requestUri = par.String("request_uri");

            Assert.False(string.IsNullOrEmpty(requestUri),
                "前提: PAR に預けられること（HTTP " + (int)par.StatusCode + "、error=" + (par.Error ?? "なし") + "）");

            AuthZResponse authz = await client.AuthorizeAsync(new Dictionary<string, string>()
            {
                { "client_id", reg.ClientId },
                { "request_uri", requestUri }
            });

            Assert.False(string.IsNullOrEmpty(authz.Code),
                "前提: 認可コードが取得できること（" + authz.ToString() + "）");

            return authz.Code;
        }

        /// <summary>code を引き換える（証明は付けなくてもよい）</summary>
        /// <param name="client">IdPClient</param>
        /// <param name="reg">クライアントの登録</param>
        /// <param name="tokenEndpoint">広告された token_endpoint</param>
        /// <param name="code">code</param>
        /// <param name="proof">`DPoP` ヘッダの値（null なら付けない）</param>
        /// <returns>応答</returns>
        private static Task<JsonResponse> TokenAsync(
            IdPClient client, ClientRegistration reg,
            string tokenEndpoint, string code, string proof)
        {
            return client.PostJsonAsync(client.ToLocalUrl(tokenEndpoint),
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

        /// <summary>DPoP の証明を作る</summary>
        /// <param name="client">IdPClient</param>
        /// <param name="htu">宛先</param>
        /// <param name="es256">true なら ES256（既定）、false なら RS256（**別の鍵**）</param>
        /// <returns>証明</returns>
        private static string Proof(IdPClient client, string htu, bool es256 = true)
        {
            return JwsSigner.SignDPoP(client, new Dictionary<string, object>()
            {
                { "jti", Guid.NewGuid().ToString("N") },
                { "htm", "POST" },
                { "htu", htu },
                { "iat", DateTimeOffset.UtcNow.ToUnixTimeSeconds() }
            }, es256);
        }

        /// <summary>access_token の `cnf.jkt`（無ければ空）</summary>
        /// <param name="accessToken">access_token</param>
        /// <returns>jkt</returns>
        private static string JktOf(string accessToken)
        {
            if (string.IsNullOrEmpty(accessToken))
            {
                return "";
            }

            JsonElement payload = Jwt.Payload(accessToken);

            if (payload.ValueKind != JsonValueKind.Object
                || !payload.TryGetProperty("cnf", out JsonElement cnf)
                || cnf.ValueKind != JsonValueKind.Object
                || !cnf.TryGetProperty("jkt", out JsonElement jkt))
            {
                return "";
            }

            return jkt.GetString() ?? "";
        }

        #endregion
    }
}
