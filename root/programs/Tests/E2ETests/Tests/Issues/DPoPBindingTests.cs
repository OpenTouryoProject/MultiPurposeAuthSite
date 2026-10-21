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
//* クラス名        ：DPoPBindingTests
//* クラス日本語名  ：RT-311 DPoP（RFC 9449）の段階 4（code と refresh_token の縛り）
//*
//* 作成日時        ：－
//* 作成者          ：－
//* 更新履歴        ：－
//*
//*  日時        更新者            内容
//*  ----------  ----------------  -------------------------------------------------
//*  2026/10/22  玄人 幸道         新規（#311 の段階 4）
//*  2026/10/22  玄人 幸道         縛っていない refresh_token からの乗り換えを追加（歯抜けで測り漏れが出た）
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
    /// RT-311. **DPoP の段階 4** — **`code` と `refresh_token` も鍵に縛る。**
    /// </summary>
    /// <remarks>
    /// **段階 1〜3 が縛っていたのは `access_token` だけ**だった。
    /// **その手前（`code`）と、その先（`refresh_token`）には、縛りが無かった。**
    ///
    /// | | 測ること |
    /// |---|---|
    /// | **`RT-311.10`** | **認可要求の `dpop_jkt` で、`code` が鍵に縛られる**（RFC 9449 §10） |
    /// | **`RT-311.11`** | **縛った `access_token` と一緒に出た `refresh_token` も、同じ鍵に縛られる**（§5） |
    ///
    /// **どちらも「断るときに資格情報を消費しない」ことまで見る** —
    /// **断られた後、正しい鍵でやり直せなければ、縛りは利用者を閉じ出す仕掛けになる。**
    /// </remarks>
    public class DPoPBindingTests : TargetTestBase
    {
        /// <summary>コンストラクタ</summary>
        /// <param name="output">ITestOutputHelper</param>
        public DPoPBindingTests(ITestOutputHelper output) : base(output)
        {
        }

        #region RT-311.10

        /// <summary>RT-311.10 dpop_jkt で code が鍵に縛られる</summary>
        /// <param name="targetKey">core / netfx</param>
        /// <returns>Task</returns>
        [SkippableTheory]
        [MemberData(nameof(AllTargets))]
        public async Task RT31110_dpop_jktでcodeが鍵に縛られる(string targetKey)
        {
            using (IdPClient client = await this.SignedInClientAsync(targetKey))
            {
                TestReport r = this.Report("RT-311.10",
                    "**認可要求に `dpop_jkt` を付けると、その `code` はその鍵でしか引き換えられない**"
                    + "（別の鍵・証明なしは `invalid_grant`）。"
                    + "**断られた `code` は、正しい鍵でまだ引き換えられる**",
                    "**`code` を盗んで `/token` に持ち込む筋**は、"
                    + "**PKCE が `code_verifier` で塞いでいる所**である。"
                    + "**`dpop_jkt` は、同じ所を鍵で塞ぐ**（RFC 9449 §10） — "
                    + "**`access_token` を縛っても、`code` の段階で奪われては間に合わない。**"
                    + "**断るときに `code` を消費してはいけない** — "
                    + "**消費すると、正しい持ち主がやり直せなくなる。**",
                    "RFC 9449 §10 / #311 の段階 4");

                ClientRegistration reg = Flows.Registration(client, KnownClients.TestClient);
                string tokenEndpoint = await DPoPBindingTests.TokenEndpointAsync(client);

                string ecJkt = JwsSigner.DPoPJkt(client);

                r.Target("POST /token（`dpop_jkt` を付けて取った code）");

                r.Step("(1) `dpop_jkt`（EC の鍵の指紋）を付けて code を取り、EC の証明で引き換える");

                string code = await DPoPBindingTests.CodeAsync(client, reg, ecJkt, "nonce-rt31110-1");

                JsonResponse ok = await DPoPBindingTests.TokenAsync(
                    client, reg, tokenEndpoint, code,
                    DPoPBindingTests.Proof(client, tokenEndpoint));

                r.VerifyEqual("HTTP 200", "200", ((int)ok.StatusCode).ToString());

                r.VerifyEqual("token_type が DPoP", "DPoP", ok.String("token_type") ?? "なし");

                r.VerifyEqual("cnf.jkt が `dpop_jkt` と一致する",
                    "一致", (DPoPBindingTests.JktOf(ok.AccessToken) == ecJkt) ? "一致" : "**違う値**");

                r.Step("(2) 同じ `dpop_jkt` の code を、**別の鍵（RSA）の証明**で引き換える");

                string code2 = await DPoPBindingTests.CodeAsync(client, reg, ecJkt, "nonce-rt31110-2");

                JsonResponse otherKey = await DPoPBindingTests.TokenAsync(
                    client, reg, tokenEndpoint, code2,
                    DPoPBindingTests.Proof(client, tokenEndpoint, es256: false));

                r.VerifyEqual("invalid_grant", "invalid_grant", otherKey.Error ?? "なし");

                r.VerifyEqual("400", "400", ((int)otherKey.StatusCode).ToString());

                r.Step("(3) 同じ code を、**証明なし**で引き換える");

                JsonResponse noProof = await DPoPBindingTests.TokenAsync(
                    client, reg, tokenEndpoint, code2, null);

                r.VerifyEqual("invalid_grant", "invalid_grant", noProof.Error ?? "なし");

                r.VerifyEqual("400", "400", ((int)noProof.StatusCode).ToString());

                r.Step("(4) **その code は、まだ使える**（EC の証明で引き換える）");

                JsonResponse retry = await DPoPBindingTests.TokenAsync(
                    client, reg, tokenEndpoint, code2,
                    DPoPBindingTests.Proof(client, tokenEndpoint));

                r.VerifyEqual("HTTP 200（断りで消費していない）", "200",
                    ((int)retry.StatusCode).ToString());

                r.Step("(5) `dpop_jkt` を付けない code は、従来どおり証明なしで引き換えられる");

                string plainCode = await DPoPBindingTests.CodeAsync(
                    client, reg, null, "nonce-rt31110-5");

                JsonResponse plain = await DPoPBindingTests.TokenAsync(
                    client, reg, tokenEndpoint, plainCode, null);

                r.VerifyEqual("HTTP 200", "200", ((int)plain.StatusCode).ToString());

                r.VerifyEqual("token_type は bearer", "bearer",
                    (plain.String("token_type") ?? "なし").ToLower());

                r.Note("**`invalid_dpop_proof` ではなく `invalid_grant` で断っている** — "
                    + "**証明そのものは正しく、「この `code` のものではない」**のである。"
                    + "**証明の作りが悪いのか、持ち主が違うのかを、クライアントが区別できる。**");

                r.Note("**デバイス / CIBA の経路には `dpop_jkt` が無い**"
                    + "（**認可要求がブラウザを通らない**ため）。**そこは測っていない。**");

                r.Done();
            }
        }

        #endregion

        #region RT-311.11

        /// <summary>RT-311.11 refresh_token も同じ鍵に縛られる</summary>
        /// <param name="targetKey">core / netfx</param>
        /// <returns>Task</returns>
        [SkippableTheory]
        [MemberData(nameof(AllTargets))]
        public async Task RT31111_refresh_tokenも同じ鍵に縛られる(string targetKey)
        {
            using (IdPClient client = await this.SignedInClientAsync(targetKey))
            {
                TestReport r = this.Report("RT-311.11",
                    "**縛った `access_token` と一緒に出た `refresh_token` は、同じ鍵でしか使えない**"
                    + "（別の鍵・証明なしは `invalid_grant`）。"
                    + "**ローテーションした後も縛られている**",
                    "**`access_token` だけを縛っても、更新で縛りの無いものに乗り換えられる**"
                    + "なら、**縛りは寿命の分しか効かない**（RFC 9449 §5）。"
                    + "**漏えいして困るのは、むしろ長命な `refresh_token` の方**である。"
                    + "**断るときに消費してはいけない** — "
                    + "**ローテーションの一族ごと失効させては、持ち主が巻き込まれる**（#188 の段階 3）。",
                    "RFC 9449 §5 / #311 の段階 4");

                ClientRegistration reg = Flows.Registration(client, KnownClients.TestClient);
                string tokenEndpoint = await DPoPBindingTests.TokenEndpointAsync(client);

                string ecJkt = JwsSigner.DPoPJkt(client);

                r.Target("POST /token（grant_type=refresh_token）");

                r.Step("(1) 証明を添えて code を引き換え、縛られた refresh_token を得る");

                string code = await DPoPBindingTests.CodeAsync(client, reg, null, "nonce-rt31111");

                JsonResponse bound = await DPoPBindingTests.TokenAsync(
                    client, reg, tokenEndpoint, code,
                    DPoPBindingTests.Proof(client, tokenEndpoint));

                r.VerifyEqual("token_type が DPoP", "DPoP", bound.String("token_type") ?? "なし");

                string refreshToken = bound.RefreshToken;

                if (string.IsNullOrEmpty(refreshToken))
                {
                    Skip.If(true, "この配備は refresh_token を返していません（EnableRefreshToken）。");
                }

                r.Step("(2) **証明なし**で更新する");

                JsonResponse noProof = await DPoPBindingTests.RefreshAsync(
                    client, reg, tokenEndpoint, refreshToken, null);

                r.VerifyEqual("invalid_grant", "invalid_grant", noProof.Error ?? "なし");

                r.VerifyEqual("400", "400", ((int)noProof.StatusCode).ToString());

                r.Step("(3) **別の鍵（RSA）の証明**で更新する");

                JsonResponse otherKey = await DPoPBindingTests.RefreshAsync(
                    client, reg, tokenEndpoint, refreshToken,
                    DPoPBindingTests.Proof(client, tokenEndpoint, es256: false));

                r.VerifyEqual("invalid_grant", "invalid_grant", otherKey.Error ?? "なし");

                r.VerifyEqual("400", "400", ((int)otherKey.StatusCode).ToString());

                r.Step("(4) **同じ鍵（EC）の証明**で更新する");

                JsonResponse renewed = await DPoPBindingTests.RefreshAsync(
                    client, reg, tokenEndpoint, refreshToken,
                    DPoPBindingTests.Proof(client, tokenEndpoint));

                r.VerifyEqual("HTTP 200（断りで消費していない）", "200",
                    ((int)renewed.StatusCode).ToString());

                r.VerifyEqual("token_type が DPoP", "DPoP", renewed.String("token_type") ?? "なし");

                r.VerifyEqual("cnf.jkt が同じ鍵の指紋",
                    "一致", (DPoPBindingTests.JktOf(renewed.AccessToken) == ecJkt) ? "一致" : "**違う値**");

                r.Step("(5) **ローテーションした refresh_token も縛られている**");

                string rotated = renewed.RefreshToken;

                if (string.IsNullOrEmpty(rotated))
                {
                    Skip.If(true, "この配備は refresh_token をローテーションしていません。");
                }

                JsonResponse rotatedNoProof = await DPoPBindingTests.RefreshAsync(
                    client, reg, tokenEndpoint, rotated, null);

                r.VerifyEqual("invalid_grant", "invalid_grant", rotatedNoProof.Error ?? "なし");

                r.Step("(6) 縛っていない refresh_token は、従来どおり証明なしで使える");

                JsonResponse plain = await Flows.RunAuthorizationCodeFlowAsync(
                    client, KnownClients.TestClient, "openid email", "nonce-rt31111-6");

                if (string.IsNullOrEmpty(plain.RefreshToken))
                {
                    Skip.If(true, "この配備は refresh_token を返していません（EnableRefreshToken）。");
                }

                JsonResponse plainRenewed = await DPoPBindingTests.RefreshAsync(
                    client, reg, tokenEndpoint, plain.RefreshToken, null);

                r.VerifyEqual("HTTP 200", "200", ((int)plainRenewed.StatusCode).ToString());

                r.VerifyEqual("token_type は bearer", "bearer",
                    (plainRenewed.String("token_type") ?? "なし").ToLower());

                r.Step("(7) 縛っていない refresh_token を、**証明を添えて**更新すると、"
                    + "**出てくる refresh_token は縛られている**");

                //  **ここが歯抜けで見つかった測り漏れ**である（#311 の段階 4）。
                //    **ローテーションで縛りを書き直さなくても、(5) は通ってしまう** —
                //    **預けた payload が、もともと `cnf.jkt` を持っている**ためである。
                //    **書き直しが効くのは、この「縛っていない → 縛る」の乗り換え**だけ。
                JsonResponse upgraded = await DPoPBindingTests.RefreshAsync(
                    client, reg, tokenEndpoint, plainRenewed.RefreshToken,
                    DPoPBindingTests.Proof(client, tokenEndpoint));

                r.VerifyEqual("乗り換えられる（token_type が DPoP）", "DPoP",
                    upgraded.String("token_type") ?? "なし");

                if (string.IsNullOrEmpty(upgraded.RefreshToken))
                {
                    Skip.If(true, "この配備は refresh_token をローテーションしていません。");
                }

                JsonResponse afterUpgrade = await DPoPBindingTests.RefreshAsync(
                    client, reg, tokenEndpoint, upgraded.RefreshToken, null);

                r.VerifyEqual("乗り換えた先も縛られている（invalid_grant）", "invalid_grant",
                    afterUpgrade.Error ?? "なし");

                r.Note("**縛っていない `refresh_token` を、証明を添えて使うと、縛られたトークンが出る**"
                    + "（`RT-311.3`）。**その向きは RFC 9449 も禁じていない** — "
                    + "**塞いだのは逆向き（縛られたものを、証明なしで使う）である。**"
                    + "**(7) は、乗り換えた先の `refresh_token` にも縛りが付くことを見ている。**");

                r.Done();
            }
        }

        #endregion

        #region 私的なヘルパ

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

        /// <summary>認可コードを取る（`dpop_jkt` を付けられる）</summary>
        /// <param name="client">IdPClient</param>
        /// <param name="reg">クライアントの登録</param>
        /// <param name="dpopJkt">`dpop_jkt`（null なら付けない）</param>
        /// <param name="nonce">nonce</param>
        /// <returns>code</returns>
        private static async Task<string> CodeAsync(
            IdPClient client, ClientRegistration reg, string dpopJkt, string nonce)
        {
            Dictionary<string, string> extra = null;

            if (!string.IsNullOrEmpty(dpopJkt))
            {
                extra = new Dictionary<string, string>() { { "dpop_jkt", dpopJkt } };
            }

            AuthZResponse authz = await Flows.AuthorizeCodeAsync(
                client, reg, "openid email", "state1", nonce, reg.RedirectUri, extra);

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
            return DPoPBindingTests.PostAsync(client, tokenEndpoint, proof,
                new Dictionary<string, string>()
                {
                    { "grant_type", "authorization_code" },
                    { "code", code },
                    { "client_id", reg.ClientId },
                    { "client_secret", reg.ClientSecret },
                    { "redirect_uri", reg.RedirectUri }
                });
        }

        /// <summary>refresh_token で更新する（証明は付けなくてもよい）</summary>
        /// <param name="client">IdPClient</param>
        /// <param name="reg">クライアントの登録</param>
        /// <param name="tokenEndpoint">広告された token_endpoint</param>
        /// <param name="refreshToken">refresh_token</param>
        /// <param name="proof">`DPoP` ヘッダの値（null なら付けない）</param>
        /// <returns>応答</returns>
        private static Task<JsonResponse> RefreshAsync(
            IdPClient client, ClientRegistration reg,
            string tokenEndpoint, string refreshToken, string proof)
        {
            return DPoPBindingTests.PostAsync(client, tokenEndpoint, proof,
                new Dictionary<string, string>()
                {
                    { "grant_type", "refresh_token" },
                    { "refresh_token", refreshToken },
                    { "client_id", reg.ClientId },
                    { "client_secret", reg.ClientSecret }
                });
        }

        /// <summary>`/token` を叩く</summary>
        /// <param name="client">IdPClient</param>
        /// <param name="tokenEndpoint">広告された token_endpoint</param>
        /// <param name="proof">`DPoP` ヘッダの値（null なら付けない）</param>
        /// <param name="form">フォーム</param>
        /// <returns>応答</returns>
        private static Task<JsonResponse> PostAsync(
            IdPClient client, string tokenEndpoint, string proof,
            IDictionary<string, string> form)
        {
            Dictionary<string, string> headers = new Dictionary<string, string>();

            if (!string.IsNullOrEmpty(proof))
            {
                headers.Add("DPoP", proof);
            }

            return client.PostJsonAsync(client.ToLocalUrl(tokenEndpoint), form, headers);
        }

        /// <summary>DPoP の証明を作る（`/token` 向け）</summary>
        /// <param name="client">IdPClient</param>
        /// <param name="tokenEndpoint">宛先</param>
        /// <param name="es256">true なら ES256（既定）、false なら RS256（**別の鍵**）</param>
        /// <returns>証明</returns>
        private static string Proof(IdPClient client, string tokenEndpoint, bool es256 = true)
        {
            return JwsSigner.SignDPoP(client, new Dictionary<string, object>()
            {
                { "jti", Guid.NewGuid().ToString("N") },
                { "htm", "POST" },
                { "htu", tokenEndpoint },
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
