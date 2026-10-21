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
//* クラス名        ：DPoPTests
//* クラス日本語名  ：RT-311 DPoP（RFC 9449）の段階 1
//*
//* 作成日時        ：－
//* 作成者          ：－
//* 更新履歴        ：－
//*
//*  日時        更新者            内容
//*  ----------  ----------------  -------------------------------------------------
//*  2026/10/21  玄人 幸道         新規（#311 の段階 1）
//*  2026/10/22  玄人 幸道         jti の使い回しについての注を直した（#311 の段階 3）
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
    /// RT-311. **DPoP（RFC 9449）の段階 1** — **`/token` で証明を受け、`cnf.jkt` で発行する。**
    /// </summary>
    /// <remarks>
    /// **いまの Sender-Constrained は mTLS だけ**だった（RFC 8705。`cnf.x5t#S256`）。
    /// **mTLS は証明書を配れる相手にしか使えない** — **SPA / ネイティブには配れない。**
    /// **DPoP は、要求ごとに「鍵を持っていること」を示させる**ので、**配布が要らない。**
    ///
    /// | | 測ること |
    /// |---|---|
    /// | **`RT-311.1`** | **Discovery が `dpop_signing_alg_values_supported` を広告する**（**`none` は入っていない**。**mTLS の広告はそのまま**） |
    /// | **`RT-311.2`** | **認可コードの `/token` に証明を添えると、`token_type` が `DPoP` になり、`access_token` の `cnf.jkt` が鍵の指紋と一致する** |
    /// | **`RT-311.3`** | **証明が無ければ従来どおり `bearer`**（`cnf` も無い）。**`refresh_token` の経路でも縛れる** |
    /// | **`RT-311.4`** | **壊した証明は `invalid_dpop_proof` で断る**。**断った要求は `refresh_token` を消費していない** |
    ///
    /// **段階 1 で縛るのは「発行」まで**である。
    /// **保護されたリソースでの照合は段階 2**（**それまでは、縛った印が付くだけ**）。
    ///
    /// **鍵はテスト用クライアントのもの**（`JwsSigner.SignDPoP`）。
    /// **DPoP の鍵は登録が要らない** — **その場の鍵で縛られる。**
    /// </remarks>
    public class DPoPTests : TargetTestBase
    {
        /// <summary>コンストラクタ</summary>
        /// <param name="output">ITestOutputHelper</param>
        public DPoPTests(ITestOutputHelper output) : base(output)
        {
        }

        #region RT-311.1

        /// <summary>RT-311.1 Discovery が DPoP を広告する</summary>
        /// <param name="targetKey">core / netfx</param>
        /// <returns>Task</returns>
        [SkippableTheory]
        [MemberData(nameof(AllTargets))]
        public async Task RT31101_DiscoveryがDPoPを広告する(string targetKey)
        {
            using (IdPClient client = this.Client(targetKey))
            {
                TestReport r = this.Report("RT-311.1",
                    "**Discovery が `dpop_signing_alg_values_supported` を広告する**",
                    "**クライアントは、DPoP が使えるかどうかと、"
                    + "どの `alg` で証明を署名すればよいかを知る必要が在る。**"
                    + "**広告が無ければ、クライアントは縛りようが無い。**"
                    + "**`none` が入っていてはならない** — "
                    + "**署名の無い証明を受けるなら、鍵を持っている証明にならない。**",
                    "RFC 9449 §5.1 / #311 の段階 1");

                r.Target("GET /.well-known/openid-configuration");

                r.Step("広告を読む");

                JsonResponse res = await client.GetJsonAsync("/.well-known/openid-configuration");

                string[] algs = res.Strings("dpop_signing_alg_values_supported");

                r.Verify("dpop_signing_alg_values_supported が在る", algs != null,
                    "在る", (algs == null) ? "**無い**" : "在る（" + algs.Length + " 件）");

                if (algs == null)
                {
                    r.Done();
                    return;
                }

                r.Verify("ES256 が入っている",
                    res.ArrayContains("dpop_signing_alg_values_supported", "ES256"),
                    "入っている",
                    res.ArrayContains("dpop_signing_alg_values_supported", "ES256")
                        ? "入っている" : "**無い**");

                r.Verify("RS256 が入っている",
                    res.ArrayContains("dpop_signing_alg_values_supported", "RS256"),
                    "入っている",
                    res.ArrayContains("dpop_signing_alg_values_supported", "RS256")
                        ? "入っている" : "**無い**");

                r.Verify("none は入っていない",
                    !res.ArrayContains("dpop_signing_alg_values_supported", "none"),
                    "無い",
                    res.ArrayContains("dpop_signing_alg_values_supported", "none")
                        ? "**入っている**" : "無い");

                r.Observe("広告された alg", string.Join(" ", algs),
                    "**一覧は `SigningKeys` の表が持つ**（発行・検証・広告が同じ表を見る。#129 の段階 3）。");

                r.Step("mTLS の広告は、そのままである");

                r.VerifyEqual("tls_client_certificate_bound_access_tokens が true",
                    "true",
                    (res.String("tls_client_certificate_bound_access_tokens") ?? "なし").ToLower());

                r.Note("**2 つの縛り方は、どちらも在ってよい**（RFC 8705 / RFC 9449）。"
                    + "**FAPI 2.0 は、どちらかを必須としている。**");

                r.Done();
            }
        }

        #endregion

        #region RT-311.2

        /// <summary>RT-311.2 認可コードで DPoP に縛れる</summary>
        /// <param name="targetKey">core / netfx</param>
        /// <returns>Task</returns>
        [SkippableTheory]
        [MemberData(nameof(AllTargets))]
        public async Task RT31102_認可コードでDPoPに縛れる(string targetKey)
        {
            using (IdPClient client = await this.SignedInClientAsync(targetKey))
            {
                TestReport r = this.Report("RT-311.2",
                    "**認可コードの `/token` に DPoP の証明を添えると、`token_type` が `DPoP` になり、"
                    + "`access_token` の `cnf.jkt` が鍵の指紋と一致する**",
                    "**これが「持ち主に縛る」の中身**である。"
                    + "**`cnf.jkt` が鍵の指紋でなければ、保護されたリソースは照合できない**"
                    + "（段階 2）。**`token_type` が変わらなければ、"
                    + "クライアントは縛られたことに気付けない。**",
                    "RFC 9449 §5 / §6 / #311 の段階 1");

                ClientRegistration reg = Flows.Registration(client, KnownClients.TestClient);
                string tokenEndpoint = await DPoPTests.TokenEndpointAsync(client);
                string expectedJkt = JwsSigner.DPoPJkt(client);

                r.Target("POST /token（`DPoP` ヘッダ付き。grant_type=authorization_code）");

                r.Step("(1) 認可コードを取る");

                AuthZResponse authz = await Flows.AuthorizeCodeAsync(
                    client, reg, "openid email", "state1", "nonce-rt3112", reg.RedirectUri);

                Assert.False(string.IsNullOrEmpty(authz.Code),
                    "前提: 認可コードが取得できること（" + authz.ToString() + "）");

                r.Step("(2) 証明を添えて交換する");

                JsonResponse token = await DPoPTests.TokenAsync(
                    client, tokenEndpoint,
                    new Dictionary<string, string>()
                    {
                        { "grant_type", "authorization_code" },
                        { "code", authz.Code },
                        { "client_id", reg.ClientId },
                        { "client_secret", reg.ClientSecret },
                        { "redirect_uri", reg.RedirectUri }
                    },
                    DPoPTests.Proof(client, "POST", tokenEndpoint));

                r.VerifyEqual("HTTP 200", "200", ((int)token.StatusCode).ToString());

                r.VerifyEqual("token_type が DPoP", "DPoP", token.String("token_type") ?? "なし");

                r.Verify("access_token が返る", !string.IsNullOrEmpty(token.AccessToken),
                    "返る", string.IsNullOrEmpty(token.AccessToken) ? "**無い**" : "返る");

                r.Step("(3) access_token の cnf.jkt");

                string jkt = DPoPTests.JktOf(token.AccessToken);

                r.Verify("cnf.jkt が、証明の鍵の指紋と一致する",
                    !string.IsNullOrEmpty(jkt) && (jkt == expectedJkt),
                    "一致",
                    string.IsNullOrEmpty(jkt)
                        ? "**cnf.jkt が無い**" : ((jkt == expectedJkt) ? "一致" : "**違う値**"));

                r.Verify("id_token も返る（OIDC の経路は壊れていない）",
                    !string.IsNullOrEmpty(token.IdToken),
                    "返る", string.IsNullOrEmpty(token.IdToken) ? "**無い**" : "返る");

                r.Note("**指紋（`jkt`）は RFC 7638 の計算**である。"
                    + "**テスト側でも独立に計算している**（実装のコードは使っていない）。");

                r.Note("**`refresh_token` は、まだ DPoP に縛っていない**（段階 4）。"
                    + "**パブリック クライアントの `refresh_token` を縛ることは RFC 9449 §5 が求めている**ので、"
                    + "**そこで入れる。**");

                r.Done();
            }
        }

        #endregion

        #region RT-311.3

        /// <summary>RT-311.3 証明が無ければ bearer のまま／refresh でも縛れる</summary>
        /// <param name="targetKey">core / netfx</param>
        /// <returns>Task</returns>
        [SkippableTheory]
        [MemberData(nameof(AllTargets))]
        public async Task RT31103_証明が無ければbearerのままでrefreshでも縛れる(string targetKey)
        {
            using (IdPClient client = await this.SignedInClientAsync(targetKey))
            {
                TestReport r = this.Report("RT-311.3",
                    "**証明が無ければ、従来どおり `bearer`**（`cnf` も無い）。"
                    + "**`refresh_token` の経路でも、証明を添えれば縛れる**",
                    "**既定の挙動を変えないこと**が、この段階の約束である"
                    + "（**DPoP を知らないクライアントは、何もしなくてよい**）。"
                    + "**一方で、縛りたいクライアントは、どのグラントでも縛れる**必要が在る — "
                    + "**`/token` を叩く経路は認可コードだけではない。**",
                    "RFC 9449 §5 / #311 の段階 1");

                ClientRegistration reg = Flows.Registration(client, KnownClients.TestClient);
                string tokenEndpoint = await DPoPTests.TokenEndpointAsync(client);
                string expectedJkt = JwsSigner.DPoPJkt(client);

                r.Target("POST /token（証明なし → 証明あり。grant_type=refresh_token）");

                r.Step("(1) 証明を添えずに交換する（従来どおり）");

                JsonResponse plain = await Flows.RunAuthorizationCodeFlowAsync(
                    client, KnownClients.TestClient, "openid email", "nonce-rt3113");

                r.VerifyEqual("token_type が bearer", "bearer",
                    (plain.String("token_type") ?? "なし").ToLower());

                r.Verify("cnf が入っていない（縛られていない）",
                    string.IsNullOrEmpty(DPoPTests.JktOf(plain.AccessToken)),
                    "無い",
                    string.IsNullOrEmpty(DPoPTests.JktOf(plain.AccessToken))
                        ? "無い" : "**cnf.jkt が在る**");

                string refreshToken = plain.RefreshToken;

                if (string.IsNullOrEmpty(refreshToken))
                {
                    r.Note("**この配備は `refresh_token` を返していない**ので、(2) は見送った"
                        + "（`EnableRefreshToken` が既定で有効なら測れる）。");
                    r.Done();
                    return;
                }

                r.Step("(2) その refresh_token を、証明を添えて使う");

                JsonResponse refreshed = await DPoPTests.TokenAsync(
                    client, tokenEndpoint,
                    new Dictionary<string, string>()
                    {
                        { "grant_type", "refresh_token" },
                        { "refresh_token", refreshToken },
                        { "client_id", reg.ClientId },
                        { "client_secret", reg.ClientSecret }
                    },
                    DPoPTests.Proof(client, "POST", tokenEndpoint));

                r.VerifyEqual("HTTP 200", "200", ((int)refreshed.StatusCode).ToString());

                r.VerifyEqual("token_type が DPoP", "DPoP",
                    refreshed.String("token_type") ?? "なし");

                string jkt = DPoPTests.JktOf(refreshed.AccessToken);

                r.Verify("取り直した access_token の cnf.jkt が一致する",
                    !string.IsNullOrEmpty(jkt) && (jkt == expectedJkt),
                    "一致",
                    string.IsNullOrEmpty(jkt)
                        ? "**cnf.jkt が無い**" : ((jkt == expectedJkt) ? "一致" : "**違う値**"));

                r.Note("**縛られていないトークンから、縛られたトークンへ乗り換えられる**"
                    + "（RFC 9449 は禁じていない）。"
                    + "**逆向き（縛られた `refresh_token` を、証明なしで使う）を拒むのは段階 4** である。");

                r.Done();
            }
        }

        #endregion

        #region RT-311.4

        /// <summary>RT-311.4 壊した証明は断る</summary>
        /// <param name="targetKey">core / netfx</param>
        /// <returns>Task</returns>
        [SkippableTheory]
        [MemberData(nameof(AllTargets))]
        public async Task RT31104_壊した証明は断る(string targetKey)
        {
            using (IdPClient client = await this.SignedInClientAsync(targetKey))
            {
                TestReport r = this.Report("RT-311.4",
                    "**壊した証明は `invalid_dpop_proof` で断る**。"
                    + "**断った要求は、`refresh_token` を消費していない**",
                    "**証明を見ずに通すなら、縛りは飾りである。**"
                    + "**`htm` / `htu` / `iat` を見ないと、別の口への証明や古い証明が使い回せる**"
                    + "（RFC 9449 §4.3）。"
                    + "**断る前に資格情報を消費してしまうと、クライアントは作り直しもできない** — "
                    + "**だから、証明の検証はグラントの入口で行っている。**",
                    "RFC 9449 §4.3 / §5 / #311 の段階 1");

                ClientRegistration reg = Flows.Registration(client, KnownClients.TestClient);
                string tokenEndpoint = await DPoPTests.TokenEndpointAsync(client);

                r.Target("POST /token（壊した `DPoP` ヘッダ。grant_type=refresh_token）");

                r.Step("(1) 証明なしで refresh_token を取る");

                JsonResponse plain = await Flows.RunAuthorizationCodeFlowAsync(
                    client, KnownClients.TestClient, "openid email", "nonce-rt3114");

                string refreshToken = plain.RefreshToken;

                if (string.IsNullOrEmpty(refreshToken))
                {
                    Skip.If(true, "この配備は refresh_token を返していません（EnableRefreshToken）。");
                }

                Dictionary<string, string> form = new Dictionary<string, string>()
                {
                    { "grant_type", "refresh_token" },
                    { "refresh_token", refreshToken },
                    { "client_id", reg.ClientId },
                    { "client_secret", reg.ClientSecret }
                };

                r.Step("(2) 壊した証明を、順に投げる");

                // **壊し方と、その理由**（RFC 9449 §4.3）。
                List<KeyValuePair<string, string>> broken =
                    new List<KeyValuePair<string, string>>()
                {
                    new KeyValuePair<string, string>("typ が JWT",
                        DPoPTests.ProofWithTyp(client, tokenEndpoint)),
                    new KeyValuePair<string, string>("htm が違う（GET）",
                        DPoPTests.Proof(client, "GET", tokenEndpoint)),
                    new KeyValuePair<string, string>("htu が別の口",
                        DPoPTests.Proof(client, "POST", tokenEndpoint + "/other")),
                    new KeyValuePair<string, string>("iat が古い（10 分前）",
                        DPoPTests.Proof(client, "POST", tokenEndpoint, -600)),
                    new KeyValuePair<string, string>("jti が無い",
                        DPoPTests.ProofWithoutJti(client, tokenEndpoint)),
                    new KeyValuePair<string, string>("署名が合わない",
                        DPoPTests.Tampered(DPoPTests.Proof(client, "POST", tokenEndpoint)))
                };

                foreach (KeyValuePair<string, string> item in broken)
                {
                    JsonResponse denied = await DPoPTests.TokenAsync(
                        client, tokenEndpoint, form, item.Value);

                    r.VerifyEqual(item.Key + " → invalid_dpop_proof",
                        "invalid_dpop_proof", denied.Error ?? "なし");

                    r.Verify(item.Key + " → 400",
                        (int)denied.StatusCode == 400,
                        "400", ((int)denied.StatusCode).ToString());
                }

                r.Step("(3) 断られた後も、refresh_token はまだ使える");

                JsonResponse after = await client.TokenAsync(form);

                r.VerifyEqual("証明なしで使える（消費されていない）", "200",
                    ((int)after.StatusCode).ToString());

                r.Verify("access_token が返る", !string.IsNullOrEmpty(after.AccessToken),
                    "返る", string.IsNullOrEmpty(after.AccessToken) ? "**無い**" : "返る");

                r.Note("**`jwk` に秘密鍵が混ざっている証明**（§4.3）**は、ここでは測っていない** — "
                    + "**ヘッダを後から書き替えると署名が合わなくなり、"
                    + "「署名が合わない」と区別が付かない**ためである（実装では見ている）。");

                r.Note("**`jti` の使い回しは、段階 3 で拒むようにした**（`RT-311.8`）。"
                    + "**ここで投げている証明は、どれも検証を通らない** — "
                    + "**だから `jti` は焼かれず、台帳とは関わりなく断られている。**");

                r.Done();
            }
        }

        #endregion

        #region 私的なヘルパ

        /// <summary>Discovery が広告する `/token` の URL（`htu` の期待値）</summary>
        /// <param name="client">IdPClient</param>
        /// <returns>token_endpoint</returns>
        /// <remarks>
        /// **サーバは設定から `htu` を作る**ので、**広告された値と同じ**である。
        /// **叩く先は `ToLocalUrl` で読み替える**（開発では待ち受けが違うことが在る）。
        /// </remarks>
        private static async Task<string> TokenEndpointAsync(IdPClient client)
        {
            JsonResponse res = await client.GetJsonAsync("/.well-known/openid-configuration");

            string endpoint = res.String("token_endpoint");

            Skip.If(string.IsNullOrEmpty(endpoint),
                "Discovery が token_endpoint を広告していません。");

            return endpoint;
        }

        /// <summary>証明を添えて `/token` を叩く</summary>
        /// <param name="client">IdPClient</param>
        /// <param name="tokenEndpoint">広告された token_endpoint</param>
        /// <param name="form">フォーム</param>
        /// <param name="proof">DPoP の証明</param>
        /// <returns>JsonResponse</returns>
        private static Task<JsonResponse> TokenAsync(
            IdPClient client, string tokenEndpoint,
            IDictionary<string, string> form, string proof)
        {
            return client.PostJsonAsync(
                client.ToLocalUrl(tokenEndpoint), form,
                new Dictionary<string, string>() { { "DPoP", proof } });
        }

        /// <summary>DPoP の証明を作る</summary>
        /// <param name="client">IdPClient</param>
        /// <param name="htm">HTTP メソッド</param>
        /// <param name="htu">宛先</param>
        /// <param name="iatOffsetSeconds">`iat` をずらす秒数（既定 0）</param>
        /// <returns>証明</returns>
        private static string Proof(
            IdPClient client, string htm, string htu, int iatOffsetSeconds = 0)
        {
            return JwsSigner.SignDPoP(client, new Dictionary<string, object>()
            {
                { "jti", Guid.NewGuid().ToString("N") },
                { "htm", htm },
                { "htu", htu },
                { "iat", DateTimeOffset.UtcNow.ToUnixTimeSeconds() + iatOffsetSeconds }
            });
        }

        /// <summary>`jti` を入れない証明</summary>
        /// <param name="client">IdPClient</param>
        /// <param name="htu">宛先</param>
        /// <returns>証明</returns>
        private static string ProofWithoutJti(IdPClient client, string htu)
        {
            return JwsSigner.SignDPoP(client, new Dictionary<string, object>()
            {
                { "htm", "POST" },
                { "htu", htu },
                { "iat", DateTimeOffset.UtcNow.ToUnixTimeSeconds() }
            });
        }

        /// <summary>`typ` を `JWT` にした証明（**普通の JWT と見分けが付かない**）</summary>
        /// <param name="client">IdPClient</param>
        /// <param name="htu">宛先</param>
        /// <returns>証明</returns>
        /// <remarks>
        /// **`typ` を見ないと、別の用途の JWT を証明として受けてしまう**（RFC 9449 §4.2）。
        /// **ここは `JwsSigner.SignRS256`（`typ=JWT`）で作る** —
        /// **署名そのものは正しい**ので、**落ちるのは `typ` の判定だけ**である。
        /// </remarks>
        private static string ProofWithTyp(IdPClient client, string htu)
        {
            return JwsSigner.SignRS256(client, new Dictionary<string, object>()
            {
                { "jti", Guid.NewGuid().ToString("N") },
                { "htm", "POST" },
                { "htu", htu },
                { "iat", DateTimeOffset.UtcNow.ToUnixTimeSeconds() }
            });
        }

        /// <summary>署名を 1 文字変える</summary>
        /// <param name="jws">JWS</param>
        /// <returns>壊れた JWS</returns>
        private static string Tampered(string jws)
        {
            string[] parts = jws.Split('.');

            char[] signature = parts[2].ToCharArray();
            signature[0] = (signature[0] == 'A') ? 'B' : 'A';

            return parts[0] + "." + parts[1] + "." + new string(signature);
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
