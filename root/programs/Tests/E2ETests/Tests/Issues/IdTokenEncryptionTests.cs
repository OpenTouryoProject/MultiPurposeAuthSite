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
//* クラス名        ：IdTokenEncryptionTests
//* クラス日本語名  ：RT-352・RT-355 fapi2 の id_token（Nested JWT）を、RP として復号して確かめる（#352・#355）
//*
//* 作成日時        ：－
//* 作成者          ：－
//* 更新履歴        ：－
//*
//*  日時        更新者            内容
//*  ----------  ----------------  -------------------------------------------------
//*  2026/11/10  玄人 幸道         新規（#352）
//*  2026/11/10  玄人 幸道         中の JWS の alg も確かめ、登録の alg で署名されることの RT-355.1 を追加（#355）
//**********************************************************************************

using System.Collections.Generic;
using System.Text.Json;
using System.Threading.Tasks;

using MultiPurposeAuthSite.Tests.E2E.Infrastructure;

using Xunit;
using Xunit.Abstractions;

namespace MultiPurposeAuthSite.Tests.E2E.Tests.Issues
{
    /// <summary>
    /// RT-352. fapi2 の id_token（JWE の中に JWS を入れた Nested JWT）を、RP として復号して確かめる。
    /// </summary>
    /// <remarks>
    /// **中の JWS の `kid` が、IdP の署名鍵ではなく、クライアントの暗号化の鍵の `kid` になっていた**（#352）。
    /// **`kid` で `jwks_uri` から鍵を引く RP は、署名を確かめられなかった。**
    ///
    /// **それまでの E2E は、JWE の id_token を復号していなかった**（`RT-239.5` は同じ経路で受け取るが、中を見ていない）。
    /// 自己テスト（サーバとクライアントを兼ねる）でも気付けない。
    /// **ここでは、実装側のクラスを使わずに復号し（`Jwe`）、`jwks_uri` の鍵だけで検証する（`Jwks`）。**
    ///
    /// **中の JWS の alg は、登録の `id_token_signed_response_alg` に従う**（#355。`RT-355.1`）。
    /// **以前は登録にかかわらず ES256 だった。** **登録が無ければ ES256 のまま**である（`RT-352.1`。FAPI 2.0 は RS256 を認めない）。
    /// </remarks>
    public class IdTokenEncryptionTests : TargetTestBase
    {
        /// <summary>コンストラクタ</summary>
        /// <param name="output">ITestOutputHelper</param>
        public IdTokenEncryptionTests(ITestOutputHelper output) : base(output)
        {
        }

        /// <summary>RT-352.1 fapi2 の id_token の中の JWS は、jwks_uri の鍵（kid）で検証できる</summary>
        /// <param name="targetKey">core / netfx</param>
        /// <returns>Task</returns>
        [SkippableTheory]
        [MemberData(nameof(AllTargets))]
        public async Task RT35201_fapi2のid_tokenの中のJWSはjwks_uriの鍵で検証できる(string targetKey)
        {
            using (IdPClient client = await this.SignedInClientAsync(targetKey))
            {
                ClientRegistration reg = Flows.Registration(client, KnownClients.Fapi2Client);

                TestReport r = this.Report("RT-352.1",
                    "fapi2 の id_token（Nested JWT）の中の JWS は、jwks_uri の鍵（kid）で検証できる",
                    "**中の JWS の `kid` は、署名した IdP の鍵の `kid` であること**"
                    + "（JWK Set に鍵が複数あるなら `kid` は必須。RP は `kid` で `jwks_uri` から鍵を引く）。"
                    + "以前は、暗号化に使うクライアントの鍵（`jwk_rsa_publickey`）の `kid` が入っていた。"
                    + "**認可コードの引き換えと、refresh_token の更新の両方**で確かめる（どちらも同じ組み立てを通る）。",
                    "OIDC Core 1.0 §10.1 / RFC 7515 §4.1.4 / #352");

                r.Target("client_name=" + KnownClients.Fapi2Client
                    + "（fapi2。`jwk_rsa_publickey` あり。JAR で認可し、private_key_jwt で交換）");

                r.Step("(1) FAPI2 の自己テストで code を得て、client_assertion で交換する");

                System.Net.Http.HttpResponseMessage starter = await client.StartSelfTestAsync(
                    "AuthorizationCodeFAPI2", "fapi2");

                string location = (starter.Headers.Location == null)
                    ? null : starter.Headers.Location.OriginalString;

                Skip.If(string.IsNullOrEmpty(location),
                    "FAPI2 の自己テストが動かない（起動 URL の食い違い。RT-197.1 を見ること）。");

                //  **自己テストの FAPI2 のボタンは PKCE（S256）を使う**（#345。RT-239.5 と同じ）。
                string codeVerifier = client.SelfTestCodeVerifier();

                Assert.False(string.IsNullOrEmpty(codeVerifier), "前提: 自己テストが code_verifier を Cookie に置くこと（#345）");

                AuthZResponse authz = await client.AuthorizeAndGrantAsync(client.ToLocalUrl(location));

                Assert.False(string.IsNullOrEmpty(authz.Code), "前提: code が発行されること");

                string issuer = await client.IssuerAsync();

                JsonResponse token = await client.TokenAsync(
                    AsymmetricAuthTests.WithClientAssertion(client, reg.ClientId,
                        new Dictionary<string, string>()
                        {
                            { "grant_type", "authorization_code" },
                            { "code", authz.Code },
                            { "redirect_uri", reg.RedirectUri },
                            { "code_verifier", codeVerifier }
                        }, issuer));

                Assert.False(string.IsNullOrEmpty(token.IdToken), "前提: id_token が返ること（" + token.ToString() + "）");

                JsonElement jwkSet = await Flows.JwkSetAsync(client);

                //  **alg の登録が無い**ので、中の JWS は ES256（#355）。
                IdTokenEncryptionTests.VerifyNested(r, client, jwkSet, token.IdToken, "引き換え", "ES256");

                r.Step("(2) client_assertion で refresh_token を更新し、返った id_token も同じく確かめる");

                string refreshToken = token.String("refresh_token");

                Assert.False(string.IsNullOrEmpty(refreshToken), "前提: refresh_token が返ること（RT-239.5）");

                JsonResponse refreshed = await client.TokenAsync(
                    AsymmetricAuthTests.WithClientAssertion(client, reg.ClientId,
                        new Dictionary<string, string>()
                        {
                            { "grant_type", "refresh_token" },
                            { "refresh_token", refreshToken }
                        }, issuer));

                Assert.False(string.IsNullOrEmpty(refreshed.IdToken), "前提: 更新でも id_token が返ること（" + refreshed.ToString() + "）");

                IdTokenEncryptionTests.VerifyNested(r, client, jwkSet, refreshed.IdToken, "更新", "ES256");

                r.Note("**外側の JWE のヘッダには `kid` を入れていない**（RFC 7516 §4.1.6 で任意。#352 では扱わない）。");

                r.Done();
            }
        }

        /// <summary>RT-355.1 fapi2 の id_token の中の JWS は、登録の id_token_signed_response_alg で署名される</summary>
        /// <param name="targetKey">core / netfx</param>
        /// <returns>Task</returns>
        [SkippableTheory]
        [MemberData(nameof(AllTargets))]
        public async Task RT35501_fapi2のid_tokenの中のJWSは登録のalgで署名される(string targetKey)
        {
            using (IdPClient client = await this.SignedInClientAsync(targetKey))
            {
                TestReport r = this.Report("RT-355.1",
                    "fapi2 の id_token（Nested JWT）の中の JWS は、登録の id_token_signed_response_alg（PS256）で署名される",
                    "**暗号化しても、中の JWS は、登録の alg で署名する**（signed then encrypted）。"
                    + "**access_token と同じ alg になる。** 以前は登録にかかわらず ES256 だった。"
                    + "**`kid` は署名した鍵（`jwks_uri` の RSA の鍵）のもの**で、その鍵で検証できること。"
                    + "**認可コードの引き換えと、refresh_token の更新の両方**で確かめる。",
                    "OIDC Registration 1.0 §2（id_token_signed_response_alg）/ OIDC Core 1.0 §10.2 / #355");

                ClientRegistration reg = Flows.InjectedRegistration(client, KnownClients.TestClient_45);

                r.Target("client_name=" + KnownClients.TestClient_45
                    + "（fapi2。`jwk_rsa_publickey` あり。private_key_jwt。id_token_signed_response_alg=PS256）");

                //  **fapi2 の aud は issuer だけ**（#323）。
                string issuer = await client.IssuerAsync();

                r.Step("(1) PKCE（S256）で認可コードを取り、client_assertion で交換する");

                AuthZResponse authz = await Flows.AuthorizeCodeAsync(
                    client, reg, scope: "openid", redirectUri: reg.RedirectUri,
                    extra: new Dictionary<string, string>()
                    {
                        { "code_challenge", IdTokenEncryptionTests.Challenge },
                        { "code_challenge_method", "S256" }
                    });

                Assert.False(string.IsNullOrEmpty(authz.Code), "前提: code が発行されること（" + authz.ToString() + "）");

                JsonResponse token = await client.TokenAsync(
                    AsymmetricAuthTests.WithClientAssertion(client, reg.ClientId,
                        new Dictionary<string, string>()
                        {
                            { "grant_type", "authorization_code" },
                            { "code", authz.Code },
                            { "redirect_uri", reg.RedirectUri },
                            { "code_verifier", IdTokenEncryptionTests.Verifier }
                        }, issuer));

                Assert.False(string.IsNullOrEmpty(token.IdToken), "前提: id_token が返ること（" + token.ToString() + "）");

                r.VerifyEqual("access_token のヘッダの alg は、登録の値", "PS256",
                    Jwt.String(Jwt.Header(token.AccessToken), "alg") ?? "（無い）");

                JsonElement jwkSet = await Flows.JwkSetAsync(client);

                IdTokenEncryptionTests.VerifyNested(r, client, jwkSet, token.IdToken, "引き換え", "PS256");

                r.Step("(2) client_assertion で refresh_token を更新し、返った id_token も同じく確かめる");

                string refreshToken = token.String("refresh_token");

                Assert.False(string.IsNullOrEmpty(refreshToken), "前提: refresh_token が返ること（" + token.ToString() + "）");

                JsonResponse refreshed = await client.TokenAsync(
                    AsymmetricAuthTests.WithClientAssertion(client, reg.ClientId,
                        new Dictionary<string, string>()
                        {
                            { "grant_type", "refresh_token" },
                            { "refresh_token", refreshToken }
                        }, issuer));

                Assert.False(string.IsNullOrEmpty(refreshed.IdToken), "前提: 更新でも id_token が返ること（" + refreshed.ToString() + "）");

                IdTokenEncryptionTests.VerifyNested(r, client, jwkSet, refreshed.IdToken, "更新", "PS256");

                r.Note("**登録が無い fapi2 のクライアントでは、中の JWS は ES256 のまま**（`RT-352.1`）。"
                    + "**暗号化しない側の既定（RS256）には倒さない**（FAPI 2.0 Security Profile §5.4.1 は RS256 を認めない）。");

                r.Done();
            }
        }

        /// <summary>RFC 7636 附録 B の例</summary>
        private const string Verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";

        /// <summary>RFC 7636 附録 B の例（SHA256(verifier) を BASE64URL したもの）</summary>
        private const string Challenge = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";

        /// <summary>Nested JWT を復号し、中の JWS を jwks_uri の鍵で検証する</summary>
        /// <param name="r">TestReport</param>
        /// <param name="client">IdPClient</param>
        /// <param name="jwkSet">jwks_uri の JWK Set</param>
        /// <param name="idToken">id_token</param>
        /// <param name="label">どの応答か（引き換え / 更新）</param>
        /// <param name="expectedAlg">中の JWS の alg の期待値（ES256 / PS256。#355）</param>
        private static void VerifyNested(TestReport r, IdPClient client, JsonElement jwkSet, string idToken, string label,
            string expectedAlg)
        {
            Jwe.Result jwe = Jwe.DecryptWithClientKey(client, idToken);

            r.Verify(label + "：id_token を、クライアントの秘密鍵で復号できる", jwe.Decrypted,
                "復号できる（RSA-OAEP / A256GCM）", jwe.Detail);

            Assert.True(jwe.Decrypted, "前提: 復号できること（" + jwe.Detail + "）");

            Jwks.Result sig = Jwks.Verify(jwe.Plaintext, jwkSet);

            // **alg は、登録の値（無ければ ES256）**（#355）。
            r.VerifyEqual(label + "：中の JWS の alg", expectedAlg, sig.Alg ?? "（alg が無い）");

            // **kid の有無と値を、直に確かめる**（別モデルのレビューの指摘）。
            //   `Jwks.Verify` は kid が無いと、種類と曲線の合う最初の鍵を使うので、**kid が抜けても通ってしまう。**
            //   ES256 の鍵（P-256）も RSA の鍵も JWK Set に 1 本なので、その kid と一致すること（OIDC Core 1.0 §10.1）。
            bool rsa = expectedAlg.StartsWith("PS") || expectedAlg.StartsWith("RS");

            r.VerifyEqual(label + "：中の JWS の kid は、jwks_uri の " + (rsa ? "RSA " : "ES256（P-256）") + "の鍵の kid",
                (rsa ? IdTokenEncryptionTests.RsaKid(jwkSet) : IdTokenEncryptionTests.EcP256Kid(jwkSet))
                    ?? "（jwks_uri に " + (rsa ? "RSA" : "P-256") + " の鍵が無い）",
                sig.Kid ?? "（kid が無い）");

            r.Verify(label + "：中の JWS の kid が jwks_uri の鍵を指し、その鍵で署名を検証できる", sig.Verified,
                "kid の鍵で検証できる",
                sig.Detail + "（alg=" + (sig.Alg ?? "なし") + " / kid=" + (sig.Kid ?? "なし") + "）");
        }

        /// <summary>JWK Set の RSA の鍵の kid を引く（#355）</summary>
        /// <param name="jwkSet">JWK Set</param>
        /// <returns>kid（無ければ null）</returns>
        /// <remarks>**RSA の鍵は 1 本で、RS* と PS* の 6 つが共有する**（kid も同じ。`CONFIGURATION.md`）。</remarks>
        private static string RsaKid(JsonElement jwkSet)
        {
            JsonElement keys;
            if (!jwkSet.TryGetProperty("keys", out keys) || keys.ValueKind != JsonValueKind.Array)
            {
                return null;
            }

            foreach (JsonElement k in keys.EnumerateArray())
            {
                if (Jwt.String(k, "kty") == "RSA")
                {
                    return Jwt.String(k, "kid");
                }
            }

            return null;
        }

        /// <summary>JWK Set の EC（P-256）の鍵の kid を引く</summary>
        /// <param name="jwkSet">JWK Set</param>
        /// <returns>kid（無ければ null）</returns>
        private static string EcP256Kid(JsonElement jwkSet)
        {
            JsonElement keys;
            if (!jwkSet.TryGetProperty("keys", out keys) || keys.ValueKind != JsonValueKind.Array)
            {
                return null;
            }

            foreach (JsonElement k in keys.EnumerateArray())
            {
                if (Jwt.String(k, "kty") == "EC" && Jwt.String(k, "crv") == "P-256")
                {
                    return Jwt.String(k, "kid");
                }
            }

            return null;
        }
    }
}
