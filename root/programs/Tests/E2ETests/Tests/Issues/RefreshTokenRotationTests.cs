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
//* クラス名        ：RefreshTokenRotationTests
//* クラス日本語名  ：RT-367 FAPI 2.0 の登録では、refresh_token を入れ替えない（FAPI 2.0 Security Profile §5.3.2.1）
//*
//* 作成日時        ：－
//* 作成者          ：－
//* 更新履歴        ：－
//*
//*  日時        更新者            内容
//*  ----------  ----------------  -------------------------------------------------
//*  2026/11/13  玄人 幸道         新規（#367）
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
    /// RT-367. **FAPI 2.0 の登録（`client_mode=fapi2`）では、refresh_token を入れ替えない**（FAPI 2.0 Security Profile §5.3.2.1 の 9）。
    /// </summary>
    /// <remarks>
    /// **以前は、どの登録でも、更新のたびに新しい refresh_token を出し、前のものを使用済みにしていた**（#188 の段階 3）。
    /// **FAPI 2.0 は「特別な事情が無い限り入れ替えない」**としており、
    /// **適合性テストは、前の refresh_token でもう一度更新して落ちていた**（`fapi2-security-profile-final-refresh-token`）。
    ///
    /// | | 測ること |
    /// |---|---|
    /// | **`RT-367.1`** | **fapi2 の登録は、更新で新しい refresh_token を返さず、同じ refresh_token で何度でも更新できる** |
    /// | **`RT-367.2`** | **fapi2 でない登録は、従来どおり入れ替え、前の refresh_token は `invalid_grant`** |
    ///
    /// **秘密を持つクライアントの refresh_token を DPoP の鍵に縛らないこと**（同じ #367）は `RT-311.11` が測る。
    /// </remarks>
    public class RefreshTokenRotationTests : TargetTestBase
    {
        /// <summary>client_assertion_type（RFC 7523 §2.2）</summary>
        private const string JwtBearerAssertionType = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer";

        /// <summary>code_verifier（RFC 7636 Appendix B）</summary>
        private const string Verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";

        /// <summary>Verifier の S256（RFC 7636 Appendix B）</summary>
        private const string Challenge = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";

        /// <summary>コンストラクタ</summary>
        /// <param name="output">ITestOutputHelper</param>
        public RefreshTokenRotationTests(ITestOutputHelper output) : base(output)
        {
        }

        #region 補助

        /// <summary>RS256 の client_assertion を作る（RFC 7523 §2.2。fapi2 の aud は issuer。#323）</summary>
        /// <param name="client">IdPClient</param>
        /// <param name="clientId">client_id</param>
        /// <param name="issuer">issuer</param>
        /// <returns>client_assertion</returns>
        private static string ClientAssertion(IdPClient client, string clientId, string issuer)
        {
            long now = DateTimeOffset.UtcNow.ToUnixTimeSeconds();

            return JwsSigner.SignRS256(client, new Dictionary<string, object>()
            {
                { "iss", clientId },
                { "sub", clientId },
                { "aud", issuer },
                { "jti", Guid.NewGuid().ToString("N") },
                { "iat", now },
                { "exp", now + 300 }
            });
        }

        /// <summary>fapi2 の登録（private_key_jwt）で、DPoP の証明を添えて更新する</summary>
        /// <param name="client">IdPClient</param>
        /// <param name="reg">クライアント</param>
        /// <param name="issuer">issuer</param>
        /// <param name="tokenEndpoint">広告された token_endpoint（`htu`）</param>
        /// <param name="refreshToken">refresh_token</param>
        /// <param name="es256">true なら EC の鍵、false なら RSA の鍵（**作り直した鍵**）で証明する</param>
        /// <returns>応答</returns>
        private static Task<JsonResponse> Fapi2RefreshAsync(
            IdPClient client, ClientRegistration reg, string issuer,
            string tokenEndpoint, string refreshToken, bool es256)
        {
            string proof = JwsSigner.SignDPoP(client, new Dictionary<string, object>()
            {
                { "jti", Guid.NewGuid().ToString("N") },
                { "htm", "POST" },
                { "htu", tokenEndpoint },
                { "iat", DateTimeOffset.UtcNow.ToUnixTimeSeconds() }
            }, es256);

            return client.PostJsonAsync(client.ToLocalUrl(tokenEndpoint),
                new Dictionary<string, string>()
                {
                    { "grant_type", "refresh_token" },
                    { "refresh_token", refreshToken },
                    { "client_assertion_type", RefreshTokenRotationTests.JwtBearerAssertionType },
                    { "client_assertion", RefreshTokenRotationTests.ClientAssertion(client, reg.ClientId, issuer) }
                },
                new Dictionary<string, string>() { { "DPoP", proof } });
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

        /// <summary>client_secret の登録で更新する</summary>
        /// <param name="client">IdPClient</param>
        /// <param name="reg">クライアント</param>
        /// <param name="refreshToken">refresh_token</param>
        /// <returns>応答</returns>
        private static Task<JsonResponse> SecretRefreshAsync(
            IdPClient client, ClientRegistration reg, string refreshToken)
        {
            return client.TokenAsync(new Dictionary<string, string>()
            {
                { "grant_type", "refresh_token" },
                { "refresh_token", refreshToken },
                { "client_id", reg.ClientId },
                { "client_secret", reg.ClientSecret }
            });
        }

        #endregion

        #region RT-367.1

        /// <summary>RT-367.1 fapi2 の登録は、refresh_token を入れ替えない</summary>
        /// <param name="targetKey">core / netfx</param>
        /// <returns>Task</returns>
        [SkippableTheory]
        [MemberData(nameof(AllTargets))]
        public async Task RT36701_fapi2の登録はrefresh_tokenを入れ替えない(string targetKey)
        {
            using (IdPClient client = await this.SignedInClientAsync(targetKey))
            {
                TestReport r = this.Report("RT-367.1",
                    "fapi2 の登録は、更新で新しい refresh_token を返さず、同じ refresh_token で（DPoP の鍵を作り直しても）何度でも更新できる",
                    "**FAPI 2.0 は、特別な事情が無い限り refresh_token を入れ替えない**ことを求める。"
                    + "**新しい refresh_token を返さなければ、クライアントは今のものを使い続ける**（RFC 6749 §6）。"
                    + "**秘密を持つクライアント（private_key_jwt）の refresh_token は、DPoP の鍵に縛らない**（RFC 9449 §5）。"
                    + "**以前は入れ替えて前のものを使用済みにし、鍵にも縛っていた**ので、適合性テストの refresh-token が落ちた。",
                    "FAPI 2.0 Security Profile §5.3.2.1 / RFC 6749 §6 / RFC 9449 §5 / #367");

                ClientRegistration reg = Flows.InjectedRegistration(client, KnownClients.TestClient_32);
                string issuer = await client.IssuerAsync();

                r.Target("POST /token（grant_type=refresh_token。client_name=" + KnownClients.TestClient_32 + "。fapi2。private_key_jwt）");

                r.Step("(1) PKCE（S256）と client_assertion で、認可コードを引き換える");

                AuthZResponse authz = await Flows.AuthorizeCodeAsync(client, reg, redirectUri: reg.RedirectUri,
                    extra: new Dictionary<string, string>()
                    {
                        { "code_challenge", RefreshTokenRotationTests.Challenge },
                        { "code_challenge_method", "S256" }
                    });

                Assert.False(string.IsNullOrEmpty(authz.Code),
                    "前提: 認可コードが取得できること（" + authz.ToString() + "）");

                JsonResponse token = await client.TokenAsync(new Dictionary<string, string>()
                {
                    { "grant_type", "authorization_code" },
                    { "code", authz.Code },
                    { "code_verifier", RefreshTokenRotationTests.Verifier },
                    { "redirect_uri", reg.RedirectUri },
                    { "client_assertion_type", RefreshTokenRotationTests.JwtBearerAssertionType },
                    { "client_assertion", RefreshTokenRotationTests.ClientAssertion(client, reg.ClientId, issuer) }
                });

                string refreshToken = token.RefreshToken;

                Assert.False(string.IsNullOrEmpty(refreshToken),
                    "前提: refresh_token が返ること（" + token.ToString() + "）");

                JsonResponse disco = await client.GetJsonAsync("/.well-known/openid-configuration");
                string tokenEndpoint = disco.String("token_endpoint");

                Assert.False(string.IsNullOrEmpty(tokenEndpoint), "前提: Discovery が token_endpoint を広告していること");

                r.Step("(2) EC の鍵の DPoP の証明を添えて更新する");

                JsonResponse first = await RefreshTokenRotationTests.Fapi2RefreshAsync(
                    client, reg, issuer, tokenEndpoint, refreshToken, es256: true);

                r.VerifyEqual("HTTP 200", "200", ((int)first.StatusCode).ToString());

                r.VerifyEqual("cnf.jkt が EC の鍵の指紋", "一致",
                    RefreshTokenRotationTests.JktOf(first.AccessToken) == JwsSigner.DPoPJkt(client) ? "一致" : "**違う値**");

                r.Verify("新しい refresh_token を返さない（入れ替えない）", string.IsNullOrEmpty(first.RefreshToken),
                    "返さない", string.IsNullOrEmpty(first.RefreshToken) ? "返さなかった" : "**返した**");

                r.Step("(3) 同じ refresh_token で、**作り直した鍵（RSA）**の証明を添えて、もう一度更新する");

                //  **適合性テストの refresh-token と同じ形**（更新の前に DPoP の鍵を作り直す）。
                //    **入れ替えないこと**（使用済みにしない）と、**秘密を持つクライアントの refresh_token を鍵に縛らないこと**
                //    （RFC 9449 §5。private_key_jwt の証明で判定する）を、併せて見る。
                JsonResponse second = await RefreshTokenRotationTests.Fapi2RefreshAsync(
                    client, reg, issuer, tokenEndpoint, refreshToken, es256: false);

                r.VerifyEqual("HTTP 200（使用済みにしていない・鍵に縛っていない）", "200", ((int)second.StatusCode).ToString());

                r.VerifyEqual("cnf.jkt が、作り直した鍵（RSA）の指紋", "一致",
                    RefreshTokenRotationTests.JktOf(second.AccessToken) == JwsSigner.DPoPJkt(client, es256: false) ? "一致" : "**違う値**");

                r.Done();
            }
        }

        #endregion

        #region RT-367.2

        /// <summary>RT-367.2 fapi2 でない登録は、従来どおり refresh_token を入れ替える</summary>
        /// <param name="targetKey">core / netfx</param>
        /// <returns>Task</returns>
        [SkippableTheory]
        [MemberData(nameof(AllTargets))]
        public async Task RT36702_fapi2でない登録は従来どおり入れ替える(string targetKey)
        {
            using (IdPClient client = await this.SignedInClientAsync(targetKey))
            {
                TestReport r = this.Report("RT-367.2",
                    "fapi2 でない登録は、従来どおり更新のたびに refresh_token を入れ替え、前のものは invalid_grant で断る",
                    "**入れ替えないのは fapi2 の登録だけ。** **ほかの登録は、盗まれた refresh_token への備えとして入れ替えを続ける**"
                    + "（再利用の検知。#188 の段階 3）。",
                    "RFC 6749 §6 / #188 / #367");

                ClientRegistration reg = Flows.Registration(client, KnownClients.TestClient);

                r.Target("POST /token（grant_type=refresh_token。client_name=" + KnownClients.TestClient + "。normal。client_secret）");

                r.Step("(1) 認可コード フローで refresh_token を得る");

                JsonResponse token = await Flows.RunAuthorizationCodeFlowAsync(
                    client, KnownClients.TestClient, "openid email", "nonce-rt3672");

                string refreshToken = token.RefreshToken;

                Assert.False(string.IsNullOrEmpty(refreshToken),
                    "前提: refresh_token が返ること（" + token.ToString() + "）");

                r.Step("(2) 更新する");

                JsonResponse first = await RefreshTokenRotationTests.SecretRefreshAsync(client, reg, refreshToken);

                r.VerifyEqual("HTTP 200", "200", ((int)first.StatusCode).ToString());

                r.Verify("新しい refresh_token を返す（入れ替える）",
                    !string.IsNullOrEmpty(first.RefreshToken) && first.RefreshToken != refreshToken,
                    "別の値", string.IsNullOrEmpty(first.RefreshToken) ? "**返さなかった**"
                        : (first.RefreshToken != refreshToken ? "別の値" : "**同じ値**"));

                r.Step("(3) 前の refresh_token で、もう一度更新する");

                JsonResponse reuse = await RefreshTokenRotationTests.SecretRefreshAsync(client, reg, refreshToken);

                r.VerifyEqual("invalid_grant（使用済み）", "invalid_grant", reuse.Error ?? "（無い）");

                r.Done();
            }
        }

        #endregion
    }
}
