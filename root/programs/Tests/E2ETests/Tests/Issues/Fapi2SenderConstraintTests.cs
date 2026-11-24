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
//* クラス名        ：Fapi2SenderConstraintTests
//* クラス日本語名  ：RT-429 fapi2 の登録は、送信者に縛れないトークン要求を断る（FAPI 2.0 Security Profile §5.3.2.1 の 4）
//*
//* 作成日時        ：－
//* 作成者          ：－
//* 更新履歴        ：－
//*
//*  日時        更新者            内容
//*  ----------  ----------------  -------------------------------------------------
//*  2026/11/24  玄人 幸道         新規（#429）
//**********************************************************************************

using System;
using System.Collections.Generic;
using System.Threading.Tasks;

using MultiPurposeAuthSite.Tests.E2E.Infrastructure;

using Xunit;
using Xunit.Abstractions;

namespace MultiPurposeAuthSite.Tests.E2E.Tests.Issues
{
    /// <summary>
    /// RT-429. **fapi2 の登録は、登録の項目によらず、送信者に縛れない（DPoP の証明も証明書も無い）トークン要求を断る**。
    /// </summary>
    /// <remarks>
    /// **FAPI 2.0 Security Profile §5.3.2.1 の 4・5**：送信者に縛ったアクセス トークンだけを出す（DPoP か MTLS）。
    /// **以前は、登録の項目（`dpop_bound_access_tokens`・`tls_client_certificate_bound_access_tokens`）を立てた登録だけを強制していた**
    /// （#346。`ANALYSIS-IdP.md` の D-16）ので、**`private_key_jwt` の fapi2 の登録が DPoP を添えずに要求すると、縛りの無い Bearer のトークンが出た**。
    ///
    /// | | 経路 | 測ること |
    /// |---|---|---|
    /// | **`RT-429.1`** | 認可コード | **DPoP の証明が無ければ `invalid_request`。断られた code は使っておらず、DPoP の証明を添えれば引き換えられる** |
    /// | **`RT-429.2`** | refresh_token | **DPoP の証明が無ければ `invalid_request`。添えれば更新できる** |
    /// | **`RT-429.3`** | client_credentials | **DPoP の証明が無ければ `invalid_request`**（添えれば通ることは `RT-424.1`） |
    ///
    /// - **`tls_client_auth` の fapi2 の登録は、DPoP が無くても証明書に縛られて通る**（`RT-424.2`・`FA-6.1`）
    /// - **client_secret の fapi2 は、従来どおり `unauthorized_client`**（許されない組み合わせには、この強制を掛けない。`RT-424.3`）
    /// - **normal の登録は変わらない**（`private_key_jwt` でも、DPoP を添えずに通る。`RT-398.1`）
    /// - クライアントは `TestClient_32`（fapi2・`private_key_jwt`。縛りの登録の項目は立てていない）
    /// </remarks>
    public class Fapi2SenderConstraintTests : TargetTestBase
    {
        /// <summary>client_assertion_type（RFC 7523 §2.2）</summary>
        private const string JwtBearerAssertionType = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer";

        /// <summary>code_verifier（RFC 7636 Appendix B）</summary>
        private const string Verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";

        /// <summary>Verifier の S256（RFC 7636 Appendix B）</summary>
        private const string Challenge = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";

        /// <summary>constructor</summary>
        /// <param name="output">ITestOutputHelper</param>
        public Fapi2SenderConstraintTests(ITestOutputHelper output) : base(output) { }

        #region RT-429.1

        /// <summary>RT-429.1 fapi2 の認可コードの引き換えは、DPoP の証明が無ければ断る</summary>
        /// <param name="targetKey">core / netfx</param>
        /// <returns>Task</returns>
        [SkippableTheory]
        [MemberData(nameof(AllTargets))]
        public async Task RT42901_fapi2の認可コードはDPoPが無ければ断る(string targetKey)
        {
            using (IdPClient client = await this.SignedInClientAsync(targetKey))
            {
                TestReport r = this.Report("RT-429.1",
                    "**fapi2 の登録の認可コードの引き換えは、DPoP の証明も証明書も無ければ `invalid_request` で断る。断られた code は使っておらず、DPoP の証明を添えれば引き換えられる**",
                    "**FAPI 2.0 は、送信者に縛ったトークンだけを出すことを求める**（§5.3.2.1 の 4）。"
                    + "**以前は、縛りの登録の項目を立てていない fapi2 の登録に、Bearer のトークンを出していた**（#346 の D-16。#424 の別モデルのレビューの指摘）。"
                    + "**断るのは code を使う前**（断られた後に、同じ code でやり直せる。#346 と同じ）。",
                    "FAPI 2.0 Security Profile §5.3.2.1 / #429");

                ClientRegistration reg = Flows.InjectedRegistration(client, KnownClients.TestClient_32);
                string issuer = await client.IssuerAsync();

                r.Target("POST /token（grant_type=authorization_code。client_name=" + KnownClients.TestClient_32 + "。fapi2。private_key_jwt）");

                r.Step("(1) PKCE（S256）で認可コードを得る");

                AuthZResponse authz = await Flows.AuthorizeCodeAsync(client, reg, redirectUri: reg.RedirectUri,
                    extra: new Dictionary<string, string>()
                    {
                        { "code_challenge", Fapi2SenderConstraintTests.Challenge },
                        { "code_challenge_method", "S256" }
                    });

                Assert.False(string.IsNullOrEmpty(authz.Code),
                    "前提: 認可コードが取得できること（" + authz.ToString() + "）");

                Dictionary<string, string> form = Fapi2SenderConstraintTests.CodeForm(client, reg, issuer, authz.Code);

                r.Step("(2) DPoP の証明を添えずに引き換える");

                JsonResponse bare = await client.TokenAsync(form);

                r.VerifyEqual("invalid_request", "invalid_request", bare.Error ?? "（無い）");
                r.Verify("トークンを出さない", string.IsNullOrEmpty(bare.AccessToken),
                    "出さない", string.IsNullOrEmpty(bare.AccessToken) ? "出さない" : "**出した**");

                r.Step("(3) 同じ code を、DPoP の証明を添えて引き換える（client_assertion は作り直す）");

                JsonResponse token = await client.TokenWithDPoPAsync(
                    Fapi2SenderConstraintTests.CodeForm(client, reg, issuer, authz.Code));

                r.VerifyEqual("HTTP 200（断られた code は使っていない）", "200", ((int)token.StatusCode).ToString());
                r.VerifyEqual("token_type が DPoP", "DPoP", token.String("token_type") ?? "（無し）");

                r.Done();
            }
        }

        #endregion

        #region RT-429.2

        /// <summary>RT-429.2 fapi2 の refresh_token の更新は、DPoP の証明が無ければ断る</summary>
        /// <param name="targetKey">core / netfx</param>
        /// <returns>Task</returns>
        [SkippableTheory]
        [MemberData(nameof(AllTargets))]
        public async Task RT42902_fapi2のrefresh_tokenはDPoPが無ければ断る(string targetKey)
        {
            using (IdPClient client = await this.SignedInClientAsync(targetKey))
            {
                TestReport r = this.Report("RT-429.2",
                    "**fapi2 の登録の refresh_token の更新は、DPoP の証明も証明書も無ければ `invalid_request` で断る。添えれば更新できる**",
                    "**更新で出す access_token も、送信者に縛る**（§5.3.2.1 の 4 はグラントを限らない）。"
                    + "**秘密を持つクライアントの refresh_token そのものは鍵に縛らない**（RFC 9449 §5。#367）ので、更新のたびに今の鍵の証明を添える。",
                    "FAPI 2.0 Security Profile §5.3.2.1 / RFC 9449 §5 / #429");

                ClientRegistration reg = Flows.InjectedRegistration(client, KnownClients.TestClient_32);
                string issuer = await client.IssuerAsync();

                r.Target("POST /token（grant_type=refresh_token。client_name=" + KnownClients.TestClient_32 + "。fapi2。private_key_jwt）");

                r.Step("(1) DPoP の証明を添えて認可コードを引き換え、refresh_token を得る");

                AuthZResponse authz = await Flows.AuthorizeCodeAsync(client, reg, redirectUri: reg.RedirectUri,
                    extra: new Dictionary<string, string>()
                    {
                        { "code_challenge", Fapi2SenderConstraintTests.Challenge },
                        { "code_challenge_method", "S256" }
                    });

                Assert.False(string.IsNullOrEmpty(authz.Code),
                    "前提: 認可コードが取得できること（" + authz.ToString() + "）");

                JsonResponse token = await client.TokenWithDPoPAsync(
                    Fapi2SenderConstraintTests.CodeForm(client, reg, issuer, authz.Code));

                Assert.False(string.IsNullOrEmpty(token.RefreshToken),
                    "前提: refresh_token が返ること（" + token.ToString() + "）");

                r.Step("(2) DPoP の証明を添えずに更新する");

                JsonResponse bare = await client.TokenAsync(
                    Fapi2SenderConstraintTests.RefreshForm(client, reg, issuer, token.RefreshToken));

                r.VerifyEqual("invalid_request", "invalid_request", bare.Error ?? "（無い）");
                r.Verify("トークンを出さない", string.IsNullOrEmpty(bare.AccessToken),
                    "出さない", string.IsNullOrEmpty(bare.AccessToken) ? "出さない" : "**出した**");

                r.Step("(3) DPoP の証明を添えて更新する");

                JsonResponse refreshed = await client.TokenWithDPoPAsync(
                    Fapi2SenderConstraintTests.RefreshForm(client, reg, issuer, token.RefreshToken));

                r.VerifyEqual("HTTP 200", "200", ((int)refreshed.StatusCode).ToString());
                r.VerifyEqual("token_type が DPoP", "DPoP", refreshed.String("token_type") ?? "（無し）");

                r.Done();
            }
        }

        #endregion

        #region RT-429.3

        /// <summary>RT-429.3 fapi2 の client_credentials は、DPoP の証明が無ければ断る</summary>
        /// <param name="targetKey">core / netfx</param>
        /// <returns>Task</returns>
        [SkippableTheory]
        [MemberData(nameof(AllTargets))]
        public async Task RT42903_fapi2のclient_credentialsはDPoPが無ければ断る(string targetKey)
        {
            using (IdPClient client = this.Client(targetKey))
            {
                TestReport r = this.Report("RT-429.3",
                    "**fapi2 の登録の client_credentials は、DPoP の証明も証明書も無ければ `invalid_request` で断る**",
                    "**#424 で fapi2 に開けた client_credentials も、送信者に縛る**（§5.3.2.1 の 4）。"
                    + "**DPoP の証明を添えれば通ることは `RT-424.1`** が測る。",
                    "FAPI 2.0 Security Profile §5.3.2.1 / #429");

                ClientRegistration reg = Flows.InjectedRegistration(client, KnownClients.TestClient_32);
                string issuer = await client.IssuerAsync();

                r.Target("POST /token（grant_type=client_credentials。client_name=" + KnownClients.TestClient_32 + "。fapi2。private_key_jwt。DPoP 無し）");

                r.Step("(1) DPoP の証明を添えずに、client_credentials を要求する");

                JsonResponse bare = await client.TokenAsync(new Dictionary<string, string>()
                {
                    { "grant_type", "client_credentials" },
                    { "scope", "profile" },
                    { "client_id", reg.ClientId },
                    { "client_assertion_type", Fapi2SenderConstraintTests.JwtBearerAssertionType },
                    { "client_assertion", Fapi2SenderConstraintTests.ClientAssertion(client, reg.ClientId, issuer) }
                });

                r.VerifyEqual("invalid_request", "invalid_request", bare.Error ?? "（無い）");
                r.Verify("トークンを出さない", string.IsNullOrEmpty(bare.AccessToken),
                    "出さない", string.IsNullOrEmpty(bare.AccessToken) ? "出さない" : "**出した**");

                r.Done();
            }
        }

        #endregion

        #region 部品

        /// <summary>PS256 の client_assertion を作る（fapi2 の aud は issuer。FAPI の登録は RS256 を断る。#323・#395）</summary>
        /// <param name="client">IdPClient</param>
        /// <param name="clientId">client_id</param>
        /// <param name="issuer">issuer</param>
        /// <returns>client_assertion</returns>
        private static string ClientAssertion(IdPClient client, string clientId, string issuer)
        {
            long now = DateTimeOffset.UtcNow.ToUnixTimeSeconds();

            return JwsSigner.SignPS256(client, new Dictionary<string, object>()
            {
                { "iss", clientId },
                { "sub", clientId },
                { "aud", issuer },
                { "jti", Guid.NewGuid().ToString("N") },
                { "iat", now },
                { "exp", now + 300 }
            });
        }

        /// <summary>認可コードの引き換えのフォーム（client_assertion は呼ぶたびに作る。jti は使い捨て）</summary>
        /// <param name="client">IdPClient</param>
        /// <param name="reg">クライアント</param>
        /// <param name="issuer">issuer</param>
        /// <param name="code">認可コード</param>
        /// <returns>フォーム</returns>
        private static Dictionary<string, string> CodeForm(IdPClient client, ClientRegistration reg, string issuer, string code)
        {
            return new Dictionary<string, string>()
            {
                { "grant_type", "authorization_code" },
                { "code", code },
                { "code_verifier", Fapi2SenderConstraintTests.Verifier },
                { "redirect_uri", reg.RedirectUri },
                { "client_assertion_type", Fapi2SenderConstraintTests.JwtBearerAssertionType },
                { "client_assertion", Fapi2SenderConstraintTests.ClientAssertion(client, reg.ClientId, issuer) }
            };
        }

        /// <summary>refresh_token の更新のフォーム</summary>
        /// <param name="client">IdPClient</param>
        /// <param name="reg">クライアント</param>
        /// <param name="issuer">issuer</param>
        /// <param name="refreshToken">refresh_token</param>
        /// <returns>フォーム</returns>
        private static Dictionary<string, string> RefreshForm(IdPClient client, ClientRegistration reg, string issuer, string refreshToken)
        {
            return new Dictionary<string, string>()
            {
                { "grant_type", "refresh_token" },
                { "refresh_token", refreshToken },
                { "client_assertion_type", Fapi2SenderConstraintTests.JwtBearerAssertionType },
                { "client_assertion", Fapi2SenderConstraintTests.ClientAssertion(client, reg.ClientId, issuer) }
            };
        }

        #endregion
    }
}
