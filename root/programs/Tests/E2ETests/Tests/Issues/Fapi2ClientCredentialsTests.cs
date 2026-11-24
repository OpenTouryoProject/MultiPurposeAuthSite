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
//* クラス名        ：Fapi2ClientCredentialsTests
//* クラス日本語名  ：RT-424 fapi2 の登録の client_credentials（FAPI 2.0 Security Profile §5.3.2.1）
//*
//* 作成日時        ：－
//* 作成者          ：－
//* 更新履歴        ：－
//*
//*  日時        更新者            内容
//*  ----------  ----------------  -------------------------------------------------
//*  2026/11/24  玄人 幸道         新規（#424）
//**********************************************************************************

using System;
using System.Collections.Generic;
using System.Security.Cryptography.X509Certificates;
using System.Threading.Tasks;

using MultiPurposeAuthSite.Tests.E2E.Infrastructure;
using MultiPurposeAuthSite.Tests.E2E.Tests.Fapi;

using Xunit;
using Xunit.Abstractions;

namespace MultiPurposeAuthSite.Tests.E2E.Tests.Issues
{
    /// <summary>
    /// RT-424. **fapi2 の登録も、非対称の証明（`private_key_jwt`・mTLS）なら client_credentials を使える**。
    /// </summary>
    /// <remarks>
    /// **以前は、client_credentials を normal の登録にしか許していなかった**（`ClientModePolicy`）ので、
    /// **FAPI 2.0 の RP として登録したクライアントは、client_credentials を使えなかった**
    /// （適合性テストの `fapi_client_credentials_grant` は、normal の登録で回していた。#416）。
    /// **FAPI 2.0 Security Profile §5.3.2.1 の NOTE 2 は、この文書の要件が client credentials grant のような他の grant にも
    /// 使えるように組み立ててあるとする**（ただし、詳しい安全性の分析を経たのは認可コードと CIBA の流れだけ、という注意も添えている）。
    ///
    /// | | 登録 | 測ること |
    /// |---|---|---|
    /// | **`RT-424.1`** | `TestClient_32`（fapi2・`private_key_jwt`） | **DPoP の証明を添えて、トークンが出て、DPoP の鍵に縛られる**。対照として、**`aud` をトークン エンドポイントの URL にすると `invalid_client`**（**fapi2 に固有の分岐ではない**。normal の登録も同じ。`RT-398.1`） |
    /// | **`RT-424.2`** | `TestClient2_2`（fapi2・`tls_client_auth`） | **証明書で認証して、トークンが出て、その証明書に縛られる**（net10.0 版だけ。net48 版は `-NetFxMtls` のとき） |
    /// | **`RT-424.3`** | `TestClient_47`（fapi2・`client_secret_post`） | **秘密で認証できても、トークンを出さない**（`unauthorized_client`。§5.3.2.1 の 6） |
    /// | **`RT-424.4`** | `FAPI1_PrivateKeyJwt_Client`（fapi1・`private_key_jwt`） | **fapi1 には開けていない**（`unauthorized_client`。#424 の範囲は fapi2） |
    /// </remarks>
    public class Fapi2ClientCredentialsTests : TargetTestBase
    {
        /// <summary>constructor</summary>
        /// <param name="output">ITestOutputHelper</param>
        public Fapi2ClientCredentialsTests(ITestOutputHelper output) : base(output) { }

        #region RT-424.1

        /// <summary>RT-424.1 fapi2 の登録は、private_key_jwt で client_credentials を使える（aud は issuer だけ）</summary>
        /// <param name="targetKey">core / netfx</param>
        /// <returns>Task</returns>
        [SkippableTheory]
        [MemberData(nameof(AllTargets))]
        public async Task RT42401_fapi2の登録はprivate_key_jwtでclient_credentialsを使える(string targetKey)
        {
            using (IdPClient client = this.Client(targetKey))
            {
                TestReport r = this.Report("RT-424.1",
                    "**fapi2 の登録は、`private_key_jwt` で認証すれば client_credentials を使える。`aud` は issuer だけを受ける**",
                    "**以前は、client_credentials を normal の登録にしか許していなかった**（`unauthorized_client`）。"
                    + "**FAPI 2.0 Security Profile は、要件が client credentials grant のような他の grant にも使えるように組み立ててあるとする**（§5.3.2.1 の NOTE 2）。"
                    + "**`aud` を issuer だけにすることは、fapi2 に固有の分岐ではない**（normal の登録も同じ。RFC 10070 §4。`RT-398.1`）。"
                    + "**fapi2 の登録が開けた後も、この規則で断られることを対照として見る**（§5.3.2.1 の 8）。",
                    "FAPI 2.0 Security Profile §5.3.2.1 / RFC 6749 §4.4 / #424");

                ClientRegistration reg = Flows.InjectedRegistration(client, KnownClients.TestClient_32);
                string issuer = await client.IssuerAsync();
                string tokenEndpoint = await MtlsAuthDPoPBindingTests.EndpointAsync(client, "token_endpoint");

                r.Target("POST /token（grant_type=client_credentials。client_name=" + KnownClients.TestClient_32
                    + "。fapi2。private_key_jwt（PS256）。DPoP の証明を添える）");

                r.Step("(1) aud = issuer の client_assertion と DPoP の証明で、client_credentials を要求する");

                JsonResponse token = await Fapi2ClientCredentialsTests.ClientCredentialsAsync(
                    client, reg, issuer, tokenEndpoint);

                r.VerifyEqual("HTTP 200", "200", ((int)token.StatusCode).ToString());
                r.Verify("トークンが返る", !string.IsNullOrEmpty(token.AccessToken),
                    "返る", string.IsNullOrEmpty(token.AccessToken) ? "**返らない**（" + token.ToString() + "）" : "返った");
                r.VerifyEqual("token_type が DPoP", "DPoP", token.String("token_type") ?? "（無し）");
                MtlsAuthDPoPBindingTests.VerifyCnf(r, token.AccessToken, expectX5t: false);

                r.Step("(2) 対照：aud = トークン エンドポイントの URL（同じクライアント・同じ鍵）");

                JsonResponse tokenAud = await Fapi2ClientCredentialsTests.ClientCredentialsAsync(
                    client, reg, client.Target.BaseUrl + "/token", tokenEndpoint);

                r.VerifyEqual("invalid_client", "invalid_client", tokenAud.Error ?? "（無い）");
                r.Verify("トークンを出さない", string.IsNullOrEmpty(tokenAud.AccessToken),
                    "出さない", string.IsNullOrEmpty(tokenAud.AccessToken) ? "出さない" : "**出した**");

                r.Done();
            }
        }

        #endregion

        #region RT-424.2

        /// <summary>RT-424.2 fapi2 の登録は、mTLS で client_credentials を使える</summary>
        /// <param name="targetKey">core（-NetFxMtls のときは netfx も）</param>
        /// <returns>Task</returns>
        [SkippableTheory]
        [MemberData(nameof(MtlsTests.MtlsTargets), MemberType = typeof(MtlsTests))]
        public async Task RT42402_fapi2の登録はmTLSでclient_credentialsを使える(string targetKey)
        {
            using (IdPClient client = this.Client(targetKey))
            {
                MtlsTests.SkipIfNoMtls(client.Target);
                ClientRegistration reg = Flows.InjectedRegistration(client, KnownClients.TestClient2_2);

                TestReport r = this.Report("RT-424.2",
                    "**fapi2 の登録は、mTLS（`tls_client_auth`）で認証すれば client_credentials を使える**",
                    "**FAPI 2.0 が認めるクライアント認証は、MTLS と `private_key_jwt`**（§5.3.2.1 の 6）。"
                    + "**`private_key_jwt`（RT-424.1）と同じく開けた。**"
                    + "**`tls_client_auth` で認証し、DPoP の証明を添えなければ、認証した証明書に縛る**（RFC 8705 §3。#346・#423）。",
                    "FAPI 2.0 Security Profile §5.3.2.1 / RFC 8705 §2・§3 / #424");

                r.Target("POST /token（grant_type=client_credentials。client_name=" + KnownClients.TestClient2_2 + "。fapi2。tls_client_auth）");

                using (X509Certificate2 cert = TestCertificate.ForTarget(client.Target, KnownClients.MtlsSubjectDn))
                {
                    r.Step("(1) 証明書で認証して、client_credentials を要求する");

                    JsonResponse token = await client.TokenWithCertificateAsync(new Dictionary<string, string>()
                    {
                        { "grant_type", "client_credentials" },
                        { "client_id", reg.ClientId },
                        { "scope", "profile" }
                    }, cert);

                    r.VerifyEqual("HTTP 200", "200", ((int)token.StatusCode).ToString());
                    r.Verify("トークンが返る", !string.IsNullOrEmpty(token.AccessToken),
                        "返る", string.IsNullOrEmpty(token.AccessToken) ? "**返らない**（" + token.ToString() + "）" : "返った");
                    MtlsAuthDPoPBindingTests.VerifyCnf(r, token.AccessToken, expectX5t: true, cert: cert, expectJkt: false);
                }

                r.Done();
            }
        }

        #endregion

        #region RT-424.4

        /// <summary>RT-424.4 fapi1 の登録には、private_key_jwt でも client_credentials を開けていない</summary>
        /// <param name="targetKey">core / netfx</param>
        /// <returns>Task</returns>
        [SkippableTheory]
        [MemberData(nameof(AllTargets))]
        public async Task RT42404_fapi1の登録にはclient_credentialsを開けていない(string targetKey)
        {
            using (IdPClient client = this.Client(targetKey))
            {
                TestReport r = this.Report("RT-424.4",
                    "**fapi1 の登録は、`private_key_jwt` で認証しても、client_credentials のトークンを出さない**（`unauthorized_client`）",
                    "**#424 で開けたのは fapi2 だけ**（`ClientModePolicy` の `private_key_jwt`・mTLS の行は normal と fapi2）。"
                    + "**FAPI 1.0 Advanced は認可コードの流れを前提にする**ので、fapi1 には開けていない。"
                    + "**`FA-1.1` は fapi1 × `client_secret` を見る**（`Proof.Any` の行）ので、**非対称の証明の行の除外は、ここで見る**（別モデルのレビューの指摘）。",
                    "RFC 6749 §5.2 / #424");

                ClientRegistration reg = Flows.Registration(client, KnownClients.Fapi1PrivateKeyJwtClient);
                string issuer = await client.IssuerAsync();
                string tokenEndpoint = await MtlsAuthDPoPBindingTests.EndpointAsync(client, "token_endpoint");

                r.Target("POST /token（grant_type=client_credentials。client_name=" + KnownClients.Fapi1PrivateKeyJwtClient
                    + "。fapi1。private_key_jwt（PS256））");

                r.Step("(1) aud = issuer の client_assertion で、client_credentials を要求する");

                JsonResponse token = await Fapi2ClientCredentialsTests.ClientCredentialsAsync(
                    client, reg, issuer, tokenEndpoint);

                r.Verify("トークンを出さない", string.IsNullOrEmpty(token.AccessToken),
                    "出さない", string.IsNullOrEmpty(token.AccessToken) ? "出さない" : "**出した**");
                r.VerifyEqual("エラーは unauthorized_client（認証は通っている）",
                    "unauthorized_client", token.Error ?? "（無し）");

                r.Done();
            }
        }

        #endregion

        #region RT-424.3

        /// <summary>RT-424.3 fapi2 の登録は、client_secret では client_credentials を使えない</summary>
        /// <param name="targetKey">core / netfx</param>
        /// <returns>Task</returns>
        [SkippableTheory]
        [MemberData(nameof(AllTargets))]
        public async Task RT42403_fapi2の登録はclient_secretではclient_credentialsを使えない(string targetKey)
        {
            using (IdPClient client = this.Client(targetKey))
            {
                TestReport r = this.Report("RT-424.3",
                    "**fapi2 の登録は、client_secret で認証できても、client_credentials のトークンを出さない**（`unauthorized_client`）",
                    "**FAPI 2.0 が認めるクライアント認証は、MTLS と `private_key_jwt` だけ**（§5.3.2.1 の 6）。"
                    + "**#424 で開けたのは、非対称の証明の行だけ**である（`ClientModePolicy`。認可コード・refresh_token の行と同じ形）。"
                    + "**`invalid_client` ではない** ＝ 秘密による認証は通り、その後の登録種別の判定で断られた（RFC 6749 §5.2）。",
                    "FAPI 2.0 Security Profile §5.3.2.1 / RFC 6749 §5.2 / #424");

                ClientRegistration reg = Flows.InjectedRegistration(client, KnownClients.TestClient_47);

                r.Target("POST /token（grant_type=client_credentials。client_name=" + KnownClients.TestClient_47 + "。fapi2。client_secret_post）");

                r.Step("(1) client_secret で、client_credentials を要求する");

                JsonResponse token = await client.TokenAsync(new Dictionary<string, string>()
                {
                    { "grant_type", "client_credentials" },
                    { "client_id", reg.ClientId },
                    { "client_secret", reg.ClientSecret },
                    { "scope", "profile" }
                });

                r.Verify("トークンを出さない", string.IsNullOrEmpty(token.AccessToken),
                    "出さない", string.IsNullOrEmpty(token.AccessToken) ? "出さない" : "**出した**");
                r.VerifyEqual("エラーは unauthorized_client（認証は通っている）",
                    "unauthorized_client", token.Error ?? "（無し）");

                r.Done();
            }
        }

        #endregion

        #region 部品

        /// <summary>client_assertion（PS256）と DPoP の証明で、client_credentials を要求する</summary>
        /// <param name="client">IdPClient</param>
        /// <param name="reg">クライアント</param>
        /// <param name="aud">client_assertion の aud</param>
        /// <param name="tokenEndpoint">広告された token_endpoint（DPoP の `htu`）</param>
        /// <returns>JsonResponse</returns>
        private static Task<JsonResponse> ClientCredentialsAsync(
            IdPClient client, ClientRegistration reg, string aud, string tokenEndpoint)
        {
            long now = DateTimeOffset.UtcNow.ToUnixTimeSeconds();

            //  **FAPI の登録は RS256 を断る**（#395）ので、PS256 で署名する。
            string assertion = JwsSigner.SignPS256(client, new Dictionary<string, object>()
            {
                { "iss", reg.ClientId },
                { "sub", reg.ClientId },
                { "aud", aud },
                { "jti", Guid.NewGuid().ToString("N") },
                { "iat", now },
                { "exp", now + 300 }
            });

            return client.PostJsonAsync(client.ToLocalUrl(tokenEndpoint), new Dictionary<string, string>()
            {
                { "grant_type", "client_credentials" },
                { "scope", "profile" },
                { "client_id", reg.ClientId },
                { "client_assertion_type", "urn:ietf:params:oauth:client-assertion-type:jwt-bearer" },
                { "client_assertion", assertion }
            }, MtlsAuthDPoPBindingTests.DPoPHeader(client, "POST", tokenEndpoint, null));
        }

        #endregion
    }
}
