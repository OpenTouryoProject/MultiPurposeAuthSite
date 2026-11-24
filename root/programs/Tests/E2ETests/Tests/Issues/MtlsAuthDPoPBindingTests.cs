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
//* クラス名        ：MtlsAuthDPoPBindingTests
//* クラス日本語名  ：RT-423 mTLS で認証して DPoP で縛るトークンは、証明書に縛らない（RFC 8705 §4・§3.4・RFC 9449 §1）
//*
//* 作成日時        ：－
//* 作成者          ：－
//* 更新履歴        ：－
//*
//*  日時        更新者            内容
//*  ----------  ----------------  -------------------------------------------------
//*  2026/11/23  玄人 幸道         新規（#423）
//*  2026/11/24  玄人 幸道         部品（EndpointAsync・DPoPHeader・VerifyCnf）を RT-424 からも使えるようにし、VerifyCnf に jkt が無いことを見る形を足した（#424）
//**********************************************************************************

using System;
using System.Collections.Generic;
using System.Net.Http;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.Json;
using System.Threading.Tasks;

using MultiPurposeAuthSite.Tests.E2E.Infrastructure;
using MultiPurposeAuthSite.Tests.E2E.Tests.Fapi;

using Xunit;
using Xunit.Abstractions;

namespace MultiPurposeAuthSite.Tests.E2E.Tests.Issues
{
    /// <summary>
    /// RT-423. **mTLS（`tls_client_auth`）で認証して DPoP で縛るトークンは、証明書に縛らない**。
    /// </summary>
    /// <remarks>
    /// **以前は、`tls_client_auth` で認証すると、登録によらず証明書にも縛っていた**（`cnf.x5t#S256` と `cnf.jkt` の両方）。
    /// **資源は `x5t#S256` があれば証明書を求める**ので、**DPoP だけで資源を呼ぶ RP が 401 になった**
    /// （適合性テストの `fapi2-sp-mtls-dpop`。#416 で足したプラン）。
    /// **mTLS の認証と、証明書に縛ることは、別々に選べる**（RFC 8705 §4。§3.4 の `tls_client_certificate_bound_access_tokens` の既定は false）。
    /// **DPoP は、認証の方法によらず縛れる**（RFC 9449 §1）。
    ///
    /// | | 登録 | 測ること |
    /// |---|---|---|
    /// | **`RT-423.1`** | `tls_client_auth`（fapi2） | **認可コードの交換に DPoP の証明を添えると、トークンは DPoP の鍵だけに縛られ、DPoP だけで `/userinfo` を使える** |
    /// | **`RT-423.2`** | `tls_client_auth`（normal） | **client_credentials でも同じ**（トークンを作る関数が別：`CreateFromClaims`） |
    /// | **`RT-423.3`** | `tls_client_certificate_bound_access_tokens` | **証明書を必須にした登録は、DPoP の証明が在っても、従来どおり証明書にも縛る** |
    ///
    /// **DPoP の証明が無ければ、従来どおり認証した証明書に縛る**（`RT-346.7`・`.12`・`FA-6.4`）。
    /// **mTLS を測れるのは net10.0 版だけ**（net48 版は `-NetFxMtls` のとき）。
    /// </remarks>
    public class MtlsAuthDPoPBindingTests : TargetTestBase
    {
        /// <summary>PKCE の code_verifier（RFC 7636 Appendix B）</summary>
        private const string PkceVerifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";

        /// <summary>PkceVerifier の S256（RFC 7636 Appendix B）。fapi2 の登録は S256 の PKCE を求める（#366）</summary>
        private const string PkceChallenge = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";

        /// <summary>コンストラクタ</summary>
        /// <param name="output">ITestOutputHelper</param>
        public MtlsAuthDPoPBindingTests(ITestOutputHelper output) : base(output)
        {
        }

        #region RT-423.1

        /// <summary>RT-423.1 tls_client_auth で認証し、DPoP の証明を添えた認可コードのトークンは、DPoP だけで資源を使える</summary>
        /// <param name="targetKey">core（-NetFxMtls のときは netfx も）</param>
        /// <returns>Task</returns>
        [SkippableTheory]
        [MemberData(nameof(MtlsTests.MtlsTargets), MemberType = typeof(MtlsTests))]
        public async Task RT42301_mTLSで認証しDPoPで縛るトークンはDPoPだけで資源を使える(string targetKey)
        {
            using (IdPClient client = await this.SignedInClientAsync(targetKey))
            {
                MtlsTests.SkipIfNoMtls(client.Target);
                ClientRegistration reg = Flows.InjectedRegistration(client, KnownClients.TestClient2_2);

                TestReport r = this.Report("RT-423.1",
                    "`tls_client_auth` で認証し、DPoP の証明を添えて認可コードを交換したトークンは、DPoP の鍵だけに縛られ（`cnf.x5t#S256` が無い）、"
                    + "証明書を提示せずに DPoP だけで `/userinfo` を使える",
                    "**mTLS の認証と、証明書に縛ることは、別々に選べる**（RFC 8705 §4）。**証明書に縛るかは登録で決まり、既定は縛らない**（§3.4）。"
                    + "**DPoP は、認証の方法によらず縛れる**（RFC 9449 §1）。"
                    + "**以前は両方に縛り、DPoP だけで呼ぶと 401（「The access token is bound to a client certificate.」）だった。**",
                    "RFC 8705 §4・§3.4 / RFC 9449 §1・§7.1 / #423");

                r.Target("client_name=" + KnownClients.TestClient2_2
                    + "（fapi2。token_endpoint_auth_method=tls_client_auth。tls_client_certificate_bound_access_tokens は立てていない）");

                string tokenEndpoint = await MtlsAuthDPoPBindingTests.EndpointAsync(client, "token_endpoint");
                string userInfoEndpoint = await MtlsAuthDPoPBindingTests.EndpointAsync(client, "userinfo_endpoint");

                AuthZResponse authz = await Flows.AuthorizeCodeAsync(client, reg, redirectUri: reg.RedirectUri,
                    extra: new Dictionary<string, string>()
                    {
                        { "code_challenge", MtlsAuthDPoPBindingTests.PkceChallenge },
                        { "code_challenge_method", "S256" }
                    });

                Assert.False(string.IsNullOrEmpty(authz.Code),
                    "前提: 認可コードが取得できること（error=" + (authz.Error ?? "なし") + "）");

                using (X509Certificate2 cert = TestCertificate.ForTarget(client.Target, KnownClients.MtlsSubjectDn))
                {
                    r.Step("(1) 証明書で認証し、DPoP の証明を添えて、認可コードを交換する");

                    JsonResponse token = await client.PostWithCertificateAsync("/token", new Dictionary<string, string>()
                    {
                        { "grant_type", "authorization_code" },
                        { "code", authz.Code },
                        { "client_id", reg.ClientId },
                        { "redirect_uri", reg.RedirectUri },
                        { "code_verifier", MtlsAuthDPoPBindingTests.PkceVerifier }
                    }, cert, MtlsAuthDPoPBindingTests.DPoPHeader(client, "POST", tokenEndpoint, null));

                    r.VerifyEqual("HTTP 200", "200", ((int)token.StatusCode).ToString());
                    r.VerifyEqual("token_type が DPoP", "DPoP", token.String("token_type") ?? "（無し）");
                    MtlsAuthDPoPBindingTests.VerifyCnf(r, token.AccessToken, expectX5t: false);

                    r.Step("(2) 証明書を提示せずに、DPoP の証明だけで /userinfo を呼ぶ");

                    HttpResponseMessage res = await client.GetAsync(client.ToLocalUrl(userInfoEndpoint),
                        new Dictionary<string, string>()
                        {
                            { "Authorization", "DPoP " + token.AccessToken },
                            { "DPoP", MtlsAuthDPoPBindingTests.Proof(client, "GET", userInfoEndpoint, token.AccessToken) }
                        });

                    string body = await res.Content.ReadAsStringAsync();

                    r.VerifyEqual("HTTP 200", "200", ((int)res.StatusCode).ToString());
                    r.Verify("sub が返る（利用者の情報が取れている）", MtlsAuthDPoPBindingTests.HasSub(body),
                        "返る", MtlsAuthDPoPBindingTests.HasSub(body) ? "返る（値は出さない）" : "**無い**");

                    r.Step("(3) DPoP の証明を添えずに、/userinfo を呼ぶ（縛りが外れていないこと）");

                    HttpResponseMessage none = await client.GetAsync(client.ToLocalUrl(userInfoEndpoint),
                        new Dictionary<string, string>()
                        {
                            { "Authorization", "Bearer " + token.AccessToken }
                        });

                    r.VerifyEqual("HTTP 401", "401", ((int)none.StatusCode).ToString());
                }

                r.Note("**DPoP の証明を添えなければ、従来どおり認証した証明書に縛る**（`FA-6.4`・`RT-346.7`・`.12`）。");

                r.Done();
            }
        }

        #endregion

        #region RT-423.2

        /// <summary>RT-423.2 tls_client_auth の client_credentials も、DPoP の証明を添えれば DPoP の鍵だけに縛られる</summary>
        /// <param name="targetKey">core（-NetFxMtls のときは netfx も）</param>
        /// <returns>Task</returns>
        [SkippableTheory]
        [MemberData(nameof(MtlsTests.MtlsTargets), MemberType = typeof(MtlsTests))]
        public async Task RT42302_mTLSで認証しDPoPで縛るclient_credentialsは証明書に縛られない(string targetKey)
        {
            using (IdPClient client = this.Client(targetKey))
            {
                MtlsTests.SkipIfNoMtls(client.Target);
                ClientRegistration reg = Flows.InjectedRegistration(client, KnownClients.TestClient_42);

                TestReport r = this.Report("RT-423.2",
                    "`tls_client_auth` で認証し、DPoP の証明を添えた client_credentials のトークンは、DPoP の鍵だけに縛られる（`cnf.x5t#S256` が無い）",
                    "**client_credentials のトークンは、認可コードとは別の関数（`CreateFromClaims`）で作る**ので、別に測る。"
                    + "**どちらも、縛るものを決めるのは `CheckSenderConstraint` の 1 か所**である。",
                    "RFC 8705 §4・§3.4 / RFC 9449 §1・§5 / #423");

                r.Target("client_name=" + KnownClients.TestClient_42 + "（normal。token_endpoint_auth_method=tls_client_auth）");

                string tokenEndpoint = await MtlsAuthDPoPBindingTests.EndpointAsync(client, "token_endpoint");

                using (X509Certificate2 cert = TestCertificate.ForTarget(client.Target, KnownClients.MtlsSubjectDn))
                {
                    r.Step("(1) 証明書で認証し、DPoP の証明を添えて、client_credentials でトークンを取る");

                    JsonResponse token = await client.PostWithCertificateAsync("/token", new Dictionary<string, string>()
                    {
                        { "grant_type", "client_credentials" },
                        { "client_id", reg.ClientId }
                    }, cert, MtlsAuthDPoPBindingTests.DPoPHeader(client, "POST", tokenEndpoint, null));

                    r.VerifyEqual("HTTP 200", "200", ((int)token.StatusCode).ToString());
                    r.VerifyEqual("token_type が DPoP", "DPoP", token.String("token_type") ?? "（無し）");
                    MtlsAuthDPoPBindingTests.VerifyCnf(r, token.AccessToken, expectX5t: false);
                }

                r.Done();
            }
        }

        #endregion

        #region RT-423.3

        /// <summary>RT-423.3 証明書を必須にした登録は、DPoP の証明が在っても証明書にも縛る</summary>
        /// <param name="targetKey">core（-NetFxMtls のときは netfx も）</param>
        /// <returns>Task</returns>
        [SkippableTheory]
        [MemberData(nameof(MtlsTests.MtlsTargets), MemberType = typeof(MtlsTests))]
        public async Task RT42303_証明書を必須にした登録はDPoPが在っても証明書にも縛る(string targetKey)
        {
            using (IdPClient client = this.Client(targetKey))
            {
                MtlsTests.SkipIfNoMtls(client.Target);
                ClientRegistration reg = Flows.InjectedRegistration(client, KnownClients.TestClient_40);

                TestReport r = this.Report("RT-423.3",
                    "`tls_client_certificate_bound_access_tokens` の登録は、DPoP の証明を添えても、従来どおり提示した証明書にも縛る（`cnf.x5t#S256` と `cnf.jkt` の両方）",
                    "**証明書に縛るかは、登録で決まる**（RFC 8705 §3.4）。**登録が求めたなら、DPoP の証明が在っても外さない**"
                    + "（#423 で外すのは、登録が求めていないときだけ）。",
                    "RFC 8705 §3.4 / RFC 9449 §6 / #346 / #423");

                r.Target("client_name=" + KnownClients.TestClient_40 + "（tls_client_certificate_bound_access_tokens=true。認証は client_secret）");

                string tokenEndpoint = await MtlsAuthDPoPBindingTests.EndpointAsync(client, "token_endpoint");

                using (X509Certificate2 cert = TestCertificate.ForTarget(client.Target, KnownClients.MtlsSubjectDn))
                {
                    r.Step("(1) 証明書と DPoP の証明を添えて、client_credentials でトークンを取る");

                    JsonResponse token = await client.PostWithCertificateAsync("/token", new Dictionary<string, string>()
                    {
                        { "grant_type", "client_credentials" },
                        { "client_id", reg.ClientId },
                        { "client_secret", reg.ClientSecret }
                    }, cert, MtlsAuthDPoPBindingTests.DPoPHeader(client, "POST", tokenEndpoint, null));

                    r.VerifyEqual("HTTP 200", "200", ((int)token.StatusCode).ToString());
                    MtlsAuthDPoPBindingTests.VerifyCnf(r, token.AccessToken, expectX5t: true, cert: cert);
                }

                r.Done();
            }
        }

        #endregion

        #region 部品

        /// <summary>Discovery が広告する口（無ければ Skip）</summary>
        /// <param name="client">IdPClient</param>
        /// <param name="name">項目の名前</param>
        /// <returns>URL</returns>
        internal static async Task<string> EndpointAsync(IdPClient client, string name)
        {
            JsonResponse res = await client.GetJsonAsync("/.well-known/openid-configuration");

            string endpoint = res.String(name);

            Skip.If(string.IsNullOrEmpty(endpoint),
                "Discovery が " + name + " を広告していません。");

            return endpoint;
        }

        /// <summary>`DPoP` ヘッダ（1 つだけの辞書）</summary>
        /// <param name="client">IdPClient</param>
        /// <param name="htm">HTTP メソッド</param>
        /// <param name="htu">宛先</param>
        /// <param name="accessToken">`ath` の材料（null なら入れない）</param>
        /// <returns>ヘッダ</returns>
        internal static Dictionary<string, string> DPoPHeader(
            IdPClient client, string htm, string htu, string accessToken)
        {
            return new Dictionary<string, string>()
            {
                { "DPoP", MtlsAuthDPoPBindingTests.Proof(client, htm, htu, accessToken) }
            };
        }

        /// <summary>DPoP の証明を作る（RFC 9449 §4.2）</summary>
        /// <param name="client">IdPClient</param>
        /// <param name="htm">HTTP メソッド</param>
        /// <param name="htu">宛先</param>
        /// <param name="accessToken">`ath` の材料（null なら入れない）</param>
        /// <returns>証明</returns>
        private static string Proof(IdPClient client, string htm, string htu, string accessToken)
        {
            Dictionary<string, object> payload = new Dictionary<string, object>()
            {
                { "jti", Guid.NewGuid().ToString("N") },
                { "htm", htm },
                { "htu", htu },
                { "iat", DateTimeOffset.UtcNow.ToUnixTimeSeconds() }
            };

            if (accessToken != null)
            {
                payload.Add("ath", Base64Url.Encode(SHA256.HashData(Encoding.ASCII.GetBytes(accessToken))));
            }

            return JwsSigner.SignDPoP(client, payload);
        }

        /// <summary>access_token の `cnf` を確かめる</summary>
        /// <param name="r">TestReport</param>
        /// <param name="accessToken">access_token</param>
        /// <param name="expectX5t">`x5t#S256` が在るべきか</param>
        /// <param name="cert">`x5t#S256` が在るべきときの証明書</param>
        /// <param name="expectJkt">`jkt` が在るべきか（DPoP の証明を添えない要求なら false。#424）</param>
        internal static void VerifyCnf(TestReport r, string accessToken, bool expectX5t, X509Certificate2 cert = null, bool expectJkt = true)
        {
            string jkt = MtlsAuthDPoPBindingTests.CnfOf(accessToken, "jkt");
            string x5t = MtlsAuthDPoPBindingTests.CnfOf(accessToken, "x5t#S256");

            if (expectJkt)
            {
                r.Verify("access_token の cnf に jkt が在る（DPoP の鍵に縛られている）", !string.IsNullOrEmpty(jkt),
                    "在る", string.IsNullOrEmpty(jkt) ? "**無い**" : "在る");
            }
            else
            {
                //  **DPoP の証明を添えない要求**（RT-424.2。#424）。
                r.Verify("access_token の cnf に jkt が無い（DPoP の証明を添えていない）", string.IsNullOrEmpty(jkt),
                    "無い", string.IsNullOrEmpty(jkt) ? "無い" : "**在る**");
            }

            if (expectX5t)
            {
                string expected = Base64Url.Encode(SHA256.HashData(cert.RawData));

                r.Verify("access_token の cnf の x5t#S256 は、提示した証明書の SHA-256（BASE64URL）",
                    x5t == expected,
                    "一致",
                    string.IsNullOrEmpty(x5t) ? "**無し**" : (x5t == expected ? "一致" : "**別の値**"));
            }
            else
            {
                r.Verify("access_token の cnf に x5t#S256 が無い（証明書には縛られていない）", string.IsNullOrEmpty(x5t),
                    "無い", string.IsNullOrEmpty(x5t) ? "無い" : "**在る**");
            }
        }

        /// <summary>access_token の `cnf` の項目（無ければ空）</summary>
        /// <param name="accessToken">access_token</param>
        /// <param name="name">項目の名前</param>
        /// <returns>値</returns>
        private static string CnfOf(string accessToken, string name)
        {
            if (string.IsNullOrEmpty(accessToken))
            {
                return "";
            }

            JsonElement payload = Jwt.Payload(accessToken);

            if (payload.ValueKind == JsonValueKind.Object
                && payload.TryGetProperty("cnf", out JsonElement cnf)
                && cnf.ValueKind == JsonValueKind.Object
                && cnf.TryGetProperty(name, out JsonElement value)
                && value.ValueKind == JsonValueKind.String)
            {
                return value.GetString() ?? "";
            }

            return "";
        }

        /// <summary>応答の本文に sub が在るか</summary>
        /// <param name="body">本文</param>
        /// <returns>在れば true</returns>
        private static bool HasSub(string body)
        {
            try
            {
                using (JsonDocument doc = JsonDocument.Parse(body))
                {
                    return doc.RootElement.ValueKind == JsonValueKind.Object
                        && doc.RootElement.TryGetProperty("sub", out JsonElement _);
                }
            }
            catch (JsonException)
            {
                return false;
            }
        }

        #endregion
    }
}
