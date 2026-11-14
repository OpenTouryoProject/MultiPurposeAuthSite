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
//* クラス名        ：FapiDefaultSigningAlgTests
//* クラス日本語名  ：RT-394 FAPI の登録は、署名の alg を登録していなければ ES256 で署名する（FAPI 1.0 Advanced §8.6・FAPI 2.0 Security Profile §5.4.1）
//*
//* 作成日時        ：－
//* 作成者          ：－
//* 更新履歴        ：－
//*
//*  日時        更新者            内容
//*  ----------  ----------------  -------------------------------------------------
//*  2026/11/14  玄人 幸道         新規（#394）
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
    /// RT-394. **FAPI の登録は、署名の alg を登録していなければ ES256 で署名する**（FAPI 1.0 Advanced §8.6・FAPI 2.0 Security Profile §5.4.1）。
    /// </summary>
    /// <remarks>
    /// **以前は、FAPI の登録も RS256 だった**（#370 で見送った。Open棟梁 の RP 側の検証が、暗号化しない ES256 を受けなかった。OpenTouryo#695 で直った）。
    ///
    /// | | 測ること |
    /// |---|---|
    /// | **`RT-394.1`** | **alg を登録していない fapi1 の登録**の access_token・id_token・JARM が **ES256** で、JWKS で検証できる。**FAPI でない登録は RS256 のまま** |
    ///
    /// **fapi2 の登録も同じ関数（`Helper.GetIdTokenSignedResponseAlg`・`GetAuthorizationSignedResponseAlg`）で決まる。**
    /// fapi2 の id_token は暗号化していて、中の JWS は以前から ES256（#355）。
    /// </remarks>
    public class FapiDefaultSigningAlgTests : TargetTestBase
    {
        /// <summary>RFC 7636 附録 B の code_verifier</summary>
        private const string Verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";

        /// <summary>RFC 7636 附録 B の code_challenge（S256）</summary>
        private const string Challenge = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";

        /// <summary>コンストラクタ</summary>
        /// <param name="output">ITestOutputHelper</param>
        public FapiDefaultSigningAlgTests(ITestOutputHelper output) : base(output)
        {
        }

        #region RT-394.1

        /// <summary>RT-394.1 alg を登録していない FAPI の登録は ES256 で署名する</summary>
        /// <param name="targetKey">core / netfx</param>
        /// <returns>Task</returns>
        [SkippableTheory]
        [MemberData(nameof(AllTargets))]
        public async Task RT39401_algを登録していないFAPIの登録はES256で署名する(string targetKey)
        {
            using (IdPClient client = await this.SignedInClientAsync(targetKey))
            {
                TestReport r = this.Report("RT-394.1",
                    "**署名の alg を登録していない FAPI の登録（fapi1）の access_token・id_token・JARM は ES256 で署名され、JWKS で検証できる。FAPI でない登録は RS256 のまま**",
                    "**FAPI 1.0 Advanced §8.6 は PS256 か ES256 を、FAPI 2.0 Security Profile §5.4.1 は PS256・ES256・EdDSA を求め、RS256 を認めない。**"
                    + "**以前は FAPI の登録も、登録が無ければ RS256 だった**（#370 で見送った。OpenTouryo#695 で RP 側の検証が直った）。"
                    + "**FAPI でない登録の既定は RS256**（OIDC Core・JARM §3）。",
                    "FAPI 1.0 Advanced §8.6 / FAPI 2.0 Security Profile §5.4.1 / #394");

                ClientRegistration fapi1 = Flows.Registration(client, KnownClients.Fapi1Client);
                ClientRegistration normal = Flows.Registration(client, KnownClients.MvcSample);
                JsonElement jwkSet = await Flows.JwkSetAsync(client);

                r.Target("client_name=" + KnownClients.Fapi1Client + "（fapi1。id_token_signed_response_alg・authorization_signed_response_alg を登録していない）"
                    + " / 対照=" + KnownClients.MvcSample + "（normal。登録していない）");

                r.Step("(1) fapi1 : 認可コード（PKCE）を引き換える");

                JsonResponse fapiToken = await FapiDefaultSigningAlgTests.CodeAsync(client, fapi1, withPkce: true);

                Assert.False(fapiToken == null || string.IsNullOrEmpty(fapiToken.AccessToken),
                    "前提: fapi1 の登録がトークンを受け取れること（" + (fapiToken == null ? "認可で失敗" : fapiToken.ToString()) + "）");

                FapiDefaultSigningAlgTests.VerifyAlg(r, "fapi1 の access_token", fapiToken.AccessToken, "ES256", jwkSet);
                FapiDefaultSigningAlgTests.VerifyAlg(r, "fapi1 の id_token", fapiToken.IdToken, "ES256", jwkSet);

                r.Step("(2) fapi1 : JARM（response_mode=query.jwt）");

                AuthZResponse jarm = await Flows.AuthorizeCodeAsync(client, fapi1,
                    state: "state-rt3941", redirectUri: fapi1.RedirectUri,
                    extra: new Dictionary<string, string>()
                    {
                        { "response_mode", "query.jwt" },
                        { "code_challenge", FapiDefaultSigningAlgTests.Challenge },
                        { "code_challenge_method", "S256" }
                    });

                FapiDefaultSigningAlgTests.VerifyAlg(r, "fapi1 の JARM", jarm.Get("response"), "ES256", jwkSet);

                r.Step("(3) 対照 : FAPI でない登録（normal）は RS256 のまま");

                JsonResponse normalToken = await FapiDefaultSigningAlgTests.CodeAsync(client, normal, withPkce: false);

                Assert.False(normalToken == null || string.IsNullOrEmpty(normalToken.AccessToken),
                    "前提: normal の登録がトークンを受け取れること");

                FapiDefaultSigningAlgTests.VerifyAlg(r, "normal の access_token", normalToken.AccessToken, "RS256", jwkSet);
                FapiDefaultSigningAlgTests.VerifyAlg(r, "normal の id_token", normalToken.IdToken, "RS256", jwkSet);

                r.Done();
            }
        }

        #endregion

        #region 補助

        /// <summary>認可コードを取り、引き換える</summary>
        /// <param name="client">IdPClient</param>
        /// <param name="reg">クライアント</param>
        /// <param name="withPkce">PKCE（S256）で引き換えるか（false なら client_secret）</param>
        /// <returns>JsonResponse（認可で失敗したら null）</returns>
        private static async Task<JsonResponse> CodeAsync(IdPClient client, ClientRegistration reg, bool withPkce)
        {
            AuthZResponse authz = await Flows.AuthorizeCodeAsync(client, reg, redirectUri: reg.RedirectUri,
                extra: withPkce
                    ? new Dictionary<string, string>()
                    {
                        { "code_challenge", FapiDefaultSigningAlgTests.Challenge },
                        { "code_challenge_method", "S256" }
                    }
                    : null);

            if (string.IsNullOrEmpty(authz.Code))
            {
                return null;
            }

            Dictionary<string, string> form = new Dictionary<string, string>()
            {
                { "grant_type", "authorization_code" },
                { "code", authz.Code },
                { "client_id", reg.ClientId },
                { "redirect_uri", reg.RedirectUri }
            };

            if (withPkce)
            {
                form["code_verifier"] = FapiDefaultSigningAlgTests.Verifier;
            }
            else
            {
                form["client_secret"] = reg.ClientSecret;
            }

            return await client.TokenAsync(form);
        }

        /// <summary>JWT の alg と、JWKS での検証を確かめる</summary>
        /// <param name="r">TestReport</param>
        /// <param name="label">何の JWT か</param>
        /// <param name="jwt">JWT</param>
        /// <param name="expectedAlg">期待する alg</param>
        /// <param name="jwkSet">JWK Set</param>
        private static void VerifyAlg(TestReport r, string label, string jwt, string expectedAlg, JsonElement jwkSet)
        {
            r.VerifyEqual(label + " : alg", expectedAlg,
                string.IsNullOrEmpty(jwt) ? "（無い）" : (Jwt.String(Jwt.Header(jwt), "alg") ?? "（読めない）"));

            if (!string.IsNullOrEmpty(jwt))
            {
                Jwks.Result sig = Jwks.Verify(jwt, jwkSet);
                r.Verify(label + " : 署名を JWKS で検証できる", sig.Verified, "検証できる", sig.Detail);
            }
        }

        #endregion
    }
}
