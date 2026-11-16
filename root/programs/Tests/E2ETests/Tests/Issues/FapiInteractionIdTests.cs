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
//* クラス名        ：FapiInteractionIdTests
//* クラス日本語名  ：RT-384 FAPI の登録のトークンの /userinfo は、x-fapi-interaction-id を返す（FAPI 1.0 Baseline §6.2.1 の 11）
//*
//* 作成日時        ：－
//* 作成者          ：－
//* 更新履歴        ：－
//*
//*  日時        更新者            内容
//*  ----------  ----------------  -------------------------------------------------
//*  2026/11/15  玄人 幸道         新規（#384）
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
    /// RT-384. **FAPI の登録のトークンの `/userinfo` は、`x-fapi-interaction-id` を返す**（FAPI 1.0 Baseline §6.2.1 の 11）。
    /// </summary>
    /// <remarks>
    /// **以前は、このヘッダを扱っていなかった**（適合性テストの FAPI 1.0 Advanced・FAPI-CIBA で、資源の検査がここで落ちていた）。
    ///
    /// | | 測ること |
    /// |---|---|
    /// | **`RT-384.1`** | **FAPI の登録（fapi1）のトークン**：要求の UUID をそのまま返す。無ければ新しい UUID、**UUID の形でなければ新しい UUID**（§6.2.2 の 5 は UUID を求める）。**FAPI でない登録のトークン・検証できないトークンには付けない** |
    ///
    /// **FAPI の判別は、トークンの `aud` で引いた登録の `client_mode`**（fapi1・fapi2・fapi_ciba。#384 の決め）。
    /// **ログ（§6.2.1 の 12）は E2E では見ない**（OPERATION のログに 1 行残す）。
    /// </remarks>
    public class FapiInteractionIdTests : TargetTestBase
    {
        /// <summary>ヘッダ名</summary>
        private const string HeaderName = "x-fapi-interaction-id";

        /// <summary>RFC 7636 附録 B の code_verifier</summary>
        private const string Verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";

        /// <summary>RFC 7636 附録 B の code_challenge（S256）</summary>
        private const string Challenge = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";

        /// <summary>コンストラクタ</summary>
        /// <param name="output">ITestOutputHelper</param>
        public FapiInteractionIdTests(ITestOutputHelper output) : base(output)
        {
        }

        #region RT-384.1

        /// <summary>RT-384.1 FAPI の登録のトークンの /userinfo は x-fapi-interaction-id を返す</summary>
        /// <param name="targetKey">core / netfx</param>
        /// <returns>Task</returns>
        [SkippableTheory]
        [MemberData(nameof(AllTargets))]
        public async Task RT38401_FAPIの登録のトークンのuserinfoはx_fapi_interaction_idを返す(string targetKey)
        {
            using (IdPClient client = await this.SignedInClientAsync(targetKey))
            {
                TestReport r = this.Report("RT-384.1",
                    "**FAPI の登録（fapi1）のトークンの /userinfo は、要求の x-fapi-interaction-id（UUID）をそのまま返し、無い・UUID の形でないときは新しい UUID を返す。FAPI でない登録・検証できないトークンには付けない**",
                    "**FAPI 1.0 Baseline §6.2.1 の 11 は、保護された資源が、要求の値か RFC 4122 の UUID を応答のヘッダに付けることを求める。**"
                    + "**§6.2.2 の 5 は、クライアントが送る値を UUID とする**ので、形の違う値は使わず新しく作る（ヘッダとログに外の値を書かない）。"
                    + "**以前はこのヘッダを扱っていなかった。**",
                    "FAPI 1.0 Baseline §6.2.1 の 11 / §6.2.2 の 5 / #384");

                ClientRegistration fapi1 = Flows.Registration(client, KnownClients.Fapi1Client);
                ClientRegistration normal = Flows.Registration(client, KnownClients.MvcSample);

                r.Target("GET /userinfo（" + KnownClients.Fapi1Client + "（fapi1）のトークン・"
                    + KnownClients.MvcSample + "（normal）のトークン）");

                string fapiToken = await FapiInteractionIdTests.AccessTokenAsync(client, fapi1, withPkce: true);
                string normalToken = await FapiInteractionIdTests.AccessTokenAsync(client, normal, withPkce: false);

                Assert.False(string.IsNullOrEmpty(fapiToken) || string.IsNullOrEmpty(normalToken),
                    "前提: fapi1・normal の登録が access_token を受け取れること");

                r.Step("(1) fapi1 : 要求に UUID を付ける（そのまま返る）");

                string requested = Guid.NewGuid().ToString("D");

                JsonResponse echoed = await client.UserInfoWithHeadersAsync("Bearer " + fapiToken,
                    new Dictionary<string, string>() { { FapiInteractionIdTests.HeaderName, requested } });

                r.VerifyEqual("HTTP 200", "200", ((int)echoed.StatusCode).ToString());
                r.VerifyEqual("x-fapi-interaction-id が要求の値", requested,
                    echoed.Header(FapiInteractionIdTests.HeaderName) ?? "（無い）");

                r.Step("(2) fapi1 : 要求に付けない（新しい UUID が返る）");

                JsonResponse generated = await client.UserInfoWithHeadersAsync("Bearer " + fapiToken, null);

                FapiInteractionIdTests.VerifyUuid(r, "x-fapi-interaction-id が UUID", generated.Header(FapiInteractionIdTests.HeaderName));

                r.Step("(3) fapi1 : UUID の形でない値を付ける（使わずに、新しい UUID が返る）");

                JsonResponse replaced = await client.UserInfoWithHeadersAsync("Bearer " + fapiToken,
                    new Dictionary<string, string>() { { FapiInteractionIdTests.HeaderName, "not-a-uuid" } });

                string replacedId = replaced.Header(FapiInteractionIdTests.HeaderName);

                FapiInteractionIdTests.VerifyUuid(r, "x-fapi-interaction-id が UUID", replacedId);
                r.Verify("要求の値は返さない", replacedId != "not-a-uuid",
                    "返さない", replacedId == "not-a-uuid" ? "**返した**" : "返さなかった");

                r.Step("(3') fapi1 : openid の無いトークン（検証できた後の 403。付く）");

                //  **トークンを検証できた後のエラーにも付ける**（#384 のレビュー）。**openid の無いトークンは 403 / insufficient_scope。**
                string noOpenidToken = await FapiInteractionIdTests.AccessTokenAsync(client, fapi1, withPkce: true, scope: "profile");

                Assert.False(string.IsNullOrEmpty(noOpenidToken), "前提: openid の無い access_token を受け取れること");

                string requested403 = Guid.NewGuid().ToString("D");

                JsonResponse forbidden = await client.UserInfoWithHeadersAsync("Bearer " + noOpenidToken,
                    new Dictionary<string, string>() { { FapiInteractionIdTests.HeaderName, requested403 } });

                r.VerifyEqual("HTTP 403", "403", ((int)forbidden.StatusCode).ToString());
                r.VerifyEqual("x-fapi-interaction-id が要求の値", requested403,
                    forbidden.Header(FapiInteractionIdTests.HeaderName) ?? "（無い）");

                r.Step("(4) FAPI でない登録（normal）のトークン（付けない）");

                JsonResponse normalRes = await client.UserInfoWithHeadersAsync("Bearer " + normalToken,
                    new Dictionary<string, string>() { { FapiInteractionIdTests.HeaderName, Guid.NewGuid().ToString("D") } });

                r.VerifyEqual("HTTP 200", "200", ((int)normalRes.StatusCode).ToString());
                r.Verify("x-fapi-interaction-id を付けない", normalRes.Header(FapiInteractionIdTests.HeaderName) == null,
                    "付けない", normalRes.Header(FapiInteractionIdTests.HeaderName) ?? "付けなかった");

                r.Step("(5) 検証できないトークン（FAPI の登録かどうか分からないので、付けない）");

                JsonResponse invalid = await client.UserInfoWithHeadersAsync("Bearer not-a-token",
                    new Dictionary<string, string>() { { FapiInteractionIdTests.HeaderName, Guid.NewGuid().ToString("D") } });

                r.VerifyEqual("HTTP 401", "401", ((int)invalid.StatusCode).ToString());
                r.Verify("x-fapi-interaction-id を付けない", invalid.Header(FapiInteractionIdTests.HeaderName) == null,
                    "付けない", invalid.Header(FapiInteractionIdTests.HeaderName) ?? "付けなかった");

                r.Done();
            }
        }

        #endregion

        #region 補助

        /// <summary>値が RFC 4122 の UUID の形（8-4-4-4-12）であることを確かめる</summary>
        /// <param name="r">TestReport</param>
        /// <param name="label">何の値か</param>
        /// <param name="value">値</param>
        private static void VerifyUuid(TestReport r, string label, string value)
        {
            bool isUuid = !string.IsNullOrEmpty(value) && Guid.TryParseExact(value, "D", out Guid _);

            r.Verify(label, isUuid, "UUID の形", isUuid ? "UUID の形" : "**" + (value ?? "（無い）") + "**");
        }

        /// <summary>認可コードを取り、引き換えて access_token を返す</summary>
        /// <param name="client">IdPClient</param>
        /// <param name="reg">クライアント</param>
        /// <param name="withPkce">PKCE（S256）で引き換えるか（false なら client_secret）</param>
        /// <param name="scope">scope（null なら既定。openid を含む）</param>
        /// <returns>access_token（取れなければ null）</returns>
        private static async Task<string> AccessTokenAsync(
            IdPClient client, ClientRegistration reg, bool withPkce, string scope = null)
        {
            AuthZResponse authz = (scope == null)
                ? await FapiInteractionIdTests.AuthorizeAsync(client, reg, withPkce)
                : await Flows.AuthorizeCodeAsync(client, reg, scope, nonce: null, redirectUri: reg.RedirectUri,
                    extra: withPkce
                        ? new Dictionary<string, string>()
                        {
                            { "code_challenge", FapiInteractionIdTests.Challenge },
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
                form["code_verifier"] = FapiInteractionIdTests.Verifier;
            }
            else
            {
                form["client_secret"] = reg.ClientSecret;
            }

            JsonResponse token = await client.TokenAsync(form);

            return token.AccessToken;
        }

        /// <summary>既定の scope で認可コードを取る</summary>
        /// <param name="client">IdPClient</param>
        /// <param name="reg">クライアント</param>
        /// <param name="withPkce">PKCE（S256）を付けるか</param>
        /// <returns>AuthZResponse</returns>
        private static Task<AuthZResponse> AuthorizeAsync(IdPClient client, ClientRegistration reg, bool withPkce)
        {
            return Flows.AuthorizeCodeAsync(client, reg, redirectUri: reg.RedirectUri,
                extra: withPkce
                    ? new Dictionary<string, string>()
                    {
                        { "code_challenge", FapiInteractionIdTests.Challenge },
                        { "code_challenge_method", "S256" }
                    }
                    : null);
        }

        #endregion
    }
}
