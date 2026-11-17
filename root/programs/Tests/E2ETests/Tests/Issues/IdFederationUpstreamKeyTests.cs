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
//* クラス名        ：IdFederationUpstreamKeyTests
//* クラス日本語名  ：RT-358 OIDC の ID 連携で、上流の鍵が決まらなければ断る
//*
//* 作成日時        ：－
//* 作成者          ：－
//* 更新履歴        ：－
//*
//*  日時        更新者            内容
//*  ----------  ----------------  -------------------------------------------------
//*  2026/11/17  玄人 幸道         新規（#358）
//**********************************************************************************

using System;
using System.Collections.Generic;
using System.Net;
using System.Net.Http;
using System.Threading.Tasks;

using MultiPurposeAuthSite.Tests.E2E.Infrastructure;

using Xunit;
using Xunit.Abstractions;

namespace MultiPurposeAuthSite.Tests.E2E.Tests.Issues
{
    /// <summary>
    /// RT-358. **OIDC の ID 連携で、上流の鍵（期待する `issuer` ＋ `jwks_uri` か証明書）が決まらなければ断る**。
    /// </summary>
    /// <remarks>
    /// **以前は、鍵を指定しない `IdToken.Verify`（この配備の設定の鍵と `SpRp_Issuer`）に進んでいた**（1:1 のテスト構成の名残）。
    /// **通るのは上流と下流が同じ鍵を持つ構成のときだけ**で、一般の上流では鍵の検証で落ちていた。
    ///
    /// | | 測ること |
    /// |---|---|
    /// | **`RT-358.1`** | **管理画面で、鍵を決められない OIDC の上流の行（`issuer`・`jwks_uri`・証明書が無い）を足し、その上流で ID 連携すると、上流は認可コードを返すが、下流にはサインインできない** |
    ///
    /// - **直す前も、このテストは落ちない**（`container/E2E` の上流は下流と別の鍵を使うので、鍵を指定しない版でも検証で落ちていた）。
    ///   **断る理由の違い**（「鍵が決まらない」か「鍵が合わない」か）は、サイトのログにしか出ず、E2E では測れない。**「通す」側に戻らないことを測る**
    /// - **上流のクライアントは、既定の上流（単数キー）と同じもの**（`test.ps1` が `E2E_IdFederationClientId_*` で渡す）。
    ///   クライアントの秘密まで正しいので、**トークンの引き換えまでは通り、id_token の検証の手前で断られる**
    /// - **行は user store に足す**ので、設定の既定の上流（導線の先頭）は変わらない（`RT-292.2`）
    /// </remarks>
    public class IdFederationUpstreamKeyTests : TargetTestBase
    {
        /// <summary>足す上流の行の鍵</summary>
        private const string TestKey = "e2e_rt358_nokey";

        /// <summary>コンストラクタ</summary>
        /// <param name="output">ITestOutputHelper</param>
        public IdFederationUpstreamKeyTests(ITestOutputHelper output) : base(output)
        {
        }

        #region RT-358.1

        /// <summary>RT-358.1 上流の鍵が決まらない OIDC の ID 連携は、サインインさせない</summary>
        /// <param name="targetKey">core / netfx</param>
        /// <returns>Task</returns>
        [SkippableTheory]
        [MemberData(nameof(AllTargets))]
        public async Task RT35801_上流の鍵が決まらないID連携はサインインさせない(string targetKey)
        {
            using (IdPClient admin = this.Client(targetKey))
            using (IdPClient client = this.Client(targetKey))
            {
                await admin.SignInAsAdministratorAsync();

                string index = await IdFederationAdmin.SkipIfLockedDownAsync(admin);
                string upstream = await IdFederation.SkipIfUpstreamIsDownAsync(client);

                TestReport r = this.Report("RT-358.1",
                    "**上流の鍵（issuer ＋ jwks_uri か証明書）を決められない OIDC の上流で ID 連携すると、上流が認可コードを返しても、下流にはサインインさせない**",
                    "**上流の鍵が決まらなければ、id_token を検証できないので断る。**"
                    + "**以前は、この配備の設定の鍵で検証する版に進んでいた**（1:1 のテスト構成の名残。上流と下流が同じ鍵を持つ構成でだけ通った）。"
                    + "**直す前も、上流の鍵が違うので落ちていた**（理由の違いはサイトのログにしか出ない）。**「通す」側に戻らないことを測る。**",
                    "OIDC Core 1.0 §3.1.3.7 / #358");

                string clientId = Environment.GetEnvironmentVariable("E2E_IdFederationClientId_" + targetKey);
                string clientSecret = Environment.GetEnvironmentVariable("E2E_IdFederationClientSecret_" + targetKey);

                //  **test.ps1 を通さずに動かしたときは、上流のクライアントが分からない**ので Skip する（上流が止まっているときと揃える）。
                Skip.If(string.IsNullOrEmpty(clientId) || string.IsNullOrEmpty(clientSecret),
                    "上流のクライアントが分かりません（test.ps1 が E2E_IdFederationClientId_" + targetKey + " を渡す）。");

                r.Target(client.Target.DisplayName + " ← 上流 " + upstream + "（user store に足した、鍵を決められない行）");

                if (IdFederationAdmin.Contains(index, IdFederationUpstreamKeyTests.TestKey))
                {
                    await IdFederationAdmin.DeleteAsync(admin, IdFederationUpstreamKeyTests.TestKey);
                }

                try
                {
                    r.Step("(1) 管理画面で、issuer・jwks_uri・discovery・証明書の無い OIDC の上流の行を足す");

                    HttpResponseMessage create = await IdFederationAdmin.CreateAsync(
                        admin, IdFederationUpstreamKeyTests.TestKey, "oidc",
                        "E2E RT-358 Upstream (no key)", "",
                        new Dictionary<string, string>()
                        {
                            { "ClientID", clientId },
                            { "ClientSecret", clientSecret },
                            { "AuthorizeEndpoint", upstream.TrimEnd('/') + "/authorize" },
                            { "TokenEndpoint", upstream.TrimEnd('/') + "/token" },
                            { "UserInfoEndpoint", upstream.TrimEnd('/') + "/userinfo" }
                        });

                    Assert.True(
                        create.StatusCode == HttpStatusCode.Found
                        || create.StatusCode == HttpStatusCode.Redirect
                        || create.StatusCode == HttpStatusCode.SeeOther,
                        "前提: 上流の行を足せること（HTTP " + (int)create.StatusCode + "）");

                    r.Step("(2) 上流でサインインしておき、下流でその上流を選んで ID 連携する");

                    Assert.True(await IdFederation.SignInUpstreamAsync(client, upstream), "前提: 上流にサインインできること");

                    FederationResult fed = await IdFederation.FederateAsync(
                        client, TestEnv.TestUserName(targetKey), IdFederationUpstreamKeyTests.TestKey);

                    r.Verify("上流は認可コードを返す（上流の行の口とクライアントは正しい）", fed.Authorized,
                        "code あり", fed.Authorized ? "あり（値は伏せる）" : "**無し**");

                    Assert.True(fed.Authorized, "前提: 上流が認可コードを返すこと");

                    r.Step("(3) 下流は、上流の鍵が決まらないので id_token を受けず、サインインさせない");

                    bool signedIn = await IdFederation.IsSignedInAsync(client);

                    r.Verify("下流にサインインしていない", !signedIn,
                        "サインインしない", signedIn ? "**サインインした**" : "サインインしていない");
                }
                finally
                {
                    await IdFederationAdmin.DeleteAsync(admin, IdFederationUpstreamKeyTests.TestKey);
                }

                r.Done();
            }
        }

        #endregion
    }
}
