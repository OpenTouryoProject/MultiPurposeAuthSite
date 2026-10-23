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
//* クラス名        ：ImplicitDisabledTests
//* クラス日本語名  ：RT-314 Implicit を閉じた配備では、Hybrid / OIDC の Implicit も閉じる
//*
//* 作成日時        ：－
//* 作成者          ：－
//* 更新履歴        ：－
//*
//*  日時        更新者            内容
//*  ----------  ----------------  -------------------------------------------------
//*  2026/10/24  玄人 幸道         新規（#314）
//**********************************************************************************

using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

using MultiPurposeAuthSite.Tests.E2E.Infrastructure;

using Xunit;
using Xunit.Abstractions;

namespace MultiPurposeAuthSite.Tests.E2E.Tests.Issues
{
    /// <summary>
    /// RT-314. **`EnableImplicitGrantType` を false にした配備では、
    /// access_token をフロント チャネルで返す response_type をすべて断る。**
    /// </summary>
    /// <remarks>
    /// | | 測ること |
    /// |---|---|
    /// | **`RT-314.1`** | **Discovery が `token` を含む response_type を広告しない**（`code` / `code id_token` は広告する） |
    /// | **`RT-314.2`** | **`token` を含む response_type を `unsupported_response_type` で断り、access_token を返さない** |
    /// | **`RT-314.3`** | **`code id_token` は従来どおり通る**（access_token をフロント チャネルで返さない） |
    ///
    /// **以前は `token` 単独しか断っておらず、Hybrid（`code token` など）で access_token を返していた**（#314）。
    ///
    /// **通しの E2E は Implicit を開けて起動する**（廃止したフローの回帰を測るため。#220）。
    /// **だから、閉じた設定で起動して測る** —
    /// **`test.ps1 -Launch -NoImplicit -Filter "FullyQualifiedName~ImplicitDisabledTests"`。**
    ///
    /// **付けなければ、このクラスは走らない**（`test.ps1` が除外する。`DPoPNonceTests` と同じ流儀）。
    /// </remarks>
    public class ImplicitDisabledTests : TargetTestBase
    {
        /// <summary>access_token をフロント チャネルで返す response_type</summary>
        private static readonly string[] TokenResponseTypes = new string[]
        {
            "token", "id_token token", "code token", "code id_token token"
        };

        /// <summary>コンストラクタ</summary>
        /// <param name="output">ITestOutputHelper</param>
        public ImplicitDisabledTests(ITestOutputHelper output) : base(output)
        {
        }

        /// <summary>測る対象 : `-NoImplicit` で起動したときだけ</summary>
        public static IEnumerable<object[]> NoImplicitTargets
        {
            get
            {
                if (Environment.GetEnvironmentVariable("MPAS_NO_IMPLICIT") == "true")
                {
                    yield return new object[] { TestEnv.CoreKey };
                    yield return new object[] { TestEnv.NetFxKey };
                }
            }
        }

        /// <summary>認可要求を送る（Hybrid のテストと同じ形）</summary>
        /// <param name="client">IdPClient</param>
        /// <param name="reg">クライアント</param>
        /// <param name="responseType">response_type</param>
        /// <returns>AuthZResponse</returns>
        private static Task<AuthZResponse> AuthorizeAsync(
            IdPClient client, ClientRegistration reg, string responseType)
        {
            return client.AuthorizeAsync(new Dictionary<string, string>()
            {
                { "response_type", responseType },
                { "client_id", reg.ClientId },
                { "scope", "openid" },
                { "redirect_uri", reg.RedirectUriToken },
                { "state", "state-rt314" },
                { "nonce", "nonce-" + Guid.NewGuid().ToString("N") },
                { "prompt", "none" }
            });
        }

        #region RT-314.1

        /// <summary>RT-314.1 Discovery が token を含む response_type を広告しない</summary>
        /// <param name="targetKey">core / netfx</param>
        /// <returns>Task</returns>
        [SkippableTheory]
        [MemberData(nameof(NoImplicitTargets))]
        public async Task RT31401_Discoveryがtokenを含むresponse_typeを広告しない(string targetKey)
        {
            using (IdPClient client = this.Client(targetKey))
            {
                TestReport r = this.Report("RT-314.1",
                    "**Implicit を閉じた配備の Discovery は、`token` を含む response_type を広告しない**"
                    + "（`code` / `code id_token` は広告する）",
                    "**受け付けないものを広告すると、RP の自動設定が失敗する経路を選ぶ。**"
                    + "**以前は `EnableImplicitGrantType` が false でも、"
                    + "Hybrid（`code token` など）を広告していた**（#314）。",
                    "OIDC Discovery 1.0 §3（response_types_supported）/ #314");

                r.Target("GET /.well-known/openid-configuration（`EnableImplicitGrantType` = false）");

                JsonResponse discovery = await client.GetJsonAsync("/.well-known/openid-configuration");
                string[] types = discovery.Strings("response_types_supported") ?? new string[0];

                r.Observe("response_types_supported", string.Join(" / ", types));

                foreach (string type in ImplicitDisabledTests.TokenResponseTypes)
                {
                    r.Verify("`" + type + "` を広告しない", !types.Contains(type),
                        "広告しない", types.Contains(type) ? "**広告している**" : "広告しない");
                }

                foreach (string type in new string[] { "code", "code id_token" })
                {
                    r.Verify("`" + type + "` は広告する", types.Contains(type),
                        "広告する", types.Contains(type) ? "広告する" : "**広告していない**");
                }

                r.Done();
            }
        }

        #endregion

        #region RT-314.2

        /// <summary>RT-314.2 token を含む response_type を断り、access_token を返さない</summary>
        /// <param name="targetKey">core / netfx</param>
        /// <returns>Task</returns>
        [SkippableTheory]
        [MemberData(nameof(NoImplicitTargets))]
        public async Task RT31402_tokenを含むresponse_typeを断る(string targetKey)
        {
            using (IdPClient client = await this.SignedInClientAsync(targetKey))
            {
                TestReport r = this.Report("RT-314.2",
                    "**Implicit を閉じた配備では、`token` を含む response_type を"
                    + "`unsupported_response_type` で断り、access_token を返さない**",
                    "**「Implicit を止めれば、フロント チャネルで access_token は出ない」**という期待を、"
                    + "**Hybrid でも成り立たせる。**"
                    + "**以前は `token` 単独しか断っておらず、`code token` / `code id_token token` は"
                    + "access_token を返していた**（#314）。",
                    "OAuth 2.0 Security BCP §2.1.2 / RFC 6749 §4.1.2.1 / #314");

                ClientRegistration reg = Flows.Registration(client, KnownClients.TestClient);

                r.Target("client_name=" + KnownClients.TestClient + " / scope=openid（`EnableImplicitGrantType` = false）");

                foreach (string type in ImplicitDisabledTests.TokenResponseTypes)
                {
                    r.Step("GET /authorize に response_type=" + type + " を付けて送る");

                    AuthZResponse res = await ImplicitDisabledTests.AuthorizeAsync(client, reg, type);

                    r.VerifyEqual("`" + type + "` は unsupported_response_type",
                        "unsupported_response_type", res.Error ?? "なし");

                    r.Verify("`" + type + "` で access_token を返さない",
                        string.IsNullOrEmpty(res.Get("access_token")),
                        "返さない", res.Get("access_token") == null ? "返さなかった" : "**返してしまった**");
                }

                r.Done();
            }
        }

        #endregion

        #region RT-314.3

        /// <summary>RT-314.3 code id_token は従来どおり通る</summary>
        /// <param name="targetKey">core / netfx</param>
        /// <returns>Task</returns>
        [SkippableTheory]
        [MemberData(nameof(NoImplicitTargets))]
        public async Task RT31403_code_id_tokenは通る(string targetKey)
        {
            using (IdPClient client = await this.SignedInClientAsync(targetKey))
            {
                TestReport r = this.Report("RT-314.3",
                    "**Implicit を閉じた配備でも、`code id_token` は従来どおり通る**",
                    "**`code id_token` は access_token をフロント チャネルで返さない**ので、"
                    + "**`EnableImplicitGrantType` の対象ではない**（閉じすぎていないことを測る）。",
                    "OIDC Core §3.3 / #314");

                ClientRegistration reg = Flows.Registration(client, KnownClients.TestClient);

                r.Target("client_name=" + KnownClients.TestClient + " / response_type=code id_token / scope=openid");
                r.Step("GET /authorize に response_type=code id_token を付けて送る");

                AuthZResponse res = await ImplicitDisabledTests.AuthorizeAsync(client, reg, "code id_token");

                r.Verify("エラーにならない", string.IsNullOrEmpty(res.Error),
                    "エラー無し", res.Error ?? "エラー無し");

                r.Verify("code が返る", !string.IsNullOrEmpty(res.Code),
                    "code あり", res.Code == null ? "なし" : "あり（値は伏せる）");

                r.Verify("id_token が返る", !string.IsNullOrEmpty(res.Get("id_token")),
                    "id_token あり", res.Get("id_token") == null ? "なし" : "あり（値は伏せる）");

                r.Verify("access_token は返さない", string.IsNullOrEmpty(res.Get("access_token")),
                    "返さない", res.Get("access_token") == null ? "返さなかった" : "**返してしまった**");

                r.Done();
            }
        }

        #endregion
    }
}
