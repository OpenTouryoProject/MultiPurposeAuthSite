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
//* クラス名        ：ClientAssertionTypeTests
//* クラス日本語名  ：RT-368 client_assertion_type の無い client_assertion を受けない（RFC 7521 §4.2）
//*
//* 作成日時        ：－
//* 作成者          ：－
//* 更新履歴        ：－
//*
//*  日時        更新者            内容
//*  ----------  ----------------  -------------------------------------------------
//*  2026/11/13  玄人 幸道         新規（#368）
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
    /// RT-368. **`client_assertion_type` の無い `client_assertion` を受けない**（RFC 7521 §4.2）。
    /// </summary>
    /// <remarks>
    /// **以前は、`client_assertion_type` が来ていなければ、`client_assertion` をそのまま検証していた**
    /// （Open棟梁 の `OAuth2AndOIDCSpec.GetClientAssertion`。**型が来ていて値が違うときだけ**断っていた。`RT-238.3`）。
    /// **適合性テストの `ensure-invalid-client-assertions-fail` が、型の無い PAR を 201 で受けたので落ちた。**
    ///
    /// | | 測ること |
    /// |---|---|
    /// | **`RT-368.1`** | **型の無い `client_assertion` は、PAR でも `/revoke` でも `invalid_client`**。型を付ければ通る |
    ///
    /// **従来の名前 `assertion` だけを送るクライアント**（OpenTouryo#592 より前）は、従来どおり通す（`RT-238.2`）。
    /// </remarks>
    public class ClientAssertionTypeTests : TargetTestBase
    {
        /// <summary>client_assertion_type（RFC 7523 §2.2）</summary>
        private const string JwtBearerAssertionType = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer";

        /// <summary>コンストラクタ</summary>
        /// <param name="output">ITestOutputHelper</param>
        public ClientAssertionTypeTests(ITestOutputHelper output) : base(output)
        {
        }

        /// <summary>RS256 の client_assertion を作る（RFC 7523 §3。aud は issuer）</summary>
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

        #region RT-368.1

        /// <summary>RT-368.1 client_assertion_type の無い client_assertion は invalid_client</summary>
        /// <param name="targetKey">core / netfx</param>
        /// <returns>Task</returns>
        [SkippableTheory]
        [MemberData(nameof(AllTargets))]
        public async Task RT36801_client_assertion_typeの無いclient_assertionはinvalid_client(string targetKey)
        {
            using (IdPClient client = this.Client(targetKey))
            {
                TestReport r = this.Report("RT-368.1",
                    "client_assertion_type の無い client_assertion は、PAR でも /revoke でも invalid_client で断り、型を付ければ通す",
                    "**RFC 7521 §4.2 は、client_assertion_type を REQUIRED としている。**"
                    + "**以前は、型が来ていなければ client_assertion をそのまま検証して通していた**（型が違うときだけ断っていた。RT-238.3）。"
                    + "**断るときのエラーは invalid_client**（クライアント認証の失敗。RFC 6749 §5.2）。",
                    "RFC 7521 §4.2 / RFC 6749 §5.2 / #368");

                string issuer = await client.IssuerAsync();

                ClientRegistration fapi2 = Flows.Registration(client, KnownClients.Fapi2Client);
                ClientRegistration pkjwt = Flows.InjectedRegistration(client, KnownClients.TestClient_24);

                r.Target("POST /par（client_name=" + KnownClients.Fapi2Client + "）・POST /revoke（client_name="
                    + KnownClients.TestClient_24 + "。private_key_jwt）");

                r.Step("(1) client_assertion_type を付けずに POST /par");

                JsonResponse par = await client.PostJsonAsync("/par", new Dictionary<string, string>()
                {
                    { "client_id", fapi2.ClientId },
                    { "client_assertion", ClientAssertionTypeTests.ClientAssertion(client, fapi2.ClientId, issuer) },
                    { "response_type", "code" },
                    { "scope", "openid" },
                    { "redirect_uri", fapi2.RedirectUri },
                    { "state", "state-rt3681" },
                    { "code_challenge", "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM" },
                    { "code_challenge_method", "S256" }
                });

                r.VerifyEqual("PAR : HTTP 401", "401", ((int)par.StatusCode).ToString());
                r.VerifyEqual("PAR : invalid_client", "invalid_client", par.Error ?? "（無し）");
                r.Verify("PAR : request_uri を返さない", string.IsNullOrEmpty(par.String("request_uri")),
                    "返さない", string.IsNullOrEmpty(par.String("request_uri")) ? "返さなかった" : "**返した**");

                r.Step("(2) client_assertion_type を付けずに POST /revoke");

                JsonResponse noType = await client.RevokeAsync(new Dictionary<string, string>()
                {
                    { "token", "not-a-token" },
                    { "client_assertion", ClientAssertionTypeTests.ClientAssertion(client, pkjwt.ClientId, issuer) }
                });

                r.VerifyEqual("/revoke : invalid_client", "invalid_client", noType.Error ?? "（無し）");

                r.Step("(3) 同じクライアントで、client_assertion_type を付けて POST /revoke（通る）");

                JsonResponse withType = await client.RevokeAsync(new Dictionary<string, string>()
                {
                    { "token", "not-a-token" },
                    { "client_assertion_type", ClientAssertionTypeTests.JwtBearerAssertionType },
                    { "client_assertion", ClientAssertionTypeTests.ClientAssertion(client, pkjwt.ClientId, issuer) }
                });

                r.VerifyEqual("/revoke : 認証が通る（HTTP 200）", "200", ((int)withType.StatusCode).ToString());

                r.Done();
            }
        }

        #endregion
    }
}
