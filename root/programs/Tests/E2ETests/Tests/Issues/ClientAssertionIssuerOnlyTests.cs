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
//* クラス名        ：ClientAssertionIssuerOnlyTests
//* クラス日本語名  ：RT-398 クライアント認証の client_assertion の aud は issuer だけを受ける（RFC 10070 §4・§5）
//*
//* 作成日時        ：－
//* 作成者          ：－
//* 更新履歴        ：－
//*
//*  日時        更新者            内容
//*  ----------  ----------------  -------------------------------------------------
//*  2026/11/17  玄人 幸道         新規（#398）
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
    /// RT-398. **クライアント認証の `client_assertion` の `aud` は、issuer だけを受ける**（RFC 10070 §4・§5）。
    /// </summary>
    /// <remarks>
    /// **RFC 10070**（2026 年 11 月。RFC 7523・RFC 9126 を更新）は、クライアント認証の JWT の `aud` を issuer の唯一の値に限り、
    /// **トークン エンドポイントの URL を audience にすることを禁じた**（§4）。**以前は、fapi2 以外の登録でトークン エンドポイントの URL も受けていた**（#294）。
    ///
    /// **CIBA の流れだけは以前のまま**（RFC 10070 は CIBA を直接の対象にしていない。人と決めた）。
    ///
    /// | | 測ること |
    /// |---|---|
    /// | **`RT-398.1`** | **`/token` の client_credentials は、トークン エンドポイントの URL を `invalid_client` で断り、issuer なら通る** |
    /// | **`RT-398.2`** | **`/token` の CIBA のグラントは、issuer・トークン エンドポイントの URL を受ける**（クライアント認証を通り、知らない `auth_req_id` として `invalid_grant`）。**CIBA の口・PAR の口の URL は `invalid_client`** |
    ///
    /// - `/revoke` は `RT-294.54`、PAR は `RT-371.2`、CIBA の口は `RT-371.1`、fapi2 の登録は `RT-323.1`・`RT-371.3` が測る
    /// - **JWT Bearer グラントの `assertion`** は、トークン エンドポイントの URL も受けるまま（RFC 10070 §4 の 1。`JwtBearerTests`）
    /// - **`RT-398.2` は、知らない `auth_req_id` で測る**（クライアント認証が通れば `invalid_grant`、通らなければ `invalid_client` で、区別できる）。
    ///   **利用者の端末を登録しない**ので、CIBA のほかのテストと同じコレクションに入れなくてよい
    /// </remarks>
    public class ClientAssertionIssuerOnlyTests : TargetTestBase
    {
        /// <summary>client_assertion_type（RFC 7523 §2.2）</summary>
        private const string JwtBearerAssertionType = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer";

        /// <summary>CIBA の grant_type</summary>
        private const string CibaGrantType = "urn:openid:params:grant-type:ciba";

        /// <summary>コンストラクタ</summary>
        /// <param name="output">ITestOutputHelper</param>
        public ClientAssertionIssuerOnlyTests(ITestOutputHelper output) : base(output)
        {
        }

        #region RT-398.1

        /// <summary>RT-398.1 /token の client_credentials は、client_assertion の aud に issuer だけを受ける</summary>
        /// <param name="targetKey">core / netfx</param>
        /// <returns>Task</returns>
        [SkippableTheory]
        [MemberData(nameof(AllTargets))]
        public async Task RT39801_tokenのclient_credentialsはaudにissuerだけを受ける(string targetKey)
        {
            using (IdPClient client = this.Client(targetKey))
            {
                TestReport r = this.Report("RT-398.1",
                    "**/token の client_credentials は、client_assertion の aud にトークン エンドポイントの URL を受けず（invalid_client）、issuer なら通る**",
                    "**RFC 10070 §4 は、クライアント認証の JWT の aud を issuer の唯一の値に限り、トークン エンドポイントの URL を audience にすることを禁じた**"
                    + "（認可サーバは、そうでない JWT を断らなければならない）。"
                    + "**以前は、fapi2 以外の登録でトークン エンドポイントの URL も受けていた**（#294）。",
                    "RFC 10070 §4 / #398");

                ClientRegistration reg = Flows.InjectedRegistration(client, KnownClients.TestClient_24);
                string issuer = await client.IssuerAsync();

                r.Target("POST /token（grant_type=client_credentials。client_name=" + KnownClients.TestClient_24 + "。normal。private_key_jwt（RS256））");

                r.Step("(1) aud = トークン エンドポイントの URL");

                JsonResponse tokenAud = await ClientAssertionIssuerOnlyTests.ClientCredentialsAsync(
                    client, reg, client.Target.BaseUrl + "/token");

                r.VerifyEqual("invalid_client", "invalid_client", tokenAud.Error ?? "（無い）");
                r.VerifyEqual("HTTP 401", "401", ((int)tokenAud.StatusCode).ToString());
                r.Verify("トークンを出さない", string.IsNullOrEmpty(tokenAud.AccessToken),
                    "出さない", string.IsNullOrEmpty(tokenAud.AccessToken) ? "出さない" : "**出した**");

                r.Step("(2) 対照：aud = issuer（同じクライアント・同じ鍵）");

                JsonResponse issuerAud = await ClientAssertionIssuerOnlyTests.ClientCredentialsAsync(client, reg, issuer);

                r.Verify("トークンが返る", !string.IsNullOrEmpty(issuerAud.AccessToken),
                    "返る", string.IsNullOrEmpty(issuerAud.AccessToken) ? "**返らない**（" + issuerAud.ToString() + "）" : "返った");

                r.Done();
            }
        }

        #endregion

        #region RT-398.2

        /// <summary>RT-398.2 /token の CIBA のグラントは、client_assertion の aud に issuer とトークン エンドポイントの URL を受ける</summary>
        /// <param name="targetKey">core / netfx</param>
        /// <returns>Task</returns>
        [SkippableTheory]
        [MemberData(nameof(AllTargets))]
        public async Task RT39802_tokenのCIBAのグラントはaudにトークンエンドポイントのURLも受ける(string targetKey)
        {
            using (IdPClient client = this.Client(targetKey))
            {
                TestReport r = this.Report("RT-398.2",
                    "**/token の CIBA のグラントは、client_assertion の aud に issuer とトークン エンドポイントの URL を受ける。CIBA の口・PAR の口の URL は受けない**",
                    "**CIBA の流れは以前のまま**（RFC 10070 は CIBA を直接の対象にしていない。#398 で人と決めた）。"
                    + "**ほかのグラントは issuer だけ**（RT-398.1）。"
                    + "**知らない auth_req_id で測る**：クライアント認証を通れば invalid_grant（CIBA Core 1.0 §11）、通らなければ invalid_client。",
                    "CIBA Core 1.0 §11 / RFC 10070 §4 / #398");

                ClientRegistration reg = Flows.InjectedRegistration(client, KnownClients.TestClient4_4);
                string issuer = await client.IssuerAsync();
                string unknownAuthReqId = "e2e-unknown-" + Guid.NewGuid().ToString("N");

                r.Target("POST /token（grant_type=" + ClientAssertionIssuerOnlyTests.CibaGrantType
                    + "。client_name=" + KnownClients.TestClient4_4 + "。fapi_ciba。private_key_jwt（ES256））");

                foreach (KeyValuePair<string, string> aud in new Dictionary<string, string>()
                {
                    { "issuer", issuer },
                    { "トークン エンドポイントの URL", client.Target.BaseUrl + "/token" }
                })
                {
                    r.Step("aud = " + aud.Key + "（クライアント認証を通る）");

                    JsonResponse res = await ClientAssertionIssuerOnlyTests.CibaTokenAsync(client, reg, aud.Value, unknownAuthReqId);

                    r.VerifyEqual("invalid_grant（知らない auth_req_id。invalid_client ではない）", "invalid_grant", res.Error ?? "（無い）");
                }

                foreach (KeyValuePair<string, string> aud in new Dictionary<string, string>()
                {
                    { "CIBA の口の URL（/token では受けない）", client.Target.BaseUrl + "/ciba_authz" },
                    { "PAR の口の URL", client.Target.BaseUrl + "/par" }
                })
                {
                    r.Step("aud = " + aud.Key);

                    JsonResponse res = await ClientAssertionIssuerOnlyTests.CibaTokenAsync(client, reg, aud.Value, unknownAuthReqId);

                    r.VerifyEqual("invalid_client", "invalid_client", res.Error ?? "（無い）");
                }

                r.Done();
            }
        }

        #endregion

        #region 補助

        /// <summary>client_assertion（RS256）で client_credentials を要求する</summary>
        /// <param name="client">IdPClient</param>
        /// <param name="reg">クライアント</param>
        /// <param name="aud">aud</param>
        /// <returns>JsonResponse</returns>
        private static Task<JsonResponse> ClientCredentialsAsync(IdPClient client, ClientRegistration reg, string aud)
        {
            return client.TokenAsync(new Dictionary<string, string>()
            {
                { "grant_type", "client_credentials" },
                { "scope", "profile" },
                { "client_id", reg.ClientId },
                { "client_assertion_type", ClientAssertionIssuerOnlyTests.JwtBearerAssertionType },
                { "client_assertion", JwsSigner.SignRS256(client, ClientAssertionIssuerOnlyTests.Payload(reg.ClientId, aud)) }
            });
        }

        /// <summary>client_assertion（ES256）で CIBA のトークンを要求する</summary>
        /// <param name="client">IdPClient</param>
        /// <param name="reg">クライアント</param>
        /// <param name="aud">aud</param>
        /// <param name="authReqId">auth_req_id</param>
        /// <returns>JsonResponse</returns>
        private static Task<JsonResponse> CibaTokenAsync(IdPClient client, ClientRegistration reg, string aud, string authReqId)
        {
            return client.TokenAsync(new Dictionary<string, string>()
            {
                { "grant_type", ClientAssertionIssuerOnlyTests.CibaGrantType },
                { "auth_req_id", authReqId },
                { "client_assertion_type", ClientAssertionIssuerOnlyTests.JwtBearerAssertionType },
                { "client_assertion", JwsSigner.SignES256(client, ClientAssertionIssuerOnlyTests.Payload(reg.ClientId, aud)) }
            });
        }

        /// <summary>client_assertion の中身（RFC 7523 §3）</summary>
        /// <param name="clientId">client_id（iss・sub）</param>
        /// <param name="aud">aud</param>
        /// <returns>payload</returns>
        private static Dictionary<string, object> Payload(string clientId, string aud)
        {
            long now = DateTimeOffset.UtcNow.ToUnixTimeSeconds();

            return new Dictionary<string, object>()
            {
                { "iss", clientId },
                { "sub", clientId },
                { "aud", aud },
                { "jti", Guid.NewGuid().ToString("N") },
                { "iat", now },
                { "exp", now + 300 }
            };
        }

        #endregion
    }
}
