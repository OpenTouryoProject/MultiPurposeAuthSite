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
//* クラス名        ：RequestObjectClaimTests
//* クラス日本語名  ：RT Request Object・client_assertion のクレームの確認（#336）
//*
//* 作成日時        ：－
//* 作成者          ：－
//* 更新履歴        ：－
//*
//*  日時        更新者            内容
//*  ----------  ----------------  -------------------------------------------------
//*  2026/11/06  玄人 幸道         新規（#336）
//*  2026/11/13  玄人 幸道         RT-336.6 の fapi2 の PAR に S256 の PKCE を足した（fapi2 は PKCE 無しを断るようになった。#366）
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
    /// RT-336. Open棟梁 の検証の厳格化（OpenTouryo#653・#654）に追随して、
    /// **`/ros` と PAR の Request Object の `aud`・`exp`・`nbf`、client_assertion の `sub`** を確かめる。
    /// </summary>
    /// <remarks>
    /// | 口 | 以前 | いま |
    /// |---|---|---|
    /// | `/ros`・PAR の `request`（JAR） | 署名と `iss`・`client_id` だけ | **`aud` は issuer だけ。在る `exp`・`nbf` も確かめる** |
    /// | 同（FAPI の登録） | 同上 | **`exp`・`nbf` を必須にし、寿命を 60 分以内に限る** |
    /// | `/ros` の CIBA の要求 | 署名だけ（時刻は `/ciba_authz` で確かめた） | **預かる前に、`aud`・`exp`・`nbf` を確かめる** |
    /// | client_assertion | `sub` を見なかった | **`sub` は `client_id`** |
    ///
    /// **預かったものの期限（300 秒）と使い切りは、JWT の `exp` とは別のもの**である（#188）。
    /// </remarks>
    public class RequestObjectClaimTests : TargetTestBase
    {
        /// <summary>client_assertion_type（RFC 7523 §2.2）</summary>
        private const string JwtBearerAssertionType = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer";

        /// <summary>FAPI の Request Object の寿命の上限（秒）</summary>
        private const long FapiMaxLifetimeSeconds = 60 * 60;

        /// <summary>コンストラクタ</summary>
        /// <param name="output">ITestOutputHelper</param>
        public RequestObjectClaimTests(ITestOutputHelper output) : base(output)
        {
        }

        #region 補助

        /// <summary>認可要求のパラメタ（Request Object の中身）</summary>
        /// <param name="reg">クライアント</param>
        /// <param name="state">state</param>
        /// <param name="overrides">上書き・取り除く指定（RequestObjectBuilder.RemoveClaim）</param>
        /// <returns>パラメタ</returns>
        private static Dictionary<string, object> Parameters(
            ClientRegistration reg, string state, IDictionary<string, object> overrides)
        {
            Dictionary<string, object> parameters = new Dictionary<string, object>()
            {
                { "response_type", "code" },
                { "redirect_uri", reg.RedirectUri },
                { "scope", "openid" },
                { "state", state }
            };

            if (overrides != null)
            {
                foreach (KeyValuePair<string, object> p in overrides)
                {
                    parameters[p.Key] = p.Value;
                }
            }

            return parameters;
        }

        /// <summary>fapi2 の登録に要る S256 の PKCE を足す（FAPI 2.0 Security Profile §5.3.2.2。#366）</summary>
        /// <param name="overrides">ほかの上書き（無ければ null）</param>
        /// <returns>上書き</returns>
        /// <remarks>**fapi2 の登録は、PKCE 無しの PAR を `invalid_request` で断る**（#366）。値は RFC 7636 Appendix B。</remarks>
        private static Dictionary<string, object> Fapi2Pkce(IDictionary<string, object> overrides = null)
        {
            Dictionary<string, object> pkce = new Dictionary<string, object>()
            {
                { "code_challenge", "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM" },
                { "code_challenge_method", "S256" }
            };

            if (overrides != null)
            {
                foreach (KeyValuePair<string, object> p in overrides)
                {
                    pkce[p.Key] = p.Value;
                }
            }

            return pkce;
        }

        /// <summary>/ros に預ける</summary>
        /// <param name="client">IdPClient</param>
        /// <param name="requestObject">Request Object</param>
        /// <returns>応答</returns>
        private static Task<JsonResponse> RegisterAsync(IdPClient client, string requestObject)
        {
            return client.PostTextAsync(RequestObjectBuilder.RegistrationPath, requestObject);
        }

        /// <summary>/ros が預かったことを確かめる</summary>
        /// <param name="r">TestReport</param>
        /// <param name="label">何の要求か</param>
        /// <param name="res">応答</param>
        private static void VerifyAccepted(TestReport r, string label, JsonResponse res)
        {
            string requestUri = res.IsJson ? res.String("request_uri") : null;

            r.Verify(label + " : 預かる（request_uri が返る）", !string.IsNullOrEmpty(requestUri),
                "request_uri あり",
                string.IsNullOrEmpty(requestUri) ? "**無し**（HTTP " + (int)res.StatusCode + "）" : "あり");
        }

        /// <summary>/ros が断ったことを確かめる</summary>
        /// <param name="r">TestReport</param>
        /// <param name="label">何の要求か</param>
        /// <param name="res">応答</param>
        private static void VerifyRejected(TestReport r, string label, JsonResponse res)
        {
            r.VerifyEqual(label + " : HTTP 400 で断る", "400", ((int)res.StatusCode).ToString());

            string requestUri = res.IsJson ? res.String("request_uri") : null;

            r.Verify(label + " : request_uri を返さない", string.IsNullOrEmpty(requestUri),
                "無し", string.IsNullOrEmpty(requestUri) ? "無し" : "**返してしまった**");
        }

        /// <summary>Discovery から PAR の口を引く</summary>
        /// <param name="client">IdPClient</param>
        /// <returns>URL</returns>
        private static async Task<string> ParEndpointAsync(IdPClient client)
        {
            JsonResponse res = await client.GetJsonAsync("/.well-known/openid-configuration");
            Assert.True(res.IsJson, "前提: Discovery 文書が JSON であること");

            string endpoint = res.String("pushed_authorization_request_endpoint");
            Assert.False(string.IsNullOrEmpty(endpoint), "前提: PAR の口が広告されていること");

            return client.ToLocalUrl(endpoint);
        }

        /// <summary>PAR が invalid_request_object で断ったことを確かめる</summary>
        /// <param name="r">TestReport</param>
        /// <param name="label">何の要求か</param>
        /// <param name="res">応答</param>
        private static void VerifyParRejected(TestReport r, string label, JsonResponse res)
        {
            r.VerifyEqual(label + " : HTTP 400", "400", ((int)res.StatusCode).ToString());
            r.VerifyEqual(label + " : invalid_request_object", "invalid_request_object", res.Error ?? "（無い）");
        }

        /// <summary>RS256 の client_assertion を作る（RFC 7523 §2.2）</summary>
        /// <param name="client">IdPClient</param>
        /// <param name="clientId">client_id（iss）</param>
        /// <param name="sub">sub</param>
        /// <param name="aud">aud</param>
        /// <returns>client_assertion</returns>
        private static string ClientAssertion(IdPClient client, string clientId, string sub, string aud)
        {
            long now = DateTimeOffset.UtcNow.ToUnixTimeSeconds();

            return JwsSigner.SignRS256(client, new Dictionary<string, object>()
            {
                { "iss", clientId },
                { "sub", sub },
                { "aud", aud },
                { "jti", Guid.NewGuid().ToString("N") },
                { "iat", now },
                { "exp", now + 300 }
            });
        }

        #endregion

        #region RT-336.1

        /// <summary>RT-336.1 /ros は Request Object の aud を issuer と照合する</summary>
        /// <param name="targetKey">core / netfx</param>
        /// <returns>Task</returns>
        [SkippableTheory]
        [MemberData(nameof(AllTargets))]
        public async Task RT33601_rosはRequestObjectのaudをissuerと照合する(string targetKey)
        {
            using (IdPClient client = this.Client(targetKey))
            {
                TestReport r = this.Report("RT-336.1",
                    "/ros は、Request Object の aud が issuer でなければ預からない",
                    "**aud は認可サーバの issuer にすべき**（RFC 9101 §4）。**FAPI は issuer を求める。**"
                    + "**以前は署名しか確かめず、別の認可サーバ宛ての Request Object も預かっていた。**"
                    + "**待ち受けている URL（issuer と違う）も、もう受けない。**",
                    "RFC 9101 §4 / FAPI 1.0 Advanced §5.2.2-15 / FAPI 2.0 Message Signing §5.3.1-2 / #336");

                ClientRegistration reg = Flows.Registration(client, KnownClients.TestClient);
                string issuer = await client.IssuerAsync();

                r.Target("POST /ros（client_name=" + KnownClients.TestClient + "）");

                r.Step("(1) aud = issuer");

                VerifyAccepted(r, "aud = issuer", await RegisterAsync(client,
                    await RequestObjectBuilder.CreateAsync(client, reg.ClientId,
                        Parameters(reg, "state-rt3361-1", null))));

                foreach (KeyValuePair<string, object> aud in new Dictionary<string, object>()
                {
                    { "待ち受けている URL", client.Target.BaseUrl },
                    { "別の認可サーバ", "https://other.example" }
                })
                {
                    r.Step("aud = " + aud.Key);

                    VerifyRejected(r, "aud = " + aud.Key, await RegisterAsync(client,
                        await RequestObjectBuilder.CreateAsync(client, reg.ClientId,
                            Parameters(reg, "state-rt3361-2", new Dictionary<string, object>() { { "aud", aud.Value } }))));
                }

                r.Done();
            }
        }

        #endregion

        #region RT-336.2

        /// <summary>RT-336.2 /ros は期限の過ぎた・まだ使えない Request Object を預からない</summary>
        /// <param name="targetKey">core / netfx</param>
        /// <returns>Task</returns>
        [SkippableTheory]
        [MemberData(nameof(AllTargets))]
        public async Task RT33602_rosは時刻の外れたRequestObjectを預からない(string targetKey)
        {
            using (IdPClient client = this.Client(targetKey))
            {
                TestReport r = this.Report("RT-336.2",
                    "/ros は、exp の過ぎた・nbf がまだ来ていない Request Object を預からない",
                    "**exp を過ぎた JWT は受けてはならない**（RFC 7519 §4.1.4）。nbf より前も同じ（§4.1.5）。"
                    + "**以前は確かめず、期限の過ぎた Request Object を預け直して、新しい request_uri を得られた**"
                    + "（預かったものの期限 300 秒は、JWT の exp とは別のもの）。",
                    "RFC 7519 §4.1.4 / RFC 7519 §4.1.5 / #336");

                ClientRegistration reg = Flows.Registration(client, KnownClients.TestClient);
                long now = DateTimeOffset.UtcNow.ToUnixTimeSeconds();

                r.Target("POST /ros（client_name=" + KnownClients.TestClient + "）");

                r.Step("(1) exp が過去");

                VerifyRejected(r, "exp が過去", await RegisterAsync(client,
                    await RequestObjectBuilder.CreateAsync(client, reg.ClientId,
                        Parameters(reg, "state-rt3362-1", new Dictionary<string, object>() { { "exp", now - 600 } }))));

                r.Step("(2) nbf が未来");

                VerifyRejected(r, "nbf が未来", await RegisterAsync(client,
                    await RequestObjectBuilder.CreateAsync(client, reg.ClientId,
                        Parameters(reg, "state-rt3362-2", new Dictionary<string, object>() { { "nbf", now + 600 } }))));

                r.Done();
            }
        }

        #endregion

        #region RT-336.3

        /// <summary>RT-336.3 PAR の request（JAR）も aud と exp を確かめる</summary>
        /// <param name="targetKey">core / netfx</param>
        /// <returns>Task</returns>
        [SkippableTheory]
        [MemberData(nameof(AllTargets))]
        public async Task RT33603_PARのrequestもaudとexpを確かめる(string targetKey)
        {
            using (IdPClient client = this.Client(targetKey))
            {
                TestReport r = this.Report("RT-336.3",
                    "/par の request（JAR）も、aud が issuer でないもの・exp の過ぎたものを invalid_request_object で断る",
                    "**/ros と同じ確認をする。** PAR はクライアント認証をするが、"
                    + "**以前は Request Object の aud と exp を確かめていなかった。**",
                    "RFC 9101 §4 / RFC 9101 §6.3 / RFC 7519 §4.1.4 / RFC 9126 §3 / #336");

                ClientRegistration reg = Flows.Registration(client, KnownClients.TestClient);
                string endpoint = await ParEndpointAsync(client);
                long now = DateTimeOffset.UtcNow.ToUnixTimeSeconds();

                r.Target("POST /par（client_name=" + KnownClients.TestClient + "。Basic で認証し、request に JAR を入れる）");

                r.Step("(1) aud = 待ち受けている URL");

                VerifyParRejected(r, "aud = 待ち受けている URL", await client.PostJsonWithBasicAuthAsync(endpoint,
                    new Dictionary<string, string>()
                    {
                        { "request", await RequestObjectBuilder.CreateAsync(client, reg.ClientId,
                            Parameters(reg, "state-rt3363-1", new Dictionary<string, object>() { { "aud", client.Target.BaseUrl } })) }
                    },
                    reg.ClientId, reg.ClientSecret));

                r.Step("(2) exp が過去");

                VerifyParRejected(r, "exp が過去", await client.PostJsonWithBasicAuthAsync(endpoint,
                    new Dictionary<string, string>()
                    {
                        { "request", await RequestObjectBuilder.CreateAsync(client, reg.ClientId,
                            Parameters(reg, "state-rt3363-2", new Dictionary<string, object>() { { "exp", now - 600 } })) }
                    },
                    reg.ClientId, reg.ClientSecret));

                r.Note("aud = issuer で預けられることは RT-229.3 が確かめる。");

                r.Done();
            }
        }

        #endregion

        #region RT-336.4

        /// <summary>RT-336.4 FAPI の登録の Request Object は exp・nbf が必須で、寿命は 60 分以内</summary>
        /// <param name="targetKey">core / netfx</param>
        /// <returns>Task</returns>
        [SkippableTheory]
        [MemberData(nameof(AllTargets))]
        public async Task RT33604_FAPIのRequestObjectはexpとnbfが必須で寿命は60分以内(string targetKey)
        {
            using (IdPClient client = this.Client(targetKey))
            {
                TestReport r = this.Report("RT-336.4",
                    "FAPI の登録の Request Object は、exp・nbf が無いもの、寿命が 60 分を超えるもの、nbf が 60 分より前のものを預からない",
                    "**FAPI は exp・nbf を必須とし、exp は nbf から 60 分以内、nbf は 60 分より前でないことを求める。**"
                    + "**RFC 9101 は求めないので、FAPI でない登録には求めない**（対照）。",
                    "FAPI 1.0 Advanced §5.2.2-13 / FAPI 1.0 Advanced §5.2.2-17 / FAPI 2.0 Message Signing §5.3.1-3 / FAPI 2.0 Message Signing §5.3.1-4 / #336");

                ClientRegistration fapi = Flows.Registration(client, KnownClients.Fapi2Client);
                ClientRegistration normal = Flows.Registration(client, KnownClients.TestClient);
                long now = DateTimeOffset.UtcNow.ToUnixTimeSeconds();

                r.Target("POST /ros（client_name=" + KnownClients.Fapi2Client + "（fapi2）。対照は " + KnownClients.TestClient + "）");

                r.Step("(1) exp・nbf があり、寿命が 60 分ちょうど（受ける）");

                VerifyAccepted(r, "寿命 60 分", await RegisterAsync(client,
                    await RequestObjectBuilder.CreateAsync(client, fapi.ClientId,
                        Parameters(fapi, "state-rt3364-1", new Dictionary<string, object>()
                        {
                            { "nbf", now },
                            { "exp", now + FapiMaxLifetimeSeconds }
                        }))));

                foreach (KeyValuePair<string, Dictionary<string, object>> c in new Dictionary<string, Dictionary<string, object>>()
                {
                    { "exp が無い", new Dictionary<string, object>() { { RequestObjectBuilder.RemoveClaim, "exp" } } },
                    { "nbf が無い", new Dictionary<string, object>() { { RequestObjectBuilder.RemoveClaim, "nbf" } } },
                    { "寿命が 60 分を超える", new Dictionary<string, object>() { { "nbf", now }, { "exp", now + FapiMaxLifetimeSeconds + 60 } } },
                    { "nbf が 60 分より前", new Dictionary<string, object>() { { "nbf", now - FapiMaxLifetimeSeconds - 60 }, { "exp", now + 600 } } }
                })
                {
                    r.Step(c.Key);

                    VerifyRejected(r, c.Key, await RegisterAsync(client,
                        await RequestObjectBuilder.CreateAsync(client, fapi.ClientId,
                            Parameters(fapi, "state-rt3364-2", c.Value))));
                }

                r.Step("(対照) FAPI でない登録は、exp が無くても預かる");

                VerifyAccepted(r, "FAPI でない登録で exp が無い", await RegisterAsync(client,
                    await RequestObjectBuilder.CreateAsync(client, normal.ClientId,
                        Parameters(normal, "state-rt3364-3", new Dictionary<string, object>()
                        {
                            { RequestObjectBuilder.RemoveClaim, "exp" }
                        }))));

                r.Done();
            }
        }

        #endregion

        #region RT-336.5

        /// <summary>RT-336.5 /ros は CIBA の要求も、預かる前に aud・exp・nbf を確かめる</summary>
        /// <param name="targetKey">core / netfx</param>
        /// <returns>Task</returns>
        [SkippableTheory]
        [MemberData(nameof(AllTargets))]
        public async Task RT33605_rosはCIBAの要求もaudとexpとnbfを確かめる(string targetKey)
        {
            using (IdPClient client = this.Client(targetKey))
            {
                TestReport r = this.Report("RT-336.5",
                    "/ros は、CIBA の要求（ES256）も、aud が issuer でないもの・exp の過ぎたもの・nbf の来ていないものを預からない",
                    "**CIBA Core は aud を OP の Issuer Identifier、exp・nbf を必須とする。**"
                    + "**以前は /ros では署名だけを確かめ、/ciba_authz で初めて断っていた**"
                    + "（RT-196.17 は /ciba_authz の側を確かめる）。",
                    "CIBA Core §7.1.1 / RFC 7519 §4.1.4 / RFC 7519 §4.1.5 / #336");

                ClientRegistration reg = Flows.Registration(client, KnownClients.FapiCibaClient);
                long now = DateTimeOffset.UtcNow.ToUnixTimeSeconds();

                r.Target("POST /ros（client_name=" + KnownClients.FapiCibaClient + "。要求は ES256 で署名する）");

                r.Step("(1) 正しい要求（受ける）");

                VerifyAccepted(r, "正しい要求", await RegisterAsync(client,
                    await RequestObjectBuilder.CreateCibaAsync(client, reg.ClientId, new Dictionary<string, object>())));

                foreach (KeyValuePair<string, Dictionary<string, object>> c in new Dictionary<string, Dictionary<string, object>>()
                {
                    { "aud が別の認可サーバ", new Dictionary<string, object>() { { "aud", "https://other.example" } } },
                    { "exp が過去", new Dictionary<string, object>() { { "exp", now - 600 } } },
                    { "nbf が未来", new Dictionary<string, object>() { { "nbf", now + 600 } } }
                })
                {
                    r.Step(c.Key);

                    VerifyRejected(r, c.Key, await RegisterAsync(client,
                        await RequestObjectBuilder.CreateCibaAsync(client, reg.ClientId, c.Value)));
                }

                r.Done();
            }
        }

        #endregion

        #region RT-336.6

        /// <summary>RT-336.6 FAPI の登録は、PAR の request（JAR）でも exp・nbf が必須</summary>
        /// <param name="targetKey">core / netfx</param>
        /// <returns>Task</returns>
        [SkippableTheory]
        [MemberData(nameof(AllTargets))]
        public async Task RT33606_FAPIの登録はPARのrequestでもexpとnbfが必須(string targetKey)
        {
            using (IdPClient client = this.Client(targetKey))
            {
                TestReport r = this.Report("RT-336.6",
                    "FAPI の登録は、/par の request（JAR）でも、exp・nbf の無いものを invalid_request_object で断る",
                    "**/ros と同じ確認をする**（RT-336.4）。PAR のクライアント認証は private_key_jwt で行う。",
                    "FAPI 2.0 Message Signing §5.3.1-3 / FAPI 2.0 Message Signing §5.3.1-4 / RFC 9101 §6.3 / #336");

                ClientRegistration reg = Flows.InjectedRegistration(client, KnownClients.TestClient_32);
                string endpoint = await ParEndpointAsync(client);
                string issuer = await client.IssuerAsync();

                r.Target("POST /par（client_name=" + KnownClients.TestClient_32 + "。fapi2。private_key_jwt で認証する）");

                r.Step("(1) exp・nbf がある（受ける）");

                JsonResponse ok = await client.PostJsonAsync(endpoint, new Dictionary<string, string>()
                {
                    { "request", await RequestObjectBuilder.CreateAsync(client, reg.ClientId,
                        Parameters(reg, "state-rt3366-1", RequestObjectClaimTests.Fapi2Pkce())) },
                    { "client_assertion_type", JwtBearerAssertionType },
                    { "client_assertion", ClientAssertion(client, reg.ClientId, reg.ClientId, issuer) }
                });

                r.VerifyEqual("HTTP 201", "201", ((int)ok.StatusCode).ToString());

                r.Step("(2) exp が無い");

                VerifyParRejected(r, "exp が無い", await client.PostJsonAsync(endpoint, new Dictionary<string, string>()
                {
                    { "request", await RequestObjectBuilder.CreateAsync(client, reg.ClientId,
                        Parameters(reg, "state-rt3366-2", RequestObjectClaimTests.Fapi2Pkce(
                            new Dictionary<string, object>() { { RequestObjectBuilder.RemoveClaim, "exp" } }))) },
                    { "client_assertion_type", JwtBearerAssertionType },
                    { "client_assertion", ClientAssertion(client, reg.ClientId, reg.ClientId, issuer) }
                }));

                r.Done();
            }
        }

        #endregion

        #region RT-336.7

        /// <summary>RT-336.7 client_assertion の sub は client_id でなければならない</summary>
        /// <param name="targetKey">core / netfx</param>
        /// <returns>Task</returns>
        [SkippableTheory]
        [MemberData(nameof(AllTargets))]
        public async Task RT33607_client_assertionのsubはclient_idでなければならない(string targetKey)
        {
            using (IdPClient client = this.Client(targetKey))
            {
                TestReport r = this.Report("RT-336.7",
                    "client_assertion の sub が client_id でなければ、invalid_client で断る",
                    "**クライアント認証の JWT では、sub は client_id でなければならない。**"
                    + "**以前は sub を見ず**、iss の鍵で署名されていれば通した。",
                    "RFC 7523 §3 / OIDC Core 1.0 §9 / #336");

                ClientRegistration reg = Flows.InjectedRegistration(client, KnownClients.TestClient_24);
                string issuer = await client.IssuerAsync();

                r.Target("POST /revoke（client_name=" + KnownClients.TestClient_24 + "。private_key_jwt で認証する）");

                r.Step("(1) sub = client_id（通る）");

                JsonResponse ok = await client.RevokeAsync(new Dictionary<string, string>()
                {
                    { "token", "not-a-token" },
                    { "client_assertion_type", JwtBearerAssertionType },
                    { "client_assertion", ClientAssertion(client, reg.ClientId, reg.ClientId, issuer) }
                });

                r.VerifyEqual("認証が通る（HTTP 200）", "200", ((int)ok.StatusCode).ToString());

                r.Step("(2) sub = 別の値");

                JsonResponse other = await client.RevokeAsync(new Dictionary<string, string>()
                {
                    { "token", "not-a-token" },
                    { "client_assertion_type", JwtBearerAssertionType },
                    { "client_assertion", ClientAssertion(client, reg.ClientId, "someone-else", issuer) }
                });

                r.VerifyEqual("invalid_client", "invalid_client", other.Error ?? "（無い）");

                r.Done();
            }
        }

        #endregion
    }
}
