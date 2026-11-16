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
//* クラス名        ：RequestDestinationCheckTests
//* クラス日本語名  ：RT-392 SAML2 の IdP は、要求の Destination を受けた口の URL と照合する
//*
//* 作成日時        ：－
//* 作成者          ：－
//* 更新履歴        ：－
//*
//*  日時        更新者            内容
//*  ----------  ----------------  -------------------------------------------------
//*  2026/11/16  玄人 幸道         新規（#392）
//**********************************************************************************

using System.Collections.Generic;
using System.Net.Http;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Threading.Tasks;

using MultiPurposeAuthSite.Tests.E2E.Infrastructure;

using Xunit;
using Xunit.Abstractions;

namespace MultiPurposeAuthSite.Tests.E2E.Tests.Saml
{
    /// <summary>
    /// RT-392. **SAML2 の IdP は、要求の `Destination` を、受けた口の URL と照合する。**
    /// </summary>
    /// <remarks>
    /// - **SAML Core 3.2.1**：`Destination` が在れば、受けた場所と一致することを確かめ、**違えば要求を捨てる**（MUST）
    /// - **SAML Bindings 3.4.5.2・3.5.5.2**：署名した要求は `Destination` を入れ、受け手は一致を確かめる（MUST）
    ///
    /// **以前は照合していなかった**（Open棟梁 の `SAML2Client.VerifyRequest` は署名と XML の構造まで）。
    /// **捨てるときは SP へ応答を返さず、エラー画面にする**（#392 の決め）。
    ///
    /// | | 測ること |
    /// |---|---|
    /// | `RT-392.1` | 鍵を登録していない SP（署名の無い要求）：正しい `Destination`・無い `Destination` は通る。**違う・空の `Destination` は捨てる** |
    /// | `RT-392.2` | 鍵を登録した SP の署名した要求（Redirect）：正しい `Destination` は通る。**無い・違う `Destination` は捨てる。** 署名しない要求でも、違えば捨てる |
    ///
    /// **署名は、構成ファイルの `SpRp_RsaPfxFilePath`（`TestClient` の `jwk_rsa_publickey` と対の鍵）で付ける。**
    /// </remarks>
    public class RequestDestinationCheckTests : TargetTestBase
    {
        /// <summary>コンストラクタ</summary>
        /// <param name="output">ITestOutputHelper</param>
        public RequestDestinationCheckTests(ITestOutputHelper output) : base(output)
        {
        }

        /// <summary>RT-392.1 鍵を登録していない SP の要求でも、違う Destination は捨てる</summary>
        /// <param name="targetKey">core / netfx</param>
        /// <returns>Task</returns>
        [SkippableTheory]
        [MemberData(nameof(AllTargets))]
        public async Task RT39201_署名の無い要求でも違うDestinationは捨てる(string targetKey)
        {
            using (IdPClient client = await this.SignedInClientAsync(targetKey))
            {
                TestReport r = this.Report("RT-392.1",
                    "鍵を登録していない SP の、署名の無い要求でも、Destination が受けた口と違えば捨てる（エラー画面）",
                    "**SAML Core 3.2.1 は、署名の有無によらず、Destination が在れば受けた場所と照合し、"
                    + "違えば要求を捨てることを求める（MUST）。** **以前は照合していなかった**（#392）。"
                    + "**Destination の無い署名の無い要求は、従来どおり通す**（Bindings の MUST は署名した要求だけ）。",
                    "SAML Core 3.2.1 / #392");

                string issuer = "http://" + KnownClients.SeededClientId(KnownClients.TestClient_21);
                string endpoint = RequestDestinationCheckTests.EndpointOf(client);

                r.Target("GET /saml2request（TestClient_21 は jwk_rsa_publickey を登録していない）");

                r.Step("(1) 対照：Destination が受けた口と同じなら、通る");

                await RequestDestinationCheckTests.VerifyAcceptedAsync(r, client,
                    Saml2.ToRedirectQuery(RequestDestinationCheckTests.Request(issuer, endpoint)));

                r.Step("(2) Destination が無ければ、従来どおり通る");

                await RequestDestinationCheckTests.VerifyAcceptedAsync(r, client,
                    Saml2.ToRedirectQuery(RequestDestinationCheckTests.Request(issuer, null)));

                r.Step("(3) Destination が受けた口と違えば、捨てる（SP へ応答を返さない）");

                await RequestDestinationCheckTests.VerifyDiscardedAsync(r, client,
                    Saml2.ToRedirectQuery(RequestDestinationCheckTests.Request(issuer, "https://idp.e2e.example/saml2request")));

                r.Step("(4) 空の Destination も、受けた場所を指さないので、捨てる");

                await RequestDestinationCheckTests.VerifyDiscardedAsync(r, client,
                    Saml2.ToRedirectQuery(RequestDestinationCheckTests.Request(issuer, "")));

                r.Done();
            }
        }

        /// <summary>RT-392.2 署名した要求は、Destination が無いか違えば捨てる</summary>
        /// <param name="targetKey">core / netfx</param>
        /// <returns>Task</returns>
        [SkippableTheory]
        [MemberData(nameof(AllTargets))]
        public async Task RT39202_署名した要求はDestinationが無いか違えば捨てる(string targetKey)
        {
            using (IdPClient client = await this.SignedInClientAsync(targetKey))
            {
                TestReport r = this.Report("RT-392.2",
                    "鍵を登録した SP の署名した要求（Redirect）は、Destination が無いか受けた口と違えば捨てる（エラー画面）",
                    "**SAML Bindings 3.4.5.2 は、署名した要求の Destination に送り先の URL を入れ、"
                    + "受け手は受けた場所と一致することを確かめることを求める（MUST）。**"
                    + "**以前は照合していなかった**ので、別の IdP 宛ての署名した要求を、この IdP で使えた（#392）。",
                    "SAML Bindings §3.4.5.2 / SAML Core 3.2.1 / #392");

                ClientRegistration reg = Flows.Registration(client, KnownClients.TestClient);
                string issuer = "http://" + reg.ClientId;
                string endpoint = RequestDestinationCheckTests.EndpointOf(client);

                r.Target("GET /saml2request（TestClient は jwk_rsa_publickey を登録している。SpRp_RsaPfxFilePath の鍵で署名する）");

                using (X509Certificate2 cert = JwsSigner.LoadCertificate(client, "SpRp_RsaPfxFilePath", "SpRp_RsaPfxPassword"))
                using (RSA rsa = cert.GetRSAPrivateKey())
                {
                    Assert.NotNull(rsa);

                    r.Step("(1) 対照：署名して、Destination が受けた口と同じなら、通る（署名を検証できている）");

                    await RequestDestinationCheckTests.VerifyAcceptedAsync(r, client,
                        Saml2.ToSignedRedirectQuery(RequestDestinationCheckTests.Request(issuer, endpoint), rsa));

                    r.Step("(2) 署名して、Destination が無ければ、捨てる");

                    await RequestDestinationCheckTests.VerifyDiscardedAsync(r, client,
                        Saml2.ToSignedRedirectQuery(RequestDestinationCheckTests.Request(issuer, null), rsa));

                    r.Step("(3) 署名して、Destination が受けた口と違えば、捨てる");

                    await RequestDestinationCheckTests.VerifyDiscardedAsync(r, client,
                        Saml2.ToSignedRedirectQuery(
                            RequestDestinationCheckTests.Request(issuer, "https://idp.e2e.example/saml2request"), rsa));
                }

                r.Step("(4) 署名しないで、Destination が受けた口と違えば、署名の検証の失敗（Requester）ではなく、捨てる");

                await RequestDestinationCheckTests.VerifyDiscardedAsync(r, client,
                    Saml2.ToRedirectQuery(RequestDestinationCheckTests.Request(issuer, "https://idp.e2e.example/saml2request")));

                r.Note("**同梱の自己テストと ID 連携の SP は、Destination を入れて署名する**（#391。`RT-391.1`・`SA-6.1`）ので、"
                    + "**流れは従来どおり通る**（`SA-1.*`・`SA-6.*`）。");

                r.Done();
            }
        }

        #region 補助

        /// <summary>この IdP の SAML2 の口の URL（構成の `OAuth2AuthorizationServerEndpointsRootURI` ＋ `/saml2request`）</summary>
        /// <param name="client">IdPClient</param>
        /// <returns>URL</returns>
        private static string EndpointOf(IdPClient client)
        {
            return client.Target.BaseUrl + "/saml2request";
        }

        /// <summary>要求の XML（応答は POST Binding で受ける）</summary>
        /// <param name="issuer">Issuer</param>
        /// <param name="destination">Destination（null なら入れない）</param>
        /// <returns>XML</returns>
        private static string Request(string issuer, string destination)
        {
            return Saml2.BuildAuthnRequest(
                Saml2.NewId(), issuer, Saml2.FormatUnspecified, Saml2.BindingPost, destination: destination);
        }

        /// <summary>要求が通り、Success の応答が返ることを確かめる</summary>
        /// <param name="r">TestReport</param>
        /// <param name="client">IdPClient</param>
        /// <param name="query">クエリ文字列</param>
        /// <returns>Task</returns>
        private static async Task VerifyAcceptedAsync(TestReport r, IdPClient client, string query)
        {
            HttpResponseMessage res = await client.GetAsync("/saml2request?" + query);
            Dictionary<string, string> hidden = Html.HiddenInputs(await res.Content.ReadAsStringAsync());

            bool has = hidden.ContainsKey("SAMLResponse") && !string.IsNullOrEmpty(hidden["SAMLResponse"]);

            r.Verify("SP へ応答を返す", has, "返す", has ? "返す" : "**返さない**");

            Assert.True(has, "前提: 応答が返ること");

            Saml2Response decoded = Saml2.ReadResponse(Saml2.FromPostValue(hidden["SAMLResponse"]));

            Assert.NotNull(decoded);

            r.VerifyEqual("StatusCode", Saml2.StatusSuccess, decoded.StatusCode);
        }

        /// <summary>要求を捨て、SP へ応答を返さず、エラー画面になることを確かめる</summary>
        /// <param name="r">TestReport</param>
        /// <param name="client">IdPClient</param>
        /// <param name="query">クエリ文字列</param>
        /// <returns>Task</returns>
        private static async Task VerifyDiscardedAsync(TestReport r, IdPClient client, string query)
        {
            HttpResponseMessage res = await client.GetAsync("/saml2request?" + query);
            int status = (int)res.StatusCode;

            r.Verify("500 にしない", status != 500,
                "500 でない", (status == 500) ? "**500**" : "HTTP " + status);

            string body = System.Net.WebUtility.HtmlDecode(await res.Content.ReadAsStringAsync());
            Dictionary<string, string> hidden = Html.HiddenInputs(body);

            bool has = hidden.ContainsKey("SAMLResponse");

            r.Verify("SP へ応答を返さない（捨てる）", !has, "返さない", has ? "**返している**" : "返さない");

            r.Verify("エラー画面が開く", body.Contains("エラーが発生しました"),
                "エラー画面", body.Contains("エラーが発生しました") ? "エラー画面" : "**別の画面**");
        }

        #endregion
    }
}
