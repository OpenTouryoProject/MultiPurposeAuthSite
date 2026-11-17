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
//* クラス名        ：UnsignedRequestTests
//* クラス日本語名  ：RT-400 SAML2 の IdP は、署名を確かめられない要求を断る（鍵を登録していない SP の要求を含む）
//*
//* 作成日時        ：－
//* 作成者          ：－
//* 更新履歴        ：－
//*
//*  日時        更新者            内容
//*  ----------  ----------------  -------------------------------------------------
//*  2026/11/17  玄人 幸道         新規（#400）
//**********************************************************************************

using System.Collections.Generic;
using System.Net.Http;
using System.Threading.Tasks;

using MultiPurposeAuthSite.Tests.E2E.Infrastructure;

using Xunit;
using Xunit.Abstractions;

namespace MultiPurposeAuthSite.Tests.E2E.Tests.Saml
{
    /// <summary>
    /// RT-400. **SAML2 の IdP は、署名を確かめられない要求を断る**（鍵を登録していない SP の要求を含む）。
    /// </summary>
    /// <remarks>
    /// **メタデータは `WantAuthnRequestsSigned="true"` を広告している**（Open棟梁 の部品が固定で埋め込む）。
    /// **以前は、鍵を登録していない SP の、署名の無い要求を通していた**（`VerifySamlRequest` の「鍵がない場合は、通す」）。
    ///
    /// | | 測ること |
    /// |---|---|
    /// | **`RT-400.1`** | **鍵を登録していない SP（`TestClient_23`）の、署名の無い要求は、登録済みの ACS URL へ Requester のエラー応答（アサーションを入れない）** |
    ///
    /// - **鍵を登録した SP の署名の無い要求が断られることは `SA-5.4`**、署名した要求が通ることは `SA-*`・`RT-*` の多くが測る（`Saml2.SignedRequestQuery`）
    /// - **`Destination` は、送り先と同じ値を入れる**（照合は署名の確かめより前。違えば捨てる。`RT-392.1`）
    /// </remarks>
    public class UnsignedRequestTests : TargetTestBase
    {
        /// <summary>コンストラクタ</summary>
        /// <param name="output">ITestOutputHelper</param>
        public UnsignedRequestTests(ITestOutputHelper output) : base(output)
        {
        }

        #region RT-400.1

        /// <summary>RT-400.1 鍵を登録していない SP の、署名の無い要求は断る</summary>
        /// <param name="targetKey">core / netfx</param>
        /// <returns>Task</returns>
        [SkippableTheory]
        [MemberData(nameof(AllTargets))]
        public async Task RT40001_鍵を登録していないSPの署名の無い要求は断る(string targetKey)
        {
            using (IdPClient client = await this.SignedInClientAsync(targetKey))
            {
                TestReport r = this.Report("RT-400.1",
                    "**鍵を登録していない SP の、署名の無い要求は、登録済みの ACS URL へ Requester のエラー応答を返す（アサーションを入れない）**",
                    "**メタデータの WantAuthnRequestsSigned=true は、この IdP が受ける AuthnRequest に署名を求めることを示す。**"
                    + "**以前は、鍵を登録していない SP の要求を、署名を確かめずに通していた**（振る舞いと広告が食い違っていた）。"
                    + "**署名を確かめられない要求は、署名の検証に失敗した要求と同じく断る**（#400）。",
                    "SAML Metadata（IDPSSODescriptor の WantAuthnRequestsSigned） / #400");

                string clientId = KnownClients.SeededClientId(KnownClients.TestClient_23);

                Assert.False(string.IsNullOrEmpty(clientId),
                    "前提: " + KnownClients.TestClient_23 + " の client_id が分かること（種データ）");

                string id = Saml2.NewId();

                r.Target("GET /saml2request（client_name=" + KnownClients.TestClient_23 + "。jwk_rsa_publickey を登録していない。署名しないで送る）");

                string xml = Saml2.BuildAuthnRequest(
                    id, "http://" + clientId, Saml2.FormatUnspecified, Saml2.BindingPost,
                    destination: Saml2.RequestEndpointOf(client));

                HttpResponseMessage res = await client.GetAsync("/saml2request?" + Saml2.ToRedirectQuery(xml));

                r.VerifyEqual("HTTP 200（自動送信フォーム）", "200", ((int)res.StatusCode).ToString());

                Dictionary<string, string> hidden = Html.HiddenInputs(await res.Content.ReadAsStringAsync());

                bool has = hidden.ContainsKey("SAMLResponse") && !string.IsNullOrEmpty(hidden["SAMLResponse"]);

                r.Verify("登録済みの ACS URL へ応答を返す", has, "返す", has ? "返す" : "**返さない**");

                Assert.True(has, "前提: 応答が返ること");

                Saml2Response decoded = Saml2.ReadResponse(Saml2.FromPostValue(hidden["SAMLResponse"]));

                Assert.NotNull(decoded);

                r.VerifyEqual("StatusCode（署名を確かめられない要求は断る）", Saml2.StatusRequester, decoded.StatusCode);
                r.Verify("アサーション（NameID）を入れない", string.IsNullOrEmpty(decoded.NameId),
                    "入れない", string.IsNullOrEmpty(decoded.NameId) ? "入れない" : "**入れている**");
                r.VerifyEqual("InResponseTo（送った要求の ID）", id, decoded.InResponseTo);

                r.Done();
            }
        }

        #endregion
    }
}
