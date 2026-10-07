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
//* クラス名        ：SignInFlowTests
//* クラス日本語名  ：SA-4 未サインインからのシングル サインオン
//*
//* 作成日時        ：－
//* 作成者          ：－
//* 更新履歴        ：－
//*
//*  日時        更新者            内容
//*  ----------  ----------------  -------------------------------------------------
//*  2026/10/07  玄人 幸道         新規（#275）
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
    /// SA-4. 未サインインの利用者を、サインインさせてからアサーションを返す。
    /// </summary>
    /// <remarks>
    /// **これが SP-initiated Web Browser SSO の本来の形である**（Web SSO Profile 4.1.1）。
    /// **従来の E2E はすべて `SignedInClientAsync` から始めていた**ので、
    /// **`[Authorize]` のチャレンジを通って戻る経路が未測定だった**（#275）。
    ///
    /// **`AccountController` はクラスに `[Authorize]`** が付いており、
    /// **`Saml2Request` に `[AllowAnonymous]` は無い。**
    /// そのため、**未サインインならサインイン画面へ送られる。**
    ///
    /// **「送られること」だけでなく「戻ってアサーションが返ること」まで見る。**
    /// 送るだけなら、**戻り先を取り違えていても気付けない。**
    /// </remarks>
    public class SignInFlowTests : TargetTestBase
    {
        /// <summary>コンストラクタ</summary>
        /// <param name="output">ITestOutputHelper</param>
        public SignInFlowTests(ITestOutputHelper output) : base(output)
        {
        }

        /// <summary>SA-4.1 未サインインならサインイン画面へ送り、サインイン後にアサーションを返す</summary>
        /// <param name="targetKey">core / netfx</param>
        /// <returns>Task</returns>
        [SkippableTheory]
        [MemberData(nameof(AllTargets))]
        public async Task SA0401_未サインインならサインインさせてからアサーションを返す(string targetKey)
        {
            // **サインインしていないクライアントで始める。**
            using (IdPClient client = this.Client(targetKey))
            {
                TestReport r = this.Report("SA-4.1",
                    "未サインインの要求はサインイン画面へ送られ、サインイン後にアサーションが返る",
                    "**SP-initiated Web Browser SSO の本来の形**である（Web SSO Profile 4.1.1）。"
                    + "**従来の E2E はすべてサインイン済みから始めていた**ので、"
                    + "**`[Authorize]` のチャレンジを通って戻る経路が未測定だった**（#275）。"
                    + "**送られることだけでなく、戻ってアサーションが返ることまで見る。**",
                    "SAML 2.0 Web SSO Profile 4.1.1 / #275");

                string clientId = KnownClients.SeededClientId(KnownClients.TestClient_21);

                Skip.If(string.IsNullOrEmpty(clientId),
                    "TestClient_21 の client_id が分かりません（種データ）。");

                string id = Saml2.NewId();

                string xml = Saml2.BuildAuthnRequest(
                    id, "http://" + clientId, Saml2.FormatUnspecified, Saml2.BindingPost);

                string url = "/saml2request?" + Saml2.ToRedirectQuery(xml);

                r.Target("GET /saml2request（サインインしていない状態）");

                r.Step("(1) 未サインインだと、サインイン画面へ送られる");

                r.Verify("まだサインインしていない（測る前提）", !client.IsSignedIn,
                    "していない", client.IsSignedIn ? "**している**" : "していない");

                HttpResponseMessage first = await client.GetAsync(url);

                string location = (first.Headers.Location == null)
                    ? "" : first.Headers.Location.ToString();

                r.Verify("リダイレクトする（302）",
                    !string.IsNullOrEmpty(location),
                    "リダイレクトする",
                    string.IsNullOrEmpty(location)
                        ? "**しない**（HTTP " + (int)first.StatusCode + "）" : "した");

                Assert.False(string.IsNullOrEmpty(location), "前提: サインインへ送られること");

                r.Verify("送り先はサインイン画面",
                    location.Contains("/Account/Login"),
                    "/Account/Login へ", location);

                // **アサーションを返していないこと**（サインインの前に返してはならない）。
                string body = await first.Content.ReadAsStringAsync();
                Dictionary<string, string> hidden = Html.HiddenInputs(body);

                r.Verify("この時点でアサーションを返さない",
                    !hidden.ContainsKey("SAMLResponse"),
                    "返さない",
                    hidden.ContainsKey("SAMLResponse") ? "**返している**" : "返していない");

                r.Step("(2) サインインして、同じ要求をもう一度送る");

                await client.SignInAsync();

                r.Verify("サインインできた", client.IsSignedIn,
                    "できた", client.IsSignedIn ? "できた" : "**できない**");

                Assert.True(client.IsSignedIn, "前提: サインインできること");

                HttpResponseMessage second = await client.GetAsync(url);

                r.VerifyEqual("HTTP 200（自動送信フォーム）", "200",
                    ((int)second.StatusCode).ToString());

                string form = await second.Content.ReadAsStringAsync();
                Dictionary<string, string> hidden2 = Html.HiddenInputs(form);

                r.Verify("SAMLResponse がある", hidden2.ContainsKey("SAMLResponse"),
                    "ある", hidden2.ContainsKey("SAMLResponse") ? "ある" : "**無い**");

                Assert.True(hidden2.ContainsKey("SAMLResponse"), "前提: 応答が返ること");

                r.Step("(3) 返ったアサーションが、送った要求に対応している");

                Saml2Response decoded = Saml2.ReadResponse(
                    Saml2.FromPostValue(hidden2["SAMLResponse"]));

                Assert.NotNull(decoded);

                r.VerifyEqual("StatusCode", Saml2.StatusSuccess, decoded.StatusCode);

                r.VerifyEqual("InResponseTo（送った要求の ID）", id, decoded.InResponseTo);

                r.VerifyEqual("Destination（登録した ACS URL）",
                    KnownClients.Saml2AcsUrl, decoded.Destination);

                r.Verify("Assertion を含む", decoded.HasAssertion,
                    "含む", decoded.HasAssertion ? "含む" : "**含まない**");

                r.Verify("NameID がある", !string.IsNullOrEmpty(decoded.NameId),
                    "ある",
                    string.IsNullOrEmpty(decoded.NameId) ? "**無い**" : "ある（値は伏せる）");

                r.Note("**同じ URL をもう一度送っている**（SP が `RelayState` で復帰させる形は測っていない）。"
                    + "**この実装の `Saml2Request` は `ReturnUrl` で戻る**ので、"
                    + "**ブラウザなら、サインインの後に自動で戻る。**");

                r.Done();
            }
        }
    }
}
