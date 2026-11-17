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
//* クラス名        ：Saml2RequestIdTests
//* クラス日本語名  ：RT-390 SAML2 の要求の ID は、NCName の形だけを応答に使う
//*
//* 作成日時        ：－
//* 作成者          ：－
//* 更新履歴        ：－
//*
//*  日時        更新者            内容
//*  ----------  ----------------  -------------------------------------------------
//*  2026/11/16  玄人 幸道         新規（#390）
//*  2026/11/17  玄人 幸道         要求を署名して送る（RT-390.2 は署名しないまま）。IdP が署名の無い要求を断るようになった（#400）
//**********************************************************************************

using System;
using System.Collections.Generic;
using System.Net;
using System.Net.Http;
using System.Threading.Tasks;
using System.Xml;

using MultiPurposeAuthSite.Tests.E2E.Infrastructure;

using Xunit;
using Xunit.Abstractions;

namespace MultiPurposeAuthSite.Tests.E2E.Tests.Saml
{
    /// <summary>
    /// RT-390. SAML2 の要求の ID は、NCName の形のものだけを、応答の InResponseTo に使う。
    /// </summary>
    /// <remarks>
    /// **要求の `ID` は送る側が決める値で、署名の検証より前に取り出される。**
    /// **この値は、IdP が署名する応答の `InResponseTo` に入る**（成功の応答にも、エラー応答にも）。
    /// **Open棟梁 の部品（`SAML2Bindings.CreateResponse`・`CreateAssertion`）は、値を文字列の置換で埋め込む**ので、
    /// **XML として意味のある文字を含む `ID` で、応答の構造が変わっていた**（#390）。
    ///
    /// **`ID` は `xs:ID`（NCName）である**（SAML Core 1.3.4）。
    /// **形の合わない `ID` は、検証の失敗として扱い、応答にも使わない**（`SamlProviders/CmnEndpoints.VerifySamlRequest`）。
    ///
    /// | | 期待 |
    /// |---|---|
    /// | `RT-390.1` | 鍵の無い SP：NCName の `ID` は通り、返る。形の合わない `ID` は `Requester` で、応答の構造が変わらない |
    /// | `RT-390.2` | 鍵を登録した SP の署名の無い要求（エラー応答の経路）でも、応答の構造が変わらない |
    /// | `RT-390.3` | NameID（EmailAddress の形式の利用者のメアド）に `<`・`&` を含むなら、アサーションを作らず `Responder`（`{`・XML で使えない文字も同じ扱い。測るのは `<`・`&`） |
    ///
    /// **値を DOM の API で入れる直し（ACS の URL なども含む）は、Open棟梁 の側で行う。**
    /// </remarks>
    public class Saml2RequestIdTests : TargetTestBase
    {
        /// <summary>
        /// 引用符で属性を閉じ、別の属性を足そうとする `ID`（NCName でない）。
        /// **文字列の置換で入れると、応答に `e2eInjected` の属性が増える。**
        /// </summary>
        private const string QuoteId = "e2e390\" e2eInjected=\"1";

        /// <summary>`&lt;`・`&amp;` を含む `ID`（NCName でない）</summary>
        private const string MarkupId = "e2e390<x/>&amp;";

        /// <summary>足されうる属性の名前</summary>
        private const string InjectedAttr = "e2eInjected";

        /// <summary>コンストラクタ</summary>
        /// <param name="output">ITestOutputHelper</param>
        public Saml2RequestIdTests(ITestOutputHelper output) : base(output)
        {
        }

        /// <summary>RT-390.1 鍵の無い SP の要求で、NCName でない ID を応答に使わない</summary>
        /// <param name="targetKey">core / netfx</param>
        /// <returns>Task</returns>
        [SkippableTheory]
        [MemberData(nameof(AllTargets))]
        public async Task RT39001_NCNameでないIDを応答に使わない(string targetKey)
        {
            using (IdPClient client = await this.SignedInClientAsync(targetKey))
            {
                TestReport r = this.Report("RT-390.1",
                    "署名した要求で、NCName の形でない ID を、応答の InResponseTo に使わない",
                    "**要求の `ID` は送る側が決め、署名の検証より前に取り出され、IdP が署名する応答に入る。**"
                    + "**Open棟梁 の部品は値を文字列の置換で埋め込む**ので、"
                    + "**XML として意味のある文字を含む `ID` で、応答の構造が変わっていた。**"
                    + "**`ID` は `xs:ID`（NCName）なので、形の合わないものは検証の失敗とし、応答に使わない**（#390）。",
                    "SAML Core 1.3.4 / SAML Core 3.2.2 / #390");

                string clientId = KnownClients.SeededClientId(KnownClients.TestClient_21);

                r.Target("GET /saml2request（TestClient_21。SpRp_RsaPfxFilePath の鍵で署名する。#400）");

                r.Step("(1) 対照：NCName の ID（`_`・`.`・`-` を含む）は通り、InResponseTo に返る");

                string goodId = "_e2e.390-" + Saml2.NewId();

                Saml2Response ok = await this.SendAsync(r, client, goodId, "http://" + clientId);

                r.VerifyEqual("StatusCode", Saml2.StatusSuccess, ok.StatusCode);
                r.VerifyEqual("InResponseTo（送った要求の ID）", goodId, ok.InResponseTo);

                r.Step("(2) 引用符と空白を含む ID は Requester で、応答の構造が変わらない");

                Saml2Response quote = await this.SendAsync(r, client, Saml2RequestIdTests.QuoteId, "http://" + clientId);

                Saml2RequestIdTests.VerifyNotUsed(r, quote);

                r.Step("(3) `<`・`&` を含む ID も Requester で、応答を読める");

                Saml2Response markup = await this.SendAsync(r, client, Saml2RequestIdTests.MarkupId, "http://" + clientId);

                Saml2RequestIdTests.VerifyNotUsed(r, markup);

                r.Step("(4) 数字で始まる ID・`:` を含む ID も NCName ではないので、Requester");

                foreach (string id in new string[] { "1e2e390" + Saml2.NewId(), "e2e:" + Saml2.NewId() })
                {
                    Saml2Response other = await this.SendAsync(r, client, id, "http://" + clientId);

                    Saml2RequestIdTests.VerifyNotUsed(r, other);
                }

                r.Note("**鍵の無い SP の要求を、署名を確かめずに通す扱いは続ける**（#390 の決め）。"
                    + "**要求から取った値（`ID`）の形を確かめる**ことで、応答に入る値を絞る。"
                    + "**`nameID`・ACS の URL を DOM の API で入れる直しは、Open棟梁 の側で行う。**");

                r.Done();
            }
        }

        /// <summary>RT-390.2 鍵を登録した SP の署名の無い要求（エラー応答）でも、NCName でない ID を使わない</summary>
        /// <param name="targetKey">core / netfx</param>
        /// <returns>Task</returns>
        [SkippableTheory]
        [MemberData(nameof(AllTargets))]
        public async Task RT39002_エラー応答でもNCNameでないIDを使わない(string targetKey)
        {
            using (IdPClient client = await this.SignedInClientAsync(targetKey))
            {
                TestReport r = this.Report("RT-390.2",
                    "鍵を登録した SP の、署名の無い要求（エラー応答の経路）でも、NCName の形でない ID を使わない",
                    "**署名の検証に失敗しても、IdP は要求の `ID` を `InResponseTo` に入れた、署名したエラー応答を返す**"
                    + "（`AccountController.Saml2` の Error Response の枝）。"
                    + "**`ID` は検証の前に取り出される**ので、**鍵を登録した SP でも当たっていた**（#390）。",
                    "SAML Core 1.3.4 / SAML Core 3.2.2 / #390");

                ClientRegistration reg = Flows.Registration(client, KnownClients.TestClient);

                r.Target("GET /saml2request（TestClient は jwk_rsa_publickey を登録している。署名を付けない）");

                r.Step("(1) 引用符と空白を含む ID で、署名の無い要求を送る");

                Saml2Response quote = await this.SendAsync(r, client, Saml2RequestIdTests.QuoteId, "http://" + reg.ClientId, sign: false);

                Saml2RequestIdTests.VerifyNotUsed(r, quote);

                r.Note("**NCName の ID なら、エラー応答の `InResponseTo` に返る**（`SA-5.1`・`SA-5.4`）。");

                r.Done();
            }
        }

        /// <summary>RT-390.3 NameID に `&lt;`・`&amp;` を含む値なら、アサーションを作らない</summary>
        /// <param name="targetKey">core / netfx</param>
        /// <returns>Task</returns>
        [SkippableTheory]
        [MemberData(nameof(AllTargets))]
        public async Task RT39003_NameIDにマークアップの文字を含むならアサーションを作らない(string targetKey)
        {
            using (IdPClient admin = await this.AdminClientAsync(targetKey))
            using (IdPClient user = this.Client(targetKey))
            {
                string name = "e2e_rt390_" + Guid.NewGuid().ToString("N").Substring(0, 8);
                string password = admin.Config.Get("TestUserPWD");

                TestReport r = this.Report("RT-390.3",
                    "NameID（EmailAddress の形式の利用者のメアド）に < や & を含むなら、アサーションを作らず Responder を返す",
                    "**Open棟梁 の部品は、NameID を文字列の置換で要素の中に埋め込む。**"
                    + "**EmailAddress の形式では利用者のメアドがそのまま入り、net10.0 版の `[EmailAddress]` は `<` を通す。**"
                    + "**`<`・`&` を含む値は、アサーションの構造を変えるか XML を壊すので、アサーションを作らない**（#390）。"
                    + "**エスケープはしない**（部品が値を DOM の API で入れるようになったとき、二重になるため）。",
                    "SAML Core 3.2.2.2 / #390");

                r.Target("GET /saml2request（NameIDPolicy = EmailAddress。使い捨ての利用者 = " + name + "）");

                await UsersAdmin.SkipIfLockedDownAsync(admin);

                bool created = false;

                try
                {
                    r.Step("(1) メアドに `<` を含む利用者を作る（受けない版は `&` にする）");

                    created = await Saml2RequestIdTests.TryCreateUserAsync(
                        admin, name, name + "<e2eInjected/>@example.com");

                    if (!created)
                    {
                        r.Note("**この版は、`<` を含むメアドを受けない**"
                            + "（net48 版は、要求の検証（request validation）がフォームの `<` を断る）。"
                            + "**`&` は受けるので、`&` で測る**（直す前は XML が壊れていた）。");

                        created = await Saml2RequestIdTests.TryCreateUserAsync(
                            admin, name, name + "&x@example.com");
                    }

                    Assert.True(created, "前提: 利用者を作れること");
                    Assert.True(await user.TrySignInAsync(name, password), "前提: 作った利用者でサインインできること");

                    r.Step("(2) EmailAddress の形式で要求する");

                    string clientId = KnownClients.SeededClientId(KnownClients.TestClient_21);

                    Saml2Response decoded = await this.SendAsync(
                        r, user, Saml2.NewId(), "http://" + clientId, Saml2.FormatEmailAddress);

                    XmlDocument doc = new XmlDocument();
                    doc.LoadXml(decoded.Xml);

                    bool injected = doc.SelectNodes("//*[local-name()='" + Saml2RequestIdTests.InjectedAttr + "']").Count != 0;

                    r.Verify("応答に、要素が増えていない（構造が変わらない）", !injected,
                        "増えていない", injected ? "**" + Saml2RequestIdTests.InjectedAttr + " の要素が増えている**" : "増えていない");

                    r.VerifyEqual("StatusCode", Saml2.StatusResponder, decoded.StatusCode);

                    r.Verify("Assertion を入れない", !decoded.HasAssertion,
                        "入れない", decoded.HasAssertion ? "**入っている**" : "入れていない");

                    r.Note("**ほかの形式（Unspecified の `user.Id`・Persistent の PPID）は、サーバが作る値**なので当たらない。"
                        + "**値を DOM の API で入れる直しは、Open棟梁 の側で行う。**");
                }
                finally
                {
                    if (created)
                    {
                        await UsersAdmin.DeleteByUserNameAsync(admin, name);
                    }
                }

                r.Done();
            }
        }

        #region 補助

        /// <summary>管理者でサインインした IdPClient</summary>
        /// <param name="targetKey">core / netfx</param>
        /// <returns>IdPClient</returns>
        private async Task<IdPClient> AdminClientAsync(string targetKey)
        {
            IdPClient client = this.Client(targetKey);
            await client.SignInAsAdministratorAsync();

            return client;
        }

        /// <summary>管理画面から利用者を作り、作れたかを一覧で確かめる</summary>
        /// <param name="admin">IdPClient（管理者）</param>
        /// <param name="userName">利用者名</param>
        /// <param name="email">メアド</param>
        /// <returns>一覧に出れば true</returns>
        /// <remarks>
        /// **net48 版は例外をエラー画面への 302 にする**ので、状態コードだけでは作れたか分からない。
        /// </remarks>
        private static async Task<bool> TryCreateUserAsync(IdPClient admin, string userName, string email)
        {
            await UsersAdmin.CreateAsync(admin, userName, email, "User");

            HttpResponseMessage index = await UsersAdmin.IndexAsync(admin);

            return !string.IsNullOrEmpty(UsersAdmin.FindId(await index.Content.ReadAsStringAsync(), userName));
        }

        /// <summary>Redirect Binding で要求を送り、POST Binding の応答を読む</summary>
        /// <param name="r">TestReport</param>
        /// <param name="client">IdPClient</param>
        /// <param name="id">要求の ID</param>
        /// <param name="issuer">要求の Issuer</param>
        /// <param name="nameIdFormat">NameIDPolicy の Format</param>
        /// <param name="sign">署名するか（既定は署名する。IdP は署名の無い要求を断る。#400）</param>
        /// <returns>Saml2Response</returns>
        private async Task<Saml2Response> SendAsync(
            TestReport r, IdPClient client, string id, string issuer, string nameIdFormat = Saml2.FormatUnspecified, bool sign = true)
        {
            // **要求の XML は、ID をエスケープして組み立てる**（`Saml2.BuildAuthnRequest`）。
            //   **要求そのものは正しい XML で、IdP が取り出す ID の値が、上の文字を含む。**
            string xml = Saml2.BuildAuthnRequest(
                id, issuer, nameIdFormat, Saml2.BindingPost);

            HttpResponseMessage res = await client.GetAsync("/saml2request?" + (sign ? Saml2.SignedRequestQuery(client, xml) : Saml2.ToRedirectQuery(xml)));

            r.VerifyEqual("HTTP 200（自動送信フォーム）", "200", ((int)res.StatusCode).ToString());

            string form = await res.Content.ReadAsStringAsync();
            Dictionary<string, string> hidden = Html.HiddenInputs(form);

            bool has = hidden.ContainsKey("SAMLResponse") && !string.IsNullOrEmpty(hidden["SAMLResponse"]);

            r.Verify("SAMLResponse がある", has, "ある", has ? "ある" : "**無い**");

            Assert.True(has, "前提: 応答が返ること");

            Saml2Response decoded = Saml2.ReadResponse(Saml2.FromPostValue(hidden["SAMLResponse"]));

            r.Verify("応答を XML として読める", decoded != null,
                "読める", (decoded != null) ? "読めた" : "**読めない**");

            Assert.NotNull(decoded);

            return decoded;
        }

        /// <summary>NCName でない ID を、応答に使っていないことを確かめる</summary>
        /// <param name="r">TestReport</param>
        /// <param name="decoded">Saml2Response</param>
        private static void VerifyNotUsed(TestReport r, Saml2Response decoded)
        {
            XmlDocument doc = new XmlDocument();
            doc.LoadXml(decoded.Xml);

            // **応答のどの要素にも**（Response・Assertion の SubjectConfirmationData など）。
            //   **直す前は、Response の根の要素に増えていた**（net10.0 版で確かめた）。
            bool injected = doc.SelectNodes("//@" + Saml2RequestIdTests.InjectedAttr).Count != 0;

            r.Verify("応答のどの要素にも、属性が増えていない（構造が変わらない）", !injected,
                "増えていない", injected ? "**" + Saml2RequestIdTests.InjectedAttr + " が増えている**" : "増えていない");

            r.VerifyEqual("StatusCode", Saml2.StatusRequester, decoded.StatusCode);

            r.Verify("InResponseTo に送った ID を入れない",
                string.IsNullOrEmpty(decoded.InResponseTo),
                "入れない（空）",
                string.IsNullOrEmpty(decoded.InResponseTo) ? "入れない（空）" : "**" + decoded.InResponseTo + "**");

            r.Verify("エラー応答に Assertion を入れない", !decoded.HasAssertion,
                "入れない", decoded.HasAssertion ? "**入っている**" : "入れていない");
        }

        #endregion
    }
}
