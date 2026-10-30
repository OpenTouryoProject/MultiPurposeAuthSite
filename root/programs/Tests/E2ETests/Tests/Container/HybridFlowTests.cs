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
//* クラス名        ：HybridFlowTests
//* クラス日本語名  ：CN-5 コンテナ 2 つでのハイブリッド IdP 構成（#284）
//*
//* 作成日時        ：－
//* 作成者          ：－
//* 更新履歴        ：－
//*
//*  日時        更新者            内容
//*  ----------  ----------------  -------------------------------------------------
//*  2026/10/08  玄人 幸道         新規（#284）
//*  2026/10/13  玄人 幸道         CN-5.3（SAML2 の ID 連携）を足した（#293 の段階 3）
//*  2026/10/13  玄人 幸道         CN-5.4〜5.6（上流2件）を足した（#292 の段階 1）
//**********************************************************************************

using System.Net.Http;
using System.Threading.Tasks;

using MultiPurposeAuthSite.Tests.E2E.Infrastructure;

using Xunit;
using Xunit.Abstractions;

namespace MultiPurposeAuthSite.Tests.E2E.Tests.Container
{
    /// <summary>
    /// CN-5. コンテナ 2 つ（下流 → 上流）で、ID 連携が一巡すること。
    /// </summary>
    /// <remarks>
    /// **#281 の目視の手順を、そのまま機械にしたもの**である。
    ///
    /// **`RT-140.*` とは目的が違う**（重複ではない）。
    ///
    /// | | 目的 |
    /// |---|---|
    /// | `RT-140.*`（`Tests/Issues`） | **ID 連携という機能が、net48 版 / net10.0 版の両方で動くこと** |
    /// | **`CN-5.*`（ここ）** | **コンテナ 2 つという配備で、一巡が通ること** |
    ///
    /// **手順の実装は `Infrastructure/IdFederation` に 1 つだけ置いてある**（#284）。
    /// **下流が違うだけ**で、押す順番は同じである。
    ///
    /// **ここが通るということは、次が全部効いているということである。**
    ///
    /// - **ブラウザが行く先と、サーバが呼ぶ先を分けた設定**
    ///   （`IdFederationAuthorizeEndpoint` ＝ ホストから届く URL /
    ///   `IdFederationTokenEndpoint` ＝ `http://upstream:8080`。#281）
    /// - **Cookie の名前が分かれている**（混ざると、途中で相手の状態を掴む）
    /// - **上流の `preferred_username` が下流へ渡っている**（#151 の段階 4）
    /// </remarks>
    public class HybridFlowTests : TargetTestBase
    {
        /// <summary>コンストラクタ</summary>
        /// <param name="output">ITestOutputHelper</param>
        public HybridFlowTests(ITestOutputHelper output) : base(output)
        {
        }

        /// <summary>CN-5.1 下流コンテナから上流コンテナへ委譲して、サインインできる</summary>
        /// <returns>Task</returns>
        [SkippableFact]
        public async Task CN0501_コンテナ2つでID連携できる()
        {
            using (IdPClient client = ContainerTargets.Client(ContainerTargets.DownstreamKey))
            {
                string upstream = await IdFederation.SkipIfUpstreamIsDownAsync(client);

                TestReport r = this.Report("CN-5.1",
                    "下流コンテナから上流コンテナへ委譲して、下流にサインインできる",
                    "**コンテナ 2 つだけでハイブリッド IdP 構成が取れること**（#281）。"
                    + "**ブラウザが行く先（`authorize`）とサーバが呼ぶ先（`token` / `userinfo`）を"
                    + "分けた設定が効いていなければ、`code` の後で止まる。**"
                    + "**どちらも「同じイメージの別の配備」**なので、"
                    + "**ここで出るのは配備の差である。**",
                    "OIDC Core §3.1 / #140 / #281 / #284");

                r.Target(client.Target.DisplayName + "（" + client.Target.BaseUrl
                    + "） ← 上流 " + upstream);

                r.Step("(1) 上流コンテナでサインインしておく（この経路の確認を 1 本に絞るため）");

                bool upstreamSignedIn = await IdFederation.SignInUpstreamAsync(client, upstream);

                r.Verify("上流にサインインできる", upstreamSignedIn,
                    "サインインする", upstreamSignedIn ? "サインインした" : "**できなかった**");

                Assert.True(upstreamSignedIn, "前提: 上流にサインインできること");

                r.Step("(2) 下流コンテナで「ID連携でサインイン」を押す");

                FederationResult fed = await IdFederation.FederateAsync(
                    client, TestEnv.UpstreamUserName);

                r.Verify("上流の認可エンドポイントへ送られる",
                    !string.IsNullOrEmpty(fed.AuthorizeUrl),
                    "上流へリダイレクト",
                    (fed.AuthorizeUrl == null) ? "**リダイレクトしない**" : fed.AuthorizeUrl);

                //  **`prompt` は、もう付けない**（#287）。
                //    **ここはコンテナの中のアプリを測る**ので、
                //    **イメージが古いと「付いている」になる**（`Container\E2E\1_DockerComposeUp.bat` で作り直す）。
                bool prompt = (fed.AuthorizeUrl ?? "").Contains("prompt=");

                r.Verify("prompt は付けない（上流が画面を出してよい）", !prompt,
                    "prompt なし",
                    prompt ? "**付いている**（イメージが古い？）" : "付いていない");

                r.Step("(3) 上流が認可応答（form_post）を返す");

                r.Verify("code が返る", fed.Authorized,
                    "code あり", fed.Authorized ? "あり（値は伏せる）" : "**無し**");

                Assert.True(fed.Authorized, "前提: 上流が認可コードを返すこと");

                r.Step("(4) 下流コンテナにサインインできている");

                bool signedIn = await IdFederation.IsSignedInAsync(client);

                r.Verify("保護された画面が開く", signedIn,
                    "開く", signedIn ? "開いた" : "**ログイン画面へ戻された**");

                r.Note("**`token` / `userinfo` はコンテナ内の宛先（`http://upstream:8080`）で呼ばれる**"
                    + "（#281）。**届いていなければ、この画面は開かない。**");

                r.Done();
            }
        }

        /// <summary>CN-5.2 二度目の連携でも同じ利用者になる</summary>
        /// <returns>Task</returns>
        /// <remarks>
        /// **連携キーは `(iss, sub)`**（#140 の段階 3）。
        /// **同じ上流・同じ利用者なら、何度連携しても同じ下流アカウントになる。**
        /// </remarks>
        [SkippableFact]
        public async Task CN0502_二度目の連携でも同じ利用者になる()
        {
            using (IdPClient client = ContainerTargets.Client(ContainerTargets.DownstreamKey))
            {
                string upstream = await IdFederation.SkipIfUpstreamIsDownAsync(client);

                TestReport r = this.Report("CN-5.2",
                    "コンテナ 2 つの構成でも、二度目の連携で同じ利用者になる",
                    "**連携キーは `(iss, sub)`**（#140 の段階 3）。"
                    + "**下流コンテナは `IssuerId` を上流と分けている**（#281）が、"
                    + "**連携キーに使うのは上流の `iss`** なので、分けても同じ利用者になる。"
                    + "**毎回新しいアカウントが作られないこと**を見る。",
                    "#140 の段階 3 / #281 / #284");

                r.Target(client.Target.DisplayName + " ← 上流 " + upstream);

                r.Step("(1) 上流でサインインして、1 回目の連携を通す");

                Assert.True(await IdFederation.SignInUpstreamAsync(client, upstream),
                    "前提: 上流にサインインできること");

                FederationResult first = await IdFederation.FederateAsync(
                    client, TestEnv.UpstreamUserName);

                Assert.True(first.Authorized, "前提: 上流が認可コードを返すこと（1 回目）");

                string firstName = await HybridFlowTests.SignedInUserNameAsync(client);

                r.Verify("1 回目でサインインできる", !string.IsNullOrEmpty(firstName),
                    "利用者名が読める",
                    string.IsNullOrEmpty(firstName) ? "**読めない**" : firstName);

                r.Step("(2) もう一度、同じ経路を通す");

                FederationResult second = await IdFederation.FederateAsync(
                    client, TestEnv.UpstreamUserName);

                Assert.True(second.Authorized, "前提: 上流が認可コードを返すこと（2 回目）");

                string secondName = await HybridFlowTests.SignedInUserNameAsync(client);

                r.Step("(3) 同じ利用者である");

                r.Verify("1 回目と 2 回目が同じ利用者", firstName == secondName,
                    firstName, secondName);

                r.Done();
            }
        }


        /// <summary>CN-5.3 コンテナ 2 つでも、SAML2 の ID 連携ができる</summary>
        /// <returns>Task</returns>
        /// <remarks>
        /// **`CN-5.1` / `CN-5.2` は OIDC である。** **SAML2 の脚は、ここで初めてコンテナを通る。**
        ///
        /// **`SA-6.*`（`Tests/Saml`）とは、測っている配備が違う。**
        ///
        /// | | 下流 | 設定の出どころ |
        /// |---|---|---|
        /// | `SA-6.*` | **ホスト**（Kestrel / IIS Express） | `test.ps1` の環境変数 |
        /// | **`CN-5.3`（ここ）** | **コンテナ** | **compose の環境変数** |
        ///
        /// **ここが通るということは、次が効いているということである。**
        ///
        /// - **(2) の署名**（下流 → 上流の `AuthnRequest`）を、
        ///   **上流が登録値（`jwk_rsa_publickey`）で検証している**（#293 の段階 2）
        /// - **(3) の検証鍵**（上流 → 下流の応答）が、**上流の鍵になっている**
        ///   （#293 の段階 1 で、上流だけ別の RSA 鍵にした）
        /// - **Cookie の名前が分かれている**（混ざると、途中で相手の状態を掴む）
        /// </remarks>
        [SkippableFact]
        public async Task CN0503_コンテナ2つでSAML2のID連携ができる()
        {
            using (IdPClient client = ContainerTargets.Client(ContainerTargets.DownstreamKey))
            {
                string upstream = await Saml2Federation.SkipIfNotAvailableAsync(client);

                TestReport r = this.Report("CN-5.3",
                    "下流コンテナから上流コンテナへ SAML2 で委譲して、下流にサインインできる",
                    "**コンテナ 2 つだけで、SAML2 のハイブリッド IdP 構成が取れること**"
                    + "（#293 の段階 3）。**`CN-5.1` / `CN-5.2` は OIDC** なので、"
                    + "**SAML2 の脚はここで初めてコンテナを通る。**"
                    + "**上流は下流と別の RSA 鍵を持つ**（#293 の段階 1）ので、"
                    + "**(3) を上流の鍵で検証できていなければ、この一巡は通らない。**",
                    "SAML 2.0 Web Browser SSO Profile / #286 / #281 / #293 の段階 3");

                r.Target(client.Target.DisplayName + "（" + client.Target.BaseUrl
                    + "） ← 上流 " + upstream);

                r.Step("(1) 上流コンテナでサインインしておく（SAML の口は同意を通らない）");

                bool upstreamSignedIn = await IdFederation.SignInUpstreamAsync(client, upstream);

                r.Verify("上流にサインインできる", upstreamSignedIn,
                    "サインインする", upstreamSignedIn ? "サインインした" : "**できなかった**");

                Assert.True(upstreamSignedIn, "前提: 上流にサインインできること");

                r.Step("(2) 下流コンテナで「SAML2 の ID 連携」を押す");

                Saml2FederationResult fed = await Saml2Federation.FederateAsync(client);

                r.Verify("サインイン画面に SAML2 の導線が出ている", fed.HasSaml2Button,
                    "出ている", fed.HasSaml2Button ? "出ている" : "**出ていない**");

                Assert.True(fed.HasSaml2Button, "前提: 下流コンテナに SAML2 の導線が出ること");

                r.Verify("上流の SSO へ送られる", !string.IsNullOrEmpty(fed.SsoUrl),
                    "上流へリダイレクト",
                    string.IsNullOrEmpty(fed.SsoUrl)
                        ? "**リダイレクトしない**" : fed.SsoUrl.Split('?')[0]);

                Assert.False(string.IsNullOrEmpty(fed.SsoUrl), "前提: 上流へ送られること");

                r.Step("(3) 上流がアサーションを返し、下流コンテナの ACS が受け取る");

                //  **上流が `AuthnRequest` の署名を検証できなければ、ここで止まる**
                //    （#293 の段階 2。上流は登録値で (2) を検証する）。
                r.Verify("上流が下流の ACS を指す", !string.IsNullOrEmpty(fed.AcsUrl),
                    "ACS へリダイレクト",
                    string.IsNullOrEmpty(fed.AcsUrl)
                        ? "**指さない**（着いた先 " + fed.LandedOn + "）"
                        : fed.AcsUrl.Split('?')[0]);

                Assert.False(string.IsNullOrEmpty(fed.AcsUrl), "前提: 上流が ACS を指すこと");

                Saml2Response response = Saml2.ReadResponse(fed.ResponseXml);

                r.Verify("応答（`SAMLResponse`）が読める", response != null,
                    "読める", (response == null) ? "**読めない**" : "読める");

                Assert.NotNull(response);

                r.VerifyEqual("StatusCode が Success", Saml2.StatusSuccess, response.StatusCode);

                r.VerifyEqual("応答の Issuer は上流である",
                    client.Config.Get("IdFederationSaml2IssuerId"), response.Issuer);

                //  **署名はクエリ文字列に付く**（Redirect Binding。SAML 2.0 Bindings 3.4.4.1）。
                //    **XML の中には無いのが正しい**ので、`HasSignature` では見ない。
                //    **脚ごとに、署名が載っていることを見る**（#293 の 2 点目）。
                string sigAlg2 = Saml2.QueryValue(fed.SsoUrl, "SigAlg");
                string sigAlg3 = Saml2.QueryValue(fed.AcsUrl, "SigAlg");

                r.Verify("(2) 下流 → 上流の AuthnRequest に署名が載っている",
                    !string.IsNullOrEmpty(Saml2.QueryValue(fed.SsoUrl, "Signature")),
                    "Signature あり（値は伏せる）",
                    string.IsNullOrEmpty(sigAlg2) ? "**無い**" : "あり（SigAlg " + sigAlg2 + "）");

                r.Verify("(3) 上流 → 下流の Response に署名が載っている",
                    !string.IsNullOrEmpty(Saml2.QueryValue(fed.AcsUrl, "Signature")),
                    "Signature あり（値は伏せる）",
                    string.IsNullOrEmpty(sigAlg3) ? "**無い**" : "あり（SigAlg " + sigAlg3 + "）");

                r.Step("(4) 下流コンテナにサインインできている");

                r.Verify("ACS がサインインさせる（リダイレクトする）", fed.Authorized,
                    "リダイレクト",
                    fed.Authorized
                        ? "した" : "**エラー画面（" + Html.Describe(fed.AcsBody) + "）**");

                bool signedIn = await Saml2Federation.IsSignedInAsync(client);

                r.Verify("保護された画面が開く", signedIn,
                    "開く", signedIn ? "開いた" : "**ログイン画面へ戻された**");

                r.Observe("下流コンテナの画面に出るメアド",
                    await Saml2Federation.SignedInEmailAsync(client),
                    "**上流の属性（`mail`）から受け取る**（#286 の段階 4）。");

                r.Note("**上流が `AuthnRequest`（(2)）を検証できなければ Success は返らない**"
                    + "（#293 の段階 2。上流は登録値 `jwk_rsa_publickey` で検証する）。"
                    + "**下流が応答（(3)）を検証できなければ ACS がサインインさせない**"
                    + "（鍵は上流のメタデータから引く。#291）。"
                    + "**上流のメタデータは、コンテナの中から届く宛先で引いている**"
                    + "（`http://upstream:8080/samlmetadata`。"
                    + "**`https://localhost:44301` はコンテナの中から届かない**。#250 で実測）。");

                r.Done();
            }
        }

        #region 上流が n 件（#292 の段階 1）

        /// <summary>CN-5.4 2 つ目の上流（鍵も issuer も違う OP）と OIDC で連携できる</summary>
        /// <returns>Task</returns>
        /// <remarks>
        /// **ここが、この製品で初めて「別の鍵・別の issuer の OP」と連携する経路**である。
        ///
        /// **`CN-5.1` の上流（44301）とは、次が違う。**
        ///
        /// | | 上流 1（44301） | **上流 2（44304）** |
        /// |---|---|---|
        /// | `issuer` | `https://ssoauth.opentouryo.com` | **`https://upstream2.ssoauth.opentouryo.com`** |
        /// | RSA の鍵 | `SHA256RSA_Upstream.*` | **`SHA256RSA_Upstream2.*`** |
        /// | 自分の `client_id` | 上流 1 の登録 | **上流 2 の登録**（別の値・別の秘密） |
        ///
        /// **どちらへ行くかは `IdpKey`**（画面の導線が送る値）。
        /// **設定は compose の `IdFederationUpstreams__upstream2__*`** である。
        /// </remarks>
        [SkippableFact]
        public async Task CN0504_2つ目の上流とOIDCで連携できる()
        {
            using (IdPClient client = ContainerTargets.Client(ContainerTargets.DownstreamKey))
            {
                string upstream2 = await HybridFlowTests.SkipIfUpstream2IsDownAsync(client);

                TestReport r = this.Report("CN-5.4",
                    "2 つ目の上流（鍵も issuer も違う OP）へ OIDC で委譲して、下流にサインインできる",
                    "**上流を n 件登録できること**（#292 の段階 1）。"
                    + "**上流 2 は、上流 1 とも下流とも別の RSA 鍵**で、**別の `issuer`** を名乗る — "
                    + "**`id_token` の検証鍵を、相手ごとに引けていなければ通らない**（#289 / #290）。"
                    + "**「鍵の違う OP と連携できる」ことは、ここで初めて測れる**"
                    + "（#289 の完了コメントに残した限界）。",
                    "OIDC Core §3.1 / #289 / #290 / #292 の段階 1");

                r.Target(client.Target.DisplayName + " ← 上流 2（" + upstream2 + "）");

                r.Step("(1) 2 つ目の上流でサインインしておく");

                bool signedInUpstream = await IdFederation.SignInUpstreamAsync(client, upstream2);

                r.Verify("2 つ目の上流にサインインできる", signedInUpstream,
                    "サインインする", signedInUpstream ? "サインインした" : "**できなかった**");

                Assert.True(signedInUpstream, "前提: 2 つ目の上流にサインインできること");

                r.Step("(2) 下流で「ID 連携でサインイン」を、上流 2 を指して押す");

                FederationResult fed = await IdFederation.FederateAsync(
                    client, TestEnv.UpstreamUserName, HybridFlowTests.Upstream2OidcKey);

                bool toUpstream2 = (fed.AuthorizeUrl ?? "").StartsWith(upstream2);

                r.Verify("上流 2 の認可エンドポイントへ送られる", toUpstream2,
                    upstream2 + " へリダイレクト",
                    string.IsNullOrEmpty(fed.AuthorizeUrl)
                        ? "**リダイレクトしない**" : fed.AuthorizeUrl.Split('?')[0]);

                Assert.True(toUpstream2, "前提: 上流 2 へ送られること");

                r.Step("(3) 上流 2 が認可応答を返し、下流が id_token を検証する");

                r.Verify("code が返る", fed.Authorized,
                    "code あり", fed.Authorized ? "あり（値は伏せる）" : "**無し**");

                Assert.True(fed.Authorized, "前提: 上流 2 が認可コードを返すこと");

                r.Step("(4) 下流にサインインできている");

                bool signedIn = await IdFederation.IsSignedInAsync(client);

                r.Verify("保護された画面が開く", signedIn,
                    "開く", signedIn ? "開いた" : "**ログイン画面へ戻された**");

                r.Note("**上流 2 の鍵は `http://upstream2:8080/jwkcerts` から引いている**"
                    + "（`IdFederationUpstreams__upstream2__jwk_set_uri`。#290）。"
                    + "**引けなければ、設定の `.cer`（`SHA256RSA_Upstream2.cer`）に倒れる。**"
                    + "**上流 1 の鍵では、どちらも検証できない。**");

                r.Done();
            }
        }

        /// <summary>CN-5.5 2 つ目の上流と SAML2 で連携できる</summary>
        /// <returns>Task</returns>
        /// <remarks>
        /// **`CN-5.3`（上流 1 の SAML2）と同じ経路を、別の上流で通す。**
        /// **期待する `entityID` も署名鍵も、上流 2 のもの**である。
        /// </remarks>
        [SkippableFact]
        public async Task CN0505_2つ目の上流とSAML2で連携できる()
        {
            using (IdPClient client = ContainerTargets.Client(ContainerTargets.DownstreamKey))
            {
                string upstream2 = await HybridFlowTests.SkipIfUpstream2IsDownAsync(client);

                TestReport r = this.Report("CN-5.5",
                    "2 つ目の上流へ SAML2 で委譲して、下流にサインインできる",
                    "**SAML2 でも上流を n 件登録できること**（#292 の段階 1）。"
                    + "**メタデータの `entityID` は上流ごとに照合する**（#291）ので、"
                    + "**相手を取り違えれば、メタデータの値は使われない。**"
                    + "**署名鍵も上流 2 のもの**であり、**上流 1 の鍵では検証できない。**",
                    "SAML 2.0 Web Browser SSO Profile / #291 / #292 の段階 1");

                r.Target(client.Target.DisplayName + " ← 上流 2（" + upstream2 + "）");

                r.Step("(1) 2 つ目の上流でサインインしておく");

                Assert.True(await IdFederation.SignInUpstreamAsync(client, upstream2),
                    "前提: 2 つ目の上流にサインインできること");

                r.Step("(2) 下流で「SAML2 の ID 連携」を、上流 2 を指して押す");

                Saml2FederationResult fed = await Saml2Federation.FederateAsync(
                    client, HybridFlowTests.Upstream2Saml2Key);

                bool toUpstream2 = (fed.SsoUrl ?? "").StartsWith(upstream2);

                r.Verify("上流 2 の SSO へ送られる", toUpstream2,
                    upstream2 + " へリダイレクト",
                    string.IsNullOrEmpty(fed.SsoUrl)
                        ? "**リダイレクトしない**" : fed.SsoUrl.Split('?')[0]);

                Assert.True(toUpstream2, "前提: 上流 2 の SSO へ送られること");

                r.Step("(3) 上流 2 がアサーションを返し、下流の ACS が受け取る");

                Saml2Response response = Saml2.ReadResponse(fed.ResponseXml);

                r.Verify("応答が読める", response != null,
                    "読める", (response == null) ? "**読めない**" : "読める");

                Assert.NotNull(response);

                r.VerifyEqual("StatusCode が Success", Saml2.StatusSuccess, response.StatusCode);

                r.VerifyEqual("応答の Issuer は上流 2 である",
                    client.Config.Get("IdFederationUpstreams__upstream2_saml2__issuer"),
                    response.Issuer);

                r.Step("(4) 下流にサインインできている");

                r.Verify("ACS がサインインさせる（リダイレクトする）", fed.Authorized,
                    "リダイレクト",
                    fed.Authorized
                        ? "した" : "**エラー画面（" + Html.Describe(fed.AcsBody) + "）**");

                bool signedIn = await Saml2Federation.IsSignedInAsync(client);

                r.Verify("保護された画面が開く", signedIn,
                    "開く", signedIn ? "開いた" : "**ログイン画面へ戻された**");

                r.Done();
            }
        }

        /// <summary>CN-5.6 上流が違っても、同じメアドなら同じ下流の利用者に結び付く</summary>
        /// <returns>Task</returns>
        /// <remarks>
        /// **上流が n 件になると、「2 つの IdP から来た同じ人」をどう扱うかが現れる。**
        /// **この製品は、検証済みのメアドで既存アカウントに結ぶ**（アカウント リンク）。
        ///
        /// | 順 | 引き方 | |
        /// |---|---|---|
        /// | 1 | **連携キー `(iss, sub)`** | **上流ごとに別の行**（`UserLogins`。#140 の段階 3） |
        /// | 2 | **メアド** | **引けたら、その利用者に `(iss, sub)` を足す**（#151 の段階 3） |
        ///
        /// **守りは「メアドが検証済みであること」**である（#140 の段階 1。
        /// `Sts.AccountLink.CheckLinkToExistingUser`）。
        /// **検証済みでなければ結ばない** — **でなければ、メアドを名乗るだけで
        /// 他人のアカウントに入れてしまう。**
        ///
        /// **上流が 1 件のときは、この規則を測れなかった**（#292 の段階 1）。
        ///
        /// > **「上流ごとに別の利用者にする」配備が要るなら、それは設計の選択である。**
        /// > **いまは「同じ人」として扱う。** 変えるなら #292 の段階 2 以降で論点にする。
        /// </remarks>
        [SkippableFact]
        public async Task CN0506_上流が違っても同じメアドなら同じ利用者になる()
        {
            //  **上流ごとに、別の Cookie の入れ物で測る**（#292 の段階 1）。
            //    **1 つの入れ物で続けると、上流 1 のサインインが残り、
            //    上流 2 の連携が失敗しても「同じ利用者」に見えてしまう**（歯抜けで実測）。
            using (IdPClient client = ContainerTargets.Client(ContainerTargets.DownstreamKey))
            using (IdPClient client2 = ContainerTargets.Client(ContainerTargets.DownstreamKey))
            {
                string upstream1 = await IdFederation.SkipIfUpstreamIsDownAsync(client);
                string upstream2 = await HybridFlowTests.SkipIfUpstream2IsDownAsync(client);

                TestReport r = this.Report("CN-5.6",
                    "上流が違っても、同じ（検証済みの）メアドなら、同じ下流の利用者に結び付く",
                    "**連携キーは `(iss, sub)`**（#140 の段階 3）なので、**上流ごとに別の行**になる。"
                    + "**行が無い初回は、メアドで既存アカウントを探し、検証済みなら結ぶ**"
                    + "（#151 の段階 3 / #140 の段階 1）。"
                    + "**結果として、2 つの上流から来た同じ人は、同じ下流の利用者になる。**"
                    + "**上流が 1 件のときは測れなかった**（#292 の段階 1）。",
                    "#140 の段階 1・3 / #151 の段階 3 / #292 の段階 1");

                r.Target(client.Target.DisplayName + " ← 上流 1（" + upstream1
                    + "） / 上流 2（" + upstream2 + "）");

                r.Step("(1) 上流 1 で連携して、下流の利用者名を読む");

                Assert.True(await IdFederation.SignInUpstreamAsync(client, upstream1),
                    "前提: 上流 1 にサインインできること");

                FederationResult first = await IdFederation.FederateAsync(
                    client, TestEnv.UpstreamUserName);

                Assert.True(first.Authorized, "前提: 上流 1 が認可コードを返すこと");

                string nameByUpstream1 = await HybridFlowTests.SignedInUserNameAsync(client);

                r.Verify("上流 1 の連携でサインインできる", !string.IsNullOrEmpty(nameByUpstream1),
                    "利用者名が読める",
                    string.IsNullOrEmpty(nameByUpstream1) ? "**読めない**" : nameByUpstream1);

                r.Step("(2) 上流 2（別の iss・別の鍵）で連携して、下流の利用者名を読む");

                Assert.True(await IdFederation.SignInUpstreamAsync(client2, upstream2),
                    "前提: 上流 2 にサインインできること");

                FederationResult second = await IdFederation.FederateAsync(
                    client2, TestEnv.UpstreamUserName, HybridFlowTests.Upstream2OidcKey);

                Assert.True(second.Authorized, "前提: 上流 2 が認可コードを返すこと");

                string nameByUpstream2 = await HybridFlowTests.SignedInUserNameAsync(client2);

                r.Verify("上流 2 の連携でサインインできる", !string.IsNullOrEmpty(nameByUpstream2),
                    "利用者名が読める",
                    string.IsNullOrEmpty(nameByUpstream2) ? "**読めない**" : nameByUpstream2);

                r.Step("(3) 同じ利用者に結び付いている（アカウント リンク）");

                //  **新しい利用者が作られていたら、ここで違う名前になる**
                //    （下流は重複を避けて連番を足すため）。
                r.VerifyEqual("上流 1 と上流 2 で同じ利用者",
                    nameByUpstream1 ?? "(読めない)", nameByUpstream2 ?? "(読めない)");

                r.Step("(4) 二度目の連携でも、同じ利用者のままである");

                //  **2 回目は `(iss, sub)` の行が在る**ので、**メアドの経路を通らない。**
                //    **行が上流ごとに増えていなければ、ここで別の利用者になる。**
                FederationResult again = await IdFederation.FederateAsync(
                    client2, TestEnv.UpstreamUserName, HybridFlowTests.Upstream2OidcKey);

                Assert.True(again.Authorized, "前提: 上流 2 が認可コードを返すこと（2 回目）");

                string nameAgain = await HybridFlowTests.SignedInUserNameAsync(client2);

                r.VerifyEqual("2 回目も同じ利用者", nameByUpstream2 ?? "(読めない)",
                    nameAgain ?? "(読めない)");

                r.Note("**結び付けの守りは「メアドが検証済みであること」**である"
                    + "（#140 の段階 1。`Sts.AccountLink.CheckLinkToExistingUser`）。"
                    + "**検証済みでなければ結ばず、理由を画面とログに出す。**"
                    + "**上流が増えるほど、この守りが効いている必要がある。**");

                r.Done();
            }
        }

        /// <summary>上流 2 の登録（OIDC）の鍵</summary>
        private const string Upstream2OidcKey = "upstream2";

        /// <summary>上流 2 の登録（SAML2）の鍵</summary>
        private const string Upstream2Saml2Key = "upstream2_saml2";

        /// <summary>2 つ目の上流が建っていなければ Skip する</summary>
        /// <param name="client">IdPClient（下流）</param>
        /// <returns>上流 2 の URL</returns>
        /// <remarks>
        /// **宛先は下流の設定から引く**（`IdFederationUpstreams__upstream2__authorize_endpoint`）。
        /// **テストに URL を書かない**（`IdFederation.SkipIfUpstreamIsDownAsync` と同じ流儀）。
        /// </remarks>
        private static async Task<string> SkipIfUpstream2IsDownAsync(IdPClient client)
        {
            string endpoint = client.Config.Get(
                "IdFederationUpstreams__upstream2__authorize_endpoint");

            Skip.If(string.IsNullOrEmpty(endpoint),
                "下流コンテナに 2 つ目の上流の登録がありません"
                + "（compose の IdFederationUpstreams__upstream2__*。#292 の段階 1）。");

            string origin = new System.Uri(endpoint).GetLeftPart(System.UriPartial.Authority);

            bool up = false;

            try
            {
                HttpResponseMessage res = await client.GetAsync(
                    origin + "/.well-known/openid-configuration");

                up = res.IsSuccessStatusCode;
            }
            catch (System.Net.Http.HttpRequestException)
            {
                up = false;
            }
            catch (System.Threading.Tasks.TaskCanceledException)
            {
                up = false;
            }

            Skip.IfNot(up,
                "2 つ目の上流（" + origin + "）が起動していません。"
                + "Container\\E2E\\1_DockerComposeUp.bat で建ててください（#292 の段階 1）。");

            return origin;
        }

        #endregion

        /// <summary>サインインしている利用者名を、画面から読む</summary>
        /// <param name="client">IdPClient</param>
        /// <returns>利用者名（読めなければ null）</returns>
        /// <remarks>
        /// **画面に出ている名前で見る。** **`sub` では見ない**
        /// （`subject_types` の既定が `public` になり、`sub` は利用者 ID である。#151 の段階 4）。
        /// </remarks>
        private static async Task<string> SignedInUserNameAsync(IdPClient client)
        {
            string html = await client.GetStringAsync("/Manage/Index");

            if (string.IsNullOrEmpty(html))
            {
                return null;
            }

            System.Text.RegularExpressions.Match m =
                System.Text.RegularExpressions.Regex.Match(
                    html, TestEnv.UpstreamUserName + "[A-Za-z0-9_@.]*");

            return m.Success ? m.Value : null;
        }
    }
}
