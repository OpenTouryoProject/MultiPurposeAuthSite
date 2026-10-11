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
//* クラス名        ：IdFederationSaml2Tests
//* クラス日本語名  ：SA-6 SAML2 の ID 連携
//*
//* 作成日時        ：－
//* 作成者          ：－
//* 更新履歴        ：－
//*
//*  日時        更新者            内容
//*  ----------  ----------------  -------------------------------------------------
//*  2026/10/11  玄人 幸道         新規（#286 の段階 3）
//**********************************************************************************

using System.Threading.Tasks;

using MultiPurposeAuthSite.Tests.E2E.Infrastructure;

using Xunit;
using Xunit.Abstractions;

namespace MultiPurposeAuthSite.Tests.E2E.Tests.Saml
{
    /// <summary>
    /// SA-6. **SAML2 の ID 連携**（この IdP が、上流の IdP に対して SP になる）。
    /// </summary>
    /// <remarks>
    /// **#286 で足した経路**である。**上流は `store/` のコンテナ**（`RT-140.*` と同じ）。
    ///
    /// | | OIDC（`RT-140.*`） | SAML2（ここ） |
    /// |---|---|---|
    /// | 押すボタン | `id_federation_signin` | **`id_federation_saml2_signin`** |
    /// | 連携キー | `(id_token の iss, sub)` | **`(上流の EntityID, NameID)`** |
    /// | 利用者の鍵 | メアド | **メアド**（＝ `NameID`。`NameIDFormat=emailAddress`） |
    /// | 検証鍵 | `kid` → ローカルの JWK Set（#601） | **設定の `IdFederationSaml2CerFilePath`** |
    /// | 期待する発行者 | `SpRp_Isser` | **`IdFederationSaml2IssuerId`** |
    ///
    /// **上流に、下流の ACS を `redirect_uri_saml` として登録してある**
    /// （`store/docker-compose.yml`。`IdFederationE2ECore` / `IdFederationE2ENetFx`）。
    ///
    /// **同意は要らない**（SAML の口は同意を通らない）ので、
    /// **`RT-140.*` の `EnsureUpstreamConsentAsync` に当たる迂回が無い。**
    ///
    /// **上流が建っていない／設定が無い配備では Skip する**（DB ストアや netfx 版と同じ扱い）。
    /// </remarks>
    public class IdFederationSaml2Tests : TargetTestBase
    {
        /// <summary>コンストラクタ</summary>
        /// <param name="output">ITestOutputHelper</param>
        public IdFederationSaml2Tests(ITestOutputHelper output) : base(output)
        {
        }

        #region SA-6.1

        /// <summary>SA-6.1 上流の IdP へ SAML2 で委譲して、下流にサインインできる</summary>
        /// <param name="targetKey">core / netfx</param>
        /// <returns>Task</returns>
        [SkippableTheory]
        [MemberData(nameof(AllTargets))]
        public async Task SA0601_SAML2のID連携でサインインできる(string targetKey)
        {
            using (IdPClient client = this.Client(targetKey))
            {
                string upstream = await Saml2Federation.SkipIfNotAvailableAsync(client);

                TestReport r = this.Report("SA-6.1",
                    "上流の IdP へ SAML2 で委譲して、下流にサインインできる",
                    "**下流は自分で認証せず、上流のアサーションを受け取る。**"
                    + "**`NameIDFormat=emailAddress` の `NameID` をメアドとして扱い**、"
                    + "**`(上流の EntityID, NameID)` を連携キーに**、下流のアカウントへ結び付ける。"
                    + "**検証鍵は設定で与える**（`IdFederationSaml2CerFilePath`）— "
                    + "**`SpRp_RsaCerFilePath` は、この配備では自分の証明書として読まれている**ため。",
                    "SAML 2.0 Web Browser SSO Profile / #286 の段階 2");

                r.Target(client.Target.DisplayName + " ← 上流 " + upstream);

                r.Step("(1) 上流でサインインしておく");

                bool upstreamSignedIn =
                    await IdFederation.SignInUpstreamAsync(client, upstream);

                r.Verify("上流にサインインできる", upstreamSignedIn,
                    "サインインする", upstreamSignedIn ? "サインインした" : "**できなかった**");

                Assert.True(upstreamSignedIn, "前提: 上流にサインインできること");

                r.Step("(2) 下流で「SAML2 の ID 連携」を押す");

                Saml2FederationResult fed = await Saml2Federation.FederateAsync(client);

                r.Verify("サインイン画面に SAML2 の導線が出ている", fed.HasSaml2Button,
                    "出ている", fed.HasSaml2Button ? "出ている" : "**出ていない**");

                r.Verify("上流の SSO へ送られる", !string.IsNullOrEmpty(fed.SsoUrl),
                    "上流へリダイレクト",
                    (fed.SsoUrl == null) ? "**リダイレクトしない**" : fed.SsoUrl.Split('?')[0]);

                Assert.False(string.IsNullOrEmpty(fed.SsoUrl), "前提: 上流へ送られること");

                r.Step("(3) 送った AuthnRequest を読む");

                string request = fed.AuthnRequestXml;

                r.Verify("SAMLRequest を読める", !string.IsNullOrEmpty(request),
                    "読める", (request == null) ? "**読めない**" : "読める");

                bool emailFormat = (request ?? "").Contains(
                    "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress");

                r.Verify("NameIDFormat に emailAddress を要求する", emailFormat,
                    "emailAddress", emailFormat ? "要求している" : "**要求していない**");

                //  **`IsPassive` は送らない**（#287 で OIDC の `prompt=none` を外したのと同じ理由）。
                //    **利用者が押している導線で、上流の UI を禁じない。**
                bool isPassive = (request ?? "").Contains("IsPassive=\"true\"");

                r.Verify("IsPassive は付けない（上流が画面を出してよい）", !isPassive,
                    "IsPassive なし", isPassive ? "**付いている**" : "付いていない");

                r.Step("(4) 上流がアサーションを返し、下流の ACS が受け取る");

                r.Verify("上流が下流の ACS を指す", !string.IsNullOrEmpty(fed.AcsUrl),
                    "ACS へリダイレクト",
                    (fed.AcsUrl == null) ? "**指さない**" : fed.AcsUrl.Split('?')[0]);

                Assert.False(string.IsNullOrEmpty(fed.AcsUrl), "前提: 上流が ACS を指すこと");

                Saml2Response response = Saml2.ReadResponse(fed.ResponseXml);

                r.Verify("応答が読める", response != null,
                    "読める", (response == null) ? "**読めない**" : "読める");

                Assert.NotNull(response);

                r.VerifyEqual("StatusCode が Success",
                    "urn:oasis:names:tc:SAML:2.0:status:Success", response.StatusCode);

                r.VerifyEqual("NameIDFormat が emailAddress",
                    "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress",
                    response.NameIdFormat);

                bool nameIdIsEmail = (response.NameId ?? "").Contains("@");

                r.Verify("NameID がメアドである", nameIdIsEmail,
                    "メアド", nameIdIsEmail ? "メアドだった" : "**違う**");

                r.Observe("上流の Issuer", response.Issuer,
                    "**期待値は設定の `IdFederationSaml2IssuerId`**（下流が照合する）。");

                r.Step("(5) 下流にサインインできている");

                r.Verify("ACS がサインインさせる（リダイレクトする）", fed.Authorized,
                    "リダイレクト",
                    fed.Authorized ? "した" : "**エラー画面（" + Html.Describe(fed.AcsBody) + "）**");

                bool signedIn = await Saml2Federation.IsSignedInAsync(client);

                r.Verify("下流にサインインできている", signedIn,
                    "/Manage/Index が開く", signedIn ? "開いた" : "**開かない**");

                string email = await Saml2Federation.SignedInEmailAsync(client);

                r.Observe("下流の画面に出るメアド", email,
                    "**上流の `NameID` と同じになる**（`NameID` をメアドとして受け取るため）。");

                r.Done();
            }
        }

        #endregion

        #region SA-6.2

        /// <summary>SA-6.2 二度目の SAML2 の ID 連携でも、同じ下流アカウントになる</summary>
        /// <param name="targetKey">core / netfx</param>
        /// <returns>Task</returns>
        /// <remarks>
        /// **連携キーが効いていることの確認**である（`RT-140.5` と同じ観点）。
        ///
        /// **1 度目は「作る／既存に結ぶ」、2 度目は「結び付けを引いて入る」**で、
        /// **通る枝が違う。** **同じ利用者に着くことを測る。**
        /// </remarks>
        [SkippableTheory]
        [MemberData(nameof(AllTargets))]
        public async Task SA0602_二度目の連携でも同じ利用者になる(string targetKey)
        {
            using (IdPClient client = this.Client(targetKey))
            {
                string upstream = await Saml2Federation.SkipIfNotAvailableAsync(client);

                TestReport r = this.Report("SA-6.2",
                    "二度目の SAML2 の ID 連携でも、同じ下流アカウントになる",
                    "**連携キーは `(上流の EntityID, NameID)`** である。"
                    + "**1 度目と 2 度目で通る枝が違う**（作る／結ぶ ⇔ 結び付けを引く）ので、"
                    + "**同じ利用者に着くことを測る。**",
                    "#286 の段階 2 / RT-140.5 と同じ観点");

                r.Target(client.Target.DisplayName + " ← 上流 " + upstream);

                r.Step("(1) 上流でサインインしておく");

                bool upstreamSignedIn =
                    await IdFederation.SignInUpstreamAsync(client, upstream);

                Assert.True(upstreamSignedIn, "前提: 上流にサインインできること");

                r.Step("(2) 1 度目の ID 連携");

                Saml2FederationResult first = await Saml2Federation.FederateAsync(client);

                r.Verify("1 度目でサインインできる", first.Authorized,
                    "リダイレクト",
                    first.Authorized ? "した" : "**エラー画面（" + Html.Describe(first.AcsBody) + "）**");

                Assert.True(first.Authorized, "前提: 1 度目が成立すること");

                string firstEmail = await Saml2Federation.SignedInEmailAsync(client);

                r.Observe("1 度目のメアド", firstEmail);

                r.Step("(3) もう一度、ID 連携を行う");

                Saml2FederationResult second = await Saml2Federation.FederateAsync(client);

                r.Verify("2 度目もサインインできる", second.Authorized,
                    "リダイレクト",
                    second.Authorized ? "した" : "**エラー画面（" + Html.Describe(second.AcsBody) + "）**");

                string secondEmail = await Saml2Federation.SignedInEmailAsync(client);

                r.VerifyEqual("2 度目も同じ利用者（メアドが一致）", firstEmail, secondEmail);

                //  **`NameID` が毎回同じであること**も見る（連携キーの土台）。
                string firstNameId = Saml2.ReadResponse(first.ResponseXml)?.NameId;
                string secondNameId = Saml2.ReadResponse(second.ResponseXml)?.NameId;

                r.VerifyEqual("NameID が毎回同じ", firstNameId, secondNameId);

                r.Done();
            }
        }

        #endregion

        #region SA-6.3

        /// <summary>SA-6.3 上流にセッションが無ければ、SAML2 の ID 連携は成立しない</summary>
        /// <param name="targetKey">core / netfx</param>
        /// <returns>Task</returns>
        /// <remarks>
        /// **下流は、上流の認証結果を受け取るだけ**である。
        /// **上流が認証していないのにサインインさせては、委譲の意味が無い。**
        ///
        /// **`IsPassive` は送らない**ので、**上流はサインイン画面を出す**（#287 と同じ考え方）。
        /// **そこを通らないかぎりアサーションは返らない。**
        /// </remarks>
        [SkippableTheory]
        [MemberData(nameof(AllTargets))]
        public async Task SA0603_上流が未サインインなら連携は成立しない(string targetKey)
        {
            using (IdPClient client = this.Client(targetKey))
            {
                string upstream = await Saml2Federation.SkipIfNotAvailableAsync(client);

                TestReport r = this.Report("SA-6.3",
                    "上流にセッションが無ければ、SAML2 の ID 連携は成立しない",
                    "**下流は、上流のアサーションを受け取るだけ**である。"
                    + "**`IsPassive` を送らないので、上流はサインイン画面を出す**（#287 と同じ考え方）。"
                    + "**そこを通らないかぎりアサーションは返らない**ので、**下流はサインインしない。**",
                    "SAML 2.0 Web Browser SSO Profile / #286 の段階 2");

                r.Target(client.Target.DisplayName + " ← 上流 " + upstream + "（未サインイン）");

                r.Step("上流にサインインせずに、下流で「SAML2 の ID 連携」を押す");

                Saml2FederationResult fed = await Saml2Federation.FederateAsync(client);

                r.Verify("上流の SSO へは送られる", !string.IsNullOrEmpty(fed.SsoUrl),
                    "上流へリダイレクト",
                    (fed.SsoUrl == null) ? "**リダイレクトしない**" : "リダイレクトした");

                r.Verify("アサーションは返らない（下流の ACS を指さない）",
                    string.IsNullOrEmpty(fed.AcsUrl),
                    "ACS を指さない",
                    (fed.AcsUrl == null) ? "指さなかった" : "**指した : " + fed.AcsUrl + "**");

                //  **上流は、自分のサインイン画面へ送る**（`IsPassive` を送っていないため）。
                //    **リダイレクトしたこと自体では判らない**ので、**着いた先で見る**。
                bool landedOnUpstreamLogin =
                    (fed.LandedOn ?? "").StartsWith(upstream, System.StringComparison.OrdinalIgnoreCase)
                    && (fed.LandedOn ?? "").Contains("/Account/Login");

                r.Verify("上流は自分のサインイン画面へ送る", landedOnUpstreamLogin,
                    "上流の /Account/Login",
                    string.IsNullOrEmpty(fed.LandedOn) ? "**着いた先が無い**" : fed.LandedOn);

                bool signedIn = await Saml2Federation.IsSignedInAsync(client);

                r.Verify("下流はサインインしない", !signedIn,
                    "サインインしない", signedIn ? "**サインインしてしまった**" : "しなかった");

                r.Observe("上流が返した画面", Html.Describe(fed.SsoBody),
                    "**サインイン画面である**（`IsPassive` を送っていないため、"
                    + "**上流は認証の UI を出せる**）。");

                r.Done();
            }
        }

        #endregion
    }
}
