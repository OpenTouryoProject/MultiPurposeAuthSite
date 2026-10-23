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
//*  2026/10/12  玄人 幸道         SA-6.4（属性を使う）を足した（#286 の段階 4）
//*  2026/10/13  玄人 幸道         SA-6.5（署名を壊した要求）を足した（#293 の段階 4）
//*  2026/10/14  玄人 幸道         SA-6.6（上流の証明書が2本）を足した（#292 の段階 3）
//*  2026/10/22  玄人 幸道         参照先の名前を Open棟梁 に改めた（#294）
//**********************************************************************************

using System.Threading.Tasks;
using System.Xml;

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
    /// | 利用者の鍵 | メアド | **メアド**（**属性の `mail`** → `NameID`。段階 4） |
    /// | 検証鍵 | `kid` → 上流の JWK Set（#290） | **上流のメタデータ**（#291。倒れ先が設定の `IdFederationSaml2CerFilePath`） |
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

        #region SA-6.4

        /// <summary>SA-6.4 ID 連携が、アサーションの属性を使う</summary>
        /// <param name="targetKey">core / netfx</param>
        /// <returns>Task</returns>
        /// <remarks>
        /// **段階 4 で足した経路**である（Open棟梁 の `SAML2Attributes`）。
        ///
        /// | | 段階 3 まで | 段階 4 |
        /// |---|---|---|
        /// | メアド | `emailAddress` の `NameID` | **属性（`mail`）** → `NameID` |
        /// | 新規作成時の名前 | メアドの `@` より前 | **属性（`uid`）** → メアドの `@` より前 |
        /// | 検証済みのメアドか | **`emailAddress` の `NameID` を検証済みとして扱う** | **属性（`email_verified`）** |
        ///
        /// **上流が属性を出すこと**は `SA-7.1` が測っている。
        /// **ここで測るのは、下流がそれを使って成立すること**である。
        /// </remarks>
        [SkippableTheory]
        [MemberData(nameof(AllTargets))]
        public async Task SA0604_ID連携がアサーションの属性を使う(string targetKey)
        {
            using (IdPClient client = this.Client(targetKey))
            {
                string upstream = await Saml2Federation.SkipIfNotAvailableAsync(client);

                TestReport r = this.Report("SA-6.4",
                    "SAML2 の ID 連携が、アサーションの属性（mail / uid / email_verified）を使う",
                    "**段階 4 で、メアド・利用者名・`email_verified` を属性で運べるようになった**"
                    + "（#286）。**下流は「属性 → `NameID`」の順でメアドを決める**ので、"
                    + "**上流が属性を出していれば、そちらが使われる。**"
                    + "**`email_verified` を上流が言うようになった**ため、"
                    + "**既存アカウントへの結び付けを、`NameID` の形で代用しなくてよい。**",
                    "SAML Core 2.7.3.1 / #286 の段階 4");

                r.Target(client.Target.DisplayName + " ← 上流 " + upstream);

                r.Step("(1) 上流でサインインして、ID 連携を 1 回通す");

                bool upstreamSignedIn =
                    await IdFederation.SignInUpstreamAsync(client, upstream);

                Assert.True(upstreamSignedIn, "前提: 上流にサインインできること");

                Saml2FederationResult fed = await Saml2Federation.FederateAsync(client);

                r.Verify("連携が成立する（サインインさせる）", fed.Authorized,
                    "リダイレクト",
                    fed.Authorized ? "した" : "**エラー画面（" + Html.Describe(fed.AcsBody) + "）**");

                Assert.True(fed.Authorized, "前提: 連携が成立すること");

                r.Step("(2) 上流のアサーションに属性が入っている");

                Saml2Response response = Saml2.ReadResponse(fed.ResponseXml);

                Assert.NotNull(response);

                r.Verify("AttributeStatement がある",
                    response.Attributes != null && response.Attributes.Count != 0,
                    "ある",
                    (response.Attributes == null || response.Attributes.Count == 0)
                        ? "**無い**" : "ある（" + response.Attributes.Count + " 件）");

                string attrEmail = response.Attribute("urn:oid:0.9.2342.19200300.100.1.3");
                string attrUserName = response.Attribute("urn:oid:0.9.2342.19200300.100.1.1");
                string attrVerified = response.Attribute("email_verified");

                r.Verify("メアドの属性（mail）がある", !string.IsNullOrEmpty(attrEmail),
                    "ある", string.IsNullOrEmpty(attrEmail) ? "**無い**" : "ある（値は伏せる）");

                r.Verify("利用者名の属性（uid）がある", !string.IsNullOrEmpty(attrUserName),
                    "ある", string.IsNullOrEmpty(attrUserName) ? "**無い**" : "ある");

                r.Verify("email_verified の属性が true", attrVerified == "true",
                    "true", string.IsNullOrEmpty(attrVerified) ? "**無い**" : attrVerified);

                r.Step("(3) 下流は、属性のメアドで利用者を引いている");

                string email = await Saml2Federation.SignedInEmailAsync(client);

                r.VerifyEqual("下流の画面に出るメアドが、属性のメアドと一致",
                    "一致", (email == attrEmail) ? "一致" : "**不一致**");

                //  **この上流は `NameID` にもメアドを入れる**（`emailAddress` を要求しているため）。
                //    **どちらを使っても同じ値になる**ので、**ここだけでは出所を切り分けられない。**
                //    **出所の切り分けは `SA-7.2`**（`persistent` でも属性からメアドが取れる）。
                r.Observe("NameID と属性のメアドの関係",
                    (response.NameId == attrEmail) ? "同じ値" : "違う値",
                    "**この上流は `emailAddress` の `NameID` を返す**ので、**同じ値になる。**"
                    + "**属性の方を使っていることは `SA-7.2` と合わせて読むこと**"
                    + "（`persistent` の `NameID` でも属性からメアドが取れる）。");

                r.Note("**`Transient` の `NameID` は受けない**（段階 4）— "
                    + "**毎回変わる値を連携キーにできない**（SAML Core 8.3.8）。");

                r.Done();
            }
        }

        #endregion

        #region SA-6.5

        /// <summary>SA-6.5 署名を壊した AuthnRequest は、上流が弾く</summary>
        /// <param name="targetKey">core / netfx</param>
        /// <returns>Task</returns>
        /// <remarks>
        /// **(2)（下流 → 上流の `AuthnRequest`）の署名が、本当に検証されていること**を測る
        /// （#293 の段階 2 を常設のケースにしたもの。段階 4）。
        ///
        /// **歯抜けを、配備を壊さずに測る。**
        /// **上流の登録鍵を差し替える**手は、**`store/docker-compose.yml` を書き換えて
        /// コンテナを作り直す**ことになり、通しには入れられない。
        /// **ここでは、製品が署名した本物の要求の、署名だけを 1 バイト変える。**
        ///
        /// | | |
        /// |---|---|
        /// | **通れば** | **検証されていない**（`jwk_rsa_publickey` の登録が外れた、など） |
        /// | **`Requester` で返れば** | **検証されている** |
        ///
        /// **`SA-5.4` は「鍵を登録したクライアントの、署名の無い要求」**である。
        /// **ここは「署名が在るが、合わない要求」**で、**検証の計算そのものを通る。**
        /// </remarks>
        [SkippableTheory]
        [MemberData(nameof(AllTargets))]
        public async Task SA0605_署名を壊したAuthnRequestを上流が弾く(string targetKey)
        {
            using (IdPClient client = this.Client(targetKey))
            {
                string upstream = await Saml2Federation.SkipIfNotAvailableAsync(client);

                TestReport r = this.Report("SA-6.5",
                    "署名を壊した AuthnRequest は、上流が弾く",
                    "**(2)（下流 → 上流の `AuthnRequest`）の署名が検証されていること**（#293 の段階 2）。"
                    + "**上流に `jwk_rsa_publickey` を登録していなければ、`VerifySamlRequest` は"
                    + "「鍵がない場合は、通す」経路に入る**ので、"
                    + "**壊した署名でも通ってしまう** — **それを落とすのがこのケースである。**"
                    + "**製品が署名した本物の要求の、署名だけを 1 バイト変えて送る**ので、"
                    + "**配備を壊さずに歯抜けが測れる**（段階 4）。",
                    "SAML 2.0 Bindings 3.4.4.1 / #275 / #293 の段階 2");

                r.Target(client.Target.DisplayName + " → 上流 " + upstream);

                r.Step("(1) 上流でサインインしておく（署名の検証まで進ませるため）");

                Assert.True(await IdFederation.SignInUpstreamAsync(client, upstream),
                    "前提: 上流にサインインできること");

                r.Step("(2) 下流に、本物の AuthnRequest を作らせる（送る手前で止める）");

                Saml2FederationResult start = await Saml2Federation.StartAsync(client);

                Assert.False(string.IsNullOrEmpty(start.SsoUrl), "前提: 上流へ送られること");

                string sigAlg = Saml2.QueryValue(start.SsoUrl, "SigAlg");
                string signature = Saml2.QueryValue(start.SsoUrl, "Signature");

                r.Verify("下流は AuthnRequest に署名している",
                    !string.IsNullOrEmpty(signature),
                    "Signature あり（値は伏せる）",
                    string.IsNullOrEmpty(signature) ? "**無い**" : "あり");

                Assert.False(string.IsNullOrEmpty(signature), "前提: 署名が載っていること");

                r.Observe("SigAlg", sigAlg,
                    "**実際に使ったアルゴリズム**（Open棟梁 #604 の追随）。");

                r.Step("(3) 署名だけを 1 バイト変えて送る");

                byte[] raw = System.Convert.FromBase64String(signature);

                //  **先頭の 1 バイトを反転する。** **長さも符号化も変えない**ので、
                //    **「署名が合わない」以外の違いが入らない。**
                raw[0] = (byte)(raw[0] ^ 0xFF);

                string tampered = Saml2.ReplaceQueryValue(
                    start.SsoUrl, "Signature", System.Convert.ToBase64String(raw));

                r.Verify("壊したのは署名だけである",
                    Saml2.QueryValue(tampered, "SAMLRequest")
                        == Saml2.QueryValue(start.SsoUrl, "SAMLRequest")
                    && Saml2.QueryValue(tampered, "SigAlg") == sigAlg,
                    "SAMLRequest と SigAlg は元のまま", "元のまま");

                Saml2FederationResult broken =
                    await Saml2Federation.FollowSsoAsync(client, tampered);

                r.Step("(4) 上流が弾く");

                Saml2Response response = Saml2.ReadResponse(broken.ResponseXml);

                r.Verify("上流が応答を返す（画面で止まらない）", response != null,
                    "応答が返る",
                    (response == null)
                        ? "**応答が無い**（着いた先 " + broken.LandedOn + "）" : "返った");

                Assert.NotNull(response);

                r.VerifyEqual("StatusCode", Saml2.StatusRequester, response.StatusCode);

                r.Verify("エラー応答に Assertion を入れない（#278）", !response.HasAssertion,
                    "入れない", response.HasAssertion ? "**入っている**" : "入れていない");

                r.Verify("下流にサインインさせない", !broken.Authorized,
                    "サインインしない",
                    broken.Authorized ? "**サインインした**" : "しなかった");

                r.Note("**このケースが通らなくなったら、まず登録を見ること**"
                    + "（`store/docker-compose.yml` の `jwk_rsa_publickey`）。"
                    + "**鍵が無いと「通す」ので、`Success` が返って落ちる。**");

                r.Done();
            }
        }

        #endregion

        #region SA-6.6

        /// <summary>SA-6.6 上流が署名証明書を 2 本広告していても、連携できる</summary>
        /// <param name="targetKey">core / netfx</param>
        /// <returns>Task</returns>
        /// <remarks>
        /// **#291 の残件を閉じたことの確認**である（#292 の段階 3）。
        ///
        /// **以前は、メタデータの最初の 1 本しか使っていなかった。**
        /// **ロールオーバー中は 2 本以上並ぶ**ので、**最初の 1 本で署名していなければ落ちていた。**
        ///
        /// **SAML2 の署名には `kid` に当たるものが無い**
        /// （`KeyInfo` は任意で、相手が入れていなければ選べない）ので、**全部試す。**
        ///
        /// **上流コンテナは 2 本広告している**（`store/docker-compose.yml` の
        /// `PreviousSigningCerFilePaths`）。**1 本目が、いま署名に使っている鍵**である。
        /// </remarks>
        [SkippableTheory]
        [MemberData(nameof(AllTargets))]
        public async Task SA0606_上流が証明書を2本広告していても連携できる(string targetKey)
        {
            using (IdPClient client = this.Client(targetKey))
            {
                string upstream = await Saml2Federation.SkipIfNotAvailableAsync(client);

                TestReport r = this.Report("SA-6.6",
                    "上流が署名証明書を 2 本広告していても、SAML2 の ID 連携ができる",
                    "**鍵の入れ替え中の上流と連携できること**（#292 の段階 3。#291 の残件）。"
                    + "**メタデータに `KeyDescriptor` が 2 本以上並ぶ**とき、"
                    + "**どれで署名されたかは応答から分からない**"
                    + "（**SAML2 の署名に `kid` に当たるものが無い**）。"
                    + "**だから受け取る側は全部試す** — "
                    + "**最初の 1 本しか見ていなかった頃は、ここで落ちていた。**",
                    "SAML 2.0 Metadata 2.4.1.1 / #291 / #292 の段階 3");

                r.Target(client.Target.DisplayName + " ← 上流 " + upstream);

                r.Step("(1) 上流のメタデータが、2 本広告していることを見る");

                string metadataUrl = client.Config.Get("IdFederationSaml2MetadataUrl");

                Skip.If(string.IsNullOrEmpty(metadataUrl),
                    "IdFederationSaml2MetadataUrl が構成ファイルにありません（#291）。");

                string xml = await client.GetStringAsync(metadataUrl);

                XmlDocument doc = new XmlDocument();
                bool parsed = true;

                try
                {
                    doc.LoadXml(xml ?? "");
                }
                catch
                {
                    parsed = false;
                }

                Skip.IfNot(parsed, "上流のメタデータを読めません（" + metadataUrl + "）。");

                XmlNodeList certs = doc.SelectNodes(
                    "//*[local-name()='KeyDescriptor'][@use='signing']"
                    + "//*[local-name()='X509Certificate']");

                int count = (certs == null) ? 0 : certs.Count;

                Skip.If(count < 2,
                    "上流が署名証明書を 1 本しか広告していません"
                    + "（compose の PreviousSigningCerFilePaths を確認。#292 の段階 3）。");

                r.Verify("上流は 2 本以上広告している", 1 < count, "2 本以上", count + " 本");

                r.Step("(2) 上流でサインインして、連携する");

                Assert.True(await IdFederation.SignInUpstreamAsync(client, upstream),
                    "前提: 上流にサインインできること");

                Saml2FederationResult fed = await Saml2Federation.FederateAsync(client);

                Saml2Response response = Saml2.ReadResponse(fed.ResponseXml);

                r.Verify("応答が読める", response != null,
                    "読める", (response == null) ? "**読めない**" : "読める");

                Assert.NotNull(response);

                r.VerifyEqual("StatusCode が Success", Saml2.StatusSuccess, response.StatusCode);

                r.Step("(3) 署名を検証して、サインインできている");

                r.Verify("ACS がサインインさせる（リダイレクトする）", fed.Authorized,
                    "リダイレクト",
                    fed.Authorized
                        ? "した" : "**エラー画面（" + Html.Describe(fed.AcsBody) + "）**");

                bool signedIn = await Saml2Federation.IsSignedInAsync(client);

                r.Verify("下流にサインインできている", signedIn,
                    "/Manage/Index が開く", signedIn ? "開いた" : "**開かない**");

                r.Note("**鍵の順が入れ替わっても通る**ことは、歯抜けで測った"
                    + "（上流の 1 本目を「署名に使っていない証明書」にすると、"
                    + "**2 本目で検証して通る**。`TESTING.md`）。");

                r.Done();
            }
        }

        #endregion
    }
}
