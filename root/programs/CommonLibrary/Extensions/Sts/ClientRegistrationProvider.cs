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
//* クラス名        ：ClientRegistrationProvider
//* クラス日本語名  ：動的クライアント登録（RFC 7591）
//*
//* 作成日時        ：－
//* 作成者          ：－
//* 更新履歴        ：－
//*
//*  日時        更新者            内容
//*  ----------  ----------------  -------------------------------------------------
//*  2026/10/18  玄人 幸道         新規（#307 の段階 1）
//*  2026/10/18  玄人 幸道         管理 API（RFC 7592 の GET / PUT / DELETE）を追加（#307 の段階 2）
//*  2026/10/19  玄人 幸道         jwks / DN / token_endpoint_auth_method を受ける（#307 の段階 3）
//*  2026/10/20  玄人 幸道         software_statement を検証して受ける（#307 の段階 4）
//*  2026/10/20  玄人 幸道         所有者を OwnerUserId へ移し、1 利用者 n クライアントにした（#307 の段階 5-a）
//*  2026/10/21  玄人 幸道         jwks_uri を受け付ける（#309 の段階 1）
//*  2026/10/21  玄人 幸道         software_statement が主張した jwks_uri も温める（#309 の段階 2）
//*  2026/10/21  玄人 幸道         backchannel_logout_uri は動的登録で変えさせない（#310 の段階 2）
//*  2026/10/21  玄人 幸道         frontchannel_logout_uri も動的登録で変えさせない（#310 の段階 3）
//*  2026/10/22  玄人 幸道         汎用部品を Open棟梁 の実装に置き換えた（#294）
//*  2026/10/24  玄人 幸道         受け付ける response_types を CmnEndpoints.SupportedResponseTypes に寄せた（#314）
//*  2026/10/24  玄人 幸道         文字列リテラルを Const / OAuth2AndOIDCConst の定数にした（#294）
//*  2026/10/25  玄人 幸道         文字列リテラルを定数にした（2 回目の洗い出し。#294）
//*  2026/10/25  玄人 幸道         auth も動的登録で付けさせない（#294）
//*  2026/10/25  玄人 幸道         仕様の要諦を冒頭に書き、段階ごとの経緯を DesignNotes へ移した（#294）
//*  2026/10/26  玄人 幸道         誤りのコードを Const へ移した（#294）
//**********************************************************************************

/*
 * 本Providerは、RFC 7591 の登録（POST）と、RFC 7592 の管理（GET / PUT / DELETE）を行う。
 * 登録は Saml2OAuth2Data の 1 行で、主キーは client_id（登録の度に新しく作る）。
 * 登録には client_registration scope のアクセス トークンが要り、所有者（OwnerUserId）はその sub の利用者
 * （利用者が居なければ、認証したクライアントの所有者）で、1 利用者が n 件の登録を持てる。
 * client_secret と registration_access_token は、登録の応答で 1 回だけ返す（後者はハッシュで保管）。
 * 管理は、その登録の registration_access_token でだけ行え、PUT は全置換、DELETE は同意も消す。
 * client_registration と auth の scope は、動的登録では付けられない（管理画面で付ける）。
 * 
 * | | ROPC（Resource Owner Password Credentials） | CC（Client Credentials） |
 * |---|---|---|
 * | `aud` | トークンを取った client_id | トークンを取った client_id |
 * | `sub` | 利用者の Id、または PPID | **そのClientIdのClientName** |
 * | `aud` の使い道 | **PPID を元の利用者に戻す鍵**（どのClient向けの `sub` か） | **所有者を引く相手**（このClientの所有者を、作る登録の所有者にする） |
 * 
 * 段階ごとの決定と経緯（#307 / #309 / #310 など）は、root/programs/DesignNotes/ClientRegistrationProvider.md に在る。
 */

using MultiPurposeAuthSite.Co;
using MultiPurposeAuthSite.Data;
#if NETFX
using MultiPurposeAuthSite.Entity;
#else
using MultiPurposeAuthSite;
#endif
using MultiPurposeAuthSite.Log;
using MultiPurposeAuthSite.TokenProviders;
using MultiPurposeAuthSite.Util;
using MultiPurposeAuthSite.ViewModels;

using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

using Newtonsoft.Json;
using Newtonsoft.Json.Linq;

using Touryo.Infrastructure.Framework.Authentication;
using Touryo.Infrastructure.Public.FastReflection;
using Touryo.Infrastructure.Public.Security.Jwt;
using Touryo.Infrastructure.Public.Security.Pwd;

namespace MultiPurposeAuthSite.Extensions.Sts
{
    /// <summary>
    /// 動的クライアント登録（RFC 7591 の登録、RFC 7592 の管理）
    /// </summary>
    /// <remarks>
    /// **口（WebAPI）は両アプリの `OAuth2ResourceServerController` に在るが、
    /// 判定と保存は、ここ 1 か所で行う**（net48 版と net10.0 版で振る舞いを食い違わせないため）。
    ///
    /// **登録**（RFC 7591。`POST`）。
    ///
    /// | | |
    /// |---|---|
    /// | 認可 | **`Const.ScopeClientRegistration` を持つアクセス トークン**（**ROPC か CC で取る**） |
    /// | 所有者 | **トークンの `sub` の利用者**、**利用者が居なければ認証したクライアントの所有者**（**1 利用者が n 件持てる**） |
    /// | 器 | **既存の `Saml2OAuth2Data`**（`DataProvider`） |
    ///
    /// **管理**（RFC 7592。`registration_client_uri` ＝ `…/register/{client_id}`）。
    ///
    /// | | |
    /// |---|---|
    /// | 認可 | **`registration_access_token`**（**登録の応答で 1 回だけ返す**。**その 1 件だけに効く**） |
    /// | `GET` | **登録を読む**（§2.1）。**`client_secret` は返さない** |
    /// | `PUT` | **全置換**（§2.2）。**`client_id` は一致必須**、**`client_secret` を入れるなら一致必須** |
    /// | `DELETE` | **消す**（§2.3）。**`204`**。**同意も落とす** |
    ///
    /// **専用 scope のアクセス トークンでは、管理 API を叩けない** —
    /// **作る権限と、直す権限は別物**である（§2 : クライアントは
    /// `registration_access_token` を使うこと）。
    ///
    /// **クライアント認証の方法**も、API から登録できる。
    ///
    /// | | |
    /// |---|---|
    /// | `token_endpoint_auth_method` | **4 つとも登録できる**（**保管して、認証で効かせる**） |
    /// | `jwks` | **`private_key_jwt` の公開鍵**（**RSA 1 本 ＋ EC 1 本まで**） |
    /// | `tls_client_auth_subject_dn` | **mTLS の Subject DN**（RFC 8705 §2.1.2） |
    /// | `token_endpoint_auth_signing_alg` | **`client_assertion` の alg を絞る**（#262 の列） |
    ///
    /// **`client_secret` は、方法に関わらず発行する** —
    /// **デバイス フローのように、秘密しか使えない口が在る**ためである。
    /// **登録された方法は `CmnEndpoints.AllowsAuthMethod` が効かせる** —
    /// **明示が無ければ、秘密ベースの 2 つだけ**（**強い方法は明示が要る**）。
    ///
    /// **署名付きの主張**（`software_statement`）も受ける。
    ///
    /// | | |
    /// |---|---|
    /// | `software_statement` | **信頼する発行者が署名した JWT**（RFC 7591 §2.3）。**検証して、主張を本文へ重ねる** |
    /// | 優先順位 | **statement が勝つ**（§2.3 は MUST）。**食い違っても断らず、ログに残す** |
    /// | 信頼の決め | **設定の `SoftwareStatementIssuers`**（**発行者ごとに 1 件**。**クライアントごとではない**） |
    /// | `RequireSoftwareStatement` | **true なら、statement の無い登録を断る**（**`PUT` にも効く**） |
    ///
    /// **statement は、2 つの専用トークンを置き換えない。**
    /// **あれは認可、これは内容の保証**である（`SoftwareStatementProvider` の remarks）。
    /// **statement はソフトウェアに同梱されて配布される ＝ 秘密ではない**ので、
    /// **認可の代わりにはならない。**
    ///
    /// **保管しない。** **応答にも返さない**（§3.2.1 で任意）。
    ///
    /// **`jwks_uri` も受け付ける。**
    /// **要求の経路ではキャッシュを読むだけ**にし、
    /// **取りに行くのは、この口（登録のとき）と背景だけ**である —
    /// **クライアント認証の鎖が同期**で、**そこで待つと net48 で止まる**ためである。
    /// </remarks>
    public static class ClientRegistrationProvider
    {
        #region 登録（RFC 7591 §3.1）

        /// <summary>登録する</summary>
        /// <param name="requestBody">要求の本体（JSON）</param>
        /// <param name="identity">検証済みのアクセス トークンの ClaimsIdentity</param>
        /// <param name="ret">応答（成功したときだけ）</param>
        /// <param name="err">誤り（失敗したときだけ）</param>
        /// <returns>HTTP の状態（201 / 400 / 401 / 403 / 404）</returns>
        /// <remarks>
        /// **状態の決め方**（RFC 7591 §3.2）。
        ///
        /// | 状態 | いつ |
        /// |---|---|
        /// | **201** | 登録できた（§3.2.1 : `201 Created`） |
        /// | **400** | メタデータが不正（§3.2.2） |
        /// | **401** | トークンが無効（RFC 6750 §3.1 : `invalid_token`） |
        /// | **403** | **scope が足りない**（`insufficient_scope`） |
        /// | **404** | **この配備では動的登録を開けていない**（本来は口が張られていない） |
        /// </remarks>
        public static int Register(
            string requestBody, ClaimsIdentity identity,
            out Dictionary<string, object> ret, out Dictionary<string, string> err)
        {
            // Register は ROPC と CC の 違いを意識する。
            // Clientの出所（定義ファイル、DB）の違いは意識しない。
            // 後者は「GetOwnerUserId が空を返すことがある」という 1 点ダケ。

            ret = null;
            err = new Dictionary<string, string>();

            //  **開けていない配備では、口そのものが張られていない**（経路を張らない）。
            //    **ここは念のための番**である。
            if (!Config.EnableDynamicClientRegistration)
            {
                return 404;
            }

            #region 認可

            // Tokenから、identity.Claimsを構築してある。
            if (identity == null)
            {
                err.Add(OAuth2AndOIDCConst.error, OAuth2AndOIDCConst.invalid_token);
                err.Add(OAuth2AndOIDCConst.error_description, "The access token is not valid.");
                return 401;
            }

            //  **専用の scope を持っているか**（RFC 6750 §3.1 : 足りなければ 403）。
            if (!identity.Claims.Any(x =>
                x.Type == OAuth2AndOIDCConst.UrnScopesClaim
                && x.Value == Const.ScopeClientRegistration))
            {
                err.Add(OAuth2AndOIDCConst.error, Const.InsufficientScope);
                err.Add(OAuth2AndOIDCConst.error_description, string.Format(
                    "The access token requires the {0} scope.", Const.ScopeClientRegistration));
                return 403;
            }

            // audはROPC、CC のグラント種別にかかわらずClientIDを返す。
            Claim aud = identity.Claims.FirstOrDefault(x => x.Type == OAuth2AndOIDCConst.UrnAudienceClaim);

            //  **`aud` の有無**（無いトークンは、この配備が出した物ではない・形が足りない）。
            if (aud == null)
            {
                err.Add(OAuth2AndOIDCConst.error, OAuth2AndOIDCConst.invalid_token);
                err.Add(OAuth2AndOIDCConst.error_description, "The access token is not valid.");
                return 401;
            }

            // aud.Value：トークンを取った client_id、identity.Name：トークンの sub
            // ちなみにROPCであれば、aud（ClientId）でGetUserFromSubを実行した場合、ROのuserが取れる。
            // aud は、sub が PPID の時に戻すため（pairwise は、クライアント毎に sub を変える機構がある）。
            ApplicationUser user = PPIDExtension.GetUserFromSub(aud.Value, identity.Name);

            // CCかどうかを確かめる。
            // - userの居ないトークンは、CC で取ったものである可能性が高い。
            // - aud（ClientId）でGetClientNameを実行した場合、sub（そのClientIdのClientName）が取れるハズ。
            // - ROPCでuser削除された場合と区別するために、2番目のチェックまで行う必要がある。
            //   （区別しないと、消えた利用者の要求が、クライアントの所有者の登録として増える）
            if (user == null && identity.Name == Helper.GetInstance().GetClientName(aud.Value))
            {
                // GetOwnerUserId が 空文字列（""） を返すケース
                // - 構成ファイルのクライアントで、owner 属性を書いていない：配備全体のクライアントで、1 人の持ち物ではない
                // - 構成ファイルの owner に書いた利用者が居ない：設定の誤り。利用者名を変えた後に直し忘れた場合など
                // - 登録の表のクライアントで、OwnerUserId が空：E2E の種データなど（例外ケース）
                string ownerUserId = Helper.GetInstance().GetOwnerUserId(aud.Value);

                // FindByIdが null を返すケース：OwnerUserId の利用者が、引く直前に消された場合
                user = string.IsNullOrEmpty(ownerUserId) ? null : CmnUserStore.FindById(ownerUserId);
            }
            
            if (user == null)
            {
                //  **所有者が決まらなかった。**

                //  **`403` にする。** **トークンは正しい**ので、
                //  **`401` では「取り直せ」と読めて誤誘導になる**
                //  （RFC 6749 §4.1.2.1 の `access_denied` ＝ 要求を容れない）。
                err.Add(OAuth2AndOIDCConst.error, OAuth2AndOIDCConst.access_denied);
                err.Add(OAuth2AndOIDCConst.error_description,
                    "The owner of this registration cannot be determined.");
                return 403;
            }
            else
            {
                //  **所有者が決まった。**
                // - ROPCの場合は、認証したROが所有者（user）になる。
                // - CCの場合は、認証したClient（aud）の所有者が、user （登録の表なら OwnerUserId、構成ファイルなら owner 属性）。
            }

            // ここで「既に登録を持っているか」は確かめない（1 人が何件でも登録できる）。
            // - 件数の上限は無い。大量の登録は、レート制限（#305。口の名前 `register`）で防ぐ。
            // - 同じ人が 2 回 POST すれば、別の登録が 2 件できる（前の登録を上書きしない）。
            //   主キーの client_id は POST の度に採番するので、上書きする登録を指せない。
            // - 登録を直すのは、RFC 7592 の PUT（registration_access_token で登録を指す）で行う。

            #endregion

            #region 本文

            JObject metadata = null;

            try
            {
                metadata = string.IsNullOrWhiteSpace(requestBody)
                    ? null : JsonConvert.DeserializeObject<JObject>(requestBody);
            }
            catch (JsonException)
            {
                metadata = null;
            }

            if (metadata == null)
            {
                err.Add(OAuth2AndOIDCConst.error, OAuth2AndOIDCConst.invalid_request);
                err.Add(OAuth2AndOIDCConst.error_description, "The request body must be a JSON object.");
                return 400;
            }

            ManageAddSaml2OAuth2DataViewModel model = new ManageAddSaml2OAuth2DataViewModel();

            // Validate：登録するClientに関する内容の検査
            //  **`grant_types` / `response_types` は、応答では `model` の列から読む**
            //    （**`POST` / `GET` / `PUT` で同じ形にするため**）。
            if (!ClientRegistrationProvider.Validate(metadata, model,
                out string code, out string description, out _, out _))
            {
                err.Add(OAuth2AndOIDCConst.error, code);
                err.Add(OAuth2AndOIDCConst.error_description, description);
                return 400;
            }

            # endregion

            #region 保存

            //  **`client_id` は、ここで払い出す**
            //  （RFC 7591 §3.2.1。管理画面の「ClientID」ボタンと同じ形）。
            string client_id = Guid.NewGuid().ToString("N");
            string client_secret = GetPassword.Base64UrlSecret(32);
            model.ClientID = client_id;
            model.ClientSecret = client_secret;

            // **管理 API のトークン**（RFC 7592 §2）。
            // **平文を作って渡すのは、この応答だけ**（`BuildClientInformation` が載せる）。
            //  `GET` / `PUT` の応答は、相手が送ってきたトークンを、そのまま返すだけ。
            string registrationAccessToken = ClientRegistrationProvider.GenerateToken();
            // **保管するのはハッシュ**である。
            model.RegistrationAccessToken = ClientRegistrationProvider.Hash(registrationAccessToken);

            // DCRされるClientのClientNameには、所有者（user）の利用者名を入れる（要求の client_name は使わない）。
            model.ClientName = user.UserName;

            //  **所有者を列に書く。**
            //    **`Users.Id` を指す**（**名前ではない** — 利用者名を変えても切れない）。
            //    **利用者の行には触らない。**
            model.OwnerUserId = user.Id;

            DataProvider.Create(client_id, model);

            // オペレーション・トレース・ログ出力
            //   **誰がいつ登録したかを残す。** **`client_secret` は書かない。**
            Logging.MyOperationTrace(string.Format(
                "{0}({1}) registered the client {2} by the dynamic client registration.",
                user.Id, user.UserName, client_id));

            #endregion

            #region 応答

            //  **登録の全体を返す**（§3.2.1）。
            //    **形は `GET` / `PUT` と同じ**にする（**RFC 7592 §3 の
            //    「クライアント情報の応答」が、3 つの口で共通**である）。
            ret = ClientRegistrationProvider.BuildClientInformation(
                client_id, model, registrationAccessToken);

            //  **秘密を返すのは、この口だけ**（`GET` / `PUT` では返さない）。
            ret.Add(OAuth2AndOIDCConst.client_secret, client_secret);

            //  **発行した時刻**（エポック秒）。
            //    **保管していない**ので、**`GET` / `PUT` では返さない**（§3.2.1 で任意）。
            ret.Add("client_id_issued_at", (long)DateTimeOffset.UtcNow.ToUnixTimeSeconds());

            return 201;

            #endregion
        }

        #endregion

        #region 管理 API（RFC 7592）

        /// <summary>読む（RFC 7592 §2.1）</summary>
        /// <param name="client_id">client_id（`registration_client_uri` の末尾）</param>
        /// <param name="bearerToken">提示された registration_access_token</param>
        /// <param name="ret">応答（成功したときだけ）</param>
        /// <param name="err">誤り（失敗したときだけ）</param>
        /// <returns>HTTP の状態（200 / 401 / 404）</returns>
        /// <remarks>
        /// **`client_secret` は返さない**（RFC 7592 §3 では任意）。
        /// **トークンが漏れても、秘密は漏らさない。** **所有者は管理画面で再表示できる。**
        /// </remarks>
        public static int Read(
            string client_id, string bearerToken,
            out Dictionary<string, object> ret, out Dictionary<string, string> err)
        {
            ret = null;

            int status = ClientRegistrationProvider.Authorize(
                client_id, bearerToken,
                out ManageAddSaml2OAuth2DataViewModel model, out err);

            if (status != 0)
            {
                return status;
            }

            ret = ClientRegistrationProvider.BuildClientInformation(client_id, model, bearerToken);

            return 200;
        }

        /// <summary>直す（RFC 7592 §2.2）</summary>
        /// <param name="client_id">client_id（`registration_client_uri` の末尾）</param>
        /// <param name="requestBody">要求の本体（JSON）</param>
        /// <param name="bearerToken">提示された registration_access_token</param>
        /// <param name="ret">応答（成功したときだけ）</param>
        /// <param name="err">誤り（失敗したときだけ）</param>
        /// <returns>HTTP の状態（200 / 400 / 401 / 404）</returns>
        /// <remarks>
        /// **全置換である**（§2.2 : クライアントは、返された全てのメタデータを入れること。
        /// **省いた項目は「消す要求」として扱われる**）。**差分更新（`PATCH`）は仕様に無い。**
        ///
        /// | | 列 |
        /// |---|---|
        /// | **要求から作り直す**（**省いたら消える**） | `RedirectUriCode` / `RedirectUriToken` / `Scopes` / `GrantTypes` / `ResponseTypes` / `ClientUri` / `LogoUri` / `TosUri` / `PolicyUri` / `Contacts` / `SoftwareId` / `SoftwareVersion` / `SubjectTypes` / `IdTokenSignedResponseAlg` |
        /// | **要求から作り直す** | `TokenEndpointAuthMethod`（**省いたら、秘密ベースに戻る**） |
        /// | **要求に在れば置き換え、無ければ持ち越す** | `TlsClientAuthSubjectDn` / `TokenEndpointAuthSigningAlg` |
        /// | **要求が片方を入れたら、もう片方は消える** | `Jwk*` ↔ `JwksUri`（**`jwks` と `jwks_uri` は排他**。**どちらも無い要求では、両方を持ち越す**） |
        /// | **持ち越す**（**要求では変えられない**） | `ClientID` / `ClientSecret` / `ClientName` / `ClientMode` / `RequirePkce` / `registration_access_token` のハッシュ ＋ **動的登録では設定できない列**（`RedirectUriSaml` / `PostLogoutRedirectUri` / `BackChannelLogoutUri` / `FrontChannelLogoutUri` / `WebOrigins` / `RequestObjectSigningAlg`） |
        ///
        /// > **動的登録で設定できない列を持ち越すのは、全置換の例外ではない** —
        /// > **それらは「このクライアントが動的登録で登録したメタデータ」ではない。**
        /// > **管理画面から入れた値を、`PUT` で消してはならない。**
        ///
        /// > **鍵と DN は「省いたら消える」にしていない。**
        /// > **管理画面から入れた鍵を、`PUT` で消してはならない**のが理由である。
        /// > **`private_key_jwt` / `tls_client_auth` を明記するなら、材料も毎回送ること**
        /// > （**材料が無ければ `400`**。**認証できない登録を作らない**）。
        ///
        /// **気をつける所**（文書にも書いた）。
        ///
        /// | | |
        /// |---|---|
        /// | **`scope` を省くと、絞りが消える** | **列が空 ＝ 絞らない。****`client_registration` と `auth` だけは、明記しても断る** |
        /// | **`redirect_uris` は省けない** | OIDC DCR 1.0 §2 で必須。**うっかり全消しにはならない** |
        /// | **`grant_types` / `response_types` を省くと狭まる** | **RFC 7591 §2 の既定**（`authorization_code` / `code`）が書かれる |
        /// </remarks>
        public static int Update(
            string client_id, string requestBody, string bearerToken,
            out Dictionary<string, object> ret, out Dictionary<string, string> err)
        {
            ret = null;

            int status = ClientRegistrationProvider.Authorize(
                client_id, bearerToken,
                out ManageAddSaml2OAuth2DataViewModel current, out err);

            if (status != 0)
            {
                return status;
            }

            #region メタデータ（RFC 7592 §2.2）

            JObject metadata = null;

            try
            {
                metadata = string.IsNullOrWhiteSpace(requestBody)
                    ? null : JsonConvert.DeserializeObject<JObject>(requestBody);
            }
            catch (JsonException)
            {
                metadata = null;
            }

            if (metadata == null)
            {
                err.Add(OAuth2AndOIDCConst.error, OAuth2AndOIDCConst.invalid_request);
                err.Add(OAuth2AndOIDCConst.error_description,
                    "The request body must be a JSON object.");
                return 400;
            }

            //  **`client_id` は必須で、一致していなければならない**（§2.2 の MUST）。
            //    **URL と本文が食い違う要求は、取り違えである。**
            string requestedClientId = ClientRegistrationProvider.GetString(
                metadata, OAuth2AndOIDCConst.client_id);

            if (requestedClientId != client_id)
            {
                err.Add(OAuth2AndOIDCConst.error, Const.InvalidClientMetadata);
                err.Add(OAuth2AndOIDCConst.error_description,
                    "The client_id must be present and match the client_id of this registration.");
                return 400;
            }

            //  **`client_secret` を入れてきたなら、現行と一致していなければならない**（§2.2 の MUST）。
            //    **自分で秘密を決めさせてはならない**（§2.2 : the client MUST NOT be allowed to
            //    set its own secret）。**この口では秘密を作り直さない。**
            if (ClientRegistrationProvider.Has(metadata, OAuth2AndOIDCConst.client_secret))
            {
                string requestedSecret = ClientRegistrationProvider.GetString(
                    metadata, OAuth2AndOIDCConst.client_secret);

                if (!ClientRegistrationProvider.FixedTimeEquals(requestedSecret, current.ClientSecret))
                {
                    err.Add(OAuth2AndOIDCConst.error,
                        Const.InvalidClientMetadata);
                    err.Add(OAuth2AndOIDCConst.error_description,
                        "The client_secret does not match the current client_secret.");
                    return 400;
                }
            }

            //  **読み取り専用の 4 つは無視する**（§2.2 は「入れるな」と書くが、
            //    **`GET` の出力をそのまま戻せる方が実用的**である。**ここで断ると
            //    「読んで直して返す」が成り立たない**）。
            //    `registration_access_token` / `registration_client_uri` /
            //    `client_id_issued_at` / `client_secret_expires_at`

            ManageAddSaml2OAuth2DataViewModel model = new ManageAddSaml2OAuth2DataViewModel();

            if (!ClientRegistrationProvider.Validate(metadata, model, out string code,
                out string description, out List<string> _, out List<string> __))
            {
                err.Add(OAuth2AndOIDCConst.error, code);
                err.Add(OAuth2AndOIDCConst.error_description, description);
                return 400;
            }

            #endregion

            #region 保存（持ち越す列を、現行から移す）

            model.ClientID = client_id;
            model.ClientSecret = current.ClientSecret;
            model.ClientName = current.ClientName;
            model.RequirePkce = current.RequirePkce;
            model.RegistrationAccessToken = current.RegistrationAccessToken;

            //  **登録種別は変えない** — **`Validate` は `normal` を入れる**が、
            //    **管理画面で FAPI の登録にしてあるものを、`PUT` で下げてはならない。**
            if (!string.IsNullOrEmpty(current.ClientMode))
            {
                model.ClientMode = current.ClientMode;
            }

            //  **動的登録では設定できない列**（管理画面から入れた値）。
            model.RedirectUriSaml = current.RedirectUriSaml;
            model.PostLogoutRedirectUri = current.PostLogoutRedirectUri;
            //  **ログアウトの通知先も、動的登録では設定できない**（#310）。
            //    **RFC 7591 のメタデータではない**ので、**画面と設定ファイルからだけ入れる。**
            model.BackChannelLogoutUri = current.BackChannelLogoutUri;
            model.FrontChannelLogoutUri = current.FrontChannelLogoutUri;
            model.WebOrigins = current.WebOrigins;
            model.RequestObjectSigningAlg = current.RequestObjectSigningAlg;

            //  **鍵・DN・alg は、要求に在れば `Validate` が入れている。**
            //    **無ければ持ち越す** — **管理画面から入れた鍵を、`PUT` で消してはならない。**
            //    **`private_key_jwt` / `tls_client_auth` を明記したなら、
            //    材料が無い要求は `Validate` が `400` で断っている**ので、
            //    **ここで持ち越しても「方法だけ在って材料が無い」にはならない。**
            //
            //  **`jwks` と `jwks_uri` は排他**（RFC 7591 §2）なので、
            //    **持ち越しで両方にならないようにする。**
            //    **要求が片方を入れてきたら、もう片方は持ち越さない** —
            //    **`PUT` で `jwks_uri` から列の鍵へ（その逆へも）移れる**ようにするためである。
            bool requestHasJwks = !string.IsNullOrEmpty(model.JwkRsaPublickey)
                || !string.IsNullOrEmpty(model.JwkECDsaPublickey);

            if (!string.IsNullOrEmpty(model.JwksUri))
            {
                //  **要求が `jwks_uri`** ＝ **列の鍵は持ち越さない。**
                model.JwkRsaPublickey = "";
                model.JwkECDsaPublickey = "";
            }
            else if (requestHasJwks)
            {
                //  **要求が `jwks`** ＝ **URL は持ち越さない。**
                model.JwksUri = "";
            }
            else
            {
                //  **要求がどちらも入れていない** ＝ **現行をそのまま持ち越す。**
                model.JwkRsaPublickey = current.JwkRsaPublickey;
                model.JwkECDsaPublickey = current.JwkECDsaPublickey;
                model.JwksUri = current.JwksUri;
            }

            model.TlsClientAuthSubjectDn = string.IsNullOrEmpty(model.TlsClientAuthSubjectDn)
                ? current.TlsClientAuthSubjectDn : model.TlsClientAuthSubjectDn;
            model.TokenEndpointAuthSigningAlg = string.IsNullOrEmpty(model.TokenEndpointAuthSigningAlg)
                ? current.TokenEndpointAuthSigningAlg : model.TokenEndpointAuthSigningAlg;

            DataProvider.Update(client_id, model);

            // オペレーション・トレース・ログ出力
            //   **誰がいつ直したかを残す。** **秘密もトークンも書かない。**
            Logging.MyOperationTrace(string.Format(
                "The client {0} was updated by the dynamic client registration management.",
                client_id));

            #endregion

            ret = ClientRegistrationProvider.BuildClientInformation(client_id, model, bearerToken);

            return 200;
        }

        /// <summary>消す（RFC 7592 §2.3）</summary>
        /// <param name="client_id">client_id（`registration_client_uri` の末尾）</param>
        /// <param name="bearerToken">提示された registration_access_token</param>
        /// <param name="err">誤り（失敗したときだけ）</param>
        /// <returns>HTTP の状態（204 / 401 / 404）</returns>
        /// <remarks>
        /// **成功は `204`（本体なし）**（§2.3 の MUST）。
        ///
        /// | | |
        /// |---|---|
        /// | **消える** | **登録の行**／**同意**（`ConsentProvider.Revoke`）／**`registration_access_token`**（**行が無くなるので、2 回目の要求は `401`**。§5） |
        /// | **残る** | **他の登録**（**同じ所有者の n 件のうち、消したものだけが消える**） |
        /// | **使えなくなる** | **既に発行されたアクセス トークン**（**登録が無くなると `Helper.HasClient` が false になる**）／**リフレッシュ トークン**（**クライアント認証が通らない**） |
        ///
        /// **所有者は `OwnerUserId` の列から引く** —
        /// **`registration_access_token` には利用者が入っていない**ので、**登録の行から引くしかない。**
        /// **利用者の行には触らない。**
        /// </remarks>
        public static int Delete(
            string client_id, string bearerToken, out Dictionary<string, string> err)
        {
            int status = ClientRegistrationProvider.Authorize(
                client_id, bearerToken,
                out ManageAddSaml2OAuth2DataViewModel model, out err);

            if (status != 0)
            {
                return status;
            }

            //  **同意を落とす**（§2.3 : 払い下げたクライアントへの許可を残さない）。
            //    **所有者は列から引く。**
            //    **空のことが在る**（構成ファイル発の種データ）ので、そのときは何もしない。
            if (!string.IsNullOrEmpty(model.OwnerUserId))
            {
                ConsentProvider.Revoke(model.OwnerUserId, client_id);
            }

            DataProvider.Delete(client_id);

            // オペレーション・トレース・ログ出力
            Logging.MyOperationTrace(string.Format(
                "The client {0} was deleted by the dynamic client registration management.",
                client_id));

            return 204;
        }

        /// <summary>管理 API の認可（RFC 7592 §2）</summary>
        /// <param name="client_id">client_id</param>
        /// <param name="bearerToken">提示された registration_access_token</param>
        /// <param name="model">登録（成功したときだけ）</param>
        /// <param name="err">誤り（失敗したときだけ）</param>
        /// <returns>通ってよければ 0、駄目なら HTTP の状態</returns>
        /// <remarks>
        /// **知らない `client_id` も、他人のトークンも `401`** である（§2.1 〜 §2.3 の MUST）。
        /// **`404` にしてはならない** — **「在るが触れない」と「無い」を、外から区別させない。**
        ///
        /// **`registration_access_token` を持たない登録**（**管理画面で作ったもの**など）
        /// **は、この口では触れない**（`401`）。
        /// **管理画面から直す**（所有者は、画面で自分の 1 件を編集・削除できる）。
        /// </remarks>
        private static int Authorize(
            string client_id, string bearerToken,
            out ManageAddSaml2OAuth2DataViewModel model, out Dictionary<string, string> err)
        {
            model = null;
            err = new Dictionary<string, string>();

            //  **開けていない配備では、口そのものが張られていない**（念のための番）。
            if (!Config.EnableDynamicClientRegistration)
            {
                return 404;
            }

            if (string.IsNullOrEmpty(bearerToken) || string.IsNullOrEmpty(client_id))
            {
                err.Add(OAuth2AndOIDCConst.error, OAuth2AndOIDCConst.invalid_token);
                err.Add(OAuth2AndOIDCConst.error_description,
                    "The registration access token is not valid.");
                return 401;
            }

            ManageAddSaml2OAuth2DataViewModel registration = DataProvider.Get(client_id);

            //  **登録が無い**（消された・そもそも無い）。
            //  **登録に `registration_access_token` が無い**（画面で作った登録）。
            //  **ハッシュが一致しない**（他人のトークン・偽のトークン）。
            //    **どれも同じ応答にする**（**どれだったかを教えない**）。
            if (registration == null
                || string.IsNullOrEmpty(registration.RegistrationAccessToken)
                || !ClientRegistrationProvider.FixedTimeEquals(
                    ClientRegistrationProvider.Hash(bearerToken),
                    registration.RegistrationAccessToken))
            {
                err.Add(OAuth2AndOIDCConst.error, OAuth2AndOIDCConst.invalid_token);
                err.Add(OAuth2AndOIDCConst.error_description,
                    "The registration access token is not valid.");
                return 401;
            }

            model = registration;

            return 0;
        }

        #region jwks_uri を先に取りに行く

        /// <summary>**本文の `jwks_uri` を、検査の前に 1 回取りに行く**</summary>
        /// <param name="requestBody">要求の本文（JSON）</param>
        /// <returns>Task</returns>
        /// <remarks>
        /// **判定はしない。** **取れたかどうかは `Validate` がキャッシュを見て決める**
        /// （**判定は 1 か所に置く**）。
        ///
        /// **ここだけが async である** — **登録の口（`POST` / `PUT`）は
        /// `async Task&lt;…&gt;` なので待てる。**
        /// **クライアント認証の経路（`/token` など）は同期なので、あちらでは待てない**
        /// （**待つと net48 で止まる**）。
        ///
        /// **本文の `jwks_uri` と、`software_statement` が主張した `jwks_uri` を見る。**
        ///
        /// **statement の署名は、ここでは検証しない**（**検証は `Validate` の中**）。
        /// **それでよい理由は 3 つある。**
        ///
        /// | | |
        /// |---|---|
        /// | **増える能力が無い** | **同じ呼び出し元は、本文の `jwks_uri` に任意の URL を書ける**（そちらも取りに行く）。**statement の中に書いても、行き先の範囲は変わらない** |
        /// | **キャッシュは信頼ではない** | **URL → 鍵の対応**でしかなく、**参照されるのは「その URL を登録したクライアント」だけ**である。**statement の検証が落ちれば登録は作られない**ので、**温めた分は誰にも使われない** |
        /// | **叩ける回数に限りが在る** | **専用 scope のトークンが要り**、**レート制限も掛かっている**（#305） |
        ///
        /// **`https` でなければ、取りにも行かない**（**ループバックの `http` は許す**）。
        /// </remarks>
        public static async Task WarmUpJwksUriAsync(string requestBody)
        {
            if (!Config.EnableDynamicClientRegistration
                || string.IsNullOrWhiteSpace(requestBody))
            {
                return;
            }

            List<string> urls = new List<string>();

            try
            {
                JObject metadata = JsonConvert.DeserializeObject<JObject>(requestBody);

                if (metadata == null)
                {
                    return;
                }

                urls.Add(ClientRegistrationProvider.GetString(metadata, OAuth2AndOIDCConst.jwks_uri));

                //  **statement が主張した分。**
                //    **payload を先に読む**ので、**JWT でない値でも例外にしない**
                //    （`JwtReader.TryReadPayload`。#241 と同じ扱い）。
                JObject claims = JwtReader.TryReadPayload(
                    ClientRegistrationProvider.GetString(metadata, Const.ClientSoftwareStatement));

                if (claims != null)
                {
                    urls.Add((string)claims[OAuth2AndOIDCConst.jwks_uri]);
                }
            }
            catch (JsonException)
            {
                //  **本文が JSON でない。** **`Register` / `Update` が `400` で断る。**
                return;
            }

            foreach (string url in urls)
            {
                if (!string.IsNullOrEmpty(url)
                    && RemoteJwkSetStore.IsUsableKeySource(url))
                {
                    //  **取れなくても例外にしない**（`RemoteJwkSetStore` が飲む）。
                    //    **断るのは `Validate`** である。
                    await RemoteJwkSetStore.WarmUpAsync(url);
                }
            }
        }

        #endregion

        #endregion

        #region メタデータの検査

        /// <summary>要求のメタデータを検査して、保存する形にする</summary>
        /// <param name="metadata">要求の JSON</param>
        /// <param name="model">保存する形（出力）</param>
        /// <param name="code">誤りのコード（RFC 7591 §3.2.2）</param>
        /// <param name="description">誤りの説明</param>
        /// <param name="grantTypes">登録する grant_types（応答に使う）</param>
        /// <param name="responseTypes">登録する response_types（応答に使う）</param>
        /// <returns>通してよいなら true</returns>
        /// <remarks>
        /// **知らないメタデータは無視する**（RFC 7591 §3.2.1 が認めている）。
        /// **ただし、無視すると黙って弱くなるものは断る**（`jwks` / `jwks_uri` /
        /// `token_endpoint_auth_method`）。
        ///
        /// **`software_statement` は、一番先に見る。**
        /// **主張を本文へ重ねてから、以降の検査にかける** —
        /// **statement が主張した値も、同じ検査を通る**
        /// （**署名が付いていても、この配備が扱えない値は通さない**）。
        /// </remarks>
        private static bool Validate(
            JObject metadata, ManageAddSaml2OAuth2DataViewModel model,
            out string code, out string description,
            out List<string> grantTypes, out List<string> responseTypes)
        {
            code = Const.InvalidClientMetadata;
            description = "";
            grantTypes = null;
            responseTypes = null;

            // 以下、全て登録するClientに関する内容の検査

            #region software_statement（RFC 7591 §2.3 / §3.1.1）

            //  **署名付きの添え状を検証し、主張されたメタデータを本文へ重ねる。**
            //    **statement が勝つ**（§2.3 は MUST）。**以降の検査は、重ねた後の値で行う。**
            //
            //  **`POST` も `PUT` も、ここを通る**（**検査は 1 か所**）。
            //    **黙って無視してはならない** — **クライアントは「主張した内容で登録された」と考える。**
            SoftwareStatementProvider.Result statement =
                SoftwareStatementProvider.Apply(metadata, out description);

            if (statement == SoftwareStatementProvider.Result.Invalid)
            {
                code = Const.InvalidSoftwareStatement;
                return false;
            }

            if (statement == SoftwareStatementProvider.Result.Unapproved)
            {
                code = Const.UnapprovedSoftwareStatement;
                return false;
            }

            //  **statement を必須にしている配備では、添えていない登録を断る。**
            //
            //  **`PUT` にも効く。** **効かせないと、`PUT` で statement を省いて
            //    「主張されていた値」を自分の値に書き換えられる**
            //    （**statement は保管しないので、省かれたことしか分からない**）。
            //
            //  **コードは `invalid_client_metadata`**（上で設定済み）。
            //    **提示されていないものを「approved でない」とは言えない** —
            //    **必須の項目が無い**のだから、メタデータの不備である。
            if (statement == SoftwareStatementProvider.Result.None
                && Config.RequireSoftwareStatement)
            {
                description = "This deployment requires a software_statement.";
                return false;
            }

            #endregion

            #region jwks / jwks_uri（RFC 7591 §2）

            //  **両方を入れてはならない**（RFC 7591 §2 の MUST NOT）。
            //    **どちらの鍵で認証するのかが決まらない**ので、断る。
            //    **`software_statement` を重ねた後で見る** — **statement が片方を主張したときも、同じ検査を通す。**
            if (ClientRegistrationProvider.Has(metadata, Const.ClientJwks)
                && !string.IsNullOrEmpty(
                    ClientRegistrationProvider.GetString(metadata, OAuth2AndOIDCConst.jwks_uri)))
            {
                description = "The jwks and jwks_uri must not both be present.";
                return false;
            }

            //  **`jwks_uri`（鍵を URL から引く）**。
            //    **鍵の入れ替えを、登録を直さずにできる**ようにするための項目である。
            //
            //  **要求の経路では取りに行かない**（`CmnEndpoints.ClientAuthentication` は
            //    `static bool` で、`/token` などから同期で呼ばれる）。
            //    **取りに行くのは、この口と背景である**
            //    （`WarmUpJwksUriAsync` / `RemoteJwkSetStore.RefillInBackground`）。
            if (!ClientRegistrationProvider.SetUri(metadata, OAuth2AndOIDCConst.jwks_uri,
                Const.MaxLengthOfUri, v => model.JwksUri = v, ref description))
            {
                return false;
            }

            if (!string.IsNullOrEmpty(model.JwksUri))
            {
                //  **平文の HTTP では受けない** — **鍵そのものを差し替えられる**
                //    （**署名の検証鍵なので、差し替えられればクライアント認証が破れる**）。
                //    **ループバックだけは許す**（RFC 8252 §7.3 と同じ扱い。開発と試験のため）。
                if (!RemoteJwkSetStore.IsUsableKeySource(model.JwksUri))
                {
                    description = "The jwks_uri must use https. (loopback may use http)";
                    return false;
                }

                //  **読めないものは、ここで断る** —
                //    **後から黙って `private_key_jwt` が通らなくなるより、
                //    登録のその場で分かる方が良い。**
                //
                //  **取りに行ったのは、この口の手前である**（`WarmUpJwksUriAsync`）。
                //    **`software_statement` が主張した `jwks_uri` も温めてある。**
                //    **あちらは署名を検証しないで読む**が、
                //    **行き先の範囲は本文と同じ**であり、**ここ（検証済み）が信頼を決める。**
                if (!RemoteJwkSetStore.HasKeysInCache(model.JwksUri))
                {
                    description = "The jwks_uri could not be read.";
                    return false;
                }
            }

            #endregion

            #region クライアント認証の方法と、その材料

            //  **方法は 1 つ**（RFC 7591 §2）。**既知でない値は拒否する**
            //    （#224 と同じ方針。「一番厳しいものに倒す」はしない）。
            //
            //  **空（省略）は `client_secret_basic` / `client_secret_post`**（RFC 7591 §2 の既定）。
            //    **列も空のまま**にして、**`AllowsAuthMethod` が暗黙に許す。**
            string authMethod = ClientRegistrationProvider.GetString(
                metadata, Const.ClientTokenEndpointAuthMethod);

            if (!string.IsNullOrEmpty(authMethod)
                && Array.IndexOf(CmnEndpoints.TokenEndpointAuthMethods, authMethod) < 0)
            {
                description = string.Format(
                    "The token_endpoint_auth_method ({0}) is not supported by this deployment.",
                    authMethod);
                return false;
            }

            model.TokenEndpointAuthMethod = authMethod;

            //  **`jwks`（RFC 7517 §5 の JWK Set）を、鍵の 2 列に移す。**
            //    **列は「JWK 1 本」**なので、**RSA 1 本 ＋ EC 1 本まで**である。
            if (ClientRegistrationProvider.Has(metadata, Const.ClientJwks))
            {
                if (!ClientRegistrationProvider.ParseJwks(
                    metadata, model, out description))
                {
                    return false;
                }
            }

            //  **mTLS の Subject DN**（RFC 8705 §2.1.2）。
            //    **照合は `x509.Subject` との完全一致**である（`CmnEndpoints.ClientAuthentication`）。
            string subjectDn = ClientRegistrationProvider.GetString(
                metadata, Const.ClientTlsClientAuthSubjectDn);

            if (!string.IsNullOrEmpty(subjectDn))
            {
                //  **列の幅と同じ**（`TlsClientAuthSubjectDn` は 512）。
                if (Const.MaxLengthOfUri < subjectDn.Length)
                {
                    description = "The tls_client_auth_subject_dn is too long.";
                    return false;
                }

                model.TlsClientAuthSubjectDn = subjectDn;
            }

            //  **`client_assertion` の alg を絞る**（#262 の列。OIDC Registration 1.0 §2）。
            //    **空なら絞らない**（登録された鍵で順に試す）。
            string authSigningAlg = ClientRegistrationProvider.GetString(
                metadata, Const.ClientTokenEndpointAuthSigningAlg);

            if (!string.IsNullOrEmpty(authSigningAlg))
            {
                if (Array.IndexOf(
                    CmnEndpoints.TokenEndpointAuthSigningAlgs, authSigningAlg) < 0)
                {
                    description = string.Format(
                        "The token_endpoint_auth_signing_alg ({0}) is not supported "
                        + "by this deployment.", authSigningAlg);
                    return false;
                }

                model.TokenEndpointAuthSigningAlg = authSigningAlg;
            }

            //  **方法に必要な材料が無ければ、登録を断る**（**認証できない登録を作らない**）。
            //    **黙って作ると、クライアントは「登録した方法で認証できる」と考えるが、
            //    永久に通らない。** **`PUT` でも同じ**（材料は毎回送ること）。
            //
            //  **`jwks_uri` も材料である。**
            //    **鍵は URL の先に在る** — **ここを数えないと、
            //    `jwks_uri` だけを送った登録が断られる。**
            if (authMethod == OAuth2AndOIDCEnum.AuthMethods.private_key_jwt.ToStringByEmit()
                && string.IsNullOrEmpty(model.JwkRsaPublickey)
                && string.IsNullOrEmpty(model.JwkECDsaPublickey)
                && string.IsNullOrEmpty(model.JwksUri))
            {
                description = "The token_endpoint_auth_method private_key_jwt requires "
                    + "jwks or jwks_uri.";
                return false;
            }

            if (authMethod == OAuth2AndOIDCEnum.AuthMethods.tls_client_auth.ToStringByEmit()
                && string.IsNullOrEmpty(model.TlsClientAuthSubjectDn))
            {
                description = "The token_endpoint_auth_method tls_client_auth requires "
                    + "tls_client_auth_subject_dn.";
                return false;
            }

            #endregion

            #region grant_types / response_types

            //  **RFC 7591 §2 の既定** : `grant_types` は `authorization_code`、
            //    `response_types` は `code`。
            //
            //  **既定を書き込むのは、ここ（動的登録）だけである。**
            //    **既存の登録（列が空）に当てはめてはならない** —
            //    **当てはめると「`authorization_code` 以外が通らなくなる」破壊になる。**
            grantTypes = ClientRegistrationProvider.GetStrings(metadata, Const.ClientGrantTypes);
            responseTypes = ClientRegistrationProvider.GetStrings(metadata, Const.ClientResponseTypes);

            if (grantTypes.Count == 0)
            {
                grantTypes = new List<string>() { OAuth2AndOIDCConst.AuthorizationCodeGrantType };
            }

            if (responseTypes.Count == 0)
            {
                responseTypes = new List<string>() { OAuth2AndOIDCConst.AuthorizationCodeResponseType };
            }

            //  **この配備が扱うグラントか**（Discovery の `grant_types_supported` と同じ判定）。
            List<string> supportedGrantTypes = ClientRegistrationProvider.SupportedGrantTypes();

            foreach (string grantType in grantTypes)
            {
                if (!supportedGrantTypes.Contains(grantType))
                {
                    description = string.Format(
                        "The grant_type ({0}) is not supported by this deployment.", grantType);
                    return false;
                }
            }

            //  **この配備が扱う response_type か。**
            List<string> supportedResponseTypes = ClientRegistrationProvider.SupportedResponseTypes();

            foreach (string responseType in responseTypes)
            {
                if (!supportedResponseTypes.Any(
                    x => ClientRegistrationProvider.IsSameTypeSet(x, responseType)))
                {
                    description = string.Format(
                        "The response_type ({0}) is not supported by this deployment.", responseType);
                    return false;
                }
            }

            //  **`grant_types` と `response_types` の対応**（RFC 7591 §2 の表）。
            //    **`code` を使うなら `authorization_code`、`token` / `id_token` を使うなら
            //    `implicit` が要る。** **片方だけ登録すると、使えない組み合わせになる。**
            bool usesCode = responseTypes.Any(x => ClientRegistrationProvider
                .Elements(x).Contains(OAuth2AndOIDCConst.AuthorizationCodeResponseType));

            bool usesToken = responseTypes.Any(x => ClientRegistrationProvider.Elements(x).Any(
                e => e == OAuth2AndOIDCConst.ImplicitResponseType
                || e == OAuth2AndOIDCConst.IDToken));

            if (usesCode && !grantTypes.Contains(OAuth2AndOIDCConst.AuthorizationCodeGrantType))
            {
                description = "The response_type code requires the authorization_code grant_type.";
                return false;
            }

            if (usesToken && !grantTypes.Contains(OAuth2AndOIDCConst.ImplicitGrantType))
            {
                description = "The response_type token / id_token requires the implicit grant_type.";
                return false;
            }

            //  **列に入れる形**（空白区切り。**要素の中の空白は `+` にする**）。
            model.GrantTypes = string.Join(" ", grantTypes);
            model.ResponseTypes = string.Join(" ", responseTypes.Select(
                x => string.Join("+", ClientRegistrationProvider.Elements(x))));

            if (Const.MaxLengthOfTypeList < model.GrantTypes.Length
                || Const.MaxLengthOfTypeList < model.ResponseTypes.Length)
            {
                description = "The grant_types / response_types are too long.";
                return false;
            }

            //  **デバイス フロー × `private_key_jwt` は断る。**
            //    **RFC 8628 の口（`/device_authz` と `/token`）は `client_assertion` を
            //    読んでいない**（両アプリの呼び出しに引数が無い）ので、
            //    **その組み合わせでは、永久に認証できない。**
            //    **`tls_client_auth` は通る**（証明書は口に渡っている）。
            if (model.TokenEndpointAuthMethod
                    == OAuth2AndOIDCEnum.AuthMethods.private_key_jwt.ToStringByEmit()
                && grantTypes.Contains(OAuth2AndOIDCConst.DeviceAuthZGrantType))
            {
                description = "The device_code grant_type cannot be used with "
                    + "the token_endpoint_auth_method private_key_jwt in this deployment.";
                return false;
            }

            #endregion

            #region redirect_uris / scope

            #region redirect_uris

            List<string> redirectUris = ClientRegistrationProvider.GetStrings(metadata, OAuth2AndOIDCConst.redirect_uris);

            if (usesCode || usesToken)
            {
                //  **折り返し先を使う経路なら、必須**（OIDC DCR 1.0 §2）。
                if (redirectUris.Count == 0)
                {
                    code = Const.InvalidRedirectUri;
                    description = "redirect_uris is required.";
                    return false;
                }
            }

            foreach (string redirectUri in redirectUris)
            {
                if (!ClientRegistrationProvider.IsValidRedirectUri(redirectUri))
                {
                    code = Const.InvalidRedirectUri;
                    description = string.Format(
                        "The redirect_uri ({0}) must be an absolute URI without a fragment.",
                        redirectUri);
                    return false;
                }
            }

            string uriList = string.Join(" ", redirectUris);

            if (Const.MaxLengthOfUriList < uriList.Length)
            {
                code = Const.InvalidRedirectUri;
                description = "The redirect_uris are too long.";
                return false;
            }

            //  **列は `response_type` で分かれている**ので、使う経路の列に入れる
            //    （`Helper.GetClientsRedirectUriList` が、`code` は `RedirectUriCode`、
            //    それ以外は `RedirectUriToken` を引く）。
            //    **両方を使う登録（Hybrid）では、同じ値を両方に入れる。**
            if (usesCode)
            {
                model.RedirectUriCode = uriList;
            }

            if (usesToken)
            {
                model.RedirectUriToken = uriList;
            }

            #endregion

            #region scope

            List<string> scopes = OAuth2AndOIDCSpec.ToDistinctList(
                ClientRegistrationProvider.GetString(metadata, OAuth2AndOIDCConst.scope));

            if (0 < scopes.Count)
            {
                List<string> supportedScopes = Helper.GetScopesSupported();

                foreach (string scope in scopes)
                {
                    //  **自分と同じ強さの scope を、自分で配らせない。**
                    //  **`client_registration` は「クライアント登録を作れる」権限**であり、
                    //    **動的登録で付けられるようにすると、権限を際限なく増やせる。**
                    //    **配るのは、管理画面か構成ファイルからだけ**にする。
                    //  **`auth`（同意画面を出さない）も同じ**（#294）。
                    //    **自分で登録できると、同意画面を飛ばすかをクライアントが決めることになる。**
                    if (scope == Const.ScopeClientRegistration
                        || scope == OAuth2AndOIDCConst.Scope_Auth)
                    {
                        description = string.Format(
                            "The scope ({0}) cannot be granted by the dynamic client registration.",
                            scope);
                        return false;
                    }

                    if (!supportedScopes.Contains(scope))
                    {
                        description = string.Format(
                            "The scope ({0}) is not supported by this deployment.", scope);
                        return false;
                    }
                }

                model.Scopes = string.Join(" ", scopes);

                if (Const.MaxLengthOfScopeList < model.Scopes.Length)
                {
                    description = "The scope is too long.";
                    return false;
                }
            }

            #endregion

            #endregion

            #region その他（保存して返すだけ）

            if (!ClientRegistrationProvider.SetUri(metadata, Const.ClientUri,
                Const.MaxLengthOfUri, v => model.ClientUri = v, ref description)
                || !ClientRegistrationProvider.SetUri(metadata, Const.ClientLogoUri,
                    Const.MaxLengthOfUri, v => model.LogoUri = v, ref description)
                || !ClientRegistrationProvider.SetUri(metadata, Const.ClientTosUri,
                    Const.MaxLengthOfUri, v => model.TosUri = v, ref description)
                || !ClientRegistrationProvider.SetUri(metadata, Const.ClientPolicyUri,
                    Const.MaxLengthOfUri, v => model.PolicyUri = v, ref description))
            {
                return false;
            }

            model.Contacts = string.Join(" ",
                ClientRegistrationProvider.GetStrings(metadata, Const.ClientContacts));

            model.SoftwareId = ClientRegistrationProvider.GetString(metadata, Const.ClientSoftwareId);
            model.SoftwareVersion = ClientRegistrationProvider.GetString(metadata, Const.ClientSoftwareVersion);

            if (Const.MaxLengthOfContacts < (model.Contacts ?? "").Length
                || Const.MaxLengthOfSoftwareId < (model.SoftwareId ?? "").Length
                || Const.MaxLengthOfSoftwareVersion < (model.SoftwareVersion ?? "").Length)
            {
                description = "The contacts / software_id / software_version are too long.";
                return false;
            }

            #endregion

            #region OIDC の登録項目（既に列が在るもの）

            //  **`subject_type`**（OIDC DCR 1.0 §2）。**扱う値は public / pairwise**（OIDC Core §8）。
            string subjectType = ClientRegistrationProvider.GetString(metadata, Const.ClientSubjectType);

            if (!string.IsNullOrEmpty(subjectType))
            {
                if (subjectType != OAuth2AndOIDCEnum.SubjectTypes.@public.ToStringByEmit()
                    && subjectType != OAuth2AndOIDCEnum.SubjectTypes.pairwise.ToStringByEmit())
                {
                    description = string.Format(
                        "The subject_type ({0}) is not supported.", subjectType);
                    return false;
                }

                model.SubjectTypes = subjectType;
            }

            //  **`id_token_signed_response_alg`**（列は #129 で足してある）。
            //    **扱える alg でなければ断る** — **ここで止めないと、
            //    発行の直前に既定（RS256）へ落ちて、登録の誤りが分からない。**
            string signingAlg = ClientRegistrationProvider.GetString(
                metadata, Const.ClientIdTokenSignedResponseAlg);

            if (!string.IsNullOrEmpty(signingAlg))
            {
                if (!JwsFactory.IsSupported(signingAlg))
                {
                    description = string.Format(
                        "The id_token_signed_response_alg ({0}) is not supported.", signingAlg);
                    return false;
                }

                model.IdTokenSignedResponseAlg = signingAlg;
            }

            #endregion

            //  **登録種別は normal。****FAPI の登録は、鍵や証明書の登録を要する。**
            model.ClientMode = OAuth2AndOIDCEnum.ClientMode.normal.ToStringByEmit();

            code = "";
            return true;
        }

        #endregion

        #region この配備が扱うもの

        /// <summary>この配備が扱うグラント</summary>
        /// <returns>grant_type の一覧</returns>
        /// <remarks>
        /// **Discovery の `grant_types_supported` と同じ設定を見る**
        /// （**広告しているものだけ登録できる**）。
        /// </remarks>
        private static List<string> SupportedGrantTypes()
        {
            List<string> ret = new List<string>();

            if (Config.EnableAuthorizationCodeGrantType)
            {
                ret.Add(OAuth2AndOIDCConst.AuthorizationCodeGrantType);
            }

            if (Config.EnableImplicitGrantType)
            {
                ret.Add(OAuth2AndOIDCConst.ImplicitGrantType);
            }

            if (Config.EnableResourceOwnerPasswordCredentialsGrantType)
            {
                ret.Add(OAuth2AndOIDCConst.ResourceOwnerPasswordCredentialsGrantType);
            }

            if (Config.EnableClientCredentialsGrantType)
            {
                ret.Add(OAuth2AndOIDCConst.ClientCredentialsGrantType);
            }

            if (Config.EnableRefreshToken)
            {
                ret.Add(OAuth2AndOIDCConst.RefreshTokenGrantType);
            }

            if (Config.EnableJwtBearerTokenFlowGrantType)
            {
                ret.Add(OAuth2AndOIDCConst.JwtBearerTokenFlowGrantType);
            }

            if (Config.EnableCibaGrantType)
            {
                ret.Add(OAuth2AndOIDCConst.CibaGrantType);
            }

            if (Config.EnableDeviceAuthZGrantType)
            {
                ret.Add(OAuth2AndOIDCConst.DeviceAuthZGrantType);
            }

            return ret;
        }

        /// <summary>この配備が扱う response_type</summary>
        /// <returns>response_type の一覧</returns>
        /// <remarks>
        /// **Discovery の `response_types_supported` と同じ一覧**
        /// （`CmnEndpoints.SupportedResponseTypes`。#314）。
        /// </remarks>
        private static List<string> SupportedResponseTypes()
        {
            return CmnEndpoints.SupportedResponseTypes();
        }

        #endregion

        #region 補助

        /// <summary>そのメタデータが在るか（null でない値として）</summary>
        /// <param name="metadata">要求の JSON</param>
        /// <param name="name">名前</param>
        /// <returns>在れば true</returns>
        private static bool Has(JObject metadata, string name)
        {
            JToken token = metadata[name];

            return token != null && token.Type != JTokenType.Null;
        }

        /// <summary>文字列のメタデータを読む</summary>
        /// <param name="metadata">要求の JSON</param>
        /// <param name="name">名前</param>
        /// <returns>値（無ければ空）</returns>
        private static string GetString(JObject metadata, string name)
        {
            return ClientRegistrationProvider.Has(metadata, name)
                ? (metadata[name].Type == JTokenType.String
                    ? (string)metadata[name] : metadata[name].ToString())
                : "";
        }

        /// <summary>配列のメタデータを読む</summary>
        /// <param name="metadata">要求の JSON</param>
        /// <param name="name">名前</param>
        /// <returns>値の一覧（無ければ 0 件）</returns>
        /// <remarks>
        /// **配列でも、空白区切りの文字列でも受ける。**
        /// **仕様は配列**（RFC 7591 §2）だが、**この実装は列挙を空白区切りで持つ**ので、
        /// **どちらで来ても同じに扱える方が、取り違えが起きない。**
        /// **空の要素と重複は捨てる。**
        /// </remarks>
        private static List<string> GetStrings(JObject metadata, string name)
        {
            List<string> ret = new List<string>();

            if (!ClientRegistrationProvider.Has(metadata, name))
            {
                return ret;
            }

            JToken token = metadata[name];

            if (token.Type == JTokenType.Array)
            {
                foreach (JToken item in (JArray)token)
                {
                    string value = ((string)item ?? "").Trim();

                    if (!string.IsNullOrEmpty(value) && !ret.Contains(value))
                    {
                        ret.Add(value);
                    }
                }

                return ret;
            }

            return OAuth2AndOIDCSpec.ToDistinctList(ClientRegistrationProvider.GetString(metadata, name));
        }

        /// <summary>URI のメタデータを読んで入れる</summary>
        /// <param name="metadata">要求の JSON</param>
        /// <param name="name">名前</param>
        /// <param name="maxLength">上限</param>
        /// <param name="set">入れ先</param>
        /// <param name="description">誤りの説明</param>
        /// <returns>通してよいなら true</returns>
        /// <remarks>**絶対 URI でなければ断る**（表示用でも、相対の値は意味を持たない）。</remarks>
        private static bool SetUri(JObject metadata, string name, int maxLength,
            Action<string> set, ref string description)
        {
            string value = ClientRegistrationProvider.GetString(metadata, name);

            if (string.IsNullOrEmpty(value))
            {
                return true;
            }

            if (maxLength < value.Length)
            {
                description = string.Format("The {0} is too long.", name);
                return false;
            }

            if (!Uri.IsWellFormedUriString(value, UriKind.Absolute))
            {
                description = string.Format("The {0} must be an absolute URI.", name);
                return false;
            }

            set(value);
            return true;
        }

        /// <summary>折り返し先として使える値か</summary>
        /// <param name="redirectUri">redirect_uri</param>
        /// <returns>使えるなら true</returns>
        /// <remarks>
        /// **絶対 URI で、フラグメントを持たないこと**（RFC 6749 §3.1.2）。
        /// **ワイルドカードは受けない**（#263 / #306 と同じ方針。照合は完全一致）。
        /// **長さは 1 本ぶんの上限まで**（`Const.MaxLengthOfUri`）。
        /// </remarks>
        private static bool IsValidRedirectUri(string redirectUri)
        {
            if (string.IsNullOrEmpty(redirectUri)
                || Const.MaxLengthOfUri < redirectUri.Length
                || redirectUri.Contains("*"))
            {
                return false;
            }

            if (!Uri.TryCreate(redirectUri, UriKind.Absolute, out Uri uri))
            {
                return false;
            }

            //  **フラグメントは禁止**（RFC 6749 §3.1.2）。
            return string.IsNullOrEmpty(uri.Fragment);
        }

        /// <summary>response_type の要素に分ける</summary>
        /// <param name="responseType">response_type（空白か「+」で区切られている）</param>
        /// <returns>要素の並び</returns>
        /// <remarks>
        /// **列には `+` で繋いで入れる**（空白は区切りと区別が付かない）。
        /// **要求の JSON では空白で来る**（`code id_token`）。**どちらでも読めるようにする。**
        /// </remarks>
        private static string[] Elements(string responseType)
        {
            return (responseType ?? "").ToLower().Split(
                new char[] { ' ', '+' }, StringSplitOptions.RemoveEmptyEntries);
        }

        /// <summary>2 つの response_type が、同じ組み合わせか</summary>
        /// <param name="a">response_type</param>
        /// <param name="b">response_type</param>
        /// <returns>同じなら true</returns>
        /// <remarks>
        /// **要素の集合として比べる**
        /// （OAuth 2.0 Multiple Response Types §4 : 順序は意味を持たない）。
        /// </remarks>
        private static bool IsSameTypeSet(string a, string b)
        {
            string[] x = ClientRegistrationProvider.Elements(a);
            string[] y = ClientRegistrationProvider.Elements(b);

            return x.Length == y.Length && x.All(t => y.Contains(t));
        }

        /// <summary>空白区切りの列挙を、応答の配列にする</summary>
        /// <param name="value">空白区切りの列挙</param>
        /// <returns>配列</returns>
        private static List<string> ToArray(string value)
        {
            return OAuth2AndOIDCSpec.ToDistinctList(value);
        }

        /// <summary>空でなければ、応答に足す</summary>
        /// <param name="ret">応答</param>
        /// <param name="name">名前</param>
        /// <param name="value">値</param>
        private static void AddIfNotEmpty(
            Dictionary<string, object> ret, string name, string value)
        {
            if (!string.IsNullOrEmpty(value))
            {
                ret.Add(name, value);
            }
        }

        #endregion

        #region 管理 API のトークンと、応答の形（RFC 7592）

        /// <summary>registration_access_token を作る</summary>
        /// <returns>トークン（**平文。登録の応答で 1 回だけ返す**）</returns>
        /// <remarks>
        /// **`client_secret` と同じ作り方**（**256 bit の乱数**）。
        /// **JWT にしていない** — **期限が必ず付き、切れたら管理できなくなる。**
        /// **RFC 7592 は、クライアントの一生もののトークンを前提にしている**（§2 / A.1）。
        /// </remarks>
        private static string GenerateToken()
        {
            return GetPassword.Base64UrlSecret(32);
        }

        /// <summary>保管する形にする（ハッシュ）</summary>
        /// <param name="token">トークン（平文）</param>
        /// <returns>ハッシュ（base64）</returns>
        /// <remarks>
        /// **暗号化（`SecretProtector`）ではなくハッシュである** —
        /// **照合しかしない**（**再表示する口が無い**）ので、**元に戻せる必要が無い。**
        /// **トークンは 256 bit の乱数**なので、**鍵の導出（PBKDF2）は要らない。**
        /// </remarks>
        private static string Hash(string token)
        {
            if (string.IsNullOrEmpty(token))
            {
                return "";
            }

            using (SHA256 sha256 = SHA256.Create())
            {
                return Convert.ToBase64String(
                    sha256.ComputeHash(Encoding.UTF8.GetBytes(token)));
            }
        }

        /// <summary>突き合わせる（長さが違えば false。時間で漏らさない）</summary>
        /// <param name="a">値</param>
        /// <param name="b">値</param>
        /// <returns>同じなら true</returns>
        /// <remarks>
        /// **先頭から 1 文字ずつ比べて、違った所で止めてはならない** —
        /// **掛かった時間から、どこまで合っていたかが分かる。**
        /// **最後まで数えてから返す。**
        /// </remarks>
        private static bool FixedTimeEquals(string a, string b)
        {
            if (a == null || b == null || a.Length != b.Length)
            {
                return false;
            }

            int diff = 0;

            for (int i = 0; i < a.Length; i++)
            {
                diff |= a[i] ^ b[i];
            }

            return diff == 0;
        }

        /// <summary>`jwks` を読んで、鍵の 2 列に入れる</summary>
        /// <param name="metadata">要求の JSON</param>
        /// <param name="model">保存する形（入出力）</param>
        /// <param name="description">誤りの説明（出力）</param>
        /// <returns>通してよいなら true</returns>
        /// <remarks>
        /// **列は「JWK 1 本を Base64URL にしたもの」が 2 本**
        /// （`JwkRsaPublickey` / `JwkECDsaPublickey`）。**JWK Set は持てない。**
        /// **`CmnEndpoints.ClientAuthentication` が、この 2 本を順に試す。**
        ///
        /// **断る形**（**どれも「黙って落とすと、後で認証に失敗する」もの**）。
        ///
        /// | | |
        /// |---|---|
        /// | `keys` が無い・空・配列でない | RFC 7517 §5 |
        /// | **同じ `kty` が 2 本以上** | **列が 1 本しか持てない。** 先頭を採ると、**もう一方の鍵で署名したときに失敗する** |
        /// | **`RSA` / `EC` 以外の `kty`** | **この実装が検証できない**（`JwtAssertion.Verify` が `kty` で RSA / EC を選ぶ） |
        /// | **`use` が `sig` でない** | **クライアント認証に使う鍵である**（暗号用を黙って受けない。RFC 7517 §4.2） |
        /// </remarks>
        private static bool ParseJwks(JObject metadata,
            ManageAddSaml2OAuth2DataViewModel model, out string description)
        {
            description = "";

            JToken jwks = metadata[Const.ClientJwks];

            if (jwks.Type != JTokenType.Object)
            {
                description = "The jwks must be a JSON object (RFC 7517 Section 5).";
                return false;
            }

            JToken keys = jwks[JwtConst.keys];

            if (keys == null || keys.Type != JTokenType.Array || !keys.Any())
            {
                description = "The jwks must have a non-empty keys array "
                    + "(RFC 7517 Section 5).";
                return false;
            }

            foreach (JToken key in keys)
            {
                if (key.Type != JTokenType.Object)
                {
                    description = "Each key in the jwks must be a JSON object.";
                    return false;
                }

                JObject jwk = (JObject)key;

                //  **署名の検証に使う鍵だけを受ける**（RFC 7517 §4.2。`use` は任意）。
                string use = (string)jwk["use"];

                if (!string.IsNullOrEmpty(use) && use != "sig")
                {
                    description = "This deployment uses the jwks for client authentication, "
                        + "so each key must have use=sig (or no use).";
                    return false;
                }

                string kty = (string)jwk[JwtConst.kty];
                string encoded = CmnEndpoints.EncodeRegisteredJwk(jwk);

                if (kty == JwtConst.RSA)
                {
                    if (!string.IsNullOrEmpty(model.JwkRsaPublickey))
                    {
                        description = "This deployment stores one RSA key per client, "
                            + "so the jwks must not have two RSA keys.";
                        return false;
                    }

                    model.JwkRsaPublickey = encoded;
                }
                else if (kty == JwtConst.EC)
                {
                    if (!string.IsNullOrEmpty(model.JwkECDsaPublickey))
                    {
                        description = "This deployment stores one EC key per client, "
                            + "so the jwks must not have two EC keys.";
                        return false;
                    }

                    model.JwkECDsaPublickey = encoded;
                }
                else
                {
                    description = string.Format(
                        "The key type ({0}) is not supported by this deployment. "
                        + "Use RSA or EC.", kty);
                    return false;
                }
            }

            return true;
        }

        /// <summary>登録された鍵を `jwks` にして返す（無ければ null）</summary>
        /// <param name="model">登録</param>
        /// <returns>JWK Set（鍵が 1 本も無ければ null）</returns>
        /// <remarks>
        /// **`ParseJwks` の逆である。** **列に在る鍵だけを `keys` に並べる。**
        /// **壊れた登録値は、黙って飛ばす**（**応答を 500 にしない**。
        /// **登録の時点で形は確かめている**ので、ここに来るのは運用で壊した値である）。
        /// </remarks>
        private static JObject BuildJwks(ManageAddSaml2OAuth2DataViewModel model)
        {
            JArray keys = new JArray();

            foreach (string registered in new string[]
                { model.JwkRsaPublickey, model.JwkECDsaPublickey })
            {
                string json = CmnEndpoints.DecodeRegisteredJwk(registered);

                if (string.IsNullOrEmpty(json))
                {
                    continue;
                }

                try
                {
                    keys.Add(JsonConvert.DeserializeObject<JObject>(json));
                }
                catch (JsonException)
                {
                    // 登録の値が壊れている（運用の誤り）。
                }
            }

            if (!keys.Any())
            {
                return null;
            }

            JObject jwks = new JObject();
            jwks.Add(JwtConst.keys, keys);

            return jwks;
        }

        /// <summary>この登録の `registration_client_uri`（RFC 7592 §3）</summary>
        /// <param name="client_id">client_id</param>
        /// <returns>絶対 URI</returns>
        /// <remarks>
        /// **絶対 URI で返す**（RFC 7592 Appendix B :
        /// **サーバが URL を渡すこと。クライアントに組み立てさせない**）。
        /// </remarks>
        private static string RegistrationClientUri(string client_id)
        {
            return Config.OAuth2AuthorizationServerEndpointsRootURI
                + Config.DcrRegistrationEndpoint + "/" + client_id;
        }

        /// <summary>クライアント情報の応答を作る（RFC 7592 §3）</summary>
        /// <param name="client_id">client_id</param>
        /// <param name="model">登録</param>
        /// <param name="registrationAccessToken">registration_access_token（平文）</param>
        /// <returns>応答</returns>
        /// <remarks>
        /// **3 つの口（`POST` / `GET` / `PUT`）で同じ形**である（RFC 7592 §3）。
        ///
        /// | | |
        /// |---|---|
        /// | **必ず入れる** | `client_id` / `redirect_uris` / `grant_types` / `response_types` / `token_endpoint_auth_method` / **`registration_access_token`** / **`registration_client_uri`**（**後の 2 つは §3 で REQUIRED**） |
        /// | **入れない** | **`client_secret`**（**`POST` だけが、呼ぶ側で足す**）／**`client_name`**（**保存しているのは利用者名**で、要求された値でもない。**返すと利用者名を漏らす**）／**`client_id_issued_at`**（**保管していない**。§3.2.1 で任意） |
        ///
        /// **`registration_access_token` は、提示されたものをそのまま返す** —
        /// **こちらはハッシュしか持たない**ので、**これで §3 の REQUIRED を満たす。**
        /// **回さない**（§5 / A.1 の MAY。**回すと、取り違えた RP が管理できなくなる**）。
        /// </remarks>
        private static Dictionary<string, object> BuildClientInformation(
            string client_id, ManageAddSaml2OAuth2DataViewModel model,
            string registrationAccessToken)
        {
            Dictionary<string, object> ret = new Dictionary<string, object>();

            ret.Add(OAuth2AndOIDCConst.client_id, client_id);

            //  **列は `response_type` で分かれている**ので、**両方を合わせて返す**
            //    （**同じ値が入っている**ことが多い。Hybrid の登録では両方に入れている）。
            List<string> redirectUris = OAuth2AndOIDCSpec.ToDistinctList(model.RedirectUriCode);

            foreach (string redirectUri in OAuth2AndOIDCSpec.ToDistinctList(model.RedirectUriToken))
            {
                if (!redirectUris.Contains(redirectUri))
                {
                    redirectUris.Add(redirectUri);
                }
            }

            ret.Add(OAuth2AndOIDCConst.redirect_uris, redirectUris);

            ret.Add(Const.ClientGrantTypes, OAuth2AndOIDCSpec.ToDistinctList(model.GrantTypes));

            //  **`response_types` は、要素の中の空白を「+」にして保管している。**
            ret.Add(Const.ClientResponseTypes, Helper.ToDistinctList(model.ResponseTypes, true));

            //  **登録された `token_endpoint_auth_method` を返す。**
            //    **空（明示なし）は `client_secret_basic`** — **RFC 7591 §2 の既定**であり、
            //    **実際に通る方法**でもある（`CmnEndpoints.AllowsAuthMethod`）。
            ret.Add(Const.ClientTokenEndpointAuthMethod,
                string.IsNullOrEmpty(model.TokenEndpointAuthMethod)
                    ? OAuth2AndOIDCEnum.AuthMethods.client_secret_basic.ToStringByEmit()
                    : model.TokenEndpointAuthMethod);

            //  **`client_secret` に期限は設けていない** — **0 は「期限なし」**（RFC 7591 §3.2.1）。
            ret.Add("client_secret_expires_at", 0);

            ClientRegistrationProvider.AddIfNotEmpty(ret, OAuth2AndOIDCConst.scope, model.Scopes);
            ClientRegistrationProvider.AddIfNotEmpty(ret, Const.ClientUri, model.ClientUri);
            ClientRegistrationProvider.AddIfNotEmpty(ret, Const.ClientLogoUri, model.LogoUri);
            ClientRegistrationProvider.AddIfNotEmpty(ret, Const.ClientTosUri, model.TosUri);
            ClientRegistrationProvider.AddIfNotEmpty(ret, Const.ClientPolicyUri, model.PolicyUri);
            ClientRegistrationProvider.AddIfNotEmpty(ret, Const.ClientSoftwareId, model.SoftwareId);
            ClientRegistrationProvider.AddIfNotEmpty(ret, Const.ClientSoftwareVersion, model.SoftwareVersion);
            ClientRegistrationProvider.AddIfNotEmpty(ret, Const.ClientSubjectType, model.SubjectTypes);
            ClientRegistrationProvider.AddIfNotEmpty(
                ret, Const.ClientIdTokenSignedResponseAlg, model.IdTokenSignedResponseAlg);
            ClientRegistrationProvider.AddIfNotEmpty(
                ret, Const.ClientTlsClientAuthSubjectDn, model.TlsClientAuthSubjectDn);
            ClientRegistrationProvider.AddIfNotEmpty(
                ret, Const.ClientTokenEndpointAuthSigningAlg, model.TokenEndpointAuthSigningAlg);

            //  **登録された鍵を `jwks` に戻して返す。**
            //    **列は 2 本に分かれている**ので、**在るものだけを `keys` に並べる。**
            JObject jwks = ClientRegistrationProvider.BuildJwks(model);

            if (jwks != null)
            {
                ret.Add(Const.ClientJwks, jwks);
            }

            //  **`jwks_uri` は、そのまま返す**（**`jwks` とは排他**）。
            ClientRegistrationProvider.AddIfNotEmpty(ret, OAuth2AndOIDCConst.jwks_uri, model.JwksUri);

            if (!string.IsNullOrEmpty(model.Contacts))
            {
                ret.Add(Const.ClientContacts, ClientRegistrationProvider.ToArray(model.Contacts));
            }

            //  **RFC 7592 §3 : どちらも REQUIRED**（**管理の口と、その鍵**）。
            ret.Add("registration_access_token", registrationAccessToken);
            ret.Add("registration_client_uri",
                ClientRegistrationProvider.RegistrationClientUri(client_id));

            return ret;
        }

        #endregion

    }
}
