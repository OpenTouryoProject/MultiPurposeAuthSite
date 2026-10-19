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
//**********************************************************************************

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
    /// **段階 1 で出来ること**（#307）。
    ///
    /// | | |
    /// |---|---|
    /// | 認可 | **`Const.ScopeClientRegistration` を持つアクセス トークン**（ROPC で取る） |
    /// | 所有者 | **トークンの `sub` の利用者。** **1 利用者 1 クライアント**（2 件目は `403` ＋ `access_denied`） |
    /// | 器 | **既存の `Saml2OAuth2Data`**（`DataProvider`）。**RFC 7591 §2 の列は #307 の段階 1 で足した** |
    ///
    /// **段階 2 で出来ること**（RFC 7592。`registration_client_uri` ＝ `…/register/{client_id}`）。
    ///
    /// | | |
    /// |---|---|
    /// | 認可 | **`registration_access_token`**（**登録の応答で 1 回だけ返す**。**その 1 件だけに効く**） |
    /// | `GET` | **登録を読む**（§2.1）。**`client_secret` は返さない** |
    /// | `PUT` | **全置換**（§2.2）。**`client_id` は一致必須**、**`client_secret` を入れるなら一致必須** |
    /// | `DELETE` | **消す**（§2.3）。**`204`**。**同意も落とす**（**`Users.ClientID` は空にしない**。一意制約） |
    ///
    /// **専用 scope のアクセス トークン（段階 1）では、管理 API を叩けない** —
    /// **作る権限と、直す権限は別物**である（§2 : クライアントは
    /// `registration_access_token` を使うこと）。
    ///
    /// **段階 3 で出来ること**（**クライアント認証の方法を、API から登録できる**）。
    ///
    /// | | |
    /// |---|---|
    /// | `token_endpoint_auth_method` | **4 つとも登録できる**（**保管して、認証で効かせる**） |
    /// | `jwks` | **`private_key_jwt` の公開鍵**（**RSA 1 本 ＋ EC 1 本まで**） |
    /// | `tls_client_auth_subject_dn` | **mTLS の Subject DN**（RFC 8705 §2.1.2） |
    /// | `token_endpoint_auth_signing_alg` | **`client_assertion` の alg を絞る**（#262 の列） |
    ///
    /// **`client_secret` は、方法に関わらず発行する**（段階 3 の決定）。
    /// **デバイス フローのように、秘密しか使えない口が在る**ためである。
    /// **登録された方法は `CmnEndpoints.AllowsAuthMethod` が効かせる** —
    /// **明示が無ければ、秘密ベースの 2 つだけ**（**強い方法は明示が要る**）。
    ///
    /// **段階 4 で出来ること**（**署名付きの主張を受ける**）。
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
    /// **＝ この段階で列は増えていない**（既存の配備に `ALTER` が要らない）。
    ///
    /// **段階 5 以降で足すもの** : `jwks_uri`（**別 Issue**。
    /// クライアント認証の経路が同期である）、`client_credentials` 経路、
    /// 1 利用者 n クライアント、**発行者ごとに許す範囲を絞ること**。
    /// </remarks>
    public static class ClientRegistrationProvider
    {
        #region 誤りのコード

        //  **RFC 7591 §3.2.2 のコード。** **Open棟梁 側の `OAuth2AndOIDCConst` には無い**ので、
        //    ここに置く（**この口でしか使わない**）。

        /// <summary>RFC 7591 §3.2.2 : redirect_uri が不正</summary>
        public const string invalid_redirect_uri = "invalid_redirect_uri";

        /// <summary>RFC 7591 §3.2.2 : メタデータが不正</summary>
        public const string invalid_client_metadata = "invalid_client_metadata";

        /// <summary>RFC 7591 §3.2.2 : software_statement が壊れている（#307 の段階 4）</summary>
        /// <remarks>
        /// **JWT として読めない・署名が合わない・`iss` が無い・`exp` が切れている**とき。
        /// **「中身は読めたが、信頼していない」のは <see cref="unapproved_software_statement"/>** である。
        /// </remarks>
        public const string invalid_software_statement = "invalid_software_statement";

        /// <summary>RFC 7591 §3.2.2 : software_statement を受け付けない</summary>
        /// <remarks>
        /// **その発行者を信頼していない**とき（§3.2.2 の
        /// "not approved for use by this authorization server"）。
        /// **信頼する発行者を 1 件も設定していない配備では、常にこれ**である（従来どおり）。
        /// </remarks>
        public const string unapproved_software_statement = "unapproved_software_statement";

        /// <summary>RFC 6750 §3.1 : トークンの scope が足りない</summary>
        public const string insufficient_scope = "insufficient_scope";

        #endregion

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
        /// | **403** | **scope が足りない**（`insufficient_scope`）／**2 件目の登録**（`access_denied`） |
        /// | **404** | **この配備では動的登録を開けていない**（本来は口が張られていない） |
        /// </remarks>
        public static int Register(
            string requestBody, ClaimsIdentity identity,
            out Dictionary<string, object> ret, out Dictionary<string, string> err)
        {
            ret = null;
            err = new Dictionary<string, string>();

            //  **開けていない配備では、口そのものが張られていない**（経路を張らない）。
            //    **ここは念のための番**である。
            if (!Config.EnableDynamicClientRegistration)
            {
                return 404;
            }

            #region 認可（トークンの scope と、所有者）

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
                err.Add(OAuth2AndOIDCConst.error, ClientRegistrationProvider.insufficient_scope);
                err.Add(OAuth2AndOIDCConst.error_description, string.Format(
                    "The access token requires the {0} scope.", Const.ScopeClientRegistration));
                return 403;
            }

            //  **所有者は、トークンの `sub` の利用者**である。
            //    **`sub` は PPID になり得る**ので、`aud`（トークンを出した相手の client_id）と
            //    組にして引く（`/userinfo` と同じ形）。
            Claim aud = identity.Claims.FirstOrDefault(
                x => x.Type == OAuth2AndOIDCConst.UrnAudienceClaim);

            ApplicationUser user = (aud == null)
                ? null : PPIDExtension.GetUserFromSub(aud.Value, identity.Name);

            if (user == null)
            {
                //  **利用者の居ないトークン**（`client_credentials` で取ったもの など）。
                //    **段階 1 は、所有者を AT から決める**ので受け付けられない。
                err.Add(OAuth2AndOIDCConst.error, OAuth2AndOIDCConst.invalid_token);
                err.Add(OAuth2AndOIDCConst.error_description,
                    "The access token is not bound to a user.");
                return 401;
            }

            //  **1 利用者 1 クライアント**（#307 の段階 1 の決定）。
            //
            //  **RFC 7591 は「1 つの主体が n 件登録できること」を求めていない** —
            //    §3.2.1 は「AS は要求されたメタデータを拒否・置換してよい」とし、
            //    §5 は「重複した登録が疑わしいときは拒否すべき」としている。
            //
            //  **誤りの形は `403` ＋ `access_denied`**（RFC 6749 §4.1.2.1 / §5.2 の既存のコード）。
            //    **§3.2.2 の 4 つはメタデータの誤り用**で、ポリシーによる断りに当てはまるものが無い。
            //    **一般の誤りは「400 unless otherwise specified」**なので、**403 は禁じられていない。**
            //
            //  **`POST` を upsert にはしない** — **`client_secret` を作り直すか据え置くかの
            //    判断が常について回り、間違えると既存の RP が止まる。**
            //    **更新は RFC 7592 の `PUT`（段階 2）で行う。**
            if (!string.IsNullOrEmpty(user.ClientID)
                && DataProvider.Get(user.ClientID) != null)
            {
                err.Add(OAuth2AndOIDCConst.error, OAuth2AndOIDCConst.access_denied);
                err.Add(OAuth2AndOIDCConst.error_description,
                    "This deployment allows one client registration per user.");
                return 403;
            }

            #endregion

            #region メタデータ（RFC 7591 §2）

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

            ManageAddSaml2OAuth2DataViewModel model = new ManageAddSaml2OAuth2DataViewModel();

            //  **`grant_types` / `response_types` は、応答では `model` の列から読む**
            //    （**`POST` / `GET` / `PUT` で同じ形にするため**。#307 の段階 2）。
            if (!ClientRegistrationProvider.Validate(metadata, model, out string code,
                out string description, out _, out _))
            {
                err.Add(OAuth2AndOIDCConst.error, code);
                err.Add(OAuth2AndOIDCConst.error_description, description);
                return 400;
            }

            #endregion

            #region 保存

            //  **`client_id` は作り直す**（画面の登録と同じ形）。
            string client_id = Guid.NewGuid().ToString("N");
            string client_secret = GetPassword.Base64UrlSecret(32);

            //  **管理 API のトークン**（RFC 7592 §2。#307 の段階 2）。
            //    **平文は、この応答で 1 回だけ返す。** **保管するのはハッシュ**である。
            string registrationAccessToken = ClientRegistrationProvider.GenerateToken();

            model.ClientID = client_id;
            model.ClientSecret = client_secret;
            model.RegistrationAccessToken =
                ClientRegistrationProvider.Hash(registrationAccessToken);

            //  **`ClientName` は、要求の `client_name` ではなく利用者名である。**
            //    **`Helper.GetClientName` / `GetClientIdByName` が、この列を
            //    「登録が在るか」の判定と逆引きに使っている**ため、他の値を入れてはならない。
            //    **`client_name` は受け取っても無視する**（RFC 7591 §3.2.1 が認めている）。
            model.ClientName = user.UserName;

            //  **古い `Users.ClientID` が残っていれば、その登録を消しておく**
            //    （**登録の行は無い**ことを上で確かめている。**宙に浮いた `client_id`** の掃除）。
            string oldClientID = user.ClientID;

            if (!string.IsNullOrEmpty(oldClientID))
            {
                DataProvider.Delete(oldClientID);
            }

            user.ClientID = client_id;
            CmnUserStore.Update(user);

            DataProvider.Create(client_id, model);

            // オペレーション・トレース・ログ出力
            //   **誰がいつ登録したかを残す。** **`client_secret` は書かない。**
            Logging.MyOperationTrace(string.Format(
                "{0}({1}) registered the client {2} by the dynamic client registration.",
                user.Id, user.UserName, client_id));

            #endregion

            #region 応答（RFC 7591 §3.2.1 / RFC 7592 §3）

            //  **登録の全体を返す**（§3.2.1）。
            //    **形は `GET` / `PUT` と同じ**にする（**RFC 7592 §3 の
            //    「クライアント情報の応答」が、3 つの口で共通**である）。
            ret = ClientRegistrationProvider.BuildClientInformation(
                client_id, model, registrationAccessToken);

            //  **秘密を返すのは、この口だけ**（`GET` / `PUT` では返さない。#307 の段階 2 の決定）。
            ret.Add("client_secret", client_secret);

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
        /// **`client_secret` は返さない**（#307 の段階 2 の決定。RFC 7592 §3 では任意）。
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
        /// | **要求から作り直す**（**段階 3**） | `TokenEndpointAuthMethod`（**省いたら、秘密ベースに戻る**） |
        /// | **要求に在れば置き換え、無ければ持ち越す**（**段階 3**） | `Jwk*` / `TlsClientAuthSubjectDn` / `TokenEndpointAuthSigningAlg` |
        /// | **持ち越す**（**要求では変えられない**） | `ClientID` / `ClientSecret` / `ClientName` / `ClientMode` / `RequirePkce` / `registration_access_token` のハッシュ ＋ **動的登録では設定できない列**（`RedirectUriSaml` / `PostLogoutRedirectUri` / `WebOrigins` / `JwksUri` / `RequestObjectSigningAlg`） |
        ///
        /// > **動的登録で設定できない列を持ち越すのは、全置換の例外ではない** —
        /// > **それらは「このクライアントが動的登録で登録したメタデータ」ではない。**
        /// > **管理画面から入れた値を、`PUT` で消してはならない。**
        ///
        /// > **鍵と DN は「省いたら消える」にしていない**（段階 3）。
        /// > **管理画面から入れた鍵を、`PUT` で消してはならない**のが理由である。
        /// > **`private_key_jwt` / `tls_client_auth` を明記するなら、材料も毎回送ること**
        /// > （**材料が無ければ `400`**。**認証できない登録を作らない**）。
        ///
        /// **気をつける所**（文書にも書いた）。
        ///
        /// | | |
        /// |---|---|
        /// | **`scope` を省くと、絞りが消える** | **列が空 ＝ 絞らない**（段階 1 の決め）。**`client_registration` だけは、明記しても断る** |
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
                err.Add(OAuth2AndOIDCConst.error, ClientRegistrationProvider.invalid_client_metadata);
                err.Add(OAuth2AndOIDCConst.error_description,
                    "The client_id must be present and match the client_id of this registration.");
                return 400;
            }

            //  **`client_secret` を入れてきたなら、現行と一致していなければならない**（§2.2 の MUST）。
            //    **自分で秘密を決めさせてはならない**（§2.2 : the client MUST NOT be allowed to
            //    set its own secret）。**この口では秘密を作り直さない**（段階 2 の決定）。
            if (ClientRegistrationProvider.Has(metadata, "client_secret"))
            {
                string requestedSecret = ClientRegistrationProvider.GetString(
                    metadata, "client_secret");

                if (!ClientRegistrationProvider.FixedTimeEquals(requestedSecret, current.ClientSecret))
                {
                    err.Add(OAuth2AndOIDCConst.error,
                        ClientRegistrationProvider.invalid_client_metadata);
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
            model.WebOrigins = current.WebOrigins;
            model.JwksUri = current.JwksUri;
            model.RequestObjectSigningAlg = current.RequestObjectSigningAlg;

            //  **鍵・DN・alg は、要求に在れば `Validate` が入れている**（#307 の段階 3）。
            //    **無ければ持ち越す** — **管理画面から入れた鍵を、`PUT` で消してはならない。**
            //    **`private_key_jwt` / `tls_client_auth` を明記したなら、
            //    材料が無い要求は `Validate` が `400` で断っている**ので、
            //    **ここで持ち越しても「方法だけ在って材料が無い」にはならない。**
            model.JwkRsaPublickey = string.IsNullOrEmpty(model.JwkRsaPublickey)
                ? current.JwkRsaPublickey : model.JwkRsaPublickey;
            model.JwkECDsaPublickey = string.IsNullOrEmpty(model.JwkECDsaPublickey)
                ? current.JwkECDsaPublickey : model.JwkECDsaPublickey;
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
        /// | **残る** | **`Users.ClientID`**（**宙に浮いた値として残る**。**一意制約があるので空にできない**。**次の登録で掃除される**） |
        /// | **使えなくなる** | **既に発行されたアクセス トークン**（**登録が無くなると `Helper.HasClient` が false になる**。#307 の段階 2）／**リフレッシュ トークン**（**クライアント認証が通らない**） |
        ///
        /// **所有者は `ClientName` から引く**（**この列には所有者の利用者名が入っている**。段階 1 の決め）。
        /// **`registration_access_token` には利用者が入っていない**ので、**この経路しかない。**
        ///
        /// **`Users.ClientID` は空にしない**（**一意制約と外部キーに当たる**。下の注）。
        /// **それでも同じ利用者が登録し直せる** —
        /// **段階 1 の `Register` が「登録の行が無ければ通す」**ため
        /// （**1 利用者 1 クライアントの縛りは解ける**）。
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

            //  **所有者を引く**（同意の取り消しと、`Users.ClientID` の後始末に要る）。
            ApplicationUser user = string.IsNullOrEmpty(model.ClientName)
                ? null : CmnUserStore.FindByName(model.ClientName);

            if (user != null && user.ClientID == client_id)
            {
                //  **同意を落とす**（§2.3 : 払い下げたクライアントへの許可を残さない）。
                ConsentProvider.Revoke(user.Id, client_id);
            }

            //  **`Users.ClientID` は空にしない。**
            //
            //  **`Users.ClientID` は NOT NULL で、一意索引が張られている**
            //    （`ClientIDIndex`）。**空にすると、2 人目で一意制約に当たる。**
            //    **`Saml2OAuth2Data.ClientID` から `Users.ClientID` への
            //    外部キー**も在るので、**行が残っているうちは空にできない。**
            //    **管理画面の `RemoveSaml2OAuth2Data` も、同じ理由で空にしていない**
            //    （「一意制約エラーになるので」というコメントが残っている）。
            //
            //  **それでも登録し直せる** — **段階 1 の `Register` は
            //    「`Users.ClientID` が在っても、その登録の行が無ければ通す」**
            //    （宙に浮いた `client_id` を許容し、作り直しのときに掃除する）。
            //
            //  **`mem` では制約が無いので通ってしまう。**
            //    **`sql` で `DELETE` が 500 になって分かった**（#307 の段階 2 の実測）。

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
        /// **`registration_access_token` を持たない登録**（**管理画面で作ったもの**や、
        /// **段階 1 で作ったもの**）**は、この口では触れない**（`401`）。
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
        /// **`software_statement` は、一番先に見る**（#307 の段階 4）。
        /// **主張を本文へ重ねてから、以降の検査にかける** —
        /// **statement が主張した値も、同じ検査を通る**
        /// （**署名が付いていても、この配備が扱えない値は通さない**）。
        /// </remarks>
        private static bool Validate(
            JObject metadata, ManageAddSaml2OAuth2DataViewModel model,
            out string code, out string description,
            out List<string> grantTypes, out List<string> responseTypes)
        {
            code = ClientRegistrationProvider.invalid_client_metadata;
            description = "";
            grantTypes = null;
            responseTypes = null;

            #region software_statement（RFC 7591 §2.3 / §3.1.1。#307 の段階 4）

            //  **署名付きの添え状を検証し、主張されたメタデータを本文へ重ねる。**
            //    **statement が勝つ**（§2.3 は MUST）。**以降の検査は、重ねた後の値で行う。**
            //
            //  **`POST` も `PUT` も、ここを通る**（**検査は 1 か所**）。
            //    **黙って無視してはならない** — **クライアントは「主張した内容で
            //    登録された」と考える。**
            SoftwareStatementProvider.Result statement =
                SoftwareStatementProvider.Apply(metadata, out description);

            if (statement == SoftwareStatementProvider.Result.Invalid)
            {
                code = ClientRegistrationProvider.invalid_software_statement;
                return false;
            }

            if (statement == SoftwareStatementProvider.Result.Unapproved)
            {
                code = ClientRegistrationProvider.unapproved_software_statement;
                return false;
            }

            //  **statement を必須にしている配備では、添えていない登録を断る**（段階 4 の決定）。
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

            #region まだ受け付けないもの

            //  **`jwks_uri`（鍵を URL から引く）は受け付けない**（**別 Issue**）。
            //
            //  **クライアント認証の経路が同期である。**
            //    `CmnEndpoints.ClientAuthentication` は `static bool` で、
            //    **`/token` / `/par` / `/ciba_authz` / `/revoke` / `/introspect` の
            //    全部から同期で呼ばれる。** **取得は非同期**（`DiscoveryJwks`）なので、
            //    **同期から待つとデッドロックの形になる**（net48 の同期コンテキスト）。
            //
            //  **登録の時点で 1 回引いて列に焼く**こともできるが、
            //    **`jwks_uri` の存在理由（鍵の入れ替え）が消える**ので、
            //    **「対応した」と言えない。**
            //
            //  **受け取って無視すると、`private_key_jwt` が黙って通らなくなる**ので、断る。
            //    **`jwks` は受け付ける**（下）。
            if (ClientRegistrationProvider.Has(metadata, "jwks_uri"))
            {
                description = "This deployment does not accept jwks_uri. Use jwks instead.";
                return false;
            }

            #endregion

            #region クライアント認証の方法と、その材料（#307 の段階 3）

            //  **方法は 1 つ**（RFC 7591 §2）。**既知でない値は拒否する**
            //    （#224 の段階 2 と同じ方針。「一番厳しいものに倒す」はしない）。
            //
            //  **空（省略）は `client_secret_basic` / `client_secret_post`**（RFC 7591 §2 の既定）。
            //    **列も空のまま**にして、**`AllowsAuthMethod` が暗黙に許す。**
            string authMethod = ClientRegistrationProvider.GetString(
                metadata, "token_endpoint_auth_method");

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
            if (ClientRegistrationProvider.Has(metadata, "jwks"))
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
                metadata, "tls_client_auth_subject_dn");

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
            //    **空なら絞らない**（登録された鍵で順に試す ＝ 従来どおり）。
            string authSigningAlg = ClientRegistrationProvider.GetString(
                metadata, "token_endpoint_auth_signing_alg");

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
            if (authMethod == OAuth2AndOIDCEnum.AuthMethods.private_key_jwt.ToStringByEmit()
                && string.IsNullOrEmpty(model.JwkRsaPublickey)
                && string.IsNullOrEmpty(model.JwkECDsaPublickey))
            {
                description = "The token_endpoint_auth_method private_key_jwt requires jwks.";
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
            grantTypes = ClientRegistrationProvider.GetStrings(metadata, "grant_types");
            responseTypes = ClientRegistrationProvider.GetStrings(metadata, "response_types");

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

            //  **デバイス フロー × `private_key_jwt` は断る**（#307 の段階 3）。
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

            #region redirect_uris

            List<string> redirectUris = ClientRegistrationProvider.GetStrings(metadata, "redirect_uris");

            if (usesCode || usesToken)
            {
                //  **折り返し先を使う経路なら、必須**（OIDC DCR 1.0 §2）。
                if (redirectUris.Count == 0)
                {
                    code = ClientRegistrationProvider.invalid_redirect_uri;
                    description = "redirect_uris is required.";
                    return false;
                }
            }

            foreach (string redirectUri in redirectUris)
            {
                if (!ClientRegistrationProvider.IsValidRedirectUri(redirectUri))
                {
                    code = ClientRegistrationProvider.invalid_redirect_uri;
                    description = string.Format(
                        "The redirect_uri ({0}) must be an absolute URI without a fragment.",
                        redirectUri);
                    return false;
                }
            }

            string uriList = string.Join(" ", redirectUris);

            if (Const.MaxLengthOfUriList < uriList.Length)
            {
                code = ClientRegistrationProvider.invalid_redirect_uri;
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

            List<string> scopes = Helper.ToDistinctList(
                ClientRegistrationProvider.GetString(metadata, "scope"));

            if (0 < scopes.Count)
            {
                List<string> supportedScopes = Helper.GetScopesSupported();

                foreach (string scope in scopes)
                {
                    //  **自分と同じ強さの scope を、自分で配らせない**（#307 の段階 1）。
                    //    **`client_registration` は「クライアント登録を作れる」権限**であり、
                    //    **動的登録で付けられるようにすると、権限を際限なく増やせる。**
                    //    **配るのは、管理画面か構成ファイルからだけ**にする。
                    if (scope == Const.ScopeClientRegistration)
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

            #region その他（保存して返すだけ）

            if (!ClientRegistrationProvider.SetUri(metadata, "client_uri",
                Const.MaxLengthOfUri, v => model.ClientUri = v, ref description)
                || !ClientRegistrationProvider.SetUri(metadata, "logo_uri",
                    Const.MaxLengthOfUri, v => model.LogoUri = v, ref description)
                || !ClientRegistrationProvider.SetUri(metadata, "tos_uri",
                    Const.MaxLengthOfUri, v => model.TosUri = v, ref description)
                || !ClientRegistrationProvider.SetUri(metadata, "policy_uri",
                    Const.MaxLengthOfUri, v => model.PolicyUri = v, ref description))
            {
                return false;
            }

            model.Contacts = string.Join(" ",
                ClientRegistrationProvider.GetStrings(metadata, "contacts"));

            model.SoftwareId = ClientRegistrationProvider.GetString(metadata, "software_id");
            model.SoftwareVersion = ClientRegistrationProvider.GetString(metadata, "software_version");

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
            string subjectType = ClientRegistrationProvider.GetString(metadata, "subject_type");

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

            //  **`id_token_signed_response_alg`**（#129 の段階 2 で列を足してある）。
            //    **扱える alg でなければ断る** — **ここで止めないと、
            //    発行の直前に既定（RS256）へ落ちて、登録の誤りが分からない。**
            string signingAlg = ClientRegistrationProvider.GetString(
                metadata, "id_token_signed_response_alg");

            if (!string.IsNullOrEmpty(signingAlg))
            {
                if (!CmnAccessToken.IsSupportedAlg(signingAlg))
                {
                    description = string.Format(
                        "The id_token_signed_response_alg ({0}) is not supported.", signingAlg);
                    return false;
                }

                model.IdTokenSignedResponseAlg = signingAlg;
            }

            #endregion

            //  **登録種別は normal**（段階 1）。**FAPI の登録は、鍵や証明書の登録を要する。**
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
        /// <remarks>**Discovery の `response_types_supported` と同じ設定を見る。**</remarks>
        private static List<string> SupportedResponseTypes()
        {
            List<string> ret = new List<string>();

            if (Config.EnableAuthorizationCodeGrantType)
            {
                ret.Add(OAuth2AndOIDCConst.AuthorizationCodeResponseType);
            }

            if (Config.EnableImplicitGrantType)
            {
                ret.Add(OAuth2AndOIDCConst.ImplicitResponseType);
            }

            if (Config.EnableOpenIDConnect)
            {
                ret.Add(OAuth2AndOIDCConst.OidcImplicit2_ResponseType);
                ret.Add(OAuth2AndOIDCConst.OidcHybrid2_Token_ResponseType);
                ret.Add(OAuth2AndOIDCConst.OidcHybrid2_IdToken_ResponseType);
                ret.Add(OAuth2AndOIDCConst.OidcHybrid3_ResponseType);
            }

            return ret;
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

            return Helper.ToDistinctList(ClientRegistrationProvider.GetString(metadata, name));
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
            return Helper.ToDistinctList(value);
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
        #region 管理 API のトークンと、応答の形（RFC 7592。#307 の段階 2）

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

        /// <summary>`jwks` を読んで、鍵の 2 列に入れる（#307 の段階 3）</summary>
        /// <param name="metadata">要求の JSON</param>
        /// <param name="model">保存する形（入出力）</param>
        /// <param name="description">誤りの説明（出力）</param>
        /// <returns>通してよいなら true</returns>
        /// <remarks>
        /// **列は「JWK 1 本を Base64URL にしたもの」が 2 本**
        /// （`JwkRsaPublickey` / `JwkECDsaPublickey`）。**JWK Set は持てない。**
        /// **`CmnEndpoints.ClientAuthentication` が、この 2 本を順に試す**（#129 の段階 2）。
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

            JToken jwks = metadata["jwks"];

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

        /// <summary>登録された鍵を `jwks` にして返す（無ければ null）（#307 の段階 3）</summary>
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
            List<string> redirectUris = Helper.ToDistinctList(model.RedirectUriCode);

            foreach (string redirectUri in Helper.ToDistinctList(model.RedirectUriToken))
            {
                if (!redirectUris.Contains(redirectUri))
                {
                    redirectUris.Add(redirectUri);
                }
            }

            ret.Add("redirect_uris", redirectUris);

            ret.Add("grant_types", Helper.ToDistinctList(model.GrantTypes));

            //  **`response_types` は、要素の中の空白を「+」にして保管している**（段階 1）。
            ret.Add("response_types", Helper.ToDistinctList(model.ResponseTypes, true));

            //  **登録された `token_endpoint_auth_method` を返す**（#307 の段階 3）。
            //    **空（明示なし）は `client_secret_basic`** — **RFC 7591 §2 の既定**であり、
            //    **実際に通る方法**でもある（`CmnEndpoints.AllowsAuthMethod`）。
            ret.Add("token_endpoint_auth_method",
                string.IsNullOrEmpty(model.TokenEndpointAuthMethod)
                    ? OAuth2AndOIDCEnum.AuthMethods.client_secret_basic.ToStringByEmit()
                    : model.TokenEndpointAuthMethod);

            //  **`client_secret` に期限は設けていない** — **0 は「期限なし」**（RFC 7591 §3.2.1）。
            ret.Add("client_secret_expires_at", 0);

            ClientRegistrationProvider.AddIfNotEmpty(ret, "scope", model.Scopes);
            ClientRegistrationProvider.AddIfNotEmpty(ret, "client_uri", model.ClientUri);
            ClientRegistrationProvider.AddIfNotEmpty(ret, "logo_uri", model.LogoUri);
            ClientRegistrationProvider.AddIfNotEmpty(ret, "tos_uri", model.TosUri);
            ClientRegistrationProvider.AddIfNotEmpty(ret, "policy_uri", model.PolicyUri);
            ClientRegistrationProvider.AddIfNotEmpty(ret, "software_id", model.SoftwareId);
            ClientRegistrationProvider.AddIfNotEmpty(ret, "software_version", model.SoftwareVersion);
            ClientRegistrationProvider.AddIfNotEmpty(ret, "subject_type", model.SubjectTypes);
            ClientRegistrationProvider.AddIfNotEmpty(
                ret, "id_token_signed_response_alg", model.IdTokenSignedResponseAlg);
            ClientRegistrationProvider.AddIfNotEmpty(
                ret, "tls_client_auth_subject_dn", model.TlsClientAuthSubjectDn);
            ClientRegistrationProvider.AddIfNotEmpty(
                ret, "token_endpoint_auth_signing_alg", model.TokenEndpointAuthSigningAlg);

            //  **登録された鍵を `jwks` に戻して返す**（#307 の段階 3）。
            //    **列は 2 本に分かれている**ので、**在るものだけを `keys` に並べる。**
            JObject jwks = ClientRegistrationProvider.BuildJwks(model);

            if (jwks != null)
            {
                ret.Add("jwks", jwks);
            }

            if (!string.IsNullOrEmpty(model.Contacts))
            {
                ret.Add("contacts", ClientRegistrationProvider.ToArray(model.Contacts));
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
