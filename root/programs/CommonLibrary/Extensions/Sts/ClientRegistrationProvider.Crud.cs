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
//* クラス日本語名  ：動的クライアント登録（RFC 7591）の 前処理・登録・管理 API
//*
//* 作成日時        ：－
//* 作成者          ：－
//* 更新履歴        ：－
//*
//*  日時        更新者            内容
//*  ----------  ----------------  -------------------------------------------------
//*  2026/10/26  玄人 幸道         新規（ClientRegistrationProvider.cs から partial に分割。#294）
//**********************************************************************************

using MultiPurposeAuthSite.Co;
using MultiPurposeAuthSite.Data;
#if NETFX
using MultiPurposeAuthSite.Entity;
#else
using MultiPurposeAuthSite;
#endif
using MultiPurposeAuthSite.Log;
using MultiPurposeAuthSite.Util;
using MultiPurposeAuthSite.ViewModels;
using MultiPurposeAuthSite.Util.Sts;

using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;
using System.Threading.Tasks;

using Newtonsoft.Json;
using Newtonsoft.Json.Linq;

using Touryo.Infrastructure.Framework.Authentication;
using Touryo.Infrastructure.Public.Security.Jwt;
using Touryo.Infrastructure.Public.Security.Pwd;

namespace MultiPurposeAuthSite.Extensions.Sts
{
    /// <summary>ClientRegistrationProvider（前処理・登録・管理 API）</summary>
    public static partial class ClientRegistrationProvider
    {
        #region 前処理（jwks_uri を先に取りに行く。#309）

        /// <summary>**本文と `software_statement` の `jwks_uri` を、検査の前に 1 回取りに行く**</summary>
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
                out string code, out string description))
            {
                err.Add(OAuth2AndOIDCConst.error, code);
                err.Add(OAuth2AndOIDCConst.error_description, description);
                return 400;
            }

            #endregion

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

            // UserのClientデータを新規作成
            Saml2OAuth2DataProvider.Create(client_id, model);

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
            ret.Add(Const.ClientIdIssuedAt, (long)DateTimeOffset.UtcNow.ToUnixTimeSeconds());

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

            // **`registration_access_token` の検証**（RFC 7592 §2.1）。
            int status = ClientRegistrationProvider.Authorize(
                client_id, bearerToken,
                out ManageAddSaml2OAuth2DataViewModel model, out err);

            if (status != 0)
            {
                return status;
            }

            // 応答：登録の全体を返す
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
        /// **現行の行を土台にし、動的登録が持つ列だけを、要求の値で置き換える。**
        /// **それ以外の列は、書かなくても持ち越される**（**表に列を足しても、ここを直さなくてよい**）。
        /// 表の順は、`#region 保存` の処理の順である。
        ///
        /// | 順 | 列 | 扱い |
        /// |---|---|---|
        /// | 1 | `RedirectUriCode` / `RedirectUriToken` / `Scopes` / `GrantTypes` / `ResponseTypes` / `ClientUri` / `LogoUri` / `TosUri` / `PolicyUri` / `Contacts` / `SoftwareId` / `SoftwareVersion` / `SubjectTypes` / `IdTokenSignedResponseAlg` / `TokenEndpointAuthMethod` | **要求から作り直す**（**省いたら消える**。`TokenEndpointAuthMethod` は、**省いたら秘密ベースに戻る**） |
        /// | 2 | `Jwk*` ↔ `JwksUri` | **要求が片方を入れたら、もう片方は消える**（**`jwks` と `jwks_uri` は排他**。**どちらも無い要求では、両方を持ち越す**） |
        /// | 3 | `TlsClientAuthSubjectDn` / `TokenEndpointAuthSigningAlg` | **要求に在れば置き換え、無ければ持ち越す** |
        /// | 4 | `ClientMode` | **持ち越す**（**空のときだけ `normal`**。管理画面で FAPI の登録にしたものを、`PUT` で下げない） |
        /// | — | **上の外の全て** : `ClientID` / `ClientSecret` / `ClientName` / `RequirePkce` / `OwnerUserId` / `registration_access_token` のハッシュ ＋ **動的登録では設定できない列**（`RedirectUriSaml` / `PostLogoutRedirectUri` / `BackChannelLogoutUri` / `FrontChannelLogoutUri` / `WebOrigins` / `RequestObjectSigningAlg`） | **持ち越す**（**要求では変えられない**。**土台が現行なので、コードには出てこない**） |
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

            // **`registration_access_token` の検証**（RFC 7592 §2.2）。
            int status = ClientRegistrationProvider.Authorize(
                client_id, bearerToken,
                out ManageAddSaml2OAuth2DataViewModel current, out err);

            if (status != 0)
            {
                return status;
            }

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
                    err.Add(OAuth2AndOIDCConst.error, Const.InvalidClientMetadata);
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

            //  **要求の値**（検査を通ったものだけ）。**保存するのは、これではない**（下の `model`）。
            ManageAddSaml2OAuth2DataViewModel requested = new ManageAddSaml2OAuth2DataViewModel();

            if (!ClientRegistrationProvider.Validate(metadata, requested,
                out string code, out string description))
            {
                err.Add(OAuth2AndOIDCConst.error, code);
                err.Add(OAuth2AndOIDCConst.error_description, description);
                return 400;
            }

            #endregion

            #region 保存

            //  **現行の行を土台にする**（`Authorize` が読んだ `current` は複製なので、書き換えてよい）。
            //    **動的登録が持つ列だけを、要求の値で置き換える** —
            //    **それ以外の列（所有者・秘密・画面から入れた列など）は、書かなくても持ち越される。**
            //    **表に列を足しても、ここを直さなくてよい**
            //    （**要求の値を土台にしていた頃は、持ち越しを足し忘れた列を `PUT` が消していた**）。
            ManageAddSaml2OAuth2DataViewModel model = current;

            //  1. **要求から作り直す**（**省いたら消える**。§2.2 の全置換）。
            model.RedirectUriCode = requested.RedirectUriCode;
            model.RedirectUriToken = requested.RedirectUriToken;
            model.Scopes = requested.Scopes;
            model.GrantTypes = requested.GrantTypes;
            model.ResponseTypes = requested.ResponseTypes;
            model.ClientUri = requested.ClientUri;
            model.LogoUri = requested.LogoUri;
            model.TosUri = requested.TosUri;
            model.PolicyUri = requested.PolicyUri;
            model.Contacts = requested.Contacts;
            model.SoftwareId = requested.SoftwareId;
            model.SoftwareVersion = requested.SoftwareVersion;
            model.SubjectTypes = requested.SubjectTypes;
            model.IdTokenSignedResponseAlg = requested.IdTokenSignedResponseAlg;

            //    **省いたら、秘密ベース（`client_secret_basic` / `client_secret_post`）に戻る。**
            model.TokenEndpointAuthMethod = requested.TokenEndpointAuthMethod;

            //  2. **`jwks` と `jwks_uri` は排他**（RFC 7591 §2）なので、
            //    **持ち越しで両方にならないようにする。**
            //    **要求が片方を入れてきたら、もう片方は消す** —
            //    **`PUT` で `jwks_uri` から列の鍵へ（その逆へも）移れる**ようにするためである。
            //    **要求がどちらも入れていなければ、現行のまま**（**管理画面から入れた鍵を、`PUT` で消してはならない**）。
            //
            //    **`private_key_jwt` / `tls_client_auth` を明記したなら、
            //    材料が無い要求は `Validate` が `400` で断っている**ので、
            //    **持ち越しても「方法だけ在って材料が無い」にはならない。**
            if (!string.IsNullOrEmpty(requested.JwksUri))
            {
                model.JwksUri = requested.JwksUri;
                model.JwkRsaPublickey = "";
                model.JwkECDsaPublickey = "";
            }
            else if (!string.IsNullOrEmpty(requested.JwkRsaPublickey)
                || !string.IsNullOrEmpty(requested.JwkECDsaPublickey))
            {
                model.JwkRsaPublickey = requested.JwkRsaPublickey;
                model.JwkECDsaPublickey = requested.JwkECDsaPublickey;
                model.JwksUri = "";
            }

            //  3. **DN と alg は、要求に在れば置き換え、無ければ持ち越す**（鍵と同じ理由）。
            if (!string.IsNullOrEmpty(requested.TlsClientAuthSubjectDn))
            {
                model.TlsClientAuthSubjectDn = requested.TlsClientAuthSubjectDn;
            }

            if (!string.IsNullOrEmpty(requested.TokenEndpointAuthSigningAlg))
            {
                model.TokenEndpointAuthSigningAlg = requested.TokenEndpointAuthSigningAlg;
            }

            //  4. **登録種別は変えない** — **`Validate` は `normal` を入れる**が、
            //    **管理画面で FAPI の登録にしてあるものを、`PUT` で下げてはならない。**
            //    **空のときだけ、要求の値（`normal`）にする。**
            if (string.IsNullOrEmpty(model.ClientMode))
            {
                model.ClientMode = requested.ClientMode;
            }

            // UserのClientデータを更新
            Saml2OAuth2DataProvider.Update(client_id, model);

            // オペレーション・トレース・ログ出力
            //   **誰がいつ直したかを残す。** **秘密もトークンも書かない。**
            Logging.MyOperationTrace(string.Format(
                "The client {0} was updated by the dynamic client registration management.",
                client_id));

            #endregion

            // 応答：登録の全体を返す
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
        /// | **消える** | **登録の行**／**同意**（**全利用者の分**。`ConsentProvider.RevokeByClient`）／**`registration_access_token`**（**行が無くなるので、2 回目の要求は `401`**。§5） |
        /// | **残る** | **他の登録**（**同じ所有者の n 件のうち、消したものだけが消える**） |
        /// | **使えなくなる** | **既に発行されたアクセス トークン**（**登録が無くなると `Helper.HasClient` が false になる**）／**リフレッシュ トークン**（**クライアント認証が通らない**） |
        ///
        /// **所有者は引かない** — **同意は `client_id` で、全利用者の分を消す**ためである。
        /// **利用者の行には触らない。**
        /// </remarks>
        public static int Delete(
            string client_id, string bearerToken, out Dictionary<string, string> err)
        {
            // **`registration_access_token` の検証**（RFC 7592 §2.3）。
            //    **登録の中身は使わない**（消すだけ）。
            int status = ClientRegistrationProvider.Authorize(
                client_id, bearerToken, out _, out err);

            if (status != 0)
            {
                return status;
            }

            // UserのClientデータを削除
            Saml2OAuth2DataProvider.Delete(client_id);

            //  **同意を落とす**（§2.3 : 払い下げたクライアントへの許可を残さない）。
            //    **所有者だけでなく、このクライアントに同意した全利用者の分を消す**
            //    （**同意の表の `ClientID` には外部キーが無い**ので、行を消しても残る）。
            //    **登録の行を先に消す**（管理画面の削除と同じ順）—
            //    **行が無くなれば、間に新しい同意は作られない。**
            ConsentProvider.RevokeByClient(client_id);

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

            ManageAddSaml2OAuth2DataViewModel registration = Saml2OAuth2DataProvider.Get(client_id);

            //  **登録が無い**（消された・そもそも無い）。
            //  **登録に `registration_access_token` が無い**（画面で作った登録）。
            //  **ハッシュが一致しない**（他人のトークン・偽のトークン）。
            //    **どれも同じ応答にする**（**どれだったかを教えない**）。
            if (registration == null
                || string.IsNullOrEmpty(registration.RegistrationAccessToken)
                || !ClientRegistrationProvider.FixedTimeEquals( // FixedTimeはタイミング攻撃防止の意
                    ClientRegistrationProvider.Hash(bearerToken), registration.RegistrationAccessToken))
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
    }
}
