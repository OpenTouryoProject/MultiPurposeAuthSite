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

using Newtonsoft.Json;
using Newtonsoft.Json.Linq;

using Touryo.Infrastructure.Framework.Authentication;
using Touryo.Infrastructure.Public.FastReflection;
using Touryo.Infrastructure.Public.Security.Pwd;

namespace MultiPurposeAuthSite.Extensions.Sts
{
    /// <summary>
    /// 動的クライアント登録（RFC 7591 の登録要求）
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
    /// **段階 2 で足すもの** : RFC 7592（`GET` / `PUT` / `DELETE`）と
    /// `registration_access_token` / `registration_client_uri`。
    ///
    /// **段階 3 で足すもの** : `software_statement`、`jwks` / `jwks_uri`、
    /// `client_credentials` 経路、1 利用者 n クライアント。
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

        /// <summary>RFC 7591 §3.2.2 : software_statement を受け付けない</summary>
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

            if (!ClientRegistrationProvider.Validate(metadata, model, out string code,
                out string description, out List<string> grantTypes, out List<string> responseTypes))
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

            model.ClientID = client_id;
            model.ClientSecret = client_secret;

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

            #region 応答（RFC 7591 §3.2.1）

            ret = new Dictionary<string, object>();

            ret.Add(OAuth2AndOIDCConst.client_id, client_id);
            ret.Add("client_secret", client_secret);

            //  **発行した時刻**（エポック秒）。
            ret.Add("client_id_issued_at", (long)DateTimeOffset.UtcNow.ToUnixTimeSeconds());

            //  **`client_secret` に期限は設けていない** — **0 は「期限なし」**（RFC 7591 §3.2.1）。
            ret.Add("client_secret_expires_at", 0);

            //  **登録された内容を返す**（§3.2.1 : 登録の全体を返すこと）。
            //    **`client_name` は返さない** — **保存しているのは利用者名**であり、
            //    **要求された値でもない**（返すと、利用者名を漏らすことにもなる）。
            ret.Add("redirect_uris", ClientRegistrationProvider.ToArray(
                string.IsNullOrEmpty(model.RedirectUriCode)
                    ? model.RedirectUriToken : model.RedirectUriCode));

            ret.Add("grant_types", grantTypes);
            ret.Add("response_types", responseTypes);

            //  **`token_endpoint_auth_method` は、段階 1 では秘密ベースの 2 つだけ。**
            ret.Add("token_endpoint_auth_method",
                OAuth2AndOIDCEnum.AuthMethods.client_secret_basic.ToStringByEmit());

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

            if (!string.IsNullOrEmpty(model.Contacts))
            {
                ret.Add("contacts", ClientRegistrationProvider.ToArray(model.Contacts));
            }

            return 201;

            #endregion
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
        /// `software_statement` / `token_endpoint_auth_method`）。
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

            #region 段階 1 では受け付けないもの

            //  **`software_statement`（署名付きの主張）は段階 3。**
            //    **黙って無視してはならない** — **クライアントは「主張した内容で登録された」と考える。**
            if (ClientRegistrationProvider.Has(metadata, "software_statement"))
            {
                code = ClientRegistrationProvider.unapproved_software_statement;
                description = "This deployment does not accept a software_statement yet.";
                return false;
            }

            //  **`jwks` / `jwks_uri` は段階 3。**
            //    **鍵を引く実装が無い**（クライアントの鍵は `JwkRsaPublickey` /
            //    `JwkECDsaPublickey` の列から読んでいる）。
            //    **受け取って無視すると、`private_key_jwt`（#239）や
            //    Request Object（JAR）の検証が黙って通らなくなる。**
            if (ClientRegistrationProvider.Has(metadata, "jwks")
                || ClientRegistrationProvider.Has(metadata, "jwks_uri"))
            {
                description = "This deployment does not accept jwks / jwks_uri yet.";
                return false;
            }

            //  **クライアント認証の方法は、秘密ベースの 2 つだけ**（段階 1）。
            //    **`private_key_jwt` / `tls_client_auth` は、鍵か DN の登録を要する**ので、
            //    **受け取って無視すると、登録したつもりの方法で認証できない。**
            string authMethod = ClientRegistrationProvider.GetString(
                metadata, "token_endpoint_auth_method");

            if (!string.IsNullOrEmpty(authMethod)
                && authMethod != OAuth2AndOIDCEnum.AuthMethods.client_secret_basic.ToStringByEmit()
                && authMethod != OAuth2AndOIDCEnum.AuthMethods.client_secret_post.ToStringByEmit())
            {
                description = "This deployment accepts only "
                    + "client_secret_basic / client_secret_post as token_endpoint_auth_method.";
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
    }
}
