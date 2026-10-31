//**********************************************************************************
//* Copyright (C) 2017 Hitachi Solutions,Ltd.
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
//* クラス名        ：Const
//* クラス日本語名  ：ASP.NET IdentityのConstクラス（ライブラリ）
//*
//* 作成日時        ：－
//* 作成者          ：－
//* 更新履歴        ：－
//*
//*  日時        更新者            内容
//*  ----------  ----------------  -------------------------------------------------
//*  2017/04/24  西野 大介         新規
//*  2020/07/24  西野 大介         OIDCではredirect_uriは必須。
//*  2020/07/24  西野 大介         ID連携（Hybrid-IdP）実装の見直し
//*  2026/09/27  玄人 幸道         ログアウト後の戻り先のテスト用の定数を追加（#232）
//*  2026/09/28  玄人 幸道         再認証の印（max_age）の Cookie キーを追加（#247）
//*  2026/09/30  玄人 幸道         ID 連携の要求スコープを標準だけにした（#140 の段階 3）
//*  2026/10/01  玄人 幸道         利用者名とメアドの規則を追加（#151 の段階 3）
//*  2026/10/04  玄人 幸道         test_self_code_manage を追加（C-10）
//*  2026/10/04  玄人 幸道         CORS のポリシー名を追加（#265）
//*  2026/10/06  玄人 幸道         セッション キャッシュの表名を追加（#256）
//*  2026/10/07  玄人 幸道         WebAuthn の RP の表示名を追加（#137）
//*  2026/10/07  玄人 幸道         SAML2 の AuthnRequest の ID を保存するキーを追加（#276）
//*  2026/10/07  玄人 幸道         データ保護のアプリケーション名を追加（#279）
//*  2026/10/09  玄人 幸道         test_self_saml を定数にした（#277 の段階 3）
//*  2026/10/09  玄人 幸道         test_self_code_manage を削除（管理画面のトークン取得の廃止に伴う）
//*  2026/10/18  玄人 幸道         動的クライアント登録の scope と、登録項目の上限を追加（#307 の段階 1）
//*  2026/10/18  玄人 幸道         URI の列挙の上限を追加（#306）
//*  2026/10/21  玄人 幸道         セッションの識別子と sid クレームを追加（#310 の段階 1）
//*  2026/10/21  玄人 幸道         cnf.jkt のクレーム型を追加（#311 の段階 2）
//*  2026/10/24  玄人 幸道         StandardScopes から userid を外した（独自 scope の userid を廃止。#294）
//*  2026/10/24  玄人 幸道         OidcScopes / SelfTestScopes / IdFederationScopes を const にした（宣言の順で初期化が欠けないように。#294）
//*  2026/10/30  玄人 幸道         EndpointSetDeviceToken を追加（#294）
//**********************************************************************************

using MultiPurposeAuthSite.Util.Sts;
using MultiPurposeAuthSite.Util.Test;

using Touryo.Infrastructure.Framework.Authentication;

/// <summary>MultiPurposeAuthSite.Co</summary>
namespace MultiPurposeAuthSite.Co
{
    /// <summary>Const</summary>
    public class Const
    {
        #region 土台

        #region DB列の幅

        #region ユーザー情報

        /// <summary>UserNameのMaxLength</summary>
        public const int MaxLengthOfUserName = 64;

        /// <summary>PasswordのMaxLength</summary>
        public const int MaxLengthOfPassword = 100;

        /// <summary>RoleNameのMaxLength</summary>
        public const int MaxLengthOfRoleName = 64;

        /// <summary>UriのMaxLength</summary>
        public const int MaxLengthOfUri = 512;

        #endregion

        #region OAuth2/OIDC

        /// <summary>ClientNameのMaxLength</summary>
        public const int MaxLengthOfClientName = 64;

        /// <summary>token_endpoint_auth_method の MaxLength</summary>
        /// <remarks>
        /// RFC 7591 §2 の `token_endpoint_auth_method`（値は 1 つ）。
        /// いちばん長い既知の値が `client_secret_basic`（19 文字）なので、32 で足りる。
        /// 既知でない値は拒否する（`CmnEndpoints.AllowsAuthMethod`）ので長い値を保管する必要が無い。
        /// </remarks>
        public const int MaxLengthOfAuthMethod = 32;

        /// <summary>software_id の MaxLength</summary>
        /// <remarks>RFC 7591 §2 の `software_id`（UUID を想定しているが、縛られていない）。</remarks>
        public const int MaxLengthOfSoftwareId = 256;

        /// <summary>software_version の MaxLength</summary>
        /// <remarks>RFC 7591 §2 の `software_version`（形は仕様が定めていない）。</remarks>
        public const int MaxLengthOfSoftwareVersion = 64;

        /// <summary>registration_access_token のハッシュの MaxLength</summary>
        /// <remarks>
        /// 保管するのはハッシュ（平文は、登録の応答で 1 回だけ返す）。
        /// SHA-256 を base64 にすると 44 文字、別のハッシュに替えても入るように 128 とした。
        /// </remarks>
        public const int MaxLengthOfTokenHash = 128;

        #region リスト

        /// <summary>grant_types / response_types の列挙の MaxLength</summary>
        /// <remarks>
        /// `grant_types` / `response_types`（空白区切りの列挙）の上限。
        /// 既知の値しか入らないので、全部並べても 256 に収まる。
        /// </remarks>
        public const int MaxLengthOfTypeList = 256;

        /// <summary>scope の列挙の MaxLength</summary>
        public const int MaxLengthOfScopeList = 2000;

        /// <summary>Uriの列挙のMaxLength</summary>
        /// <remarks>
        /// 空白区切りで複数の URI を持つ項目の上限。
        /// （`redirect_uri_code` / `redirect_uri_token` / `web_origins`）
        /// 2000 は、Oracle の `NVARCHAR2` の上限で 3 方言とも同じ幅に揃えられる。
        /// WebOrigins の列は LOB のまま（ALTER は既存の配備に重いので、そのまま）。
        /// </remarks>
        public const int MaxLengthOfUriList = 2000;

        /// <summary>contacts（連絡先）の列挙の MaxLength（#307 の段階 1）</summary>
        /// <remarks>RFC 7591 §2 の `contacts`（空白区切りのメール アドレスの列挙）。</remarks>
        public const int MaxLengthOfContacts = 2000;

        #endregion

        #endregion

        #endregion

        #region ログ

        /// <summary>ログに出す説明・例外のメッセージの長さの上限</summary>
        /// <remarks>
        /// **`LogSanitizer.Sanitize` の既定（64）では、`error_description` や例外のメッセージが切れて読めない。**
        /// **要求から来る値なので、上限は置く**（長い値でログを埋められないように）。
        /// </remarks>
        public const int LogDetailMaxLength = 256;

        #endregion

        #region HTTP ヘッダ

        // **ヘッダの名前と、決まった値。** net48 / net10.0 の両方で使える形にするため、文字列で持つ。

        /// <summary>WWW-Authenticate（RFC 9110 §11.6.1）</summary>
        public const string HeaderWwwAuthenticate = "WWW-Authenticate";

        /// <summary>Authorization（RFC 9110 §11.6.2）</summary>
        public const string HeaderAuthorization = "Authorization";

        /// <summary>Retry-After（RFC 9110 §10.2.3。レート制限の 429）</summary>
        public const string HeaderRetryAfter = "Retry-After";

        #region キャッシュ

        /// <summary>Cache-Control（RFC 9111 §5.2）</summary>
        public const string HeaderCacheControl = "Cache-Control";

        /// <summary>Pragma（RFC 9111 §5.4）</summary>
        public const string HeaderPragma = "Pragma";

        /// <summary>Cache-Control の no-store（トークンの応答。RFC 6749 §5.1）</summary>
        public const string CacheControlNoStore = "no-store";

        /// <summary>Pragma の no-cache（同上）</summary>
        public const string PragmaNoCache = "no-cache";

        #endregion

        #endregion

        #endregion

        #region 配備

        #region CORS のポリシー名

        /// <summary>公開情報の口のポリシー名</summary>
        /// <remarks>
        /// PublicDocs はどのオリジンにも許す
        /// `.well-known/openid-configuration` / `jwkcerts` / `samlmetadata`。
        /// </remarks>
        public const string CorsPolicyPublicDocs = "MpasPublicDocs";

        /// <summary>ブラウザから叩く口のポリシー名</summary>
        /// <remarks>
        /// BrowserApi は許したオリジンだけ（CmnEndpoints.GetCorsAllowedOrigins）
        /// `/token` / `/userinfo` / `/SetDeviceToken` / `/ciba_result` / `/2fa_result`。
        /// `/revoke` / `/introspect` には付けない（SPA からのrevokeは想定していない）。
        /// </remarks>
        public const string CorsPolicyBrowserApi = "MpasBrowserApi";

        #endregion

        #region セッションの置き場

        // Startup.cs で、AddDistributedSqlServerCache に 渡している。
        // DDL と一致すると機能するが、一致しないと黙って壊れるので注意

        /// <summary>SessionCacheのスキーマ名（SqlServer）</summary>
        /// <remarks>
        /// `Create_SessionCache.sql` と同じ値にすること。
        /// </remarks>
        public const string SessionCacheSchemaName = "dbo";

        /// <summary>SessionCacheのテーブル名（SqlServer）</summary>
        /// <remarks>`Create_SessionCache.sql` と同じ値にすること。</remarks>
        public const string SessionCacheTableName = "SessionCache";

        #endregion

        #region データ保護のアプリ名

        /// <summary>データ保護のアプリ名</summary>
        /// <remarks>
        /// 鍵リングの置き場は設定キー `DataProtectionKeyPath` を使用して設定する。
        /// （未指定なら `%LOCALAPPDATA%\ASP.NET\DataProtection-Keys`、Linux / macOS は `~/.aspnet/DataProtection-Keys`）。
        /// 設定キー `DataProtectionKeyPath` で、置き場を共有しても、アプリ名が揃わないと復号できない。
        /// 既定のアプリ名はパスから決まるり、設定キーにすると揃っていない配備ができる。
        /// この場合、復号できなくなるが、症状が「ログインし直しになる」だけで気付けないので固定化した。
        /// </remarks>
        public const string DataProtectionApplicationName = "MultiPurposeAuthSite";

        #endregion

        #endregion

        #region IdP

        #region 利用者の識別子

        /// <summary>
        /// 利用者名を運ぶ標準のクレーム
        /// </summary>
        /// <remarks>
        /// - **`sub` の代わりに利用者名を運ぶのは、これ**（OIDC Core §5.1）。
        /// - **出す側は `UserClaimsMapping`** で `user:UserName` に対応付ける。
        /// - **受ける側（ID 連携の下流）は、新規作成の利用者名にこれを使う。**
        /// </remarks>
        public const string PreferredUserNameClaim = "preferred_username";

        #endregion

        #region WebAuthn

        /// <summary>WebAuthn の RP の表示名</summary>
        /// <remarks>
        /// - **認証器の画面に出る名前**（`RPName`）。
        /// - **RPID とは別物**で、**RPID は配備先のホスト名から取る**（`WebAuthnHelper` の constructor）。
        /// - **設定キーにしていない**のは、**表示名を変えても振る舞いが変わらない**ため。
        /// </remarks>
        public const string WebAuthnRpName = "MultiPurposeAuthSite";

        /// <summary>認証の options を保存する Session の Key</summary>
        public const string WebAuthnSessionAssertionOptions = "fido2.AssertionOptions";

        /// <summary>登録の options を保存する Session の Key</summary>
        public const string WebAuthnSessionCredentialCreateOptions = "fido2.CredentialCreateOptions";

        /// <summary>画面（JavaScript）から送る JSON の利用者名の項目</summary>
        public const string WebAuthnRequestUserName = "username";

        #endregion

        #region Roles

        /// <summary>SystemAdministrator or Administratorのrole</summary>
        public const string Role_SystemAdminOrAdmin
            = Role_SystemAdmin + ", " + Role_Admin;

        /// <summary>SystemAdministrator or Administrator or Userのrole</summary>
        public const string Role_SystemAdminOrAdminOrUser
            = Role_SystemAdmin + ", " + Role_Admin + ", " + Role_User;

        /// <summary>SystemAdministratorのrole</summary>
        public const string Role_SystemAdmin = "SystemAdmin";

        /// <summary>Administratorのrole</summary>
        public const string Role_Admin = "Admin";

        /// <summary>Userのrole</summary>
        public const string Role_User = "User";

        #endregion

        #endregion

        #region STS

        #region token_type

        /// <summary>token_type（RFC 6750）</summary>
        /// <remarks>
        /// **値は大文字小文字を区別しない**（RFC 6749 §5.1）。**従来どおり小文字で返す**
        /// （Open棟梁 の `OAuth2AndOIDCConst.Bearer` は、Authorization ヘッダの "Bearer"）。
        /// </remarks>
        public const string TokenTypeBearer = "bearer";

        #endregion

        #region Scope

        /// <summary>DCRの管理 API 専用の scope</summary>
        /// <remarks>
        /// **この scope を持つアクセス トークンだけが、`registration_endpoint` を叩ける。**
        ///
        /// **仕様が定めた名前ではない**（RFC 7591 は initial access token の取り方を定めていない）。**この配備が決めた値**である。
        /// **広告するのは、DCRを開けた配備だけ**（`Helper.GetScopesSupported`）。
        ///
        /// > **この scope は、登録に明記したクライアントにしか出さない**
        /// > （`Helper.FilterSupportedScopes`）。
        /// > **他の scope の「登録が無ければ制限しない」とは、逆の倒し方である** —
        /// > **登録を作れる強い権限なので、既定で持たせてはならない。**
        /// </remarks>
        public const string ScopeClientRegistration = "client_registration";

        /// <summary>OIDCのscopes</summary>
        /// <remarks>
        /// `openid` と <see cref="SelfTestScopes"/> を合わせたもの。
        /// </remarks>
        public const string OidcScopes =
            OAuth2AndOIDCConst.Scope_Openid + " " + SelfTestScopes;

        /// <summary>ID連携のscopes</summary>
        /// <remarks>
        /// 標準のスコープだけを要求する。
        /// 上流が `email_verified` を返す。突き合わせは常にメアド。
        /// </remarks>
        public const string IdFederationScopes =
            OAuth2AndOIDCConst.Scope_Openid + " "
            + OAuth2AndOIDCConst.Scope_Profile + " "
            + OAuth2AndOIDCConst.Scope_Email + " "
            + OAuth2AndOIDCConst.Scope_Phone + " "
            + OAuth2AndOIDCConst.Scope_Address;

        #endregion

        #region 要求パラメタ名

        // **Open棟梁 の OAuth2AndOIDCConst に無いもの。**

        /// <summary>username（ROPC。RFC 6749 §4.3.2）</summary>
        public const string ParamUsername = "username";

        /// <summary>password（ROPC。RFC 6749 §4.3.2）</summary>
        public const string ParamPassword = "password";

        /// <summary>認証デバイスの FCM トークン（/SetDeviceToken。この IdP の独自）</summary>
        public const string ParamDeviceToken = "device_token";

        /// <summary>post_logout_redirect_uri（RP-Initiated Logout 1.0 §2。/end_session の要求）</summary>
        /// <remarks>登録の項目（<see cref="ClientPostLogoutRedirectUri"/>）と同じ名前だが、こちらは要求のパラメタである。</remarks>
        public const string ParamPostLogoutRedirectUri = "post_logout_redirect_uri";

        #endregion

        #region Endpoint名

        // **レート制限の数える単位**（`RateLimitProvider`）と、**WWW-Authenticate の realm** に使う。

        /// <summary>/token</summary>
        public const string EndpointToken = "token";

        /// <summary>/userinfo</summary>
        public const string EndpointUserInfo = "userinfo";

        /// <summary>/revoke</summary>
        public const string EndpointRevoke = "revoke";

        /// <summary>/introspect</summary>
        public const string EndpointIntrospect = "introspect";

        /// <summary>/device_authz</summary>
        public const string EndpointDeviceAuthZ = "device_authz";

        /// <summary>/device_verify</summary>
        public const string EndpointDeviceVerify = "device_verify";

        /// <summary>/ciba_authz</summary>
        public const string EndpointCibaAuthZ = "ciba_authz";

        /// <summary>/par</summary>
        public const string EndpointPar = "par";

        /// <summary>/jwkcerts</summary>
        public const string EndpointJwkCerts = "jwkcerts";

        /// <summary>/register（動的クライアント登録）</summary>
        public const string EndpointRegister = "register";

        /// <summary>/ciba_result（認証デバイスからの結果）</summary>
        public const string EndpointCibaResult = "ciba_result";

        /// <summary>/2fa_result（認証デバイスからの結果）</summary>
        public const string EndpointTwoFactorResult = "2fa_result";

        /// <summary>/SetDeviceToken（認証デバイスの登録）</summary>
        public const string EndpointSetDeviceToken = "SetDeviceToken";

        #endregion

        #region 再認証 (max_age)

        /// <summary>再認証を求めた時刻を保存するCookieのKey</summary>
        /// <remarks>
        /// **`max_age` の超過で再認証へ送ったことの印。**
        /// これが無いと、`max_age=0` のときに
        /// 「送る → 認証する → また超過している → 送る」で**繰り返しになる。**
        /// 印より後に認証されていれば、**一度は再認証した**と判断して先へ進む。
        /// </remarks>
        public const string ReAuthenticatedAt = "re_auth_at";

        #endregion

        #region DPoP/mTLS

        /// <summary>cnf.jkt を運ぶ ClaimsIdentity のクレーム型</summary>
        /// <remarks>
        /// **`urn:oauth:` は Open棟梁 が使っている名前空間**に合わせてある
        /// （**mTLS の `UrnCnfX5tClaim` と同じ流儀**）。
        /// **トークンの `cnf.jkt` を、検証後の `ClaimsIdentity` に移すために使う。**
        /// </remarks>
        public const string UrnCnfJktClaim = "urn:oauth:cnf:jkt";

        /// <summary>tls_client_auth_subject_dn（RFC 8705 §2.1.2）</summary>
        public const string ClientTlsClientAuthSubjectDn = "tls_client_auth_subject_dn";

        #endregion

        #region response_mode（JARM）

        /// <summary>query.jwt（JARM §2.3.1）</summary>
        public const string ResponseModeQueryJwt = "query.jwt";

        /// <summary>fragment.jwt（JARM §2.3.2）</summary>
        public const string ResponseModeFragmentJwt = "fragment.jwt";

        /// <summary>form_post.jwt（JARM §2.3.3）</summary>
        public const string ResponseModeFormPostJwt = "form_post.jwt";
        #endregion

        #region sid（Front / Back-Channel Logout）

        /// <summary>OP のセッションの識別子を保存するCookieのKey</summary>
        /// <remarks>
        /// **中身は guid。** **サインインで作り、サインアウトで消す。**
        /// **これは `sid` そのものではない。台帳を引くための鍵**である。
        ///
        /// **接頭辞が掛かる**（`Config.PrefixCookieName`）。
        /// </remarks>
        public const string OpSession = "op_session";

        /// <summary>OP のセッションを用意し直したことを示す印</summary>
        /// <remarks>
        /// **認可の口で `op_session` が無かったとき、Cookie を置いて同じ URL へ送り返す。**
        /// **その送り返しに 1 回だけ付ける印**である（**無いと永久に送り返す**）。
        ///
        /// **Cookie を置けない文脈が在る** —
        /// **third-party cookie を遮る設定のブラウザで、iframe から `prompt=none`** を投げた場合など。
        /// **そこでは印だけが残り、セッションの識別子はその場で作る**（台帳は 1 行だけ残る）。
        ///
        /// **再認証の `re_auth_at` と同じ考え方**である。
        /// </remarks>
        public const string OpSessionRetry = "op_session_retry";

        /// <summary>sid クレームの名前</summary>
        /// <remarks>
        /// **OP のセッションの識別子**（OIDC Core §2）。
        /// **Front-Channel / Back-Channel Logout が「どのセッションか」を言う手段**である。
        /// </remarks>
        public const string Sid = "sid";

        /// <summary>sid を運ぶ ClaimsIdentity のクレーム型</summary>
        /// <remarks>
        /// **`urn:oauth:` は Open棟梁 が使っている名前空間**に合わせてある
        /// （`UrnAuthTimeClaim` などと同じ流儀）。
        /// **プロセスの外には出ない**（トークンに入るのは <see cref="Sid"/> の名前）。
        /// </remarks>
        public const string UrnSidClaim = "urn:oauth:sid";

        /// <summary>logout_token を運ぶ要求の項目名</summary>
        /// <remarks>**POST の本文に 1 項目だけ**（Back-Channel Logout 1.0 §2.5）。</remarks>
        public const string LogoutToken = "logout_token";

        /// <summary>logout_token の typ ヘッダ</summary>
        /// <remarks>
        /// **Back-Channel Logout 1.0 §2.4 が推している型**である。
        /// **`id_token` と取り違えないため**（`at+jwt` を付けた）。
        /// </remarks>
        public const string LogoutJwtTyp = "logout+jwt";

        /// <summary>events クレームの名前（Back-Channel Logout 1.0 §2.4）</summary>
        public const string EventsClaim = "events";

        #endregion

        #region Error Code

        // **Open棟梁 の OAuth2AndOIDCConst に無いもの。**

        /// <summary>invalid_request_object（RFC 9101 §6.3）</summary>
        public const string InvalidRequestObject = "invalid_request_object";

        /// <summary>invalid_redirect_uri（RFC 7591 §3.2.2 : redirect_uri が不正）</summary>
        public const string InvalidRedirectUri = "invalid_redirect_uri";

        /// <summary>invalid_client_metadata（RFC 7591 §3.2.2 : メタデータが不正）</summary>
        public const string InvalidClientMetadata = "invalid_client_metadata";

        /// <summary>invalid_software_statement（RFC 7591 §3.2.2 : software_statement が壊れている）</summary>
        /// <remarks>
        /// **JWT として読めない・署名が合わない・`iss` が無い・`exp` が切れている**とき。
        /// **「中身は読めたが、信頼していない」のは <see cref="UnapprovedSoftwareStatement"/>** である。
        /// </remarks>
        public const string InvalidSoftwareStatement = "invalid_software_statement";

        /// <summary>unapproved_software_statement（RFC 7591 §3.2.2 : software_statement を受け付けない）</summary>
        /// <remarks>
        /// **その発行者を信頼していない**とき（§3.2.2 の
        /// "not approved for use by this authorization server"）。
        /// **信頼する発行者を 1 件も設定していない配備では、常にこれ**である。
        /// </remarks>
        public const string UnapprovedSoftwareStatement = "unapproved_software_statement";

        /// <summary>insufficient_scope（RFC 6750 §3.1 : トークンの scope が足りない）</summary>
        public const string InsufficientScope = "insufficient_scope";

        #endregion

        #region Client登録項目

        // **登録（DB の JSON・TestClients・画面・動的クライアント登録）で同じ名前を使う。**
        //   **Open棟梁 の OAuth2AndOIDCConst に在るもの**（scope / jwks_uri / redirect_uris / client_secret）は、そちらを使う。

        #region RFC 7591 DCR

        /// <summary>token_endpoint_auth_method</summary>
        public const string ClientTokenEndpointAuthMethod = "token_endpoint_auth_method";

        /// <summary>grant_types</summary>
        public const string ClientGrantTypes = "grant_types";

        /// <summary>response_types</summary>
        public const string ClientResponseTypes = "response_types";

        /// <summary>client_name</summary>
        public const string ClientName = "client_name";

        /// <summary>client_uri</summary>
        public const string ClientUri = "client_uri";

        /// <summary>logo_uri</summary>
        public const string ClientLogoUri = "logo_uri";

        /// <summary>contacts</summary>
        public const string ClientContacts = "contacts";

        /// <summary>tos_uri</summary>
        public const string ClientTosUri = "tos_uri";

        /// <summary>policy_uri</summary>
        public const string ClientPolicyUri = "policy_uri";

        /// <summary>jwks</summary>
        public const string ClientJwks = "jwks";

        /// <summary>software_id</summary>
        public const string ClientSoftwareId = "software_id";

        /// <summary>software_version</summary>
        public const string ClientSoftwareVersion = "software_version";

        /// <summary>software_statement（RFC 7591 §2.3）</summary>
        public const string ClientSoftwareStatement = "software_statement";

        #endregion

        #region OIDC DCR

        /// <summary>subject_type</summary>
        public const string ClientSubjectType = "subject_type";

        /// <summary>id_token_signed_response_alg</summary>
        public const string ClientIdTokenSignedResponseAlg = "id_token_signed_response_alg";

        /// <summary>request_object_signing_alg</summary>
        public const string ClientRequestObjectSigningAlg = "request_object_signing_alg";

        /// <summary>token_endpoint_auth_signing_alg</summary>
        public const string ClientTokenEndpointAuthSigningAlg = "token_endpoint_auth_signing_alg";

        #endregion

        #region Logout

        //（RP-Initiated / Front-Channel / Back-Channel Logout 1.0）

        /// <summary>post_logout_redirect_uri（RP-Initiated Logout 1.0）</summary>
        public const string ClientPostLogoutRedirectUri = "post_logout_redirect_uri";

        /// <summary>frontchannel_logout_uri（Front-Channel Logout 1.0）</summary>
        public const string ClientFrontChannelLogoutUri = "frontchannel_logout_uri";

        /// <summary>backchannel_logout_uri（Back-Channel Logout 1.0）</summary>
        public const string ClientBackChannelLogoutUri = "backchannel_logout_uri";

        #endregion

        #region この IdP の独自

        /// <summary>code を返す redirect_uri</summary>
        public const string ClientRedirectUriCode = "redirect_uri_code";

        /// <summary>token を返す redirect_uri</summary>
        public const string ClientRedirectUriToken = "redirect_uri_token";

        /// <summary>SAML2 の ACS URL</summary>
        public const string ClientRedirectUriSaml = "redirect_uri_saml";

        /// <summary>CORS で許すオリジン</summary>
        public const string ClientWebOrigins = "web_origins";

        /// <summary>クライアントの種別</summary>
        public const string ClientType = "client_type";

        /// <summary>クライアントのモード</summary>
        public const string ClientMode = "client_mode";

        /// <summary>PKCE を必須にするか</summary>
        public const string ClientRequirePkce = "require_pkce";

        /// <summary>クライアントの所有者の利用者名</summary>
        public const string ClientOwner = "owner";

        #region JWK

        /// <summary>RSA の公開鍵</summary>
        public const string ClientJwkRsaPublicKey = "jwk_rsa_publickey";

        /// <summary>ECDSA の公開鍵</summary>
        public const string ClientJwkEcdsaPublicKey = "jwk_ecdsa_publickey";

        #endregion

        #region 保存名

        /// <summary>sub の種別</summary>
        public const string ClientSubjectTypes = "subject_types";

        /// <summary>管理用トークンのハッシュ（RFC 7592）</summary>
        public const string ClientRegistrationAccessTokenHash = "registration_access_token_hash";

        #endregion

        #region 応答だけの項目（RFC 7591 §3.2.1 / RFC 7592 §3）

        /// <summary>client_id_issued_at（RFC 7591 §3.2.1）</summary>
        public const string ClientIdIssuedAt = "client_id_issued_at";

        /// <summary>client_secret_expires_at（RFC 7591 §3.2.1）</summary>
        public const string ClientSecretExpiresAt = "client_secret_expires_at";

        /// <summary>registration_access_token（RFC 7592 §3）</summary>
        public const string ClientRegistrationAccessToken = "registration_access_token";

        /// <summary>registration_client_uri（RFC 7592 §3）</summary>
        public const string ClientRegistrationClientUri = "registration_client_uri";

        #endregion

        #region JWK のパラメタ（RFC 7517）

        /// <summary>use（RFC 7517 §4.2 : 公開鍵の用途）</summary>
        public const string JwkUse = "use";

        /// <summary>sig（use の値 : 署名用。RFC 7517 §4.2）</summary>
        public const string JwkUseSig = "sig";

        #endregion

        #endregion

        #endregion

        #region 台帳項目名

        #region code（DB-JSON）

        /// <summary>access_token の payload（`AuthorizationCodeProvider`）</summary>
        public const string AuthZCodeAccessTokenPayload = "access_token_payload";

        #endregion

        #region Device Polling（memory）

        // **CIBA と Device Authorization Grant の台帳**（`CibaProvider` / `DeviceAuthZProvider`）の項目。

        /// <summary>要求の期限</summary>
        public const string PollingAuthReqExp = "authReqExp";

        /// <summary>承認されたときの認可コード</summary>
        public const string PollingAuthZCode = "authZCode";

        /// <summary>認証デバイスの結果</summary>
        public const string PollingResult = "result";

        /// <summary>前回のポーリングの時刻（slow_down の判定）</summary>
        public const string PollingLastPolled = "lastPolled";

        /// <summary>auth_req_id（CIBA）</summary>
        public const string PollingAuthReqId = "authReqId";

        /// <summary>利用者の Id（CIBA）</summary>
        public const string PollingUserId = "userId";

        /// <summary>user_code（Device Authorization Grant）</summary>
        public const string PollingUserCode = "userCode";

        /// <summary>認可コードを作るための要求の内容（Device Authorization Grant）</summary>
        public const string PollingTempData = "tempData";

        #endregion

        #endregion

        #region 自己テスト

        #region 判定

        /// <summary>成功（画面の判定欄）</summary>
        public const string VerdictNormalEnd = "NORMAL_END";

        /// <summary>失敗（画面の判定欄）</summary>
        public const string VerdictAbnormalEnd = "ABNORMAL_END";
        #endregion

        #region RedirectUri

        // サイトごとに URL が違う**（net48, net10.0）ので、定数で登録し、サーバ側で解決

        /// <summary>SAML2のテスト用のRedirectUri（ACS URL）</summary>
        public const string TestSelfSaml = "test_self_saml";
        
        /// <summary>codeのテスト用のRedirectUri</summary>
        public const string TestSelfCode = "test_self_code";

        /// <summary>tokenのテスト用のRedirectUri</summary>
        public const string TestSelfToken = "test_self_token";

        #endregion

        #region Scopes

        /// <summary>自己テストのscope</summary>
        /// <remarks>
        /// **自己テストで要求する、利用者の属性の scope**（`openid` は含まない）。
        ///
        /// | scope | 種別 | 載るもの |
        /// |---|---|---|
        /// | `profile` / `email` / `phone` / `address` | OIDC Core §5.4 の標準 | 利用者の属性のクレーム |
        /// | `roles` | **この IdP の独自** | ロールの一覧 |
        ///
        /// **独自の `userid` は、PPID の意味を打ち消すため scope ごと廃止した**（#294）。
        ///
        /// **独自の `roles` を含む。** **他の OP へ送ってはならない**
        /// - 厳格な OP では `invalid_scope` になりうる。
        /// - ID 連携は標準だけの `IdFederationScopes` を使う。
        ///
        /// **`roles` は、自前のResource Server（Web API）で使う可能性を考えて残している**
        /// - access_token の `scopes` には scope 名が載る。
        /// - ロールそのものは載らないので、/userinfo から取る。
        ///
        /// **使うのは自己テストだけ**。**自分自身に対して要求する**ので、独自の scope も通る。
        /// OIDC として要求するときは、`openid` を足した <see cref="OidcScopes"/> を使う。
        ///
        /// **発行するかは、要求とは別に絞られる** —
        /// Discovery で広告した scope（`Helper.GetScopesSupported`）と、クライアントごとの登録の範囲だけが出る。
        /// </remarks>
        public const string SelfTestScopes =
            OAuth2AndOIDCConst.Scope_Profile + " "
            + OAuth2AndOIDCConst.Scope_Email + " "
            + OAuth2AndOIDCConst.Scope_Phone + " "
            + OAuth2AndOIDCConst.Scope_Address + " "
            + OAuth2AndOIDCConst.Scope_Roles;

        #endregion

        #region Logout

        /// <summary>ログアウト後の戻り先（post_logout_redirect_uri）のテスト用の値</summary>
        public const string TestSelfLogout = "test_self_logout";

        /// <summary>Front-Channel Logout の受け口のテスト用の値</summary>
        /// <remarks>
        /// **ブラウザが `iframe` で開く口**である（**`logout_token` は来ない**。`iss` と `sid` だけ）。
        /// **E2E は `iframe` を開けない**ので、**テストが自分で叩く**（`TestFrontChannelLogoutBox`）。
        /// **口は `IsLockedDownTestEndpoints` で閉じる。**
        /// </remarks>
        public const string TestSelfFrontChannelLogout = "test_self_fclogout";

        /// <summary>Back-Channel Logout の受け口のテスト用の値</summary>
        /// <remarks>
        /// **このサイトは、自分の RP も兼ねている**（`test_self_code` と同じ考え方）。
        /// **受け取った `logout_token` は覚えておく**（`TestLogoutTokenBox`）。
        /// **口は `IsLockedDownTestEndpoints` で閉じる。**
        /// </remarks>
        public const string TestSelfBackChannelLogout = "test_self_bclogout";

        #endregion

        #region Session, Cookie のキー

        /// <summary>テスト用ClientIdを保存するSession, CookieのKey</summary>
        public const string TestClientId = "test_client_id";

        /// <summary>テスト用Stateを保存するSession, CookieのKey</summary>
        public const string TestState = "test_state";

        /// <summary>テスト用RedirectUriを保存するSession, CookieのKey</summary>
        public const string TestRedirectUri = "test_redirect_uri";

        /// <summary>テスト用Nonceを保存するSession, CookieのKey</summary>
        public const string TestNonce = "test_nonce";

        /// <summary>テスト用CodeVerifierを保存するSession, CookieのKey</summary>
        public const string TestCodeVerifier = "test_code_verifier";

        /// <summary>テスト用の SAML2 AuthnRequest の ID を保存する Session, Cookie の Key</summary>
        /// <remarks>
        /// **応答の `InResponseTo` と照合するために保存する**（Web SSO Profile 4.1.4.3）。
        /// **以前は `out id` を捨てていた**ので、照合できなかった。
        /// </remarks>
        public const string TestSamlRequestId = "test_saml_request_id";

        #endregion

        #region NameIDFormat の選択肢

        // **画面の選択肢の値**（SAML2。`SAML2Enum.NameIDFormat` へは `HomeController` で写す）。

        /// <summary>unspecified（利用者名）</summary>
        public const string NameIdFormatUnspecified = "unspecified";

        /// <summary>emailAddress（メアド）</summary>
        public const string NameIdFormatEmailAddress = "emailAddress";

        /// <summary>persistent（RP ごとの PPID）</summary>
        public const string NameIdFormatPersistent = "persistent";

        #endregion

        #endregion

        #endregion

        #region ID 連携

        #region Session のキー

        /// <summary>OIDC の ID 連携の state</summary>
        public const string IdFederationSigninState = "id_federation_signin_state";

        /// <summary>OIDC の ID 連携の上流（キー）</summary>
        public const string IdFederationSigninUpstream = "id_federation_signin_upstream";

        /// <summary>ID 連携を始めた画面の ReturnUrl（OIDC・SAML2 で共用。戻ってきたら、ここへ返す。#294）</summary>
        public const string IdFederationSigninReturnUrl = "id_federation_signin_return_url";

        /// <summary>OIDC の ID 連携の nonce</summary>
        public const string IdFederationSigninNonce = "id_federation_signin_nonce";

        /// <summary>OIDC の ID 連携の code_verifier（PKCE）</summary>
        public const string IdFederationSigninVerifier = "id_federation_signin_verifier";

        /// <summary>SAML2 の ID 連携の RelayState</summary>
        public const string IdFederationSaml2State = "id_federation_saml2_state";

        /// <summary>SAML2 の ID 連携の上流（キー）</summary>
        public const string IdFederationSaml2Upstream = "id_federation_saml2_upstream";

        /// <summary>SAML2 の ID 連携の AuthnRequest の ID（InResponseTo と照合）</summary>
        public const string IdFederationSaml2RequestId = "id_federation_saml2_request_id";
        #endregion

        #endregion
    }
}
