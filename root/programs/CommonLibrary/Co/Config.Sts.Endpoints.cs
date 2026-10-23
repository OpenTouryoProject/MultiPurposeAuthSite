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
//* クラス名        ：Config
//* クラス日本語名  ：ASP.NET IdentityのConfigクラス（ライブラリ）の STS（口）
//*
//* 作成日時        ：－
//* 作成者          ：－
//* 更新履歴        ：－
//*
//*  日時        更新者            内容
//*  ----------  ----------------  -------------------------------------------------
//*  2026/10/23  玄人 幸道         新規（Config.cs から partial に分割。#294）
//*  2026/10/23  玄人 幸道         口ごとの役・URL の組み立て・同じ値を見る所を、コメントに書き足した（#294）
//*  2026/10/23  玄人 幸道         パスの設定に既定値（雛形の値）を持たせた（#294）
//*  2026/10/23  玄人 幸道         OAuth2ClientsInformation / UserClaimsMapping を Config.Sts.Features.cs へ移した（#294）
//**********************************************************************************

using System;

using Touryo.Infrastructure.Public.Util;

/// <summary>MultiPurposeAuthSite.Co</summary>
namespace MultiPurposeAuthSite.Co
{
    /// <summary>Config（STS（口））</summary>
    public partial class Config
    {
        //  **この節は「口（エンドポイント）の URL」を持つ。**
        //
        //  | 区分 | 中身 | URL の組み立て |
        //  |---|---|---|
        //  | **認可サーバの口** | Authorize・Token・UserInfo・Revoke・Introspection・DCR・Device・CIBA・SAML2 の要求 | **`OAuth2AuthorizationServerEndpointsRootURI` ＋ パス** |
        //  | **自己テストのクライアントの口** | 自己テストの折り返し口（`test_self_*`）・SAML2 の ACS | **`OAuth2ClientEndpointsRootURI` ＋ パス** |
        //
        //  パスの設定は `/` で始める。ルートの登録は先頭の `/` を落として使うので、空や `/` 無しでは起動時に落ちるか、口がずれる。
        //  同じ値を、ルートの登録・Discovery の広告・DPoP の `htu` の期待値・レート制限の対象が見ている（片方だけ書き換えると、黙って食い違う）。
        //
        //  **パスの設定は、どれも既定値を持つ**（**雛形の値**。`EndpointPathOrDefault`）。**キーが無い・空なら既定値**になる
        //  （**後から足したキーが、既存の配備の設定ファイルに無くても動く**。**空のままルートを登録して落ちることもない**）。
        //  **基底（`…RootURI`）は既定値を持たない** — **配備ごとに違う値**で、**黙って既定のホストへ向けると、別の相手を指してしまう。**

        #region 基底

        /// <summary>
        /// OAuth2のAuthorizationServerのEndpointのRootのURI
        /// </summary>
        /// <remarks>
        /// 認可サーバの口の URL は、すべて「この値 ＋ パスの設定」（例 : `https://localhost:44300/MultiPurposeAuthSite` ＋ `/token`）。
        /// VisualStudioデバッグ版は仮想ディレクトリを含める（コンテナ版は含めない）。末尾に `/` を付けない。
        ///
        /// **この値で決まるもの**（**相手に見せる URL と、相手に求める URL**）。
        ///
        /// | | |
        /// |---|---|
        /// | **広告する口の URL** | Discovery（`authorization_endpoint` / `token_endpoint` ほか）と、SAML2 のメタデータ（`SingleSignOnService`） |
        /// | **相手に求める宛先** | DPoP の証明の `htu`、`private_key_jwt` の `aud` — **要求の `Host` ではなく、この値と照合する**（#311） |
        /// | **自分の口を叩く宛先** | 自己テストがサーバ間で叩く URL（コンテナでは `OAuth2Containerizated…` で差し替える） |
        ///
        /// **相手は、広告された URL をそのまま使う。** **実際に届く URL と違えば、照合が落ちる**（DPoP・`private_key_jwt`）。
        ///
        /// **Issuer（`IssuerId`）とは別の値**である（Issuer は論理名で、URL である必要は無い）。
        /// </remarks>
        public static string OAuth2AuthorizationServerEndpointsRootURI
        {
            get
            {
                return GetConfigParameter.GetConfigValue("OAuth2AuthorizationServerEndpointsRootURI");
            }
        }

        /// <summary>
        /// 自己テストがコンテナの中から、サーバ間で自分の口（/token など）を叩くときの、スキームを含む基底（`http://localhost:8080` など）を指定する。
        /// </summary>
        /// <remarks>
        /// 理由 : コンテナの中からは外向きのポートに届かない（だから localhost）。中の HTTPS では開発用証明書を検証できない（だから http）。
        /// 以下の条件を満たすときには差し替えない。
        /// - **空なら差し替えない**（従来どおり）
        /// - **ID 連携の相手（他の IdP）には効かない**（宛先が自分ではないため）。
        /// - **Windows では効かない**（`PlatformID.Win32NT` なら差し替えない）
        /// </remarks>
        public static string OAuth2ContainerizatedAuthSvrEPRootURI
        {
            get
            {
                return GetConfigParameter.GetConfigValue("OAuth2ContainerizatedAuthSvrEPRootURI");
            }
        }

        /// <summary>
        /// 自己テストがコンテナの中から、サーバ間で自分の口（/token など）を叩くときの、ホスト名とポート（`localhost:8081` など）
        /// </summary>
        /// <remarks>
        /// 元のスキームで良い場合なので「HTTPS で検証できる証明書がある配備向け」
        /// 差し替え条件は OAuth2ContainerizatedAuthSvrEPRootURI と同じで、`OAuth2Containerizated*が両方在れば、こちらが優先
        /// </remarks>
        public static string OAuth2ContainerizatedAuthSvrFqdnAndPort
        {
            get
            {
                return GetConfigParameter.GetConfigValue("OAuth2ContainerizatedAuthSvrFqdnAndPort");
            }
        }

        /// <summary>パスの設定を読む（キーが無い・空なら既定値）</summary>
        /// <param name="key">設定キー</param>
        /// <param name="defaultPath">既定値（雛形の値。`/` で始まる）</param>
        /// <returns>パス</returns>
        /// <remarks>
        /// **既定値は雛形（`_app.config` / `_appsettings.json`）と同じ値にすること**
        /// **食い違うと、キーを書いた配備と書かない配備で口がずれる。**
        /// **値の形（`/` で始まるか）は確かめない**（書いた値はそのまま使う。従来どおり）。
        /// </remarks>
        private static string EndpointPathOrDefault(string key, string defaultPath)
        {
            string value = GetConfigParameter.GetConfigValue(key);

            return string.IsNullOrEmpty(value) ? defaultPath : value;
        }

        #endregion

        #region SAML2

        //  **基本的に、OAuth2/OIDC のインフラを流用する**（クライアントの登録・利用者・署名鍵は共通）。
        //    **SP の登録は、OAuth2 のクライアント登録に `redirect_uri_saml`（ACS）を足したもの**で、
        //    **要求の `Issuer`（`http://<client_id>`）から引く。**
        //
        //  **2 つは役が違う。**
        //
        //  | 設定 | 役 | 基底 |
        //  |---|---|---|
        //  | `Saml2RequestEndpoint` | **IdP の口**（SP から `AuthnRequest` を受ける。SSO） | `OAuth2AuthorizationServerEndpointsRootURI` |
        //  | `Saml2ResponseEndpoint` | **自己テストの SP の口**（応答を受けて画面に出す。ACS） | `OAuth2ClientEndpointsRootURI` |
        //
        //  **ID 連携で上流から応答を受ける口は別**である（`IdFederationSaml2ResponseEndpoint`。`Config.IdFederation.cs`）。

        /// <summary>
        /// Saml2のRequestエンドポイント（IdP の SSO の口。`AuthnRequest` を受ける）
        /// </summary>
        /// <remarks>
        /// **Redirect / POST の両方の Binding で受ける。**
        /// **この配備のメタデータ（`/samlmetadata`）の `SingleSignOnService` に、この URL を載せる。**
        /// </remarks>
        public static string Saml2RequestEndpoint
        {
            get
            {
                return Config.EndpointPathOrDefault("Saml2RequestEndpoint", "/saml2request");
            }
        }

        /// <summary>
        /// Saml2のResponseエンドポイント（自己テストの SP の ACS）
        /// </summary>
        /// <remarks>
        /// **IdP が応答を返す先ではあるが、IdP の口ではない。** **自己テストの SP 役**として応答を受け、
        /// **アサーションと検証の結果を画面に出す**（#246）。
        ///
        /// - **クライアント登録の ACS に `test_self_saml` と書くと、この URL に展開される**
        ///   （`OAuth2ClientEndpointsRootURI` ＋ この値）
        /// - **Audience / Recipient の期待値にも、同じ URL を使う**（#276）
        /// - **`IsLockedDownTestEndpoints` で閉じる**（本番では開けない）
        /// </remarks>
        public static string Saml2ResponseEndpoint
        {
            get
            {
                return Config.EndpointPathOrDefault("Saml2ResponseEndpoint", "/Account/AssertionConsumerService");
            }
        }

        #endregion

        #region OAuth2/OIDC

        /// <summary>
        /// OAuth2のAuthorizeエンドポイント（認可エンドポイント。RFC 6749 §3.1）
        /// </summary>
        /// <remarks>
        /// **ブラウザが来る口**（MVC のルート）。
        /// **Discovery の `authorization_endpoint` に、`OAuth2AuthorizationServerEndpointsRootURI` ＋ この値を広告する。**
        /// </remarks>
        public static string OAuth2AuthorizeEndpoint
        {
            get
            {
                return Config.EndpointPathOrDefault("OAuth2AuthorizeEndpoint", "/authorize");
            }
        }

        /// <summary>
        /// OAuth2のTokenエンドポイント（RFC 6749 §3.2）
        /// </summary>
        /// <remarks>
        /// **サーバ間で叩かれる口**（WebAPI のルート）。**グラント種別はすべてここ 1 本**
        /// （認可コード・refresh_token・client_credentials・ROPC・JWT Bearer・Device AuthZ・CIBA）。
        ///
        /// **この値で決まるもの**（`OAuth2AuthorizationServerEndpointsRootURI` ＋ この値）。
        ///
        /// | | |
        /// |---|---|
        /// | **広告する URL** | Discovery の `token_endpoint` |
        /// | **相手に求める宛先** | DPoP の証明の `htu`（#311）、`private_key_jwt` の `aud`（RFC 7523 §3） |
        /// | **レート制限の対象** | この口への要求を数える（#305） |
        /// </remarks>
        public static string OAuth2TokenEndpoint
        {
            get
            {
                return Config.EndpointPathOrDefault("OAuth2TokenEndpoint", "/token");
            }
        }

        /// <summary>
        /// RP-Initiated Logout のエンドポイント（#232）
        /// </summary>
        /// <remarks>
        /// **ブラウザが来る口**（MVC のルート）。**Discovery の `end_session_endpoint` に広告する。**
        /// **サインアウトの後、RP へ伝える**（Back-Channel / Front-Channel Logout。#310）。
        ///
        /// **新しいキーなので、既に配備された設定ファイルには無い。**
        /// 無ければ既定値（/end_session）を使う。**設定ファイルを直さなくても動く。**
        /// ルートの組み立て（.Substring(1)）で空文字列を渡さないためでもある。
        /// </remarks>
        public static string OAuth2EndSessionEndpoint
        {
            get
            {
                return Config.EndpointPathOrDefault("OAuth2EndSessionEndpoint", "/end_session");
            }
        }

        #endregion

        #region WebAPI

        //  **AccessToken（またはクライアント認証）を付けて、サーバ間で叩く口**（WebAPI のルート）。
        //  Discovery に広告する（`userinfo_endpoint` / `revocation_endpoint` / `introspection_endpoint` / `registration_endpoint`）。

        /// <summary>
        /// OAuth2/OIDCのUserInfoエンドポイント（OIDC Core §5.3）
        /// </summary>
        /// <remarks>
        /// **access_token で利用者のクレームを返す。**
        /// **DPoP で縛ったトークンも受ける**ので、**証明の `htu` にはこの URL を求める**（#311）。
        /// </remarks>
        public static string OAuth2UserInfoEndpoint
        {
            get
            {
                return Config.EndpointPathOrDefault("OAuth2UserInfoEndpoint", "/userinfo");
            }
        }

        /// <summary>
        /// OAuth2のRevokeエンドポイント（RFC 7009）
        /// </summary>
        /// <remarks>
        /// **クライアント認証を要する**（失敗は 401。RFC 6749 §5.2）。**レート制限の対象**（#305）。
        /// </remarks>
        public static string OAuth2RevokeTokenEndpoint
        {
            get
            {
                return Config.EndpointPathOrDefault("OAuth2RevokeTokenEndpoint", "/revoke");
            }
        }

        /// <summary>
        /// OAuth2のIntrospectエンドポイント（RFC 7662）
        /// </summary>
        /// <remarks>
        /// **クライアント認証を要する**（失敗は 401。RFC 7662 §2.3）。**レート制限の対象**（#305）。
        /// </remarks>
        public static string OAuth2IntrospectTokenEndpoint
        {
            get
            {
                return Config.EndpointPathOrDefault("OAuth2IntrospectTokenEndpoint", "/introspect");
            }
        }

        /// <summary>
        /// DynamicClientRegistrationのエンドポイント（RFC 7591 / OIDC Discovery §3 の registration_endpoint）（#307 の段階 1）
        /// </summary>
        /// <remarks>
        /// **`EnableDynamicClientRegistration` が false なら、この口は張らない**（**404 になる**。`IsLockedDownTestEndpoints` とは別のキー）。
        /// **管理 API（RFC 7592）も同じ口の下**に在る（`registration_client_uri`）。**レート制限の対象**（#305）。
        /// **未設定・空なら `/register` に倒す**（**既存の配備にはこのキーが無い**）。
        /// **広告（Discovery）も、張ったときだけ行う。**
        /// </remarks>
        public static string DcrRegistrationEndpoint
        {
            get
            {
                return Config.EndpointPathOrDefault("DcrRegistrationEndpoint", "/register");
            }
        }

        #endregion

        #region その他の WebAPI

        //  **標準の口ではない、この製品だけの WebAPI。** **Discovery には広告しない。**

        /// <summary>
        /// Hybrid Flowのテスト用WebAPI
        /// </summary>
        /// <remarks>
        /// **自己テストの画面（Implicit / Hybrid）が、受け取った access_token で叩く口**である。
        /// **`IsLockedDownTestEndpoints` が true なら、ルートを張らない**（#219）。
        /// </remarks>
        public static string TestHybridFlowWebAPI
        {
            get
            {
                //  **雛形の値が版で違う**（net48 版は `/TestHybridFlow`、net10.0 版は `/TestHybridFlowWebAPI`）。
                //    **既定値も、それぞれの雛形に合わせる。**
#if NETFX
                return Config.EndpointPathOrDefault("TestHybridFlowWebAPI", "/TestHybridFlow");
#else
                return Config.EndpointPathOrDefault("TestHybridFlowWebAPI", "/TestHybridFlowWebAPI");
#endif
            }
        }

        /// <summary>
        /// ユーザ情報にデバイス・トークンを追加するWebAPI
        /// </summary>
        /// <remarks>
        /// **認証デバイス（`authentication_device`）が、プッシュ通知の宛先（FCM のデバイス トークン）を登録する口**である。
        /// **CIBA と 2FA のプッシュは、ここで登録した宛先へ送る。**
        ///
        /// **Bearer（または DPoP）のトークンで叩く。** 本文は `OK` / `NG`（**端末が本文を見ている**ので変えない。#196）。
        /// **DPoP の証明の `htu` には、この URL を求める**（#311）。
        /// </remarks>
        public static string SetDeviceTokenWebAPI
        {
            get
            {
                return Config.EndpointPathOrDefault("SetDeviceTokenWebAPI", "/SetDeviceToken");
            }
        }

        /// <summary>
        /// 2FAのプッシュ承認を受信するWebAPI（#213）
        /// </summary>
        /// <remarks>
        /// **認証デバイスが、2 要素認証の承認・拒否の結果を返す口**である。
        /// **叩き方は `SetDeviceTokenWebAPI` と同じ**（Bearer / DPoP。本文は `OK` / `NG`）。
        /// </remarks>
        public static string TwoFactorPushResultEndpoint
        {
            get
            {
                return Config.EndpointPathOrDefault("TwoFactorPushResultEndpoint", "/2fa_result");
            }
        }

        #endregion

        #region Device AuthZ

        //  **Device Authorization Grant（RFC 8628）。** **口は 2 つで、トークンは `/token` で引き換える。**
        //
        //  | 口 | 誰が来るか（何を貰う／どの URL で来る） |
        //  |---|---|
        //  | `DeviceAuthZAuthorizeEndpoint` | **デバイス**（`device_code`・`user_code`・`expires_in`・`interval`・`verification_uri`・`verification_uri_complete` を貰う） |
        //  | `DeviceAuthZVerifyEndpoint` | **利用者のブラウザ**（`user_code` を入れて承認する。`verification_uri`・`verification_uri_complete`） |

        /// <summary>
        /// Device AuthZのAuthorizeエンドポイント（RFC 8628 §3.1 の device_authorization_endpoint）
        /// </summary>
        /// <remarks>
        /// **Discovery に広告する。** **レート制限の対象**（#305）。
        /// </remarks>
        public static string DeviceAuthZAuthorizeEndpoint
        {
            get
            {
                return Config.EndpointPathOrDefault("DeviceAuthZAuthorizeEndpoint", "/device_authz");
            }
        }

        /// <summary>
        /// Device AuthZの検証用エンドポイント（RFC 8628 §3.2 の verification_uri）
        /// </summary>
        /// <remarks>
        /// **ブラウザが来る口**（MVC のルート）。**`user_code` の総当たりを防ぐため、レート制限の対象**（#305）。
        /// </remarks>
        public static string DeviceAuthZVerifyEndpoint
        {
            get
            {
                return Config.EndpointPathOrDefault("DeviceAuthZVerifyEndpoint", "/device_verify");
            }
        }

        #endregion

        #region CIBA Core

        //  **Client Initiated Backchannel Authentication（CIBA Core）。** **トークンは `/token` で引き換える**（poll）。
        //
        //  | 口 | 誰が来るか（何を送る／何を貰う） |
        //  |---|---|
        //  | `CibaAuthorizeEndpoint` | **クライアント**（署名した認証要求を送り、`auth_req_id`・`expires_in`・`interval` を貰う） |
        //  | `CibaPushResultEndpoint` | **認証デバイス**（プッシュ通知で受けた `auth_req_id` と、利用者の承認・拒否（`result`）を送る。応答は `OK` / `NG`） |

        /// <summary>
        /// CIBAのAuthorizeエンドポイント（backchannel_authentication_endpoint）
        /// </summary>
        /// <remarks>
        /// **Discovery に広告する。** **レート制限の対象**（#305）。
        /// **要求は、クライアントが署名した Request Object**で、**クライアント認証も要る**（CIBA Core 7.1）。
        /// 
        /// 成功の応答は auth_req_id・expires_in・interval の 3 つ（interval は CibaPollingIntervalSeconds）。
        /// </remarks>
        public static string CibaAuthorizeEndpoint
        {
            get
            {
                return Config.EndpointPathOrDefault("CibaAuthorizeEndpoint", "/ciba_authz");
            }
        }

        /// <summary>
        /// CIBAのプッシュ結果を受信するエンドポイント
        /// </summary>
        /// <remarks>
        /// 認証デバイスが、CIBA の承認・拒否の結果を返す口（標準の口ではない。Discovery には広告しない）。
        /// 叩き方は `SetDeviceTokenWebAPI` と同じ、フォームで `auth_req_id` と `result` を受け、
        /// Bearer（または DPoP）で認証。成功は 200 と本文 `OK`、失敗は 400 / 401 と本文 `NG`。
        /// </remarks>
        public static string CibaPushResultEndpoint
        {
            get
            {
                return Config.EndpointPathOrDefault("CibaPushResultEndpoint", "/ciba_result");
            }
        }

        #endregion

        #region 自己テスト

        //  **自己テストのクライアントの口**（`OAuth2ClientEndpointsRootURI` ＋ パス）。
        //  **構成ファイルに書くクライアントの登録（`OAuth2ClientsInformation`）は `Config.Sts.Features.cs`** に在る。

        /// <summary>
        /// OAuth2のClientのEndpointのRootURI（自己テストのクライアントの口の基底）
        /// </summary>
        /// <remarks>
        /// **自己テストのクライアント（この配備自身）の口は、すべて「この値 ＋ パスの設定」で作る**
        /// （`OAuth2AuthorizationCodeGrantClient_Account` / `OAuth2ImplicitGrantClient_Account` / `Saml2ResponseEndpoint`）。
        /// **ふつうは `OAuth2AuthorizationServerEndpointsRootURI` と同じ値**（IdP と自己テストの SP / RP が同じサイトに居る）。
        /// </remarks>
        public static string OAuth2ClientEndpointsRootURI
        {
            get
            {
                return GetConfigParameter.GetConfigValue("OAuth2ClientEndpointsRootURI");
            }
        }

        /// <summary>
        /// AccountController.OAuth2AuthorizationCodeGrantClientのRedirectエンドポイント
        /// </summary>
        /// <remarks>
        /// **`redirect_uri_code` に `test_self_code` と書いたクライアントの折り返し口**（認可コードの自己テスト）。
        /// **`IsLockedDownTestEndpoints` で閉じる。**
        /// </remarks>
        public static string OAuth2AuthorizationCodeGrantClient_Account
        {
            get
            {
                return Config.EndpointPathOrDefault("OAuth2AuthorizationCodeGrantClient_Account", "/Account/OAuth2AuthorizationCodeGrantClient");
            }
        }

        /// <summary>
        /// AccountController.OAuth2ImplicitGrantClientのRedirectエンドポイント
        /// </summary>
        /// <remarks>
        /// **`redirect_uri_token` に `test_self_token` と書いたクライアントの折り返し口**（Implicit / Hybrid の自己テスト）。
        /// **`IsLockedDownTestEndpoints` で閉じる。**
        /// </remarks>
        public static string OAuth2ImplicitGrantClient_Account
        {
            get
            {
                return Config.EndpointPathOrDefault("OAuth2ImplicitGrantClient_Account", "/Account/OAuth2ImplicitGrantClient");
            }
        }

        /// <summary>
        /// テスト用のエンドポイントがロックダウンされているかどうか。
        /// </summary>
        /// <remarks>
        /// **true にすると、自己テストの口を閉じる**（#219）。**本番では true にすること**（false のままだと、起動時に警告が出る）。
        ///
        /// | 閉じるもの | |
        /// |---|---|
        /// | 自己テストの折り返し口・ACS | `OAuth2AuthorizationCodeGrantClient_Account` / `OAuth2ImplicitGrantClient_Account` / `Saml2ResponseEndpoint` |
        /// | テスト用の WebAPI | `TestHybridFlowWebAPI`（**ルートを張らない**） |
        /// | 自己テストの画面 | SAML2 / OAuth2 の自己テストの開始画面（**トップ画面に戻す**） |
        ///
        /// **閉じないもの** : 本番の口（ID 連携の折り返し口・DCR など）。**DCR は `EnableDynamicClientRegistration` で別に開閉する。**
        /// </remarks>
        public static bool IsLockedDownTestEndpoints
        {
            get
            {
                // **旧いキー名も読む（#219）。**
                //   未設定は false（＝「開く」）なので、改名しただけだと
                //   既存の設定ファイル（旧キーしか無い）で、本番が黙って開いてしまう。
                return Convert.ToBoolean(
                    Config.GetRenamedConfigValue("IsLockedDownTestEndpoints"));
            }
        }

        #endregion
    }
}