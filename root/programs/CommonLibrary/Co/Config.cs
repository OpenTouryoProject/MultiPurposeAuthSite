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
//* クラス名        ：Config
//* クラス日本語名  ：ASP.NET IdentityのConfigクラス（ライブラリ）
//*
//* 作成日時        ：－
//* 作成者          ：－
//* 更新履歴        ：－
//*
//*  日時        更新者            内容
//*  ----------  ----------------  -------------------------------------------------
//*  2017/04/24  西野 大介         新規
//*  2019/05/2*  西野 大介         SAML2対応実施
//*  2020/02/27  西野 大介         プッシュ通知、FAPI CIBA対応実施
//*  2020/06/19  西野 大介         GetConfigSectionメソッドを廃止に伴う変更
//*                                GetConfigSection → GetAnyConfigSection
//*  2020/08/04  西野 大介         コンテナ化対応実施
//*  2020/12/18  西野 大介         Device AuthZ対応実施
//*  2026/09/12  玄人 幸道         FcmOutboxDirectory（プッシュ通知の送信箱。テスト用）を追加（#196）
//*  2026/09/16  玄人 幸道         TwoFactorAuthPushResultWebAPI を削除（未実装のため）（#203）
//*  2026/09/16  玄人 幸道         TwoFactorPushResultEndpoint を追加（#213）
//*  2026/09/17  玄人 幸道         IsLockedDownRedirectEndpoint を IsLockedDownTestEndpoints に改名（#219）
//*  2026/09/17  玄人 幸道         PKCE で S256 だけを受け付ける設定を追加（#220）
//*  2026/09/18  玄人 幸道         PKCE（code_challenge）を必須にする設定を追加（#220）
//*  2026/09/24  玄人 幸道         Discovery の service_documentation を設定値にする（#228）
//*  2026/09/24  玄人 幸道         認可コードと Request Object の有効期限の設定を追加（#188）
//*  2026/09/25  玄人 幸道         設定キーの改名と、旧キーの読み替え（#236）
//*  2026/09/25  玄人 幸道         UserClaimsMapping（profile / address のクレームの対応付け）を追加（#230）
//**********************************************************************************

using MultiPurposeAuthSite.Data;
//using MultiPurposeAuthSite.Extensions.FIDO;

using System;
using System.Collections.Generic;

#if NETFX
using Newtonsoft.Json;
#else
using Microsoft.Extensions.Configuration;
#endif

using Touryo.Infrastructure.Public.FastReflection;
using Touryo.Infrastructure.Public.Util;

/// <summary>MultiPurposeAuthSite.Co</summary>
namespace MultiPurposeAuthSite.Co
{
    /// <summary>Config</summary>
    public class Config
    {
        #region Proxy

        #region Internet Proxy

        /// <summary>
        /// UseInternetProxy
        /// </summary>
        public static bool UseInternetProxy
        {
            get
            {
                return Convert.ToBoolean(GetConfigParameter.GetConfigValue("UseInternetProxy"));
            }
        }

        /// <summary>
        /// InternetプロキシURL
        /// </summary>
        public static string InternetProxyURL
        {
            get
            {
                return GetConfigParameter.GetConfigValue("InternetProxyURL");
            }
        }

        /// <summary>
        /// InternetプロキシUID
        /// </summary>
        public static string InternetProxyUID
        {
            get
            {
                return GetConfigParameter.GetConfigValue("InternetProxyUID");
            }
        }

        /// <summary>
        /// InternetプロキシPWD
        /// </summary>
        public static string InternetProxyPWD
        {
            get
            {
                return GetConfigParameter.GetConfigValue("InternetProxyPWD");
            }
        }

        #endregion

        #region Intranet Proxy

        /// <summary>
        /// UseIntranetProxy
        /// </summary>
        public static bool UseIntranetProxy
        {
            get
            {
                return Convert.ToBoolean(GetConfigParameter.GetConfigValue("UseIntranetProxy"));
            }
        }

        /// <summary>
        /// IntranetプロキシURL
        /// </summary>
        public static string IntranetProxyURL
        {
            get
            {
                return GetConfigParameter.GetConfigValue("IntranetProxyURL");
            }
        }

        /// <summary>
        /// IntranetプロキシUID
        /// </summary>
        public static string IntranetProxyUID
        {
            get
            {
                return GetConfigParameter.GetConfigValue("IntranetProxyUID");
            }
        }

        /// <summary>
        /// IntranetプロキシPWD
        /// </summary>
        public static string IntranetProxyPWD
        {
            get
            {
                return GetConfigParameter.GetConfigValue("IntranetProxyPWD");
            }
        }

        #endregion

        #region DebugProxy

        /// <summary>
        /// UseDebugProxy
        /// </summary>
        public static bool UseDebugProxy
        {
            get
            {
                return Convert.ToBoolean(GetConfigParameter.GetConfigValue("UseDebugProxy"));
            }
        }

        /// <summary>
        /// DebugProxyURL
        /// </summary>
        public static string DebugProxyURL
        {
            get
            {
                return GetConfigParameter.GetConfigValue("DebugProxyURL");
            }
        }

        /// <summary>
        /// DebugProxyUID
        /// </summary>
        public static string DebugProxyUID
        {
            get
            {
                return GetConfigParameter.GetConfigValue("DebugProxyUID");
            }
        }

        /// <summary>
        /// DebugProxyPWD
        /// </summary>
        public static string DebugProxyPWD
        {
            get
            {
                return GetConfigParameter.GetConfigValue("DebugProxyPWD");
            }
        }

        #endregion

        #endregion

        #region IsDebug

        /// <summary>Debugかどうか</summary>
        public static bool IsDebug
        {
            get
            {
                if (Config.UserStoreType == EnumUserStoreType.Memory)
                {
                    return true; // Memory Provider 利用時は = Debug 扱い。
                }
                else
                {
                    return Convert.ToBoolean(GetConfigParameter.GetConfigValue("IsDebug"));
                }
            }
        }

        /// <summary>DebugTraceLogを有効にする</summary>
        /// <remarks>**改名した**（綴りが `Enabe` だった。#236）。旧いキー名も読む。</remarks>
        public static bool EnableDebugTraceLog
        {
            get
            {
                return Convert.ToBoolean(Config.GetRenamedConfigValue("EnableDebugTraceLog"));
            }
        }

        #endregion

        #region UserStore

        /// <summary>UserStoreのTypeを返す。</summary>
        public static EnumUserStoreType UserStoreType
        {
            get
            {
                switch (GetConfigParameter.GetConfigValue("UserStoreType").ToUpper())
                {
                    case "MEM":
                        return EnumUserStoreType.Memory;
                    case "SQL":
                        return EnumUserStoreType.SqlServer;
                    case "ORA":
                        return EnumUserStoreType.ODPManagedDriver;
                    case "NPG":
                        return EnumUserStoreType.PostgreSQL;
                    default:
                        return EnumUserStoreType.Memory;
                }
            }
        }

        #endregion
        
        #region UserListCount

        /// <summary>
        /// ユーザ一覧の件数
        /// </summary>
        public static int UserListCount
        {
            get
            {
                return Convert.ToInt32(GetConfigParameter.GetConfigValue("UserListCount"));
            }
        }

        #endregion

        #region 事前登録ユーザ

        #region 管理者ユーザ

        /// <summary>AdministratorUID</summary>
        public static string AdministratorUID
        {
            get
            {
                return GetConfigParameter.GetConfigValue("AdministratorUID");
            }
        }

        /// <summary>AdministratorPWD</summary>
        public static string AdministratorPWD
        {
            get
            {
                return GetConfigParameter.GetConfigValue("AdministratorPWD");
            }
        }

        #endregion

        /// <summary>TestUserPWD</summary>
        public static string TestUserPWD
        {
            get
            {
                return GetConfigParameter.GetConfigValue("TestUserPWD");
            }
        }

        #endregion

        #region Notification Provider

        #region SMTP

        /// <summary>SmtpHostName</summary>
        public static string SmtpHostName
        {
            get
            {
                return GetConfigParameter.GetConfigValue("SmtpHostName");
            }
        }

        /// <summary>SmtpPortNo</summary>
        public static int SmtpPortNo
        {
            get
            {
                return Convert.ToInt32(GetConfigParameter.GetConfigValue("SmtpPortNo"));
            }
        }

        /// <summary>SmtpSSL</summary>
        public static bool SmtpSSL
        {
            get
            {
                return Convert.ToBoolean(GetConfigParameter.GetConfigValue("SmtpSSL"));
            }
        }

        /// <summary>SmtpAccountUID</summary>
        public static string SmtpAccountUID
        {
            get
            {
                return GetConfigParameter.GetConfigValue("SmtpAccountUID");
            }
        }

        /// <summary>SmtpAccountPWD</summary>
        public static string SmtpAccountPWD
        {
            get
            {
                return GetConfigParameter.GetConfigValue("SmtpAccountPWD");
            }
        }

        #endregion

        #region SMS (Twilio)

        /// <summary>TwilioAccountSid</summary>
        public static string TwilioAccountSid
        {
            get
            {
                return GetConfigParameter.GetConfigValue("TwilioAccountSid");
            }
        }

        /// <summary>TwilioAuthToken</summary>
        public static string TwilioAuthToken
        {
            get
            {
                return GetConfigParameter.GetConfigValue("TwilioAuthToken");
            }
        }

        /// <summary>TwilioFromPhoneNumber</summary>
        public static string TwilioFromPhoneNumber
        {
            get
            {
                return GetConfigParameter.GetConfigValue("TwilioFromPhoneNumber");
            }
        }

        #endregion

        #region PushNotification (FCM)

        /// <summary>FirebaseServiceAccountKey</summary>
        public static string FirebaseServiceAccountKey
        {
            get
            {
                return GetConfigParameter.GetConfigValue("FirebaseServiceAccountKey");
            }
        }

        /// <summary>
        /// FcmOutboxDirectory（テスト用）。
        /// 設定すると、プッシュ通知を FCM に送らず、このディレクトリにファイルとして書く（#196）。
        /// E2E テスト（test.ps1 -Launch）が環境変数で設定する。本番では空のままにする。
        /// </summary>
        public static string FcmOutboxDirectory
        {
            get
            {
                return GetConfigParameter.GetConfigValue("FcmOutboxDirectory");
            }
        }

        #endregion

        #endregion

        #region ログイン

        #region ユーザ名検証

        /// <summary>
        /// ユーザ名検証（アルファベットと数値のみ）
        /// </summary>
        public static bool AllowOnlyAlphanumericUserNames
        {
            get
            {
                return Convert.ToBoolean(GetConfigParameter.GetConfigValue("AllowOnlyAlphanumericUserNames"));
            }
        }

        /// <summary>
        /// ユーザ名検証（E-mail形式で要求）
        /// </summary>
        public static bool RequireUniqueEmail
        {
            get
            {
                return Convert.ToBoolean(GetConfigParameter.GetConfigValue("RequireUniqueEmail"));
            }
        }

        /// <summary>
        /// 約款画面を表示するかどうか
        /// </summary>
        public static bool DisplayAgreementScreen
        {
            get
            {
                return Convert.ToBoolean(GetConfigParameter.GetConfigValue("DisplayAgreementScreen"));
            }
        }

        /// <summary>
        /// 約款画面などに表示するテキスト・ファイルのフォルダ
        /// </summary>
        public static string ContentOfLetterFilePath
        {
            get
            {
                return GetConfigParameter.GetConfigValue("ContentOfLetterFilePath");
            }
        }

        /// <summary>
        /// EmailConfirmationリンクの有効期限
        /// </summary>
        public static TimeSpan EmailConfirmationTokenLifespanFromHours
        {
            get
            {
                return TimeSpan.FromHours(Double.Parse(GetConfigParameter.GetConfigValue("EmailConfirmationTokenLifespanFromHours")));
            }
        }

        /// <summary>
        /// ユーザ名の編集許可
        /// </summary>
        public static bool AllowEditingUserName
        {
            get
            {
                return Convert.ToBoolean(GetConfigParameter.GetConfigValue("AllowEditingUserName"));
            }
        }

        /// <summary>
        /// パスワード入力を要求（ユーザ名の編集許可時）
        /// </summary>
        public static bool RequirePasswordInEditingUserNameAndEmail
        {
            get
            {
                return Convert.ToBoolean(GetConfigParameter.GetConfigValue("RequirePasswordInEditingUserNameAndEmail"));
            }
        }

        #endregion

        #region パスワード検証

        /// <summary>
        /// パスワード検証（長さ）
        /// </summary>
        public static int RequiredLength
        {
            get
            {
                return Convert.ToInt32(GetConfigParameter.GetConfigValue("RequiredLength"));
            }
        }

        /// <summary>
        /// パスワード検証（記号の要求）
        /// </summary>
        public static bool RequireNonLetterOrDigit
        {
            get
            {
                return Convert.ToBoolean(GetConfigParameter.GetConfigValue("RequireNonLetterOrDigit"));
            }
        }

        /// <summary>
        /// パスワード検証（数値の要求）
        /// </summary>
        public static bool RequireDigit
        {
            get
            {
                return Convert.ToBoolean(GetConfigParameter.GetConfigValue("RequireDigit"));
            }
        }

        /// <summary>
        /// パスワード検証（小文字の要求）
        /// </summary>
        public static bool RequireLowercase
        {
            get
            {
                return Convert.ToBoolean(GetConfigParameter.GetConfigValue("RequireLowercase"));
            }
        }

        /// <summary>
        /// パスワード検証（大文字の要求）
        /// </summary>
        public static bool RequireUppercase
        {
            get
            {
                return Convert.ToBoolean(GetConfigParameter.GetConfigValue("RequireUppercase"));
            }
        }

        /// <summary>
        /// パスワード・ハッシュ生成に利用されるストレッチ回数
        /// </summary>
        public static int StretchCount
        {
            get
            {
                return Convert.ToInt32(GetConfigParameter.GetConfigValue("StretchCount"));
            }
        }

        #endregion

        #region ユーザ ロックアウト

        /// <summary>
        /// ユーザ ロックアウトの有効と無効
        /// </summary>
        public static bool UserLockoutEnabledByDefault
        {
            get
            {
                return Convert.ToBoolean(GetConfigParameter.GetConfigValue("UserLockoutEnabledByDefault"));
            }
        }

        /// <summary>
        /// ユーザ ロックアウトの期間
        /// </summary>
        public static TimeSpan DefaultAccountLockoutTimeSpanFromSeconds
        {
            get
            {
                return TimeSpan.FromSeconds(Double.Parse(GetConfigParameter.GetConfigValue("DefaultAccountLockoutTimeSpanFromSeconds")));
            }
        }

        /// <summary>
        /// ユーザ ロックアウトされるまでのサインインの失敗回数
        /// </summary>
        public static int MaxFailedAccessAttemptsBeforeLockout
        {
            get
            {
                return Convert.ToInt32(GetConfigParameter.GetConfigValue("MaxFailedAccessAttemptsBeforeLockout"));
            }
        }

        #endregion

        #region Cookie認証チケット

        /// <summary>
        /// Cookie認証チケットの有効期限
        /// </summary>
        public static TimeSpan AuthCookieExpiresFromHours
        {
            get
            {
                return TimeSpan.FromHours(Double.Parse(GetConfigParameter.GetConfigValue("AuthCookieExpiresFromHours")));
            }
        }

        /// <summary>
        /// Cookie認証チケットのSliding（再発行）機能
        /// </summary>
        public static bool AuthCookieSlidingExpiration
        {
            get
            {
                return Convert.ToBoolean(GetConfigParameter.GetConfigValue("AuthCookieSlidingExpiration"));
            }
        }

        #endregion

        #region 2要素認証 (2FA)

        /// <summary>
        /// 2FA:TwoFactorAuthentication
        /// </summary>
        public static bool TwoFactorEnabled
        {
            get
            {
                return Convert.ToBoolean(GetConfigParameter.GetConfigValue("TwoFactorEnabled"));
            }
        }

        /// <summary>
        /// 2FAのCookieの有効期限
        /// </summary>
        public static TimeSpan TwoFactorCookieExpiresFromHours
        {
            get
            {
                return TimeSpan.FromHours(Double.Parse(GetConfigParameter.GetConfigValue("TwoFactorCookieExpiresFromHours")));
            }
        }

        #endregion

        #region 外部ログイン

        /// <summary>本サイトでSaltとして機能する値</summary>
        public static string SaltParameter
        {
            get
            {
                return GetConfigParameter.GetConfigValue("SaltParameter");
            }
        }

        #region MicrosoftAccountAuthentication

        /// <summary>
        /// MicrosoftAccountAuthentication
        /// </summary>
        public static bool MicrosoftAccountAuthentication
        {
            get
            {
                return Convert.ToBoolean(GetConfigParameter.GetConfigValue("MicrosoftAccountAuthentication"));
            }
        }

        /// <summary>
        /// MicrosoftAccountAuthenticationのClientId
        /// </summary>
        public static string MicrosoftAccountAuthenticationClientId
        {
            get
            {
                return GetConfigParameter.GetConfigValue("MicrosoftAccountAuthenticationClientId");
            }
        }

        /// <summary>
        /// MicrosoftAccountAuthenticationのClientSecret
        /// </summary>
        public static string MicrosoftAccountAuthenticationClientSecret
        {
            get
            {
                return GetConfigParameter.GetConfigValue("MicrosoftAccountAuthenticationClientSecret");
            }
        }

        #endregion

        #region GoogleAuthentication

        /// <summary>
        /// GoogleAuthentication
        /// </summary>
        public static bool GoogleAuthentication
        {
            get
            {
                return Convert.ToBoolean(GetConfigParameter.GetConfigValue("GoogleAuthentication"));
            }
        }

        /// <summary>
        /// GoogleAuthenticationのClientId
        /// </summary>
        public static string GoogleAuthenticationClientId
        {
            get
            {
                return GetConfigParameter.GetConfigValue("GoogleAuthenticationClientId");
            }
        }

        /// <summary>
        /// GoogleAuthenticationのClientSecret
        /// </summary>
        public static string GoogleAuthenticationClientSecret
        {
            get
            {
                return GetConfigParameter.GetConfigValue("GoogleAuthenticationClientSecret");
            }
        }

        #endregion

        #region FacebookAuthentication

        /// <summary>
        /// FacebookAuthentication
        /// </summary>
        public static bool FacebookAuthentication
        {
            get
            {
                return Convert.ToBoolean(GetConfigParameter.GetConfigValue("FacebookAuthentication"));
            }
        }

        /// <summary>
        /// FacebookAuthenticationのClientId
        /// </summary>
        public static string FacebookAuthenticationClientId
        {
            get
            {
                return GetConfigParameter.GetConfigValue("FacebookAuthenticationClientId");
            }
        }

        /// <summary>
        /// FacebookAuthenticationのClientSecret
        /// </summary>
        public static string FacebookAuthenticationClientSecret
        {
            get
            {
                return GetConfigParameter.GetConfigValue("FacebookAuthenticationClientSecret");
            }
        }

        #endregion

        #region TwitterAuthentication

        /// <summary>
        /// TwitterAuthentication
        /// </summary>
        public static bool TwitterAuthentication
        {
            get
            {
                return Convert.ToBoolean(GetConfigParameter.GetConfigValue("TwitterAuthentication"));
            }
        }

        /// <summary>
        /// TwitterAuthenticationのClientId
        /// </summary>
        public static string TwitterAuthenticationClientId
        {
            get
            {
                return GetConfigParameter.GetConfigValue("TwitterAuthenticationClientId");
            }
        }

        /// <summary>
        /// TwitterAuthenticationのClientSecret
        /// </summary>
        public static string TwitterAuthenticationClientSecret
        {
            get
            {
                return GetConfigParameter.GetConfigValue("TwitterAuthenticationClientSecret");
            }
        }

        #endregion

        #endregion

        #endregion

        #region SecurityStamp

        /// <summary>
        /// SecurityStampの検証間隔
        /// </summary>
        public static TimeSpan SecurityStampValidateIntervalFromSeconds
        {
            get
            {
                return TimeSpan.FromSeconds(Double.Parse(GetConfigParameter.GetConfigValue("SecurityStampValidateIntervalFromSeconds")));
            }
        }

        #endregion

        #region 属性編集の可否

        /// <summary>
        /// CanEditEmail
        /// </summary>
        public static bool CanEditEmail
        {
            get
            {
                return Convert.ToBoolean(GetConfigParameter.GetConfigValue("CanEditEmail"));
            }
        }

        /// <summary>
        /// CanEditPhone
        /// </summary>
        public static bool CanEditPhone
        {
            get
            {
                return Convert.ToBoolean(GetConfigParameter.GetConfigValue("CanEditPhone"));
            }
        }

        /// <summary>
        /// CanEdit2FA
        /// </summary>
        public static bool CanEdit2FA
        {
            get
            {
                return Convert.ToBoolean(GetConfigParameter.GetConfigValue("CanEdit2FA"));
            }
        }

        /// <summary>
        /// CanEditUnstructuredData
        /// </summary>
        public static bool CanEditUnstructuredData
        {
            get
            {
                return Convert.ToBoolean(GetConfigParameter.GetConfigValue("CanEditUnstructuredData"));
            }
        }

        /// <summary>
        /// CanEditSaml2OAuth2Data
        /// </summary>
        public static bool CanEditSaml2OAuth2Data
        {
            get
            {
                return Convert.ToBoolean(GetConfigParameter.GetConfigValue("CanEditSaml2OAuth2Data"));
            }
        }        

        /// <summary>
        /// CanUseGdprFunction
        /// </summary>
        public static bool CanUseGdprFunction
        {
            get
            {
                return Convert.ToBoolean(GetConfigParameter.GetConfigValue("CanUseGdprFunction"));
            }
        }

        #region 複合

        /// <summary>
        /// CanEditExtLogin
        /// </summary>
        public static bool CanEditExtLogin
        {
            get
            {
                return
                    Config.MicrosoftAccountAuthentication
                    || Config.GoogleAuthentication
                    || Config.FacebookAuthentication;
            }
        }

        /// <summary>
        /// CanEditPayment
        /// </summary>
        public static bool CanEditPayment
        {
            get
            {
                return
                    Config.EnableStripe
                    || Config.EnablePAYJP;
            }
        }

        #endregion

        #endregion

        #region FIDO
        /*
        /// <summary>
        /// FIDOServerMode
        /// </summary>
        public static EnumFidoType FIDOServerMode
        {
            get
            {
                string temp = GetConfigParameter.GetConfigValue("FIDOServerMode");
                switch (temp.ToLower())
                {
                    case "webauthn":
                        return EnumFidoType.WebAuthn;
                    case "mspass":
                        return EnumFidoType.MsPass;
                    default:
                        return EnumFidoType.None;
                }
            }
        }
        */
        #endregion

        #region STS

        /// <summary>
        /// IssuerId
        /// </summary>
        public static string IssuerId
        {
            get
            {
                return GetConfigParameter.GetConfigValue("IssuerId");
            }
        }

        #region 証明書

        #region RSA

        /// <summary>
        /// RSA署名用証明書（*.pfx）のパスワード
        /// </summary>
        public static string RsaPfxPassword
        {
            get
            {
                return GetConfigParameter.GetConfigValue("RsaPfxPassword");
            }
        }

        /// <summary>
        /// RSA署名用証明書（*.pfx）のパス
        /// </summary>
        public static string RsaPfxFilePath
        {
            get
            {
                return GetConfigParameter.GetConfigValue("RsaPfxFilePath");
            }
        }

        #endregion

        #region ECDSA

        /// <summary>
        /// ECDSA署名用証明書（*.pfx）のパスワード
        /// </summary>
        public static string EcdsaPfxPassword
        {
            get
            {
                return GetConfigParameter.GetConfigValue("EcdsaPfxPassword");
            }
        }

        /// <summary>
        /// ECDSA署名用証明書（*.pfx）のパス
        /// </summary>
        public static string EcdsaPfxFilePath
        {
            get
            {
                return GetConfigParameter.GetConfigValue("EcdsaPfxFilePath");
            }
        }
        #endregion

        #endregion

        #region Saml2

        // 基本的に、OAuth2/OIDCインフラを流用

        /// <summary>
        /// SAML2 Assertionの有効期限（分）
        /// </summary>
        public static double Saml2AssertionExpireTimeSpanFromMinutes
        {
            get
            {
                return double.Parse(GetConfigParameter.GetConfigValue("OidcIdTokenExpireTimeSpanFromMinutes"));
            }
        }

        /// <summary>
        /// Saml2のRequestエンドポイント 
        /// </summary>
        public static string Saml2RequestEndpoint
        {
            get
            {
                return GetConfigParameter.GetConfigValue("Saml2RequestEndpoint");
            }
        }

        /// <summary>
        /// Saml2のResponseエンドポイント 
        /// </summary>
        public static string Saml2ResponseEndpoint
        {
            get
            {
                return GetConfigParameter.GetConfigValue("Saml2ResponseEndpoint");
            }
        }

        #endregion

        #region OAuth2

        #region OAuth2関連プロパティ

        #region ExpireTime

        /// <summary>
        /// OAuth2のAccessTokenの有効期限（分）
        /// </summary>
        public static TimeSpan OAuth2AccessTokenExpireTimeSpanFromMinutes
        {
            get
            {
                return TimeSpan.FromMinutes(int.Parse(GetConfigParameter.GetConfigValue("OAuth2AccessTokenExpireTimeSpanFromMinutes")));
            }
        }

        /// <summary>
        /// OAuth2の認可コードの有効期限（秒）（#188）
        /// </summary>
        /// <remarks>
        /// **RFC 6749 §4.1.2 は「短命（10 分以内を推奨）」を求めている。**
        /// 以前は CreatedDate を書くだけで読んでおらず、事実上の無期限だった。
        /// </remarks>
        public static TimeSpan OAuth2AuthorizationCodeExpireTimeSpanFromSeconds
        {
            get
            {
                return TimeSpan.FromSeconds(int.Parse(
                    GetConfigParameter.GetConfigValue("OAuth2AuthorizationCodeExpireTimeSpanFromSeconds")));
            }
        }

        /// <summary>
        /// Request Object（/ros に預けたもの）の有効期限（秒）（#188）
        /// </summary>
        /// <remarks>
        /// **預けてから認可要求に使うまでの短い時間だけ有効にする。**
        /// 以前は CreatedDate を書くだけで読んでおらず、事実上の無期限だった。
        /// </remarks>
        public static TimeSpan RequestObjectExpireTimeSpanFromSeconds
        {
            get
            {
                return TimeSpan.FromSeconds(int.Parse(
                    GetConfigParameter.GetConfigValue("RequestObjectExpireTimeSpanFromSeconds")));
            }
        }

        /// <summary>
        /// OAuth2のRefreshTokenの有効期限（日）
        /// </summary>
        public static TimeSpan OAuth2RefreshTokenExpireTimeSpanFromDays
        {
            get
            {
                return TimeSpan.FromDays(int.Parse(GetConfigParameter.GetConfigValue("OAuth2RefreshTokenExpireTimeSpanFromDays")));
            }
        }

        /// <summary>
        /// OIDCのIdTokenの有効期限（分）
        /// </summary>
        public static TimeSpan OidcIdTokenExpireTimeSpanFromMinutes
        {
            get
            {
                return TimeSpan.FromMinutes(int.Parse(GetConfigParameter.GetConfigValue("OidcIdTokenExpireTimeSpanFromMinutes")));
            }
        }

        /// <summary>
        /// Device AuthZのdevice_codeの有効期限（秒）
        /// </summary>
        public static int DeviceAuthZExpireTimeSpanFromSeconds
        {
            get
            {
                return int.Parse(GetConfigParameter.GetConfigValue("DeviceAuthZExpireTimeSpanFromSeconds"));
            }
        }        

        /// <summary>
        /// CIBAのauth_req_idの有効期限（秒）
        /// </summary>
        public static int CibaExpireTimeSpanFromSeconds
        {
            get
            {
                return int.Parse(GetConfigParameter.GetConfigValue("CibaExpireTimeSpanFromSeconds"));
            }
        }

        #endregion

        #region Interval

        /// <summary>
        /// Device AuthZのPollingのInterval（秒）
        /// </summary>
        public static int DeviceAuthZPollingIntervalSeconds
        {
            get
            {
                return int.Parse(GetConfigParameter.GetConfigValue("DeviceAuthZPollingIntervalSeconds"));
            }
        }

        /// <summary>
        /// CIBAのPollingのInterval（秒）
        /// </summary>
        public static int CibaPollingIntervalSeconds
        {
            get
            {
                return int.Parse(GetConfigParameter.GetConfigValue("CibaPollingIntervalSeconds"));
            }
        }

        #endregion

        #endregion

        #region AuthorizationServer関連

        #region Grant Typeの有効 / 無効

        /// <summary>EnableAuthorizationCodeGrantType</summary>
        public static bool EnableAuthorizationCodeGrantType
        {
            get
            {
                return Convert.ToBoolean(GetConfigParameter.GetConfigValue("EnableAuthorizationCodeGrantType"));
            }
        }

        /// <summary>EnableImplicitGrantType</summary>
        public static bool EnableImplicitGrantType
        {
            get
            {
                return Convert.ToBoolean(GetConfigParameter.GetConfigValue("EnableImplicitGrantType"));
            }
        }

        /// <summary>EnableResourceOwnerPasswordCredentialsGrantType</summary>
        public static bool EnableResourceOwnerPasswordCredentialsGrantType
        {
            get
            {
                return Convert.ToBoolean(GetConfigParameter.GetConfigValue("EnableResourceOwnerPasswordCredentialsGrantType"));
            }
        }

        /// <summary>EnableClientCredentialsGrantType</summary>
        public static bool EnableClientCredentialsGrantType
        {
            get
            {
                return Convert.ToBoolean(GetConfigParameter.GetConfigValue("EnableClientCredentialsGrantType"));
            }
        }

        /// <summary>EnableRefreshToken</summary>
        public static bool EnableRefreshToken
        {
            get
            {
                return Convert.ToBoolean(GetConfigParameter.GetConfigValue("EnableRefreshToken"));
            }
        }

        /// <summary>EnableJwtBearerTokenFlowGrantType</summary>
        public static bool EnableJwtBearerTokenFlowGrantType
        {
            get
            {
                return Convert.ToBoolean(GetConfigParameter.GetConfigValue("EnableJwtBearerTokenFlowGrantType"));
            }
        }

        /// <summary>EnableDeviceAuthZGrantType</summary>
        public static bool EnableDeviceAuthZGrantType
        {
            get
            {
                return Convert.ToBoolean(GetConfigParameter.GetConfigValue("EnableDeviceAuthZGrantType"));
            }
        }

        /// <summary>EnableCibaGrantType</summary>
        public static bool EnableCibaGrantType
        {
            get
            {
                return Convert.ToBoolean(GetConfigParameter.GetConfigValue("EnableCibaGrantType"));
            }
        }

        /// <summary>EnableOpenIDConnect</summary>
        public static bool EnableOpenIDConnect
        {
            get
            {
                return Convert.ToBoolean(GetConfigParameter.GetConfigValue("EnableOpenIDConnect"));
            }
        }

        #endregion

        #region エンドポイント 

        /// <summary>
        /// OAuth2のAuthorizationServerのEndpointのRootのURI
        /// </summary>
        public static string OAuth2AuthorizationServerEndpointsRootURI
        {
            get
            {
                return GetConfigParameter.GetConfigValue("OAuth2AuthorizationServerEndpointsRootURI");
            }
        }

        /// <summary>
        /// OAuth2ContainerizatedAuthSvrFqdnAndPort
        /// </summary>
        public static string OAuth2ContainerizatedAuthSvrFqdnAndPort
        {
            get
            {
                return GetConfigParameter.GetConfigValue("OAuth2ContainerizatedAuthSvrFqdnAndPort");
            }
        }

        /// <summary>
        /// OAuth2ContainerizatedAuthSvrEPRootURI
        /// </summary>
        public static string OAuth2ContainerizatedAuthSvrEPRootURI
        {
            get
            {
                return GetConfigParameter.GetConfigValue("OAuth2ContainerizatedAuthSvrEPRootURI");
            }
        }

        #region 既定

        /// <summary>
        /// OAuth2のAuthorizeエンドポイント 
        /// </summary>
        public static string OAuth2AuthorizeEndpoint
        {
            get
            {
                return GetConfigParameter.GetConfigValue("OAuth2AuthorizeEndpoint");
            }
        }

        /// <summary>
        /// OAuth2のTokenエンドポイント 
        /// </summary>
        public static string OAuth2TokenEndpoint
        {
            get
            {
                return GetConfigParameter.GetConfigValue("OAuth2TokenEndpoint");
            }
        }

        #endregion

        #region OAuth2拡張

        #region Device AuthZ
        /// <summary>
        /// Device AuthZのAuthorizeエンドポイント 
        /// </summary>
        public static string DeviceAuthZAuthorizeEndpoint
        {
            get
            {
                return GetConfigParameter.GetConfigValue("DeviceAuthZAuthorizeEndpoint");
            }
        }

        /// <summary>
        /// Device AuthZの検証用エンドポイント
        /// </summary>
        public static string DeviceAuthZVerifyEndpoint
        {
            get
            {
                return GetConfigParameter.GetConfigValue("DeviceAuthZVerifyEndpoint");
            }
        }

        // Tokenエンドポイントは共用。

        #endregion

        #region CIBA
        /// <summary>
        /// CIBAのAuthorizeエンドポイント 
        /// </summary>
        public static string CibaAuthorizeEndpoint
        {
            get
            {
                return GetConfigParameter.GetConfigValue("CibaAuthorizeEndpoint");
            }
        }

        /// <summary>
        /// CIBAのプッッシュ結果を受信するエンドポイント
        /// </summary>
        public static string CibaPushResultEndpoint
        {
            get
            {
                return GetConfigParameter.GetConfigValue("CibaPushResultEndpoint");
            }
        }

        // Tokenエンドポイントは共用。

        #endregion

        #region WebAPI

        /// <summary>
        /// OAuth2/OIDCのUserInfoエンドポイント 
        /// </summary>
        public static string OAuth2UserInfoEndpoint
        {
            get
            {
                return GetConfigParameter.GetConfigValue("OAuth2UserInfoEndpoint");
            }
        }

        /// <summary>
        /// OAuth2のRevokeエンドポイント 
        /// </summary>
        public static string OAuth2RevokeTokenEndpoint
        {
            get
            {
                return GetConfigParameter.GetConfigValue("OAuth2RevokeTokenEndpoint");
            }
        }

        /// <summary>
        /// OAuth2のIntrospectエンドポイント 
        /// </summary>
        public static string OAuth2IntrospectTokenEndpoint
        {
            get
            {
                return GetConfigParameter.GetConfigValue("OAuth2IntrospectTokenEndpoint");
            }
        }

        #endregion

        #endregion

        #region その他

        #region Token取得用

        /// <summary>
        /// ManageController.OAuth2AuthorizationCodeGrantClientのRedirectエンドポイント
        /// </summary>
        public static string OAuth2AuthorizationCodeGrantClient_Manage
        {
            get
            {
                return GetConfigParameter.GetConfigValue("OAuth2AuthorizationCodeGrantClient_Manage");
            }
        }

        #endregion

        #region WebAPI

        /// <summary>
        /// Hybrid Flowのテスト用WebAPI
        /// </summary>
        public static string TestHybridFlowWebAPI
        {
            get
            {
                return GetConfigParameter.GetConfigValue("TestHybridFlowWebAPI");
            }
        }

        /// <summary>
        /// ユーザ情報に課金するWebAPI
        /// </summary>
        public static string ChageToUserWebAPI
        {
            get
            {
                return GetConfigParameter.GetConfigValue("ChageToUserWebAPI");
            }
        }

        /// <summary>
        /// ユーザ情報にデバイス・トークンを追加するWebAPI
        /// </summary>
        public static string SetDeviceTokenWebAPI
        {
            get
            {
                return GetConfigParameter.GetConfigValue("SetDeviceTokenWebAPI");
            }
        }

        /// <summary>
        /// 2FAのプッシュ承認を受信するWebAPI（#213）
        /// </summary>
        public static string TwoFactorPushResultEndpoint
        {
            get
            {
                return GetConfigParameter.GetConfigValue("TwoFactorPushResultEndpoint");
            }
        }

        #endregion

        #endregion

        #endregion

        #endregion

        #region Client関連

        #region 静的設定

        /// <summary>
        /// OAuth2のClientのInformation
        /// </summary>
        public static Dictionary<string, Dictionary<string, string>> OAuth2ClientsInformation
        {
            get
            {
#if NETFX
                return JsonConvert.DeserializeObject<Dictionary<string, Dictionary<string, string>>>(
                    GetConfigParameter.GetConfigValue("OAuth2ClientsInformation"));
#else
                IConfigurationSection section = GetConfigParameter
                    .GetAnyConfigSection("appSettings:OAuth2ClientsInformation");

                return section.Get<Dictionary<string, Dictionary<string, string>>>();
#endif
            }
        }

        /// <summary>
        /// profile / address のクレームの対応付け（#230）
        /// </summary>
        /// <remarks>
        /// **「どのキーを、どのクレームとして返すか」だけを持つ。**
        /// 値の在り処は `ApplicationUser.UnstructuredData`（JSON）の中のパス、
        /// または `user:&lt;項目&gt;`（白名簿。<see cref="Extensions.Sts.UserClaims"/>）。
        ///
        /// **既定は空で、何も返らない**（従来どおり）。設定した分だけ返る。
        /// どのクレームがどの scope に属するかは**仕様が決めている**ので、ここには書かせない
        /// （OIDC Core §5.4。表は `UserClaims`）。
        ///
        /// 読み方は `OAuth2ClientsInformation` と同じ（net48 は JSON 文字列、net10.0 は節）。
        /// </remarks>
        public static Dictionary<string, string> UserClaimsMapping
        {
            get
            {
                Dictionary<string, string> mapping = null;

#if NETFX
                string json = GetConfigParameter.GetConfigValue("UserClaimsMapping");

                if (!string.IsNullOrEmpty(json))
                {
                    mapping = JsonConvert.DeserializeObject<Dictionary<string, string>>(json);
                }
#else
                IConfigurationSection section = GetConfigParameter
                    .GetAnyConfigSection("appSettings:UserClaimsMapping");

                if (section != null)
                {
                    mapping = section.Get<Dictionary<string, string>>();
                }
#endif
                // **未設定・空は「対応付け無し」として扱う。** null を返して呼び先を壊さない。
                return mapping ?? new Dictionary<string, string>();
            }
        }

        #endregion

        #region エンドポイント

        /// <summary>
        /// OAuth2のClientのEndpointのRootURI
        /// </summary>
        public static string OAuth2ClientEndpointsRootURI
        {
            get
            {
                return GetConfigParameter.GetConfigValue("OAuth2ClientEndpointsRootURI");
            }
        }

        #region Redirect

        /// <summary>
        /// AccountController.OAuth2AuthorizationCodeGrantClientのRedirectエンドポイント
        /// </summary>
        public static string OAuth2AuthorizationCodeGrantClient_Account
        {
            get
            {
                return GetConfigParameter.GetConfigValue("OAuth2AuthorizationCodeGrantClient_Account");
            }
        }

        /// <summary>
        /// AccountController.OAuth2ImplicitGrantClientのRedirectエンドポイント
        /// </summary>
        public static string OAuth2ImplicitGrantClient_Account
        {
            get
            {
                return GetConfigParameter.GetConfigValue("OAuth2ImplicitGrantClient_Account");
            }
        }
        
        /// <summary>
        /// テスト用のエンドポイントがロックダウンされているかどうか。
        /// </summary>
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
        /// <summary>
        /// PKCE で S256 だけを受け付けるかどうか（#220）
        /// </summary>
        /// <remarks>
        /// OAuth 2.1 / FAPI は S256 のみを許す。plain は保護にならない。
        /// **既定は false（従来どおり plain も受理）。** 下位互換のため。
        /// </remarks>
        public static bool RequirePkceS256
        {
            get
            {
                return Convert.ToBoolean(GetConfigParameter.GetConfigValue("RequirePkceS256"));
            }
        }

        /// <summary>
        /// PAR（RFC 9126）のエンドポイント（#229）
        /// </summary>
        /// <remarks>
        /// **独自の /ros（Request Object の預け先）とは別の口。**
        /// /ros は署名付き JWT を生の本文で受け、クライアント認証をしない（後方互換のため残す）。
        /// こちらは RFC 9126 のとおり、**フォーム形式＋クライアント認証**で受ける。
        ///
        /// **キー名は `AuthRequestPushUri`**（#236 で改名。旧 `PushedAuthorizationRequestEndpoint`）。
        /// `RequestObjectRegUri` と同じく**クライアント側も読む設定**なので、名前をそちらに寄せた。
        /// **Open棟梁 の OAuth2AndOIDCParams に移す予定**で、それまでは、ここで読む。
        /// </remarks>
        public static string AuthRequestPushUri
        {
            get
            {
                return GetConfigParameter.GetConfigValue("AuthRequestPushUri");
            }
        }

        /// <summary>
        /// Discovery の service_documentation（この IdP の使い方を書いた文書の URL）（#228）
        /// </summary>
        /// <remarks>
        /// **任意の項目**（OIDC Discovery 1.0 §3）。**既定は空で、空なら Discovery に出さない。**
        /// 以前は "・・・" というプレースホルダを配っていた。
        /// </remarks>
        public static string ServiceDocumentation
        {
            get
            {
                return GetConfigParameter.GetConfigValue("ServiceDocumentation");
            }
        }

        /// <summary>
        /// 認可コード フローで code_challenge（PKCE）を必須にするかどうか（#220）
        /// </summary>
        /// <remarks>
        /// OAuth 2.1 は、クライアントの種別によらず PKCE を必須とする。
        /// **既定は false（従来どおり PKCE 無しでも通る）。** 下位互換のため。
        ///
        /// **RequirePkceS256 とは別のもの。**
        /// - RequirePkce     : PKCE 自体を求める（認可エンドポイントで判定）
        /// - RequirePkceS256 : 使うなら S256 に限る（トークン エンドポイントで判定）
        ///
        /// Device AuthZ / CIBA は認可エンドポイントを通らないので、この判定に掛からない。
        /// </remarks>
        public static bool RequirePkce
        {
            get
            {
                return Convert.ToBoolean(GetConfigParameter.GetConfigValue("RequirePkce"));
            }
        }


        #region 改名した設定キー

        /// <summary>改名した設定キー（新しい名前 → 改名前の名前。#236）</summary>
        /// <remarks>
        /// **改名しても、旧いキー名を読み続ける**（#219 で始めた扱い）。
        /// 設定ファイルは配備済みのものがあり、**改名だけで黙って既定値に戻ると危ない**ため。
        /// 旧いキー名だけが設定されている場合は、起動時に ProductionCheck が警告する。
        ///
        /// **ここに載せたキーは、Config 側も新しい名前で読むこと**
        /// （<see cref="GetRenamedConfigValue"/> を通す）。
        /// </remarks>
        public static readonly Dictionary<string, string> RenamedKeys =
            new Dictionary<string, string>()
            {
                // テスト用の口をまとめて閉じるキー（#219）
                { "IsLockedDownTestEndpoints", "IsLockedDownRedirectEndpoint" },
                // 綴りの誤り（Enabe → Enable。#236）
                { "EnableDebugTraceLog", "EnabeDebugTraceLog" },
                // EndPoint → Endpoint（この実装の他のキーに揃えた。#236）
                { "IdFederationAuthorizeEndpoint", "IdFederationAuthorizeEndPoint" },
                { "IdFederationRedirectEndpoint", "IdFederationRedirectEndPoint" },
                { "IdFederationTokenEndpoint", "IdFederationTokenEndPoint" },
                { "IdFederationUserInfoEndpoint", "IdFederationUserInfoEndPoint" },
            };

        /// <summary>改名した設定キーの値を読む（新しい名前を優先し、無ければ旧い名前）</summary>
        /// <param name="key">新しいキー名（<see cref="RenamedKeys"/> に載っているもの）</param>
        /// <returns>値</returns>
        private static string GetRenamedConfigValue(string key)
        {
            string value = GetConfigParameter.GetConfigValue(key);

            if (string.IsNullOrEmpty(value))
            {
                value = GetConfigParameter.GetConfigValue(Config.RenamedKeys[key]);
            }

            return value;
        }

        /// <summary>
        /// 旧いキー名だけが設定されているものを返す（起動時の警告に使う）
        /// </summary>
        /// <returns>「旧いキー名 → 新しいキー名」の一覧（無ければ空）</returns>
        public static List<KeyValuePair<string, string>> OldKeysStillUsed()
        {
            List<KeyValuePair<string, string>> used = new List<KeyValuePair<string, string>>();

            foreach (KeyValuePair<string, string> renamed in Config.RenamedKeys)
            {
                if (string.IsNullOrEmpty(GetConfigParameter.GetConfigValue(renamed.Key))
                    && !string.IsNullOrEmpty(GetConfigParameter.GetConfigValue(renamed.Value)))
                {
                    used.Add(new KeyValuePair<string, string>(renamed.Value, renamed.Key));
                }
            }

            return used;
        }

        #endregion

        #endregion

        #endregion

        #endregion

        #region ResourceServer関連

        #region エンドポイント

        ///// <summary>
        ///// OAuth2のResourceServerのEndpointのRootURI
        ///// </summary>
        //public static string OAuth2ResourceServerEndpointsRootURI
        //{
        //    get
        //    {
        //        return GetConfigParameter.GetConfigValue("OAuth2ResourceServerEndpointsRootURI");
        //    }
        //}

        #endregion

        #endregion

        #endregion

        #endregion

        #region 外部サービス

        #region オンライン決済サービス

        #region Stripe

        /// <summary>EnableStripe</summary>
        public static bool EnableStripe
        {
            get
            {
                return Convert.ToBoolean(GetConfigParameter.GetConfigValue("EnableStripe"));
            }
        }

        /// <summary>Stripeのpublicキー</summary>
        public static string Stripe_PK
        {
            get
            {
                return GetConfigParameter.GetConfigValue("Stripe_PK");
            }
        }

        /// <summary>Stripeのprivateキー</summary>
        public static string Stripe_SK
        {
            get
            {
                return GetConfigParameter.GetConfigValue("Stripe_SK");
            }
        }

        #endregion

        #region PAY.JP

        /// <summary>EnablePAYJP</summary>
        public static bool EnablePAYJP
        {
            get
            {
                return Convert.ToBoolean(GetConfigParameter.GetConfigValue("EnablePAYJP"));
            }
        }

        /// <summary>PAY.JPのpublicキー</summary>
        public static string PAYJP_PK
        {
            get
            {
                return GetConfigParameter.GetConfigValue("PAYJP_PK");
            }
        }

        /// <summary>PAY.JPのprivateキー</summary>
        public static string PAYJP_SK
        {
            get
            {
                return GetConfigParameter.GetConfigValue("PAYJP_SK");
            }
        }

        #endregion

        #endregion

        #endregion

        #region 機能ロックダウン（STS専用モード）

        /// <summary>
        /// EnableSignupProcess
        /// </summary>
        public static bool EnableSignupProcess
        {
            get
            {
                return Convert.ToBoolean(GetConfigParameter.GetConfigValue("EnableSignupProcess"));
            }
        }

        /// <summary>
        /// EnableEditingOfUserAttribute
        /// </summary>
        public static bool EnableEditingOfUserAttribute
        {
            get
            {
                return Convert.ToBoolean(GetConfigParameter.GetConfigValue("EnableEditingOfUserAttribute"));
            }
        }

        /// <summary>
        /// EnableAdministrationOfUsersAndRoles
        /// </summary>
        public static bool EnableAdministrationOfUsersAndRoles
        {
            get
            {
                return Convert.ToBoolean(GetConfigParameter.GetConfigValue("EnableAdministrationOfUsersAndRoles"));
            }
        }

        #endregion

        #region IDフェデレーション関連

        /// <summary>
        /// IDフェデレーション時の認可エンドポイント
        /// </summary>
        public static string IdFederationAuthorizeEndpoint
        {
            get
            {
                return Config.GetRenamedConfigValue("IdFederationAuthorizeEndpoint");
            }
        }

        /// <summary>
        /// IDフェデレーション時のRedirectエンドポイント
        /// </summary>
        public static string IdFederationRedirectEndpoint
        {
            get
            {
                return Config.GetRenamedConfigValue("IdFederationRedirectEndpoint");
            }
        }

        /// <summary>
        /// IDフェデレーション時のTokenエンドポイント
        /// </summary>
        public static string IdFederationTokenEndpoint
        {
            get
            {
                return Config.GetRenamedConfigValue("IdFederationTokenEndpoint");
            }
        }

        /// <summary>
        /// IDフェデレーション時のUserInfoエンドポイント
        /// </summary>
        public static string IdFederationUserInfoEndpoint
        {
            get
            {
                return Config.GetRenamedConfigValue("IdFederationUserInfoEndpoint");
            }
        }

        #endregion
    }
}