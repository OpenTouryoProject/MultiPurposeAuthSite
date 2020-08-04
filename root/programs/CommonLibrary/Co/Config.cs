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
//*  2020/02/27  西野 大介         プッシュ通知、CIBA対応実施
//*  2020/06/19  西野 大介         GetConfigSectionメソッドを廃止に伴う変更
//*                                GetConfigSection → GetAnyConfigSection
//*  2020/08/04  西野 大介         コンテナ化対応実施
//**********************************************************************************

using MultiPurposeAuthSite.Data;
using MultiPurposeAuthSite.Extensions.FIDO;

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
        public static bool EnabeDebugTraceLog
        {
            get
            {
                return Convert.ToBoolean(GetConfigParameter.GetConfigValue("EnabeDebugTraceLog"));
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
        /// CIBAのauth_req_idの有効期限（秒）
        /// </summary>
        public static int CibaExpireTimeSpanFromSeconds
        {
            get
            {
                return int.Parse(GetConfigParameter.GetConfigValue("CibaExpireTimeSpanFromSeconds"));
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
        /// 2FAのプッッシュ結果を受信するWebAPI
        /// </summary>
        public static string TwoFactorAuthPushResultWebAPI
        {
            get
            {
                return GetConfigParameter.GetConfigValue("TwoFactorAuthPushResultWebAPI");
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
        /// Redirectエンドポイントがロックダウンされているかどうか。
        /// </summary>
        public static bool IsLockedDownRedirectEndpoint
        {
            get
            {
                return Convert.ToBoolean(GetConfigParameter.GetConfigValue("IsLockedDownRedirectEndpoint"));
            }
        }

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
        public static string IdFederationAuthorizeEndPoint
        {
            get
            {
                return GetConfigParameter.GetConfigValue("IdFederationAuthorizeEndPoint");
            }
        }

        /// <summary>
        /// IDフェデレーション時のRedirectエンドポイント
        /// </summary>
        public static string IdFederationRedirectEndPoint
        {
            get
            {
                return GetConfigParameter.GetConfigValue("IdFederationRedirectEndPoint");
            }
        }

        /// <summary>
        /// IDフェデレーション時のTokenエンドポイント
        /// </summary>
        public static string IdFederationTokenEndPoint
        {
            get
            {
                return GetConfigParameter.GetConfigValue("IdFederationTokenEndPoint");
            }
        }

        /// <summary>
        /// IDフェデレーション時のUserInfoエンドポイント
        /// </summary>
        public static string IdFederationUserInfoEndPoint
        {
            get
            {
                return GetConfigParameter.GetConfigValue("IdFederationUserInfoEndPoint");
            }
        }

        #endregion
    }
}