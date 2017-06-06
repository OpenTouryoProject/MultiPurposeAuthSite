//**********************************************************************************
//* Copyright (C) 2007,2016 Hitachi Solutions,Ltd.
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
//* クラス名        ：ASPNETIdentityConfig
//* クラス日本語名  ：ASP.NET IdentityのConfigクラス（ライブラリ）
//*
//* 作成日時        ：－
//* 作成者          ：－
//* 更新履歴        ：－
//*
//*  日時        更新者            内容
//*  ----------  ----------------  -------------------------------------------------
//*  2017/04/24  西野 大介         新規
//**********************************************************************************

using System;
using System.Configuration;

/// <summary>MultiPurposeAuthSite.Models.ASPNETIdentity</summary>
namespace MultiPurposeAuthSite.Models.ASPNETIdentity
{
    /// <summary>列挙型</summary>
    public enum EnumUserStoreType
    {
        /// <summary>Memory Provider</summary>
        Memory,
        /// <summary>DBMS Provider (SqlServer)</summary>
        SqlServer,
        /// <summary>DBMS Provider (Oracle Manage Driver)</summary>
        OracleMD,
        /// <summary>DBMS Provider (PostgreSQL)</summary>
        PostgreSQL
    }

    /// <summary>ASPNETIdentityConfig</summary>
    public class ASPNETIdentityConfig
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
                return Convert.ToBoolean(ConfigurationManager.AppSettings["UseInternetProxy"]);
            }
        }

        /// <summary>
        /// InternetプロキシURL
        /// </summary>
        public static string InternetProxyURL
        {
            get
            {
                return ConfigurationManager.AppSettings["InternetProxyURL"];
            }
        }

        /// <summary>
        /// InternetプロキシUID
        /// </summary>
        public static string InternetProxyUID
        {
            get
            {
                return ConfigurationManager.AppSettings["InternetProxyUID"];
            }
        }

        /// <summary>
        /// InternetプロキシPWD
        /// </summary>
        public static string InternetProxyPWD
        {
            get
            {
                return ConfigurationManager.AppSettings["InternetProxyPWD"];
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
                return Convert.ToBoolean(ConfigurationManager.AppSettings["UseIntranetProxy"]);
            }
        }

        /// <summary>
        /// IntranetプロキシURL
        /// </summary>
        public static string IntranetProxyURL
        {
            get
            {
                return ConfigurationManager.AppSettings["IntranetProxyURL"];
            }
        }

        /// <summary>
        /// IntranetプロキシUID
        /// </summary>
        public static string IntranetProxyUID
        {
            get
            {
                return ConfigurationManager.AppSettings["IntranetProxyUID"];
            }
        }

        /// <summary>
        /// IntranetプロキシPWD
        /// </summary>
        public static string IntranetProxyPWD
        {
            get
            {
                return ConfigurationManager.AppSettings["IntranetProxyPWD"];
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
                return Convert.ToBoolean(ConfigurationManager.AppSettings["UseDebugProxy"]);
            }
        }

        /// <summary>
        /// DebugProxyURL
        /// </summary>
        public static string DebugProxyURL
        {
            get
            {
                return ConfigurationManager.AppSettings["DebugProxyURL"];
            }
        }

        /// <summary>
        /// DebugProxyUID
        /// </summary>
        public static string DebugProxyUID
        {
            get
            {
                return ConfigurationManager.AppSettings["DebugProxyUID"];
            }
        }

        /// <summary>
        /// DebugProxyPWD
        /// </summary>
        public static string DebugProxyPWD
        {
            get
            {
                return ConfigurationManager.AppSettings["DebugProxyPWD"];
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
                if (ASPNETIdentityConfig.UserStoreType == EnumUserStoreType.Memory)
                {
                    return true; // Memory Provider 利用時は = Debug 扱い。
                }
                else
                {
                    return Convert.ToBoolean(ConfigurationManager.AppSettings["IsDebug"]);
                }
            }
        }

        /// <summary>UserStoreのTypeを返す。</summary>
        public static EnumUserStoreType UserStoreType
        {
            get
            {
                switch (ConfigurationManager.AppSettings["UserStoreType"].ToUpper())
                {
                    case "MEM":
                        return EnumUserStoreType.Memory;
                    case "SQL":
                        return EnumUserStoreType.SqlServer;
                    case "ORA":
                        return EnumUserStoreType.OracleMD;
                    case "NPG":
                        return EnumUserStoreType.PostgreSQL;
                    default:
                        return EnumUserStoreType.Memory;
                }
            }
        }

        #endregion

        #region マルチテナント

        /// <summary>マルチテナント</summary>
        public static bool MultiTenant
        {
            get
            {
                return Convert.ToBoolean(ConfigurationManager.AppSettings["Multi-tenant"]);
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
                return Convert.ToInt32(ConfigurationManager.AppSettings["UserListCount"]);
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
                return ConfigurationManager.AppSettings["AdministratorUID"];
            }
        }

        /// <summary>AdministratorPWD</summary>
        public static string AdministratorPWD
        {
            get
            {
                return ConfigurationManager.AppSettings["AdministratorPWD"];
            }
        }

        #endregion

        /// <summary>TestUserPWD</summary>
        public static string TestUserPWD
        {
            get
            {
                return ConfigurationManager.AppSettings["TestUserPWD"];
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
                return ConfigurationManager.AppSettings["SmtpHostName"];
            }
        }

        /// <summary>SmtpPortNo</summary>
        public static int SmtpPortNo
        {
            get
            {
                return Convert.ToInt32(ConfigurationManager.AppSettings["SmtpPortNo"]);
            }
        }

        /// <summary>SmtpSSL</summary>
        public static bool SmtpSSL
        {
            get
            {
                return Convert.ToBoolean(ConfigurationManager.AppSettings["SmtpSSL"]);
            }
        }

        /// <summary>SmtpAccountUID</summary>
        public static string SmtpAccountUID
        {
            get
            {
                return ConfigurationManager.AppSettings["SmtpAccountUID"];
            }
        }

        /// <summary>SmtpAccountPWD</summary>
        public static string SmtpAccountPWD
        {
            get
            {
                return ConfigurationManager.AppSettings["SmtpAccountPWD"];
            }
        }

        #endregion

        #region SMS (Twilio)

        /// <summary>TwilioAccountSid</summary>
        public static string TwilioAccountSid
        {
            get
            {
                return ConfigurationManager.AppSettings["TwilioAccountSid"];
            }
        }

        /// <summary>TwilioAuthToken</summary>
        public static string TwilioAuthToken
        {
            get
            {
                return ConfigurationManager.AppSettings["TwilioAuthToken"];
            }
        }

        /// <summary>TwilioFromPhoneNumber</summary>
        public static string TwilioFromPhoneNumber
        {
            get
            {
                return ConfigurationManager.AppSettings["TwilioFromPhoneNumber"];
            }
        }

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
                return TimeSpan.FromSeconds(Double.Parse(ConfigurationManager.AppSettings["SecurityStampValidateIntervalFromSeconds"]));
            }
        }

        #endregion

        #region ユーザ名検証

        /// <summary>
        /// ユーザ名検証（アルファベットと数値のみ）
        /// </summary>
        public static bool AllowOnlyAlphanumericUserNames
        {
            get
            {
                return Convert.ToBoolean(ConfigurationManager.AppSettings["AllowOnlyAlphanumericUserNames"]);
            }
        }

        /// <summary>
        /// ユーザ名検証（E-mail形式で要求）
        /// </summary>
        public static bool RequireUniqueEmail
        {
            get
            {
                return Convert.ToBoolean(ConfigurationManager.AppSettings["RequireUniqueEmail"]);
            }
        }

        /// <summary>
        /// ユーザ名の編集許可
        /// </summary>
        public static bool AllowEditingUserName
        {
            get
            {
                return Convert.ToBoolean(ConfigurationManager.AppSettings["AllowEditingUserName"]);
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
                return Convert.ToInt32(ConfigurationManager.AppSettings["RequiredLength"]);
            }
        }

        /// <summary>
        /// パスワード検証（記号の要求）
        /// </summary>
        public static bool RequireNonLetterOrDigit
        {
            get
            {
                return Convert.ToBoolean(ConfigurationManager.AppSettings["RequireNonLetterOrDigit"]);
            }
        }

        /// <summary>
        /// パスワード検証（数値の要求）
        /// </summary>
        public static bool RequireDigit
        {
            get
            {
                return Convert.ToBoolean(ConfigurationManager.AppSettings["RequireDigit"]);
            }
        }

        /// <summary>
        /// パスワード検証（小文字の要求）
        /// </summary>
        public static bool RequireLowercase
        {
            get
            {
                return Convert.ToBoolean(ConfigurationManager.AppSettings["RequireLowercase"]);
            }
        }

        /// <summary>
        /// パスワード検証（大文字の要求）
        /// </summary>
        public static bool RequireUppercase
        {
            get
            {
                return Convert.ToBoolean(ConfigurationManager.AppSettings["RequireUppercase"]);
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
                return Convert.ToBoolean(ConfigurationManager.AppSettings["UserLockoutEnabledByDefault"]);
            }
        }

        /// <summary>
        /// ユーザ ロックアウトの期間
        /// </summary>
        public static TimeSpan DefaultAccountLockoutTimeSpanFromSeconds
        {
            get
            {
                return TimeSpan.FromSeconds(Double.Parse(ConfigurationManager.AppSettings["DefaultAccountLockoutTimeSpanFromSeconds"]));
            }
        }

        /// <summary>
        /// ユーザ ロックアウトされるまでのサインインの失敗回数
        /// </summary>
        public static int MaxFailedAccessAttemptsBeforeLockout
        {
            get
            {
                return Convert.ToInt32(ConfigurationManager.AppSettings["MaxFailedAccessAttemptsBeforeLockout"]);
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
                return Convert.ToBoolean(ConfigurationManager.AppSettings["TwoFactorEnabled"]);
            }
        }

        /// <summary>
        /// 2FAのCookieの有効期限
        /// </summary>
        public static TimeSpan TwoFactorCookieExpiresFromHours
        {
            get
            {
                return TimeSpan.FromHours(Double.Parse(ConfigurationManager.AppSettings["TwoFactorCookieExpiresFromHours"]));
            }
        }

        #endregion

        #region 外部ログイン

        /// <summary>
        /// Used for XSRF protection when adding external logins
        /// 外部ログインの追加時に XSRF の防止に使用します
        /// </summary>
        public static string XsrfKey
        {
            get
            {
                return ConfigurationManager.AppSettings["XsrfKey"];
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
                return Convert.ToBoolean(ConfigurationManager.AppSettings["MicrosoftAccountAuthentication"]);
            }
        }

        /// <summary>
        /// MicrosoftAccountAuthenticationのClientId
        /// </summary>
        public static string MicrosoftAccountAuthenticationClientId
        {
            get
            {
                return ConfigurationManager.AppSettings["MicrosoftAccountAuthenticationClientId"];
            }
        }

        /// <summary>
        /// MicrosoftAccountAuthenticationのClientSecret
        /// </summary>
        public static string MicrosoftAccountAuthenticationClientSecret
        {
            get
            {
                return ConfigurationManager.AppSettings["MicrosoftAccountAuthenticationClientSecret"];
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
                return Convert.ToBoolean(ConfigurationManager.AppSettings["GoogleAuthentication"]);
            }
        }

        /// <summary>
        /// GoogleAuthenticationのClientId
        /// </summary>
        public static string GoogleAuthenticationClientId
        {
            get
            {
                return ConfigurationManager.AppSettings["GoogleAuthenticationClientId"];
            }
        }

        /// <summary>
        /// GoogleAuthenticationのClientSecret
        /// </summary>
        public static string GoogleAuthenticationClientSecret
        {
            get
            {
                return ConfigurationManager.AppSettings["GoogleAuthenticationClientSecret"];
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
                return Convert.ToBoolean(ConfigurationManager.AppSettings["FacebookAuthentication"]);
            }
        }

        /// <summary>
        /// FacebookAuthenticationのClientId
        /// </summary>
        public static string FacebookAuthenticationClientId
        {
            get
            {
                return ConfigurationManager.AppSettings["FacebookAuthenticationClientId"];
            }
        }

        /// <summary>
        /// FacebookAuthenticationのClientSecret
        /// </summary>
        public static string FacebookAuthenticationClientSecret
        {
            get
            {
                return ConfigurationManager.AppSettings["FacebookAuthenticationClientSecret"];
            }
        }

        #endregion

        #endregion

        #region 属性編集の可否

        /// <summary>
        /// CanEditEmail
        /// </summary>
        public static bool CanEditEmail
        {
            get
            {
                return Convert.ToBoolean(ConfigurationManager.AppSettings["CanEditEmail"]);
            }
        }

        /// <summary>
        /// CanEditPhone
        /// </summary>
        public static bool CanEditPhone
        {
            get
            {
                return Convert.ToBoolean(ConfigurationManager.AppSettings["CanEditPhone"]);
            }
        }

        /// <summary>
        /// CanEdit2FA
        /// </summary>
        public static bool CanEdit2FA
        {
            get
            {
                return Convert.ToBoolean(ConfigurationManager.AppSettings["CanEdit2FA"]);
            }
        }

        /// <summary>
        /// CanEditUnstructuredData
        /// </summary>
        public static bool CanEditUnstructuredData
        {
            get
            {
                return Convert.ToBoolean(ConfigurationManager.AppSettings["CanEditUnstructuredData"]);
            }
        }

        /// <summary>
        /// CanEditExtLogin
        /// </summary>
        public static bool CanEditExtLogin
        {
            get
            {
                return
                    ASPNETIdentityConfig.MicrosoftAccountAuthentication
                    || ASPNETIdentityConfig.GoogleAuthentication
                    || ASPNETIdentityConfig.FacebookAuthentication;
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
                    ASPNETIdentityConfig.EnableStripe
                    || ASPNETIdentityConfig.EnablePAYJP;
            }
        }

        #endregion

        #region OAuth Client & Server

        #region 共通設定

        /// <summary>
        /// OAuthServerを実装しているか・どうか
        /// </summary>
        public static bool EquipOAuthServer
        {
            get
            {
                return Convert.ToBoolean(ConfigurationManager.AppSettings["EquipOAuthServer"]);
            }
        }

        #region プロパティ

        /// <summary>
        /// OAuthのAllowInsecureHttpEndpointsプロパティ値
        /// </summary>
        public static bool AllowOAuthInsecureHttpEndpoints
        {
            get
            {
                return Convert.ToBoolean(ConfigurationManager.AppSettings["AllowOAuthInsecureHttpEndpoints"]);
            }
        }

        /// <summary>
        /// OAuthのAuthorizeEndpointCanDisplayErrorsプロパティ値
        /// </summary>
        public static bool OAuthAuthorizeEndpointCanDisplayErrors
        {
            get
            {
                return Convert.ToBoolean(ConfigurationManager.AppSettings["OAuthAuthorizeEndpointCanDisplayErrors"]);
            }
        }

        /// <summary>
        /// OAuthのAccessTokenの有効期限
        /// </summary>
        public static TimeSpan OAuthAccessTokenExpireTimeSpanFromMinutes
        {
            get
            {
                return TimeSpan.FromMinutes(int.Parse(ConfigurationManager.AppSettings["OAuthAccessTokenExpireTimeSpanFromMinutes"]));
            }
        }

        /// <summary>
        /// OAuthのRefreshTokenの有効期限
        /// </summary>
        public static TimeSpan OAuthRefreshTokenExpireTimeSpanFromDays
        {
            get
            {
                return TimeSpan.FromDays(int.Parse(ConfigurationManager.AppSettings["OAuthRefreshTokenExpireTimeSpanFromDays"]));
            }
        }


        #endregion

        #region JWT

        /// <summary>
        /// Custom Token Format (JWT) のサポート
        /// </summary>
        public static bool EnableCustomTokenFormat
        {
            get
            {
                return Convert.ToBoolean(ConfigurationManager.AppSettings["EnableCustomTokenFormat"]);
            }
        }

        /// <summary>
        /// JWTのIssuerId (OAuth Server)
        /// </summary>
        public static string OAuthIssuerId
        {
            get
            {
                return ConfigurationManager.AppSettings["OAuthIssuerId"];
            }
        }

        #region 証明書

        /// <summary>
        /// OAuthのAccess Tokenに使用するJWTの署名用証明書（*.pfx）のパスワード
        /// </summary>
        public static string OAuthJWTPassword
        {
            get
            {
                return ConfigurationManager.AppSettings["OAuthJWTPassword"];
            }
        }

        /// <summary>
        /// OAuthのAccess Tokenに使用するJWTの署名用証明書（*.pfx）のパス
        /// </summary>
        public static string OAuthJWT_pfx
        {
            get
            {
                return ConfigurationManager.AppSettings["OAuthJWT_pfx"];
            }
        }

        /// <summary>
        /// OAuthのAccess Tokenに使用するJWTの検証用証明書（*.cer）のパス
        /// </summary>
        public static string OAuthJWT_cer
        {
            get
            {
                return ConfigurationManager.AppSettings["OAuthJWT_cer"];
            }
        }

        #endregion

        #endregion

        #endregion

        #region AuthorizationServer

        #region Grant Type

        /// <summary>EnableResourceOwnerCredentialsGrantType</summary>
        public static bool EnableResourceOwnerCredentialsGrantType
        {
            get
            {
                return Convert.ToBoolean(ConfigurationManager.AppSettings["EnableResourceOwnerCredentialsGrantType"]);
            }
        }

        /// <summary>EnableClientCredentialsGrantType</summary>
        public static bool EnableClientCredentialsGrantType
        {
            get
            {
                return Convert.ToBoolean(ConfigurationManager.AppSettings["EnableClientCredentialsGrantType"]);
            }
        }

        /// <summary>EnableRefreshToken</summary>
        public static bool EnableRefreshToken
        {
            get
            {
                return Convert.ToBoolean(ConfigurationManager.AppSettings["EnableRefreshToken"]);
            }
        }

        #endregion

        #region Endpoint

        /// <summary>
        /// OAuthのAuthorizationServerのEndpointのRootのURI
        /// </summary>
        public static string OAuthAuthorizationServerEndpointsRootURI
        {
            get
            {
                return ConfigurationManager.AppSettings["OAuthAuthorizationServerEndpointsRootURI"];
            }
        }

        /// <summary>
        /// OAuthのAuthorizeのEndpoint
        /// </summary>
        public static string OAuthAuthorizeEndpoint
        {
            get
            {
                return ConfigurationManager.AppSettings["OAuthAuthorizeEndpoint"];
            }
        }

        /// <summary>
        /// OAuthのBearerTokenのEndpoint
        /// </summary>
        public static string OAuthBearerTokenEndpoint
        {
            get
            {
                return ConfigurationManager.AppSettings["OAuthBearerTokenEndpoint"];
            }
        }

        #endregion

        #endregion

        #region Client (Test)

        /// <summary>
        /// OAuthのClientのInformation
        /// </summary>
        public static string OAuthClientsInformation
        {
            get
            {
                return ConfigurationManager.AppSettings["OAuthClientsInformation"];
            }
        }

        #region Endpoint

        /// <summary>
        /// OAuthのClientのEndpointのRootURI
        /// </summary>
        public static string OAuthClientEndpointsRootURI
        {
            get
            {
                return ConfigurationManager.AppSettings["OAuthClientEndpointsRootURI"];
            }
        }

        /// <summary>
        /// OAuthAuthorizationCodeGrantClientのEndpoint
        /// </summary>
        public static string OAuthAuthorizationCodeGrantClient
        {
            get
            {
                return ConfigurationManager.AppSettings["OAuthAuthorizationCodeGrantClient"];
            }
        }

        /// <summary>
        /// OAuthImplicitGrantClientのEndpoint
        /// </summary>
        public static string OAuthImplicitGrantClient
        {
            get
            {
                return ConfigurationManager.AppSettings["OAuthImplicitGrantClient"];
            }
        }

        #endregion

        #endregion

        #region ResourceServer

        #region Endpoint (WebAPI)

        /// <summary>
        /// OAuthのResourceServerのEndpointのRootURI
        /// </summary>
        public static string OAuthResourceServerEndpointsRootURI
        {
            get
            {
                return ConfigurationManager.AppSettings["OAuthResourceServerEndpointsRootURI"];
            }
        }

        /// <summary>
        /// OAuthで認証を認可したユーザ情報のClaimを発行するWebAPI
        /// </summary>
        public static string OAuthAuthenticateUserWebAPI
        {
            get
            {
                return ConfigurationManager.AppSettings["OAuthAuthenticateUserWebAPI"];
            }
        }

        /// <summary>
        /// OAuthで認可したユーザ情報に課金するWebAPI
        /// </summary>
        public static string OAuthChageToUserWebAPI
        {
            get
            {
                return ConfigurationManager.AppSettings["OAuthChageToUserWebAPI"];
            }
        }

        /// <summary>
        /// OAuthで認可したユーザ情報のClaimを発行するWebAPI
        /// </summary>
        public static string OAuthGetUserClaimsWebAPI
        {
            get
            {
                return ConfigurationManager.AppSettings["OAuthGetUserClaimsWebAPI"];
            }
        }

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
                return Convert.ToBoolean(ConfigurationManager.AppSettings["EnableStripe"]);
            }
        }

        /// <summary>Stripeのpublicキー</summary>
        public static string Stripe_PK
        {
            get
            {
                return ConfigurationManager.AppSettings["Stripe_PK"];
            }
        }

        /// <summary>Stripeのprivateキー</summary>
        public static string Stripe_SK
        {
            get
            {
                return ConfigurationManager.AppSettings["Stripe_SK"];
            }
        }

        #endregion

        #region PAY.JP

        /// <summary>EnablePAYJP</summary>
        public static bool EnablePAYJP
        {
            get
            {
                return Convert.ToBoolean(ConfigurationManager.AppSettings["EnablePAYJP"]);
            }
        }

        /// <summary>PAY.JPのpublicキー</summary>
        public static string PAYJP_PK
        {
            get
            {
                return ConfigurationManager.AppSettings["PAYJP_PK"];
            }
        }

        /// <summary>PAY.JPのprivateキー</summary>
        public static string PAYJP_SK
        {
            get
            {
                return ConfigurationManager.AppSettings["PAYJP_SK"];
            }
        }

        #endregion

        #endregion

        #endregion
    }
}