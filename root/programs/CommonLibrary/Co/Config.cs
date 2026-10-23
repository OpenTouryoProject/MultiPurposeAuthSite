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
//*  2026/09/24  玄人 幸道         PAR の口（PushedAuthorizationRequestEndpoint）を追加（#229）
//*  2026/09/25  玄人 幸道         設定キーの改名と、旧キーの読み替え（#236）
//*  2026/09/25  玄人 幸道         UserClaimsMapping（profile / address のクレームの対応付け）を追加（#230）
//*  2026/09/27  玄人 幸道         AuthRequestPushUri は Open棟梁 側で読むようにした（#236 の宿題）
//*  2026/09/27  玄人 幸道         OAuth2EndSessionEndpoint（RP-Initiated Logout）を追加（#232）
//*  2026/09/29  玄人 幸道         RequireVerifiedEmailForAccountLinking を追加（#140 の段階 1）
//*  2026/09/30  玄人 幸道         DataProtectionKeyPath を追加（#251）
//*  2026/09/30  玄人 幸道         AuthCookieName を追加（#250 の段階 4）
//*  2026/09/30  玄人 幸道         CookieNamePrefix を追加（#255）
//*  2026/10/01  玄人 幸道         RequireUniqueEmail の設定を削除（#151 の段階 3）
//*  2026/10/03  玄人 幸道         TestUserSuffix を追加（#260）
//*  2026/10/04  玄人 幸道         CorsAllowedOrigins を追加（#265）
//*  2026/10/06  玄人 幸道         SessionStoreType / SessionStoreConnectionString を追加（#256）
//*  2026/10/07  玄人 幸道         FIDOServerModeをnet10.0版だけで復活（#137）
//*  2026/10/07  玄人 幸道         Saml2AssertionExpireTimeSpanFromMinutesを専用キーにした（#276）
//*  2026/10/07  玄人 幸道         配備で切り替える設定を 4 つ追加（#279）
//*  2026/10/09  西野 大介         オンライン決済サービス系処理の削除
//*  2026/10/09  玄人 幸道         ChageToUserWebAPI（課金の口）の設定を削除
//*  2026/10/09  玄人 幸道         OAuth2AuthorizationCodeGrantClient_Manage を削除
//*  2026/10/10  玄人 幸道         SAML2のID連携の設定を追加（#286の段階1）
//*  2026/10/10  玄人 幸道         ID連携の導線を設定の有無で出す（#286の段階2）
//*  2026/10/13  玄人 幸道         自分の値と上流の値を、別の設定キーに分けた（#290）
//*  2026/10/13  玄人 幸道         上流の SAML2 メタデータの URL を設定で与えられるようにした（#291）
//*  2026/10/14  玄人 幸道         ID 連携の上流を n 件持てるようにした（IdFederationUpstreams）（#292 の段階 1）
//*  2026/10/14  玄人 幸道         user store の秘密を暗号化する鍵を追加（#297）
//*  2026/10/16  玄人 幸道         slow_down・失敗回数・レート制限の設定を追加（#305）
//*  2026/10/16  玄人 幸道         /jwkcerts のキャッシュの秒数を追加（#303。E-7）
//*  2026/10/18  玄人 幸道         動的クライアント登録の設定を追加（#307 の段階 1）
//*  2026/10/20  玄人 幸道         software_statement の設定を追加（#307 の段階 4）
//*  2026/10/21  玄人 幸道         OP のセッションの Cookie 名を追加（#310 の段階 1）
//*  2026/10/22  玄人 幸道         DPoP の nonce の設定を追加（#311 の段階 4）
//*  2026/10/22  玄人 幸道         IssuerId などを Open棟梁 の CmnServerParams に移した（#294）
//**********************************************************************************

using MultiPurposeAuthSite.Data;
#if NETCORE
using MultiPurposeAuthSite.Extensions.FIDO;
#endif

using System;
using System.Collections.Generic;

#if NETFX
using Newtonsoft.Json;
#else
using Microsoft.Extensions.Configuration;
#endif

using Touryo.Infrastructure.Framework.Authentication;
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

        /// <summary>TestUserSuffix（テスト利用者の名前に付ける接尾辞。#260）</summary>
        /// <remarks>
        /// **空なら従来どおり**（`super_tanaka` / `tanaka`）。
        ///
        /// **なぜ要るか。** E2E は **net48 版と net10.0 版を同時に立てて、同じケースを両方に流す。**
        /// **DB ストアでは 1 つの DB を共有する**ので、
        /// **両サイトが同じテスト利用者の属性（`DeviceToken` / `UnstructuredData`）を
        /// 書き換え合って、間欠で落ちていた。**
        ///
        /// **サイトごとに違う接尾辞を与えると、テスト利用者が分かれる**（`_core` / `_netfx`）。
        /// **`mem` では各サイトが自前のストアを持つので、以前から起きていない。**
        ///
        /// **製品の既定は空である。** 接尾辞を与えるのは `test.ps1` だけ。
        /// </remarks>
        public static string TestUserSuffix
        {
            get
            {
                return GetConfigParameter.GetConfigValue("TestUserSuffix") ?? "";
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

        #region このサイト自身が書くCookieの名前（#255）

        /// <summary>
        /// このサイト自身が書く Cookie の名前に付ける接頭辞（#255）
        /// </summary>
        /// <remarks>
        /// **空なら、従来どおり接頭辞なし。**
        ///
        /// **同じホストに 2 つ立てるときだけ指定する。**
        /// **Cookie のスコープにポートは入らない**（RFC 6265 §8.5）ので、
        /// `localhost:44300` と `localhost:44301` は **Cookie を共有し、上書きし合う。**
        ///
        /// **名前を決められる Cookie すべてに掛かる。**
        /// **名前そのものは下の設定で決め、この設定は「どの配備か」を表す**（役割が違う）。
        ///
        /// | Cookie | 名前の決め方 |
        /// |---|---|
        /// | 認証・外部ログイン・2FA（Identity の 4 スキーム） | <see cref="AuthCookieName"/>、または枠組みの既定 |
        /// | セッション | `sessionState:SessionCookieName` |
        /// | `auth_time` / `re_auth_at` / `op_session` | このクラスの定数 |
        /// | TempData（net10.0 版だけ） | 枠組みの既定 |
        ///
        /// **外部ログインの Cookie も要る。** **ID フェデレーションの途中で使う**ので、
        /// ここが混ざると連携が壊れる（サインインの Cookie だけでは足りない）。
        ///
        /// **Open棟梁 が書く `SessionTimeOut` は分けられない**（`FxHttpCookieIndex` の定数）。
        /// 雛形は `FxSessionTimeOutCheck` を `off` にしているため、**いまは読まれない。**
        ///
        /// **AntiForgery は対象外。** net10.0 版は名前にアプリごとのハッシュが入り、
        /// **もともと衝突しない。** **net48 版のセッション Cookie も対象外**
        /// （ASP.NET のもので、`system.web/sessionState` の `cookieName` で決まる）。
        /// </remarks>
        public static string CookieNamePrefix
        {
            get
            {
                return GetConfigParameter.GetConfigValue("CookieNamePrefix");
            }
        }

        /// <summary>セッションの置き場（net10.0 版だけ。#256）</summary>
        /// <remarks>
        /// **`mem`（既定） / `sql` / `redis`。**
        /// **書かなければ `mem`**（＝ 従来どおり。プロセス内のメモリ）。
        ///
        /// **net48 版は読まない。** あちらは `Web.config` の `sessionState` で選ぶ。
        ///
        /// | 値 | 置き場 | 複数インスタンス |
        /// |---|---|---|
        /// | `mem` | プロセス内 | **共有されない**（単一インスタンス向け） |
        /// | `sql` | SQL Server のテーブル | 共有される。`Create_SessionCache.sql` を流しておく |
        /// | `redis` | Redis | 共有される。**`UserStoreType` の方言に依らない** |
        ///
        /// **`UserStoreType` と同じ流儀**にしてある（`EnumSessionStoreType`）。
        /// **Oracle / PostgreSQL 用の `IDistributedCache` は標準に無い**ので、
        /// **それらのストアで複数インスタンスにするなら `redis` を使う。**
        /// </remarks>
        public static EnumSessionStoreType SessionStoreType
        {
            get
            {
                // **キーが無いと null が返る。** `UserStoreType` と違い、
                //   **このキーは雛形以外では無いことがある**（既存の配備）ので、
                //   そのまま `ToUpper()` すると、起動時に落ちる。
                string sessionStoreType = GetConfigParameter.GetConfigValue("SessionStoreType");

                switch ((sessionStoreType ?? "").ToUpper())
                {
                    case "MEM":
                        return EnumSessionStoreType.Memory;
                    case "SQL":
                        return EnumSessionStoreType.SqlServer;
                    case "REDIS":
                        return EnumSessionStoreType.Redis;
                    default:
                        // **書かなければプロセス内**（＝ 従来どおり）。
                        return EnumSessionStoreType.Memory;
                }
            }
        }

        /// <summary>セッションの置き場への接続文字列（net10.0 版だけ。#256）</summary>
        /// <remarks>
        /// **`SessionStoreType` で意味が変わる。**
        ///
        /// | `SessionStoreType` | 書くもの |
        /// |---|---|
        /// | `mem` | **要らない**（読まない） |
        /// | `sql` | **SQL Server の接続文字列。** `ConnectionString_SQL` と同じでよいが、別の DB にもできる |
        /// | `redis` | **Redis の接続文字列**（`localhost:6379` など） |
        ///
        /// **`UserStoreType` のように方言ごとに分けていない**のは、
        /// **`SessionStoreType` が置き場を一意に決める**ためである。
        /// </remarks>
        public static string SessionStoreConnectionString
        {
            get
            {
                return GetConfigParameter.GetConfigValue("SessionStoreConnectionString");
            }
        }

        /// <summary>CORS で追加して許可するオリジン（任意。#265）</summary>
        /// <remarks>
        /// **空でよい。** 既定では、**構成ファイルに登録された public クライアントの
        /// `redirect_uri_*` からオリジンを導く**（`CmnEndpoints.GetCorsAllowedOrigins`）。
        /// **ここは、その導出で拾えないものを足すための口**である。
        ///
        /// **区切りは空白かカンマ。** 値はオリジン（`https://host:port`）で書く。
        /// **末尾の `/` は付けない**（CORS の比較はオリジン同士で、パスを含まない）。
        ///
        /// **`*` は書かないこと。** 書いても拒否する（`ProductionCheck` が警告する）。
        /// </remarks>
        public static string CorsAllowedOrigins
        {
            get
            {
                return GetConfigParameter.GetConfigValue("CorsAllowedOrigins");
            }
        }

        /// <summary>Cookie の名前に接頭辞を付ける（#255）</summary>
        /// <param name="name">元の名前</param>
        /// <returns>接頭辞を付けた名前（接頭辞が空なら、元のまま）</returns>
        /// <remarks>
        /// **先頭が `.` なら、その後ろに差し込む。**
        ///
        /// | 元の名前 | 付けた後（接頭辞が `upstream_`） |
        /// |---|---|
        /// | `auth_time` | `upstream_auth_time` |
        /// | `.MultiPurposeAuthSite` | `.upstream_MultiPurposeAuthSite` |
        /// | `.AspNetCore.Mvc.CookieTempDataProvider` | `.upstream_AspNetCore.Mvc.CookieTempDataProvider` |
        ///
        /// **先頭の `.` は「ホスト専用（host-only）」を表す慣習**で、
        /// **枠組みが付けた `.` を潰さない**ため、後ろへ入れる。
        /// **見た目も揃う**（どの Cookie も `.` の直後に接頭辞が来る）。
        /// </remarks>
        public static string PrefixCookieName(string name)
        {
            string prefix = Config.CookieNamePrefix;

            if (string.IsNullOrEmpty(prefix) || string.IsNullOrEmpty(name))
            {
                return name;
            }

            if (name.StartsWith("."))
            {
                return "." + prefix + name.Substring(1);
            }

            return prefix + name;
        }

        /// <summary>
        /// 前回の認証時刻を保存する Cookie の名前（#247 / #255）
        /// </summary>
        /// <remarks>**`max_age` の判定に使う。** 中身は W3C 形式の時刻。</remarks>
        public static string AuthTimeCookieName
        {
            get
            {
                return Config.PrefixCookieName(OAuth2AndOIDCConst.auth_time);
            }
        }

        /// <summary>
        /// 再認証を求めた時刻を保存する Cookie の名前（#247 / #255）
        /// </summary>
        /// <remarks>**繰り返しを防ぐための印。** 判定は <see cref="AuthTimeCookieName"/> と対で行う。</remarks>
        public static string ReAuthenticatedAtCookieName
        {
            get
            {
                return Config.PrefixCookieName(Const.ReAuthenticatedAt);
            }
        }

        /// <summary>
        /// OP のセッションの識別子を保存する Cookie の名前（#310 の段階 1）
        /// </summary>
        /// <remarks>
        /// **`sid` の台帳（`SessionClientProvider`）を引く鍵**である。
        /// **中身は guid** で、**サインインで作り、サインアウトで消す。**
        ///
        /// **セッション Cookie である**（期限を付けない） — **ブラウザを閉じれば終わる。**
        /// **認証 Cookie が「次回から自動的にサインイン」で残っていても、
        /// この Cookie が無ければ別のセッションとして扱う**（**新しい `sid` になる**）。
        /// </remarks>
        public static string OpSessionCookieName
        {
            get
            {
                return Config.PrefixCookieName(Const.OpSession);
            }
        }

        #endregion

        #region Cookie認証チケット

        /// <summary>
        /// Cookie認証チケットの名前（#250 の段階 4）
        /// </summary>
        /// <remarks>
        /// **空なら、そのプラットフォームの既定のまま**（従来どおり）。
        ///   net10.0 版 : `.AspNetCore.Identity.Application`
        ///   net48 版   : `.AspNet.ApplicationCookie`
        ///
        /// **同じホストに 2 つ立てるときだけ指定する。**
        /// **Cookie のスコープにポートは入らない**（RFC 6265 §8.5）ので、
        /// `localhost:44300` と `localhost:44301` は **Cookie を共有する。**
        /// 名前が同じだと、**後にサインインした側が相手の Cookie を上書きし、
        /// 相手は復号できずサインアウトする。**
        ///
        /// **パスが違っても解決しない。** 仮想ディレクトリ配下（`/MultiPurposeAuthSite`）と
        /// root で **同名・別パスの Cookie が 2 つ並び**、どちらが読まれるかは決まらない。
        ///
        /// **ID フェデレーションは「上流にサインイン → 下流がサインイン」**なので、
        /// **この経路を通るたびに、どちらかが必ず切れる**（#250 の段階 4 で実測）。
        /// </remarks>
        public static string AuthCookieName
        {
            get
            {
                return GetConfigParameter.GetConfigValue("AuthCookieName");
            }
        }

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

        #region DataProtectionKeyPath

        /// <summary>
        /// DataProtection の鍵の置き場（#251。C-13）
        /// </summary>
        /// <remarks>
        /// **net10.0 版だけで使う。** net48 版は machineKey の話で、別。
        ///
        /// **指定しなければ、従来どおり `%LOCALAPPDATA%` 配下**（コンテナでは揮発）。
        /// **指定すると、そこに鍵リングを置く**ので、
        /// **再起動やコンテナの作り直しでもサインインが切れない。**
        ///
        /// **鍵そのものは書かない**（net48 の `machineKey` との違い）。
        /// **鍵は自動生成・自動ローテーションされる。共有するのは置き場である。**
        ///
        /// **効くのは「画面のセッション」**（認証 Cookie / AntiForgery /
        /// メール確認・パスワード リセットのリンク）。
        /// **access_token / id_token・PPID・認可コード・refresh_token には影響しない。**
        ///
        /// **鍵リングは平文の XML。** 置き場の保護は運用側の責任。
        /// </remarks>
        public static string DataProtectionKeyPath
        {
            get
            {
                return GetConfigParameter.GetConfigValue("DataProtectionKeyPath");
            }
        }

        #endregion

        #region 配備で切り替えるもの（#279）

        //  **本番でだけ有効にしたい設定を「コメントアウトして置いておく」と、
        //    環境を移すときにソースを書き換えることになる。**
        //    Open棟梁 の MVC_Sample に倣い、設定で切り替える形にした（#279 / 上流 #541・#549）。
        //
        //  **いずれも net10.0 版だけの設定である。**
        //    net48 版は `Web.config` の `<httpCookies>` / `<rewrite>` などで行う。
        //    **`_app.config` にキーを置いていない**のは、`DataProtectionKeyPath`（#251）と同じ理由。
        //
        //  **既定値は、いずれも従来どおりの動作**である。

        /// <summary>HTTP を HTTPS へリダイレクトするか（#279）</summary>
        /// <remarks>
        /// **既定は off。** 平文 HTTP で動かす環境（疎通確認や、
        /// TLS を前段のリバース プロキシで終端する構成）でリダイレクトすると、
        /// **到達できなくなる**ため。TLS を自分で終端するなら `on` にする。
        ///
        /// **on にするだけでは足りない。リダイレクト先のポートも要る。**
        /// 決められないと、ミドルウェアは警告を出すだけで素通りする。
        /// </remarks>
        public static bool UseHttpsRedirection
        {
            get
            {
                return (GetConfigParameter.GetConfigValue("UseHttpsRedirection") ?? "")
                    .ToLower() == "on";
            }
        }

        /// <summary>Cookie に Secure 属性を必ず付けるか（#279）</summary>
        /// <remarks>
        /// **設定キーは `CookieSecurePolicy`**（`always` のときだけ true）。
        ///
        /// **既定は空＝各 Cookie の設定に従う。**
        /// **平文 HTTP の環境で `always` にすると、Cookie が送られずサインインできなくなる**
        /// （AntiForgery の Cookie も返らないので、
        /// 症状は「サインイン画面は出るが POST が 400」になる）。
        /// </remarks>
        public static bool CookieSecurePolicyAlways
        {
            get
            {
                return (GetConfigParameter.GetConfigValue("CookieSecurePolicy") ?? "")
                    .ToLower() == "always";
            }
        }

        /// <summary>転送ヘッダ（X-Forwarded-Proto / -For）を取り込むか（#279）</summary>
        /// <remarks>
        /// **リバース プロキシで TLS を終端すると、アプリから見た接続は HTTP になる。**
        /// 利用者のブラウザは HTTPS で繋いでいるのに `Request.IsHttps` は false のままで、
        /// **Secure 属性が付かず、生成する絶対 URL も http になる。**
        ///
        /// **既定は off。** 素の HTTP で動かす環境では、
        /// **転送ヘッダを誰でも付けられる（＝ クライアントが詐称できる）**ため。
        /// </remarks>
        public static bool UseForwardedHeaders
        {
            get
            {
                return (GetConfigParameter.GetConfigValue("UseForwardedHeaders") ?? "")
                    .ToLower() == "on";
            }
        }

        /// <summary>信用する前段のアドレス（#279。カンマ区切り。空なら範囲を制限しない）</summary>
        /// <remarks>
        /// **既定ではループバックからの転送しか信用しない。**
        /// コンテナや Kubernetes では前段が別アドレスになるため、
        /// **指定しないとヘッダが黙って捨てられ、何も起きない。**
        /// **「on にしたのに直らない」の原因はほぼこれである。**
        /// </remarks>
        public static string ForwardedHeadersKnownProxies
        {
            get
            {
                return GetConfigParameter.GetConfigValue("ForwardedHeadersKnownProxies");
            }
        }

        #endregion

        #region RequireVerifiedEmailForAccountLinking

        /// <summary>
        /// 外部 ID を既存アカウントに結び付けるとき、検証済みのメアドを要求するかどうか（#140 の段階 1）
        /// </summary>
        /// <remarks>
        /// **既定は true（要求する）。**
        /// 他の Require* と違い、**未設定を false（従来どおり）にしない。**
        /// 未検証のメアドで既存アカウントに結び付けられるのは弱点であり、
        /// **下位互換のために穴を開けたままにする既定にはしない**（#140 の段階 1）。
        ///
        /// false にすると従来どおりになる。**上流が `email_verified` を返さない場合に、
        /// それでもメアドで結び付けたいとき**の逃げ道である
        /// （その場合の代替は、ローカルでサインインしてから `/Manage/ManageLogins` で追加すること）。
        ///
        /// 判定は `Extensions.Sts.AccountLink` にある。
        /// </remarks>
        public static bool RequireVerifiedEmailForAccountLinking
        {
            get
            {
                string value = GetConfigParameter.GetConfigValue(
                    "RequireVerifiedEmailForAccountLinking");

                // **未設定は true（安全側）。** 他のキーと既定の向きが違うので、明示的に書く。
                return string.IsNullOrEmpty(value) ? true : Convert.ToBoolean(value);
            }
        }

        #endregion

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

        #endregion

        #endregion

        #region FIDO
#if NETCORE

        /// <summary>
        /// FIDOServerMode
        /// </summary>
        /// <remarks>
        /// **net10.0 版だけの設定**（#137）。
        /// **`Fido2` は 2.0.2 を最後に `netstandard2.0` を落としている**ので、
        /// **net48 版では WebAuthn を支えられない。**
        /// **設定キーも net48 版の `_app.config` から落としてある。**
        /// </remarks>
        public static EnumFidoType FIDOServerMode
        {
            get
            {
                // **キーが無ければ null が返る**ので、null 合流で受ける（#256 と同じ）。
                string temp = GetConfigParameter.GetConfigValue("FIDOServerMode");
                switch ((temp ?? "").ToLower())
                {
                    case "webauthn":
                        return EnumFidoType.WebAuthn;
                    default:
                        return EnumFidoType.None;
                }
            }
        }

#endif
        #endregion

        #region STS

        // **IssuerId は Open棟梁 の `CmnServerParams` が読む**（キー名は同じ。#294）。

        #region 証明書

        #region RSA

        // **RsaPfxPassword / RsaPfxFilePath は Open棟梁 の `CmnServerParams` が読む**（キー名は同じ。#294）。

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
        /// <remarks>
        /// **専用のキーを読む**（#276）。
        /// **以前は `OidcIdTokenExpireTimeSpanFromMinutes` を読んでいた**が、
        /// **この名前のキーはどちらの雛形にも在らなかった**。
        ///
        /// **キーが無ければ、従来どおり id_token の値を使う**
        /// （**既存の配備を壊さないため**）。
        ///
        /// > **单位に注意。** `SAML2Bindings.CreateAssertion` の引数は
        /// > **`double expiresFromSecond`（秒）** である。
        /// > **渡すときに 60 を掛けること**（`SamlProviders/CmnEndpoints`）。
        /// </remarks>
        public static double Saml2AssertionExpireTimeSpanFromMinutes
        {
            get
            {
                string temp = GetConfigParameter.GetConfigValue("Saml2AssertionExpireTimeSpanFromMinutes");

                if (string.IsNullOrEmpty(temp))
                {
                    // **従来の振る舞い**（id_token の値を流用）。
                    temp = GetConfigParameter.GetConfigValue("OidcIdTokenExpireTimeSpanFromMinutes");
                }

                return double.Parse(temp);
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
        /// クライアント登録の管理 API 専用のアクセス トークンの有効期限（秒）（#307 の段階 1）
        /// </summary>
        /// <remarks>
        /// **`Const.ScopeClientRegistration` を要求したときだけ、この期限で出す。**
        /// **配備ぜんたいの `OAuth2AccessTokenExpireTimeSpanFromMinutes`（既定 360 分）では長すぎる** —
        /// **この口は、人の操作より CI から叩く想定**で、長く持たせる理由が無い。
        ///
        /// **未設定・空なら既定値（300 秒）に倒す**（**既存の配備にはこのキーが無い**）。
        /// **倒れ先を読む先例は `Saml2AssertionExpireTimeSpanFromMinutes`**（#276）。
        ///
        /// > **0 以下を書いたときも既定値に倒す。**
        /// > **0 は「発行した瞬間に切れるトークン」であり、設定の誤りとしか考えられない。**
        /// </remarks>
        public static TimeSpan DcrAccessTokenExpireTimeSpanFromSeconds
        {
            get
            {
                string temp = GetConfigParameter.GetConfigValue(
                    "DcrAccessTokenExpireTimeSpanFromSeconds");

                if (!int.TryParse(temp, out int seconds) || seconds <= 0)
                {
                    //  **既定値**（キーが無い配備でも動く）。
                    seconds = 300;
                }

                return TimeSpan.FromSeconds(seconds);
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

        /// <summary>
        /// 認証の失敗を、この回数で断る（#305 の段階 2）
        /// </summary>
        /// <remarks>
        /// **クライアント認証（`client_secret` / mTLS）と、
        /// `user_code` の投入**の失敗を数える（`Extensions/Sts/AuthFailureProvider`）。
        ///
        /// | 値 | |
        /// |---|---|
        /// | **0（または未設定）** | **数えない**（従来どおり） |
        /// | 正の回数（雛形は 5） | **連続してこの回数失敗したら、`AuthFailureLockoutSeconds` の間断る** |
        ///
        /// **断っている間は、正しい資格情報でも通さない**（ロックアウトの意味）。
        /// **成功したら回数は消える。**
        ///
        /// **利用者のパスワードは、ASP.NET Identity 側で数えている**
        /// （`MaxFailedAccessAttemptsBeforeLockout`）。**こちらは別の口である。**
        ///
        /// **数えるのは「クライアント ＋ 送信元」ごと**である（#305 の段階 4）。
        /// **`client_id` だけで数えると、誰でもそのクライアントを止められる。**
        /// </remarks>
        public static int AuthFailureMaxAttempts
        {
            get
            {
                string value = GetConfigParameter.GetConfigValue("AuthFailureMaxAttempts");

                if (string.IsNullOrEmpty(value))
                {
                    //  **未設定は 0**（数えない。従来どおり）。
                    return 0;
                }

                int attempts = 0;
                return int.TryParse(value, out attempts) ? attempts : 0;
            }
        }

        /// <summary>
        /// 認証の失敗が上限に達したとき、断る長さ（秒。#305 の段階 2）
        /// </summary>
        /// <remarks>**未設定は 300 秒**（5 分）。</remarks>
        public static int AuthFailureLockoutSeconds
        {
            get
            {
                string value = GetConfigParameter.GetConfigValue("AuthFailureLockoutSeconds");

                if (string.IsNullOrEmpty(value))
                {
                    return 300;
                }

                int seconds = 0;
                return (int.TryParse(value, out seconds) && 0 < seconds) ? seconds : 300;
            }
        }

        /// <summary>
        /// 数えた分を、いつまで覚えているか（秒。#305 の段階 4）
        /// </summary>
        /// <remarks>
        /// **最後の失敗からこの時間が過ぎると、数えた分は忘れる**
        /// （**間隔を空けた失敗が、いつまでも積み上がらない**）。
        /// **行の寿命もこれで決まる** — **期限の過ぎた行は掃除される**
        /// （`AuthFailureProvider.PruneExpired`）。
        ///
        /// **未設定は `AuthFailureLockoutSeconds` と同じ**（雛形では 300 秒）。
        ///
        /// **`AuthFailureMaxAttempts` 回を試すのに掛かる時間より、長くすること。**
        /// **短いと、数が積まれる前に忘れるので、いつまでも断らない。**
        /// </remarks>
        public static int AuthFailureWindowSeconds
        {
            get
            {
                string value = GetConfigParameter.GetConfigValue("AuthFailureWindowSeconds");

                if (string.IsNullOrEmpty(value))
                {
                    //  **未設定は、断る長さと同じ。**
                    return Config.AuthFailureLockoutSeconds;
                }

                int seconds = 0;
                return (int.TryParse(value, out seconds) && 0 < seconds)
                    ? seconds : Config.AuthFailureLockoutSeconds;
            }
        }

        /// <summary>
        /// 口ごとのレート制限 : クライアント 1 つあたりの上限（#305 の段階 3）
        /// </summary>
        /// <remarks>
        /// **`client_id` が分かる要求を、`client_id` ごとに数える**
        /// （`Extensions/Sts/RateLimitProvider`）。**窓は `RateLimitWindowSeconds`。**
        ///
        /// | 値 | |
        /// |---|---|
        /// | **0（または未設定）** | **制限しない**（従来どおり） |
        /// | 正の回数（雛形は 120） | **窓の中でこの回数を超えた要求に `429`**（`Retry-After` 付き） |
        ///
        /// **数えるのは口ごと**である（`/token` の洪水で `/revoke` が止まらない）。
        /// **段階 2 は「失敗の回数」、ここは「要求の回数」**（成否を問わない）。
        /// </remarks>
        public static int RateLimitPerClientPermits
        {
            get
            {
                string value = GetConfigParameter.GetConfigValue("RateLimitPerClientPermits");

                if (string.IsNullOrEmpty(value))
                {
                    //  **未設定は 0**（制限しない。従来どおり）。
                    return 0;
                }

                int permits = 0;
                return int.TryParse(value, out permits) ? permits : 0;
            }
        }

        /// <summary>
        /// 口ごとのレート制限 : 送信元 1 つあたりの上限（#305 の段階 3）
        /// </summary>
        /// <remarks>
        /// **`client_id` が分からない要求**（`/jwkcerts` の読み出しなど）**と、**
        /// **`client_id` が分かる要求の両方**を、**送信元アドレスごとに数える。**
        /// **`client_id` を毎回変えて `client_id` ごとの上限を避ける**攻撃に、これが効く。
        ///
        /// | 値 | |
        /// |---|---|
        /// | **0（または未設定）** | **制限しない**（従来どおり） |
        /// | 正の回数（雛形は 600） | **窓の中でこの回数を超えた要求に `429`** |
        ///
        /// **リバース プロキシの後ろでは、見えるアドレスはプロキシのものになる。**
        /// **net10.0 版は `UseForwardedHeaders`**（設定キーも同名。`ForwardedHeadersKnownProxies` と併せて使う）**で元に戻せるが、**
        /// **net48 版は戻さない**（`Request.UserHostAddress` をそのまま使う）。
        /// **プロキシの後ろに置く配備では、プロキシ側で制限する方が確かである。**
        /// </remarks>
        public static int RateLimitPerIpPermits
        {
            get
            {
                string value = GetConfigParameter.GetConfigValue("RateLimitPerIpPermits");

                if (string.IsNullOrEmpty(value))
                {
                    return 0;
                }

                int permits = 0;
                return int.TryParse(value, out permits) ? permits : 0;
            }
        }

        /// <summary>
        /// 口ごとのレート制限 : 数える窓の長さ（秒。#305 の段階 3）
        /// </summary>
        /// <remarks>
        /// **未設定は 60 秒。**
        /// **窓は固定窓**（`UNIX 時刻 / 窓` で切る。窓が変わると回数は 0 に戻る）。
        /// **窓の境目では、瞬間的に上限の 2 倍まで通り得る**
        /// （固定窓の性質。**滑る窓にするほどの精度は、ここでは要らない**）。
        /// </remarks>
        public static int RateLimitWindowSeconds
        {
            get
            {
                string value = GetConfigParameter.GetConfigValue("RateLimitWindowSeconds");

                if (string.IsNullOrEmpty(value))
                {
                    return 60;
                }

                int seconds = 0;
                return (int.TryParse(value, out seconds) && 0 < seconds) ? seconds : 60;
            }
        }

        /// <summary>
        /// ポーリングが速すぎるときに `slow_down` を返すか（#305 の段階 1）
        /// </summary>
        /// <remarks>
        /// **Device Authorization Grant と CIBA は、クライアントが `/token` を繰り返し叩く。**
        /// **間隔は `interval`**（`DeviceAuthZPollingIntervalSeconds` /
        /// `CibaPollingIntervalSeconds`）**で伝えてあるが、守らなくても何も起きなかった。**
        ///
        /// **true なら、前回から `interval` 未満で来た要求に `slow_down` を返す**
        /// （RFC 8628 §3.5 / CIBA §11。**クライアントは間隔を 5 秒伸ばす**）。
        ///
        /// **未設定なら true**（**仕様どおりの振る舞い**）。
        /// **false にすると従来どおり**、`authorization_pending` を返し続ける。
        /// </remarks>
        public static bool EnablePollingSlowDown
        {
            get
            {
                string value = GetConfigParameter.GetConfigValue("EnablePollingSlowDown");

                //  **未設定は true**（仕様どおり）。**false と書いたときだけ止める。**
                if (string.IsNullOrEmpty(value))
                {
                    return true;
                }

                bool enabled = true;
                return bool.TryParse(value, out enabled) ? enabled : true;
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

        /// <summary>DPoP の証明に `nonce` を要求するか（#311 の段階 4）</summary>
        /// <remarks>
        /// **RFC 9449 §8 / §9 : サーバは `nonce` を要求してよい**（MAY）。
        /// **要求すると、クライアントは 1 往復多く掛かる**
        /// （**`use_dpop_nonce` で断られ、`DPoP-Nonce` で受け取った値を入れて出し直す**）。
        ///
        /// **既定は false** — **要求すると、`nonce` を知らないクライアントが全部止まる。**
        /// **使い回しの拒否（段階 3）は、この設定とは無関係に効いている。**
        /// </remarks>
        public static bool EnableDPoPNonce
        {
            get
            {
                return Convert.ToBoolean(GetConfigParameter.GetConfigValue("EnableDPoPNonce"));
            }
        }

        /// <summary>DPoP の `nonce` を作る鍵（#311 の段階 4）</summary>
        /// <remarks>
        /// **`nonce` は、この値から計算する**（**台帳を持たない**）。
        /// **同じ値を持つインスタンスなら、互いの `nonce` を受け付けられる。**
        ///
        /// **空なら、プロセスごとのランダムな値を使う** —
        /// **単一のインスタンスなら、それで足りる**
        /// （**再起動すると、前の `nonce` は通らなくなる** ＝ **1 往復増えるだけ**）。
        ///
        /// **インスタンスを増やす配備では、設定すること** —
        /// **設定しないと、要求が別のインスタンスへ行くたびに断られ、やり直しが終わらない。**
        /// </remarks>
        public static string DPoPNonceSecret
        {
            get
            {
                return GetConfigParameter.GetConfigValue("DPoPNonceSecret");
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

        /// <summary>動的クライアント登録（RFC 7591）を開けるか（#307 の段階 1）</summary>
        /// <remarks>
        /// **既定は false**（**口そのものを張らない**）。
        ///
        /// **`Convert.ToBoolean` ではなく `bool.TryParse` で読む** —
        /// **既存の配備にはこのキーが無く、`Convert.ToBoolean("")` は例外になる**
        /// （`EnableOpenIDConnect` などの既存キーは、どちらの雛形にも在る）。
        ///
        /// **この口は `IsLockedDownTestEndpoints` の対象ではない**
        /// （**本番で使う口**であり、テスト用の口とは別に、このキーで開閉する）。
        /// </remarks>
        public static bool EnableDynamicClientRegistration
        {
            get
            {
                bool.TryParse(
                    GetConfigParameter.GetConfigValue("EnableDynamicClientRegistration"),
                    out bool enable);

                return enable;
            }
        }

        /// <summary>
        /// `software_statement`（RFC 7591 §2.3）の発行者の登録（n 件。#307 の段階 4）
        /// </summary>
        /// <remarks>
        /// **読み方は `OAuth2ClientsInformation` / `IdFederationUpstreams` と同じ**
        /// （net48 は JSON 文字列、net10.0 は節）。**値はすべて文字列**で、
        /// **鍵 → 属性の辞書**である。
        ///
        /// **解釈は <see cref="SoftwareStatementIssuers"/> が持つ。**
        /// **ここは「設定を読むだけ」**にしてある（`Config` に判断を増やさない）。
        ///
        /// **空なら、`software_statement` は受け付けない**
        /// （**従来どおり `unapproved_software_statement`**）。
        /// **既存の配備は、このキーを書かなくても従来どおり動く。**
        ///
        /// **「発行者ごと」である。** **クライアントごとではない**
        /// （クライアント自身の鍵は `Saml2OAuth2Data` の列。段階 3）。
        /// </remarks>
        public static Dictionary<string, Dictionary<string, string>> SoftwareStatementIssuers
        {
            get
            {
#if NETFX
                string json = GetConfigParameter.GetConfigValue("SoftwareStatementIssuers");

                if (string.IsNullOrEmpty(json))
                {
                    return null;
                }

                return JsonConvert.DeserializeObject<
                    Dictionary<string, Dictionary<string, string>>>(json);
#else
                IConfigurationSection section = GetConfigParameter
                    .GetAnyConfigSection("appSettings:SoftwareStatementIssuers");

                if (section == null)
                {
                    return null;
                }

                return section.Get<Dictionary<string, Dictionary<string, string>>>();
#endif
            }
        }

        /// <summary>
        /// 動的クライアント登録に `software_statement` を必須とするか（#307 の段階 4）
        /// </summary>
        /// <remarks>
        /// **既定は false**（**従来どおり、添えなくても登録できる**）。
        ///
        /// **true にすると、「審査を通したソフトウェアだけ登録させる」配備になる。**
        /// **`POST /register` と `PUT`（RFC 7592）の両方に効く。**
        ///
        /// > **`PUT` にも効かせるのが要点である。**
        /// > **効かせないと、`PUT` で statement を省いて
        /// > 「主張されていた値」を自分の値に書き換えられる**
        /// > （**statement は保管しないので、省かれたことしか分からない**）。
        ///
        /// **信頼する発行者（`SoftwareStatementIssuers`）を 1 件も書かずに true にすると、
        /// 動的登録は通らなくなる**（**必須なのに、どの statement も approved にならない**）。
        /// </remarks>
        public static bool RequireSoftwareStatement
        {
            get
            {
                bool.TryParse(
                    GetConfigParameter.GetConfigValue("RequireSoftwareStatement"),
                    out bool require);

                return require;
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

        /// <summary>
        /// RP-Initiated Logout のエンドポイント（#232）
        /// </summary>
        /// <remarks>
        /// **新しいキーなので、既に配備された設定ファイルには無い。**
        /// 無ければ既定値（/end_session）を使う。**設定ファイルを直さなくても動く。**
        /// ルートの組み立て（.Substring(1)）で空文字列を渡さないためでもある。
        /// </remarks>
        public static string OAuth2EndSessionEndpoint
        {
            get
            {
                string value = GetConfigParameter.GetConfigValue("OAuth2EndSessionEndpoint");
                return string.IsNullOrEmpty(value) ? "/end_session" : value;
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
        /// 動的クライアント登録のエンドポイント（RFC 7591 / OIDC Discovery §3 の registration_endpoint）（#307 の段階 1）
        /// </summary>
        /// <remarks>
        /// **`EnableDynamicClientRegistration` が false なら、この口は張らない。**
        /// **未設定・空なら `/register` に倒す**（**既存の配備にはこのキーが無い**）。
        /// **広告（Discovery）も、張ったときだけ行う。**
        /// </remarks>
        public static string DcrRegistrationEndpoint
        {
            get
            {
                string temp = GetConfigParameter.GetConfigValue("DcrRegistrationEndpoint");

                return string.IsNullOrEmpty(temp) ? "/register" : temp;
            }
        }

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
        // **RequirePkceS256**（PKCE で S256 だけを受け付けるか。#220）**は Open棟梁 の `CmnServerParams` が読む**
        //   （キー名は同じ。**既定は false**（従来どおり plain も受理）。#294）。

        // **PAR（RFC 9126）のエンドポイントは、Open棟梁 の OAuth2AndOIDCParams が持つ**（#236 の宿題）。
        //   キー名 AuthRequestPushUri は、RequestObjectRegUri / JwkSetUri と同じく
        //   **クライアント側も読む設定**なので、框の側に置く（OpenTouryo #592 で実装された）。
        //   ここに自前のプロパティは置かない。

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

        #endregion

        #endregion

        #region user store の秘密（#297）

        /// <summary>
        /// user store に入る秘密を暗号化する鍵（パスワード）
        /// </summary>
        /// <remarks>
        /// **空なら暗号化しない**（平文のまま入る ＝ 従来どおり）。
        ///
        /// **対象は「元に戻せる形でなければならない秘密」**である（#297）。
        ///
        /// | 表 | 列 |
        /// |---|---|
        /// | `Saml2OAuth2Data` | `ClientSecret`（**クライアント認証で照合し、画面で再表示する**） |
        /// | `IdFederationUpstreams` | `ClientSecret`（**上流へ送る**） |
        ///
        /// **`DataProtectionKeyPath`（#251）とは別物**である
        /// （あちらは Cookie とトークンの保護で、**枠組みが使う**）。
        ///
        /// **設定ファイルの秘密は平文のまま**である。
        /// **ここで守るのは「DB を見られたとき」**であり、
        /// **設定ファイルを見られたら、この鍵も読める**（そこはファイルの権限で守る）。
        ///
        /// **本番では、設定ファイルに直接書かないこと**（環境変数・秘密の管理機構から渡す）。
        /// </remarks>
        public static string UserStoreSecretPassword
        {
            get
            {
                return GetConfigParameter.GetConfigValue("UserStoreSecretPassword");
            }
        }

        #endregion

        #region /jwkcerts のキャッシュ（#303。E-7）

        /// <summary>
        /// `/jwkcerts` の応答に付ける `Cache-Control: public, max-age=` の秒数
        /// </summary>
        /// <remarks>
        /// **`/jwkcerts` は、トークンを検証する相手が必ず読む口**である。
        /// **内容は鍵を入れ替えるまで変わらない**ので、**持ち回らせてよい。**
        ///
        /// | 値 | |
        /// |---|---|
        /// | **0（または未設定）** | **`no-store`**（**従来どおり**。毎回取りに来る） |
        /// | 正の秒数 | **`public, max-age=<秒>`** ＋ `ETag`（`If-None-Match` に `304`） |
        ///
        /// **鍵を入れ替えた直後は、この秒数の間だけ古い鍵を見る相手が居る。**
        /// **出す側は新旧 2 本を広告する**作りにしてある（#291 / #292 の段階 3）ので、
        /// **入れ替えの最中も検証は通る。** **入れ替えの周期より短くすること。**
        ///
        /// **サーバ側で覚える分は、この値に関係なく効く**
        /// （Open棟梁 の `JwkSetDocument`。**ファイルの更新を見て読み直す**）。
        /// </remarks>
        public static int JwkSetCacheMaxAgeSeconds
        {
            get
            {
                string value = GetConfigParameter.GetConfigValue("JwkSetCacheMaxAgeSeconds");

                if (string.IsNullOrEmpty(value))
                {
                    //  **未設定なら 0**（従来どおり `no-store`）。
                    return 0;
                }

                int seconds = 0;
                return int.TryParse(value, out seconds) ? seconds : 0;
            }
        }

        #endregion

        #region 鍵のロールオーバー（#292 の段階 3）

        // **PreviousSigningCerFilePaths**（退役させる途中の署名証明書。#292 の段階 3）**は Open棟梁 の `CmnServerParams` が読む**
        //   （キー名は同じ。#294）。**鍵の入れ替えの手順は `CONFIGURATION.md`** にある。

        #endregion

        #region IDフェデレーション関連

        #region 上流の登録（n 件。#292 の段階 1）

        /// <summary>
        /// ID 連携の上流 IdP の登録（n 件）
        /// </summary>
        /// <remarks>
        /// **読み方は `OAuth2ClientsInformation` と同じ**（net48 は JSON 文字列、net10.0 は節）。
        /// **値はすべて文字列**で、**鍵 → 属性の辞書**である。
        ///
        /// **解釈と、従来の単数キーとの互換は <see cref="IdFederationUpstreams"/> が持つ。**
        /// **ここは「設定を読むだけ」**にしてある（`Config` に判断を増やさない）。
        ///
        /// **空なら、従来の単数キーから 1〜2 件が組み立てられる**ので、
        /// **既存の配備は、このキーを書かなくても従来どおり動く。**
        /// </remarks>
        public static Dictionary<string, Dictionary<string, string>> IdFederationUpstreams
        {
            get
            {
#if NETFX
                string json = GetConfigParameter.GetConfigValue("IdFederationUpstreams");

                if (string.IsNullOrEmpty(json))
                {
                    return null;
                }

                return JsonConvert.DeserializeObject<
                    Dictionary<string, Dictionary<string, string>>>(json);
#else
                IConfigurationSection section = GetConfigParameter
                    .GetAnyConfigSection("appSettings:IdFederationUpstreams");

                if (section == null)
                {
                    return null;
                }

                return section.Get<Dictionary<string, Dictionary<string, string>>>();
#endif
            }
        }

        #endregion

        #region OIDC

        /// <summary>
        /// OIDCのID連携で、上流のdiscovery（OpenID Provider Metadata）のURL
        /// </summary>
        /// <remarks>
        /// **書けば、上流の `jwks_uri` を、ここから引く**（#289 の段階 2）。
        /// **空なら `IdFederationAuthorizeEndpoint` の基底から組み立てる**
        /// （`https://host/authorize` → `https://host/.well-known/openid-configuration`）。
        ///
        /// **SAML2 側の `IdFederationSaml2MetadataUrl` と対称**である。
        /// **「相手のメタデータの在り処」は、どちらも設定で与えられる。**
        ///
        /// **組み立てでは足りない配備がある。**
        ///
        /// | | |
        /// |---|---|
        /// | **パスの下に discovery を置く OP** | `https://host/tenant/v2.0/.well-known/openid-configuration` のような形。**基底だけでは当たらない** |
        /// | 口とメタデータでホストが違う配備 | 同上 |
        ///
        /// **`iss` そのものからは引かない**（`IdFederationOidcCerFilePath` の説明）。
        /// </remarks>
        public static string IdFederationOidcDiscoveryUrl
        {
            get
            {
                return GetConfigParameter.GetConfigValue("IdFederationOidcDiscoveryUrl");
            }
        }

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

        /// <summary>OIDCのID連携が有効か（設定が揃っているか）</summary>
        /// <remarks>
        /// **4 本すべてが要る。** **1 本でも欠けていれば、導線を出さない**（#286 の段階 2）。
        ///
        /// **以前は、サインイン画面に無条件でボタンが出ていた。**
        /// **口を設定していない配備でも押せた**ので、**押すとエラー画面に着いた。**
        /// </remarks>
        public static bool CanIdFederationByOidc
        {
            get
            {
                return !string.IsNullOrEmpty(Config.IdFederationAuthorizeEndpoint)
                    && !string.IsNullOrEmpty(Config.IdFederationRedirectEndpoint)
                    && !string.IsNullOrEmpty(Config.IdFederationTokenEndpoint)
                    && !string.IsNullOrEmpty(Config.IdFederationUserInfoEndpoint);
            }
        }

        /// <summary>
        /// OIDCのID連携で、上流のJWK SetのURL
        /// </summary>
        /// <remarks>
        /// **書けば、ここから直に引く**（discovery を読まない）。
        /// **空なら discovery の `jwks_uri` から引く**（`IdFederationOidcDiscoveryUrl`。#289 の段階 2）。
        ///
        /// | 順 | 鍵の出どころ | |
        /// |---|---|---|
        /// | 1 | **このキー**（上流の JWK Set） | **discovery を出さない OP でも、`kid` で引ける** |
        /// | 2 | discovery → `jwks_uri` → `kid` | **ロールオーバーに追随する** |
        /// | 3 | 設定の `.cer`（`IdFederationOidcCerFilePath`） | 1 本。倒れ先 |
        ///
        /// **`JwkSetUri` とは役が違う。**
        /// **`JwkSetUri` は「この配備の JWK Set の口」**（クライアント・サーバの共通設定）であり、
        /// **自分の `/jwkcerts` のパスとして読む**（ルート登録・discovery の `jwks_uri`）。
        /// **`jku` には使わない**（#302 で、ヘッダに `jku` を入れるのをやめた）。
        /// **上流（相手）の JWK Set は別の値**なので、このキーで持つ。
        ///
        /// > **信頼の根拠は、このキーを書いた人である**（discovery のような `issuer` の照合が無い）。
        /// > **`issuer` と結び付けたいなら、discovery（2 番目）を使うこと。**
        /// </remarks>
        public static string IdFederationJwkSetUri
        {
            get
            {
                return GetConfigParameter.GetConfigValue("IdFederationJwkSetUri");
            }
        }

        /// <summary>
        /// OIDCのID連携で、上流の id_token の署名を検証する証明書（.cer のパス）
        /// </summary>
        /// <remarks>
        /// **空なら、従来どおり** discovery（`jwks_uri`）から引く形は、#289 の段階 2**。
        /// </remarks>
        public static string IdFederationOidcCerFilePath
        {
            get
            {
                return GetConfigParameter.GetConfigValue("IdFederationOidcCerFilePath");
            }
        }

        #endregion

        #region SAML2

        /// <summary>
        /// SAML2のID連携で、上流のメタデータ（EntityDescriptor）のURL
        /// </summary>
        /// <remarks>
        /// **書けば、上流の SSO の口と署名証明書を、ここから引く**（#291）。
        /// **空なら従来どおり**（`IdFederationSaml2RequestEndpoint` と
        /// `IdFederationSaml2CerFilePath` を読む）。**引けなかったときも、そちらに倒れる。**
        ///
        /// | メタデータから引くもの | 設定で与える形（従来） |
        /// |---|---|
        /// | `SingleSignOnService`（HTTP-Redirect）の `Location` | `IdFederationSaml2RequestEndpoint` |
        /// | `KeyDescriptor use="signing"` の証明書 | `IdFederationSaml2CerFilePath` |
        ///
        /// **`entityID` は引かない。** **`IdFederationSaml2IssuerId` と照合する**ために使う
        /// （**一致しなければ、メタデータの値を使わない**）。
        /// **自分の ACS（`IdFederationSaml2ResponseEndpoint`）も、設定のまま**である。
        ///
        /// **SAML2 には、メタデータの既知のパスが無い**（OIDC の `/.well-known/…` に当たるものが無い）。
        /// **だから、OIDC 側（#289）のように口の URL から組み立てる形にはしていない** —
        /// **URL を設定で与える。**
        /// </remarks>
        public static string IdFederationSaml2MetadataUrl
        {
            get
            {
                return GetConfigParameter.GetConfigValue("IdFederationSaml2MetadataUrl");
            }
        }

        //  **上の 4 本は OIDC 用である。** ここは SAML2 用で、別に持つ。
        //
        //  **OIDC と SAML2 で、要る設定の数が違う。**
        //    OIDC は口が 3 つ（authorize / token / userinfo）あり、鍵は discovery から引ける前提。
        //    SAML2 は口が 1 つ（SSO）で、**鍵と EntityID を設定で与える**（#286）。
        //
        //  **1 本でも空なら、SAML2 の ID 連携は無効**（`CanIdFederationBySaml2`）。
        //    **導線（サインイン画面のボタン）も出さない。**
        //    **押しても成立しないボタンを出さないため**である。

        /// <summary>
        /// SAML2のID連携で、AuthnRequestを送る先（上流IdPのSSOの口）
        /// </summary>
        /// <remarks>
        /// **上流の `/samlmetadata` の `SingleSignOnService`（HTTP-Redirect）の値**である。
        /// </remarks>
        public static string IdFederationSaml2RequestEndpoint
        {
            get
            {
                return GetConfigParameter.GetConfigValue("IdFederationSaml2RequestEndpoint");
            }
        }

        /// <summary>
        /// SAML2のID連携で、応答（アサーション）を受け取る口（自分のACS）
        /// </summary>
        /// <remarks>
        /// **上流のクライアント登録（`redirect_uri_saml`）に、この値を登録する。**
        /// **自己テストの ACS（`Saml2ResponseEndpoint`）とは別の口**である
        /// （あちらは `IsLockedDownTestEndpoints` で閉じる）。
        /// </remarks>
        public static string IdFederationSaml2ResponseEndpoint
        {
            get
            {
                return GetConfigParameter.GetConfigValue("IdFederationSaml2ResponseEndpoint");
            }
        }

        /// <summary>
        /// SAML2のID連携で、期待する上流のIssuer（EntityID）
        /// </summary>
        /// <remarks>
        /// **上流の `/samlmetadata` の `entityID` の値**である。
        /// **OIDC の `SpRp_Isser` に当たるもの**だが、**あちらは Open棟梁 の設定**なので分けてある。
        /// </remarks>
        public static string IdFederationSaml2IssuerId
        {
            get
            {
                return GetConfigParameter.GetConfigValue("IdFederationSaml2IssuerId");
            }
        }

        /// <summary>
        /// SAML2のID連携で、上流の署名を検証する証明書（.cer のパス）
        /// </summary>
        /// <remarks>
        /// **上流の `/samlmetadata` の `KeyDescriptor use="signing"` の証明書**である。
        ///
        /// **`SpRp_RsaCerFilePath` は使えない。**
        /// **あのキーは、この配備では「自分の証明書」として読まれている**
        /// （`/samlmetadata` の広告・`JwkSet.json` の素・検証の控え）ので、
        /// **上流のものに差し替えると、そちらが壊れる**（`CmnSaml2Response` の説明）。
        /// </remarks>
        public static string IdFederationSaml2CerFilePath
        {
            get
            {
                return GetConfigParameter.GetConfigValue("IdFederationSaml2CerFilePath");
            }
        }

        /// <summary>SAML2のID連携が有効か（設定が揃っているか）</summary>
        /// <remarks>
        /// **自分の ACS と、期待する上流の EntityID は、必ず要る。**
        ///
        /// **上流の口と鍵は、2 通りのどちらかで揃っていればよい**（#291）。
        ///
        /// | | |
        /// |---|---|
        /// | **メタデータの URL** | そこから口と鍵を引く |
        /// | **口（`…RequestEndpoint`）と鍵（`…CerFilePath`）** | 従来の形 |
        ///
        /// **どちらも無ければ、導線を出さない**（押しても成立しないため）。
        /// </remarks>
        public static bool CanIdFederationBySaml2
        {
            get
            {
                if (string.IsNullOrEmpty(Config.IdFederationSaml2ResponseEndpoint)
                    || string.IsNullOrEmpty(Config.IdFederationSaml2IssuerId))
                {
                    return false;
                }

                return !string.IsNullOrEmpty(Config.IdFederationSaml2MetadataUrl)
                    || (!string.IsNullOrEmpty(Config.IdFederationSaml2RequestEndpoint)
                        && !string.IsNullOrEmpty(Config.IdFederationSaml2CerFilePath));
            }
        }

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

        #endregion
    }
}