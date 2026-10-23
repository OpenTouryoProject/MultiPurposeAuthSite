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
//* クラス日本語名  ：ASP.NET IdentityのConfigクラス（ライブラリ）の アカウント
//*
//* 作成日時        ：－
//* 作成者          ：－
//* 更新履歴        ：－
//*
//*  日時        更新者            内容
//*  ----------  ----------------  -------------------------------------------------
//*  2026/10/23  玄人 幸道         新規（Config.cs から partial に分割。#294）
//**********************************************************************************

#if NETCORE
using MultiPurposeAuthSite.Extensions.FIDO;
#endif

using System;

using Touryo.Infrastructure.Framework.Authentication;
using Touryo.Infrastructure.Public.Util;

/// <summary>MultiPurposeAuthSite.Co</summary>
namespace MultiPurposeAuthSite.Co
{
    /// <summary>Config（アカウント）</summary>
    public partial class Config
    {
        #region アカウント

        #region 事前登録ユーザ

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

        #region サインアップ・ユーザ名

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

        #region パスワード

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

        #region ロックアウト

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

        #region このサイト自身が書く Cookie の名前（#255）

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

        #region Cookie 認証チケット

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

        #region 2 要素認証 (2FA)

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

        #region 機能ロックダウン（STS 専用モード）・管理画面

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

        #endregion
    }
}