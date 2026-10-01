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
//**********************************************************************************

using Touryo.Infrastructure.Framework.Authentication;

/// <summary>MultiPurposeAuthSite.Co</summary>
namespace MultiPurposeAuthSite.Co
{
    /// <summary>Const</summary>
    public class Const
    {
        #region MaxLength

        /// <summary>UriのMaxLength</summary>
        public const int MaxLengthOfUri = 512;

        /// <summary>ClientNameのMaxLength</summary>
        public const int MaxLengthOfClientName = 64;

        /// <summary>RoleNameのMaxLength</summary>
        public const int MaxLengthOfRoleName = 64;

        /// <summary>UserNameのMaxLength</summary>
        public const int MaxLengthOfUserName = 64;

        /// <summary>PasswordのMaxLength</summary>
        public const int MaxLengthOfPassword = 100;

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

        #region Scope

        #region ScopeSet

        /// <summary>標準的なscope</summary>
        public static readonly string StandardScopes =
            OAuth2AndOIDCConst.Scope_Profile + " "
            + OAuth2AndOIDCConst.Scope_Email + " "
            + OAuth2AndOIDCConst.Scope_Phone + " "
            + OAuth2AndOIDCConst.Scope_Address + " "
            + OAuth2AndOIDCConst.Scope_UserID + " "
            + OAuth2AndOIDCConst.Scope_Roles;

        /// <summary>OIDCのscope</summary>
        public static readonly string OidcScopes =
            OAuth2AndOIDCConst.Scope_Openid + " " + StandardScopes;
        
        /// <summary>ID連携 scope</summary>
        /// <remarks>
        /// **標準のスコープだけを要求する**（#140 の段階 3）。
        ///
        /// **以前は `StandardScopes`（独自の `userid` / `roles` を含む）を要求していた。**
        /// **独自のスコープは、厳格な OP では `invalid_scope` になりうる**
        /// （この IdP 自身も #198 で、宣言外のスコープを発行しないようにした）。
        /// **汎用の OP と連携するには、標準だけを要求するのが筋。**
        ///
        /// **`userid` はもう連携キーではない**（#140 の段階 3 で `(iss, sub)` に移した）。
        /// 旧い鍵（`"MultiPurposeAuthSite"` × `userid`）を持つ利用者は、
        /// **`userid` が返らなくなっても、検証済みメアドの突き合わせで拾われて新しい鍵へ移行する**
        /// （C-23 の判定を通る。上流が `email_verified` を返すため）。
        ///
        /// > **突き合わせは常にメアドである**（#151 の段階 3）。
        /// > 以前は `RequireUniqueEmail` が false の配備で利用者名が鍵になり、
        /// > **旧い鍵の利用者が拾われない**という穴があった。その設定は落とした。
        /// </remarks>
        public static readonly string IdFederationScopes =
            OAuth2AndOIDCConst.Scope_Openid + " "
            + OAuth2AndOIDCConst.Scope_Profile + " "
            + OAuth2AndOIDCConst.Scope_Email + " "
            + OAuth2AndOIDCConst.Scope_Phone + " "
            + OAuth2AndOIDCConst.Scope_Address;

        #endregion

        #endregion

        #region RedirectUri

        /// <summary>codeのテスト用のRedirectUri</summary>
        public const string TestSelfCode = "test_self_code";

        /// <summary>tokenのテスト用のRedirectUri</summary>
        public const string TestSelfToken = "test_self_token";

        /// <summary>ログアウト後の戻り先（post_logout_redirect_uri）のテスト用の値（#232）</summary>
        /// <remarks>
        /// **サイトごとに URL が違う**（net48 と net10.0 で待ち受けが別）ので、
        /// 定数で登録し、サーバ側で解決する（test_self_code / test_self_token と同じ考え）。
        /// </remarks>
        public const string TestSelfLogout = "test_self_logout";

        #endregion

        #region テスト用

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

        #endregion

        #region 再認証（max_age。#247）

        /// <summary>再認証を求めた時刻を保存するCookieのKey（#247）</summary>
        /// <remarks>
        /// **`max_age` の超過で再認証へ送ったことの印。**
        /// これが無いと、`max_age=0` のときに
        /// 「送る → 認証する → また超過している → 送る」で**繰り返しになる。**
        /// 印より後に認証されていれば、**一度は再認証した**と判断して先へ進む。
        /// </remarks>
        public const string ReAuthenticatedAt = "re_auth_at";

        #endregion

        #region 利用者の識別子（#151 の段階 3）

        /// <summary>
        /// 入力された識別子が、メアドの形かどうか（#151 の段階 3）
        /// </summary>
        /// <param name="identifier">サインイン画面に入力された値</param>
        /// <returns>メアドの形なら true</returns>
        /// <remarks>
        /// **利用者名とメアドの両方でサインインできる。**
        /// どちらとして引くかを、**`@` を含むかどうか**で決める。
        ///
        /// **新しい利用者名に `@` を禁じている**ので（<see cref="IsValidUserName"/>）、
        /// **この判定は曖昧にならない。**
        ///
        /// > **既存の利用者名は書き換えていない。** 以前は「利用者名＝メアド」だったため、
        /// > **`@` を含む利用者名が残っている。**
        /// > その利用者は**メアドとして引かれる**が、**値が同じなので同じ利用者に当たる。**
        /// </remarks>
        public static bool LooksLikeEmail(string identifier)
        {
            return !string.IsNullOrEmpty(identifier) && identifier.Contains("@");
        }

        /// <summary>
        /// 利用者名として使える値かどうか（#151 の段階 3）
        /// </summary>
        /// <param name="userName">利用者名</param>
        /// <returns>使えるなら true</returns>
        /// <remarks>
        /// **`@` を含む利用者名を認めない。**
        /// 認めると、**サインインの入力がメアドなのか利用者名なのか決まらない。**
        ///
        /// **新しく作る・変えるときだけ掛ける。**
        /// **既存の利用者名（以前の「利用者名＝メアド」）は、そのまま使い続けられる。**
        /// </remarks>
        public static bool IsValidUserName(string userName)
        {
            return !string.IsNullOrWhiteSpace(userName) && !userName.Contains("@");
        }

        /// <summary>
        /// メアドから、利用者名の既定値を作る（#151 の段階 3）
        /// </summary>
        /// <param name="email">メアド</param>
        /// <returns>`@` より前の部分（`@` が無ければ、そのまま）</returns>
        /// <remarks>
        /// **利用者名を別に決められない場面で使う。**
        ///
        /// | 使う場所 | なぜ |
        /// |---|---|
        /// | 管理者・テスト利用者の生成 | 設定にあるのは**メアドだけ**（`AdministratorUID`） |
        /// | 外部ログイン・ID 連携での新規作成 | 上流が返すのは `sub` と**メアド**で、利用者名は無い |
        ///
        /// **一意性は呼び出し側が確かめる。** ここは形を整えるだけ。
        /// </remarks>
        public static string UserNameFromEmail(string email)
        {
            if (string.IsNullOrEmpty(email))
            {
                return email;
            }

            int at = email.IndexOf('@');

            return (at > 0) ? email.Substring(0, at) : email;
        }

        #endregion
    }
}