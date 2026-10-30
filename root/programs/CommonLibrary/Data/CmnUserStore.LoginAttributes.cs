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
//* クラス名        ：CmnUserStore
//* クラス日本語名  ：CmnUserStore（ライブラリ）の ログイン属性
//*
//* 作成日時        ：－
//* 作成者          ：－
//* 更新履歴        ：－
//*
//*  日時        更新者            内容
//*  ----------  ----------------  -------------------------------------------------
//*  2026/10/30  玄人 幸道         新規（CmnUserStore.cs から partial に分割。#294）
//*  2026/10/30  玄人 幸道         ロックアウトの終了日時を UTC で保存する（#294）
//**********************************************************************************

#if NETFX
using MultiPurposeAuthSite.Entity;
#else
using MultiPurposeAuthSite;
#endif
using MultiPurposeAuthSite.Log;

using System;

using System.Reflection;

namespace MultiPurposeAuthSite.Data
{
    /// <summary>CmnUserStore（ログイン属性）</summary>
    internal partial class CmnUserStore
    {
        #region ログイン属性

        #region IUserSecurityStampStore

        /// <summary>セキュリティスタンプを設定</summary>
        /// <param name="user">ApplicationUser</param>
        /// <param name="stamp">string</param>
        public static void SetSecurityStamp(ApplicationUser user, string stamp)
        {
            // ストレージを直接、触らない。
            //OnlySts.STSOnly_M();

            // Debug
            Logging.MyDebugSQLTrace(
                MethodBase.GetCurrentMethod().DeclaringType.FullName +
                "." + MethodBase.GetCurrentMethod().Name +
                Logging.GetParametersString(MethodBase.GetCurrentMethod().GetParameters()));

            // セキュリティスタンプを設定
            user.SecurityStamp = stamp;

            return;
        }

        /// <summary>セキュリティスタンプを取得</summary>
        /// <param name="user">ApplicationUser</param>
        /// <returns>SecurityStamp</returns>
        public static string GetSecurityStamp(ApplicationUser user)
        {
            // ストレージを直接、触らない。
            //OnlySts.STSOnly_M();

            // Debug
            Logging.MyDebugSQLTrace(
                MethodBase.GetCurrentMethod().DeclaringType.FullName +
                "." + MethodBase.GetCurrentMethod().Name +
                Logging.GetParametersString(MethodBase.GetCurrentMethod().GetParameters()));

            // セキュリティスタンプを取得
            return user.SecurityStamp;
        }

        #endregion

        #region IUserLockoutStore

        /// <summary>ユーザがロックアウト可能かどうかを設定</summary>
        /// <param name="user">ApplicationUser</param>
        /// <param name="enabled">真・偽：ユーザがロックアウト可能かどうか</param>
        public static void SetLockoutEnabled(ApplicationUser user, bool enabled)
        {
            // ストレージを直接、触らない。
            //OnlySts.STSOnly_M();

            // Debug
            Logging.MyDebugSQLTrace(
                MethodBase.GetCurrentMethod().DeclaringType.FullName +
                "." + MethodBase.GetCurrentMethod().Name +
                Logging.GetParametersString(MethodBase.GetCurrentMethod().GetParameters()));

            // ユーザがロックアウト可能かどうかを設定
            user.LockoutEnabled = enabled;

            return;
        }

        /// <summary>ユーザがロックアウト可能かどうかを取得</summary>
        /// <param name="user">ApplicationUser</param>
        /// <returns>真・偽：ユーザがロックアウト可能かどうか</returns>
        public static bool GetLockoutEnabled(ApplicationUser user)
        {
            // ストレージを直接、触らない。
            //OnlySts.STSOnly_M();

            // Debug
            Logging.MyDebugSQLTrace(
                MethodBase.GetCurrentMethod().DeclaringType.FullName +
                "." + MethodBase.GetCurrentMethod().Name +
                Logging.GetParametersString(MethodBase.GetCurrentMethod().GetParameters()));

            // ユーザがロックアウト可能かどうかを取得
            return user.LockoutEnabled;
        }

        /// <summary>サインインに失敗した試行回数を記録</summary>
        /// <param name="user">ApplicationUser</param>
        /// <returns>サインインに失敗した試行回数</returns>
        public static int IncrementAccessFailedCount(ApplicationUser user)
        {
            // ストレージを直接、触らない。
            //OnlySts.STSOnly_M();

            // Debug
            Logging.MyDebugSQLTrace(
                MethodBase.GetCurrentMethod().DeclaringType.FullName +
                "." + MethodBase.GetCurrentMethod().Name +
                Logging.GetParametersString(MethodBase.GetCurrentMethod().GetParameters()));

            // サインインに失敗した試行回数を記録
            user.AccessFailedCount++;

            return user.AccessFailedCount;
        }

        /// <summary>失敗したサインインの試行回数を取得</summary>
        /// <param name="user">ApplicationUser</param>
        /// <returns>現在の失敗したサインインの試行回数</returns>
        /// <remarks>パスワードが確認されるか、アカウントがロックアウトされるたびに、この数は、リセットされる。</remarks>
        public static int GetAccessFailedCount(ApplicationUser user)
        {
            // ストレージを直接、触らない。
            //OnlySts.STSOnly_M();

            // Debug
            Logging.MyDebugSQLTrace(
                MethodBase.GetCurrentMethod().DeclaringType.FullName +
                "." + MethodBase.GetCurrentMethod().Name +
                Logging.GetParametersString(MethodBase.GetCurrentMethod().GetParameters()));

            // 失敗したサインインの試行回数を取得
            return user.AccessFailedCount;
        }

        /// <summary>失敗したサインインの試行回数をリセット</summary>
        /// <param name="user">ApplicationUser</param>
        /// <remarks>
        /// 慣例的に、サインインが成功した場合にリセットされる。
        /// </remarks>
        public static void ResetAccessFailedCount(ApplicationUser user)
        {
            // ストレージを直接、触らない。
            //OnlySts.STSOnly_M();

            // Debug
            Logging.MyDebugSQLTrace(
                MethodBase.GetCurrentMethod().DeclaringType.FullName +
                "." + MethodBase.GetCurrentMethod().Name +
                Logging.GetParametersString(MethodBase.GetCurrentMethod().GetParameters()));

            // 失敗したサインインの試行回数をリセット
            user.AccessFailedCount = 0;

            return;
        }

        /// <summary>
        /// ロックアウト終了日を設定
        /// （指定された終了日まで、ユーザをロックアウト）
        /// </summary>
        /// <param name="user">ApplicationUser</param>
        /// <param name="lockoutEnd">ロックアウト終了日</param>
        /// <remarks>
        /// 過去の日付に設定すると、ロックアウトを解除する。
        /// </remarks>
        public static void SetLockoutEndDate(ApplicationUser user, DateTimeOffset? lockoutEnd)
        {
            // ストレージを直接、触らない。
            //OnlySts.STSOnly_M();

            // Debug
            Logging.MyDebugSQLTrace(
                MethodBase.GetCurrentMethod().DeclaringType.FullName +
                "." + MethodBase.GetCurrentMethod().Name +
                Logging.GetParametersString(MethodBase.GetCurrentMethod().GetParameters()));

            // ロックアウト終了日を設定（指定された終了日まで、ユーザをロックアウト）

            // DateTime と DateTimeOffset 間の変換
            // https://msdn.microsoft.com/ja-jp/library/bb546101.aspx
            if (lockoutEnd.HasValue)
            {
                //  **UTC に直して保存する**（#294。以前は `.DateTime` で、UTC 以外の時差を渡されるとずれた）。
                user.LockoutEndDateUtc = lockoutEnd.Value.UtcDateTime;
            }
            else
            {
                user.LockoutEndDateUtc = null;
            }

            return;
        }

        /// <summary>
        /// ロックアウト終了日を取得
        /// （指定された終了日まで、ユーザをロックアウト）</summary>
        /// <param name="user">ApplicationUser</param>
        /// <returns>ロックアウト終了日</returns>
        /// <remarks>
        /// 過去の日付を返すときは既にロックアウトされていない。
        /// </remarks>
        public static DateTimeOffset? GetLockoutEndDate(ApplicationUser user)
        {
            // ストレージを直接、触らない。
            //OnlySts.STSOnly_M();

            // Debug
            Logging.MyDebugSQLTrace(
                MethodBase.GetCurrentMethod().DeclaringType.FullName +
                "." + MethodBase.GetCurrentMethod().Name +
                Logging.GetParametersString(MethodBase.GetCurrentMethod().GetParameters()));

            // ロックアウト終了日を取得（指定された終了日まで、ユーザをロックアウト）

            // DateTime と DateTimeOffset 間の変換
            // https://msdn.microsoft.com/ja-jp/library/bb546101.aspx

            if (user.LockoutEndDateUtc.HasValue)
            {
                return DateTime.SpecifyKind(user.LockoutEndDateUtc.Value, DateTimeKind.Utc);
            }
            else
            {
                return null;
            }
        }

        #endregion

        #region IUserTwoFactor...
        
        #region IUserTwoFactorStore

        /// <summary>2FAの有効・無効を設定</summary>
        /// <param name="user">ApplicationUser</param>
        /// <param name="enabled">真・偽：2FAが有効かどうか</param>
        public static void SetTwoFactorEnabled(ApplicationUser user, bool enabled)
        {
            // ストレージを直接、触らない。
            //OnlySts.STSOnly_M();

            // Debug
            Logging.MyDebugSQLTrace(
                MethodBase.GetCurrentMethod().DeclaringType.FullName +
                "." + MethodBase.GetCurrentMethod().Name +
                Logging.GetParametersString(MethodBase.GetCurrentMethod().GetParameters()));

            // 2FAの有効・無効を設定
            user.TwoFactorEnabled = enabled;

            return;
        }

        /// <summary>2FAの有効・無効を取得</summary>
        /// <param name="user">ApplicationUser</param>
        /// <returns>真・偽：2FAが有効かどうか</returns>
        public static bool GetTwoFactorEnabled(ApplicationUser user)
        {
            // ストレージを直接、触らない。
            //OnlySts.STSOnly_M();

            // Debug
            Logging.MyDebugSQLTrace(
                MethodBase.GetCurrentMethod().DeclaringType.FullName +
                "." + MethodBase.GetCurrentMethod().Name +
                Logging.GetParametersString(MethodBase.GetCurrentMethod().GetParameters()));

            // 2FAの有効・無効を取得

            return user.TwoFactorEnabled;
        }

        #endregion

#if NETFX
#else
        #region UserAuthenticatorKeyStore

        /// <summary>SetAuthenticatorKey</summary>
        /// <param name="user">ApplicationUser</param>
        /// <param name="key">string</param>
        public static void SetAuthenticatorKey(ApplicationUser user, string key)
        {
            // ストレージを直接、触らない。
            //OnlySts.STSOnly_M();

            // Debug
            Logging.MyDebugSQLTrace(
                MethodBase.GetCurrentMethod().DeclaringType.FullName +
                "." + MethodBase.GetCurrentMethod().Name +
                Logging.GetParametersString(MethodBase.GetCurrentMethod().GetParameters()));

            user.TotpAuthenticatorKey = key;

            return;
        }

        /// <summary>GetAuthenticatorKey</summary>
        /// <param name="user">ApplicationUser</param>
        /// <returns>key string</returns>
        public static string GetAuthenticatorKey(ApplicationUser user)
        {
            // ストレージを直接、触らない。
            //OnlySts.STSOnly_M();

            // Debug
            Logging.MyDebugSQLTrace(
                MethodBase.GetCurrentMethod().DeclaringType.FullName +
                "." + MethodBase.GetCurrentMethod().Name +
                Logging.GetParametersString(MethodBase.GetCurrentMethod().GetParameters()));

            return user.TotpAuthenticatorKey;
        }

        #endregion
#endif

        // 以下は、Collection (TotpTokens)に実装。
        // - IUserAuthenticationTokenStore
        // - IUserTwoFactorRecoveryCodeStore

        #endregion

        #endregion
    }
}