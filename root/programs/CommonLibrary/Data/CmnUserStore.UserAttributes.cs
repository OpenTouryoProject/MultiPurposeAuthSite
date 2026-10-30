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
//* クラス日本語名  ：CmnUserStore（ライブラリ）の ユーザ属性
//*
//* 作成日時        ：－
//* 作成者          ：－
//* 更新履歴        ：－
//*
//*  日時        更新者            内容
//*  ----------  ----------------  -------------------------------------------------
//*  2026/10/30  玄人 幸道         新規（CmnUserStore.cs から partial に分割。#294）
//*  2026/10/30  玄人 幸道         STS 専用モードでの FindByEmail の扱いを記した（#294）
//**********************************************************************************

using MultiPurposeAuthSite.Co;
#if NETFX
using MultiPurposeAuthSite.Entity;
#else
using MultiPurposeAuthSite;
#endif
using MultiPurposeAuthSite.Log;
using MultiPurposeAuthSite.Util.Sts;

using System;
using System.Data;
using System.Linq;
using System.Collections.Generic;

using System.Reflection;

using Dapper;

namespace MultiPurposeAuthSite.Data
{
    /// <summary>CmnUserStore（ユーザ属性）</summary>
    internal partial class CmnUserStore
    {
        #region ユーザ属性

        #region IUserPasswordStore

        /// <summary>ユーザがパスワードを持っているか</summary>
        /// <param name="user">ApplicationUser</param>
        /// <returns>真・偽：ユーザがパスワードを持っているか</returns>
        public static bool HasPassword(ApplicationUser user)
        {
            // ストレージを直接、触らない。
            //OnlySts.STSOnly_M();

            // Debug
            Logging.MyDebugSQLTrace(
                MethodBase.GetCurrentMethod().DeclaringType.FullName +
                "." + MethodBase.GetCurrentMethod().Name +
                Logging.GetParametersString(MethodBase.GetCurrentMethod().GetParameters()));

            // ユーザがパスワードを持っているか
            return !string.IsNullOrEmpty(user.PasswordHash);
        }

        /// <summary>ユーザーにハッシュ化されたパスワードを設定</summary>
        /// <param name="user">ApplicationUser</param>
        /// <param name="passwordHash">string</param>
        public static void SetPasswordHash(ApplicationUser user, string passwordHash)
        {
            // ストレージを直接、触らない。
            //OnlySts.STSOnly_M();

            // Debug
            Logging.MyDebugSQLTrace(
                MethodBase.GetCurrentMethod().DeclaringType.FullName +
                "." + MethodBase.GetCurrentMethod().Name +
                Logging.GetParametersString(MethodBase.GetCurrentMethod().GetParameters()));

            // ユーザーにハッシュ化されたパスワードを設定
            user.PasswordHash = passwordHash;

            return;
        }

        /// <summary>ユーザのパスワードのハッシュを取得</summary>
        /// <param name="user">ApplicationUser</param>
        /// <returns>パスワードのハッシュ</returns>
        public static string GetPasswordHash(ApplicationUser user)
        {
            // ストレージを直接、触らない。
            //OnlySts.STSOnly_M();

            // Debug
            Logging.MyDebugSQLTrace(
                MethodBase.GetCurrentMethod().DeclaringType.FullName +
                "." + MethodBase.GetCurrentMethod().Name +
                Logging.GetParametersString(MethodBase.GetCurrentMethod().GetParameters()));

            // ユーザのパスワードのハッシュを取得

            if (string.IsNullOrEmpty(user.PasswordHash))
            {
                return null;
            }
            else
            {
                return user.PasswordHash;
            }
        }

        #endregion

        #region IUserEmailStore

        /// <summary>ユーザを（email指定で）検索して取得</summary>
        /// <param name="email">string</param>
        /// <returns>ApplicationUser</returns>
        public static ApplicationUser FindByEmail(string email)
        {
            // 参照系の機能のため、
            //   **STS 専用モードでは例外を投げる**（`FindById` / `FindByName` と違い、テスト用の分岐を持たない）。
            OnlySts.STSOnly_M();

            // Debug
            Logging.MyDebugSQLTrace("★ : " +
                MethodBase.GetCurrentMethod().DeclaringType.FullName +
                "." + MethodBase.GetCurrentMethod().Name +
                Logging.GetParametersString(MethodBase.GetCurrentMethod().GetParameters()));

            ApplicationUser user = null;

            try
            {
                // ユーザを（email指定で）検索して取得
                switch (Config.UserStoreType)
                {
                    case EnumUserStoreType.Memory:

#if NETFX
                        user = CmnStore._users.FirstOrDefault(x => x.Email == email);
#else
                        user = CmnStore._users.FirstOrDefault(x => x.NormalizedEmail == email);
#endif

                        break;

                    case EnumUserStoreType.SqlServer:
                    case EnumUserStoreType.ODPManagedDriver:
                    case EnumUserStoreType.PostgreSQL: // DMBMS Provider

                        using (IDbConnection cnn = DataAccess.CreateConnection())
                        {
                            cnn.Open();

                            // ユーザの情報の取得
                            IEnumerable<ApplicationUser> users = null;

                            switch (Config.UserStoreType)
                            {
                                case EnumUserStoreType.SqlServer:
#if NETFX
                                    users = cnn.Query<ApplicationUser>(
                                        "SELECT * From [Users] WHERE [Email] = @Email", new { Email = email });
#else
                                    users = cnn.Query<ApplicationUser>(
                                        "SELECT * From [Users] WHERE [NormalizedEmail] = @Email", new { Email = email });
#endif
                                    break;

                                case EnumUserStoreType.ODPManagedDriver:
#if NETFX
                                    users = cnn.Query<ApplicationUser>(
                                        "SELECT * From \"Users\" WHERE \"Email\" = :Email", new { Email = email });
#else
                                    users = cnn.Query<ApplicationUser>(
                                        "SELECT * From \"Users\" WHERE \"NormalizedEmail\" = :Email", new { Email = email });
#endif
                                    break;

                                case EnumUserStoreType.PostgreSQL:
#if NETFX
                                    users = cnn.Query<ApplicationUser>(
                                        "SELECT * From \"users\" WHERE \"email\" = @Email", new { Email = email });
#else
                                    users = cnn.Query<ApplicationUser>(
                                        "SELECT * From \"users\" WHERE \"normalizedemail\" = @Email", new { Email = email });
#endif
                                    break;
                            }

                            if (users.Count() != 0)
                            {
                                user = users.First();

                                // ユーザの関連情報の取得（ Roles, Logins, Claims, TotpTokens ）
                                CmnStore.SelectChildTablesOfUser(cnn, user);
                            }
                        }

                        break;
                }
            }
            catch (Exception ex)
            {
                Logging.MySQLLogForEx(ex);
            }

            return user;
        }

        /// <summary>メアドの設定</summary>
        /// <param name="user">ApplicationUser</param>
        /// <param name="email">string</param>
        /// <returns>－</returns>
        public static void SetEmail(ApplicationUser user, string email)
        {
            // ストレージを直接、触らない。
            //OnlySts.STSOnly_M();

            // Debug
            Logging.MyDebugSQLTrace(
                MethodBase.GetCurrentMethod().DeclaringType.FullName +
                "." + MethodBase.GetCurrentMethod().Name +
                Logging.GetParametersString(MethodBase.GetCurrentMethod().GetParameters()));

            // メアドの設定
            user.Email = email;

            return;
        }

        /// <summary>メアドの取得</summary>
        /// <param name="user">ApplicationUser</param>
        /// <returns>Email</returns>
        public static string GetEmail(ApplicationUser user)
        {
            // ストレージを直接、触らない。
            //OnlySts.STSOnly_M();

            // Debug
            Logging.MyDebugSQLTrace(
                MethodBase.GetCurrentMethod().DeclaringType.FullName +
                "." + MethodBase.GetCurrentMethod().Name +
                Logging.GetParametersString(MethodBase.GetCurrentMethod().GetParameters()));

            // メアドの取得
            return user.Email;
        }

        /// <summary>メアド確認の設定</summary>
        /// <param name="user">ApplicationUser</param>
        /// <param name="confirmed">bool</param>
        public static void SetEmailConfirmed(ApplicationUser user, bool confirmed)
        {
            // ストレージを直接、触らない。
            //OnlySts.STSOnly_M();

            // Debug
            Logging.MyDebugSQLTrace(
                MethodBase.GetCurrentMethod().DeclaringType.FullName +
                "." + MethodBase.GetCurrentMethod().Name +
                Logging.GetParametersString(MethodBase.GetCurrentMethod().GetParameters()));

            // メアド確認の設定
            user.EmailConfirmed = confirmed;

            return;
        }

        /// <summary>メアド確認の取得</summary>
        /// <param name="user">ApplicationUser</param>
        /// <returns>EmailConfirmed</returns>
        public static bool GetEmailConfirmed(ApplicationUser user)
        {
            // ストレージを直接、触らない。
            //OnlySts.STSOnly_M();

            // Debug
            Logging.MyDebugSQLTrace(
                MethodBase.GetCurrentMethod().DeclaringType.FullName +
                "." + MethodBase.GetCurrentMethod().Name +
                Logging.GetParametersString(MethodBase.GetCurrentMethod().GetParameters()));

            // メアド確認の取得
            return user.EmailConfirmed;
        }

        /// <summary>メアドの設定</summary>
        /// <param name="user">ApplicationUser</param>
        /// <param name="normalizedEmail">string</param>
        public static void SetNormalizedEmail(ApplicationUser user, string normalizedEmail)
        {
            // ストレージを直接、触らない。
            //OnlySts.STSOnly_M();

            // Debug
            Logging.MyDebugSQLTrace(
                MethodBase.GetCurrentMethod().DeclaringType.FullName +
                "." + MethodBase.GetCurrentMethod().Name +
                Logging.GetParametersString(MethodBase.GetCurrentMethod().GetParameters()));

            // Normalizedメアドの設定
            user.NormalizedEmail = normalizedEmail;

            return;
        }

        /// <summary>Normalizedメアドの取得</summary>
        /// <param name="user">ApplicationUser</param>
        /// <returns>NormalizedEmail</returns>
        public static string GetNormalizedEmail(ApplicationUser user)
        {
            // ストレージを直接、触らない。
            //OnlySts.STSOnly_M();

            // Debug
            Logging.MyDebugSQLTrace(
                MethodBase.GetCurrentMethod().DeclaringType.FullName +
                "." + MethodBase.GetCurrentMethod().Name +
                Logging.GetParametersString(MethodBase.GetCurrentMethod().GetParameters()));

            // Normalizedメアドの取得
            return user.NormalizedEmail;
        }

        #endregion

        #region IUserPhoneNumberStore

        /// <summary>電話番号の設定</summary>
        /// <param name="user">ApplicationUser</param>
        /// <param name="phoneNumber">string</param>
        public static void SetPhoneNumber(ApplicationUser user, string phoneNumber)
        {
            // ストレージを直接、触らない。
            //OnlySts.STSOnly_M();

            // Debug
            Logging.MyDebugSQLTrace(
                MethodBase.GetCurrentMethod().DeclaringType.FullName +
                "." + MethodBase.GetCurrentMethod().Name +
                Logging.GetParametersString(MethodBase.GetCurrentMethod().GetParameters()));

            // 電話番号の設定
            user.PhoneNumber = phoneNumber;

            return;
        }

        /// <summary>電話番号の取得</summary>
        /// <param name="user">ApplicationUser</param>
        /// <returns>phone number</returns>
        public static string GetPhoneNumber(ApplicationUser user)
        {
            // ストレージを直接、触らない。
            //OnlySts.STSOnly_M();

            // Debug
            Logging.MyDebugSQLTrace(
                MethodBase.GetCurrentMethod().DeclaringType.FullName +
                "." + MethodBase.GetCurrentMethod().Name +
                Logging.GetParametersString(MethodBase.GetCurrentMethod().GetParameters()));

            // 電話番号の取得
            return user.PhoneNumber;
        }

        /// <summary>電話番号確認の設定</summary>
        /// <param name="user">ApplicationUser</param>
        /// <param name="confirmed">bool</param>
        public static void SetPhoneNumberConfirmed(ApplicationUser user, bool confirmed)
        {
            // ストレージを直接、触らない。
            //OnlySts.STSOnly_M();

            // Debug
            Logging.MyDebugSQLTrace(
                MethodBase.GetCurrentMethod().DeclaringType.FullName +
                "." + MethodBase.GetCurrentMethod().Name +
                Logging.GetParametersString(MethodBase.GetCurrentMethod().GetParameters()));

            // 電話番号確認の設定
            user.PhoneNumberConfirmed = confirmed;

            return;
        }

        /// <summary>電話番号確認の取得</summary>
        /// <param name="user">ApplicationUser</param>
        /// <returns>phone number is confirmed</returns>
        public static bool GetPhoneNumberConfirmed(ApplicationUser user)
        {
            // ストレージを直接、触らない。
            //OnlySts.STSOnly_M();

            // Debug
            Logging.MyDebugSQLTrace(
                MethodBase.GetCurrentMethod().DeclaringType.FullName +
                "." + MethodBase.GetCurrentMethod().Name +
                Logging.GetParametersString(MethodBase.GetCurrentMethod().GetParameters()));

            // 電話番号確認の取得

            return user.PhoneNumberConfirmed;
        }

        #endregion

        #endregion
    }
}