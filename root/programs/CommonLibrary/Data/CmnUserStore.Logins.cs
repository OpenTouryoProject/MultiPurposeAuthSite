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
//* クラス日本語名  ：CmnUserStore（ライブラリ）の 外部ログイン
//*
//* 作成日時        ：－
//* 作成者          ：－
//* 更新履歴        ：－
//*
//*  日時        更新者            内容
//*  ----------  ----------------  -------------------------------------------------
//*  2026/10/30  玄人 幸道         新規（CmnUserStore.cs から partial に分割。#294）
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

#if NETFX
using Microsoft.AspNet.Identity;
#else
using Microsoft.AspNetCore.Identity;
#endif

using Dapper;

namespace MultiPurposeAuthSite.Data
{
    /// <summary>CmnUserStore（外部ログイン）</summary>
    internal partial class CmnUserStore
    {
        #region Collection

        #region Logins: IUserLoginStore

        /// <summary>ユーザーに外部ログインを追加</summary>
        /// <param name="user">ApplicationUser</param>
        /// <param name="login">UserLoginInfo</param>
        public static void AddLogin(ApplicationUser user, UserLoginInfo login)
        {
            // 他テーブルのため、
            OnlySts.STSOnly_M();

            // Debug
            Logging.MyDebugSQLTrace("★ : " +
                MethodBase.GetCurrentMethod().DeclaringType.FullName +
                "." + MethodBase.GetCurrentMethod().Name +
                Logging.GetParametersString(MethodBase.GetCurrentMethod().GetParameters()));

            try
            {
                // ユーザーに外部ログインを追加
                switch (Config.UserStoreType)
                {
                    case EnumUserStoreType.Memory:

                        user.Logins.Add(login);

                        break;

                    case EnumUserStoreType.SqlServer:
                    case EnumUserStoreType.ODPManagedDriver:
                    case EnumUserStoreType.PostgreSQL: // DMBMS Provider

                        using (IDbConnection cnn = DataAccess.CreateConnection())
                        {
                            cnn.Open();

                            switch (Config.UserStoreType)
                            {
                                case EnumUserStoreType.SqlServer:

                                    cnn.Execute(
                                        "INSERT INTO [UserLogins] ([UserId], [LoginProvider], [ProviderKey]) " +
                                        "VALUES (@UserId, @LoginProvider, @ProviderKey)",
                                        new { UserId = user.Id, LoginProvider = login.LoginProvider, ProviderKey = login.ProviderKey });

                                    break;

                                case EnumUserStoreType.ODPManagedDriver:

                                    cnn.Execute(
                                        "INSERT INTO \"UserLogins\" (\"UserId\", \"LoginProvider\", \"ProviderKey\") " +
                                        "VALUES (:UserId, :LoginProvider, :ProviderKey)",
                                        new { UserId = user.Id, LoginProvider = login.LoginProvider, ProviderKey = login.ProviderKey });

                                    break;

                                case EnumUserStoreType.PostgreSQL:

                                    cnn.Execute(
                                        "INSERT INTO \"userlogins\" (\"userid\", \"loginprovider\", \"providerkey\") " +
                                        "VALUES (@UserId, @LoginProvider, @ProviderKey)",
                                        new { UserId = user.Id, LoginProvider = login.LoginProvider, ProviderKey = login.ProviderKey });

                                    break;
                            }
                        }

                        break;
                }
            }
            catch (Exception ex)
            {
                //  **書き込みの失敗は、握らない**（#300）。**ログに書いてから投げ直す。**
                Logging.MySQLLogForEx(ex);
                throw;
            }

            return;
        }

        /// <summary>外部ログインでユーザーを検索</summary>
        /// <param name="user">ApplicationUser</param>
        /// <returns>ApplicationUser</returns>
        public static ApplicationUser Find(UserLoginInfo login)
        {
            // 他テーブルのため、
            OnlySts.STSOnly_M();

            // Debug
            Logging.MyDebugSQLTrace("★ : " +
                MethodBase.GetCurrentMethod().DeclaringType.FullName +
                "." + MethodBase.GetCurrentMethod().Name +
                Logging.GetParametersString(MethodBase.GetCurrentMethod().GetParameters()));

            ApplicationUser user = null;

            try
            {
                // 外部ログインでユーザーを検索
                switch (Config.UserStoreType)
                {
                    case EnumUserStoreType.Memory:

                        // LINQ挫折
                        foreach (ApplicationUser x in CmnStore._users)
                        {
                            if (x.Logins == null)
                            {
                                // null
                            }
                            else
                            {
                                foreach (UserLoginInfo y in x.Logins)
                                {
                                    if (y.LoginProvider == login.LoginProvider
                                         && y.ProviderKey == login.ProviderKey)
                                    {
                                        user = x;

                                        return user;
                                    }
                                }
                            }
                        }

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

                                    users = cnn.Query<ApplicationUser>(
                                        "SELECT * From [Users], [UserLogins] " + // * でイケるか？
                                        "WHERE  [Users].[Id] = [UserLogins].[UserId]" +
                                        "    AND [UserLogins].[LoginProvider] = @LoginProvider" +
                                        "    AND [UserLogins].[ProviderKey] = @ProviderKey",
                                        new { LoginProvider = login.LoginProvider, ProviderKey = login.ProviderKey });

                                    break;

                                case EnumUserStoreType.ODPManagedDriver:

                                    users = cnn.Query<ApplicationUser>(
                                        "SELECT * From \"Users\", \"UserLogins\" " + // * でイケるか？
                                        "WHERE  \"Users\".\"Id\" = \"UserLogins\".\"UserId\"" +
                                        "    AND \"UserLogins\".\"LoginProvider\" = :LoginProvider" +
                                        "    AND \"UserLogins\".\"ProviderKey\" = :ProviderKey",
                                        new { LoginProvider = login.LoginProvider, ProviderKey = login.ProviderKey });

                                    break;

                                case EnumUserStoreType.PostgreSQL:

                                    users = cnn.Query<ApplicationUser>(
                                        "SELECT * From \"users\", \"userlogins\" " + // * でイケるか？
                                        "WHERE  \"users\".\"id\" = \"userlogins\".\"userid\"" +
                                        "    AND \"userlogins\".\"loginprovider\" = @LoginProvider" +
                                        "    AND \"userlogins\".\"providerkey\" = @ProviderKey",
                                        new { LoginProvider = login.LoginProvider, ProviderKey = login.ProviderKey });

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

        /// <summary>ユーザの外部ログイン一覧を取得</summary>
        /// <param name="user">ApplicationUser</param>
        /// <returns>IList<UserLoginInfo></returns>>
        public static IList<UserLoginInfo> GetLogins(ApplicationUser user)
        {
            // 他テーブルのため、
            //OnlySts.STSOnly_M();
            if (OnlySts.STSOnly_P)
            {
                return new List<UserLoginInfo>();
            }

            // ストレージを直接、触らない。

            // Debug
            Logging.MyDebugSQLTrace(
                MethodBase.GetCurrentMethod().DeclaringType.FullName +
                "." + MethodBase.GetCurrentMethod().Name +
                Logging.GetParametersString(MethodBase.GetCurrentMethod().GetParameters()));

            // ユーザの外部ログイン一覧を取得

            return user.Logins;
        }

        /// <summary>ユーザーから外部ログインを削除</summary>
        /// <param name="user">ApplicationUser</param>
        /// <param name="login">UserLoginInfo</param>
        public static void RemoveLogin(ApplicationUser user, UserLoginInfo login)
        {
            // 他テーブルのため、
            OnlySts.STSOnly_M();

            // Debug
            Logging.MyDebugSQLTrace("★ : " +
                MethodBase.GetCurrentMethod().DeclaringType.FullName +
                "." + MethodBase.GetCurrentMethod().Name +
                Logging.GetParametersString(MethodBase.GetCurrentMethod().GetParameters()));

            try
            {
                // ユーザーから外部ログインを削除
                switch (Config.UserStoreType)
                {
                    case EnumUserStoreType.Memory:

                        for (int i = 0; i < user.Logins.Count; i++)
                        {
                            if (user.Logins[i].LoginProvider == login.LoginProvider
                                && user.Logins[i].ProviderKey == login.ProviderKey)
                            {
                                user.Logins.RemoveAt(i);
                            }
                        }

                        break;

                    case EnumUserStoreType.SqlServer:
                    case EnumUserStoreType.ODPManagedDriver:
                    case EnumUserStoreType.PostgreSQL: // DMBMS Provider

                        using (IDbConnection cnn = DataAccess.CreateConnection())
                        {
                            cnn.Open();

                            switch (Config.UserStoreType)
                            {
                                case EnumUserStoreType.SqlServer:

                                    cnn.Execute(
                                        "DELETE FROM [UserLogins] WHERE [UserId] = @UserId AND [LoginProvider] = @LoginProvider AND [ProviderKey] = @ProviderKey ",
                                        new { UserId = user.Id, LoginProvider = login.LoginProvider, ProviderKey = login.ProviderKey });

                                    break;

                                case EnumUserStoreType.ODPManagedDriver:

                                    cnn.Execute(
                                        "DELETE FROM \"UserLogins\" WHERE \"UserId\" = :UserId AND \"LoginProvider\" = :LoginProvider AND \"ProviderKey\" = :ProviderKey ",
                                        new { UserId = user.Id, LoginProvider = login.LoginProvider, ProviderKey = login.ProviderKey });

                                    break;

                                case EnumUserStoreType.PostgreSQL:

                                    cnn.Execute(
                                        "DELETE FROM \"userlogins\" WHERE \"userid\" = @UserId AND \"loginprovider\" = @LoginProvider AND \"providerkey\" = @ProviderKey ",
                                        new { UserId = user.Id, LoginProvider = login.LoginProvider, ProviderKey = login.ProviderKey });

                                    break;
                            }
                        }

                        break;
                }
            }
            catch (Exception ex)
            {
                //  **書き込みの失敗は、握らない**（#300）。**ログに書いてから投げ直す。**
                Logging.MySQLLogForEx(ex);
                throw;
            }

            return;
        }

        #endregion

        #endregion
    }
}