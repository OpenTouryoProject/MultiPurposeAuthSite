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
//*  2026/10/30  玄人 幸道         外部ログインを大文字小文字まで比べる（SQL Server の照合順序で、違う sub が一致していた）・DB でも渡された user の一覧を揃える・mem の削除で隣り合う組を飛ばさない（#294）
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

        /// <summary>外部ログインの組が同じか</summary>
        /// <param name="x">UserLoginInfo</param>
        /// <param name="y">UserLoginInfo</param>
        /// <returns>同じなら true</returns>
        /// <remarks>
        /// **大文字小文字まで比べる**（#294）。`LoginProvider` は相手の `iss` / entityID、
        /// `ProviderKey` は相手の `sub` / NameID で、**どちらも大文字小文字を区別する値**である。
        /// </remarks>
        private static bool IsSameLogin(UserLoginInfo x, UserLoginInfo y)
        {
            return string.Equals(x.LoginProvider, y.LoginProvider, StringComparison.Ordinal)
                && string.Equals(x.ProviderKey, y.ProviderKey, StringComparison.Ordinal);
        }

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

                        // 下で、一覧に足す。

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

                //  **渡された user の一覧に足す**（#294）。
                //    **mem では、これが保存そのもの**（共有の実体）。
                //    **DB では、同じ要求の中で見えるようにする**（以前は足しておらず、古い一覧が見えていた）。
                user.Logins.Add(login);
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
                                    if (CmnUserStore.IsSameLogin(y, login))
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

                            //  **大文字小文字まで一致するものだけを採る**（#294）。
                            //    **照合は DB の照合順序に従う** — SQL Server の既定（CI）では、
                            //    **大文字小文字だけが違う `sub` / NameID も一致していた**（mem / ora / npg は区別する）。
                            //    **結び付けた値を読み直して、C# の側で Ordinal に比べ直す。**
                            foreach (ApplicationUser candidate in users)
                            {
                                // ユーザの関連情報の取得（ Roles, Logins, Claims, TotpTokens ）
                                CmnStore.SelectChildTablesOfUser(cnn, candidate);

                                if (candidate.Logins.Any(x => CmnUserStore.IsSameLogin(x, login)))
                                {
                                    user = candidate;
                                    break;
                                }
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

                        // 下で、一覧から消す。

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

                //  **渡された user の一覧から消す**（#294。mem では、これが保存そのもの）。
                //    **後ろから消す** — 以前は前から `RemoveAt` して、隣り合う同じ組を飛ばしていた。
                //    **DB でも消す**（以前は消しておらず、同じ要求の中で古い一覧が見えていた）。
                for (int i = user.Logins.Count - 1; i >= 0; i--)
                {
                    if (CmnUserStore.IsSameLogin(user.Logins[i], login))
                    {
                        user.Logins.RemoveAt(i);
                    }
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