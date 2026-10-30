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
//* クラス日本語名  ：CmnUserStore（ライブラリ）の 読み取り
//*
//* 作成日時        ：－
//* 作成者          ：－
//* 更新履歴        ：－
//*
//*  日時        更新者            内容
//*  ----------  ----------------  -------------------------------------------------
//*  2026/10/30  玄人 幸道         新規（CmnUserStore.cs から partial に分割。#294）
//*  2026/10/30  玄人 幸道         利用者の一覧で、失敗しても 500 にせず、mem でも検索条件と件数を効かせる・ToUpperInvariant に揃える（#294）
//*  2026/10/30  玄人 幸道         net48 の mem で、利用者名を大文字小文字を区別せずに引く（#294）
//**********************************************************************************

using MultiPurposeAuthSite.Co;
#if NETFX
using MultiPurposeAuthSite.Entity;
#else
using MultiPurposeAuthSite;
#endif
using MultiPurposeAuthSite.Password;
using MultiPurposeAuthSite.Log;
using MultiPurposeAuthSite.Util.Sts;
using MultiPurposeAuthSite.Util.IdP;

using System;
using System.Data;
using System.Linq;
using System.Collections.Generic;

using System.Reflection;

#if NETFX
using System.Web;
#else
using Microsoft.AspNetCore.Http;
using Touryo.Infrastructure.Framework.StdMigration;
#endif

using Dapper;

namespace MultiPurposeAuthSite.Data
{
    /// <summary>CmnUserStore（読み取り）</summary>
    internal partial class CmnUserStore
    {
        #region CRUD(共通)

        #region R (Read)

        /// <summary>ユーザを（Id指定で）検索</summary>
        /// <param name="userId">string</param>
        /// <returns>ApplicationUser</returns>
        public static ApplicationUser FindById(string userId)
        {
            // 参照系の機能のため、
            //OnlySts.STSOnly_M();

            // Debug
            Logging.MyDebugSQLTrace("★ : " +
                MethodBase.GetCurrentMethod().DeclaringType.FullName +
                "." + MethodBase.GetCurrentMethod().Name +
                Logging.GetParametersString(MethodBase.GetCurrentMethod().GetParameters()));

            ApplicationUser user = null;

            try
            {
                // ユーザを（Id指定で）検索

                // todo: 必要に応じて、ここに、STS専用モードでの実装を行う。
                if (OnlySts.STSOnly_P)
                {
                    #region STS専用モードのテストコード

                    // 既存のユーザストアに接続して、ユーザを返す。

                    // テスト：管理者ユーザを返す。
                    //   **どの Id でも管理者を返す**（テスト用のコード）。
                    //   **STS 専用の配備で使うなら、既存のユーザストアを引く実装に置き換える。**
                    user = ApplicationUser.CreateUser(
                        UserIdentifier.UserNameFromEmail(Config.AdministratorUID),
                        Config.AdministratorUID, true);
                    user.Id = userId;

#if NETFX
                    user.PasswordHash = (new CustomPasswordHasher()).HashPassword(Config.AdministratorPWD);
#else
                    user.PasswordHash = (new CustomPasswordHasher<ApplicationUser>()).HashPassword(user, Config.AdministratorPWD);
#endif

                    return user;

                    #endregion
                }

                // 通常のモードでの実装を行う。
                switch (Config.UserStoreType)
                {
                    case EnumUserStoreType.Memory:

                        user = CmnStore._users.FirstOrDefault(x => x.Id == userId);

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
                                        "SELECT * FROM [Users] WHERE [Id] = @userId", new { userId = userId });

                                    break;

                                case EnumUserStoreType.ODPManagedDriver:

                                    users = cnn.Query<ApplicationUser>(
                                        "SELECT * FROM \"Users\" WHERE \"Id\" = :userId", new { userId = userId });

                                    break;

                                case EnumUserStoreType.PostgreSQL:

                                    users = cnn.Query<ApplicationUser>(
                                        "SELECT * FROM \"users\" WHERE \"id\" = @userId", new { userId = userId });

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

        /// <summary>ユーザを（ユーザ名指定で）検索</summary>
        /// <param name="userName">string</param>
        /// <returns>ApplicationUser</returns>
        public static ApplicationUser FindByName(string userName)
        {
            // 参照系の機能のため、
            //OnlySts.STSOnly_M();

            // Debug
            Logging.MyDebugSQLTrace("★ : " +
                MethodBase.GetCurrentMethod().DeclaringType.FullName +
                "." + MethodBase.GetCurrentMethod().Name +
                Logging.GetParametersString(MethodBase.GetCurrentMethod().GetParameters()));

            ApplicationUser user = null;
            IEnumerable<ApplicationUser> users = null;

            try
            {
                // ユーザを（ユーザ名指定で）検索

                // todo: 必要に応じて、ここに、STS専用モードでの実装を行う。
                if (OnlySts.STSOnly_P)
                {
                    #region STS専用モードのテストコード

                    // 既存のユーザストアに接続して、ユーザを返す。

                    // テスト：管理者ユーザを返す。
#if NETFX
                    if (userName == Config.AdministratorUID)
#else
                    if (userName.ToUpperInvariant() == Config.AdministratorUID.ToUpperInvariant())
#endif
                    {
                        user = ApplicationUser.CreateUser(
                        UserIdentifier.UserNameFromEmail(Config.AdministratorUID),
                        Config.AdministratorUID, true);
#if NETFX
                        user.PasswordHash = (new CustomPasswordHasher()).HashPassword(Config.AdministratorPWD);
#else
                        user.PasswordHash = (new CustomPasswordHasher<ApplicationUser>()).HashPassword(user, Config.AdministratorPWD);
#endif
                    }

                    #endregion
                }
                else
                {
                    // 通常のモードでの実装を行う。
                    switch (Config.UserStoreType)
                    {
                        case EnumUserStoreType.Memory:

#if NETFX
                            //  **大文字小文字を区別しない**（#294。SQL Server の既定の照合順序に揃える。
                            //    以前は区別していて、大文字小文字だけが違う利用者を作れた）。
                            user = CmnStore._users.FirstOrDefault(
                                x => string.Equals(x.UserName, userName, StringComparison.OrdinalIgnoreCase));
#else
                            user = CmnStore._users.FirstOrDefault(x => x.NormalizedUserName == userName.ToUpperInvariant());
#endif

                            break;

                        case EnumUserStoreType.SqlServer:
                        case EnumUserStoreType.ODPManagedDriver:
                        case EnumUserStoreType.PostgreSQL: // DMBMS Provider

                            using (IDbConnection cnn = DataAccess.CreateConnection())
                            {
                                cnn.Open();

                                // ユーザの情報の取得
                                switch (Config.UserStoreType)
                                {
                                    case EnumUserStoreType.SqlServer:
#if NETFX
                                        users = cnn.Query<ApplicationUser>(
                                            "SELECT * FROM [Users] WHERE [UserName] = @userName", new { userName = userName });
#else
                                        users = cnn.Query<ApplicationUser>(
                                            "SELECT * FROM [Users] WHERE [NormalizedUserName] = @userName", new { userName = userName.ToUpperInvariant() });
#endif
                                        break;

                                    case EnumUserStoreType.ODPManagedDriver:
#if NETFX
                                        users = cnn.Query<ApplicationUser>(
                                            "SELECT * FROM \"Users\" WHERE \"UserName\" = :userName", new { userName = userName });
#else
                                        users = cnn.Query<ApplicationUser>(
                                            "SELECT * FROM \"Users\" WHERE \"NormalizedUserName\" = :userName", new { userName = userName.ToUpperInvariant() });
#endif
                                        break;

                                    case EnumUserStoreType.PostgreSQL:
#if NETFX
                                        users = cnn.Query<ApplicationUser>(
                                            "SELECT * FROM \"users\" WHERE \"username\" = @userName", new { userName = userName });
#else
                                        users = cnn.Query<ApplicationUser>(
                                            "SELECT * FROM \"users\" WHERE \"normalizedusername\" = @userName", new { userName = userName.ToUpperInvariant() });
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
            }
            catch (Exception ex)
            {
                Logging.MySQLLogForEx(ex);
            }

            return user;
        }

        /// <summary>ユーザ一覧を返す。</summary>
        /// <remarks>
        /// ★ マルチテナント化対応を施した
        /// （場合によってはページングも必要になる）
        /// </remarks>
        public static IQueryable<ApplicationUser> Users
        {
            get
            {
                // 管理系の機能のため、
                OnlySts.STSOnly_M();

                // Debug
                Logging.MyDebugSQLTrace("★ : " +
                    MethodBase.GetCurrentMethod().DeclaringType.FullName +
                    "." + MethodBase.GetCurrentMethod().Name +
                    Logging.GetParametersString(MethodBase.GetCurrentMethod().GetParameters()));

                IEnumerable<ApplicationUser> users = null;

                // ASP.NET Identity上に検索条件を渡すI/Fが無いので已む無くSession。
                string searchConditionOfUsers = "";
#if NETFX
                searchConditionOfUsers = (string)HttpContext.Current.Session["SearchConditionOfUsers"];
                HttpContext.Current.Session["SearchConditionOfUsers"] = ""; // クリアしないと・・・
#else
                searchConditionOfUsers = (string)MyHttpContext.Current.Session.GetString("SearchConditionOfUsers");
                MyHttpContext.Current.Session.SetString("SearchConditionOfUsers", ""); // クリアしないと・・・
#endif

                // 検索条件で検索されたユーザ一覧を返す。
                try
                {
                    switch (Config.UserStoreType)
                    {
                        case EnumUserStoreType.Memory:

                            //  **検索条件と件数を、DB と同じく効かせる**（#294。以前は全件を返していた）。
                            //    `Like` と同じく部分一致。**大文字小文字は区別しない**（SQL Server の既定の照合順序に揃える）。
                            users = CmnStore._users
                                .Where(x => string.IsNullOrEmpty(searchConditionOfUsers)
                                    || (x.UserName ?? "").IndexOf(searchConditionOfUsers, StringComparison.OrdinalIgnoreCase) >= 0)
                                .Take(Config.UserListCount)
                                .ToList();

                            break;

                        case EnumUserStoreType.SqlServer:
                        case EnumUserStoreType.ODPManagedDriver:
                        case EnumUserStoreType.PostgreSQL: // DMBMS Provider

                            string sql = "";
                            using (IDbConnection cnn = DataAccess.CreateConnection())
                            {
                                switch (Config.UserStoreType)
                                {
                                    case EnumUserStoreType.SqlServer:

                                        sql = "SELECT TOP {0} * FROM [Users] ";

                                        // Like
                                        if (!string.IsNullOrEmpty(searchConditionOfUsers))
                                        {
                                            if (sql.IndexOf(" WHERE ") == -1)
                                                sql += " WHERE";
                                            else
                                                sql += " AND";

                                            sql += " [UserName] Like CONCAT('%', @searchConditionOfUsers, '%')";
                                        }

                                        // TOP（`UserListCount` は int なので、空の場合は無い）
                                        sql = string.Format(sql, Config.UserListCount);

                                        break;

                                    case EnumUserStoreType.ODPManagedDriver:

                                        sql = "SELECT * FROM \"Users\" WHERE ROWNUM <= {0}";

                                        // Like
                                        if (!string.IsNullOrEmpty(searchConditionOfUsers))
                                            sql += " AND \"UserName\" Like '%' || :searchConditionOfUsers || '%'";

                                        // TOP（`UserListCount` は int なので、空の場合は無い）
                                        sql = string.Format(sql, Config.UserListCount);

                                        break;

                                    case EnumUserStoreType.PostgreSQL:

                                        sql = "SELECT * FROM \"users\"";

                                        // Like
                                        if (!string.IsNullOrEmpty(searchConditionOfUsers))
                                        {
                                            if (sql.IndexOf(" WHERE ") == -1)
                                                sql += " WHERE";
                                            else
                                                sql += " AND";

                                            sql += " \"username\" Like CONCAT('%', @searchConditionOfUsers, '%')";
                                        }

                                        // TOP
                                        sql += " LIMIT {0}";
                                        sql = string.Format(sql, Config.UserListCount);

                                        break;
                                }

                                cnn.Open();
                                users = cnn.Query<ApplicationUser>(sql, new
                                {
                                    searchConditionOfUsers = searchConditionOfUsers
                                });
                            }

                            break;
                    }
                }
                catch (Exception ex)
                {
                    Logging.MySQLLogForEx(ex);
                }

                // IQueryableとして戻す。
                //   **読み取りの失敗は、空の一覧にする**（#294。以前は null のまま `AsQueryable` を呼び、500 になっていた）。
                return (users ?? new List<ApplicationUser>()).AsQueryable();
            }
        }

        #endregion

        #endregion
    }
}