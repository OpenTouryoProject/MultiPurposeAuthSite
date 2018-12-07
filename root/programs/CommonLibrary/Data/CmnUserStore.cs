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
//* クラス名        ：BaseUserStore
//* クラス日本語名  ：BaseUserStore（ライブラリ）
//*
//* 作成日時        ：－
//* 作成者          ：－
//* 更新履歴        ：－
//*
//*  日時        更新者            内容
//*  ----------  ----------------  -------------------------------------------------
//*  2018/12/04  西野 大介         新規
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

using System;
using System.Data;
using System.Linq;
using System.Collections.Generic;

using System.Reflection;
using System.Security.Claims;

#if NETFX
using System.Web;
using Microsoft.AspNet.Identity;
#else
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Touryo.Infrastructure.Framework.StdMigration;
#endif

using Dapper;

/// <summary>MultiPurposeAuthSite.Data</summary>
namespace MultiPurposeAuthSite.Data
{
    /// <summary>BaseUserStore</summary>
    public class CmnUserStore : CmnStore
    {
        #region CRUD(共通)

        #region C (Create)

        /// <summary>新規ユーザーの追加</summary>
        /// <param name="user">ApplicationUser</param>
        public static void Create(ApplicationUser user)
        {
            // 更新系の機能のため、
            OnlySts.STSOnly_M();

            // Debug
            Logging.MyDebugSQLTrace("★ : " +
                MethodBase.GetCurrentMethod().DeclaringType.FullName +
                "." + MethodBase.GetCurrentMethod().Name +
                Logging.GetParametersString(MethodBase.GetCurrentMethod().GetParameters()));

            try
            {
                // 新規ユーザーの追加
                switch (Config.UserStoreType)
                {
                    case EnumUserStoreType.Memory:

                        CmnStore._users.Add(user);

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
                                        "INSERT INTO [Users] ( " +
                                        "    [Id], [UserName], [PasswordHash], " +
                                        "    [Email], [EmailConfirmed], [PhoneNumber], [PhoneNumberConfirmed], " +
                                        "    [LockoutEnabled], [AccessFailedCount], [LockoutEndDateUtc], [SecurityStamp], [TwoFactorEnabled], " +
                                        "    [ClientID], [PaymentInformation], [UnstructuredData], [FIDO2PublicKey], [CreatedDate], [PasswordChangeDate])" +
                                        "    VALUES ( " +
                                        "        @Id, @UserName, @PasswordHash, " +
                                        "        @Email, @EmailConfirmed, @PhoneNumber, @PhoneNumberConfirmed, " +
                                        "        @LockoutEnabled, @AccessFailedCount, @LockoutEndDateUtc, @SecurityStamp, @TwoFactorEnabled, " +
                                        "        @ClientID, @PaymentInformation, @UnstructuredData, @FIDO2PublicKey, @CreatedDate, @PasswordChangeDate)", user);

                                    break;

                                case EnumUserStoreType.ODPManagedDriver:

                                    cnn.Execute(
                                        "INSERT INTO \"Users\" ( " +
                                        "    \"Id\", \"UserName\", \"PasswordHash\", " +
                                        "    \"Email\", \"EmailConfirmed\", \"PhoneNumber\", \"PhoneNumberConfirmed\", " +
                                        "    \"LockoutEnabled\", \"AccessFailedCount\", \"LockoutEndDateUtc\", \"SecurityStamp\", \"TwoFactorEnabled\", " +
                                        "    \"ClientID\", \"PaymentInformation\", \"UnstructuredData\", \"FIDO2PublicKey\", \"CreatedDate\", \"PasswordChangeDate\")" +
                                        "    VALUES ( " +
                                        "        :Id, :UserName, :PasswordHash, " +
                                        "        :Email, :EmailConfirmed, :PhoneNumber, :PhoneNumberConfirmed, " +
                                        "        :LockoutEnabled, :AccessFailedCount, :LockoutEndDateUtc, :SecurityStamp, :TwoFactorEnabled, " +
                                        "        :ClientID, :PaymentInformation, :UnstructuredData, :FIDO2PublicKey, :CreatedDate, :PasswordChangeDate)",
                                        new // 拡張メソッドで対策できる。
                                        {
                                            Id = user.Id,
                                            UserName = user.UserName,
                                            PasswordHash = user.PasswordHash,
                                            Email = user.Email,
                                            EmailConfirmed = user.EmailConfirmed ? -1 : 0,
                                            PhoneNumber = user.PhoneNumber,
                                            PhoneNumberConfirmed = user.PhoneNumberConfirmed ? -1 : 0,
                                            LockoutEnabled = user.LockoutEnabled ? -1 : 0,
                                            AccessFailedCount = user.AccessFailedCount,
                                            LockoutEndDateUtc = user.LockoutEndDateUtc,
                                            SecurityStamp = user.SecurityStamp,
                                            TwoFactorEnabled = user.TwoFactorEnabled ? -1 : 0,
                                            ClientID = user.ClientID,
                                            PaymentInformation = user.PaymentInformation,
                                            UnstructuredData = user.UnstructuredData,
                                            FIDO2PublicKey = user.FIDO2PublicKey,
                                            CreatedDate = user.CreatedDate,
                                            PasswordChangeDate = user.PasswordChangeDate
                                        });

                                    break;

                                case EnumUserStoreType.PostgreSQL:

                                    cnn.Execute(
                                        "INSERT INTO \"users\" ( " +
                                        "    \"id\", \"username\", \"passwordhash\", " +
                                        "    \"email\", \"emailconfirmed\", \"phonenumber\", \"phonenumberconfirmed\", " +
                                        "    \"lockoutenabled\", \"accessfailedcount\", \"lockoutenddateutc\", \"securitystamp\", \"twofactorenabled\", " +
                                        "    \"clientid\", \"paymentinformation\", \"unstructureddata\", \"fido2publickey\", \"createddate\", \"passwordchangedate\")" +
                                        "    VALUES ( " +
                                        "        @Id, @UserName, @PasswordHash, " +
                                        "        @Email, @EmailConfirmed, @PhoneNumber, @PhoneNumberConfirmed, " +
                                        "        @LockoutEnabled, @AccessFailedCount, @LockoutEndDateUtc, @SecurityStamp, @TwoFactorEnabled, " +
                                        "        @ClientID, @PaymentInformation, @UnstructuredData, @FIDO2PublicKey, @CreatedDate, @PasswordChangeDate)", user);

                                    break;
                            }

                            // ユーザの関連情報は、このタイミングで追加しない（Roles, Logins, Claims）
                        }

                        break;

                }

                Logging.MyOperationTrace(string.Format("{0}({1}) was created.", user.Id, user.UserName));
            }
            catch (Exception ex)
            {
                Logging.MySQLLogForEx(ex);
            }

            return;
        }

        #endregion

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
                    user = ApplicationUser.CreateUser(Config.AdministratorUID, true);
                    user.Id = userId;

#if NETFX
                    user.PasswordHash = (new CustomPasswordHasher()).HashPassword(Config.AdministratorPWD);
#else
                    user.PasswordHash = (new CustomPasswordHasher()).HashPassword(user, Config.AdministratorPWD);
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

                                // ユーザの関連情報の取得（ Roles, Logins, Claims ）
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
                    if (userName == Config.AdministratorUID)
                    {
                        user = ApplicationUser.CreateUser(Config.AdministratorUID, true);
#if NETFX
                        user.PasswordHash = (new CustomPasswordHasher()).HashPassword(Config.AdministratorPWD);
#else
                        user.PasswordHash = (new CustomPasswordHasher()).HashPassword(user, Config.AdministratorPWD);
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

                            user = CmnStore._users.FirstOrDefault(x => x.UserName == userName);

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

                                        users = cnn.Query<ApplicationUser>(
                                            "SELECT * FROM [Users] WHERE [UserName] = @userName", new { userName = userName });

                                        break;

                                    case EnumUserStoreType.ODPManagedDriver:

                                        users = cnn.Query<ApplicationUser>(
                                            "SELECT * FROM \"Users\" WHERE \"UserName\" = :userName", new { userName = userName });

                                        break;

                                    case EnumUserStoreType.PostgreSQL:

                                        users = cnn.Query<ApplicationUser>(
                                            "SELECT * FROM \"users\" WHERE \"username\" = :userName", new { userName = userName });

                                        break;
                                }

                                if (users.Count() != 0)
                                {
                                    user = users.First();

                                    // ユーザの関連情報の取得（ Roles, Logins, Claims ）
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

                            IEnumerable<ApplicationUser> _users = CmnStore._users;
                            users = _users.ToList();

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

                                        // TOP
                                        if (!string.IsNullOrEmpty(Config.UserListCount.ToString()))
                                        {
                                            sql = string.Format(sql, "" + Config.UserListCount);
                                        }
                                        else
                                        {
                                            sql = string.Format(sql, 100);
                                        }

                                        break;

                                    case EnumUserStoreType.ODPManagedDriver:

                                        sql = "SELECT * FROM \"Users\" WHERE ROWNUM <= {0}";

                                        // Like
                                        if (!string.IsNullOrEmpty(searchConditionOfUsers))
                                            sql += " AND \"UserName\" Like '%' || :searchConditionOfUsers || '%'";

                                        // TOP
                                        if (!string.IsNullOrEmpty(Config.UserListCount.ToString()))
                                        {
                                            sql = string.Format(sql, Config.UserListCount);
                                        }
                                        else
                                        {
                                            sql = string.Format(sql, 100);
                                        }

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
                                        if (!string.IsNullOrEmpty(Config.UserListCount.ToString()))
                                        {
                                            sql = string.Format(sql, Config.UserListCount);
                                        }
                                        else
                                        {
                                            sql = string.Format(sql, 100);
                                        }

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
                return users.AsQueryable();
            }
        }

        #endregion

        #region U (Update)

        /// <summary>ユーザー情報を更新</summary>
        /// <param name="user">ApplicationUser</param>
        public static void Update(ApplicationUser user)
        {
            // 更新系の機能のため、
            //OnlySts.STSOnly_M();
            if (OnlySts.STSOnly_P)
            {
                // 何も更新しない。
                // IUserLockoutStore機能などで使用するため。
                return;
            }
            // Debug
            Logging.MyDebugSQLTrace("★ : " +
                MethodBase.GetCurrentMethod().DeclaringType.FullName +
                "." + MethodBase.GetCurrentMethod().Name +
                Logging.GetParametersString(MethodBase.GetCurrentMethod().GetParameters()));

            try
            {
                // MemoryStore同一インスタンス問題。
                // SerializeできないMemberもあり、DeepCloneもできず。

                // ユーザー情報を更新
                switch (Config.UserStoreType)
                {
                    case EnumUserStoreType.Memory:

                        // MemoryStore同一インスタンス

                        //// 既定の属性
                        //tgtUser.Id = user.Id;
                        //tgtUser.UserName = user.UserName;
                        //tgtUser.PasswordHash = user.PasswordHash;
                        //tgtUser.Email = user.Email;
                        //tgtUser.EmailConfirmed = user.EmailConfirmed;
                        //tgtUser.PhoneNumber = user.PhoneNumber;
                        //tgtUser.PhoneNumberConfirmed = user.PhoneNumberConfirmed;
                        //tgtUser.AccessFailedCount = user.AccessFailedCount;
                        //tgtUser.LockoutEnabled = user.LockoutEnabled;
                        //tgtUser.LockoutEndDateUtc = user.LockoutEndDateUtc;
                        //tgtUser.SecurityStamp = user.SecurityStamp;
                        //tgtUser.TwoFactorEnabled = user.TwoFactorEnabled;
                        //// Collection
                        //tgtUser.Roles = user.Roles;
                        //tgtUser.Logins = user.Logins;
                        //tgtUser.Claims = user.Claims;

                        //// 追加の属性
                        //tgtUser.ClientID = user.ClientID;
                        //tgtUser.PaymentInformation = user.PaymentInformation;
                        //tgtUser.UnstructuredData = user.UnstructuredData;
                        //tgtUser.FIDO2PublicKey = user.FIDO2PublicKey;

                        break;

                    case EnumUserStoreType.SqlServer:
                    case EnumUserStoreType.ODPManagedDriver:
                    case EnumUserStoreType.PostgreSQL: // DMBMS Provider

                        using (IDbConnection cnn = DataAccess.CreateConnection())
                        {
                            cnn.Open();

                            // ユーザー情報を更新
                            switch (Config.UserStoreType)
                            {
                                case EnumUserStoreType.SqlServer:

                                    cnn.Execute(
                                        "UPDATE [Users] " +
                                        "SET [UserName] = @UserName, [PasswordHash] = @PasswordHash, " +
                                        "    [Email] = @Email, [EmailConfirmed] = @EmailConfirmed, [PhoneNumber] = @PhoneNumber, [PhoneNumberConfirmed] = @PhoneNumberConfirmed, " +
                                        "    [LockoutEnabled] = @LockoutEnabled, [AccessFailedCount] = @AccessFailedCount, [LockoutEndDateUtc] = @LockoutEndDateUtc, [SecurityStamp] = @SecurityStamp, [TwoFactorEnabled] = @TwoFactorEnabled, " +
                                        "    [ClientID] = @ClientID, [PaymentInformation] = @PaymentInformation, [UnstructuredData] = @UnstructuredData, [FIDO2PublicKey] = @FIDO2PublicKey, [PasswordChangeDate] = @PasswordChangeDate " +
                                        "WHERE [Id] = @Id", user);

                                    break;

                                case EnumUserStoreType.ODPManagedDriver:

                                    cnn.Execute(
                                        "UPDATE \"Users\" " +
                                        "SET \"UserName\" = :UserName, \"PasswordHash\" = :PasswordHash, " +
                                        "    \"Email\" = :Email, \"EmailConfirmed\" = :EmailConfirmed, \"PhoneNumber\" = :PhoneNumber, \"PhoneNumberConfirmed\" = :PhoneNumberConfirmed, " +
                                        "    \"LockoutEnabled\" = :LockoutEnabled, \"AccessFailedCount\" = :AccessFailedCount, \"LockoutEndDateUtc\" = :LockoutEndDateUtc, \"SecurityStamp\" = :SecurityStamp, \"TwoFactorEnabled\" = :TwoFactorEnabled, " +
                                        "    \"ClientID\" = :ClientID, \"PaymentInformation\" = :PaymentInformation, \"UnstructuredData\" = :UnstructuredData, \"FIDO2PublicKey\" = :FIDO2PublicKey, \"PasswordChangeDate\" = :PasswordChangeDate " +
                                        "WHERE \"Id\" = :Id",
                                        new // 拡張メソッドで対策できる。
                                        {
                                            Id = user.Id,
                                            UserName = user.UserName,
                                            PasswordHash = user.PasswordHash,
                                            Email = user.Email,
                                            EmailConfirmed = user.EmailConfirmed ? -1 : 0,
                                            PhoneNumber = user.PhoneNumber,
                                            PhoneNumberConfirmed = user.PhoneNumberConfirmed ? -1 : 0,
                                            LockoutEnabled = user.LockoutEnabled ? -1 : 0,
                                            AccessFailedCount = user.AccessFailedCount,
                                            LockoutEndDateUtc = user.LockoutEndDateUtc,
                                            SecurityStamp = user.SecurityStamp,
                                            TwoFactorEnabled = user.TwoFactorEnabled ? -1 : 0,
                                            ClientID = user.ClientID,
                                            PaymentInformation = user.PaymentInformation,
                                            UnstructuredData = user.UnstructuredData,
                                            FIDO2PublicKey = user.FIDO2PublicKey,
                                            PasswordChangeDate = user.PasswordChangeDate
                                        });

                                    break;

                                case EnumUserStoreType.PostgreSQL:

                                    cnn.Execute(
                                       "UPDATE \"users\" " +
                                       "SET \"username\" = @UserName, \"passwordhash\" = @PasswordHash, " +
                                       "    \"email\" = @Email, \"emailconfirmed\" = @EmailConfirmed, \"phonenumber\" = @PhoneNumber, \"phonenumberconfirmed\" = @PhoneNumberConfirmed, " +
                                       "    \"lockoutenabled\" = @LockoutEnabled, \"accessfailedcount\" = @AccessFailedCount, \"lockoutenddateutc\" = @LockoutEndDateUtc, \"securitystamp\" = @SecurityStamp, \"twofactorenabled\" = @TwoFactorEnabled, " +
                                       "    \"clientid\" = @ClientID, \"paymentinformation\" = @PaymentInformation, \"unstructureddata\" = @UnstructuredData, \"fido2publickey\" = @FIDO2PublicKey, \"passwordchangedate\" = @PasswordChangeDate " +
                                       "WHERE \"id\" = @Id", user);

                                    break;
                            }

                            // ★ 基本的に、以下のプロパティ更新には、プロパティ更新メソッド（UserManager.XXXX[PropertyName]Async）を使用する。
                            //    この際、ASP.NET Identity Frameworkにより、本メソッド（UserStore.UpdateAsync）が呼び出されることがあるもよう。
                            //    その際、二重実行により二重登録（制約により例外になる）が起き得るので、以下は、ココに実装しないことにした。
                            // await this.UpdateRoles(user, tgtUser);    
                            // await this.UpdateLogins(user, tgtUser);
                            // await this.UpdateClaims(user, tgtUser);
                        }

                        break;
                }

                Logging.MyOperationTrace(string.Format("{0}({1}) was updated.", user.Id, user.UserName));
                //}
            }
            catch (Exception ex)
            {
                Logging.MySQLLogForEx(ex);
            }

            return;
        }

        #region ユーザの関連情報の更新（ Roles, Logins, Claims ）

        /// <summary>Rolesの更新</summary>
        /// <param name="user">更新</param>
        /// <param name="tgtUser">ターゲット</param>
        public static void UpdateRoles(ApplicationUser user, ApplicationUser tgtUser)
        {
            // 更新系の機能のため、
            OnlySts.STSOnly_M();

            // Debug
            Logging.MyDebugSQLTrace("★ : " +
                MethodBase.GetCurrentMethod().DeclaringType.FullName +
                "." + MethodBase.GetCurrentMethod().Name +
                Logging.GetParametersString(MethodBase.GetCurrentMethod().GetParameters()));

            try
            {
                // Rolesの更新
                switch (Config.UserStoreType)
                {
                    case EnumUserStoreType.Memory:

                        // tgtUserに含まれないApplicationRoleは削除対象。
                        IList<ApplicationRole> toRmvRoles = user.Roles.Except(tgtUser.Roles).ToList<ApplicationRole>();
                        // userに含まれないApplicationRoleは追加対象。
                        IList<ApplicationRole> toAddRoles = tgtUser.Roles.Except(user.Roles).ToList<ApplicationRole>();

                        foreach (ApplicationRole role in toRmvRoles)
                        {
                            tgtUser.Roles.Remove(role);
                        }

                        foreach (ApplicationRole role in toAddRoles)
                        {
                            tgtUser.Roles.Add(role);
                        }

                        break;

                    case EnumUserStoreType.SqlServer:
                    case EnumUserStoreType.ODPManagedDriver:
                    case EnumUserStoreType.PostgreSQL: // DMBMS Provider

                        // ここはSQLが無いので分岐も無い。

                        // .Except(が上手く動かないので手組する。

                        // LINQ・Except　参照型は要注意 | 猫に紙袋かぶせたらぎゃーって鳴いた
                        // http://nekokan333.blog.fc2.com/blog-entry-373.html?sp

                        // tgtUserに含まれないApplicationRoleは削除対象。
                        List<string> toRmvRolesName = new List<string>();
                        foreach (ApplicationRole r1 in user.Roles)
                        {
                            // userのロールが、
                            bool exist = false;
                            foreach (ApplicationRole r2 in tgtUser.Roles)
                            {
                                // tgtUserのロールに、
                                if (r1.Id == r2.Id)
                                {
                                    // 含まれる。
                                    exist = true;
                                }
                                else
                                {
                                    // 含まれない。
                                }
                            }

                            if (exist)
                            {
                                // （userのロールが、）tgtUser（のロール）に（、）含まれる。
                            }
                            else
                            {
                                // （userのロールが、）tgtUser（のロール）に（、）含まれない。
                                toRmvRolesName.Add(r1.Name);
                            }
                        }

                        // userに含まれないApplicationRoleは追加対象。
                        List<string> toAddRolesName = new List<string>();
                        foreach (ApplicationRole r1 in tgtUser.Roles)
                        {
                            // tgtUserのロールが、
                            bool exist = false;
                            foreach (ApplicationRole r2 in user.Roles)
                            {
                                // userのロールに、
                                if (r1.Id == r2.Id)
                                {
                                    // 含まれる。
                                    exist = true;
                                }
                                else
                                {
                                    // 含まれない。
                                }
                            }

                            if (exist)
                            {
                                // （tgtUserのロールが、）user（のロール）に（、）含まれる。
                            }
                            else
                            {
                                // （tgtUserのロールが、）user（のロール）に（、）含まれない。
                                toAddRolesName.Add(r1.Name);
                            }
                        }

                        // 原子性に問題があるのでやはり修正する。

                        //foreach (string roleName in toRmvRolesName)
                        //{
                        //    // 効率悪いが品質的に、RemoveFromRole使用する。
                        //    await RemoveFromRole(user, roleName);
                        //}
                        //foreach (string roleName in toAddRolesName)
                        //{
                        //    // 効率悪いが品質的に、AddToRoleを使用する。
                        //    await AddToRole(user, roleName);
                        //}

                        using (IDbConnection cnn = DataAccess.CreateConnection())
                        {
                            cnn.Open();
                            using (IDbTransaction tr = cnn.BeginTransaction())
                            {
                                // ロール・マップを削除（ロール情報を取得する。
                                foreach (string roleName in toRmvRolesName)
                                {
                                    switch (Config.UserStoreType)
                                    {
                                        case EnumUserStoreType.SqlServer:

                                            cnn.Execute(
                                                "DELETE FROM [UserRoles] " +
                                                "WHERE [UserRoles].[UserId] = @UserId " +
                                                "      AND [UserRoles].[RoleId] = (SELECT [Roles].[Id] FROM [Roles] WHERE [Roles].[Name] = @roleName)",
                                                new { UserId = user.Id, roleName = roleName });

                                            break;

                                        case EnumUserStoreType.ODPManagedDriver:

                                            cnn.Execute(
                                                "DELETE FROM \"UserRoles\" " +
                                                "WHERE \"UserRoles\".\"UserId\" = :UserId " +
                                                "      AND \"UserRoles\".\"RoleId\" = (SELECT \"Roles\".\"Id\" FROM \"Roles\" WHERE \"Roles\".\"Name\" = :roleName)",
                                                new { UserId = user.Id, roleName = roleName });

                                            break;

                                        case EnumUserStoreType.PostgreSQL:

                                            cnn.Execute(
                                                "DELETE FROM \"userroles\" " +
                                                "WHERE \"userroles\".\"userid\" = @UserId " +
                                                "      AND \"userroles\".\"roleid\" = (SELECT \"roles\".\"id\" FROM \"roles\" WHERE \"roles\".\"name\" = @roleName)",
                                                new { UserId = user.Id, roleName = roleName });

                                            break;
                                    }
                                }

                                // ロール・マップを追加（ロール情報を取得する。
                                foreach (string roleName in toAddRolesName)
                                {
                                    switch (Config.UserStoreType)
                                    {
                                        case EnumUserStoreType.SqlServer:

                                            cnn.Execute(
                                                "INSERT INTO [UserRoles] ([UserRoles].[UserId], [UserRoles].[RoleId]) " +
                                                "VALUES (@UserId, (SELECT [Roles].[Id] FROM [Roles] WHERE [Roles].[Name] = @roleName))",
                                                new { UserId = user.Id, roleName = roleName });

                                            break;

                                        case EnumUserStoreType.ODPManagedDriver:

                                            cnn.Execute(
                                                "INSERT INTO \"UserRoles\" (\"UserRoles\".\"UserId\", \"UserRoles\".\"RoleId\") " +
                                                "VALUES (:UserId, (SELECT \"Roles\".\"Id\" FROM \"Roles\" WHERE \"Roles\".\"Name\" = :roleName))",
                                                new { UserId = user.Id, roleName = roleName });

                                            break;

                                        case EnumUserStoreType.PostgreSQL:

                                            cnn.Execute(
                                                "INSERT INTO \"userroles\" (\"userid\", \"roleid\") " +
                                                "VALUES (@UserId, (SELECT \"id\" FROM \"roles\" WHERE \"name\" = @roleName))",
                                                new { UserId = user.Id, roleName = roleName });

                                            break;
                                    }
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

            return;
        }

        //Logins, ClaimsはDel-Insで対応するため、UpdateLogins, UpdateClaimsのメソッドは不要

        #endregion

        #endregion

        #region D (Delete)

        /// <summary>ユーザの論理削除</summary>
        /// <param name="user">ApplicationUser</param>
        /// <remarks>
        /// 削除するエンティティにマークを付けます
        /// </remarks>
        public static void Delete(ApplicationUser user)
        {
            // 更新系の機能のため、
            OnlySts.STSOnly_M();

            // Debug
            Logging.MyDebugSQLTrace("★ : " +
                MethodBase.GetCurrentMethod().DeclaringType.FullName +
                "." + MethodBase.GetCurrentMethod().Name +
                Logging.GetParametersString(MethodBase.GetCurrentMethod().GetParameters()));

            // AccountControllerのメアド検証の再送で利用するため。
            // UsersAdminControllerではチェックしている。

            try
            {
                // ユーザの論理削除
                switch (Config.UserStoreType)
                {
                    case EnumUserStoreType.Memory:

                        // ユーザを削除
                        CmnStore._users.Remove(CmnStore._users.First(x => x.Id == user.Id));
                        // ユーザの関連情報を削除
                        CmnStore._userRoleMap.RemoveAll(x => x.Item1 == user.Id);

                        break;

                    case EnumUserStoreType.SqlServer:
                    case EnumUserStoreType.ODPManagedDriver:
                    case EnumUserStoreType.PostgreSQL: // DMBMS Provider

                        using (IDbConnection cnn = DataAccess.CreateConnection())
                        {
                            cnn.Open();
                            using (IDbTransaction tr = cnn.BeginTransaction())
                            {
                                switch (Config.UserStoreType)
                                {
                                    case EnumUserStoreType.SqlServer:

                                        // ユーザの情報を削除
                                        cnn.Execute("DELETE FROM [Users] WHERE [Id] = @UserId", new { UserId = user.Id }, tr);

                                        // ユーザの関連情報を削除
                                        cnn.Execute("DELETE FROM [UserRoles]  WHERE [UserId] = @UserId", new { UserId = user.Id }, tr);
                                        cnn.Execute("DELETE FROM [UserLogins] WHERE [UserId] = @UserId", new { UserId = user.Id }, tr);
                                        cnn.Execute("DELETE FROM [UserClaims] WHERE [UserId] = @UserId", new { UserId = user.Id }, tr);

                                        break;

                                    case EnumUserStoreType.ODPManagedDriver:

                                        // ユーザの情報を削除
                                        cnn.Execute("DELETE FROM \"Users\" WHERE \"Id\" = :UserId", new { UserId = user.Id }, tr);

                                        // ユーザの関連情報を削除
                                        cnn.Execute("DELETE FROM \"UserRoles\"  WHERE \"UserId\" = :UserId", new { UserId = user.Id }, tr);
                                        cnn.Execute("DELETE FROM \"UserLogins\" WHERE \"UserId\" = :UserId", new { UserId = user.Id }, tr);
                                        cnn.Execute("DELETE FROM \"UserClaims\" WHERE \"UserId\" = :UserId", new { UserId = user.Id }, tr);

                                        break;

                                    case EnumUserStoreType.PostgreSQL:

                                        // ユーザの情報を削除
                                        cnn.Execute("DELETE FROM \"users\" WHERE \"id\" = @UserId", new { UserId = user.Id }, tr);

                                        // ユーザの関連情報を削除
                                        cnn.Execute("DELETE FROM \"userroles\"  WHERE \"userid\" = @UserId", new { UserId = user.Id }, tr);
                                        cnn.Execute("DELETE FROM \"userlogins\" WHERE \"userid\" = @UserId", new { UserId = user.Id }, tr);
                                        cnn.Execute("DELETE FROM \"userclaims\" WHERE \"userid\" = @UserId", new { UserId = user.Id }, tr);

                                        break;
                                }

                                tr.Commit();
                            }
                        }

                        break;
                }

                Logging.MyOperationTrace(string.Format("{0}({1}) was deleted.", user.Id, user.UserName));
            }
            catch (Exception ex)
            {
                Logging.MySQLLogForEx(ex);
            }

            return;
        }

        #endregion

        #endregion

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

            return user.PasswordHash;
        }

        #endregion

        #region IUserEmailStore

        /// <summary>ユーザを（email指定で）検索して取得</summary>
        /// <param name="email">string</param>
        /// <returns>ApplicationUser</returns>
        public static ApplicationUser FindByEmail(string email)
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
                // ユーザを（email指定で）検索して取得
                switch (Config.UserStoreType)
                {
                    case EnumUserStoreType.Memory:

                        user = CmnStore._users.FirstOrDefault(x => x.Email == email);

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
                                        "SELECT * From [Users] WHERE [Email] = @Email", new { Email = email });

                                    break;

                                case EnumUserStoreType.ODPManagedDriver:

                                    users = cnn.Query<ApplicationUser>(
                                        "SELECT * From \"Users\" WHERE \"Email\" = :Email", new { Email = email });

                                    break;

                                case EnumUserStoreType.PostgreSQL:

                                    users = cnn.Query<ApplicationUser>(
                                        "SELECT * From \"users\" WHERE \"email\" = @Email", new { Email = email });

                                    break;
                            }

                            if (users.Count() != 0)
                            {
                                user = users.First();

                                // ユーザの関連情報の取得（ Roles, Logins, Claims ）
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

        #region IUserRoleStore

        /// <summary>ロールにユーザを追加</summary>
        /// <param name="user">ApplicationUser</param>
        /// <param name="roleName">string</param>
        public static void AddToRole(ApplicationUser user, string roleName)
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
                // ロールにユーザを追加
                ApplicationRole role = null;
                switch (Config.UserStoreType)
                {
                    case EnumUserStoreType.Memory:

                        // ロール情報を取得する
                        role = CmnStore._roles.FirstOrDefault(x => x.Name == roleName);

                        if (role == null)
                        {
                            // 存在しないロール
                            throw new InvalidOperationException();
                        }
                        else
                        {
                            // ロール・マップ情報を取得する
                            Tuple<string, string> userRoleMap = CmnStore._userRoleMap.FirstOrDefault(
                                x => x.Item1 == user.Id && x.Item2 == role.Id);

                            if (userRoleMap != null)
                            {
                                // 既に追加されている。
                            }
                            else
                            {
                                // ロール・マップにユーザとロールに追加
                                CmnStore._userRoleMap.Add(Tuple.Create(user.Id, role.Id));
                            }
                        }

                        break;

                    case EnumUserStoreType.SqlServer:
                    case EnumUserStoreType.ODPManagedDriver:
                    case EnumUserStoreType.PostgreSQL: // DMBMS Provider

                        using (IDbConnection cnn = DataAccess.CreateConnection())
                        {
                            cnn.Open();

                            // ロール・マップを追加（ロール情報を取得する。
                            switch (Config.UserStoreType)
                            {
                                case EnumUserStoreType.SqlServer:

                                    cnn.Execute(
                                        "INSERT INTO [UserRoles] ([UserRoles].[UserId], [UserRoles].[RoleId]) " +
                                        "VALUES (@UserId, (SELECT [Roles].[Id] FROM [Roles] WHERE [Roles].[Name] = @roleName))",
                                        new { UserId = user.Id, roleName = roleName });

                                    break;

                                case EnumUserStoreType.ODPManagedDriver:

                                    cnn.Execute(
                                        "INSERT INTO \"UserRoles\" (\"UserRoles\".\"UserId\", \"UserRoles\".\"RoleId\") " +
                                        "VALUES (:UserId, (SELECT \"Roles\".\"Id\" FROM \"Roles\" WHERE \"Roles\".\"Name\" = :roleName))",
                                        new { UserId = user.Id, roleName = roleName });

                                    break;

                                case EnumUserStoreType.PostgreSQL:

                                    cnn.Execute(
                                        "INSERT INTO \"userroles\" (\"userid\", \"roleid\") " +
                                        "VALUES (@UserId, (SELECT \"id\" FROM \"roles\" WHERE \"name\" = @roleName))",
                                        new { UserId = user.Id, roleName = roleName });

                                    break;
                            }
                        }

                        break;
                }
            }
            catch (Exception ex)
            {
                Logging.MySQLLogForEx(ex);
            }

            return;
        }

        /// <summary>ユーザがロールに所属するか？</summary>
        /// <param name="user">ApplicationUser</param>
        /// <param name="roleName">ロール名</param>
        /// <returns>真・偽：ユーザがロールに所属するか</returns>
        public static bool IsInRole(ApplicationUser user, string roleName)
        {
            // ストレージを直接、触らない。
            //OnlySts.STSOnly_M();

            // Debug
            Logging.MyDebugSQLTrace(
                MethodBase.GetCurrentMethod().DeclaringType.FullName +
                "." + MethodBase.GetCurrentMethod().Name +
                Logging.GetParametersString(MethodBase.GetCurrentMethod().GetParameters()));

            // ユーザがロールに所属するか？

            // ユーザのロール一覧を返す。
            IList<string> roles = CmnUserStore.GetRoles(user);

            // bool (ユーザのロール一覧から、一致するロール名を取得できたら真、できなかったら偽
            return roles.FirstOrDefault(x => x.ToUpper() == roleName.ToUpper()) != null;
        }

        /// <summary>ユーザのロール一覧を取得</summary>
        /// <param name="user">ApplicationUser</param>
        /// <returns>ユーザのロール一覧</returns>
        public static IList<string> GetRoles(ApplicationUser user)
        {
            // 他テーブルのため、
            //OnlySts.STSOnly_M();
            if (OnlySts.STSOnly_P)
            {
                // 空の一覧を返す。
                return new List<string>();
            }

            // Debug
            Logging.MyDebugSQLTrace("★ : " +
                MethodBase.GetCurrentMethod().DeclaringType.FullName +
                "." + MethodBase.GetCurrentMethod().Name +
                Logging.GetParametersString(MethodBase.GetCurrentMethod().GetParameters()));

            IList<string> roleNames = null;

            try
            {
                // ユーザのロール一覧を取得
                switch (Config.UserStoreType)
                {
                    case EnumUserStoreType.Memory:

                        // UserRoleMapに含まれるuserId = user.Id のTupleに含まれるRole.IdのRole.Nameを一覧する。
                        roleNames = CmnStore._userRoleMap // List<Tuple<string, sting>>
                                                         // Tuple.Item1 == user.IdのTupleのListを抽出。
                            .Where(x => x.Item1 == user.Id)
                            // 結果のTupleのListの中からTuple.Item2（ = Role.Id）の射影を取る。
                            .Select(x => x.Item2)
                            // Tuple.Item2の射影の中からRoles.Idと一致するRole(List<ApplicationRole>)のListを抽出して射影。
                            .Select(x => CmnStore._roles.First(y => y.Id == x))
                            // 結果のApplicationRoleのListのApplicationRole.Nameの射影を取る。
                            .Select(x => x.Name)
                            // ApplicationRole.NameのListを射影
                            .ToArray();

                        break;

                    case EnumUserStoreType.SqlServer:
                    case EnumUserStoreType.ODPManagedDriver:
                    case EnumUserStoreType.PostgreSQL: // DMBMS Provider

                        using (IDbConnection cnn = DataAccess.CreateConnection())
                        {
                            cnn.Open();
                            IEnumerable<ApplicationRole> roles = null;

                            switch (Config.UserStoreType)
                            {
                                case EnumUserStoreType.SqlServer:

                                    roles = cnn.Query<ApplicationRole>(
                                        "SELECT [Roles].[Id] as Id, [Roles].[Name] as Name " +
                                        "FROM   [Roles], [UserRoles], [Users] " +
                                        "WHERE  [Roles].[Id] = [UserRoles].[RoleId] " +
                                        "   AND [UserRoles].[UserId] = [Users].[Id] " +
                                        "   AND [Users].[Id] = @UserId",
                                        new { UserId = user.Id });

                                    break;

                                case EnumUserStoreType.ODPManagedDriver:

                                    roles = cnn.Query<ApplicationRole>(
                                        "SELECT \"Roles\".\"Id\" as Id, \"Roles\".\"Name\" as Name " +
                                        "FROM   \"Roles\", \"UserRoles\", \"Users\" " +
                                        "WHERE  \"Roles\".\"Id\" = \"UserRoles\".\"RoleId\" " +
                                        "   AND \"UserRoles\".\"UserId\" = \"Users\".\"Id\" " +
                                        "   AND \"Users\".\"Id\" = :UserId",
                                        new { UserId = user.Id });

                                    break;

                                case EnumUserStoreType.PostgreSQL:

                                    roles = cnn.Query<ApplicationRole>(
                                        "SELECT \"roles\".\"id\" as id, \"roles\".\"name\" as name " +
                                        "FROM   \"roles\", \"userroles\", \"users\" " +
                                        "WHERE  \"roles\".\"id\" = \"userroles\".\"roleid\" " +
                                        "   AND \"userroles\".\"userid\" = \"users\".\"id\" " +
                                        "   AND \"users\".\"id\" = @userid",
                                        new { UserId = user.Id });

                                    break;
                            }

                            List<string> temp = new List<string>();
                            foreach (ApplicationRole role in roles)
                            {
                                temp.Add(role.Name);
                            }
                            roleNames = temp.ToArray();
                        }

                        break;
                }
            }
            catch (Exception ex)
            {
                Logging.MySQLLogForEx(ex);
            }

            // ユーザのロール一覧を返す。
            return roleNames;
        }

        /// <summary>ユーザをロールから削除</summary>
        /// <param name="user">ApplicationUser</param>
        /// <param name="roleName">ロール名</param>
        public static void RemoveFromRole(ApplicationUser user, string roleName)
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
                // ユーザーをロールから削除
                ApplicationRole role = null;
                switch (Config.UserStoreType)
                {
                    case EnumUserStoreType.Memory:

                        // 名称の一致するロールを取得
                        role = CmnStore._roles.FirstOrDefault(x => x.Name == roleName);

                        if (role == null)
                        {
                            // なにもしない（というか何もできない）
                        }
                        else
                        {
                            // UserRoleMapに含まれるTuple.Item1 == user.Id && Tuple.Item2 == role.IdのTupleを返す。
                            Tuple<string, string> userRoleMap = CmnStore._userRoleMap
                                .FirstOrDefault(x => x.Item1 == user.Id && x.Item2 == role.Id);

                            // ユーザをロールから削除
                            if (userRoleMap != null)
                            {
                                // 取得できたら、Tupleを削除。
                                CmnStore._userRoleMap.Remove(userRoleMap);
                            }
                        }

                        break;

                    case EnumUserStoreType.SqlServer:
                    case EnumUserStoreType.ODPManagedDriver:
                    case EnumUserStoreType.PostgreSQL: // DMBMS Provider

                        using (IDbConnection cnn = DataAccess.CreateConnection())
                        {
                            cnn.Open();

                            // ロール・マップを削除（ロール情報を取得する。
                            switch (Config.UserStoreType)
                            {
                                case EnumUserStoreType.SqlServer:

                                    cnn.Execute(
                                        "DELETE FROM [UserRoles] " +
                                        "WHERE [UserRoles].[UserId] = @UserId " +
                                        "      AND [UserRoles].[RoleId] = (SELECT [Roles].[Id] FROM [Roles] WHERE [Roles].[Name] = @roleName)",
                                        new { UserId = user.Id, roleName = roleName });

                                    break;

                                case EnumUserStoreType.ODPManagedDriver:

                                    cnn.Execute(
                                        "DELETE FROM \"UserRoles\" " +
                                        "WHERE \"UserRoles\".\"UserId\" = :UserId " +
                                        "      AND \"UserRoles\".\"RoleId\" = (SELECT \"Roles\".\"Id\" FROM \"Roles\" WHERE \"Roles\".\"Name\" = :roleName)",
                                        new { UserId = user.Id, roleName = roleName });

                                    break;

                                case EnumUserStoreType.PostgreSQL:

                                    cnn.Execute(
                                        "DELETE FROM \"userroles\" " +
                                        "WHERE \"userroles\".\"userid\" = @UserId " +
                                        "      AND \"userroles\".\"roleid\" = (SELECT \"roles\".\"id\" FROM \"roles\" WHERE \"roles\".\"name\" = @roleName)",
                                        new { UserId = user.Id, roleName = roleName });

                                    break;
                            }
                        }

                        break;
                }
            }
            catch (Exception ex)
            {
                Logging.MySQLLogForEx(ex);
            }

            return;
        }

        #endregion

        #endregion

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
                user.LockoutEndDateUtc = lockoutEnd.Value.DateTime;
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

            user.AuthenticatorKey = key;

            return;
        }

        /// <summary>GetAuthenticatorKey</summary>
        /// <param name="user">ApplicationUser</param>
        /// <param name="cancellationToken">CancellationToken</param>
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

            return user.AuthenticatorKey;
        }

        #endregion
#endif

        #endregion

        #region Collection (Logins, Claims)

        #region IUserLoginStore

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
                Logging.MySQLLogForEx(ex);
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

                                // ユーザの関連情報の取得（ Roles, Logins, Claims ）
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
                Logging.MySQLLogForEx(ex);
            }

            return;
        }

        #endregion

        #region IUserClaimStore

        /// <summary>ユーザに外部ログインのクレームを追加</summary>
        /// <param name="user">ApplicationUser</param>
        /// <param name="claim">Claim</param>
        public static void AddClaim(ApplicationUser user, Claim claim)
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
                // ユーザに外部ログインのクレームを追加
                switch (Config.UserStoreType)
                {
                    case EnumUserStoreType.Memory:

                        user.Claims.Add(claim);

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
                                        "INSERT INTO [UserClaims] ([UserId], [Issuer], [ClaimType], [ClaimValue]) " +
                                        "VALUES (@UserId, @Issuer, @ClaimType, @ClaimValue)",
                                         new { UserId = user.Id, Issuer = claim.Issuer, ClaimType = claim.Type, ClaimValue = claim.Value });

                                    break;

                                case EnumUserStoreType.ODPManagedDriver:

                                    cnn.Execute(
                                        "INSERT INTO \"UserClaims\" (\"Id\", \"UserId\", \"Issuer\", \"ClaimType\", \"ClaimValue\") " +
                                        "VALUES (TS_UserClaimID.NEXTVAL, :UserId, :Issuer, :ClaimType, :ClaimValue)",
                                        new { UserId = user.Id, Issuer = claim.Issuer, ClaimType = claim.Type, ClaimValue = claim.Value });

                                    break;

                                case EnumUserStoreType.PostgreSQL:

                                    cnn.Execute(
                                        "INSERT INTO \"userclaims\" (\"id\", \"userid\", \"issuer\", \"claimtype\", \"claimvalue\") " +
                                        "VALUES (@UserId, @Issuer, @ClaimType, @ClaimValue)",
                                        new { UserId = user.Id, Issuer = claim.Issuer, ClaimType = claim.Type, ClaimValue = claim.Value });

                                    break;
                            }
                        }

                        break;
                }
            }
            catch (Exception ex)
            {
                Logging.MySQLLogForEx(ex);
            }

            return;
        }

        /// <summary>ユーザの（外部ログインの）クレーム一覧を取得</summary>
        /// <param name="user">ApplicationUser</param>
        /// <returns>IList<Claim></returns>
        public static IList<Claim> GetClaims(ApplicationUser user)
        {
            // 他テーブルのため、
            //OnlySts.STSOnly_M();
            if (OnlySts.STSOnly_P)
            {
                return new List<Claim>();
            }

            // ストレージを直接、触らない。

            // Debug
            Logging.MyDebugSQLTrace(
                MethodBase.GetCurrentMethod().DeclaringType.FullName +
                "." + MethodBase.GetCurrentMethod().Name +
                Logging.GetParametersString(MethodBase.GetCurrentMethod().GetParameters()));

            // ユーザの（外部ログインの）クレーム一覧を取得
            return user.Claims;
        }

        /// <summary>ユーザの（外部ログインの）クレームを削除</summary>
        /// <param name="user">ApplicationUser</param>
        /// <param name="claim">Claim</param>
        public static void RemoveClaim(ApplicationUser user, Claim claim)
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
                // ユーザの（外部ログインの）クレームを削除
                switch (Config.UserStoreType)
                {
                    case EnumUserStoreType.Memory:

                        user.Claims.Remove(claim);

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
                                        "DELETE FROM [UserClaims] WHERE [UserId] = @UserId AND [Issuer] = @Issuer AND [ClaimType] = @ClaimType",
                                        new { UserId = user.Id, Issuer = claim.Issuer, ClaimType = claim.Type });

                                    break;

                                case EnumUserStoreType.ODPManagedDriver:

                                    cnn.Execute(
                                        "DELETE FROM \"UserClaims\" WHERE \"UserId\" = :UserId AND \"Issuer\" = :Issuer AND \"ClaimType\" = :ClaimType",
                                        new { UserId = user.Id, Issuer = claim.Issuer, ClaimType = claim.Type });

                                    break;

                                case EnumUserStoreType.PostgreSQL:

                                    cnn.Execute(
                                        "DELETE FROM \"userclaims\" WHERE \"userid\" = @UserId AND \"issuer\" = @Issuer AND \"claimtype\" = @ClaimType",
                                        new { UserId = user.Id, Issuer = claim.Issuer, ClaimType = claim.Type });

                                    break;
                            }
                        }

                        break;
                }
            }
            catch (Exception ex)
            {
                Logging.MySQLLogForEx(ex);
            }

            return;
        }

        #endregion

        #endregion

        #endregion
    }
}