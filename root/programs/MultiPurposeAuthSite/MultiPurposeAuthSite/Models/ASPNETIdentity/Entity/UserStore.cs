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
//* クラス名        ：UserStore
//* クラス日本語名  ：UserStore（ライブラリ）
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
using System.Data;
using System.Linq;
using System.Collections.Generic;

using System.Reflection;
using System.Threading.Tasks;
using System.Security.Claims;

using System.Web;

using Dapper;
using Microsoft.AspNet.Identity;

using MultiPurposeAuthSite.Models.Log;
using MultiPurposeAuthSite.Models.Util;
using MultiPurposeAuthSite.Models.ASPNETIdentity.Manager;
using MultiPurposeAuthSite.Models.ASPNETIdentity.Util;

// --------------------------------------------------
// UserStoreのTransaction管理について。
// --------------------------------------------------
// 制御の反転で実装されているので、
// ASP.NET Identity側が（Entityの外から）Transaction管理しない以上、
// UserStoreのmethodレベルでTransactionalに実装することは難しい。
// ただし、LDAP、NoSQLなどと実装を共通化していくにはメリットになる。
// 
// --------------------------------------------------
// DBMS ProviderとMemory Providerとの動作の差異
// --------------------------------------------------
// DBMS Providerを使用する際、性能向上のため、
// Userの参照処理では、Roles, Logins, Claimsなどの情報はロードしない仕様とした。
// 別途、GetRoles, Logins, Claimsなどのmethodを使用してロードする。
// Memory Providerを使用する際と、動作が異なるのでテストの際は注意が必要。
// --------------------------------------------------

/// <summary>MultiPurposeAuthSite.Models.ASPNETIdentity.Entity</summary>
namespace MultiPurposeAuthSite.Models.ASPNETIdentity.Entity
{
    /// <summary>
    /// UserStoreでApplicationUserを永続化する。
    /// </summary>
    public class UserStore :

        IUserStore<ApplicationUser>,
        IUserStore<ApplicationUser, string>,
        IUserPasswordStore<ApplicationUser, string>,
        IUserEmailStore<ApplicationUser, string>,
        IUserPhoneNumberStore<ApplicationUser, string>,
        IUserRoleStore<ApplicationUser, string>,
        IUserSecurityStampStore<ApplicationUser>,
        IUserLockoutStore<ApplicationUser, string>,
        IUserTwoFactorStore<ApplicationUser, string>,
        IUserLoginStore<ApplicationUser, string>,
        IUserClaimStore<ApplicationUser, string>,
        IRoleStore<ApplicationRole, string>,
        IQueryableUserStore<ApplicationUser, string>,
        IQueryableRoleStore<ApplicationRole, string>,
        IDisposable

    {
        #region constructor

        /// <summary>constructor</summary>
        public UserStore() { }

        #endregion

        #region Utility

        #region Log

        /// <summary>GetParametersString</summary>
        /// <param name="parameters">string[]</param>
        /// <returns>Parameters string</returns>
        private static string GetParametersString(ParameterInfo[] parameters)
        {
            string s = "";

            if (ASPNETIdentityConfig.IsDebug)
            {
                s += "(";
                for (int i = 0; i < parameters.Length; i++)
                {
                    s += parameters[i].Name + ", ";
                }
                if (s.Length >= 2)
                {
                    s = s.Substring(0, s.Length - 2);
                }
                s += ")";
            }

            return s;
        }

        #endregion

        #region Memory Provider

        #region メンバ（マスタ系データ）

        // ユーザ属性（子エンティティ）は、
        // ApplicationUserのPropertyを使用する。

        /// <summary>ユーザ保存先</summary>
        public static List<ApplicationUser> _users { get; } = new List<ApplicationUser>();

        /// <summary>ロールの保存先</summary>
        public static List<ApplicationRole> _roles { get; } = new List<ApplicationRole>();

        /// <summary>ユーザとロールのリレーション</summary>
        public static List<Tuple<string, string>> _userRoleMap { get; } = new List<Tuple<string, string>>();

        #endregion

        #endregion

        #region DBMS Provider

        #region メソッド

        #region 初期化

        /// <summary>DBMSの初期化確認メソッド</summary>
        /// <returns>bool</returns>
        public static Task<bool> IsDBMSInitialized()
        {
            // テスト時の機能のため、
            //OnlySts.STSOnly_M();

            // Debug
            Logging.MyDebugSQLTrace("★ : " + 
                MethodBase.GetCurrentMethod().DeclaringType.FullName + 
                "." + MethodBase.GetCurrentMethod().Name +
                UserStore.GetParametersString(MethodBase.GetCurrentMethod().GetParameters()));

            try
            {
                using (IDbConnection cnn = DataAccess.CreateConnection())
                {
                    cnn.Open();
                    int count = 0;

                    // [Roles] が [Users] に先立って登録されるので。
                    switch (ASPNETIdentityConfig.UserStoreType)
                    {
                        case EnumUserStoreType.SqlServer:

                            count = cnn.ExecuteScalar<int>("SELECT COUNT(*) FROM [Roles]");

                            break;

                        case EnumUserStoreType.ODPManagedDriver:

                            count = cnn.ExecuteScalar<int>("SELECT COUNT(*) FROM \"Roles\"");

                            break;

                        case EnumUserStoreType.PostgreSQL:

                            count = cnn.ExecuteScalar<int>("SELECT COUNT(*) FROM \"roles\"");

                            break;
                    }

                    return Task.FromResult((0 < count));
                }
            }
            catch (Exception ex)
            {
                Logging.MySQLLogForEx(ex);
            }

            return Task.FromResult(false); ;
        }

        #endregion

        #region データ アクセス

        /// <summary>ユーザの関連情報の取得（ Roles, Logins, Claims ）</summary>
        private void SelectChildTablesOfUser(IDbConnection cnn, ApplicationUser user)
        {
            // 他テーブルのため、
            //OnlySts.STSOnly_M();
            if (OnlySts.STSOnly_P)
            {
                // 何もロードしない。
                return;
            }

            // Debug
            Logging.MyDebugSQLTrace("★ : " + 
                MethodBase.GetCurrentMethod().DeclaringType.FullName +
                "." + MethodBase.GetCurrentMethod().Name +
                UserStore.GetParametersString(MethodBase.GetCurrentMethod().GetParameters()));

            try
            {
                IEnumerable<ApplicationRole> roles = null;
                IEnumerable<UserLoginInfo> userLogins = null;
                IEnumerable<dynamic> claims = null;

                switch (ASPNETIdentityConfig.UserStoreType)
                {
                    case EnumUserStoreType.SqlServer:

                        // Roles
                        roles = cnn.Query<ApplicationRole>(
                            "SELECT [Roles].[Id] as Id, [Roles].[Name] as Name, [Roles].[ParentId] as ParentId " +
                            "FROM   [UserRoles], [Roles] " +
                            "WHERE  [UserRoles].[RoleId] = [Roles].[Id] " +
                            "   AND [UserRoles].[UserId] = @userId", new { userId = user.Id });
                        user.Roles = roles.ToList();

                        // Logins
                        userLogins = cnn.Query<UserLoginInfo>(
                            "SELECT [LoginProvider], [ProviderKey] " +
                            "FROM   [UserLogins] WHERE [UserId] = @userId", new { userId = user.Id });
                        user.Logins = userLogins.ToList();

                        // Claims
                        claims = cnn.Query(
                            "SELECT [Issuer], [ClaimType], [ClaimValue] " +
                            "FROM   [UserClaims] WHERE [UserId] = @userId", new { userId = user.Id });
                        user.Claims = new List<Claim>();

                        break;

                    case EnumUserStoreType.ODPManagedDriver:

                        // Roles
                        roles = cnn.Query<ApplicationRole>(
                            "SELECT \"Roles\".\"Id\" as Id, \"Roles\".\"Name\" as Name, \"Roles\".\"ParentId\" as ParentId " +
                            "FROM   \"UserRoles\", \"Roles\" " +
                            "WHERE  \"UserRoles\".\"RoleId\" = \"Roles\".\"Id\" " +
                            "   AND \"UserRoles\".\"UserId\" = :userId", new { userId = user.Id });
                        user.Roles = roles.ToList();

                        // Logins
                        userLogins = cnn.Query<UserLoginInfo>(
                            "SELECT \"LoginProvider\", \"ProviderKey\" " +
                            "FROM   \"UserLogins\" WHERE \"UserId\" = :userId", new { userId = user.Id });
                        user.Logins = userLogins.ToList();

                        // Claims
                        claims = cnn.Query(
                            "SELECT \"Issuer\", \"ClaimType\", \"ClaimValue\" " +
                            "FROM   \"UserClaims\" WHERE \"UserId\" = :userId", new { userId = user.Id });
                        user.Claims = new List<Claim>();

                        break;

                    case EnumUserStoreType.PostgreSQL:

                        // Roles
                        roles = cnn.Query<ApplicationRole>(
                            "SELECT \"roles\".\"id\" as id, \"roles\".\"name\" as name, \"roles\".\"parentid\" as parentid " +
                            "FROM   \"userroles\", \"roles\" " +
                            "WHERE  \"userroles\".\"roleid\" = \"roles\".\"id\" " +
                            "   AND \"userroles\".\"userid\" = @userId", new { userId = user.Id });
                        user.Roles = roles.ToList();

                        // Logins
                        userLogins = cnn.Query<UserLoginInfo>(
                            "SELECT \"loginprovider\", \"providerkey\" " +
                            "FROM   \"userlogins\" WHERE \"userid\" = @userId", new { userId = user.Id });
                        user.Logins = userLogins.ToList();

                        // Claims
                        claims = cnn.Query(
                            "SELECT \"issuer\", \"claimtype\", \"claimvalue\" " +
                            "FROM   \"userclaims\" WHERE \"userid\" = @userId", new { userId = user.Id });
                        user.Claims = new List<Claim>();

                        break;
                }

                foreach (dynamic d in claims)
                {
                    user.Claims.Add(new Claim(d.ClaimType, d.ClaimValue, null, d.Issuer));
                }
            }
            catch (Exception ex)
            {
                Logging.MySQLLogForEx(ex);
            }
        }

        #endregion

        #endregion

        #endregion

        #endregion

        #region CRUD(共通)

        #region C (Create)

        /// <summary>新規ユーザーの追加</summary>
        /// <param name="user">ApplicationUser</param>
        /// <returns>－</returns>
        public Task CreateAsync(ApplicationUser user)
        {
            // 更新系の機能のため、
            OnlySts.STSOnly_M();

            // Debug
            Logging.MyDebugSQLTrace("★ : " + 
                MethodBase.GetCurrentMethod().DeclaringType.FullName +
                "." + MethodBase.GetCurrentMethod().Name +
                UserStore.GetParametersString(MethodBase.GetCurrentMethod().GetParameters()));

            try
            {
                // 新規ユーザーの追加
                switch (ASPNETIdentityConfig.UserStoreType)
                {
                    case EnumUserStoreType.Memory:

                        UserStore._users.Add(user);

                        break;

                    case EnumUserStoreType.SqlServer:
                    case EnumUserStoreType.ODPManagedDriver:
                    case EnumUserStoreType.PostgreSQL: // DMBMS Provider

                        using (IDbConnection cnn = DataAccess.CreateConnection())
                        {
                            cnn.Open();

                            switch (ASPNETIdentityConfig.UserStoreType)
                            {
                                case EnumUserStoreType.SqlServer:

                                    cnn.Execute(
                                        "INSERT INTO [Users] ( " +
                                        "    [Id], [UserName], [PasswordHash], " +
                                        "    [Email], [EmailConfirmed], [PhoneNumber], [PhoneNumberConfirmed], " +
                                        "    [LockoutEnabled], [AccessFailedCount], [LockoutEndDateUtc], " +
                                        "    [SecurityStamp], [TwoFactorEnabled], [ParentId], [ClientID], [PaymentInformation], [UnstructuredData], [CreatedDate])" +
                                        "    VALUES ( " +
                                        "        @Id, @UserName, @PasswordHash, " +
                                        "        @Email, @EmailConfirmed, @PhoneNumber, @PhoneNumberConfirmed, " +
                                        "        @LockoutEnabled, @AccessFailedCount, @LockoutEndDateUtc, " +
                                        "        @SecurityStamp, @TwoFactorEnabled, @ParentId, @ClientID, @PaymentInformation, @UnstructuredData, @CreatedDate)", user);

                                    break;

                                case EnumUserStoreType.ODPManagedDriver:
                                    
                                    cnn.Execute(
                                        "INSERT INTO \"Users\" ( " +
                                        "    \"Id\", \"UserName\", \"PasswordHash\", " +
                                        "    \"Email\", \"EmailConfirmed\", \"PhoneNumber\", \"PhoneNumberConfirmed\", " +
                                        "    \"LockoutEnabled\", \"AccessFailedCount\", \"LockoutEndDateUtc\", " +
                                        "    \"SecurityStamp\", \"TwoFactorEnabled\", \"ParentId\", \"ClientID\", \"PaymentInformation\", \"UnstructuredData\", \"CreatedDate\")" +
                                        "    VALUES ( " +
                                        "        :Id, :UserName, :PasswordHash, " +
                                        "        :Email, :EmailConfirmed, :PhoneNumber, :PhoneNumberConfirmed, " +
                                        "        :LockoutEnabled, :AccessFailedCount, :LockoutEndDateUtc, " +
                                        "        :SecurityStamp, :TwoFactorEnabled, :ParentId, :ClientID, :PaymentInformation, :UnstructuredData, :CreatedDate)",
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
                                            ParentId = user.ParentId,
                                            ClientID = user.ClientID,
                                            PaymentInformation = user.PaymentInformation,
                                            UnstructuredData = user.UnstructuredData,
                                            CreatedDate = user.CreatedDate
                                        });

                                    break;

                                case EnumUserStoreType.PostgreSQL:

                                    cnn.Execute(
                                        "INSERT INTO \"users\" ( " +
                                        "    \"id\", \"username\", \"passwordhash\", " +
                                        "    \"email\", \"emailconfirmed\", \"phonenumber\", \"phonenumberconfirmed\", " +
                                        "    \"lockoutenabled\", \"accessfailedcount\", \"lockoutenddateutc\", " +
                                        "    \"securitystamp\", \"twofactorenabled\", \"parentid\", \"clientid\", \"paymentinformation\", \"unstructureddata\", \"createddate\")" +
                                        "    VALUES ( " +
                                        "        @Id, @UserName, @PasswordHash, " +
                                        "        @Email, @EmailConfirmed, @PhoneNumber, @PhoneNumberConfirmed, " +
                                        "        @LockoutEnabled, @AccessFailedCount, @LockoutEndDateUtc, " +
                                        "        @SecurityStamp, @TwoFactorEnabled, @ParentId, @ClientID, @PaymentInformation, @UnstructuredData, @CreatedDate)", user);

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

            return Task.FromResult(default(object));
        }

        #endregion

        #region R (Read)

        /// <summary>ユーザを（Id指定で）検索</summary>
        /// <param name="userId">string</param>
        /// <returns>ApplicationUser</returns>
        public async Task<ApplicationUser> FindByIdAsync(string userId)
        {
            // 参照系の機能のため、
            //OnlySts.STSOnly_M();

            // Debug
            Logging.MyDebugSQLTrace("★ : " + 
                MethodBase.GetCurrentMethod().DeclaringType.FullName +
                "." + MethodBase.GetCurrentMethod().Name +
                UserStore.GetParametersString(MethodBase.GetCurrentMethod().GetParameters()));

            ApplicationUser user = null;

            try
            {
                // ユーザを（Id指定で）検索

                // ここに、STS専用モードでの実装を行う。
                if (OnlySts.STSOnly_P)
                {
                    #region STS専用モードのテストコード

                    // 既存のユーザストアに接続して、ユーザを返す。

                    // テスト：管理者ユーザを返す。
                    user = await ApplicationUser.CreateBySignup(ASPNETIdentityConfig.AdministratorUID, true);
                    user.Id = userId;
                    user.PasswordHash = (new CustomPasswordHasher()).HashPassword(ASPNETIdentityConfig.AdministratorPWD);
                    return user;

                    #endregion
                }

                // 通常のモードでの実装を行う。
                switch (ASPNETIdentityConfig.UserStoreType)
                {
                    case EnumUserStoreType.Memory:

                        user = UserStore._users.FirstOrDefault(x => x.Id == userId);

                        break;

                    case EnumUserStoreType.SqlServer:
                    case EnumUserStoreType.ODPManagedDriver:
                    case EnumUserStoreType.PostgreSQL: // DMBMS Provider

                        using (IDbConnection cnn = DataAccess.CreateConnection())
                        {
                            cnn.Open();

                            // ユーザの情報の取得
                            IEnumerable<ApplicationUser> users = null;

                            switch (ASPNETIdentityConfig.UserStoreType)
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
                                this.SelectChildTablesOfUser(cnn, user);
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
        public async Task<ApplicationUser> FindByNameAsync(string userName)
        {
            // 参照系の機能のため、
            //OnlySts.STSOnly_M();

            // Debug
            Logging.MyDebugSQLTrace("★ : " + 
                MethodBase.GetCurrentMethod().DeclaringType.FullName +
                "." + MethodBase.GetCurrentMethod().Name +
                UserStore.GetParametersString(MethodBase.GetCurrentMethod().GetParameters()));

            ApplicationUser user = null;

            try
            {
                // ユーザを（ユーザ名指定で）検索

                // ここに、STS専用モードでの実装を行う。
                if (OnlySts.STSOnly_P)
                {
                    #region STS専用モードのテストコード

                    // 既存のユーザストアに接続して、ユーザを返す。

                    // テスト：管理者ユーザを返す。
                    if (userName == ASPNETIdentityConfig.AdministratorUID)
                    {
                        user = await ApplicationUser.CreateBySignup(ASPNETIdentityConfig.AdministratorUID, true);
                        // user.Id = userId; // ??
                        user.PasswordHash = (new CustomPasswordHasher()).HashPassword(ASPNETIdentityConfig.AdministratorPWD);
                        return user;
                    }

                    #endregion
                }

                // 通常のモードでの実装を行う。
                switch (ASPNETIdentityConfig.UserStoreType)
                {
                    case EnumUserStoreType.Memory:

                        user = UserStore._users.FirstOrDefault(x => x.UserName == userName);

                        break;

                    case EnumUserStoreType.SqlServer:
                    case EnumUserStoreType.ODPManagedDriver:
                    case EnumUserStoreType.PostgreSQL: // DMBMS Provider

                        using (IDbConnection cnn = DataAccess.CreateConnection())
                        {
                            cnn.Open();

                            // ユーザの情報の取得
                            IEnumerable<ApplicationUser> users = null;

                            switch (ASPNETIdentityConfig.UserStoreType)
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
                                this.SelectChildTablesOfUser(cnn, user);
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

        /// <summary>ユーザ一覧を返す。</summary>
        /// <remarks>
        /// ★ マルチテナント化対応を施した
        /// （場合によってはページングも必要になる）
        /// </remarks>
        public IQueryable<ApplicationUser> Users
        {
            get
            {
                // 管理系の機能のため、
                OnlySts.STSOnly_M();

                // Debug
                Logging.MyDebugSQLTrace("★ : " + 
                    MethodBase.GetCurrentMethod().DeclaringType.FullName +
                    "." + MethodBase.GetCurrentMethod().Name +
                    UserStore.GetParametersString(MethodBase.GetCurrentMethod().GetParameters()));

                IEnumerable<ApplicationUser> users = null;

                try
                {
                    // ASP.NET Identity上に分割キーを渡すI/Fが無いので已む無くSession。
                    string parentId = (string)HttpContext.Current.Session["ParentId"];
                    string searchConditionOfUsers = (string)HttpContext.Current.Session["SearchConditionOfUsers"];
                    HttpContext.Current.Session["SearchConditionOfUsers"] = ""; // クリアしないと・・・

                    // （マルチテナント化対応されたテナント）ユーザ一覧を返す。
                    switch (ASPNETIdentityConfig.UserStoreType)
                    {
                        case EnumUserStoreType.Memory:

                            IEnumerable<ApplicationUser> _users = UserStore._users;

                            if (ASPNETIdentityConfig.MultiTenant && !(bool)HttpContext.Current.Session["IsSystemAdmin"])
                            {
                                // マルチテナントの場合、テナントで絞り込む。
                                _users = _users.Where(p => p.ParentId == parentId).ToList();
                            }
                            else
                            {
                                // マルチテナントでない場合か、
                                // マルチテナントでも「既定の管理者ユーザ」の場合。絞り込まない。
                            }

                            // Like
                            if (!string.IsNullOrEmpty(searchConditionOfUsers))
                                _users = _users.Where(p => p.UserName.Contains(searchConditionOfUsers));

                            users = _users.ToList();

                            break;

                        case EnumUserStoreType.SqlServer:
                        case EnumUserStoreType.ODPManagedDriver:
                        case EnumUserStoreType.PostgreSQL: // DMBMS Provider

                            string sql = "";
                            using (IDbConnection cnn = DataAccess.CreateConnection())
                            {
                                switch (ASPNETIdentityConfig.UserStoreType)
                                {
                                    case EnumUserStoreType.SqlServer:

                                        sql = "SELECT TOP {0} * FROM [Users]";

                                        if (ASPNETIdentityConfig.MultiTenant && !(bool)HttpContext.Current.Session["IsSystemAdmin"])
                                        {
                                            // マルチテナントの場合、テナントで絞り込む。
                                            sql += " WHERE [ParentId] = @parentId";
                                        }
                                        else
                                        {
                                            // マルチテナントでない場合か、
                                            // マルチテナントでも「既定の管理者ユーザ」の場合。絞り込まない。
                                        }

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
                                        if (!string.IsNullOrEmpty(ASPNETIdentityConfig.UserListCount.ToString()))
                                        {
                                            sql = string.Format(sql, "" + ASPNETIdentityConfig.UserListCount);
                                        }
                                        else
                                        {
                                            sql = string.Format(sql, 100);
                                        }

                                        break;

                                    case EnumUserStoreType.ODPManagedDriver:

                                        sql = "SELECT * FROM \"Users\" WHERE ROWNUM <= {0}";

                                        if (ASPNETIdentityConfig.MultiTenant && !(bool)HttpContext.Current.Session["IsSystemAdmin"])
                                        {
                                            // マルチテナントの場合、テナントで絞り込む。
                                            sql += " AND \"ParentId\" = :parentId";
                                        }
                                        else
                                        {
                                            // マルチテナントでない場合か、
                                            // マルチテナントでも「既定の管理者ユーザ」の場合。絞り込まない。
                                        }

                                        // Like
                                        if (!string.IsNullOrEmpty(searchConditionOfUsers))
                                            sql += " AND \"UserName\" Like '%' || :searchConditionOfUsers || '%'";

                                        // TOP
                                        if (!string.IsNullOrEmpty(ASPNETIdentityConfig.UserListCount.ToString()))
                                        {
                                            sql = string.Format(sql, ASPNETIdentityConfig.UserListCount);
                                        }
                                        else
                                        {
                                            sql = string.Format(sql, 100);
                                        }   

                                        break;

                                    case EnumUserStoreType.PostgreSQL:

                                        sql = "SELECT * FROM \"users\"";

                                        if (ASPNETIdentityConfig.MultiTenant && !(bool)HttpContext.Current.Session["IsSystemAdmin"])
                                        {
                                            // マルチテナントの場合、テナントで絞り込む。
                                            sql += " WHERE \"parentid\" = @parentId";
                                        }
                                        else
                                        {
                                            // マルチテナントでない場合か、
                                            // マルチテナントでも「既定の管理者ユーザ」の場合。絞り込まない。
                                        }

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
                                        if (!string.IsNullOrEmpty(ASPNETIdentityConfig.UserListCount.ToString()))
                                        {
                                            sql = string.Format(sql, ASPNETIdentityConfig.UserListCount);
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
                                    parentId = parentId,
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
        /// <returns>－</returns>
        public async Task UpdateAsync(ApplicationUser user)
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
                UserStore.GetParametersString(MethodBase.GetCurrentMethod().GetParameters()));

            try
            {
                // ユーザー情報を取得
                ApplicationUser tgtUser = await this.FindByIdAsync(user.Id);

                // ユーザー情報を更新
                if (tgtUser == null)
                {
                    // なにもしない（というか何もできない）
                }
                else
                {
                    // ユーザー情報を更新
                    switch (ASPNETIdentityConfig.UserStoreType)
                    {
                        case EnumUserStoreType.Memory:

                            // 既定の属性
                            tgtUser.Id = user.Id;
                            tgtUser.UserName = user.UserName;
                            tgtUser.PasswordHash = user.PasswordHash;
                            tgtUser.Email = user.Email;
                            tgtUser.EmailConfirmed = user.EmailConfirmed;
                            tgtUser.PhoneNumber = user.PhoneNumber;
                            tgtUser.PhoneNumberConfirmed = user.PhoneNumberConfirmed;
                            tgtUser.AccessFailedCount = user.AccessFailedCount;
                            tgtUser.LockoutEnabled = user.LockoutEnabled;
                            tgtUser.LockoutEndDateUtc = user.LockoutEndDateUtc;
                            tgtUser.SecurityStamp = user.SecurityStamp;
                            tgtUser.TwoFactorEnabled = user.TwoFactorEnabled;
                            // Collection
                            tgtUser.Roles = user.Roles;
                            tgtUser.Logins = user.Logins;
                            tgtUser.Claims = user.Claims;

                            // 追加の属性
                            tgtUser.ParentId = user.ParentId;
                            tgtUser.ClientID = user.ClientID;
                            tgtUser.PaymentInformation = user.PaymentInformation;
                            tgtUser.UnstructuredData = user.UnstructuredData;

                            break;

                        case EnumUserStoreType.SqlServer:
                        case EnumUserStoreType.ODPManagedDriver:
                        case EnumUserStoreType.PostgreSQL: // DMBMS Provider

                            using (IDbConnection cnn = DataAccess.CreateConnection())
                            {
                                cnn.Open();

                                // ユーザー情報を更新
                                switch (ASPNETIdentityConfig.UserStoreType)
                                {
                                    case EnumUserStoreType.SqlServer:

                                        cnn.Execute(
                                            "UPDATE [Users] " +
                                            "SET [UserName] = @UserName, [PasswordHash] = @PasswordHash, " +
                                            "    [Email] = @Email, [EmailConfirmed] = @EmailConfirmed, " +
                                            "    [PhoneNumber] = @PhoneNumber, [PhoneNumberConfirmed] = @PhoneNumberConfirmed, " +
                                            "    [LockoutEnabled] = @LockoutEnabled, [AccessFailedCount] = @AccessFailedCount, [LockoutEndDateUtc] = @LockoutEndDateUtc, " +
                                            "    [SecurityStamp] = @SecurityStamp, [TwoFactorEnabled] = @TwoFactorEnabled, " +
                                            "    [ParentId] = @ParentId, [ClientID] = @ClientID, " + 
                                            "    [PaymentInformation] = @PaymentInformation, [UnstructuredData] = @UnstructuredData " +
                                            "WHERE [Id] = @Id", user);

                                        break;

                                    case EnumUserStoreType.ODPManagedDriver:

                                        cnn.Execute(
                                            "UPDATE \"Users\" " +
                                            "SET \"UserName\" = :UserName, \"PasswordHash\" = :PasswordHash, " +
                                            "    \"Email\" = :Email, \"EmailConfirmed\" = :EmailConfirmed, " +
                                            "    \"PhoneNumber\" = :PhoneNumber, \"PhoneNumberConfirmed\" = :PhoneNumberConfirmed, " +
                                            "    \"LockoutEnabled\" = :LockoutEnabled, \"AccessFailedCount\" = :AccessFailedCount, \"LockoutEndDateUtc\" = :LockoutEndDateUtc, " +
                                            "    \"SecurityStamp\" = :SecurityStamp, \"TwoFactorEnabled\" = :TwoFactorEnabled, " +
                                            "    \"ParentId\" = :ParentId, \"ClientID\" = :ClientID, " +
                                            "    \"PaymentInformation\" = :PaymentInformation, \"UnstructuredData\" = :UnstructuredData " +
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
                                                ParentId = user.ParentId,
                                                ClientID = user.ClientID,
                                                PaymentInformation = user.PaymentInformation,
                                                UnstructuredData = user.UnstructuredData
                                            });

                                        break;

                                    case EnumUserStoreType.PostgreSQL:

                                        cnn.Execute(
                                           "UPDATE \"users\" " +
                                           "SET \"username\" = @UserName, \"passwordhash\" = @PasswordHash, " +
                                           "    \"email\" = @Email, \"emailconfirmed\" = @EmailConfirmed, " +
                                           "    \"phonenumber\" = @PhoneNumber, \"phonenumberconfirmed\" = @PhoneNumberConfirmed, " +
                                           "    \"lockoutenabled\" = @LockoutEnabled, \"accessfailedcount\" = @AccessFailedCount, \"lockoutenddateutc\" = @LockoutEndDateUtc, " +
                                           "    \"securitystamp\" = @SecurityStamp, \"twofactorenabled\" = @TwoFactorEnabled, " +
                                           "    \"parentid\" = @ParentId, \"clientid\" = @ClientID, " +
                                           "    \"paymentinformation\" = @PaymentInformation, \"unstructureddata\" = @UnstructuredData " +
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
                }
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
        private Task UpdateRoles(ApplicationUser user, ApplicationUser tgtUser)
        {
            // 更新系の機能のため、
            OnlySts.STSOnly_M();

            // Debug
            Logging.MyDebugSQLTrace("★ : " + 
                MethodBase.GetCurrentMethod().DeclaringType.FullName +
                "." + MethodBase.GetCurrentMethod().Name +
                UserStore.GetParametersString(MethodBase.GetCurrentMethod().GetParameters()));

            try
            {
                // Rolesの更新
                switch (ASPNETIdentityConfig.UserStoreType)
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
                        //    // 効率悪いが品質的に、this.RemoveFromRoleAsyncを使用する。
                        //    await this.RemoveFromRoleAsync(user, roleName);
                        //}
                        //foreach (string roleName in toAddRolesName)
                        //{
                        //    // 効率悪いが品質的に、this.AddToRoleAsyncを使用する。
                        //    await this.AddToRoleAsync(user, roleName);
                        //}

                        using (IDbConnection cnn = DataAccess.CreateConnection())
                        {
                            cnn.Open();
                            using (IDbTransaction tr = cnn.BeginTransaction())
                            {
                                // ロール・マップを削除（ロール情報を取得する。
                                foreach (string roleName in toRmvRolesName)
                                {
                                    switch (ASPNETIdentityConfig.UserStoreType)
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
                                    switch (ASPNETIdentityConfig.UserStoreType)
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

            return Task.FromResult(default(object));
        }

        //Logins, ClaimsはDel-Insで対応するため、UpdateLogins, UpdateClaimsのメソッドは不要

        #endregion

        #endregion

        #region D (Delete)

        /// <summary>ユーザの論理削除</summary>
        /// <param name="user">ApplicationUser</param>
        /// <returns>－</returns>
        /// <remarks>
        /// 削除するエンティティにマークを付けます
        /// </remarks>
        public Task DeleteAsync(ApplicationUser user)
        {
            // 更新系の機能のため、
            OnlySts.STSOnly_M();

            // Debug
            Logging.MyDebugSQLTrace("★ : " +
                MethodBase.GetCurrentMethod().DeclaringType.FullName +
                "." + MethodBase.GetCurrentMethod().Name +
                UserStore.GetParametersString(MethodBase.GetCurrentMethod().GetParameters()));

            // AccountControllerのメアド検証の再送で利用するため。
            // UsersAdminControllerではチェックしている。

            // 
            //if (user.Id == user.ParentId)
            //{
            //    // 管理者ユーザは削除しない。
            //}
            //else
            //{

            try
            {
                // ユーザの論理削除
                switch (ASPNETIdentityConfig.UserStoreType)
                {
                    case EnumUserStoreType.Memory:

                        // ユーザを削除
                        UserStore._users.Remove(UserStore._users.First(x => x.Id == user.Id));
                        // ユーザの関連情報を削除
                        UserStore._userRoleMap.RemoveAll(x => x.Item1 == user.Id);

                        break;

                    case EnumUserStoreType.SqlServer:
                    case EnumUserStoreType.ODPManagedDriver:
                    case EnumUserStoreType.PostgreSQL: // DMBMS Provider

                        using (IDbConnection cnn = DataAccess.CreateConnection())
                        {
                            cnn.Open();
                            using (IDbTransaction tr = cnn.BeginTransaction())
                            {
                                switch (ASPNETIdentityConfig.UserStoreType)
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
            //}

            return Task.FromResult(default(object));
        }

        #endregion

        #endregion

        #region ユーザ属性

        #region IUserPasswordStore

        /// <summary>ユーザがパスワードを持っているか</summary>
        /// <param name="user">ApplicationUser</param>
        /// <returns>真・偽：ユーザがパスワードを持っているか</returns>
        public Task<bool> HasPasswordAsync(ApplicationUser user)
        {
            // ストレージを直接、触らない。
            //OnlySts.STSOnly_M();

            // Debug
            Logging.MyDebugSQLTrace(
                MethodBase.GetCurrentMethod().DeclaringType.FullName +
                "." + MethodBase.GetCurrentMethod().Name +
                UserStore.GetParametersString(MethodBase.GetCurrentMethod().GetParameters()));

            // ユーザがパスワードを持っているか

            return Task.FromResult(!string.IsNullOrEmpty(user.PasswordHash));
        }

        /// <summary>ユーザーにハッシュ化されたパスワードを設定</summary>
        /// <param name="user">ApplicationUser</param>
        /// <param name="passwordHash">string</param>
        /// <returns>－</returns>
        public Task SetPasswordHashAsync(ApplicationUser user, string passwordHash)
        {
            // ストレージを直接、触らない。
            //OnlySts.STSOnly_M();

            // Debug
            Logging.MyDebugSQLTrace(
                MethodBase.GetCurrentMethod().DeclaringType.FullName +
                "." + MethodBase.GetCurrentMethod().Name +
                UserStore.GetParametersString(MethodBase.GetCurrentMethod().GetParameters()));

            // ユーザーにハッシュ化されたパスワードを設定
            user.PasswordHash = passwordHash;

            return Task.FromResult(default(object));
        }

        /// <summary>ユーザのパスワードのハッシュを取得</summary>
        /// <param name="user">ApplicationUser</param>
        /// <returns>パスワードのハッシュ</returns>
        public Task<string> GetPasswordHashAsync(ApplicationUser user)
        {
            // ストレージを直接、触らない。
            //OnlySts.STSOnly_M();

            // Debug
            Logging.MyDebugSQLTrace(
                MethodBase.GetCurrentMethod().DeclaringType.FullName +
                "." + MethodBase.GetCurrentMethod().Name +
                UserStore.GetParametersString(MethodBase.GetCurrentMethod().GetParameters()));

            // ユーザのパスワードのハッシュを取得

            return Task.FromResult(user.PasswordHash);
        }

        #endregion

        #region IUserEmailStore

        /// <summary>ユーザを（email指定で）検索して取得</summary>
        /// <param name="email">string</param>
        /// <returns>ApplicationUser</returns>
        public Task<ApplicationUser> FindByEmailAsync(string email)
        {
            // 参照系の機能のため、
            //OnlySts.STSOnly_M();

            // Debug
            Logging.MyDebugSQLTrace("★ : " + 
                MethodBase.GetCurrentMethod().DeclaringType.FullName +
                "." + MethodBase.GetCurrentMethod().Name +
                UserStore.GetParametersString(MethodBase.GetCurrentMethod().GetParameters()));

            ApplicationUser user = null;

            try
            {
                // ユーザを（email指定で）検索して取得
                switch (ASPNETIdentityConfig.UserStoreType)
                {
                    case EnumUserStoreType.Memory:

                        user = UserStore._users.FirstOrDefault(x => x.Email == email);

                        break;

                    case EnumUserStoreType.SqlServer:
                    case EnumUserStoreType.ODPManagedDriver:
                    case EnumUserStoreType.PostgreSQL: // DMBMS Provider

                        using (IDbConnection cnn = DataAccess.CreateConnection())
                        {
                            cnn.Open();

                            // ユーザの情報の取得
                            IEnumerable<ApplicationUser> users = null;

                            switch (ASPNETIdentityConfig.UserStoreType)
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
                                this.SelectChildTablesOfUser(cnn, user);
                            }
                        }
                        
                        break;
                }
            }
            catch (Exception ex)
            {
                Logging.MySQLLogForEx(ex);
            }

            return Task.FromResult(user);
        }

        /// <summary>メアドの設定</summary>
        /// <param name="user">ApplicationUser</param>
        /// <param name="email">string</param>
        /// <returns>－</returns>
        public Task SetEmailAsync(ApplicationUser user, string email)
        {
            // ストレージを直接、触らない。
            //OnlySts.STSOnly_M();

            // Debug
            Logging.MyDebugSQLTrace(
                MethodBase.GetCurrentMethod().DeclaringType.FullName +
                "." + MethodBase.GetCurrentMethod().Name +
                UserStore.GetParametersString(MethodBase.GetCurrentMethod().GetParameters()));

            // メアドの設定
            user.Email = email;

            return Task.FromResult(default(object));
        }

        /// <summary>メアドの取得</summary>
        /// <param name="user">ApplicationUser</param>
        /// <returns>Email</returns>
        public Task<string> GetEmailAsync(ApplicationUser user)
        {
            // ストレージを直接、触らない。
            //OnlySts.STSOnly_M();

            // Debug
            Logging.MyDebugSQLTrace(
                MethodBase.GetCurrentMethod().DeclaringType.FullName +
                "." + MethodBase.GetCurrentMethod().Name +
                UserStore.GetParametersString(MethodBase.GetCurrentMethod().GetParameters()));

            // メアドの取得

            return Task.FromResult(user.Email);
        }

        /// <summary>メアド確認の設定</summary>
        /// <param name="user">ApplicationUser</param>
        /// <param name="confirmed">bool</param>
        /// <returns>－</returns>
        public Task SetEmailConfirmedAsync(ApplicationUser user, bool confirmed)
        {
            // ストレージを直接、触らない。
            //OnlySts.STSOnly_M();

            // Debug
            Logging.MyDebugSQLTrace(
                MethodBase.GetCurrentMethod().DeclaringType.FullName +
                "." + MethodBase.GetCurrentMethod().Name +
                UserStore.GetParametersString(MethodBase.GetCurrentMethod().GetParameters()));

            // メアド確認の設定
            user.EmailConfirmed = confirmed;

            return Task.FromResult(default(object));
        }

        /// <summary>メアド確認の取得</summary>
        /// <param name="user">ApplicationUser</param>
        /// <returns>EmailConfirmed</returns>
        public Task<bool> GetEmailConfirmedAsync(ApplicationUser user)
        {
            // ストレージを直接、触らない。
            //OnlySts.STSOnly_M();

            // Debug
            Logging.MyDebugSQLTrace(
                MethodBase.GetCurrentMethod().DeclaringType.FullName +
                "." + MethodBase.GetCurrentMethod().Name +
                UserStore.GetParametersString(MethodBase.GetCurrentMethod().GetParameters()));

            // メアド確認の取得

            return Task.FromResult(user.EmailConfirmed);
        }

        #endregion

        #region IUserPhoneNumberStore

        /// <summary>電話番号の設定</summary>
        /// <param name="user">ApplicationUser</param>
        /// <param name="phoneNumber">string</param>
        /// <returns>－</returns>
        public Task SetPhoneNumberAsync(ApplicationUser user, string phoneNumber)
        {
            // ストレージを直接、触らない。
            //OnlySts.STSOnly_M();

            // Debug
            Logging.MyDebugSQLTrace(
                MethodBase.GetCurrentMethod().DeclaringType.FullName +
                "." + MethodBase.GetCurrentMethod().Name +
                UserStore.GetParametersString(MethodBase.GetCurrentMethod().GetParameters()));

            // 電話番号の設定
            user.PhoneNumber = phoneNumber;

            return Task.FromResult(default(object));
        }

        /// <summary>電話番号の取得</summary>
        /// <param name="user">ApplicationUser</param>
        /// <returns>phone number</returns>
        public Task<string> GetPhoneNumberAsync(ApplicationUser user)
        {
            // ストレージを直接、触らない。
            //OnlySts.STSOnly_M();

            // Debug
            Logging.MyDebugSQLTrace(
                MethodBase.GetCurrentMethod().DeclaringType.FullName +
                "." + MethodBase.GetCurrentMethod().Name +
                UserStore.GetParametersString(MethodBase.GetCurrentMethod().GetParameters()));

            // 電話番号の取得

            return Task.FromResult(user.PhoneNumber);
        }

        /// <summary>電話番号確認の設定</summary>
        /// <param name="user">ApplicationUser</param>
        /// <param name="confirmed">bool</param>
        /// <returns>－</returns>
        public Task SetPhoneNumberConfirmedAsync(ApplicationUser user, bool confirmed)
        {
            // ストレージを直接、触らない。
            //OnlySts.STSOnly_M();

            // Debug
            Logging.MyDebugSQLTrace(
                MethodBase.GetCurrentMethod().DeclaringType.FullName +
                "." + MethodBase.GetCurrentMethod().Name +
                UserStore.GetParametersString(MethodBase.GetCurrentMethod().GetParameters()));

            // 電話番号確認の設定
            user.PhoneNumberConfirmed = confirmed;

            return Task.FromResult(default(object));
        }

        /// <summary>電話番号確認の取得</summary>
        /// <param name="user">ApplicationUser</param>
        /// <returns>phone number is confirmed</returns>
        public Task<bool> GetPhoneNumberConfirmedAsync(ApplicationUser user)
        {
            // ストレージを直接、触らない。
            //OnlySts.STSOnly_M();

            // Debug
            Logging.MyDebugSQLTrace(
                MethodBase.GetCurrentMethod().DeclaringType.FullName +
                "." + MethodBase.GetCurrentMethod().Name +
                UserStore.GetParametersString(MethodBase.GetCurrentMethod().GetParameters()));

            // 電話番号確認の取得

            return Task.FromResult(user.PhoneNumberConfirmed);
        }

        #endregion

        #region IUserRoleStore

        /// <summary>ロールにユーザを追加</summary>
        /// <param name="user">ApplicationUser</param>
        /// <param name="roleName">string</param>
        /// <returns>－</returns>
        public Task AddToRoleAsync(ApplicationUser user, string roleName)
        {
            // 他テーブルのため、
            OnlySts.STSOnly_M();

            // Debug
            Logging.MyDebugSQLTrace("★ : " + 
                MethodBase.GetCurrentMethod().DeclaringType.FullName +
                "." + MethodBase.GetCurrentMethod().Name +
                UserStore.GetParametersString(MethodBase.GetCurrentMethod().GetParameters()));

            try
            {
                // ロールにユーザを追加
                ApplicationRole role = null;
                switch (ASPNETIdentityConfig.UserStoreType)
                {
                    case EnumUserStoreType.Memory:

                        // ロール情報を取得する
                        role = UserStore._roles.FirstOrDefault(x => x.Name == roleName);

                        if (role == null)
                        {
                            // 存在しないロール
                            throw new InvalidOperationException();
                        }
                        else
                        {
                            // ロール・マップ情報を取得する
                            Tuple<string, string> userRoleMap = UserStore._userRoleMap.FirstOrDefault(
                                x => x.Item1 == user.Id && x.Item2 == role.Id);

                            if (userRoleMap != null)
                            {
                                // 既に追加されている。
                            }
                            else
                            {
                                // ロール・マップにユーザとロールに追加
                                UserStore._userRoleMap.Add(Tuple.Create(user.Id, role.Id));
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
                            switch (ASPNETIdentityConfig.UserStoreType)
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

            return Task.FromResult(default(object));
        }

        /// <summary>ユーザがロールに所属するか？</summary>
        /// <param name="user">ApplicationUser</param>
        /// <param name="roleName">ロール名</param>
        /// <returns>真・偽：ユーザがロールに所属するか</returns>
        public async Task<bool> IsInRoleAsync(ApplicationUser user, string roleName)
        {
            // ストレージを直接、触らない。
            //OnlySts.STSOnly_M();

            // Debug
            Logging.MyDebugSQLTrace(
                MethodBase.GetCurrentMethod().DeclaringType.FullName +
                "." + MethodBase.GetCurrentMethod().Name +
                UserStore.GetParametersString(MethodBase.GetCurrentMethod().GetParameters()));

            // ユーザがロールに所属するか？

            // ユーザのロール一覧を返す。
            IList<string> roles = await this.GetRolesAsync(user);

            // bool (ユーザのロール一覧から、一致するロール名を取得できたら真、できなかったら偽
            return roles.FirstOrDefault(x => x.ToUpper() == roleName.ToUpper()) != null;
        }

        /// <summary>ユーザのロール一覧を取得</summary>
        /// <param name="user">ApplicationUser</param>
        /// <returns>ユーザのロール一覧</returns>
        public Task<IList<string>> GetRolesAsync(ApplicationUser user)
        {
            // 他テーブルのため、
            //OnlySts.STSOnly_M();
            if (OnlySts.STSOnly_P)
            {
                // 空の一覧を返す。
                return Task.FromResult((IList<string>)new List<string>());
            }

            // Debug
            Logging.MyDebugSQLTrace("★ : " + 
                MethodBase.GetCurrentMethod().DeclaringType.FullName +
                "." + MethodBase.GetCurrentMethod().Name +
                UserStore.GetParametersString(MethodBase.GetCurrentMethod().GetParameters()));

            IList<string> roleNames = null;

            try
            {
                // ユーザのロール一覧を取得
                switch (ASPNETIdentityConfig.UserStoreType)
                {
                    case EnumUserStoreType.Memory:

                        // UserRoleMapに含まれるuserId = user.Id のTupleに含まれるRole.IdのRole.Nameを一覧する。
                        roleNames = UserStore._userRoleMap // List<Tuple<string, sting>>
                                                           // Tuple.Item1 == user.IdのTupleのListを抽出。
                            .Where(x => x.Item1 == user.Id)
                            // 結果のTupleのListの中からTuple.Item2（ = Role.Id）の射影を取る。
                            .Select(x => x.Item2)
                            // Tuple.Item2の射影の中からRoles.Idと一致するRole(List<ApplicationRole>)のListを抽出して射影。
                            .Select(x => UserStore._roles.First(y => y.Id == x))
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

                            switch (ASPNETIdentityConfig.UserStoreType)
                            {
                                case EnumUserStoreType.SqlServer:

                                    roles = cnn.Query<ApplicationRole>(
                                        "SELECT [Roles].[Id] as Id, [Roles].[Name] as Name, [Roles].[ParentId] as ParentId " +
                                        "FROM   [Roles], [UserRoles], [Users] " +
                                        "WHERE  [Roles].[Id] = [UserRoles].[RoleId] " +
                                        "   AND [UserRoles].[UserId] = [Users].[Id] " +
                                        "   AND [Users].[Id] = @UserId",
                                        new { UserId = user.Id });

                                    break;

                                case EnumUserStoreType.ODPManagedDriver:

                                    roles = cnn.Query<ApplicationRole>(
                                        "SELECT \"Roles\".\"Id\" as Id, \"Roles\".\"Name\" as Name, \"Roles\".\"ParentId\" as ParentId " +
                                        "FROM   \"Roles\", \"UserRoles\", \"Users\" " +
                                        "WHERE  \"Roles\".\"Id\" = \"UserRoles\".\"RoleId\" " +
                                        "   AND \"UserRoles\".\"UserId\" = \"Users\".\"Id\" " +
                                        "   AND \"Users\".\"Id\" = :UserId",
                                        new { UserId = user.Id });

                                    break;

                                case EnumUserStoreType.PostgreSQL:

                                    roles = cnn.Query<ApplicationRole>(
                                        "SELECT \"roles\".\"id\" as id, \"roles\".\"name\" as name, \"roles\".\"parentid\" as parentid " +
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
            return Task.FromResult(roleNames);
        }

        /// <summary>ユーザをロールから削除</summary>
        /// <param name="user">ApplicationUser</param>
        /// <param name="roleName">ロール名</param>
        /// <returns>－</returns>
        public Task RemoveFromRoleAsync(ApplicationUser user, string roleName)
        {
            // 他テーブルのため、
            OnlySts.STSOnly_M();

            // Debug
            Logging.MyDebugSQLTrace("★ : " + 
                MethodBase.GetCurrentMethod().DeclaringType.FullName +
                "." + MethodBase.GetCurrentMethod().Name +
                UserStore.GetParametersString(MethodBase.GetCurrentMethod().GetParameters()));

            if ((user.Id == user.ParentId)                     // 管理者ユーザー
                && roleName == ASPNETIdentityConst.Role_Admin) // global role of Administrator
            {
                // 管理者ユーザーをAdministratorsグループ（ロール）から削除しない。
            }
            else
            {
                try
                {
                    // ユーザーをロールから削除
                    ApplicationRole role = null;
                    switch (ASPNETIdentityConfig.UserStoreType)
                    {
                        case EnumUserStoreType.Memory:

                            // 名称の一致するロールを取得
                            role = UserStore._roles.FirstOrDefault(x => x.Name == roleName);

                            if (role == null)
                            {
                                // なにもしない（というか何もできない）
                            }
                            else
                            {
                                // UserRoleMapに含まれるTuple.Item1 == user.Id && Tuple.Item2 == role.IdのTupleを返す。
                                Tuple<string, string> userRoleMap = UserStore._userRoleMap
                                    .FirstOrDefault(x => x.Item1 == user.Id && x.Item2 == role.Id);

                                // ユーザをロールから削除
                                if (userRoleMap != null)
                                {
                                    // 取得できたら、Tupleを削除。
                                    UserStore._userRoleMap.Remove(userRoleMap);
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
                                switch (ASPNETIdentityConfig.UserStoreType)
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
            }

            return Task.FromResult(default(object));
        }

        #endregion

        #endregion

        #region ログイン属性

        #region IUserSecurityStampStore

        /// <summary>セキュリティスタンプを設定</summary>
        /// <param name="user">ApplicationUser</param>
        /// <param name="stamp">string</param>
        /// <returns>－</returns>
        public Task SetSecurityStampAsync(ApplicationUser user, string stamp)
        {
            // ストレージを直接、触らない。
            //OnlySts.STSOnly_M();

            // Debug
            Logging.MyDebugSQLTrace(
                MethodBase.GetCurrentMethod().DeclaringType.FullName +
                "." + MethodBase.GetCurrentMethod().Name +
                UserStore.GetParametersString(MethodBase.GetCurrentMethod().GetParameters()));

            // セキュリティスタンプを設定
            user.SecurityStamp = stamp;

            return Task.FromResult(default(object));
        }

        /// <summary>セキュリティスタンプを取得</summary>
        /// <param name="user">ApplicationUser</param>
        /// <returns>SecurityStamp</returns>
        public Task<string> GetSecurityStampAsync(ApplicationUser user)
        {
            // ストレージを直接、触らない。
            //OnlySts.STSOnly_M();

            // Debug
            Logging.MyDebugSQLTrace(
                MethodBase.GetCurrentMethod().DeclaringType.FullName +
                "." + MethodBase.GetCurrentMethod().Name +
                UserStore.GetParametersString(MethodBase.GetCurrentMethod().GetParameters()));

            // セキュリティスタンプを取得
            return Task.FromResult(user.SecurityStamp);
        }

        #endregion

        #region IUserLockoutStore

        /// <summary>ユーザがロックアウト可能かどうかを設定</summary>
        /// <param name="user">ApplicationUser</param>
        /// <param name="enabled">真・偽：ユーザがロックアウト可能かどうか</param>
        /// <returns>－</returns>
        public Task SetLockoutEnabledAsync(ApplicationUser user, bool enabled)
        {
            // ストレージを直接、触らない。
            //OnlySts.STSOnly_M();

            // Debug
            Logging.MyDebugSQLTrace(
                MethodBase.GetCurrentMethod().DeclaringType.FullName +
                "." + MethodBase.GetCurrentMethod().Name +
                UserStore.GetParametersString(MethodBase.GetCurrentMethod().GetParameters()));

            // ユーザがロックアウト可能かどうかを設定
            user.LockoutEnabled = enabled;

            return Task.FromResult(default(object));
        }

        /// <summary>ユーザがロックアウト可能かどうかを取得</summary>
        /// <param name="user">ApplicationUser</param>
        /// <returns>真・偽：ユーザがロックアウト可能かどうか</returns>
        public Task<bool> GetLockoutEnabledAsync(ApplicationUser user)
        {
            // ストレージを直接、触らない。
            //OnlySts.STSOnly_M();

            // Debug
            Logging.MyDebugSQLTrace(
                MethodBase.GetCurrentMethod().DeclaringType.FullName +
                "." + MethodBase.GetCurrentMethod().Name +
                UserStore.GetParametersString(MethodBase.GetCurrentMethod().GetParameters()));

            // ユーザがロックアウト可能かどうかを取得
            return Task.FromResult(user.LockoutEnabled);
        }

        /// <summary>サインインに失敗した試行回数を記録</summary>
        /// <param name="user">ApplicationUser</param>
        /// <returns>サインインに失敗した試行回数</returns>
        public Task<int> IncrementAccessFailedCountAsync(ApplicationUser user)
        {
            // ストレージを直接、触らない。
            //OnlySts.STSOnly_M();

            // Debug
            Logging.MyDebugSQLTrace(
                MethodBase.GetCurrentMethod().DeclaringType.FullName +
                "." + MethodBase.GetCurrentMethod().Name +
                UserStore.GetParametersString(MethodBase.GetCurrentMethod().GetParameters()));

            // サインインに失敗した試行回数を記録
            user.AccessFailedCount++;

            return Task.FromResult(user.AccessFailedCount);
        }

        /// <summary>失敗したサインインの試行回数を取得</summary>
        /// <param name="user">ApplicationUser</param>
        /// <returns>現在の失敗したサインインの試行回数</returns>
        /// <remarks>パスワードが確認されるか、アカウントがロックアウトされるたびに、この数は、リセットされる。</remarks>
        public Task<int> GetAccessFailedCountAsync(ApplicationUser user)
        {
            // ストレージを直接、触らない。
            //OnlySts.STSOnly_M();

            // Debug
            Logging.MyDebugSQLTrace(
                MethodBase.GetCurrentMethod().DeclaringType.FullName +
                "." + MethodBase.GetCurrentMethod().Name +
                UserStore.GetParametersString(MethodBase.GetCurrentMethod().GetParameters()));

            // 失敗したサインインの試行回数を取得
            return Task.FromResult(user.AccessFailedCount);
        }

        /// <summary>失敗したサインインの試行回数をリセット</summary>
        /// <param name="user">ApplicationUser</param>
        /// <returns>－</returns>
        /// <remarks>
        /// 慣例的に、サインインが成功した場合にリセットされる。
        /// </remarks>
        public Task ResetAccessFailedCountAsync(ApplicationUser user)
        {
            // ストレージを直接、触らない。
            //OnlySts.STSOnly_M();

            // Debug
            Logging.MyDebugSQLTrace(
                MethodBase.GetCurrentMethod().DeclaringType.FullName +
                "." + MethodBase.GetCurrentMethod().Name +
                UserStore.GetParametersString(MethodBase.GetCurrentMethod().GetParameters()));

            // 失敗したサインインの試行回数をリセット
            user.AccessFailedCount = 0;

            return Task.FromResult(default(object));
        }

        /// <summary>
        /// ロックアウト終了日を設定
        /// （指定された終了日まで、ユーザをロックアウト）
        /// </summary>
        /// <param name="user">ApplicationUser</param>
        /// <param name="lockoutEnd">ロックアウト終了日</param>
        /// <returns>－</returns>
        /// <remarks>
        /// 過去の日付に設定すると、ロックアウトを解除する。
        /// </remarks>
        public Task SetLockoutEndDateAsync(ApplicationUser user, DateTimeOffset lockoutEnd)
        {
            // ストレージを直接、触らない。
            //OnlySts.STSOnly_M();

            // Debug
            Logging.MyDebugSQLTrace(
                MethodBase.GetCurrentMethod().DeclaringType.FullName +
                "." + MethodBase.GetCurrentMethod().Name +
                UserStore.GetParametersString(MethodBase.GetCurrentMethod().GetParameters()));

            // ロックアウト終了日を設定（指定された終了日まで、ユーザをロックアウト）

            // DateTime と DateTimeOffset 間の変換
            // https://msdn.microsoft.com/ja-jp/library/bb546101.aspx
            user.LockoutEndDateUtc = lockoutEnd.DateTime;

            return Task.FromResult(default(object));
        }

        /// <summary>
        /// ロックアウト終了日を取得
        /// （指定された終了日まで、ユーザをロックアウト）</summary>
        /// <param name="user">ApplicationUser</param>
        /// <returns>ロックアウト終了日</returns>
        /// <remarks>
        /// 過去の日付を返すときは既にロックアウトされていない。
        /// </remarks>
        public Task<DateTimeOffset> GetLockoutEndDateAsync(ApplicationUser user)
        {
            // ストレージを直接、触らない。
            //OnlySts.STSOnly_M();

            // Debug
            Logging.MyDebugSQLTrace(
                MethodBase.GetCurrentMethod().DeclaringType.FullName +
                "." + MethodBase.GetCurrentMethod().Name +
                UserStore.GetParametersString(MethodBase.GetCurrentMethod().GetParameters()));

            // ロックアウト終了日を取得（指定された終了日まで、ユーザをロックアウト）

            // DateTime と DateTimeOffset 間の変換
            // https://msdn.microsoft.com/ja-jp/library/bb546101.aspx

            if (user.LockoutEndDateUtc.HasValue)
            {
                return Task.FromResult(
                    (DateTimeOffset)DateTime.SpecifyKind(user.LockoutEndDateUtc.Value, DateTimeKind.Utc));
            }
            else
            {
                return Task.FromResult(DateTimeOffset.MinValue);
            }
        }

        #endregion

        #region IUserTwoFactorStore

        /// <summary>2FAの有効・無効を設定</summary>
        /// <param name="user">ApplicationUser</param>
        /// <param name="enabled">真・偽：2FAが有効かどうか</param>
        /// <returns>－</returns>
        public Task SetTwoFactorEnabledAsync(ApplicationUser user, bool enabled)
        {
            // ストレージを直接、触らない。
            //OnlySts.STSOnly_M();

            // Debug
            Logging.MyDebugSQLTrace(
                MethodBase.GetCurrentMethod().DeclaringType.FullName +
                "." + MethodBase.GetCurrentMethod().Name +
                UserStore.GetParametersString(MethodBase.GetCurrentMethod().GetParameters()));

            // 2FAの有効・無効を設定
            user.TwoFactorEnabled = enabled;

            return Task.FromResult(default(object));
        }

        /// <summary>2FAの有効・無効を取得</summary>
        /// <param name="user">ApplicationUser</param>
        /// <returns>真・偽：2FAが有効かどうか</returns>
        public Task<bool> GetTwoFactorEnabledAsync(ApplicationUser user)
        {
            // ストレージを直接、触らない。
            //OnlySts.STSOnly_M();

            // Debug
            Logging.MyDebugSQLTrace(
                MethodBase.GetCurrentMethod().DeclaringType.FullName +
                "." + MethodBase.GetCurrentMethod().Name +
                UserStore.GetParametersString(MethodBase.GetCurrentMethod().GetParameters()));

            // 2FAの有効・無効を取得

            return Task.FromResult(user.TwoFactorEnabled);
        }

        #endregion

        #region Collection (Roles, Logins, Claims)

        #region IRoleStore

        #region CRUD(共通)

        #region C

        /// <summary>ロールを追加</summary>
        /// <param name="role">ApplicationRole</param>
        /// <returns>－</returns>
        public Task CreateAsync(ApplicationRole role)
        {
            // 他テーブルのため、
            OnlySts.STSOnly_M();

            // Debug
            Logging.MyDebugSQLTrace("★ : " + 
                MethodBase.GetCurrentMethod().DeclaringType.FullName +
                "." + MethodBase.GetCurrentMethod().Name +
                UserStore.GetParametersString(MethodBase.GetCurrentMethod().GetParameters()));

            try
            {
                switch (ASPNETIdentityConfig.UserStoreType)
                {
                    case EnumUserStoreType.Memory:

                        // ロールを追加
                        UserStore._roles.Add(role);

                        break;

                    case EnumUserStoreType.SqlServer:
                    case EnumUserStoreType.ODPManagedDriver:
                    case EnumUserStoreType.PostgreSQL: // DMBMS Provider

                        using (IDbConnection cnn = DataAccess.CreateConnection())
                        {
                            cnn.Open();

                            switch (ASPNETIdentityConfig.UserStoreType)
                            {
                                case EnumUserStoreType.SqlServer:

                                    cnn.Execute(
                                        "INSERT INTO [Roles] ( [Id], [Name], [ParentId] ) VALUES ( @Id, @Name, @ParentId )", role);

                                    break;

                                case EnumUserStoreType.ODPManagedDriver:

                                    cnn.Execute(
                                        "INSERT INTO \"Roles\" ( \"Id\", \"Name\", \"ParentId\" ) VALUES ( :Id, :Name, :ParentId )", role);

                                    break;

                                case EnumUserStoreType.PostgreSQL:

                                    cnn.Execute(
                                        "INSERT INTO \"roles\" ( \"id\", \"name\", \"parentid\" ) VALUES ( @Id, @Name, @ParentId )", role);

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

            return Task.FromResult(default(object));
        }

        #endregion

        #region R

        /// <summary>ロールを ID から検索</summary>
        /// <param name="roleId">string</param>
        /// <returns>ApplicationRole</returns>
        Task<ApplicationRole> IRoleStore<ApplicationRole, string>.FindByIdAsync(string roleId)
        {
            // 他テーブルのため、
            OnlySts.STSOnly_M();

            // Debug
            Logging.MyDebugSQLTrace("★ : " + 
                MethodBase.GetCurrentMethod().DeclaringType.FullName +
                "." + MethodBase.GetCurrentMethod().Name +
                UserStore.GetParametersString(MethodBase.GetCurrentMethod().GetParameters()));

            ApplicationRole role = null;

            try
            {
                switch (ASPNETIdentityConfig.UserStoreType)
                {
                    case EnumUserStoreType.Memory:

                        // ロールを ID から検索
                        role = UserStore._roles.FirstOrDefault(x => x.Id == roleId);

                        break;

                    case EnumUserStoreType.SqlServer:
                    case EnumUserStoreType.ODPManagedDriver:
                    case EnumUserStoreType.PostgreSQL: // DMBMS Provider

                        using (IDbConnection cnn = DataAccess.CreateConnection())
                        {
                            cnn.Open();

                            // ユーザの情報の取得
                            IEnumerable<ApplicationRole> roles = null;
                            switch (ASPNETIdentityConfig.UserStoreType)
                            {
                                case EnumUserStoreType.SqlServer:
                                    roles = cnn.Query<ApplicationRole>(
                                        "SELECT * FROM [Roles] WHERE [Id] = @roleId", new { roleId = roleId });

                                    break;

                                case EnumUserStoreType.ODPManagedDriver:

                                    roles = cnn.Query<ApplicationRole>(
                                        "SELECT * FROM \"Roles\" WHERE \"Id\" = :roleId", new { roleId = roleId });

                                    break;

                                case EnumUserStoreType.PostgreSQL:

                                    roles = cnn.Query<ApplicationRole>(
                                        "SELECT * FROM \"roles\" WHERE \"id\" = @roleId", new { roleId = roleId });

                                    break;
                            }

                            if (roles.Count() != 0)
                            {
                                role = roles.First();
                            }
                        }

                        break;
                }
            }
            catch (Exception ex)
            {
                Logging.MySQLLogForEx(ex);
            }

            return Task.FromResult(role);
        }

        /// <summary>ロールを（ロール名指定で）検索</summary>
        /// <param name="roleName">string</param>
        /// <returns>ApplicationRole</returns>
        Task<ApplicationRole> IRoleStore<ApplicationRole, string>.FindByNameAsync(string roleName)
        {
            // 他テーブルのため、
            OnlySts.STSOnly_M();

            // Debug
            Logging.MyDebugSQLTrace("★ : " + 
                MethodBase.GetCurrentMethod().DeclaringType.FullName +
                "." + MethodBase.GetCurrentMethod().Name +
                UserStore.GetParametersString(MethodBase.GetCurrentMethod().GetParameters()));

            ApplicationRole role = null;

            try
            {
                switch (ASPNETIdentityConfig.UserStoreType)
                {
                    case EnumUserStoreType.Memory:

                        // ロールを（ロール名指定で）検索
                        role = UserStore._roles.FirstOrDefault(x => x.Name == roleName);

                        break;

                    case EnumUserStoreType.SqlServer:
                    case EnumUserStoreType.ODPManagedDriver:
                    case EnumUserStoreType.PostgreSQL: // DMBMS Provider

                        using (IDbConnection cnn = DataAccess.CreateConnection())
                        {
                            cnn.Open();

                            // ユーザの情報の取得
                            IEnumerable<ApplicationRole> roles = null;
                            switch (ASPNETIdentityConfig.UserStoreType)
                            {
                                case EnumUserStoreType.SqlServer:

                                    roles = cnn.Query<ApplicationRole>(
                                        "SELECT * FROM [Roles] WHERE [Name] = @roleName", new { roleName = roleName });

                                    break;

                                case EnumUserStoreType.ODPManagedDriver:

                                    roles = cnn.Query<ApplicationRole>(
                                        "SELECT * FROM \"Roles\" WHERE \"Name\" = :roleName", new { roleName = roleName });

                                    break;

                                case EnumUserStoreType.PostgreSQL:

                                    roles = cnn.Query<ApplicationRole>(
                                        "SELECT * FROM \"roles\" WHERE \"name\" = @roleName", new { roleName = roleName });

                                    break;
                            }

                            if (roles.Count() != 0)
                            {
                                role = roles.First();
                            }
                        }

                        break;
                }
            }
            catch (Exception ex)
            {
                Logging.MySQLLogForEx(ex);
            }

            return Task.FromResult(role);
        }

        /// <summary>
        /// ロール一覧を返す。
        /// </summary>
        /// <remarks>
        /// ★ マルチテナント化対応を施した
        /// （場合によってはページングも必要になる）
        /// </remarks>
        public IQueryable<ApplicationRole> Roles
        {
            get
            {
                // 他テーブルのため、
                // 管理系の機能のため、
                OnlySts.STSOnly_M();

                // Debug
                Logging.MyDebugSQLTrace("★ : " + 
                    MethodBase.GetCurrentMethod().DeclaringType.FullName +
                    "." + MethodBase.GetCurrentMethod().Name +
                    UserStore.GetParametersString(MethodBase.GetCurrentMethod().GetParameters()));

                // システム共通のロール
                IEnumerable<ApplicationRole> commonRoles = null;
                // 個別のロール
                IEnumerable<ApplicationRole> individualRoles = null;

                try
                {
                    // ASP.NET Identity上に分割キーを渡すI/Fが無いので已む無くSession。
                    string parentId = (string)HttpContext.Current.Session["ParentId"];

                    // ロール一覧を返す。
                    switch (ASPNETIdentityConfig.UserStoreType)
                    {
                        case EnumUserStoreType.Memory:

                            // システム共通のロール
                            commonRoles = UserStore._roles.Where(p => p.ParentId == "").ToList();

                            // 個別のロール
                            if (ASPNETIdentityConfig.MultiTenant && !(bool)HttpContext.Current.Session["IsSystemAdmin"])
                            {
                                // マルチテナントの場合、テナントで絞り込む。
                                individualRoles = UserStore._roles.Where(p => p.ParentId == parentId).ToList();
                            }
                            else
                            {
                                // マルチテナントでない場合か、
                                // マルチテナントでも「既定の管理者ユーザ」の場合。絞り込まない。
                                individualRoles = UserStore._roles.Where(p => p.ParentId != "").ToList();
                            }

                            // 統合して返却
                            commonRoles = commonRoles.Union(individualRoles);

                            break;

                        case EnumUserStoreType.SqlServer:
                        case EnumUserStoreType.ODPManagedDriver:
                        case EnumUserStoreType.PostgreSQL: // DMBMS Provider

                            using (IDbConnection cnn = DataAccess.CreateConnection())
                            {
                                cnn.Open();

                                switch (ASPNETIdentityConfig.UserStoreType)
                                {
                                    case EnumUserStoreType.SqlServer:

                                        // システム共通のロール
                                        commonRoles = cnn.Query<ApplicationRole>(
                                            "SELECT * FROM [Roles] WHERE [ParentId] = @parentId", new { parentId = "" });

                                        // 個別のロール
                                        if (ASPNETIdentityConfig.MultiTenant && !(bool)HttpContext.Current.Session["IsSystemAdmin"])
                                        {
                                            // マルチテナントの場合、テナントで絞り込む。
                                            individualRoles = cnn.Query<ApplicationRole>(
                                                "SELECT * FROM [Roles] WHERE [ParentId] = @parentId", new { parentId = parentId });
                                        }
                                        else
                                        {
                                            // マルチテナントでない場合か、
                                            // マルチテナントでも「既定の管理者ユーザ」の場合。絞り込まない。
                                            individualRoles = cnn.Query<ApplicationRole>(
                                                string.Format("SELECT TOP {0} * FROM [Roles] WHERE [ParentId] != ''", ASPNETIdentityConfig.UserListCount));
                                        }

                                        break;

                                    case EnumUserStoreType.ODPManagedDriver:

                                        // システム共通のロール
                                        commonRoles = cnn.Query<ApplicationRole>(
                                            "SELECT * FROM \"Roles\" WHERE \"ParentId\" IS NULL");

                                        // 個別のロール
                                        if (ASPNETIdentityConfig.MultiTenant && !(bool)HttpContext.Current.Session["IsSystemAdmin"])
                                        {
                                            // マルチテナントの場合、テナントで絞り込む。
                                            individualRoles = cnn.Query<ApplicationRole>(
                                                "SELECT * FROM \"Roles\" WHERE \"ParentId\" = :parentId", new { parentId = parentId });
                                        }
                                        else
                                        {
                                            // マルチテナントでない場合か、
                                            // マルチテナントでも「既定の管理者ユーザ」の場合。絞り込まない。
                                            individualRoles = cnn.Query<ApplicationRole>(
                                                string.Format("SELECT * FROM \"Roles\" WHERE \"ParentId\" IS NOT NULL AND ROWNUM <= {0}", ASPNETIdentityConfig.UserListCount));
                                        }

                                        break;

                                    case EnumUserStoreType.PostgreSQL:

                                        // システム共通のロール
                                        commonRoles = cnn.Query<ApplicationRole>(
                                            "SELECT * FROM \"roles\" WHERE \"parentid\" IS NULL");

                                        // 個別のロール
                                        if (ASPNETIdentityConfig.MultiTenant && !(bool)HttpContext.Current.Session["IsSystemAdmin"])
                                        {
                                            // マルチテナントの場合、テナントで絞り込む。
                                            individualRoles = cnn.Query<ApplicationRole>(
                                                "SELECT * FROM \"roles\" WHERE \"parentid\" = @parentId", new { parentId = parentId });
                                        }
                                        else
                                        {
                                            // マルチテナントでない場合か、
                                            // マルチテナントでも「既定の管理者ユーザ」の場合。絞り込まない。
                                            individualRoles = cnn.Query<ApplicationRole>(
                                                string.Format("SELECT * FROM \"roles\" WHERE \"parentid\" IS NOT NULL LIMIT {0}", ASPNETIdentityConfig.UserListCount));
                                        }

                                        break;
                                }
                            }

                            // 統合して返却
                            commonRoles = commonRoles.Union(individualRoles);

                            break;
                    }
                }
                catch (Exception ex)
                {
                    Logging.MySQLLogForEx(ex);
                }

                // IQueryableとして戻す。
                return commonRoles.AsQueryable();
            }
        }

        #endregion

        #region U

        /// <summary>ロールを更新する</summary>
        /// <param name="role">ApplicationRole</param>
        /// <returns>－</returns>
        public Task UpdateAsync(ApplicationRole role)
        {
            // 他テーブルのため、
            OnlySts.STSOnly_M();

            // Debug
            Logging.MyDebugSQLTrace("★ : " + 
                MethodBase.GetCurrentMethod().DeclaringType.FullName +
                "." + MethodBase.GetCurrentMethod().Name +
                UserStore.GetParametersString(MethodBase.GetCurrentMethod().GetParameters()));

            if (string.IsNullOrEmpty(role.ParentId))
            {
                // グローバル ロールは更新しない。
            }
            else
            {
                try
                {
                    // テナント ロールを更新する
                    switch (ASPNETIdentityConfig.UserStoreType)
                    {
                        case EnumUserStoreType.Memory:

                            // RolesからIdが同じApplicationRoleを取得する。
                            ApplicationRole r = UserStore._roles.FirstOrDefault(x => x.Id == role.Id);

                            if (r == null)
                            {
                                // ・・・
                            }
                            else
                            {
                                // ロールを更新（ApplicationRole.Nameを更新
                                r.Name = role.Name;
                            }

                            break;

                        case EnumUserStoreType.SqlServer:
                        case EnumUserStoreType.ODPManagedDriver:
                        case EnumUserStoreType.PostgreSQL: // DMBMS Provider

                            using (IDbConnection cnn = DataAccess.CreateConnection())
                            {
                                cnn.Open();

                                // ユーザー情報を更新
                                switch (ASPNETIdentityConfig.UserStoreType)
                                {
                                    case EnumUserStoreType.SqlServer:

                                        cnn.Execute(
                                            "UPDATE [Roles] SET [Name] = @Name WHERE [Id] = @Id",
                                            new { Id = role.Id, Name = role.Name });

                                        break;

                                    case EnumUserStoreType.ODPManagedDriver:

                                        cnn.Execute(
                                            "UPDATE \"Roles\" SET \"Name\" = :Name WHERE \"Id\" = :Id",
                                            new { Id = role.Id, Name = role.Name });

                                        break;

                                    case EnumUserStoreType.PostgreSQL:

                                        cnn.Execute(
                                            "UPDATE \"roles\" SET \"name\" = @Name WHERE \"id\" = @Id",
                                            new { Id = role.Id, Name = role.Name });

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
            }

            return Task.FromResult(default(object));
        }

        #endregion

        #region D

        /// <summary>ロールを削除する</summary>
        /// <param name="role">ApplicationRole</param>
        /// <returns>－</returns>
        public Task DeleteAsync(ApplicationRole role)
        {
            // 他テーブルのため、
            OnlySts.STSOnly_M();

            // Debug
            Logging.MyDebugSQLTrace("★ : " + 
                MethodBase.GetCurrentMethod().DeclaringType.FullName +
                "." + MethodBase.GetCurrentMethod().Name +
                UserStore.GetParametersString(MethodBase.GetCurrentMethod().GetParameters()));

            if (string.IsNullOrEmpty(role.ParentId))
            {
                // グローバル ロールは削除しない。
            }
            else
            {
                try
                {
                    // テナント ロールを削除する
                    switch (ASPNETIdentityConfig.UserStoreType)
                    {
                        case EnumUserStoreType.Memory:

                            // Memory Providerには外部参照制約が無いので自らチェック
                            Tuple<string, string> userRoleMap = 
                                UserStore._userRoleMap.FirstOrDefault(x => x.Item2 == role.Id);

                            if (userRoleMap == null)
                            {
                                // RolesからIdが同じApplicationRoleを取得する。
                                ApplicationRole r = UserStore._roles.FirstOrDefault(x => x.Id == role.Id);

                                if (r == null)
                                {
                                    // ・・・
                                }
                                else
                                {
                                    // ロールを削除
                                    UserStore._roles.Remove(r);
                                }
                            }
                            else
                            {
                                // 使用されているロールは削除しない。
                            }

                            break;

                        case EnumUserStoreType.SqlServer:
                        case EnumUserStoreType.ODPManagedDriver:
                        case EnumUserStoreType.PostgreSQL: // DMBMS Provider

                            using (IDbConnection cnn = DataAccess.CreateConnection())
                            {
                                cnn.Open();

                                // ユーザー情報を更新
                                int cnt = 0;
                                switch (ASPNETIdentityConfig.UserStoreType)
                                {
                                    case EnumUserStoreType.SqlServer:

                                        // 外部参照制約に依存しないようにチェック
                                        cnt = cnn.ExecuteScalar<int>(
                                            "SELECT COUNT(*) FROM [UserRoles] WHERE [RoleId] = @RoleId", new { RoleId = role.Id });

                                        if (cnt == 0)
                                        {
                                            cnn.Execute(
                                            	"DELETE FROM [Roles] WHERE [Id] = @Id", new { Id = role.Id });
                                        }
                                        else
                                        {
                                            // 使用されているロールは削除しない。
                                        }

                                        break;

                                    case EnumUserStoreType.ODPManagedDriver:

                                        // 外部参照制約に依存しないようにチェック
                                        cnt = cnn.ExecuteScalar<int>(
                                            "SELECT COUNT(*) FROM \"UserRoles\" WHERE \"RoleId\" = :RoleId", new { RoleId = role.Id });

                                        if (cnt == 0)
                                        {
                                            cnn.Execute(
                                            	"DELETE FROM \"Roles\" WHERE \"Id\" = :Id", new { Id = role.Id });
                                        }
                                        else
                                        {
                                            // 使用されているロールは削除しない。
                                        }

                                        break;

                                    case EnumUserStoreType.PostgreSQL:

                                        // 外部参照制約に依存しないようにチェック
                                        cnt = cnn.ExecuteScalar<int>(
                                            "SELECT COUNT(*) FROM \"userroles\" WHERE \"roleid\" = @RoleId", new { RoleId = role.Id });

                                        if (cnt == 0)
                                        {
                                            cnn.Execute(
                                                "DELETE FROM \"roles\" WHERE \"id\" = @Id", new { Id = role.Id });
                                        }
                                        else
                                        {
                                            // 使用されているロールは削除しない。
                                        }

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
            }

            return Task.FromResult(default(object));
        }

        #endregion

        #endregion

        #endregion

        #region IUserLoginStore

        /// <summary>ユーザーに外部ログインを追加</summary>
        /// <param name="user">ApplicationUser</param>
        /// <param name="login">UserLoginInfo</param>
        /// <returns>－</returns>
        public Task AddLoginAsync(ApplicationUser user, UserLoginInfo login)
        {
            // 他テーブルのため、
            OnlySts.STSOnly_M();

            // Debug
            Logging.MyDebugSQLTrace("★ : " + 
                MethodBase.GetCurrentMethod().DeclaringType.FullName +
                "." + MethodBase.GetCurrentMethod().Name +
                UserStore.GetParametersString(MethodBase.GetCurrentMethod().GetParameters()));

            try
            {
                // ユーザーに外部ログインを追加
                switch (ASPNETIdentityConfig.UserStoreType)
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

                            switch (ASPNETIdentityConfig.UserStoreType)
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

            return Task.FromResult(default(object));
        }

        /// <summary>外部ログインでユーザーを検索</summary>
        /// <param name="user">ApplicationUser</param>
        /// <returns>ApplicationUser</returns>
        public Task<ApplicationUser> FindAsync(UserLoginInfo login)
        {
            // 他テーブルのため、
            OnlySts.STSOnly_M();

            // Debug
            Logging.MyDebugSQLTrace("★ : " + 
                MethodBase.GetCurrentMethod().DeclaringType.FullName +
                "." + MethodBase.GetCurrentMethod().Name +
                UserStore.GetParametersString(MethodBase.GetCurrentMethod().GetParameters()));

            ApplicationUser user = null;

            try
            {
                // 外部ログインでユーザーを検索
                switch (ASPNETIdentityConfig.UserStoreType)
                {
                    case EnumUserStoreType.Memory:

                        // LINQ挫折
                        foreach (ApplicationUser x in UserStore._users)
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

                                        return Task.FromResult(user);
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
                            switch (ASPNETIdentityConfig.UserStoreType)
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
                                this.SelectChildTablesOfUser(cnn, user);
                            }
                        }

                        break;
                }
            }
            catch (Exception ex)
            {
                Logging.MySQLLogForEx(ex);
            }

            return Task.FromResult(user);
        }

        /// <summary>ユーザの外部ログイン一覧を取得</summary>
        /// <param name="user">ApplicationUser</param>
        /// <returns>IList<UserLoginInfo></returns>>
        public Task<IList<UserLoginInfo>> GetLoginsAsync(ApplicationUser user)
        {
            // 他テーブルのため、
            //OnlySts.STSOnly_M();
            if (OnlySts.STSOnly_P)
            {
                return Task.FromResult((IList<UserLoginInfo>)new List<UserLoginInfo>());
            }

            // ストレージを直接、触らない。

            // Debug
            Logging.MyDebugSQLTrace(
                MethodBase.GetCurrentMethod().DeclaringType.FullName +
                "." + MethodBase.GetCurrentMethod().Name +
                UserStore.GetParametersString(MethodBase.GetCurrentMethod().GetParameters()));

            // ユーザの外部ログイン一覧を取得

            return Task.FromResult(user.Logins);
        }

        /// <summary>ユーザーから外部ログインを削除</summary>
        /// <param name="user">ApplicationUser</param>
        /// <param name="login">UserLoginInfo</param>
        /// <returns>－</returns>
        public Task RemoveLoginAsync(ApplicationUser user, UserLoginInfo login)
        {
            // 他テーブルのため、
            OnlySts.STSOnly_M();

            // Debug
            Logging.MyDebugSQLTrace("★ : " + 
                MethodBase.GetCurrentMethod().DeclaringType.FullName +
                "." + MethodBase.GetCurrentMethod().Name +
                UserStore.GetParametersString(MethodBase.GetCurrentMethod().GetParameters()));

            try
            {
                // ユーザーから外部ログインを削除
                switch (ASPNETIdentityConfig.UserStoreType)
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

                            switch (ASPNETIdentityConfig.UserStoreType)
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

            return Task.FromResult(default(object));
        }

        #endregion

        #region IUserClaimStore

        /// <summary>ユーザに外部ログインのクレームを追加</summary>
        /// <param name="user">ApplicationUser</param>
        /// <param name="claim">Claim</param>
        /// <returns>－</returns>
        public Task AddClaimAsync(ApplicationUser user, Claim claim)
        {
            // 他テーブルのため、
            OnlySts.STSOnly_M();

            // Debug
            Logging.MyDebugSQLTrace("★ : " + 
                MethodBase.GetCurrentMethod().DeclaringType.FullName +
                "." + MethodBase.GetCurrentMethod().Name +
                UserStore.GetParametersString(MethodBase.GetCurrentMethod().GetParameters()));

            try
            {
                // ユーザに外部ログインのクレームを追加
                switch (ASPNETIdentityConfig.UserStoreType)
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

                            switch (ASPNETIdentityConfig.UserStoreType)
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

            return Task.FromResult(default(object));
        }

        /// <summary>ユーザの（外部ログインの）クレーム一覧を取得</summary>
        /// <param name="user">ApplicationUser</param>
        /// <returns>IList<Claim></returns>
        public Task<IList<Claim>> GetClaimsAsync(ApplicationUser user)
        {
            // 他テーブルのため、
            //OnlySts.STSOnly_M();
            if (OnlySts.STSOnly_P)
            {
                return Task.FromResult((IList<Claim>)new List<Claim>());
            }

            // ストレージを直接、触らない。

            // Debug
            Logging.MyDebugSQLTrace(
                MethodBase.GetCurrentMethod().DeclaringType.FullName +
                "." + MethodBase.GetCurrentMethod().Name +
                UserStore.GetParametersString(MethodBase.GetCurrentMethod().GetParameters()));

            // ユーザの（外部ログインの）クレーム一覧を取得

            return Task.FromResult(user.Claims);
        }

        /// <summary>ユーザの（外部ログインの）クレームを削除</summary>
        /// <param name="user">ApplicationUser</param>
        /// <param name="claim">Claim</param>
        /// <returns>－</returns>
        public Task RemoveClaimAsync(ApplicationUser user, Claim claim)
        {
            // 他テーブルのため、
            OnlySts.STSOnly_M();

            // Debug
            Logging.MyDebugSQLTrace("★ : " + 
                MethodBase.GetCurrentMethod().DeclaringType.FullName +
                "." + MethodBase.GetCurrentMethod().Name +
                UserStore.GetParametersString(MethodBase.GetCurrentMethod().GetParameters()));

            try
            {
                // ユーザの（外部ログインの）クレームを削除
                switch (ASPNETIdentityConfig.UserStoreType)
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

                            switch (ASPNETIdentityConfig.UserStoreType)
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

            return Task.FromResult(default(object));
        }

        #endregion

        #endregion

        #endregion

        #region IDisposable

        /// <summary>Disposeが呼ばれたかどうかを追跡する</summary>
        /// <remarks>SharedMemory.csを参考に実装</remarks>
        private bool IsDisposed = false;

        /// <summary>Close（→ Dispose）</summary>
        /// <remarks>SharedMemory.csを参考に実装</remarks>
        public void Close()
        {
            this.Dispose();
        }

        /// <summary>IDisposable.Dispose（１）</summary>
        /// <remarks>SharedMemory.csを参考に実装</remarks>
        public void Dispose()
        {
            // trueはユーザからの直接・間接的実行を意味する。
            this.Dispose(true);

            // このクラスのデストラクタ（Finalizeメソッド）を呼び出さないようGCに命令。
            GC.SuppressFinalize(this);
        }

        /// <summary>IDisposable.Dispose（２）</summary>
        /// <param name="disposing">
        /// true：ユーザからの直接・間接的実行を意味する。
        /// false：デストラクタ（Finalizeメソッド）からの実行を意味する。
        /// </param>
        /// <remarks>SharedMemory.csを参考に実装</remarks>
        protected virtual void Dispose(bool disposing)
        {
            // Disposeが既に呼ばれたかチェック
            if (!this.IsDisposed)
            {
                // まだ呼ばれていない場合、
                // 全てのリソースをクリーンナップ

                if (disposing)
                {
                    // ユーザからの直接・間接的実行
                    this.DisposeManagedResources();
                    this.DisposeUnManagedResources();
                }
                else
                {
                    // デストラクタ（Finalizeメソッド）からの実行
                    this.DisposeUnManagedResources();
                }

                // Disposeが既に呼ばれたとフラグを立てる。
                this.IsDisposed = true;
            }
            else
            {
                // 既に呼ばれている場合、
                // なにもしない。
            }
        }

        /// <summary>マネージ リソースをクリーンナップ</summary>
        /// <remarks>SharedMemory.csを参考に実装</remarks>
        private void DisposeManagedResources()
        {
            // マネージ リソースをクリーンナップ
        }

        /// <summary>アンマネージ リソースをクリーンナップ</summary>
        /// <remarks>SharedMemory.csを参考に実装</remarks>
        private void DisposeUnManagedResources()
        {
            // アンマネージ リソースをクリーンナップ
        }
        /// <summary>デストラクタ（Finalizeメソッド）を実装</summary>
        /// <remarks>SharedMemory.csを参考に実装</remarks>
        ~UserStore() // アクセス修飾子はない（ユーザから呼べない）
        {
            // falseはデストラクタ（Finalizeメソッド）からの実行を意味する。
            this.Dispose(false);
        }
        #endregion
    }
}