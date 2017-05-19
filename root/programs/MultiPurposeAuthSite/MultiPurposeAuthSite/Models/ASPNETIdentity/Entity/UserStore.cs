//**********************************************************************************
//* Copyright (C) 2007,2016 Hitachi Solutions,Ltd.
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

using System.Diagnostics;
using System.Reflection;
using System.Threading.Tasks;
using System.Security.Claims;

using System.Web;

using Dapper;
using Microsoft.AspNet.Identity;

using MultiPurposeAuthSite.Models.Util;
using Touryo.Infrastructure.Public.Log;

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

        /// <summary>MyDebugWriteLine</summary>
        /// <param name="log">string</param>
        private static void MyDebugWriteLine(string log)
        {
            // UserStoreのトレース情報をデバッグ時にログ出力
            if (ASPNETIdentityConfig.IsDebug) Debug.WriteLine(log);
        }

        /// <summary>MyDebugWriteLine</summary>
        /// <param name="log">string</param>
        private static void MyDebugWriteLineForEx(Exception ex)
        {
            // UserStoreのデータアクセス・エラーは以下に出力。
            if (ASPNETIdentityConfig.IsDebug)
            {
            	// デバッグ時
                Debug.WriteLine(ex.ToString());
            }
            else
            {
            	// 本番時
                LogIF.DebugLog("OPERATION", ex.ToString());
            }
        }

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
        public static bool IsDBMSInitialized()
        {
            // Debug
            UserStore.MyDebugWriteLine("★ : " + MethodBase.GetCurrentMethod().Name);

            try
            {
                switch (ASPNETIdentityConfig.UserStoreType)
                {
                    case EnumUserStoreType.SqlServer:

                        using (IDbConnection cnn = DataAccess.CreateConnection())
                        {
                            cnn.Open();
                            // [Roles] が [Users] に先立って登録されるので。
                            int count = cnn.ExecuteScalar<int>("SELECT COUNT(*) FROM [Roles]");
                            return (0 < count);
                        }

                    case EnumUserStoreType.PostgreSQL:

                        break;
                }
            }
            catch (Exception ex)
            {
                UserStore.MyDebugWriteLineForEx(ex);
            }

            return false;
        }

        #endregion

        #region データ アクセス

        /// <summary>ユーザの関連情報の取得（ Roles, Logins, Claims ）</summary>
        private void SelectChildTablesOfUser(IDbConnection cnn, ApplicationUser user)
        {
            // Debug
            UserStore.MyDebugWriteLine("★ : " + MethodBase.GetCurrentMethod().Name);

            try
            {
                // Roles
                IEnumerable<ApplicationRole> roles = cnn.Query<ApplicationRole>(
                "SELECT [Roles].[Id] as Id, [Roles].[Name] as Name, [Roles].[ParentId] as ParentId " +
                "FROM   [UserRoles], [Roles] " +
                "WHERE  [UserRoles].[RoleId] = [Roles].[Id] " +
                "   AND [UserRoles].[UserId] = @userId", new { userId = user.Id });
                user.Roles = roles.ToList();

                // Logins
                IEnumerable<UserLoginInfo> userLogins = cnn.Query<UserLoginInfo>(
                    "SELECT [LoginProvider], [ProviderKey] " +
                    "FROM   [UserLogins] WHERE [UserId] = @userId", new { userId = user.Id });
                user.Logins = userLogins.ToList();

                // Claims
                IEnumerable<dynamic> claims = cnn.Query(
                    "SELECT [Issuer], [ClaimType], [ClaimValue] " +
                    "FROM   [UserClaims] WHERE [UserId] = @userId", new { userId = user.Id });
                user.Claims = new List<Claim>();
                foreach (dynamic d in claims)
                {
                    user.Claims.Add(new Claim(d.ClaimType, d.ClaimValue, null, d.Issuer));
                }
            }
            catch (Exception ex)
            {
                UserStore.MyDebugWriteLineForEx(ex);
            }
        }

        #endregion

        #endregion

        #endregion

        #endregion

        #region CRUD(共通)

        #region C

        /// <summary>新規ユーザーの追加</summary>
        /// <param name="user">ApplicationUser</param>
        /// <returns>－</returns>
        public Task CreateAsync(ApplicationUser user)
        {
            // Debug
            UserStore.MyDebugWriteLine("★ : " + MethodBase.GetCurrentMethod().Name);

            try
            {
                // 新規ユーザーの追加
                switch (ASPNETIdentityConfig.UserStoreType)
                {
                    case EnumUserStoreType.Memory:

                        UserStore._users.Add(user);

                        break;

                    case EnumUserStoreType.SqlServer:

                        using (IDbConnection cnn = DataAccess.CreateConnection())
                        {
                            cnn.Open();
                            cnn.Execute(
                                "INSERT INTO [Users] ( " +
                                "    [Id], [UserName], [PasswordHash], " +
                                "    [Email], [EmailConfirmed], [PhoneNumber], [PhoneNumberConfirmed], " +
                                "    [LockoutEnabled], [AccessFailedCount], [LockoutEndDateUtc], " +
                                "    [SecurityStamp], [TwoFactorEnabled], [ParentId], [PaymentInformation], [UnstructuredData])" +
                                "    VALUES ( " +
                                "        @Id, @UserName, @PasswordHash, " +
                                "        @Email, @EmailConfirmed, @PhoneNumber, @PhoneNumberConfirmed, " +
                                "        @LockoutEnabled, @AccessFailedCount, @LockoutEndDateUtc, " +
                                "        @SecurityStamp, @TwoFactorEnabled, @ParentId, @PaymentInformation, @UnstructuredData)", user);
                        }

                        // ユーザの関連情報は、このタイミングで追加しない（Roles, Logins, Claims）

                        break;

                    case EnumUserStoreType.PostgreSQL:

                        break;
                }
            }
            catch (Exception ex)
            {
                UserStore.MyDebugWriteLineForEx(ex);
            }

            // return
            return Task.FromResult(default(object));
        }

        #endregion

        #region R

        /// <summary>ユーザを（Id指定で）検索</summary>
        /// <param name="userId">string</param>
        /// <returns>ApplicationUser</returns>
        public Task<ApplicationUser> FindByIdAsync(string userId)
        {
            // Debug
            UserStore.MyDebugWriteLine("★ : " + MethodBase.GetCurrentMethod().Name);

            ApplicationUser user = null;

            try
            {
                // ユーザを（Id指定で）検索
                switch (ASPNETIdentityConfig.UserStoreType)
                {
                    case EnumUserStoreType.Memory:

                        user = UserStore._users.FirstOrDefault(x => x.Id == userId);

                        break;

                    case EnumUserStoreType.SqlServer:

                        using (IDbConnection cnn = DataAccess.CreateConnection())
                        {
                            cnn.Open();

                            // ユーザの情報の取得
                            IEnumerable<ApplicationUser> users = cnn.Query<ApplicationUser>(
                                "SELECT * FROM [Users] WHERE [Id] = @userId", new { userId = userId });

                            if (users.Count() != 0)
                            {
                                user = users.First();

                                // ユーザの関連情報の取得（ Roles, Logins, Claims ）
                                this.SelectChildTablesOfUser(cnn, user);
                            }
                        }

                        break;

                    case EnumUserStoreType.PostgreSQL:

                        break;
                }
            }
            catch (Exception ex)
            {
                UserStore.MyDebugWriteLineForEx(ex);
            }

            // return (ユーザ)
            return Task.FromResult(user);
        }

        /// <summary>ユーザを（ユーザ名指定で）検索</summary>
        /// <param name="userName">string</param>
        /// <returns>ApplicationUser</returns>
        public Task<ApplicationUser> FindByNameAsync(string userName)
        {
            // Debug
            UserStore.MyDebugWriteLine("★ : " + MethodBase.GetCurrentMethod().Name);

            ApplicationUser user = null;

            try
            {
                // ユーザを（ユーザ名指定で）検索
                switch (ASPNETIdentityConfig.UserStoreType)
                {
                    case EnumUserStoreType.Memory:

                        user = UserStore._users.FirstOrDefault(x => x.UserName == userName);

                        break;

                    case EnumUserStoreType.SqlServer:

                        using (IDbConnection cnn = DataAccess.CreateConnection())
                        {
                            cnn.Open();

                            // ユーザの情報の取得
                            IEnumerable<ApplicationUser> users = cnn.Query<ApplicationUser>(
                                "SELECT * FROM [Users] WHERE [UserName] = @userName", new { userName = userName });

                            if (users.Count() != 0)
                            {
                                user = users.First();

                                // ユーザの関連情報の取得（ Roles, Logins, Claims ）
                                this.SelectChildTablesOfUser(cnn, user);
                            }
                        }

                        break;

                    case EnumUserStoreType.PostgreSQL:

                        break;
                }
            }
            catch (Exception ex)
            {
                UserStore.MyDebugWriteLineForEx(ex);
            }

            // return (ユーザ)
            return Task.FromResult(user);
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
                // Debug
                UserStore.MyDebugWriteLine("★ : " + MethodBase.GetCurrentMethod().Name);

                IEnumerable<ApplicationUser> users = null;

                try
                {
                    // ASP.NET Identity上に分割キーを渡すI/Fが無いので已む無くSession。
                    string parentId = (string)HttpContext.Current.Session["CurrentUserId"];

                    // （マルチテナント化対応されたテナント）ユーザ一覧を返す。
                    switch (ASPNETIdentityConfig.UserStoreType)
                    {
                        case EnumUserStoreType.Memory:

                            users = UserStore._users.Where(p => p.ParentId == parentId).ToList();

                            break;

                        case EnumUserStoreType.SqlServer:

                            using (IDbConnection cnn = DataAccess.CreateConnection())
                            {
                                cnn.Open();
                                users = cnn.Query<ApplicationUser>(
                                    "SELECT * FROM [Users] WHERE [ParentId] = @parentId", new { parentId = parentId });
                            }

                            break;

                        case EnumUserStoreType.PostgreSQL:

                            break;
                    }
                }
                catch (Exception ex)
                {
                    UserStore.MyDebugWriteLineForEx(ex);
                }

                // IQueryableとして戻す。
                return users.AsQueryable();
            }
        }

        #endregion

        #region U

        /// <summary>ユーザー情報を更新</summary>
        /// <param name="user">ApplicationUser</param>
        /// <returns>－</returns>
        public async Task UpdateAsync(ApplicationUser user)
        {
            // Debug
            UserStore.MyDebugWriteLine("★ : " + MethodBase.GetCurrentMethod().Name);

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
                            tgtUser.PaymentInformation = user.PaymentInformation;
                            tgtUser.UnstructuredData = user.UnstructuredData;

                            break;

                        case EnumUserStoreType.SqlServer:

                            using (IDbConnection cnn = DataAccess.CreateConnection())
                            {
                                cnn.Open();

                                // ユーザー情報を更新
                                cnn.Execute(
                                    "UPDATE [Users] " +
                                    "SET [UserName] = @UserName, [PasswordHash] = @PasswordHash, " +
                                    "    [Email] = @Email, [EmailConfirmed] = @EmailConfirmed, " +
                                    "    [PhoneNumber] = @PhoneNumber, [PhoneNumberConfirmed] = @PhoneNumberConfirmed, " +
                                    "    [LockoutEnabled] = @LockoutEnabled, [AccessFailedCount] = @AccessFailedCount, [LockoutEndDateUtc] = @LockoutEndDateUtc, " +
                                    "    [SecurityStamp] = @SecurityStamp, [TwoFactorEnabled] = @TwoFactorEnabled, " +
                                    "    [ParentId] = @ParentId, [PaymentInformation] = @PaymentInformation, [UnstructuredData] = @UnstructuredData " +
                                    "WHERE [Id] = @Id", user);

                                // ★ 基本的に、以下のプロパティ更新には、プロパティ更新メソッド（UserManager.XXXX[PropertyName]Async）を使用する。
                                //    この際、ASP.NET Identity Frameworkにより、本メソッド（UserStore.UpdateAsync）が呼び出されることがあるもよう。
                                //    その際、二重実行により二重登録（制約により例外になる）が起き得るので、以下は、ココに実装しないことにした。
                                // await this.UpdateRoles(user, tgtUser);    
                                // await this.UpdateLogins(user, tgtUser);
                                // await this.UpdateClaims(user, tgtUser);
                            }

                            break;

                        case EnumUserStoreType.PostgreSQL:

                            break;
                    }
                }
            }
            catch (Exception ex)
            {
                UserStore.MyDebugWriteLineForEx(ex);
            }

            return;
        }

        #region ユーザの関連情報の更新（ Roles, Logins, Claims ）

        /// <summary>Rolesの更新</summary>
        /// <param name="user">更新</param>
        /// <param name="tgtUser">ターゲット</param>
        private async Task UpdateRoles(ApplicationUser user, ApplicationUser tgtUser)
        {
            // Debug
            UserStore.MyDebugWriteLine("★ : " + MethodBase.GetCurrentMethod().Name);

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

                        //using (IDbConnection cnn = DataAccess.CreateConnection())
                        //{
                        //    cnn.Open();

                        foreach (string roleName in toRmvRolesName)
                        {
                            //cnn.Execute(
                            //    "DELETE FROM [UserRoles] WHERE [UserId] = @UserId AND [RoleId] = @RoleId",
                            //    new { UserId = user.Id, RoleId = roleId });

                            // 効率悪いが品質的に、this.RemoveFromRoleAsyncを使用する。
                            await this.RemoveFromRoleAsync(user, roleName);
                        }

                        foreach (string roleName in toAddRolesName)
                        {
                            //cnn.Execute(
                            //    "INSERT INTO [UserRoles] ( [UserId], [RoleId] ) VALUES ( @UserId, @RoleId )",
                            //    new { UserId = user.Id, RoleId = roleId });

                            // 効率悪いが品質的に、this.AddToRoleAsyncを使用する。
                            await this.AddToRoleAsync(user, roleName);
                        }

                        //}

                        break;

                    case EnumUserStoreType.PostgreSQL:

                        break;
                }
            }
            catch (Exception ex)
            {
                UserStore.MyDebugWriteLineForEx(ex);
            }
        }

        //Logins, ClaimsはDel-Insで対応するため、UpdateLogins, UpdateClaimsのメソッドは不要

        #endregion

        #endregion

        #region D

        /// <summary>ユーザの論理削除</summary>
        /// <param name="user">ApplicationUser</param>
        /// <returns>－</returns>
        /// <remarks>
        /// 削除するエンティティにマークを付けます
        /// </remarks>
        public Task DeleteAsync(ApplicationUser user)
        {
            // Debug
            UserStore.MyDebugWriteLine("★ : " + MethodBase.GetCurrentMethod().Name);

            if (user.Id == user.ParentId)
            {
                // 管理者ユーザは削除しない。
            }
            else
            {
                try
                {
                    // ユーザの論理削除
                    switch (ASPNETIdentityConfig.UserStoreType)
                    {
                        case EnumUserStoreType.Memory:

                            // ユーザを削除
                            UserStore._users.Remove(UserStore._users.First(x => x.Id == user.Id));

                            break;

                        case EnumUserStoreType.SqlServer:

                            using (IDbConnection cnn = DataAccess.CreateConnection())
                            {
                                cnn.Open();
                                using (IDbTransaction tr = cnn.BeginTransaction())
                                {
                                    // ユーザの情報を削除
                                    cnn.Execute("DELETE FROM [Users] WHERE [Id] = @UserId", new { UserId = user.Id }, tr);

                                    // ユーザの関連情報を削除
                                    cnn.Execute("DELETE FROM [UserRoles]  WHERE [UserId] = @UserId", new { UserId = user.Id }, tr);
                                    cnn.Execute("DELETE FROM [UserLogins] WHERE [UserId] = @UserId", new { UserId = user.Id }, tr);
                                    cnn.Execute("DELETE FROM [UserClaims] WHERE [UserId] = @UserId", new { UserId = user.Id }, tr);

                                    tr.Commit();
                                }
                            }

                            break;

                        case EnumUserStoreType.PostgreSQL:

                            break;
                    }
                }
                catch (Exception ex)
                {
                    UserStore.MyDebugWriteLineForEx(ex);
                }
            }

            // return
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
            // UserStoreを直接、触らない。

            // Debug
            UserStore.MyDebugWriteLine(MethodBase.GetCurrentMethod().Name);

            // ユーザがパスワードを持っているか

            // return (パスワードの有無)
            return Task.FromResult(!string.IsNullOrEmpty(user.PasswordHash));
        }

        /// <summary>ユーザーにハッシュ化されたパスワードを設定</summary>
        /// <param name="user">ApplicationUser</param>
        /// <param name="passwordHash">string</param>
        /// <returns>－</returns>
        public Task SetPasswordHashAsync(ApplicationUser user, string passwordHash)
        {
            // UserStoreを直接、触らない。

            // Debug
            UserStore.MyDebugWriteLine(MethodBase.GetCurrentMethod().Name);

            // ユーザーにハッシュ化されたパスワードを設定
            user.PasswordHash = passwordHash;

            // return
            return Task.FromResult(default(object));
        }

        /// <summary>ユーザのパスワードのハッシュを取得</summary>
        /// <param name="user">ApplicationUser</param>
        /// <returns>パスワードのハッシュ</returns>
        public Task<string> GetPasswordHashAsync(ApplicationUser user)
        {
            // UserStoreを直接、触らない。

            // Debug
            UserStore.MyDebugWriteLine(MethodBase.GetCurrentMethod().Name);

            // ユーザのパスワードのハッシュを取得

            // return (パスワードのハッシュ)
            return Task.FromResult(user.PasswordHash);
        }

        #endregion

        #region IUserEmailStore

        /// <summary>ユーザを（email指定で）検索して取得</summary>
        /// <param name="email">string</param>
        /// <returns>ApplicationUser</returns>
        public Task<ApplicationUser> FindByEmailAsync(string email)
        {
            // Debug
            UserStore.MyDebugWriteLine("★ : " + MethodBase.GetCurrentMethod().Name);

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

                        using (IDbConnection cnn = DataAccess.CreateConnection())
                        {
                            cnn.Open();

                            // ユーザの情報の取得
                            IEnumerable<ApplicationUser> users = cnn.Query<ApplicationUser>(
                                "SELECT * From [Users] WHERE [Email] = @Email", new { Email = email });

                            if (users.Count() != 0)
                            {
                                user = users.First();

                                // ユーザの関連情報の取得（ Roles, Logins, Claims ）
                                this.SelectChildTablesOfUser(cnn, user);
                            }
                        }

                        break;

                    case EnumUserStoreType.PostgreSQL:

                        break;
                }
            }
            catch (Exception ex)
            {
                UserStore.MyDebugWriteLineForEx(ex);
            }

            // return (user)
            return Task.FromResult(user);
        }

        /// <summary>メアドの設定</summary>
        /// <param name="user">ApplicationUser</param>
        /// <param name="email">string</param>
        /// <returns>－</returns>
        public Task SetEmailAsync(ApplicationUser user, string email)
        {
            // UserStoreを直接、触らない。

            // Debug
            UserStore.MyDebugWriteLine(MethodBase.GetCurrentMethod().Name);

            // メアドの設定
            user.Email = email;

            // return
            return Task.FromResult(default(object));
        }

        /// <summary>メアドの取得</summary>
        /// <param name="user">ApplicationUser</param>
        /// <returns>Email</returns>
        public Task<string> GetEmailAsync(ApplicationUser user)
        {
            // UserStoreを直接、触らない。

            // Debug
            UserStore.MyDebugWriteLine(MethodBase.GetCurrentMethod().Name);

            // メアドの取得

            // return (Email)
            return Task.FromResult(user.Email);
        }

        /// <summary>メアド確認の設定</summary>
        /// <param name="user">ApplicationUser</param>
        /// <param name="confirmed">bool</param>
        /// <returns>－</returns>
        public Task SetEmailConfirmedAsync(ApplicationUser user, bool confirmed)
        {
            // UserStoreを直接、触らない。

            // Debug
            UserStore.MyDebugWriteLine(MethodBase.GetCurrentMethod().Name);

            // メアド確認の設定
            user.EmailConfirmed = confirmed;

            // return
            return Task.FromResult(default(object));
        }

        /// <summary>メアド確認の取得</summary>
        /// <param name="user">ApplicationUser</param>
        /// <returns>EmailConfirmed</returns>
        public Task<bool> GetEmailConfirmedAsync(ApplicationUser user)
        {
            // UserStoreを直接、触らない。

            // Debug
            UserStore.MyDebugWriteLine(MethodBase.GetCurrentMethod().Name);

            // メアド確認の取得

            // return (EmailConfirmed)
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
            // UserStoreを直接、触らない。

            // Debug
            UserStore.MyDebugWriteLine(MethodBase.GetCurrentMethod().Name);

            // 電話番号の設定
            user.PhoneNumber = phoneNumber;

            // return
            return Task.FromResult(default(object));
        }

        /// <summary>電話番号の取得</summary>
        /// <param name="user">ApplicationUser</param>
        /// <returns>phone number</returns>
        public Task<string> GetPhoneNumberAsync(ApplicationUser user)
        {
            // UserStoreを直接、触らない。

            // Debug
            UserStore.MyDebugWriteLine(MethodBase.GetCurrentMethod().Name);

            // 電話番号の取得

            // return (PhoneNumber)
            return Task.FromResult(user.PhoneNumber);
        }

        /// <summary>電話番号確認の設定</summary>
        /// <param name="user">ApplicationUser</param>
        /// <param name="confirmed">bool</param>
        /// <returns>－</returns>
        public Task SetPhoneNumberConfirmedAsync(ApplicationUser user, bool confirmed)
        {
            // UserStoreを直接、触らない。

            // Debug
            UserStore.MyDebugWriteLine(MethodBase.GetCurrentMethod().Name);

            // 電話番号確認の設定
            user.PhoneNumberConfirmed = confirmed;

            // return
            return Task.FromResult(default(object));
        }

        /// <summary>電話番号確認の取得</summary>
        /// <param name="user">ApplicationUser</param>
        /// <returns>phone number is confirmed</returns>
        public Task<bool> GetPhoneNumberConfirmedAsync(ApplicationUser user)
        {
            // UserStoreを直接、触らない。

            // Debug
            UserStore.MyDebugWriteLine(MethodBase.GetCurrentMethod().Name);

            // 電話番号確認の取得

            // return (PhoneNumberConfirmed)
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
            // Debug
            UserStore.MyDebugWriteLine("★ : " + MethodBase.GetCurrentMethod().Name);

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

                        using (IDbConnection cnn = DataAccess.CreateConnection())
                        {
                            cnn.Open();

                            // ロール・マップを追加（ロール情報を取得する。
                            cnn.Execute(
                                "INSERT INTO [UserRoles] ([UserRoles].[UserId], [UserRoles].[RoleId]) " +
                                "VALUES (@UserId, (SELECT [Roles].[Id] FROM [Roles] WHERE [Roles].[Name] = @roleName))",
                                new { UserId = user.Id, roleName = roleName });
                        }

                        break;

                    case EnumUserStoreType.PostgreSQL:

                        break;
                }
            }
            catch (Exception ex)
            {
                UserStore.MyDebugWriteLineForEx(ex);
            }

            return Task.FromResult(default(object));
        }

        /// <summary>ユーザがロールに所属するか？</summary>
        /// <param name="user">ApplicationUser</param>
        /// <param name="roleName">ロール名</param>
        /// <returns>真・偽：ユーザがロールに所属するか</returns>
        public async Task<bool> IsInRoleAsync(ApplicationUser user, string roleName)
        {
            // UserStoreを直接、触らない。

            // Debug
            UserStore.MyDebugWriteLine(MethodBase.GetCurrentMethod().Name);

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
            // Debug
            UserStore.MyDebugWriteLine("★ : " + MethodBase.GetCurrentMethod().Name);

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

                        using (IDbConnection cnn = DataAccess.CreateConnection())
                        {
                            cnn.Open();

                            IEnumerable<ApplicationRole> roles = cnn.Query<ApplicationRole>(
                                "SELECT [Roles].[Id] as Id, [Roles].[Name] as Name, [Roles].[ParentId] as ParentId " +
                                "FROM   [Roles], [UserRoles], [Users] " +
                                "WHERE  [Roles].[Id] = [UserRoles].[RoleId] " +
                                "   AND [UserRoles].[UserId] = [Users].[Id] " +
                                "   AND [Users].[Id] = @UserId",
                                new { UserId = user.Id });
                            List<string> temp = new List<string>();
                            foreach (ApplicationRole role in roles)
                            {
                                temp.Add(role.Name);
                            }
                            roleNames = temp.ToArray();
                        }

                        break;

                    case EnumUserStoreType.PostgreSQL:

                        break;
                }
            }
            catch (Exception ex)
            {
                UserStore.MyDebugWriteLineForEx(ex);
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
            // Debug
            UserStore.MyDebugWriteLine("★ : " + MethodBase.GetCurrentMethod().Name);

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

                            using (IDbConnection cnn = DataAccess.CreateConnection())
                            {
                                cnn.Open();

                                // ロール・マップを削除（ロール情報を取得する。
                                cnn.Execute(
                                "DELETE FROM [UserRoles] " +
                                "WHERE [UserRoles].[UserId] = @UserId " +
                                "      AND [UserRoles].[RoleId] = (SELECT [Roles].[Id] FROM [Roles] WHERE [Roles].[Name] = @roleName)",
                                new { UserId = user.Id, roleName = roleName });
                            }

                            break;

                        case EnumUserStoreType.PostgreSQL:

                            break;
                    }
                }
                catch (Exception ex)
                {
                    UserStore.MyDebugWriteLineForEx(ex);
                }
            }

            // return
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
            // UserStoreを直接、触らない。

            // Debug
            UserStore.MyDebugWriteLine(MethodBase.GetCurrentMethod().Name);

            // セキュリティスタンプを設定
            user.SecurityStamp = stamp;

            // return
            return Task.FromResult(default(object));
        }

        /// <summary>セキュリティスタンプを取得</summary>
        /// <param name="user">ApplicationUser</param>
        /// <returns>SecurityStamp</returns>
        public Task<string> GetSecurityStampAsync(ApplicationUser user)
        {
            // UserStoreを直接、触らない。

            // Debug
            UserStore.MyDebugWriteLine(MethodBase.GetCurrentMethod().Name);

            // セキュリティスタンプを取得

            // return (SecurityStamp)
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
            // UserStoreを直接、触らない。

            // Debug
            UserStore.MyDebugWriteLine(MethodBase.GetCurrentMethod().Name);

            // ユーザがロックアウト可能かどうかを設定
            user.LockoutEnabled = enabled;

            // return
            return Task.FromResult(default(object));
        }

        /// <summary>ユーザがロックアウト可能かどうかを取得</summary>
        /// <param name="user">ApplicationUser</param>
        /// <returns>真・偽：ユーザがロックアウト可能かどうか</returns>
        public Task<bool> GetLockoutEnabledAsync(ApplicationUser user)
        {
            // UserStoreを直接、触らない。

            // Debug
            UserStore.MyDebugWriteLine(MethodBase.GetCurrentMethod().Name);

            // ユーザがロックアウト可能かどうかを取得

            // ユーザがロックアウト可能かどうかを返す。
            return Task.FromResult(user.LockoutEnabled);
        }

        /// <summary>サインインに失敗した試行回数を記録</summary>
        /// <param name="user">ApplicationUser</param>
        /// <returns>サインインに失敗した試行回数</returns>
        public Task<int> IncrementAccessFailedCountAsync(ApplicationUser user)
        {
            // UserStoreを直接、触らない。

            // Debug
            UserStore.MyDebugWriteLine(MethodBase.GetCurrentMethod().Name);

            // サインインに失敗した試行回数を記録
            user.AccessFailedCount++;

            // return (サインインに失敗した試行回数)
            return Task.FromResult(user.AccessFailedCount);
        }

        /// <summary>失敗したサインインの試行回数を取得</summary>
        /// <param name="user">ApplicationUser</param>
        /// <returns>現在の失敗したサインインの試行回数</returns>
        /// <remarks>パスワードが確認されるか、アカウントがロックアウトされるたびに、この数は、リセットされる。</remarks>
        public Task<int> GetAccessFailedCountAsync(ApplicationUser user)
        {
            // UserStoreを直接、触らない。

            // Debug
            UserStore.MyDebugWriteLine(MethodBase.GetCurrentMethod().Name);

            // 失敗したサインインの試行回数を取得

            // 失敗したサインインの試行回数を返す。
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
            // UserStoreを直接、触らない。

            // Debug
            UserStore.MyDebugWriteLine(MethodBase.GetCurrentMethod().Name);

            // 失敗したサインインの試行回数をリセット
            user.AccessFailedCount = 0;

            // return
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
            // UserStoreを直接、触らない。

            // Debug
            UserStore.MyDebugWriteLine(MethodBase.GetCurrentMethod().Name);

            // ロックアウト終了日を設定（指定された終了日まで、ユーザをロックアウト）

            // DateTime と DateTimeOffset 間の変換
            // https://msdn.microsoft.com/ja-jp/library/bb546101.aspx
            user.LockoutEndDateUtc = lockoutEnd.DateTime;

            // return
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
            // UserStoreを直接、触らない。

            // Debug
            UserStore.MyDebugWriteLine(MethodBase.GetCurrentMethod().Name);

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
            // UserStoreを直接、触らない。

            // Debug
            UserStore.MyDebugWriteLine(MethodBase.GetCurrentMethod().Name);

            // 2FAの有効・無効を設定
            user.TwoFactorEnabled = enabled;

            // return
            return Task.FromResult(default(object));
        }

        /// <summary>2FAの有効・無効を取得</summary>
        /// <param name="user">ApplicationUser</param>
        /// <returns>真・偽：2FAが有効かどうか</returns>
        public Task<bool> GetTwoFactorEnabledAsync(ApplicationUser user)
        {
            // UserStoreを直接、触らない。

            // Debug
            UserStore.MyDebugWriteLine(MethodBase.GetCurrentMethod().Name);

            // 2FAの有効・無効を取得

            // return (2FAが有効かどうか)
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
            // Debug
            UserStore.MyDebugWriteLine("★ : " + MethodBase.GetCurrentMethod().Name);

            try
            {
                switch (ASPNETIdentityConfig.UserStoreType)
                {
                    case EnumUserStoreType.Memory:

                        // ロールを追加
                        UserStore._roles.Add(role);

                        break;

                    case EnumUserStoreType.SqlServer:

                        using (IDbConnection cnn = DataAccess.CreateConnection())
                        {
                            cnn.Open();
                            cnn.Execute(
                                "INSERT INTO [Roles] ( [Id], [Name], [ParentId] ) VALUES ( @Id, @Name, @ParentId )", role);
                        }

                        break;

                    case EnumUserStoreType.PostgreSQL:

                        break;
                }
            }
            catch (Exception ex)
            {
                UserStore.MyDebugWriteLineForEx(ex);
            }

            // return
            return Task.FromResult(default(object));
        }

        #endregion

        #region R

        /// <summary>ロールを ID から検索</summary>
        /// <param name="roleId">string</param>
        /// <returns>ApplicationRole</returns>
        Task<ApplicationRole> IRoleStore<ApplicationRole, string>.FindByIdAsync(string roleId)
        {
            // Debug
            UserStore.MyDebugWriteLine("★ : " + MethodBase.GetCurrentMethod().Name);

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

                        using (IDbConnection cnn = DataAccess.CreateConnection())
                        {
                            cnn.Open();

                            // ユーザの情報の取得
                            IEnumerable<ApplicationRole> roles = cnn.Query<ApplicationRole>(
                                "SELECT * FROM [Roles] WHERE [Id] = @roleId", new { roleId = roleId });

                            if (roles.Count() != 0)
                            {
                                role = roles.First();
                            }
                        }

                        break;

                    case EnumUserStoreType.PostgreSQL:

                        break;
                }
            }
            catch (Exception ex)
            {
                UserStore.MyDebugWriteLineForEx(ex);
            }

            // return (ApplicationRole)
            return Task.FromResult(role);
        }

        /// <summary>ロールを（ロール名指定で）検索</summary>
        /// <param name="roleName">string</param>
        /// <returns>ApplicationRole</returns>
        Task<ApplicationRole> IRoleStore<ApplicationRole, string>.FindByNameAsync(string roleName)
        {
            // Debug
            UserStore.MyDebugWriteLine("★ : " + MethodBase.GetCurrentMethod().Name);

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

                        using (IDbConnection cnn = DataAccess.CreateConnection())
                        {
                            cnn.Open();

                            // ユーザの情報の取得
                            IEnumerable<ApplicationRole> roles = cnn.Query<ApplicationRole>(
                                "SELECT * FROM [Roles] WHERE [Name] = @roleName", new { roleName = roleName });

                            if (roles.Count() != 0)
                            {
                                role = roles.First();
                            }
                        }

                        break;

                    case EnumUserStoreType.PostgreSQL:

                        break;
                }
            }
            catch (Exception ex)
            {
                UserStore.MyDebugWriteLineForEx(ex);
            }

            // return (ApplicationRole)
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
                // Debug
                UserStore.MyDebugWriteLine("★ : " + MethodBase.GetCurrentMethod().Name);

                // システム共通のロール
                IEnumerable<ApplicationRole> commonRoles = null;
                // マルチテナント化対応されたテナントロール
                IEnumerable<ApplicationRole> tenantRoles = null;

                try
                {
                    // ASP.NET Identity上に分割キーを渡すI/Fが無いので已む無くSession。
                    string parentId = (string)HttpContext.Current.Session["CurrentUserId"];

                    // ロール一覧を返す。
                    switch (ASPNETIdentityConfig.UserStoreType)
                    {
                        case EnumUserStoreType.Memory:

                            // システム共通のロール
                            commonRoles = UserStore._roles.Where(p => p.ParentId == "").ToList();
                            // マルチテナント化対応されたテナントロール
                            tenantRoles = UserStore._roles.Where(p => p.ParentId == parentId).ToList();

                            // 統合して返却
                            commonRoles = commonRoles.Union(tenantRoles);

                            break;

                        case EnumUserStoreType.SqlServer:

                            using (IDbConnection cnn = DataAccess.CreateConnection())
                            {
                                cnn.Open();

                                // システム共通のロール
                                commonRoles = cnn.Query<ApplicationRole>(
                                    "SELECT * FROM [Roles] WHERE [ParentId] = @parentId", new { parentId = "" });
                                // マルチテナント化対応されたテナントロール
                                tenantRoles = cnn.Query<ApplicationRole>(
                                    "SELECT * FROM [Roles] WHERE [ParentId] = @parentId", new { parentId = parentId });
                            }

                            // 統合して返却
                            commonRoles = commonRoles.Union(tenantRoles);

                            break;

                        case EnumUserStoreType.PostgreSQL:

                            break;
                    }
                }
                catch (Exception ex)
                {
                    UserStore.MyDebugWriteLineForEx(ex);
                }

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
            // Debug
            UserStore.MyDebugWriteLine("★ : " + MethodBase.GetCurrentMethod().Name);

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

                            using (IDbConnection cnn = DataAccess.CreateConnection())
                            {
                                cnn.Open();

                                // ユーザー情報を更新
                                cnn.Execute(
                                    "UPDATE [Roles] SET [Name] = @Name WHERE [Id] = @Id",
                                    new { Id = role.Id, Name = role.Name });
                            }

                            break;

                        case EnumUserStoreType.PostgreSQL:

                            break;
                    }
                }
                catch (Exception ex)
                {
                    UserStore.MyDebugWriteLineForEx(ex);
                }
            }

            // return
            return Task.FromResult(default(object));
        }

        #endregion

        #region D

        /// <summary>ロールを削除する</summary>
        /// <param name="role">ApplicationRole</param>
        /// <returns>－</returns>
        public Task DeleteAsync(ApplicationRole role)
        {
            // Debug
            UserStore.MyDebugWriteLine("★ : " + MethodBase.GetCurrentMethod().Name);

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

                            break;

                        case EnumUserStoreType.SqlServer:

                            using (IDbConnection cnn = DataAccess.CreateConnection())
                            {
                                cnn.Open();

                                // ユーザー情報を更新
                                cnn.Execute("DELETE FROM [Roles] WHERE [Id] = @Id", new { Id = role.Id });
                            }

                            break;

                        case EnumUserStoreType.PostgreSQL:

                            break;
                    }
                }
                catch (Exception ex)
                {
                    UserStore.MyDebugWriteLineForEx(ex);
                }
            }

            // return
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
            // Debug
            UserStore.MyDebugWriteLine("★ : " + MethodBase.GetCurrentMethod().Name);

            try
            {
                // ユーザーに外部ログインを追加
                switch (ASPNETIdentityConfig.UserStoreType)
                {
                    case EnumUserStoreType.Memory:

                        user.Logins.Add(login);

                        break;

                    case EnumUserStoreType.SqlServer:

                        using (IDbConnection cnn = DataAccess.CreateConnection())
                        {
                            cnn.Open();
                            cnn.Execute(
                                "INSERT INTO [UserLogins] ([UserId], [LoginProvider], [ProviderKey]) " +
                                "VALUES (@UserId, @LoginProvider, @ProviderKey)",
                                new { UserId = user.Id, LoginProvider = login.LoginProvider, ProviderKey = login.ProviderKey });
                        }

                        break;

                    case EnumUserStoreType.PostgreSQL:

                        break;
                }
            }
            catch (Exception ex)
            {
                UserStore.MyDebugWriteLineForEx(ex);
            }

            // return
            return Task.FromResult(default(object));
        }

        /// <summary>外部ログインでユーザーを検索</summary>
        /// <param name="user">ApplicationUser</param>
        /// <returns>ApplicationUser</returns>
        public Task<ApplicationUser> FindAsync(UserLoginInfo login)
        {
            // Debug
            UserStore.MyDebugWriteLine("★ : " + MethodBase.GetCurrentMethod().Name);

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

                                        // return (ApplicationRole)
                                        return Task.FromResult(user);
                                    }
                                }
                            }
                        }

                        break;

                    case EnumUserStoreType.SqlServer:

                        using (IDbConnection cnn = DataAccess.CreateConnection())
                        {
                            cnn.Open();

                            // ユーザの情報の取得
                            IEnumerable<ApplicationUser> users = cnn.Query<ApplicationUser>(
                                "SELECT * From [Users], [UserLogins] " + // * でイケるか？
                                "WHERE  [Users].[Id] = [UserLogins].[UserId]" +
                                "    AND [UserLogins].[LoginProvider] = @LoginProvider" +
                                "    AND [UserLogins].[ProviderKey] = @ProviderKey",
                                new { LoginProvider = login.LoginProvider, ProviderKey = login.ProviderKey });

                            if (users.Count() != 0)
                            {
                                user = users.First();

                                // ユーザの関連情報の取得（ Roles, Logins, Claims ）
                                this.SelectChildTablesOfUser(cnn, user);
                            }
                        }

                        break;

                    case EnumUserStoreType.PostgreSQL:

                        break;
                }
            }
            catch (Exception ex)
            {
                UserStore.MyDebugWriteLineForEx(ex);
            }

            return Task.FromResult(user);
        }

        /// <summary>ユーザの外部ログイン一覧を取得</summary>
        /// <param name="user">ApplicationUser</param>
        /// <returns>IList<UserLoginInfo></returns>>
        public Task<IList<UserLoginInfo>> GetLoginsAsync(ApplicationUser user)
        {
            // UserStoreを直接、触らない。

            // Debug
            UserStore.MyDebugWriteLine(MethodBase.GetCurrentMethod().Name);

            // ユーザの外部ログイン一覧を取得

            // return (Logins)
            return Task.FromResult(user.Logins);
        }

        /// <summary>ユーザーから外部ログインを削除</summary>
        /// <param name="user">ApplicationUser</param>
        /// <param name="login">UserLoginInfo</param>
        /// <returns>－</returns>
        public Task RemoveLoginAsync(ApplicationUser user, UserLoginInfo login)
        {
            // Debug
            UserStore.MyDebugWriteLine("★ : " + MethodBase.GetCurrentMethod().Name);

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

                        using (IDbConnection cnn = DataAccess.CreateConnection())
                        {
                            cnn.Open();
                            cnn.Execute(
                                "DELETE FROM [UserLogins] WHERE [UserId] = @UserId AND [LoginProvider] = @LoginProvider AND [ProviderKey] = @ProviderKey ",
                                new { UserId = user.Id, LoginProvider = login.LoginProvider, ProviderKey = login.ProviderKey });
                        }

                        break;

                    case EnumUserStoreType.PostgreSQL:

                        break;
                }
            }
            catch (Exception ex)
            {
                UserStore.MyDebugWriteLineForEx(ex);
            }

            // return
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
            // Debug
            UserStore.MyDebugWriteLine("★ : " + MethodBase.GetCurrentMethod().Name);

            try
            {
                // ユーザに外部ログインのクレームを追加
                switch (ASPNETIdentityConfig.UserStoreType)
                {
                    case EnumUserStoreType.Memory:

                        user.Claims.Add(claim);

                        break;

                    case EnumUserStoreType.SqlServer:

                        using (IDbConnection cnn = DataAccess.CreateConnection())
                        {
                            cnn.Open();
                            cnn.Execute(
                                "INSERT INTO [UserClaims] ([UserId], [Issuer], [ClaimType], [ClaimValue]) " +
                                "VALUES (@UserId, @Issuer, @ClaimType, @ClaimValue)",
                                new { UserId = user.Id, Issuer = claim.Issuer, ClaimType = claim.Type, ClaimValue = claim.Value });
                        }

                        break;

                    case EnumUserStoreType.PostgreSQL:

                        break;
                }
            }
            catch (Exception ex)
            {
                UserStore.MyDebugWriteLineForEx(ex);
            }

            // return
            return Task.FromResult(default(object));
        }

        /// <summary>ユーザの（外部ログインの）クレーム一覧を取得</summary>
        /// <param name="user">ApplicationUser</param>
        /// <returns>IList<Claim></returns>
        public Task<IList<Claim>> GetClaimsAsync(ApplicationUser user)
        {
            // UserStoreを直接、触らない。

            // Debug
            UserStore.MyDebugWriteLine(MethodBase.GetCurrentMethod().Name);

            // ユーザの（外部ログインの）クレーム一覧を取得

            // return (クレーム一覧)
            return Task.FromResult(user.Claims);
        }

        /// <summary>ユーザの（外部ログインの）クレームを削除</summary>
        /// <param name="user">ApplicationUser</param>
        /// <param name="claim">Claim</param>
        /// <returns>－</returns>
        public Task RemoveClaimAsync(ApplicationUser user, Claim claim)
        {
            // Debug
            UserStore.MyDebugWriteLine("★ : " + MethodBase.GetCurrentMethod().Name);

            try
            {
                // ユーザの（外部ログインの）クレームを削除
                switch (ASPNETIdentityConfig.UserStoreType)
                {
                    case EnumUserStoreType.Memory:

                        user.Claims.Remove(claim);

                        break;

                    case EnumUserStoreType.SqlServer:

                        using (IDbConnection cnn = DataAccess.CreateConnection())
                        {
                            cnn.Open();
                            cnn.Execute(
                                "DELETE FROM [UserClaims] WHERE [UserId] = @UserId AND [Issuer] = @Issuer AND [ClaimType] = @ClaimType",
                                new { UserId = user.Id, Issuer = claim.Issuer, ClaimType = claim.Type });
                        }

                        break;

                    case EnumUserStoreType.PostgreSQL:

                        break;
                }
            }
            catch (Exception ex)
            {
                UserStore.MyDebugWriteLineForEx(ex);
            }

            // return
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
            // Debug
            //UserStore.MyDebugWriteLine(MethodBase.GetCurrentMethod().Name);

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