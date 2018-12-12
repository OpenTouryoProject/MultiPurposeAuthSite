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
//* クラス名        ：CmnRoleStore
//* クラス日本語名  ：CmnRoleStore（ライブラリ）
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
    /// <summary>BaseRoleStore</summary>
    public class CmnRoleStore : CmnStore
    {
        #region IRoleStore

        #region CRUD(共通)

        #region C (Create)

        /// <summary>ロールを追加</summary>
        /// <param name="role">ApplicationRole</param>
        public static void Create(ApplicationRole role)
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
                switch (Config.UserStoreType)
                {
                    case EnumUserStoreType.Memory:

                        // ロールを追加
                        CmnStore._roles.Add(role);

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
                                        "INSERT INTO [Roles] ( [Id], [Name], [NormalizedName] ) VALUES ( @Id, @Name, @NormalizedName )", role);

                                    break;

                                case EnumUserStoreType.ODPManagedDriver:

                                    cnn.Execute(
                                        "INSERT INTO \"Roles\" ( \"Id\", \"Name\", \"NormalizedName\" ) VALUES ( :Id, :Name, :NormalizedName )", role);

                                    break;

                                case EnumUserStoreType.PostgreSQL:

                                    cnn.Execute(
                                        "INSERT INTO \"roles\" ( \"id\", \"name\", \"normalizedname\" ) VALUES ( @Id, @Name, @NormalizedName )", role);

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

        #region R (Read)

        /// <summary>ロールを ID から検索</summary>
        /// <param name="roleId">string</param>
        /// <returns>ApplicationRole</returns>
        public static ApplicationRole FindById(string roleId)
        {
            // 他テーブルのため、
            OnlySts.STSOnly_M();

            // Debug
            Logging.MyDebugSQLTrace("★ : " + 
                MethodBase.GetCurrentMethod().DeclaringType.FullName +
                "." + MethodBase.GetCurrentMethod().Name +
                Logging.GetParametersString(MethodBase.GetCurrentMethod().GetParameters()));

            ApplicationRole role = null;

            try
            {
                switch (Config.UserStoreType)
                {
                    case EnumUserStoreType.Memory:

                        // ロールを ID から検索
                        role = CmnStore._roles.FirstOrDefault(x => x.Id == roleId);

                        break;

                    case EnumUserStoreType.SqlServer:
                    case EnumUserStoreType.ODPManagedDriver:
                    case EnumUserStoreType.PostgreSQL: // DMBMS Provider

                        using (IDbConnection cnn = DataAccess.CreateConnection())
                        {
                            cnn.Open();

                            // ユーザの情報の取得
                            IEnumerable<ApplicationRole> roles = null;
                            switch (Config.UserStoreType)
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

            return role;
        }

        /// <summary>ロールを（ロール名指定で）検索</summary>
        /// <param name="roleName">string</param>
        /// <returns>ApplicationRole</returns>
        /// <remarks>
        /// （マルチテナント化のため）一意ではないので、
        /// ・グローバル ロールを優先して返す。
        /// ・無ければ自テナントを検索して返す。
        /// </remarks>
        public static ApplicationRole FindByName(string roleName)
        {
            // 他テーブルのため、
            OnlySts.STSOnly_M();

            // Debug
            Logging.MyDebugSQLTrace("★ : " + 
                MethodBase.GetCurrentMethod().DeclaringType.FullName +
                "." + MethodBase.GetCurrentMethod().Name +
                Logging.GetParametersString(MethodBase.GetCurrentMethod().GetParameters()));

            ApplicationRole role = null;
            IEnumerable<ApplicationRole> roles = null;
            
            try
            {
                switch (Config.UserStoreType)
                {
                    case EnumUserStoreType.Memory:

#if NETFX
                        role = CmnStore._roles.FirstOrDefault(x => x.Name == roleName);
#else
                        role = CmnStore._roles.FirstOrDefault(x => x.NormalizedName == roleName);
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
                                    roles = cnn.Query<ApplicationRole>(
                                        "SELECT * FROM [Roles] WHERE [Name] = @roleName", new { roleName = roleName });
#else
                                    roles = cnn.Query<ApplicationRole>(
                                        "SELECT * FROM [Roles] WHERE [NormalizedName] = @roleName", new { roleName = roleName });
#endif
                                    break;

                                case EnumUserStoreType.ODPManagedDriver:
#if NETFX
                                    roles = cnn.Query<ApplicationRole>(
                                        "SELECT * FROM \"Roles\" WHERE \"Name\" = :roleName", new { roleName = roleName });
#else
                                    roles = cnn.Query<ApplicationRole>(
                                        "SELECT * FROM \"Roles\" WHERE \"NormalizedName\" = :roleName", new { roleName = roleName });
#endif
                                    break;

                                case EnumUserStoreType.PostgreSQL:
#if NETFX
                                    roles = cnn.Query<ApplicationRole>(
                                        "SELECT * FROM \"roles\" WHERE \"name\" = @roleName", new { roleName = roleName });
#else
                                    roles = cnn.Query<ApplicationRole>(
                                        "SELECT * FROM \"roles\" WHERE \"normalizedname\" = @roleName", new { roleName = roleName });
#endif
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

            return role;
        }

        /// <summary>
        /// ロール一覧を返す。
        /// </summary>
        /// <remarks>
        /// ★ マルチテナント化対応を施した
        /// （場合によってはページングも必要になる）
        /// </remarks>
        public static IQueryable<ApplicationRole> Roles
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
                    Logging.GetParametersString(MethodBase.GetCurrentMethod().GetParameters()));

                // ロール
                IEnumerable<ApplicationRole> roles = null;

                try
                {
                    // ロール一覧を返す。
                    switch (Config.UserStoreType)
                    {
                        case EnumUserStoreType.Memory:

                            roles = CmnStore._roles.ToList();

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

                                        roles = cnn.Query<ApplicationRole>("SELECT * FROM [Roles]");
                                        break;

                                    case EnumUserStoreType.ODPManagedDriver:

                                        roles = cnn.Query<ApplicationRole>("SELECT * FROM \"Roles\"");
                                        break;

                                    case EnumUserStoreType.PostgreSQL:

                                        roles = cnn.Query<ApplicationRole>("SELECT * FROM \"roles\"");
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

                // IQueryableとして戻す。
                return roles.AsQueryable();
            }
        }

        #endregion

        #region U (Update)

        /// <summary>ロールを更新する</summary>
        /// <param name="role">ApplicationRole</param>
        public static void Update(ApplicationRole role)
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
                // ロールを更新する
                switch (Config.UserStoreType)
                {
                    case EnumUserStoreType.Memory:

                        // RolesからIdが同じApplicationRoleを取得する。
                        ApplicationRole r = CmnStore._roles.FirstOrDefault(x => x.Id == role.Id);

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
                            switch (Config.UserStoreType)
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

            return;
        }

        #endregion

        #region D (Delete)

        /// <summary>ロールを削除する</summary>
        /// <param name="role">ApplicationRole</param>
        public static void Delete(ApplicationRole role)
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
                // ロールを削除する
                switch (Config.UserStoreType)
                {
                    case EnumUserStoreType.Memory:

                        // Memory Providerには外部参照制約が無いので自らチェック
                        Tuple<string, string> userRoleMap =
                            CmnStore._userRoleMap.FirstOrDefault(x => x.Item2 == role.Id);

                        if (userRoleMap == null)
                        {
                            // RolesからIdが同じApplicationRoleを取得する。
                            ApplicationRole r = CmnStore._roles.FirstOrDefault(x => x.Id == role.Id);

                            if (r == null)
                            {
                                // ・・・
                            }
                            else
                            {
                                // ロールを削除
                                CmnStore._roles.Remove(r);
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
                            switch (Config.UserStoreType)
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

            return;
        }

        #endregion

        #endregion

        #endregion
    }
}