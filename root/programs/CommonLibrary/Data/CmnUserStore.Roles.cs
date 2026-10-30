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
//* クラス日本語名  ：CmnUserStore（ライブラリ）の ロール
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

using Dapper;

namespace MultiPurposeAuthSite.Data
{
    /// <summary>CmnUserStore（ロール）</summary>
    internal partial class CmnUserStore
    {
        #region ロール名の突き合わせに使う列

        /// <remarks>
        /// **Identity Core は、ストアに「正規化した名前」（大文字）を渡す。**
        /// `UserManager.AddToRoleAsync(user, "User")` は、ストアには `"USER"` で届く。
        ///
        /// **`Roles.Name` と突き合わせると、大文字小文字を区別するストアで一致しない。**
        ///
        /// | ストア | 以前の挙動 |
        /// |---|---|
        /// | `mem` | **正しかった**（`NormalizedName` と突き合わせていた） |
        /// | `sql` | **偶然通っていた**（照合順序が大文字小文字を区別しない） |
        /// | `ora` / `npg` | **一致せず、副問い合わせが NULL になり、挿入が失敗していた** |
        ///
        /// 失敗は `catch` で握り潰されるため、**ロールが付かないことしか残らなかった**
        /// （`ORA-01400: ("UserRoles"."RoleId")にはNULLは挿入できません`）。
        ///
        /// **net48（Identity 2.x）は正規化しない**ので、そちらは `Name` で突き合わせる。
        /// **`NormalizedName` は、どちらの経路でも入っている**
        /// （`ApplicationRole.NormalizedName` は net48 では `Name.ToUpper()` を返す）。
        /// </remarks>
#if NETCORE
        /// <summary>ロール名の突き合わせに使う列（SQL Server）</summary>
        private const string RoleNameCol_Sql = "[NormalizedName]";
        /// <summary>ロール名の突き合わせに使う列（Oracle）</summary>
        private const string RoleNameCol_Ora = "\"NormalizedName\"";
        /// <summary>ロール名の突き合わせに使う列（PostgreSQL）</summary>
        private const string RoleNameCol_Npg = "\"normalizedname\"";
#else
        /// <summary>ロール名の突き合わせに使う列（SQL Server）</summary>
        private const string RoleNameCol_Sql = "[Name]";
        /// <summary>ロール名の突き合わせに使う列（Oracle）</summary>
        private const string RoleNameCol_Ora = "\"Name\"";
        /// <summary>ロール名の突き合わせに使う列（PostgreSQL）</summary>
        private const string RoleNameCol_Npg = "\"name\"";
#endif

        #endregion

        #region CRUD(共通)

        #region U (Update)

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
                                                "      AND [UserRoles].[RoleId] = (SELECT [Roles].[Id] FROM [Roles] WHERE [Roles]." + RoleNameCol_Sql + " = @roleName)",
                                                new { UserId = user.Id, roleName = roleName });

                                            break;

                                        case EnumUserStoreType.ODPManagedDriver:

                                            cnn.Execute(
                                                "DELETE FROM \"UserRoles\" " +
                                                "WHERE \"UserRoles\".\"UserId\" = :UserId " +
                                                "      AND \"UserRoles\".\"RoleId\" = (SELECT \"Roles\".\"Id\" FROM \"Roles\" WHERE \"Roles\"." + RoleNameCol_Ora + " = :roleName)",
                                                new { UserId = user.Id, roleName = roleName });

                                            break;

                                        case EnumUserStoreType.PostgreSQL:

                                            cnn.Execute(
                                                "DELETE FROM \"userroles\" " +
                                                "WHERE \"userroles\".\"userid\" = @UserId " +
                                                "      AND \"userroles\".\"roleid\" = (SELECT \"roles\".\"id\" FROM \"roles\" WHERE \"roles\"." + RoleNameCol_Npg + " = @roleName)",
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
                                                "VALUES (@UserId, (SELECT [Roles].[Id] FROM [Roles] WHERE [Roles]." + RoleNameCol_Sql + " = @roleName))",
                                                new { UserId = user.Id, roleName = roleName });

                                            break;

                                        case EnumUserStoreType.ODPManagedDriver:

                                            cnn.Execute(
                                                "INSERT INTO \"UserRoles\" (\"UserRoles\".\"UserId\", \"UserRoles\".\"RoleId\") " +
                                                "VALUES (:UserId, (SELECT \"Roles\".\"Id\" FROM \"Roles\" WHERE \"Roles\"." + RoleNameCol_Ora + " = :roleName))",
                                                new { UserId = user.Id, roleName = roleName });

                                            break;

                                        case EnumUserStoreType.PostgreSQL:

                                            cnn.Execute(
                                                "INSERT INTO \"userroles\" (\"userid\", \"roleid\") " +
                                                "VALUES (@UserId, (SELECT \"id\" FROM \"roles\" WHERE " + RoleNameCol_Npg + " = @roleName))",
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
                //  **書き込みの失敗は、握らない**（#300）。**ログに書いてから投げ直す。**
                Logging.MySQLLogForEx(ex);
                throw;
            }

            return;
        }

        //Logins, ClaimsはDel-Insで対応するため、UpdateLogins, UpdateClaimsのメソッドは不要

        #endregion

        #endregion

        #endregion

        #region ユーザ属性

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
#if NETCORE
                        role = CmnStore._roles.FirstOrDefault(x => x.NormalizedName == roleName);
#else
                        role = CmnStore._roles.FirstOrDefault(x => x.Name == roleName);
#endif

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
                                        "VALUES (@UserId, (SELECT [Roles].[Id] FROM [Roles] WHERE [Roles]." + RoleNameCol_Sql + " = @roleName))",
                                        new { UserId = user.Id, roleName = roleName });

                                    break;

                                case EnumUserStoreType.ODPManagedDriver:

                                    cnn.Execute(
                                        "INSERT INTO \"UserRoles\" (\"UserRoles\".\"UserId\", \"UserRoles\".\"RoleId\") " +
                                        "VALUES (:UserId, (SELECT \"Roles\".\"Id\" FROM \"Roles\" WHERE \"Roles\"." + RoleNameCol_Ora + " = :roleName))",
                                        new { UserId = user.Id, roleName = roleName });

                                    break;

                                case EnumUserStoreType.PostgreSQL:

                                    cnn.Execute(
                                        "INSERT INTO \"userroles\" (\"userid\", \"roleid\") " +
                                        "VALUES (@UserId, (SELECT \"id\" FROM \"roles\" WHERE " + RoleNameCol_Npg + " = @roleName))",
                                        new { UserId = user.Id, roleName = roleName });

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
                                        "      AND [UserRoles].[RoleId] = (SELECT [Roles].[Id] FROM [Roles] WHERE [Roles]." + RoleNameCol_Sql + " = @roleName)",
                                        new { UserId = user.Id, roleName = roleName });

                                    break;

                                case EnumUserStoreType.ODPManagedDriver:

                                    cnn.Execute(
                                        "DELETE FROM \"UserRoles\" " +
                                        "WHERE \"UserRoles\".\"UserId\" = :UserId " +
                                        "      AND \"UserRoles\".\"RoleId\" = (SELECT \"Roles\".\"Id\" FROM \"Roles\" WHERE \"Roles\"." + RoleNameCol_Ora + " = :roleName)",
                                        new { UserId = user.Id, roleName = roleName });

                                    break;

                                case EnumUserStoreType.PostgreSQL:

                                    cnn.Execute(
                                        "DELETE FROM \"userroles\" " +
                                        "WHERE \"userroles\".\"userid\" = @UserId " +
                                        "      AND \"userroles\".\"roleid\" = (SELECT \"roles\".\"id\" FROM \"roles\" WHERE \"roles\"." + RoleNameCol_Npg + " = @roleName)",
                                        new { UserId = user.Id, roleName = roleName });

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