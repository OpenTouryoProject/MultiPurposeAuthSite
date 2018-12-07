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
//* クラス名        ：BaseStore
//* クラス日本語名  ：BaseStore（ライブラリ）
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
using System.Security.Claims;

#if NETFX
using Microsoft.AspNet.Identity;
#else
using Microsoft.AspNetCore.Identity;
#endif

using Dapper;

namespace MultiPurposeAuthSite.Data
{
    /// <summary>BaseStore</summary>
    public class CmnStore
    {
        #region Memory

        /// <summary>ユーザ保存先</summary>
        protected static List<ApplicationUser> _users { get; } = new List<ApplicationUser>();

        /// <summary>ロールの保存先</summary>
        protected static List<ApplicationRole> _roles { get; } = new List<ApplicationRole>();

        /// <summary>ユーザとロールのリレーション</summary>
        protected static List<Tuple<string, string>> _userRoleMap { get; } = new List<Tuple<string, string>>();

        #endregion

        #region DBMS

        /// <summary>ユーザの関連情報の取得（ Roles, Logins, Claims ）</summary>
        public static void SelectChildTablesOfUser(IDbConnection cnn, ApplicationUser user)
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
                Logging.GetParametersString(MethodBase.GetCurrentMethod().GetParameters()));

            try
            {
                IEnumerable<ApplicationRole> roles = null;
                IEnumerable<UserLoginInfo> userLogins = null;
                IEnumerable<dynamic> claims = null;

                switch (Config.UserStoreType)
                {
                    case EnumUserStoreType.SqlServer:

                        // Roles
                        roles = cnn.Query<ApplicationRole>(
                            "SELECT [Roles].[Id] as Id, [Roles].[Name] as Name " +
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
                            "SELECT \"Roles\".\"Id\" as Id, \"Roles\".\"Name\" as Name " +
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
                            "SELECT \"roles\".\"id\" as id, \"roles\".\"name\" as name " +
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
    }
}