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
//*  2020/07/22  西野 大介         クリーンアーキテクチャ維持or放棄 → 放棄
//*  2026/10/30  玄人 幸道         値の無いクレーム（Oracle は空文字を NULL にする）で、残りの関連情報を読み落とさない（#294）
//*  2026/11/02  玄人 幸道         mem ストアの入れ物を、並行に読み書きできるものに変えた（#325）
//*  2026/11/03  玄人 幸道         読み取りの失敗を握らず投げ直す（#331）
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
    internal class CmnStore
    {
        #region Memory

        /// <summary>ユーザ保存先</summary>
        protected static MemoryStoreList<ApplicationUser> _users { get; } = new MemoryStoreList<ApplicationUser>();

        /// <summary>ロールの保存先</summary>
        protected static MemoryStoreList<ApplicationRole> _roles { get; } = new MemoryStoreList<ApplicationRole>();

        /// <summary>ユーザとロールのリレーション</summary>
        protected static MemoryStoreList<Tuple<string, string>> _userRoleMap { get; } = new MemoryStoreList<Tuple<string, string>>();

        #endregion

        #region DBMS

        /// <summary>DB で引ける値か（#331）</summary>
        /// <param name="value">利用者名・メアドなど、外から来た値</param>
        /// <returns>引けるなら true</returns>
        /// <remarks>
        /// **PostgreSQL は NUL 文字を、Oracle は列の幅を大きく超える値を、例外で断る。**
        /// **読み取りの失敗を握らない**ので、確かめないと 500 になる。
        /// **列の幅（256）を超える値は、どの行にも一致しない。** `mem` には幅が無いので確かめない。
        /// </remarks>
        public static bool IsSearchable(string value)
        {
            return Config.UserStoreType == EnumUserStoreType.Memory
                || value == null
                || (value.Length <= 256 && value.IndexOf('\0') < 0);
        }

        /// <summary>ユーザの関連情報の取得（ Roles, Logins, Claims, TotpTokens ）</summary>
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
                IEnumerable<dynamic> userLogins = null;
                IEnumerable<dynamic> claims = null;
#if NETFX
#else
                IEnumerable<dynamic> tokens = null;
#endif
                switch (Config.UserStoreType)
                {
                    //case EnumUserStoreType.Memory:
                    //    DBMSストアの時だけ。

                    case EnumUserStoreType.SqlServer:

                        // Roles
                        roles = cnn.Query<ApplicationRole>(
                            "SELECT [Roles].[Id] as Id, [Roles].[Name] as Name " +
                            "FROM   [UserRoles], [Roles] " +
                            "WHERE  [UserRoles].[RoleId] = [Roles].[Id] " +
                            "   AND [UserRoles].[UserId] = @userId", new { userId = user.Id });
                        user.Roles = roles.ToList();

                        // Logins
                        userLogins = cnn.Query(
                            "SELECT [LoginProvider], [ProviderKey] " +
                            "FROM   [UserLogins] WHERE [UserId] = @userId", new { userId = user.Id });
                        user.Logins = new List<UserLoginInfo>();

                        // Claims
                        claims = cnn.Query(
                            "SELECT [Issuer], [ClaimType], [ClaimValue] " +
                            "FROM   [UserClaims] WHERE [UserId] = @userId", new { userId = user.Id });
                        user.Claims = new List<Claim>();

#if NETFX
#else
                        // TotpTokens
                        tokens = cnn.Query(
                            "SELECT [LoginProvider], [Name], [Value] " +
                            "FROM   [TotpTokens] WHERE [UserId] = @userId", new { userId = user.Id });
                        user.TotpTokens = new List<IdentityUserToken<string>>();
#endif

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
                        userLogins = cnn.Query(
                            "SELECT \"LoginProvider\", \"ProviderKey\" " +
                            "FROM   \"UserLogins\" WHERE \"UserId\" = :userId", new { userId = user.Id });
                        user.Logins = new List<UserLoginInfo>();

                        // Claims
                        claims = cnn.Query(
                            "SELECT \"Issuer\", \"ClaimType\", \"ClaimValue\" " +
                            "FROM   \"UserClaims\" WHERE \"UserId\" = :userId", new { userId = user.Id });
                        user.Claims = new List<Claim>();

#if NETFX
#else
                        // TotpTokens
                        tokens = cnn.Query(
                            "SELECT \"LoginProvider\", \"Name\", \"Value\" " +
                            "FROM   \"TotpTokens\" WHERE \"UserId\" = :userId", new { userId = user.Id });
                        user.TotpTokens = new List<IdentityUserToken<string>>();
#endif

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
                        userLogins = cnn.Query(
                            "SELECT \"loginprovider\", \"providerkey\" " +
                            "FROM   \"userlogins\" WHERE \"userid\" = @userId", new { userId = user.Id });
                        user.Logins = new List<UserLoginInfo>();

                        // Claims
                        claims = cnn.Query(
                            "SELECT \"issuer\", \"claimtype\", \"claimvalue\" " +
                            "FROM   \"userclaims\" WHERE \"userid\" = @userId", new { userId = user.Id });
                        user.Claims = new List<Claim>();

#if NETFX
#else
                        // TotpTokens
                        tokens = cnn.Query(
                            "SELECT \"loginprovider\", \"name\", \"value\" " +
                            "FROM   \"totptokens\" WHERE \"userid\" = @userId", new { userId = user.Id });
                        user.TotpTokens = new List<IdentityUserToken<string>>();
#endif

                        break;
                }

                // PostgreSQLだとdynamicが全部小文字になる。

                //  **NULL は空文字で受ける**（#294）。**Oracle は空文字を NULL として保存する**ので、
                //    **値の無いクレームを `new Claim(type, null)` にして例外になり**、
                //    **握られて、後に読む外部ログインと TOTP のトークン（回復コード）が読み込まれなかった。**
                foreach (dynamic d in claims)
                {
                    if (Config.UserStoreType == EnumUserStoreType.PostgreSQL)
                    {
                        user.Claims.Add(new Claim(
                            (string)d.claimtype ?? "", (string)d.claimvalue ?? "", null, (string)d.issuer));
                    }
                    else
                    {
                        user.Claims.Add(new Claim(
                            (string)d.ClaimType ?? "", (string)d.ClaimValue ?? "", null, (string)d.Issuer));
                    }
                }

#if NETFX
                foreach (dynamic d in userLogins)
                {
                    if (Config.UserStoreType == EnumUserStoreType.PostgreSQL)
                    {
                        user.Logins.Add(new UserLoginInfo(
                            d.loginprovider, d.providerkey));
                    }
                    else
                    {
                        user.Logins.Add(new UserLoginInfo(
                            d.LoginProvider, d.ProviderKey));
                    }
                }
#else
                foreach (dynamic d in userLogins)
                {
                    if (Config.UserStoreType == EnumUserStoreType.PostgreSQL)
                    {
                        user.Logins.Add(new UserLoginInfo(
                            d.loginprovider, d.providerkey, ""));
                    }
                    else
                    {
                        user.Logins.Add(new UserLoginInfo(
                            d.LoginProvider, d.ProviderKey, ""));
                    }
                }

                foreach (dynamic d in tokens)
                {
                    if (Config.UserStoreType == EnumUserStoreType.PostgreSQL)
                    {
                        user.TotpTokens.Add(new IdentityUserToken<string>()
                        {
                            UserId = user.Id,
                            LoginProvider = d.loginprovider,
                            Name = d.name,
                            Value = d.value
                        });
                    }
                    else
                    {
                        user.TotpTokens.Add(new IdentityUserToken<string>()
                        {
                            UserId = user.Id,
                            LoginProvider = d.LoginProvider,
                            Name = d.Name,
                            Value = d.Value
                        });
                    }
                }
#endif

            }
            catch (Exception ex)
            {
                //  **読み取りの失敗は「無い」にしない**（#331）。**ログに書いてから投げ直す。**
                Logging.MySQLLogForEx(ex);
                throw;
            }
        }
        
#endregion
    }
}