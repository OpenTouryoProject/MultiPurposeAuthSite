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
//* クラス日本語名  ：CmnUserStore（ライブラリ）の 認証トークン・回復コード（net10.0 のみ）
//*
//* 作成日時        ：－
//* 作成者          ：－
//* 更新履歴        ：－
//*
//*  日時        更新者            内容
//*  ----------  ----------------  -------------------------------------------------
//*  2026/10/30  玄人 幸道         新規（CmnUserStore.cs から partial に分割。#294）
//*  2026/10/30  玄人 幸道         回復コードで空のコードを断る・トークンを渡された user の一覧で扱う（読み直さない・重ねない）・INSERT / UPDATE を Execute で（#294）
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
    /// <summary>CmnUserStore（認証トークン・回復コード（net10.0 のみ））</summary>
    internal partial class CmnUserStore
    {
        #region Collection

        #region TotpTokens: IUser...

#if NETFX
#else
        #region Prerequisite private methods(CRUD)

        /// <summary>CreateTotpToken</summary>
        /// <param name="user">ApplicationUser</param>
        /// <param name="loginProvider">string</param>
        /// <param name="name">string</param>
        /// <param name="value">string</param>
        /// <returns>IdentityUserToken(string)</returns>
        private static IdentityUserToken<string> CreateTotpToken(ApplicationUser user, string loginProvider, string name, string value)
        {
            // ストレージを直接、触らない。
            //OnlySts.STSOnly_M();

            return new IdentityUserToken<string>
            {
                UserId = user.Id,
                LoginProvider = loginProvider,
                Name = name,
                Value = value
            };
        }

        /// <summary>AddTotpTokenAsync</summary>
        /// <param name="user">ApplicationUser</param>
        /// <param name="token">IdentityUserToken(string)</param>
        /// <returns>－</returns>
        private static void AddTotpToken(ApplicationUser user, IdentityUserToken<string> token)
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
                //  **渡された user の一覧に足す**（#294）。**mem では、これが保存そのもの**（共有の実体）。
                //    以前は `FindById` で読み直していて、**DB では別の実体に足していた**（渡された user には見えなかった）。
                if (user.TotpTokens == null)
                {
                    user.TotpTokens = new List<IdentityUserToken<string>>();
                }

                user.TotpTokens.Add(token);

                switch (Config.UserStoreType)
                {
                    //case EnumUserStoreType.Memory:
                    //    break;

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
                                        "INSERT INTO [TotpTokens] ([UserId], [LoginProvider], [Name], [Value]) " +
                                        "  VALUES (@UserId, @LoginProvider, @Name, @Value)",
                                        new { UserId = token.UserId, LoginProvider = token.LoginProvider, Name = token.Name, Value = token.Value, });

                                    break;

                                case EnumUserStoreType.ODPManagedDriver:

                                    cnn.Execute(
                                        "INSERT INTO \"TotpTokens\" (\"UserId\", \"LoginProvider\", \"Name\", \"Value\") " +
                                        "  VALUES (:UserId, :LoginProvider, :Name, :Value)",
                                        new { UserId = token.UserId, LoginProvider = token.LoginProvider, Name = token.Name, Value = token.Value, });

                                    break;

                                case EnumUserStoreType.PostgreSQL:

                                    cnn.Execute(
                                        "INSERT INTO \"totptokens\" (\"userid\", \"loginprovider\", \"name\", \"value\") " +
                                        "  VALUES (@UserId, @LoginProvider, @Name, @Value)",
                                        new { UserId = token.UserId, LoginProvider = token.LoginProvider, Name = token.Name, Value = token.Value, });

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

        /// <summary>FindTotpToken</summary>
        /// <param name="user">ApplicationUser</param>
        /// <param name="loginProvider">string</param>
        /// <param name="name">string</param>
        /// <returns>IdentityUserToken(string)</returns>
        private static IdentityUserToken<string> FindTotpToken(ApplicationUser user, string loginProvider, string name)
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
                        if (user.TotpTokens == null)
                        {
                            return null;
                        }
                        else
                        {
                            IdentityUserToken<string> token = user.TotpTokens.FirstOrDefault(
                                t => (t.LoginProvider == loginProvider && t.Name == name));
                            return token;
                        }

                    case EnumUserStoreType.SqlServer:
                    case EnumUserStoreType.ODPManagedDriver:
                    case EnumUserStoreType.PostgreSQL: // DMBMS Provider

                        using (IDbConnection cnn = DataAccess.CreateConnection())
                        {
                            cnn.Open();

                            IEnumerable<string> values = null;

                            switch (Config.UserStoreType)
                            {
                                case EnumUserStoreType.SqlServer:

                                    values = cnn.Query<string>(
                                        "SELECT [Value] FROM [TotpTokens] " +
                                        "  WHERE [UserId] = @UserId AND [LoginProvider] = @LoginProvider AND [Name] = @Name",
                                        new { UserId = user.Id, LoginProvider = loginProvider, Name = name, });

                                    break;

                                case EnumUserStoreType.ODPManagedDriver:

                                    values = cnn.Query<string>(
                                        "SELECT \"Value\" FROM \"TotpTokens\" " +
                                        "  WHERE \"UserId\" = :UserId AND \"LoginProvider\" = :LoginProvider AND \"Name\" = :Name",
                                        new { UserId = user.Id, LoginProvider = loginProvider, Name = name, });

                                    break;

                                case EnumUserStoreType.PostgreSQL:

                                    values = cnn.Query<string>(
                                        "SELECT \"value\" FROM \"totptokens\" " +
                                        "  WHERE \"userid\" = @UserId AND \"loginprovider\" = @LoginProvider AND \"name\" = @Name",
                                        new { UserId = user.Id, LoginProvider = loginProvider, Name = name, });

                                    break;
                            }

                            if (values.Count() != 0)
                            {
                                IdentityUserToken<string> token 
                                    = new IdentityUserToken<string>()
                                    {
                                        UserId = user.Id,
                                        LoginProvider = loginProvider,
                                        Name = name,
                                        Value = values.First()
                                    };

                                if (user.TotpTokens == null)
                                {
                                    user.TotpTokens = new List<IdentityUserToken<string>>();
                                }

                                //  **同じ組の古い物を外してから足す**（#294。以前は読むたびに重なっていた）。
                                for (int i = user.TotpTokens.Count - 1; i >= 0; i--)
                                {
                                    if (user.TotpTokens[i].LoginProvider == loginProvider
                                        && user.TotpTokens[i].Name == name)
                                    {
                                        user.TotpTokens.RemoveAt(i);
                                    }
                                }

                                user.TotpTokens.Add(token);

                                return token;
                            }
                        }

                        break;
                }
            }
            catch (Exception ex)
            {
                Logging.MySQLLogForEx(ex);
            }

            return null;
        }

        /// <summary>UpdateTotpToken</summary>
        /// <param name="token">IdentityUserToken(string)</param>
        private static void UpdateTotpToken(IdentityUserToken<string> token)
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
                        // なにもしない（更新済みのため
                        //   **break が無く、下の DB の枝へ落ちていた**
                        //   （#294。mem ストアで回復コードを使うと 500 になった）。
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
                                        "UPDATE [TotpTokens] " +
                                        "  SET [Value] = @Value " +
                                        "  WHERE [UserId] = @UserId AND [LoginProvider] = @LoginProvider AND [Name] = @Name",
                                        new
                                        {
                                            UserId = token.UserId,
                                            LoginProvider = token.LoginProvider,
                                            Name = token.Name,
                                            Value = token.Value
                                        });

                                    break;

                                case EnumUserStoreType.ODPManagedDriver:

                                    cnn.Execute(
                                        "UPDATE \"TotpTokens\" " +
                                        "  SET \"Value\" = :Value " +
                                        "  WHERE \"UserId\" = :UserId AND \"LoginProvider\" = :LoginProvider AND \"Name\" = :Name",
                                        new
                                        {
                                            UserId = token.UserId,
                                            LoginProvider = token.LoginProvider,
                                            Name = token.Name,
                                            Value = token.Value
                                        });

                                    break;

                                case EnumUserStoreType.PostgreSQL:

                                    cnn.Execute(
                                        "UPDATE \"totptokens\" " +
                                        "  SET \"value\" = @Value " +
                                        "  WHERE \"userid\" = @UserId AND \"loginprovider\" = @LoginProvider AND \"name\" = @Name",
                                        new
                                        {
                                            UserId = token.UserId,
                                            LoginProvider = token.LoginProvider,
                                            Name = token.Name,
                                            Value = token.Value
                                        });

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

        /// <summary>RemoveTotpTokenAsync</summary>
        /// <param name="user">ApplicationUser</param>
        /// <param name="token">IdentityUserToken(string)</param>
        /// <returns>－</returns>
        private static void RemoveTotpToken(ApplicationUser user, IdentityUserToken<string> token)
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
                                        "DELETE FROM [TotpTokens] " +
                                        "       WHERE [UserId] = @UserId AND [LoginProvider] = @LoginProvider AND [Name] = @Name",
                                        new { UserId = token.UserId, LoginProvider = token.LoginProvider, Name = token.Name, });

                                    break;

                                case EnumUserStoreType.ODPManagedDriver:

                                    cnn.Execute(
                                        "DELETE FROM \"TotpTokens\" " +
                                        "       WHERE \"UserId\" = :UserId AND \"LoginProvider\" = :LoginProvider AND \"Name\" = :Name",
                                        new { UserId = token.UserId, LoginProvider = token.LoginProvider, Name = token.Name, });

                                    break;

                                case EnumUserStoreType.PostgreSQL:

                                    cnn.Execute(
                                        "DELETE FROM \"totptokens\" " +
                                        "       WHERE \"userid\" = @UserId AND \"loginprovider\" = @LoginProvider AND \"name\" = @Name",
                                        new { UserId = token.UserId, LoginProvider = token.LoginProvider, Name = token.Name, });

                                    break;
                            }
                        }

                        break;
                }

                //  **渡された user の一覧から消す**（#294。mem では、これが保存そのもの）。
                //    以前は `FindById` で読み直していた（DB では、渡された user に残っていた）。
                user.TotpTokens?.Remove(token);
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

        #region IUserAuthenticationTokenStore

        /// <summary>SetTokenAsync</summary>
        /// <param name="user">ApplicationUser</param>
        /// <param name="loginProvider">string</param>
        /// <param name="name">string</param>
        /// <param name="value">string</param>
        public static void SetToken(ApplicationUser user, string loginProvider, string name, string value)
        {
            // ストレージを直接、触らない。
            //OnlySts.STSOnly_M();

            // Debug
            Logging.MyDebugSQLTrace(
                MethodBase.GetCurrentMethod().DeclaringType.FullName +
                "." + MethodBase.GetCurrentMethod().Name +
                Logging.GetParametersString(MethodBase.GetCurrentMethod().GetParameters()));

            // DBMSからロードする場合は、userと関連付ける。
            IdentityUserToken<string> token = CmnUserStore.FindTotpToken(user, loginProvider, name);

            if (token == null)
            {
                
                CmnUserStore.AddTotpToken(user, // (2) Memory and DBMS
                    CmnUserStore.CreateTotpToken( // (1) Memory only
                        user, loginProvider, name, value));
            }
            else
            {
                token.Value = value; // (1) tokenを更新 (Memory)
                CmnUserStore.UpdateTotpToken(token); // (2) DBMS only
            }

            return;
        }

        /// <summary>GetTokenAsync</summary>
        /// <param name="user">ApplicationUser</param>
        /// <param name="loginProvider">string</param>
        /// <param name="name">string</param>
        /// <returns>Token</returns>
        public static string GetToken(ApplicationUser user, string loginProvider, string name)
        {
            // ストレージを直接、触らない。
            //OnlySts.STSOnly_M();

            // Debug
            Logging.MyDebugSQLTrace(
                MethodBase.GetCurrentMethod().DeclaringType.FullName +
                "." + MethodBase.GetCurrentMethod().Name +
                Logging.GetParametersString(MethodBase.GetCurrentMethod().GetParameters()));

            IdentityUserToken<string> token = CmnUserStore.FindTotpToken(user, loginProvider, name);
            return token?.Value;
        }

        /// <summary>RemoveTokenAsync</summary>
        /// <param name="user">ApplicationUser</param>
        /// <param name="loginProvider">string</param>
        /// <param name="name">string</param>
        public static void RemoveToken(ApplicationUser user, string loginProvider, string name)
        {
            // ストレージを直接、触らない。
            //OnlySts.STSOnly_M();

            // Debug
            Logging.MyDebugSQLTrace(
                MethodBase.GetCurrentMethod().DeclaringType.FullName +
                "." + MethodBase.GetCurrentMethod().Name +
                Logging.GetParametersString(MethodBase.GetCurrentMethod().GetParameters()));

            IdentityUserToken<string> token = CmnUserStore.FindTotpToken(user, loginProvider, name);

            if (token != null)
            {
                CmnUserStore.RemoveTotpToken(user, token);
            }

            return;
        }

        #endregion

        #region IUserTwoFactorRecoveryCodeStore

        /// <summary>InternalLoginProvider</summary>
        private static readonly string InternalLoginProvider = "[AspNetUserStore]";
        ///// <summary>AuthenticatorKeyTokenName</summary>
        //private static readonly string AuthenticatorKeyTokenName = "AuthenticatorKey";
        /// <summary>RecoveryCodeTokenName</summary>
        private static readonly string RecoveryCodeTokenName = "RecoveryCodes";

        /// <summary>CountCodesAsync</summary>
        /// <param name="user">ApplicationUser</param>
        /// <returns>int</returns>
        public static int CountCodes(ApplicationUser user)
        {
            // ストレージを直接、触らない。
            //OnlySts.STSOnly_M();

            // Debug
            Logging.MyDebugSQLTrace(
                MethodBase.GetCurrentMethod().DeclaringType.FullName +
                "." + MethodBase.GetCurrentMethod().Name +
                Logging.GetParametersString(MethodBase.GetCurrentMethod().GetParameters()));

            string mergedCodes = CmnUserStore.GetToken(user, CmnUserStore.InternalLoginProvider, CmnUserStore.RecoveryCodeTokenName) ?? "";

            if (string.IsNullOrEmpty(mergedCodes))
            {
                return 0;
            }
            else
            {
                return mergedCodes.Split(new char[] { ';' }, StringSplitOptions.RemoveEmptyEntries).Length;
            }
        }

        /// <summary>ReplaceCodesAsync</summary>
        /// <param name="user">ApplicationUser</param>
        /// <param name="recoveryCodes">IEnumerable(string)</param>
        public static void ReplaceCodes(ApplicationUser user, IEnumerable<string> recoveryCodes)
        {
            // ストレージを直接、触らない。
            //OnlySts.STSOnly_M();

            // Debug
            Logging.MyDebugSQLTrace(
                MethodBase.GetCurrentMethod().DeclaringType.FullName +
                "." + MethodBase.GetCurrentMethod().Name +
                Logging.GetParametersString(MethodBase.GetCurrentMethod().GetParameters()));

            string mergedCodes = string.Join(";", recoveryCodes);
            CmnUserStore.SetToken(user, CmnUserStore.InternalLoginProvider, CmnUserStore.RecoveryCodeTokenName, mergedCodes);
        }

        /// <summary>RedeemCodeAsync</summary>
        /// <param name="user">ApplicationUser</param>
        /// <param name="code">string</param>
        /// <returns>bool</returns>
        public static bool RedeemCode(ApplicationUser user, string code)
        {
            // ストレージを直接、触らない。
            //OnlySts.STSOnly_M();

            // Debug
            Logging.MyDebugSQLTrace(
                MethodBase.GetCurrentMethod().DeclaringType.FullName +
                "." + MethodBase.GetCurrentMethod().Name +
                Logging.GetParametersString(MethodBase.GetCurrentMethod().GetParameters()));

            string mergedCodes = CmnUserStore.GetToken(user, InternalLoginProvider, RecoveryCodeTokenName) ?? "";
            //  **空のコードは断る**（#294）。
            //    **コードが 0 件だと `"".Split(';')` が `[""]` になり、空のコードが一致していた**
            //    （画面は `[Required]` で止めているが、ストアの側でも断る）。
            if (string.IsNullOrEmpty(code))
            {
                return false;
            }

            string[] splitCodes = mergedCodes.Split(new char[] { ';' }, StringSplitOptions.RemoveEmptyEntries);
            if (splitCodes.Contains(code))
            {
                // ココで使用されたRecoveryCodeが削除される。
                List<string> updatedCodes = new List<string>(splitCodes.Where(s => s != code));
                CmnUserStore.ReplaceCodes(user, updatedCodes);
                return true;
            }
            return false;
        }

        #endregion
#endif

        #endregion

        #endregion
    }
}