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
//* クラス日本語名  ：CmnUserStore（ライブラリ）の クレーム
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
using System.Collections.Generic;

using System.Reflection;
using System.Security.Claims;

using Dapper;

namespace MultiPurposeAuthSite.Data
{
    /// <summary>CmnUserStore（クレーム）</summary>
    internal partial class CmnUserStore
    {
        #region Collection

        #region Claims: IUserClaimStore

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

                                    //  **id は書かない**（#300 で判明）。
                                    //    **`serial`**（自動連番）なので、**列に挙げると値が 1 つ足りない。**
                                    //    **PostgreSQL が `42601: INSERT has more target columns than
                                    //    expressions` を返していたが、握っていたので表に出なかった** —
                                    //    **クレームが 1 件も保存されていなかった**（ID 連携が属性を保存できない）。
                                    cnn.Execute(
                                        "INSERT INTO \"userclaims\" (\"userid\", \"issuer\", \"claimtype\", \"claimvalue\") " +
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
                //  **書き込みの失敗は、握らない**（#300）。**ログに書いてから投げ直す。**
                Logging.MySQLLogForEx(ex);
                throw;
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