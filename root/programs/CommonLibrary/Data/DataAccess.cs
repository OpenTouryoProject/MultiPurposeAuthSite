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
//* クラス名        ：DataAccess
//* クラス日本語名  ：DataAccess（ライブラリ）
//*
//* 作成日時        ：－
//* 作成者          ：－
//* 更新履歴        ：－
//*
//*  日時        更新者            内容
//*  ----------  ----------------  -------------------------------------------------
//*  2017/04/24  西野 大介         新規
//**********************************************************************************

using MultiPurposeAuthSite.Co;
using MultiPurposeAuthSite.Log;

using System;
using System.Data;
using System.Data.SqlClient;
using System.Reflection;
using System.Threading.Tasks;
#if NETFX
using Oracle.ManagedDataAccess.Client;
# endif
using Npgsql;

using Dapper;
using StackExchange.Profiling.Data;

using Touryo.Infrastructure.Public.Util;

namespace MultiPurposeAuthSite.Data
{
    /// <summary>DataAccessクラス</summary>
    public class DataAccess
    {
        #region DB接続

        /// <summary>Connectionオブジェクト生成メソッド</summary>
        /// <returns>IDbConnection</returns>
        public static IDbConnection CreateConnection()
        {
            switch (Config.UserStoreType)
            {
                case EnumUserStoreType.SqlServer:
                    //return new SqlConnection(GetConfigParameter.GetConnectionString("ConnectionString_SQL"));
                    return new ProfiledDbConnection(
                        new SqlConnection(GetConfigParameter.GetConnectionString("ConnectionString_SQL")),
                        new TraceDbProfiler());

#if NETFX
                case EnumUserStoreType.ODPManagedDriver:
                    //return new OracleConnection(GetConfigParameter.GetConnectionString("ConnectionString_ODP"));
                    return new ProfiledDbConnection(
                        new OracleConnection(GetConfigParameter.GetConnectionString("ConnectionString_ODP")),
                        new TraceDbProfiler());
#endif

                case EnumUserStoreType.PostgreSQL:
                    //return new NpgsqlConnection(GetConfigParameter.GetConnectionString("ConnectionString_NPS"));
                    return new ProfiledDbConnection(
                        new NpgsqlConnection(GetConfigParameter.GetConnectionString("ConnectionString_NPS")),
                        new TraceDbProfiler());

                default:
                    return null;
            }
        }

        #endregion

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
                Logging.GetParametersString(MethodBase.GetCurrentMethod().GetParameters()));

            try
            {
                using (IDbConnection cnn = DataAccess.CreateConnection())
                {
                    cnn.Open();
                    int count = 0;

                    // [Roles] が [Users] に先立って登録されるので。
                    switch (Config.UserStoreType)
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
    }
}