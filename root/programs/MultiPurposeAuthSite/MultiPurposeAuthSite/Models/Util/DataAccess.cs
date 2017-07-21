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

using System.Data;
using System.Data.SqlClient;
using Oracle.ManagedDataAccess.Client;
//using Npgsql;

using StackExchange.Profiling.Data;

using MultiPurposeAuthSite.Models.Log;
using MultiPurposeAuthSite.Models.ASPNETIdentity;

using Touryo.Infrastructure.Public.Util;

namespace MultiPurposeAuthSite.Models.Util
{
    /// <summary>DataAccessクラス</summary>
    public class DataAccess
    {
        #region DB接続

        /// <summary>Connectionオブジェクト生成メソッド</summary>
        /// <returns>IDbConnection</returns>
        public static IDbConnection CreateConnection()
        {
            switch (ASPNETIdentityConfig.UserStoreType)
            {
                case EnumUserStoreType.SqlServer:
                    //return new SqlConnection(GetConfigParameter.GetConnectionString("ConnectionString_SQL"));
                    return new ProfiledDbConnection(
                        new SqlConnection(GetConfigParameter.GetConnectionString("ConnectionString_SQL")),
                        new TraceDbProfiler());

                case EnumUserStoreType.OracleMD:
                    //return new OracleConnection(GetConfigParameter.GetConnectionString("ConnectionString_ODP2"));
                    return new ProfiledDbConnection(
                        new OracleConnection(GetConfigParameter.GetConnectionString("ConnectionString_ODP2")),
                        new TraceDbProfiler());

                //case EnumUserStoreType.PostgreSQL:
                //    return new NpgsqlConnection(GetConfigParameter.GetConnectionString("ConnectionString_NPS"));

                default:
                    return null;
            }
        }

        #endregion

        #region その他の接続
        // ・・・
        #endregion
    }
}