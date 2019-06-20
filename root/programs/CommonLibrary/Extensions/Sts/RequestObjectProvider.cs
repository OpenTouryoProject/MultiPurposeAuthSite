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
//* クラス名        ：RequestObjectProvider
//* クラス日本語名  ：登録されたRequestObjectを管理する（ライブラリ）
//*
//* 作成日時        ：－
//* 作成者          ：－
//* 更新履歴        ：－
//*
//*  日時        更新者            内容
//*  ----------  ----------------  -------------------------------------------------
//*  2019/06/20  西野 大介         新規
//**********************************************************************************

using MultiPurposeAuthSite.Co;
using MultiPurposeAuthSite.Data;

using System;
using System.Data;
using System.Collections.Concurrent;

using Dapper;

namespace MultiPurposeAuthSite.Extensions.Sts
{
    /// <summary>
    /// 登録されたRequestObjectを管理する。
    /// </summary>
    public class RequestObjectProvider
    {
        /// <summary>
        /// RequestObjectBean
        /// （メモリストア用）
        /// </summary>
        private class RequestObjectBean
        {
            /// <summary>Value</summary>
            public string Value = "";
            /// <summary>CreatedDate</summary>
            public DateTime CreatedDate = DateTime.MinValue;
        }

        /// <summary>
        /// RequestObjects
        /// ConcurrentDictionaryは、.NET 4.0の新しいスレッドセーフなHashtable
        /// </summary>
        private static ConcurrentDictionary<string, RequestObjectBean>
            RequestObjects = new ConcurrentDictionary<string, RequestObjectBean>();

        #region Create

        /// <summary>Create</summary>
        /// <param name="urn">string</param>
        /// <param name="value">string</param>
        public static void Create(string urn, string value)
        {
            switch (Config.UserStoreType)
            {
                case EnumUserStoreType.Memory:

                    RequestObjectProvider.RequestObjects.TryAdd(
                        urn,
                        new RequestObjectBean{
                            Value = value,
                            CreatedDate = DateTime.Now
                        });
                    break;

                case EnumUserStoreType.SqlServer:
                case EnumUserStoreType.ODPManagedDriver:
                case EnumUserStoreType.PostgreSQL: // DMBMS

                    using (IDbConnection cnn = DataAccess.CreateConnection())
                    {
                        cnn.Open();

                        switch (Config.UserStoreType)
                        {
                            case EnumUserStoreType.SqlServer:

                                cnn.Execute(
                                    "INSERT INTO [RequestObject]" +
                                    " ([Urn], [Value], [CreatedDate])" +
                                    " VALUES (@Urn, @Value, @CreatedDate)",
                                    new { Urn = urn, Value = value, CreatedDate = DateTime.Now });

                                break;

                            case EnumUserStoreType.ODPManagedDriver:

                                cnn.Execute(
                                    "INSERT INTO \"RequestObject\"" +
                                    " (\"Urn\", \"Value\", \"CreatedDate\")" +
                                    " VALUES (:Urn, :Value, :CreatedDate)",
                                    new { Urn = urn, Value = value, CreatedDate = DateTime.Now });

                                break;

                            case EnumUserStoreType.PostgreSQL:

                                cnn.Execute(
                                    "INSERT INTO \"requestobject\"" +
                                    " (\"urn\", \"value\", \"createddate\")" +
                                    " VALUES (@Urn, @Value, @CreatedDate)",
                                    new { Urn = urn, Value = value, CreatedDate = DateTime.Now });

                                break;
                        }
                    }

                    break;
            }
        }

        #endregion

        #region Get(Reference)

        /// <summary>Get</summary>
        /// <param name="urn">string</param>
        /// <returns>RequestObject</returns>
        public static string Get(string urn)
        {
            string requestObjectValue = "";

            switch (Config.UserStoreType)
            {
                case EnumUserStoreType.Memory:

                    RequestObjectBean requestObject = null;
                    if (RequestObjectProvider.RequestObjects.TryGetValue(urn, out requestObject))
                    {
                        requestObjectValue = requestObject.Value;
                    }

                    break;

                case EnumUserStoreType.SqlServer:
                case EnumUserStoreType.ODPManagedDriver:
                case EnumUserStoreType.PostgreSQL: // DMBMS

                    using (IDbConnection cnn = DataAccess.CreateConnection())
                    {
                        cnn.Open();

                        switch (Config.UserStoreType)
                        {
                            case EnumUserStoreType.SqlServer:

                                requestObjectValue = cnn.ExecuteScalar<string>(
                                    "SELECT [Value] FROM [RequestObject] WHERE [Urn] = @Urn", new { Urn = urn });

                                break;

                            case EnumUserStoreType.ODPManagedDriver:

                                requestObjectValue = cnn.ExecuteScalar<string>(
                                    "SELECT \"Value\" FROM \"RequestObject\" WHERE \"Urn\" = :Urn", new { Urn = urn });

                                break;

                            case EnumUserStoreType.PostgreSQL:

                                requestObjectValue = cnn.ExecuteScalar<string>(
                                    "SELECT \"value\" FROM \"requestobject\" WHERE \"urn\" = @Urn", new { Urn = urn });

                                break;
                        }
                    }

                    break;
            }

            return requestObjectValue;
        }

        #endregion
    }
}