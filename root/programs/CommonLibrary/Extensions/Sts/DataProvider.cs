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
//* クラス名        ：DataProvider
//* クラス日本語名  ：Saml2OAuth2DataにUnstructuredDataを保存する。
//*
//* 作成日時        ：－
//* 作成者          ：－
//* 更新履歴        ：－
//*
//*  日時        更新者            内容
//*  ----------  ----------------  -------------------------------------------------
//*  2017/06/07  西野 大介         新規
//*  2019/05/2*  西野 大介         SAML2対応実施
//*  2026/10/04  玄人 幸道         GetAll を追加（#266）
//**********************************************************************************

using MultiPurposeAuthSite.Co;
using MultiPurposeAuthSite.Data;

using System;
using System.Collections.Generic;
using System.Data;
using System.Collections.Concurrent;

using Dapper;

namespace MultiPurposeAuthSite.Extensions.Sts
{
    /// <summary>
    /// DataProvider
    /// Saml2OAuth2DataにUnstructuredDataを保存する。
    /// </summary>
    public class DataProvider
    {
        /// <summary>
        /// Saml2OAuth2Data
        /// ConcurrentDictionaryは、.NET 4.0の新しいスレッドセーフなHashtable
        /// </summary>
        private static ConcurrentDictionary<string, string> Saml2OAuth2Data = new ConcurrentDictionary<string, string>();

        #region Create

        /// <summary>Create</summary>
        /// <param name="clientID">string</param>
        /// <param name="unstructuredData">string</param>
        public static void Create(string clientID, string unstructuredData)
        {
            switch (Config.UserStoreType)
            {
                case EnumUserStoreType.Memory:
                    DataProvider.Saml2OAuth2Data.TryAdd(clientID, unstructuredData);
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
                                    "INSERT INTO [Saml2OAuth2Data] ([ClientID], [UnstructuredData]) VALUES (@ClientID, @UnstructuredData)",
                                    new { ClientID = clientID, UnstructuredData = unstructuredData });

                                break;

                            case EnumUserStoreType.ODPManagedDriver:

                                cnn.Execute(
                                    "INSERT INTO \"Saml2OAuth2Data\" (\"ClientID\", \"UnstructuredData\") VALUES (:ClientID, :UnstructuredData)",
                                    new { ClientID = clientID, UnstructuredData = unstructuredData });

                                break;

                            case EnumUserStoreType.PostgreSQL:

                                cnn.Execute(
                                    "INSERT INTO \"saml2oauth2data\" (\"clientid\", \"unstructureddata\") VALUES (@ClientID, @UnstructuredData)",
                                    new { ClientID = clientID, UnstructuredData = unstructuredData });

                                break;
                        }
                    }

                    break;
            }
        }

        #endregion

        #region Get(Reference)

        /// <summary>Get</summary>
        /// <param name="clientID">string</param>
        /// <returns>unstructuredData</returns>
        public static string Get(string clientID)
        {
            string unstructuredData = "";

            switch (Config.UserStoreType)
            {
                case EnumUserStoreType.Memory:
                    DataProvider.Saml2OAuth2Data.TryGetValue(clientID, out unstructuredData);

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

                                unstructuredData = cnn.ExecuteScalar<string>(
                                    "SELECT [UnstructuredData] FROM [Saml2OAuth2Data] WHERE [ClientID] = @ClientID", new { ClientID = clientID });

                                break;

                            case EnumUserStoreType.ODPManagedDriver:

                                unstructuredData = cnn.ExecuteScalar<string>(
                                    "SELECT \"UnstructuredData\" FROM \"Saml2OAuth2Data\" WHERE \"ClientID\" = :ClientID", new { ClientID = clientID });

                                break;

                            case EnumUserStoreType.PostgreSQL:

                                unstructuredData = cnn.ExecuteScalar<string>(
                                    "SELECT \"unstructureddata\" FROM \"saml2oauth2data\" WHERE \"clientid\" = @ClientID", new { ClientID = clientID });

                                break;
                        }
                    }

                    break;
            }

            return unstructuredData;
        }
        
        #endregion

        #region GetAll

        /// <summary>全件の UnstructuredData を返す（#266）</summary>
        /// <returns>UnstructuredData の一覧（1 件も無ければ空）</returns>
        /// <remarks>
        /// **CORS の許可オリジンを作るために要る**（`CmnEndpoints.GetCorsAllowedOrigins`）。
        /// **プリフライト（`OPTIONS`）は `client_id` を持たない**ので、
        /// **オリジンの集合全体**が必要になる。
        ///
        /// **`clientID` は返さない。** 呼ぶ側は中身（JSON）だけを使うため。
        ///
        /// **毎回呼ばないこと。** 呼ぶ側でキャッシュする
        /// （`CmnEndpoints` が持つ。登録の保存で捨て、期限でも捨てる）。
        /// </remarks>
        public static List<string> GetAll()
        {
            List<string> all = new List<string>();

            switch (Config.UserStoreType)
            {
                case EnumUserStoreType.Memory:
                    all.AddRange(DataProvider.Saml2OAuth2Data.Values);

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

                                all.AddRange(cnn.Query<string>(
                                    "SELECT [UnstructuredData] FROM [Saml2OAuth2Data]"));

                                break;

                            case EnumUserStoreType.ODPManagedDriver:

                                all.AddRange(cnn.Query<string>(
                                    "SELECT \"UnstructuredData\" FROM \"Saml2OAuth2Data\""));

                                break;

                            case EnumUserStoreType.PostgreSQL:

                                all.AddRange(cnn.Query<string>(
                                    "SELECT \"unstructureddata\" FROM \"saml2oauth2data\""));

                                break;
                        }
                    }

                    break;
            }

            return all;
        }

        #endregion

        #region Update

        /// <summary>Update</summary>
        /// <param name="clientID">string</param>
        /// <param name="unstructuredData">string</param>
        public static void Update(string clientID, string unstructuredData)
        {
            switch (Config.UserStoreType)
            {
                case EnumUserStoreType.Memory:
                    // TryUpdate が使えないので del -> ins にする。
                    string temp = "";
                    DataProvider.Saml2OAuth2Data.TryRemove(clientID, out temp);
                    DataProvider.Saml2OAuth2Data.TryAdd(clientID, unstructuredData);

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
                                    "UPDATE [Saml2OAuth2Data] SET [UnstructuredData] = @UnstructuredData WHERE [ClientID] = @ClientID",
                                    new { ClientID = clientID, UnstructuredData = unstructuredData });

                                break;

                            case EnumUserStoreType.ODPManagedDriver:

                                cnn.Execute(
                                    "UPDATE \"Saml2OAuth2Data\" SET \"UnstructuredData\" = :UnstructuredData WHERE \"ClientID\" = :ClientID",
                                    new { ClientID = clientID, UnstructuredData = unstructuredData });

                                break;

                            case EnumUserStoreType.PostgreSQL:

                                cnn.Execute(
                                    "UPDATE \"saml2oauth2data\" SET \"unstructureddata\" = @UnstructuredData WHERE \"clientid\" = @ClientID",
                                    new { ClientID = clientID, UnstructuredData = unstructuredData });

                                break;
                        }
                    }

                    break;
            }
        }

        #endregion

        #region Delete

        /// <summary>Delete</summary>
        /// <param name="clientID">string</param>
        public static void Delete(string clientID)
        {
            switch (Config.UserStoreType)
            {
                case EnumUserStoreType.Memory:
                    string unstructuredData = "";
                    DataProvider.Saml2OAuth2Data.TryRemove(clientID, out unstructuredData);

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
                                    "DELETE FROM [Saml2OAuth2Data] WHERE [ClientID] = @ClientID", new { ClientID = clientID });

                                break;

                            case EnumUserStoreType.ODPManagedDriver:

                                cnn.Execute(
                                    "DELETE FROM \"Saml2OAuth2Data\" WHERE \"ClientID\" = :ClientID", new { ClientID = clientID });

                                break;

                            case EnumUserStoreType.PostgreSQL:

                                cnn.Execute(
                                    "DELETE FROM \"saml2oauth2data\" WHERE \"clientid\" = @ClientID", new { ClientID = clientID });

                                break;
                        }
                    }

                    break;
            }
        }

        #endregion
    }
}