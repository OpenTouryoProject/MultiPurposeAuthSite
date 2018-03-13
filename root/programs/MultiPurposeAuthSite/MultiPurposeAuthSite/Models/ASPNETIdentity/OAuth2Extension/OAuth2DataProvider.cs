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
//* クラス名        ：OAuth2DataProvider
//* クラス日本語名  ：OAuth2DataProvider（ライブラリ）
//*
//* 作成日時        ：－
//* 作成者          ：－
//* 更新履歴        ：－
//*
//*  日時        更新者            内容
//*  ----------  ----------------  -------------------------------------------------
//*  2017/06/07  西野 大介         新規
//**********************************************************************************

using System;
using System.Data;
using System.Collections.Concurrent;

using Dapper;

using MultiPurposeAuthSite.Models.Util;

namespace MultiPurposeAuthSite.Models.ASPNETIdentity.OAuth2Extension
{
    /// <summary>
    /// OAuth2DataProvider
    /// OAuth2DataにUnstructuredDataを保存する。
    /// </summary>
    public class OAuth2DataProvider
    {
        /// <summary>シングルトン</summary>
        private static OAuth2DataProvider _OAuth2DataProvider = new OAuth2DataProvider();

        /// <summary>
        /// OAuth2Data
        /// ConcurrentDictionaryは、.NET 4.0の新しいスレッドセーフなHashtable
        /// </summary>
        private static ConcurrentDictionary<string, string> OAuth2Data = new ConcurrentDictionary<string, string>();

        /// <summary>GetInstance</summary>
        /// <returns>OAuth2DataProvider</returns>
        public static OAuth2DataProvider GetInstance()
        {
            return OAuth2DataProvider._OAuth2DataProvider;
        }

        #region Create

        /// <summary>Create</summary>
        /// <param name="clientID">string</param>
        /// <param name="unstructuredData">string</param>
        public void Create(string clientID, string unstructuredData)
        {
            switch (ASPNETIdentityConfig.UserStoreType)
            {
                case EnumUserStoreType.Memory:
                    OAuth2DataProvider.OAuth2Data.TryAdd(clientID, unstructuredData);
                    break;

                case EnumUserStoreType.SqlServer:
                case EnumUserStoreType.ODPManagedDriver:
                case EnumUserStoreType.PostgreSQL: // DMBMS

                    using (IDbConnection cnn = DataAccess.CreateConnection())
                    {
                        cnn.Open();

                        switch (ASPNETIdentityConfig.UserStoreType)
                        {
                            case EnumUserStoreType.SqlServer:

                                cnn.Execute(
                                    "INSERT INTO [OAuth2Data] ([ClientID], [UnstructuredData]) VALUES (@ClientID, @UnstructuredData)",
                                    new { ClientID = clientID, UnstructuredData = unstructuredData });

                                break;

                            case EnumUserStoreType.ODPManagedDriver:

                                cnn.Execute(
                                    "INSERT INTO \"OAuth2Data\" (\"ClientID\", \"UnstructuredData\") VALUES (:ClientID, :UnstructuredData)",
                                    new { ClientID = clientID, UnstructuredData = unstructuredData });

                                break;

                            case EnumUserStoreType.PostgreSQL:

                                cnn.Execute(
                                    "INSERT INTO \"oauth2data\" (\"clientid\", \"unstructureddata\") VALUES (@ClientID, @UnstructuredData)",
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
        public string Get(string clientID)
        {
            string unstructuredData = "";

            switch (ASPNETIdentityConfig.UserStoreType)
            {
                case EnumUserStoreType.Memory:
                    OAuth2DataProvider.OAuth2Data.TryGetValue(clientID, out unstructuredData);

                    break;

                case EnumUserStoreType.SqlServer:
                case EnumUserStoreType.ODPManagedDriver:
                case EnumUserStoreType.PostgreSQL: // DMBMS

                    using (IDbConnection cnn = DataAccess.CreateConnection())
                    {
                        cnn.Open();

                        switch (ASPNETIdentityConfig.UserStoreType)
                        {
                            case EnumUserStoreType.SqlServer:

                                unstructuredData = cnn.ExecuteScalar<string>(
                                    "SELECT [UnstructuredData] FROM [OAuth2Data] WHERE [ClientID] = @ClientID", new { ClientID = clientID });

                                break;

                            case EnumUserStoreType.ODPManagedDriver:

                                unstructuredData = cnn.ExecuteScalar<string>(
                                    "SELECT \"UnstructuredData\" FROM \"OAuth2Data\" WHERE \"ClientID\" = :ClientID", new { ClientID = clientID });

                                break;

                            case EnumUserStoreType.PostgreSQL:

                                unstructuredData = cnn.ExecuteScalar<string>(
                                    "SELECT \"unstructureddata\" FROM \"oauth2data\" WHERE \"clientid\" = @ClientID", new { ClientID = clientID });

                                break;
                        }
                    }

                    break;
            }

            return unstructuredData;
        }
        
        #endregion

        #region Update

        /// <summary>Update</summary>
        /// <param name="clientID">string</param>
        /// <param name="unstructuredData">string</param>
        public void Update(string clientID, string unstructuredData)
        {
            switch (ASPNETIdentityConfig.UserStoreType)
            {
                case EnumUserStoreType.Memory:
                    // OAuth2DataProvider.OAuth2Data.TryUpdate が使えないので del -> ins にする。
                    string temp = "";
                    OAuth2DataProvider.OAuth2Data.TryRemove(clientID, out temp);
                    OAuth2DataProvider.OAuth2Data.TryAdd(clientID, unstructuredData);

                    break;

                case EnumUserStoreType.SqlServer:
                case EnumUserStoreType.ODPManagedDriver:
                case EnumUserStoreType.PostgreSQL: // DMBMS

                    using (IDbConnection cnn = DataAccess.CreateConnection())
                    {
                        cnn.Open();

                        switch (ASPNETIdentityConfig.UserStoreType)
                        {
                            case EnumUserStoreType.SqlServer:

                                cnn.Execute(
                                    "UPDATE [OAuth2Data] SET [UnstructuredData] = @UnstructuredData WHERE [ClientID] = @ClientID",
                                    new { ClientID = clientID, UnstructuredData = unstructuredData });

                                break;

                            case EnumUserStoreType.ODPManagedDriver:

                                cnn.Execute(
                                    "UPDATE \"OAuth2Data\" SET \"UnstructuredData\" = :UnstructuredData WHERE \"ClientID\" = :ClientID",
                                    new { ClientID = clientID, UnstructuredData = unstructuredData });

                                break;

                            case EnumUserStoreType.PostgreSQL:

                                cnn.Execute(
                                    "UPDATE \"oauth2data\" SET \"unstructureddata\" = @UnstructuredData WHERE \"clientid\" = @ClientID",
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
        public void Delete(string clientID)
        {
            switch (ASPNETIdentityConfig.UserStoreType)
            {
                case EnumUserStoreType.Memory:
                    string unstructuredData = "";
                    OAuth2DataProvider.OAuth2Data.TryRemove(clientID, out unstructuredData);

                    break;

                case EnumUserStoreType.SqlServer:
                case EnumUserStoreType.ODPManagedDriver:
                case EnumUserStoreType.PostgreSQL: // DMBMS

                    using (IDbConnection cnn = DataAccess.CreateConnection())
                    {
                        cnn.Open();

                        switch (ASPNETIdentityConfig.UserStoreType)
                        {
                            case EnumUserStoreType.SqlServer:

                                cnn.Execute(
                                    "DELETE FROM [OAuth2Data] WHERE [ClientID] = @ClientID", new { ClientID = clientID });

                                break;

                            case EnumUserStoreType.ODPManagedDriver:

                                cnn.Execute(
                                    "DELETE FROM \"OAuth2Data\" WHERE \"ClientID\" = :ClientID", new { ClientID = clientID });

                                break;

                            case EnumUserStoreType.PostgreSQL:

                                cnn.Execute(
                                    "DELETE FROM \"oauth2data\" WHERE \"clientid\" = @ClientID", new { ClientID = clientID });

                                break;
                        }
                    }

                    break;
            }
        }

        #endregion
    }
}