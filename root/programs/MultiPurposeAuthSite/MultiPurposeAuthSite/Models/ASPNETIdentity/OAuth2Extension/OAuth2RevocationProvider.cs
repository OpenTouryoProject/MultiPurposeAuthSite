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
//* クラス名        ：OAuth2RevocationProvider
//* クラス日本語名  ：OAuth2RevocationProvider（ライブラリ）
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
    /// OAuth2RevocationProvider
    /// RevocationしたOAuth2のaccess_tokenのjtiを保存する。
    /// </summary>
    public class OAuth2RevocationProvider
    {
        /// <summary>シングルトン</summary>
        private static OAuth2RevocationProvider _OAuth2RevocationProvider = new OAuth2RevocationProvider();

        /// <summary>
        /// OAuth2RevocationProvider
        /// ConcurrentDictionaryは、.NET 4.0の新しいスレッドセーフなHashtable
        /// </summary>
        private static ConcurrentDictionary<string, DateTime> OAuth2Revocation = new ConcurrentDictionary<string, DateTime>();

        /// <summary>GetInstance</summary>
        /// <returns>OAuth2RevocationProvider</returns>
        public static OAuth2RevocationProvider GetInstance()
        {
            return OAuth2RevocationProvider._OAuth2RevocationProvider;
        }

        #region Create

        /// <summary>Create</summary>
        /// <param name="jti">string</param>
        public void Create(string jti)
        {
            switch (ASPNETIdentityConfig.UserStoreType)
            {
                case EnumUserStoreType.Memory:
                    OAuth2RevocationProvider.OAuth2Revocation.TryAdd(jti, DateTime.Now);
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
                                    "INSERT INTO [OAuth2Revocation] ([Jti], [CreatedDate]) VALUES (@Jti, @CreatedDate)",
                                    new { Jti = jti, CreatedDate = DateTime.Now });

                                break;

                            case EnumUserStoreType.ODPManagedDriver:

                                cnn.Execute(
                                    "INSERT INTO \"OAuth2Revocation\" (\"Jti\", \"CreatedDate\") VALUES (:Jti, :CreatedDate)",
                                    new { Jti = jti, CreatedDate = DateTime.Now });

                                break;

                            case EnumUserStoreType.PostgreSQL:

                                cnn.Execute(
                                    "INSERT INTO \"oauth2revocation\" (\"jti\", \"createddate\") VALUES (@Jti, @CreatedDate)",
                                    new { Jti = jti, CreatedDate = DateTime.Now });

                                break;
                        }
                    }

                    break;
            }
        }

        #endregion

        #region Get(Reference)

        /// <summary>Get</summary>
        /// <param name="jti">string</param>
        /// <returns>DateTime?</returns>
        public DateTime? Get(string jti)
        {
            DateTime? datetime = null;

            switch (ASPNETIdentityConfig.UserStoreType)
            {
                case EnumUserStoreType.Memory:

                    DateTime temp = DateTime.MinValue;
                    if (OAuth2RevocationProvider.OAuth2Revocation.TryGetValue(jti, out temp))
                    {
                        datetime = temp;
                    }

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

                                datetime = cnn.ExecuteScalar<DateTime>(
                                    "SELECT [CreatedDate] FROM [OAuth2Revocation] WHERE [Jti] = @Jti", new { Jti = jti });

                                break;

                            case EnumUserStoreType.ODPManagedDriver:

                                datetime = cnn.ExecuteScalar<DateTime>(
                                    "SELECT \"CreatedDate\" FROM \"OAuth2Revocation\" WHERE \"Jti\" = :Jti", new { Jti = jti });

                                break;

                            case EnumUserStoreType.PostgreSQL:

                                datetime = cnn.ExecuteScalar<DateTime>(
                                    "SELECT \"createddate\" FROM \"oauth2revocation\" WHERE \"jti\" = @Jti", new { Jti = jti });

                                break;
                        }
                    }

                    break;
            }

            // {0001/01/01 00:00} チェック
            if (datetime == DateTime.MinValue)
            {
                return null;
            }
            else
            {
                return datetime;
            }
        }
        
        #endregion
    }
}