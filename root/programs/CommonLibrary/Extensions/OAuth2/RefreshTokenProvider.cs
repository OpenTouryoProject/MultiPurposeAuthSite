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
//* クラス名        ：RefreshTokenProvider
//* クラス日本語名  ：RefreshTokenProvider（ライブラリ）
//*
//* 作成日時        ：－
//* 作成者          ：－
//* 更新履歴        ：－
//*
//*  日時        更新者            内容
//*  ----------  ----------------  -------------------------------------------------
//*  2018/12/26  西野 大介         新規（分割
//**********************************************************************************

using System;
using System.Data;
using System.Collections.Generic;
using System.Collections.Concurrent;

using MultiPurposeAuthSite.Data;
using MultiPurposeAuthSite.Co;

using Dapper;

using Touryo.Infrastructure.Public.Security;

namespace MultiPurposeAuthSite.Extensions.OAuth2
{
    /// <summary>SerializeTicket一時保存する。</summary>
    public class RefreshTokenProvider
    {
        /// <summary>
        /// _refreshTokens
        /// ConcurrentDictionaryは、.NET 4.0の新しいスレッドセーフなHashtable
        /// </summary>
        private static ConcurrentDictionary<string, byte[]>
            RefreshTokens = new ConcurrentDictionary<string, byte[]>();

        #region Create

        /// <summary>Create</summary>
        /// <param name="authenticationTicket">byte[]</param>
        /// <returns>token id</returns>
        public static void Create(string tokenId, byte[] authenticationTicket)
        {
            if (Config.EnableRefreshToken)
            {
                // EnableRefreshToken == true
                switch (Config.UserStoreType)
                {
                    case EnumUserStoreType.Memory:
                        RefreshTokenProvider.RefreshTokens.TryAdd(tokenId, authenticationTicket);
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
                                        "INSERT INTO [RefreshTokenDictionary] ([Key], [Value], [CreatedDate]) VALUES (@Key, @Value, @CreatedDate)",
                                        new { Key = tokenId, Value = authenticationTicket, CreatedDate = DateTime.Now });

                                    break;

                                case EnumUserStoreType.ODPManagedDriver:

                                    cnn.Execute(
                                        "INSERT INTO \"RefreshTokenDictionary\" (\"Key\", \"Value\", \"CreatedDate\") VALUES (:Key, :Value, :CreatedDate)",
                                        new { Key = tokenId, Value = authenticationTicket, CreatedDate = DateTime.Now });

                                    break;

                                case EnumUserStoreType.PostgreSQL:

                                    cnn.Execute(
                                        "INSERT INTO \"refreshtokendictionary\" (\"key\", \"value\", \"createddate\") VALUES (@Key, @Value, @CreatedDate)",
                                        new { Key = tokenId, Value = authenticationTicket, CreatedDate = DateTime.Now });

                                    break;
                            }
                        }

                        break;
                }
            }
            else
            {
                // EnableRefreshToken == false
            }
        }

        #endregion

        #region Receive

        /// <summary>Receive</summary>
        /// <param name="tokenId">string</param>
        /// <returns>AuthenticationTicket</returns>
        public static byte[] Receive(string tokenId)
        {
            if (Config.EnableRefreshToken)
            {
                // EnableRefreshToken == true
                byte[] ticket = null;
                IEnumerable<byte[]> values = null;
                List<byte[]> list = null;

                switch (Config.UserStoreType)
                {
                    case EnumUserStoreType.Memory:
                        RefreshTokenProvider.RefreshTokens.TryRemove(tokenId, out ticket);
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

                                    values = cnn.Query<byte[]>(
                                        "SELECT [Value] FROM [RefreshTokenDictionary] WHERE [Key] = @Key", new { Key = tokenId });

                                    list = values.AsList();
                                    if (list.Count != 0)
                                    {
                                        ticket = values.AsList()[0];

                                        cnn.Execute(
                                            "DELETE FROM [RefreshTokenDictionary] WHERE [Key] = @Key", new { Key = tokenId });
                                    }

                                    break;

                                case EnumUserStoreType.ODPManagedDriver:

                                    values = cnn.Query<byte[]>(
                                        "SELECT \"Value\" FROM \"RefreshTokenDictionary\" WHERE \"Key\" = :Key", new { Key = tokenId });

                                    list = values.AsList();
                                    if (list.Count != 0)
                                    {
                                        ticket = values.AsList()[0];

                                        cnn.Execute(
                                            "DELETE FROM \"RefreshTokenDictionary\" WHERE \"Key\" = :Key", new { Key = tokenId });
                                    }

                                    break;

                                case EnumUserStoreType.PostgreSQL:

                                    values = cnn.Query<byte[]>(
                                       "SELECT \"value\" FROM \"refreshtokendictionary\" WHERE \"key\" = @Key", new { Key = tokenId });

                                    list = values.AsList();
                                    if (list.Count != 0)
                                    {
                                        ticket = values.AsList()[0];

                                        cnn.Execute(
                                            "DELETE FROM \"refreshtokendictionary\" WHERE \"key\" = @Key", new { Key = tokenId });
                                    }

                                    break;
                            }
                        }

                        break;
                }

                return ticket;
            }
            else
            {
                // EnableRefreshToken == false
                return null;
            }
        }

        #endregion

        #region Reference

        /// <summary>Reference</summary>
        /// <param name="tokenId">string</param>
        /// <returns>AuthenticationTicket</returns>
        /// <remarks>OAuth 2.0 Token Introspectionのサポートのために必要</remarks>
        public static byte[] Refer(string tokenId)
        {
            if (Config.EnableRefreshToken)
            {
                // EnableRefreshToken == true
                byte[] ticket = null;
                IEnumerable<byte[]> values = null;
                List<byte[]> list = null;

                switch (Config.UserStoreType)
                {
                    case EnumUserStoreType.Memory:
                        RefreshTokenProvider.RefreshTokens.TryGetValue(tokenId, out ticket);
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

                                    values = cnn.Query<byte[]>(
                                        "SELECT [Value] FROM [RefreshTokenDictionary] WHERE [Key] = @Key", new { Key = tokenId });

                                    list = values.AsList();
                                    if (list.Count != 0)
                                    {
                                        ticket = values.AsList()[0];
                                    }

                                    break;

                                case EnumUserStoreType.ODPManagedDriver:

                                    values = cnn.Query<byte[]>(
                                        "SELECT \"Value\" FROM \"RefreshTokenDictionary\" WHERE \"Key\" = :Key", new { Key = tokenId });

                                    list = values.AsList();
                                    if (list.Count != 0)
                                    {
                                        ticket = values.AsList()[0];
                                    }

                                    break;

                                case EnumUserStoreType.PostgreSQL:

                                    values = cnn.Query<byte[]>(
                                      "SELECT \"value\" FROM \"refreshtokendictionary\" WHERE \"key\" = @Key", new { Key = tokenId });

                                    list = values.AsList();
                                    if (list.Count != 0)
                                    {
                                        ticket = values.AsList()[0];
                                    }

                                    break;
                            }
                        }

                        break;
                }

                return ticket;
            }
            else
            {
                // EnableRefreshToken == false
                return null;
            }
        }

        #endregion

        #region Delete

        /// <summary>DeleteDirectly</summary>
        /// <param name="tokenId">string</param>
        /// <returns>削除できたか否か</returns>
        /// <remarks>OAuth 2.0 Token Revocationサポート</remarks>
        public static bool Delete(string tokenId)
        {
            int ret = 0;

            if (Config.EnableRefreshToken)
            {
                // EnableRefreshToken == true
                byte[] ticket;

                switch (Config.UserStoreType)
                {
                    case EnumUserStoreType.Memory:
                        if (RefreshTokenProvider.RefreshTokens.TryRemove(tokenId, out ticket))
                        {
                            // 1 refresh : 1 access なので、単に捨てればOK。
                            ret = 1;
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

                                    // 1 refresh : 1 access なので、単に捨てればOK。
                                    ret = cnn.Execute(
                                        "DELETE FROM [RefreshTokenDictionary] WHERE [Key] = @Key", new { Key = tokenId });

                                    break;

                                case EnumUserStoreType.ODPManagedDriver:

                                    // 1 refresh : 1 access なので、単に捨てればOK。
                                    ret = cnn.Execute(
                                        "DELETE FROM \"RefreshTokenDictionary\" WHERE \"Key\" = :Key", new { Key = tokenId });

                                    break;

                                case EnumUserStoreType.PostgreSQL:

                                    // 1 refresh : 1 access なので、単に捨てればOK。
                                    ret = cnn.Execute(
                                        "DELETE FROM \"refreshtokendictionary\" WHERE \"key\" = @Key", new { Key = tokenId });

                                    break;
                            }
                        }

                        break;
                }
            }
            else
            {
                // EnableRefreshToken == false
            }

            return !(ret == 0);
        }

        #endregion
    }
}