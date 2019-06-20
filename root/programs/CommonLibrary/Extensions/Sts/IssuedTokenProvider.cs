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
//* クラス名        ：IssuedTokenProvider
//* クラス日本語名  ：IssueしたOAuth2のTokenのjtiを保存する（ライブラリ）
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
    /// IssueしたOAuth2のTokenのjtiを保存する。
    /// </summary>
    public class IssuedTokenProvider
    {
        /// <summary>
        /// IssuedTokenBean
        /// （メモリストア用）
        /// </summary>
        private class IssuedTokenBean
        {
            /// <summary>Value</summary>
            public string Value = "";
            /// <summary>ClientID</summary>
            public string ClientID = "";
            /// <summary>Audience</summary>
            public string Audience = "";
            /// <summary>CreatedDate</summary>
            public DateTime CreatedDate = DateTime.MinValue;
        }

        /// <summary>
        /// IssuedTokenProvider
        /// ConcurrentDictionaryは、.NET 4.0の新しいスレッドセーフなHashtable
        /// </summary>
        private static ConcurrentDictionary<string, IssuedTokenBean>
            IssuedTokens = new ConcurrentDictionary<string, IssuedTokenBean>();

        #region Create

        /// <summary>Create</summary>
        /// <param name="jti">string</param>
        /// <param name="value">string</param>
        /// <param name="clientID">string</param>
        /// <param name="audience">string</param>
        public static void Create(string jti, string value, string clientID, string audience)
        {
            switch (Config.UserStoreType)
            {
                case EnumUserStoreType.Memory:
                    IssuedTokenProvider.IssuedTokens.TryAdd(
                        jti,
                        new IssuedTokenBean() {
                            Value = value,
                            ClientID = clientID,
                            Audience = audience,
                            CreatedDate = DateTime.Now,
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
                                    "INSERT INTO [IssuedToken]" + 
                                    " ([Jti], [Value], [ClientID], [Audience], [CreatedDate])" +
                                    " VALUES (@Jti, @Value, @ClientID, @Audience, @CreatedDate)",
                                    new { Jti = jti, Value = value, ClientID = clientID, Audience = audience, CreatedDate = DateTime.Now });

                                break;

                            case EnumUserStoreType.ODPManagedDriver:

                                cnn.Execute(
                                    "INSERT INTO \"IssuedToken\"" +
                                    " (\"Jti\", \"Value\", \"ClientID\", \"Audience\", \"CreatedDate\")" +
                                    " VALUES (:Jti, :Value, :ClientID, :Audience, :CreatedDate)",
                                    new { Jti = jti, Value = value, ClientID = clientID, Audience = audience, CreatedDate = DateTime.Now });

                                break;

                            case EnumUserStoreType.PostgreSQL:

                                cnn.Execute(
                                    "INSERT INTO \"issuedtoken\"" +
                                    " (\"jti\", \"value\", \"clientid\", \"audience\", \"createddate\")" +
                                    " VALUES (@Jti, @Value, @ClientID, @Audience, @CreatedDate)",
                                    new { Jti = jti, Value = value, ClientID = clientID, Audience = audience, CreatedDate = DateTime.Now });

                                break;
                        }
                    }

                    break;
            }
        }

        #endregion
    }
}