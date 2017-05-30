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
//* クラス名        ：AuthorizationCodeProvider
//* クラス日本語名  ：AuthorizationCodeProvider（ライブラリ）
//*
//* 作成日時        ：－
//* 作成者          ：－
//* 更新履歴        ：－
//*
//*  日時        更新者            内容
//*  ----------  ----------------  -------------------------------------------------
//*  2017/04/24  西野 大介         新規
//**********************************************************************************

using System;
using System.Data;
using System.Collections.Generic;
using System.Collections.Concurrent;
using System.Threading.Tasks;

using Dapper;

using MultiPurposeAuthSite.Models.Util;
using Microsoft.Owin.Security.Infrastructure;

namespace MultiPurposeAuthSite.Models.ASPNETIdentity.TokenProviders
{   
    /// <summary>
    /// AuthorizationCodeのProvider
    /// TokenにSerializeTicket一時保存する。
    /// （Cluster対応する場合、ストアを用意する必要がある）
    /// </summary>
    /// <see cref="https://msdn.microsoft.com/ja-jp/library/microsoft.owin.security.infrastructure.authenticationtokenprovider.aspx"/>
    /// <seealso cref="https://msdn.microsoft.com/ja-jp/library/dn385573.aspx"/>
    public class AuthorizationCodeProvider : IAuthenticationTokenProvider
    {
        /// <summary>シングルトン</summary>
        private static AuthorizationCodeProvider _AuthorizationCodeProvider = new AuthorizationCodeProvider();
        
        /// <summary>
        /// _authenticationCodes
        /// ConcurrentDictionaryは、.NET 4.0の新しいスレッドセーフなHashtable
        /// </summary>
        private readonly ConcurrentDictionary<string, string>
                    _authenticationCodes = new ConcurrentDictionary<string, string>(StringComparer.Ordinal);

        /// <summary>GetInstance</summary>
        /// <returns>AuthorizationCodeProvider</returns>
        public static AuthorizationCodeProvider GetInstance()
        {
            return AuthorizationCodeProvider._AuthorizationCodeProvider;
        }

        #region Create

        /// <summary>Create</summary>
        /// <param name="context">AuthenticationTokenCreateContext</param>
        public void Create(AuthenticationTokenCreateContext context)
        {
            this.CreateAuthenticationCode(context);
        }

        /// <summary>CreateAsync</summary>
        /// <param name="context">AuthenticationTokenCreateContext</param>
        /// <returns>Task</returns>
        public Task CreateAsync(AuthenticationTokenCreateContext context)
        {
            return Task.Factory.StartNew(() => this.CreateAuthenticationCode(context));
        }

        /// <summary>CreateAuthenticationCode</summary>
        /// <param name="context">AuthenticationTokenCreateContext</param>
        private void CreateAuthenticationCode(AuthenticationTokenCreateContext context)
        {
            context.SetToken(Guid.NewGuid().ToString("n") + Guid.NewGuid().ToString("n"));

            switch (ASPNETIdentityConfig.UserStoreType)
            {
                case EnumUserStoreType.Memory:
                    _authenticationCodes[context.Token] = context.SerializeTicket();
                    break;

                case EnumUserStoreType.SqlServer:
                case EnumUserStoreType.OracleMD:
                case EnumUserStoreType.PostgreSQL: // DMBMS

                    using (IDbConnection cnn = DataAccess.CreateConnection())
                    {
                        cnn.Open();

                        switch (ASPNETIdentityConfig.UserStoreType)
                        {
                            case EnumUserStoreType.SqlServer:

                                cnn.Execute(
                                    "INSERT INTO [AuthenticationCodeDictionary] ([Key], [Value]) VALUES (@Key, @Value)",
                                    new { Key = context.Token, Value = context.SerializeTicket() });

                                break;

                            case EnumUserStoreType.OracleMD:

                                cnn.Execute(
                                    "INSERT INTO \"AuthenticationCodeDictionary\" (\"Key\", \"Value\") VALUES (:Key, :Value)",
                                    new { Key = context.Token, Value = context.SerializeTicket() });

                                break;

                            case EnumUserStoreType.PostgreSQL:

                                break;

                        }
                    }

                    break;
            }
        }

        #endregion

        #region Receive

        /// <summary>Receive</summary>
        /// <param name="context">AuthenticationTokenReceiveContext</param>
        public void Receive(AuthenticationTokenReceiveContext context)
        {
            this.ReceiveAuthenticationCode(context);
        }

        /// <summary>ReceiveAsync</summary>
        /// <param name="context">AuthenticationTokenReceiveContext</param>
        /// <returns>Task</returns>
        public Task ReceiveAsync(AuthenticationTokenReceiveContext context)
        {
            return Task.Factory.StartNew(() => this.ReceiveAuthenticationCode(context));
        }

        /// <summary>ReceiveAuthenticationCode</summary>
        /// <param name="context">AuthenticationTokenReceiveContext</param>
        private void ReceiveAuthenticationCode(AuthenticationTokenReceiveContext context)
        {
            IEnumerable<string> values = null;

            switch (ASPNETIdentityConfig.UserStoreType)
            {
                case EnumUserStoreType.Memory:
                    string value;
                    if (_authenticationCodes.TryRemove(context.Token, out value))
                    {
                        context.DeserializeTicket(value);
                    }
                    break;

                case EnumUserStoreType.SqlServer:
                case EnumUserStoreType.OracleMD:
                case EnumUserStoreType.PostgreSQL: // DMBMS

                    using (IDbConnection cnn = DataAccess.CreateConnection())
                    {
                        cnn.Open();

                        switch (ASPNETIdentityConfig.UserStoreType)
                        {
                            case EnumUserStoreType.SqlServer:

                                values = cnn.Query<string>(
                                  "SELECT [Value] FROM [AuthenticationCodeDictionary] WHERE [Key] = @Key", new { Key = context.Token });

                                context.DeserializeTicket(values.AsList()[0]);

                                cnn.Execute(
                                    "DELETE FROM [AuthenticationCodeDictionary] WHERE [Key] = @Key", new { Key = context.Token });

                                break;

                            case EnumUserStoreType.OracleMD:

                                values = cnn.Query<string>(
                                    "SELECT \"Value\" FROM \"AuthenticationCodeDictionary\" WHERE \"Key\" = :Key", new { Key = context.Token });

                                context.DeserializeTicket(values.AsList()[0]);

                                cnn.Execute(
                                    "DELETE FROM [AuthenticationCodeDictionary] WHERE \"Key\" = :Key", new { Key = context.Token });

                                break;

                            case EnumUserStoreType.PostgreSQL:

                                break;

                        }
                    }

                    break;
            }
        }

        #endregion

    }
}