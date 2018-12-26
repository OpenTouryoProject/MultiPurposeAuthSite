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
//* クラス名        ：AuthorizationCodeProvider
//* クラス日本語名  ：AuthorizationCodeProvider（ライブラリ）
//*
//* 作成日時        ：－
//* 作成者          ：－
//* 更新履歴        ：－
//*
//*  日時        更新者            内容
//*  ----------  ----------------  -------------------------------------------------
//*  2018/12/26  西野 大介         新規（分割
//**********************************************************************************

using MultiPurposeAuthSite.Co;
using MultiPurposeAuthSite.Data;
using ExtOAuth2 = MultiPurposeAuthSite.Extensions.OAuth2;

using System;
using System.IO;
using System.Data;
using System.Collections.Generic;
using System.Collections.Concurrent;
using System.Threading.Tasks;

using Microsoft.Owin.Security.Infrastructure;

using Dapper;
using Newtonsoft.Json;

using Touryo.Infrastructure.Framework.Authentication;

namespace MultiPurposeAuthSite.Extensions.OAuth2
{
    /// <summary>
    /// </summary>
    public class AuthorizationCodeProvider
    {
        /// <summary>
        /// AuthenticationCodes
        /// ConcurrentDictionaryは、.NET 4.0の新しいスレッドセーフなHashtable
        /// </summary>
        private static ConcurrentDictionary<string, string>
                    AuthenticationCodes = new ConcurrentDictionary<string, string>(StringComparer.Ordinal);

        #region Create

        /// <summary>CreateAuthenticationCode</summary>
        /// <param name="code">string</param>
        /// <param name="jsonString">string</param>
        public static void CreateAuthenticationCode(string code, string jsonString)
        {
            switch (Config.UserStoreType)
            {
                case EnumUserStoreType.Memory:
                    AuthorizationCodeProvider.AuthenticationCodes[code] = jsonString;
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
                                    "INSERT INTO [AuthenticationCodeDictionary] ([Key], [Value], [CreatedDate]) VALUES (@Key, @Value, @CreatedDate)",
                                    new { Key = code, Value = jsonString, CreatedDate = DateTime.Now });

                                break;

                            case EnumUserStoreType.ODPManagedDriver:

                                cnn.Execute(
                                    "INSERT INTO \"AuthenticationCodeDictionary\" (\"Key\", \"Value\", \"CreatedDate\") VALUES (:Key, :Value, :CreatedDate)",
                                    new { Key = code, Value = jsonString, CreatedDate = DateTime.Now });

                                break;

                            case EnumUserStoreType.PostgreSQL:

                                cnn.Execute(
                                    "INSERT INTO \"authenticationcodedictionary\" (\"key\", \"value\", \"createddate\") VALUES (@Key, @Value, @CreatedDate)",
                                    new { Key = code, Value = jsonString, CreatedDate = DateTime.Now });

                                break;
                        }
                    }

                    break;
            }
        }

        #endregion

        #region Receive

        /// <summary>ReceiveAuthenticationCode</summary>
        /// <param name="code">string</param>
        /// <param name="code_verifier">string</param>
        /// <returns>ticket</returns>
        public static string ReceiveAuthenticationCode(string code, string code_verifier)
        {
            string value = "";
            string ticket = "";

            switch (Config.UserStoreType)
            {
                case EnumUserStoreType.Memory:
                    if (AuthorizationCodeProvider.AuthenticationCodes.TryRemove(code, out value))
                    {
                        ticket = AuthorizationCodeProvider.VerifyCodeVerifier(value, code_verifier);
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

                                value = cnn.ExecuteScalar<string>(
                                  "SELECT [Value] FROM [AuthenticationCodeDictionary] WHERE [Key] = @Key", new { Key = code });

                                ticket = AuthorizationCodeProvider.VerifyCodeVerifier(value, code_verifier);

                                cnn.Execute(
                                    "DELETE FROM [AuthenticationCodeDictionary] WHERE [Key] = @Key", new { Key = code });

                                break;

                            case EnumUserStoreType.ODPManagedDriver:

                                value = cnn.ExecuteScalar<string>(
                                    "SELECT \"Value\" FROM \"AuthenticationCodeDictionary\" WHERE \"Key\" = :Key", new { Key = code });

                                ticket = AuthorizationCodeProvider.VerifyCodeVerifier(value, code_verifier);

                                cnn.Execute(
                                    "DELETE FROM \"AuthenticationCodeDictionary\" WHERE \"Key\" = :Key", new { Key = code });

                                break;

                            case EnumUserStoreType.PostgreSQL:

                                value = cnn.ExecuteScalar<string>(
                                    "SELECT \"value\" FROM \"authenticationcodedictionary\" WHERE \"key\" = @Key", new { Key = code });

                                ticket = AuthorizationCodeProvider.VerifyCodeVerifier(value, code_verifier);

                                cnn.Execute(
                                    "DELETE FROM \"authenticationcodedictionary\" WHERE \"key\" = @Key", new { Key = code });

                                break;
                        }
                    }

                    break;
            }

            return ticket;
        }

        /// <summary>VerifyCodeVerifier</summary>
        /// <param name="value">string</param>
        /// <param name="code_verifier">string</param>
        /// <returns>ticket</returns>
        private static string VerifyCodeVerifier(string value, string code_verifier)
        {
            // null チェック
            if (string.IsNullOrEmpty(value)) { return ""; }

            Dictionary<string, string> temp = JsonConvert.DeserializeObject<Dictionary<string, string>>(value);

            bool isPKCE = !string.IsNullOrEmpty(code_verifier);
            
            if (!isPKCE)
            {
                // 通常のアクセストークン・リクエスト
                if (string.IsNullOrEmpty(temp[OAuth2AndOIDCConst.code_challenge]))
                {
                    // Authorization Codeのcode
                    return temp["ticket"];
                }
                else
                {
                    // OAuth PKCEのcode（要 code_verifier）
                    return "";
                }
            }
            else
            {
                // OAuth PKCEのアクセストークン・リクエスト
                if (!string.IsNullOrEmpty(temp[OAuth2AndOIDCConst.code_challenge]) && !string.IsNullOrEmpty(code_verifier))
                {
                    if (temp[OAuth2AndOIDCConst.code_challenge_method].ToLower() == OAuth2AndOIDCConst.PKCE_plain)
                    {
                        // plain
                        if (temp[OAuth2AndOIDCConst.code_challenge] == code_verifier)
                        {
                            // 検証成功
                            return temp["ticket"];
                        }
                        else
                        {
                            // 検証失敗
                        }
                    }
                    else if (temp[OAuth2AndOIDCConst.code_challenge_method].ToUpper() == OAuth2AndOIDCConst.PKCE_S256)
                    {
                        // S256
                        if (temp[OAuth2AndOIDCConst.code_challenge] == OAuth2AndOIDCClient.PKCE_S256_CodeChallengeMethod(code_verifier))
                        {
                            // 検証成功
                            return temp["ticket"];
                        }
                        else
                        {
                            // 検証失敗
                        }
                    }
                    else
                    {
                        // パラメタ不正
                    }
                }
                else
                {
                    // パラメタ不正
                }

                return null;
            }
        }

        #endregion

        #region Hybrid Flow対応

        /// <summary>
        /// Hybrid Flow対応
        ///   OAuthAuthorizationServerHandler経由での呼び出しができず、
        ///   AuthenticationTokenXXXXContextを取得できないため、抜け道。
        /// </summary>
        /// <param name="code">code</param>
        /// <returns>Jwt AccessTokenのPayload部</returns>
        public static string GetAccessTokenPayload(string code)
        {
            string value = "";

            switch (Config.UserStoreType)
            {
                case EnumUserStoreType.Memory:
                    AuthorizationCodeProvider.AuthenticationCodes.TryGetValue(code, out value);
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

                                value = cnn.ExecuteScalar<string>(
                                  "SELECT [Value] FROM [AuthenticationCodeDictionary] WHERE [Key] = @Key", new { Key = code });
                                break;

                            case EnumUserStoreType.ODPManagedDriver:

                                value = cnn.ExecuteScalar<string>(
                                    "SELECT \"Value\" FROM \"AuthenticationCodeDictionary\" WHERE \"Key\" = :Key", new { Key = code });
                                break;

                            case EnumUserStoreType.PostgreSQL:

                                value = cnn.ExecuteScalar<string>(
                                    "SELECT \"value\" FROM \"authenticationcodedictionary\" WHERE \"key\" = @Key", new { Key = code });
                                break;
                        }
                    }

                    break;
            }

            Dictionary<string, string> temp = JsonConvert.DeserializeObject<Dictionary<string, string>>(value);

            //// AuthenticationTicketを生成して返す。
            //return new AuthenticationTicket(
            //    (ClaimsIdentity)BinarySerialize.BytesToObject(CustomEncode.FromBase64String(temp["claims"])),
            //    new AuthenticationProperties((IDictionary<string, string>)BinarySerialize.BytesToObject(CustomEncode.FromBase64String(temp["properties"]))));

            return temp["access_token_payload"];
        }

        #endregion
    }
}