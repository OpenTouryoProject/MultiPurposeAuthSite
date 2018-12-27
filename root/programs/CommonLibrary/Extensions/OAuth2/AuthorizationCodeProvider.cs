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

using MultiPurposeAuthSite.TokenProviders;

using System;
using System.Data;
using System.Collections.Generic;
using System.Collections.Concurrent;
using System.Collections.Specialized;
using System.Security.Claims;

using Dapper;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;

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
        /// <param name="identity">ClaimsIdentity</param>
        /// <returns>code</returns>
        public static string Create(ClaimsIdentity identity, NameValueCollection queryString)
        {
            string code = Guid.NewGuid().ToString("n") + Guid.NewGuid().ToString("n");

            Dictionary<string, string> temp = new Dictionary<string, string>();

            // 有効期限が無効なtokenのペイロードだけ作成
            string access_token_payload = CmnAccessToken.CreatePayloadForCode(identity, DateTimeOffset.Now);
            temp.Add("access_token_payload", access_token_payload);

            // redirect_uri 対応
            temp.Add(OAuth2AndOIDCConst.redirect_uri, queryString[OAuth2AndOIDCConst.redirect_uri]);

            // OAuth PKCE 対応
            temp.Add(OAuth2AndOIDCConst.code_challenge, queryString[OAuth2AndOIDCConst.code_challenge]);
            temp.Add(OAuth2AndOIDCConst.code_challenge_method, queryString[OAuth2AndOIDCConst.code_challenge_method]);

            // 新しいCodeのticketをストアに保存
            string jsonString = JsonConvert.SerializeObject(temp);

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

            return code;
        }

        #endregion

        #region Receive

        /// <summary>Receive</summary>
        /// <param name="code">string</param>
        /// <param name="redirect_uri">string</param>
        /// <param name="code_verifier">string</param>
        /// <returns>PayloadForCode</returns>
        public static string Receive(string code, string redirect_uri, string code_verifier)
        {
            string value = "";
            string payload = "";

            switch (Config.UserStoreType)
            {
                case EnumUserStoreType.Memory:
                    if (AuthorizationCodeProvider.AuthenticationCodes.TryRemove(code, out value)) { }
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

                                cnn.Execute(
                                    "DELETE FROM [AuthenticationCodeDictionary] WHERE [Key] = @Key", new { Key = code });

                                break;

                            case EnumUserStoreType.ODPManagedDriver:

                                value = cnn.ExecuteScalar<string>(
                                    "SELECT \"Value\" FROM \"AuthenticationCodeDictionary\" WHERE \"Key\" = :Key", new { Key = code });

                                cnn.Execute(
                                    "DELETE FROM \"AuthenticationCodeDictionary\" WHERE \"Key\" = :Key", new { Key = code });

                                break;

                            case EnumUserStoreType.PostgreSQL:

                                value = cnn.ExecuteScalar<string>(
                                    "SELECT \"value\" FROM \"authenticationcodedictionary\" WHERE \"key\" = @Key", new { Key = code });

                                cnn.Execute(
                                    "DELETE FROM \"authenticationcodedictionary\" WHERE \"key\" = @Key", new { Key = code });

                                break;
                        }
                    }

                    break;
            }

            JObject jobj = (JObject)JsonConvert.DeserializeObject(value);
            string _redirect_uri = (string)jobj[OAuth2AndOIDCConst.redirect_uri];

            if (string.IsNullOrEmpty(_redirect_uri))
            {
                // 指定なし（継続）
            }
            else
            {
                // 指定あり
                if (_redirect_uri == redirect_uri)
                {
                    // 一致（継続）
                }
                else
                {
                    // 不一致（中断）
                    return "";
                }
            }

            if (string.IsNullOrEmpty(code_verifier))
            {
                // 通常のアクセストークン・リクエスト
                if (string.IsNullOrEmpty((string)jobj[OAuth2AndOIDCConst.code_challenge]))
                {
                    payload = (string)jobj["access_token_payload"];
                }
            }
            else
            {
                // OAuth PKCEのアクセストークン・リクエスト
                if (!string.IsNullOrEmpty((string)jobj[OAuth2AndOIDCConst.code_challenge]) && !string.IsNullOrEmpty(code_verifier))
                {
                    if (((string)jobj[OAuth2AndOIDCConst.code_challenge_method]).ToLower() == OAuth2AndOIDCConst.PKCE_plain)
                    {
                        // plain
                        if ((string)jobj[OAuth2AndOIDCConst.code_challenge] == code_verifier)
                        {
                            // 検証成功
                            payload = (string)jobj["access_token_payload"];
                        }
                    }
                    else if (((string)jobj[OAuth2AndOIDCConst.code_challenge_method]).ToUpper() == OAuth2AndOIDCConst.PKCE_S256)
                    {
                        // S256
                        if ((string)jobj[OAuth2AndOIDCConst.code_challenge] == OAuth2AndOIDCClient.PKCE_S256_CodeChallengeMethod(code_verifier))
                        {
                            // 検証成功
                            payload = (string)jobj["access_token_payload"];
                        }
                    }
                }
            }

            return payload;
        }

        #endregion

        #region Hybrid Flow対応

        /// <summary>GetAccessTokenPayload</summary>
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

            return temp["access_token_payload"];
        }

        #endregion
    }
}