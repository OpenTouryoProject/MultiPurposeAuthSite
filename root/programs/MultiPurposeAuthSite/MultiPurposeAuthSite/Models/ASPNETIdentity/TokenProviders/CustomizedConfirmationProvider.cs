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
//* クラス名        ：CustomizedConfirmationProvider
//* クラス日本語名  ：CustomizedConfirmationProvider（ライブラリ）
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
using System.Collections.Generic;
using System.Collections.Concurrent;

using Dapper;
using Newtonsoft.Json;

using MultiPurposeAuthSite.Models.Util;

namespace MultiPurposeAuthSite.Models.ASPNETIdentity.TokenProviders
{
    /// <summary>CustomizedConfirmationData</summary>
    public class CustomizedConfirmationJson
    {
        [JsonProperty(PropertyName = "code")]
        public string Code { get; set; }

        [JsonProperty(PropertyName = "email")]
        public string Email { get; set; }

        [JsonProperty(PropertyName = "fname ")]
        public string FirstName { get; set; }

        [JsonProperty(PropertyName = "lname")]
        public string LastName { get; set; }
    }

    /// <summary>CustomizedConfirmationRet</summary>
    public class CustomizedConfirmationRet
    {
        public string Value { get; set; }
        public DateTime CreatedDate { get; set; }
    }

    /// <summary>CustomizedConfirmationProvider</summary>
    public class CustomizedConfirmationProvider
    {
        /// <summary>シングルトン</summary>
        private static CustomizedConfirmationProvider _CustomizedConfirmationProvider = new CustomizedConfirmationProvider();

        /// <summary>
        /// CustomizedConfirmationData
        /// ConcurrentDictionaryは、.NET 4.0の新しいスレッドセーフなHashtable
        /// </summary>
        private static ConcurrentDictionary<string, string> CustomizedConfirmationData = new ConcurrentDictionary<string, string>();

        /// <summary>GetInstance</summary>
        /// <returns>CustomizedConfirmationProvider</returns>
        public static CustomizedConfirmationProvider GetInstance()
        {
            return CustomizedConfirmationProvider._CustomizedConfirmationProvider;
        }

        #region Create

        /// <summary>CreateCustomizedConfirmationData</summary>
        /// <param name="userID">string</param>
        /// <param name="CustomizedConfirmationJson">customizedConfirmationJson</param>
        public void CreateCustomizedConfirmationData(string userID, CustomizedConfirmationJson customizedConfirmationJson)
        {
            string json = JsonConvert.SerializeObject(customizedConfirmationJson);

            switch (ASPNETIdentityConfig.UserStoreType)
            {
                case EnumUserStoreType.Memory:

                    // Memoryでは、有効期限のチェックはしない。
                    string temp = "";
                    CustomizedConfirmationProvider.CustomizedConfirmationData.TryRemove(userID, out temp);
                    CustomizedConfirmationProvider.CustomizedConfirmationData.TryAdd(userID, json);

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
                                cnn.Execute("DELETE FROM [CustomizedConfirmation] WHERE [UserId] = @UserId", new { UserId = userID });
                                cnn.Execute(
                                    "INSERT INTO [CustomizedConfirmation] ([UserId], [Value], [CreatedDate]) VALUES (@UserId, @Value, @CreatedDate)",
                                    new { UserId = userID, Value = json, CreatedDate = DateTime.Now });

                                break;

                            case EnumUserStoreType.OracleMD:
                                cnn.Execute("DELETE FROM \"CustomizedConfirmation\" WHERE \"UserId\" = :UserId", new { UserId = userID });
                                cnn.Execute(
                                    "INSERT INTO \"CustomizedConfirmation\" (\"UserId\", \"Value\", \"CreatedDate\") VALUES (:UserId, :Value, :CreatedDate)",
                                    new { UserId = userID, Value = json, CreatedDate = DateTime.Now });

                                break;

                            case EnumUserStoreType.PostgreSQL:

                                break;

                        }
                    }

                    break;
            }
        }

        #endregion

        #region Get(Reference)

        /// <summary>CheckCustomizedConfirmationData</summary>
        /// <param name="userID">string</param>
        /// <param name="code">string</param>
        /// <param name="fname">string</param>
        /// <param name="lname">string</param>
        public string CheckCustomizedConfirmationData(string userID, string code, out string fname, out string lname)
        {
            fname = "";
            lname = "";
            CustomizedConfirmationJson customizedConfirmationJson = null;

            switch (ASPNETIdentityConfig.UserStoreType)
            {
                case EnumUserStoreType.Memory:

                    string temp = "";
                    CustomizedConfirmationProvider.CustomizedConfirmationData.TryRemove(userID, out temp);

                    // Memoryでは、有効期限のチェックはしない。
                    customizedConfirmationJson = (CustomizedConfirmationJson)JsonConvert.DeserializeObject<CustomizedConfirmationJson>(temp);
                    if (code == customizedConfirmationJson.Code)
                    {
                        fname = customizedConfirmationJson.FirstName;
                        lname = customizedConfirmationJson.LastName;
                        return customizedConfirmationJson.Email;
                    }
                    else
                    {
                        return "";
                    }
                    //break;

                case EnumUserStoreType.SqlServer:
                case EnumUserStoreType.OracleMD:
                case EnumUserStoreType.PostgreSQL: // DMBMS

                    CustomizedConfirmationRet customizedConfirmationRet = null;
                    IEnumerable<CustomizedConfirmationRet> customizedConfirmationRets = null;

                    using (IDbConnection cnn = DataAccess.CreateConnection())
                    {
                        cnn.Open();

                        switch (ASPNETIdentityConfig.UserStoreType)
                        {
                            case EnumUserStoreType.SqlServer:
                                customizedConfirmationRets = cnn.Query<CustomizedConfirmationRet>(
                                    "SELECT [Value], [CreatedDate] FROM [CustomizedConfirmation] WHERE [UserId] = @UserId", new { UserId = userID });
                                cnn.Execute("DELETE FROM [CustomizedConfirmation] WHERE [UserId] = @UserId", new { UserId = userID });
                                break;

                            case EnumUserStoreType.OracleMD:
                                customizedConfirmationRets = cnn.Query<CustomizedConfirmationRet>(
                                    "SELECT \"Value\", \"CreatedDate\" FROM \"CustomizedConfirmation\" WHERE \"UserId\" = :UserId", new { UserId = userID });
                                cnn.Execute("DELETE FROM \"CustomizedConfirmation\" WHERE \"UserId\" = :UserId", new { UserId = userID });
                                break;

                            case EnumUserStoreType.PostgreSQL:

                                break;
                        }
                    }

                    // 有効期限のチェック
                    customizedConfirmationRet = customizedConfirmationRets.AsList()[0];
                    if (DateTime.Now <= customizedConfirmationRet.CreatedDate.Add(ASPNETIdentityConfig.EmailConfirmationTokenLifespanFromHours))
                    {
                        customizedConfirmationJson = (CustomizedConfirmationJson)JsonConvert.DeserializeObject<CustomizedConfirmationJson>(customizedConfirmationRet.Value);
                        if (code == customizedConfirmationJson.Code)
                        {
                            fname = customizedConfirmationJson.FirstName;
                            lname = customizedConfirmationJson.LastName;
                            return customizedConfirmationJson.Email;
                        }
                        else
                        {
                            return "";
                        }
                    }
                    else
                    {
                        return "";
                    }

                    //break;
            }

            return "";
        }

        #endregion
    }
}