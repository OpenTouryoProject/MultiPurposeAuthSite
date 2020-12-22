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
//* クラス名        ：DeviceAuthZProvider
//* クラス日本語名  ：DeviceAuthZProvider（ライブラリ）
//*
//* 作成日時        ：－
//* 作成者          ：－
//* 更新履歴        ：－
//*
//*  日時        更新者            内容
//*  ----------  ----------------  -------------------------------------------------
//*  2020/12/18  西野 大介         新規
//**********************************************************************************

using System;
using System.Data;
using System.Security.Claims;
using System.Security.Principal;
using System.Collections.Generic;
using System.Collections.Concurrent;
using System.Collections.Specialized;

using MultiPurposeAuthSite.Co;
using MultiPurposeAuthSite.Data;
#if NETFX
using MultiPurposeAuthSite.Entity;
#else
using MultiPurposeAuthSite;
#endif
using MultiPurposeAuthSite.Util;
using Token = MultiPurposeAuthSite.TokenProviders;
using Sts = MultiPurposeAuthSite.Extensions.Sts;

using Newtonsoft.Json;
using Dapper;

using Touryo.Infrastructure.Framework.Authentication;
using Touryo.Infrastructure.Public.Str;
using Touryo.Infrastructure.Public.Security.Pwd;

namespace MultiPurposeAuthSite.Extensions.Sts
{
    /// <summary>DeviceAuthZProvider</summary>
    public class DeviceAuthZProvider
    {
        /// <summary>
        /// DeviceAuthZData
        /// ConcurrentDictionaryは、.NET 4.0の新しいスレッドセーフなHashtable
        /// </summary>
        private static ConcurrentDictionary<string, string>
            DeviceAuthZData = new ConcurrentDictionary<string, string>();

#region Create

        /// <summary>Create</summary>
        /// <param name="authReqExp">long</param>
        /// <param name="tempData">string</param>
        /// <param name="deviceCode">string</param>
        /// <param name="userCode">string</param>
        public static void Create(long authReqExp, string tempData,
            out string deviceCode, out string userCode)
        {
            // 初期化
            deviceCode = ""; 
            userCode = "";

            if (Config.EnableDeviceAuthZGrantType)
            {
                deviceCode = Guid.NewGuid().ToString("N");
                userCode = GetPassword.Generate(8, 0);

                // EnableDeviceAuthZGrantType == true
                switch (Config.UserStoreType)
                {
                    case EnumUserStoreType.Memory:

                        Dictionary<string, string> temp = new Dictionary<string, string>()
                        { 
                            { "userCode", userCode },
                            { "authReqExp", authReqExp.ToString() },
                            { "tempData", tempData },
                            { "result", "" }
                        };

                        DeviceAuthZProvider.DeviceAuthZData.TryAdd(
                            deviceCode, JsonConvert.SerializeObject(temp));

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
                                        "INSERT INTO [DeviceAuthZData]"
                                        + " ([DeviceCode], [UserCode], [AuthReqExp], [TempData])"
                                        + " VALUES (@DeviceCode, @UserCode, @AuthReqExp, @TempData)",
                                        new {
                                            DeviceCode = deviceCode,
                                            UserCode = userCode,
                                            AuthReqExp = authReqExp,
                                            TempData = tempData
                                        });
                                     break;

                                case EnumUserStoreType.ODPManagedDriver:

                                    cnn.Execute(
                                        "INSERT INTO \"DeviceAuthZData\""
                                        + " (\"DeviceCode\", \"UserCode\", \"AuthReqExp\", \"TempData\")"
                                        + " VALUES (:DeviceCode, :UserCode, :AuthReqExp, :TempData)",
                                        new
                                        {
                                            DeviceCode = deviceCode,
                                            UserCode = userCode,
                                            AuthReqExp = authReqExp,
                                            TempData = tempData
                                        });

                                    break;

                                case EnumUserStoreType.PostgreSQL:

                                    cnn.Execute(
                                        "INSERT INTO \"deviceauthzdata\""
                                        + " (\"devicecode\", \"usercode\", \"authreqexp\", \"tempdata\")"
                                        + " VALUES (@DeviceCode, @UserCode, @AuthReqExp, @TempData)",
                                         new
                                         {
                                             DeviceCode = deviceCode,
                                             UserCode = userCode,
                                             AuthReqExp = authReqExp,
                                             TempData = tempData
                                         });

                                    break;
                            }
                        }

                        break;
                }
            }
            else
            {
                // EnableDeviceAuthZGrantType == false
            }

            return;
        }

#endregion

#region ReceiveResult

        /// <summary>ReceiveResult</summary>
        /// <param name="userCode">string</param>
        /// <param name="userName">string</param>
        /// <param name="result">bool</param>
        public static bool ReceiveResult(string userCode, string userName, bool result)
        {
            bool retVal = false;

            if (Config.EnableDeviceAuthZGrantType)
            {
                // EnableDeviceAuthZGrantType == true

                switch (Config.UserStoreType)
                {
                    case EnumUserStoreType.Memory:

                        foreach (string deviceCode in DeviceAuthZProvider.DeviceAuthZData.Keys)
                        {
                            string temp = DeviceAuthZProvider.DeviceAuthZData[deviceCode];

                            Dictionary<string, string> dic
                                = JsonConvert.DeserializeObject<Dictionary<string, string>>(temp);

                            string _userCode = dic["userCode"];

                            if (userCode == _userCode)
                            {
                                string tempData = dic["tempData"];

                                Dictionary<string, string> tempdic
                                     = JsonConvert.DeserializeObject<Dictionary<string, string>>(tempData);

                                string client_id = tempdic["client_id"];
                                string scope = tempdic["scope"];

                                ApplicationUser user = null;
                                string sub = PPIDExtension.GetSubForOIDC(client_id, userName, out user);

                                string code = Token.CmnEndpoints.CreateCodeInAuthZNRes(
                                    new ClaimsIdentity(new GenericIdentity(sub)), new NameValueCollection(),
                                    client_id, "", (scope ?? "").Split(' '), null, "");

                                // 更新
                                dic["authZCode"] = code;
                                dic["result"] = result.ToString();

                                DeviceAuthZProvider.DeviceAuthZData[deviceCode] = JsonConvert.SerializeObject(dic);
                                retVal = true;
                                break;
                            }
                        }
                        break;

                    case EnumUserStoreType.SqlServer:
                    case EnumUserStoreType.ODPManagedDriver:
                    case EnumUserStoreType.PostgreSQL: // DMBMS

                        using (IDbConnection cnn = DataAccess.CreateConnection())
                        {
                            cnn.Open();
                            /*
                            switch (Config.UserStoreType)
                            {
                                case EnumUserStoreType.SqlServer:

                                    cnn.Execute(
                                        "UPDATE [CibaData] SET [Result] = @Result WHERE [AuthReqId] = @AuthReqId",
                                        new { AuthReqId = authReqId, Result = result });

                                    break;

                                case EnumUserStoreType.ODPManagedDriver:

                                    cnn.Execute(
                                        "UPDATE \"CibaData\" SET \"Result\" = :Result WHERE \"AuthReqId\" = :AuthReqId",
                                        new { AuthReqId = authReqId, Result = result });

                                    break;

                                case EnumUserStoreType.PostgreSQL:

                                    cnn.Execute(
                                        "UPDATE \"cibadata\" SET \"result\" = @Result WHERE \"authreqid\" = @AuthReqId",
                                        new { AuthReqId = authReqId, Result = result });

                                    break;
                            }*/
                        }

                        break;
                }
            }
            else
            {
                // EnableDeviceAuthZGrantType == false
            }

            return retVal;
        }

#endregion

#region ReceiveTokenReq

        /// <summary>ReceiveTokenReq</summary>
        /// <param name="deviceCode">string</param>
        /// <param name="authZCode">string</param>
        /// <param name="states">DeviceAuthZState</param>
        /// <returns>結果</returns>
        public static bool ReceiveTokenReq(string deviceCode, out string authZCode, out OAuth2AndOIDCEnum.DeviceAuthZState states)
        {
            bool retVal = false;
            authZCode = "";
            states = OAuth2AndOIDCEnum.DeviceAuthZState.not_found;

            if (Config.EnableDeviceAuthZGrantType)
            {
                // EnableDeviceAuthZGrantType == true

                string temp = "";
                switch (Config.UserStoreType)
                {
                    case EnumUserStoreType.Memory:

                        temp = DeviceAuthZProvider.DeviceAuthZData[deviceCode];

                        if (string.IsNullOrEmpty(temp))
                        {
                            // 異常レコード
                            states = OAuth2AndOIDCEnum.DeviceAuthZState.irregularity_data;
                        }
                        else
                        {
                            // 正常レコード
                            Dictionary<string, string> dic
                                = JsonConvert.DeserializeObject<Dictionary<string, string>>(temp);
                            
                            // 結果の判別
                            if (DeviceAuthZProvider.GetState(dic["authReqExp"], dic["result"], out states))
                            {
                                // Code
                                authZCode = dic["authZCode"];
                                // retVal
                                retVal = true;
                            }
                        }

                        // 削除（pendingのケースを除いて）
                        if (states != OAuth2AndOIDCEnum.DeviceAuthZState.authorization_pending)
                        {
                            DeviceAuthZProvider.DeviceAuthZData.TryRemove(deviceCode, out temp);
                        }

                        break;

                    case EnumUserStoreType.SqlServer:
                    case EnumUserStoreType.ODPManagedDriver:
                    case EnumUserStoreType.PostgreSQL: // DMBMS

                        using (IDbConnection cnn = DataAccess.CreateConnection())
                        {
                            cnn.Open();
                            /*
                            dynamic dyn = null;
                            switch (Config.UserStoreType)
                            {   
                                case EnumUserStoreType.SqlServer:
                                    dyn = cnn.QueryFirst(
                                        "SELECT [AuthReqExp], [AuthZCode], [Result] FROM [CibaData] WHERE [AuthReqId] = @AuthReqId",
                                        new { AuthReqId = authReqId });

                                    if (dyn == null)
                                    {
                                        // レコードなし。
                                        states = OAuth2AndOIDCEnum.DeviceAuthZState.not_found;
                                    }
                                    else
                                    {
                                        // Code
                                        authZCode = dyn.AuthZCode;

                                        // states判別
                                        result = DeviceAuthZProvider.GetState(
                                            ((long)dyn.AuthReqExp).ToString(),
                                            ((bool)dyn.Result).ToString().ToLower(),
                                            out states);
                                    }

                                    // 削除（pendingのケースを除いて）
                                    if (states != OAuth2AndOIDCEnum.DeviceAuthZState.authorization_pending)
                                    {
                                        cnn.Execute(
                                            "DELETE FROM [CibaData] WHERE [AuthReqId] = @AuthReqId",
                                            new { AuthReqId = authReqId });
                                    }

                                    break;

                                case EnumUserStoreType.ODPManagedDriver:
                                    dyn = cnn.QueryFirst(
                                        "SELECT \"AuthReqExp\", \"AuthZCode\", \"Result\" FROM \"CibaData\" WHERE \"AuthReqId\" = :AuthReqId",
                                        new { AuthReqId = authReqId });

                                    if (dyn == null)
                                    {
                                        // レコードなし。
                                        states = OAuth2AndOIDCEnum.DeviceAuthZState.not_found;
                                    }
                                    else
                                    {
                                        // Code
                                        authZCode = dyn.AuthZCode;

                                        // states判別
                                        result = DeviceAuthZProvider.GetState(
                                            ((long)dyn.AuthReqExp).ToString(),
                                            ((bool)dyn.Result).ToString().ToLower(),
                                            out states);
                                    }

                                    // 削除（pendingのケースを除いて）
                                    if (states != OAuth2AndOIDCEnum.DeviceAuthZState.authorization_pending)
                                    {
                                        cnn.Execute(
                                            "DELETE FROM \"CibaData\" WHERE \"AuthReqId\" = :AuthReqId",
                                            new { AuthReqId = authReqId });
                                    }

                                    break;

                                case EnumUserStoreType.PostgreSQL:
                                    dyn = cnn.QueryFirst(
                                        "SELECT \"authreqexp\", \"authzcode\", \"result\" FROM \"cibadata\" WHERE \"authreqid\" = @AuthReqId",
                                        new { AuthReqId = authReqId });

                                    if (dyn == null)
                                    {
                                        // レコードなし。
                                        states = OAuth2AndOIDCEnum.DeviceAuthZState.not_found;
                                    }
                                    else
                                    {
                                        // Code
                                        authZCode = dyn.authzcode;

                                        // states判別
                                        result = DeviceAuthZProvider.GetState(
                                            ((long)dyn.authreqexp).ToString(),
                                            ((bool)dyn.result).ToString().ToLower(),
                                            out states);
                                    }

                                    // 削除（pendingのケースを除いて）
                                    if (states != OAuth2AndOIDCEnum.DeviceAuthZState.authorization_pending)
                                    {
                                        cnn.Execute(
                                            "DELETE FROM \"cibadata\" WHERE \"authreqid\" = @AuthReqId",
                                            new { AuthReqId = authReqId });
                                    }

                                    break;
                            }*/
                        }

                        break;
                }
            }
            else
            {
                // EnableDeviceAuthZGrantType == false
            }

            return retVal;
        }

#endregion

#region GetState

        /// <summary>GetState</summary>
        /// <param name="authReqExp">string</param>
        /// <param name="result">string</param>
        /// <param name="states">DeviceAuthZState</param>
        /// <returns>bool</returns>
        private static bool GetState(string authReqExp, string result, out OAuth2AndOIDCEnum.DeviceAuthZState states)
        {
            bool _result = false;

            if (string.IsNullOrEmpty(authReqExp))
            {
                // 異常
                states = OAuth2AndOIDCEnum.DeviceAuthZState.irregularity_data;
            }
            else
            {
                // 正常
                if (CmnJwtToken.VerifyExp(authReqExp))
                {
                    // 期限内
                    if (string.IsNullOrEmpty(result))
                    {
                        // 未応答
                        states = OAuth2AndOIDCEnum.DeviceAuthZState.authorization_pending;
                    }
                    else
                    {
                        // 既応答
                        if (bool.TryParse(result, out _result))
                        {
                            // = bool
                            if (_result)
                            {
                                states = OAuth2AndOIDCEnum.DeviceAuthZState.access_permitted;
                                _result = true; // 唯一の正常ケース
                            }
                            else
                            {
                                states = OAuth2AndOIDCEnum.DeviceAuthZState.access_denied;
                            }
                        }
                        else
                        {
                            // ≠ bool
                            states = OAuth2AndOIDCEnum.DeviceAuthZState.irregularity_data;
                        }
                    }
                }
                else
                {
                    // 期限外
                    states = OAuth2AndOIDCEnum.DeviceAuthZState.expired_token;
                }
            }

            return _result;
        }

#endregion
    }
}