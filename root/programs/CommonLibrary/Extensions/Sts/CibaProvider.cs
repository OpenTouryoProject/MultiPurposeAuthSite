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
//* クラス名        ：CibaProvider
//* クラス日本語名  ：CibaProvider（ライブラリ）
//*
//* 作成日時        ：－
//* 作成者          ：－
//* 更新履歴        ：－
//*
//*  日時        更新者            内容
//*  ----------  ----------------  -------------------------------------------------
//*  2020/03/02  西野 大介         新規
//*  2020/12/16  西野 大介         PostgreSQL疎通（Debugモード）
//**********************************************************************************

using System;
using System.Data;
using System.Collections.Generic;
using System.Collections.Concurrent;

using MultiPurposeAuthSite.Data;
using MultiPurposeAuthSite.Co;

using Newtonsoft.Json;
using Dapper;

using Touryo.Infrastructure.Framework.Authentication;
using Touryo.Infrastructure.Public.Str;
using Touryo.Infrastructure.Public.Security.Pwd;

namespace MultiPurposeAuthSite.Extensions.Sts
{
    /// <summary>CibaProvider</summary>
    public class CibaProvider
    {
        /// <summary>AD無しのテストをする場合、tureに設定。</summary>
        public const bool DebugModeWithOutAD = true;  //false;

        /// <summary>
        /// CibaData
        /// ConcurrentDictionaryは、.NET 4.0の新しいスレッドセーフなHashtable
        /// </summary>
        private static ConcurrentDictionary<string, string>
            CibaData = new ConcurrentDictionary<string, string>();

        #region Create

        /// <summary>Create</summary>
        /// <param name="clientNotificationToken">string</param>
        /// <param name="authReqExp">long</param>
        /// <param name="authZCode">string</param>
        /// <param name="unstructuredData">string</param>
        /// <param name="authReqId">string</param>
        public static void Create(string clientNotificationToken,
            long authReqExp, string authZCode, string unstructuredData, out string authReqId)
        {
            authReqId = ""; // 初期化

            if (Config.EnableCibaGrantType)
            {
                authReqId = CustomEncode.ToBase64UrlString(GetPassword.RandomByte(160));

                // EnableCibaGrantType == true
                switch (Config.UserStoreType)
                {
                    case EnumUserStoreType.Memory:

                        Dictionary<string, string> temp = new Dictionary<string, string>()
                        { 
                            { "authReqId", authReqId },
                            { "authReqExp", authReqExp.ToString() },
                            { "authZCode", authZCode },
                            { "unstructuredData", unstructuredData },
                            { "result", "" }
                        };
                        
                        CibaProvider.CibaData.TryAdd(
                            clientNotificationToken, JsonConvert.SerializeObject(temp));

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
                                        "INSERT INTO [CibaData]"
                                        + " ([ClientNotificationToken], [AuthReqId], [AuthReqExp], [AuthZCode], [UnstructuredData])"
                                        + " VALUES (@ClientNotificationToken, @AuthReqId, @AuthReqExp, @AuthZCode, @UnstructuredData)",
                                        new {
                                            ClientNotificationToken = clientNotificationToken,
                                            AuthReqId = authReqId,
                                            AuthReqExp = authReqExp,
                                            AuthZCode = authZCode,
                                            UnstructuredData = unstructuredData
                                        });
                                     break;

                                case EnumUserStoreType.ODPManagedDriver:

                                    cnn.Execute(
                                        "INSERT INTO \"CibaData\""
                                        + " (\"ClientNotificationToken\", \"AuthReqId\", \"AuthReqExp\", \"AuthZCode\", \"UnstructuredData\")"
                                        + " VALUES (:ClientNotificationToken, :AuthReqId, :AuthReqExp, :AuthZCode, :UnstructuredData)",
                                        new
                                        {
                                            ClientNotificationToken = clientNotificationToken,
                                            AuthReqId = authReqId,
                                            AuthReqExp = authReqExp,
                                            AuthZCode = authZCode,
                                            UnstructuredData = unstructuredData
                                        });

                                    break;

                                case EnumUserStoreType.PostgreSQL:

                                    cnn.Execute(
                                        "INSERT INTO \"cibadata\""
                                        + " (\"clientnotificationtoken\", \"authreqid\", \"authreqexp\", \"authzcode\", \"unstructureddata\")"
                                        + " VALUES (@ClientNotificationToken, @AuthReqId, @AuthReqExp, @AuthZCode, @UnstructuredData)",
                                         new
                                         {
                                             ClientNotificationToken = clientNotificationToken,
                                             AuthReqId = authReqId,
                                             AuthReqExp = authReqExp,
                                             AuthZCode = authZCode,
                                             UnstructuredData = unstructuredData
                                         });

                                    break;
                            }
                        }

                        break;
                }
            }
            else
            {
                // EnableCibaGrantType == false
            }

            return;
        }

        #endregion

        #region ReceiveResult

        /// <summary>ReceiveResult</summary>
        /// <param name="authReqId">string</param>
        /// <param name="result">bool</param>
        public static void ReceiveResult(string authReqId, bool result)
        {
            if (Config.EnableCibaGrantType)
            {
                // EnableCibaGrantType == true

                switch (Config.UserStoreType)
                {
                    case EnumUserStoreType.Memory:

                        foreach (string clientNotificationToken in CibaProvider.CibaData.Keys)
                        {
                            if (CibaProvider.CibaData.ContainsKey(clientNotificationToken))
                            {
                                string temp = CibaProvider.CibaData[clientNotificationToken];
                                if (string.IsNullOrEmpty(temp))
                                {
                                    // 異常レコード
                                    CibaProvider.CibaData.TryRemove(clientNotificationToken, out temp);
                                }
                                else
                                {
                                    // 正常レコード
                                    Dictionary<string, string> dic
                                        = JsonConvert.DeserializeObject<Dictionary<string, string>>(temp);

                                    // 結果の登録
                                    dic["result"] = result.ToString();
                                    CibaProvider.CibaData[clientNotificationToken] = JsonConvert.SerializeObject(dic);

                                }
                            }
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
                            }
                        }

                        break;
                }
            }
            else
            {
                // EnableCibaGrantType == false
            }

            return; // 空振っても呼び出し元は気にしない。
        }

        #endregion

        #region ReceiveTokenReq

        /// <summary>ReceiveTokenReq</summary>
        /// <param name="authReqId">string</param>
        /// <param name="authZCode">string</param>
        /// <param name="states">CibaState</param>
        /// <returns>結果</returns>
        public static bool ReceiveTokenReq(string authReqId, out string authZCode, out OAuth2AndOIDCEnum.CibaState states)
        {
            bool result = false;
            authZCode = "";
            states = OAuth2AndOIDCEnum.CibaState.not_found;

            if (Config.EnableCibaGrantType)
            {
                // EnableCibaGrantType == true

                string temp = "";
                switch (Config.UserStoreType)
                {
                    case EnumUserStoreType.Memory:

                        string clientNotificationToken = "";

                        foreach (string _clientNotificationToken in CibaProvider.CibaData.Keys)
                        {
                            clientNotificationToken = _clientNotificationToken;

                            // レコードあり。
                            temp = CibaProvider.CibaData[_clientNotificationToken];

                            if (string.IsNullOrEmpty(temp))
                            {
                                // 異常レコード
                                states = OAuth2AndOIDCEnum.CibaState.irregularity_data;
                            }
                            else
                            {
                                // 正常レコード
                                Dictionary<string, string> dic
                                    = JsonConvert.DeserializeObject<Dictionary<string, string>>(temp);

                                if (authReqId == dic["authReqId"])
                                {
                                    // Code
                                    authZCode = dic["authZCode"];
                                    // states判別
                                    result = CibaProvider.GetCibaState(dic["authReqExp"], dic["result"], out states);
                                }
                            }
                        }

                        // 削除（pendingのケースを除いて）
                        if (states != OAuth2AndOIDCEnum.CibaState.authorization_pending)
                        {
                            CibaProvider.CibaData.TryRemove(clientNotificationToken, out temp);
                        }

                        break;

                    case EnumUserStoreType.SqlServer:
                    case EnumUserStoreType.ODPManagedDriver:
                    case EnumUserStoreType.PostgreSQL: // DMBMS

                        using (IDbConnection cnn = DataAccess.CreateConnection())
                        {
                            cnn.Open();

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
                                        states = OAuth2AndOIDCEnum.CibaState.not_found;
                                    }
                                    else
                                    {
                                        // Code
                                        authZCode = dyn.AuthZCode;

                                        // states判別
                                        result = CibaProvider.GetCibaState(
                                            ((long)dyn.AuthReqExp).ToString(),
                                            ((bool)dyn.Result).ToString().ToLower(),
                                            out states);
                                    }

                                    // 削除（pendingのケースを除いて）
                                    if (states != OAuth2AndOIDCEnum.CibaState.authorization_pending)
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
                                        states = OAuth2AndOIDCEnum.CibaState.not_found;
                                    }
                                    else
                                    {
                                        // Code
                                        authZCode = dyn.AuthZCode;

                                        // states判別
                                        result = CibaProvider.GetCibaState(
                                            ((long)dyn.AuthReqExp).ToString(),
                                            ((bool)dyn.Result).ToString().ToLower(),
                                            out states);
                                    }

                                    // 削除（pendingのケースを除いて）
                                    if (states != OAuth2AndOIDCEnum.CibaState.authorization_pending)
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
                                        states = OAuth2AndOIDCEnum.CibaState.not_found;
                                    }
                                    else
                                    {
                                        // Code
                                        authZCode = dyn.authzcode;

                                        // states判別
                                        result = CibaProvider.GetCibaState(
                                            ((long)dyn.authreqexp).ToString(),
                                            ((bool)dyn.result).ToString().ToLower(),
                                            out states);
                                    }

                                    // 削除（pendingのケースを除いて）
                                    if (states != OAuth2AndOIDCEnum.CibaState.authorization_pending)
                                    {
                                        cnn.Execute(
                                            "DELETE FROM \"cibadata\" WHERE \"authreqid\" = @AuthReqId",
                                            new { AuthReqId = authReqId });
                                    }

                                    break;
                            }
                        }

                        break;
                }
            }
            else
            {
                // EnableCibaGrantType == false
            }

            return result;
        }

        /// <summary>hogehoge</summary>
        /// <param name="authReqExp">string</param>
        /// <param name="result">string</param>
        /// <param name="states">CibaState</param>
        /// <returns>bool</returns>
        private static bool GetCibaState(string authReqExp, string result, out OAuth2AndOIDCEnum.CibaState states)
        {
            bool _result = false;

            if (string.IsNullOrEmpty(authReqExp))
            {
                // 異常
                states = OAuth2AndOIDCEnum.CibaState.irregularity_data;
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
                        states = OAuth2AndOIDCEnum.CibaState.authorization_pending;
                    }
                    else
                    {
                        // 既応答
                        if (bool.TryParse(result, out _result))
                        {
                            // = bool
                            if (_result)
                            {
                                states = OAuth2AndOIDCEnum.CibaState.access_permitted;
                                _result = true; // 唯一の正常ケース
                            }
                            else
                            {
                                states = OAuth2AndOIDCEnum.CibaState.access_denied;
                            }
                        }
                        else
                        {
                            // ≠ bool
                            states = OAuth2AndOIDCEnum.CibaState.irregularity_data;
                        }
                    }
                }
                else
                {
                    // 期限外
                    states = OAuth2AndOIDCEnum.CibaState.expired_token;
                }
            }

            return _result;
        }

        #endregion
    }
}