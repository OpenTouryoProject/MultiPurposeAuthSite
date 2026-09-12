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
//*  2026/09/13  玄人 幸道         CIBAの返答に所有者確認を追加。メモリ ストアの取り違えも修正
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
        public const bool DebugModeWithOutAD = false;

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
        /// <param name="userId">
        /// 承認する利用者の ApplicationUser.Id（login_hint で解決した利用者）。
        /// **誰宛ての要求かを記録する。** ReceiveResult が、返答者と突き合わせるために使う。
        /// PPID により sub はクライアントごとに変わるので、利用者に固定な Id を使う。
        /// </param>
        /// <param name="authReqId">string</param>
        public static void Create(string clientNotificationToken,
            long authReqExp, string authZCode, string unstructuredData, string userId, out string authReqId)
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
                            { "userId", userId },
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
                                        + " ([ClientNotificationToken], [AuthReqId], [AuthReqExp], [AuthZCode], [UnstructuredData], [UserId])"
                                        + " VALUES (@ClientNotificationToken, @AuthReqId, @AuthReqExp, @AuthZCode, @UnstructuredData, @UserId)",
                                        new {
                                            ClientNotificationToken = clientNotificationToken,
                                            AuthReqId = authReqId,
                                            AuthReqExp = authReqExp,
                                            AuthZCode = authZCode,
                                            UnstructuredData = unstructuredData,
                                            UserId = userId
                                        });
                                     break;

                                case EnumUserStoreType.ODPManagedDriver:

                                    cnn.Execute(
                                        "INSERT INTO \"CibaData\""
                                        + " (\"ClientNotificationToken\", \"AuthReqId\", \"AuthReqExp\", \"AuthZCode\", \"UnstructuredData\", \"UserId\")"
                                        + " VALUES (:ClientNotificationToken, :AuthReqId, :AuthReqExp, :AuthZCode, :UnstructuredData, :UserId)",
                                        new
                                        {
                                            ClientNotificationToken = clientNotificationToken,
                                            AuthReqId = authReqId,
                                            AuthReqExp = authReqExp,
                                            AuthZCode = authZCode,
                                            UnstructuredData = unstructuredData,
                                            UserId = userId
                                        });

                                    break;

                                case EnumUserStoreType.PostgreSQL:

                                    cnn.Execute(
                                        "INSERT INTO \"cibadata\""
                                        + " (\"clientnotificationtoken\", \"authreqid\", \"authreqexp\", \"authzcode\", \"unstructureddata\", \"userid\")"
                                        + " VALUES (@ClientNotificationToken, @AuthReqId, @AuthReqExp, @AuthZCode, @UnstructuredData, @UserId)",
                                         new
                                         {
                                             ClientNotificationToken = clientNotificationToken,
                                             AuthReqId = authReqId,
                                             AuthReqExp = authReqExp,
                                             AuthZCode = authZCode,
                                             UnstructuredData = unstructuredData,
                                             UserId = userId
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
        /// <param name="userId">
        /// 返答した利用者の ApplicationUser.Id（Bearer トークンから解決した利用者）。
        /// **Create で記録した宛先と一致しなければ、書き込まない。**
        /// </param>
        /// <param name="result">bool</param>
        /// <returns>
        /// 書き込んだら true。
        /// **見つからない場合と、自分宛てでない場合を区別しない**（どちらも false）。
        /// 区別すると、auth_req_id の存在を推測させる。
        /// </returns>
        public static bool ReceiveResult(string authReqId, string userId, bool result)
        {
            bool retVal = false;

            if (Config.EnableCibaGrantType)
            {
                // EnableCibaGrantType == true

                switch (Config.UserStoreType)
                {
                    case EnumUserStoreType.Memory:

                        // **authReqId で 1 件だけを特定する。**
                        //   以前はここで authReqId を見ておらず、保留中の全レコードに
                        //   結果を書き込んでいた（別の利用者の要求にも波及した）。
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

                                    if (authReqId != dic["authReqId"])
                                    {
                                        // 別の要求
                                        continue;
                                    }

                                    if (!CibaProvider.IsSameUser(dic, userId))
                                    {
                                        // **宛先が違う。** 他人の要求には返答できない。
                                        break;
                                    }

                                    // 結果の登録
                                    dic["result"] = result.ToString();
                                    CibaProvider.CibaData[clientNotificationToken] = JsonConvert.SerializeObject(dic);
                                    retVal = true;

                                    break;
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

                                    retVal = 0 < cnn.Execute(
                                        "UPDATE [CibaData] SET [Result] = @Result"
                                        + " WHERE [AuthReqId] = @AuthReqId AND [UserId] = @UserId",
                                        new { AuthReqId = authReqId, UserId = userId, Result = result });

                                    break;

                                case EnumUserStoreType.ODPManagedDriver:

                                    retVal = 0 < cnn.Execute(
                                        "UPDATE \"CibaData\" SET \"Result\" = :Result"
                                        + " WHERE \"AuthReqId\" = :AuthReqId AND \"UserId\" = :UserId",
                                        new { AuthReqId = authReqId, UserId = userId, Result = result });

                                    break;

                                case EnumUserStoreType.PostgreSQL:

                                    retVal = 0 < cnn.Execute(
                                        "UPDATE \"cibadata\" SET \"result\" = @Result"
                                        + " WHERE \"authreqid\" = @AuthReqId AND \"userid\" = @UserId",
                                        new { AuthReqId = authReqId, UserId = userId, Result = result });

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

            // **空振りは、呼び出し元に伝える。**
            //   以前は void で、未知の auth_req_id でも成功（200 / OK）に見えていた。
            return retVal;
        }

        /// <summary>レコードの宛先が、返答した利用者と一致するか</summary>
        /// <param name="dic">CibaData のレコード</param>
        /// <param name="userId">返答した利用者の ApplicationUser.Id</param>
        /// <returns>一致すれば true</returns>
        /// <remarks>
        /// **記録が無いレコードは、一致しないものとして扱う。**
        /// 本修正より前に作られた保留中のレコードには userId が無い。
        /// 「記録が無ければ通す」にすると、確認を入れた意味がなくなる。
        /// </remarks>
        private static bool IsSameUser(Dictionary<string, string> dic, string userId)
        {
            string temp;

            if (!dic.TryGetValue("userId", out temp) || string.IsNullOrEmpty(temp))
            {
                return false;
            }

            return temp == userId;
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
            bool retVal = false;
            authZCode = "";
            states = OAuth2AndOIDCEnum.CibaState.not_found;

            if (Config.EnableCibaGrantType)
            {
                // EnableCibaGrantType == true

                string temp = "";
                switch (Config.UserStoreType)
                {
                    case EnumUserStoreType.Memory:

                        // **一致したレコードのキーだけを覚える。**
                        //   以前はループ変数に最後に残ったキーを消しており、
                        //   一致したものとは別の保留要求を削除しうる状態だった。
                        string clientNotificationToken = null;

                        foreach (string _clientNotificationToken in CibaProvider.CibaData.Keys)
                        {
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
                                    clientNotificationToken = _clientNotificationToken;

                                    // Code
                                    authZCode = dic["authZCode"];
                                    // CibaState
                                    retVal = CibaProvider.GetState(dic["authReqExp"], dic["result"], out states);

                                    break;
                                }
                            }
                        }

                        // 削除（pendingのケースを除いて）
                        if (clientNotificationToken != null
                            && states != OAuth2AndOIDCEnum.CibaState.authorization_pending)
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
                                        retVal = CibaProvider.GetState(
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
                                        retVal = CibaProvider.GetState(
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
                                        retVal = CibaProvider.GetState(
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

            return retVal;
        }

        #endregion

        #region GetState

        /// <summary>GetState</summary>
        /// <param name="authReqExp">string</param>
        /// <param name="result">string</param>
        /// <param name="states">CibaState</param>
        /// <returns>bool</returns>
        private static bool GetState(string authReqExp, string result, out OAuth2AndOIDCEnum.CibaState states)
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