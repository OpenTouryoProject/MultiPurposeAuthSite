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
//*  2026/09/11  玄人 幸道         使用済み・発行していない device_code で HTTP 500 になる問題を修正（#199）
//*  2026/09/13  玄人 幸道         SQL系: 行なしで500になる不具合と、Result(NULL)のキャストを修正（#207で判明）
//*  2026/09/13  玄人 幸道         Oracle: Result(NUMBER(3))の読み出しをConvertで正規化（#207で判明）
//*  2026/09/13  玄人 幸道         Oracle: AuthReqExp(decimal)のlongへの明示キャスト（#207で判明）
//*  2026/10/01  玄人 幸道         codeのidentityに利用者名を入れる（subではない）（#151 の段階 4）
//*  2026/10/16  玄人 幸道         速すぎるポーリングに slow_down を返す（#305 の段階 1）
//*  2026/11/03  玄人 幸道         列の幅を超える値は、引かずに「無い」とする（Oracle で 500 になっていた。#331）
//*  2026/11/14  玄人 幸道         device_code を出したクライアント（TempData の client_id）と、トークン要求のクライアントが違えば、記録に触れずに not_found を返す（RFC 6749 §5.2。#387）
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

        #region Public

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
                            { Const.PollingUserCode, userCode },
                            { Const.PollingAuthReqExp, authReqExp.ToString() },
                            { Const.PollingTempData, tempData },
                            { Const.PollingResult, "" }
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

                //  **列の幅（10）を超える値は、引くまでもなく「無い」**（#331。Oracle は例外にする）。
                if (!MultiPurposeAuthSite.Data.CmnStore.IsSearchable(userCode, 10))
                {
                    return retVal;
                }

                switch (Config.UserStoreType)
                {
                    case EnumUserStoreType.Memory:

                        foreach (string deviceCode in DeviceAuthZProvider.DeviceAuthZData.Keys)
                        {
                            // 列挙した後に、トークン要求側（ReceiveTokenReq）が削除していることがある。
                            // 索引子で読むと KeyNotFoundException になるので TryGetValue で読む（#199）。
                            string temp;
                            if (!DeviceAuthZProvider.DeviceAuthZData.TryGetValue(deviceCode, out temp))
                            {
                                continue;
                            }

                            Dictionary<string, string> dic
                                = JsonConvert.DeserializeObject<Dictionary<string, string>>(temp);

                            string _userCode = dic[Const.PollingUserCode];

                            if (userCode == _userCode)
                            {
                                string tempData = dic[Const.PollingTempData];

                                Dictionary<string, string> tempdic
                                     = JsonConvert.DeserializeObject<Dictionary<string, string>>(tempData);

                                string code = DeviceAuthZProvider.GetCode(userName, tempdic);

                                // 更新
                                dic[Const.PollingAuthZCode] = code;
                                dic[Const.PollingResult] = result.ToString();

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

                            dynamic dyn = null;
                            switch (Config.UserStoreType)
                            {
                                case EnumUserStoreType.SqlServer:

                                    // 参照
                                    dyn = cnn.QueryFirstOrDefault(
                                        "SELECT [TempData]"
                                         + " FROM [DeviceAuthZData]"
                                         + " WHERE [UserCode] = @UserCode",
                                        new { UserCode = userCode });

                                    if (dyn == null)
                                    {
                                        // レコードなし。
                                    }
                                    else
                                    {
                                        // レコードあり。
                                        string tempData = dyn.TempData;

                                        Dictionary<string, string> tempdic
                                             = JsonConvert.DeserializeObject<Dictionary<string, string>>(tempData);

                                        string code = DeviceAuthZProvider.GetCode(userName, tempdic);

                                        // 更新
                                        cnn.Execute(
                                            "UPDATE [DeviceAuthZData]"
                                            + " SET [AuthZCode] = @AuthZCode, [Result] = @Result"
                                            + " WHERE [UserCode] = @UserCode",
                                            new { UserCode = userCode, AuthZCode = code, Result = result });
                                        retVal = true;
                                    }

                                    break;

                                case EnumUserStoreType.ODPManagedDriver:

                                    // 参照
                                    dyn = cnn.QueryFirstOrDefault(
                                        "SELECT \"TempData\""
                                         + " FROM \"DeviceAuthZData\""
                                         + " WHERE \"UserCode\" = :UserCode",
                                        new { UserCode = userCode });

                                    if (dyn == null)
                                    {
                                        // レコードなし。
                                    }
                                    else
                                    {
                                        // レコードあり。
                                        string tempData = dyn.TempData;

                                        Dictionary<string, string> tempdic
                                             = JsonConvert.DeserializeObject<Dictionary<string, string>>(tempData);

                                        string code = DeviceAuthZProvider.GetCode(userName, tempdic);

                                        // 更新
                                        cnn.Execute(
                                            "UPDATE \"DeviceAuthZData\""
                                            + " SET \"AuthZCode\" = :AuthZCode, \"Result\" = :Result"
                                            + " WHERE \"UserCode\" = :UserCode",
                                            new { UserCode = userCode, AuthZCode = code, Result = result });
                                        retVal = true;
                                    }

                                    break;

                                case EnumUserStoreType.PostgreSQL:

                                    // 参照
                                    dyn = cnn.QueryFirstOrDefault(
                                        "SELECT \"tempdata\""
                                         + " FROM \"deviceauthzdata\""
                                         + " WHERE \"usercode\" = @UserCode",
                                        new { UserCode = userCode });

                                    if (dyn == null)
                                    {
                                        // レコードなし。
                                    }
                                    else
                                    {
                                        // レコードあり。
                                        string tempData = dyn.tempdata;

                                        Dictionary<string, string> tempdic
                                             = JsonConvert.DeserializeObject<Dictionary<string, string>>(tempData);

                                        string code = DeviceAuthZProvider.GetCode(userName, tempdic);

                                        // 更新
                                        cnn.Execute(
                                            "UPDATE \"deviceauthzdata\""
                                            + " SET \"authzcode\" = @AuthZCode, \"result\" = @Result"
                                            + " WHERE \"usercode\" = @UserCode",
                                            new { UserCode = userCode, AuthZCode = code, Result = result });
                                        retVal = true;
                                    }

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

            return retVal;
        }

        #endregion

        #region ReceiveTokenReq

        /// <summary>前回から interval 未満なら true（= slow_down）</summary>
        /// <param name="lastPolledAt">前回の UNIX 時刻（無ければ null）</param>
        /// <returns>速すぎれば true</returns>
        /// <remarks>
        /// **判定そのものは `PollingThrottle`**（CIBA と同じものを使う）。
        /// **ここは「どの interval を使うか」だけ**を決める。
        /// </remarks>
        private static bool ThrottlePolling(long? lastPolledAt)
        {
            return PollingThrottle.TooFast(
                lastPolledAt, Config.DeviceAuthZPollingIntervalSeconds);
        }

        /// <summary>device_code を、このクライアントに出したか（#387）</summary>
        /// <param name="tempData">記録の TempData（device_authz の要求の内容。JSON）</param>
        /// <param name="clientId">トークン要求で認証したクライアント</param>
        /// <returns>同じなら true（**読めない・どちらかが空なら false**）</returns>
        private static bool IsIssuedTo(string tempData, string clientId)
        {
            if (string.IsNullOrEmpty(tempData) || string.IsNullOrEmpty(clientId))
            {
                return false;
            }

            try
            {
                Dictionary<string, string> tempdic =
                    JsonConvert.DeserializeObject<Dictionary<string, string>>(tempData);

                return tempdic != null
                    && tempdic.TryGetValue(OAuth2AndOIDCConst.client_id, out string issuedTo)
                    && !string.IsNullOrEmpty(issuedTo)
                    && issuedTo == clientId;
            }
            catch (JsonException)
            {
                // 読めない記録は、照合できないので断る。
                return false;
            }
        }

        /// <summary>ReceiveTokenReq</summary>
        /// <param name="deviceCode">string</param>
        /// <param name="clientId">トークン要求で認証したクライアント（#387）</param>
        /// <param name="authZCode">string</param>
        /// <param name="states">DeviceAuthZState</param>
        /// <returns>結果</returns>
        /// <remarks>
        /// **device_code を出したクライアントと違えば、`not_found` を返し、記録に触れない**（#387）。
        /// RFC 8628 §3.5 は RFC 6749 §5.2 のエラーを使い、§5.2 の `invalid_grant` は「issued to another client」を含む
        /// （呼び出し側が `not_found` を `invalid_grant` にする）。
        /// **以前は照合せずに、状態を返し、ポーリングの時刻を書き換え、承認済みなら記録を消していた**（CIBA と同じ形）。
        /// **照合は、状態を見る前に行う。** 記録の `TempData` の `client_id`（device_authz で受けたもの）と比べる。
        /// </remarks>
        public static bool ReceiveTokenReq(
            string deviceCode, string clientId, out string authZCode, out OAuth2AndOIDCEnum.DeviceAuthZState states)
        {
            bool retVal = false;
            authZCode = "";
            states = OAuth2AndOIDCEnum.DeviceAuthZState.not_found;

            if (Config.EnableDeviceAuthZGrantType)
            {
                // EnableDeviceAuthZGrantType == true

                string temp = "";
                //  **列の幅（38）を超える値は、引くまでもなく「無い」**（#331。Oracle は例外にする）。
                if (!MultiPurposeAuthSite.Data.CmnStore.IsSearchable(deviceCode, 38))
                {
                    return retVal;
                }

                switch (Config.UserStoreType)
                {
                    case EnumUserStoreType.Memory:

                        // 使用済み（トークンを渡した時点で削除済み）・発行していない device_code は、キーが無い。
                        // 索引子で読むと KeyNotFoundException → HTTP 500 になる。
                        // null のキーも ConcurrentDictionary は例外にするので、先に弾く（#199）。
                        if (string.IsNullOrEmpty(deviceCode)
                            || !DeviceAuthZProvider.DeviceAuthZData.TryGetValue(deviceCode, out temp))
                        {
                            // 見つからない（states は not_found のまま）
                            break;
                        }

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

                            //  **別のクライアントに出したものなら、記録に触れずに「無い」とする**（#387）。
                            if (!DeviceAuthZProvider.IsIssuedTo(
                                dic.TryGetValue(Const.PollingTempData, out string tempData) ? tempData : "",
                                clientId))
                            {
                                states = OAuth2AndOIDCEnum.DeviceAuthZState.not_found;
                                break;
                            }

                            // 結果の判別
                            if (DeviceAuthZProvider.GetState(dic[Const.PollingAuthReqExp], dic[Const.PollingResult], out states))
                            {
                                // Code
                                authZCode = dic[Const.PollingAuthZCode];
                                // retVal
                                retVal = true;
                            }

                            //  **速すぎるポーリングには slow_down を返す**（#305 の段階 1）。
                            //    **記録は辞書の中**（`lastPolled`。**無ければ初回**）。
                            if (states == OAuth2AndOIDCEnum.DeviceAuthZState.authorization_pending)
                            {
                                long? last = null;
                                string lastPolled = dic.ContainsKey(Const.PollingLastPolled) ? dic[Const.PollingLastPolled] : "";

                                long parsed = 0;
                                if (!string.IsNullOrEmpty(lastPolled) && long.TryParse(lastPolled, out parsed))
                                {
                                    last = parsed;
                                }

                                bool tooFast = PollingThrottle.TooFast(
                                    last, Config.DeviceAuthZPollingIntervalSeconds);

                                dic[Const.PollingLastPolled] = PollingThrottle.NowUnixSeconds().ToString();
                                DeviceAuthZProvider.DeviceAuthZData[deviceCode] =
                                    JsonConvert.SerializeObject(dic);

                                if (tooFast)
                                {
                                    states = OAuth2AndOIDCEnum.DeviceAuthZState.slow_down;
                                    //  **コードは渡さない**（まだ承認されていない）。
                                    authZCode = "";
                                    retVal = false;
                                }
                            }
                        }

                        //  **削除（pending と slow_down のケースを除いて）。**
                        //    **slow_down はまだ pending** なので、消してはいけない（#305 の段階 1）。
                        if (states != OAuth2AndOIDCEnum.DeviceAuthZState.authorization_pending
                            && states != OAuth2AndOIDCEnum.DeviceAuthZState.slow_down)
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
                            
                            dynamic dyn = null;
                            switch (Config.UserStoreType)
                            {   
                                case EnumUserStoreType.SqlServer:

                                    // 参照
                                    dyn = cnn.QueryFirstOrDefault(
                                        "SELECT [AuthReqExp], [AuthZCode], [Result], [LastPolledAt], [TempData]"
                                        + " FROM [DeviceAuthZData]"
                                        + " WHERE [DeviceCode] = @DeviceCode",
                                        new { DeviceCode = deviceCode });

                                    if (dyn == null || !DeviceAuthZProvider.IsIssuedTo((string)dyn.TempData, clientId))
                                    {
                                        // レコードなし、または別のクライアントに出したもの（#387）。
                                        //   **記録に触れずに返す**（下の更新・削除をしない）。
                                        states = OAuth2AndOIDCEnum.DeviceAuthZState.not_found;
                                        break;
                                    }
                                    else
                                    {
                                        // レコードあり。
                                        long authReqExp = dyn.AuthReqExp;

                                        // **Result は未応答のとき NULL。** キャストすると落ちる。
                                        //   GetState は空文字を「未応答」として扱い、
                                        //   authorization_pending を返す。
                                        string result = (dyn.Result == null)
                                            ? "" : ((bool)dyn.Result).ToString();

                                        // 結果の判別
                                        if (DeviceAuthZProvider.GetState(
                                            authReqExp.ToString(), result, out states))
                                        {
                                            // Code
                                            authZCode = dyn.AuthZCode;
                                            // retVal
                                            retVal = true;
                                        }
                                    }

                                    //  **速すぎるポーリングには slow_down を返す**（#305 の段階 1）。
                                    if (states == OAuth2AndOIDCEnum.DeviceAuthZState.authorization_pending)
                                    {
                                        if (DeviceAuthZProvider.ThrottlePolling(
                                            (dyn.LastPolledAt == null) ? (long?)null : (long)dyn.LastPolledAt))
                                        {
                                            states = OAuth2AndOIDCEnum.DeviceAuthZState.slow_down;
                                            authZCode = "";
                                            retVal = false;
                                        }

                                        cnn.Execute(
                                            "UPDATE [DeviceAuthZData] SET [LastPolledAt] = @LastPolledAt" +
                                            " WHERE [DeviceCode] = @DeviceCode",
                                            new
                                            {
                                                DeviceCode = deviceCode,
                                                LastPolledAt = PollingThrottle.NowUnixSeconds()
                                            });
                                    }

                                    //  **削除（pending と slow_down のケースを除いて）。**
                                    if (states != OAuth2AndOIDCEnum.DeviceAuthZState.authorization_pending
                                        && states != OAuth2AndOIDCEnum.DeviceAuthZState.slow_down)
                                    {
                                        cnn.Execute(
                                            "DELETE FROM [DeviceAuthZData]" +
                                            " WHERE [DeviceCode] = @DeviceCode",
                                            new { DeviceCode = deviceCode });
                                    }

                                    break;

                                case EnumUserStoreType.ODPManagedDriver:

                                    // 参照
                                    dyn = cnn.QueryFirstOrDefault(
                                        "SELECT \"AuthReqExp\", \"AuthZCode\", \"Result\", \"LastPolledAt\", \"TempData\""
                                        + " FROM \"DeviceAuthZData\""
                                        + " WHERE \"DeviceCode\" = :DeviceCode",
                                        new { DeviceCode = deviceCode });

                                    if (dyn == null || !DeviceAuthZProvider.IsIssuedTo((string)dyn.TempData, clientId))
                                    {
                                        // レコードなし、または別のクライアントに出したもの（#387）。
                                        //   **記録に触れずに返す**（下の更新・削除をしない）。
                                        states = OAuth2AndOIDCEnum.DeviceAuthZState.not_found;
                                        break;
                                    }
                                    else
                                    {
                                        // レコードあり。
                                        // **Oracle の NUMBER は decimal で返る。**
                                        //   dynamic 経由の暗黙変換は通らず、
                                        //   RuntimeBinderException になる（#207 で実測）。
                                        //   CibaProvider も ((long)dyn.AuthReqExp) と明示している。
                                        long authReqExp = (long)dyn.AuthReqExp;

                                        // **Result は未応答のとき NULL。** キャストすると落ちる。
                                        //   GetState は空文字を「未応答」として扱い、
                                        //   authorization_pending を返す。
                                        // **Oracle に boolean が無い。** Result は NUMBER(3) で 0 / 1 / NULL。
                                        //   ((bool)...) では変換できず、bool.TryParse が失敗して
                                        //   irregularity_data になる（#207 で実測）。
                                        string result = (dyn.Result == null)
                                            ? "" : Convert.ToBoolean(dyn.Result).ToString();

                                        // 結果の判別
                                        if (DeviceAuthZProvider.GetState(
                                            authReqExp.ToString(), result, out states))
                                        {
                                            // Code
                                            authZCode = dyn.AuthZCode;
                                            // retVal
                                            retVal = true;
                                        }
                                    }

                                    //  **速すぎるポーリングには slow_down を返す**（#305 の段階 1）。
                                    //    **Oracle の NUMBER は decimal で返る**ので、Convert を通す。
                                    if (states == OAuth2AndOIDCEnum.DeviceAuthZState.authorization_pending)
                                    {
                                        if (DeviceAuthZProvider.ThrottlePolling(
                                            (dyn.LastPolledAt == null)
                                                ? (long?)null : Convert.ToInt64(dyn.LastPolledAt)))
                                        {
                                            states = OAuth2AndOIDCEnum.DeviceAuthZState.slow_down;
                                            authZCode = "";
                                            retVal = false;
                                        }

                                        cnn.Execute(
                                            "UPDATE \"DeviceAuthZData\" SET \"LastPolledAt\" = :LastPolledAt" +
                                            " WHERE \"DeviceCode\" = :DeviceCode",
                                            new
                                            {
                                                DeviceCode = deviceCode,
                                                LastPolledAt = PollingThrottle.NowUnixSeconds()
                                            });
                                    }

                                    //  **削除（pending と slow_down のケースを除いて）。**
                                    if (states != OAuth2AndOIDCEnum.DeviceAuthZState.authorization_pending
                                        && states != OAuth2AndOIDCEnum.DeviceAuthZState.slow_down)
                                    {
                                        cnn.Execute(
                                            "DELETE FROM \"DeviceAuthZData\"" +
                                            " WHERE \"DeviceCode\" = :DeviceCode",
                                            new { DeviceCode = deviceCode });
                                    }

                                    break;

                                case EnumUserStoreType.PostgreSQL:

                                    // 参照
                                    dyn = cnn.QueryFirstOrDefault(
                                        "SELECT \"authreqexp\", \"authzcode\", \"result\", \"lastpolledat\", \"tempdata\""
                                        + " FROM \"deviceauthzdata\""
                                        + " WHERE \"devicecode\" = @DeviceCode",
                                        new { DeviceCode = deviceCode });

                                    if (dyn == null || !DeviceAuthZProvider.IsIssuedTo((string)dyn.tempdata, clientId))
                                    {
                                        // レコードなし、または別のクライアントに出したもの（#387）。
                                        //   **記録に触れずに返す**（下の更新・削除をしない）。
                                        states = OAuth2AndOIDCEnum.DeviceAuthZState.not_found;
                                        break;
                                    }
                                    else
                                    {
                                        // レコードあり。
                                        long authReqExp = dyn.authreqexp;

                                        // **Result は未応答のとき NULL。** キャストすると落ちる。
                                        //   GetState は空文字を「未応答」として扱い、
                                        //   authorization_pending を返す。
                                        string result = (dyn.result == null)
                                            ? "" : ((bool)dyn.result).ToString();

                                        // 結果の判別
                                        if (DeviceAuthZProvider.GetState(
                                            authReqExp.ToString(), result, out states))
                                        {
                                            // Code
                                            authZCode = dyn.authzcode;
                                            // retVal
                                            retVal = true;
                                        }
                                    }

                                    //  **速すぎるポーリングには slow_down を返す**（#305 の段階 1）。
                                    if (states == OAuth2AndOIDCEnum.DeviceAuthZState.authorization_pending)
                                    {
                                        if (DeviceAuthZProvider.ThrottlePolling(
                                            (dyn.lastpolledat == null)
                                                ? (long?)null : (long)dyn.lastpolledat))
                                        {
                                            states = OAuth2AndOIDCEnum.DeviceAuthZState.slow_down;
                                            authZCode = "";
                                            retVal = false;
                                        }

                                        cnn.Execute(
                                            "UPDATE \"deviceauthzdata\" SET \"lastpolledat\" = @LastPolledAt" +
                                            " WHERE \"devicecode\" = @DeviceCode",
                                            new
                                            {
                                                DeviceCode = deviceCode,
                                                LastPolledAt = PollingThrottle.NowUnixSeconds()
                                            });
                                    }

                                    //  **削除（pending と slow_down のケースを除いて）。**
                                    if (states != OAuth2AndOIDCEnum.DeviceAuthZState.authorization_pending
                                        && states != OAuth2AndOIDCEnum.DeviceAuthZState.slow_down)
                                    {
                                        cnn.Execute(
                                            "DELETE FROM \"deviceauthzdata\"" +
                                            " WHERE \"devicecode\" = @DeviceCode",
                                            new { DeviceCode = deviceCode });
                                    }

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

            return retVal;
        }

        #endregion

        #endregion

        #region Private

        #region GetCode

        /// <summary>GetCode</summary>
        /// <param name="userName">string</param>
        /// <param name="tempdic">Dictionary(string, string)</param>
        /// <returns>Code</returns>
        private static string GetCode(string userName, Dictionary<string, string> tempdic)
        {
            string client_id = tempdic[OAuth2AndOIDCConst.client_id];
            string scope = tempdic[OAuth2AndOIDCConst.scope];

            // **identity.Name に入れるのは利用者名**（#151 の段階 4）。
            //   **sub を入れてはいけない。** sub は利用者 ID（または PPID）であり、
            //   **CmnAccessToken が identity.Name から改めて sub を作る**ため、
            //   入れると token エンドポイントで利用者を引けなくなる。
            return Token.CmnEndpoints.CreateCodeInAuthZNRes(
                new ClaimsIdentity(new GenericIdentity(userName)), new NameValueCollection(),
                client_id, "", (scope ?? "").Split(' '), null, "");
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
        
        #endregion
    }
}