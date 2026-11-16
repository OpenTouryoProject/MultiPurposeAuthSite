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
//*  2026/09/13  玄人 幸道         SQL系: 行なしで500になる不具合と、Result(NULL)のキャストを修正（#207で判明）
//*  2026/09/13  玄人 幸道         Oracle: Result(NUMBER(3))の読み出しをConvertで正規化（#207で判明）
//*  2026/10/16  玄人 幸道         速すぎるポーリングに slow_down を返す（#305 の段階 1）
//*  2026/11/02  玄人 幸道         client_notification_token を保存のキーに使わない（poll で 500。#328）
//*  2026/11/03  玄人 幸道         列の幅を超える値は、引かずに「無い」とする（Oracle で 500 になっていた。#331）
//*  2026/11/14  玄人 幸道         auth_req_id を出したクライアント（ClientID）を記録し、トークン要求のクライアントと違えば記録に触れずに not_found を返す（CIBA Core 1.0 §11。#387）
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
        /// <param name="authReqExp">long</param>
        /// <param name="authZCode">string</param>
        /// <param name="unstructuredData">string</param>
        /// <param name="userId">
        /// 承認する利用者の ApplicationUser.Id（login_hint で解決した利用者）。
        /// **誰宛ての要求かを記録する。** ReceiveResult が、返答者と突き合わせるために使う。
        /// PPID により sub はクライアントごとに変わるので、利用者に固定な Id を使う。
        /// </param>
        /// <param name="clientId">
        /// auth_req_id を出したクライアントの client_id（#387）。
        /// **トークン要求のクライアントと突き合わせる**（`ReceiveTokenReq`。CIBA Core 1.0 §11）。
        /// </param>
        /// <param name="authReqId">string</param>
        //  **`client_notification_token` は保存しない**（#328）。
        //    **この実装は poll だけを扱い**、この値は ping / push の通知にしか使わない（CIBA Core §7.1）ので、読む箇所が無い。
        //    **poll では値が無い**ので、`NOT NULL` で一意の `ClientNotificationToken` 列に入れると 500 になっていた
        //    （mem では辞書のキーが衝突し、2 件目が黙って保存されなかった）。
        //    **その列には、一意な乱数である `auth_req_id` を入れる。** 列の名前と中身は合わないが、DDL を変えずに済む。
        //    **ping / push を実装するときは、DDL を変えて、本来の値を持たせる。**
        public static void Create(
            long authReqExp, string authZCode, string unstructuredData, string userId, string clientId,
            out string authReqId)
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
                            { Const.PollingAuthReqId, authReqId },
                            { Const.PollingAuthReqExp, authReqExp.ToString() },
                            { Const.PollingAuthZCode, authZCode },
                            { "unstructuredData", unstructuredData },
                            { Const.PollingUserId, userId },
                            { Const.PollingClientId, clientId },
                            { Const.PollingResult, "" }
                        };
                        
                        CibaProvider.CibaData.TryAdd(
                            authReqId, JsonConvert.SerializeObject(temp));

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
                                        + " ([ClientNotificationToken], [AuthReqId], [AuthReqExp], [AuthZCode], [UnstructuredData], [UserId], [ClientID])"
                                        + " VALUES (@ClientNotificationToken, @AuthReqId, @AuthReqExp, @AuthZCode, @UnstructuredData, @UserId, @ClientID)",
                                        new {
                                            ClientNotificationToken = authReqId,
                                            AuthReqId = authReqId,
                                            AuthReqExp = authReqExp,
                                            AuthZCode = authZCode,
                                            UnstructuredData = unstructuredData,
                                            UserId = userId,
                                            ClientID = clientId
                                        });
                                     break;

                                case EnumUserStoreType.ODPManagedDriver:

                                    cnn.Execute(
                                        "INSERT INTO \"CibaData\""
                                        + " (\"ClientNotificationToken\", \"AuthReqId\", \"AuthReqExp\", \"AuthZCode\", \"UnstructuredData\", \"UserId\", \"ClientID\")"
                                        + " VALUES (:ClientNotificationToken, :AuthReqId, :AuthReqExp, :AuthZCode, :UnstructuredData, :UserId, :ClientID)",
                                        new
                                        {
                                            ClientNotificationToken = authReqId,
                                            AuthReqId = authReqId,
                                            AuthReqExp = authReqExp,
                                            AuthZCode = authZCode,
                                            UnstructuredData = unstructuredData,
                                            UserId = userId,
                                            ClientID = clientId
                                        });

                                    break;

                                case EnumUserStoreType.PostgreSQL:

                                    cnn.Execute(
                                        "INSERT INTO \"cibadata\""
                                        + " (\"clientnotificationtoken\", \"authreqid\", \"authreqexp\", \"authzcode\", \"unstructureddata\", \"userid\", \"clientid\")"
                                        + " VALUES (@ClientNotificationToken, @AuthReqId, @AuthReqExp, @AuthZCode, @UnstructuredData, @UserId, @ClientID)",
                                         new
                                         {
                                             ClientNotificationToken = authReqId,
                                             AuthReqId = authReqId,
                                             AuthReqExp = authReqExp,
                                             AuthZCode = authZCode,
                                             UnstructuredData = unstructuredData,
                                             UserId = userId,
                                             ClientID = clientId
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

                                    if (authReqId != dic[Const.PollingAuthReqId])
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
                                    dic[Const.PollingResult] = result.ToString();
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

            if (!dic.TryGetValue(Const.PollingUserId, out temp) || string.IsNullOrEmpty(temp))
            {
                return false;
            }

            return temp == userId;
        }

        #endregion

        #region ReceiveTokenReq

        /// <summary>前回から interval 未満なら true（= slow_down）</summary>
        /// <param name="lastPolledAt">前回の UNIX 時刻（無ければ null）</param>
        /// <returns>速すぎれば true</returns>
        /// <remarks>
        /// **判定そのものは `PollingThrottle`**（Device Authorization Grant と同じものを使う）。
        /// **ここは「どの interval を使うか」だけ**を決める。
        /// </remarks>
        private static bool ThrottlePolling(long? lastPolledAt)
        {
            return PollingThrottle.TooFast(
                lastPolledAt, Config.CibaPollingIntervalSeconds);
        }

        /// <summary>auth_req_id を、このクライアントに出したか（#387）</summary>
        /// <param name="issuedTo">記録した client_id（列を足す前の記録では空）</param>
        /// <param name="clientId">トークン要求で認証したクライアント</param>
        /// <returns>同じなら true（**どちらかが空なら false**）</returns>
        private static bool IsIssuedTo(string issuedTo, string clientId)
        {
            return !string.IsNullOrEmpty(issuedTo)
                && !string.IsNullOrEmpty(clientId)
                && issuedTo == clientId;
        }

        /// <summary>ReceiveTokenReq</summary>
        /// <param name="authReqId">string</param>
        /// <param name="clientId">トークン要求で認証したクライアント（#387）</param>
        /// <param name="authZCode">string</param>
        /// <param name="states">CibaState</param>
        /// <returns>結果</returns>
        /// <remarks>
        /// **auth_req_id を出したクライアントと違えば、`not_found` を返し、記録に触れない**（#387）。
        /// CIBA Core 1.0 §11 は「issued to another Client」に `invalid_grant` を求める（呼び出し側が `not_found` を `invalid_grant` にする）。
        /// **以前は照合せずに、状態（`authorization_pending`・`slow_down`）を返し、ポーリングの時刻を書き換え、
        /// 承認済みなら記録を消していた**（認可コードも、`AuthorizationCodeProvider.Receive` が照合の前に消す）ので、
        /// **auth_req_id を知る別のクライアントが先に引くと、正規のクライアントが結果を受け取れなかった。**
        /// **照合は、状態を見る前に行う。** 列を足す前の記録（`ClientID` が空）は、照合できないので断る。
        /// </remarks>
        public static bool ReceiveTokenReq(
            string authReqId, string clientId, out string authZCode, out OAuth2AndOIDCEnum.CibaState states)
        {
            bool retVal = false;
            authZCode = "";
            states = OAuth2AndOIDCEnum.CibaState.not_found;

            if (Config.EnableCibaGrantType)
            {
                // EnableCibaGrantType == true

                string temp = "";
                //  **列の幅（800）を超える値は、引くまでもなく「無い」**（#331。Oracle は例外にする）。
                if (!MultiPurposeAuthSite.Data.CmnStore.IsSearchable(authReqId, 800))
                {
                    return retVal;
                }

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

                                if (authReqId == dic[Const.PollingAuthReqId])
                                {
                                    //  **別のクライアントに出したものなら、記録に触れずに「無い」とする**（#387）。
                                    if (!CibaProvider.IsIssuedTo(
                                        dic.TryGetValue(Const.PollingClientId, out string issuedTo) ? issuedTo : "",
                                        clientId))
                                    {
                                        states = OAuth2AndOIDCEnum.CibaState.not_found;
                                        break;
                                    }

                                    clientNotificationToken = _clientNotificationToken;

                                    // Code
                                    authZCode = dic[Const.PollingAuthZCode];
                                    // CibaState
                                    retVal = CibaProvider.GetState(dic[Const.PollingAuthReqExp], dic[Const.PollingResult], out states);

                                    //  **速すぎるポーリングには slow_down を返す**（#305 の段階 1）。
                                    //    **記録は辞書の中**（`lastPolled`。**無ければ初回**）。
                                    if (states == OAuth2AndOIDCEnum.CibaState.authorization_pending)
                                    {
                                        long? last = null;
                                        string lastPolled =
                                            dic.ContainsKey(Const.PollingLastPolled) ? dic[Const.PollingLastPolled] : "";

                                        long parsed = 0;
                                        if (!string.IsNullOrEmpty(lastPolled)
                                            && long.TryParse(lastPolled, out parsed))
                                        {
                                            last = parsed;
                                        }

                                        bool tooFast = CibaProvider.ThrottlePolling(last);

                                        dic[Const.PollingLastPolled] = PollingThrottle.NowUnixSeconds().ToString();
                                        CibaProvider.CibaData[_clientNotificationToken] =
                                            JsonConvert.SerializeObject(dic);

                                        if (tooFast)
                                        {
                                            states = OAuth2AndOIDCEnum.CibaState.slow_down;
                                            //  **コードは渡さない**（まだ承認されていない）。
                                            authZCode = "";
                                            retVal = false;
                                        }
                                    }

                                    break;
                                }
                            }
                        }

                        //  **削除（pending と slow_down のケースを除いて）。**
                        //    **slow_down はまだ pending** なので、消してはいけない（#305 の段階 1）。
                        if (clientNotificationToken != null
                            && states != OAuth2AndOIDCEnum.CibaState.authorization_pending
                            && states != OAuth2AndOIDCEnum.CibaState.slow_down)
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
                                    dyn = cnn.QueryFirstOrDefault(
                                        "SELECT [AuthReqExp], [AuthZCode], [Result], [LastPolledAt], [ClientID] FROM [CibaData] WHERE [AuthReqId] = @AuthReqId",
                                        new { AuthReqId = authReqId });

                                    if (dyn == null || !CibaProvider.IsIssuedTo((string)dyn.ClientID, clientId))
                                    {
                                        // レコードなし、または別のクライアントに出したもの（#387）。
                                        //   **記録に触れずに返す**（下の更新・削除をしない）。
                                        states = OAuth2AndOIDCEnum.CibaState.not_found;
                                        break;
                                    }
                                    else
                                    {
                                        // Code
                                        authZCode = dyn.AuthZCode;

                                        // states判別
                                        // **Result は未応答のとき NULL。** キャストすると落ちる。
                                        //   GetState は空文字を「未応答」として扱い、
                                        //   authorization_pending を返す。
                                        retVal = CibaProvider.GetState(
                                            ((long)dyn.AuthReqExp).ToString(),
                                            (dyn.Result == null) ? "" : ((bool)dyn.Result).ToString().ToLower(),
                                            out states);
                                    }

                                    // 削除（pendingのケースを除いて）
                                    //  **速すぎるポーリングには slow_down を返す**（#305 の段階 1）。
                                    if (states == OAuth2AndOIDCEnum.CibaState.authorization_pending)
                                    {
                                        if (CibaProvider.ThrottlePolling(
                                            (dyn.LastPolledAt == null) ? (long?)null : (long)dyn.LastPolledAt))
                                        {
                                            states = OAuth2AndOIDCEnum.CibaState.slow_down;
                                            authZCode = "";
                                            retVal = false;
                                        }

                                        cnn.Execute(
                                            "UPDATE [CibaData] SET [LastPolledAt] = @LastPolledAt"
                                            + " WHERE [AuthReqId] = @AuthReqId",
                                            new
                                            {
                                                AuthReqId = authReqId,
                                                LastPolledAt = PollingThrottle.NowUnixSeconds()
                                            });
                                    }

                                    //  **削除（pending と slow_down のケースを除いて）。**
                                    if (states != OAuth2AndOIDCEnum.CibaState.authorization_pending
                                        && states != OAuth2AndOIDCEnum.CibaState.slow_down)
                                    {
                                        cnn.Execute(
                                            "DELETE FROM [CibaData] WHERE [AuthReqId] = @AuthReqId",
                                            new { AuthReqId = authReqId });
                                    }

                                    break;

                                case EnumUserStoreType.ODPManagedDriver:
                                    dyn = cnn.QueryFirstOrDefault(
                                        "SELECT \"AuthReqExp\", \"AuthZCode\", \"Result\", \"LastPolledAt\", \"ClientID\"" + " FROM \"CibaData\" WHERE \"AuthReqId\" = :AuthReqId",
                                        new { AuthReqId = authReqId });

                                    if (dyn == null || !CibaProvider.IsIssuedTo((string)dyn.ClientID, clientId))
                                    {
                                        // レコードなし、または別のクライアントに出したもの（#387）。
                                        //   **記録に触れずに返す**（下の更新・削除をしない）。
                                        states = OAuth2AndOIDCEnum.CibaState.not_found;
                                        break;
                                    }
                                    else
                                    {
                                        // Code
                                        authZCode = dyn.AuthZCode;

                                        // states判別
                                        // **Result は未応答のとき NULL。** キャストすると落ちる。
                                        //   GetState は空文字を「未応答」として扱い、
                                        //   authorization_pending を返す。
                                        retVal = CibaProvider.GetState(
                                            ((long)dyn.AuthReqExp).ToString(),
                                            // **Oracle に boolean が無い。** Result は NUMBER(3) で 0 / 1 / NULL。
                                            //   ((bool)...) では変換できず、bool.TryParse が失敗して
                                            //   irregularity_data になる（#207 で実測）。
                                            (dyn.Result == null) ? "" : Convert.ToBoolean(dyn.Result).ToString().ToLower(),
                                            out states);
                                    }

                                    // 削除（pendingのケースを除いて）
                                    //  **速すぎるポーリングには slow_down を返す**（#305 の段階 1）。
                                    //    **Oracle の NUMBER は decimal で返る**ので、Convert を通す。
                                    if (states == OAuth2AndOIDCEnum.CibaState.authorization_pending)
                                    {
                                        if (CibaProvider.ThrottlePolling(
                                            (dyn.LastPolledAt == null)
                                                ? (long?)null : Convert.ToInt64(dyn.LastPolledAt)))
                                        {
                                            states = OAuth2AndOIDCEnum.CibaState.slow_down;
                                            authZCode = "";
                                            retVal = false;
                                        }

                                        cnn.Execute(
                                            "UPDATE \"CibaData\" SET \"LastPolledAt\" = :LastPolledAt"
                                            + " WHERE \"AuthReqId\" = :AuthReqId",
                                            new
                                            {
                                                AuthReqId = authReqId,
                                                LastPolledAt = PollingThrottle.NowUnixSeconds()
                                            });
                                    }

                                    //  **削除（pending と slow_down のケースを除いて）。**
                                    if (states != OAuth2AndOIDCEnum.CibaState.authorization_pending
                                        && states != OAuth2AndOIDCEnum.CibaState.slow_down)
                                    {
                                        cnn.Execute(
                                            "DELETE FROM \"CibaData\" WHERE \"AuthReqId\" = :AuthReqId",
                                            new { AuthReqId = authReqId });
                                    }

                                    break;

                                case EnumUserStoreType.PostgreSQL:
                                    dyn = cnn.QueryFirstOrDefault(
                                        "SELECT \"authreqexp\", \"authzcode\", \"result\", \"lastpolledat\", \"clientid\"" + " FROM \"cibadata\" WHERE \"authreqid\" = @AuthReqId",
                                        new { AuthReqId = authReqId });

                                    if (dyn == null || !CibaProvider.IsIssuedTo((string)dyn.clientid, clientId))
                                    {
                                        // レコードなし、または別のクライアントに出したもの（#387）。
                                        //   **記録に触れずに返す**（下の更新・削除をしない）。
                                        states = OAuth2AndOIDCEnum.CibaState.not_found;
                                        break;
                                    }
                                    else
                                    {
                                        // Code
                                        authZCode = dyn.authzcode;

                                        // states判別
                                        // **Result は未応答のとき NULL。** キャストすると落ちる。
                                        //   GetState は空文字を「未応答」として扱い、
                                        //   authorization_pending を返す。
                                        retVal = CibaProvider.GetState(
                                            ((long)dyn.authreqexp).ToString(),
                                            (dyn.result == null) ? "" : ((bool)dyn.result).ToString().ToLower(),
                                            out states);
                                    }

                                    // 削除（pendingのケースを除いて）
                                    //  **速すぎるポーリングには slow_down を返す**（#305 の段階 1）。
                                    if (states == OAuth2AndOIDCEnum.CibaState.authorization_pending)
                                    {
                                        if (CibaProvider.ThrottlePolling(
                                            (dyn.lastpolledat == null)
                                                ? (long?)null : (long)dyn.lastpolledat))
                                        {
                                            states = OAuth2AndOIDCEnum.CibaState.slow_down;
                                            authZCode = "";
                                            retVal = false;
                                        }

                                        cnn.Execute(
                                            "UPDATE \"cibadata\" SET \"lastpolledat\" = @LastPolledAt"
                                            + " WHERE \"authreqid\" = @AuthReqId",
                                            new
                                            {
                                                AuthReqId = authReqId,
                                                LastPolledAt = PollingThrottle.NowUnixSeconds()
                                            });
                                    }

                                    //  **削除（pending と slow_down のケースを除いて）。**
                                    if (states != OAuth2AndOIDCEnum.CibaState.authorization_pending
                                        && states != OAuth2AndOIDCEnum.CibaState.slow_down)
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