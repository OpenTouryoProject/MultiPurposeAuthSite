//**********************************************************************************
//* Copyright (C) 2026 Hitachi Solutions,Ltd.
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
//* クラス名        ：SessionClientProvider
//* クラス日本語名  ：セッション × クライアントの台帳（sid を持つ）
//*
//* 作成日時        ：－
//* 作成者          ：－
//* 更新履歴        ：－
//*
//*  日時        更新者            内容
//*  ----------  ----------------  -------------------------------------------------
//*  2026/10/21  玄人 幸道         新規（#310 の段階 1）
//**********************************************************************************

using MultiPurposeAuthSite.Co;
using MultiPurposeAuthSite.Data;
using MultiPurposeAuthSite.Log;

#if NETCORE
//using MultiPurposeAuthSite;
#else
using MultiPurposeAuthSite.Entity;
#endif

using System;
using System.Collections.Generic;
using System.Collections.Concurrent;
using System.Data;

using Dapper;

namespace MultiPurposeAuthSite.Extensions.Sts
{
    /// <summary>
    /// SessionClientProvider
    /// **「このセッションで、どのクライアントに、どの `sid` を名乗ったか」を持つ**（#310 の段階 1）。
    /// </summary>
    /// <remarks>
    /// **2 つの役目が在る。**
    ///
    /// | | |
    /// |---|---|
    /// | **`sid` を安定させる** | **同じセッション・同じクライアントなら、同じ `sid` を返す**（OIDC Core §2） |
    /// | **伝える先を知る** | **ログアウトを伝える相手は「このセッションが触ったクライアント」である**（`BackChannelLogout`。#310 の段階 2） |
    ///
    /// **`sid` はクライアントごとに別の値にしてある。**
    /// **セッション単位で 1 つにすると、`sub` を `pairwise` にしている配備で、
    /// 2 つの RP が突き合わせたときに同じ利用者だと分かってしまう**
    /// （**`sub` を分けた意味が消える**）。
    /// **仕様が求めるのは「その RP に出した `id_token` の `sid` と、
    /// その RP へ送る `logout_token` の `sid` が同じこと」**なので、
    /// **RP ごとに別の値でよい**（Back-Channel Logout 1.0 §2.4）。
    ///
    /// **セッションの識別子（`SessionId`）は、この表の外から渡される。**
    /// **Cookie が持っている**（<see cref="Config.OpSessionCookieName"/>）。
    /// **`sid` そのものを Cookie に置かない**のは、上の「RP ごとに別」と両立しないため。
    ///
    /// **利用者を削除したときの後始末は、DB では外部キー（ON DELETE CASCADE）が行う。**
    /// `mem` では、この実装が消す（<see cref="DeleteByUser"/>）。
    /// </remarks>
    public class SessionClientProvider
    {
        #region Memory Provider

        /// <summary>1 行（Memory Provider 用）</summary>
        private class Entry
        {
            /// <summary>そのクライアントに名乗った sid</summary>
            public string Sid = "";

            /// <summary>Users.Id</summary>
            public string UserId = "";

            /// <summary>作成日時</summary>
            public DateTime CreatedDate = DateTime.Now;
        }

        /// <summary>
        /// SessionClient（Memory Provider 用）
        /// キーは MemoryKey(sessionId, clientId)。
        /// </summary>
        private static ConcurrentDictionary<string, Entry> SessionClients
            = new ConcurrentDictionary<string, Entry>();

        /// <summary>Memory Provider のキー</summary>
        /// <param name="sessionId">SessionId</param>
        /// <param name="clientId">ClientID</param>
        /// <returns>キー</returns>
        /// <remarks>**タブで繋ぐ。** guid にも client_id にもタブは入らない（`ConsentProvider` と同じ）。</remarks>
        private static string MemoryKey(string sessionId, string clientId)
        {
            return (sessionId ?? "") + "\t" + (clientId ?? "");
        }

        #endregion

        #region 掃除（放置されたセッションの行）

        /// <summary>前回まとめて消した時刻</summary>
        private static DateTime LastSweep = DateTime.MinValue;

        /// <summary>掃除の間隔を測るための錠</summary>
        private static readonly object SweepLock = new object();

        /// <summary>まとめて消す間隔</summary>
        /// <remarks>
        /// **常駐の仕組み（バッチ・タイマ）を増やさず、書き込みのついでに消す**
        /// （`AuthorizationCodeProvider` と同じ流儀）。
        /// </remarks>
        private static readonly TimeSpan SweepInterval = TimeSpan.FromMinutes(10);

        /// <summary>これより古い行は消す</summary>
        /// <remarks>
        /// **サインアウトを通らずに捨てられたセッションの行**が残るため。
        /// **認証 Cookie の有効期限 ＋ 1 日**を目安にしてある
        /// （**Sliding で延びることが在る**ので、丸 1 日の猶予を足している）。
        /// </remarks>
        private static DateTime SweepLimit
        {
            get
            {
                return DateTime.Now - Config.AuthCookieExpiresFromHours - TimeSpan.FromDays(1);
            }
        }

        /// <summary>間隔を過ぎていたら、古い行をまとめて消す</summary>
        private static void SweepIfNeeded()
        {
            DateTime now = DateTime.Now;

            lock (SessionClientProvider.SweepLock)
            {
                if (now - SessionClientProvider.LastSweep < SessionClientProvider.SweepInterval)
                {
                    return;
                }

                SessionClientProvider.LastSweep = now;
            }

            DateTime limit = SessionClientProvider.SweepLimit;

            switch (Config.UserStoreType)
            {
                case EnumUserStoreType.Memory:

                    foreach (KeyValuePair<string, Entry> kv in SessionClientProvider.SessionClients)
                    {
                        if (kv.Value.CreatedDate <= limit)
                        {
                            SessionClientProvider.SessionClients.TryRemove(kv.Key, out Entry _);
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
                                    "DELETE FROM [SessionClient] WHERE [CreatedDate] <= @Limit",
                                    new { Limit = limit });

                                break;

                            case EnumUserStoreType.ODPManagedDriver:

                                cnn.Execute(
                                    "DELETE FROM \"SessionClient\" WHERE \"CreatedDate\" <= :Limit",
                                    new { Limit = limit });

                                break;

                            case EnumUserStoreType.PostgreSQL:

                                cnn.Execute(
                                    "DELETE FROM \"sessionclient\" WHERE \"createddate\" <= @Limit",
                                    new { Limit = limit });

                                break;
                        }
                    }

                    break;
            }
        }

        #endregion

        #region GetOrCreateSid

        /// <summary>そのクライアントに名乗る sid を返す（#310 の段階 1）</summary>
        /// <param name="sessionId">セッションの識別子（Cookie が持つ値）</param>
        /// <param name="clientId">ClientID</param>
        /// <param name="userName">利用者名（Users.Id を引くために使う）</param>
        /// <returns>sid。記録できない経路では空</returns>
        /// <remarks>
        /// **在れば引き、無ければ作る。**
        /// **引けるからこそ `sid` が安定する** — **同じセッションの 2 回目の認可で、同じ値が返る。**
        ///
        /// **空を返すのは、記録する意味が無い経路**である。
        ///
        /// | | |
        /// |---|---|
        /// | **セッションが無い** | `grant_type=password` / `client_credentials` / CIBA / Device（**ブラウザのセッションを経ていない**） |
        /// | **利用者が引けない** | **クライアント自身がトークンを取る経路**（`sub` がクライアント名） |
        ///
        /// **空のときは `sid` クレームを付けない**（**嘘の値を出さない**）。
        /// </remarks>
        public static string GetOrCreateSid(string sessionId, string clientId, string userName)
        {
            if (string.IsNullOrEmpty(sessionId) || string.IsNullOrEmpty(clientId))
            {
                return "";
            }

            string sid = SessionClientProvider.GetSid(sessionId, clientId);

            if (!string.IsNullOrEmpty(sid))
            {
                return sid;
            }

            // **利用者が引けなければ記録しない。**
            //   **`UserId` は `Users.Id` への外部キー**なので、推測で入れられない。
            ApplicationUser user = CmnUserStore.FindByName(userName);

            if (user == null)
            {
                return "";
            }

            sid = Guid.NewGuid().ToString("N");

            try
            {
                SessionClientProvider.Insert(sessionId, clientId, sid, user.Id);
            }
            catch (Exception ex)
            {
                // **同時に 2 本の要求が来ると、一意制約で落ちることが在る。**
                //   **その場合は、相手が入れた行を引き直す**（**自分の値は捨てる**）。
                string inserted = SessionClientProvider.GetSid(sessionId, clientId);

                if (string.IsNullOrEmpty(inserted))
                {
                    // オペレーション・トレース・ログ出力
                    //   **`sid` が無くても認可は続ける**（**段階 1 では誰も使っていない**）。
                    Logging.MyOperationTrace(string.Format(
                        "The sid could not be recorded. ({0})", ex.GetType().Name));

                    return "";
                }

                return inserted;
            }

            SessionClientProvider.SweepIfNeeded();

            return sid;
        }

        #endregion

        #region GetBySession

        /// <summary>伝える先（台帳の 1 行。#310 の段階 2）</summary>
        public class Target
        {
            /// <summary>ClientID</summary>
            public string ClientId = "";

            /// <summary>そのクライアントに名乗った sid</summary>
            public string Sid = "";

            /// <summary>Users.Id</summary>
            public string UserId = "";
        }

        /// <summary>そのセッションが触ったクライアントを読む（#310 の段階 2）</summary>
        /// <param name="sessionId">セッションの識別子</param>
        /// <returns>伝える先（1 件も無ければ空）</returns>
        /// <remarks>
        /// **ログアウトを伝える先を引くために使う**（`BackChannelLogout`）。
        ///
        /// **消す前に読むこと。** **<see cref="DeleteBySession"/> を先に呼ぶと、
        /// 誰に伝えるかが分からなくなる。**
        ///
        /// **「触った」＝「トークンを発行した」**である（#310 の段階 2 の冒頭）。
        /// **同意画面を出しただけ・拒否された相手は、この表に入っていない。**
        /// </remarks>
        public static List<Target> GetBySession(string sessionId)
        {
            List<Target> all = new List<Target>();

            if (string.IsNullOrEmpty(sessionId))
            {
                return all;
            }

            switch (Config.UserStoreType)
            {
                case EnumUserStoreType.Memory:

                    string prefix = sessionId + "\t";

                    foreach (KeyValuePair<string, Entry> kv in SessionClientProvider.SessionClients)
                    {
                        if (kv.Key.StartsWith(prefix))
                        {
                            all.Add(new Target()
                            {
                                ClientId = kv.Key.Substring(prefix.Length),
                                Sid = kv.Value.Sid,
                                UserId = kv.Value.UserId
                            });
                        }
                    }

                    break;

                case EnumUserStoreType.SqlServer:
                case EnumUserStoreType.ODPManagedDriver:
                case EnumUserStoreType.PostgreSQL: // DMBMS

                    using (IDbConnection cnn = DataAccess.CreateConnection())
                    {
                        cnn.Open();

                        string sql = null;

                        switch (Config.UserStoreType)
                        {
                            case EnumUserStoreType.SqlServer:
                                sql = "SELECT [ClientID], [Sid], [UserId] FROM [SessionClient]"
                                    + " WHERE [SessionId] = @SessionId ORDER BY [ClientID]";
                                break;

                            case EnumUserStoreType.ODPManagedDriver:
                                sql = "SELECT \"ClientID\", \"Sid\", \"UserId\" FROM \"SessionClient\""
                                    + " WHERE \"SessionId\" = :SessionId ORDER BY \"ClientID\"";
                                break;

                            case EnumUserStoreType.PostgreSQL:
                                sql = "SELECT \"clientid\", \"sid\", \"userid\" FROM \"sessionclient\""
                                    + " WHERE \"sessionid\" = @SessionId ORDER BY \"clientid\"";
                                break;
                        }

                        foreach (dynamic row in cnn.Query(sql, new { SessionId = sessionId }))
                        {
                            IDictionary<string, object> r = (IDictionary<string, object>)row;

                            all.Add(new Target()
                            {
                                ClientId = (string)SessionClientProvider.Value(r, "ClientID"),
                                Sid = (string)SessionClientProvider.Value(r, "Sid"),
                                UserId = (string)SessionClientProvider.Value(r, "UserId")
                            });
                        }
                    }

                    break;
            }

            return all;
        }

        /// <summary>方言で大文字小文字が違う列名を引く</summary>
        /// <param name="row">1 行</param>
        /// <param name="name">列名</param>
        /// <returns>値</returns>
        /// <remarks>**PostgreSQL は小文字で返る**（`ConsentProvider` と同じ）。</remarks>
        private static object Value(IDictionary<string, object> row, string name)
        {
            if (row.ContainsKey(name))
            {
                return row[name];
            }

            return row.ContainsKey(name.ToLower()) ? row[name.ToLower()] : null;
        }

        #endregion

        #region DeleteBySession

        /// <summary>そのセッションの行を消す（#310 の段階 1）</summary>
        /// <param name="sessionId">セッションの識別子</param>
        /// <remarks>
        /// **サインアウトのときに呼ぶ。** **セッションが終われば `sid` も終わる。**
        ///
        /// **消す前に「伝える先」を読むこと**（<see cref="GetBySession"/>。#310 の段階 2）。
        /// **消してしまうと、誰に伝えるかが分からなくなる。**
        /// </remarks>
        public static void DeleteBySession(string sessionId)
        {
            if (string.IsNullOrEmpty(sessionId))
            {
                return;
            }

            switch (Config.UserStoreType)
            {
                case EnumUserStoreType.Memory:

                    string prefix = sessionId + "\t";

                    foreach (KeyValuePair<string, Entry> kv in SessionClientProvider.SessionClients)
                    {
                        if (kv.Key.StartsWith(prefix))
                        {
                            SessionClientProvider.SessionClients.TryRemove(kv.Key, out Entry _);
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
                                    "DELETE FROM [SessionClient] WHERE [SessionId] = @SessionId",
                                    new { SessionId = sessionId });

                                break;

                            case EnumUserStoreType.ODPManagedDriver:

                                cnn.Execute(
                                    "DELETE FROM \"SessionClient\" WHERE \"SessionId\" = :SessionId",
                                    new { SessionId = sessionId });

                                break;

                            case EnumUserStoreType.PostgreSQL:

                                cnn.Execute(
                                    "DELETE FROM \"sessionclient\" WHERE \"sessionid\" = @SessionId",
                                    new { SessionId = sessionId });

                                break;
                        }
                    }

                    break;
            }
        }

        #endregion

        #region DeleteByUser

        /// <summary>その利用者の行を消す（#310 の段階 1）</summary>
        /// <param name="userId">Users.Id</param>
        /// <remarks>
        /// **`mem` のための後始末**である（**DB は外部キーの `ON DELETE CASCADE` が消す**）。
        /// **利用者の削除（GDPR の消去を含む）で呼ぶ**
        /// （`ConsentProvider` / `SubjectIdProvider` と同じ扱い）。
        /// </remarks>
        public static void DeleteByUser(string userId)
        {
            if (string.IsNullOrEmpty(userId))
            {
                return;
            }

            if (Config.UserStoreType == EnumUserStoreType.Memory)
            {
                foreach (KeyValuePair<string, Entry> kv in SessionClientProvider.SessionClients)
                {
                    if (kv.Value.UserId == userId)
                    {
                        SessionClientProvider.SessionClients.TryRemove(kv.Key, out Entry _);
                    }
                }
            }
        }

        #endregion

        #region private

        /// <summary>記録した sid を引く</summary>
        /// <param name="sessionId">セッションの識別子</param>
        /// <param name="clientId">ClientID</param>
        /// <returns>sid。記録が無ければ空</returns>
        private static string GetSid(string sessionId, string clientId)
        {
            switch (Config.UserStoreType)
            {
                case EnumUserStoreType.Memory:

                    SessionClientProvider.SessionClients.TryGetValue(
                        SessionClientProvider.MemoryKey(sessionId, clientId), out Entry entry);

                    return (entry == null) ? "" : entry.Sid;

                case EnumUserStoreType.SqlServer:
                case EnumUserStoreType.ODPManagedDriver:
                case EnumUserStoreType.PostgreSQL: // DMBMS

                    using (IDbConnection cnn = DataAccess.CreateConnection())
                    {
                        cnn.Open();

                        switch (Config.UserStoreType)
                        {
                            case EnumUserStoreType.SqlServer:

                                return cnn.ExecuteScalar<string>(
                                    "SELECT [Sid] FROM [SessionClient]"
                                    + " WHERE [SessionId] = @SessionId AND [ClientID] = @ClientID",
                                    new { SessionId = sessionId, ClientID = clientId }) ?? "";

                            case EnumUserStoreType.ODPManagedDriver:

                                return cnn.ExecuteScalar<string>(
                                    "SELECT \"Sid\" FROM \"SessionClient\""
                                    + " WHERE \"SessionId\" = :SessionId AND \"ClientID\" = :ClientID",
                                    new { SessionId = sessionId, ClientID = clientId }) ?? "";

                            case EnumUserStoreType.PostgreSQL:

                                return cnn.ExecuteScalar<string>(
                                    "SELECT \"sid\" FROM \"sessionclient\""
                                    + " WHERE \"sessionid\" = @SessionId AND \"clientid\" = @ClientID",
                                    new { SessionId = sessionId, ClientID = clientId }) ?? "";
                        }
                    }

                    break;
            }

            return "";
        }

        /// <summary>1 行を足す</summary>
        /// <param name="sessionId">セッションの識別子</param>
        /// <param name="clientId">ClientID</param>
        /// <param name="sid">sid</param>
        /// <param name="userId">Users.Id</param>
        private static void Insert(string sessionId, string clientId, string sid, string userId)
        {
            switch (Config.UserStoreType)
            {
                case EnumUserStoreType.Memory:

                    Entry entry = new Entry();
                    entry.Sid = sid;
                    entry.UserId = userId;
                    entry.CreatedDate = DateTime.Now;

                    if (!SessionClientProvider.SessionClients.TryAdd(
                        SessionClientProvider.MemoryKey(sessionId, clientId), entry))
                    {
                        // **既に在る**（同時に入った）。**例外にして、呼び元に引き直させる。**
                        throw new InvalidOperationException("The sid was already recorded.");
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
                                    "INSERT INTO [SessionClient]"
                                    + " ([SessionId], [ClientID], [Sid], [UserId], [CreatedDate])"
                                    + " VALUES (@SessionId, @ClientID, @Sid, @UserId, @CreatedDate)",
                                    new
                                    {
                                        SessionId = sessionId,
                                        ClientID = clientId,
                                        Sid = sid,
                                        UserId = userId,
                                        CreatedDate = DateTime.Now
                                    });

                                break;

                            case EnumUserStoreType.ODPManagedDriver:

                                cnn.Execute(
                                    "INSERT INTO \"SessionClient\""
                                    + " (\"SessionId\", \"ClientID\", \"Sid\", \"UserId\", \"CreatedDate\")"
                                    + " VALUES (:SessionId, :ClientID, :Sid, :UserId, :CreatedDate)",
                                    new
                                    {
                                        SessionId = sessionId,
                                        ClientID = clientId,
                                        Sid = sid,
                                        UserId = userId,
                                        CreatedDate = DateTime.Now
                                    });

                                break;

                            case EnumUserStoreType.PostgreSQL:

                                cnn.Execute(
                                    "INSERT INTO \"sessionclient\""
                                    + " (\"sessionid\", \"clientid\", \"sid\", \"userid\", \"createddate\")"
                                    + " VALUES (@SessionId, @ClientID, @Sid, @UserId, @CreatedDate)",
                                    new
                                    {
                                        SessionId = sessionId,
                                        ClientID = clientId,
                                        Sid = sid,
                                        UserId = userId,
                                        CreatedDate = DateTime.Now
                                    });

                                break;
                        }
                    }

                    break;
            }
        }

        #endregion
    }
}
