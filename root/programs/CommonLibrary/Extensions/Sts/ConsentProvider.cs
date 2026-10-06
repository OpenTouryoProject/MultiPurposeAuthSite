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
//* クラス名        ：ConsentProvider
//* クラス日本語名  ：同意（consent grant）を記録する。
//*
//* 作成日時        ：－
//* 作成者          ：－
//* 更新履歴        ：－
//*
//*  日時        更新者            内容
//*  ----------  ----------------  -------------------------------------------------
//*  2026/10/06  玄人 幸道         新規（#272 の段階 2 / D-6）
//**********************************************************************************

using MultiPurposeAuthSite.Co;
using MultiPurposeAuthSite.Data;

using System;
using System.Linq;
using System.Collections.Generic;
using System.Collections.Concurrent;
using System.Data;

using Dapper;

namespace MultiPurposeAuthSite.Extensions.Sts
{
    /// <summary>
    /// ConsentProvider
    /// 同意（consent grant）を記録する。
    /// </summary>
    /// <remarks>
    /// **「この利用者が、このクライアントに、どの scope を許したか」を持つ**（#272 の段階 2 / D-6）。
    ///
    /// **これが無いと `prompt=none` の判定ができない。**
    /// OIDC Core §3.1.2.1 の `prompt=none` は「UI を出すな。出す必要があるならエラーを返せ」
    /// という意味だが、**「出す必要があるか」は「以前に同意済みか」で決まる。**
    /// 記録が無ければ、**同意画面を出さずに code を発行する**か、
    /// **毎回同意画面を出す**かの二択しかなかった（C-3 の根本原因）。
    ///
    /// **粒度は (利用者, クライアント) で 1 行。** scope は**集合として足し込む**。
    ///
    /// | | |
    /// |---|---|
    /// | 要求 scope が記録の**部分集合** | **同意済み**（同意画面を出さない） |
    /// | 要求 scope に**記録に無いものが在る** | **同意を取り直す**（許可されたら記録に足す） |
    ///
    /// **並びは辞書順に正規化して持つ**（`response_type` の #267 と同じ理由。
    /// **"openid email" と "email openid" を別物にしない**）。
    ///
    /// **`Users.Id` への FK（`ON DELETE CASCADE`）を張ってある**ので、
    /// **利用者を消せば同意も消える。**
    /// </remarks>
    public class ConsentProvider
    {
        /// <summary>
        /// ConsentGrant（Memory Provider 用）
        /// キーは MemoryKey(userId, clientId)、値は正規化した scope の文字列。
        /// </summary>
        private static ConcurrentDictionary<string, string> ConsentGrants
            = new ConcurrentDictionary<string, string>();

        /// <summary>Memory Provider のキー</summary>
        /// <param name="userId">UserId</param>
        /// <param name="clientId">ClientID</param>
        /// <returns>キー</returns>
        private static string MemoryKey(string userId, string clientId)
        {
            // **タブで繋ぐ。** guid にも client_id にもタブは入らない。
            return (userId ?? "") + "\t" + (clientId ?? "");
        }

        #region scope の集合

        /// <summary>scope を正規化する（#272 の段階 2）</summary>
        /// <param name="scopes">scope の並び</param>
        /// <returns>空白区切り・重複なし・辞書順</returns>
        /// <remarks>
        /// **並びを意味に含めない**ための正規化である（`NormalizeResponseType` と同じ流儀）。
        /// **`scope` の値は case-sensitive**（RFC 6749 §3.3）なので、**ここでは小文字化しない。**
        /// `response_type` と違い、**以前から小文字化していない**ので、変える理由が無い。
        /// </remarks>
        public static string NormalizeScopes(IEnumerable<string> scopes)
        {
            List<string> normalized = new List<string>();

            if (scopes != null)
            {
                foreach (string scope in scopes)
                {
                    string s = (scope ?? "").Trim();

                    if (!string.IsNullOrEmpty(s) && !normalized.Contains(s))
                    {
                        normalized.Add(s);
                    }
                }
            }

            normalized.Sort(StringComparer.Ordinal);

            return string.Join(" ", normalized);
        }

        /// <summary>記録した scope を分ける</summary>
        /// <param name="scopes">記録（空白区切り）</param>
        /// <returns>scope の一覧</returns>
        private static List<string> SplitScopes(string scopes)
        {
            if (string.IsNullOrEmpty(scopes))
            {
                return new List<string>();
            }

            return scopes.Split(
                new char[] { ' ', '\t' }, StringSplitOptions.RemoveEmptyEntries).ToList();
        }

        #endregion

        #region HasConsent

        /// <summary>同意済みか（#272 の段階 2）</summary>
        /// <param name="userId">UserId</param>
        /// <param name="clientId">ClientID</param>
        /// <param name="requestedScopes">要求された scope</param>
        /// <returns>要求が記録の部分集合なら true</returns>
        /// <remarks>
        /// **要求に、記録に無い scope が 1 つでも在れば false**（同意を取り直す）。
        /// **要求が空なら true**（許すものが無いので、同意を求める意味が無い）。
        /// </remarks>
        public static bool HasConsent(string userId, string clientId, IEnumerable<string> requestedScopes)
        {
            if (string.IsNullOrEmpty(userId) || string.IsNullOrEmpty(clientId))
            {
                return false;
            }

            string granted = ConsentProvider.Get(userId, clientId);

            if (granted == null)
            {
                // **記録そのものが無い。**
                return false;
            }

            List<string> grantedScopes = ConsentProvider.SplitScopes(granted);

            foreach (string requested in requestedScopes ?? new string[0])
            {
                string s = (requested ?? "").Trim();

                if (string.IsNullOrEmpty(s))
                {
                    continue;
                }

                if (!grantedScopes.Contains(s))
                {
                    return false;
                }
            }

            return true;
        }

        #endregion

        #region Grant

        /// <summary>同意を記録する（#272 の段階 2）</summary>
        /// <param name="userId">UserId</param>
        /// <param name="clientId">ClientID</param>
        /// <param name="scopes">許可された scope</param>
        /// <remarks>
        /// **在れば足し込み、無ければ作る。**
        /// **足し込みにするのは、scope を増やす要求で同意し直したときに、
        /// 以前の分を失わないため**である。
        /// </remarks>
        public static void Grant(string userId, string clientId, IEnumerable<string> scopes)
        {
            if (string.IsNullOrEmpty(userId) || string.IsNullOrEmpty(clientId))
            {
                // 記録しない（利用者が居ない経路）
                return;
            }

            string granted = ConsentProvider.Get(userId, clientId);

            List<string> merged = ConsentProvider.SplitScopes(granted);

            foreach (string scope in scopes ?? new string[0])
            {
                string s = (scope ?? "").Trim();

                if (!string.IsNullOrEmpty(s) && !merged.Contains(s))
                {
                    merged.Add(s);
                }
            }

            string value = ConsentProvider.NormalizeScopes(merged);

            if (granted == null)
            {
                ConsentProvider.Insert(userId, clientId, value);
            }
            else if (granted != value)
            {
                // **変わっていなければ書かない。** 同意画面を通るたびに更新しても意味が無い。
                ConsentProvider.Update(userId, clientId, value);
            }
        }

        #endregion

        #region Get

        /// <summary>記録した scope を返す（#272 の段階 2）</summary>
        /// <param name="userId">UserId</param>
        /// <param name="clientId">ClientID</param>
        /// <returns>scope（空白区切り）。記録が無ければ null</returns>
        /// <remarks>**「記録が無い」と「scope が空」を区別する**ので、null で返す。</remarks>
        public static string Get(string userId, string clientId)
        {
            switch (Config.UserStoreType)
            {
                case EnumUserStoreType.Memory:

                    string value = null;
                    ConsentProvider.ConsentGrants.TryGetValue(
                        ConsentProvider.MemoryKey(userId, clientId), out value);

                    return value;

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
                                    "SELECT [Scopes] FROM [ConsentGrant]"
                                    + " WHERE [UserId] = @UserId AND [ClientID] = @ClientID",
                                    new { UserId = userId, ClientID = clientId });

                            case EnumUserStoreType.ODPManagedDriver:

                                return cnn.ExecuteScalar<string>(
                                    "SELECT \"Scopes\" FROM \"ConsentGrant\""
                                    + " WHERE \"UserId\" = :UserId AND \"ClientID\" = :ClientID",
                                    new { UserId = userId, ClientID = clientId });

                            case EnumUserStoreType.PostgreSQL:

                                return cnn.ExecuteScalar<string>(
                                    "SELECT \"scopes\" FROM \"consentgrant\""
                                    + " WHERE \"userid\" = @UserId AND \"clientid\" = @ClientID",
                                    new { UserId = userId, ClientID = clientId });
                        }
                    }

                    break;
            }

            return null;
        }

        #endregion

        #region GetByUser

        /// <summary>その利用者の同意を全部返す（#272 の段階 2）</summary>
        /// <param name="userId">UserId</param>
        /// <returns>ClientID と scope の対（1 件も無ければ空）</returns>
        /// <remarks>**管理画面の一覧で使う**（取り消しのため）。</remarks>
        public static List<KeyValuePair<string, string>> GetByUser(string userId)
        {
            List<KeyValuePair<string, string>> all = new List<KeyValuePair<string, string>>();

            if (string.IsNullOrEmpty(userId))
            {
                return all;
            }

            switch (Config.UserStoreType)
            {
                case EnumUserStoreType.Memory:

                    string prefix = userId + "\t";

                    foreach (KeyValuePair<string, string> kv in ConsentProvider.ConsentGrants)
                    {
                        if (kv.Key.StartsWith(prefix))
                        {
                            all.Add(new KeyValuePair<string, string>(
                                kv.Key.Substring(prefix.Length), kv.Value));
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
                                sql = "SELECT [ClientID], [Scopes] FROM [ConsentGrant]"
                                    + " WHERE [UserId] = @UserId ORDER BY [ClientID]";
                                break;

                            case EnumUserStoreType.ODPManagedDriver:
                                sql = "SELECT \"ClientID\", \"Scopes\" FROM \"ConsentGrant\""
                                    + " WHERE \"UserId\" = :UserId ORDER BY \"ClientID\"";
                                break;

                            case EnumUserStoreType.PostgreSQL:
                                sql = "SELECT \"clientid\", \"scopes\" FROM \"consentgrant\""
                                    + " WHERE \"userid\" = @UserId ORDER BY \"clientid\"";
                                break;
                        }

                        foreach (dynamic row in cnn.Query(sql, new { UserId = userId }))
                        {
                            IDictionary<string, object> r = (IDictionary<string, object>)row;

                            all.Add(new KeyValuePair<string, string>(
                                (string)ConsentProvider.Value(r, "ClientID"),
                                (string)ConsentProvider.Value(r, "Scopes")));
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
        /// <remarks>**PostgreSQL は小文字で返る**（引用符なしの識別子が畳まれるため）。</remarks>
        private static object Value(IDictionary<string, object> row, string name)
        {
            if (row.ContainsKey(name))
            {
                return row[name];
            }

            return row.ContainsKey(name.ToLower()) ? row[name.ToLower()] : null;
        }

        #endregion

        #region Revoke

        /// <summary>同意を取り消す（#272 の段階 2）</summary>
        /// <param name="userId">UserId</param>
        /// <param name="clientId">ClientID</param>
        /// <remarks>
        /// **管理画面から呼ぶ。** 取り消した後は、**次の認可で同意画面が出る**
        /// （`prompt=none` なら `consent_required`）。
        ///
        /// **発行済みのトークンは失効しない。** そちらは `/revoke`（RFC 7009）の役目である。
        /// </remarks>
        public static void Revoke(string userId, string clientId)
        {
            switch (Config.UserStoreType)
            {
                case EnumUserStoreType.Memory:

                    string removed = null;
                    ConsentProvider.ConsentGrants.TryRemove(
                        ConsentProvider.MemoryKey(userId, clientId), out removed);

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
                                    "DELETE FROM [ConsentGrant]"
                                    + " WHERE [UserId] = @UserId AND [ClientID] = @ClientID",
                                    new { UserId = userId, ClientID = clientId });

                                break;

                            case EnumUserStoreType.ODPManagedDriver:

                                cnn.Execute(
                                    "DELETE FROM \"ConsentGrant\""
                                    + " WHERE \"UserId\" = :UserId AND \"ClientID\" = :ClientID",
                                    new { UserId = userId, ClientID = clientId });

                                break;

                            case EnumUserStoreType.PostgreSQL:

                                cnn.Execute(
                                    "DELETE FROM \"consentgrant\""
                                    + " WHERE \"userid\" = @UserId AND \"clientid\" = @ClientID",
                                    new { UserId = userId, ClientID = clientId });

                                break;
                        }
                    }

                    break;
            }
        }

        #endregion

        #region Insert / Update

        /// <summary>記録を作る</summary>
        /// <param name="userId">UserId</param>
        /// <param name="clientId">ClientID</param>
        /// <param name="scopes">scope（正規化済み）</param>
        private static void Insert(string userId, string clientId, string scopes)
        {
            switch (Config.UserStoreType)
            {
                case EnumUserStoreType.Memory:

                    ConsentProvider.ConsentGrants.TryAdd(
                        ConsentProvider.MemoryKey(userId, clientId), scopes);

                    break;

                case EnumUserStoreType.SqlServer:
                case EnumUserStoreType.ODPManagedDriver:
                case EnumUserStoreType.PostgreSQL: // DMBMS

                    using (IDbConnection cnn = DataAccess.CreateConnection())
                    {
                        cnn.Open();

                        DateTime now = DateTime.Now;

                        switch (Config.UserStoreType)
                        {
                            case EnumUserStoreType.SqlServer:

                                cnn.Execute(
                                    "INSERT INTO [ConsentGrant]"
                                    + " ([UserId], [ClientID], [Scopes], [CreatedDate], [UpdatedDate])"
                                    + " VALUES (@UserId, @ClientID, @Scopes, @CreatedDate, @UpdatedDate)",
                                    new
                                    {
                                        UserId = userId, ClientID = clientId, Scopes = scopes,
                                        CreatedDate = now, UpdatedDate = now
                                    });

                                break;

                            case EnumUserStoreType.ODPManagedDriver:

                                cnn.Execute(
                                    "INSERT INTO \"ConsentGrant\""
                                    + " (\"UserId\", \"ClientID\", \"Scopes\", \"CreatedDate\", \"UpdatedDate\")"
                                    + " VALUES (:UserId, :ClientID, :Scopes, :CreatedDate, :UpdatedDate)",
                                    new
                                    {
                                        UserId = userId, ClientID = clientId, Scopes = scopes,
                                        CreatedDate = now, UpdatedDate = now
                                    });

                                break;

                            case EnumUserStoreType.PostgreSQL:

                                cnn.Execute(
                                    "INSERT INTO \"consentgrant\""
                                    + " (\"userid\", \"clientid\", \"scopes\", \"createddate\", \"updateddate\")"
                                    + " VALUES (@UserId, @ClientID, @Scopes, @CreatedDate, @UpdatedDate)",
                                    new
                                    {
                                        UserId = userId, ClientID = clientId, Scopes = scopes,
                                        CreatedDate = now, UpdatedDate = now
                                    });

                                break;
                        }
                    }

                    break;
            }
        }

        /// <summary>記録を更新する</summary>
        /// <param name="userId">UserId</param>
        /// <param name="clientId">ClientID</param>
        /// <param name="scopes">scope（正規化済み）</param>
        private static void Update(string userId, string clientId, string scopes)
        {
            switch (Config.UserStoreType)
            {
                case EnumUserStoreType.Memory:

                    ConsentProvider.ConsentGrants[
                        ConsentProvider.MemoryKey(userId, clientId)] = scopes;

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
                                    "UPDATE [ConsentGrant] SET [Scopes] = @Scopes, [UpdatedDate] = @UpdatedDate"
                                    + " WHERE [UserId] = @UserId AND [ClientID] = @ClientID",
                                    new
                                    {
                                        UserId = userId, ClientID = clientId,
                                        Scopes = scopes, UpdatedDate = DateTime.Now
                                    });

                                break;

                            case EnumUserStoreType.ODPManagedDriver:

                                cnn.Execute(
                                    "UPDATE \"ConsentGrant\" SET \"Scopes\" = :Scopes, \"UpdatedDate\" = :UpdatedDate"
                                    + " WHERE \"UserId\" = :UserId AND \"ClientID\" = :ClientID",
                                    new
                                    {
                                        UserId = userId, ClientID = clientId,
                                        Scopes = scopes, UpdatedDate = DateTime.Now
                                    });

                                break;

                            case EnumUserStoreType.PostgreSQL:

                                cnn.Execute(
                                    "UPDATE \"consentgrant\" SET \"scopes\" = @Scopes, \"updateddate\" = @UpdatedDate"
                                    + " WHERE \"userid\" = @UserId AND \"clientid\" = @ClientID",
                                    new
                                    {
                                        UserId = userId, ClientID = clientId,
                                        Scopes = scopes, UpdatedDate = DateTime.Now
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
