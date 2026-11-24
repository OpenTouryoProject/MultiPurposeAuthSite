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
//* クラス名        ：RefreshTokenProvider
//* クラス日本語名  ：RefreshTokenProvider（ライブラリ）
//*
//* 作成日時        ：－
//* 作成者          ：－
//* 更新履歴        ：－
//*
//*  日時        更新者            内容
//*  ----------  ----------------  -------------------------------------------------
//*  2018/12/26  西野 大介         新規（分割
//*  2026/09/24  玄人 幸道         有効期限を検証する（期限切れは無いものとして扱う）（#188）
//*  2026/11/03  玄人 幸道         列の幅を超える値は、引かずに「無い」とする（Oracle で 500 になっていた。#331）
//*  2026/11/04  玄人 幸道         使用済みにできた 1 つだけが使う（同時に使うと、複数にトークンが出ていた。#332）
//*  2026/11/23  玄人 幸道         RevokeFamily を internal にした（認可の ID の失効から呼ぶ。#421）
//*  2026/11/23  玄人 幸道         新しい一族は、payload に認可の ID が在れば、それを識別子にする（#421）
//*  2026/11/23  玄人 幸道         一族を失効させるとき、同じ認可から出した access_token も失効させる（RFC 7009 §2.1。E-13。#421）
//**********************************************************************************

using System;
using System.Data;
using System.Collections.Generic;
using System.Collections.Concurrent;

using MultiPurposeAuthSite.Data;
using MultiPurposeAuthSite.Co;
using MultiPurposeAuthSite.Util.Sts;

using Dapper;
using Newtonsoft.Json.Linq;

namespace MultiPurposeAuthSite.TokenProviders
{
    /// <summary>RefreshTokenのpayloadを一時保存する。</summary>
    /// <remarks>
    /// **ローテーションと、再利用の検知（#188 の段階 3）。**
    ///
    /// 更新のたびに新しい refresh_token を発行する（ローテーション）。
    /// 以前は「使ったら行を消す」方式だったので、**使用済みだったのか、元から無いのかを区別できなかった。**
    /// いまは消さずに `UsedDate` を入れ、**使用済みが再び提示されたら、その一族（FamilyId）ごと失効させる。**
    ///
    /// - `FamilyId` : **1 回の認可から派生した refresh_token のまとまり**（GUID）。
    ///   最初の発行で作り、更新では引き継ぐ。認可をやり直せば別の値になる
    /// - `UsedDate` : 使った時刻。NULL なら未使用
    ///
    /// **なぜ一族ごとか。** 漏れたトークンと正規のトークンは、サーバから見分けられない。
    /// OAuth 2.0 Security BCP §4.14.2 は、この場合に一族の失効を挙げている。
    /// </remarks>
    public class RefreshTokenProvider
    {
        /// <summary>
        /// RefreshTokens
        /// ConcurrentDictionaryは、.NET 4.0の新しいスレッドセーフなHashtable
        /// </summary>
        private static ConcurrentDictionary<string, TokenEntry>
            RefreshTokens = new ConcurrentDictionary<string, TokenEntry>();

        /// <summary>メモリ ストアの 1 件（#188）</summary>
        private class TokenEntry
        {
            /// <summary>値</summary>
            public string Value = "";
            /// <summary>作成時刻</summary>
            public DateTime CreatedDate = DateTime.MinValue;
            /// <summary>一族の識別子（同じ認可から派生したもの）</summary>
            public string FamilyId = "";
            /// <summary>使った時刻（NULL なら未使用）</summary>
            public DateTime? UsedDate = null;
        }

        /// <summary>DBMS から読むときの 1 行（#188）</summary>
        private class TokenRow
        {
            /// <summary>値</summary>
            public string Value { get; set; }
            /// <summary>一族の識別子</summary>
            public string FamilyId { get; set; }
            /// <summary>使った時刻（NULL なら未使用）</summary>
            public DateTime? UsedDate { get; set; }
        }

        /// <summary>
        /// **これより古い refresh_token は、無いものとして扱う**（#188）
        /// </summary>
        /// <remarks>
        /// Config.OAuth2RefreshTokenExpireTimeSpanFromDays（既定 14 日）は、
        /// 以前は**定義だけで、どこからも参照されていなかった**（事実上の無期限）。
        /// </remarks>
        private static DateTime ExpireLimit
        {
            get { return DateTime.Now - Config.OAuth2RefreshTokenExpireTimeSpanFromDays; }
        }


        #region 掃除（期限切れの行）

        /// <summary>前回まとめて消した時刻</summary>
        private static DateTime LastSweep = DateTime.MinValue;

        /// <summary>まとめて消す間隔</summary>
        /// <remarks>
        /// **常駐の仕組み（バッチ・タイマ）を増やさず、書き込みのついでに消す**（#188 の案 4）。
        /// 参照時にも期限切れは消えるが、**一度も参照されない行は残る**ため。
        /// 間隔を空けるのは、書き込みのたびに全件を走査しないため。
        /// </remarks>
        private static readonly TimeSpan SweepInterval = TimeSpan.FromMinutes(10);

        /// <summary>間隔を過ぎていたら、期限切れの行をまとめて消す</summary>
        private static void SweepIfNeeded()
        {
            DateTime now = DateTime.Now;

            lock (RefreshTokenProvider.SweepLock)
            {
                if (now - RefreshTokenProvider.LastSweep < RefreshTokenProvider.SweepInterval)
                {
                    return;
                }

                RefreshTokenProvider.LastSweep = now;
            }

            DateTime limit = RefreshTokenProvider.ExpireLimit;

            switch (Config.UserStoreType)
            {
                case EnumUserStoreType.Memory:

                    foreach (KeyValuePair<string, TokenEntry> kv in RefreshTokenProvider.RefreshTokens)
                    {
                        if (kv.Value.CreatedDate < limit)
                        {
                            RefreshTokenProvider.RefreshTokens.TryRemove(kv.Key, out TokenEntry _);
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
                                    "DELETE FROM [RefreshTokenDictionary] WHERE [CreatedDate] <= @Limit",
                                    new { Limit = limit });

                                break;

                            case EnumUserStoreType.ODPManagedDriver:

                                cnn.Execute(
                                    "DELETE FROM \"RefreshTokenDictionary\" WHERE \"CreatedDate\" <= :Limit",
                                    new { Limit = limit });

                                break;

                            case EnumUserStoreType.PostgreSQL:

                                cnn.Execute(
                                    "DELETE FROM \"refreshtokendictionary\" WHERE \"createddate\" <= @Limit",
                                    new { Limit = limit });

                                break;
                        }
                    }

                    break;
            }
        }

        /// <summary>掃除の間隔を測るための錠</summary>
        private static readonly object SweepLock = new object();

        #endregion

        #region Create

        /// <summary>新しい一族として発行する（認可コードなどからの初回）</summary>
        /// <param name="payload">payload</param>
        /// <returns>refresh_token</returns>
        /// <remarks>
        /// **payload に認可の ID（`Const.AuthorizationIdClaim`）が在れば、それを一族の識別子にする**（#421）。
        /// **認可コードが再利用されたら、同じ値で access_token と refresh_token をまとめて失効させる**（`RevocationProvider.RevokeAuthorization`）。
        /// **無ければ（認可コードを通らない経路）、新しい GUID**（従来どおり）。
        /// </remarks>
        public static string Create(string payload)
        {
            string familyId = RefreshTokenProvider.AuthorizationIdOf(payload);

            return RefreshTokenProvider.Create(payload,
                string.IsNullOrEmpty(familyId) ? Guid.NewGuid().ToString("N") : familyId);
        }

        /// <summary>payload の認可の ID（無ければ空）（#421）</summary>
        /// <param name="payload">payload</param>
        /// <returns>認可の ID</returns>
        private static string AuthorizationIdOf(string payload)
        {
            if (string.IsNullOrEmpty(payload))
            {
                return "";
            }

            JObject jobj = JwtUtil.TryParseObjectAsIs(payload);

            JToken value = (jobj == null) ? null : jobj[Const.AuthorizationIdClaim];

            return (value != null && value.Type == JTokenType.String) ? (string)value : "";
        }

        /// <summary>一族を引き継いで発行する（ローテーション）</summary>
        /// <param name="payload">payload</param>
        /// <param name="familyId">一族の識別子</param>
        /// <returns>refresh_token</returns>
        public static string Create(string payload, string familyId)
        {
            // 期限切れの行を、間隔を空けてまとめて消す（#188 の案 4）
            //   **使用済みの行は、期限までは消さない。** 再利用の検知に要るため。
            RefreshTokenProvider.SweepIfNeeded();

            string tokenId = Guid.NewGuid().ToString("N");

            if (string.IsNullOrEmpty(familyId))
            {
                familyId = Guid.NewGuid().ToString("N");
            }

            if (Config.EnableRefreshToken)
            {
                switch (Config.UserStoreType)
                {
                    case EnumUserStoreType.Memory:
                        RefreshTokenProvider.RefreshTokens.TryAdd(tokenId,
                            new TokenEntry
                            {
                                Value = payload,
                                CreatedDate = DateTime.Now,
                                FamilyId = familyId
                            });
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
                                        "INSERT INTO [RefreshTokenDictionary]"
                                        + " ([Key], [Value], [CreatedDate], [FamilyId])"
                                        + " VALUES (@Key, @Value, @CreatedDate, @FamilyId)",
                                        new { Key = tokenId, Value = payload, CreatedDate = DateTime.Now, FamilyId = familyId });

                                    break;

                                case EnumUserStoreType.ODPManagedDriver:

                                    cnn.Execute(
                                        "INSERT INTO \"RefreshTokenDictionary\""
                                        + " (\"Key\", \"Value\", \"CreatedDate\", \"FamilyId\")"
                                        + " VALUES (:Key, :Value, :CreatedDate, :FamilyId)",
                                        new { Key = tokenId, Value = payload, CreatedDate = DateTime.Now, FamilyId = familyId });

                                    break;

                                case EnumUserStoreType.PostgreSQL:

                                    cnn.Execute(
                                        "INSERT INTO \"refreshtokendictionary\""
                                        + " (\"key\", \"value\", \"createddate\", \"familyid\")"
                                        + " VALUES (@Key, @Value, @CreatedDate, @FamilyId)",
                                        new { Key = tokenId, Value = payload, CreatedDate = DateTime.Now, FamilyId = familyId });

                                    break;
                            }
                        }

                        break;
                }

                return tokenId;
            }

            return "";
        }

        #endregion

        #region Receive（ローテーションと再利用の検知）

        /// <summary>使う（ローテーション）</summary>
        /// <param name="tokenId">refresh_token</param>
        /// <returns>payload（使えなければ空）</returns>
        public static string Receive(string tokenId)
        {
            return RefreshTokenProvider.Receive(tokenId, out string _);
        }

        /// <summary>使う（ローテーション）</summary>
        /// <param name="tokenId">refresh_token</param>
        /// <param name="familyId">一族の識別子（次の発行で引き継ぐ）</param>
        /// <returns>payload（使えなければ空）</returns>
        /// <remarks>
        /// **使用済みが再び提示されたら、その一族をすべて失効させる**（#188 の段階 3）。
        /// 漏れたトークンと正規のトークンを見分けられないため（BCP §4.14.2）。
        /// 期限切れ・存在しない場合と同じく、空を返す（呼び出し元は invalid_grant にする）。
        /// </remarks>
        public static string Receive(string tokenId, out string familyId)
        {
            familyId = "";

            TokenRow row = RefreshTokenProvider.Find(tokenId);

            if (row == null)
            {
                // 存在しない、または期限切れ
                return "";
            }

            if (row.UsedDate != null)
            {
                // **再利用。** 一族ごと失効させる。
                //   **同じ認可から出した access_token も失効させる**（一族の識別子は認可の ID。E-13。#421）。
                RevocationProvider.RevokeAuthorization(row.FamilyId);
                return "";
            }

            //  **使用済みにできた 1 つだけが使う**（#332）。
            //    **できなければ、同時に来た別の要求が先に使った** — **再利用と同じく、一族ごと失効させる。**
            if (!RefreshTokenProvider.MarkAsUsed(tokenId))
            {
                RevocationProvider.RevokeAuthorization(row.FamilyId);
                return "";
            }

            familyId = row.FamilyId;
            return row.Value;
        }

        #endregion

        #region Refer（覗く）

        /// <summary>覗く（消費しない）</summary>
        /// <param name="tokenId">refresh_token</param>
        /// <returns>payload（使えなければ空）</returns>
        /// <remarks>
        /// **使用済み・期限切れは「無い」と同じ。** introspect が active: true を返さないようにする（#188）。
        /// </remarks>
        public static string Refer(string tokenId)
        {
            TokenRow row = RefreshTokenProvider.Find(tokenId);

            if (row == null || row.UsedDate != null)
            {
                return "";
            }

            return row.Value;
        }

        #endregion

        #region Delete（失効）

        /// <summary>失効させる（一族ごと）</summary>
        /// <param name="tokenId">refresh_token</param>
        /// <returns>失効させたか</returns>
        /// <remarks>
        /// **一族ごと失効させる**（#188 の段階 3）。
        /// RFC 7009 §2.1 は、refresh_token を失効させるとき、
        /// **同じ認可グラントに基づくトークンも無効にすべき**としている。
        /// 漏れたトークンを失効させたのに、そこから派生した新しいトークンが生き残るのは、利用者の意図と違う。
        ///
        /// **同じ認可から出した access_token も失効させる**（E-13。#421）。
        /// **一族の識別子は認可の ID**（`Create`）なので、**`RevocationProvider.RevokeAuthorization` で、一族と access_token をまとめて止める。**
        /// **以前は一族だけを消していた**ので、**access_token は期限まで使えた。**
        /// **認可の ID を持たない access_token**（この変更の前に出したもの）**は、従来どおり期限まで使える。**
        /// </remarks>
        public static bool Delete(string tokenId)
        {
            TokenRow row = RefreshTokenProvider.Find(tokenId);

            if (row == null)
            {
                // 存在しない、または期限切れ
                return false;
            }

            RevocationProvider.RevokeAuthorization(row.FamilyId);

            return true;
        }

        #endregion

        #region 内部（探す・使用済みにする・一族を失効させる）

        /// <summary>期限内の 1 行を探す（期限切れは消す）</summary>
        /// <param name="tokenId">refresh_token</param>
        /// <returns>行（無い・期限切れなら null）</returns>
        private static TokenRow Find(string tokenId)
        {
            //  **列の幅（256）を超える値は、引くまでもなく「無い」**（#331。Oracle は例外にする）。
            if (!MultiPurposeAuthSite.Data.CmnStore.IsSearchable(tokenId, 256))
            {
                return null;
            }

            switch (Config.UserStoreType)
            {
                case EnumUserStoreType.Memory:

                    TokenEntry entry = null;

                    if (!RefreshTokenProvider.RefreshTokens.TryGetValue(tokenId, out entry))
                    {
                        return null;
                    }

                    if (entry.CreatedDate < RefreshTokenProvider.ExpireLimit)
                    {
                        // 期限切れ。参照した時点で消す。
                        RefreshTokenProvider.RefreshTokens.TryRemove(tokenId, out TokenEntry _);
                        return null;
                    }

                    return new TokenRow
                    {
                        Value = entry.Value,
                        FamilyId = entry.FamilyId,
                        UsedDate = entry.UsedDate
                    };

                case EnumUserStoreType.SqlServer:
                case EnumUserStoreType.ODPManagedDriver:
                case EnumUserStoreType.PostgreSQL: // DMBMS

                    using (IDbConnection cnn = DataAccess.CreateConnection())
                    {
                        cnn.Open();

                        switch (Config.UserStoreType)
                        {
                            case EnumUserStoreType.SqlServer:

                                return cnn.QueryFirstOrDefault<TokenRow>(
                                    "SELECT [Value], [FamilyId], [UsedDate] FROM [RefreshTokenDictionary]"
                                    + " WHERE [Key] = @Key AND [CreatedDate] > @Limit",
                                    new { Key = tokenId, Limit = RefreshTokenProvider.ExpireLimit });

                            case EnumUserStoreType.ODPManagedDriver:

                                return cnn.QueryFirstOrDefault<TokenRow>(
                                    "SELECT \"Value\", \"FamilyId\", \"UsedDate\" FROM \"RefreshTokenDictionary\""
                                    + " WHERE \"Key\" = :Key AND \"CreatedDate\" > :Limit",
                                    new { Key = tokenId, Limit = RefreshTokenProvider.ExpireLimit });

                            case EnumUserStoreType.PostgreSQL:

                                return cnn.QueryFirstOrDefault<TokenRow>(
                                    "SELECT \"value\" AS \"Value\", \"familyid\" AS \"FamilyId\","
                                    + " \"useddate\" AS \"UsedDate\" FROM \"refreshtokendictionary\""
                                    + " WHERE \"key\" = @Key AND \"createddate\" > @Limit",
                                    new { Key = tokenId, Limit = RefreshTokenProvider.ExpireLimit });
                        }
                    }

                    break;
            }

            return null;
        }

        /// <summary>使用済みにする（消さない）</summary>
        /// <param name="tokenId">refresh_token</param>
        /// <returns>**この呼び出しが使用済みにしたら true**（他が先に使用済みにしていたら false）</returns>
        /// <remarks>
        /// **未使用のときだけ書く**（#332）。**以前は条件なしに書き、書けたかを見ていなかった**ので、
        /// **同時に来た要求の両方が「未使用」と読めて、両方にトークンが出た。**
        /// </remarks>
        private static bool MarkAsUsed(string tokenId)
        {
            int updated = 0;

            switch (Config.UserStoreType)
            {
                case EnumUserStoreType.Memory:

                    TokenEntry entry = null;

                    if (RefreshTokenProvider.RefreshTokens.TryGetValue(tokenId, out entry))
                    {
                        lock (entry)
                        {
                            if (entry.UsedDate == null)
                            {
                                entry.UsedDate = DateTime.Now;
                                updated = 1;
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

                                //  **同じ行の更新が重なると、SQL Server はデッドロックの犠牲を選ぶ**（#332）。やり直す。
                                updated = DataAccess.RetryWriteOnDeadlock(() => cnn.Execute(
                                    "UPDATE [RefreshTokenDictionary] SET [UsedDate] = @UsedDate"
                                    + " WHERE [Key] = @Key AND [UsedDate] IS NULL",
                                    new { Key = tokenId, UsedDate = DateTime.Now }));

                                break;

                            case EnumUserStoreType.ODPManagedDriver:

                                updated = cnn.Execute(
                                    "UPDATE \"RefreshTokenDictionary\" SET \"UsedDate\" = :UsedDate"
                                    + " WHERE \"Key\" = :Key AND \"UsedDate\" IS NULL",
                                    new { Key = tokenId, UsedDate = DateTime.Now });

                                break;

                            case EnumUserStoreType.PostgreSQL:

                                updated = cnn.Execute(
                                    "UPDATE \"refreshtokendictionary\" SET \"useddate\" = @UsedDate"
                                    + " WHERE \"key\" = @Key AND \"useddate\" IS NULL",
                                    new { Key = tokenId, UsedDate = DateTime.Now });

                                break;
                        }
                    }

                    break;
            }

            return updated == 1;
        }

        /// <summary>一族ごと失効させる（消す）</summary>
        /// <param name="familyId">一族の識別子</param>
        /// <remarks>**認可の ID の失効（`RevocationProvider.RevokeAuthorization`）からも呼ぶ**ので internal にした（#421）。</remarks>
        internal static void RevokeFamily(string familyId)
        {
            if (string.IsNullOrEmpty(familyId))
            {
                return;
            }

            switch (Config.UserStoreType)
            {
                case EnumUserStoreType.Memory:

                    foreach (KeyValuePair<string, TokenEntry> kv in RefreshTokenProvider.RefreshTokens)
                    {
                        if (kv.Value.FamilyId == familyId)
                        {
                            RefreshTokenProvider.RefreshTokens.TryRemove(kv.Key, out TokenEntry _);
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
                                    "DELETE FROM [RefreshTokenDictionary] WHERE [FamilyId] = @FamilyId",
                                    new { FamilyId = familyId });

                                break;

                            case EnumUserStoreType.ODPManagedDriver:

                                cnn.Execute(
                                    "DELETE FROM \"RefreshTokenDictionary\" WHERE \"FamilyId\" = :FamilyId",
                                    new { FamilyId = familyId });

                                break;

                            case EnumUserStoreType.PostgreSQL:

                                cnn.Execute(
                                    "DELETE FROM \"refreshtokendictionary\" WHERE \"familyid\" = @FamilyId",
                                    new { FamilyId = familyId });

                                break;
                        }
                    }

                    break;
            }
        }

        #endregion
    }
}
