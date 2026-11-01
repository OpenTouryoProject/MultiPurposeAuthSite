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
//* クラス名        ：RevocationProvider
//* クラス日本語名  ：RevocationしたOAuth2のaccess_tokenのjtiを保存する（ライブラリ）
//*
//* 作成日時        ：－
//* 作成者          ：－
//* 更新履歴        ：－
//*
//*  日時        更新者            内容
//*  ----------  ----------------  -------------------------------------------------
//*  2017/06/07  西野 大介         新規
//*  2026/11/01  玄人 幸道         Extensions/Sts から TokenProviders へ移した（RFC 7009 の失効の状態。失効・照会は OAuth 2.0 として本体に置く。#321）
//*  2026/11/01  玄人 幸道         access_token の exp を記録し、exp を過ぎた記録を消す（#322）
//**********************************************************************************

using MultiPurposeAuthSite.Co;
using MultiPurposeAuthSite.Data;

using System;
using System.Data;
using System.Collections.Concurrent;

using Dapper;

namespace MultiPurposeAuthSite.TokenProviders
{
    /// <summary>
    /// RevocationしたOAuth2のaccess_tokenのjtiを保存する。
    /// </summary>
    public class RevocationProvider
    {
        /// <summary>
        /// OAuth2RevocationProvider
        /// ConcurrentDictionaryは、.NET 4.0の新しいスレッドセーフなHashtable
        /// </summary>
        /// <remarks>値は（記録した時刻, access_token の exp（UNIX 秒。分からなければ null））。</remarks>
        private static ConcurrentDictionary<string, Tuple<DateTime, long?>>
            OAuth2Revocation = new ConcurrentDictionary<string, Tuple<DateTime, long?>>();

        /// <summary>何回の記録ごとに掃除するか（要求ごとに DELETE を撃たない）</summary>
        private const int PruneInterval = 100;

        /// <summary>exp を過ぎてから消すまでの余裕（秒）</summary>
        /// <remarks>
        /// **消すのが早いと、失効させた access_token が期限内に通ってしまう**ので、**遅い側に倒す**
        /// （**サーバ間の時計のずれ**を見込む）。**exp は UTC の UNIX 秒**なので、夏時間には左右されない。
        /// </remarks>
        private const long RetentionMarginSeconds = 300;

        /// <summary>記録の回数（掃除の間隔を数える）</summary>
        private static int CreateCount = 0;

        #region Create

        /// <summary>Create</summary>
        /// <param name="jti">string</param>
        /// <param name="exp">access_token の exp（UNIX 秒。分からなければ null ＝ 消さない）</param>
        public static void Create(string jti, long? exp)
        {
            switch (Config.UserStoreType)
            {
                case EnumUserStoreType.Memory:
                    RevocationProvider.OAuth2Revocation.TryAdd(jti, Tuple.Create(DateTime.Now, exp));
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
                                    "INSERT INTO [OAuth2Revocation] ([Jti], [CreatedDate], [ExpiresAt]) VALUES (@Jti, @CreatedDate, @ExpiresAt)",
                                    new { Jti = jti, CreatedDate = DateTime.Now, ExpiresAt = exp });

                                break;

                            case EnumUserStoreType.ODPManagedDriver:

                                cnn.Execute(
                                    "INSERT INTO \"OAuth2Revocation\" (\"Jti\", \"CreatedDate\", \"ExpiresAt\") VALUES (:Jti, :CreatedDate, :ExpiresAt)",
                                    new { Jti = jti, CreatedDate = DateTime.Now, ExpiresAt = exp });

                                break;

                            case EnumUserStoreType.PostgreSQL:

                                cnn.Execute(
                                    "INSERT INTO \"oauth2revocation\" (\"jti\", \"createddate\", \"expiresat\") VALUES (@Jti, @CreatedDate, @ExpiresAt)",
                                    new { Jti = jti, CreatedDate = DateTime.Now, ExpiresAt = exp });

                                break;
                        }
                    }

                    break;
            }

            RevocationProvider.PruneExpired();
        }

        #endregion

        #region PruneExpired

        /// <summary>access_token の exp を過ぎた記録を消す（#322）</summary>
        /// <remarks>
        /// **exp を過ぎた access_token は、`exp` の確認で落ちる**ので、**失効の記録はもう要らない。**
        /// **そのトークンの exp を基準にする**ので、**期限の設定を変えても、早く消えない。**
        /// **exp の無い記録**（列を足す前の行）**は消さない**（いつ消してよいか分からない）。
        /// **書き込み `PruneInterval` 回に 1 回だけ**行う。
        /// **掃除に失敗しても、失効は済んでいる**（次の機会に消せばよい）。
        /// </remarks>
        private static void PruneExpired()
        {
            if (0 != (System.Threading.Interlocked.Increment(
                ref RevocationProvider.CreateCount) % RevocationProvider.PruneInterval))
            {
                return;
            }

            long limit = DateTimeOffset.UtcNow.ToUnixTimeSeconds() - RevocationProvider.RetentionMarginSeconds;

            try
            {
                switch (Config.UserStoreType)
                {
                    case EnumUserStoreType.Memory:

                        foreach (System.Collections.Generic.KeyValuePair<string, Tuple<DateTime, long?>> kv in RevocationProvider.OAuth2Revocation)
                        {
                            if (kv.Value.Item2.HasValue && kv.Value.Item2.Value <= limit)
                            {
                                RevocationProvider.OAuth2Revocation.TryRemove(kv.Key, out Tuple<DateTime, long?> _);
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
                                        "DELETE FROM [OAuth2Revocation] WHERE [ExpiresAt] <= @Limit",
                                        new { Limit = limit });

                                    break;

                                case EnumUserStoreType.ODPManagedDriver:

                                    cnn.Execute(
                                        "DELETE FROM \"OAuth2Revocation\" WHERE \"ExpiresAt\" <= :Limit",
                                        new { Limit = limit });

                                    break;

                                case EnumUserStoreType.PostgreSQL:

                                    cnn.Execute(
                                        "DELETE FROM \"oauth2revocation\" WHERE \"expiresat\" <= @Limit",
                                        new { Limit = limit });

                                    break;
                            }
                        }

                        break;
                }
            }
            catch
            {
                //  **掃除は、落ちても構わない。**
            }
        }

        #endregion

        #region Get(Reference)

        /// <summary>Get</summary>
        /// <param name="jti">string</param>
        /// <returns>DateTime?</returns>
        public static DateTime? Get(string jti)
        {
            DateTime? datetime = null;

            switch (Config.UserStoreType)
            {
                case EnumUserStoreType.Memory:

                    Tuple<DateTime, long?> temp = null;
                    if (RevocationProvider.OAuth2Revocation.TryGetValue(jti, out temp))
                    {
                        datetime = temp.Item1;
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

                                datetime = cnn.ExecuteScalar<DateTime>(
                                    "SELECT [CreatedDate] FROM [OAuth2Revocation] WHERE [Jti] = @Jti", new { Jti = jti });

                                break;

                            case EnumUserStoreType.ODPManagedDriver:

                                datetime = cnn.ExecuteScalar<DateTime>(
                                    "SELECT \"CreatedDate\" FROM \"OAuth2Revocation\" WHERE \"Jti\" = :Jti", new { Jti = jti });

                                break;

                            case EnumUserStoreType.PostgreSQL:

                                datetime = cnn.ExecuteScalar<DateTime>(
                                    "SELECT \"createddate\" FROM \"oauth2revocation\" WHERE \"jti\" = @Jti", new { Jti = jti });

                                break;
                        }
                    }

                    break;
            }

            // {0001/01/01 00:00} チェック
            if (datetime == DateTime.MinValue)
            {
                return null;
            }
            else
            {
                return datetime;
            }
        }

        #endregion
    }
}