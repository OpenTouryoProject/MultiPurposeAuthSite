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
//* クラス名        ：AuthFailureProvider
//* クラス日本語名  ：認証の失敗を数えて、一定回数で一定時間断る
//*
//* 作成日時        ：－
//* 作成者          ：－
//* 更新履歴        ：－
//*
//*  日時        更新者            内容
//*  ----------  ----------------  -------------------------------------------------
//*  2026/10/16  玄人 幸道         新規（#305 の段階 2）
//**********************************************************************************

using MultiPurposeAuthSite.Co;
using MultiPurposeAuthSite.Data;

using System;
using System.Collections.Concurrent;
using System.Data;

using Dapper;

/// <summary>MultiPurposeAuthSite.Extensions.Sts</summary>
namespace MultiPurposeAuthSite.Extensions.Sts
{
    /// <summary>
    /// 認証の失敗を数えて、**一定回数で一定時間断る**（#305 の段階 2）。
    /// </summary>
    /// <remarks>
    /// **総当たりを「回数」で止める**（`ANALYSIS-IdP.md` の D-13）。
    ///
    /// | 鍵 | 何の失敗か |
    /// |---|---|
    /// | **`client:<client_id>`** | **クライアント認証**（`client_secret` / `private_key_jwt`） |
    /// | **`device_verify:<利用者>`** | **`user_code` の投入**（RFC 8628 §5.2） |
    ///
    /// | 設定 | |
    /// |---|---|
    /// | `AuthFailureMaxAttempts` | **この回数で断る**（**0 なら数えない** ＝ 従来どおり） |
    /// | `AuthFailureLockoutSeconds` | **断る長さ**（秒） |
    ///
    /// **成功したら消す**（連続した失敗だけを数える。ASP.NET Identity のロックアウトと同じ考え）。
    /// **表に持つ**ので、**インスタンスを増やしても効く。**
    ///
    /// **断っている間は、正しい資格情報でも通さない。**
    /// **それが「効いている」ことの見え方**である（`RT-305.3` / `RT-305.4`）。
    ///
    /// **サインインのロックアウトとは別**である（あちらは ASP.NET Identity の
    /// `MaxFailedAccessAttemptsBeforeLockout`。**利用者のパスワード**が対象）。
    /// </remarks>
    public class AuthFailureProvider
    {
        #region mem の入れ物

        /// <summary>mem のときの入れ物（鍵 → 回数と期限）</summary>
        private static ConcurrentDictionary<string, Tuple<int, long?>> Failures
            = new ConcurrentDictionary<string, Tuple<int, long?>>();

        #endregion

        #region 公開

        /// <summary>いま断っているか</summary>
        /// <param name="key">鍵</param>
        /// <returns>断っていれば true</returns>
        public static bool IsLockedOut(string key)
        {
            if (!AuthFailureProvider.Enabled || string.IsNullOrEmpty(key))
            {
                return false;
            }

            long? lockoutEndAt = AuthFailureProvider.Get(key).Item2;

            return lockoutEndAt.HasValue
                && AuthFailureProvider.NowUnixSeconds() < lockoutEndAt.Value;
        }

        /// <summary>失敗を 1 回数える（上限に達したら断り始める）</summary>
        /// <param name="key">鍵</param>
        /// <returns>断り始めたら true</returns>
        public static bool Record(string key)
        {
            if (!AuthFailureProvider.Enabled || string.IsNullOrEmpty(key))
            {
                return false;
            }

            Tuple<int, long?> current = AuthFailureProvider.Get(key);
            int count = current.Item1 + 1;
            long? lockoutEndAt = current.Item2;

            if (Config.AuthFailureMaxAttempts <= count)
            {
                //  **上限に達した。** **断る期限を入れ、回数を 0 に戻す**
                //    （**期限が切れたら、また同じ回数だけ試せる**）。
                lockoutEndAt = AuthFailureProvider.NowUnixSeconds()
                    + Config.AuthFailureLockoutSeconds;
                count = 0;
            }

            AuthFailureProvider.Save(key, count, lockoutEndAt);

            return lockoutEndAt.HasValue
                && AuthFailureProvider.NowUnixSeconds() < lockoutEndAt.Value;
        }

        /// <summary>成功したので消す</summary>
        /// <param name="key">鍵</param>
        public static void Clear(string key)
        {
            if (!AuthFailureProvider.Enabled || string.IsNullOrEmpty(key))
            {
                return;
            }

            switch (Config.UserStoreType)
            {
                case EnumUserStoreType.Memory:

                    Tuple<int, long?> temp = null;
                    AuthFailureProvider.Failures.TryRemove(key, out temp);

                    break;

                case EnumUserStoreType.SqlServer:
                case EnumUserStoreType.ODPManagedDriver:
                case EnumUserStoreType.PostgreSQL: // DMBMS

                    using (IDbConnection cnn = DataAccess.CreateConnection())
                    {
                        cnn.Open();

                        cnn.Execute(
                            "DELETE FROM " + AuthFailureProvider.TableName()
                            + AuthFailureProvider.WhereKey(),
                            new { FailureKey = key });
                    }

                    break;
            }
        }

        #endregion

        #region 内部

        /// <summary>この配備で数えるか（`AuthFailureMaxAttempts` が正のときだけ）</summary>
        private static bool Enabled
        {
            get
            {
                return 0 < Config.AuthFailureMaxAttempts;
            }
        }

        /// <summary>いまの UNIX 時刻（秒）</summary>
        private static long NowUnixSeconds()
        {
            return DateTimeOffset.UtcNow.ToUnixTimeSeconds();
        }

        /// <summary>いまの回数と期限（無ければ 0 と null）</summary>
        /// <param name="key">鍵</param>
        /// <returns>回数と期限</returns>
        private static Tuple<int, long?> Get(string key)
        {
            switch (Config.UserStoreType)
            {
                case EnumUserStoreType.Memory:

                    Tuple<int, long?> value = null;
                    return AuthFailureProvider.Failures.TryGetValue(key, out value)
                        ? value : new Tuple<int, long?>(0, null);

                case EnumUserStoreType.SqlServer:
                case EnumUserStoreType.ODPManagedDriver:
                case EnumUserStoreType.PostgreSQL: // DMBMS

                    using (IDbConnection cnn = DataAccess.CreateConnection())
                    {
                        cnn.Open();

                        dynamic dyn = cnn.QueryFirstOrDefault(
                            "SELECT " + AuthFailureProvider.SelectColumnList()
                            + " FROM " + AuthFailureProvider.TableName()
                            + AuthFailureProvider.WhereKey(),
                            new { FailureKey = key });

                        if (dyn == null)
                        {
                            return new Tuple<int, long?>(0, null);
                        }

                        //  **Oracle の NUMBER は decimal で返る**ので、Convert を通す（#207 の教訓）。
                        int count = Convert.ToInt32(dyn.FailedCount);
                        long? lockoutEndAt = (dyn.LockoutEndAt == null)
                            ? (long?)null : Convert.ToInt64(dyn.LockoutEndAt);

                        return new Tuple<int, long?>(count, lockoutEndAt);
                    }
            }

            return new Tuple<int, long?>(0, null);
        }

        /// <summary>回数と期限を書く（無ければ足す）</summary>
        /// <param name="key">鍵</param>
        /// <param name="count">回数</param>
        /// <param name="lockoutEndAt">期限</param>
        private static void Save(string key, int count, long? lockoutEndAt)
        {
            switch (Config.UserStoreType)
            {
                case EnumUserStoreType.Memory:

                    AuthFailureProvider.Failures[key] = new Tuple<int, long?>(count, lockoutEndAt);

                    break;

                case EnumUserStoreType.SqlServer:
                case EnumUserStoreType.ODPManagedDriver:
                case EnumUserStoreType.PostgreSQL: // DMBMS

                    using (IDbConnection cnn = DataAccess.CreateConnection())
                    {
                        cnn.Open();

                        //  **更新 → 0 件なら挿入**（方言ごとの UPSERT を書かない）。
                        int updated = cnn.Execute(
                            "UPDATE " + AuthFailureProvider.TableName()
                            + " SET " + AuthFailureProvider.SetList()
                            + AuthFailureProvider.WhereKey(),
                            new { FailureKey = key, FailedCount = count, LockoutEndAt = lockoutEndAt });

                        if (updated == 0)
                        {
                            cnn.Execute(
                                "INSERT INTO " + AuthFailureProvider.TableName()
                                + " (" + AuthFailureProvider.InsertColumnList() + ")"
                                + " VALUES (" + AuthFailureProvider.ParameterList() + ")",
                                new { FailureKey = key, FailedCount = count, LockoutEndAt = lockoutEndAt });
                        }
                    }

                    break;
            }
        }

        #endregion

        #region 方言

        /// <summary>テーブル名</summary>
        private static string TableName()
        {
            switch (Config.UserStoreType)
            {
                case EnumUserStoreType.SqlServer:
                    return "[AuthFailure]";
                case EnumUserStoreType.ODPManagedDriver:
                    return "\"AuthFailure\"";
                default:
                    return "\"authfailure\"";
            }
        }

        /// <summary>SELECT の列の並び</summary>
        /// <remarks>
        /// **PostgreSQL は引用符なしの識別子が小文字に畳まれる**ので、
        /// **小文字で引き、別名を付けて属性名で受け取る**（`IdFederationUpstreamProvider` と同じ）。
        /// **別名は SELECT だけ** — **INSERT の列に別名は書けない**
        /// （実測 : 共用して PostgreSQL の INSERT が落ち、`RT-305.3` / `RT-305.4` が落ちた）。
        /// </remarks>
        private static string SelectColumnList()
        {
            switch (Config.UserStoreType)
            {
                case EnumUserStoreType.SqlServer:
                    return "[FailureKey], [FailedCount], [LockoutEndAt]";
                case EnumUserStoreType.ODPManagedDriver:
                    return "\"FailureKey\", \"FailedCount\", \"LockoutEndAt\"";
                default:
                    return "\"failurekey\" AS \"FailureKey\", \"failedcount\" AS \"FailedCount\""
                        + ", \"lockoutendat\" AS \"LockoutEndAt\"";
            }
        }

        /// <summary>INSERT の列の並び（別名を付けない）</summary>
        private static string InsertColumnList()
        {
            switch (Config.UserStoreType)
            {
                case EnumUserStoreType.SqlServer:
                    return "[FailureKey], [FailedCount], [LockoutEndAt]";
                case EnumUserStoreType.ODPManagedDriver:
                    return "\"FailureKey\", \"FailedCount\", \"LockoutEndAt\"";
                default:
                    return "\"failurekey\", \"failedcount\", \"lockoutendat\"";
            }
        }

        /// <summary>パラメタの並び（Oracle だけ「:」）</summary>
        private static string ParameterList()
        {
            string p = (Config.UserStoreType == EnumUserStoreType.ODPManagedDriver) ? ":" : "@";

            return p + "FailureKey, " + p + "FailedCount, " + p + "LockoutEndAt";
        }

        /// <summary>UPDATE の SET 句</summary>
        private static string SetList()
        {
            switch (Config.UserStoreType)
            {
                case EnumUserStoreType.SqlServer:
                    return "[FailedCount] = @FailedCount, [LockoutEndAt] = @LockoutEndAt";
                case EnumUserStoreType.ODPManagedDriver:
                    return "\"FailedCount\" = :FailedCount, \"LockoutEndAt\" = :LockoutEndAt";
                default:
                    return "\"failedcount\" = @FailedCount, \"lockoutendat\" = @LockoutEndAt";
            }
        }

        /// <summary>鍵の条件句</summary>
        private static string WhereKey()
        {
            switch (Config.UserStoreType)
            {
                case EnumUserStoreType.SqlServer:
                    return " WHERE [FailureKey] = @FailureKey";
                case EnumUserStoreType.ODPManagedDriver:
                    return " WHERE \"FailureKey\" = :FailureKey";
                default:
                    return " WHERE \"failurekey\" = @FailureKey";
            }
        }

        #endregion

        #region 鍵の作り方

        /// <summary>クライアント認証の鍵</summary>
        /// <param name="clientId">client_id</param>
        /// <returns>鍵（client_id が空なら空）</returns>
        public static string ClientKey(string clientId)
        {
            return string.IsNullOrEmpty(clientId) ? "" : ("client:" + clientId);
        }

        /// <summary>`user_code` の投入の鍵（投入した利用者ごと）</summary>
        /// <param name="userName">利用者名</param>
        /// <returns>鍵（利用者名が空なら空）</returns>
        /// <remarks>
        /// **間違えた `user_code` では、どの要求を狙ったか分からない。**
        /// **だから「投入した人」で数える**（RFC 8628 §5.2 が求めるのは、投入の制限である）。
        /// </remarks>
        public static string DeviceVerifyKey(string userName)
        {
            return string.IsNullOrEmpty(userName) ? "" : ("device_verify:" + userName);
        }

        #endregion
    }
}
