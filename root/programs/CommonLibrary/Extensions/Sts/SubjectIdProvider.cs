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
//* クラス名        ：SubjectIdProvider
//* クラス日本語名  ：発行した sub（Subject Identifier）の対応表
//*
//* 作成日時        ：－
//* 作成者          ：－
//* 更新履歴        ：－
//*
//*  日時        更新者            内容
//*  ----------  ----------------  -------------------------------------------------
//*  2026/09/30  玄人 幸道         新規（#151 の段階 2）
//**********************************************************************************

using MultiPurposeAuthSite.Co;
using MultiPurposeAuthSite.Data;

using System;
using System.Collections.Concurrent;
using System.Data;

using Dapper;

namespace MultiPurposeAuthSite.Extensions.Sts
{
    /// <summary>
    /// **発行した `sub` を記録し、引く**（#151 の段階 2）。
    /// </summary>
    /// <remarks>
    /// **なぜ在るか。**
    /// `sub` を**その場で計算していると、計算の仕方を変えた瞬間に全部変わる。**
    /// RP は **`sub` を利用者の主キーとして保存する**ので、**RP 側では全員が別人になる。**
    ///
    /// **表に記録すると、`sub` が「導出」から「データ」になる。**
    /// `subject_types` の既定を変えても、PPID の秘密を替えても、**発行済みの `sub` は動かない。**
    ///
    /// | 解ける問題 | |
    /// |---|---|
    /// | #151 | `subject_types` の既定を `public` に変えても、既存の RP が壊れない |
    /// | D-9-2 | PPID の秘密（`SaltParameter`）を**漏洩時に替えられる** |
    ///
    /// **`pairwise` 専用ではない。** `uname` / `public` の `sub` も入れる
    /// （そうしないと、既定値の変更を無害にできない）。
    /// `uname` / `public` では**同じ値が Sector ごとに入る**（冗長）が、害は無い。
    /// むしろ表の意味が **「この RP には、この利用者を、この `sub` で名乗った」**になり、
    /// **守りたい契約そのもの**を記録することになる。
    ///
    /// **Sector は、いまは `client_id`。**
    /// `sector_identifier_uri`（OIDC Core §8.1）に対応したら、その解決結果が入る。
    /// **列の意味は「Sector Identifier」**なので、対応しても**既存行はそのまま有効**である。
    ///
    /// **利用者を削除したときの後始末は、DB では外部キー（ON DELETE CASCADE）が行う。**
    /// `mem` では、この実装が消す。
    /// </remarks>
    public class SubjectIdProvider
    {
        /// <summary>
        /// Memory ストア用。キーは Sector + "\t" + UserId。
        /// ConcurrentDictionary は、.NET 4.0 の新しいスレッドセーフな Hashtable
        /// </summary>
        private static ConcurrentDictionary<string, string> SubjectIds
            = new ConcurrentDictionary<string, string>();

        #region キー

        /// <summary>Memory ストア用のキーを作る</summary>
        /// <param name="sector">Sector Identifier</param>
        /// <param name="userId">UserId</param>
        /// <returns>キー</returns>
        private static string MemoryKey(string sector, string userId)
        {
            return (sector ?? "") + "\t" + (userId ?? "");
        }

        #endregion

        #region GetOrAdd

        /// <summary>
        /// 記録済みの `sub` を返す。無ければ `newSub` を記録して返す。
        /// </summary>
        /// <param name="sector">Sector Identifier（いまは client_id）</param>
        /// <param name="userId">UserId</param>
        /// <param name="newSub">記録されていないときに記録する値</param>
        /// <returns>sub</returns>
        /// <remarks>
        /// **「在れば返す、無ければ入れる」**。**発行のたびに通る**ので、
        /// **在るときは書き込まない。**
        ///
        /// **競合したときは、入っている方を返す。**
        /// 同じ (Sector, UserId) なら計算結果も同じなので、どちらでも同じ値になる。
        /// </remarks>
        public static string GetOrAdd(string sector, string userId, string newSub)
        {
            if (string.IsNullOrEmpty(sector) || string.IsNullOrEmpty(userId)
                || string.IsNullOrEmpty(newSub))
            {
                // 記録しない（クライアント認証など、利用者が居ない経路）
                return newSub;
            }

            string sub = SubjectIdProvider.Get(sector, userId);

            if (!string.IsNullOrEmpty(sub))
            {
                return sub;
            }

            SubjectIdProvider.Add(sector, userId, newSub);

            // **入れた直後に引き直す。** 競合していたら、入っている方が返る。
            sub = SubjectIdProvider.Get(sector, userId);

            return string.IsNullOrEmpty(sub) ? newSub : sub;
        }

        #endregion

        #region Get（Sector × UserId → sub）

        /// <summary>記録済みの `sub` を引く</summary>
        /// <param name="sector">Sector Identifier</param>
        /// <param name="userId">UserId</param>
        /// <returns>sub（無ければ空文字）</returns>
        public static string Get(string sector, string userId)
        {
            string sub = "";

            switch (Config.UserStoreType)
            {
                case EnumUserStoreType.Memory:
                    SubjectIdProvider.SubjectIds.TryGetValue(
                        SubjectIdProvider.MemoryKey(sector, userId), out sub);
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

                                sub = cnn.ExecuteScalar<string>(
                                    "SELECT [Sub] FROM [SubjectIdentifier]"
                                    + " WHERE [Sector] = @Sector AND [UserId] = @UserId",
                                    new { Sector = sector, UserId = userId });

                                break;

                            case EnumUserStoreType.ODPManagedDriver:

                                sub = cnn.ExecuteScalar<string>(
                                    "SELECT \"Sub\" FROM \"SubjectIdentifier\""
                                    + " WHERE \"Sector\" = :Sector AND \"UserId\" = :UserId",
                                    new { Sector = sector, UserId = userId });

                                break;

                            case EnumUserStoreType.PostgreSQL:

                                sub = cnn.ExecuteScalar<string>(
                                    "SELECT \"sub\" FROM \"subjectidentifier\""
                                    + " WHERE \"sector\" = @Sector AND \"userid\" = @UserId",
                                    new { Sector = sector, UserId = userId });

                                break;
                        }
                    }

                    break;
            }

            return sub ?? "";
        }

        #endregion

        #region GetUserId（Sector × sub → UserId。逆引き）

        /// <summary>`sub` から UserId を引く（逆引き）</summary>
        /// <param name="sector">Sector Identifier</param>
        /// <param name="sub">sub</param>
        /// <returns>UserId（無ければ空文字）</returns>
        /// <remarks>
        /// **外から来た値を渡される**（アクセス トークンの `sub`）ので、
        /// **見つからないことは普通である**（他の Sector 向け・でたらめ）。
        /// </remarks>
        public static string GetUserId(string sector, string sub)
        {
            string userId = "";

            if (string.IsNullOrEmpty(sector) || string.IsNullOrEmpty(sub))
            {
                return "";
            }

            switch (Config.UserStoreType)
            {
                case EnumUserStoreType.Memory:

                    string prefix = (sector ?? "") + "\t";

                    foreach (System.Collections.Generic.KeyValuePair<string, string> one
                        in SubjectIdProvider.SubjectIds)
                    {
                        if (one.Key.StartsWith(prefix, StringComparison.Ordinal)
                            && one.Value == sub)
                        {
                            userId = one.Key.Substring(prefix.Length);
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

                        switch (Config.UserStoreType)
                        {
                            case EnumUserStoreType.SqlServer:

                                userId = cnn.ExecuteScalar<string>(
                                    "SELECT [UserId] FROM [SubjectIdentifier]"
                                    + " WHERE [Sector] = @Sector AND [Sub] = @Sub",
                                    new { Sector = sector, Sub = sub });

                                break;

                            case EnumUserStoreType.ODPManagedDriver:

                                userId = cnn.ExecuteScalar<string>(
                                    "SELECT \"UserId\" FROM \"SubjectIdentifier\""
                                    + " WHERE \"Sector\" = :Sector AND \"Sub\" = :Sub",
                                    new { Sector = sector, Sub = sub });

                                break;

                            case EnumUserStoreType.PostgreSQL:

                                userId = cnn.ExecuteScalar<string>(
                                    "SELECT \"userid\" FROM \"subjectidentifier\""
                                    + " WHERE \"sector\" = @Sector AND \"sub\" = @Sub",
                                    new { Sector = sector, Sub = sub });

                                break;
                        }
                    }

                    break;
            }

            return userId ?? "";
        }

        #endregion

        #region Add

        /// <summary>記録する</summary>
        /// <param name="sector">Sector Identifier</param>
        /// <param name="userId">UserId</param>
        /// <param name="sub">sub</param>
        /// <remarks>
        /// **競合は例外にしない。** 同時に 2 本走れば、片方が主キーで弾かれる。
        /// **同じ値になる**ので、弾かれた側は「入っている方」を読めばよい。
        /// </remarks>
        private static void Add(string sector, string userId, string sub)
        {
            try
            {
                switch (Config.UserStoreType)
                {
                    case EnumUserStoreType.Memory:
                        SubjectIdProvider.SubjectIds.TryAdd(
                            SubjectIdProvider.MemoryKey(sector, userId), sub);
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
                                        "INSERT INTO [SubjectIdentifier]"
                                        + " ([Sector], [UserId], [Sub], [CreatedDate])"
                                        + " VALUES (@Sector, @UserId, @Sub, @CreatedDate)",
                                        new
                                        {
                                            Sector = sector, UserId = userId, Sub = sub,
                                            CreatedDate = DateTime.Now
                                        });

                                    break;

                                case EnumUserStoreType.ODPManagedDriver:

                                    cnn.Execute(
                                        "INSERT INTO \"SubjectIdentifier\""
                                        + " (\"Sector\", \"UserId\", \"Sub\", \"CreatedDate\")"
                                        + " VALUES (:Sector, :UserId, :Sub, :CreatedDate)",
                                        new
                                        {
                                            Sector = sector, UserId = userId, Sub = sub,
                                            CreatedDate = DateTime.Now
                                        });

                                    break;

                                case EnumUserStoreType.PostgreSQL:

                                    cnn.Execute(
                                        "INSERT INTO \"subjectidentifier\""
                                        + " (\"sector\", \"userid\", \"sub\", \"createddate\")"
                                        + " VALUES (@Sector, @UserId, @Sub, @CreatedDate)",
                                        new
                                        {
                                            Sector = sector, UserId = userId, Sub = sub,
                                            CreatedDate = DateTime.Now
                                        });

                                    break;
                            }
                        }

                        break;
                }
            }
            catch
            {
                // **競合（主キーの重複）は無視する。** 呼び出し元が引き直す。
            }
        }

        #endregion

        #region Delete（利用者の削除に伴う後始末。mem のみ）

        /// <summary>その利用者の記録を消す（`mem` のみ。DB は外部キーが消す）</summary>
        /// <param name="userId">UserId</param>
        /// <remarks>
        /// **DB では `ON DELETE CASCADE` が消す**ので、ここでは何もしない。
        /// `mem` は外部キーが無いので、この実装が消す。
        /// </remarks>
        public static void DeleteByUserId(string userId)
        {
            if (Config.UserStoreType != EnumUserStoreType.Memory
                || string.IsNullOrEmpty(userId))
            {
                return;
            }

            string suffix = "\t" + userId;

            foreach (string key in SubjectIdProvider.SubjectIds.Keys)
            {
                if (key.EndsWith(suffix, StringComparison.Ordinal))
                {
                    SubjectIdProvider.SubjectIds.TryRemove(key, out string _);
                }
            }
        }

        #endregion
    }
}
