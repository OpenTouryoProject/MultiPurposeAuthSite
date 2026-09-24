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
//**********************************************************************************

using System;
using System.Data;
using System.Collections.Generic;
using System.Collections.Concurrent;

using MultiPurposeAuthSite.Data;
using MultiPurposeAuthSite.Co;

using Dapper;

namespace MultiPurposeAuthSite.TokenProviders
{
    /// <summary>RefreshTokenのpayloadを一時保存する。</summary>
    public class RefreshTokenProvider
    {
        /// <summary>
        /// RefreshTokens
        /// ConcurrentDictionaryは、.NET 4.0の新しいスレッドセーフなHashtable
        /// </summary>
        private static ConcurrentDictionary<string, TokenEntry>
            RefreshTokens = new ConcurrentDictionary<string, TokenEntry>();

        /// <summary>メモリ ストアの 1 件（値と作成時刻）（#188）</summary>
        private class TokenEntry
        {
            /// <summary>値</summary>
            public string Value = "";
            /// <summary>作成時刻</summary>
            public DateTime CreatedDate = DateTime.MinValue;
        }

        /// <summary>
        /// **これより古い refresh_token は、無いものとして扱う**（#188）
        /// </summary>
        /// <remarks>
        /// Config.OAuth2RefreshTokenExpireTimeSpanFromDays（既定 14 日）は、
        /// 以前は**定義だけで、どこからも参照されていなかった**（事実上の無期限）。
        ///
        /// **DBMS では SELECT の条件に入れる**ので、期限切れの行は「見つからない」になり、
        /// これまでの「存在しない token」と同じ経路（空を返す ＝ invalid_grant）に合流する。
        /// </remarks>
        private static DateTime ExpireLimit
        {
            get { return DateTime.Now - Config.OAuth2RefreshTokenExpireTimeSpanFromDays; }
        }

        /// <summary>メモリ ストアから、期限内の値を取り出す（期限切れは消す）（#188）</summary>
        /// <param name="tokenId">refresh_token</param>
        /// <param name="remove">取り出せたら消すか（ローテーション・失効）</param>
        /// <returns>値（無い・期限切れなら空）</returns>
        private static string GetFromMemory(string tokenId, bool remove)
        {
            TokenEntry entry = null;

            if (!RefreshTokenProvider.RefreshTokens.TryGetValue(tokenId, out entry))
            {
                return "";
            }

            if (entry.CreatedDate < RefreshTokenProvider.ExpireLimit)
            {
                // 期限切れ。参照した時点で消す。
                RefreshTokenProvider.RefreshTokens.TryRemove(tokenId, out TokenEntry _);
                return "";
            }

            if (remove)
            {
                RefreshTokenProvider.RefreshTokens.TryRemove(tokenId, out TokenEntry _);
            }

            return entry.Value;
        }

        #region Create

        /// <summary>Create</summary>
        /// <param name="payload">string</param>
        /// <returns>token id</returns>
        public static string Create(string payload)
        {
            string tokenId = Guid.NewGuid().ToString("n") + Guid.NewGuid().ToString("n");

            if (Config.EnableRefreshToken)
            {
                // EnableRefreshToken == true
                switch (Config.UserStoreType)
                {
                    case EnumUserStoreType.Memory:
                        RefreshTokenProvider.RefreshTokens.TryAdd(tokenId,
                            new TokenEntry { Value = payload, CreatedDate = DateTime.Now });
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
                                        "INSERT INTO [RefreshTokenDictionary] ([Key], [Value], [CreatedDate]) VALUES (@Key, @Value, @CreatedDate)",
                                        new { Key = tokenId, Value = payload, CreatedDate = DateTime.Now });

                                    break;

                                case EnumUserStoreType.ODPManagedDriver:

                                    cnn.Execute(
                                        "INSERT INTO \"RefreshTokenDictionary\" (\"Key\", \"Value\", \"CreatedDate\") VALUES (:Key, :Value, :CreatedDate)",
                                        new { Key = tokenId, Value = payload, CreatedDate = DateTime.Now });

                                    break;

                                case EnumUserStoreType.PostgreSQL:

                                    cnn.Execute(
                                        "INSERT INTO \"refreshtokendictionary\" (\"key\", \"value\", \"createddate\") VALUES (@Key, @Value, @CreatedDate)",
                                        new { Key = tokenId, Value = payload, CreatedDate = DateTime.Now });

                                    break;
                            }
                        }

                        break;
                }
            }
            else
            {
                // EnableRefreshToken == false
            }

            return tokenId;
        }

        #endregion

        #region Receive

        /// <summary>Receive</summary>
        /// <param name="tokenId">string</param>
        /// <returns>payload</returns>
        public static string Receive(string tokenId)
        {
            if (Config.EnableRefreshToken)
            {
                // EnableRefreshToken == true
                string payload = null;
                IEnumerable<string> values = null;
                List<string> list = null;

                switch (Config.UserStoreType)
                {
                    case EnumUserStoreType.Memory:
                        payload = RefreshTokenProvider.GetFromMemory(tokenId, remove: true);
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

                                    values = cnn.Query<string>(
                                        "SELECT [Value] FROM [RefreshTokenDictionary]"
                                        + " WHERE [Key] = @Key AND [CreatedDate] > @Limit",
                                        new { Key = tokenId, Limit = RefreshTokenProvider.ExpireLimit });

                                    list = values.AsList();
                                    if (list.Count != 0)
                                    {
                                        payload = values.AsList()[0];

                                        cnn.Execute(
                                            "DELETE FROM [RefreshTokenDictionary] WHERE [Key] = @Key", new { Key = tokenId });
                                    }

                                    break;

                                case EnumUserStoreType.ODPManagedDriver:

                                    values = cnn.Query<string>(
                                        "SELECT \"Value\" FROM \"RefreshTokenDictionary\""
                                        + " WHERE \"Key\" = :Key AND \"CreatedDate\" > :Limit",
                                        new { Key = tokenId, Limit = RefreshTokenProvider.ExpireLimit });

                                    list = values.AsList();
                                    if (list.Count != 0)
                                    {
                                        payload = values.AsList()[0];

                                        cnn.Execute(
                                            "DELETE FROM \"RefreshTokenDictionary\" WHERE \"Key\" = :Key", new { Key = tokenId });
                                    }

                                    break;

                                case EnumUserStoreType.PostgreSQL:

                                    values = cnn.Query<string>(
                                       "SELECT \"value\" FROM \"refreshtokendictionary\""
                                       + " WHERE \"key\" = @Key AND \"createddate\" > @Limit",
                                       new { Key = tokenId, Limit = RefreshTokenProvider.ExpireLimit });

                                    list = values.AsList();
                                    if (list.Count != 0)
                                    {
                                        payload = values.AsList()[0];

                                        cnn.Execute(
                                            "DELETE FROM \"refreshtokendictionary\" WHERE \"key\" = @Key", new { Key = tokenId });
                                    }

                                    break;
                            }
                        }

                        break;
                }

                return payload;
            }
            else
            {
                // EnableRefreshToken == false
                return null;
            }
        }

        #endregion

        #region Reference

        /// <summary>Reference</summary>
        /// <param name="tokenId">string</param>
        /// <returns>payload</returns>
        /// <remarks>OAuth 2.0 Token Introspectionのサポートのために必要</remarks>
        public static string Refer(string tokenId)
        {
            if (Config.EnableRefreshToken)
            {
                // EnableRefreshToken == true
                string payload = null;
                IEnumerable<string> values = null;
                List<string> list = null;

                switch (Config.UserStoreType)
                {
                    case EnumUserStoreType.Memory:
                        payload = RefreshTokenProvider.GetFromMemory(tokenId, remove: false);
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

                                    values = cnn.Query<string>(
                                        "SELECT [Value] FROM [RefreshTokenDictionary]"
                                        + " WHERE [Key] = @Key AND [CreatedDate] > @Limit",
                                        new { Key = tokenId, Limit = RefreshTokenProvider.ExpireLimit });

                                    list = values.AsList();
                                    if (list.Count != 0)
                                    {
                                        payload = values.AsList()[0];
                                    }

                                    break;

                                case EnumUserStoreType.ODPManagedDriver:

                                    values = cnn.Query<string>(
                                        "SELECT \"Value\" FROM \"RefreshTokenDictionary\""
                                        + " WHERE \"Key\" = :Key AND \"CreatedDate\" > :Limit",
                                        new { Key = tokenId, Limit = RefreshTokenProvider.ExpireLimit });

                                    list = values.AsList();
                                    if (list.Count != 0)
                                    {
                                        payload = values.AsList()[0];
                                    }

                                    break;

                                case EnumUserStoreType.PostgreSQL:

                                    values = cnn.Query<string>(
                                      "SELECT \"value\" FROM \"refreshtokendictionary\""
                                      + " WHERE \"key\" = @Key AND \"createddate\" > @Limit",
                                      new { Key = tokenId, Limit = RefreshTokenProvider.ExpireLimit });

                                    list = values.AsList();
                                    if (list.Count != 0)
                                    {
                                        payload = values.AsList()[0];
                                    }

                                    break;
                            }
                        }

                        break;
                }

                return payload;
            }
            else
            {
                // EnableRefreshToken == false
                return null;
            }
        }

        #endregion

        #region Delete

        /// <summary>DeleteDirectly</summary>
        /// <param name="tokenId">string</param>
        /// <returns>削除できたか否か</returns>
        /// <remarks>OAuth 2.0 Token Revocationサポート</remarks>
        public static bool Delete(string tokenId)
        {
            int ret = 0;

            if (Config.EnableRefreshToken)
            {
                // EnableRefreshToken == true
                string payload = null;

                switch (Config.UserStoreType)
                {
                    case EnumUserStoreType.Memory:
                        payload = RefreshTokenProvider.GetFromMemory(tokenId, remove: true);
                        if (!string.IsNullOrEmpty(payload))
                        {
                            // 1 refresh : 1 access なので、単に捨てればOK。
                            ret = 1;
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

                                    // 1 refresh : 1 access なので、単に捨てればOK。
                                    ret = cnn.Execute(
                                        "DELETE FROM [RefreshTokenDictionary] WHERE [Key] = @Key", new { Key = tokenId });

                                    break;

                                case EnumUserStoreType.ODPManagedDriver:

                                    // 1 refresh : 1 access なので、単に捨てればOK。
                                    ret = cnn.Execute(
                                        "DELETE FROM \"RefreshTokenDictionary\" WHERE \"Key\" = :Key", new { Key = tokenId });

                                    break;

                                case EnumUserStoreType.PostgreSQL:

                                    // 1 refresh : 1 access なので、単に捨てればOK。
                                    ret = cnn.Execute(
                                        "DELETE FROM \"refreshtokendictionary\" WHERE \"key\" = @Key", new { Key = tokenId });

                                    break;
                            }
                        }

                        break;
                }
            }
            else
            {
                // EnableRefreshToken == false
            }

            return !(ret == 0);
        }

        #endregion
    }
}