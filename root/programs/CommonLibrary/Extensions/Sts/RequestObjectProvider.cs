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
//* クラス名        ：RequestObjectProvider
//* クラス日本語名  ：登録されたRequestObjectを管理する（ライブラリ）
//*
//* 作成日時        ：－
//* 作成者          ：－
//* 更新履歴        ：－
//*
//*  日時        更新者            内容
//*  ----------  ----------------  -------------------------------------------------
//*  2019/06/20  西野 大介         新規
//*  2026/09/13  玄人 幸道         SQL系: 行なしで500になる不具合と、Result(NULL)のキャストを修正（#207で判明）
//*  2026/09/24  玄人 幸道         有効期限を検証する（期限切れは無いものとして扱う）（#188）
//**********************************************************************************

using MultiPurposeAuthSite.Co;
using MultiPurposeAuthSite.Data;

using System;
using System.Data;
using System.Collections.Concurrent;

using Dapper;

namespace MultiPurposeAuthSite.Extensions.Sts
{
    /// <summary>
    /// 登録されたRequestObjectを管理する。
    /// </summary>
    public class RequestObjectProvider
    {
        /// <summary>
        /// RequestObjectBean
        /// （メモリストア用）
        /// </summary>
        private class RequestObjectBean
        {
            /// <summary>Value</summary>
            public string Value = "";
            /// <summary>CreatedDate</summary>
            public DateTime CreatedDate = DateTime.MinValue;
        }

        /// <summary>
        /// RequestObjects
        /// ConcurrentDictionaryは、.NET 4.0の新しいスレッドセーフなHashtable
        /// </summary>
        private static ConcurrentDictionary<string, RequestObjectBean>
            RequestObjects = new ConcurrentDictionary<string, RequestObjectBean>();

        /// <summary>
        /// **これより古い Request Object は、無いものとして扱う**（#188）
        /// </summary>
        /// <remarks>
        /// 預けてから認可要求に使うまでの短い時間だけ有効にする
        /// （Config.RequestObjectExpireTimeSpanFromSeconds。既定 300 秒）。
        /// 以前は CreatedDate を書くだけで読んでおらず、事実上の無期限だった。
        ///
        /// **使い切り（ワンタイム）にはしていない。** 1 回の認可の中で複数回読むため
        /// （同意画面・コード発行・CIBA の開始）、消す場所を決める必要がある（#188 の段階 2 / #229）。
        /// </remarks>
        private static DateTime ExpireLimit
        {
            get { return DateTime.Now - Config.RequestObjectExpireTimeSpanFromSeconds; }
        }

        #region Create

        /// <summary>Create</summary>
        /// <param name="urn">string</param>
        /// <param name="value">string</param>
        public static void Create(string urn, string value)
        {
            switch (Config.UserStoreType)
            {
                case EnumUserStoreType.Memory:

                    RequestObjectProvider.RequestObjects.TryAdd(
                        urn,
                        new RequestObjectBean{
                            Value = value,
                            CreatedDate = DateTime.Now
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
                                    "INSERT INTO [RequestObject]" +
                                    " ([Urn], [Value], [CreatedDate])" +
                                    " VALUES (@Urn, @Value, @CreatedDate)",
                                    new { Urn = urn, Value = value, CreatedDate = DateTime.Now });

                                break;

                            case EnumUserStoreType.ODPManagedDriver:

                                cnn.Execute(
                                    "INSERT INTO \"RequestObject\"" +
                                    " (\"Urn\", \"Value\", \"CreatedDate\")" +
                                    " VALUES (:Urn, :Value, :CreatedDate)",
                                    new { Urn = urn, Value = value, CreatedDate = DateTime.Now });

                                break;

                            case EnumUserStoreType.PostgreSQL:

                                cnn.Execute(
                                    "INSERT INTO \"requestobject\"" +
                                    " (\"urn\", \"value\", \"createddate\")" +
                                    " VALUES (@Urn, @Value, @CreatedDate)",
                                    new { Urn = urn, Value = value, CreatedDate = DateTime.Now });

                                break;
                        }
                    }

                    break;
            }
        }

        #endregion

        #region Get(Reference)

        /// <summary>Get</summary>
        /// <param name="urn">string</param>
        /// <returns>RequestObject</returns>
        public static string Get(string urn)
        {
            string requestObjectValue = "";

            switch (Config.UserStoreType)
            {
                case EnumUserStoreType.Memory:

                    RequestObjectBean requestObject = null;
                    if (RequestObjectProvider.RequestObjects.TryGetValue(urn, out requestObject)
                        && requestObject.CreatedDate >= RequestObjectProvider.ExpireLimit)
                    {
                        requestObjectValue = requestObject.Value;
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

                                requestObjectValue = cnn.ExecuteScalar<string>(
                                    "SELECT [Value] FROM [RequestObject]"
                                    + " WHERE [Urn] = @Urn AND [CreatedDate] > @Limit",
                                    new { Urn = urn, Limit = RequestObjectProvider.ExpireLimit });

                                break;

                            case EnumUserStoreType.ODPManagedDriver:

                                requestObjectValue = cnn.ExecuteScalar<string>(
                                    "SELECT \"Value\" FROM \"RequestObject\""
                                    + " WHERE \"Urn\" = :Urn AND \"CreatedDate\" > :Limit",
                                    new { Urn = urn, Limit = RequestObjectProvider.ExpireLimit });

                                break;

                            case EnumUserStoreType.PostgreSQL:

                                requestObjectValue = cnn.ExecuteScalar<string>(
                                    "SELECT \"value\" FROM \"requestobject\""
                                    + " WHERE \"urn\" = @Urn AND \"createddate\" > @Limit",
                                    new { Urn = urn, Limit = RequestObjectProvider.ExpireLimit });

                                break;
                        }
                    }

                    // **行が無いと ExecuteScalar は null を返す。**
                    //   Memory 分岐は "" を返すので、揃えておく。
                    //   null をそのまま返すと、呼び出し元（CIBA の認可リクエスト）で
                    //   JsonConvert.DeserializeObject(null) となり ArgumentNullException になる。
                    if (requestObjectValue == null)
                    {
                        requestObjectValue = "";
                    }

                    break;
            }

            return requestObjectValue;
        }

        #endregion

        #region Delete

        /// <summary>Delete</summary>
        /// <param name="urn">string</param>
        public static void Delete(string urn)
        {
            switch (Config.UserStoreType)
            {
                case EnumUserStoreType.Memory:
                    RequestObjectBean requestObject = null;
                    RequestObjectProvider.RequestObjects.TryRemove(urn, out requestObject);

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
                                    "DELETE FROM [RequestObject] WHERE [Urn] = @Urn", new { Urn = urn });

                                break;

                            case EnumUserStoreType.ODPManagedDriver:

                                cnn.Execute(
                                    "DELETE FROM \"RequestObject\" WHERE \"Urn\" = :Urn", new { Urn = urn });

                                break;

                            case EnumUserStoreType.PostgreSQL:

                                cnn.Execute(
                                    "DELETE FROM \"requestobject\" WHERE \"urn\" = @Urn", new { Urn = urn });

                                break;
                        }
                    }

                    break;
            }
        }

        #endregion
    }
}