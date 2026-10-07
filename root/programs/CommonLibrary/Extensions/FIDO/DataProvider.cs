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
//* クラス名        ：DataProvider
//* クラス日本語名  ：DataProvider（ライブラリ）
//*
//* 作成日時        ：－
//* 作成者          ：－
//* 更新履歴        ：－
//*
//*  日時        更新者            内容
//*  ----------  ----------------  -------------------------------------------------
//*  2019/03/13  西野 大介         新規
//*  2026/10/07  玄人 幸道         fido2-net-lib 4.2.0 に合わせた（#137）
//**********************************************************************************

using MultiPurposeAuthSite.Co;
using MultiPurposeAuthSite.Data;

using System;
using System.Data;
using System.Linq;
using System.Collections.Generic;
using System.Collections.Concurrent;

using Dapper;

using Newtonsoft.Json;
using Newtonsoft.Json.Linq;
using Newtonsoft.Json.Serialization;

using Fido2NetLib;
using Fido2NetLib.Objects;

using Touryo.Infrastructure.Public.Str;


namespace MultiPurposeAuthSite.Extensions.FIDO
{
    /// <summary>
    /// DataProvider
    /// FIDO2Dataを保存する。
    /// </summary>
    public class DataProvider
    {
        //  《 保存する形 》
        //
        //  ・FIDO2Data 表
        //    - PublicKeyId      : StoredCredential.CredentialId の base64url（主キー）
        //    - UserName         : StoredCredential.UserId の UTF-8（検索キー）
        //    - UnstructuredData : StoredCredential の JSON
        //
        //  **StoredCredential は自前の型である**（`StoredCredential.cs`）。
        //  **以前は `Fido2NetLib.Development.StoredCredential` を直列化していた**が、
        //  **`Development` 名前空間は 3.0 で消えた**（#137）。

        /// <summary>
        /// FIDO2Data
        /// ConcurrentDictionaryは、.NET 4.0の新しいスレッドセーフなHashtable
        /// </summary>
        private static ConcurrentDictionary<string, string> FIDO2Data = new ConcurrentDictionary<string, string>();

        #region Create

        /// <summary>Create</summary>
        /// <param name="storedCredential">StoredCredential</param>
        public static void Create(StoredCredential storedCredential)
        {
            string publicKeyId = CustomEncode.ToBase64UrlString(storedCredential.CredentialId);
            string userName = CustomEncode.ByteToString(storedCredential.UserId, CustomEncode.UTF_8);
            string unstructuredData = JsonConvert.SerializeObject(storedCredential);
            
            switch (Config.UserStoreType)
            {
                case EnumUserStoreType.Memory:
                    DataProvider.FIDO2Data.TryAdd(publicKeyId, unstructuredData);
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
                                    "INSERT INTO [FIDO2Data] ([PublicKeyId], [UserName], [UnstructuredData]) "
                                    + "VALUES (@PublicKeyId, @UserName, @UnstructuredData)",
                                    new { PublicKeyId = publicKeyId, UserName = userName, UnstructuredData = unstructuredData });

                                break;

                            case EnumUserStoreType.ODPManagedDriver:

                                cnn.Execute(
                                    "INSERT INTO \"FIDO2Data\" (\"PublicKeyId\", \"UserName\", \"UnstructuredData\") "
                                    + "VALUES (:PublicKeyId, :UserName, :UnstructuredData)",
                                    new { PublicKeyId = publicKeyId, UserName = userName, UnstructuredData = unstructuredData });

                                break;

                            case EnumUserStoreType.PostgreSQL:

                                cnn.Execute(
                                    "INSERT INTO \"fido2data\" (\"publickeyid\", \"username\", \"unstructureddata\") "
                                    + "VALUES (@PublicKeyId, @UserName, @UnstructuredData)",
                                    new { PublicKeyId = publicKeyId, UserName = userName, UnstructuredData = unstructuredData });

                                break;
                        }
                    }

                    break;
            }
        }

        #endregion

        #region Get(Reference)

        /// <summary>GetCredentialById</summary>
        /// <param name="publicKeyId">byte[]</param>
        public static StoredCredential GetCredentialById(byte[] publicKeyId)
        {
            string _publicKeyId = CustomEncode.ToBase64UrlString(publicKeyId);

            string unstructuredData = DataProvider.GetDataByCredential(_publicKeyId);

            if (string.IsNullOrEmpty(unstructuredData))
            {
                return null;
            }
            else
            {
                return JsonConvert.DeserializeObject<StoredCredential>(unstructuredData);
            }
        }

        /// <summary>GetUserByCredential</summary>
        /// <param name="publicKeyId"></param>
        /// <returns>Fido2User</returns>
        public static Fido2User GetUserByCredential(byte[] publicKeyId)
        {
            string _publicKeyId = CustomEncode.ToBase64UrlString(publicKeyId);

            string unstructuredData = DataProvider.GetDataByCredential(_publicKeyId);

            if (string.IsNullOrEmpty(unstructuredData))
            {
                return null;
            }
            else
            {
                StoredCredential storedCredential =
                    JsonConvert.DeserializeObject<StoredCredential>(unstructuredData);

                string username = CustomEncode.ByteToString(storedCredential.UserId, CustomEncode.UTF_8);

                return new Fido2User
                {
                    DisplayName = username,
                    Name = username,
                    Id = storedCredential.UserId
                };
            }
        }

        /// <summary>GetDataByCredential</summary>
        /// <param name="publicKeyId">string</param>
        private static string GetDataByCredential(string publicKeyId)
        {
            string unstructuredData = "";

            switch (Config.UserStoreType)
            {
                case EnumUserStoreType.Memory:
                    DataProvider.FIDO2Data.TryGetValue(publicKeyId, out unstructuredData);

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

                                unstructuredData = cnn.ExecuteScalar<string>(
                                    "SELECT [UnstructuredData] FROM [FIDO2Data] WHERE [PublicKeyId] = @PublicKeyId", new { PublicKeyId = publicKeyId });

                                break;

                            case EnumUserStoreType.ODPManagedDriver:

                                unstructuredData = cnn.ExecuteScalar<string>(
                                    "SELECT \"UnstructuredData\" FROM \"FIDO2Data\" WHERE \"PublicKeyId\" = :PublicKeyId", new { PublicKeyId = publicKeyId });

                                break;

                            case EnumUserStoreType.PostgreSQL:

                                unstructuredData = cnn.ExecuteScalar<string>(
                                    "SELECT \"unstructureddata\" FROM \"fido2data\" WHERE \"publickeyid\" = @PublicKeyId", new { PublicKeyId = publicKeyId });

                                break;
                        }
                    }

                    break;
            }

            return unstructuredData;
        }

        /// <summary>GetCredentialsByUser</summary>
        /// <param name="userName">string</param>
        /// <returns>List(PublicKeyCredentialDescriptor)</returns>
        public static List<PublicKeyCredentialDescriptor> GetCredentialsByUser(string userName)
        {
            List <PublicKeyCredentialDescriptor> existingPubCredDescriptor = new List<PublicKeyCredentialDescriptor>();

            switch (Config.UserStoreType)
            {
                case EnumUserStoreType.Memory:

                    foreach (string key in DataProvider.FIDO2Data.Keys)
                    {
                        string unstructuredData = DataProvider.FIDO2Data[key];
                        if (!string.IsNullOrEmpty(unstructuredData))
                        {
                            StoredCredential storedCredential = 
                                JsonConvert.DeserializeObject<StoredCredential>(unstructuredData);

                            if (CustomEncode.ByteToString(storedCredential.UserId, CustomEncode.UTF_8) == userName)
                            {
                                existingPubCredDescriptor.Add(storedCredential.ToDescriptor());
                            }
                        }
                    }

                    break;

                case EnumUserStoreType.SqlServer:
                case EnumUserStoreType.ODPManagedDriver:
                case EnumUserStoreType.PostgreSQL: // DMBMS

                    IEnumerable<string> resultSet = null;

                    using (IDbConnection cnn = DataAccess.CreateConnection())
                    {
                        cnn.Open();

                        switch (Config.UserStoreType)
                        {
                            case EnumUserStoreType.SqlServer:

                                resultSet = cnn.Query<string>(
                                    "SELECT [UnstructuredData] FROM [FIDO2Data] WHERE [UserName] = @UserName", new { UserName = userName });

                                break;

                            case EnumUserStoreType.ODPManagedDriver:

                                resultSet = cnn.Query<string>(
                                    "SELECT \"UnstructuredData\" FROM \"FIDO2Data\" WHERE \"UserName\" = :UserName", new { UserName = userName });

                                break;

                            case EnumUserStoreType.PostgreSQL:

                                resultSet = cnn.Query<string>(
                                    "SELECT \"unstructureddata\" FROM \"fido2data\" WHERE \"username\" = @UserName", new { UserName = userName });

                                break;
                        }
                    }

                    foreach (string unstructuredData in resultSet)
                    {
                        StoredCredential storedCredential =
                            JsonConvert.DeserializeObject<StoredCredential>(unstructuredData);

                        if (storedCredential != null)
                        {
                            existingPubCredDescriptor.Add(storedCredential.ToDescriptor());
                        }
                    }

                    break;
            }

            return existingPubCredDescriptor;
        }

        /// <summary>GetCredentialIdsByUser</summary>
        /// <param name="userName">string</param>
        /// <returns>List(string) — base64url の credentialId</returns>
        //  **画面（RemoveWebAuthnData）は id の文字列しか要らない**ので、
        //    **PublicKeyCredentialDescriptor を画面まで持ち込まない。**
        public static List<string> GetCredentialIdsByUser(string userName)
        {
            List<string> ids = new List<string>();

            foreach (PublicKeyCredentialDescriptor descriptor
                in DataProvider.GetCredentialsByUser(userName))
            {
                ids.Add(CustomEncode.ToBase64UrlString(descriptor.Id));
            }

            return ids;
        }

        #endregion

        #region Update

        /// <summary>Update</summary>
        /// <param name="storedCredential">StoredCredential</param>
        public static void Update(StoredCredential storedCredential)
        {
            string publicKeyId = CustomEncode.ToBase64UrlString(storedCredential.CredentialId);
            string userName = CustomEncode.ByteToString(storedCredential.UserId, CustomEncode.UTF_8);
            string unstructuredData = JsonConvert.SerializeObject(storedCredential);
        
            switch (Config.UserStoreType)
            {
                case EnumUserStoreType.Memory:
                    // TryUpdate が使えないので del -> ins にする。
                    string temp = "";
                    DataProvider.FIDO2Data.TryRemove(publicKeyId, out temp);
                    DataProvider.FIDO2Data.TryAdd(publicKeyId, unstructuredData);

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
                                    "UPDATE [FIDO2Data] SET [UnstructuredData] = @UnstructuredData WHERE [PublicKeyId] = @PublicKeyId",
                                    new { PublicKeyId = publicKeyId, UnstructuredData = unstructuredData });

                                break;

                            case EnumUserStoreType.ODPManagedDriver:

                                cnn.Execute(
                                    "UPDATE \"FIDO2Data\" SET \"UnstructuredData\" = :UnstructuredData WHERE \"PublicKeyId\" = :PublicKeyId",
                                    new { PublicKeyId = publicKeyId, UnstructuredData = unstructuredData });

                                break;

                            case EnumUserStoreType.PostgreSQL:

                                cnn.Execute(
                                    "UPDATE \"fido2data\" SET \"unstructureddata\" = @UnstructuredData WHERE \"publickeyid\" = @PublicKeyId",
                                    new { PublicKeyId = publicKeyId, UnstructuredData = unstructuredData });

                                break;
                        }
                    }

                    break;
            }
        }

        #endregion

        #region Delete

        /// <summary>Delete</summary>
        /// <param name="publicKeyId">string</param>
        /// <param name="userName">string</param>
        public static void Delete(string publicKeyId, string userName)
        {
            switch (Config.UserStoreType)
            {
                case EnumUserStoreType.Memory:
                    string unstructuredData = "";
                    DataProvider.FIDO2Data.TryRemove(publicKeyId, out unstructuredData);

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
                                    "DELETE FROM [FIDO2Data] WHERE [PublicKeyId] = @PublicKeyId AND [UserName] = @UserName",
                                    new { PublicKeyId = publicKeyId, UserName = userName });

                                break;

                            case EnumUserStoreType.ODPManagedDriver:

                                cnn.Execute(
                                    "DELETE FROM \"FIDO2Data\" WHERE \"PublicKeyId\" = :PublicKeyId AND \"UserName\" = :UserName",
                                    new { PublicKeyId = publicKeyId, UserName = userName });

                                break;

                            case EnumUserStoreType.PostgreSQL:

                                cnn.Execute(
                                    "DELETE FROM \"fido2data\" WHERE \"publickeyid\" = @PublicKeyId AND \"username\" = @UserName",
                                    new { PublicKeyId = publicKeyId, UserName = userName });

                                break;
                        }
                    }

                    break;
            }
        }

        /// <summary>DeleteByUser</summary>
        /// <param name="userName">string</param>
        //  **利用者ごと消す**（#137）。
        //    **FIDO2Data は UserName で持っており、Users への外部キーが無い。**
        //    **利用者を消しても資格情報が残る**ので、GDPR の削除から呼ぶ。
        public static void DeleteByUser(string userName)
        {
            switch (Config.UserStoreType)
            {
                case EnumUserStoreType.Memory:

                    foreach (string key in DataProvider.FIDO2Data.Keys)
                    {
                        string unstructuredData = "";
                        if (DataProvider.FIDO2Data.TryGetValue(key, out unstructuredData)
                            && !string.IsNullOrEmpty(unstructuredData))
                        {
                            StoredCredential storedCredential =
                                JsonConvert.DeserializeObject<StoredCredential>(unstructuredData);

                            if (storedCredential != null
                                && CustomEncode.ByteToString(
                                    storedCredential.UserId, CustomEncode.UTF_8) == userName)
                            {
                                string temp = "";
                                DataProvider.FIDO2Data.TryRemove(key, out temp);
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

                                cnn.Execute(
                                    "DELETE FROM [FIDO2Data] WHERE [UserName] = @UserName",
                                    new { UserName = userName });

                                break;

                            case EnumUserStoreType.ODPManagedDriver:

                                cnn.Execute(
                                    "DELETE FROM \"FIDO2Data\" WHERE \"UserName\" = :UserName",
                                    new { UserName = userName });

                                break;

                            case EnumUserStoreType.PostgreSQL:

                                cnn.Execute(
                                    "DELETE FROM \"fido2data\" WHERE \"username\" = @UserName",
                                    new { UserName = userName });

                                break;
                        }
                    }

                    break;
            }
        }

        #endregion
    }
}