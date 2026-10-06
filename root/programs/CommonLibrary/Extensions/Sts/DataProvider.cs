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
//* クラス日本語名  ：Saml2OAuth2Dataにクライアント登録を保存する。
//*
//* 作成日時        ：－
//* 作成者          ：－
//* 更新履歴        ：－
//*
//*  日時        更新者            内容
//*  ----------  ----------------  -------------------------------------------------
//*  2017/06/07  西野 大介         新規
//*  2019/05/2*  西野 大介         SAML2対応実施
//*  2026/10/04  玄人 幸道         GetAll を追加（#266）
//*  2026/10/06  玄人 幸道         JSON 1 列から専用列に切り出した（#270）
//**********************************************************************************

using MultiPurposeAuthSite.Co;
using MultiPurposeAuthSite.Data;
using MultiPurposeAuthSite.ViewModels;

using System;
using System.Linq;
using System.Collections.Generic;
using System.Data;
using System.Collections.Concurrent;

using Dapper;

namespace MultiPurposeAuthSite.Extensions.Sts
{
    /// <summary>
    /// DataProvider
    /// Saml2OAuth2Dataにクライアント登録を保存する。
    /// </summary>
    /// <remarks>
    /// **JSON 1 列ではなく、専用列で持つ**（#270）。
    ///
    /// 以前は `UnstructuredData` 1 列に、登録の全項目を JSON で入れていた。
    /// **それをやめた理由**は次のとおり。
    ///
    /// | | |
    /// |---|---|
    /// | **1 項目が長いと、他が入らない** | 全項目まとめて 1 列の幅だった（#269 の根っこ） |
    /// | **問い合わせられない** | CORS の許可オリジンを作るのに、全行を読んで 1 件ずつ逆直列化していた |
    /// | **妥当性検査が DB 側に効かない** | 幅・NOT NULL をデータベースに持たせられなかった |
    /// | **意図しないものが混ざる** | 画面の選択肢（`Ddl*Items`）が直列化されていた（#266 で踏んだ） |
    ///
    /// **授受する型は `ManageAddSaml2OAuth2DataViewModel`。**
    /// **以前も、呼ぶ側は全部この型に逆直列化していた**ので、入口の形は変わらない。
    ///
    /// **構成ファイル側（`OAuth2ClientsInformation`）は JSON のまま**である
    /// （設定ファイルなので列にはできない）。
    /// **読み出しの入口は `Helper` の各 `Get*` 1 か所に保たれている**
    /// （「構成ファイル → user store」の順に見る）。
    /// </remarks>
    public class DataProvider
    {
        /// <summary>
        /// Saml2OAuth2Data
        /// ConcurrentDictionaryは、.NET 4.0の新しいスレッドセーフなHashtable
        /// </summary>
        private static ConcurrentDictionary<string, ManageAddSaml2OAuth2DataViewModel> Saml2OAuth2Data
            = new ConcurrentDictionary<string, ManageAddSaml2OAuth2DataViewModel>();

        #region 列の並び

        /// <summary>列の並び（#270）</summary>
        /// <remarks>
        /// **1 か所で持つ。** 17 列 × 3 方言 × 3 文（INSERT / SELECT / UPDATE）を
        /// **手で書き並べると、必ずどれかが取り残される**
        /// （この Issue が直そうとしているのが、まさにその種の食い違いである）。
        ///
        /// **並びは `ManageAddSaml2OAuth2DataViewModel` の宣言順**にしてある。
        /// **列名は属性名と同じ**なので、Dapper が別名なしで対応付けられる。
        /// </remarks>
        private static readonly string[] Columns = new string[]
        {
            "ClientID",
            "ClientSecret",
            "RedirectUriSaml",
            "RedirectUriCode",
            "RedirectUriToken",
            "PostLogoutRedirectUri",
            "WebOrigins",
            "JwkRsaPublickey",
            "JwkECDsaPublickey",
            "TlsClientAuthSubjectDn",
            "SubjectTypes",
            "IdTokenSignedResponseAlg",
            "TokenEndpointAuthSigningAlg",
            "RequestObjectSigningAlg",
            "ClientMode",
            "RequirePkce",
            "ClientName"
        };

        /// <summary>CORS の許可オリジンを作るのに要る列だけ（#270）</summary>
        /// <remarks>
        /// **`GetAllUris` が使う。** 全列を読む必要はない
        /// （**列にしたので、こう絞れる**。JSON 1 列では全部読むしかなかった）。
        /// **`ClientSecret` が要る**のは、**public クライアントに限る**ため。
        /// </remarks>
        private static readonly string[] UriColumns = new string[]
        {
            "ClientSecret",
            "RedirectUriSaml",
            "RedirectUriCode",
            "RedirectUriToken",
            "PostLogoutRedirectUri",
            "WebOrigins"
        };

        /// <summary>列の並びを、方言の書き方で並べる</summary>
        /// <param name="columns">列の並び</param>
        /// <param name="storeType">EnumUserStoreType</param>
        /// <returns>「[A], [B]」のような文字列</returns>
        private static string ColumnList(string[] columns, EnumUserStoreType storeType)
        {
            switch (storeType)
            {
                case EnumUserStoreType.SqlServer:
                    return string.Join(", ", columns.Select(c => "[" + c + "]"));

                case EnumUserStoreType.ODPManagedDriver:
                    return string.Join(", ", columns.Select(c => "\"" + c + "\""));

                case EnumUserStoreType.PostgreSQL:
                    // **PostgreSQL は、引用符なしの識別子が小文字に畳まれる。**
                    //   DDL を引用符なしで書いているので、ここは小文字で引く。
                    return string.Join(", ", columns.Select(c => "\"" + c.ToLower() + "\""));

                default:
                    throw new NotSupportedException(storeType.ToString());
            }
        }

        /// <summary>パラメタの並び</summary>
        /// <param name="columns">列の並び</param>
        /// <param name="storeType">EnumUserStoreType</param>
        /// <returns>「@A, @B」のような文字列</returns>
        private static string ParameterList(string[] columns, EnumUserStoreType storeType)
        {
            // **Oracle だけ「:」**（他は「@」）。
            string p = (storeType == EnumUserStoreType.ODPManagedDriver) ? ":" : "@";
            return string.Join(", ", columns.Select(c => p + c));
        }

        /// <summary>UPDATE の SET 句（ClientID は外す）</summary>
        /// <param name="storeType">EnumUserStoreType</param>
        /// <returns>「[A] = @A, [B] = @B」のような文字列</returns>
        private static string SetList(EnumUserStoreType storeType)
        {
            string p = (storeType == EnumUserStoreType.ODPManagedDriver) ? ":" : "@";

            return string.Join(", ", DataProvider.Columns
                .Where(c => c != "ClientID")
                .Select(c =>
                {
                    switch (storeType)
                    {
                        case EnumUserStoreType.SqlServer:
                            return "[" + c + "] = " + p + c;
                        case EnumUserStoreType.ODPManagedDriver:
                            return "\"" + c + "\" = " + p + c;
                        default:
                            return "\"" + c.ToLower() + "\" = " + p + c;
                    }
                }));
        }

        /// <summary>テーブル名（方言ごと）</summary>
        private static string TableName(EnumUserStoreType storeType)
        {
            switch (storeType)
            {
                case EnumUserStoreType.SqlServer:
                    return "[Saml2OAuth2Data]";
                case EnumUserStoreType.ODPManagedDriver:
                    return "\"Saml2OAuth2Data\"";
                default:
                    return "\"saml2oauth2data\"";
            }
        }

        /// <summary>ClientID の条件句</summary>
        private static string WhereClientID(EnumUserStoreType storeType)
        {
            switch (storeType)
            {
                case EnumUserStoreType.SqlServer:
                    return " WHERE [ClientID] = @ClientID";
                case EnumUserStoreType.ODPManagedDriver:
                    return " WHERE \"ClientID\" = :ClientID";
                default:
                    return " WHERE \"clientid\" = @ClientID";
            }
        }

        /// <summary>モデルをパラメタにする</summary>
        /// <param name="clientID">string</param>
        /// <param name="model">ManageAddSaml2OAuth2DataViewModel</param>
        /// <param name="storeType">EnumUserStoreType</param>
        /// <returns>DynamicParameters</returns>
        /// <remarks>
        /// **`RequirePkce` だけ方言で形が違う。**
        /// **Oracle は `NUMBER(3)` で、真を -1 で持つ**（`Users` の bool 列と同じ流儀）。
        /// </remarks>
        private static DynamicParameters ToParameters(
            string clientID, ManageAddSaml2OAuth2DataViewModel model, EnumUserStoreType storeType)
        {
            DynamicParameters prm = new DynamicParameters();

            prm.Add("ClientID", clientID);
            prm.Add("ClientSecret", model.ClientSecret);
            prm.Add("RedirectUriSaml", model.RedirectUriSaml);
            prm.Add("RedirectUriCode", model.RedirectUriCode);
            prm.Add("RedirectUriToken", model.RedirectUriToken);
            prm.Add("PostLogoutRedirectUri", model.PostLogoutRedirectUri);
            prm.Add("WebOrigins", model.WebOrigins);
            prm.Add("JwkRsaPublickey", model.JwkRsaPublickey);
            prm.Add("JwkECDsaPublickey", model.JwkECDsaPublickey);
            prm.Add("TlsClientAuthSubjectDn", model.TlsClientAuthSubjectDn);
            prm.Add("SubjectTypes", model.SubjectTypes);
            prm.Add("IdTokenSignedResponseAlg", model.IdTokenSignedResponseAlg);
            prm.Add("TokenEndpointAuthSigningAlg", model.TokenEndpointAuthSigningAlg);
            prm.Add("RequestObjectSigningAlg", model.RequestObjectSigningAlg);
            prm.Add("ClientMode", model.ClientMode);
            prm.Add("ClientName", model.ClientName);

            if (storeType == EnumUserStoreType.ODPManagedDriver)
            {
                prm.Add("RequirePkce", model.RequirePkce ? -1 : 0);
            }
            else
            {
                prm.Add("RequirePkce", model.RequirePkce);
            }

            return prm;
        }

        /// <summary>モデルを複製する（Memory Provider 用）</summary>
        /// <param name="clientID">string</param>
        /// <param name="model">ManageAddSaml2OAuth2DataViewModel</param>
        /// <returns>複製</returns>
        /// <remarks>
        /// **参照を入れてはならない。** 画面が持っているモデルをそのまま入れると、
        /// **後から画面側で書き換えた内容が、保存済みの登録に混ざる。**
        /// **JSON 文字列で持っていた頃は、直列化が複製を兼ねていた。**
        /// </remarks>
        private static ManageAddSaml2OAuth2DataViewModel Copy(
            string clientID, ManageAddSaml2OAuth2DataViewModel model)
        {
            if (model == null)
            {
                return null;
            }

            return new ManageAddSaml2OAuth2DataViewModel()
            {
                ClientID = clientID ?? model.ClientID,
                ClientSecret = model.ClientSecret,
                RedirectUriSaml = model.RedirectUriSaml,
                RedirectUriCode = model.RedirectUriCode,
                RedirectUriToken = model.RedirectUriToken,
                PostLogoutRedirectUri = model.PostLogoutRedirectUri,
                WebOrigins = model.WebOrigins,
                JwkRsaPublickey = model.JwkRsaPublickey,
                JwkECDsaPublickey = model.JwkECDsaPublickey,
                TlsClientAuthSubjectDn = model.TlsClientAuthSubjectDn,
                SubjectTypes = model.SubjectTypes,
                IdTokenSignedResponseAlg = model.IdTokenSignedResponseAlg,
                TokenEndpointAuthSigningAlg = model.TokenEndpointAuthSigningAlg,
                RequestObjectSigningAlg = model.RequestObjectSigningAlg,
                ClientMode = model.ClientMode,
                RequirePkce = model.RequirePkce,
                ClientName = model.ClientName
            };
        }

        #endregion

        #region Create

        /// <summary>Create</summary>
        /// <param name="clientID">string</param>
        /// <param name="model">ManageAddSaml2OAuth2DataViewModel</param>
        public static void Create(string clientID, ManageAddSaml2OAuth2DataViewModel model)
        {
            switch (Config.UserStoreType)
            {
                case EnumUserStoreType.Memory:
                    DataProvider.Saml2OAuth2Data.TryAdd(clientID, DataProvider.Copy(clientID, model));
                    break;

                case EnumUserStoreType.SqlServer:
                case EnumUserStoreType.ODPManagedDriver:
                case EnumUserStoreType.PostgreSQL: // DMBMS

                    using (IDbConnection cnn = DataAccess.CreateConnection())
                    {
                        cnn.Open();

                        EnumUserStoreType storeType = Config.UserStoreType;

                        cnn.Execute(
                            "INSERT INTO " + DataProvider.TableName(storeType)
                            + " (" + DataProvider.ColumnList(DataProvider.Columns, storeType) + ")"
                            + " VALUES (" + DataProvider.ParameterList(DataProvider.Columns, storeType) + ")",
                            DataProvider.ToParameters(clientID, model, storeType));
                    }

                    break;
            }
        }

        #endregion

        #region Get(Reference)

        /// <summary>Get</summary>
        /// <param name="clientID">string</param>
        /// <returns>クライアント登録（無ければ null）</returns>
        /// <remarks>
        /// **無いことは null で表す**（以前は空文字列だった。#270）。
        /// </remarks>
        public static ManageAddSaml2OAuth2DataViewModel Get(string clientID)
        {
            ManageAddSaml2OAuth2DataViewModel model = null;

            switch (Config.UserStoreType)
            {
                case EnumUserStoreType.Memory:
                    DataProvider.Saml2OAuth2Data.TryGetValue(clientID, out model);

                    // **複製を返す。** 呼ぶ側が書き換えても、保存済みの登録は動かない。
                    model = DataProvider.Copy(clientID, model);

                    break;

                case EnumUserStoreType.SqlServer:
                case EnumUserStoreType.ODPManagedDriver:
                case EnumUserStoreType.PostgreSQL: // DMBMS

                    using (IDbConnection cnn = DataAccess.CreateConnection())
                    {
                        cnn.Open();

                        EnumUserStoreType storeType = Config.UserStoreType;

                        model = cnn.QuerySingleOrDefault<ManageAddSaml2OAuth2DataViewModel>(
                            "SELECT " + DataProvider.ColumnList(DataProvider.Columns, storeType)
                            + " FROM " + DataProvider.TableName(storeType)
                            + DataProvider.WhereClientID(storeType),
                            new { ClientID = clientID });
                    }

                    break;
            }

            return model;
        }

        #endregion

        #region GetAllUris

        /// <summary>全件の URI 関連の列を返す（#266 / #270）</summary>
        /// <returns>登録の一覧（1 件も無ければ空）</returns>
        /// <remarks>
        /// **CORS の許可オリジンを作るために要る**（`CmnEndpoints.GetCorsAllowedOrigins`）。
        /// **プリフライト（`OPTIONS`）は `client_id` を持たない**ので、
        /// **オリジンの集合全体**が必要になる。
        ///
        /// **`UriColumns` の列しか入っていない。** 他の項目は null のまま返る
        /// （**列にしたので、読む量を絞れる**。JSON 1 列では全部読むしかなかった）。
        ///
        /// **public クライアントに限る絞り込みは、呼ぶ側で行う**（`Helper`）。
        /// **構成ファイル側と同じ規則を 1 か所に置く**ためで、
        /// **SQL の `WHERE` に下ろすと、規則が方言ごとに散る。**
        /// </remarks>
        public static List<ManageAddSaml2OAuth2DataViewModel> GetAllUris()
        {
            List<ManageAddSaml2OAuth2DataViewModel> all
                = new List<ManageAddSaml2OAuth2DataViewModel>();

            switch (Config.UserStoreType)
            {
                case EnumUserStoreType.Memory:
                    all.AddRange(DataProvider.Saml2OAuth2Data.Values
                        .Select(m => DataProvider.Copy(null, m)));

                    break;

                case EnumUserStoreType.SqlServer:
                case EnumUserStoreType.ODPManagedDriver:
                case EnumUserStoreType.PostgreSQL: // DMBMS

                    using (IDbConnection cnn = DataAccess.CreateConnection())
                    {
                        cnn.Open();

                        EnumUserStoreType storeType = Config.UserStoreType;

                        all.AddRange(cnn.Query<ManageAddSaml2OAuth2DataViewModel>(
                            "SELECT " + DataProvider.ColumnList(DataProvider.UriColumns, storeType)
                            + " FROM " + DataProvider.TableName(storeType)));
                    }

                    break;
            }

            return all;
        }

        #endregion

        #region Update

        /// <summary>Update</summary>
        /// <param name="clientID">string</param>
        /// <param name="model">ManageAddSaml2OAuth2DataViewModel</param>
        public static void Update(string clientID, ManageAddSaml2OAuth2DataViewModel model)
        {
            switch (Config.UserStoreType)
            {
                case EnumUserStoreType.Memory:
                    // TryUpdate が使えないので del -> ins にする。
                    ManageAddSaml2OAuth2DataViewModel temp = null;
                    DataProvider.Saml2OAuth2Data.TryRemove(clientID, out temp);
                    DataProvider.Saml2OAuth2Data.TryAdd(clientID, DataProvider.Copy(clientID, model));

                    break;

                case EnumUserStoreType.SqlServer:
                case EnumUserStoreType.ODPManagedDriver:
                case EnumUserStoreType.PostgreSQL: // DMBMS

                    using (IDbConnection cnn = DataAccess.CreateConnection())
                    {
                        cnn.Open();

                        EnumUserStoreType storeType = Config.UserStoreType;

                        cnn.Execute(
                            "UPDATE " + DataProvider.TableName(storeType)
                            + " SET " + DataProvider.SetList(storeType)
                            + DataProvider.WhereClientID(storeType),
                            DataProvider.ToParameters(clientID, model, storeType));
                    }

                    break;
            }
        }

        #endregion

        #region Delete

        /// <summary>Delete</summary>
        /// <param name="clientID">string</param>
        public static void Delete(string clientID)
        {
            switch (Config.UserStoreType)
            {
                case EnumUserStoreType.Memory:
                    ManageAddSaml2OAuth2DataViewModel model = null;
                    DataProvider.Saml2OAuth2Data.TryRemove(clientID, out model);

                    break;

                case EnumUserStoreType.SqlServer:
                case EnumUserStoreType.ODPManagedDriver:
                case EnumUserStoreType.PostgreSQL: // DMBMS

                    using (IDbConnection cnn = DataAccess.CreateConnection())
                    {
                        cnn.Open();

                        EnumUserStoreType storeType = Config.UserStoreType;

                        cnn.Execute(
                            "DELETE FROM " + DataProvider.TableName(storeType)
                            + DataProvider.WhereClientID(storeType),
                            new { ClientID = clientID });
                    }

                    break;
            }
        }

        #endregion
    }
}
