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
//* クラス名        ：SoftwareStatementIssuerProvider
//* クラス日本語名  ：software_statement の発行者（ベンダ）の登録を、user store に保存する
//*
//* 作成日時        ：－
//* 作成者          ：－
//* 更新履歴        ：－
//*
//*  日時        更新者            内容
//*  ----------  ----------------  -------------------------------------------------
//*  2026/10/21  玄人 幸道         新規（#308 の段階 1）
//**********************************************************************************

using MultiPurposeAuthSite.Co;
using MultiPurposeAuthSite.Data;
using MultiPurposeAuthSite.ViewModels;

using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Data;
using System.Linq;

using Dapper;

namespace MultiPurposeAuthSite.Extensions.Sts
{
    /// <summary>
    /// SoftwareStatementIssuerProvider
    /// `software_statement` の発行者の登録を、`SoftwareStatementIssuers` 表に保存する（#308 の段階 1）。
    /// </summary>
    /// <remarks>
    /// **`IdFederationUpstreamProvider`（#292 の段階 2）と同じ作り**である。
    /// **列の並びを 1 か所で持ち、方言ごとの書き方だけを分ける。**
    ///
    /// | | |
    /// |---|---|
    /// | `mem` | プロセス内の辞書（**作り直すと消える**） |
    /// | `sql` / `ora` / `npg` | `SoftwareStatementIssuers` 表（DDL は 3 方言） |
    ///
    /// **設定（`appSettings` の `SoftwareStatementIssuers`）とは、併存する。**
    /// **読み出しの入口は `Co.SoftwareStatementIssuers`** で、**設定 → DB の順に見る**
    /// （**同じ鍵なら設定が勝つ**。`IdFederationUpstreams` と同じ流儀）。
    ///
    /// **暗号化する列は無い。**
    /// **持っているのは公開鍵（`.cer` のパスか本文）と上限だけ**で、
    /// **`client_secret` や `.pfx` のパスワードのような秘密は入らない**（#297 の対象外）。
    /// </remarks>
    public class SoftwareStatementIssuerProvider
    {
        /// <summary>SoftwareStatementIssuers（mem のときの入れ物）</summary>
        private static ConcurrentDictionary<string, SoftwareStatementIssuerViewModel> Issuers
            = new ConcurrentDictionary<string, SoftwareStatementIssuerViewModel>();

        #region 列の並び

        /// <summary>列の並び</summary>
        /// <remarks>
        /// **1 か所で持つ**（#270 と同じ理由。**手で書き並べると、どれかが取り残される**）。
        /// **並びは `SoftwareStatementIssuerViewModel` の宣言順**で、**列名は属性名と同じ**である。
        /// </remarks>
        private static readonly string[] Columns = new string[]
        {
            "IssuerKey",
            "DisplayName",
            "Enabled",
            "Issuer",
            "CerFilePath",
            "CerBody",
            "Alg",
            "AllowedScope",
            "AllowedGrantTypes"
        };

        /// <summary>列の並びを、方言の書き方で並べる</summary>
        /// <param name="storeType">EnumUserStoreType</param>
        /// <returns>「[A], [B]」のような文字列</returns>
        private static string ColumnList(EnumUserStoreType storeType)
        {
            switch (storeType)
            {
                case EnumUserStoreType.SqlServer:
                    return string.Join(", ", SoftwareStatementIssuerProvider.Columns
                        .Select(c => "[" + c + "]"));

                case EnumUserStoreType.ODPManagedDriver:
                    return string.Join(", ", SoftwareStatementIssuerProvider.Columns
                        .Select(c => "\"" + c + "\""));

                case EnumUserStoreType.PostgreSQL:
                    // **PostgreSQL は、引用符なしの識別子が小文字に畳まれる。**
                    //   DDL を引用符なしで書いているので、ここは小文字で引く。
                    //   **別名を付けて、属性名で受け取る。**
                    return string.Join(", ", SoftwareStatementIssuerProvider.Columns
                        .Select(c => "\"" + c.ToLower() + "\" AS \"" + c + "\""));

                default:
                    throw new NotSupportedException(storeType.ToString());
            }
        }

        /// <summary>INSERT の列の並び（別名を付けない）</summary>
        /// <param name="storeType">EnumUserStoreType</param>
        /// <returns>「[A], [B]」のような文字列</returns>
        private static string InsertColumnList(EnumUserStoreType storeType)
        {
            switch (storeType)
            {
                case EnumUserStoreType.SqlServer:
                    return string.Join(", ", SoftwareStatementIssuerProvider.Columns
                        .Select(c => "[" + c + "]"));

                case EnumUserStoreType.ODPManagedDriver:
                    return string.Join(", ", SoftwareStatementIssuerProvider.Columns
                        .Select(c => "\"" + c + "\""));

                default:
                    return string.Join(", ", SoftwareStatementIssuerProvider.Columns
                        .Select(c => "\"" + c.ToLower() + "\""));
            }
        }

        /// <summary>パラメタの並び</summary>
        /// <param name="storeType">EnumUserStoreType</param>
        /// <returns>「@A, @B」のような文字列</returns>
        private static string ParameterList(EnumUserStoreType storeType)
        {
            // **Oracle だけ「:」**（他は「@」）。
            string p = (storeType == EnumUserStoreType.ODPManagedDriver) ? ":" : "@";

            return string.Join(", ", SoftwareStatementIssuerProvider.Columns.Select(c => p + c));
        }

        /// <summary>UPDATE の SET 句（IssuerKey は外す）</summary>
        /// <param name="storeType">EnumUserStoreType</param>
        /// <returns>「[A] = @A, [B] = @B」のような文字列</returns>
        private static string SetList(EnumUserStoreType storeType)
        {
            string p = (storeType == EnumUserStoreType.ODPManagedDriver) ? ":" : "@";

            return string.Join(", ", SoftwareStatementIssuerProvider.Columns
                .Where(c => c != "IssuerKey")
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
        /// <param name="storeType">EnumUserStoreType</param>
        /// <returns>テーブル名</returns>
        private static string TableName(EnumUserStoreType storeType)
        {
            switch (storeType)
            {
                case EnumUserStoreType.SqlServer:
                    return "[SoftwareStatementIssuers]";
                case EnumUserStoreType.ODPManagedDriver:
                    return "\"SoftwareStatementIssuers\"";
                default:
                    return "\"softwarestatementissuers\"";
            }
        }

        /// <summary>IssuerKey の条件句</summary>
        /// <param name="storeType">EnumUserStoreType</param>
        /// <returns>WHERE 句</returns>
        private static string WhereIssuerKey(EnumUserStoreType storeType)
        {
            switch (storeType)
            {
                case EnumUserStoreType.SqlServer:
                    return " WHERE [IssuerKey] = @IssuerKey";
                case EnumUserStoreType.ODPManagedDriver:
                    return " WHERE \"IssuerKey\" = :IssuerKey";
                default:
                    return " WHERE \"issuerkey\" = @IssuerKey";
            }
        }

        /// <summary>モデルをパラメタにする</summary>
        /// <param name="model">SoftwareStatementIssuerViewModel</param>
        /// <param name="storeType">EnumUserStoreType</param>
        /// <returns>DynamicParameters</returns>
        /// <remarks>
        /// **`Enabled` だけ方言で形が違う。**
        /// **Oracle は `NUMBER(3)` で、真を -1 で持つ**（`Users` の bool 列と同じ流儀）。
        /// </remarks>
        private static DynamicParameters ToParameters(
            SoftwareStatementIssuerViewModel model, EnumUserStoreType storeType)
        {
            DynamicParameters prm = new DynamicParameters();

            prm.Add("IssuerKey", model.IssuerKey);
            prm.Add("DisplayName", model.DisplayName);
            prm.Add("Issuer", model.Issuer);
            prm.Add("CerFilePath", model.CerFilePath);
            prm.Add("CerBody", model.CerBody);
            prm.Add("Alg", model.Alg);
            prm.Add("AllowedScope", model.AllowedScope);
            prm.Add("AllowedGrantTypes", model.AllowedGrantTypes);

            if (storeType == EnumUserStoreType.ODPManagedDriver)
            {
                prm.Add("Enabled", model.Enabled ? -1 : 0);
            }
            else
            {
                prm.Add("Enabled", model.Enabled);
            }

            return prm;
        }

        /// <summary>複製を作る（mem のとき、呼ぶ側と入れ物を分けるため）</summary>
        /// <param name="model">SoftwareStatementIssuerViewModel</param>
        /// <returns>複製（null なら null）</returns>
        /// <remarks>
        /// **画面が持っているモデルをそのまま入れると、
        /// 後から画面側で書き換えた内容が、保存済みの登録に混ざる。**
        /// </remarks>
        private static SoftwareStatementIssuerViewModel Copy(
            SoftwareStatementIssuerViewModel model)
        {
            if (model == null)
            {
                return null;
            }

            return new SoftwareStatementIssuerViewModel()
            {
                IssuerKey = model.IssuerKey,
                DisplayName = model.DisplayName,
                Enabled = model.Enabled,
                Issuer = model.Issuer,
                CerFilePath = model.CerFilePath,
                CerBody = model.CerBody,
                Alg = model.Alg,
                AllowedScope = model.AllowedScope,
                AllowedGrantTypes = model.AllowedGrantTypes
            };
        }

        #endregion

        #region Create

        /// <summary>Create</summary>
        /// <param name="model">SoftwareStatementIssuerViewModel</param>
        public static void Create(SoftwareStatementIssuerViewModel model)
        {
            switch (Config.UserStoreType)
            {
                case EnumUserStoreType.Memory:
                    SoftwareStatementIssuerProvider.Issuers.TryAdd(
                        model.IssuerKey, SoftwareStatementIssuerProvider.Copy(model));
                    break;

                case EnumUserStoreType.SqlServer:
                case EnumUserStoreType.ODPManagedDriver:
                case EnumUserStoreType.PostgreSQL: // DMBMS

                    using (IDbConnection cnn = DataAccess.CreateConnection())
                    {
                        cnn.Open();

                        EnumUserStoreType storeType = Config.UserStoreType;

                        cnn.Execute(
                            "INSERT INTO " + SoftwareStatementIssuerProvider.TableName(storeType)
                            + " (" + SoftwareStatementIssuerProvider.InsertColumnList(storeType) + ")"
                            + " VALUES (" + SoftwareStatementIssuerProvider.ParameterList(storeType) + ")",
                            SoftwareStatementIssuerProvider.ToParameters(model, storeType));
                    }

                    break;
            }
        }

        #endregion

        #region Get(Reference)

        /// <summary>Get</summary>
        /// <param name="issuerKey">鍵</param>
        /// <returns>登録（無ければ null）</returns>
        public static SoftwareStatementIssuerViewModel Get(string issuerKey)
        {
            SoftwareStatementIssuerViewModel model = null;

            if (string.IsNullOrEmpty(issuerKey))
            {
                return null;
            }

            switch (Config.UserStoreType)
            {
                case EnumUserStoreType.Memory:
                    SoftwareStatementIssuerProvider.Issuers.TryGetValue(issuerKey, out model);

                    // **複製を返す。** 呼ぶ側が書き換えても、保存済みの登録は動かない。
                    model = SoftwareStatementIssuerProvider.Copy(model);

                    break;

                case EnumUserStoreType.SqlServer:
                case EnumUserStoreType.ODPManagedDriver:
                case EnumUserStoreType.PostgreSQL: // DMBMS

                    using (IDbConnection cnn = DataAccess.CreateConnection())
                    {
                        cnn.Open();

                        EnumUserStoreType storeType = Config.UserStoreType;

                        model = cnn.QuerySingleOrDefault<SoftwareStatementIssuerViewModel>(
                            "SELECT " + SoftwareStatementIssuerProvider.ColumnList(storeType)
                            + " FROM " + SoftwareStatementIssuerProvider.TableName(storeType)
                            + SoftwareStatementIssuerProvider.WhereIssuerKey(storeType),
                            new { IssuerKey = issuerKey });
                    }

                    break;
            }

            return model;
        }

        #endregion

        #region GetAll

        /// <summary>全件返す</summary>
        /// <returns>登録の一覧（1 件も無ければ空）</returns>
        /// <remarks>
        /// **読み出しの入口（`Co.SoftwareStatementIssuers`）と管理画面の両方が、これを使う。**
        /// **件数は提携先の数**（数件）なので、**全件読んでよい。**
        /// </remarks>
        public static List<SoftwareStatementIssuerViewModel> GetAll()
        {
            List<SoftwareStatementIssuerViewModel> all =
                new List<SoftwareStatementIssuerViewModel>();

            switch (Config.UserStoreType)
            {
                case EnumUserStoreType.Memory:
                    all.AddRange(SoftwareStatementIssuerProvider.Issuers.Values
                        .Select(m => SoftwareStatementIssuerProvider.Copy(m)));

                    break;

                case EnumUserStoreType.SqlServer:
                case EnumUserStoreType.ODPManagedDriver:
                case EnumUserStoreType.PostgreSQL: // DMBMS

                    using (IDbConnection cnn = DataAccess.CreateConnection())
                    {
                        cnn.Open();

                        EnumUserStoreType storeType = Config.UserStoreType;

                        all.AddRange(cnn.Query<SoftwareStatementIssuerViewModel>(
                            "SELECT " + SoftwareStatementIssuerProvider.ColumnList(storeType)
                            + " FROM " + SoftwareStatementIssuerProvider.TableName(storeType)));
                    }

                    break;
            }

            //  **鍵の順に並べる**（画面の並びが実行ごとに変わらないように）。
            return all.OrderBy(m => m.IssuerKey, StringComparer.Ordinal).ToList();
        }

        #endregion

        #region Update

        /// <summary>Update</summary>
        /// <param name="model">SoftwareStatementIssuerViewModel</param>
        public static void Update(SoftwareStatementIssuerViewModel model)
        {
            switch (Config.UserStoreType)
            {
                case EnumUserStoreType.Memory:
                    // TryUpdate が使えないので del -> ins にする。
                    SoftwareStatementIssuerViewModel temp = null;
                    SoftwareStatementIssuerProvider.Issuers.TryRemove(model.IssuerKey, out temp);
                    SoftwareStatementIssuerProvider.Issuers.TryAdd(
                        model.IssuerKey, SoftwareStatementIssuerProvider.Copy(model));

                    break;

                case EnumUserStoreType.SqlServer:
                case EnumUserStoreType.ODPManagedDriver:
                case EnumUserStoreType.PostgreSQL: // DMBMS

                    using (IDbConnection cnn = DataAccess.CreateConnection())
                    {
                        cnn.Open();

                        EnumUserStoreType storeType = Config.UserStoreType;

                        cnn.Execute(
                            "UPDATE " + SoftwareStatementIssuerProvider.TableName(storeType)
                            + " SET " + SoftwareStatementIssuerProvider.SetList(storeType)
                            + SoftwareStatementIssuerProvider.WhereIssuerKey(storeType),
                            SoftwareStatementIssuerProvider.ToParameters(model, storeType));
                    }

                    break;
            }
        }

        #endregion

        #region Delete

        /// <summary>Delete</summary>
        /// <param name="issuerKey">鍵</param>
        public static void Delete(string issuerKey)
        {
            switch (Config.UserStoreType)
            {
                case EnumUserStoreType.Memory:
                    SoftwareStatementIssuerViewModel model = null;
                    SoftwareStatementIssuerProvider.Issuers.TryRemove(issuerKey, out model);

                    break;

                case EnumUserStoreType.SqlServer:
                case EnumUserStoreType.ODPManagedDriver:
                case EnumUserStoreType.PostgreSQL: // DMBMS

                    using (IDbConnection cnn = DataAccess.CreateConnection())
                    {
                        cnn.Open();

                        EnumUserStoreType storeType = Config.UserStoreType;

                        cnn.Execute(
                            "DELETE FROM " + SoftwareStatementIssuerProvider.TableName(storeType)
                            + SoftwareStatementIssuerProvider.WhereIssuerKey(storeType),
                            new { IssuerKey = issuerKey });
                    }

                    break;
            }
        }

        #endregion
    }
}
