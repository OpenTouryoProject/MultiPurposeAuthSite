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
//* クラス名        ：IdFederationUpstreamProvider
//* クラス日本語名  ：ID 連携の上流 IdP の登録を、user store に保存する
//*
//* 作成日時        ：－
//* 作成者          ：－
//* 更新履歴        ：－
//*
//*  日時        更新者            内容
//*  ----------  ----------------  -------------------------------------------------
//*  2026/10/14  玄人 幸道         新規（#292 の段階 2）
//*  2026/10/14  玄人 幸道         ClientSecretを暗号化して保管（#297）
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
    /// IdFederationUpstreamProvider
    /// ID 連携の上流 IdP の登録を、`IdFederationUpstreams` 表に保存する（#292 の段階 2）。
    /// </summary>
    /// <remarks>
    /// **`Extensions/Sts/Saml2OAuth2DataProvider`（クライアント登録）と同じ作り**である。
    /// **列の並びを 1 か所で持ち、方言ごとの書き方だけを分ける。**
    ///
    /// | | |
    /// |---|---|
    /// | `mem` | プロセス内の辞書（**作り直すと消える**） |
    /// | `sql` / `ora` / `npg` | `IdFederationUpstreams` 表（DDL は 3 方言） |
    ///
    /// **設定（`appSettings` の `IdFederationUpstreams`）とは、併存する。**
    /// **読み出しの入口は `Co.IdFederationUpstreams`** で、**設定 → DB の順に見る**
    /// （**クライアント登録と同じ流儀**。`Helper` が構成ファイル → `Saml2OAuth2Data` の順に見る）。
    ///
    /// **授受する型は `IdFederationUpstreamViewModel`。**
    /// **画面（`IdFederationAdminController`）と DB で、同じ型を使う。**
    /// </remarks>
    public class IdFederationUpstreamProvider
    {
        /// <summary>IdFederationUpstreams（mem のときの入れ物）</summary>
        private static ConcurrentDictionary<string, IdFederationUpstreamViewModel> Upstreams
            = new ConcurrentDictionary<string, IdFederationUpstreamViewModel>();

        #region 列の並び

        /// <summary>列の並び</summary>
        /// <remarks>
        /// **1 か所で持つ**（#270 と同じ理由。**手で書き並べると、どれかが取り残される**）。
        /// **並びは `IdFederationUpstreamViewModel` の宣言順**で、**列名は属性名と同じ**である。
        /// </remarks>
        private static readonly string[] Columns = new string[]
        {
            "UpstreamKey",
            "DisplayName",
            "Protocol",
            "Enabled",
            "Issuer",
            "ClientID",
            "ClientSecret",
            "DiscoveryUrl",
            "JwkSetUri",
            "MetadataUrl",
            "CerFilePath",
            "AuthorizeEndpoint",
            "TokenEndpoint",
            "UserInfoEndpoint",
            "SsoEndpoint",
            "SigningPfxFilePath",
            "SigningPfxPassword"
        };

        /// <summary>列の並びを、方言の書き方で並べる</summary>
        /// <param name="storeType">EnumUserStoreType</param>
        /// <returns>「[A], [B]」のような文字列</returns>
        private static string ColumnList(EnumUserStoreType storeType)
        {
            switch (storeType)
            {
                case EnumUserStoreType.SqlServer:
                    return string.Join(", ", IdFederationUpstreamProvider.Columns
                        .Select(c => "[" + c + "]"));

                case EnumUserStoreType.ODPManagedDriver:
                    return string.Join(", ", IdFederationUpstreamProvider.Columns
                        .Select(c => "\"" + c + "\""));

                case EnumUserStoreType.PostgreSQL:
                    // **PostgreSQL は、引用符なしの識別子が小文字に畳まれる。**
                    //   DDL を引用符なしで書いているので、ここは小文字で引く。
                    //   **別名を付けて、属性名で受け取る。**
                    return string.Join(", ", IdFederationUpstreamProvider.Columns
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
                    return string.Join(", ", IdFederationUpstreamProvider.Columns
                        .Select(c => "[" + c + "]"));

                case EnumUserStoreType.ODPManagedDriver:
                    return string.Join(", ", IdFederationUpstreamProvider.Columns
                        .Select(c => "\"" + c + "\""));

                default:
                    return string.Join(", ", IdFederationUpstreamProvider.Columns
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

            return string.Join(", ", IdFederationUpstreamProvider.Columns.Select(c => p + c));
        }

        /// <summary>UPDATE の SET 句（UpstreamKey は外す）</summary>
        /// <param name="storeType">EnumUserStoreType</param>
        /// <returns>「[A] = @A, [B] = @B」のような文字列</returns>
        private static string SetList(EnumUserStoreType storeType)
        {
            string p = (storeType == EnumUserStoreType.ODPManagedDriver) ? ":" : "@";

            return string.Join(", ", IdFederationUpstreamProvider.Columns
                .Where(c => c != "UpstreamKey")
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
                    return "[IdFederationUpstreams]";
                case EnumUserStoreType.ODPManagedDriver:
                    return "\"IdFederationUpstreams\"";
                default:
                    return "\"idfederationupstreams\"";
            }
        }

        /// <summary>UpstreamKey の条件句</summary>
        private static string WhereUpstreamKey(EnumUserStoreType storeType)
        {
            switch (storeType)
            {
                case EnumUserStoreType.SqlServer:
                    return " WHERE [UpstreamKey] = @UpstreamKey";
                case EnumUserStoreType.ODPManagedDriver:
                    return " WHERE \"UpstreamKey\" = :UpstreamKey";
                default:
                    return " WHERE \"upstreamkey\" = @UpstreamKey";
            }
        }

        /// <summary>モデルをパラメタにする</summary>
        /// <param name="model">IdFederationUpstreamViewModel</param>
        /// <param name="storeType">EnumUserStoreType</param>
        /// <returns>DynamicParameters</returns>
        /// <remarks>
        /// **`Enabled` だけ方言で形が違う。**
        /// **Oracle は `NUMBER(3)` で、真を -1 で持つ**（`Users` の bool 列と同じ流儀）。
        /// </remarks>
        private static DynamicParameters ToParameters(
            IdFederationUpstreamViewModel model, EnumUserStoreType storeType)
        {
            DynamicParameters prm = new DynamicParameters();

            prm.Add("UpstreamKey", model.UpstreamKey);
            prm.Add("DisplayName", model.DisplayName);
            prm.Add("Protocol", model.Protocol);
            prm.Add("Issuer", model.Issuer);
            prm.Add("ClientID", model.ClientID);
            prm.Add("ClientSecret", model.ClientSecret);
            prm.Add("DiscoveryUrl", model.DiscoveryUrl);
            prm.Add("JwkSetUri", model.JwkSetUri);
            prm.Add("MetadataUrl", model.MetadataUrl);
            prm.Add("CerFilePath", model.CerFilePath);
            prm.Add("AuthorizeEndpoint", model.AuthorizeEndpoint);
            prm.Add("TokenEndpoint", model.TokenEndpoint);
            prm.Add("UserInfoEndpoint", model.UserInfoEndpoint);
            prm.Add("SsoEndpoint", model.SsoEndpoint);
            prm.Add("SigningPfxFilePath", model.SigningPfxFilePath);
            prm.Add("SigningPfxPassword", model.SigningPfxPassword);

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

        /// <summary>保管する形にする（秘密を暗号化する。#297）</summary>
        /// <param name="model">IdFederationUpstreamViewModel</param>
        /// <returns>複製（元のモデルは書き換えない）</returns>
        /// <remarks>
        /// **呼ばれた側のモデルを書き換えない**（画面が持っている値が暗号文になると、
        /// **そのまま再表示されてしまう**）。
        /// </remarks>
        private static IdFederationUpstreamViewModel Protect(IdFederationUpstreamViewModel model)
        {
            IdFederationUpstreamViewModel copy = IdFederationUpstreamProvider.Copy(model);

            if (copy != null)
            {
                //  **秘密は 2 つある**（#292 の段階 4-b で `.pfx` のパスワードが増えた）。
                copy.ClientSecret = SecretProtector.Protect(copy.ClientSecret);
                copy.SigningPfxPassword = SecretProtector.Protect(copy.SigningPfxPassword);
            }

            return copy;
        }

        /// <summary>使う形にする（秘密を復号する。#297）</summary>
        /// <param name="model">IdFederationUpstreamViewModel</param>
        /// <returns>同じインスタンス（null なら null）</returns>
        private static IdFederationUpstreamViewModel Unprotect(IdFederationUpstreamViewModel model)
        {
            if (model != null)
            {
                model.ClientSecret = SecretProtector.Unprotect(model.ClientSecret);
                model.SigningPfxPassword = SecretProtector.Unprotect(model.SigningPfxPassword);
            }

            return model;
        }

        /// <summary>モデルを複製する（Memory Provider 用）</summary>
        /// <param name="model">IdFederationUpstreamViewModel</param>
        /// <returns>複製</returns>
        /// <remarks>
        /// **参照を入れてはならない**（#270 と同じ理由）。
        /// **画面が持っているモデルをそのまま入れると、
        /// 後から画面側で書き換えた内容が、保存済みの登録に混ざる。**
        /// </remarks>
        private static IdFederationUpstreamViewModel Copy(IdFederationUpstreamViewModel model)
        {
            if (model == null)
            {
                return null;
            }

            return new IdFederationUpstreamViewModel()
            {
                UpstreamKey = model.UpstreamKey,
                DisplayName = model.DisplayName,
                Protocol = model.Protocol,
                Enabled = model.Enabled,
                Issuer = model.Issuer,
                ClientID = model.ClientID,
                ClientSecret = model.ClientSecret,
                DiscoveryUrl = model.DiscoveryUrl,
                JwkSetUri = model.JwkSetUri,
                MetadataUrl = model.MetadataUrl,
                CerFilePath = model.CerFilePath,
                AuthorizeEndpoint = model.AuthorizeEndpoint,
                TokenEndpoint = model.TokenEndpoint,
                UserInfoEndpoint = model.UserInfoEndpoint,
                SsoEndpoint = model.SsoEndpoint,
                SigningPfxFilePath = model.SigningPfxFilePath,
                SigningPfxPassword = model.SigningPfxPassword
            };
        }

        #endregion

        #region Create

        /// <summary>Create</summary>
        /// <param name="model">IdFederationUpstreamViewModel</param>
        public static void Create(IdFederationUpstreamViewModel model)
        {
            //  **秘密は暗号化して保管する**（#297。**鍵が空なら平文のまま**）。
            model = IdFederationUpstreamProvider.Protect(model);

            switch (Config.UserStoreType)
            {
                case EnumUserStoreType.Memory:
                    IdFederationUpstreamProvider.Upstreams.TryAdd(
                        model.UpstreamKey, IdFederationUpstreamProvider.Copy(model));
                    break;

                case EnumUserStoreType.SqlServer:
                case EnumUserStoreType.ODPManagedDriver:
                case EnumUserStoreType.PostgreSQL: // DMBMS

                    using (IDbConnection cnn = DataAccess.CreateConnection())
                    {
                        cnn.Open();

                        EnumUserStoreType storeType = Config.UserStoreType;

                        cnn.Execute(
                            "INSERT INTO " + IdFederationUpstreamProvider.TableName(storeType)
                            + " (" + IdFederationUpstreamProvider.InsertColumnList(storeType) + ")"
                            + " VALUES (" + IdFederationUpstreamProvider.ParameterList(storeType) + ")",
                            IdFederationUpstreamProvider.ToParameters(model, storeType));
                    }

                    break;
            }
        }

        #endregion

        #region Get(Reference)

        /// <summary>Get</summary>
        /// <param name="upstreamKey">鍵</param>
        /// <returns>登録（無ければ null）</returns>
        public static IdFederationUpstreamViewModel Get(string upstreamKey)
        {
            IdFederationUpstreamViewModel model = null;

            if (string.IsNullOrEmpty(upstreamKey))
            {
                return null;
            }

            switch (Config.UserStoreType)
            {
                case EnumUserStoreType.Memory:
                    IdFederationUpstreamProvider.Upstreams.TryGetValue(upstreamKey, out model);

                    // **複製を返す。** 呼ぶ側が書き換えても、保存済みの登録は動かない。
                    model = IdFederationUpstreamProvider.Copy(model);

                    break;

                case EnumUserStoreType.SqlServer:
                case EnumUserStoreType.ODPManagedDriver:
                case EnumUserStoreType.PostgreSQL: // DMBMS

                    using (IDbConnection cnn = DataAccess.CreateConnection())
                    {
                        cnn.Open();

                        EnumUserStoreType storeType = Config.UserStoreType;

                        model = cnn.QuerySingleOrDefault<IdFederationUpstreamViewModel>(
                            "SELECT " + IdFederationUpstreamProvider.ColumnList(storeType)
                            + " FROM " + IdFederationUpstreamProvider.TableName(storeType)
                            + IdFederationUpstreamProvider.WhereUpstreamKey(storeType),
                            new { UpstreamKey = upstreamKey });
                    }

                    break;
            }

            //  **使う形に戻す**（#297）。
            return IdFederationUpstreamProvider.Unprotect(model);
        }

        #endregion

        #region GetAll

        /// <summary>全件返す</summary>
        /// <returns>登録の一覧（1 件も無ければ空）</returns>
        /// <remarks>
        /// **サインイン画面と管理画面の両方が、これを使う。**
        /// **件数は配備の上流の数**（数件〜数十件）なので、**全件読んでよい。**
        /// </remarks>
        public static List<IdFederationUpstreamViewModel> GetAll()
        {
            List<IdFederationUpstreamViewModel> all = new List<IdFederationUpstreamViewModel>();

            switch (Config.UserStoreType)
            {
                case EnumUserStoreType.Memory:
                    all.AddRange(IdFederationUpstreamProvider.Upstreams.Values
                        .Select(m => IdFederationUpstreamProvider.Copy(m)));

                    break;

                case EnumUserStoreType.SqlServer:
                case EnumUserStoreType.ODPManagedDriver:
                case EnumUserStoreType.PostgreSQL: // DMBMS

                    using (IDbConnection cnn = DataAccess.CreateConnection())
                    {
                        cnn.Open();

                        EnumUserStoreType storeType = Config.UserStoreType;

                        all.AddRange(cnn.Query<IdFederationUpstreamViewModel>(
                            "SELECT " + IdFederationUpstreamProvider.ColumnList(storeType)
                            + " FROM " + IdFederationUpstreamProvider.TableName(storeType)));
                    }

                    break;
            }

            //  **使う形に戻す**（#297）。
            for (int i = 0; i < all.Count; i++)
            {
                all[i] = IdFederationUpstreamProvider.Unprotect(all[i]);
            }

            //  **鍵の順に並べる**（画面の並びが実行ごとに変わらないように）。
            return all.OrderBy(m => m.UpstreamKey, StringComparer.Ordinal).ToList();
        }

        #endregion

        #region Update

        /// <summary>Update</summary>
        /// <param name="model">IdFederationUpstreamViewModel</param>
        public static void Update(IdFederationUpstreamViewModel model)
        {
            //  **秘密は暗号化して保管する**（#297）。
            model = IdFederationUpstreamProvider.Protect(model);

            switch (Config.UserStoreType)
            {
                case EnumUserStoreType.Memory:
                    // TryUpdate が使えないので del -> ins にする。
                    IdFederationUpstreamViewModel temp = null;
                    IdFederationUpstreamProvider.Upstreams.TryRemove(model.UpstreamKey, out temp);
                    IdFederationUpstreamProvider.Upstreams.TryAdd(
                        model.UpstreamKey, IdFederationUpstreamProvider.Copy(model));

                    break;

                case EnumUserStoreType.SqlServer:
                case EnumUserStoreType.ODPManagedDriver:
                case EnumUserStoreType.PostgreSQL: // DMBMS

                    using (IDbConnection cnn = DataAccess.CreateConnection())
                    {
                        cnn.Open();

                        EnumUserStoreType storeType = Config.UserStoreType;

                        cnn.Execute(
                            "UPDATE " + IdFederationUpstreamProvider.TableName(storeType)
                            + " SET " + IdFederationUpstreamProvider.SetList(storeType)
                            + IdFederationUpstreamProvider.WhereUpstreamKey(storeType),
                            IdFederationUpstreamProvider.ToParameters(model, storeType));
                    }

                    break;
            }
        }

        #endregion

        #region Delete

        /// <summary>Delete</summary>
        /// <param name="upstreamKey">鍵</param>
        public static void Delete(string upstreamKey)
        {
            switch (Config.UserStoreType)
            {
                case EnumUserStoreType.Memory:
                    IdFederationUpstreamViewModel model = null;
                    IdFederationUpstreamProvider.Upstreams.TryRemove(upstreamKey, out model);

                    break;

                case EnumUserStoreType.SqlServer:
                case EnumUserStoreType.ODPManagedDriver:
                case EnumUserStoreType.PostgreSQL: // DMBMS

                    using (IDbConnection cnn = DataAccess.CreateConnection())
                    {
                        cnn.Open();

                        EnumUserStoreType storeType = Config.UserStoreType;

                        cnn.Execute(
                            "DELETE FROM " + IdFederationUpstreamProvider.TableName(storeType)
                            + IdFederationUpstreamProvider.WhereUpstreamKey(storeType),
                            new { UpstreamKey = upstreamKey });
                    }

                    break;
            }
        }

        #endregion
    }
}
