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
//* クラス名        ：Saml2OAuth2DataProvider
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
//*  2026/10/14  玄人 幸道         ClientSecretを暗号化して保管（#297）
//*  2026/10/18  玄人 幸道         RFC 7591 §2 のメタデータの列を追加（#307 の段階 1）
//*  2026/10/21  玄人 幸道         BackChannelLogoutUri の列を追加（#310 の段階 2）
//*  2026/10/21  玄人 幸道         登録されている jwks_uri を全部返す口を追加（#309 の段階 2）
//*  2026/10/31  玄人 幸道         CORS の public の判定のため、GetAllUris で token_endpoint_auth_method も読む（#294）
//**********************************************************************************

using MultiPurposeAuthSite.Co;
using MultiPurposeAuthSite.Data;
using MultiPurposeAuthSite.ViewModels;
using MultiPurposeAuthSite.Util.Sts;

using System;
using System.Linq;
using System.Collections.Generic;
using System.Data;
using System.Collections.Concurrent;

using Dapper;

namespace MultiPurposeAuthSite.Extensions.Sts
{
    /// <summary>
    /// Saml2OAuth2DataProvider
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
    public class Saml2OAuth2DataProvider
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
        /// **1 か所で持つ。** 30 列 × 3 方言 × 3 文（INSERT / SELECT / UPDATE）を
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
            "ClientName",
            //  **RFC 7591 §2 のクライアント メタデータ**（#307 の段階 1）。
            //    **末尾に足す。** **既存のデータベースは `ALTER … ADD` で足せる**ので、
            //    **作り直した `CREATE` と物理的な並びも揃う。**
            "Scopes",
            "GrantTypes",
            "ResponseTypes",
            "JwksUri",
            "ClientUri",
            "LogoUri",
            "TosUri",
            "PolicyUri",
            "Contacts",
            "SoftwareId",
            "SoftwareVersion",
            //  **RFC 7592 の管理 API 用**（#307 の段階 2）。**ハッシュが入る。**
            "RegistrationAccessToken",
            //  **クライアント認証の方法**（#307 の段階 3）。**空なら秘密ベースの 2 つ。**
            "TokenEndpointAuthMethod",
            //  **所有者**（#307 の段階 5-a）。**`Users.Id` を指す。** **空が在り得る。**
            "OwnerUserId",
            //  **ログアウトを伝える先**（#310 の段階 2）。**末尾に足す**（`ALTER … ADD` で揃う）。
            "BackChannelLogoutUri",
            //  **ブラウザ経由で伝える先**（#310 の段階 3）。**末尾に足す**（同上）。
            "FrontChannelLogoutUri"
        };

        /// <summary>CORS の許可オリジンを作るのに要る列だけ（#270）</summary>
        /// <remarks>
        /// **`GetAllUris` が使う。** 全列を読む必要はない
        /// （**列にしたので、こう絞れる**。JSON 1 列では全部読むしかなかった）。
        /// **`ClientSecret` と `TokenEndpointAuthMethod` が要る**のは、**public クライアントに限る**ため
        /// （`Helper.IsPublicClientForCors`。#294）。
        /// </remarks>
        private static readonly string[] UriColumns = new string[]
        {
            "ClientSecret",
            "TokenEndpointAuthMethod",
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

            return string.Join(", ", Saml2OAuth2DataProvider.Columns
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

        /// <summary>OwnerUserId の条件句（#307 の段階 5-a）</summary>
        /// <param name="storeType">EnumUserStoreType</param>
        /// <returns>条件句</returns>
        private static string WhereOwnerUserId(EnumUserStoreType storeType)
        {
            switch (storeType)
            {
                case EnumUserStoreType.SqlServer:
                    return " WHERE [OwnerUserId] = @OwnerUserId";
                case EnumUserStoreType.ODPManagedDriver:
                    return " WHERE \"OwnerUserId\" = :OwnerUserId";
                default:
                    return " WHERE \"owneruserid\" = @OwnerUserId";
            }
        }

        /// <summary>並びを決める句（#307 の段階 5-a-2）</summary>
        /// <param name="storeType">EnumUserStoreType</param>
        /// <returns>「 ORDER BY [ClientID]」のような文字列</returns>
        /// <remarks>
        /// **一覧の並びを決める**（#307 の段階 5-a-2）。
        ///
        /// **段階 5-a-1 では決めていなかった** — **1 件を取り出すだけ**で、
        /// **どれが来てもよかった**ためである。
        /// **一覧にすると、並びが毎回変わるのは使いにくい**
        /// （**E2E も「2 件目」を指せない**）ので、ここで決める。
        ///
        /// **鍵は `client_id`**（**32 桁の 16 進**。`Guid.ToString("N")`）。
        /// **大文字小文字の揺れが無い**ので、**照合順序の違いが結果を変えない。**
        /// **`mem` は序数で並べる**（`StringComparer.Ordinal`）。
        /// </remarks>
        private static string OrderByClientID(EnumUserStoreType storeType)
        {
            switch (storeType)
            {
                case EnumUserStoreType.SqlServer:
                    return " ORDER BY [ClientID]";
                case EnumUserStoreType.ODPManagedDriver:
                    return " ORDER BY \"ClientID\"";
                default:
                    return " ORDER BY \"clientid\"";
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

            //  **RFC 7591 §2 のクライアント メタデータ**（#307 の段階 1）。
            prm.Add("Scopes", model.Scopes);
            prm.Add("GrantTypes", model.GrantTypes);
            prm.Add("ResponseTypes", model.ResponseTypes);
            prm.Add("JwksUri", model.JwksUri);
            prm.Add("ClientUri", model.ClientUri);
            prm.Add("LogoUri", model.LogoUri);
            prm.Add("TosUri", model.TosUri);
            prm.Add("PolicyUri", model.PolicyUri);
            prm.Add("Contacts", model.Contacts);
            prm.Add("SoftwareId", model.SoftwareId);
            prm.Add("SoftwareVersion", model.SoftwareVersion);
            prm.Add("RegistrationAccessToken", model.RegistrationAccessToken);

            //  **クライアント認証の方法**（#307 の段階 3）。
            prm.Add("TokenEndpointAuthMethod", model.TokenEndpointAuthMethod);
            prm.Add("OwnerUserId", model.OwnerUserId);

            //  **ログアウトを伝える先**（#310 の段階 2・3）。
            prm.Add("BackChannelLogoutUri", model.BackChannelLogoutUri);
            prm.Add("FrontChannelLogoutUri", model.FrontChannelLogoutUri);

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

        /// <summary>保管する形にする（秘密を暗号化する。#297）</summary>
        /// <param name="clientID">string</param>
        /// <param name="model">ManageAddSaml2OAuth2DataViewModel</param>
        /// <returns>複製（元のモデルは書き換えない）</returns>
        /// <remarks>
        /// **呼ばれた側のモデルを書き換えない**（画面が持っている値が暗号文になると、
        /// **そのまま再表示されてしまう**）。
        /// </remarks>
        private static ManageAddSaml2OAuth2DataViewModel Protect(
            string clientID, ManageAddSaml2OAuth2DataViewModel model)
        {
            ManageAddSaml2OAuth2DataViewModel copy = Saml2OAuth2DataProvider.Copy(clientID, model);

            if (copy != null)
            {
                copy.ClientSecret = SecretProtector.Protect(copy.ClientSecret);
            }

            return copy;
        }

        /// <summary>使う形にする（秘密を復号する。#297）</summary>
        /// <param name="model">ManageAddSaml2OAuth2DataViewModel</param>
        /// <returns>同じインスタンス（null なら null）</returns>
        private static ManageAddSaml2OAuth2DataViewModel Unprotect(
            ManageAddSaml2OAuth2DataViewModel model)
        {
            if (model != null)
            {
                model.ClientSecret = SecretProtector.Unprotect(model.ClientSecret);
            }

            return model;
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
                ClientName = model.ClientName,
                //  **RFC 7591 §2 のクライアント メタデータ**（#307 の段階 1）。
                Scopes = model.Scopes,
                GrantTypes = model.GrantTypes,
                ResponseTypes = model.ResponseTypes,
                JwksUri = model.JwksUri,
                ClientUri = model.ClientUri,
                LogoUri = model.LogoUri,
                TosUri = model.TosUri,
                PolicyUri = model.PolicyUri,
                Contacts = model.Contacts,
                SoftwareId = model.SoftwareId,
                SoftwareVersion = model.SoftwareVersion,
                RegistrationAccessToken = model.RegistrationAccessToken,
                //  **クライアント認証の方法**（#307 の段階 3）。
                TokenEndpointAuthMethod = model.TokenEndpointAuthMethod,
                //  **所有者**（#307 の段階 5-a）。
                OwnerUserId = model.OwnerUserId,
                //  **ログアウトを伝える先**（#310 の段階 2・3）。
                BackChannelLogoutUri = model.BackChannelLogoutUri,
                FrontChannelLogoutUri = model.FrontChannelLogoutUri
            };
        }

        #endregion

        #region Create

        /// <summary>Create</summary>
        /// <param name="clientID">string</param>
        /// <param name="model">ManageAddSaml2OAuth2DataViewModel</param>
        public static void Create(string clientID, ManageAddSaml2OAuth2DataViewModel model)
        {
            //  **秘密は暗号化して保管する**（#297。**鍵が空なら平文のまま**）。
            model = Saml2OAuth2DataProvider.Protect(clientID, model);

            switch (Config.UserStoreType)
            {
                case EnumUserStoreType.Memory:
                    Saml2OAuth2DataProvider.Saml2OAuth2Data.TryAdd(clientID, Saml2OAuth2DataProvider.Copy(clientID, model));
                    break;

                case EnumUserStoreType.SqlServer:
                case EnumUserStoreType.ODPManagedDriver:
                case EnumUserStoreType.PostgreSQL: // DMBMS

                    using (IDbConnection cnn = DataAccess.CreateConnection())
                    {
                        cnn.Open();

                        EnumUserStoreType storeType = Config.UserStoreType;

                        cnn.Execute(
                            "INSERT INTO " + Saml2OAuth2DataProvider.TableName(storeType)
                            + " (" + Saml2OAuth2DataProvider.ColumnList(Saml2OAuth2DataProvider.Columns, storeType) + ")"
                            + " VALUES (" + Saml2OAuth2DataProvider.ParameterList(Saml2OAuth2DataProvider.Columns, storeType) + ")",
                            Saml2OAuth2DataProvider.ToParameters(clientID, model, storeType));
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
                    Saml2OAuth2DataProvider.Saml2OAuth2Data.TryGetValue(clientID, out model);

                    // **複製を返す。** 呼ぶ側が書き換えても、保存済みの登録は動かない。
                    model = Saml2OAuth2DataProvider.Copy(clientID, model);

                    break;

                case EnumUserStoreType.SqlServer:
                case EnumUserStoreType.ODPManagedDriver:
                case EnumUserStoreType.PostgreSQL: // DMBMS

                    using (IDbConnection cnn = DataAccess.CreateConnection())
                    {
                        cnn.Open();

                        EnumUserStoreType storeType = Config.UserStoreType;

                        model = cnn.QuerySingleOrDefault<ManageAddSaml2OAuth2DataViewModel>(
                            "SELECT " + Saml2OAuth2DataProvider.ColumnList(Saml2OAuth2DataProvider.Columns, storeType)
                            + " FROM " + Saml2OAuth2DataProvider.TableName(storeType)
                            + Saml2OAuth2DataProvider.WhereClientID(storeType),
                            new { ClientID = clientID });
                    }

                    break;
            }

            //  **使う形に戻す**（#297）。
            return Saml2OAuth2DataProvider.Unprotect(model);
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
                    all.AddRange(Saml2OAuth2DataProvider.Saml2OAuth2Data.Values
                        .Select(m => Saml2OAuth2DataProvider.Copy(null, m)));

                    break;

                case EnumUserStoreType.SqlServer:
                case EnumUserStoreType.ODPManagedDriver:
                case EnumUserStoreType.PostgreSQL: // DMBMS

                    using (IDbConnection cnn = DataAccess.CreateConnection())
                    {
                        cnn.Open();

                        EnumUserStoreType storeType = Config.UserStoreType;

                        all.AddRange(cnn.Query<ManageAddSaml2OAuth2DataViewModel>(
                            "SELECT " + Saml2OAuth2DataProvider.ColumnList(Saml2OAuth2DataProvider.UriColumns, storeType)
                            + " FROM " + Saml2OAuth2DataProvider.TableName(storeType)));
                    }

                    break;
            }

            //  **使う形に戻す**（#297。**public クライアントの判定に使う**ので、ここも戻す）。
            for (int i = 0; i < all.Count; i++)
            {
                all[i] = Saml2OAuth2DataProvider.Unprotect(all[i]);
            }

            return all;
        }

        #endregion

        #region GetAllJwksUris

        /// <summary>登録されている `jwks_uri` を全件返す（#309 の段階 2）</summary>
        /// <returns>URL の一覧（**空の行は含まない**。1 件も無ければ空）</returns>
        /// <remarks>
        /// **起動のときに温めるために要る**（`JwksUriWarmUp`）。
        /// **クライアント認証はキャッシュを読むだけ**なので、
        /// **起こし直した直後は、最初の 1 本が断られる**（#309 の段階 1 の決め (C)(1)）。
        ///
        /// **`JwksUri` の 1 列だけを読む**（`GetAllUris` と同じ流儀。**読む量を絞れる**）。
        ///
        /// **`Unprotect` は通さない。** **暗号化しているのは `ClientSecret` だけ**であり、
        /// **`jwks_uri` は公開情報**である（#297 の対象外）。
        /// </remarks>
        public static List<string> GetAllJwksUris()
        {
            List<string> urls = new List<string>();

            switch (Config.UserStoreType)
            {
                case EnumUserStoreType.Memory:
                    urls.AddRange(Saml2OAuth2DataProvider.Saml2OAuth2Data.Values
                        .Select(m => m.JwksUri));

                    break;

                case EnumUserStoreType.SqlServer:
                case EnumUserStoreType.ODPManagedDriver:
                case EnumUserStoreType.PostgreSQL: // DMBMS

                    using (IDbConnection cnn = DataAccess.CreateConnection())
                    {
                        cnn.Open();

                        EnumUserStoreType storeType = Config.UserStoreType;

                        urls.AddRange(cnn.Query<string>(
                            "SELECT " + Saml2OAuth2DataProvider.ColumnList(
                                new string[] { "JwksUri" }, storeType)
                            + " FROM " + Saml2OAuth2DataProvider.TableName(storeType)));
                    }

                    break;
            }

            //  **空の行は落とす**（**登録の大半は `jwks_uri` を持たない**）。
            return urls.Where(u => !string.IsNullOrEmpty(u)).ToList();
        }

        #endregion

        #region GetByOwner

        /// <summary>所有者の登録を全件返す（#307 の段階 5-a）</summary>
        /// <param name="ownerUserId">所有者（`Users.Id`）</param>
        /// <returns>登録の一覧（1 件も無ければ空）</returns>
        /// <remarks>
        /// **1 利用者 n クライアント**になったので、**所有者で引く口が要る**
        /// （**以前は `Users.ClientID` が 1 件を指していた**ので、`Get` 1 つで足りた）。
        ///
        /// **並びは `client_id` の昇順**（#307 の段階 5-a-2 で決めた）。
        /// **`mem` も DB も同じ順になる** — **一覧の並びが毎回変わらない**ようにするためで、
        /// **E2E が「2 件目」を指せる**ようにもなる。
        ///
        /// **段階 5-a-1 では決めていなかった**（**1 件を取り出すだけ**だった）。
        ///
        /// **空の `ownerUserId` では、1 件も返さない** —
        /// **所有者の無い登録**（構成ファイル発の種データ）**を、誰かのものにしないため**である。
        /// </remarks>
        public static List<ManageAddSaml2OAuth2DataViewModel> GetByOwner(string ownerUserId)
        {
            List<ManageAddSaml2OAuth2DataViewModel> all
                = new List<ManageAddSaml2OAuth2DataViewModel>();

            if (string.IsNullOrEmpty(ownerUserId))
            {
                return all;
            }

            switch (Config.UserStoreType)
            {
                case EnumUserStoreType.Memory:
                    all.AddRange(Saml2OAuth2DataProvider.Saml2OAuth2Data.Values
                        .Where(m => m != null && m.OwnerUserId == ownerUserId)
                        .OrderBy(m => m.ClientID, StringComparer.Ordinal)
                        .Select(m => Saml2OAuth2DataProvider.Copy(null, m)));

                    break;

                case EnumUserStoreType.SqlServer:
                case EnumUserStoreType.ODPManagedDriver:
                case EnumUserStoreType.PostgreSQL: // DMBMS

                    using (IDbConnection cnn = DataAccess.CreateConnection())
                    {
                        cnn.Open();

                        EnumUserStoreType storeType = Config.UserStoreType;

                        all.AddRange(cnn.Query<ManageAddSaml2OAuth2DataViewModel>(
                            "SELECT " + Saml2OAuth2DataProvider.ColumnList(Saml2OAuth2DataProvider.Columns, storeType)
                            + " FROM " + Saml2OAuth2DataProvider.TableName(storeType)
                            + Saml2OAuth2DataProvider.WhereOwnerUserId(storeType)
                            + Saml2OAuth2DataProvider.OrderByClientID(storeType),
                            new { OwnerUserId = ownerUserId }));
                    }

                    break;
            }

            //  **使う形に戻す**（#297）。
            for (int i = 0; i < all.Count; i++)
            {
                all[i] = Saml2OAuth2DataProvider.Unprotect(all[i]);
            }

            return all;
        }

        /// <summary>所有者の登録のうち 1 件を返す（#307 の段階 5-a）</summary>
        /// <param name="ownerUserId">所有者（`Users.Id`）</param>
        /// <returns>登録（1 件も無ければ null）</returns>
        /// <remarks>
        /// **「その人のクライアント」を 1 つ要る所のため**である
        /// （**自己テストの導線・認可ログ**）。
        /// **`client_id` の昇順で先頭**（#307 の段階 5-a-2 で並びを決めた）。
        ///
        /// **管理画面は、もうこれを使わない** — **一覧を出す**ようになった（段階 5-a-2）。
        /// </remarks>
        public static ManageAddSaml2OAuth2DataViewModel GetFirstByOwner(string ownerUserId)
        {
            List<ManageAddSaml2OAuth2DataViewModel> all = Saml2OAuth2DataProvider.GetByOwner(ownerUserId);

            return (all.Count == 0) ? null : all[0];
        }

        /// <summary>所有者の、その 1 件を返す（#307 の段階 5-a-2）</summary>
        /// <param name="ownerUserId">所有者（`Users.Id`）</param>
        /// <param name="clientID">client_id</param>
        /// <returns>登録（無い・他人のものなら null）</returns>
        /// <remarks>
        /// **管理画面が「どの登録を編集・削除するか」を受け取るため**に在る（段階 5-a-2）。
        ///
        /// **他人の `client_id` を渡されても null を返す** —
        /// **画面の経路で、他人の登録を読み書きさせないため**である
        /// （**動的登録の側は `registration_access_token` で守っている**。RFC 7592 §2）。
        ///
        /// **所有者の無い登録**（構成ファイル発の種データ）**も null になる** —
        /// **空の `ownerUserId` では 1 件も引かない**作りと、同じ理屈である。
        /// </remarks>
        public static ManageAddSaml2OAuth2DataViewModel GetByOwnerAndClientID(
            string ownerUserId, string clientID)
        {
            if (string.IsNullOrEmpty(ownerUserId) || string.IsNullOrEmpty(clientID))
            {
                return null;
            }

            ManageAddSaml2OAuth2DataViewModel model = Saml2OAuth2DataProvider.Get(clientID);

            if (model == null || model.OwnerUserId != ownerUserId)
            {
                return null;
            }

            return model;
        }

        /// <summary>所有者の登録を全件消す（#307 の段階 5-a）</summary>
        /// <param name="ownerUserId">所有者（`Users.Id`）</param>
        /// <remarks>
        /// **`mem` のためだけに在る。**
        /// **DB では外部キー**（`OwnerUserId` → `Users.Id` の `ON DELETE CASCADE`）
        /// **が消す**ので、**呼ぶ必要が無い。**
        /// **`mem` には制約が無い**ので、**消す側が明示的に消す**
        /// （**#151 の段階 2 で、`sub` の対応表に対して同じことをしている**）。
        ///
        /// **空の `ownerUserId` では、1 件も消さない** —
        /// **所有者の無い登録**（構成ファイル発の種データ）**を巻き込まないため**である。
        /// </remarks>
        public static void DeleteByOwner(string ownerUserId)
        {
            if (string.IsNullOrEmpty(ownerUserId))
            {
                return;
            }

            foreach (ManageAddSaml2OAuth2DataViewModel model
                in Saml2OAuth2DataProvider.GetByOwner(ownerUserId))
            {
                Saml2OAuth2DataProvider.Delete(model.ClientID);
            }
        }

        #endregion

        #region Update

        /// <summary>Update</summary>
        /// <param name="clientID">string</param>
        /// <param name="model">ManageAddSaml2OAuth2DataViewModel</param>
        public static void Update(string clientID, ManageAddSaml2OAuth2DataViewModel model)
        {
            //  **秘密は暗号化して保管する**（#297）。
            model = Saml2OAuth2DataProvider.Protect(clientID, model);

            switch (Config.UserStoreType)
            {
                case EnumUserStoreType.Memory:
                    // TryUpdate が使えないので del -> ins にする。
                    ManageAddSaml2OAuth2DataViewModel temp = null;
                    Saml2OAuth2DataProvider.Saml2OAuth2Data.TryRemove(clientID, out temp);
                    Saml2OAuth2DataProvider.Saml2OAuth2Data.TryAdd(clientID, Saml2OAuth2DataProvider.Copy(clientID, model));

                    break;

                case EnumUserStoreType.SqlServer:
                case EnumUserStoreType.ODPManagedDriver:
                case EnumUserStoreType.PostgreSQL: // DMBMS

                    using (IDbConnection cnn = DataAccess.CreateConnection())
                    {
                        cnn.Open();

                        EnumUserStoreType storeType = Config.UserStoreType;

                        cnn.Execute(
                            "UPDATE " + Saml2OAuth2DataProvider.TableName(storeType)
                            + " SET " + Saml2OAuth2DataProvider.SetList(storeType)
                            + Saml2OAuth2DataProvider.WhereClientID(storeType),
                            Saml2OAuth2DataProvider.ToParameters(clientID, model, storeType));
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
                    Saml2OAuth2DataProvider.Saml2OAuth2Data.TryRemove(clientID, out model);

                    break;

                case EnumUserStoreType.SqlServer:
                case EnumUserStoreType.ODPManagedDriver:
                case EnumUserStoreType.PostgreSQL: // DMBMS

                    using (IDbConnection cnn = DataAccess.CreateConnection())
                    {
                        cnn.Open();

                        EnumUserStoreType storeType = Config.UserStoreType;

                        cnn.Execute(
                            "DELETE FROM " + Saml2OAuth2DataProvider.TableName(storeType)
                            + Saml2OAuth2DataProvider.WhereClientID(storeType),
                            new { ClientID = clientID });
                    }

                    break;
            }
        }

        #endregion
    }
}
