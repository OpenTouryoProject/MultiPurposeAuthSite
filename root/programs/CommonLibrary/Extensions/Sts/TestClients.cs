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
//* クラス名        ：TestClients
//* クラス日本語名  ：E2E 専用のクライアント登録（種データ）の表
//*
//* 作成日時        ：－
//* 作成者          ：－
//* 更新履歴        ：－
//*
//*  日時        更新者            内容
//*  ----------  ----------------  -------------------------------------------------
//*  2026/10/03  玄人 幸道         新規（#264）
//*  2026/10/04  玄人 幸道         TestClient_15（test_self_code_manage）を追加（C-10）
//**********************************************************************************

using MultiPurposeAuthSite.ViewModels;

using System.Collections.Generic;

using Newtonsoft.Json;

using Touryo.Infrastructure.Framework.Authentication;
using Touryo.Infrastructure.Public.Security.Jwt;

namespace MultiPurposeAuthSite.Extensions.Sts
{
    /// <summary>E2E 専用のクライアント登録（種データ）の表（#264）</summary>
    /// <remarks>
    /// **E2E は、構成ファイルに無いクライアント登録を要る。**
    /// **以前は `test.ps1 -Launch` が環境変数で差し込んでいた**が、
    /// **net48 版だけ一覧ごと 1 本の環境変数で渡す**ため、
    /// **件数に上限があった**（約 17 件で Windows の環境ブロック 32,767 文字を超え、
    /// IIS Express が起動するのに全要求が 500 になる）。#262 で踏んで #264 で直した。
    ///
    /// **そこで、テスト利用者の登録（`saml2OAuth2Data`）に寄せた。**
    /// user store は 1 件ずつ別の行なので**上限が無い。**
    ///
    /// | | |
    /// |---|---|
    /// | **構成ファイルに残すもの** | 自己テスト画面が名前で選ぶもの（`TestClient`〜`TestClient6`。`HomeController`）、`IdFederation`、サンプル RP |
    /// | **ここで作るもの** | **E2E だけが使うもの**（FAPI 系と、署名 alg を測るもの） |
    ///
    /// **`client_name` は利用者名そのもの**である（`GetClientIdByName` が
    /// `CmnUserStore.FindByName` を引き、`AddSaml2OAuth2Data` 画面も
    /// `model.ClientName = user.UserName` としている）。
    /// **したがって 1 利用者 ＝ 1 クライアント登録**で、**N 件には利用者が N 人要る。**
    ///
    /// **`client_id` と `client_secret` は固定値**である。
    /// **E2E は構成ファイルを直接読んでいて**（`ClientsConfig.FindClientIdByName`）、
    /// **user store は読めない**ため、**この表と E2E の `KnownClients` を同じ値で揃える。**
    ///
    /// **`isResourceOwner` は、どの呼び出し元も分岐に使っていない**ので、
    /// **構成ファイルの登録と同じに振る舞う**（`Helper` の各 `Get*` が `out` で返すだけ）。
    /// </remarks>
    public static class TestClients
    {
        #region Entry

        /// <summary>E2E 専用のクライアント登録 1 件（#264）</summary>
        public class Entry
        {
            /// <summary>クライアント名（＝ 利用者名）</summary>
            public string ClientName { get; set; }

            /// <summary>client_id（固定値。E2E の KnownClients と揃える）</summary>
            public string ClientId { get; set; }

            /// <summary>oauth2_oidc_mode（normal / fapi_1 / fapi2 …）</summary>
            public string ClientMode { get; set; }

            /// <summary>写す元のクライアント名（構成ファイル）</summary>
            public string SourceName { get; set; }

            /// <summary>写した後に差し替える項目（*.config の項目名 → 値）</summary>
            public Dictionary<string, string> Overrides { get; set; }
        }

        #endregion

        #region 表

        /// <summary>E2E 専用のクライアント登録（#264）</summary>
        /// <remarks>
        /// **写す元から公開鍵ごと写す**ので、署名検証を通り、**登録種別の判定まで届く。**
        /// **鍵の実体をここに書かない**のは、構成ファイルと二重に持たないためである。
        ///
        /// **`client_id` は、E2E の `KnownClients` と同じ値にすること。**
        /// 揃っていなければ、テストは「登録されていない」で落ちる。
        /// </remarks>
        public static readonly Entry[] Entries = new Entry[]
        {
            // ---------------------------------------------------------------- FAPI 系
            //   **写す元は TestClient4 / TestClient2。** 自己テスト画面が使う登録には触らない。
            new Entry()
            {
                ClientName = "TestClient4_2", ClientId = "e2e0tc42000000000000000000000000",
                ClientMode = "normal", SourceName = "TestClient4"
            },
            new Entry()
            {
                ClientName = "TestClient4_3", ClientId = "e2e0tc43000000000000000000000000",
                ClientMode = "fapi_1", SourceName = "TestClient4"
            },
            new Entry()
            {
                // **mTLS（FA-6）で使う。** Subject は E2E の KnownClients.MtlsSubjectDn と同じ値にすること。
                ClientName = "TestClient2_2", ClientId = "e2e0tc22000000000000000000000000",
                ClientMode = "fapi2", SourceName = "TestClient2",
                Overrides = new Dictionary<string, string>()
                {
                    { "tls_client_auth_subject_dn", "CN=mpas-e2e-mtls-client" }
                }
            },
            new Entry()
            {
                ClientName = "TestClient2_3", ClientId = "e2e0tc23000000000000000000000000",
                ClientMode = "fapi_1", SourceName = "TestClient2",
                Overrides = new Dictionary<string, string>()
                {
                    { "tls_client_auth_subject_dn", "CN=mpas-e2e-mtls-client" }
                }
            },

            // ---------------------------------------------------------------- 署名アルゴリズム（#129）
            //   **鍵は alg で決まる**（RS* / PS* は同じ RSA 鍵、ES* は曲線ごとに別）。
            //   **ここで登録するのは「このクライアントに発行する alg」**である。
            new Entry()
            {
                // **発行する側（RS512）と受ける側（RS256）を同時に登録している**（#129 の段階 2 / #262）。
                //   向きが違う項目なので干渉しない（`RT-129.3` は authorization code で測る）。
                ClientName = "TestClient_8", ClientId = "e2e0tc08000000000000000000000000",
                ClientMode = "normal", SourceName = "TestClient",
                Overrides = new Dictionary<string, string>()
                {
                    { "id_token_signed_response_alg", JwtConst.RS512 },
                    { "token_endpoint_auth_signing_alg", JwtConst.RS256 }
                }
            },
            new Entry()
            {
                ClientName = "TestClient_9", ClientId = "e2e0tc09000000000000000000000000",
                ClientMode = "normal", SourceName = "TestClient",
                Overrides = new Dictionary<string, string>()
                {
                    { "id_token_signed_response_alg", JwtConst.ES384 }
                }
            },
            new Entry()
            {
                ClientName = "TestClient_10", ClientId = "e2e0tc10000000000000000000000000",
                ClientMode = "normal", SourceName = "TestClient",
                Overrides = new Dictionary<string, string>()
                {
                    { "id_token_signed_response_alg", JwtConst.ES512 }
                }
            },
            new Entry()
            {
                ClientName = "TestClient_11", ClientId = "e2e0tc11000000000000000000000000",
                ClientMode = "normal", SourceName = "TestClient",
                Overrides = new Dictionary<string, string>()
                {
                    { "id_token_signed_response_alg", JwtConst.PS256 }
                }
            },
            new Entry()
            {
                ClientName = "TestClient_12", ClientId = "e2e0tc12000000000000000000000000",
                ClientMode = "normal", SourceName = "TestClient",
                Overrides = new Dictionary<string, string>()
                {
                    { "id_token_signed_response_alg", JwtConst.PS384 }
                }
            },
            new Entry()
            {
                ClientName = "TestClient_13", ClientId = "e2e0tc13000000000000000000000000",
                ClientMode = "normal", SourceName = "TestClient",
                Overrides = new Dictionary<string, string>()
                {
                    { "id_token_signed_response_alg", JwtConst.PS512 }
                }            },

            // ---------------------------------------------------------------- 基本プロファイル
            //   **以前は test.ps1 -Launch が環境変数で差し込んでいた**（#264 でこちらへ移した）。
            new Entry()
            {
                // **記号を含む client_secret**（#237）。
                //   **E2E の KnownClients.SymbolSecret と同じ値にすること。**
                //   「+」は form-urlencoded の復号で空白に変わるので、**符号化したかどうかで値が変わる。**
                ClientName = "TestClient_2", ClientId = "e2e0tc02000000000000000000000000",
                ClientMode = "normal", SourceName = "TestClient",
                Overrides = new Dictionary<string, string>()
                {
                    { "client_secret", "e2e+ab/cd=ef" }
                }
            },
            new Entry()
            {
                // **「:」を含む client_secret**（#237）。
                //   **E2E の KnownClients.ColonSecret と同じ値にすること。**
                //   「:」は Basic の分割位置そのものなので、**符号化しないと資格情報として読めない。**
                ClientName = "TestClient_3", ClientId = "e2e0tc03000000000000000000000000",
                ClientMode = "normal", SourceName = "TestClient",
                Overrides = new Dictionary<string, string>()
                {
                    { "client_secret", "e2e:ab+cd" }
                }
            },
            new Entry()
            {
                // **ログアウト後の戻り先**（#232）。サイトごとに URL が違うので、
                //   定数で登録して `CmnEndpoints.GetRedirectUriFromConstr` に解決させる。
                ClientName = "TestClient_4", ClientId = "e2e0tc04000000000000000000000000",
                ClientMode = "normal", SourceName = "TestClient",
                Overrides = new Dictionary<string, string>()
                {
                    { "post_logout_redirect_uri", "test_self_logout" }
                }
            },
            new Entry()
            {
                // **pairwise の登録**（#140 の段階 2）。sub が PPID（RP ごとに違う値）になる。
                ClientName = "TestClient_5", ClientId = "e2e0tc05000000000000000000000000",
                ClientMode = "normal", SourceName = "TestClient",
                Overrides = new Dictionary<string, string>()
                {
                    { "subject_types", "pairwise" }
                }
            },
            new Entry()
            {
                // **subject_types を書かない**（#151 の段階 4）。**既定が public になった**ことを測る。
                //   **2 件要る**（public は「RP が違っても同じ sub」なので、
                //   2 つの client_id で同じ値になることを見る）。
                //   **client_id を変えるときは、使ったことのない値にすること。**
                //   発行済みの sub は対応表から返るため（段階 2）、**既に使った値では測れない。**
                ClientName = "TestClient_6", ClientId = "e2e0tc06000000000000000000000000",
                ClientMode = "normal", SourceName = "TestClient"
            },
            new Entry()
            {
                ClientName = "TestClient_7", ClientId = "e2e0tc07000000000000000000000000",
                ClientMode = "normal", SourceName = "TestClient"
            },
            new Entry()
            {
                // **管理画面の自己テストの折り返し先を登録したもの**（C-10）。
                //   **記号が解決され、通常の照合で通ること**を測る（`RT-C10.1`）。
                //   以前は `CheckRedirectUri` の分岐が、**登録を確かめずにこの URL を通していた。**
                ClientName = "TestClient_15", ClientId = "e2e0tc15000000000000000000000000",
                ClientMode = "normal", SourceName = "TestClient",
                Overrides = new Dictionary<string, string>()
                {
                    { "redirect_uri_code", Co.Const.TestSelfCodeManage }
                }
            }
        };

        #endregion

        #region CreateSaml2OAuth2Data

        /// <summary>登録（saml2OAuth2Data）の JSON を作る（#264）</summary>
        /// <param name="entry">表の 1 件</param>
        /// <returns>saml2OAuth2Data の JSON（写す元が無ければ空）</returns>
        /// <remarks>
        /// **`AddSaml2OAuth2Data` 画面が保存するものと同じ形**にする
        /// （`ManageAddSaml2OAuth2DataViewModel` を `JsonConvert` する）。
        /// **読む側（`Helper` の各 `Get*`）は、この形で逆変換する**ため、
        /// **画面から登録したのと区別がつかない。**
        ///
        /// **写す元は `Helper` の公開の取得口から読む。**
        /// 構成ファイルの辞書を直接見ないので、**写す項目がここで明示される。**
        /// </remarks>
        public static string CreateSaml2OAuth2Data(Entry entry)
        {
            Helper helper = Helper.GetInstance();

            string sourceId = helper.GetClientIdByName(entry.SourceName);

            if (string.IsNullOrEmpty(sourceId))
            {
                // **写す元が構成ファイルに無い。** 種データを作らない（E2E はその分を Skip する）。
                return "";
            }

            ManageAddSaml2OAuth2DataViewModel model = new ManageAddSaml2OAuth2DataViewModel()
            {
                // **client_name は利用者名**（画面も model.ClientName = user.UserName としている）。
                ClientName = entry.ClientName,

                ClientSecret = helper.GetClientSecret(sourceId),

                RedirectUriCode = helper.GetClientsRedirectUri(
                    sourceId, OAuth2AndOIDCConst.AuthorizationCodeResponseType),
                RedirectUriToken = helper.GetClientsRedirectUri(
                    sourceId, OAuth2AndOIDCConst.ImplicitResponseType),

                // **公開鍵ごと写す**（署名検証を通すため）。
                JwkRsaPublickey = helper.GetJwkRsaPublickey(sourceId),
                JwkECDsaPublickey = helper.GetJwkECDsaPublickey(sourceId),

                TlsClientAuthSubjectDn = helper.GetTlsClientAuthSubjectDn(sourceId),

                // **oauth2_oidc_mode は、写さず表の値を使う**（登録種別を変えるのが目的のため）。
                ClientMode = entry.ClientMode
            };

            if (entry.Overrides != null)
            {
                foreach (KeyValuePair<string, string> kv in entry.Overrides)
                {
                    TestClients.Override(model, kv.Key, kv.Value);
                }
            }

            return JsonConvert.SerializeObject(model);
        }

        #endregion

        #region Override

        /// <summary>*.config の項目名で、登録の 1 項目を差し替える（#264）</summary>
        /// <param name="model">登録</param>
        /// <param name="key">*.config の項目名</param>
        /// <param name="value">値</param>
        /// <remarks>
        /// **表には *.config の項目名で書く**（以前の `test.ps1` の差し込みと同じ綴り）。
        /// **知らない項目名は、黙って捨てずに例外にする**
        /// （綴り間違いが「登録したのに効かない」になると、原因に辿り着けない）。
        /// </remarks>
        private static void Override(
            ManageAddSaml2OAuth2DataViewModel model, string key, string value)
        {
            switch (key)
            {
                case "client_secret":
                    model.ClientSecret = value;
                    break;

                case "redirect_uri_code":
                    model.RedirectUriCode = value;
                    break;

                case "redirect_uri_token":
                    model.RedirectUriToken = value;
                    break;

                case "post_logout_redirect_uri":
                    model.PostLogoutRedirectUri = value;
                    break;

                case "subject_types":
                    model.SubjectTypes = value;
                    break;

                case "tls_client_auth_subject_dn":
                    model.TlsClientAuthSubjectDn = value;
                    break;

                case "id_token_signed_response_alg":
                    model.IdTokenSignedResponseAlg = value;
                    break;

                case "token_endpoint_auth_signing_alg":
                    model.TokenEndpointAuthSigningAlg = value;
                    break;

                case "request_object_signing_alg":
                    model.RequestObjectSigningAlg = value;
                    break;

                default:
                    throw new System.NotSupportedException(
                        "TestClients.Override: 知らない項目名です: " + key);
            }
        }

        #endregion
    }
}
