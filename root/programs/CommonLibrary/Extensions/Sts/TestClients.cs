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
//*  2026/10/04  玄人 幸道         web_originsのTestClient_16を追加（#266）
//*  2026/10/04  玄人 幸道         2000文字を超える登録のTestClient_17を追加（#269）
//*  2026/10/06  玄人 幸道         require_pkceのTestClient_18を追加（#270）
//*  2026/10/06  玄人 幸道         同意を記録しないTestClient_19を追加（#272 の段階 2）
//*  2026/10/07  玄人 幸道         SAML2用のTestClient_21/_22を追加（鍵なし。#275）
//*  2026/10/09  玄人 幸道         TestClient_15 の折り返し先を、記号から実 URL に変えた（C-10）
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
                // **2000 文字を超える登録**（#269）。
                //   **Oracle / PostgreSQL の UnstructuredData が 2000 文字だと保存できない。**
                //   **画面から入れられる範囲で作ってある**（各項目は Const.MaxLengthOfUri = 512 以内）。
                //   **`web_origins` に 24 件**＋**長い redirect_uri を 2 つ**で、
                //   JWK 2 本と合わせて **2000 文字を超える**。
                //   **保存できていれば、先頭のオリジンで CORS が通る**（`RT-269.1`）。
                ClientName = "TestClient_17", ClientId = "e2e0tc17000000000000000000000000",
                ClientMode = "normal", SourceName = "TestClient",
                Overrides = new Dictionary<string, string>()
                {
                    { "client_secret", "" },
                    { "web_origins", "https://o001.example https://o002.example https://o003.example https://o004.example https://o005.example https://o006.example https://o007.example https://o008.example https://o009.example https://o010.example https://o011.example https://o012.example https://o013.example https://o014.example https://o015.example https://o016.example https://o017.example https://o018.example https://o019.example https://o020.example https://o021.example https://o022.example https://o023.example https://o024.example" },
                    { "redirect_uri_saml", "https://long.example/cb?p=xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx" },
                    { "post_logout_redirect_uri", "https://long.example/cb?p=xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx" }
                }
            },
            new Entry()
            {
                // **同意を記録しないクライアント**（#272 の段階 2）。
                //   **「同意の記録が無い」状態を測るためだけに在る。**
                //   **このクライアントに対しては、どのテストも「許可」を押さない。**
                //   **押すと記録が残り、DB ストアでは 2 回目の実行から
                //   `RT-272.3` / `RT-272.4` が測れなくなる。**
                ClientName = "TestClient_19", ClientId = "e2e0tc19000000000000000000000000",
                ClientMode = "normal", SourceName = "TestClient"
            },
            new Entry()
            {
                // **同意の取り消しを測るためのクライアント**（#272 の段階 2）。
                //   **`RT-272.7` が「許可 → 取り消し → prompt=none」を回す。**
                //   **専用にしてあるのは、取り消しが他のテストに影響しないようにするため。**
                ClientName = "TestClient_20", ClientId = "e2e0tc20000000000000000000000000",
                ClientMode = "normal", SourceName = "TestClient"
            },
            new Entry()
            {
                // **登録で require_pkce を立てたクライアント**（#270）。
                //   **構成ファイル側の TestClient6 と対をなす。**
                //   `require_pkce` は**唯一の bool の登録項目**で、
                //   **列に切り出した後は方言で形が違う**
                //   （SQL Server : bit / PostgreSQL : boolean / Oracle : NUMBER(3) の -1）。
                //   **これが落ちると「締めたつもりが締まっていない」になる**ので、
                //   **登録経由で測る**（`RT-270.1`）。
                ClientName = "TestClient_18", ClientId = "e2e0tc18000000000000000000000000",
                ClientMode = "normal", SourceName = "TestClient",
                Overrides = new Dictionary<string, string>()
                {
                    { "require_pkce", "true" }
                }
            },
            new Entry()
            {
                // **CORS の許可オリジンを登録で決めたクライアント**（#266）。
                //   **`client_secret` を空にして public にする**（CORS は public だけに効く）。
                //   **`web_origins` が `redirect_uri_code` に勝つ**ことを測るため、
                //   **`redirect_uri_code` には別のオリジン**を入れてある（`RT-266.1`）。
                //   **画面登録（user store）の経路そのもの**でもある（種データは user store に入る）。
                ClientName = "TestClient_16", ClientId = "e2e0tc16000000000000000000000000",
                ClientMode = "normal", SourceName = "TestClient",
                Overrides = new Dictionary<string, string>()
                {
                    { "client_secret", "" },
                    { "redirect_uri_code", "https://notallowed.example/cb" },
                    { "web_origins", "https://spa.example" }
                }
            },
            new Entry()
            {
                // **「このクライアントにだけ登録されている折り返し先」**（C-10）。
                //   **他のクライアントが、この URI を宛先にできないこと**を測る（`RT-C10.1`）。
                //   以前は `CheckRedirectUri` に、**登録を確かめずに通す URL** が在った
                //   （管理画面の「トークンを取る」の折り返し先）。
                //   **その画面は廃止されたが、「例外は無い」ことは測り続ける。**
                ClientName = "TestClient_15", ClientId = "e2e0tc15000000000000000000000000",
                ClientMode = "normal", SourceName = "TestClient",
                Overrides = new Dictionary<string, string>()
                {
                    { "redirect_uri_code", "https://rtc10.example/cb" }
                }
            },
            new Entry()
            {
                // **SAML2 を測るためのクライアント**（#275）。
                //   **写す元を TestClient3 にしているのは、
                //   そこに `jwk_rsa_publickey` が無いからである。**
                //   **鍵が無いクライアントの AuthnRequest は、署名が無くても通る**
                //   （`SamlProviders/CmnEndpoints.VerifySamlRequest` の「鍵がない場合は、通す」）。
                //   **そのため、要求を自前で組み立てて測れる**
                //   （NameIDPolicy の差い、ACS URL の不一致など）。
                //
                //   **ACS URL は存在しない URL でよい。** 応答は辣らず、
                //   **返ってきた場所と SAMLResponse を読むだけ**である。
                //   **client_id の接頭辞を `sa` にしている**（#275）。
                //     **`tcNN` は `TestClient_NN` という意味ではない。**
                //     `TestClient2_2` が `e2e0tc22`、`TestClient2_3` が `e2e0tc23`、
                //     `TestClient4_2` が `e2e0tc42`、`TestClient4_3` が `e2e0tc43` を使っている。
                //     **`e2e0tc22` を取ろうとして衝突した**（先に在る方が登録され、
                //     こちらは「登録されていない」ことになり、応答が返らなかった）。
                ClientName = "TestClient_21", ClientId = "e2e0sa21000000000000000000000000",
                ClientMode = "normal", SourceName = "TestClient3",
                Overrides = new Dictionary<string, string>()
                {
                    { "redirect_uri_saml", "https://saml.e2e.example/acs" }
                }
            },
            new Entry()
            {
                // **PPID が RP ごとに違うことを測るための 2 つ目**（#275）。
                //   `NameIDFormat=persistent` は `GeneratePPIDByUserID(iss, user.Id)` なので、
                //   **iss が違えば値が違う**ことを確かめる。
                ClientName = "TestClient_22", ClientId = "e2e0sa22000000000000000000000000",
                ClientMode = "normal", SourceName = "TestClient3",
                Overrides = new Dictionary<string, string>()
                {
                    { "redirect_uri_saml", "https://saml.e2e.example/acs2" }
                }
            }
        };

        #endregion

        #region CreateSaml2OAuth2Data

        /// <summary>登録（saml2OAuth2Data）を作る（#264）</summary>
        /// <param name="entry">表の 1 件</param>
        /// <returns>クライアント登録（写す元が無ければ null）</returns>
        /// <remarks>
        /// **`AddSaml2OAuth2Data` 画面が保存するものと同じ形**にする
        /// （同じ `ManageAddSaml2OAuth2DataViewModel` を `DataProvider` に渡す。#270）。
        /// **読む側（`Helper` の各 `Get*`）も同じ型で受け取る**ため、
        /// **画面から登録したのと区別がつかない。**
        ///
        /// **写す元は `Helper` の公開の取得口から読む。**
        /// 構成ファイルの辞書を直接見ないので、**写す項目がここで明示される。**
        /// </remarks>
        public static ManageAddSaml2OAuth2DataViewModel CreateSaml2OAuth2Data(Entry entry)
        {
            Helper helper = Helper.GetInstance();

            string sourceId = helper.GetClientIdByName(entry.SourceName);

            if (string.IsNullOrEmpty(sourceId))
            {
                // **写す元が構成ファイルに無い。** 種データを作らない（E2E はその分を Skip する）。
                return null;
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

            return model;
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

                case "redirect_uri_saml":
                    model.RedirectUriSaml = value;
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

                case "web_origins":
                    model.WebOrigins = value;
                    break;

                case "require_pkce":
                    // **ここだけ bool**（#270）。
                    //   **綾り違いを黙って false にしない**ため、`Parse` で落とす。
                    model.RequirePkce = bool.Parse(value);
                    break;

                default:
                    throw new System.NotSupportedException(
                        "TestClients.Override: 知らない項目名です: " + key);
            }
        }

        #endregion
    }
}
