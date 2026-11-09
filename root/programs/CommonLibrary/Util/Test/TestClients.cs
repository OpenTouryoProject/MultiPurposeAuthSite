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
//*  2026/10/19  玄人 幸道         token_endpoint_auth_method を写し、TestClient_24 を追加（#307 の段階 3）
//*  2026/10/21  玄人 幸道         Back-Channel Logout の TestClient_26 / _27 を追加（#310 の段階 2）
//*  2026/10/25  玄人 幸道         scope に auth を登録した TestClient_29 を追加（#294）
//*  2026/10/29  玄人 幸道         private_key_jwt の fapi_ciba の TestClient4_4 を追加（#294）
//*  2026/10/29  玄人 幸道         TestClient_30 〜 _34（C-40・N1・S3・grant_types の絞り）を追加（#294）
//*  2026/10/31  玄人 幸道         「:」だけを含む秘密の TestClient_35 を追加（RT-237.3。OpenTouryo#645 への備え。#294）
//*  2026/10/31  玄人 幸道         Extensions/Sts から Util/Test へ移した（配置の見直し。#294）
//*  2026/11/03  玄人 幸道         E2E 専用のクライアントの登録（RegisterInStore）を AccountController から移した（#294）
//*  2026/11/04  玄人 幸道         クライアント名を改めた（TestClient1〜4・6。TestClient5 は種データの TestClient_36 へ移した）
//*  2026/11/06  玄人 幸道         Open棟梁 の OAuth2AndOIDCConst に在る名前は、そちらを使うようにした（OpenTouryo#663。#337）
//*  2026/11/08  玄人 幸道         プロファイルを強制する登録の項目（4 つ）を差し替えられるようにした（#346 の段階 1）
//*  2026/11/09  玄人 幸道         プロファイルを強制する登録の TestClient_37〜40 と、device × private_key_jwt の TestClient_41 を追加（#346 の段階 2）
//*  2026/11/09  玄人 幸道         normal で tls_client_auth の TestClient_42、証明書を必須にした device の TestClient_43 を追加（#346）
//**********************************************************************************

using System;
using MultiPurposeAuthSite.Co;
using MultiPurposeAuthSite.ViewModels;

using System.Collections.Generic;

using Newtonsoft.Json;

using Touryo.Infrastructure.Framework.Authentication;
using Touryo.Infrastructure.Public.Security.Jwt;
using MultiPurposeAuthSite.Extensions.Sts;
using MultiPurposeAuthSite.Util.Sts;

namespace MultiPurposeAuthSite.Util.Test
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
    /// | **構成ファイルに残すもの** | 自己テスト画面が選ぶもの（`TestClient` は名前で、`FAPI1_Client`〜`RequirePKCE_Client` は `client_mode` で。`HomeController`）、`IdFederation`、サンプル RP |
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

            /// <summary>client_mode（normal / fapi_1 / fapi2 …）</summary>
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
            //   **写す元は FAPI_CIBA_Client / FAPI2_Client。** 自己テスト画面が使う登録には触らない。
            new Entry()
            {
                ClientName = "TestClient4_2", ClientId = "e2e0tc42000000000000000000000000",
                ClientMode = "normal", SourceName = "FAPI_CIBA_Client"
            },
            new Entry()
            {
                ClientName = "TestClient4_3", ClientId = "e2e0tc43000000000000000000000000",
                ClientMode = "fapi_1", SourceName = "FAPI_CIBA_Client"
            },
            new Entry()
            {
                // **`private_key_jwt` で認証する fapi_ciba のクライアント**（#294）。
                //   **CIBA の `/token` で `client_assertion` を受けることを測る**（`RT-294.43`）。
                //   **`FAPI_CIBA_Client` は秘密で認証する**ので、**鍵で認証する分はこちらで測る**
                //   （**登録された方法でなければ通さない**。#307 の段階 3）。
                //   **写し元は `FAPI_CIBA_Client`** なので、**ECDSA の公開鍵を持つ**（アサーションは ES256 で作る）。
                ClientName = "TestClient4_4", ClientId = "e2e0tc44000000000000000000000000",
                ClientMode = "fapi_ciba", SourceName = "FAPI_CIBA_Client",
                Overrides = new Dictionary<string, string>()
                {
                    { OAuth2AndOIDCConst.token_endpoint_auth_method, "private_key_jwt" }
                }
            },
            new Entry()
            {
                // **`private_key_jwt` で認証する normal のクライアント**（#307 の段階 3）。
                //
                //   **`TestClient` では測れなくなった。** **段階 3 で、登録された
                //   `token_endpoint_auth_method` を認証で効かせるようにしたため**、
                //   **1 つのクライアントが「秘密でも鍵でも通る」ことはできない。**
                //   **`TestClient` は秘密で認証する**（ほぼ全てのテストがそう使う）ので、
                //   **鍵で認証する分は、こちらで測る**（`RT-239.1` 〜 `.4` / `RT-129.1`）。
                //
                //   **写し元は `TestClient`** なので、**RSA と EC の公開鍵を両方持つ**
                //   （`RT-129.1` が ES256 を測れる）。**alg は絞らない。**
                ClientName = "TestClient_24", ClientId = "e2e0tc24000000000000000000000000",
                ClientMode = "normal", SourceName = "TestClient",
                Overrides = new Dictionary<string, string>()
                {
                    { OAuth2AndOIDCConst.token_endpoint_auth_method, "private_key_jwt" }
                }
            },
            new Entry()
            {
                // **mTLS（FA-6）で使う。** Subject は E2E の KnownClients.MtlsSubjectDn と同じ値にすること。
                //   **方法も明示する**（#307 の段階 3）。**DN を登録しただけでは通らない。**
                ClientName = "TestClient2_2", ClientId = "e2e0tc22000000000000000000000000",
                ClientMode = "fapi2", SourceName = "FAPI2_Client",
                Overrides = new Dictionary<string, string>()
                {
                    { OAuth2AndOIDCConst.tls_client_auth_subject_dn, "CN=mpas-e2e-mtls-client" },
                    { OAuth2AndOIDCConst.token_endpoint_auth_method, "tls_client_auth" }
                }
            },
            new Entry()
            {
                ClientName = "TestClient2_3", ClientId = "e2e0tc23000000000000000000000000",
                ClientMode = "fapi_1", SourceName = "FAPI2_Client",
                Overrides = new Dictionary<string, string>()
                {
                    { OAuth2AndOIDCConst.tls_client_auth_subject_dn, "CN=mpas-e2e-mtls-client" },
                    { OAuth2AndOIDCConst.token_endpoint_auth_method, "tls_client_auth" }
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
                    { Const.ClientIdTokenSignedResponseAlg, JwtConst.RS512 },
                    { Const.ClientTokenEndpointAuthSigningAlg, JwtConst.RS256 }
                }
            },
            new Entry()
            {
                // **受ける alg を絞った、`private_key_jwt` のクライアント**（#307 の段階 3）。
                //
                //   **`RT-262.1` は、ここで測る。** **`TestClient_8` とは分けた** —
                //   **`RT-129.3` が `TestClient_8` を `client_secret` で使う**ので、
                //   **段階 3 の「1 クライアントは 1 方法」と両立しない。**
                //
                //   **以前は 1 件に相乗りしていた**（**net48 が一覧ごと 1 本の環境変数で受け、
                //   件数に上限があったため**）。**#264 で種データをサーバ側に寄せた**ので、
                //   **1 件ずつ別の行になり、上限は無い。**
                ClientName = "TestClient_25", ClientId = "e2e0tc25000000000000000000000000",
                ClientMode = "normal", SourceName = "TestClient",
                Overrides = new Dictionary<string, string>()
                {
                    { Const.ClientTokenEndpointAuthSigningAlg, JwtConst.RS256 },
                    { OAuth2AndOIDCConst.token_endpoint_auth_method, "private_key_jwt" }
                }
            },
            new Entry()
            {
                ClientName = "TestClient_9", ClientId = "e2e0tc09000000000000000000000000",
                ClientMode = "normal", SourceName = "TestClient",
                Overrides = new Dictionary<string, string>()
                {
                    { Const.ClientIdTokenSignedResponseAlg, JwtConst.ES384 }
                }
            },
            new Entry()
            {
                ClientName = "TestClient_10", ClientId = "e2e0tc10000000000000000000000000",
                ClientMode = "normal", SourceName = "TestClient",
                Overrides = new Dictionary<string, string>()
                {
                    { Const.ClientIdTokenSignedResponseAlg, JwtConst.ES512 }
                }
            },
            new Entry()
            {
                ClientName = "TestClient_11", ClientId = "e2e0tc11000000000000000000000000",
                ClientMode = "normal", SourceName = "TestClient",
                Overrides = new Dictionary<string, string>()
                {
                    { Const.ClientIdTokenSignedResponseAlg, JwtConst.PS256 }
                }
            },
            new Entry()
            {
                ClientName = "TestClient_12", ClientId = "e2e0tc12000000000000000000000000",
                ClientMode = "normal", SourceName = "TestClient",
                Overrides = new Dictionary<string, string>()
                {
                    { Const.ClientIdTokenSignedResponseAlg, JwtConst.PS384 }
                }
            },
            new Entry()
            {
                ClientName = "TestClient_13", ClientId = "e2e0tc13000000000000000000000000",
                ClientMode = "normal", SourceName = "TestClient",
                Overrides = new Dictionary<string, string>()
                {
                    { Const.ClientIdTokenSignedResponseAlg, JwtConst.PS512 }
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
                    { OAuth2AndOIDCConst.client_secret, "e2e+ab/cd=ef" }
                }
            },
            new Entry()
            {
                // **「:」を含む client_secret**（#237）。
                //   **E2E の KnownClients.ColonSecret と同じ値にすること。**
                //   **「+」も含む**ので、符号化しないと**復号前の値での照合**で通る（RT-237.4。4.0 でやめる。OpenTouryo#645）。
                ClientName = "TestClient_3", ClientId = "e2e0tc03000000000000000000000000",
                ClientMode = "normal", SourceName = "TestClient",
                Overrides = new Dictionary<string, string>()
                {
                    { OAuth2AndOIDCConst.client_secret, "e2e:ab+cd" }
                }
            },
            new Entry()
            {
                // **「:」だけを含む client_secret**（RT-237.3。#294）。
                //   **E2E の KnownClients.ColonOnlySecret と同じ値にすること。**
                //   **英数字と「:」だけ**なので、復号前の値での照合に頼らず「最初の「:」で分ける」だけを測れる。
                ClientName = "TestClient_35", ClientId = "e2e0tc35000000000000000000000000",
                ClientMode = "normal", SourceName = "TestClient",
                Overrides = new Dictionary<string, string>()
                {
                    { OAuth2AndOIDCConst.client_secret, "e2e:abcd" }
                }
            },
            new Entry()
            {
                // **登録の scope で、要求してよいスコープを制限したクライアント**（#198。`RT-198.3` / `.4`、`EX-2.7`）。
                //   **以前は雛形の TestClient5** だった（E2E だけが使うので、種データに移した）。
                //   **scope は E2E の `ScopeTests.RestrictedScope` と同じ値にすること。**
                //   **折り返し先は、どこの口でもない URI**（`RT-198.4` は応答の Location から code を取るだけ）。
                ClientName = "TestClient_36", ClientId = "e2e0tc36000000000000000000000000",
                ClientMode = "normal", SourceName = "TestClient",
                Overrides = new Dictionary<string, string>()
                {
                    { Const.ClientRedirectUriCode, "http://localhost:12346/" },
                    { OAuth2AndOIDCConst.scope, "openid profile email" }
                }
            },
            new Entry()
            {
                // **PAR を必須にした登録**（require_pushed_authorization_requests。#346。`RT-346.2`）。
                ClientName = "TestClient_37", ClientId = "e2e0tc37000000000000000000000000",
                ClientMode = "normal", SourceName = "TestClient",
                Overrides = new Dictionary<string, string>()
                {
                    { Const.ClientRequirePushedAuthorizationRequests, "true" }
                }
            },
            new Entry()
            {
                // **署名付きの Request Object を必須にした登録**（require_signed_request_object。#346。`RT-346.3`）。
                //   **鍵は写す元（TestClient）と同じ**なので、E2E が署名できる。
                ClientName = "TestClient_38", ClientId = "e2e0tc38000000000000000000000000",
                ClientMode = "normal", SourceName = "TestClient",
                Overrides = new Dictionary<string, string>()
                {
                    { Const.ClientRequireSignedRequestObject, "true" }
                }
            },
            new Entry()
            {
                // **トークン要求に DPoP を必須にした登録**（dpop_bound_access_tokens。#346。`RT-346.4`）。
                ClientName = "TestClient_39", ClientId = "e2e0tc39000000000000000000000000",
                ClientMode = "normal", SourceName = "TestClient",
                Overrides = new Dictionary<string, string>()
                {
                    { Const.ClientDPoPBoundAccessTokens, "true" }
                }
            },
            new Entry()
            {
                // **トークン要求にクライアント証明書を必須にした登録**（tls_client_certificate_bound_access_tokens。#346。`RT-346.5`）。
                //   **認証は秘密のまま**（証明書で認証しない登録でも、提示された証明書で縛ることを測る）。
                ClientName = "TestClient_40", ClientId = "e2e0tc40000000000000000000000000",
                ClientMode = "normal", SourceName = "TestClient",
                Overrides = new Dictionary<string, string>()
                {
                    { Const.ClientTlsClientCertificateBoundAccessTokens, "true" }
                }
            },
            new Entry()
            {
                // **device の登録で、private_key_jwt を明示したもの**（#346。`FA-3.2`）。
                //   **認可コード × private_key_jwt の行から device を外した**ことを測る。**鍵は写す元と同じ。**
                ClientName = "TestClient_41", ClientId = "e2e0tc41000000000000000000000000",
                ClientMode = "device", SourceName = "TestClient",
                Overrides = new Dictionary<string, string>()
                {
                    { OAuth2AndOIDCConst.token_endpoint_auth_method, "private_key_jwt" }
                }
            },
            new Entry()
            {
                // **normal の登録で、tls_client_auth を明示したもの**（#346。`RT-346.7`）。
                //   **client_credentials のトークンが、認証に使った証明書に縛られる**ことを測る
                //   （**以前は縛られなかった**。CreateFromClaims が証明書を受けていなかった）。
                //   Subject は E2E の KnownClients.MtlsSubjectDn と同じ値にすること。
                ClientName = "TestClient_42", ClientId = "e2e0tc42200000000000000000000000",
                ClientMode = "normal", SourceName = "TestClient",
                Overrides = new Dictionary<string, string>()
                {
                    { OAuth2AndOIDCConst.tls_client_auth_subject_dn, "CN=mpas-e2e-mtls-client" },
                    { OAuth2AndOIDCConst.token_endpoint_auth_method, "tls_client_auth" }
                }
            },
            new Entry()
            {
                // **証明書を必須にした device の登録**（tls_client_certificate_bound_access_tokens。#346。`RT-346.8`）。
                //   **device_code のトークンも、提示された証明書に縛られる**ことを測る（**以前は、device だけ縛っていなかった**）。
                //   **認証は秘密**（写す元の TestClient のまま）。
                ClientName = "TestClient_43", ClientId = "e2e0tc43300000000000000000000000",
                ClientMode = "device", SourceName = "TestClient",
                Overrides = new Dictionary<string, string>()
                {
                    { Const.ClientTlsClientCertificateBoundAccessTokens, "true" }
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
                    { OAuth2AndOIDCConst.post_logout_redirect_uri, Const.TestSelfLogout }
                }
            },
            new Entry()
            {
                // **Back-Channel Logout の受け先を登録した**（#310 の段階 2）。
                //   **サイトごとに URL が違う**ので、定数で登録して
                //   `CmnEndpoints.GetRedirectUriFromConstr` に解決させる
                //   （**受け口はこのサイト自身**。`IsLockedDownTestEndpoints` で閉じる）。
                //   **`post_logout_redirect_uri` も登録してある** —
                //   **RP からのログアウトで、戻り先と通知の両方を 1 回で測れる**ようにするため。
                ClientName = "TestClient_26", ClientId = "e2e0tc26000000000000000000000000",
                ClientMode = "normal", SourceName = "TestClient",
                Overrides = new Dictionary<string, string>()
                {
                    { Const.ClientBackChannelLogoutUri, Const.TestSelfBackChannelLogout },
                    { OAuth2AndOIDCConst.post_logout_redirect_uri, Const.TestSelfLogout }
                }
            },
            new Entry()
            {
                // **Front-Channel Logout の受け先を登録した**（#310 の段階 3）。
                //   **Back-Channel の TestClient_26 とは別にしてある** —
                //   **あちらでログアウトすると、応答が `iframe` の画面になり**、
                //   **段階 2 の測り（302 を見ている）が変わってしまう。**
                //   **`post_logout_redirect_uri` も登録**（**画面の後に戻る先**を測るため）。
                ClientName = "TestClient_28", ClientId = "e2e0tc28000000000000000000000000",
                ClientMode = "normal", SourceName = "TestClient",
                Overrides = new Dictionary<string, string>()
                {
                    { Const.ClientFrontChannelLogoutUri, Const.TestSelfFrontChannelLogout },
                    { OAuth2AndOIDCConst.post_logout_redirect_uri, Const.TestSelfLogout }
                }
            },
            new Entry()
            {
                // **受け口は登録してあるが、同意されないクライアント**（#310 の段階 2）。
                //   **「トークンを発行していない相手には伝えない」ことを測るためだけに在る。**
                //   **このクライアントに対しては、どのテストも「許可」を押さない**
                //   （**押すと同意が記録され、DB ストアでは 2 回目の実行から
                //   `RT-310.6` が測れなくなる**。`TestClient_19` と同じ事情）。
                ClientName = "TestClient_27", ClientId = "e2e0tc27000000000000000000000000",
                ClientMode = "normal", SourceName = "TestClient",
                Overrides = new Dictionary<string, string>()
                {
                    { Const.ClientBackChannelLogoutUri, Const.TestSelfBackChannelLogout }
                }
            },
            new Entry()
            {
                // **pairwise の登録**（#140 の段階 2）。sub が PPID（RP ごとに違う値）になる。
                ClientName = "TestClient_5", ClientId = "e2e0tc05000000000000000000000000",
                ClientMode = "normal", SourceName = "TestClient",
                Overrides = new Dictionary<string, string>()
                {
                    { Const.ClientSubjectTypes, "pairwise" }
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
                    { OAuth2AndOIDCConst.client_secret, "" },
                    { Const.ClientWebOrigins, "https://o001.example https://o002.example https://o003.example https://o004.example https://o005.example https://o006.example https://o007.example https://o008.example https://o009.example https://o010.example https://o011.example https://o012.example https://o013.example https://o014.example https://o015.example https://o016.example https://o017.example https://o018.example https://o019.example https://o020.example https://o021.example https://o022.example https://o023.example https://o024.example" },
                    { Const.ClientRedirectUriSaml, "https://long.example/cb?p=xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx" },
                    { OAuth2AndOIDCConst.post_logout_redirect_uri, "https://long.example/cb?p=xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx" }
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
                // **登録の scope に `auth` を明記したクライアント**（#294）。
                //   **`auth` で同意画面を飛ばせるのは、登録に明記したクライアントだけ**である。
                //   **明記していない側は `TestClient_19` で測る**（`RT-294.1`）。
                ClientName = "TestClient_29", ClientId = "e2e0tc29000000000000000000000000",
                ClientMode = "normal", SourceName = "TestClient",
                Overrides = new Dictionary<string, string>()
                {
                    { OAuth2AndOIDCConst.scope, OAuth2AndOIDCConst.Scope_Openid + " " + OAuth2AndOIDCConst.Scope_Auth }
                }
            },
            new Entry()
            {
                // **認証の方法を `client_secret_basic` と明示したクライアント**（C-40。#294）。
                //   **明示すると、PKCE だけでは認可コードを引き換えられない**（`RT-294.52`）。
                ClientName = "TestClient_30", ClientId = "e2e0tc30000000000000000000000000",
                ClientMode = "normal", SourceName = "TestClient",
                Overrides = new Dictionary<string, string>()
                {
                    { OAuth2AndOIDCConst.token_endpoint_auth_method, "client_secret_basic" }
                }
            },
            new Entry()
            {
                // **`token_endpoint_auth_method` を `none`（パブリック）にしたクライアント**（C-40。#294）。
                //   **PKCE だけで引き換えられ、秘密では認証できない**（`RT-294.52`）。
                ClientName = "TestClient_31", ClientId = "e2e0tc31000000000000000000000000",
                ClientMode = "normal", SourceName = "TestClient",
                Overrides = new Dictionary<string, string>()
                {
                    { OAuth2AndOIDCConst.token_endpoint_auth_method, "none" }
                }
            },
            new Entry()
            {
                // **`private_key_jwt` で認証する fapi2 のクライアント**（N1。#294）。
                //   **PKCE と client_assertion を併用して、認可コードを引き換える**（`RT-294.51`。FAPI 2.0）。
                //   **写し元は `FAPI2_Client`**（RSA の公開鍵を持つ）。
                ClientName = "TestClient_32", ClientId = "e2e0tc32000000000000000000000000",
                ClientMode = "fapi2", SourceName = "FAPI2_Client",
                Overrides = new Dictionary<string, string>()
                {
                    { OAuth2AndOIDCConst.token_endpoint_auth_method, "private_key_jwt" }
                }
            },
            new Entry()
            {
                // **client_credentials の sub を測るクライアント**（S3。#294）。
                //   **テストが同じ名前の利用者を作り、トークンがその利用者に結び付かないことを見る**（`RT-294.50`）。
                ClientName = "TestClient_33", ClientId = "e2e0tc33000000000000000000000000",
                ClientMode = "normal", SourceName = "TestClient"
            },
            new Entry()
            {
                // **grant_types に implicit を登録していないクライアント**（#294）。
                //   **Hybrid の要求を、認可エンドポイントで、同意の前に断る**ことを測る（`RT-294.55`）。
                ClientName = "TestClient_34", ClientId = "e2e0tc34000000000000000000000000",
                ClientMode = "normal", SourceName = "TestClient",
                Overrides = new Dictionary<string, string>()
                {
                    { Const.ClientGrantTypes, OAuth2AndOIDCConst.ClientCredentialsGrantType }
                }
            },
            new Entry()
            {
                // **登録で require_pkce を立てたクライアント**（#270）。
                //   **構成ファイル側の RequirePKCE_Client と対をなす。**
                //   `require_pkce` は**bool の登録項目**で（#346 で 4 つ増えた）、
                //   **列に切り出した後は方言で形が違う**
                //   （SQL Server : bit / PostgreSQL : boolean / Oracle : NUMBER(3) の -1）。
                //   **これが落ちると「締めたつもりが締まっていない」になる**ので、
                //   **登録経由で測る**（`RT-270.1`）。
                ClientName = "TestClient_18", ClientId = "e2e0tc18000000000000000000000000",
                ClientMode = "normal", SourceName = "TestClient",
                Overrides = new Dictionary<string, string>()
                {
                    { Const.ClientRequirePkce, "true" }
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
                    { OAuth2AndOIDCConst.client_secret, "" },
                    { Const.ClientRedirectUriCode, "https://notallowed.example/cb" },
                    { Const.ClientWebOrigins, "https://spa.example" }
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
                    { Const.ClientRedirectUriCode, "https://rtc10.example/cb" }
                }
            },
            new Entry()
            {
                // **SAML2 を測るためのクライアント**（#275）。
                //   **写す元を Device_Client にしているのは、
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
                ClientMode = "normal", SourceName = "Device_Client",
                Overrides = new Dictionary<string, string>()
                {
                    { Const.ClientRedirectUriSaml, "https://saml.e2e.example/acs" }
                }
            },
            new Entry()
            {
                // **PPID が RP ごとに違うことを測るための 2 つ目**（#275）。
                //   `NameIDFormat=persistent` は `GeneratePPIDByUserID(iss, user.Id)` なので、
                //   **iss が違えば値が違う**ことを確かめる。
                ClientName = "TestClient_22", ClientId = "e2e0sa22000000000000000000000000",
                ClientMode = "normal", SourceName = "Device_Client",
                Overrides = new Dictionary<string, string>()
                {
                    { Const.ClientRedirectUriSaml, "https://saml.e2e.example/acs2" }
                }
            }
        };

        #endregion

        #region CreateSaml2OAuth2Data

        /// <summary>このプロセスが E2E 専用のクライアントの登録を済ませたか（#294）</summary>
        /// <remarks>
        /// **メモリと DB の両方で使う。** 登録は「無ければ作る」なので、
        /// このフラグは**ストアに聞きに行くのを、プロセスごとに 1 回にする**ためにある。
        /// </remarks>
        private static volatile bool HasRegisteredInStore = false;

        /// <summary>
        /// E2E 専用のクライアントを登録する（呼ぶ側が SeedsTestData を確かめる）。
        /// </summary>
        /// <remarks>
        /// **起動ごとに 1 回だけ通す**（HasRegisteredInStore。#294）。
        /// **IsTestUsersInitialized の判定には入れない。** 接尾辞が無く 2 つのサイトで共有し、
        /// **TestClients に後から足したクライアントを、既存の DB に入れる役目もある**ため。
        /// </remarks>
        public static void RegisterInStore()
        {
            if (TestClients.HasRegisteredInStore)
            {
                // 起動ごとの 1 回が済んでいる。
                return;
            }

            #region E2E 専用のクライアント登録

            // E2E だけが使うクライアント登録を、構成ファイルの既存のクライアントを写して作り、user store に無ければ入れる。
            //   **user store に寄せてある**ので、**件数に上限が無い**
            //   （環境変数で差し込むと、net48 版は一覧ごと 1 本になり、件数に上限が出る。#262 / #264）。
            //   **接尾辞は付けない。** E2E が client_name と固定の client_id で引くため
            //   （TestClients の表と、E2E の KnownClients を同じ値で揃える）。
            foreach (TestClients.Entry entry in TestClients.Entries)
            {
                // 写す元（構成ファイル）から、登録を作る。
                ManageAddSaml2OAuth2DataViewModel saml2OAuth2Data = TestClients.CreateSaml2OAuth2Data(entry);

                if (saml2OAuth2Data == null)
                {
                    // **写す元が構成ファイルに無い。** その分は E2E が Skip する。
                    continue;
                }

                // **所有者（OwnerUserId）は持たせない**（#307）。
                //   構成ファイルの owner 無しのクライアントと同じく、**配備全体のもの**である。
                //   **所有者の無い登録を作るのは、ここだけ**（管理画面と DCR は、必ず所有者を書く）。

                // **この client_id の登録が無ければ入れる**（在れば触らない）。
                //   **DB ストアでは 2 つのサイトが同じ user store を共有する**（#260）ので、
                //   **書き込みを 1 回に閉じる。**
                if (MultiPurposeAuthSite.Extensions.Sts.Saml2OAuth2DataProvider.Get(entry.ClientId) == null)
                {
                    try
                    {
                        MultiPurposeAuthSite.Extensions.Sts.Saml2OAuth2DataProvider.Create(entry.ClientId, saml2OAuth2Data);
                    }
                    catch (Exception) when (MultiPurposeAuthSite.Extensions.Sts.Saml2OAuth2DataProvider.Get(entry.ClientId) != null)
                    {
                        //  **もう一方のサイトが、確かめてから入れるまでの間に入れた**（#325）。
                        //    **在れば目的は果たしているので、サインイン画面を落とさない。**
                    }
                }
            }

            #endregion

            // **最後まで通ってから立てる**（途中で例外なら、次の呼び出しでやり直す）。
            TestClients.HasRegisteredInStore = true;
        }

        /// <summary>登録（saml2OAuth2Data）を作る（#264）</summary>
        /// <param name="entry">表の 1 件</param>
        /// <returns>クライアント登録（写す元が無ければ null）</returns>
        /// <remarks>
        /// **`AddSaml2OAuth2Data` 画面が保存するものと同じ形**にする
        /// （同じ `ManageAddSaml2OAuth2DataViewModel` を `Saml2OAuth2DataProvider` に渡す。#270）。
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

                // **クライアント認証の方法ごと写す**（#307 の段階 3）。
                //   **写さないと、写し先が「明示なし ＝ 秘密ベース」に落ちる** —
                //   **写し元が `private_key_jwt` でも、鍵では通らなくなる。**
                TokenEndpointAuthMethod = helper.GetTokenEndpointAuthMethod(sourceId),

                // **client_mode は、写さず表の値を使う**（登録種別を変えるのが目的のため）。
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
                case OAuth2AndOIDCConst.client_secret:
                    model.ClientSecret = value;
                    break;

                case Const.ClientRedirectUriSaml:
                    model.RedirectUriSaml = value;
                    break;

                case Const.ClientRedirectUriCode:
                    model.RedirectUriCode = value;
                    break;

                case Const.ClientRedirectUriToken:
                    model.RedirectUriToken = value;
                    break;

                case OAuth2AndOIDCConst.post_logout_redirect_uri:
                    model.PostLogoutRedirectUri = value;
                    break;

                case Const.ClientBackChannelLogoutUri:
                    model.BackChannelLogoutUri = value;
                    break;

                case Const.ClientFrontChannelLogoutUri:
                    model.FrontChannelLogoutUri = value;
                    break;

                case Const.ClientSubjectTypes:
                    model.SubjectTypes = value;
                    break;

                case OAuth2AndOIDCConst.tls_client_auth_subject_dn:
                    model.TlsClientAuthSubjectDn = value;
                    break;

                case Const.ClientIdTokenSignedResponseAlg:
                    model.IdTokenSignedResponseAlg = value;
                    break;

                case Const.ClientTokenEndpointAuthSigningAlg:
                    model.TokenEndpointAuthSigningAlg = value;
                    break;

                case OAuth2AndOIDCConst.token_endpoint_auth_method:
                    model.TokenEndpointAuthMethod = value;
                    break;

                case Const.ClientRequestObjectSigningAlg:
                    model.RequestObjectSigningAlg = value;
                    break;

                case Const.ClientWebOrigins:
                    model.WebOrigins = value;
                    break;

                case OAuth2AndOIDCConst.scope:
                    model.Scopes = value;
                    break;

                case Const.ClientGrantTypes:
                    model.GrantTypes = value;
                    break;

                case Const.ClientRequirePkce:
                    // **bool**（#270。#346 の 4 つも同じ）。
                    //   **綾り違いを黙って false にしない**ため、`Parse` で落とす。
                    model.RequirePkce = bool.Parse(value);
                    break;

                case Const.ClientRequirePushedAuthorizationRequests:
                    model.RequirePar = bool.Parse(value);
                    break;

                case Const.ClientRequireSignedRequestObject:
                    model.RequireSignedRequestObject = bool.Parse(value);
                    break;

                case Const.ClientDPoPBoundAccessTokens:
                    model.DPoPBoundAccessTokens = bool.Parse(value);
                    break;

                case Const.ClientTlsClientCertificateBoundAccessTokens:
                    model.TlsCertBoundAccessTokens = bool.Parse(value);
                    break;

                default:
                    throw new System.NotSupportedException(
                        string.Format(Resources.Diagnostics.TestClientsUnknownKey, key));
            }
        }

        #endregion
    }
}
