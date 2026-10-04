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
//* クラス名        ：Flows, KnownClients
//* クラス日本語名  ：よく使うフローの組み立て
//*
//* 作成日時        ：－
//* 作成者          ：－
//* 更新履歴        ：－
//*
//*  日時        更新者            内容
//*  ----------  ----------------  -------------------------------------------------
//*  2026/09/08  玄人 幸道         新規（E2Eテスト基盤）
//*  2026/09/10  玄人 幸道         JWK Set の取得を追加（拡張仕様のテスト）
//*  2026/09/11  玄人 幸道         scope を登録した TestClient5 を追加（#198 の後半）
//*  2026/09/11  玄人 幸道         トークンの更新・失効・問い合わせ（RefreshAsync / RevokeAsync / IntrospectAsync）を、テスト クラスから移す
//*  2026/09/18  玄人 幸道         既定で無効な機能を Skip する口を追加（#220）
//*  2026/09/18  玄人 幸道         TestClient6 と、未登録なら Skip する口を追加（#221）
//*  2026/09/22  玄人 幸道         環境変数で差し込む TestClient4_2 と、その登録を引く口を追加（#224）
//*  2026/09/22  玄人 幸道         登録値が不正な TestClient4_3 を追加（#224 の段階 2）
//*  2026/09/22  玄人 幸道         mTLS 用の TestClient2_2 / TestClient2_3 と、その Subject を追加（#226）
//*  2026/09/27  玄人 幸道         記号を含む client_secret の TestClient_2 / TestClient_3 を追加（#237）
//*  2026/09/27  玄人 幸道         post_logout_redirect_uri を登録した TestClient_4 を追加（#232）
//*  2026/09/30  玄人 幸道         subject_types=pairwise のクライアント（TestClient_5）を追加（#140 の段階 2）
//*  2026/10/01  玄人 幸道         既定の subject_types を測る TestClient_6 / TestClient_7 を追加（#151 の段階 4）
//*  2026/10/02  玄人 幸道         RS512 で署名する TestClient_8 を追加（#129 の段階 2）
//*  2026/10/02  玄人 幸道         ES384 / ES512 で署名する TestClient_9 / _10 を追加（#129 の段階 3）
//*  2026/10/03  玄人 幸道         PS256 / PS384 / PS512 の TestClient_11 〜 _13 を追加（#129 の段階 4）
//*  2026/10/03  玄人 幸道         TestClient_8に検証する側のalgの登録を相乗りさせた（#262）
//*  2026/10/03  玄人 幸道         差し込みを種データに寄せ、client_idを固定値にした（#264）
//*  2026/10/04  玄人 幸道         TestClient_15とtest_self_code_manageの解決を追加（C-10）
//*  2026/10/04  玄人 幸道         web_originsのTestClient_16を追加（#266）
//**********************************************************************************

using System;
using System.Collections.Generic;
using System.Text.Json;
using System.Threading.Tasks;

using Xunit;

namespace MultiPurposeAuthSite.Tests.E2E.Infrastructure
{
    /// <summary>
    /// 構成ファイルに登録済みのクライアント。
    /// client_id は環境ごとに違う（CreateClientsIdentity.exe で生成する）ため、
    /// テストでは client_id を直書きせず client_name から引く。
    /// </summary>
    public static class KnownClients
    {
        /// <summary>redirect_uri が絶対URLで登録された、コンフィデンシャル クライアント</summary>
        public const string MvcSample = "MVC_Sample";

        /// <summary>自己テスト用（redirect_uri は test_self_code / test_self_token）</summary>
        public const string TestClient = "TestClient";

        /// <summary>FAPI1 用</summary>
        public const string TestClient1 = "TestClient1";

        /// <summary>FAPI2 用（Request Object を使う）</summary>
        public const string TestClient2 = "TestClient2";

        /// <summary>Device Authorization Grant 用（client_secret 無し ＝ パブリック）</summary>
        public const string TestClient3 = "TestClient3";

        /// <summary>CIBA 用</summary>
        public const string TestClient4 = "TestClient4";

        /// <summary>登録の scope で、要求してよいスコープを制限したクライアント（#198）</summary>
        public const string TestClient5 = "TestClient5";

        /// <summary>クライアント単位で PKCE を必須にしたクライアント（#221）</summary>
        public const string TestClient6 = "TestClient6";

        /// <summary>
        /// TestClient4（fapi_ciba）を写し、登録種別だけ normal にしたクライアント（#224）。
        /// **構成ファイルには無い。** test.ps1 -Launch が環境変数でサイトへ差し込む
        /// （Flows.InjectedRegistration で引く）。
        /// </summary>
        public const string TestClient4_2 = "TestClient4_2";

        /// <summary>
        /// TestClient4（fapi_ciba）を写し、登録種別を既知でない値（fapi_1）にしたクライアント（#224 の段階 2）。
        /// **構成ファイルには無い。** TestClient4_2 と同じく test.ps1 -Launch が差し込む。
        /// </summary>
        public const string TestClient4_3 = "TestClient4_3";

        /// <summary>
        /// TestClient2（fapi2）を写し、tls_client_auth_subject_dn をテスト専用の値（MtlsSubjectDn）にしたクライアント（#226）。
        /// **構成ファイルには無い。** test.ps1 -Launch が差し込む。
        /// </summary>
        public const string TestClient2_2 = "TestClient2_2";

        /// <summary>
        /// TestClient2_2 と同じ Subject で、登録種別を既知でない値（fapi_1）にしたクライアント（#226 / #224 の段階 2）。
        /// </summary>
        public const string TestClient2_3 = "TestClient2_3";

        /// <summary>
        /// TestClient（normal）を写し、client_secret を**記号を含む値**（SymbolSecret）にしたクライアント（#237）。
        /// **構成ファイルには無い。** test.ps1 -Launch が差し込む。
        /// </summary>
        public const string TestClient_2 = "TestClient_2";

        /// <summary>
        /// TestClient（normal）を写し、client_secret を**「:」を含む値**（ColonSecret）にしたクライアント（#237）。
        /// **構成ファイルには無い。** test.ps1 -Launch が差し込む。
        /// </summary>
        public const string TestClient_3 = "TestClient_3";

        /// <summary>
        /// TestClient（normal）を写し、**post_logout_redirect_uri を登録**したクライアント（#232）。
        /// **構成ファイルには無い。** test.ps1 -Launch が差し込む。
        /// </summary>
        /// <remarks>
        /// 登録値は定数（test_self_logout）で、**サーバ側で URL に解決される**
        /// （サイトごとに URL が違うため。CmnEndpoints.GetRedirectUriFromConstr）。
        /// 解決後の URL は PostLogoutRedirectUri で引く。
        /// </remarks>
        public const string TestClient_4 = "TestClient_4";

        /// <summary>
        /// TestClient（normal）を写し、**subject_types を pairwise にした**クライアント（#140 の段階 2）。
        /// **構成ファイルには無い。** test.ps1 -Launch が差し込む。
        /// </summary>
        /// <remarks>
        /// **sub が PPID（クライアントごとに違う値）になる。**
        /// **PPID は OP だけが戻せる**ので、`/userinfo` は従来どおりクレームを返せる。
        /// 以前は戻せず、**`sub` だけを返していた**（#140 の段階 2 で直した）。
        /// </remarks>
        public const string TestClient_5 = "TestClient_5";

        /// <summary>
        /// TestClient（normal）を写しただけのクライアント（#151 の段階 4）。
        /// **構成ファイルには無い。** test.ps1 -Launch が差し込む。
        /// </summary>
        /// <remarks>
        /// **subject_types を書いていない**ので、**既定（段階 4 から public）**になる。
        ///
        /// **新しい client_id であることに意味がある。**
        /// 発行済みの `sub` は対応表から返るので（段階 2）、
        /// **既に使った client_id では「既定が変わったこと」を測れない。**
        /// </remarks>
        public const string TestClient_6 = "TestClient_6";

        /// <summary>
        /// TestClient_6 と同じ（subject_types を書いていない）、別の client_id（#151 の段階 4）。
        /// **構成ファイルには無い。** test.ps1 -Launch が差し込む。
        /// </summary>
        /// <remarks>
        /// **public は「RP が違っても同じ sub」**なので、**2 件ないと測れない**
        /// （pairwise との違いが、ここに出る）。
        /// </remarks>
        public const string TestClient_7 = "TestClient_7";

        /// <summary>
        /// TestClient（normal）を写し、**id_token_signed_response_alg を RS512**、
        /// **token_endpoint_auth_signing_alg を RS256** にしたクライアント
        /// （#129 の段階 2 / #262）。**構成ファイルには無い。** test.ps1 -Launch が差し込む。
        /// </summary>
        /// <remarks>
        /// **鍵は RS256 と同じ**（同じ RSA の証明書）。**ダイジェストだけが違う。**
        /// **kid も同じ**（RFC 7638 は鍵から作る）ので、**`jwkcerts` の同じ鍵で検証できる。**
        ///
        /// **2 つの登録は、別の向きを指している**（#262）。
        /// `id_token_signed_response_alg` は**発行する側**、
        /// `token_endpoint_auth_signing_alg` は**受ける側**なので、同居しても干渉しない
        /// （`RT-129.3` は authorization code で測るため、受ける側の絞り込みは効かない）。
        /// **写す元は RSA と ECDSA の公開鍵を両方登録している**ので、
        /// **絞らなければ、どちらの鍵でも `client_assertion` が通る**（`RT-129.1`）。
        /// **絞ると、`ES256` は通らない**（`RT-262.1`）。
        ///
        /// **専用のクライアントを足していないのは、net48 の制約のため。**
        /// net48 は一覧ごと 1 本の環境変数で受けるので、**件数に上限がある**
        /// （test.ps1 の差し込み一覧のコメント / TESTING.md 1 節）。
        /// </remarks>
        public const string TestClient_8 = "TestClient_8";

        /// <summary>
        /// TestClient（normal）を写し、**id_token_signed_response_alg を ES384** にしたクライアント（#129 の段階 3）。
        /// **構成ファイルには無い。** test.ps1 -Launch が差し込む。
        /// </summary>
        /// <remarks>
        /// **EC は曲線が alg に紐づく**（JWA : ES384 → P-384）ので、**RS とは違って鍵が分かれる。**
        /// **kid も曲線ごとに違う**ので、`jwkcerts` には P-256 / P-384 / P-521 の 3 本が載る。
        /// </remarks>
        public const string TestClient_9 = "TestClient_9";

        /// <summary>
        /// TestClient（normal）を写し、**id_token_signed_response_alg を ES512** にしたクライアント（#129 の段階 3）。
        /// **構成ファイルには無い。** test.ps1 -Launch が差し込む。
        /// </summary>
        /// <remarks>**`ES512` の曲線は `P-521`**（512 ではない。JWA）。</remarks>
        public const string TestClient_10 = "TestClient_10";

        /// <summary>
        /// TestClient（normal）を写し、**id_token_signed_response_alg を PS256** にしたクライアント（#129 の段階 4）。
        /// **構成ファイルには無い。** test.ps1 -Launch が差し込む。
        /// </summary>
        /// <remarks>
        /// **RSASSA-PSS。鍵は `RS*` と同じ 1 本**で、**パディングだけが違う。**
        /// **`kid` も `RS256` と同じ**（RFC 7638 は kty / n / e から作る）。
        /// </remarks>
        public const string TestClient_11 = "TestClient_11";

        /// <summary>同 PS384（#129 の段階 4）</summary>
        public const string TestClient_12 = "TestClient_12";

        /// <summary>同 PS512（#129 の段階 4）</summary>
        public const string TestClient_13 = "TestClient_13";

        /// <summary>
        /// TestClient（normal）を写し、**redirect_uri_code を `test_self_code_manage`** にした
        /// クライアント（C-10）。**構成ファイルには無い。** 種データが作る（#264）。
        /// </summary>
        /// <remarks>
        /// **管理画面の自己テスト（`GetOAuth2Token`）の折り返し先を、登録値として表したもの。**
        /// **以前は `CheckRedirectUri` に「この URL なら登録を確かめずに通す」分岐が在った**
        /// （`ANALYSIS-IdP.md` の C-10）。**記号にして通常の照合に載せ、分岐を消した。**
        /// </remarks>
        public const string TestClient_15 = "TestClient_15";

        /// <summary>
        /// TestClient（normal）を写し、**`web_origins` を登録した public クライアント**（#266）。
        /// **構成ファイルには無い。** 種データが作る（#264）。
        /// </summary>
        /// <remarks>
        /// **`client_secret` を空にして public にしてある**（CORS は public クライアントだけに効く）。
        /// **`redirect_uri_code` には別のオリジン**（`https://notallowed.example/cb`）を入れてあり、
        /// **`web_origins`（`https://spa.example`）が勝つ**ことを `RT-266.1` で測る。
        /// </remarks>
        public const string TestClient_16 = "TestClient_16";

        /// <summary>TestClient_16 に登録した web_origins（#266）</summary>
        public const string WebOrigin = "https://spa.example";

        /// <summary>TestClient_16 の redirect_uri_code のオリジン（#266。許されない側）</summary>
        public const string NotAllowedOrigin = "https://notallowed.example";

        #region 種データで登録される client_id（#264）

        /// <summary>
        /// **種データ（`Sts.TestClients`）で登録されるクライアントの client_id**（#264）。
        /// </summary>
        /// <remarks>
        /// **以前は test.ps1 -Launch が環境変数で差し込み、client_id を `MPAS_<名前>` で渡していた。**
        /// **net48 版は一覧ごと 1 本の環境変数**なので**件数に上限があり**（#262 で踏んだ）、
        /// **利用者の登録（`saml2OAuth2Data`）に寄せた**（#264）。
        ///
        /// **user store は構成ファイルから読めない**ので、**client_id を固定値で持つ。**
        /// **サーバ側の `Sts.TestClients.Entries` と同じ値にすること。**
        /// 揃っていなければ「登録されていない」で落ちる。
        /// </remarks>
        private static readonly Dictionary<string, string> SeededClientIds
            = new Dictionary<string, string>()
            {
                { KnownClients.TestClient_2,  "e2e0tc02000000000000000000000000" },
                { KnownClients.TestClient_3,  "e2e0tc03000000000000000000000000" },
                { KnownClients.TestClient_4,  "e2e0tc04000000000000000000000000" },
                { KnownClients.TestClient_5,  "e2e0tc05000000000000000000000000" },
                { KnownClients.TestClient_6,  "e2e0tc06000000000000000000000000" },
                { KnownClients.TestClient_7,  "e2e0tc07000000000000000000000000" },
                { KnownClients.TestClient_16, "e2e0tc16000000000000000000000000" },
                { KnownClients.TestClient_15, "e2e0tc15000000000000000000000000" },
                { KnownClients.TestClient4_2, "e2e0tc42000000000000000000000000" },
                { KnownClients.TestClient4_3, "e2e0tc43000000000000000000000000" },
                { KnownClients.TestClient2_2, "e2e0tc22000000000000000000000000" },
                { KnownClients.TestClient2_3, "e2e0tc23000000000000000000000000" },
                { KnownClients.TestClient_8,  "e2e0tc08000000000000000000000000" },
                { KnownClients.TestClient_9,  "e2e0tc09000000000000000000000000" },
                { KnownClients.TestClient_10, "e2e0tc10000000000000000000000000" },
                { KnownClients.TestClient_11, "e2e0tc11000000000000000000000000" },
                { KnownClients.TestClient_12, "e2e0tc12000000000000000000000000" },
                { KnownClients.TestClient_13, "e2e0tc13000000000000000000000000" }
            };

        /// <summary>種データで登録される client_id（無ければ null）（#264）</summary>
        /// <param name="clientName">クライアント名</param>
        /// <returns>client_id（種データに無ければ null）</returns>
        public static string SeededClientId(string clientName)
        {
            return KnownClients.SeededClientIds.TryGetValue(clientName ?? "", out string clientId)
                ? clientId : null;
        }

        #endregion

        /// <summary>
        /// TestClient_2 の client_secret（#237）。
        /// **test.ps1 の差し込みと同じ値にすること。**
        /// </summary>
        /// <remarks>
        /// **テスト専用の値**（差し込みで作るクライアントのもの）なので、ここに書いてよい。
        /// 「+」は form-urlencoded の復号で空白に変わるため、
        /// **符号化して送ったか否かで、受け側に届く値が変わる**（RFC 6749 §2.3.1）。
        /// 「/」「=」は、base64 の秘密によく現れる（符号化すると %2F / %3D）。
        /// </remarks>
        public const string SymbolSecret = "e2e+ab/cd=ef";

        /// <summary>
        /// TestClient_3 の client_secret（#237）。
        /// **test.ps1 の差し込みと同じ値にすること。**
        /// </summary>
        /// <remarks>
        /// **「:」は Basic の分割位置そのもの**なので、符号化しないと資格情報として読めない
        /// （"id:e2e:ab+cd" は 3 つに割れる）。符号化したときだけ通る。
        /// </remarks>
        public const string ColonSecret = "e2e:ab+cd";

        /// <summary>
        /// TestClient2_2 / TestClient2_3 の tls_client_auth_subject_dn（#226）。
        /// **test.ps1 の差し込みと同じ値にすること。** 雛形の TestClient1 / TestClient2 は同じ Subject を共有しているので使わない。
        /// </summary>
        public const string MtlsSubjectDn = "CN=mpas-e2e-mtls-client";

        /// <summary>
        /// TestClient_4 に登録された post_logout_redirect_uri の**解決後の値**（#232）。
        /// </summary>
        /// <param name="client">IdPClient（対象ごとに URL が違う）</param>
        /// <returns>ログアウト後に戻ってよい URL</returns>
        /// <remarks>
        /// **サーバ側の解決（test_self_logout → クライアント側の口 ＋ /Home/Index）と同じ値**を作る。
        /// ここを実装側のコードから引かないのは、テストをブラックボックスに保つため。
        ///
        /// **待ち受けている URL に合わせる**（構成ファイルの値は net48 / net10.0 で共通だが、
        /// test.ps1 が対象ごとに環境変数で上書きする）。Flows.ResolveRedirectUri に任せる。
        /// </remarks>
        public static string PostLogoutRedirectUri(IdPClient client)
        {
            return Flows.ResolveRedirectUri(client, "test_self_logout");
        }
    }

    /// <summary>クライアントの登録内容（テストから参照する分だけ）</summary>
    public sealed class ClientRegistration
    {
        /// <summary>client_id</summary>
        public string ClientId { get; set; }

        /// <summary>client_secret（出力しないこと）</summary>
        public string ClientSecret { get; set; }

        /// <summary>redirect_uri（response_type=code 用・解決済み）</summary>
        public string RedirectUri { get; set; }

        /// <summary>redirect_uri（response_type=token 用・解決済み）</summary>
        public string RedirectUriToken { get; set; }
    }

    /// <summary>よく使うフローの組み立て</summary>
    public static class Flows
    {
        /// <summary>client_name から登録内容を引く</summary>
        /// <param name="client">IdPClient</param>
        /// <param name="clientName">client_name</param>
        /// <returns>ClientRegistration</returns>
        public static ClientRegistration Registration(IdPClient client, string clientName)
        {
            string clientId = client.Config.FindClientIdByName(clientName);

            if (string.IsNullOrEmpty(clientId))
            {
                throw new InvalidOperationException(
                    "client_name=" + clientName + " が構成ファイルに登録されていません: "
                    + client.Config.Path);
            }

            return new ClientRegistration()
            {
                ClientId = clientId,
                ClientSecret = client.Config.GetClientAttribute(clientId, "client_secret"),
                RedirectUri = ResolveRedirectUri(
                    client, client.Config.GetClientAttribute(clientId, "redirect_uri_code")),
                RedirectUriToken = ResolveRedirectUri(
                    client, client.Config.GetClientAttribute(clientId, "redirect_uri_token"))
            };
        }

        /// <summary>
        /// 登録された redirect_uri を、実際のURLに解決する。
        ///
        /// 自己テスト用のクライアントは、絶対URLではなく
        /// test_self_code / test_self_token という記号で登録されている。
        /// サーバは、これを構成ファイルの画面パスと突き合わせて実URLにする。
        /// </summary>
        /// <param name="client">IdPClient</param>
        /// <param name="value">登録値</param>
        /// <returns>解決したURL</returns>
        public static string ResolveRedirectUri(IdPClient client, string value)
        {
            if (string.IsNullOrEmpty(value))
            {
                return value;
            }

            if (value.StartsWith("http://", StringComparison.OrdinalIgnoreCase)
                || value.StartsWith("https://", StringComparison.OrdinalIgnoreCase))
            {
                return value;
            }

            // サーバ側（CmnEndpoints.GetRedirectUriFromConstr）は
            // OAuth2ClientEndpointsRootURI を使う。ここも合わせる。
            string root = client.Config.Get("OAuth2ClientEndpointsRootURI");

            if (string.IsNullOrEmpty(root))
            {
                return value;
            }

            root = root.TrimEnd('/');

            if (value == "test_self_code")
            {
                return client.ToLocalUrl(
                    root + client.Config.Get("OAuth2AuthorizationCodeGrantClient_Account"));
            }

            if (value == "test_self_token")
            {
                return client.ToLocalUrl(
                    root + client.Config.Get("OAuth2ImplicitGrantClient_Account"));
            }

            // 管理画面の自己テストの折り返し先（C-10）。
            if (value == "test_self_code_manage")
            {
                return client.ToLocalUrl(
                    root + client.Config.Get("OAuth2AuthorizationCodeGrantClient_Manage"));
            }

            // ログアウト後の戻り先（#232）。サーバ側は「クライアント側の口 ＋ /Home/Index」。
            if (value == "test_self_logout")
            {
                return client.ToLocalUrl(root + "/Home/Index");
            }

            // test_self_saml やカスタム スキーム（myapp:/oauthredirect）は、そのまま。
            return value;
        }

        /// <summary>
        /// 認可コードを取得する（サインイン済みであること）。
        /// </summary>
        /// <param name="client">IdPClient</param>
        /// <param name="registration">クライアント</param>
        /// <param name="scope">スコープ</param>
        /// <param name="state">state（null なら送らない）</param>
        /// <param name="nonce">nonce（null なら送らない）</param>
        /// <param name="redirectUri">redirect_uri（null なら送らない）</param>
        /// <param name="extra">追加パラメタ</param>
        /// <returns>AuthZResponse</returns>
        public static Task<AuthZResponse> AuthorizeCodeAsync(
            IdPClient client, ClientRegistration registration,
            string scope = "openid email", string state = "state1", string nonce = "nonce1",
            string redirectUri = null, IDictionary<string, string> extra = null)
        {
            Dictionary<string, string> q = new Dictionary<string, string>()
            {
                { "response_type", "code" },
                { "client_id", registration.ClientId },
                { "scope", scope },
                { "state", state },
                { "nonce", nonce },
                { "redirect_uri", redirectUri },

                // 同意画面を挟まず、サインイン済みのセッションでそのまま認可させる。
                { "prompt", "none" }
            };

            if (extra != null)
            {
                foreach (KeyValuePair<string, string> p in extra)
                {
                    q[p.Key] = p.Value;
                }
            }

            return client.AuthorizeAsync(q);
        }

        /// <summary>
        /// 認可コードをトークンに交換する。
        /// </summary>
        /// <param name="client">IdPClient</param>
        /// <param name="registration">クライアント</param>
        /// <param name="code">認可コード</param>
        /// <param name="redirectUri">redirect_uri（null なら送らない）</param>
        /// <param name="extra">追加パラメタ</param>
        /// <returns>JsonResponse</returns>
        public static Task<JsonResponse> ExchangeCodeAsync(
            IdPClient client, ClientRegistration registration,
            string code, string redirectUri = null, IDictionary<string, string> extra = null)
        {
            Dictionary<string, string> form = new Dictionary<string, string>()
            {
                { "grant_type", "authorization_code" },
                { "code", code },
                { "client_id", registration.ClientId },
                { "client_secret", registration.ClientSecret },
                { "redirect_uri", redirectUri }
            };

            if (extra != null)
            {
                foreach (KeyValuePair<string, string> p in extra)
                {
                    form[p.Key] = p.Value;
                }
            }

            return client.TokenAsync(form);
        }

        /// <summary>
        /// 認可コード フローを最後まで通し、トークン応答を返す。
        /// </summary>
        /// <param name="client">IdPClient</param>
        /// <param name="clientName">client_name</param>
        /// <param name="scope">スコープ</param>
        /// <param name="nonce">nonce（null なら送らない）</param>
        /// <returns>JsonResponse</returns>
        public static async Task<JsonResponse> RunAuthorizationCodeFlowAsync(
            IdPClient client, string clientName = KnownClients.MvcSample,
            string scope = "openid email", string nonce = "nonce1")
        {
            ClientRegistration registration = Registration(client, clientName);

            AuthZResponse authz = await AuthorizeCodeAsync(
                client, registration, scope, "state1", nonce, registration.RedirectUri);

            if (string.IsNullOrEmpty(authz.Code))
            {
                throw new InvalidOperationException(
                    "認可コードを取得できませんでした: " + authz.ToString());
            }

            return await ExchangeCodeAsync(client, registration, authz.Code, registration.RedirectUri);
        }

        /// <summary>grant_type=refresh_token でトークンを取り直す</summary>
        /// <param name="client">IdPClient</param>
        /// <param name="registration">認証に使うクライアント</param>
        /// <param name="refreshToken">refresh_token</param>
        /// <returns>JsonResponse</returns>
        public static Task<JsonResponse> RefreshAsync(
            IdPClient client, ClientRegistration registration, string refreshToken)
        {
            return client.TokenAsync(new Dictionary<string, string>()
            {
                { "grant_type", "refresh_token" },
                { "refresh_token", refreshToken },
                { "client_id", registration.ClientId },
                { "client_secret", registration.ClientSecret }
            });
        }

        /// <summary>トークンを失効させる（POST /revoke）</summary>
        /// <param name="client">IdPClient</param>
        /// <param name="registration">認証に使うクライアント</param>
        /// <param name="token">失効させるトークン</param>
        /// <param name="tokenTypeHint">token_type_hint（null なら送らない）</param>
        /// <returns>JsonResponse</returns>
        public static Task<JsonResponse> RevokeAsync(
            IdPClient client, ClientRegistration registration, string token, string tokenTypeHint)
        {
            return client.RevokeAsync(new Dictionary<string, string>()
            {
                { "token", token },
                { "token_type_hint", tokenTypeHint },
                { "client_id", registration.ClientId },
                { "client_secret", registration.ClientSecret }
            });
        }

        /// <summary>トークンを問い合わせる（POST /introspect）</summary>
        /// <param name="client">IdPClient</param>
        /// <param name="registration">認証に使うクライアント（null なら認証しない）</param>
        /// <param name="token">問い合わせるトークン</param>
        /// <param name="tokenTypeHint">token_type_hint（null なら送らない）</param>
        /// <returns>JsonResponse</returns>
        public static Task<JsonResponse> IntrospectAsync(
            IdPClient client, ClientRegistration registration, string token, string tokenTypeHint)
        {
            return client.IntrospectAsync(new Dictionary<string, string>()
            {
                { "token", token },
                { "token_type_hint", tokenTypeHint },
                { "client_id", registration == null ? null : registration.ClientId },
                { "client_secret", registration == null ? null : registration.ClientSecret }
            });
        }

        /// <summary>
        /// Discovery の jwks_uri から JWK Set を取得する。
        /// </summary>
        /// <param name="client">IdPClient</param>
        /// <returns>JWK Set（keys 配列を持つ JSON）</returns>
        public static async Task<JsonElement> JwkSetAsync(IdPClient client)
        {
            JsonResponse discovery = await client.GetJsonAsync("/.well-known/openid-configuration");
            string jwksUri = discovery.String("jwks_uri");

            if (string.IsNullOrEmpty(jwksUri))
            {
                throw new InvalidOperationException(
                    "Discovery に jwks_uri がありません: " + discovery.ToString());
            }

            JsonResponse jwks = await client.GetJsonAsync(client.ToLocalUrl(jwksUri));

            if (!jwks.IsJson)
            {
                throw new InvalidOperationException(
                    "JWK Set を取得できませんでした: " + jwks.ToString());
            }

            return jwks.Json;
        }

        #region 既定で無効な機能の Skip（#220）

        /// <summary>
        /// discovery に広告されていない grant_type なら Skip する（#220）
        /// </summary>
        /// <param name="client">IdPClient</param>
        /// <param name="grantType">grant_type</param>
        /// <returns>Task</returns>
        /// <remarks>
        /// **OAuth 2.1 に寄せて、Implicit / ROPC は雛形の既定で無効にした（#220）。**
        /// 有効にしている環境では従来どおり測り、無効な環境では Skip する。
        /// discovery は設定を反映するので、そこを見れば分かる。
        /// </remarks>
        public static async Task SkipIfGrantTypeNotSupportedAsync(IdPClient client, string grantType)
        {
            JsonResponse discovery = await client.GetJsonAsync("/.well-known/openid-configuration");

            Skip.IfNot(discovery.ArrayContains("grant_types_supported", grantType),
                "grant_type=" + grantType + " が無効です（#220 で既定を無効にした）。");
        }

        /// <summary>
        /// そのクライアントが構成ファイルに登録されていなければ Skip する（#221）
        /// </summary>
        /// <param name="client">IdPClient</param>
        /// <param name="clientName">client_name</param>
        /// <remarks>
        /// **雛形に足したクライアントは、既存の環境の実設定には無い。**
        /// 実設定は各自のものなので、雛形を当て直すまでは登録されていない。
        /// その間は測れないので Skip する（**登録すれば、そのまま測れる**）。
        /// </remarks>
        public static void SkipIfClientNotRegistered(IdPClient client, string clientName)
        {
            Skip.If(string.IsNullOrEmpty(client.Config.FindClientIdByName(clientName)),
                "client_name=" + clientName + " が構成ファイルに登録されていません（#221 で雛形に追加）。");
        }

        /// <summary>
        /// test.ps1 が環境変数で差し込んだクライアントの登録内容を引く（#224）。差し込まれていなければ Skip する
        /// </summary>
        /// <param name="client">IdPClient</param>
        /// <param name="clientName">client_name（TestClient4_2 / TestClient4_3 / TestClient2_2 / TestClient2_3 / TestClient_2 / TestClient_3 / TestClient_4）</param>
        /// <returns>ClientRegistration（client_id と client_secret だけ）</returns>
        /// <remarks>
        /// **構成ファイルには無いクライアント**なので、Registration では引けない。
        /// 差し込むのは `test.ps1 -Launch` だけで、既に動いているサイトへ向けたときは Skip する。
        /// </remarks>
        public static ClientRegistration InjectedRegistration(IdPClient client, string clientName)
        {
            // test.ps1 -Launch が、起動したサイトに差し込んだ client_id を渡してくる（MPAS_<client_name の大文字>）。
            //   写す元 : TestClient4_x は TestClient4、TestClient2_x は TestClient2、TestClient_x は TestClient
            string sourceName = null;

            // **client_secret を差し替えたものは、写す元の秘密では認証できない**（#237）。
            string overriddenSecret = null;

            // **redirect_uri を差し替えたものも、写す元の値では通らない**（C-10）。
            string overriddenRedirectUri = null;

            if (clientName == KnownClients.TestClient4_2 || clientName == KnownClients.TestClient4_3)
            {
                sourceName = KnownClients.TestClient4;
            }
            else if (clientName == KnownClients.TestClient2_2 || clientName == KnownClients.TestClient2_3)
            {
                sourceName = KnownClients.TestClient2;
            }
            else if (clientName == KnownClients.TestClient_2)
            {
                sourceName = KnownClients.TestClient;
                overriddenSecret = KnownClients.SymbolSecret;
            }
            else if (clientName == KnownClients.TestClient_3)
            {
                sourceName = KnownClients.TestClient;
                overriddenSecret = KnownClients.ColonSecret;
            }
            else if (clientName == KnownClients.TestClient_4)
            {
                // client_secret は写す元のまま（登録に足したのは post_logout_redirect_uri だけ）。
                sourceName = KnownClients.TestClient;
            }
            else if (clientName == KnownClients.TestClient_5)
            {
                // client_secret は写す元のまま（登録で変えたのは subject_types だけ）。
                sourceName = KnownClients.TestClient;
            }
            else if (clientName == KnownClients.TestClient_6
                || clientName == KnownClients.TestClient_7)
            {
                // client_secret は写す元のまま（**写しただけ**。#151 の段階 4）。
                sourceName = KnownClients.TestClient;
            }
            else if (clientName == KnownClients.TestClient_8
                || clientName == KnownClients.TestClient_9
                || clientName == KnownClients.TestClient_10
                || clientName == KnownClients.TestClient_11
                || clientName == KnownClients.TestClient_12
                || clientName == KnownClients.TestClient_13)
            {
                // client_secret は写す元のまま（登録で変えたのは alg だけ。#129 の段階 2〜4）。
                sourceName = KnownClients.TestClient;
            }
            else if (clientName == KnownClients.TestClient_16)
            {
                // **web_origins を登録した public クライアント**（#266）。
                //   **client_secret は空**にしてある（CORS は public だけに効く）ので、
                //   写す元の秘密では認証できない。**このテストは CORS だけを測る。**
                sourceName = KnownClients.TestClient;
                overriddenSecret = "";
            }
            else if (clientName == KnownClients.TestClient_15)
            {
                // **折り返し先だけを差し替えた**（C-10）。client_secret は写す元のまま。
                sourceName = KnownClients.TestClient;
                overriddenRedirectUri = Flows.ResolveRedirectUri(client, "test_self_code_manage");
            }

            // **client_id は固定値**（#264）。
            //   **以前は test.ps1 -Launch が環境変数（`MPAS_<名前>`）で渡していた**が、
            //   **サーバ側の種データ（`Sts.TestClients`）に寄せた**ので、環境変数を使わない。
            //   **`-Launch` を付けずに、手で起動したサイトに対しても測れる**ようになった。
            string clientId = sourceName != null
                ? KnownClients.SeededClientId(clientName) : null;

            Skip.If(string.IsNullOrEmpty(clientId),
                "client_name=" + clientName + " の登録がありません"
                + "（種データは IsDebug ＋ TestUserPWD のときだけ作る。#264）。");

            // client_secret・redirect_uri・公開鍵は写す元と同じなので、構成ファイルの写す元から引ける。
            ClientRegistration source = Flows.Registration(client, sourceName);

            return new ClientRegistration()
            {
                ClientId = clientId,
                ClientSecret = overriddenSecret ?? source.ClientSecret,
                RedirectUri = overriddenRedirectUri ?? source.RedirectUri,
                RedirectUriToken = source.RedirectUriToken
            };
        }

        #endregion
    }
}
