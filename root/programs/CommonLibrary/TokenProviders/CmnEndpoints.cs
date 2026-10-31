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
//* クラス名        ：CmnEndpoints
//* クラス日本語名  ：CmnEndpoints（ライブラリ）
//*
//* 作成日時        ：－
//* 作成者          ：－
//* 更新履歴        ：－
//*
//*  日時        更新者            内容
//*  ----------  ----------------  -------------------------------------------------
//*  2017/04/24  西野 大介         新規
//*  2019/02/07  西野 大介         - Code, Token生成処理の集約
//*                                - CheckClientModeの集約
//*                                - Client認証のclient_idとToken類のaudをチェック追加
//*                                - オペレーション・トレース・ログ出力の集約
//*                                  - 情報源
//*                                    - Client情報はclient_idから取得する。
//*                                    - User情報はTokenのsubから取得する。
//*                                  - 以下は、Client = User
//*                                    - GrantClientCredentials
//*                                    - GrantJwtBearerTokenCredentials
//*                                - CheckClientModeの再チェック（PKCE、Hybrid部分
//*  2019/02/08  西野 大介         - F-API2, Confidential Client実装
//*  2019/08/01  西野 大介         - client_secret_postのサポートを追加
//*  2019/08/01  西野 大介         - PKCEのClient認証方法を変更
//*  2019/12/25  西野 大介         PPID対応による見直し（Metadataにsubject_types_supportedを追加）
//*  2020/01/07  西野 大介         PPID対応実施（ログ出力時のUser Account）
//*  2020/01/08  西野 大介         #126（Feedback）対応実施
//*  2020/02/28  西野 大介         エラーメッセージ通知の改善
//*  2020/02/28  西野 大介         プッシュ通知、FAPI CIBA対応実施
//*  2020/07/24  西野 大介         OIDCではredirect_uriは必須。
//*  2020/07/24  西野 大介         ID連携（Hybrid-IdP）実装の見直し
//*  2020/12/18  西野 大介         Device AuthZ対応実施
//*  2020/12/21  西野 大介         ClientMode追加対応実施
//*  2021/05/24  西野 大介         LIRでPKCEを使用した場合の例外措置
//*  2026/09/07  玄人 幸道         expires_inが常に0になる不具合を修正（#182）
//*  2026/09/07  玄人 幸道         Implicit / Hybridでnonceを必須化（#190）
//*  2026/09/07  玄人 幸道         nonceをstateから捏造しないよう修正（#191）
//*  2026/09/07  玄人 幸道         不正な入力での未処理例外を修正（#185）
//*  2026/09/07  玄人 幸道         discoveryのキー名の末尾スペースを除去（#189）
//*  2026/09/08  玄人 幸道         Device AuthZのクライアント認証を追加（#193）
//*  2026/09/08  玄人 幸道         revoke/introspectの所有者確認を追加（#194）
//*  2026/09/08  玄人 幸道         エラー コードをRFC 6749に合わせる（#187）
//*  2026/09/11  玄人 幸道         device_code のエラーを RFC の値で返すよう修正（#199）
//*  2026/09/11  玄人 幸道         revoke/introspectの本体を両アプリから移し、RFC 7009 / 7662 に合わせる（#200）
//*  2026/09/11  玄人 幸道         scopes_supported に無いスコープを発行せず、トークン応答に scope を返す（#198）
//*  2026/09/11  玄人 幸道         エラー応答の HTTP ステータスを決める GetErrorStatusCode を追加（#196）
//*  2026/09/17  玄人 幸道         /introspect の token_type を RFC 7662 2.2 の意味に直す（#218）
//*  2026/09/17  玄人 幸道         PKCE : client_secret との同時送信を通し、検証を 1 箇所にまとめた（#220）
//*  2026/09/22  玄人 幸道         Device AuthZ グラントでも、登録種別を判定する（#224）
//*  2026/09/24  玄人 幸道         Discovery の誤りを直し、実装済みの項目を広告する（#189 の 2〜8）
//*  2026/09/24  玄人 幸道         code_challenge_methods_supported を設定に合わせ、service_documentation を設定値にする（#228）
//*  2026/09/24  玄人 幸道         Request Object を、認可応答を作った時点で消す（ワンタイム化。#188 の段階 2）
//*  2026/09/24  玄人 幸道         認可応答に iss を付ける（RFC 9207。#231）
//*  2026/09/24  玄人 幸道         PAR（RFC 9126）のエンドポイントを追加（#229）
//*  2026/09/24  玄人 幸道         CIBA の認証要求を request で直接受け取る（CIBA Core 7.1.1。#233）
//*  2026/09/25  玄人 幸道         CIBA の認証要求の aud を検証する（CIBA Core 7.1.1。#234 の段階 1）
//*  2026/09/25  玄人 幸道         client_assertion（RFC 7523 2.2）を読む（#238）
//*  2026/09/25  玄人 幸道         claims_supported を、クレームの対応付けから作る（#230）
//*  2026/09/26  玄人 幸道         refresh_token / ROPC / client_credentials でも非対称の認証を受ける（#239）
//*  2026/09/26  玄人 幸道         JWT でない値・未登録の鍵で 500 にしない（#241）
//*  2026/09/27  玄人 幸道         Basic の資格情報を復号して照合する（RFC 6749 2.3.1。#237）
//*  2026/09/27  玄人 幸道         RP-Initiated Logout（/end_session）を追加（#232）
//*  2026/09/27  玄人 幸道         CIBA の jti を記録するキーを固定長にした（#243）
//*  2026/09/28  玄人 幸道         max_age の判定を結果で場合分けできる形にした（#247）
//*  2026/09/29  玄人 幸道         経過を秒単位で比べる（再認証の直後を超過としない）（#247）
//*  2026/09/29  玄人 幸道         refresh で登録種別のクレーム（fapi）が消えていたのを修正（#245）
//*  2026/09/29  玄人 幸道         code_challenge を送った code は code_verifier を必須にした（#245）
//*  2026/09/30  玄人 幸道         client_assertion を ES256 でも検証できるようにし、広告を揃えた（#129 の段階 2）
//*  2026/10/01  玄人 幸道         subject_types_supported の並びを public 先頭に（#151 の段階 4）
//*  2026/10/03  玄人 幸道         検証する側のalgを登録で絞る（#262）
//*  2026/10/03  玄人 幸道         redirect_uriを単純文字列比較にした（#263）
//*  2026/10/04  玄人 幸道         redirect_uriの登録迂回の分岐を削除（C-10）
//*  2026/10/04  玄人 幸道         CORSで許可するオリジンの導出を追加（#265）
//*  2026/10/04  玄人 幸道         response_typeを順不同の集合として扱う（#267）
//*  2026/10/04  玄人 幸道         CORSのオリジンにweb_originsと画面登録を含める（#266）
//*  2026/10/06  玄人 幸道         CORSの許可オリジンをキャッシュしないようにした（#271）
//*  2026/10/06  玄人 幸道         promptを空白区切りの集合として扱う（#272 の段階 1）
//*  2026/10/16  玄人 幸道         ポーリングが速すぎたら slow_down を返す（#305 の段階 1）
//*  2026/10/18  玄人 幸道         登録の grant_types / response_types を効かせ、registration_endpoint を広告（#307 の段階 1）
//*  2026/10/18  玄人 幸道         redirect_uri の事前登録を n 件にし、全件と照合する（#306）
//*  2026/10/21  玄人 幸道         client_assertion の鍵を jwks_uri からも引く（#309 の段階 1）
//*  2026/10/21  玄人 幸道         Back-Channel Logout を広告し、受け口の記号を解決する（#310 の段階 2）
//*  2026/10/21  玄人 幸道         DPoP の証明を /token で受け、cnf.jkt で発行する（#311 の段階 1）
//*  2026/10/24  玄人 幸道         Hybrid / OIDC の Implicit も Enable*GrantType に従わせ、EnableOpenIDConnect を廃止した（#314）
//*  2026/10/24  玄人 幸道         独自 scope の userid を廃止した（pairwise の sub を打ち消すため。#294）
//*  2026/10/29  玄人 幸道         partial に分割した（CmnEndpoints.*.cs。#294）
//*  2026/10/29  玄人 幸道         using を整理した（#294）
//**********************************************************************************

using MultiPurposeAuthSite.Co;
using MultiPurposeAuthSite.Extensions.Sts;
using MultiPurposeAuthSite.Util.Sts;

using System;
using System.Collections.Generic;

using Touryo.Infrastructure.Framework.Authentication;
using Touryo.Infrastructure.Public.Security.Jwt;

namespace MultiPurposeAuthSite.TokenProviders
{
    /// <summary>CmnEndpoints</summary>
    public partial class CmnEndpoints
    {
        // 本体は、partial の次のファイルに在る（#294 で分割した）。
        //   CmnEndpoints.Discovery.cs            : .well-known/openid-configuration
        //   CmnEndpoints.Authorize.cs            : 認可エンドポイント（要求の検証・redirect_uri・PKCE）
        //   CmnEndpoints.AuthorizeResponse.cs    : 認可エンドポイント（code / Implicit / Hybrid の応答）
        //   CmnEndpoints.RequestObject.cs        : Request Object・PAR
        //   CmnEndpoints.Ciba.cs                 : CIBA の受付
        //   CmnEndpoints.Logout.cs               : RP-Initiated Logout
        //   CmnEndpoints.Token.cs                : トークン エンドポイント（各 grant）
        //   CmnEndpoints.Revocation.cs           : 取り消し・照会エンドポイント
        //   CmnEndpoints.ClientAuthentication.cs : クライアント認証
        //   CmnEndpoints.TokenIssuance.cs        : 発行の共通部品（ロックアウト・CheckClientMode・DPoP・応答）
        // このファイルには、どの口からも使う公開の部品（redirect_uri の定数・CORS・エラー応答）を置く。

        #region Common

        #region Public

        /// <summary>定数文字列からRedirectUriを取得する。</summary>
        /// <param name="constr">定数文字列</param>
        /// <returns>RedirectUri</returns>
        public static string GetRedirectUriFromConstr(string constr)
        {
            string ret = "";

            // 事前登録されている。
            if (constr.ToLower() == Const.TestSelfCode)
            {
                // Authorization Codeグラント種別のテスト用のセルフRedirectエンドポイント
                ret = Config.OAuth2ClientEndpointsRootURI + Config.OAuth2AuthorizationCodeGrantClient_Account;
            }
            else if (constr.ToLower() == Const.TestSelfToken)
            {
                // Implicitグラント種別のテスト用のセルフRedirectエンドポイント
                ret = Config.OAuth2ClientEndpointsRootURI + Config.OAuth2ImplicitGrantClient_Account;
            }
            else if (constr.ToLower() == Const.TestSelfLogout)
            {
                // **ログアウト後の戻り先のテスト用**（#232）。
                //   サイトごとに URL が違う（net48 / net10.0）ので、定数で登録して、ここで解決する。
                ret = Config.OAuth2ClientEndpointsRootURI + "/Home/Index";
            }
            else if (constr.ToLower() == Const.TestSelfFrontChannelLogout)
            {
                // **Front-Channel Logout の受け口のテスト用**（#310 の段階 3）。
                //   **ブラウザが `iframe` で開く口**（`IsLockedDownTestEndpoints` で閉じる）。
                ret = Config.OAuth2ClientEndpointsRootURI + "/Account/FrontChannelLogoutClient";
            }
            else if (constr.ToLower() == Const.TestSelfBackChannelLogout)
            {
                // **Back-Channel Logout の受け口のテスト用**（#310 の段階 2）。
                //   **このサイトが自分の RP も兼ねる**（`IsLockedDownTestEndpoints` で閉じる口）。
                ret = Config.OAuth2ClientEndpointsRootURI + "/Account/BackChannelLogoutClient";
            }
            else
            {
                // そのまま使用する。
                ret = constr;
            }

            return ret;
        }

        #region GetCorsAllowedOrigins

        /// <summary>CORS で許可するオリジン（#265）</summary>
        /// <returns>オリジンの一覧（重複なし。1 件も無ければ空）</returns>
        /// <remarks>
        /// **2 つを合わせる。**
        ///
        /// | | |
        /// |---|---|
        /// | **導出** | **構成ファイルの public クライアントの `redirect_uri_*`**（記号を解決し、`http` / `https` のオリジンだけ取る） |
        /// | **追加分** | `Config.CorsAllowedOrigins`（空でよい） |
        ///
        /// **SPA の `redirect_uri` は、必ずその SPA のオリジン上にある**ので、
        /// **登録を足せば、CORS の設定を別に書かなくてよい。**
        /// **Keycloak の Web origins の既定値 `+`（Valid Redirect URIs のオリジンを使う）と、
        /// Entra ID の SPA プラットフォームと同じ考え方**である。
        ///
        /// **`*` は受けない。** 書かれていても落とす（`ProductionCheck` が警告する）。
        /// **カスタム スキーム**（`com.opentouryo:/oauthredirect` など）**も落とす。**
        /// ネイティブの折り返し先はブラウザの話ではないため。
        ///
        /// **キャッシュしない**（#271）。**毎回作る。**
        ///
        /// 以前は 60 秒のキャッシュを持ち、登録の保存で破棄していた。
        /// **やめた理由は 3 つ。**
        ///
        /// | | |
        /// |---|---|
        /// | **読む量が減った** | #270 で専用列に切り出したので、`Saml2OAuth2DataProvider.GetAllUris` は **URI 関連の 6 列だけ**を読む。以前は**全行の JSON を読んで 1 件ずつ逆直列化**していた |
        /// | **複数インスタンスでは正しく捨てられない** | `static` なので、**他のインスタンスの分は捨てられない**。登録を保存してから最長 60 秒、そちらでは新しいオリジンが許されなかった |
        /// | **間接的に消える経路を捕まえていなかった** | **利用者の削除**（`UsersAdmin`）で登録も FK で消えるが、破棄を呼んでいなかった。**消した登録のオリジンが、最長 60 秒許され続けていた** |
        ///
        /// **呼ばれるのは、`Origin` 付きの要求のときだけ**である
        /// （`MpasBrowserApi` ポリシー。**公開情報の口は全開なので、この一覧を引かない**）。
        /// **重くなったときは、共有キャッシュ（`IDistributedCache`。#256）を考えること。
        /// **プロセス内に戻すのは、上の 2 つ目・3 つ目を戻すことになる。**
        /// </remarks>
        public static List<string> GetCorsAllowedOrigins()
        {
            // **キャッシュしない**（#271）。理由は上の remarks。
            return CmnEndpoints.BuildCorsAllowedOrigins();
        }

        /// <summary>許可オリジンを作る（#266）</summary>
        /// <returns>オリジンの一覧（重複なし）</returns>
        /// <remarks>
        /// **3 つを合わせる。** **登録（構成ファイル）→ 登録（画面）→ 設定の追加分**の順。
        /// </remarks>
        private static List<string> BuildCorsAllowedOrigins()
        {
            List<string> origins = new List<string>();

            // 1. 登録から導く（構成ファイル ＋ 画面）。
            List<string> registeredAll = Helper.GetInstance().GetConfigClientsPublicRedirectUris();
            registeredAll.AddRange(Helper.GetInstance().GetStoredClientsPublicRedirectUris());

            foreach (string registered in registeredAll)
            {
                // **`web_origins` は複数書ける**（#266）ので、区切って 1 つずつ解決する。
                //   `redirect_uri_*` は 1 つだけなので、分けても 1 件のまま。
                foreach (string value in registered.Split(
                    new char[] { ' ', ',', '	' }, StringSplitOptions.RemoveEmptyEntries))
                {
                    // 定数値（test_self_code など）は実 URL に変換する。
                    string origin = CmnEndpoints.ToOrigin(
                        CmnEndpoints.GetRedirectUriFromConstr(value.Trim()));

                    if (!string.IsNullOrEmpty(origin)
                        && !origins.Contains(origin))
                    {
                        origins.Add(origin);
                    }
                }
            }

            // 2. 追加分（設定）。
            string extra = Config.CorsAllowedOrigins;

            if (!string.IsNullOrEmpty(extra))
            {
                foreach (string value in extra.Split(
                    new char[] { ' ', ',', '	' }, StringSplitOptions.RemoveEmptyEntries))
                {
                    string origin = CmnEndpoints.ToOrigin(value.Trim());

                    if (!string.IsNullOrEmpty(origin)
                        && !origins.Contains(origin))
                    {
                        origins.Add(origin);
                    }
                }
            }

            return origins;
        }

        /// <summary>URL をオリジン（scheme://host[:port]）にする（#265）</summary>
        /// <param name="url">URL（またはオリジン）</param>
        /// <returns>オリジン（`http` / `https` でなければ空）</returns>
        /// <remarks>
        /// **`http` / `https` だけを受ける。**
        /// **カスタム スキームと `*` は空を返す**（ブラウザのオリジンにならないため）。
        /// **既定のポートは付けない**（`Uri` の規則どおり。CORS の比較はヘッダの文字列同士）。
        /// </remarks>
        private static string ToOrigin(string url)
        {
            if (string.IsNullOrEmpty(url))
            {
                return "";
            }

            if (!Uri.TryCreate(url, UriKind.Absolute, out Uri uri))
            {
                return "";
            }

            if (uri.Scheme != Uri.UriSchemeHttp
                && uri.Scheme != Uri.UriSchemeHttps)
            {
                return "";
            }

            // GetLeftPart(Authority) は、既定のポートを省いた「scheme://host[:port]」を返す。
            return uri.GetLeftPart(UriPartial.Authority);
        }

        #endregion

        #region エラー応答（HTTP ステータス・WWW-Authenticate）

        /// <summary>エラー応答の HTTP ステータスを決める（RFC 6749 5.2 / RFC 6750 3.1）</summary>
        /// <param name="err">error / error_description を持つ辞書</param>
        /// <returns>HTTP ステータス（invalid_client / invalid_token は 401、それ以外は 400）</returns>
        /// <remarks>
        /// **表は Open棟梁 の `OAuth2AndOIDCSpec.GetErrorStatusCode` が持つ**（#294）。
        /// ここは**辞書から `error` を取り出すだけ**である。
        /// 実際の応答（IActionResult / IHttpActionResult）は、フレームワークごとに各アプリで作る。
        /// </remarks>
        public static int GetErrorStatusCode(Dictionary<string, string> err)
        {
            return OAuth2AndOIDCSpec.GetErrorStatusCode(CmnEndpoints.ErrorOf(err));
        }

        /// <summary>保護されたリソースのエラー応答の HTTP ステータス（#311 の段階 4）</summary>
        /// <param name="err">error / error_description を持つ辞書</param>
        /// <returns>HTTP ステータス</returns>
        /// <remarks>
        /// **`use_dpop_nonce` は、口によって状態が違う**（RFC 9449。`/token` は 400、リソースは 401）。
        /// **表は Open棟梁 の `OAuth2AndOIDCSpec.GetResourceErrorStatusCode` が持つ**（#294）。
        /// </remarks>
        public static int GetResourceErrorStatusCode(Dictionary<string, string> err)
        {
            return OAuth2AndOIDCSpec.GetResourceErrorStatusCode(CmnEndpoints.ErrorOf(err));
        }

        /// <summary>チャレンジの中身を作る（RFC 6750 §3 / RFC 9449 §7.1）</summary>
        /// <param name="scheme">`AuthenticationHeader.GetChallengeScheme` が返したスキーム</param>
        /// <param name="realm">realm（保護資源の名前）</param>
        /// <param name="err">error / error_description を持つ辞書（トークンが無かった場合は空）</param>
        /// <returns>スキーム名より後ろ</returns>
        /// <remarks>
        /// **組み立ては Open棟梁 の `AuthenticationHeader.CreateChallengeParameter` が行う**（#294）。
        /// ここで決めるのは、**`DPoP` のときに示す `algs`**（§7.1。**証明の署名に使える alg**）で、
        /// **Discovery の `dpop_signing_alg_values_supported` と同じ一覧**を渡す。
        /// </remarks>
        public static string GetChallengeParameter(
            string scheme, string realm, Dictionary<string, string> err)
        {
            string errorDescription = null;

            if (err != null)
            {
                err.TryGetValue(OAuth2AndOIDCConst.error_description, out errorDescription);
            }

            return AuthenticationHeader.CreateChallengeParameter(
                scheme, realm, CmnEndpoints.ErrorOf(err), errorDescription, JwsFactory.SupportedAlgs);
        }

        /// <summary>辞書から error を取り出す</summary>
        /// <param name="err">error / error_description を持つ辞書</param>
        /// <returns>error（無ければ null）</returns>
        private static string ErrorOf(Dictionary<string, string> err)
        {
            string error = null;

            if (err != null)
            {
                err.TryGetValue(OAuth2AndOIDCConst.error, out error);
            }

            return error;
        }

        #endregion

        #endregion

        #endregion
    }
}