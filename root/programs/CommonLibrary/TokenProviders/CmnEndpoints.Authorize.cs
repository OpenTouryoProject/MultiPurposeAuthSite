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
//* クラス日本語名  ：CmnEndpoints（ライブラリ）の 認可エンドポイント（要求の検証）
//*
//* 作成日時        ：－
//* 作成者          ：－
//* 更新履歴        ：－
//*
//*  日時        更新者            内容
//*  ----------  ----------------  -------------------------------------------------
//*  2026/10/29  玄人 幸道         新規（CmnEndpoints.cs から partial に分割。#294）
//*  2026/10/29  玄人 幸道         CheckAuthTime の記述を実装に合わせ、using を整理した（#294）
//**********************************************************************************

using MultiPurposeAuthSite.Co;
using MultiPurposeAuthSite.Extensions.Sts;

using System;
using System.Linq;
using System.Collections.Generic;

using Touryo.Infrastructure.Framework.Authentication;
using Touryo.Infrastructure.Public.Str;

namespace MultiPurposeAuthSite.TokenProviders
{
    /// <summary>CmnEndpoints（認可エンドポイント（要求の検証））</summary>
    public partial class CmnEndpoints
    {
        #region AuthZ(N)Endpoint

        #region auth_time（max_age。#247）

        /// <summary>再認証の印（Cookie）を有効とみなす長さ（秒）</summary>
        /// <remarks>
        /// **繰り返しを防ぐ最後の砦。** 主たる判定は秒単位の比較（`OAuth2AndOIDCSpec.CheckAuthTime`）で、
        /// **印はそれでも収束しない場合のための保険**である。
        /// **人がサインインを終えるまでの時間**を見込んで 10 分。
        /// </remarks>
        private const int ReAuthenticationMarkerLifetimeSeconds = 600;

        /// <summary>max_age と auth_time を照合する（#247）</summary>
        /// <param name="max_age">要求の max_age（空なら判定しない）</param>
        /// <param name="authTime">前回の認証時刻（Cookie の auth_time。W3C 形式）</param>
        /// <param name="reAuthenticatedAt">再認証を求めた時刻（Cookie。W3C 形式。無ければ空）</param>
        /// <returns>判定</returns>
        /// <remarks>
        /// **判定だけを行う。** Cookie の読み書きとリダイレクトは呼び出し側（Controller）に残す。
        /// **両アプリに同文で在った `CheckAuthTime` を、結果で場合分けできる形にして寄せた。**
        ///
        /// **なぜ bool ではないか。** 以前は bool で、false のときに
        /// **再認証もエラー応答もせず、文面の無いエラー画面**になっていた（`ANALYSIS-IdP.md` の A-12）。
        /// 仕様は次の 3 つを求めており、**bool では区別できない。**
        ///
        /// | 状況 | あるべき応答 | 根拠 |
        /// |---|---|---|
        /// | max_age を超えている | **再認証する** | OIDC Core 3.1.2.1 |
        /// | 同上 かつ prompt=none | `login_required` | OIDC Core 3.1.2.6 |
        /// | max_age が数値でない | `invalid_request` | RFC 6749 4.1.2.1 |
        ///
        /// **`reAuthenticatedAt` は繰り返しを防ぐための印。**
        /// `max_age=0` は「毎回再認証」を意味するが、再認証の直後でも
        /// 経過時間は 0 より大きくなるため、印が無いと延々と送り返すことになる。
        /// **印が新しければ（求めてから `ReAuthenticationMarkerLifetimeSeconds` 以内）、一度は再認証したと見て続ける。**
        /// **`auth_time` と印の時刻は比べていない** — **印を残すとき、Controller はサインアウトさせる**ので、
        /// 印が在って、なおサインインしているなら、その間に認証し直している（#294 で記述を実装に合わせた）。
        /// </remarks>
        public static OAuth2AndOIDCEnum.AuthTimeCheck CheckAuthTime(string max_age, string authTime, string reAuthenticatedAt)
        {
            //  **照合（max_age の形・秒単位の比較）は Open棟梁 の `OAuth2AndOIDCSpec.CheckAuthTime`**（#294）。
            //    **秒で比べるのが要**である（小数で比べると、`max_age=0` では再認証の直後も超過になる）。
            OAuth2AndOIDCEnum.AuthTimeCheck ret =
                OAuth2AndOIDCSpec.CheckAuthTime(max_age, CmnEndpoints.FromW3c(authTime));

            if (ret != OAuth2AndOIDCEnum.AuthTimeCheck.NeedsReAuthentication)
            {
                return ret;
            }

            // **印（一度求めた証）が在って、それが古すぎなければ通す**（繰り返しの最後の砦）。
            //   **この印だけに頼らない。** 上の「秒単位の比較」で、たいていの場合はここまで来ない。
            //   印は**サインインの往復で失われることがある**ため（実測）、
            //   **主たる判定は上の秒単位の比較**に置く。
            DateTime? askedAt = CmnEndpoints.FromW3c(reAuthenticatedAt);

            if (askedAt != null
                && (DateTime.UtcNow - (DateTime)askedAt).TotalSeconds
                    <= CmnEndpoints.ReAuthenticationMarkerLifetimeSeconds)
            {
                return OAuth2AndOIDCEnum.AuthTimeCheck.Ok;
            }

            return ret;
        }

        /// <summary>W3C 形式の時刻を読む（読めなければ null）</summary>
        /// <param name="value">W3C 形式の時刻</param>
        /// <returns>DateTime（読めなければ null）</returns>
        private static DateTime? FromW3c(string value)
        {
            if (string.IsNullOrEmpty(value))
            {
                return null;
            }

            try
            {
                //  **UTC として読む**（W3C 形式の末尾の `Z` を落として読むので、種別が不定になる）。
                //    **不定のまま渡すと、`OAuth2AndOIDCSpec.CheckAuthTime` が現地時刻とみなして UTC へずらす。**
                return DateTime.SpecifyKind(FormatConverter.FromW3cTimestamp(value), DateTimeKind.Utc);
            }
            catch
            {
                // Cookie が壊れている・形式が違う。**例外にしない**（#241 と同じ方針）。
                return null;
            }
        }

        #endregion

        #region ValidateAuthZReqParam

        /// <summary>ValidateAuthZReqParam</summary>
        /// <param name="client_id">string</param>
        /// <param name="redirect_uri">string</param>
        /// <param name="response_type">string</param>
        /// <param name="scope">string</param>
        /// <param name="nonce">string</param>
        /// <param name="valid_redirect_uri">string</param>
        /// <param name="err">string</param>
        /// <param name="errDescription">string</param>
        /// <param name="code_challenge">string</param>
        /// <param name="prompt">string</param>
        /// <returns>成功 or 失敗</returns>
        /// <remarks>
        /// **エラーは、返せるなら RP へリダイレクトで返す**（RFC 6749 4.1.2.1。#187 の残り）。
        /// 画面で止めると、RP からは何が起きたのか分からない。
        ///
        /// 判定そのもの（順序・エラー コード）は ValidateAuthZReqParamCore のまま変えない。
        /// ここで足すのは、**失敗したときの返し先**だけ。
        ///
        /// code_challenge は、Config.RequirePkce が true のときだけ見る（#220）。
        /// 既定（false）では、渡さなくても従来どおり動く。
        /// </remarks>
        public static bool ValidateAuthZReqParam(string client_id, string redirect_uri,
            ref string response_type, string scope, string nonce,
            out string valid_redirect_uri, out string err, out string errDescription,
            string code_challenge = "", string prompt = "")
        {
            // **response_type を正規化する**（#267）。**ここで 1 回だけ掛ける。**
            //   **`ref` で受けているので、呼び出し元の変数も正規化された値になる。**
            //   そのため、**この後ろの照合（検証・redirect_uri の選択・応答の振り分け）は、
            //   完全一致のままで正しくなる。**
            //   **`ref` にしたのは、呼び出し元を取りこぼさないため**
            //   （コンパイラが全ての呼び出し元に `ref` を書かせる）。
            response_type = OAuth2AndOIDCSpec.NormalizeResponseType(response_type);

            bool isValid = CmnEndpoints.ValidateAuthZReqParamCore(
                client_id, redirect_uri, response_type, scope, nonce,
                out valid_redirect_uri, out err, out errDescription, code_challenge, prompt);

            if (!isValid && string.IsNullOrEmpty(valid_redirect_uri))
            {
                // **response_type の誤りなど、redirect_uri を確かめる前に失敗した場合。**
                //   返してよい先かどうかは ResolveErrorRedirectUri が確かめる
                //   （登録と一致しなければ空。その場合は、呼び出し元が画面で知らせる）。
                valid_redirect_uri = CmnEndpoints.ResolveErrorRedirectUri(
                    redirect_uri, client_id, response_type);
            }

            return isValid;
        }

        /// <summary>ValidateAuthZReqParam</summary>
        /// <param name="grant_type">string</param>
        /// <param name="client_id">string</param>
        /// <param name="redirect_uri">string</param>
        /// <param name="response_type">string</param>
        /// <param name="scope">string</param>
        /// <param name="nonce">string</param>
        /// <param name="valid_redirect_uri">string</param>
        /// <param name="err">string</param>
        /// <param name="errDescription">string</param>
        /// <param name="code_challenge">string</param>
        /// <returns>成功 or 失敗</returns>
        private static bool ValidateAuthZReqParamCore(string client_id, string redirect_uri,
            string response_type, string scope, string nonce,
            out string valid_redirect_uri, out string err, out string errDescription,
            string code_challenge, string prompt)
        {
            valid_redirect_uri = "";
            // 各分岐で上書きする。ここは想定外のケースの既定値（#187）。
            err = OAuth2AndOIDCConst.server_error;
            errDescription = "";

            #region client_id

            // client_idチェック
            if (string.IsNullOrEmpty(client_id))
            {
                err = OAuth2AndOIDCConst.invalid_request;
                errDescription = Resources.ApplicationOAuthBearerTokenProvider.client_id_NotSett;
                return false;
            }
            else
            {
                string clientName = Helper.GetInstance().GetClientName(client_id);

                if (string.IsNullOrEmpty(clientName))
                {
                    err = OAuth2AndOIDCConst.unauthorized_client;
                    errDescription = Resources.ApplicationOAuthBearerTokenProvider.Invalid_client_id;
                    return false;
                }
            }

            #endregion

            #region response_type

            // response_typeチェック
            //   **フロント チャネルで返すものごとに、グラント種別の設定を見る**（#314）。
            //
            //   | 含む要素 | 要る設定 |
            //   |---|---|
            //   | `code` | `EnableAuthorizationCodeGrantType` |
            //   | `token`（access_token をフロント チャネルで返す） | `EnableImplicitGrantType` |
            //
            //   **Hybrid / OIDC の Implicit（`code token` / `id_token token` など）も対象**である。
            //   以前は `code` / `token` 単独のときだけ見ており、**`EnableImplicitGrantType` を false にしても、
            //   Hybrid で access_token をフロント チャネルに返していた。**
            if (!string.IsNullOrEmpty(response_type))
            {
                string rt = response_type.ToLower();

                bool isOAuth2 = rt == OAuth2AndOIDCConst.AuthorizationCodeResponseType
                    || rt == OAuth2AndOIDCConst.ImplicitResponseType;

                bool isOidc = rt == OAuth2AndOIDCConst.OidcImplicit1_ResponseType
                    || rt == OAuth2AndOIDCConst.OidcImplicit2_ResponseType
                    || rt == OAuth2AndOIDCConst.OidcHybrid2_IdToken_ResponseType
                    || rt == OAuth2AndOIDCConst.OidcHybrid2_Token_ResponseType
                    || rt == OAuth2AndOIDCConst.OidcHybrid3_ResponseType;

                if (!isOAuth2 && !isOidc)
                {
                    err = OAuth2AndOIDCConst.unsupported_response_type;
                    errDescription = "This response_type is unknown.";
                    return false;
                }

                string[] types = OAuth2AndOIDCSpec.SplitSpaceDelimited(rt);

                if (types.Contains(OAuth2AndOIDCConst.AuthorizationCodeResponseType)
                    && !Config.EnableAuthorizationCodeGrantType)
                {
                    err = OAuth2AndOIDCConst.unsupported_response_type;
                    errDescription = Resources.ApplicationOAuthBearerTokenProvider.EnableAuthorizationCodeGrantType;
                    return false;
                }

                if (types.Contains(OAuth2AndOIDCConst.ImplicitResponseType)
                    && !Config.EnableImplicitGrantType)
                {
                    err = OAuth2AndOIDCConst.unsupported_response_type;
                    errDescription = Resources.ApplicationOAuthBearerTokenProvider.EnableImplicitGrantType;
                    return false;
                }

                // OIDCチェック１（`code` / `token` 単独以外は、OIDC の response_type）
                if (isOidc && !scope.Split(' ').Any(x => x == OAuth2AndOIDCConst.Scope_Openid))
                {
                    err = OAuth2AndOIDCConst.invalid_request;
                    errDescription = string.Format(
                        "This response_type is required {0} value in scope param.",
                        OAuth2AndOIDCConst.Scope_Openid);

                    return false;
                }
            }
            else
            {
                err = OAuth2AndOIDCConst.invalid_request;
                errDescription = "response_type is empty.";
                return false;
            }

            // 関数化して移動（valid_redirect_uri早期入手のため）
            if (CmnEndpoints.CheckRedirectUri(
                redirect_uri, client_id, response_type,
                out valid_redirect_uri, ref err, ref errDescription))
            {
                #region 登録の response_types（#307 の段階 1）

                // **登録で許された `response_type` か**（RFC 7591 §2 の `response_types`）。
                //   **`ClientModePolicy` の手前に 1 段置く** —
                //   **登録が「`code` だけ」と言っているのに認可サーバが他も通すのでは、**
                //   **登録の意味が無い。**
                //   **登録が無ければ絞らない**（既存の登録を壊さないため。#198 と同じ倒し方）。
                //   ※ redirect_uri を確かめた後に置く。エラーを RP へ返せるようにするため（#187）。
                if (!CmnEndpoints.CheckClientResponseType(client_id, response_type))
                {
                    err = OAuth2AndOIDCConst.unauthorized_client;
                    errDescription = "This response_type is not registered for this client.";
                    return false;
                }

                #endregion

                #region 登録種別（#224 の段階 2）

                // **この response_type の経路を、登録種別で使えるか。**
                //   以前は、利用者がログイン・同意した後（トークンを作る時点）で初めて拒否していた。
                //   ここでは証明（client_secret / PKCE など）がまだ分からないので、
                //   「何かの証明で使えるか」（ClientModePolicy.MayUse）で見る。最終の判定は従来どおりトークンの時点。
                //   ※ redirect_uri を確かめた後に置く。エラーを RP へ返せるようにするため（#187）。
                //   RFC 6749 4.1.2.1 / 4.2.2.1 : このクライアントに許されていない要求は unauthorized_client。
                if (!ClientModePolicy.MayUse(
                    Helper.GetInstance().GetClientMode(client_id),
                    CmnEndpoints.GetFlowOfResponseType(response_type)))
                {
                    err = OAuth2AndOIDCConst.unauthorized_client;
                    errDescription = "This client is not allowed to use this response_type.";
                    return false;
                }

                #endregion

                #region code_challenge（PKCE）

                // **OAuth 2.1 は、クライアントの種別によらず PKCE を必須とする（#220）。**
                //   既定（RequirePkce = false）では従来どおり任意。
                //   有効にすると、code を発行する response_type
                //   （code / code id_token / code token / code id_token token）で必須になる。
                //   ※ redirect_uri を確かめた後に置く。エラーを RP へ返せるようにするため（#187）。
                //   ※ Device AuthZ / CIBA はこの口を通らないので、掛からない。
                //
                // **サーバ全体（Config）と、クライアント個別（登録の require_pkce）の OR（#221）。**
                //   サーバは「全クライアント共通の床」、クライアント側は「個別の引き上げ」。
                //   **クライアント側から、サーバが締めているものを緩めることはできない。**
                //   移行では、締められるクライアントから順に true にしていく。
                bool requirePkce = Config.RequirePkce
                    || Helper.GetInstance().GetClientRequirePkce(client_id);

                if (requirePkce
                    && response_type.ToLower().Split(' ').Any(
                        x => x == OAuth2AndOIDCConst.AuthorizationCodeResponseType)
                    && string.IsNullOrEmpty(code_challenge))
                {
                    err = OAuth2AndOIDCConst.invalid_request;
                    errDescription = "code_challenge is required.";
                    return false;
                }

                #endregion

                #region prompt（#272 の段階 1）

                // **`none` を他の値と併記していないか**（OIDC Core §3.1.2.1）。
                //   ※ redirect_uri を確かめた後に置く。エラーを RP へ返せるようにするため（#187）。
                if (!OAuth2AndOIDCSpec.CheckPrompt(prompt, ref err, ref errDescription))
                {
                    return false;
                }

                #endregion

                // OIDCチェック２
                if (scope.Split(' ').Any(x => x == OAuth2AndOIDCConst.Scope_Openid))
                {
                    // redirect_uriパラメタ 必須
                    if (string.IsNullOrEmpty(redirect_uri) 
                        || string.IsNullOrEmpty(valid_redirect_uri))
                    {
                        err = OAuth2AndOIDCConst.invalid_request;
                        errDescription = "OIDC is required the valid redirect_uri.";
                        return false;
                    }

                    // nonceパラメタ
                    // - Authorization Codeフロー（response_type=code）では任意（OIDC Core 3.1.2.1）
                    // - Implicit / Hybridフローでは必須（OIDC Core 3.2.2.1 / 3.3.2.1）
                    if (string.IsNullOrEmpty(nonce))
                    {
                        string _response_type = response_type.ToLower();

                        if (_response_type == OAuth2AndOIDCConst.OidcImplicit1_ResponseType
                            || _response_type == OAuth2AndOIDCConst.OidcImplicit2_ResponseType
                            || _response_type == OAuth2AndOIDCConst.OidcHybrid2_IdToken_ResponseType
                            || _response_type == OAuth2AndOIDCConst.OidcHybrid2_Token_ResponseType
                            || _response_type == OAuth2AndOIDCConst.OidcHybrid3_ResponseType)
                        {
                            err = OAuth2AndOIDCConst.invalid_request;
                            errDescription = "There was no nonce in query.";
                            return false;
                        }
                    }
                }

                return true;
            }

            #endregion

            // 結果を返す。
            return false;
        }

        #endregion

        #region 扱うグラント（#294）

        /// <summary>この配備が扱うグラント（Discovery の `grant_types_supported`）</summary>
        /// <param name="includeDcrPath">
        /// **動的登録のための細い道を含めるか**（Discovery は true、動的登録の検査は false）
        /// </param>
        /// <returns>grant_type の一覧</returns>
        /// <remarks>
        /// **Discovery の広告と、動的クライアント登録で受け付ける `grant_types` が、この一覧を見る**
        /// （**広告しているものだけ登録できる**）。
        ///
        /// **違いは `client_credentials` の 1 件だけ**である（#307 の段階 5-b）。
        /// **`EnableClientCredentialsGrantType` が false でも、動的登録を開けた配備では、
        /// 専用 scope（`client_registration`）のトークンだけは出す**ので、
        /// **口が受け付ける事実を広告に出す**（`includeDcrPath` = true）。
        /// **「その scope しか出ない」ことは、Discovery では表せない**
        /// （**クライアントごとの `scope` の絞りと同じ事情**）ので、文書に書く。
        /// **登録では、その経路を `grant_types` として受け付けない**（`includeDcrPath` = false） —
        /// **登録の口を叩くための道であり、登録したクライアントが使うグラントではない。**
        /// </remarks>
        public static List<string> SupportedGrantTypes(bool includeDcrPath)
        {
            List<string> ret = new List<string>();

            if (Config.EnableAuthorizationCodeGrantType)
            {
                ret.Add(OAuth2AndOIDCConst.AuthorizationCodeGrantType);
            }

            if (Config.EnableImplicitGrantType)
            {
                ret.Add(OAuth2AndOIDCConst.ImplicitGrantType);
            }

            if (Config.EnableResourceOwnerPasswordCredentialsGrantType)
            {
                ret.Add(OAuth2AndOIDCConst.ResourceOwnerPasswordCredentialsGrantType);
            }

            if (Config.EnableClientCredentialsGrantType
                || (includeDcrPath && Config.EnableDynamicClientRegistration))
            {
                ret.Add(OAuth2AndOIDCConst.ClientCredentialsGrantType);
            }

            if (Config.EnableRefreshToken)
            {
                ret.Add(OAuth2AndOIDCConst.RefreshTokenGrantType);
            }

            if (Config.EnableJwtBearerTokenFlowGrantType)
            {
                ret.Add(OAuth2AndOIDCConst.JwtBearerTokenFlowGrantType);
            }

            if (Config.EnableCibaGrantType)
            {
                ret.Add(OAuth2AndOIDCConst.CibaGrantType);
            }

            if (Config.EnableDeviceAuthZGrantType)
            {
                ret.Add(OAuth2AndOIDCConst.DeviceAuthZGrantType);
            }

            return ret;
        }

        #endregion

        #region 受け付ける response_type（#314）

        /// <summary>この配備が受け付ける response_type（Discovery の `response_types_supported`）</summary>
        /// <returns>response_type の一覧（正規化した形）</returns>
        /// <remarks>
        /// **認可要求の検査（`ValidateAuthZReqParam`）と同じ規則**である（#314）。
        /// **Discovery の広告と、動的クライアント登録で受け付ける `response_types` が、この一覧を見る**
        /// （**受け付けないものを広告しない・登録させない**）。
        ///
        /// | 含む要素 | 要る設定 |
        /// |---|---|
        /// | `code` | `EnableAuthorizationCodeGrantType` |
        /// | `token`（access_token をフロント チャネルで返す） | `EnableImplicitGrantType` |
        ///
        /// **`id_token` 単独は広告しない**（従来どおり。受け付けはする）。
        /// </remarks>
        public static List<string> SupportedResponseTypes()
        {
            bool code = Config.EnableAuthorizationCodeGrantType;
            bool token = Config.EnableImplicitGrantType;

            List<string> ret = new List<string>();

            if (code) { ret.Add(OAuth2AndOIDCConst.AuthorizationCodeResponseType); }
            if (token) { ret.Add(OAuth2AndOIDCConst.ImplicitResponseType); }
            if (token) { ret.Add(OAuth2AndOIDCConst.OidcImplicit2_ResponseType); }
            if (code && token) { ret.Add(OAuth2AndOIDCConst.OidcHybrid2_Token_ResponseType); }
            if (code) { ret.Add(OAuth2AndOIDCConst.OidcHybrid2_IdToken_ResponseType); }
            if (code && token) { ret.Add(OAuth2AndOIDCConst.OidcHybrid3_ResponseType); }

            return ret;
        }

        #endregion

        #region GetFlowOfResponseType

        /// <summary>response_type から、ClientModePolicy の経路を引く（#224 の段階 2）</summary>
        /// <param name="response_type">response_type（既知の値であることは確かめ済み）</param>
        /// <returns>経路</returns>
        /// <remarks>
        /// code だけなら認可コード、code を含まなければ Implicit、code と他を含めば Hybrid。
        /// </remarks>
        private static ClientModePolicy.Flow GetFlowOfResponseType(string response_type)
        {
            string[] types = response_type.ToLower().Split(' ');

            if (!types.Any(x => x == OAuth2AndOIDCConst.AuthorizationCodeResponseType))
            {
                return ClientModePolicy.Flow.Implicit;
            }

            return types.Length == 1 ? ClientModePolicy.Flow.AuthorizationCode : ClientModePolicy.Flow.Hybrid;
        }

        #endregion

        #region 登録の grant_types / response_types（#307 の段階 1）

        /// <summary>登録された response_types に、この response_type が入っているか</summary>
        /// <param name="client_id">client_id</param>
        /// <param name="response_type">要求の response_type</param>
        /// <returns>通してよいなら true</returns>
        /// <remarks>
        /// **RFC 7591 §2 の `response_types`。**
        /// **登録が無ければ絞らない**（既存の登録を壊さないため）。
        ///
        /// **比較は「要素の集合」として行う** — **`code id_token` と `id_token code` は同じ**
        /// （OAuth 2.0 Multiple Response Types §4 : 順序は意味を持たない。#254 と同じ扱い）。
        /// </remarks>
        private static bool CheckClientResponseType(string client_id, string response_type)
        {
            List<string> permitted = Helper.GetInstance().GetClientResponseTypes(client_id);

            if (permitted == null)
            {
                // **登録が無い（列が空）** ＝ 絞らない。
                return true;
            }

            foreach (string registered in permitted)
            {
                if (CmnEndpoints.IsSameResponseType(registered, response_type))
                {
                    return true;
                }
            }

            return false;
        }

        /// <summary>2 つの response_type が、同じ組み合わせか</summary>
        /// <param name="a">response_type</param>
        /// <param name="b">response_type</param>
        /// <returns>同じなら true</returns>
        /// <remarks>**空白で切った要素の集合として比べる**（順序は意味を持たない）。</remarks>
        private static bool IsSameResponseType(string a, string b)
        {
            string[] x = (a ?? "").ToLower().Split(
                new char[] { ' ' }, StringSplitOptions.RemoveEmptyEntries);
            string[] y = (b ?? "").ToLower().Split(
                new char[] { ' ' }, StringSplitOptions.RemoveEmptyEntries);

            return x.Length == y.Length && x.All(t => y.Contains(t));
        }

        /// <summary>登録された grant_types に、この経路が入っているか</summary>
        /// <param name="client_id">client_id</param>
        /// <param name="flow">経路</param>
        /// <returns>通してよいなら true</returns>
        /// <remarks>
        /// **RFC 7591 §2 の `grant_types`。**
        /// **`ClientModePolicy` の手前に 1 段置く**（#307 の段階 1）。
        /// **登録が無ければ絞らない**（既存の登録を壊さないため）。
        ///
        /// **`ClientModePolicy` との役割の違い** :
        ///
        /// | | 何を見るか |
        /// |---|---|
        /// | **この関数** | **そのクライアントが、その経路を登録したか**（RP の申告） |
        /// | `ClientModePolicy` | **その登録種別（normal / fapi1 / fapi2…）に、その経路と証明を許すか**（AS の方針） |
        /// </remarks>
        private static bool CheckClientGrantType(string client_id, ClientModePolicy.Flow flow)
        {
            List<string> permitted = Helper.GetInstance().GetClientGrantTypes(client_id);

            if (permitted == null)
            {
                // **登録が無い（列が空）** ＝ 絞らない。
                return true;
            }

            string grantType = CmnEndpoints.GrantTypeOfFlow(flow);

            return grantType == null || permitted.Contains(grantType);
        }

        /// <summary>経路から、RFC 7591 §2 の grant_types の値を引く</summary>
        /// <param name="flow">経路</param>
        /// <returns>grant_type の値（表に無ければ null ＝ 絞らない）</returns>
        /// <remarks>
        /// **認可エンドポイントで発行する経路（Implicit / Hybrid）は `implicit`**
        /// （RFC 7591 §2 : `response_types` の `token` には `grant_types` の `implicit` が対応する）。
        /// **Hybrid は `authorization_code` と `implicit` の両方を要する** ので、
        /// **その 2 つを `response_types` 側で突き合わせる**（この関数は代表の 1 つを返す）。
        /// </remarks>
        private static string GrantTypeOfFlow(ClientModePolicy.Flow flow)
        {
            switch (flow)
            {
                case ClientModePolicy.Flow.AuthorizationCode:
                    return OAuth2AndOIDCConst.AuthorizationCodeGrantType;

                case ClientModePolicy.Flow.Implicit:
                case ClientModePolicy.Flow.Hybrid:
                    return OAuth2AndOIDCConst.ImplicitGrantType;

                case ClientModePolicy.Flow.RefreshToken:
                    return OAuth2AndOIDCConst.RefreshTokenGrantType;

                case ClientModePolicy.Flow.ResourceOwnerPassword:
                    return OAuth2AndOIDCConst.ResourceOwnerPasswordCredentialsGrantType;

                case ClientModePolicy.Flow.ClientCredentials:
                    return OAuth2AndOIDCConst.ClientCredentialsGrantType;

                case ClientModePolicy.Flow.JwtBearer:
                    return OAuth2AndOIDCConst.JwtBearerTokenFlowGrantType;

                case ClientModePolicy.Flow.Ciba:
                    return OAuth2AndOIDCConst.CibaGrantType;

                case ClientModePolicy.Flow.DeviceAuthZ:
                    return OAuth2AndOIDCConst.DeviceAuthZGrantType;

                default:
                    // **表に無い経路は絞らない**（新しい経路を足したときに、黙って塞がないため）。
                    return null;
            }
        }

        #endregion

        #region UsedPkce

        /// <summary>認可要求で PKCE を使ったか（その code に code_challenge が紐づいているか）</summary>
        /// <param name="code">認可コード</param>
        /// <param name="client_id">client_id</param>
        /// <param name="redirect_uri">redirect_uri</param>
        /// <returns>使っていれば true</returns>
        /// <remarks>
        /// **`ReceiveChallenge` は code を消さない**（`remove: false` / `DELETE` はコメント アウト）ので、
        /// 交換の前に引いても、後続の `Receive` に影響しない。
        /// </remarks>
        private static bool UsedPkce(string code, string client_id, string redirect_uri)
        {
            AuthorizationCodeProvider.ReceiveChallenge(
                code, client_id, redirect_uri,
                out string code_challenge_method, out string code_challenge);

            return !string.IsNullOrEmpty(code_challenge_method)
                && !string.IsNullOrEmpty(code_challenge);
        }

        #endregion

        #region VerifyPkce

        /// <summary>PKCE（RFC 7636）の検証（#220）</summary>
        /// <param name="code">認可コード</param>
        /// <param name="client_id">client_id</param>
        /// <param name="redirect_uri">redirect_uri</param>
        /// <param name="code_verifier">code_verifier</param>
        /// <param name="usedS256">S256 で検証できたか</param>
        /// <returns>検証の成否</returns>
        /// <remarks>
        /// **クライアント認証とは別の検証である。** 呼び出し元は、認証の成否と併せて判断する。
        ///
        /// `plain` は保護にならないので、`RequirePkceS256` が true なら受け付けない
        /// （既定は false ＝ 従来どおり受理。OAuth 2.1 / FAPI は S256 のみ）。
        /// </remarks>
        private static bool VerifyPkce(
            string code, string client_id, string redirect_uri,
            string code_verifier, out bool usedS256)
        {
            AuthorizationCodeProvider.ReceiveChallenge(
                code, client_id, redirect_uri,
                out string code_challenge_method, out string code_challenge);

            //  **照合は Open棟梁 の `OAuth2AndOIDCSpec.VerifyPkce`**（#294）。
            //    認可要求で PKCE を使っていない（code_verifier だけ送られた）・未知のメソッドは false。
            //    **plain を受けるかは `RequirePkceS256` で決まる**（設定を読む版）。
            return OAuth2AndOIDCSpec.VerifyPkce(
                code_challenge_method, code_challenge, code_verifier, out usedS256);
        }

        #endregion

        #region ResolveErrorRedirectUri

        /// <summary>エラーをリダイレクトで返してよい redirect_uri を決める（#187）</summary>
        /// <param name="redirect_uri">string</param>
        /// <param name="client_id">string</param>
        /// <param name="response_type">string</param>
        /// <returns>返してよい redirect_uri（無ければ空）</returns>
        /// <remarks>
        /// **成功したときの宛先には使わない。** エラー（error / error_description / state）を
        /// RP に返してよいかだけを決める（RFC 6749 4.1.2.1）。
        ///
        /// **response_type が不明だと、種別ごとの登録（redirect_uri_code / redirect_uri_token）を引けない。**
        /// 返してよいかは「このクライアントに登録された URI か」で決まるので、両方と突き合わせる。
        /// 一致しなければ空を返し、呼び出し元は画面で知らせる（検証していない URI へ飛ばさない）。
        /// </remarks>
        private static string ResolveErrorRedirectUri(
            string redirect_uri, string client_id, string response_type)
        {
            // CheckRedirectUri は ref で受けるが、ここでの失敗は呼び出し元に伝えない
            // （エラーの内容は、元の判定で決まったものを使う）。
            string dummyErr = "";
            string dummyErrDescription = "";

            if (CmnEndpoints.CheckRedirectUri(redirect_uri, client_id, response_type,
                out string uri, ref dummyErr, ref dummyErrDescription))
            {
                return uri;
            }

            foreach (string responseType in new string[] {
                OAuth2AndOIDCConst.AuthorizationCodeResponseType,
                OAuth2AndOIDCConst.ImplicitResponseType })
            {
                if (CmnEndpoints.CheckRedirectUri(redirect_uri, client_id, responseType,
                    out uri, ref dummyErr, ref dummyErrDescription))
                {
                    return uri;
                }
            }

            return "";
        }

        #endregion

        #region CheckRedirectUri
        /// <summary>CheckRedirectUri</summary>
        /// <param name="redirect_uri">string</param>
        /// <param name="client_id">string</param>
        /// <param name="response_type">string</param>
        /// <param name="valid_redirect_uri">string</param>
        /// <param name="err">string</param>
        /// <param name="errDescription">string</param>
        /// <returns>bool</returns>
        private static bool CheckRedirectUri(
            string redirect_uri, string client_id, string response_type,
            out string valid_redirect_uri, ref string err, ref string errDescription)
        {
            valid_redirect_uri = "";

            //  **事前登録は n 件ある**（#306）。**全件を読み、要素ごとに定数値を解決する。**
            //    **登録は空白区切りの 1 つの文字列**（設定ファイルでも DB の列でも同じ形）。
            string[] preRegisteredUris = Helper.GetInstance().GetClientsRedirectUris(client_id, response_type);

            for (int i = 0; i < preRegisteredUris.Length; i++)
            {
                // 定数値は変換する（test_self_code など）。
                preRegisteredUris[i] = CmnEndpoints.GetRedirectUriFromConstr(preRegisteredUris[i]) ?? "";
            }

            // redirect_uriのチェック
            if (string.IsNullOrEmpty(redirect_uri))
            {
                // redirect_uriの指定が無い。

                if (preRegisteredUris.Length == 1)
                {
                    //  **1 件だけ登録されている。** **それを使う**（従来どおり）。
                    valid_redirect_uri = preRegisteredUris[0];
                    return true;
                }
                else if (preRegisteredUris.Length == 0)
                {
                    // 事前登録されていない。
                    err = OAuth2AndOIDCConst.invalid_request;
                    errDescription = Resources.ApplicationOAuthBearerTokenProvider.redirect_uri_NotRegistered;
                    return false;
                }
                else
                {
                    //  **2 件以上登録されている**（#306）。
                    //    **どれを使うべきか決められない**ので、**要求で指定させる。**
                    //    RFC 6749 §3.1.2.3 : **複数登録しているなら、要求に redirect_uri を含めること。**
                    //    **1 件だけの配備では、従来どおり省略できる**（上の分岐）。
                    err = OAuth2AndOIDCConst.invalid_request;
                    errDescription = "redirect_uri is required because multiple redirect_uris are registered.";
                    return false;
                }
            }
            else
            {
                // redirect_uriの指定が有る。

                // **指定された redirect_uri は、必ず登録と突き合わせる。**
                //   **以前は「管理画面の折り返し先なら、登録を確かめずに通す」分岐が在った**（C-10）。
                //   **`IsLockedDownTestEndpoints` の対象外で、本番で閉じられなかった。**
                //   **`test_self_code_manage` を記号にして登録値で表せるようにし、分岐を消した。**
                //   **例外は無い。**
                {
                    // **単純文字列比較**（#263）。**大文字小文字を区別する。**
                    //   RFC 6749 §3.1.2.3 は RFC 3986 §6.2.1（Simple String Comparison）を指しており、
                    //   **正規化せず、1 文字ずつ比べること**を求めている（OIDC Core §3.1.2.1 も exact match）。
                    //   **URI 全体を比べる。** スキームとホストは RFC 3986 では大文字小文字を区別しないが、
                    //   **仕様が「正規化しない比較」と言っているので、そこも揃っていなければ通さない。**
                    //   以前は `ToLower()` 同士で比べていたため、**パスの大文字小文字だけが違う値でも通っていた**
                    //   （`post_logout_redirect_uri` の方は #232 の時点から Ordinal で比べている）。
                    //
                    //  **n 件のときは、どれか 1 つと完全一致すればよい**（#306）。
                    //    **前方一致にはしない。** **登録の 1 本が、別の登録の接頭辞になっていても、
                    //    それぞれ別の値として扱う。**
                    foreach (string preRegisteredUri in preRegisteredUris)
                    {
                        if (string.Equals(redirect_uri, preRegisteredUri, StringComparison.Ordinal))
                        {
                            // 完全一致する場合。
                            valid_redirect_uri = redirect_uri;
                            return true;
                        }
                    }

                    // どれとも完全一致しない場合。
                    err = OAuth2AndOIDCConst.invalid_request;
                    errDescription = Resources.ApplicationOAuthBearerTokenProvider.Invalid_redirect_uri;
                    return false;
                }
            }
        }
        #endregion

        #endregion
    }
}