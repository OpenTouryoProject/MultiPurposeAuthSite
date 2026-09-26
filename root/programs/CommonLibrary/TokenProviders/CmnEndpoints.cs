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
//*  2026/09/11  玄人 幸道         クライアントの登録（scope）でも、発行するスコープを絞る（#198 の後半）
//*  2026/09/11  玄人 幸道         エラー応答の HTTP ステータスを決める GetErrorStatusCode を追加（#196）
//*  2026/09/11  玄人 幸道         #region の配置を整理（ClientAuthentication の下に置いていた #187 / #194 / #196 / #200 の追加分を移動）
//*  2026/09/11  玄人 幸道         Public / Private の region を中身に合わせる（ClientAuthentication を Public へ、Token所有者の確認を private に）
//*  2026/09/11  玄人 幸道         /userinfo の Bearer のエラー（invalid_token は 401、WWW-Authenticate の組み立て）を追加（#196）
//*  2026/09/11  玄人 幸道         /ciba_authz の空のエラー コードを CIBA Core 13 のコードに（unknown_user_id を追加）（#196）
//*  2026/09/13  玄人 幸道         エラー コードを Open棟梁 の定数に寄せる（OpenTouryo #587）
//*  2026/09/17  玄人 幸道         認可エラーを、可能ならリダイレクトで返す（#187 の残り）
//*  2026/09/17  玄人 幸道         /introspect の token_type を RFC 7662 2.2 の意味に直す（#218）
//*  2026/09/17  玄人 幸道         JWT Bearer で、トークン要求の scope を尊重する（#218）
//*  2026/09/17  玄人 幸道         PKCE : client_secret との同時送信を通し、検証を 1 箇所にまとめた（#220）
//*  2026/09/18  玄人 幸道         PKCE : code_challenge の必須化を、認可エンドポイントに追加（#220）
//*  2026/09/18  玄人 幸道         トークンのクレームを、permittedLevel から clientMode に分離（#220）
//*  2026/09/22  玄人 幸道         Device AuthZ グラントでも、登録種別を判定する（#224）
//*  2026/09/22  玄人 幸道         登録種別の判定を、permittedLevel の大小比較から ClientModePolicy の表に置き換える（#224 の段階 1）
//*  2026/09/22  玄人 幸道         登録種別で拒否するときは unauthorized_client。認可エンドポイントと /ciba_authz でも先に判定する。
//*                                使えない refresh_token は発行しない。既知でない登録値は不正として拒否する（#224 の段階 2）
//*  2026/09/24  玄人 幸道         Discovery の誤りを直し、実装済みの項目を広告する（#189 の 2〜8）
//*  2026/09/24  玄人 幸道         code_challenge_methods_supported を設定に合わせ、service_documentation を設定値にする（#228）
//*  2026/09/24  玄人 幸道         Request Object を、認可応答を作った時点で消す（ワンタイム化。#188 の段階 2）
//*  2026/09/24  玄人 幸道         refresh_token のローテーションで、一族（FamilyId）を引き継ぐ（#188 の段階 3）
//*  2026/09/24  玄人 幸道         認可応答に iss を付ける（RFC 9207。#231）
//*  2026/09/24  玄人 幸道         PAR（RFC 9126）のエンドポイントを追加（#229）
//*  2026/09/24  玄人 幸道         CIBA の認証要求を request で直接受け取る（CIBA Core 7.1.1。#233）
//*  2026/09/25  玄人 幸道         CIBA の認証要求の aud を検証する（CIBA Core 7.1.1。#234 の段階 1）
//*  2026/09/25  玄人 幸道         CIBA の認証要求を jti で使い切りにする（#234 の段階 2）
//*  2026/09/25  玄人 幸道         /ciba_authz にクライアント認証を入れる（CIBA Core 7.1。#234 の段階 3）
//*  2026/09/25  玄人 幸道         /ros の処理を、両アプリの Controller から移した（#235）
//*  2026/09/25  玄人 幸道         client_assertion（RFC 7523 2.2）を読む（#238）
//*  2026/09/26  玄人 幸道         refresh_token / ROPC / client_credentials でも非対称の認証を受ける（#239）
//*  2026/09/26  玄人 幸道         JWT でない値・未登録の鍵で 500 にしない（#241）
//*  2026/09/27  玄人 幸道         Basic の資格情報を復号して照合する（RFC 6749 2.3.1。#237）
//**********************************************************************************

using MultiPurposeAuthSite.Co;
#if NETFX
using MultiPurposeAuthSite.Entity;
#else
using MultiPurposeAuthSite;
#endif
using MultiPurposeAuthSite.Data;
using MultiPurposeAuthSite.Util;

using MultiPurposeAuthSite.Password;
using MultiPurposeAuthSite.Log;
using MultiPurposeAuthSite.Extensions.Sts;

using System;
using System.Linq;
using System.Collections.Generic;
using System.Text;
using System.Collections.Specialized;
using System.Security.Claims;
using System.Security.Cryptography.X509Certificates;

#if NETFX
using Microsoft.AspNet.Identity;
#else
using Microsoft.AspNetCore.Identity;
# endif

using Newtonsoft.Json;
using Newtonsoft.Json.Linq;

using Touryo.Infrastructure.Framework.Authentication;
using Touryo.Infrastructure.Public.Str;
using Touryo.Infrastructure.Public.FastReflection;
using Touryo.Infrastructure.Public.Security.Jwt;

namespace MultiPurposeAuthSite.TokenProviders
{
    /// <summary>CmnEndpoints</summary>
    public class CmnEndpoints
    {
        #region .well-known/openid-configuration

        /// <summary>OpenIDConfig</summary>
        /// <returns>Dictionary(string, object)</returns>
        public static Dictionary<string, object> OpenIDConfig()
        {
            Dictionary<string, object> OpenIDConfig = new Dictionary<string, object>();

            #region 基本

            OpenIDConfig.Add("issuer", Config.IssuerId);

            OpenIDConfig.Add("authorization_endpoint",
                Config.OAuth2AuthorizationServerEndpointsRootURI + Config.OAuth2AuthorizeEndpoint);

            OpenIDConfig.Add("token_endpoint",
                Config.OAuth2AuthorizationServerEndpointsRootURI + Config.OAuth2TokenEndpoint);

            OpenIDConfig.Add("userinfo_endpoint",
                Config.OAuth2AuthorizationServerEndpointsRootURI + Config.OAuth2UserInfoEndpoint);

            #endregion

            #region オプション

            List<string> scopes_supported = new List<string>();
            List<string> grant_types_supported = new List<string>();
            List<string> response_types_supported = new List<string>();
            List<string> response_modes_supported = new List<string>();

            OpenIDConfig.Add("scopes_supported", scopes_supported);
            OpenIDConfig.Add("grant_types_supported", grant_types_supported);
            OpenIDConfig.Add("response_types_supported", response_types_supported);
            OpenIDConfig.Add("response_modes_supported", response_modes_supported);

            #region token
            OpenIDConfig.Add("token_endpoint_auth_methods_supported", new List<string> {
                OAuth2AndOIDCEnum.AuthMethods.client_secret_basic.ToStringByEmit(),
                OAuth2AndOIDCEnum.AuthMethods.client_secret_post.ToStringByEmit(),
                OAuth2AndOIDCEnum.AuthMethods.private_key_jwt.ToStringByEmit(),
                OAuth2AndOIDCEnum.AuthMethods.tls_client_auth.ToStringByEmit()
            });

            OpenIDConfig.Add("token_endpoint_auth_signing_alg_values_supported", new List<string> {
                "RS256"
            });
            #endregion

            #region scopes
            // 発行時の絞り込み（Helper.FilterSupportedScopes）と同じ一覧を使う（#198）。
            // openid は OIDC が有効なときだけ含まれる。
            scopes_supported.AddRange(Helper.GetScopesSupported());
            #endregion

            #region grant and response_types
            if (Config.EnableAuthorizationCodeGrantType)
            {
                grant_types_supported.Add(OAuth2AndOIDCConst.AuthorizationCodeGrantType);
                response_types_supported.Add(OAuth2AndOIDCConst.AuthorizationCodeResponseType);
            }

            if (Config.EnableImplicitGrantType)
            {
                grant_types_supported.Add(OAuth2AndOIDCConst.ImplicitGrantType);
                response_types_supported.Add(OAuth2AndOIDCConst.ImplicitResponseType);
            }

            if (Config.EnableResourceOwnerPasswordCredentialsGrantType)
            {
                grant_types_supported.Add(OAuth2AndOIDCConst.ResourceOwnerPasswordCredentialsGrantType);
            }

            if (Config.EnableClientCredentialsGrantType)
            {
                grant_types_supported.Add(OAuth2AndOIDCConst.ClientCredentialsGrantType);
            }

            if (Config.EnableRefreshToken)
            {
                grant_types_supported.Add(OAuth2AndOIDCConst.RefreshTokenGrantType);
            }

            if (Config.EnableJwtBearerTokenFlowGrantType)
            {
                grant_types_supported.Add(OAuth2AndOIDCConst.JwtBearerTokenFlowGrantType);
            }

            if (Config.EnableCibaGrantType)
            {
                grant_types_supported.Add(OAuth2AndOIDCConst.CibaGrantType);
            }

            // **Device Authorization Grant は、広告していなかった**（#189 の 6・7）。
            //   実装済み（/device_authz と device_code のグラント）なのに Discovery から
            //   Config.EnableDeviceAuthZGrantType を一度も見ていなかったため、
            //   RP の自動設定が通らなかった。
            if (Config.EnableDeviceAuthZGrantType)
            {
                grant_types_supported.Add(OAuth2AndOIDCConst.DeviceAuthZGrantType);

                // RFC 8628 §4
                OpenIDConfig.Add("device_authorization_endpoint",
                    Config.OAuth2AuthorizationServerEndpointsRootURI + Config.DeviceAuthZAuthorizeEndpoint);
            }
            #endregion

            #region response_modes
            response_modes_supported.Add(OAuth2AndOIDCEnum.ResponseMode.query.ToStringByEmit());
            response_modes_supported.Add(OAuth2AndOIDCEnum.ResponseMode.fragment.ToStringByEmit());
            response_modes_supported.Add(OAuth2AndOIDCEnum.ResponseMode.form_post.ToStringByEmit());
            #endregion

            #region OpenID Connect

            if (Config.EnableOpenIDConnect)
            {
                // openid は、上の Helper.GetScopesSupported で追加済み（#198）

                #region response_types
                response_types_supported.Add(OAuth2AndOIDCConst.OidcImplicit2_ResponseType);
                response_types_supported.Add(OAuth2AndOIDCConst.OidcHybrid2_Token_ResponseType);
                response_types_supported.Add(OAuth2AndOIDCConst.OidcHybrid2_IdToken_ResponseType);
                response_types_supported.Add(OAuth2AndOIDCConst.OidcHybrid3_ResponseType);
                #endregion

                #region id_token
                OpenIDConfig.Add("id_token_signing_alg_values_supported", new List<string> {
                    "RS256", "ES256"
                });

                // **alg と enc は対で広告する**（OIDC Discovery 1.0 §3。#189 の 5）。
                //   実装は JWE_RsaOaepAesGcm（Open棟梁）で、鍵の暗号化が RSA-OAEP、本文が A256GCM。
                OpenIDConfig.Add("id_token_encryption_alg_values_supported", new List<string> {
                    "RSA-OAEP"
                });

                OpenIDConfig.Add("id_token_encryption_enc_values_supported", new List<string> {
                    "A256GCM"
                });
                #endregion

                #region subject_types
                OpenIDConfig.Add("subject_types_supported", new List<string> {
                    OAuth2AndOIDCEnum.SubjectTypes.uname.ToStringByEmit(),
                    OAuth2AndOIDCEnum.SubjectTypes.@public.ToStringByEmit(),
                    OAuth2AndOIDCEnum.SubjectTypes.pairwise.ToStringByEmit()
                });
                #endregion

                #region claims
                OpenIDConfig.Add("claims_parameter_supported", false); // RequestObjectでのみサポート
                // **profile / address のクレームは、対応付けから作る**（#230）。
                //   固定の一覧にすると「広告しているのに返らない」が起きる（#228 の 13）。
                List<string> claimsSupported = new List<string> {
                    //Jwt
                    OAuth2AndOIDCConst.iss,
                    OAuth2AndOIDCConst.aud,
                    OAuth2AndOIDCConst.sub,
                    OAuth2AndOIDCConst.exp,
                    OAuth2AndOIDCConst.nbf,
                    OAuth2AndOIDCConst.iat,
                    OAuth2AndOIDCConst.jti,
                    // scope
                    // 標準
                    OAuth2AndOIDCConst.Scope_Email,
                    OAuth2AndOIDCConst.email_verified,
                    OAuth2AndOIDCConst.phone_number,
                    OAuth2AndOIDCConst.phone_number_verified,
                    // 拡張
                    OAuth2AndOIDCConst.scopes,
                    OAuth2AndOIDCConst.Scope_Roles,
                    OAuth2AndOIDCConst.Scope_UserID,
                    // OIDC, FAPI1
                    OAuth2AndOIDCConst.nonce,
                    OAuth2AndOIDCConst.at_hash,
                    OAuth2AndOIDCConst.c_hash,
                    OAuth2AndOIDCConst.s_hash //,
                    //OAuth2AndOIDCConst.auth
                };

                claimsSupported.AddRange(UserClaims.GetSupportedClaims());

                OpenIDConfig.Add("claims_supported", claimsSupported);
                #endregion

                #region RequestObject
                OpenIDConfig.Add("request_object_signing_alg_values_supported", new List<string> {
                    "RS256"
                });
                OpenIDConfig.Add("request_parameter_supported", false);
                OpenIDConfig.Add("request_uri_parameter_supported", true);
                OpenIDConfig.Add("request_object_endpoint",
                    Config.OAuth2AuthorizationServerEndpointsRootURI + OAuth2AndOIDCParams.RequestObjectRegUri);

                // **PAR（RFC 9126）の口**（#229）。
                //   request_object_endpoint（独自の /ros）は、後方互換のため残している。
                //   こちらは RFC のとおり、フォーム形式＋クライアント認証で受ける。
                OpenIDConfig.Add("pushed_authorization_request_endpoint",
                    Config.OAuth2AuthorizationServerEndpointsRootURI + OAuth2AndOIDCParams.AuthRequestPushUri);

                // **PAR を必須にはしていない**（RFC 9126 §5。既定は false）。
                OpenIDConfig.Add("require_pushed_authorization_requests", false);
                #endregion

                #region ResponseObject(JARM)
                // 「.」がね...。
                response_modes_supported.Add("query.jwt");
                response_modes_supported.Add("fragment.jwt");
                response_modes_supported.Add("form_post.jwt");

                // **応答の署名アルゴリズムを広告していなかった**（JARM §7。#189 の 8）。
                //   *.jwt の response_mode を出しているのに、RP は何で検証すればよいか分からなかった。
                //   実装は CmnResponseObject の JWS(RS256)。
                OpenIDConfig.Add("authorization_signing_alg_values_supported", new List<string> {
                    "RS256"
                });
                #endregion
            }

            // **認可応答に iss を付けることを広告する**（RFC 9207 §3。#231）
            OpenIDConfig.Add("authorization_response_iss_parameter_supported", true);

            OpenIDConfig.Add("jwks_uri",
                    Config.OAuth2AuthorizationServerEndpointsRootURI + OAuth2AndOIDCParams.JwkSetUri);

            #endregion

            #region OAuth2拡張

            #region Revocation
            OpenIDConfig.Add("revocation_endpoint",
                Config.OAuth2AuthorizationServerEndpointsRootURI + Config.OAuth2RevokeTokenEndpoint);

            OpenIDConfig.Add("revocation_endpoint_auth_methods_supported", new List<string> {
               OAuth2AndOIDCEnum.AuthMethods.client_secret_basic.ToStringByEmit(),
               OAuth2AndOIDCEnum.AuthMethods.client_secret_post.ToStringByEmit()
            });
            #endregion

            #region Introspect
            OpenIDConfig.Add("introspection_endpoint",
                Config.OAuth2AuthorizationServerEndpointsRootURI + Config.OAuth2IntrospectTokenEndpoint);

            OpenIDConfig.Add("introspection_endpoint_auth_methods_supported", new List<string> {
               OAuth2AndOIDCEnum.AuthMethods.client_secret_basic.ToStringByEmit(),
               OAuth2AndOIDCEnum.AuthMethods.client_secret_post.ToStringByEmit()
            });
            #endregion

            #region OAuth PKCE

            // **広告は、実装に合わせる**（#228 の 9）。
            //   plain を受けるかどうかは RequirePkceS256（サーバ全体の設定）だけで決まる。
            //   締めた配置では plain を広告しない。
            //   ※ クライアント単位の require_pkce（#221）は「PKCE を必須にするか」であって、
            //     ここ（対応するメソッド）とは別。Discovery にクライアント別の項目は無い。
            List<string> code_challenge_methods_supported = new List<string>();

            if (!Config.RequirePkceS256)
            {
                code_challenge_methods_supported.Add(OAuth2AndOIDCConst.PKCE_plain);
            }

            code_challenge_methods_supported.Add(OAuth2AndOIDCConst.PKCE_S256);

            OpenIDConfig.Add("code_challenge_methods_supported", code_challenge_methods_supported);

            #endregion

            #endregion

            #region FAPI

            // **RFC 8705 §3.3 の名前は tls_client_certificate_bound_access_tokens、値は boolean**（#189 の 2）。
            //   以前は mutual_tls_sender_constrained_access_tokens（草案の名前）に文字列の "true" を入れていた。
            OpenIDConfig.Add("tls_client_certificate_bound_access_tokens", true);

            #endregion

            #region CIBA

            OpenIDConfig.Add("backchannel_authentication_endpoint",
                Config.OAuth2AuthorizationServerEndpointsRootURI + Config.CibaAuthorizeEndpoint);

            OpenIDConfig.Add("backchannel_token_delivery_modes_supported", new List<string> {
               OAuth2AndOIDCEnum.CibaMode.poll.ToStringByEmit(),
               //OAuth2AndOIDCEnum.CibaMode.ping.ToStringByEmit(),
               //OAuth2AndOIDCEnum.CibaMode.push.ToStringByEmit()
            });

            // FAPI-CIBA プロファイルの
            // RequestObjectの署名は、ES256 と PS256のみ許可
            // ちなみに、Tokenの署名は、FAPI2に準拠する。
            // **配列と boolean で広告する**（CIBA Core §4。#189 の 3・4）。
            //   以前は文字列だったため、素直に読む RP は型で落ちる。
            OpenIDConfig.Add("backchannel_authentication_request_signing_alg_values_supported", new List<string> {
                "ES256"
            });
            OpenIDConfig.Add("backchannel_user_code_parameter_supported", false);

            #endregion

            #region その他
            OpenIDConfig.Add("display_values_supported", new List<string> {
                "page"
            });

            // **プレースホルダを配らない**（#228 の 12）。
            //   任意の項目なので、設定が空なら出さない。
            if (!string.IsNullOrEmpty(Config.ServiceDocumentation))
            {
                OpenIDConfig.Add("service_documentation", Config.ServiceDocumentation);
            }
            #endregion

            #endregion

            return OpenIDConfig;
        }

        #endregion

        #region AuthZ(N)Endpoint

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
            string response_type, string scope, string nonce,
            out string valid_redirect_uri, out string err, out string errDescription,
            string code_challenge = "")
        {
            bool isValid = CmnEndpoints.ValidateAuthZReqParamCore(
                client_id, redirect_uri, response_type, scope, nonce,
                out valid_redirect_uri, out err, out errDescription, code_challenge);

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
            string code_challenge)
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
            if (!string.IsNullOrEmpty(response_type))
            {
                if (response_type.ToLower() == OAuth2AndOIDCConst.AuthorizationCodeResponseType)
                {
                    if (!Config.EnableAuthorizationCodeGrantType)
                    {
                        err = OAuth2AndOIDCConst.unsupported_response_type;
                        errDescription = Resources.ApplicationOAuthBearerTokenProvider.EnableAuthorizationCodeGrantType;
                        return false;
                    }
                }
                else if (response_type.ToLower() == OAuth2AndOIDCConst.ImplicitResponseType)
                {
                    if (!Config.EnableImplicitGrantType)
                    {
                        err = OAuth2AndOIDCConst.unsupported_response_type;
                        errDescription = Resources.ApplicationOAuthBearerTokenProvider.EnableImplicitGrantType;
                        return false;
                    }
                }
                else if (response_type.ToLower() == OAuth2AndOIDCConst.OidcImplicit1_ResponseType
                            || response_type.ToLower() == OAuth2AndOIDCConst.OidcImplicit2_ResponseType
                            || response_type.ToLower() == OAuth2AndOIDCConst.OidcHybrid2_IdToken_ResponseType
                            || response_type.ToLower() == OAuth2AndOIDCConst.OidcHybrid2_Token_ResponseType
                            || response_type.ToLower() == OAuth2AndOIDCConst.OidcHybrid3_ResponseType)
                {
                    // OIDCチェック１
                    if (!scope.Split(' ').Any(x => x == OAuth2AndOIDCConst.Scope_Openid))
                    {
                        // OIDC無効
                        err = OAuth2AndOIDCConst.invalid_request;
                        errDescription = string.Format(
                            "This response_type is required {0} value in scope param.",
                            OAuth2AndOIDCConst.Scope_Openid);

                        return false;
                    }
                }
                else
                {
                    err = OAuth2AndOIDCConst.unsupported_response_type;
                    errDescription = "This response_type is unknown.";
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

                // OIDCチェック２
                if (scope.Split(' ').Any(x => x == OAuth2AndOIDCConst.Scope_Openid))
                {
                    // OIDC有効
                    if (!Config.EnableOpenIDConnect)
                    {
                        err = OAuth2AndOIDCConst.invalid_scope;
                        errDescription = "OIDC is not enabled.";
                        return false;
                    }

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

        #region Basic の資格情報（#237）

        /// <summary>
        /// Authorization ヘッダ（Basic）から資格情報を取り出す（#237）
        /// </summary>
        /// <param name="authHeader">Authorization ヘッダの値</param>
        /// <param name="client_id">client_id</param>
        /// <param name="client_secret">client_secret</param>
        /// <returns>Basic の資格情報があったか</returns>
        /// <remarks>
        /// **RFC 6749 §2.3.1 は、`client_id` と `client_secret` を
        /// `application/x-www-form-urlencoded` で符号化してから Base64 にする**ことを求めている。
        /// 以前は復号しておらず、**仕様に従うクライアントは、記号を含む秘密だと認証できなかった**
        /// （`+` `/` `=` `%` `:` など。特に `:` は分割位置がずれる）。
        ///
        /// **復号後と復号前の両方を受ける。**
        /// 復号後で認証できなければ、復号前の値を返す（**符号化しないクライアントを壊さない**）。
        /// Open棟梁 の既存のクライアントは符号化しない（OpenTouryo #592 で送り側も符号化するようになったが、
        /// 配備済みのものは残る）。
        ///
        /// **英数字だけの値では、どちらも同じ文字列になる**ので、この分岐は効かない。
        ///
        /// ここで照合を試すのは**読むだけ**（設定・ストアの参照）なので、副作用は無い。
        /// **フォーム（`client_secret_post`）の値は復号しない。**
        /// そちらは枠組みが既に復号しており、二重に復号すると壊れる。
        /// </remarks>
        public static bool GetBasicCredentials(
            string authHeader, out string client_id, out string client_secret)
        {
            client_id = "";
            client_secret = "";

            if (!AuthenticationHeader.GetCredentials(authHeader,
                out string decodedId, out string decodedSecret,
                out string rawId, out string rawSecret))
            {
                return false;
            }

            client_id = decodedId;
            client_secret = decodedSecret;

            if (decodedId != rawId || decodedSecret != rawSecret)
            {
                // 符号化されていた（または、符号化しないクライアントが記号を含む値を送った）。
                //   **復号後で認証できなければ、復号前で扱う。**
                X509Certificate2 none = null;

                if (!CmnEndpoints.ClientAuthentication(
                    decodedId, decodedSecret, ref none, out ClientModePolicy.Proof _))
                {
                    client_id = rawId;
                    client_secret = rawSecret;
                }
            }

            return true;
        }

        #endregion

        #region JWT の読み取り（#241）

        /// <summary>JWT の payload を読む（JWT でなければ null）</summary>
        /// <param name="jwt">JWS（コンパクト形式）</param>
        /// <returns>payload（読めなければ null）</returns>
        /// <remarks>
        /// **外から来た文字列を、例外にせず読む**（#241）。
        /// 公開鍵を引くには payload の `iss` が要るので、**署名検証の前に読む**ことになる。
        /// そこで壊れた値を渡されると、以前は処理されない例外で **HTTP 500** になっていた。
        ///
        /// | 渡された値 | 以前 |
        /// |---|---|
        /// | `.` が無い | `Split('.')[1]` が IndexOutOfRangeException |
        /// | Base64URL でない | FormatException |
        /// | JSON がオブジェクトでない | null が返り、呼び先で NullReferenceException |
        ///
        /// **`JObject` で読む**（`Dictionary&lt;string, string&gt;` だと、
        /// 入れ子のクレーム（`cnf` など）で変換に失敗する）。
        /// </remarks>
        public static JObject TryReadJwtPayload(string jwt)
        {
            if (string.IsNullOrEmpty(jwt))
            {
                return null;
            }

            string[] parts = jwt.Split('.');

            if (parts.Length < 2)
            {
                return null;
            }

            try
            {
                return JsonConvert.DeserializeObject(CustomEncode.ByteToString(
                    CustomEncode.FromBase64UrlString(parts[1]), CustomEncode.us_ascii)) as JObject;
            }
            catch
            {
                // Base64URL でない、JSON でない（外から来た値なので、例外にしない）。
                return null;
            }
        }

        /// <summary>登録された公開鍵（Base64URL の JWK）を復号する（無ければ空）</summary>
        /// <param name="base64UrlJwk">登録された値</param>
        /// <returns>JWK の JSON（無ければ空）</returns>
        /// <remarks>
        /// **未登録のクライアントでは空が返る**（#241）。
        /// 以前は空かどうかを確かめる前に復号しており、
        /// `FromBase64UrlString(null)` が NullReferenceException になって **HTTP 500** だった。
        /// </remarks>
        public static string DecodeRegisteredJwk(string base64UrlJwk)
        {
            if (string.IsNullOrEmpty(base64UrlJwk))
            {
                return "";
            }

            try
            {
                return CustomEncode.ByteToString(
                    CustomEncode.FromBase64UrlString(base64UrlJwk), CustomEncode.us_ascii);
            }
            catch
            {
                // 登録の値が壊れている（運用の誤り）。**要求の側の誤りと区別せず、認証失敗にする。**
                return "";
            }
        }

        #endregion

        #region GetClientAssertion

        /// <summary>client_assertion（RFC 7523 §2.2）</summary>
        /// <remarks>Open棟梁 の定数に無いので、ここで定義する（#238）。</remarks>
        public const string ClientAssertion = "client_assertion";

        /// <summary>client_assertion_type（RFC 7523 §2.2）</summary>
        public const string ClientAssertionType = "client_assertion_type";

        /// <summary>client_assertion_type の値（RFC 7523 §2.2）</summary>
        public const string JwtBearerClientAssertionType =
            "urn:ietf:params:oauth:client-assertion-type:jwt-bearer";

        /// <summary>
        /// クライアント認証のアサーションを取り出す（#238）
        /// </summary>
        /// <param name="clientAssertion">client_assertion（RFC 7523 §2.2 の名前）</param>
        /// <param name="clientAssertionType">client_assertion_type</param>
        /// <param name="assertion">assertion（この実装が従来読んでいた名前）</param>
        /// <returns>アサーション（無い・受け付けられないなら空）</returns>
        /// <remarks>
        /// **RFC 7523 §2.2 が定めているのは `client_assertion`**（＋ `client_assertion_type`）。
        /// `assertion` は **JWT Bearer グラント**（§2.1）のパラメタで、別物である。
        /// この実装は 3 つの口（`/token`・`/par`・`/ciba_authz`）で `assertion` を読んでいたため、
        /// **仕様に従うクライアントが private_key_jwt で認証できなかった。**
        ///
        /// **両方を受ける。** `client_assertion` を優先し、無ければ `assertion` も読む
        /// （Open棟梁 の既存のクライアントは `assertion` を送るため。OpenTouryo #592）。
        ///
        /// **`client_assertion_type` が来ていて、値が違うなら受け付けない**（空を返す）。
        /// 呼び先はアサーション無しとして扱い、**クライアント認証の失敗**（`invalid_client`）になる。
        /// </remarks>
        public static string GetClientAssertion(
            string clientAssertion, string clientAssertionType, string assertion)
        {
            if (!string.IsNullOrEmpty(clientAssertion))
            {
                // **型が明示されていれば、確かめる。**
                //   省略されていても受ける（この実装が従来、型を見ていなかったため）。
                if (!string.IsNullOrEmpty(clientAssertionType)
                    && clientAssertionType != CmnEndpoints.JwtBearerClientAssertionType)
                {
                    return "";
                }

                return clientAssertion;
            }

            // 従来の名前（後方互換）
            return assertion ?? "";
        }

        #endregion

        #region RegisterRequestObject

        /// <summary>
        /// Request Object を預かる（`/ros`）（#235）
        /// </summary>
        /// <param name="requestObject">本文に入っていた署名付き JWT</param>
        /// <param name="ret">応答（iss / aud / request_uri / exp）</param>
        /// <returns>預かれたか（false なら 400）</returns>
        /// <remarks>
        /// **両アプリの Controller に同じものが書かれていたので、ここへ移した（#235）。**
        /// **振る舞いは変えていない。** 署名だけを確かめ、**クライアント認証はしない**。
        ///
        /// **この口は RFC 9101（JAR）§5.2.1 が認めている任意機能**
        /// （「認可サーバが、Request Object を POST して request_uri を得る URL を提供してもよい」）。
        /// ただし RFC は中身を規定していないので、**相互運用できる口ではない。**
        /// 新しい RP は `/par`（RFC 9126。クライアント認証とパラメタの検証も行う。#229）を使う。
        ///
        /// CIBA と FAPI2 CC で、署名検証に使う鍵の種類が違う（ES256 / RS256）。
        /// **`client_notification_token` があるかどうかで見分ける**（従来どおり）。
        ///
        /// **応答を組み立てるのは Controller 側**（net48 は HttpResponseMessage、
        /// net10.0 は Created で包む）。ここは中身だけを返す。
        /// </remarks>
        public static bool RegisterRequestObject(string requestObject, out Dictionary<string, object> ret)
        {
            ret = null;

            if (string.IsNullOrEmpty(requestObject))
            {
                return false;
            }

            // 公開鍵取得にissが必要。
            // - issを取り出す。
            //   **JWT でない値を渡されても、例外にしない**（#241）。
            JObject payload = CmnEndpoints.TryReadJwtPayload(requestObject);

            if (payload == null)
            {
                return false;
            }

            string requestObjectString = payload.ToString(Formatting.None);
            string iss = (string)payload[OAuth2AndOIDCConst.iss];
            string pubKey = "";
            bool result = false;

            if (string.IsNullOrEmpty(iss))
            {
                // iss が無ければ、公開鍵を引けない（#241）。
                return false;
            }

            if (payload.ContainsKey(OAuth2AndOIDCConst.client_notification_token))
            {
                // CIBA

                // - 公開鍵取得を取り出す。
                pubKey = CmnEndpoints.DecodeRegisteredJwk(
                    Helper.GetInstance().GetJwkECDsaPublickey(iss));

                // 署名検証
                result = !string.IsNullOrEmpty(pubKey)
                    && RequestObject.VerifyCiba(requestObject, out iss, pubKey);
            }
            else
            {
                // F-API2 CC

                // - 公開鍵取得を取り出す。
                pubKey = CmnEndpoints.DecodeRegisteredJwk(
                    Helper.GetInstance().GetJwkRsaPublickey(iss));

                // 署名検証
                result = !string.IsNullOrEmpty(pubKey)
                    && RequestObject.Verify(requestObject, out iss, pubKey);
            }

            if (!result)
            {
                return false;
            }

            string urn = Guid.NewGuid().ToString("N");

            // RequestObjectの登録
            RequestObjectProvider.Create(urn, requestObjectString);

            // 従来と同じ並びで入れる（**JSON の項目の順序は、RP に対する取り決めではない**。
            //   差分を読みやすくするためだけ）。`exp` は**数値**で返す（文字列にしない）。
            ret = new Dictionary<string, object>()
            {
                { OAuth2AndOIDCConst.iss, Config.IssuerId },
                { OAuth2AndOIDCConst.aud, iss },
                { OAuth2AndOIDCConst.request_uri, OAuth2AndOIDCConst.UrnRequestUriBase + urn },
                // **有効期限を返す**（#188。以前は空文字だった）。
                //   NumericDate（RFC 7519 2章）＝ 秒。**数値で返す**（文字列にしない）。
                { OAuth2AndOIDCConst.exp, DateTimeOffset.Now.Add(
                    Config.RequestObjectExpireTimeSpanFromSeconds).ToUnixTimeSeconds() },
            };

            return true;
        }

        #endregion

        #region PushedAuthorizationRequest（PAR）

        /// <summary>
        /// PAR（RFC 9126）: 認可要求を先に預かり、request_uri を払い出す（#229）
        /// </summary>
        /// <param name="client_id">client_id（フォーム）</param>
        /// <param name="client_secret">client_secret（フォーム。Basic 認証のときは呼び出し元が取り出す）</param>
        /// <param name="assertion">client_assertion（private_key_jwt）</param>
        /// <param name="x509">クライアント証明書（mTLS）</param>
        /// <param name="parameters">フォームのパラメタ（request を含むことがある）</param>
        /// <param name="ret">応答（request_uri / expires_in）</param>
        /// <param name="err">エラー</param>
        /// <returns>成否</returns>
        /// <remarks>
        /// **独自の /ros との違いは、クライアント認証と、要求の検証、応答の形。**
        ///
        /// | | /ros（独自。後方互換で残す） | ここ（RFC 9126） |
        /// |---|---|---|
        /// | 認証 | Request Object の署名だけ | **トークン エンドポイントと同じクライアント認証**（§2） |
        /// | 本文 | 署名付き JWT を生で | **フォーム**（request に JAR を入れてもよい） |
        /// | 応答 | iss / aud / request_uri / exp | **request_uri / expires_in**（§2.2） |
        ///
        /// 有効期限と使い切りは、#188 で入れた RequestObjectProvider の仕組みをそのまま使う。
        /// </remarks>
        public static bool PushedAuthorizationRequest(
            string client_id, string client_secret, string assertion, X509Certificate2 x509,
            NameValueCollection parameters,
            out Dictionary<string, string> ret, out Dictionary<string, string> err)
        {
            ret = null;
            err = new Dictionary<string, string>();

            #region クライアント認証

            bool authned = false;

            if (!string.IsNullOrEmpty(assertion))
            {
                // private_key_jwt
                authned = CmnEndpoints.ClientAuthentication(
                    assertion, out client_id, ref x509, out ClientModePolicy.Proof _);
            }
            else
            {
                // client_secret（basic / post）または mTLS
                authned = CmnEndpoints.ClientAuthentication(
                    client_id, client_secret, ref x509, out ClientModePolicy.Proof _);
            }

            if (!authned)
            {
                // RFC 9126 §2.3 : クライアント認証の失敗は invalid_client（401）
                err.Add(OAuth2AndOIDCConst.error, OAuth2AndOIDCConst.invalid_client);
                err.Add(OAuth2AndOIDCConst.error_description, "Invalid credential.");
                return false;
            }

            #endregion

            #region 預かる中身を決める（request（JAR）か、フォームのパラメタか）

            // **request_uri は受け付けない**（RFC 9126 §2.1）。
            if (!string.IsNullOrEmpty(parameters[OAuth2AndOIDCConst.request_uri]))
            {
                err.Add(OAuth2AndOIDCConst.error, OAuth2AndOIDCConst.invalid_request);
                err.Add(OAuth2AndOIDCConst.error_description, "request_uri is not allowed here.");
                return false;
            }

            JObject payload = null;
            string request = parameters["request"];

            if (!string.IsNullOrEmpty(request))
            {
                // **署名付き Request Object（JAR）。** /ros と同じ鍵で検証する。
                string pubKey = Helper.GetInstance().GetJwkRsaPublickey(client_id);

                if (string.IsNullOrEmpty(pubKey))
                {
                    err.Add(OAuth2AndOIDCConst.error, OAuth2AndOIDCConst.invalid_request);
                    err.Add(OAuth2AndOIDCConst.error_description, "This client has no registered key for the request object.");
                    return false;
                }

                pubKey = CustomEncode.ByteToString(CustomEncode.FromBase64UrlString(pubKey), CustomEncode.us_ascii);

                if (!RequestObject.Verify(request, out string iss, pubKey))
                {
                    err.Add(OAuth2AndOIDCConst.error, "invalid_request_object"); // RFC 9101 §6.3（Open棟梁の定数に無い）
                    err.Add(OAuth2AndOIDCConst.error_description, "The request object is not verified.");
                    return false;
                }

                if (iss != client_id)
                {
                    // **認証したクライアントと、要求の中の iss が食い違う。**
                    err.Add(OAuth2AndOIDCConst.error, "invalid_request_object"); // RFC 9101 §6.3（Open棟梁の定数に無い）
                    err.Add(OAuth2AndOIDCConst.error_description, "The request object was not issued by this client.");
                    return false;
                }

                payload = (JObject)JsonConvert.DeserializeObject(
                    CustomEncode.ByteToString(
                        CustomEncode.FromBase64UrlString(request.Split('.')[1]), CustomEncode.us_ascii));
            }
            else
            {
                // **フォームのパラメタ。** 認可エンドポイントに送るはずの値を、そのまま預かる。
                payload = new JObject();

                foreach (string key in parameters.AllKeys)
                {
                    if (string.IsNullOrEmpty(key)) continue;

                    switch (key)
                    {
                        // クライアント認証の値は預からない（#238 で assertion も対象にした）
                        case OAuth2AndOIDCConst.client_secret:
                        case CmnEndpoints.ClientAssertion:
                        case CmnEndpoints.ClientAssertionType:
                        case OAuth2AndOIDCConst.assertion:
                            break;

                        default:
                            payload[key] = parameters[key];
                            break;
                    }
                }

                // **認証したクライアントの client_id を使う**（フォームの値は上書きする）。
                payload[OAuth2AndOIDCConst.client_id] = client_id;
            }

            #endregion

            #region 認可エンドポイントと同じ検証（RFC 9126 §2.1）

            if (!CmnEndpoints.ValidateAuthZReqParam(
                (string)payload[OAuth2AndOIDCConst.client_id],
                (string)payload[OAuth2AndOIDCConst.redirect_uri],
                (string)payload[OAuth2AndOIDCConst.response_type],
                (string)payload[OAuth2AndOIDCConst.scope] ?? "",
                (string)payload[OAuth2AndOIDCConst.nonce],
                out string _, out string error, out string errorDescription,
                (string)payload[OAuth2AndOIDCConst.code_challenge] ?? ""))
            {
                err.Add(OAuth2AndOIDCConst.error, error);
                err.Add(OAuth2AndOIDCConst.error_description, errorDescription);
                return false;
            }

            #endregion

            #region 預かる

            string urn = Guid.NewGuid().ToString("N");

            RequestObjectProvider.Create(urn, payload.ToString(Formatting.None));

            ret = new Dictionary<string, string>()
            {
                { OAuth2AndOIDCConst.request_uri, OAuth2AndOIDCConst.UrnRequestUriBase + urn },
                { "expires_in", ((int)Config.RequestObjectExpireTimeSpanFromSeconds.TotalSeconds).ToString() }
            };

            return true;

            #endregion
        }

        #endregion

        #region ReceiveCibaRequest

        /// <summary>
        /// CIBA の認証要求を受け取る（#233）
        /// </summary>
        /// <param name="client_id">client_id（client_secret_basic / post）</param>
        /// <param name="client_secret">client_secret（client_secret_basic / post）</param>
        /// <param name="assertion">client_assertion（private_key_jwt）</param>
        /// <param name="x509">クライアント証明書（mTLS）</param>
        /// <param name="request">署名付き JWT（CIBA Core §7.1.1）</param>
        /// <param name="request_uri">/ros に預けたものの参照（独自拡張。後方互換）</param>
        /// <param name="payload">要求の中身</param>
        /// <param name="err">error</param>
        /// <param name="errDescription">error_description</param>
        /// <returns>受け取れたか</returns>
        /// <remarks>
        /// **CIBA Core が定めているのは `request`（署名付き JWT）を直接送る形**（§7.1.1）で、
        /// **`request_uri` にあたる仕組みは無い。**
        /// これまでは `/ros` に預けて `request_uri` を渡す独自の形だけを受け付けており、
        /// 標準の CIBA クライアントからは使えなかった。
        ///
        /// **両方を受け付ける。** `request` があればそちらを使う（下位互換のため `request_uri` も残す）。
        /// `request_uri` の受け口は、`/ros` の廃止（#229 の完了報告を参照）と合わせて外す。
        ///
        /// 署名の検証は、登録された `jwk_ecdsa_publickey` で行う（FAPI-CIBA は ES256）。
        ///
        /// **クライアント認証も、ここで行う**（CIBA Core §7.1 : MUST。#234 の段階 3）。
        /// 以前は署名だけで識別しており、`/token` や `/device_authz` と違って
        /// `ClientAuthentication` を呼んでいなかった。
        /// </remarks>
        public static bool ReceiveCibaRequest(
            string client_id, string client_secret, string assertion, X509Certificate2 x509,
            string request, string request_uri,
            out JObject payload, out string err, out string errDescription)
        {
            payload = null;
            err = OAuth2AndOIDCConst.invalid_request;
            errDescription = "";

            #region クライアント認証（CIBA Core 7.1 : MUST）

            bool authned = false;

            if (!string.IsNullOrEmpty(assertion))
            {
                // private_key_jwt（FAPI-CIBA が求める方式）
                authned = CmnEndpoints.ClientAuthentication(
                    assertion, out client_id, ref x509, out ClientModePolicy.Proof _);
            }
            else
            {
                // client_secret（basic / post）または mTLS
                authned = CmnEndpoints.ClientAuthentication(
                    client_id, client_secret, ref x509, out ClientModePolicy.Proof _);
            }

            if (!authned)
            {
                // CIBA Core 13 : クライアント認証の失敗は invalid_client（401）
                err = OAuth2AndOIDCConst.invalid_client;
                errDescription = "Invalid credential.";
                return false;
            }

            #endregion

            if (!string.IsNullOrEmpty(request))
            {
                // **CIBA Core §7.1.1 : 署名した認証要求を request で受け取る。**
                string json = "";

                try
                {
                    json = CustomEncode.ByteToString(
                        CustomEncode.FromBase64UrlString(request.Split('.')[1]), CustomEncode.us_ascii);
                }
                catch
                {
                    // JWT でない文字列を渡されても、例外にしない（#185 と同じ方針）。
                    errDescription = "The request is not a JWT.";
                    return false;
                }

                JObject unverified = (JObject)JsonConvert.DeserializeObject(json);

                if (unverified == null || unverified[OAuth2AndOIDCConst.iss] == null)
                {
                    errDescription = "The request has no iss.";
                    return false;
                }

                // 署名の検証に使う公開鍵は、登録（iss ＝ client_id）から引く。
                string pubKey = Helper.GetInstance().GetJwkECDsaPublickey(
                    (string)unverified[OAuth2AndOIDCConst.iss]);

                if (string.IsNullOrEmpty(pubKey))
                {
                    // 登録されていないクライアント（CIBA Core 13 : invalid_client）
                    err = OAuth2AndOIDCConst.invalid_client;
                    errDescription = Resources.ApplicationOAuthBearerTokenProvider.Invalid_client_id;
                    return false;
                }

                pubKey = CustomEncode.ByteToString(
                    CustomEncode.FromBase64UrlString(pubKey), CustomEncode.us_ascii);

                if (!RequestObject.VerifyCiba(request, out string _, pubKey))
                {
                    errDescription = "The request is not verified.";
                    return false;
                }

                payload = unverified;
                return CmnEndpoints.VerifyCibaRequestIssuer(
                    client_id, payload, ref err, ref errDescription);
            }

            if (!string.IsNullOrEmpty(request_uri))
            {
                // **独自拡張（後方互換）。** /ros に預けたものを引く。
                string json = RequestObjectProvider.Get(
                    request_uri.Replace(OAuth2AndOIDCConst.UrnRequestUriBase, ""));

                // 存在しない・期限切れの request_uri では空になる（#185 / #188）。
                payload = (JObject)JsonConvert.DeserializeObject(json ?? "");

                if (payload == null)
                {
                    errDescription = "Invalid request_uri.";
                    return false;
                }

                return CmnEndpoints.VerifyCibaRequestIssuer(
                    client_id, payload, ref err, ref errDescription);
            }

            errDescription = "request or request_uri is required.";
            return false;
        }

        #endregion

        /// <summary>使い切りにした CIBA の jti を記録するキーの接頭辞（#234 の段階 2）</summary>
        private const string CibaJtiKeyPrefix = "ciba:jti:";

        #region VerifyCibaRequestIssuer

        /// <summary>認証したクライアントと、要求の iss が同じかを確かめる（#234 の段階 3）</summary>
        /// <param name="client_id">クライアント認証で確かめた client_id</param>
        /// <param name="payload">要求の中身</param>
        /// <param name="err">error</param>
        /// <param name="errDescription">error_description</param>
        /// <returns>同じなら true</returns>
        /// <remarks>
        /// **認証を入れただけでは足りない。**
        /// CIBA Core §7.1.1 は `iss` を「クライアントの client_id」と定めており、
        /// これを確かめないと、**自分の資格情報で認証し、他人の要求を代わりに送れる**。
        /// （要求の署名は、その他人の鍵で正しく検証できてしまう）
        /// </remarks>
        private static bool VerifyCibaRequestIssuer(
            string client_id, JObject payload, ref string err, ref string errDescription)
        {
            if ((string)payload[OAuth2AndOIDCConst.iss] != client_id)
            {
                // CIBA Core 13 : invalid_request
                err = OAuth2AndOIDCConst.invalid_request;
                errDescription = "The iss does not match the authenticated client.";
                return false;
            }

            return true;
        }

        #endregion

        #region ConsumeCibaJti

        /// <summary>CIBA の認証要求を使い切りにする（#234 の段階 2）</summary>
        /// <param name="jti">署名した認証要求の一意な識別子</param>
        /// <returns>まだ使われていなければ true（使ったものとして記録する）</returns>
        /// <remarks>
        /// **記録先は Request Object のストアを使い回す。**
        /// #188 で入れた有効期限（`RequestObjectExpireTimeSpanFromSeconds`。既定 300 秒）と
        /// 掃除がそのまま効き、**新しい表を作らずに済む**（DDL を 3 方言とも変えなくてよい）。
        /// 名前と用途がずれるので、**キーに接頭辞を付けて**、Request Object 本体と混ざらないようにする。
        ///
        /// **保持は、このストアの有効期限まで。**
        /// 要求の `exp` がそれより長いと、記録が消えた後は同じ `jti` を受け付ける。
        /// （既定では、要求の `exp` を 300 秒以内にしておけば隙間は無い）
        ///
        /// **厳密な排他はしていない。** 同じ `jti` の要求が同時に届くと、
        /// 両方が「まだ使われていない」と判定され得る。
        /// 防ぎたいのは繰り返しの再送で、同時到着はそれに当たらない。
        /// </remarks>
        private static bool ConsumeCibaJti(string jti)
        {
            string key = CmnEndpoints.CibaJtiKeyPrefix + jti;

            if (!string.IsNullOrEmpty(RequestObjectProvider.Get(key)))
            {
                // 既に使われている（期限内）。
                return false;
            }

            // **期限切れで読めなくなった行が、まだ残っていることがある**（掃除は間隔を空けて行う）。
            //   そのまま Create すると、DBMS では主キーの重複になる。先に消しておく。
            RequestObjectProvider.Delete(key);
            RequestObjectProvider.Create(key, "used");

            return true;
        }

        #endregion

        #region ValidateAuthZCibaReqParam

        /// <summary>ValidateCibaAuthZReqParam</summary>
        /// <param name="json">JObject</param>
        /// <param name="client_id">string</param>
        /// <param name="scope">string</param>
        /// <param name="client_notification_token">string</param>
        /// <param name="binding_message">string</param>
        /// <param name="user_code">string</param>
        /// <param name="requested_expiry">string</param>
        /// <param name="login_hint">string</param>
        /// <param name="err">string</param>
        /// <param name="errDescription">string</param>
        /// <returns>成功 or 失敗</returns>
        public static bool ValidateCibaAuthZReqParam(
            JObject json, out string client_id, out string scope,
            out string client_notification_token, out string binding_message,
            out string user_code, out string requested_expiry, out string login_hint,
            out string err, out string errDescription)
        {
            #region 定義
            string aud = "";
            string exp = "";
            //string iat = "";
            string nbf = "";
            string jti = "";            
            #endregion

            #region 初期化
            client_id = "";
            scope = "";
            client_notification_token = "";
            binding_message = "";
            user_code = "";
            requested_expiry = "";
            login_hint = "";

            err = OAuth2AndOIDCConst.invalid_request;
            errDescription = "";
            #endregion

            #region 取得 → チェック
            // iss → client_id
            if (!CmnEndpoints.GetCibaClaim(
                json, OAuth2AndOIDCConst.iss,
                out client_id, out err, out errDescription))
            {
                return false;
            }
            else
            {
                string clientName = Helper.GetInstance().GetClientName(client_id);

                if (string.IsNullOrEmpty(clientName))
                {
                    // 登録されていないクライアント（CIBA Core 13 : invalid_client）。以前はコードが空だった（#196）。
                    err = OAuth2AndOIDCConst.invalid_client;
                    errDescription = Resources.ApplicationOAuthBearerTokenProvider.Invalid_client_id;
                    return false;
                }

                // **登録種別で CIBA を使えるか（#224 の段階 2）。**
                //   以前はトークンの時点（GrantCiba）で初めて拒否していたため、
                //   利用者にプッシュ通知が届き、承認させた後で失敗していた。
                //   CIBA Core 13 : このクライアントに許されていない要求は unauthorized_client。
                if (!ClientModePolicy.MayUse(
                    Helper.GetInstance().GetClientMode(client_id), ClientModePolicy.Flow.Ciba))
                {
                    err = OAuth2AndOIDCConst.unauthorized_client;
                    errDescription = "This client is not allowed to use CIBA.";
                    return false;
                }
            }
            // aud
            // **CIBA Core 7.1.1 : aud は OP の Issuer Identifier でなければならない（#234 の段階 1）。**
            //   以前は取り出しも検証もしていなかった（この行はコメントだけだった）。
            //   見ないと、**別の認可サーバ宛てに作られた要求**を、
            //   同じクライアントの鍵が登録されているこの IdP でも受け付けてしまう。
            if (!CmnEndpoints.GetCibaClaim(
                json, OAuth2AndOIDCConst.aud,
                out aud, out err, out errDescription))
            {
                return false;
            }
            else
            {
                if (aud != Config.IssuerId)
                {
                    // CIBA Core 13 : invalid_request
                    err = OAuth2AndOIDCConst.invalid_request;
                    errDescription = "The aud is not the issuer identifier.";
                    return false;
                }
            }
            // exp
            if (!CmnEndpoints.GetCibaClaim(
                    json, OAuth2AndOIDCConst.exp,
                    out exp, out err, out errDescription))
            {
                return false;
            }
            else
            {
                if (!CmnJwtToken.VerifyExp(exp))
                {
                    // CIBA Core 13 : invalid_request。以前はコードが空だった（#196）。
                    err = OAuth2AndOIDCConst.invalid_request;
                    errDescription = "This PAR is expired.";
                    return false;
                }
            }
            // iat
            // nbf
            if (!CmnEndpoints.GetCibaClaim(
                json, OAuth2AndOIDCConst.nbf,
                out nbf, out err, out errDescription))
            {
                return false;
            }
            else
            {
                if (!CmnJwtToken.VerifyNbf(nbf))
                {
                    // CIBA Core 13 : invalid_request。以前はコードが空だった（#196）。
                    err = OAuth2AndOIDCConst.invalid_request;
                    errDescription = "This PAR is before enabled.";
                    return false;
                }
            }
            // jti
            // **同じ要求を二度受け付けない（#234 の段階 2）。**
            //   CIBA Core 7.1.1 は jti を「署名した認証要求の一意な識別子」としている。
            //   見ないと、**同じ要求 JWT を exp まで何度でも送り直せる**（利用者に通知が繰り返し届く）。
            if (!CmnEndpoints.GetCibaClaim(
                json, OAuth2AndOIDCConst.jti,
                out jti, out err, out errDescription))
            {
                return false;
            }
            else
            {
                if (!CmnEndpoints.ConsumeCibaJti(jti))
                {
                    // CIBA Core 13 : invalid_request
                    err = OAuth2AndOIDCConst.invalid_request;
                    errDescription = "The jti was already used.";
                    return false;
                }
            }
            // scope
            if (!CmnEndpoints.GetCibaClaim(
                json, OAuth2AndOIDCConst.scope,
                out scope, out err, out errDescription))
            {
                return false;
            }
            else
            {
                if (!scope.Split(' ').Any(x => x == OAuth2AndOIDCConst.Scope_Openid))
                {
                    // OIDC無効（CIBA Core 13 : invalid_scope）。以前はコードが空だった（#196）。
                    err = OAuth2AndOIDCConst.invalid_scope;
                    errDescription = string.Format(
                        "CIBA is required {0} value in scope param.",
                        OAuth2AndOIDCConst.Scope_Openid);

                    return false;
                }
            }
            // client_notification_token
            if (!CmnEndpoints.GetCibaClaim(
                json, OAuth2AndOIDCConst.client_notification_token,
                out client_notification_token, out err, out errDescription))
            {
                return false;
            }
            // binding_message
            if (!CmnEndpoints.GetCibaClaim(
                json, OAuth2AndOIDCConst.binding_message,
                out binding_message, out err, out errDescription))
            {
                return false;
            }
            // user_code
            CmnEndpoints.GetCibaClaim(
                json, OAuth2AndOIDCConst.user_code,
                out user_code, out err, out errDescription, nullable: true);
            // requested_expiry
            CmnEndpoints.GetCibaClaim(
                json, OAuth2AndOIDCConst.requested_expiry,
                out requested_expiry, out err, out errDescription, nullable: true);
            // login_hint
            if (!CmnEndpoints.GetCibaClaim(
                json, OAuth2AndOIDCConst.login_hint,
                out login_hint, out err, out errDescription))
            {
                return false;
            }

            return true;
        }

        /// <summary>CIBA の認証リクエストのクレームを取り出す（CmnJwtToken.CheckClaims の包み）</summary>
        /// <param name="json">JObject</param>
        /// <param name="key">クレーム名</param>
        /// <param name="value">値</param>
        /// <param name="err">error</param>
        /// <param name="errDescription">error_description</param>
        /// <param name="nullable">省略できるクレームか</param>
        /// <returns>取り出せたか（省略できるクレームが無い場合も true）</returns>
        /// <remarks>
        /// Open棟梁 の CheckClaims は、クレームが無いと server_error を返す。
        /// 要求の不備なので、CIBA Core 13 のとおり invalid_request にする（#196）。
        /// </remarks>
        private static bool GetCibaClaim(JObject json, string key,
            out string value, out string err, out string errDescription, bool nullable = false)
        {
            if (CmnJwtToken.CheckClaims(json, key, out value, out err, out errDescription, nullable))
            {
                return true;
            }

            err = OAuth2AndOIDCConst.invalid_request;
            return false;
        }
        #endregion

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
            usedS256 = false;

            AuthorizationCodeProvider.ReceiveChallenge(
                code, client_id, redirect_uri,
                out string code_challenge_method, out string code_challenge);

            if (string.IsNullOrEmpty(code_challenge_method)
                || string.IsNullOrEmpty(code_challenge))
            {
                // 認可要求で PKCE を使っていない（code_verifier だけ送られた）。
                return false;
            }

            if (code_challenge_method.ToUpper() == OAuth2AndOIDCConst.PKCE_S256)
            {
                usedS256 = (code_challenge
                    == OAuth2AndOIDCClient.PKCE_S256_CodeChallengeMethod(code_verifier));

                return usedS256;
            }

            if (code_challenge_method.ToLower() == OAuth2AndOIDCConst.PKCE_plain)
            {
                if (Config.RequirePkceS256)
                {
                    // plain は受け付けない設定（#220）
                    return false;
                }

                return (code_challenge == code_verifier);
            }

            // 未知のメソッド
            return false;
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

            // redirect_uriのチェック
            if (string.IsNullOrEmpty(redirect_uri))
            {
                // redirect_uriの指定が無い。

                // クライアント識別子に対応する事前登録したredirect_uriを取得する。
                redirect_uri = Helper.GetInstance().GetClientsRedirectUri(client_id, response_type);

                if (!string.IsNullOrEmpty(redirect_uri))
                {
                    // 事前登録されている。
                    // 定数値は変換する。
                    valid_redirect_uri = CmnEndpoints.GetRedirectUriFromConstr(redirect_uri);
                    return true;
                }
                else
                {
                    // 事前登録されていない。
                    err = OAuth2AndOIDCConst.invalid_request;
                    errDescription = Resources.ApplicationOAuthBearerTokenProvider.redirect_uri_NotRegistered;
                    return false;
                }
            }
            else
            {
                // redirect_uriの指定が有る。

                // 指定されたredirect_uriを使用する場合は、チェックが必要になる。
                if (
                    // self_code : Authorization Codeグラント種別
                    redirect_uri == (Config.OAuth2ClientEndpointsRootURI + Config.OAuth2AuthorizationCodeGrantClient_Manage))
                {
                    // 特別に、許可されたredirect_uri
                    valid_redirect_uri = redirect_uri;
                    return true;
                }
                else
                {
                    // クライアント識別子に対応する事前登録したredirect_uri
                    string preRegisteredUri = Helper.GetInstance().GetClientsRedirectUri(client_id, response_type);
                    
                    // 定数値は変換する。
                    preRegisteredUri = CmnEndpoints.GetRedirectUriFromConstr(preRegisteredUri);

                    //if (redirect_uri.StartsWith(preRegisteredUri))
                    if (preRegisteredUri == null) preRegisteredUri = ""; // null対策
                    if (redirect_uri.ToLower() == preRegisteredUri.ToLower()) // LowerCaseに揃える
                    {
                        // 完全一致する場合。
                        valid_redirect_uri = redirect_uri;
                        return true;
                    }
                    else
                    {
                        // 完全一致しない場合。
                        err = OAuth2AndOIDCConst.invalid_request;
                        errDescription = Resources.ApplicationOAuthBearerTokenProvider.Invalid_redirect_uri;
                        return false;
                    }
                }
            }
        }
        #endregion

        #region Create Response

        #region ConsumeRequestObject

        /// <summary>
        /// 認可応答を作り終えた Request Object を消す（ワンタイム化）（#188 の段階 2）
        /// </summary>
        /// <param name="queryString">認可リクエストのクエリ文字列（request_uri が在れば消す）</param>
        /// <remarks>
        /// **1 回の認可の中では、同じ request_uri を何度も読む。**
        /// 同意画面（Controller）、コードの生成（AuthorizationCodeProvider）と続くため、
        /// **最初の読み取りで消すと、その認可自体が壊れる。**
        /// そこで**認可応答を作り終えた時点**（ここ）で消し、
        /// **2 回目の認可要求には使えない**ようにする。
        ///
        /// 消し忘れても期限で無効になる（#188 の段階 1）。ここは**使い回しを断つ**ためのもの。
        /// </remarks>
        private static void ConsumeRequestObject(NameValueCollection queryString)
        {
            if (queryString == null)
            {
                return;
            }

            string request_uri = queryString[OAuth2AndOIDCConst.request_uri];

            if (string.IsNullOrEmpty(request_uri))
            {
                return;
            }

            RequestObjectProvider.Delete(
                request_uri.Replace(OAuth2AndOIDCConst.UrnRequestUriBase, ""));
        }

        #endregion

        #region CreateCodeInAuthZNRes

        /// <summary>CreateCodeInAuthZNRes</summary>
        /// <param name="identity">ClaimsIdentity</param>
        /// <param name="queryString">NameValueCollection</param>
        /// <param name="client_id">string</param>
        /// <param name="state">string</param>
        /// <param name="scopes">string</param>
        /// <param name="claims">JObject</param>
        /// <param name="nonce">string</param>
        /// <returns>code</returns>
        public static string CreateCodeInAuthZNRes(
            ClaimsIdentity identity, NameValueCollection queryString,
            string client_id, string state, IEnumerable<string> scopes, JObject claims, string nonce)
        {
            // ClaimsIdentityに、その他、所定のClaimを追加する。
            // scopes_supported に無いスコープと、クライアントに許されていないスコープは発行しない（#198）
            Helper.AddClaim(identity, client_id, Helper.FilterSupportedScopes(scopes, client_id), claims, nonce);

            // Codeの生成
            string code = AuthorizationCodeProvider.Create(identity, queryString);

            // オペレーション・トレース・ログ出力
            string name = Helper.GetInstance().GetClientName(client_id);
            Logging.MyOperationTrace(string.Format(
                "{0}({1}) passed the authorization endpoint of Hybrid by {2}({3}).",
                client_id, name,                                                        // Client Account
                Helper.GetInstance().GetClientIdByName(identity.Name), identity.Name)); // User Account

            // 使い終わった Request Object を消す（ワンタイム化。#188 の段階 2）
            CmnEndpoints.ConsumeRequestObject(queryString);

            return code;
        }

        #endregion

        #region CreateAuthZRes4ImplicitFlow

        /// <summary>CreateAuthZRes4ImplicitFlow</summary>
        /// <param name="identity">ClaimsIdentity</param>
        /// <param name="queryString">NameValueCollection</param>
        /// <param name="response_type">string</param>
        /// <param name="client_id">string</param>
        /// <param name="state">string</param>
        /// <param name="scopes">IEnumerable(string)</param>
        /// <param name="claims">JObject</param>
        /// <param name="nonce">string</param>
        /// <param name="access_token">out string</param>
        /// <param name="id_token">out string</param>
        public static void CreateAuthZRes4ImplicitFlow(
            ClaimsIdentity identity, NameValueCollection queryString, string response_type,
            string client_id, string state, IEnumerable<string> scopes, JObject claims, string nonce,
            out string access_token, out string id_token)
        {
            string jwkString = "";

            access_token = ""; // 初期化
            id_token = "";     // 初期化

            if (Config.EnableImplicitGrantType)
            {
                #region CheckClientMode

                // このフローが認められるか？
                Dictionary<string, string> err = new Dictionary<string, string>();
                if (CmnEndpoints.CheckClientMode(client_id,
                    ClientModePolicy.Flow.Implicit, ClientModePolicy.Proof.None,
                    out OAuth2AndOIDCEnum.ClientMode _, out jwkString, out err))
                {
                    // 継続可
                }
                else
                {
                    // 継続不可
                    // err設定済み
                    return;
                }

                #endregion

                #region Token発行

                // ClaimsIdentityに、その他、所定のClaimを追加する。
                // scopes_supported に無いスコープと、クライアントに許されていないスコープは発行しない（#198）
                Helper.AddClaim(identity, client_id, Helper.FilterSupportedScopes(scopes, client_id), claims, nonce);

                // AccessTokenの生成
                access_token = CmnAccessToken.CreateFromClaims(
                	client_id, identity.Name, identity.Claims,
                    DateTimeOffset.Now.AddMinutes(Config.OAuth2AccessTokenExpireTimeSpanFromMinutes.TotalMinutes));

                JObject jObj = (JObject)JsonConvert.DeserializeObject(
                    CustomEncode.ByteToString(CustomEncode.FromBase64UrlString(
                        access_token.Split('.')[1]), CustomEncode.us_ascii));

                // id_token
                if (response_type.IndexOf(OAuth2AndOIDCConst.IDToken) != -1)
                {
                    JArray jAry = (JArray)jObj["scopes"];
                    foreach (string s in jAry)
                    {
                        if (s == OAuth2AndOIDCConst.Scope_Openid)
                        {
                            id_token = CmnIdToken.ChangeToIdTokenFromAccessToken(
                                access_token, "", state, // c_hash, は Implicit Flow で生成不可
                                HashClaimType.AtHash | HashClaimType.SHash,
                                Config.RsaPfxFilePath, Config.RsaPfxPassword, jwkString);
                        }
                    }
                }

                // オペレーション・トレース・ログ出力
                string name = Helper.GetInstance().GetClientName(client_id);
                Logging.MyOperationTrace(string.Format(
                    "{0}({1}) passed the authorization endpoint of Hybrid by {2}({3}).",
                    client_id, name,                                                        // Client Account
                    Helper.GetInstance().GetClientIdByName(identity.Name), identity.Name)); // User Account

                // 使い終わった Request Object を消す（ワンタイム化。#188 の段階 2）
                CmnEndpoints.ConsumeRequestObject(queryString);

                #endregion
            }
        }

        #endregion

        #region CreateAuthNRes4HybridFlow

        /// <summary>CreateAuthNRes4HybridFlow</summary>
        /// <param name="identity">ClaimsIdentity</param>
        /// <param name="queryString">NameValueCollection</param>
        /// <param name="client_id">string</param>
        /// <param name="state">string</param>
        /// <param name="scopes">IEnumerable(string)</param>
        /// <param name="claims">JObject</param>
        /// <param name="nonce">string</param>
        /// <param name="access_token">out string</param>
        /// <param name="id_token">out string</param>
        /// <returns></returns>
        public static string CreateAuthNRes4HybridFlow(
            ClaimsIdentity identity, NameValueCollection queryString,
            string client_id, string state, IEnumerable<string> scopes, JObject claims, string nonce,
            out string access_token, out string id_token)
        {
            string code = "";
            string jwkString = "";

            access_token = ""; // 初期化
            id_token = "";     // 初期化

            if (Config.EnableOpenIDConnect)
            {
                #region CheckClientMode

                // ★ 未実装
                // TokenBinding を実装するなら、証明（ClientModePolicy.Proof）の 1 つとして扱う。
                //   いまは証明なし（Proof.None）で判定する（#224）。

                // このフローが認められるか？（経路 × 証明 → ClientModePolicy の表で引く。#224）
                Dictionary<string, string> err = new Dictionary<string, string>();
                if (CmnEndpoints.CheckClientMode(client_id,
                    ClientModePolicy.Flow.Hybrid, ClientModePolicy.Proof.None,
                    out OAuth2AndOIDCEnum.ClientMode clientMode, out jwkString, out err))
                {
                    // 継続可
                }
                else
                {
                    // 継続不可
                    return "";
                }

                #endregion

                #region Token発行

                // ClaimsIdentityに、その他、所定のClaimを追加する。
                // scopes_supported に無いスコープと、クライアントに許されていないスコープは発行しない（#198）
                Helper.AddClaim(identity, client_id, Helper.FilterSupportedScopes(scopes, client_id), claims, nonce);

                // Codeの生成
                code = AuthorizationCodeProvider.Create(identity, queryString);

                string tokenPayload = AuthorizationCodeProvider.GetAccessTokenPayload(code);

                // ★ 必要に応じて、scopeを調整する。

                // access_token
                // **クレームは、登録された種別（clientMode）で書く**（#220）。
                //   経路や証明（ClientModePolicy の表。#224）は、トークンの名乗りには使わない。
                access_token = CmnAccessToken.ProtectFromPayload(
                	client_id, tokenPayload,
                    DateTimeOffset.Now.Add(Config.OAuth2AccessTokenExpireTimeSpanFromMinutes),
                    null, clientMode, out string aud, out string sub);

                // Client認証のclient_idとToken類のaudをチェック
                if (client_id != aud) { throw new Exception("[client_id != aud]"); }

                JObject jObj = (JObject)JsonConvert.DeserializeObject(
                                CustomEncode.ByteToString(CustomEncode.FromBase64UrlString(
                                    access_token.Split('.')[1]), CustomEncode.us_ascii));

                // id_token
                JArray jAry = (JArray)jObj["scopes"];
                foreach (string s in jAry)
                {
                    if (s == OAuth2AndOIDCConst.Scope_Openid)
                    {
                        id_token = CmnIdToken.ChangeToIdTokenFromAccessToken(
                            access_token, code, state, // at_hash, c_hash, s_hash
                            HashClaimType.AtHash | HashClaimType.CHash | HashClaimType.SHash,
                            Config.RsaPfxFilePath, Config.RsaPfxPassword, jwkString);
                    }
                }

                // オペレーション・トレース・ログ出力
                string name = Helper.GetInstance().GetClientName(client_id);
                Logging.MyOperationTrace(string.Format(
                    "{0}({1}) passed the authorization endpoint of Hybrid by {2}({3}).",
                    client_id, name,                                         // Client Account
                    PPIDExtension.GetUserNameFromSub(client_id, sub), sub)); // User Account (PPID化により...)

                // 使い終わった Request Object を消す（ワンタイム化。#188 の段階 2）
                CmnEndpoints.ConsumeRequestObject(queryString);

                #endregion
            }

            return code;
        }

        #endregion

        #endregion

        #endregion

        #region TokenEndpoint

        #region GrantAuthorizationCodeCredentials

        /// <summary>
        /// GrantAuthorizationCodeCredentials
        /// Authorization Codeグラント種別
        /// </summary>
        /// <param name="grant_type">string</param>
        /// <param name="client_id">string</param>
        /// <param name="client_secret">string</param>
        /// <param name="assertion">string</param>
        /// <param name="x509">X509Certificate2</param>
        /// <param name="code">string</param>
        /// <param name="code_verifier">string</param>
        /// <param name="redirect_uri">string</param>
        /// <param name="ret">Dictionary(string, string)</param>
        /// <param name="err">Dictionary(string, string)</param>
        /// <returns>成否</returns>
        public static bool GrantAuthorizationCodeCredentials(
            string grant_type, string client_id, string client_secret,
            string assertion, X509Certificate2 x509,
            string code, string code_verifier, string redirect_uri,
            out Dictionary<string, string> ret, out Dictionary<string, string> err)
        {
            ret = null;

            string jwkString = "";
            err = new Dictionary<string, string>();

            if (Config.EnableAuthorizationCodeGrantType)
            {
                // この要求で、クライアントが何を証明したか（#224）。
                //   以前は水準（permittedLevel）を持ち、登録種別との大小で判定していた。
                //   いまは「経路 × 証明 → 通す登録種別」を ClientModePolicy の表で引く。
                ClientModePolicy.Proof proof = ClientModePolicy.Proof.None;

                #region 認証

                bool authned = false;
                if (grant_type.ToLower() == OAuth2AndOIDCConst.AuthorizationCodeGrantType)
                {
                    if (string.IsNullOrEmpty(code_verifier) && string.IsNullOrEmpty(assertion))
                    {
                        // client_id & (client_secret or x509)
                        authned = CmnEndpoints.ClientAuthentication(
                            client_id, client_secret, ref x509, out proof);
                    }
                    else if (!string.IsNullOrEmpty(code_verifier)
                        && string.IsNullOrEmpty(client_secret))
                    {
                        // パブリック クライアント : PKCE だけで認証する（client_id & code_verifier）
                        authned = CmnEndpoints.VerifyPkce(
                            code, client_id, redirect_uri, code_verifier, out bool usedS256);

                        // S256 か plain か（#224）。通す登録種別は ClientModePolicy の表で決まる。
                        //   以前は S256 のとき水準を fapi1 に格上げしていた。表では
                        //   「認可コード × PKCE S256 → normal / fapi1 / device」の 1 行にあたる。
                        proof = usedS256
                            ? ClientModePolicy.Proof.PkceS256 : ClientModePolicy.Proof.PkcePlain;
                    }
                    else if (!string.IsNullOrEmpty(code_verifier)
                        && !string.IsNullOrEmpty(client_secret))
                    {
                        // **コンフィデンシャル クライアント ＋ PKCE**（client_id & client_secret & code_verifier）（#220）
                        //
                        //   PKCE は当初「client_secret を持てないクライアントの代わり」だったが、
                        //   いまは**種別によらない標準的な防壁**で、client_secret と併用される
                        //   （OAuth 2.1 / 最近の RP ライブラリ）。
                        //   **認証は client_secret、PKCE はそれとは別に検証する。両方が通ること。**
                        //   以前はこの分岐が空実装で、必ず invalid_client になっていた。
                        authned = CmnEndpoints.ClientAuthentication(
                            client_id, client_secret, ref x509, out ClientModePolicy.Proof _);

                        if (authned)
                        {
                            authned = CmnEndpoints.VerifyPkce(
                                code, client_id, redirect_uri, code_verifier, out bool _);
                        }

                        proof = ClientModePolicy.Proof.ClientSecretAndPkce;
                    }
                    else if (!string.IsNullOrEmpty(assertion))
                    {
                        // assertion
                        authned = CmnEndpoints.ClientAuthentication(
                            assertion, out client_id, ref x509, out proof);
                    }
                }

                #endregion

                if (authned)
                {
                    string tokenPayload = AuthorizationCodeProvider.Receive(code, client_id, redirect_uri);

                    #region CheckClientMode

                    // このフローが認められるか？
                    if (CmnEndpoints.CheckClientMode(client_id,
                        ClientModePolicy.Flow.AuthorizationCode, proof,
                        out OAuth2AndOIDCEnum.ClientMode clientMode, out jwkString, out err))
                    {
                        // 継続可
                    }
                    else
                    {
                        // 継続不可
                        // err設定済み
                        return false;
                    }

                    #endregion

                    #region 発行

                    // codeが不正（存在しない・使用済み・別Clientのもの）ならpayloadは空になる（#185）。
                    if (string.IsNullOrEmpty(tokenPayload))
                    {
                        err.Add(OAuth2AndOIDCConst.error, OAuth2AndOIDCConst.invalid_grant);
                        err.Add(OAuth2AndOIDCConst.error_description, "Invalid code.");
                        return false;
                    }

                    // access_token
                    // **クレームは、登録された種別（clientMode）で書く**（#220）。
                    //   経路や証明（ClientModePolicy の表。#224）は、トークンの名乗りには使わない。
                    string access_token = CmnAccessToken.ProtectFromPayload(
                        client_id, tokenPayload,
                        DateTimeOffset.Now.Add(Config.OAuth2AccessTokenExpireTimeSpanFromMinutes),
                        x509, clientMode, out string aud, out string sub);

                    // Client認証のclient_idとToken類のaudをチェック
                    if (client_id != aud)
                    {
                        err.Add(OAuth2AndOIDCConst.error, OAuth2AndOIDCConst.invalid_grant);
                        err.Add(OAuth2AndOIDCConst.error_description, "The code was not issued to this client.");
                        return false;
                    }

                    // refresh_token
                    // **登録種別で refresh_token の経路を使えないなら、発行しない**（#224 の段階 2）。
                    //   以前は発行していたが、使うと必ず拒否された（受け取ったのに使えない資格情報）。
                    string refresh_token = "";
                    if (Config.EnableRefreshToken
                        && ClientModePolicy.MayUse(clientMode, ClientModePolicy.Flow.RefreshToken))
                    {
                        refresh_token = RefreshTokenProvider.Create(tokenPayload);
                    }

                    // オペレーション・トレース・ログ出力
                    string name = Helper.GetInstance().GetClientName(client_id);
                    Logging.MyOperationTrace(string.Format(
                        "{0}({1}) passed the 'Authorization Code flow' by {2}({3}).",
                        client_id, name,                                         // Client Account
                        PPIDExtension.GetUserNameFromSub(client_id, sub), sub)); // User Account (PPID化により...)

                    ret = CmnEndpoints.CreateAccessTokenResponse(access_token, refresh_token, jwkString);

                    return true;

                    #endregion
                }
                else
                {
                    // クライアント認証エラー（Credential不正
                    err.Add(OAuth2AndOIDCConst.error, OAuth2AndOIDCConst.invalid_client);
                    err.Add(OAuth2AndOIDCConst.error_description, "Invalid credential.");
                }
            }
            else
            {
                // サポートされていない
                err.Add(OAuth2AndOIDCConst.error, OAuth2AndOIDCConst.unsupported_grant_type);
                err.Add(OAuth2AndOIDCConst.error_description, Resources.ApplicationOAuthBearerTokenProvider.EnableAuthorizationCodeGrantType);
            }

            return false;
        }

        #endregion

        // 以下は、AuthZAuthNEndpointを参照。
        // GrantImplicitCredentials
        // GrantHybridCredentials

        #region GrantRefreshTokenCredentials

        /// <summary>
        /// GrantRefreshTokenCredentials
        /// Authorization Codeグラント種別
        /// </summary>
        /// <param name="grant_type">string</param>
        /// <param name="client_id">string</param>
        /// <param name="client_secret">string</param>
        /// <param name="x509">X509Certificate2</param>
        /// <param name="refresh_token">string</param>
        /// <param name="ret">Dictionary(string, string)</param>
        /// <param name="err">Dictionary(string, string)</param>
        /// <returns>成否</returns>
        public static bool GrantRefreshTokenCredentials(
            string grant_type, string client_id, string client_secret, string clientAssertion,
            X509Certificate2 x509,
            string refresh_token, out Dictionary<string, string> ret, out Dictionary<string, string> err)
        {
            ret = null;

            string jwkString = "";
            err = new Dictionary<string, string>();

            if (Config.EnableRefreshToken)
            {
                #region 認証

                bool authned = false;
                ClientModePolicy.Proof proof = ClientModePolicy.Proof.None; // 何を証明したか（#224）
                if (grant_type.ToLower() == OAuth2AndOIDCConst.RefreshTokenGrantType)
                {
                    // client_secret / mTLS / private_key_jwt（#239）
                    authned = CmnEndpoints.ClientAuthentication(
                        client_id, client_secret, clientAssertion,
                        ref x509, out client_id, out proof);
                }

                #endregion

                if (authned)
                {
                    #region CheckClientMode

                    // このフローが認められるか？
                    if (CmnEndpoints.CheckClientMode(client_id,
                        ClientModePolicy.Flow.RefreshToken, proof,
                        out OAuth2AndOIDCEnum.ClientMode _, out jwkString, out err))
                    {
                        // 継続可
                    }
                    else
                    {
                        // 継続不可
                        // err設定済み
                        return false;
                    }

                    #endregion

                    #region 発行

                    // **一族（FamilyId）を引き継ぐ**（#188 の段階 3）。
                    //   使用済みが再び提示されたら、Receive の中で一族ごと失効させ、空を返す。
                    string tokenPayload = RefreshTokenProvider.Receive(refresh_token, out string familyId);

                    if (!string.IsNullOrEmpty(tokenPayload))
                    {
                        // access_token
                        string access_token = CmnAccessToken.ProtectFromPayload(
                            client_id, tokenPayload,
                            DateTimeOffset.Now.Add(Config.OAuth2AccessTokenExpireTimeSpanFromMinutes),
                            x509, OAuth2AndOIDCEnum.ClientMode.normal, out string aud, out string sub);

                        // Client認証のclient_idとToken類のaudをチェック
                        if (client_id != aud)
                        {
                            err.Add(OAuth2AndOIDCConst.error, OAuth2AndOIDCConst.invalid_grant);
                            err.Add(OAuth2AndOIDCConst.error_description, "The refresh_token was not issued to this client.");
                            return false;
                        }

                        string new_refresh_token = "";
                        if (Config.EnableRefreshToken)
                        {
                            new_refresh_token = RefreshTokenProvider.Create(tokenPayload, familyId);
                        }

                        // オペレーション・トレース・ログ出力
                        string name = Helper.GetInstance().GetClientName(client_id);
                        Logging.MyOperationTrace(string.Format(
                            "{0}({1}) passed the 'Refresh Token flow' by {2}({3}).",
                            client_id, name,                                         // Client Account
                            PPIDExtension.GetUserNameFromSub(client_id, sub), sub)); // User Account (PPID化により...)

                        ret = CmnEndpoints.CreateAccessTokenResponse(access_token, new_refresh_token, jwkString);

                        return true;
                    }
                    else
                    {
                        // refresh_tokenが不正（ローテーション済み・存在しない）（#185）。
                        err.Add(OAuth2AndOIDCConst.error, OAuth2AndOIDCConst.invalid_grant);
                        err.Add(OAuth2AndOIDCConst.error_description, "Invalid refresh_token.");
                    }

                    #endregion
                }
                else
                {
                    // クライアント認証エラー（Credential不正
                    err.Add(OAuth2AndOIDCConst.error, OAuth2AndOIDCConst.invalid_client);
                    err.Add(OAuth2AndOIDCConst.error_description, "Invalid credential.");
                }
            }
            else
            {
                // サポートされていない
                err.Add(OAuth2AndOIDCConst.error, OAuth2AndOIDCConst.unsupported_grant_type);
                err.Add(OAuth2AndOIDCConst.error_description, Resources.ApplicationOAuthBearerTokenProvider.EnableRefreshToken);
            }

            return false;
        }

        #endregion

        #region GrantResourceOwnerCredentials

        /// <summary>GrantResourceOwnerCredentials</summary>
        /// <param name="grant_type">string</param>
        /// <param name="client_id">string</param>
        /// <param name="client_secret">string</param>
        /// <param name="x509">X509Certificate2</param>
        /// <param name="username">string</param>
        /// <param name="password">string</param>
        /// <param name="scopes">string</param>
        /// <param name="ret">Dictionary(string, string)</param>
        /// <param name="err">Dictionary(string, string)</param>
        /// <returns>成否</returns>
        public static bool GrantResourceOwnerCredentials(
            string grant_type, string client_id,
            string client_secret, string clientAssertion, X509Certificate2 x509,
            string username, string password, string scopes,
            out Dictionary<string, string> ret, out Dictionary<string, string> err)
        {
            ret = null;

            string jwkString = "";
            err = new Dictionary<string, string>();

            if (Config.EnableResourceOwnerPasswordCredentialsGrantType)
            {
                #region 認証

                bool authned = false;
                ClientModePolicy.Proof proof = ClientModePolicy.Proof.None; // 何を証明したか（#224）
                if (grant_type.ToLower() == OAuth2AndOIDCConst.ResourceOwnerPasswordCredentialsGrantType)
                {
                    // client_secret / mTLS / private_key_jwt（#239）
                    authned = CmnEndpoints.ClientAuthentication(
                        client_id, client_secret, clientAssertion,
                        ref x509, out client_id, out proof);
                }

                #endregion

                if (authned)
                {
                    #region CheckClientMode

                    // このフローが認められるか？
                    if (CmnEndpoints.CheckClientMode(client_id,
                        ClientModePolicy.Flow.ResourceOwnerPassword, proof,
                        out OAuth2AndOIDCEnum.ClientMode _, out jwkString, out err))
                    {
                        // 継続可
                    }
                    else
                    {
                        // 継続不可
                        // err設定済み
                        return false;
                    }

                    #endregion

                    #region 発行

                    // username=ユーザ名&password=パスワードとして送付されたクレデンシャルを検証する。
                    ApplicationUser user = CmnUserStore.FindByName(username);

                    if (user != null)
                    {
                        // ユーザーが見つかった場合。
#if NETFX
                        PasswordVerificationResult pvRet = (new CustomPasswordHasher()).VerifyHashedPassword(user.PasswordHash, password);
#else
                        PasswordVerificationResult pvRet = (new CustomPasswordHasher<ApplicationUser>()).VerifyHashedPassword(user, user.PasswordHash, password);
#endif
                        if (pvRet.HasFlag(PasswordVerificationResult.Success))
                        {
                            // ClaimsIdentityにClaimを追加する。
                            ClaimsIdentity identity = new ClaimsIdentity(OAuth2AndOIDCConst.Bearer);

                            // Name Claimを追加
                            identity.AddClaim(new Claim(ClaimTypes.Name, user.UserName));

                            // ClaimsIdentityに、その他、所定のClaimを追加する。
                            // scopes_supported に無いスコープと、クライアントに許されていないスコープは発行しない（#198）
                            identity = Helper.AddClaim(identity, client_id, Helper.FilterSupportedScopes(scopes.Split(' '), client_id), null, "");

                            // access_token
                            string access_token = CmnAccessToken.CreateFromClaims(
                            	client_id, identity.Name, identity.Claims,
                                DateTimeOffset.Now.Add(Config.OAuth2AccessTokenExpireTimeSpanFromMinutes));

                            // オペレーション・トレース・ログ出力
                            string name = Helper.GetInstance().GetClientName(client_id);
                            Logging.MyOperationTrace(string.Format(
                                "{0}({1}) passed the 'resource owner password credentials flow' by {2}({3}).",
                                user.Id, user.UserName, // User Account
                                client_id, name));      // Client Account

                            ret = CmnEndpoints.CreateAccessTokenResponse(access_token, "", jwkString);
                            return true;
                        }
                        else
                        {
                            // パスワードが一致しない場合。
                            err.Add(OAuth2AndOIDCConst.error, OAuth2AndOIDCConst.access_denied);
                            err.Add(OAuth2AndOIDCConst.error_description, Resources.ApplicationOAuthBearerTokenProvider.access_denied);
                        }
                    }
                    else
                    {
                        // ユーザーが見つからない場合。
                        err.Add(OAuth2AndOIDCConst.error, OAuth2AndOIDCConst.access_denied);
                        err.Add(OAuth2AndOIDCConst.error_description, Resources.ApplicationOAuthBearerTokenProvider.access_denied);
                    }

                    #endregion
                }
                else
                {
                    // クライアント認証エラー（Credential不正
                    err.Add(OAuth2AndOIDCConst.error, OAuth2AndOIDCConst.invalid_client);
                    err.Add(OAuth2AndOIDCConst.error_description, "Invalid credential.");
                }
            }
            else
            {
                // サポートされていない
                err.Add(OAuth2AndOIDCConst.error, OAuth2AndOIDCConst.unsupported_grant_type);
                err.Add(OAuth2AndOIDCConst.error_description, Resources.ApplicationOAuthBearerTokenProvider.EnableResourceOwnerCredentialsGrantType);
            }

            return false;
        }

        #endregion

        #region GrantClientCredentials

        /// <summary>
        /// GrantClientCredentials
        /// Client Credentialsグラント種別
        /// </summary>
        /// <param name="grant_type">string</param>
        /// <param name="client_id">string</param>
        /// <param name="client_secret">string</param>
        /// <param name="x509">X509Certificate2</param>
        /// <param name="scopes">string</param>
        /// <param name="ret">Dictionary(string, string)</param>
        /// <param name="err">Dictionary(string, string)</param>
        /// <returns>成否</returns>
        public static bool GrantClientCredentials(
            string grant_type, string client_id, string client_secret, string clientAssertion,
            X509Certificate2 x509,
            string scopes, out Dictionary<string, string> ret, out Dictionary<string, string> err)
        {
            ret = null;

            string jwkString = "";
            err = new Dictionary<string, string>();

            if (Config.EnableClientCredentialsGrantType)
            {
                #region 認証

                bool authned = false;
                ClientModePolicy.Proof proof = ClientModePolicy.Proof.None; // 何を証明したか（#224）
                if (grant_type.ToLower() == OAuth2AndOIDCConst.ClientCredentialsGrantType)
                {
                    // client_secret / mTLS / private_key_jwt（#239）
                    authned = CmnEndpoints.ClientAuthentication(
                        client_id, client_secret, clientAssertion,
                        ref x509, out client_id, out proof);
                }

                #endregion

                if (authned)
                {
                    #region CheckClientMode

                    // このフローが認められるか？
                    if (CmnEndpoints.CheckClientMode(client_id,
                        ClientModePolicy.Flow.ClientCredentials, proof,
                        out OAuth2AndOIDCEnum.ClientMode _, out jwkString, out err))
                    {
                        // 継続可
                    }
                    else
                    {
                        // 継続不可
                        // err設定済み
                        return false;
                    }

                    #endregion

                    #region 発行

                    // client_idに対応するsubを取得する。
                    string sub = Helper.GetInstance().GetClientName(client_id);

                    // ClaimsIdentityにClaimを追加する。
                    ClaimsIdentity identity = new ClaimsIdentity(OAuth2AndOIDCConst.Bearer);

                    // ClaimsIdentityに、その他、所定のClaimを追加する。
                    identity.AddClaim(new Claim(ClaimTypes.Name, sub));
                    // scopes_supported に無いスコープと、クライアントに許されていないスコープは発行しない（#198）
                    identity = Helper.AddClaim(identity, client_id, Helper.FilterSupportedScopes(scopes.Split(' '), client_id), null, "");

                    // access_token
                    string access_token = CmnAccessToken.CreateFromClaims(
                        client_id, identity.Name, identity.Claims,
                        DateTimeOffset.Now.Add(Config.OAuth2AccessTokenExpireTimeSpanFromMinutes));

                    // オペレーション・トレース・ログ出力
                    Logging.MyOperationTrace(string.Format(
                        "Passed the 'client credentials flow' by {0}({1}).",
                        client_id, sub)); // Client Account

                    ret = CmnEndpoints.CreateAccessTokenResponse(access_token, "", jwkString);
                    return true;

                    #endregion
                }
                else
                {
                    // クライアント認証エラー（Credential不正
                    err.Add(OAuth2AndOIDCConst.error, OAuth2AndOIDCConst.invalid_client);
                    err.Add(OAuth2AndOIDCConst.error_description, "Invalid credential.");
                }
            }
            else
            {
                // サポートされていない
                err.Add(OAuth2AndOIDCConst.error, OAuth2AndOIDCConst.unsupported_grant_type);
                err.Add(OAuth2AndOIDCConst.error_description, Resources.ApplicationOAuthBearerTokenProvider.EnableClientCredentialsGrantType);
            }

            return false;
        }

        #endregion

        #region GrantJwtBearerTokenCredentials

        /// <summary>
        /// GrantJwtBearerTokenCredentials
        /// Authorization Codeグラント種別
        /// </summary>
        /// <param name="grant_type">string</param>
        /// <param name="assertion">string</param>
        /// <param name="x509">X509Certificate2</param>
        /// <param name="scope">string（トークン要求の scope。RFC 7521 4.1 / RFC 7523 2.1）</param>
        /// <param name="ret">Dictionary(string, string)</param>
        /// <param name="err">Dictionary(string, string)</param>
        /// <returns>成否</returns>
        public static bool GrantJwtBearerTokenCredentials(
            string grant_type, string assertion, X509Certificate2 x509, string scope,
            out Dictionary<string, string> ret, out Dictionary<string, string> err)
        {
            ret = null;

            string jwkString = "";
            err = new Dictionary<string, string>();

            if (Config.EnableJwtBearerTokenFlowGrantType &&
                grant_type.ToLower() == OAuth2AndOIDCConst.JwtBearerTokenFlowGrantType)
            {
                Dictionary<string, string> dic = JsonConvert.DeserializeObject<Dictionary<string, string>>(
                    CustomEncode.ByteToString(CustomEncode.FromBase64UrlString(
                        assertion.Split('.')[1]), CustomEncode.us_ascii));

                string pubKey = Helper.GetInstance().GetJwkRsaPublickey(dic[OAuth2AndOIDCConst.iss]);
                pubKey = CustomEncode.ByteToString(CustomEncode.FromBase64UrlString(pubKey), CustomEncode.us_ascii);

                if (!string.IsNullOrEmpty(pubKey))
                {
                    if (JwtAssertion.Verify(
                        assertion, out string iss, out string aud, out string scopes, out JObject jobj, pubKey))
                    {
                        // aud 検証
                        if (aud == Config.OAuth2AuthorizationServerEndpointsRootURI + Config.OAuth2TokenEndpoint)
                        {
                            // このフローが認められるか？
                            if (CmnEndpoints.CheckClientMode(iss,
                                ClientModePolicy.Flow.JwtBearer, ClientModePolicy.Proof.None,
                                out OAuth2AndOIDCEnum.ClientMode _, out jwkString, out err))
                            {
                                // JwtTokenを作る

                                // issに対応するsubを取得する。
                                string sub = Helper.GetInstance().GetClientName(iss);

                                // ClaimsIdentityにClaimを追加する。
                                ClaimsIdentity identity = new ClaimsIdentity(OAuth2AndOIDCConst.Bearer);

                                // ClaimsIdentityに、その他、所定のClaimを追加する。
                                identity.AddClaim(new Claim(ClaimTypes.Name, sub));
                                // **scope は、トークン要求のパラメタが優先**
                                //   （RFC 7521 4.1 / RFC 7523 2.1。#218）。
                                //   要求に無ければ、これまでどおり assertion の値を使う
                                //   （要求に scope を付けていない利用者を壊さないため）。
                                string requested = string.IsNullOrEmpty(scope) ? scopes : scope;

                                // scopes_supported に無いスコープと、クライアントに許されていないスコープは発行しない（#198）
                                identity = Helper.AddClaim(identity, iss, Helper.FilterSupportedScopes(requested.Split(' '), iss), null, "");

                                // access_token
                                string access_token = CmnAccessToken.CreateFromClaims(
                                    iss, identity.Name, identity.Claims,
                                    DateTimeOffset.Now.Add(Config.OAuth2AccessTokenExpireTimeSpanFromMinutes));

                                // オペレーション・トレース・ログ出力
                                Logging.MyOperationTrace(string.Format(
                                    "Passed the 'jwt bearer token flow' by {0}({1}).", iss, sub)); // Client Account

                                ret = CmnEndpoints.CreateAccessTokenResponse(access_token, "", jwkString);
                                return true;
                            }
                            else
                            {
                                // 設定済み
                            }
                        }
                        else
                        {
                            // クライアント認証エラー（Credential（aud）不正
                            err.Add(OAuth2AndOIDCConst.error, OAuth2AndOIDCConst.invalid_client);
                            err.Add(OAuth2AndOIDCConst.error_description, "Invalid credential.");
                        }
                    }
                    else
                    {
                        // クライアント認証エラー（Credential（署名）不正
                        err.Add(OAuth2AndOIDCConst.error, OAuth2AndOIDCConst.invalid_client);
                        err.Add(OAuth2AndOIDCConst.error_description, "Invalid credential.");
                    }
                }
                else
                {
                    // クライアント認証エラー（Credential（iss or pubKey）不正
                    err.Add(OAuth2AndOIDCConst.error, OAuth2AndOIDCConst.invalid_client);
                    err.Add(OAuth2AndOIDCConst.error_description, "Invalid credential or pubkey is not set.");
                }
            }

            return false;
        }

        #endregion

        #region GrantDeviceAuthZ

        /// <summary>GrantDeviceAuthZ（OAuth 2.0 Device Authorization Grant）</summary>
        /// <param name="grant_type">string</param>
        /// <param name="client_id">string</param>
        /// <param name="device_code">string</param>
        /// <param name="ret">Dictionary(string, string)</param>
        /// <param name="err">Dictionary(string, string)</param>
        /// <returns>成否</returns>
        public static bool GrantDeviceAuthZ(
            string grant_type, string client_id, string client_secret,
            X509Certificate2 x509, string device_code,
            out Dictionary<string, string> ret, out Dictionary<string, string> err)
        {
            ret = null;
            err = new Dictionary<string, string>();

            if (Config.EnableDeviceAuthZGrantType)
            {
                #region 認証

                // RFC 8628 3.4 : コンフィデンシャル クライアントは認証する（#193）。
                // ※ device_codeとclient_idの紐付けは、この先の
                //    AuthorizationCodeProvider.Receive(code, client_id, "")で確認される。
                if (!CmnEndpoints.DeviceAuthZClientAuthentication(client_id, client_secret, ref x509))
                {
                    // クライアント認証エラー（Credential不正
                    err.Add(OAuth2AndOIDCConst.error, OAuth2AndOIDCConst.invalid_client);
                    err.Add(OAuth2AndOIDCConst.error_description, "Invalid credential.");
                    return false;
                }

                // **登録種別で、このグラントを許すか。** 許すのは normal と device だけ。
                //   fapi1 / fapi2 / fapi_ciba の登録は、このグラントでは発行しない。
                //   RFC 6749 5.2 : 認証済みのクライアントに許されていないグラントは unauthorized_client。
                if (!CmnEndpoints.IsDeviceAuthZAllowed(client_id))
                {
                    err.Add(OAuth2AndOIDCConst.error, OAuth2AndOIDCConst.unauthorized_client);
                    err.Add(OAuth2AndOIDCConst.error_description,
                        "This client is not allowed to use the device authorization grant.");
                    return false;
                }

                #endregion

                #region 発行

                // Tokenレスポンスを生成する。
                string code = "";
                OAuth2AndOIDCEnum.DeviceAuthZState deviceState = OAuth2AndOIDCEnum.DeviceAuthZState.not_found;

                // device_code は必須（RFC 8628 §3.4）。無ければ invalid_request（#199）。
                if (string.IsNullOrEmpty(device_code))
                {
                    err.Add(OAuth2AndOIDCConst.error, OAuth2AndOIDCConst.invalid_request);
                    err.Add(OAuth2AndOIDCConst.error_description, "device_code is required.");
                    return false;
                }

                if (DeviceAuthZProvider.ReceiveTokenReq(device_code, out code, out deviceState))
                {
                    // = OAuth2AndOIDCEnum.CibaState.access_permitted
                    // Tokenレスポンス（正常）
                    string tokenPayload = AuthorizationCodeProvider.Receive(code, client_id, "");

                    // codeが不正（別Clientのものなど）ならpayloadは空になる（#185）。
                    if (string.IsNullOrEmpty(tokenPayload))
                    {
                        err.Add(OAuth2AndOIDCConst.error, OAuth2AndOIDCConst.invalid_grant);
                        err.Add(OAuth2AndOIDCConst.error_description, "Invalid device_code.");
                        return false;
                    }

                    // access_token
                    string access_token = CmnAccessToken.ProtectFromPayload(
                        client_id, tokenPayload,
                        DateTimeOffset.Now.Add(Config.OAuth2AccessTokenExpireTimeSpanFromMinutes),
                        null,  OAuth2AndOIDCEnum.ClientMode.device, out string aud, out string sub);

                    // Client認証のclient_idとToken類のaudをチェック
                    if (client_id != aud)
                    {
                        err.Add(OAuth2AndOIDCConst.error, OAuth2AndOIDCConst.invalid_grant);
                        err.Add(OAuth2AndOIDCConst.error_description, "The device_code was not issued to this client.");
                        return false;
                    }

                    // refresh_token
                    // **登録種別で refresh_token の経路を使えないなら、発行しない**（#224 の段階 2）。
                    //   device の登録は refresh_token の経路を使えない（normal の登録は従来どおり発行する）。
                    string refresh_token = "";
                    if (Config.EnableRefreshToken
                        && ClientModePolicy.MayUse(
                            Helper.GetInstance().GetClientMode(client_id), ClientModePolicy.Flow.RefreshToken))
                    {
                        refresh_token = RefreshTokenProvider.Create(tokenPayload);
                    }

                    // オペレーション・トレース・ログ出力
                    string name = Helper.GetInstance().GetClientName(client_id);
                    Logging.MyOperationTrace(string.Format(
                        "{0}({1}) passed the 'Authorization Code flow' by {2}({3}).",
                        client_id, name,                                         // Client Account
                        PPIDExtension.GetUserNameFromSub(client_id, sub), sub)); // User Account (PPID化により...)

                    ret = CmnEndpoints.CreateAccessTokenResponse(access_token, "", "");

                    return true;
                }
                else
                {
                    // ≠ OAuth2AndOIDCEnum.DeviceAuthZState.access_permitted
                    // Tokenレスポンス（異常）
                    switch (deviceState)
                    {
                        case OAuth2AndOIDCEnum.DeviceAuthZState.authorization_pending:

                            // このケースだけ、slow_downを検討する（どうやって？）。

                            //if() err.Add(OAuth2AndOIDCConst.error, OAuth2AndOIDCEnum.DeviceAuthZState.slow_down.ToStringByEmit());
                            //else
                            err.Add(OAuth2AndOIDCConst.error, OAuth2AndOIDCEnum.DeviceAuthZState.authorization_pending.ToStringByEmit());
                            break;

                        case OAuth2AndOIDCEnum.DeviceAuthZState.access_denied:
                        case OAuth2AndOIDCEnum.DeviceAuthZState.expired_token:
                            // RFC 8628 §3.5 の値そのもの
                            err.Add(OAuth2AndOIDCConst.error, deviceState.ToStringByEmit());
                            break;

                        default:
                            // not_found（使用済み・発行していない）/ irregularity_data は仕様外の値。
                            // enum 名をそのまま返さず、RFC 6749 §5.2 の invalid_grant で返す（#199）。
                            err.Add(OAuth2AndOIDCConst.error, OAuth2AndOIDCConst.invalid_grant);
                            err.Add(OAuth2AndOIDCConst.error_description, "Invalid device_code.");
                            break;
                    }
                }

                #endregion
                //}
                //else
                //{
                //    // クライアント認証エラー（Credential不正
                //    err.Add(OAuth2AndOIDCConst.error, OAuth2AndOIDCConst.invalid_client);
                //    err.Add(OAuth2AndOIDCConst.error_description, "Invalid credential.");
                //}
            }
            else
            {
                // サポートされていない
                err.Add(OAuth2AndOIDCConst.error, OAuth2AndOIDCConst.unsupported_grant_type);
                err.Add(OAuth2AndOIDCConst.error_description, Resources.ApplicationOAuthBearerTokenProvider.EnableCibaGrantType);
            }

            return false;
        }

        #endregion

        #region GrantCiba

        /// <summary>GrantCiba（CIBA）</summary>
        /// <param name="grant_type">string</param>
        /// <param name="client_id">string</param>
        /// <param name="client_secret">string</param>
        /// <param name="x509">X509Certificate2</param>
        /// <param name="auth_req_id">string</param>
        /// <param name="ret">Dictionary(string, string)</param>
        /// <param name="err">Dictionary(string, string)</param>
        /// <returns>成否</returns>
        public static bool GrantCiba(
            string grant_type, string client_id, string client_secret, X509Certificate2 x509, 
            string auth_req_id, out Dictionary<string, string> ret, out Dictionary<string, string> err)
        {
            ret = null;

            string jwkString = "";
            err = new Dictionary<string, string>();

            if (Config.EnableCibaGrantType)
            {
                #region 認証

                bool authned = false;
                ClientModePolicy.Proof proof = ClientModePolicy.Proof.None; // 何を証明したか（#224）
                if (grant_type.ToLower() == OAuth2AndOIDCConst.CibaGrantType)
                {
                    // client_id & (client_secret or x509)
                    authned = CmnEndpoints.ClientAuthentication(client_id, client_secret,
                        ref x509, out proof);
                }

                #endregion

                if (authned)
                {
                    #region CheckClientMode

                    // このフローが認められるか？（fapi2に設定
                    if (CmnEndpoints.CheckClientMode(client_id,
                        ClientModePolicy.Flow.Ciba, proof,
                        out OAuth2AndOIDCEnum.ClientMode _, out jwkString, out err))
                    {
                        // 継続可
                    }
                    else
                    {
                        // 継続不可
                        // err設定済み
                        return false;
                    }

                    #endregion

                    #region 発行

                    // Tokenレスポンスを生成する。
                    string code = ""; 
                    OAuth2AndOIDCEnum.CibaState cibaState = OAuth2AndOIDCEnum.CibaState.not_found;

                    if (CibaProvider.ReceiveTokenReq(auth_req_id, out code,  out cibaState))
                    {
                        // = OAuth2AndOIDCEnum.CibaState.access_permitted
                        // Tokenレスポンス（正常）
                        string tokenPayload = AuthorizationCodeProvider.Receive(code, client_id, "");

                        // codeが不正（別Clientのものなど）ならpayloadは空になる（#185）。
                        if (string.IsNullOrEmpty(tokenPayload))
                        {
                            err.Add(OAuth2AndOIDCConst.error, OAuth2AndOIDCConst.invalid_grant);
                            err.Add(OAuth2AndOIDCConst.error_description, "Invalid auth_req_id.");
                            return false;
                        }

                        // access_token
                        string access_token = CmnAccessToken.ProtectFromPayload(
                            client_id, tokenPayload,
                            DateTimeOffset.Now.Add(Config.OAuth2AccessTokenExpireTimeSpanFromMinutes),
                            x509, OAuth2AndOIDCEnum.ClientMode.fapi_ciba, out string aud, out string sub, JwtConst.ES256);

                        // Client認証のclient_idとToken類のaudをチェック
                        if (client_id != aud)
                        {
                            err.Add(OAuth2AndOIDCConst.error, OAuth2AndOIDCConst.invalid_grant);
                            err.Add(OAuth2AndOIDCConst.error_description, "The auth_req_id was not issued to this client.");
                            return false;
                        }

                        #region refresh_token
                        // 発行しないことに。
                        // ・単純に要らんのと、
                        // ・現状、refresh_token使った際、ES256にできない。
                        // ので。

                        //// refresh_token
                        //string refresh_token = "";
                        //if (Config.EnableRefreshToken)
                        //{
                        //    refresh_token = RefreshTokenProvider.Create(tokenPayload);
                        //}
                        #endregion

                        // オペレーション・トレース・ログ出力
                        string name = Helper.GetInstance().GetClientName(client_id);
                        Logging.MyOperationTrace(string.Format(
                            "{0}({1}) passed the 'Authorization Code flow' by {2}({3}).",
                            client_id, name,                                         // Client Account
                            PPIDExtension.GetUserNameFromSub(client_id, sub), sub)); // User Account (PPID化により...)

                        ret = CmnEndpoints.CreateAccessTokenResponse(access_token, "", "");

                        return true;
                    }
                    else
                    {
                        // ≠ OAuth2AndOIDCEnum.CibaState.access_permitted
                        // Tokenレスポンス（異常）
                        switch (cibaState)
                        {
                            case OAuth2AndOIDCEnum.CibaState.authorization_pending:
                                
                                // このケースだけ、slow_downを検討する（どうやって？）。

                                //if() err.Add(OAuth2AndOIDCConst.error, OAuth2AndOIDCEnum.CibaState.slow_down.ToStringByEmit());
                                //else
                                err.Add(OAuth2AndOIDCConst.error, OAuth2AndOIDCEnum.CibaState.authorization_pending.ToStringByEmit());
                                break;

                            default:
                                err.Add(OAuth2AndOIDCConst.error, cibaState.ToStringByEmit());
                                break;
                        }
                    }

                    #endregion
                }
                else
                {
                    // クライアント認証エラー（Credential不正
                    err.Add(OAuth2AndOIDCConst.error, OAuth2AndOIDCConst.invalid_client);
                    err.Add(OAuth2AndOIDCConst.error_description, "Invalid credential.");
                }
            }
            else
            {
                // サポートされていない
                err.Add(OAuth2AndOIDCConst.error, OAuth2AndOIDCConst.unsupported_grant_type);
                err.Add(OAuth2AndOIDCConst.error_description, Resources.ApplicationOAuthBearerTokenProvider.EnableCibaGrantType);
            }

            return false;
        }

        #endregion

        #endregion

        #region Revocation / Introspection Endpoint

        #region Public

        #region RevokeToken / IntrospectToken

        /// <summary>トークンを失効させる（RFC 7009）。クライアント認証は済んでいること。</summary>
        /// <param name="client_id">認証済みのclient_id</param>
        /// <param name="token">失効させるトークン</param>
        /// <param name="token_type_hint">token_type_hint（任意）</param>
        /// <returns>成功なら空の辞書。他クライアントのトークンなら error を持つ辞書</returns>
        /// <remarks>
        /// 両アプリの /revoke から呼ぶ（#200 で Controller から移した）。
        /// ・無効なトークン（存在しない・失効済み・期限切れ）も成功として扱う（RFC 7009 2.2）（#200）
        /// ・他のクライアントのトークンは、要求を拒否してエラーを返す（RFC 7009 2.1）（#194）
        /// </remarks>
        public static Dictionary<string, string> RevokeToken(
            string client_id, string token, string token_type_hint)
        {
            Dictionary<string, string> err = new Dictionary<string, string>();

            foreach (string type in CmnEndpoints.TokenSearchOrder(token_type_hint))
            {
                if (type == OAuth2AndOIDCConst.AccessToken)
                {
                    // 検証（署名・期限・失効済みか）に通らなければ、access_token としては見つからない。
                    if (!CmnAccessToken.VerifyAccessToken(token, out ClaimsIdentity identity))
                    {
                        continue;
                    }

                    // Tokenが呼び出し元に発行されたものかを確認（RFC 7009 2.1）（#194）
                    if (!CmnEndpoints.CheckTokenOwner(client_id, identity))
                    {
                        err.Add(OAuth2AndOIDCConst.error, OAuth2AndOIDCConst.invalid_grant);
                        err.Add(OAuth2AndOIDCConst.error_description, "The token was not issued to this client.");
                        return err;
                    }

                    // access_token取消（jtiで記録する）
                    Claim jti = identity.Claims.Where(
                        x => x.Type == OAuth2AndOIDCConst.UrnJwtIdClaim).FirstOrDefault<Claim>();

                    if (jti != null)
                    {
                        RevocationProvider.Create(jti.Value);
                    }

                    return err; // 成功（空）
                }
                else
                {
                    string tokenPayload = RefreshTokenProvider.Refer(token);

                    if (string.IsNullOrEmpty(tokenPayload))
                    {
                        continue;
                    }

                    // Tokenが呼び出し元に発行されたものかを確認（RFC 7009 2.1）（#194）
                    if (!CmnEndpoints.CheckRefreshTokenOwner(client_id, tokenPayload))
                    {
                        err.Add(OAuth2AndOIDCConst.error, OAuth2AndOIDCConst.invalid_grant);
                        err.Add(OAuth2AndOIDCConst.error_description, "The token was not issued to this client.");
                        return err;
                    }

                    // refresh_token取消
                    RefreshTokenProvider.Delete(token);
                    return err; // 成功（空）
                }
            }

            // どの種類でも見つからない ＝ 無効なトークン。
            // 使えなくするという目的は達しているので、エラーにしない（RFC 7009 2.2）（#200）。
            return err;
        }

        /// <summary>トークンのメタデータを返す（RFC 7662）。クライアント認証は済んでいること。</summary>
        /// <param name="client_id">認証済みのclient_id</param>
        /// <param name="token">問い合わせるトークン</param>
        /// <param name="token_type_hint">token_type_hint（任意）</param>
        /// <returns>active と、有効ならメタデータ</returns>
        /// <remarks>
        /// 両アプリの /introspect から呼ぶ（#200 で Controller から移した）。
        /// ・無効なトークン（存在しない・失効済み・期限切れ）は active=false（RFC 7662 2.2）（#200）
        /// ・他のクライアントのトークンも active=false だけを返す（RFC 7662 2.2 / 4）（#194）
        /// </remarks>
        public static Dictionary<string, object> IntrospectToken(
            string client_id, string token, string token_type_hint)
        {
            Dictionary<string, object> ret = new Dictionary<string, object>();

            foreach (string type in CmnEndpoints.TokenSearchOrder(token_type_hint))
            {
                string accessToken = token;

                if (type == OAuth2AndOIDCConst.RefreshToken)
                {
                    string tokenPayload = RefreshTokenProvider.Refer(token);

                    if (string.IsNullOrEmpty(tokenPayload))
                    {
                        continue;
                    }

                    // AccessToken化して、検証とメタデータの取り出しを共通化する。
                    // 有効期限を「現在時刻」にすると、作ってから検証するまでの間に秒をまたいだとき
                    // 失効扱いになる（VerifyExp は秒単位の exp >= now）。検証の間は持つ期限にする（#200）。
                    accessToken = CmnAccessToken.ProtectFromPayload(
                        "", tokenPayload, DateTimeOffset.Now.Add(Config.OAuth2AccessTokenExpireTimeSpanFromMinutes),
                        null, OAuth2AndOIDCEnum.ClientMode.normal, out string aud, out string sub);
                }

                if (string.IsNullOrEmpty(accessToken)
                    || !CmnAccessToken.VerifyAccessToken(accessToken, out ClaimsIdentity identity))
                {
                    continue;
                }

                // Tokenが呼び出し元に発行されたものでなければ、
                // メタデータを返さない（RFC 7662 2.2 / 4）（#194）。
                if (!CmnEndpoints.CheckTokenOwner(client_id, identity))
                {
                    ret.Add(OAuth2AndOIDCConst.active, false);
                    return ret;
                }

                // メタデータの返却
                ret.Add(OAuth2AndOIDCConst.active, true);

                // **token_type は「トークンの型」**（RFC 6749 5.1 の bearer など）であって、
                //   見つかった種別（access_token / refresh_token）ではない（#218）。
                //   トークン応答（CreateAccessTokenResponse）と同じ値を返す。
                //   **リフレッシュ トークンには 5.1 の型が無いので、付けない**
                //   （RFC 7662 2.2 では OPTIONAL）。
                if (type == OAuth2AndOIDCConst.AccessToken)
                {
                    ret.Add(OAuth2AndOIDCConst.token_type, OAuth2AndOIDCConst.Bearer.ToLower());
                }

                string scopes = "";
                foreach (Claim claim in identity.Claims)
                {
                    if (!claim.Type.StartsWith(OAuth2AndOIDCConst.UrnClaimBase))
                    {
                        continue;
                    }

                    if (claim.Type == OAuth2AndOIDCConst.UrnScopesClaim)
                    {
                        scopes += claim.Value + " ";
                    }
                    else if (claim.Type.StartsWith(OAuth2AndOIDCConst.UrnCnfX5tClaim))
                    {
                        string temp = OAuth2AndOIDCConst.x5t
                            + claim.Type.Substring(OAuth2AndOIDCConst.UrnCnfX5tClaim.Length);
                        ret.Add(OAuth2AndOIDCConst.cnf, new Dictionary<string, string>()
                        {
                            { temp, claim.Value }
                        });
                    }
                    else
                    {
                        string name = claim.Type.Substring(OAuth2AndOIDCConst.UrnClaimBase.Length);

                        // refresh_token の exp / nbf / iat / jti は、上で作った一時的な access_token の値で、
                        // refresh_token 自身のものではない。誤解を招くので返さない（#200）。
                        if (type == OAuth2AndOIDCConst.RefreshToken
                            && (name == OAuth2AndOIDCConst.exp || name == OAuth2AndOIDCConst.nbf
                                || name == OAuth2AndOIDCConst.iat || name == OAuth2AndOIDCConst.jti))
                        {
                            continue;
                        }

                        ret.Add(name, claim.Value);
                    }
                }

                ret.Add(OAuth2AndOIDCConst.UrnScopesClaim.Substring(
                    OAuth2AndOIDCConst.UrnClaimBase.Length), scopes.Trim());

                return ret; // 成功
            }

            // どの種類でも見つからない ＝ 使えないトークン。
            // エラーではなく、問い合わせへの正常な答えとして active=false を返す（RFC 7662 2.2）（#200）。
            ret.Add(OAuth2AndOIDCConst.active, false);
            return ret;
        }

        #endregion

        #endregion

        #region Private

        #region Token所有者の確認

        /// <summary>Tokenが、認証したクライアントに発行されたものかを確認する</summary>
        /// <param name="client_id">認証済みのclient_id</param>
        /// <param name="identity">ClaimsIdentity（VerifyAccessTokenの結果）</param>
        /// <returns>bool</returns>
        /// <remarks>RFC 7009 2.1 / RFC 7662 2.1（#194）</remarks>
        private static bool CheckTokenOwner(string client_id, ClaimsIdentity identity)
        {
            if (string.IsNullOrEmpty(client_id) || identity == null) return false;

            Claim aud = identity.Claims.Where(
                x => x.Type == OAuth2AndOIDCConst.UrnAudienceClaim).FirstOrDefault<Claim>();

            return (aud != null && aud.Value == client_id);
        }

        /// <summary>RefreshTokenが、認証したクライアントに発行されたものかを確認する</summary>
        /// <param name="client_id">認証済みのclient_id</param>
        /// <param name="tokenPayload">RefreshTokenProvider.Referの結果</param>
        /// <returns>bool</returns>
        /// <remarks>RFC 7009 2.1（#194）</remarks>
        private static bool CheckRefreshTokenOwner(string client_id, string tokenPayload)
        {
            if (string.IsNullOrEmpty(client_id) || string.IsNullOrEmpty(tokenPayload)) return false;

            JObject payload = (JObject)JsonConvert.DeserializeObject(tokenPayload);

            return (payload != null
                && (string)payload[OAuth2AndOIDCConst.aud] == client_id);
        }

        #endregion

        #region TokenSearchOrder

        /// <summary>
        /// token_type_hint から、トークンを探す順番を決める。
        /// </summary>
        /// <param name="token_type_hint">token_type_hint（省略・未知の値は既定の順番）</param>
        /// <returns>探す順番（access_token / refresh_token）</returns>
        /// <remarks>
        /// ヒントは探す順番の手掛かりにすぎない。
        /// ヒントの種類で見つからなければ、他の種類も探す（RFC 7009 2.1 / RFC 7662 2.1）（#200）。
        /// </remarks>
        private static string[] TokenSearchOrder(string token_type_hint)
        {
            if (token_type_hint == OAuth2AndOIDCConst.RefreshToken)
            {
                return new string[] { OAuth2AndOIDCConst.RefreshToken, OAuth2AndOIDCConst.AccessToken };
            }

            return new string[] { OAuth2AndOIDCConst.AccessToken, OAuth2AndOIDCConst.RefreshToken };
        }

        #endregion

        #endregion

        #endregion

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
            else
            {
                // そのまま使用する。
                ret = constr;
            }

            return ret;
        }

        #region Redirect URLの組み立て

        /// <summary>リダイレクト先URLに、パラメタを付ける</summary>
        /// <param name="redirectUri">リダイレクト先</param>
        /// <param name="parameters">付けるパラメタ（値が空のものは付けない）</param>
        /// <param name="useFragment">true : フラグメント（#）、false : クエリ文字列（?）</param>
        /// <returns>URL</returns>
        /// <remarks>
        /// #187
        /// - **既にクエリ文字列を持つredirect_uriでも壊れない**よう、区切りを ? と & で切り替える。
        /// - **値は必ずURLエンコードする。** stateはクライアントが自由に決められるため、
        ///   生で連結するとリダイレクト先URLにパラメタを注入できてしまう。
        /// - 値が空のパラメタは付けない。stateは、要求に含まれた場合のみ返す（RFC 6749 4.1.2）。
        /// </remarks>
        public static string BuildRedirectUrl(
            string redirectUri, Dictionary<string, string> parameters, bool useFragment = false)
        {
            StringBuilder sb = new StringBuilder();

            // **どの認可サーバからの応答かを示す**（RFC 9207。#231）。
            //   RP が複数の IdP を使うとき、応答を取り違えさせる攻撃（Mix-Up）への対策。
            //   **成功にも失敗にも付ける**（同 §2）。
            //
            //   JARM（response=...）のときは付けない。**署名された JWT の中に iss が入っており**
            //   （CmnResponseObject）、そちらが同じ役目を果たすため。
            if (!parameters.ContainsKey(OAuth2AndOIDCConst.iss)
                && !parameters.ContainsKey("response"))
            {
                parameters = new Dictionary<string, string>(parameters);
                parameters[OAuth2AndOIDCConst.iss] = Config.IssuerId;
            }

            foreach (KeyValuePair<string, string> p in parameters)
            {
                if (string.IsNullOrEmpty(p.Value)) continue;

                if (sb.Length != 0) sb.Append("&");
                sb.Append(Uri.EscapeDataString(p.Key));
                sb.Append("=");
                sb.Append(Uri.EscapeDataString(p.Value));
            }

            if (sb.Length == 0) return redirectUri;

            if (useFragment)
            {
                return redirectUri + (redirectUri.Contains("#") ? "&" : "#") + sb.ToString();
            }
            else
            {
                return redirectUri + (redirectUri.Contains("?") ? "&" : "?") + sb.ToString();
            }
        }

        #endregion

        #region エラー応答（HTTP ステータス・WWW-Authenticate）

        /// <summary>エラー応答の HTTP ステータスを決める（RFC 6749 5.2 / RFC 6750 3.1）</summary>
        /// <param name="err">error / error_description を持つ辞書</param>
        /// <returns>HTTP ステータス（invalid_client / invalid_token は 401、それ以外は 400）</returns>
        /// <remarks>
        /// 以前は、どのエンドポイントも Dictionary をそのまま返していたため、エラーでも HTTP 200 だった（#196）。
        /// RFC 6749 5.2 : エラーは 400。invalid_client（クライアント認証の失敗）は 401。
        /// RFC 6750 3.1 : invalid_token（無効・失効・期限切れの Bearer トークン）は 401。
        /// CIBA Core 13 : invalid_client は 401、それ以外（invalid_scope・unknown_user_id など）は 400。
        /// Device / CIBA のポーリングのエラー（authorization_pending など）も 400（RFC 8628 3.5）。
        /// 実際の応答（IActionResult / IHttpActionResult）は、フレームワークごとに各アプリで作る。
        /// </remarks>
        public static int GetErrorStatusCode(Dictionary<string, string> err)
        {
            string error = null;

            if (err != null)
            {
                err.TryGetValue(OAuth2AndOIDCConst.error, out error);
            }

            if (error == OAuth2AndOIDCConst.invalid_client || error == OAuth2AndOIDCConst.invalid_token)
            {
                return 401;
            }

            return 400;
        }

        /// <summary>Bearer トークンのエラー応答の WWW-Authenticate を作る（RFC 6750 3）</summary>
        /// <param name="realm">realm（保護資源の名前）</param>
        /// <param name="err">error / error_description を持つ辞書（トークンが無かった場合は空）</param>
        /// <returns>WWW-Authenticate の値のうち、スキーム名（Bearer）より後ろ</returns>
        /// <remarks>
        /// RFC 6750 3 : 保護資源は、トークンが無い・無効な要求に WWW-Authenticate: Bearer を返す（#196）。
        /// - トークンが無い（ヘッダ無し、または他の方式）: realm だけ。エラー情報は付けない（3.1 : SHOULD NOT）
        /// - 無効なトークン : error と error_description を付ける
        /// 値には固定の文字列を渡すこと（quoted-string の中に " と \ は入れられない）。
        /// ヘッダの付け方はフレームワークごとに違うので、各アプリで付ける。
        /// </remarks>
        public static string GetBearerChallengeParameter(string realm, Dictionary<string, string> err)
        {
            List<string> items = new List<string>();
            items.Add("realm=\"" + realm + "\"");

            if (err != null)
            {
                foreach (string key in new string[] { OAuth2AndOIDCConst.error, OAuth2AndOIDCConst.error_description })
                {
                    if (err.TryGetValue(key, out string value) && !string.IsNullOrEmpty(value))
                    {
                        items.Add(key + "=\"" + value + "\"");
                    }
                }
            }

            return string.Join(", ", items);
        }

        #endregion

        #region　ClientAuthentication

        /// <summary>クライアント認証（送られてきた資格情報の種類を問わない）</summary>
        /// <param name="client_id">client_id（client_secret / mTLS のとき）</param>
        /// <param name="client_secret">client_secret</param>
        /// <param name="clientAssertion">client_assertion（private_key_jwt）</param>
        /// <param name="x509">クライアント証明書（mTLS）</param>
        /// <param name="authnedClientId">認証できたクライアントの client_id</param>
        /// <param name="proof">何を証明したか</param>
        /// <returns>認証できたか</returns>
        /// <remarks>
        /// **どの方式で来ても、ここで受ける**（#239）。
        /// 以前は `client_secret` / mTLS の版と、アサーションの版が別々で、
        /// **認可コード グラントだけがアサーションを受けていた。**
        /// `refresh_token` や `/revoke` では `private_key_jwt` が通らなかった。
        ///
        /// **アサーションのときは `client_id` をアサーションの `iss` から得る**
        /// （RFC 7523 §3 : `iss` はクライアントの識別子）。
        /// 認証の後で client_id を使う処理（トークンとの紐付け、失効）は、**こちらを使うこと。**
        ///
        /// **要否は決めない。** コンフィデンシャルかどうかは呼び出し側が判断する
        /// （RFC 6749 §3.2.1。パブリック クライアントは認証しない）。
        /// この関数は「**何を証明したか**」を返すだけで、
        /// その証明で通す登録種別は `ClientModePolicy` の表が決める（#224）。
        /// </remarks>
        public static bool ClientAuthentication(
            string client_id, string client_secret, string clientAssertion,
            ref X509Certificate2 x509, out string authnedClientId, out ClientModePolicy.Proof proof)
        {
            if (!string.IsNullOrEmpty(clientAssertion))
            {
                // private_key_jwt（client_id はアサーションから得る）
                return CmnEndpoints.ClientAuthentication(
                    clientAssertion, out authnedClientId, ref x509, out proof);
            }

            authnedClientId = client_id;

            // client_secret（basic / post）または mTLS
            return CmnEndpoints.ClientAuthentication(
                client_id, client_secret, ref x509, out proof);
        }

        #region client_id & (client_secret or x509)

        /// <summary>ClientAuthentication</summary>
        /// <param name="client_id">string</param>
        /// <param name="client_secret">string</param>
        /// <param name="x509">X509Certificate2</param>
        /// <param name="proof">何を証明したか（client_secret か mTLS か）</param>
        /// <returns>bool</returns>
        /// <remarks>
        /// **以前は水準（permittedLevel）を返していた**（client_secret なら normal、x509 なら fapi2）。
        /// いまは何を証明したかを返し、通す登録種別は ClientModePolicy の表で決める（#224）。
        /// </remarks>
        public static bool ClientAuthentication(string client_id, string client_secret,
            ref X509Certificate2 x509, out ClientModePolicy.Proof proof)
        {
            proof = ClientModePolicy.Proof.None;

            // client_id & client_secret
            if (!string.IsNullOrEmpty(client_id))
            {
                if (!string.IsNullOrEmpty(client_secret))
                {
                    // *.config or Saml2OAuth2Dataテーブルを参照して、
                    // クライアント認証（client_secret）を行なう。
                    if (client_secret == Helper.GetInstance().GetClientSecret(client_id))
                    {
                        proof = ClientModePolicy.Proof.ClientSecret;
                        x509 = null; // client_secretがあった場合、x509を無効化
                        return true;
                    }
                }
                else if (x509 != null)
                {
                    // *.config or Saml2OAuth2Dataテーブルを参照して、
                    // クライアント認証（X509Certificate2）を行なう。
                    if (x509.Subject == Helper.GetInstance().GetTlsClientAuthSubjectDn(client_id))
                    {
                        proof = ClientModePolicy.Proof.Mtls;
                        return true;
                    }
                }
            }

            return false;
        }

        /// <summary>ClientAuthentication（互換の入口）</summary>
        /// <param name="client_id">string</param>
        /// <param name="client_secret">string</param>
        /// <param name="x509">X509Certificate2</param>
        /// <param name="permittedLevel">OAuth2AndOIDCEnum.ClientMode</param>
        /// <returns>bool</returns>
        /// <remarks>
        /// **水準を返す以前の形を、呼び出し元のために残してある**（両アプリの revoke / introspect）。
        /// そこでは水準を使っていない。**新しく使うときは、証明を返す版を使うこと**（#224）。
        /// </remarks>
        public static bool ClientAuthentication(string client_id, string client_secret,
            ref X509Certificate2 x509, out OAuth2AndOIDCEnum.ClientMode permittedLevel)
        {
            bool authned = CmnEndpoints.ClientAuthentication(
                client_id, client_secret, ref x509, out ClientModePolicy.Proof proof);

            permittedLevel = (proof == ClientModePolicy.Proof.Mtls)
                ? OAuth2AndOIDCEnum.ClientMode.fapi2 : OAuth2AndOIDCEnum.ClientMode.normal;

            return authned;
        }

        #endregion

        #region Device AuthZ

        /// <summary>
        /// Device AuthZ グラントを、このクライアントに許すか（登録種別で判定する）
        /// </summary>
        /// <param name="client_id">string</param>
        /// <returns>許すなら true</returns>
        /// <remarks>
        /// **許すのは normal と device の登録だけ。**
        /// fapi1 / fapi2 / fapi_ciba の登録は、より強いクライアント認証
        /// （PKCE / private_key_jwt / mTLS など）を求めている。
        /// このグラントは client_secret だけで通るので、**使わせると、登録で求めた強さを満たさずに
        /// トークンが出てしまう。**
        ///
        /// ※ 他のグラントは CheckClientMode で登録種別を見ているが、このグラントには判定が無かった。
        ///    段階 1 で ClientModePolicy の表に取り込んだ（#224）。
        /// </remarks>
        public static bool IsDeviceAuthZAllowed(string client_id)
        {
            // 表の「Device AuthZ → normal / device」の行で判定する（#224 の段階 1）。
            //   この行は証明を問わないので、MayUse で足りる。既知でない登録値は拒否（段階 2）。
            return ClientModePolicy.MayUse(
                Helper.GetInstance().GetClientMode(client_id), ClientModePolicy.Flow.DeviceAuthZ);
        }

        /// <summary>Device AuthZのクライアント認証</summary>
        /// <param name="client_id">string</param>
        /// <param name="client_secret">string</param>
        /// <param name="x509">X509Certificate2</param>
        /// <returns>bool</returns>
        /// <remarks>
        /// RFC 8628
        /// - 3.1 : デバイス認可要求で、クライアントを識別する。
        /// - 3.4 : トークン要求で、コンフィデンシャル クライアントは認証する。
        /// パブリック クライアント（client_secret未登録）は、client_idの確認だけを行う。
        /// </remarks>
        public static bool DeviceAuthZClientAuthentication(
            string client_id, string client_secret, ref X509Certificate2 x509)
        {
            // client_idは必須
            if (string.IsNullOrEmpty(client_id)) return false;

            // 未登録のclient_idは拒否
            if (string.IsNullOrEmpty(Helper.GetInstance().GetClientName(client_id))) return false;

            // コンフィデンシャル クライアントは認証必須
            // - client_secretを登録済み
            // - tls_client_auth_subject_dnを登録済み（mTLSのみのクライアント）
            // - x509を提示してきた
            if (!string.IsNullOrEmpty(Helper.GetInstance().GetClientSecret(client_id))
                || !string.IsNullOrEmpty(Helper.GetInstance().GetTlsClientAuthSubjectDn(client_id))
                || x509 != null)
            {
                return CmnEndpoints.ClientAuthentication(
                    client_id, client_secret, ref x509,
                    out ClientModePolicy.Proof _);
            }

            // パブリック クライアントは、client_idの確認のみ
            return true;
        }

        #endregion

        #region assertion

        /// <summary>ClientAuthentication</summary>
        /// <param name="client_id">string</param>
        /// <param name="client_secret">string</param>
        /// <param name="x509">X509Certificate2</param>
        /// <param name="proof">何を証明したか（成功なら private_key_jwt）</param>
        /// <returns>bool</returns>
        public static bool ClientAuthentication(string assertion, out string client_id,
            ref X509Certificate2 x509, out ClientModePolicy.Proof proof)
        {
            if (!string.IsNullOrEmpty(assertion))
            {
                // assertionがあった場合、x509を無効化
                x509 = null;

                // **JWT でない値・iss の無い JWT・未登録のクライアントで、例外にしない**（#241）。
                //   ここは /token・/par・/ciba_authz・/revoke・/introspect の全てから通る（#238 / #239）。
                JObject payload = CmnEndpoints.TryReadJwtPayload(assertion);
                string assertionIss = (payload == null)
                    ? "" : (string)payload[OAuth2AndOIDCConst.iss];

                // pubKey
                string pubKey = string.IsNullOrEmpty(assertionIss)
                    ? "" : CmnEndpoints.DecodeRegisteredJwk(
                        Helper.GetInstance().GetJwkRsaPublickey(assertionIss));

                if (!string.IsNullOrEmpty(pubKey))
                {
                    // 署名検証 ≒ クライアント認証
                    if (JwtAssertion.Verify(
                        assertion, out string iss, out string aud, out string scopes, out JObject jobj, pubKey))
                    {
                        // aud 検証
                        if (aud == Config.OAuth2AuthorizationServerEndpointsRootURI + Config.OAuth2TokenEndpoint)
                        {
                            proof = ClientModePolicy.Proof.PrivateKeyJwt;
                            client_id = iss;
                            return true;
                        }
                    }
                }
            }

            proof = ClientModePolicy.Proof.None;
            client_id = "";
            return false;
        }

        #endregion

        #endregion

        #endregion

        #region Private

        #region CheckClientMode

        /// <summary>CheckClientMode</summary>
        /// <param name="client_id">ClientId</param>
        /// <param name="flow">経路</param>
        /// <param name="proof">その要求で、クライアントが何を証明したか</param>
        /// <param name="clientMode">クライアントに登録されたClientMode</param>
        /// <param name="jwkString">jwkString</param>
        /// <param name="err">Dictionary(string, string)</param>
        /// <returns>継続の可否</returns>
        /// <remarks>
        /// **「経路 × 証明 → 通す登録種別」を ClientModePolicy の表で引く（#224 の段階 1）。**
        /// 以前は水準（permittedLevel）との大小で判定していた。表は、その判定をそのまま展開したもので、
        /// **判定の結果は 1 つも変えていない**（全組み合わせを突き合わせて確認した）。
        ///
        /// **トークンに載せるクレームは clientMode を使う**（#220）。
        ///
        /// 段階 2 で、拒否のエラー コードを unauthorized_client に改め（以前は unsupported_grant_type）、
        /// **既知でない登録値は fapi2 とみなさず、不正として拒否する**ようにした。
        /// </remarks>
        private static bool CheckClientMode(
            string client_id,
            ClientModePolicy.Flow flow,
            ClientModePolicy.Proof proof,
            out OAuth2AndOIDCEnum.ClientMode clientMode,
            out string jwkString,
            out Dictionary<string, string> err)
        {
            // out
            jwkString = "";
            err = new Dictionary<string, string>();
            clientMode = OAuth2AndOIDCEnum.ClientMode.normal;

            if (string.IsNullOrEmpty(client_id))
            {
                err.Add(OAuth2AndOIDCConst.error, OAuth2AndOIDCConst.invalid_client);
                err.Add(OAuth2AndOIDCConst.error_description, string.Format("client_id is not set."));
                return false; // NullOrEmptyだとmode無しとかになるのでここで切る。
            }

            // 登録された種別
            string clientModeString = Helper.GetInstance().GetClientMode(client_id);

            // RFC 6749 5.2 : 認証済みのクライアントに許されていないグラントは unauthorized_client。
            //   以前は unsupported_grant_type（サーバがそのグラントを扱わない、の意）を返していた（#224 の段階 2）。
            if (!ClientModePolicy.TryParse(clientModeString, out clientMode))
            {
                // **既知のどれにも当たらない登録値（空・書き間違い）は、不正な登録として拒否する。**
                //   以前は fapi2 とみなしていた（#224 の段階 2）。
                err.Add(OAuth2AndOIDCConst.error, OAuth2AndOIDCConst.unauthorized_client);

                if (string.IsNullOrEmpty(clientModeString))
                {
                    err.Add(OAuth2AndOIDCConst.error_description, "This client is not set the mode.");
                }
                else
                {
                    err.Add(OAuth2AndOIDCConst.error_description, string.Format(
                        "The mode of this client ({0}) is invalid.", clientModeString));
                }

                return false;
            }

            if (clientModeString == OAuth2AndOIDCEnum.ClientMode.fapi2.ToStringByEmit())
            {
                // fapi2 の登録は、JWK（RSA 公開鍵）も読む
                jwkString = CustomEncode.ByteToString(CustomEncode.FromBase64UrlString(
                    Helper.GetInstance().GetJwkRsaPublickey(client_id)), CustomEncode.us_ascii);
            }

            if (ClientModePolicy.IsAllowed(clientMode, flow, proof))
            {
                return true;
            }

            // エラーを追加（説明文は水準の言い回しをやめた。#224）
            err.Add(OAuth2AndOIDCConst.error, OAuth2AndOIDCConst.unauthorized_client);
            err.Add(OAuth2AndOIDCConst.error_description, string.Format(
                "This client ({0}) is not allowed to use this flow.", clientModeString));

            return false;
        }

        #endregion

        #region CreateAccessTokenResponse

        /// <summary>CreateAccessTokenResponse</summary>
        /// <param name="access_token">string</param>
        /// <param name="refresh_token">string</param>
        /// <param name="jwkString">string</param>
        /// <returns>Dictionary(string, string)</returns>
        private static Dictionary<string, string> CreateAccessTokenResponse(
            string access_token, string refresh_token, string jwkString)
        {
            Dictionary<string, string> ret = new Dictionary<string, string>();

            // token_type
            ret.Add(OAuth2AndOIDCConst.token_type, OAuth2AndOIDCConst.Bearer.ToLower());

            // access_token
            ret.Add(OAuth2AndOIDCConst.AccessToken, access_token);

            // refresh_token
            if (!string.IsNullOrEmpty(refresh_token))
            {
                ret.Add(OAuth2AndOIDCConst.RefreshToken, refresh_token);
            }

            // ヘッダ
            JObject jObjHeader = (JObject)JsonConvert.DeserializeObject(
                            CustomEncode.ByteToString(CustomEncode.FromBase64UrlString(
                                access_token.Split('.')[0]), CustomEncode.us_ascii));
            // ペイロード
            JObject jObjPayload = (JObject)JsonConvert.DeserializeObject(
                            CustomEncode.ByteToString(CustomEncode.FromBase64UrlString(
                                access_token.Split('.')[1]), CustomEncode.us_ascii));

            // id_token
            JArray jAry = (JArray)jObjPayload["scopes"];

            foreach (string s in jAry)
            {
                if (s == OAuth2AndOIDCConst.Scope_Openid)
                {
                    string id_token = "";
                    if (string.IsNullOrEmpty(jwkString))
                    {
                        // JWS
                        string alg = (string)jObjHeader[JwtConst.alg];
                        if (alg == JwtConst.ES256)
                        {
                            // ES256
                            id_token = CmnIdToken.ChangeToIdTokenFromAccessToken(
                                access_token, "", "", // c_hash, s_hash は /token で生成不可
                                HashClaimType.None, Config.EcdsaPfxFilePath, Config.EcdsaPfxPassword, "", alg);
                        }
                        else
                        {
                            // RS256
                            id_token = CmnIdToken.ChangeToIdTokenFromAccessToken(
                                access_token, "", "", // c_hash, s_hash は /token で生成不可
                                HashClaimType.None, Config.RsaPfxFilePath, Config.RsaPfxPassword, "");
                        }
                    }
                    else
                    {
                        // JWE
                        id_token = CmnIdToken.ChangeToIdTokenFromAccessToken(
                            access_token, "", "", // c_hash, s_hash は /token で生成不可
                            HashClaimType.None, Config.EcdsaPfxFilePath, Config.EcdsaPfxPassword, jwkString);
                    }

                    if (!string.IsNullOrEmpty(id_token))
                    {
                        ret.Add(OAuth2AndOIDCConst.IDToken, id_token);
                    }
                }
            }

            // expires_in
            ret.Add(OAuth2AndOIDCConst.expires_in, ((int)Config.OAuth2AccessTokenExpireTimeSpanFromMinutes.TotalSeconds).ToString());

            // scope
            // 発行したスコープを返す。要求と異なる場合は必須（RFC 6749 5.1）。
            // scopes_supported に無いスコープは発行しないので、要求と異なることがある（#198）。
            List<string> issued = new List<string>();
            foreach (string s in jAry)
            {
                if (!string.IsNullOrEmpty(s))
                {
                    issued.Add(s);
                }
            }

            if (issued.Count > 0)
            {
                ret.Add(OAuth2AndOIDCConst.scope, string.Join(" ", issued));
            }

            return ret;
        }

        #endregion

        #endregion

        #endregion
    }
}