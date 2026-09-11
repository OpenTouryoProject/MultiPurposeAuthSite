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

                OpenIDConfig.Add("id_token_encryption_alg_values_supported", new List<string> {
                    "RSA-OAEP"
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
                OpenIDConfig.Add("claims_supported", new List<string> {
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
                });
                #endregion

                #region RequestObject
                OpenIDConfig.Add("request_object_signing_alg_values_supported", new List<string> {
                    "RS256"
                });
                OpenIDConfig.Add("request_parameter_supported", false);
                OpenIDConfig.Add("request_uri_parameter_supported", true);
                OpenIDConfig.Add("request_object_endpoint",
                    Config.OAuth2AuthorizationServerEndpointsRootURI + OAuth2AndOIDCParams.RequestObjectRegUri);
                #endregion

                #region ResponseObject(JARM)
                // 「.」がね...。
                response_modes_supported.Add("query.jwt");
                response_modes_supported.Add("fragment.jwt");
                response_modes_supported.Add("form_post.jwt");
                #endregion
            }

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

            OpenIDConfig.Add("code_challenge_methods_supported", new List<string> {
                OAuth2AndOIDCConst.PKCE_plain,
                OAuth2AndOIDCConst.PKCE_S256
            });

            #endregion

            #endregion

            #region FAPI

            OpenIDConfig.Add("mutual_tls_sender_constrained_access_tokens", "true");

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
            OpenIDConfig.Add("backchannel_authentication_request_signing_alg_values_supported", "ES256");
            OpenIDConfig.Add("backchannel_user_code_parameter_supported", "false");

            #endregion

            #region その他
            OpenIDConfig.Add("display_values_supported", new List<string> {
                "page"
            });

            OpenIDConfig.Add("service_documentation", "・・・");
            #endregion

            #endregion

            return OpenIDConfig;
        }

        #endregion

        #region AuthZ(N)Endpoint

        #region ValidateAuthZReqParam

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
        /// <returns>成功 or 失敗</returns>
        public static bool ValidateAuthZReqParam(string client_id, string redirect_uri,
            string response_type, string scope, string nonce,
            out string valid_redirect_uri, out string err, out string errDescription)
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
            //string aud = "";
            string exp = "";
            //string iat = "";
            string nbf = "";
            //string jti = "";            
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
            if (!CmnJwtToken.CheckClaims(
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
                    //err = "server_error";
                    errDescription = Resources.ApplicationOAuthBearerTokenProvider.Invalid_client_id;
                    return false;
                }
            }
            // aud
            // exp
            if (!CmnJwtToken.CheckClaims(
                    json, OAuth2AndOIDCConst.exp,
                    out exp, out err, out errDescription))
            {
                return false;
            }
            else
            {
                if (!CmnJwtToken.VerifyExp(exp))
                {
                    //err = "server_error";
                    errDescription = "This PAR is expired.";
                    return false;
                }
            }
            // iat
            // nbf
            if (!CmnJwtToken.CheckClaims(
                json, OAuth2AndOIDCConst.nbf,
                out nbf, out err, out errDescription))
            {
                return false;
            }
            else
            {
                if (!CmnJwtToken.VerifyNbf(nbf))
                {
                    //err = "server_error";
                    errDescription = "This PAR is before enabled.";
                    return false;
                }
            }
            // jti
            // scope
            if (!CmnJwtToken.CheckClaims(
                json, OAuth2AndOIDCConst.scope,
                out scope, out err, out errDescription))
            {
                return false;
            }
            else
            {
                if (!scope.Split(' ').Any(x => x == OAuth2AndOIDCConst.Scope_Openid))
                {
                    // OIDC無効
                    //err = "server_error";
                    errDescription = string.Format(
                        "CIBA is required {0} value in scope param.",
                        OAuth2AndOIDCConst.Scope_Openid);

                    return false;
                }
            }
            // client_notification_token
            if (!CmnJwtToken.CheckClaims(
                json, OAuth2AndOIDCConst.client_notification_token,
                out client_notification_token, out err, out errDescription))
            {
                return false;
            }
            // binding_message
            if (!CmnJwtToken.CheckClaims(
                json, OAuth2AndOIDCConst.binding_message,
                out binding_message, out err, out errDescription))
            {
                return false;
            }
            // user_code
            CmnJwtToken.CheckClaims(
                json, OAuth2AndOIDCConst.user_code,
                out user_code, out err, out errDescription, nullable: true);
            // requested_expiry
            CmnJwtToken.CheckClaims(
                json, OAuth2AndOIDCConst.requested_expiry,
                out requested_expiry, out err, out errDescription, nullable: true);
            // login_hint
            if (!CmnJwtToken.CheckClaims(
                json, OAuth2AndOIDCConst.login_hint,
                out login_hint, out err, out errDescription))
            {
                return false;
            }

            return true;
        }
        #endregion

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
                if (CmnEndpoints.CheckClientMode(client_id, OAuth2AndOIDCEnum.ClientMode.normal, out jwkString, out err))
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

                // 初期値の許容レベルは最低レベルに設定
                OAuth2AndOIDCEnum.ClientMode permittedLevel = OAuth2AndOIDCEnum.ClientMode.normal;

                // ★ 未実装
                // TokenBindingの有無で、permittedLevelを変更する。
                // TokenBindingの無
                //permittedLevel = OAuth2AndOIDCEnum.ClientMode.normal;
                // TokenBindingの有
                //permittedLevel = OAuth2AndOIDCEnum.ClientMode.fapi2;

                // このフローが認められるか？
                Dictionary<string, string> err = new Dictionary<string, string>();
                if (CmnEndpoints.CheckClientMode(client_id, permittedLevel, out jwkString, out err))
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
                access_token = CmnAccessToken.ProtectFromPayload(
                	client_id, tokenPayload,
                    DateTimeOffset.Now.Add(Config.OAuth2AccessTokenExpireTimeSpanFromMinutes),
                    null, permittedLevel, out string aud, out string sub);

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
                // 初期値の許容レベルは最低レベルに設定
                OAuth2AndOIDCEnum.ClientMode permittedLevel = OAuth2AndOIDCEnum.ClientMode.normal;

                #region 認証

                bool authned = false;
                if (grant_type.ToLower() == OAuth2AndOIDCConst.AuthorizationCodeGrantType)
                {
                    if (string.IsNullOrEmpty(code_verifier) && string.IsNullOrEmpty(assertion))
                    {
                        // client_id & (client_secret or x509)
                        authned = CmnEndpoints.ClientAuthentication(
                            client_id, client_secret, ref x509, out permittedLevel);
                    }
                    else if (!string.IsNullOrEmpty(code_verifier)
                        && string.IsNullOrEmpty(client_secret))
                    {
                        // PKCE (client_id & code_verifier)
                        AuthorizationCodeProvider.ReceiveChallenge(
                            code, client_id, redirect_uri,
                            out string code_challenge_method, out string code_challenge);

                        if (!string.IsNullOrEmpty(code_challenge_method))
                        {
                            if (!string.IsNullOrEmpty(code_challenge))
                            {
                                if (code_challenge_method.ToLower() == OAuth2AndOIDCConst.PKCE_plain)
                                {
                                    if (code_challenge == code_verifier)
                                    {
                                        // passed.
                                        authned = true;
                                    }
                                }
                                else if (code_challenge_method.ToUpper() == OAuth2AndOIDCConst.PKCE_S256)
                                {
                                    if (code_challenge == OAuth2AndOIDCClient.PKCE_S256_CodeChallengeMethod(code_verifier))
                                    {
                                        // passed.
                                        authned = true;
                                        permittedLevel = OAuth2AndOIDCEnum.ClientMode.fapi1;
                                    }
                                }
                            }
                        }
                    }
                    else if (!string.IsNullOrEmpty(code_verifier)
                        && !string.IsNullOrEmpty(client_secret))
                    {
                        // "OAuth 2.0 authorization code flow with the PKCE extension"
                        //  (client_id & client_secret & code_verifier)
                        // これを実装する場合、client_id から Native か SPA否かを見極めて、
                        // SPAの場合、通常のPKCE（前カバレッジ）を拒否する実装が必要になる。
                    }
                    else if (!string.IsNullOrEmpty(assertion))
                    {
                        // assertion
                        authned = CmnEndpoints.ClientAuthentication(
                            assertion, out client_id, ref x509, out permittedLevel);
                    }
                }

                #endregion

                if (authned)
                {
                    string tokenPayload = AuthorizationCodeProvider.Receive(code, client_id, redirect_uri);

                    #region CheckClientMode

                    // このフローが認められるか？
                    if (CmnEndpoints.CheckClientMode(client_id, permittedLevel, out jwkString, out err))
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
                    string access_token = CmnAccessToken.ProtectFromPayload(
                        client_id, tokenPayload,
                        DateTimeOffset.Now.Add(Config.OAuth2AccessTokenExpireTimeSpanFromMinutes),
                        x509, permittedLevel, out string aud, out string sub);

                    // Client認証のclient_idとToken類のaudをチェック
                    if (client_id != aud)
                    {
                        err.Add(OAuth2AndOIDCConst.error, OAuth2AndOIDCConst.invalid_grant);
                        err.Add(OAuth2AndOIDCConst.error_description, "The code was not issued to this client.");
                        return false;
                    }

                    // refresh_token
                    string refresh_token = "";
                    if (Config.EnableRefreshToken)
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
            string grant_type, string client_id, string client_secret, X509Certificate2 x509,
            string refresh_token, out Dictionary<string, string> ret, out Dictionary<string, string> err)
        {
            ret = null;

            string jwkString = "";
            err = new Dictionary<string, string>();

            if (Config.EnableRefreshToken)
            {
                #region 認証

                bool authned = false;
                if (grant_type.ToLower() == OAuth2AndOIDCConst.RefreshTokenGrantType)
                {
                    // client_id & (client_secret or x509)
                    authned = CmnEndpoints.ClientAuthentication(client_id, client_secret,
                        ref x509,　out OAuth2AndOIDCEnum.ClientMode permittedLevel);
                }

                #endregion

                if (authned)
                {
                    #region CheckClientMode

                    // このフローが認められるか？
                    if (CmnEndpoints.CheckClientMode(client_id, OAuth2AndOIDCEnum.ClientMode.normal, out jwkString, out err))
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

                    string tokenPayload = RefreshTokenProvider.Receive(refresh_token);

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
                            new_refresh_token = RefreshTokenProvider.Create(tokenPayload);
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
            string client_secret, X509Certificate2 x509,
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
                if (grant_type.ToLower() == OAuth2AndOIDCConst.ResourceOwnerPasswordCredentialsGrantType)
                {
                    // client_id & client_secret
                    authned = CmnEndpoints.ClientAuthentication(client_id, client_secret,
                        ref x509, out OAuth2AndOIDCEnum.ClientMode permittedLevel);
                }

                #endregion

                if (authned)
                {
                    #region CheckClientMode

                    // このフローが認められるか？
                    if (CmnEndpoints.CheckClientMode(client_id, OAuth2AndOIDCEnum.ClientMode.normal, out jwkString, out err))
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
                            err.Add(OAuth2AndOIDCConst.error, "access_denied");
                            err.Add(OAuth2AndOIDCConst.error_description, Resources.ApplicationOAuthBearerTokenProvider.access_denied);
                        }
                    }
                    else
                    {
                        // ユーザーが見つからない場合。
                        err.Add(OAuth2AndOIDCConst.error, "access_denied");
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
            string grant_type, string client_id, string client_secret, X509Certificate2 x509,
            string scopes, out Dictionary<string, string> ret, out Dictionary<string, string> err)
        {
            ret = null;

            string jwkString = "";
            err = new Dictionary<string, string>();

            if (Config.EnableClientCredentialsGrantType)
            {
                #region 認証

                bool authned = false;
                if (grant_type.ToLower() == OAuth2AndOIDCConst.ClientCredentialsGrantType)
                {
                    // client_id & client_secret
                    authned = CmnEndpoints.ClientAuthentication(client_id, client_secret,
                        ref x509, out OAuth2AndOIDCEnum.ClientMode permittedLevel);
                }

                #endregion

                if (authned)
                {
                    #region CheckClientMode

                    // このフローが認められるか？
                    if (CmnEndpoints.CheckClientMode(client_id, OAuth2AndOIDCEnum.ClientMode.normal, out jwkString, out err))
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
        /// <param name="ret">Dictionary(string, string)</param>
        /// <param name="err">Dictionary(string, string)</param>
        /// <returns>成否</returns>
        public static bool GrantJwtBearerTokenCredentials(
            string grant_type, string assertion, X509Certificate2 x509,
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
                            if (CmnEndpoints.CheckClientMode(iss, OAuth2AndOIDCEnum.ClientMode.normal, out jwkString, out err))
                            {
                                // JwtTokenを作る

                                // issに対応するsubを取得する。
                                string sub = Helper.GetInstance().GetClientName(iss);

                                // ClaimsIdentityにClaimを追加する。
                                ClaimsIdentity identity = new ClaimsIdentity(OAuth2AndOIDCConst.Bearer);

                                // ClaimsIdentityに、その他、所定のClaimを追加する。
                                identity.AddClaim(new Claim(ClaimTypes.Name, sub));
                                // scopes_supported に無いスコープと、クライアントに許されていないスコープは発行しない（#198）
                                identity = Helper.AddClaim(identity, iss, Helper.FilterSupportedScopes(scopes.Split(' '), iss), null, "");

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
                    string refresh_token = "";
                    if (Config.EnableRefreshToken)
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
                if (grant_type.ToLower() == OAuth2AndOIDCConst.CibaGrantType)
                {
                    // client_id & (client_secret or x509)
                    authned = CmnEndpoints.ClientAuthentication(client_id, client_secret,
                        ref x509, out OAuth2AndOIDCEnum.ClientMode permittedLevel);
                }

                #endregion

                if (authned)
                {
                    #region CheckClientMode

                    // このフローが認められるか？（fapi2に設定
                    if (CmnEndpoints.CheckClientMode(client_id, OAuth2AndOIDCEnum.ClientMode.fapi_ciba, out jwkString, out err))
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

        #region Token所有者の確認

        /// <summary>Tokenが、認証したクライアントに発行されたものかを確認する</summary>
        /// <param name="client_id">認証済みのclient_id</param>
        /// <param name="identity">ClaimsIdentity（VerifyAccessTokenの結果）</param>
        /// <returns>bool</returns>
        /// <remarks>RFC 7009 2.1 / RFC 7662 2.1（#194）</remarks>
        public static bool CheckTokenOwner(string client_id, ClaimsIdentity identity)
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
        public static bool CheckRefreshTokenOwner(string client_id, string tokenPayload)
        {
            if (string.IsNullOrEmpty(client_id) || string.IsNullOrEmpty(tokenPayload)) return false;

            JObject payload = (JObject)JsonConvert.DeserializeObject(tokenPayload);

            return (payload != null
                && (string)payload[OAuth2AndOIDCConst.aud] == client_id);
        }

        #endregion

        #region RevokeToken / IntrospectToken

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
                    ret.Add("active", false);
                    return ret;
                }

                // メタデータの返却
                ret.Add("active", true);
                ret.Add(OAuth2AndOIDCConst.token_type, type);

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
            ret.Add("active", false);
            return ret;
        }

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

        #region エラー応答の HTTP ステータス

        /// <summary>エラー応答の HTTP ステータスを決める（RFC 6749 5.2）</summary>
        /// <param name="err">error / error_description を持つ辞書</param>
        /// <returns>HTTP ステータス（invalid_client は 401、それ以外は 400）</returns>
        /// <remarks>
        /// 以前は、どのエンドポイントも Dictionary をそのまま返していたため、エラーでも HTTP 200 だった（#196）。
        /// RFC 6749 5.2 : エラーは 400。invalid_client（クライアント認証の失敗）は 401。
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

            return (error == OAuth2AndOIDCConst.invalid_client) ? 401 : 400;
        }

        #endregion

        #endregion

        #region Private

        #region　ClientAuthentication

        #region client_id & (client_secret or x509)

        /// <summary>ClientAuthentication</summary>
        /// <param name="client_id">string</param>
        /// <param name="client_secret">string</param>
        /// <param name="x509">X509Certificate2</param>
        /// <param name="permittedLevel">OAuth2AndOIDCEnum.ClientMode</param>
        /// <returns>bool</returns>
        public static bool ClientAuthentication(string client_id, string client_secret,
            ref X509Certificate2 x509, out OAuth2AndOIDCEnum.ClientMode permittedLevel)
        {
            permittedLevel = OAuth2AndOIDCEnum.ClientMode.normal;

            // client_id & client_secret
            if (!string.IsNullOrEmpty(client_id))
            {
                if (!string.IsNullOrEmpty(client_secret))
                {
                    // *.config or Saml2OAuth2Dataテーブルを参照して、
                    // クライアント認証（client_secret）を行なう。
                    if (client_secret == Helper.GetInstance().GetClientSecret(client_id))
                    {
                        //permittedLevel = OAuth2AndOIDCEnum.ClientMode.normal;
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
                        permittedLevel = OAuth2AndOIDCEnum.ClientMode.fapi2;
                        return true;
                    }
                }
            }

            return false;
        }

        #endregion

        #region Device AuthZ

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
                    out OAuth2AndOIDCEnum.ClientMode permittedLevel);
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
        /// <param name="permittedLevel">OAuth2AndOIDCEnum.ClientMode</param>
        /// <returns>bool</returns>
        public static bool ClientAuthentication(string assertion, out string client_id,
            ref X509Certificate2 x509, out OAuth2AndOIDCEnum.ClientMode permittedLevel)
        {
            if (!string.IsNullOrEmpty(assertion))
            {
                // assertionがあった場合、x509を無効化
                x509 = null;

                // pubKey
                Dictionary<string, string> dic = JsonConvert.DeserializeObject<Dictionary<string, string>>(
                    CustomEncode.ByteToString(CustomEncode.FromBase64UrlString(
                        assertion.Split('.')[1]), CustomEncode.us_ascii));

                string pubKey = Helper.GetInstance().GetJwkRsaPublickey(dic[OAuth2AndOIDCConst.iss]);
                pubKey = CustomEncode.ByteToString(CustomEncode.FromBase64UrlString(pubKey), CustomEncode.us_ascii);

                if (!string.IsNullOrEmpty(pubKey))
                {
                    // 署名検証 ≒ クライアント認証
                    if (JwtAssertion.Verify(
                        assertion, out string iss, out string aud, out string scopes, out JObject jobj, pubKey))
                    {
                        // aud 検証
                        if (aud == Config.OAuth2AuthorizationServerEndpointsRootURI + Config.OAuth2TokenEndpoint)
                        {
                            permittedLevel = OAuth2AndOIDCEnum.ClientMode.fapi1;
                            client_id = iss;
                            return true;
                        }
                    }
                }
            }

            permittedLevel = OAuth2AndOIDCEnum.ClientMode.normal;
            client_id = "";
            return false;
        }

        #endregion

        #endregion

        #region CheckClientMode

        /// <summary>CheckClientMode</summary>
        /// <param name="client_id">ClientId</param>
        /// <param name="permittedLevel">当該フローのClientModeの許容レベル</param>
        /// <param name="jwkString">jwkString</param>
        /// <param name="err">Dictionary(string, string)</param>
        /// <returns>継続の可否</returns>
        private static bool CheckClientMode(
            string client_id,
            OAuth2AndOIDCEnum.ClientMode permittedLevel,
            out string jwkString,
            out Dictionary<string, string> err)
        {
            // ret
            bool retval = false;

            // out
            jwkString = "";
            err = new Dictionary<string, string>();

            // 要求値を最大値に設定
            OAuth2AndOIDCEnum.ClientMode clientModeEnum = OAuth2AndOIDCEnum.ClientMode.fapi2;

            // clientMode <= permittedLevel であればOK。
            string clientModeString = "";
            if (string.IsNullOrEmpty(client_id))
            {
                err.Add(OAuth2AndOIDCConst.error, OAuth2AndOIDCConst.invalid_client);
                err.Add(OAuth2AndOIDCConst.error_description, string.Format("client_id is not set."));
                return false; // NullOrEmptyだとmode無しとかになるのでここで切る。
            }
            else
            {
                clientModeString = Helper.GetInstance().GetClientMode(client_id);

                if (clientModeString == OAuth2AndOIDCEnum.ClientMode.normal.ToStringByEmit())
                {
                    clientModeEnum = (int)OAuth2AndOIDCEnum.ClientMode.normal;
                }
                else if (clientModeString == OAuth2AndOIDCEnum.ClientMode.fapi1.ToStringByEmit())
                {
                    clientModeEnum = OAuth2AndOIDCEnum.ClientMode.fapi1;
                }
                else if (clientModeString == OAuth2AndOIDCEnum.ClientMode.fapi2.ToStringByEmit())
                {
                    clientModeEnum = OAuth2AndOIDCEnum.ClientMode.fapi2;
                    jwkString = CustomEncode.ByteToString(CustomEncode.FromBase64UrlString(
                        Helper.GetInstance().GetJwkRsaPublickey(client_id)), CustomEncode.us_ascii);
                }
                else if (clientModeString == OAuth2AndOIDCEnum.ClientMode.device.ToStringByEmit())
                {
                    clientModeEnum = OAuth2AndOIDCEnum.ClientMode.device;
                }
                else if (clientModeString == OAuth2AndOIDCEnum.ClientMode.fapi_ciba.ToStringByEmit())
                {
                    clientModeEnum = OAuth2AndOIDCEnum.ClientMode.fapi_ciba;
                }
            }

            if ((int)permittedLevel <= (int)OAuth2AndOIDCEnum.ClientMode.fapi2)
            {
                // permittedLevelがfapi2以下の場合
                if ((int)clientModeEnum <= (int)permittedLevel)
                {
                    // permittedLevelがclientMode以上
                    retval = true;
                }
                else
                {
                    // permittedLevelがclientMode未満
                    if (clientModeEnum == OAuth2AndOIDCEnum.ClientMode.device
                        && permittedLevel == OAuth2AndOIDCEnum.ClientMode.fapi1)
                    {
                        // LIRでPKCEを使用した場合、
                        // ・clientModeEnum = device
                        // ・permittedLevel = fapi1
                        // ...となるので例外措置を施す。
                        retval = true;
                    }
                    else
                    {
                        // 上記以外の場合、
                        retval = false;
                    }
                }
            }
            else
            {
                // permittedLevelがfapi2より大きい場合
                // 大小関係は意味を持たず、一致している必要がある。
                if ((int)clientModeEnum == (int)permittedLevel)
                    retval = true;
                else
                    retval = false;
            }

            if (!retval)
            {
                // エラーを追加
                err.Add(OAuth2AndOIDCConst.error, OAuth2AndOIDCConst.unsupported_grant_type);

                if (string.IsNullOrEmpty(clientModeString))
                {
                    err.Add(OAuth2AndOIDCConst.error_description, string.Format("This client is not set the mode."));
                }
                else
                {
                    err.Add(OAuth2AndOIDCConst.error_description, string.Format(
                        "This client is set the {0} mode, but this flow permitted up to {1} mode.",
                        clientModeString, permittedLevel.ToStringByEmit()));
                }
            }

            return retval;
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