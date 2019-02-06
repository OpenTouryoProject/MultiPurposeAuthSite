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
//*  2019/02/xx  西野 大介         - Token生成処理の集約（code + Implicitも ★）
//*                                - CheckClientModeの集約
//*                                - Client認証のclient_idとtoken類のaudをチェック ★
//*                                - オペレーション・トレース・ログ出力の集約
//*                                  - 情報源
//*                                    - Client情報はclient_idから取得する。
//*                                    - User情報はTokenのsubから取得する。 ★
//*                                  - 以下は、Client = User
//*                                    - GrantClientCredentials
//*                                    - GrantJwtBearerTokenCredentials
//**********************************************************************************

using MultiPurposeAuthSite.Co;
#if NETFX
using MultiPurposeAuthSite.Entity;
#else
using MultiPurposeAuthSite;
#endif
using MultiPurposeAuthSite.Data;
using MultiPurposeAuthSite.Password;
using MultiPurposeAuthSite.Log;
using MultiPurposeAuthSite.Extensions.OAuth2;

using System;
using System.Collections.Generic;
using System.Security.Claims;

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

            OpenIDConfig.Add("issuer", Config.OAuth2IssuerId);

            OpenIDConfig.Add("authorization_endpoint",
                Config.OAuth2AuthorizationServerEndpointsRootURI + Config.OAuth2AuthorizeEndpoint);

            OpenIDConfig.Add("token_endpoint",
                Config.OAuth2AuthorizationServerEndpointsRootURI + Config.OAuth2TokenEndpoint);

            OpenIDConfig.Add("userinfo_endpoint",
                Config.OAuth2AuthorizationServerEndpointsRootURI + Config.OAuth2UserInfoEndpoint);

            #endregion

            #region オプション

            List<string> grant_types_supported = new List<string>();
            List<string> response_types_supported = new List<string>();
            List<string> scopes_supported = new List<string>();

            OpenIDConfig.Add("grant_types_supported", grant_types_supported);
            OpenIDConfig.Add("response_types_supported", response_types_supported);
            OpenIDConfig.Add("scopes_supported", scopes_supported);

            #region token

            scopes_supported.Add(OAuth2AndOIDCConst.Scope_Profile);
            scopes_supported.Add(OAuth2AndOIDCConst.Scope_Email);
            scopes_supported.Add(OAuth2AndOIDCConst.Scope_Phone);
            scopes_supported.Add(OAuth2AndOIDCConst.Scope_Address);
            scopes_supported.Add(OAuth2AndOIDCConst.Scope_Auth);
            scopes_supported.Add(OAuth2AndOIDCConst.Scope_UserID);
            scopes_supported.Add(OAuth2AndOIDCConst.Scope_Roles);
            //scopes_supported.Add(OAuth2AndOIDCConst.Scope_Openid);↓で追加

            OpenIDConfig.Add("token_endpoint_auth_methods_supported", new List<string> {
                OAuth2AndOIDCEnum.AuthMethods.client_secret_basic.ToStringFromEnum(),
                OAuth2AndOIDCEnum.AuthMethods.private_key_jwt.ToStringFromEnum()
            });

            OpenIDConfig.Add("token_endpoint_auth_signing_alg_values_supported", new List<string> {
                "RS256"
            });

            #endregion

            #region grant_types and response_types

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

            if (Config.EnableJwtBearerTokenFlowGrantType)
            {
                grant_types_supported.Add(OAuth2AndOIDCConst.JwtBearerTokenFlowGrantType);
            }

            if (Config.EnableRefreshToken)
            {
                grant_types_supported.Add(OAuth2AndOIDCConst.RefreshTokenGrantType);
            }


            #endregion

            #region OpenID Connect

            if (Config.EnableOpenIDConnect)
            {
                scopes_supported.Add(OAuth2AndOIDCConst.Scope_Openid);

                response_types_supported.Add(OAuth2AndOIDCConst.OidcImplicit2_ResponseType);
                response_types_supported.Add(OAuth2AndOIDCConst.OidcHybrid2_Token_ResponseType);
                response_types_supported.Add(OAuth2AndOIDCConst.OidcHybrid2_IdToken_ResponseType);
                response_types_supported.Add(OAuth2AndOIDCConst.OidcHybrid3_ResponseType);

                // subject_types_supported
                OpenIDConfig.Add("subject_types_supported", new List<string> {
                    "public"
                });

                // claims_supported
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
                    OAuth2AndOIDCConst.s_hash
                });

                OpenIDConfig.Add("id_token_signing_alg_values_supported", new List<string> {
                    "RS256"
                });

                OpenIDConfig.Add("jwks_uri",
                    Config.OAuth2AuthorizationServerEndpointsRootURI + OAuth2AndOIDCParams.JwkSetUri);
            }

            #endregion

            #region OAuth2拡張

            #region response_modes
            OpenIDConfig.Add("response_modes_supported", new List<string> {
                OAuth2AndOIDCEnum.ResponseMode.query.ToStringFromEnum(),
                OAuth2AndOIDCEnum.ResponseMode.fragment.ToStringFromEnum(),
                OAuth2AndOIDCEnum.ResponseMode.form_post.ToStringFromEnum()
            });
            #endregion

            #region revocation

            OpenIDConfig.Add("revocation_endpoint", new List<string> {
                Config.OAuth2AuthorizationServerEndpointsRootURI + Config.OAuth2RevokeTokenEndpoint
            });

            OpenIDConfig.Add("revocation_endpoint_auth_methods_supported", new List<string> {
               OAuth2AndOIDCEnum.AuthMethods.client_secret_basic.ToStringFromEnum()
            });

            #endregion

            #region revocation

            OpenIDConfig.Add("introspection_endpoint", new List<string> {
                Config.OAuth2AuthorizationServerEndpointsRootURI + Config.OAuth2IntrospectTokenEndpoint
            });

            OpenIDConfig.Add("introspection_endpoint_auth_methods_supported", new List<string> {
               OAuth2AndOIDCEnum.AuthMethods.client_secret_basic.ToStringFromEnum()
            });

            #endregion

            #region OAuth2拡張

            OpenIDConfig.Add("code_challenge_methods_supported", new List<string> {
                OAuth2AndOIDCConst.PKCE_plain,
                OAuth2AndOIDCConst.PKCE_S256
            });

            #endregion

            OpenIDConfig.Add("service_documentation", "・・・");

            #endregion

            #endregion

            return OpenIDConfig;
        }

        #endregion

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
        public static bool ValidateAuthZReqParam(
            string grant_type, string client_id, string redirect_uri,
            string response_type, string scope, string nonce,
            out string valid_redirect_uri, out string err, out string errDescription)
        {
            valid_redirect_uri = "";
            err = "";
            errDescription = "";

            #region grant_type

            // grant_typeチェック
            if (!string.IsNullOrEmpty(grant_type))
            {
                if (grant_type.ToLower() == OAuth2AndOIDCConst.RefreshTokenGrantType
                    || grant_type.ToLower() == OAuth2AndOIDCConst.ClientCredentialsGrantType
                    || grant_type.ToLower() == OAuth2AndOIDCConst.ResourceOwnerPasswordCredentialsGrantType
                    || grant_type.ToLower() == OAuth2AndOIDCConst.JwtBearerTokenFlowGrantType)
                {
                    err = "server_error";
                    errDescription = "This grant_type is valid in here.";
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
                        err = "server_error";
                        errDescription = Resources.ApplicationOAuthBearerTokenProvider.EnableAuthorizationCodeGrantType;
                        return false;
                    }
                }
                else if (response_type.ToLower() == OAuth2AndOIDCConst.ImplicitResponseType)
                {
                    if (!Config.EnableImplicitGrantType)
                    {
                        err = "server_error";
                        errDescription = Resources.ApplicationOAuthBearerTokenProvider.EnableImplicitGrantType;
                        return false;
                    }
                }
                else
                {
                    // OIDCチェック
                    if (scope.IndexOf(OAuth2AndOIDCConst.Scope_Openid) != -1) // トリガはscope=openid
                    {
                        // OIDC有効
                        if (!Config.EnableOpenIDConnect)
                        {
                            err = "server_error";
                            errDescription = "OIDC is not enabled.";
                            return false;
                        }

                        // nonceパラメタ 必須
                        if (string.IsNullOrEmpty(nonce))
                        {
                            err = "server_error";
                            errDescription = "There was no nonce in query.";
                            return false;
                        }
                    }
                    else
                    {
                        // response_typeチェック
                        if (response_type.ToLower() == OAuth2AndOIDCConst.OidcImplicit1_ResponseType
                            || response_type.ToLower() == OAuth2AndOIDCConst.OidcImplicit2_ResponseType
                            || response_type.ToLower() == OAuth2AndOIDCConst.OidcHybrid2_IdToken_ResponseType
                            || response_type.ToLower() == OAuth2AndOIDCConst.OidcHybrid2_Token_ResponseType
                            || response_type.ToLower() == OAuth2AndOIDCConst.OidcHybrid3_ResponseType)
                        {
                            err = "server_error";
                            errDescription = "This response_type is valid only for oidc.";
                            return false;
                        }
                    }
                }
            }

            #endregion

            #region redirect_uri

            // redirect_uriのチェック
            if (string.IsNullOrEmpty(redirect_uri))
            {
                // redirect_uriの指定が無い。

                // クライアント識別子に対応する事前登録したredirect_uriを取得する。
                redirect_uri = Helper.GetInstance().GetClientsRedirectUri(client_id, response_type);

                if (!string.IsNullOrEmpty(redirect_uri))
                {
                    // 事前登録されている。
                    if (redirect_uri.ToLower() == "test_self_code")
                    {
                        // Authorization Codeグラント種別のテスト用のセルフRedirectエンドポイント
                        valid_redirect_uri = Config.OAuth2ClientEndpointsRootURI + Config.OAuth2AuthorizationCodeGrantClient_Account;
                    }
                    else if (redirect_uri.ToLower() == "test_self_token")
                    {
                        // Implicitグラント種別のテスト用のセルフRedirectエンドポイント
                        valid_redirect_uri = Config.OAuth2ClientEndpointsRootURI + Config.OAuth2ImplicitGrantClient_Account;
                    }
                    else if (redirect_uri.ToLower() == "id_federation_code")
                    {
                        // ID連携時のエンドポイント
                        valid_redirect_uri = Config.IdFederationRedirectEndPoint;
                    }
                    else
                    {
                        // 事前登録した、redirect_uriをそのまま使用する。
                        valid_redirect_uri = redirect_uri;
                    }

                    return true;
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
                    // 不特定多数のクライアント識別子に許可されたredirect_uri
                    valid_redirect_uri = redirect_uri;
                    return true;
                }
                else
                {
                    // クライアント識別子に対応する事前登録したredirect_uriに
                    string preRegisteredUri = Helper.GetInstance().GetClientsRedirectUri(client_id, response_type);

                    //if (redirect_uri.StartsWith(preRegisteredUri))
                    if (redirect_uri == preRegisteredUri)
                    {
                        // 完全一致する場合。
                        valid_redirect_uri = redirect_uri;
                        return true;
                    }
                    else
                    {
                        // 完全一致しない場合。
                        err = "server_error";
                        errDescription = Resources.ApplicationOAuthBearerTokenProvider.Invalid_redirect_uri;
                        return false;
                    }
                }
            }

            #endregion

            // 結果を返す。
            return false;
        }

        #endregion

        #region CreateToken

        #region GrantAuthorizationCodeCredentials

        /// <summary>
        /// GrantAuthorizationCodeCredentials
        /// Authorization Codeグラント種別
        /// </summary>
        /// <param name="grant_type">string</param>
        /// <param name="client_id">string</param>
        /// <param name="client_secret">string</param>
        /// <param name="assertion">string</param>
        /// <param name="code">string</param>
        /// <param name="code_verifier">string</param>
        /// <param name="redirect_uri">string</param>
        /// <param name="ret">Dictionary(string, string)</param>
        /// <param name="err">Dictionary(string, string)</param>
        /// <returns>成否</returns>
        public static bool GrantAuthorizationCodeCredentials(
            string grant_type, string client_id, string client_secret, string assertion,
            string code, string code_verifier, string redirect_uri,
            out Dictionary<string, string> ret, out Dictionary<string, string> err)
        {
            ret = null;
            err = new Dictionary<string, string>();

            if (Config.EnableAuthorizationCodeGrantType)
            {
                // 初期値の許容レベルは最高値に設定
                OAuth2AndOIDCEnum.ClientMode acceptedLevel = OAuth2AndOIDCEnum.ClientMode.fapi2;

                #region 認証

                bool authned = false;
                if (grant_type.ToLower() == OAuth2AndOIDCConst.AuthorizationCodeGrantType)
                {
                    if (!string.IsNullOrEmpty(client_secret))
                    {
                        // client_id & client_secret
                        if (!(string.IsNullOrEmpty(client_id) && string.IsNullOrEmpty(client_secret)))
                        {
                            // *.config or OAuth2Dataテーブルを参照してクライアント認証を行なう。
                            if (client_secret == Helper.GetInstance().GetClientSecret(client_id))
                            {
                                authned = true;
                                acceptedLevel = OAuth2AndOIDCEnum.ClientMode.normal;
                            }
                        }
                    }
                    else if (!string.IsNullOrEmpty(assertion))
                    {
                        // assertion
                        Dictionary<string, string> dic = JsonConvert.DeserializeObject<Dictionary<string, string>>(
                            CustomEncode.ByteToString(CustomEncode.FromBase64UrlString(
                                assertion.Split('.')[1]), CustomEncode.us_ascii));

                        string pubKey = Helper.GetInstance().GetJwtAssertionPublickey(dic[OAuth2AndOIDCConst.iss]);
                        pubKey = CustomEncode.ByteToString(CustomEncode.FromBase64UrlString(pubKey), CustomEncode.us_ascii);

                        if (!string.IsNullOrEmpty(pubKey))
                        {
                            if (JwtAssertion.VerifyJwtBearerTokenFlowAssertionJWK(
                                assertion, out string iss, out string aud, out string scopes, out JObject jobj, pubKey))
                            {
                                // aud 検証
                                if (aud == Config.OAuth2AuthorizationServerEndpointsRootURI + Config.OAuth2TokenEndpoint)
                                {
                                    authned = true;
                                    client_id = iss;
                                    acceptedLevel = OAuth2AndOIDCEnum.ClientMode.fapi1;
                                }
                            }
                        }
                    }
                    else
                    {
                        // MTLSなどTBをチェックした場合、fapi2を設定
                        //authned = true;
                        //acceptedLevel = OAuth2AndOIDCEnum.ClientMode.fapi2;
                    }
                }

                #endregion

                #region CheckClientMode

                // このフローが認められるか？
                if (CmnEndpoints.CheckClientMode(client_id, acceptedLevel, err))
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

                if (authned)
                {
                    string tokenPayload = AuthorizationCodeProvider.Receive(code, redirect_uri, code_verifier);

                    // access_token
                    string access_token = CmnAccessToken.ProtectFromPayloadForCode(tokenPayload,
                        DateTimeOffset.Now.Add(Config.OAuth2AccessTokenExpireTimeSpanFromMinutes));

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
                        client_id, name, "u_id", "u_name")); // User Account & Client Account

                    ret = CmnEndpoints.CreateAccessTokenResponse(access_token, refresh_token);

                    return true;
                }
                else
                {
                    // クライアント認証エラー（Credential不正
                    err.Add("error", "invalid_client");
                    err.Add("error_description", "Invalid credential");
                }

                #endregion
            }
            else
            {
                // サポートされていない
                err.Add("error", "not_supported");
                err.Add("error_description", Resources.ApplicationOAuthBearerTokenProvider.EnableAuthorizationCodeGrantType);
            }

            return false;
        }

        #endregion

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
        /// <param name="tokenId">string</param>
        /// <param name="ret">Dictionary(string, string)</param>
        /// <param name="err">Dictionary(string, string)</param>
        /// <returns>成否</returns>
        public static bool GrantRefreshTokenCredentials(
            string grant_type, string client_id, string client_secret, string tokenId,
            out Dictionary<string, string> ret, out Dictionary<string, string> err)
        {
            ret = null;
            err = new Dictionary<string, string>();

            if (Config.EnableRefreshToken)
            {
                #region 認証

                bool authned = false;
                if (grant_type.ToLower() == OAuth2AndOIDCConst.RefreshTokenGrantType)
                {
                    if (!string.IsNullOrEmpty(client_secret))
                    {
                        // client_id & client_secret
                        if (!(string.IsNullOrEmpty(client_id) && string.IsNullOrEmpty(client_secret)))
                        {
                            // *.config or OAuth2Dataテーブルを参照してクライアント認証を行なう。
                            if (client_secret == Helper.GetInstance().GetClientSecret(client_id))
                            {
                                // 検証完了
                                authned = true;
                            }
                        }
                    }
                }

                #endregion

                #region CheckClientMode

                // このフローが認められるか？
                if (CmnEndpoints.CheckClientMode(client_id, OAuth2AndOIDCEnum.ClientMode.normal, err))
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

                if (authned)
                {
                    string tokenPayload = RefreshTokenProvider.Receive(tokenId);

                    if (!string.IsNullOrEmpty(tokenPayload))
                    {
                        // access_token
                        string access_token = CmnAccessToken.ProtectFromPayloadForCode(tokenPayload,
                            DateTimeOffset.Now.Add(Config.OAuth2AccessTokenExpireTimeSpanFromMinutes));

                        string refresh_token = "";
                        if (Config.EnableRefreshToken)
                        {
                            refresh_token = RefreshTokenProvider.Create(tokenPayload);
                        }

                        // オペレーション・トレース・ログ出力
                        string name = Helper.GetInstance().GetClientName(client_id);
                        Logging.MyOperationTrace(string.Format(
                            "{0}({1}) passed the 'Refresh Token flow' by {2}({3}).",
                            client_id, name, "u_id", "u_name")); // User Account & Client Account

                        ret = CmnEndpoints.CreateAccessTokenResponse(access_token, refresh_token);

                        return true;
                    }
                }
                else
                {
                    // クライアント認証エラー（Credential不正
                    err.Add("error", "invalid_client");
                    err.Add("error_description", "Invalid credential");
                }

                #endregion
            }
            else
            {
                // サポートされていない
                err.Add("error", "not_supported");
                err.Add("error_description", Resources.ApplicationOAuthBearerTokenProvider.EnableRefreshToken);
            }
            
            return false;
        }

        #endregion

        #region GrantResourceOwnerCredentials

        /// <summary>GrantResourceOwnerCredentials</summary>
        /// <param name="grant_type">string</param>
        /// <param name="client_id">string</param>
        /// <param name="client_secret">string</param>
        /// <param name="username">string</param>
        /// <param name="password">string</param>
        /// <param name="scopes">string</param>
        /// <param name="ret">Dictionary(string, string)</param>
        /// <param name="err">Dictionary(string, string)</param>
        /// <returns>成否</returns>
        public static bool GrantResourceOwnerCredentials(
            string grant_type, string client_id, string client_secret,
            string username, string password, string scopes,
            out Dictionary<string, string> ret, out Dictionary<string, string> err)
        {
            ret = null;
            err = new Dictionary<string, string>();

            if (Config.EnableResourceOwnerPasswordCredentialsGrantType)
            {
                #region 認証

                bool authned = false;
                if (grant_type.ToLower() == OAuth2AndOIDCConst.ResourceOwnerPasswordCredentialsGrantType)
                {
                    // client_id & client_secret
                    if (!string.IsNullOrEmpty(client_secret))
                    {
                        if (!(string.IsNullOrEmpty(client_id) && string.IsNullOrEmpty(client_secret)))
                        {
                            // *.config or OAuth2Dataテーブルを参照してクライアント認証を行なう。
                            if (client_secret == Helper.GetInstance().GetClientSecret(client_id))
                            {
                                // 検証完了
                                authned = true;
                            }
                        }
                    }
                }

                #endregion

                #region CheckClientMode

                // このフローが認められるか？
                if (CmnEndpoints.CheckClientMode(client_id, OAuth2AndOIDCEnum.ClientMode.normal, err))
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

                if (authned)
                {
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
                            identity = Helper.AddClaim(identity, client_id, "", scopes.Split(' '), "");

                            // access_token
                            string access_token = CmnAccessToken.CreateFromClaims(identity.Name, identity.Claims,
                                DateTimeOffset.Now.Add(Config.OAuth2AccessTokenExpireTimeSpanFromMinutes));

                            // オペレーション・トレース・ログ出力
                            string name = Helper.GetInstance().GetClientName(client_id);
                            Logging.MyOperationTrace(string.Format(
                                "{0}({1}) passed the 'resource owner password credentials flow' by {2}({3}).",
                                user.Id, user.UserName, // User Account
                                client_id, name)); // Client Account

                            ret = CmnEndpoints.CreateAccessTokenResponse(access_token, "");
                            return true;
                        }
                        else
                        {
                            // パスワードが一致しない場合。
                            err.Add("error", "access_denied");
                            err.Add("error_description", Resources.ApplicationOAuthBearerTokenProvider.access_denied);
                        }
                    }
                    else
                    {
                        // ユーザーが見つからない場合。
                        err.Add("error", "access_denied");
                        err.Add("error_description", Resources.ApplicationOAuthBearerTokenProvider.access_denied);
                    }
                }
                else
                {
                    // クライアント認証エラー（Credential不正
                    err.Add("error", "invalid_client");
                    err.Add("error_description", "Invalid credential");
                }

                #endregion
            }
            else
            {
                // サポートされていない
                err.Add("error", "not_supported");
                err.Add("error_description", Resources.ApplicationOAuthBearerTokenProvider.EnableResourceOwnerCredentialsGrantType);
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
        /// <param name="scopes">string</param>
        /// <param name="ret">Dictionary(string, string)</param>
        /// <param name="err">Dictionary(string, string)</param>
        /// <returns>成否</returns>
        public static bool GrantClientCredentials(
            string grant_type, string client_id, string client_secret, string scopes,
            out Dictionary<string, string> ret, out Dictionary<string, string> err)
        {
            ret = null;
            err = new Dictionary<string, string>();

            if (Config.EnableClientCredentialsGrantType)
            {
                #region 認証

                bool authned = false;
                if (grant_type.ToLower() == OAuth2AndOIDCConst.ClientCredentialsGrantType)
                {
                    // client_id & client_secret
                    if (!string.IsNullOrEmpty(client_secret))
                    {
                        if (!(string.IsNullOrEmpty(client_id) && string.IsNullOrEmpty(client_secret)))
                        {
                            // *.config or OAuth2Dataテーブルを参照してクライアント認証を行なう。
                            if (client_secret == Helper.GetInstance().GetClientSecret(client_id))
                            {
                                // 検証完了
                                authned = true;
                            }
                        }
                    }
                }

                #endregion

                #region CheckClientMode

                // このフローが認められるか？
                if (CmnEndpoints.CheckClientMode(client_id, OAuth2AndOIDCEnum.ClientMode.normal, err))
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

                if (authned)
                {
                    // client_idに対応するsubを取得する。
                    string sub = Helper.GetInstance().GetClientName(client_id, out bool isResourceOwner);

                    // ClaimsIdentityにClaimを追加する。
                    ClaimsIdentity identity = new ClaimsIdentity(OAuth2AndOIDCConst.Bearer);

                    if (isResourceOwner)
                    {
                        // User Accountの場合、
                        ApplicationUser user = CmnUserStore.FindByName(sub);

                        // Name Claimを追加
                        identity.AddClaim(new Claim(ClaimTypes.Name, user.UserName));

                        // ClaimsIdentityに、その他、所定のClaimを追加する。
                        identity = Helper.AddClaim(identity, client_id, "", scopes.Split(' '), "");

                        // access_token
                        string access_token = CmnAccessToken.CreateFromClaims(identity.Name, identity.Claims,
                            DateTimeOffset.Now.Add(Config.OAuth2AccessTokenExpireTimeSpanFromMinutes));

                        // オペレーション・トレース・ログ出力
                        Logging.MyOperationTrace(string.Format(
                            "{0}({1}) passed the 'client credentials flow'.",
                            user.Id, user.UserName)); // User Account

                        ret = CmnEndpoints.CreateAccessTokenResponse(access_token, "");
                        return true;
                    }
                    else
                    {
                        // Client Accountの場合、
                        if (string.IsNullOrEmpty(sub))
                        {
                            // subの取得に失敗
                            err.Add("error", "invalid_client");
                            err.Add("error_description", "sub is null or empty");

                            return false;
                        }
                        else
                        {
                            // Name Claimを追加
                            identity.AddClaim(new Claim(ClaimTypes.Name, sub));

                            // ClaimsIdentityに、その他、所定のClaimを追加する。
                            identity = Helper.AddClaim(identity, client_id, "", scopes.Split(' '), "");

                            // access_token
                            string access_token = CmnAccessToken.CreateFromClaims(identity.Name, identity.Claims,
                                DateTimeOffset.Now.Add(Config.OAuth2AccessTokenExpireTimeSpanFromMinutes));

                            // オペレーション・トレース・ログ出力
                            Logging.MyOperationTrace(string.Format(
                                "Passed the 'client credentials flow' by {0}({1}).",
                                client_id, sub)); // Client Account

                            ret = CmnEndpoints.CreateAccessTokenResponse(access_token, "");
                            return true;
                        }
                    }
                }
                else
                {
                    // クライアント認証エラー（Credential不正
                    err.Add("error", "invalid_client");
                    err.Add("error_description", "Invalid credential");
                }

                #endregion
            }
            else
            {
                // サポートされていない
                err.Add("error", "not_supported");
                err.Add("error_description", Resources.ApplicationOAuthBearerTokenProvider.EnableClientCredentialsGrantType);
            }

            return false;
        }

        #endregion

        #region GrantJwtBearerTokenCredentials

        /// <summary>GrantJwtBearerTokenCredentials</summary>

        /// <summary>
        /// GrantJwtBearerTokenCredentials
        /// Authorization Codeグラント種別
        /// </summary>
        /// <param name="grant_type">string</param>
        /// <param name="assertion">string</param>
        /// <param name="ret">Dictionary(string, string)</param>
        /// <param name="err">Dictionary(string, string)</param>
        /// <returns>成否</returns>
        public static bool GrantJwtBearerTokenCredentials(
            string grant_type, string assertion,
            out Dictionary<string, string> ret, out Dictionary<string, string> err)
        {
            ret = null;
            err = new Dictionary<string, string>();

            if (Config.EnableJwtBearerTokenFlowGrantType &&
                grant_type.ToLower() == OAuth2AndOIDCConst.JwtBearerTokenFlowGrantType)
            {
                Dictionary<string, string> dic = JsonConvert.DeserializeObject<Dictionary<string, string>>(
                    CustomEncode.ByteToString(CustomEncode.FromBase64UrlString(
                        assertion.Split('.')[1]), CustomEncode.us_ascii));

                string pubKey = Helper.GetInstance().GetJwtAssertionPublickey(dic[OAuth2AndOIDCConst.iss]);
                pubKey = CustomEncode.ByteToString(CustomEncode.FromBase64UrlString(pubKey), CustomEncode.us_ascii);

                if (!string.IsNullOrEmpty(pubKey))
                {
                    if (JwtAssertion.VerifyJwtBearerTokenFlowAssertionJWK(
                        assertion, out string iss, out string aud, out string scopes, out JObject jobj, pubKey))
                    {
                        // aud 検証
                        if (aud == Config.OAuth2AuthorizationServerEndpointsRootURI + Config.OAuth2TokenEndpoint)
                        {
                            // このフローが認められるか？
                            if (CmnEndpoints.CheckClientMode(iss, OAuth2AndOIDCEnum.ClientMode.normal, err))
                            {
                                // JwtTokenを作る

                                // issに対応するsubを取得する。
                                string sub = Helper.GetInstance().GetClientName(iss);

                                // ClaimsIdentityにClaimを追加する。
                                ClaimsIdentity identity = new ClaimsIdentity(OAuth2AndOIDCConst.Bearer);
                                identity.AddClaim(new Claim(ClaimTypes.Name, sub));
                                identity = Helper.AddClaim(identity, iss, "", scopes.Split(' '), "");

                                // access_token
                                string access_token = CmnAccessToken.CreateFromClaims(identity.Name, identity.Claims,
                                    DateTimeOffset.Now.Add(Config.OAuth2AccessTokenExpireTimeSpanFromMinutes));

                                // オペレーション・トレース・ログ出力
                                Logging.MyOperationTrace(string.Format(
                                    "Passed the 'jwt bearer token flow' by {0}({1}).",
                                    iss, sub)); // Client Account

                                ret = CmnEndpoints.CreateAccessTokenResponse(access_token, "");
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
                            err.Add("error", "invalid_client");
                            err.Add("error_description", "Invalid credential");
                        }
                    }
                    else
                    {
                        // クライアント認証エラー（Credential（署名）不正
                        err.Add("error", "invalid_client");
                        err.Add("error_description", "Invalid credential");
                    }
                }
                else
                {
                    // クライアント認証エラー（Credential（iss or pubKey）不正
                    err.Add("error", "invalid_client");
                    err.Add("error_description", "Invalid credential");
                }
            }

            return false;
        }

        #endregion

        #endregion

        #region CreateAutheNRes4HybridFlow

        /// <summary>CreateAutheNRes4HybridFlow</summary>
        /// <param name="client_id">string</param>
        /// <param name="code">string</param>
        /// <param name="state">string</param>
        /// <param name="access_token">string</param>
        /// <param name="refresh_token">string</param>
        public static void CreateAutheNRes4HybridFlow(
            string client_id, string code, string state, out string access_token, out string id_token)
        {
            access_token = "";
            id_token = "";

            string tokenPayload = AuthorizationCodeProvider.GetAccessTokenPayload(code);

            // ★ 必要に応じて、scopeを調整する。

            // access_token
            access_token = CmnAccessToken.ProtectFromPayloadForCode(tokenPayload,
                DateTimeOffset.Now.Add(Config.OAuth2AccessTokenExpireTimeSpanFromMinutes));

            JObject jObj = (JObject)JsonConvert.DeserializeObject(
                            CustomEncode.ByteToString(CustomEncode.FromBase64UrlString(
                                access_token.Split('.')[1]), CustomEncode.us_ascii));

            // id_token
            JArray jAry = (JArray)jObj["scopes"];
            foreach (string s in jAry)
            {
                if (s == OAuth2AndOIDCConst.Scope_Openid)
                {
                    id_token = IdToken.ChangeToIdTokenFromAccessToken(
                        access_token, code, state, // at_hash, c_hash, s_hash
                        HashClaimType.AtHash | HashClaimType.CHash | HashClaimType.SHash,
                        Config.OAuth2JWT_pfx, Config.OAuth2JWTPassword);
                }
            }

            // オペレーション・トレース・ログ出力
            string name = Helper.GetInstance().GetClientName(client_id);
            Logging.MyOperationTrace(string.Format(
                "{0}({1}) passed the authorization endpoint of Hybrid by {2}({3}).",
                client_id, name, "u_id", "u_name")); // User Account & Client Account
        }

        #endregion

        #region CreateAccessTokenResponse

        /// <summary>CreateAccessTokenResponse</summary>
        /// <param name="access_token">string</param>
        /// <param name="refresh_token">string</param>
        /// <returns>Dictionary(string, string)</returns>
        private static Dictionary<string, string> CreateAccessTokenResponse(string access_token, string refresh_token)
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

            JObject jObj = (JObject)JsonConvert.DeserializeObject(
                            CustomEncode.ByteToString(CustomEncode.FromBase64UrlString(
                                access_token.Split('.')[1]), CustomEncode.us_ascii));

            // id_token
            JArray jAry = (JArray)jObj["scopes"];
            foreach (string s in jAry)
            {
                if (s == OAuth2AndOIDCConst.Scope_Openid)
                {
                    string id_token = IdToken.ChangeToIdTokenFromAccessToken(
                        access_token, "", "", // c_hash, s_hash は /token で生成不可
                        HashClaimType.None, Config.OAuth2JWT_pfx, Config.OAuth2JWTPassword);

                    if (!string.IsNullOrEmpty(id_token))
                    {
                        ret.Add(OAuth2AndOIDCConst.IDToken, id_token);
                    }
                }
            }

            // expires_in
            ret.Add("expires_in", Config.OAuth2AccessTokenExpireTimeSpanFromMinutes.Seconds.ToString());

            return ret;
        }

        #endregion

        #region CheckClientMode

        /// <summary>CheckClientMode</summary>
        /// <param name="client_id">ClientId</param>
        /// <param name="acceptedLevel">当該フローのClientModeの許容レベル</param>
        /// <param name="err">Dictionary(string, string)</param>
        /// <returns>継続の可否</returns>
        public static bool CheckClientMode(
            string client_id,
            OAuth2AndOIDCEnum.ClientMode acceptedLevel,
            Dictionary<string, string> err)
        {
            bool retval = false;

            string clientMode = Helper.GetInstance().GetClientMode(client_id);

            // switch には定数値が必要なので if で。
            if (clientMode == OAuth2AndOIDCEnum.ClientMode.normal.ToStringFromEnum())
            {
                // clientMode == normal
                if (acceptedLevel == OAuth2AndOIDCEnum.ClientMode.normal)
                {
                    // acceptedLevel == normal
                    retval = true;
                }
                else
                {
                    // acceptedLevel != normal
                    retval = false;
                }
            }
            else if (clientMode == OAuth2AndOIDCEnum.ClientMode.fapi1.ToStringFromEnum())
            {
                // clientMode == fapi1
                if (acceptedLevel == OAuth2AndOIDCEnum.ClientMode.normal)
                {
                    // acceptedLevel == normal
                    retval = false; 
                }
                else
                {
                    // acceptedLevel != normal, == fapi1 or fapi2
                    retval = true;
                }
            }
            else if (clientMode == OAuth2AndOIDCEnum.ClientMode.fapi2.ToStringFromEnum())
            {
                // clientMode == fapi2
                if (acceptedLevel == OAuth2AndOIDCEnum.ClientMode.normal
                    || acceptedLevel == OAuth2AndOIDCEnum.ClientMode.fapi1)
                {
                    // acceptedLevel == normal, == fapi1
                    retval = false;
                }
                else
                {
                    // acceptedLevel != normal || != fapi1, == fapi2
                    retval = true;
                }
            }

            if (!retval)
            {
                // エラーを追加
                err.Add("error", "not_supported");

                if (string.IsNullOrEmpty(clientMode))
                {
                    err.Add("error_description", string.Format("This client is not set the mode."));
                }
                else
                {
                    err.Add("error_description", string.Format("This client is required the {0} mode.", clientMode));
                }
            }

            return retval;
        }

        #endregion
    }
}