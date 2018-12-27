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
//* クラス名        ：OAuth2EndpointApiController
//* クラス日本語名  ：OAuth2EndpointのApiController
//*
//* 作成日時        ：－
//* 作成者          ：－
//* 更新履歴        ：－
//*
//*  日時        更新者            内容
//*  ----------  ----------------  -------------------------------------------------
//*  2017/04/24  西野 大介         新規
//*  2018/12/26  西野 大介         分割
//**********************************************************************************

using MultiPurposeAuthSite.Co;
using MultiPurposeAuthSite.Entity;
using MultiPurposeAuthSite.Data;
using MultiPurposeAuthSite.Log;

using MultiPurposeAuthSite.TokenProviders;
using MultiPurposeAuthSite.Extensions.OAuth2;

using System;
using System.Text;
using System.Linq;
using System.Collections.Generic;
using System.Security.Claims;
using System.Threading.Tasks;

using System.Web;
using System.Web.Http;
using System.Web.Http.Cors;
using System.Net.Http;
using System.Net.Http.Formatting;

using Microsoft.Owin.Security;

using Newtonsoft.Json;
using Newtonsoft.Json.Linq;
using Newtonsoft.Json.Serialization;

using Touryo.Infrastructure.Business.Presentation;
using Touryo.Infrastructure.Framework.Authentication;
using Touryo.Infrastructure.Framework.Presentation;
using Touryo.Infrastructure.Public.IO;
using Touryo.Infrastructure.Public.Str;

/// <summary>MultiPurposeAuthSite.Controllers</summary>
namespace MultiPurposeAuthSite.Controllers
{
    /// <summary>OAuth2ResourceServerのApiController（ライブラリ）</summary>
    [EnableCors(
        // リソースへのアクセスを許可されている発生元
        origins: "*",
        // リソースによってサポートされているヘッダー
        headers: "*",
        // リソースによってサポートされているメソッド
        methods: "*",
        // 
        SupportsCredentials = true)]
    public class OAuth2EndpointApiController : ApiController
    {
        #region /.well-known/openid-configuration

        /// <summary>
        /// OpenID Provider Configurationを返すWebAPI
        /// GET: /jwks.json
        /// </summary>
        /// <returns>HttpResponseMessage</returns>
        [HttpGet]
        [Route(".well-known/openid-configuration")]
        public HttpResponseMessage OpenIDConfig()
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
                OAuth2AndOIDCConst.ClientSecretBasic,
                OAuth2AndOIDCConst.PrivateKeyJwt
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
                OAuth2AndOIDCConst.query,
                OAuth2AndOIDCConst.fragment,
                OAuth2AndOIDCConst.form_post
            });
            #endregion

            #region revocation

            OpenIDConfig.Add("revocation_endpoint", new List<string> {
                Config.OAuth2AuthorizationServerEndpointsRootURI + Config.OAuth2RevokeTokenEndpoint
            });

            OpenIDConfig.Add("revocation_endpoint_auth_methods_supported", new List<string> {
               OAuth2AndOIDCConst.ClientSecretBasic
            });

            #endregion

            #region revocation

            OpenIDConfig.Add("introspection_endpoint", new List<string> {
                Config.OAuth2AuthorizationServerEndpointsRootURI + Config.OAuth2IntrospectTokenEndpoint
            });

            OpenIDConfig.Add("introspection_endpoint_auth_methods_supported", new List<string> {
               OAuth2AndOIDCConst.ClientSecretBasic
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

            // JsonSerializerSettingsを指定して、可読性の高いJSONを返す。
            return new HttpResponseMessage()
            {
                Content = new JsonContent(OpenIDConfig,
                    new JsonSerializerSettings
                    {
                        Formatting = Formatting.Indented,
                        ContractResolver = new CamelCasePropertyNamesContractResolver()
                    })
            };
        }

        #endregion

        #region /jwks.json

        /// <summary>
        /// JWK Set documentを返すWebAPI
        /// GET: /jwkcerts
        /// </summary>
        /// <returns>HttpResponseMessage</returns>
        [HttpGet]
        [Route("jwkcerts")]
        public HttpResponseMessage JwksUri()
        {   
            return new HttpResponseMessage()
            {
                Content = new JsonContent(
                    ResourceLoader.LoadAsString(
                        OAuth2AndOIDCParams.JwkSetFilePath,
                        Encoding.GetEncoding(CustomEncode.UTF_8)))
            };
        }

        #endregion

        #region /token

        /// <summary>
        /// Tokenエンドポイント
        /// POST: /OAuth2Token
        /// </summary>
        /// <param name="formData">FormDataCollection</param>
        /// <returns>Dictionary(string, string)</returns>
        [HttpPost]
        public Dictionary<string, string> OAuth2Token(FormDataCollection formData)
        {
            Dictionary<string, string> ret = null;
            Dictionary<string, string> err = null;

            string clientId = "";
            string clientSecret = "";
            string grant_type = "";
            string assertion = "";

            AuthenticationHeader.GetCredentials(
                    HttpContext.Current.Request.Headers[OAuth2AndOIDCConst.HttpHeader_Authorization], out string[] temp);

            if (temp.Length == 2)
            {
                clientId = temp[0];
                clientSecret = temp[1];
            }

            grant_type = formData[OAuth2AndOIDCConst.grant_type];
            assertion = formData[OAuth2AndOIDCConst.assertion];

            string code = formData[OAuth2AndOIDCConst.code];
            string redirect_uri = formData[OAuth2AndOIDCConst.redirect_uri];
            string code_verifier = formData[OAuth2AndOIDCConst.code_verifier];
            string refresh_token = formData[OAuth2AndOIDCConst.RefreshToken];

            if (grant_type.ToLower() == OAuth2AndOIDCConst.AuthorizationCodeGrantType)
            {
                if (CmnEndpoints.GrantAuthorizationCodeCredentials(
                    grant_type, clientId, clientSecret, assertion,
                    code, code_verifier, redirect_uri, out ret, out err))
                {
                    return ret;
                }
            }
            if (grant_type.ToLower() == OAuth2AndOIDCConst.RefreshTokenGrantType)
            {
                if (CmnEndpoints.GrantRefreshTokenCredentials(
                    grant_type, clientId, clientSecret, refresh_token, out ret, out err))
                {
                    return ret;
                }
            }
            else if (grant_type.ToLower() == OAuth2AndOIDCConst.JwtBearerTokenFlowGrantType)
            {
                if (CmnEndpoints.GrantJwtBearerTokenCredentials(
                    grant_type, assertion, out ret, out err))
                {
                    return ret;
                }
            }
            else
            {   
            }

            return err; // 失敗
        }

        #endregion

        #region /userinfo

        /// <summary>
        /// OAuthで認可したユーザ情報のClaimを発行するWebAPI
        /// GET: /userinfo
        /// </summary>
        /// <returns>Dictionary(string, object)</returns>
        [HttpGet]
        [Route("userinfo")] // OpenID Connectライクなインターフェイスに変更した。
        public async Task<Dictionary<string, object>> GetUserClaims()
        {
            // 戻り値（エラー）
            Dictionary<string, object> err = new Dictionary<string, object>();

            // クライアント認証
            AuthenticationHeader.GetCredentials(
                HttpContext.Current.Request.Headers[OAuth2AndOIDCConst.HttpHeader_Authorization], out string[] temp);

            if (temp.Length == 1)
            {
                if (CmnAccessToken.VerifyAccessToken(temp[0], out ClaimsIdentity identity))
                {
                    ApplicationUser user = CmnUserStore.FindByName(identity.Name);

                    string sub = "";
                    if (user == null)
                    {
                        // Client認証
                        sub = identity.Name;
                    }
                    else
                    {
                        // Resource Owner認証
                        sub = user.UserName;
                    }

                    Dictionary<string, object> userinfoClaimSet = new Dictionary<string, object>();
                    userinfoClaimSet.Add(OAuth2AndOIDCConst.sub, sub);

                    // Scope
                    IEnumerable<Claim> scopes = identity.Claims.Where(x => x.Type == OAuth2AndOIDCConst.Claim_Scopes);

                    // scope値によって、返す値を変更する。
                    foreach (Claim claim in scopes)
                    {
                        string scope = claim.Value;
                        if (user != null)
                        {
                            switch (scope.ToLower())
                            {
                                #region OpenID Connect

                                case OAuth2AndOIDCConst.Scope_Profile:
                                    // ・・・
                                    break;
                                case OAuth2AndOIDCConst.Scope_Email:
                                    userinfoClaimSet.Add(OAuth2AndOIDCConst.Scope_Email, user.Email);
                                    userinfoClaimSet.Add(OAuth2AndOIDCConst.email_verified, user.EmailConfirmed.ToString());
                                    break;
                                case OAuth2AndOIDCConst.Scope_Phone:
                                    userinfoClaimSet.Add(OAuth2AndOIDCConst.phone_number, user.PhoneNumber);
                                    userinfoClaimSet.Add(OAuth2AndOIDCConst.phone_number_verified, user.PhoneNumberConfirmed.ToString());
                                    break;
                                case OAuth2AndOIDCConst.Scope_Address:
                                    // ・・・
                                    break;

                                #endregion

                                #region Else

                                case OAuth2AndOIDCConst.Scope_UserID:
                                    userinfoClaimSet.Add(OAuth2AndOIDCConst.Scope_UserID, user.Id);
                                    break;
                                case OAuth2AndOIDCConst.Scope_Roles:
                                    userinfoClaimSet.Add(
                                        OAuth2AndOIDCConst.Scope_Roles,
                                        CmnUserStore.GetRoles(user));
                                    break;

                                    #endregion
                            }
                        }
                    }

                    return userinfoClaimSet;

                }
                else
                {
                    err.Add("error", "invalid_request");
                    err.Add("error_description", "invalid token");
                }
            }
            else
            {
                // クライアント認証エラー（ヘッダ不正
                err.Add("error", "invalid_request");
                err.Add("error_description", "Invalid authentication header");
            }

            return err; // 失敗
        }

        #endregion

        #region /revoke 

        /// <summary>
        /// AccessTokenとRefreshTokenの取り消し
        /// POST: /revoke
        /// </summary>
        /// <param name="formData">
        /// token
        /// token_type_hint
        /// </param>
        /// <returns>Dictionary(string, string)</returns>
        [HttpPost]
        [Route("revoke")]
        public Dictionary<string, string> RevokeToken(FormDataCollection formData)
        {
            // 戻り値（エラー）
            Dictionary<string, string> err = new Dictionary<string, string>();

            // 変数
            string token = formData[OAuth2AndOIDCConst.token];
            string token_type_hint = formData[OAuth2AndOIDCConst.token_type_hint];

            // クライアント認証
            AuthenticationHeader.GetCredentials(
                HttpContext.Current.Request.Headers[OAuth2AndOIDCConst.HttpHeader_Authorization], out string[] temp);

            if (temp.Length == 2)
            {
                string clientId = temp[0];
                string clientSecret = temp[1];

                if (!(string.IsNullOrEmpty(clientId) && string.IsNullOrEmpty(clientSecret)))
                {
                    // *.config or OAuth2Dataテーブルを参照してクライアント認証を行なう。
                    if (clientSecret == Helper.GetInstance().GetClientSecret(clientId))
                    {
                        // 検証完了

                        if (token_type_hint == OAuth2AndOIDCConst.AccessToken)
                        {
                            //// 検証
                            if (CmnAccessToken.VerifyAccessToken(token, out ClaimsIdentity identity))
                            {
                                // 検証成功

                                // jtiの取り出し
                                Claim jti = identity.Claims.Where(
                                    x => x.Type == OAuth2AndOIDCConst.Claim_JwtId).FirstOrDefault<Claim>();

                                // access_token取消
                                RevocationProvider.Create(jti.Value);
                                return null; // 成功
                            }
                            else
                            {
                                // 検証失敗
                                // 検証エラー
                                err.Add("error", "invalid_request");
                                err.Add("error_description", "invalid token");
                            }
                        }
                        else if (token_type_hint == OAuth2AndOIDCConst.RefreshToken)
                        {
                            // refresh_token取消
                            if (RefreshTokenProvider.Delete(token))
                            {
                                // 取り消し成功
                                return null; // 成功
                            }
                            else
                            {
                                // 取り消し失敗
                                err.Add("error", "invalid_request");
                                err.Add("error_description", "invalid token");
                            }
                        }
                        else
                        {
                            // token_type_hint パラメタ・エラー
                            err.Add("error", "invalid_request");
                            err.Add("error_description", "invalid token_type_hint");
                        }
                    }
                    else
                    {
                        // クライアント認証エラー（Credential不正
                        err.Add("error", "invalid_client");
                        err.Add("error_description", "Invalid credential");
                    }
                }
                else
                {
                    // クライアント認証エラー（Credential不正
                    err.Add("error", "invalid_client");
                    err.Add("error_description", "Invalid credential");
                }
            }
            else
            {
                // クライアント認証エラー（ヘッダ不正
                err.Add("error", "invalid_request");
                err.Add("error_description", "Invalid authentication header");
            }

            return err; // 失敗

        }

        #endregion

        #region /introspect 

        /// <summary>
        /// AccessTokenとRefreshTokenのメタデータを返す。
        /// POST: /introspect
        /// </summary>
        /// <param name="formData">
        /// token
        /// token_type_hint
        /// </param>
        /// <returns>Dictionary(string, string)</returns>
        [HttpPost]
        [Route("introspect")]
        public Dictionary<string, string> IntrospectToken(FormDataCollection formData)
        {
            // 戻り値
            // ・正常
            Dictionary<string, string> ret = new Dictionary<string, string>();
            // ・異常
            Dictionary<string, string> err = new Dictionary<string, string>();

            // 変数
            string token = formData[OAuth2AndOIDCConst.token];
            string token_type_hint = formData[OAuth2AndOIDCConst.token_type_hint];

            // クライアント認証
            AuthenticationHeader.GetCredentials(
                HttpContext.Current.Request.Headers[OAuth2AndOIDCConst.HttpHeader_Authorization], out string[] temp);

            if (temp.Length == 2)
            {
                string clientId = temp[0];
                string clientSecret = temp[1];

                if (!(string.IsNullOrEmpty(clientId) && string.IsNullOrEmpty(clientSecret)))
                {
                    // *.config or OAuth2Dataテーブルを参照してクライアント認証を行なう。
                    if (clientSecret == Helper.GetInstance().GetClientSecret(clientId))
                    {
                        // 検証完了
                        if (token_type_hint == OAuth2AndOIDCConst.AccessToken)
                        {
                            // ↓に続く
                        }
                        else if (token_type_hint == OAuth2AndOIDCConst.RefreshToken)
                        {   
                            string tokenPayload = RefreshTokenProvider.Refer(token);
                            if (!string.IsNullOrEmpty(tokenPayload))
                            {
                                token = CmnAccessToken.ProtectFromPayloadForCode(tokenPayload, DateTimeOffset.Now);
                            }
                            else
                            {
                                token = "";
                            }
                            // ↓に続く
                        }
                        else
                        {
                            // token_type_hint パラメタ・エラー
                            err.Add("error", "invalid_request");
                            err.Add("error_description", "invalid token_type_hint");
                        }

                        // AccessToken化して共通処理
                        if (!string.IsNullOrEmpty(token)
                            && CmnAccessToken.VerifyAccessToken(token, out ClaimsIdentity identity))
                        {
                            // 検証成功
                            // メタデータの返却
                            ret.Add("active", "true");
                            ret.Add(OAuth2AndOIDCConst.token_type, token_type_hint);

                            string scopes = "";
                            foreach (Claim claim in identity.Claims)
                            {
                                if (claim.Type.StartsWith(OAuth2AndOIDCConst.Claim_Base))
                                {
                                    if (claim.Type == OAuth2AndOIDCConst.Claim_Scopes)
                                    {
                                        scopes += claim.Value + " ";
                                    }
                                    else
                                    {
                                        ret.Add(claim.Type.Substring(
                                            OAuth2AndOIDCConst.Claim_Base.Length), claim.Value);
                                    }
                                }
                            }
                            ret.Add(OAuth2AndOIDCConst.Claim_Scopes.Substring(
                                OAuth2AndOIDCConst.Claim_Base.Length), scopes.Trim());

                            return ret; // 成功
                        }
                        else
                        {
                            // 検証失敗
                            // 検証エラー
                            err.Add("error", "invalid_request");
                            err.Add("error_description", "invalid token");
                        }
                    }
                    else
                    {
                        // クライアント認証エラー（Credential不正
                        err.Add("error", "invalid_client");
                        err.Add("error_description", "Invalid credential");
                    }
                }
                else
                {
                    // クライアント認証エラー（Credential不正
                    err.Add("error", "invalid_client");
                    err.Add("error_description", "Invalid credential");
                }
            }
            else
            {
                // クライアント認証エラー（ヘッダ不正
                err.Add("error", "invalid_request");
                err.Add("error_description", "Invalid authentication header");
            }

            return err; // 失敗
        }

        #endregion
    }
}