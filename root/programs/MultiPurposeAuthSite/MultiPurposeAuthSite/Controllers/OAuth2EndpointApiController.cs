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
using ExtOAuth2 = MultiPurposeAuthSite.Extensions.OAuth2;

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
using Microsoft.Owin.Security.OAuth;

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

            OpenIDConfig.Add("token_endpoint", new List<string> {
                Config.OAuth2AuthorizationServerEndpointsRootURI + Config.OAuth2BearerTokenEndpoint,
                Config.OAuth2AuthorizationServerEndpointsRootURI + Config.OAuth2BearerTokenEndpoint2
            });

            OpenIDConfig.Add("userinfo_endpoint",
                Config.OAuth2AuthorizationServerEndpointsRootURI + Config.OAuth2GetUserClaimsWebAPI);

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
                Config.OAuth2AuthorizationServerEndpointsRootURI + Config.OAuth2RevokeTokenWebAPI
            });

            OpenIDConfig.Add("revocation_endpoint_auth_methods_supported", new List<string> {
               OAuth2AndOIDCConst.ClientSecretBasic
            });

            #endregion

            #region revocation

            OpenIDConfig.Add("introspection_endpoint", new List<string> {
                Config.OAuth2AuthorizationServerEndpointsRootURI + Config.OAuth2IntrospectTokenWebAPI
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

            // 変数
            string[] temp = null;
            
            // クライアント認証
            string authHeader = HttpContext.Current.Request.Headers[OAuth2AndOIDCConst.HttpHeader_Authorization];
            temp = authHeader.Split(' ');

            if (temp[0] == OAuth2AndOIDCConst.Bearer)
            {
                ClaimsIdentity identity = new ClaimsIdentity();
                if (CmnAccessToken.Unprotect(temp[1], identity))
                {
                    ApplicationUser user = CmnUserStore.FindByName(identity.Name);

                    string subject = "";
                    if (user == null)
                    {
                        // Client認証
                        subject = ExtOAuth2.Helper.GetInstance().GetClientName(
                            MyBaseAsyncApiController.GetClaimsIdentity()
                            .FindFirst(OAuth2AndOIDCConst.Claim_Audience).Value);
                    }
                    else
                    {
                        // Resource Owner認証
                        subject = user.UserName;
                    }

                    Dictionary<string, object> userinfoClaimSet = new Dictionary<string, object>();
                    userinfoClaimSet.Add(OAuth2AndOIDCConst.sub, subject);

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
            string[] temp = null;
            string token = formData[OAuth2AndOIDCConst.token];
            string token_type_hint = formData[OAuth2AndOIDCConst.token_type_hint];

            // クライアント認証
            string authHeader = HttpContext.Current.Request.Headers[OAuth2AndOIDCConst.HttpHeader_Authorization];
            temp = authHeader.Split(' ');

            if (temp[0] == OAuth2AndOIDCConst.Basic)
            {
                temp = CustomEncode.ByteToString(
                    CustomEncode.FromBase64String(temp[1]), CustomEncode.us_ascii).Split(':');

                string clientId = temp[0];
                string clientSecret = temp[1];

                if (!(string.IsNullOrEmpty(clientId) && string.IsNullOrEmpty(clientSecret)))
                {
                    // *.config or OAuth2Dataテーブルを参照してクライアント認証を行なう。
                    if (clientSecret == ExtOAuth2.Helper.GetInstance().GetClientSecret(clientId))
                    {
                        // 検証完了

                        if (token_type_hint == OAuth2AndOIDCConst.AccessToken)
                        {
                            //// 検証
                            ClaimsIdentity identity = new ClaimsIdentity();
                            if (CmnAccessToken.Unprotect(token, identity))
                            {
                                // 検証成功

                                // jtiの取り出し
                                Claim jti = identity.Claims.Where(
                                    x => x.Type == OAuth2AndOIDCConst.Claim_JwtId).FirstOrDefault<Claim>();

                                // access_token取消
                                ExtOAuth2.RevocationProvider.Create(jti.Value);
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
                            if (RefreshTokenProvider.DeleteDirectly(token))
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
            string[] temp = null;
            string token = formData[OAuth2AndOIDCConst.token];
            string token_type_hint = formData[OAuth2AndOIDCConst.token_type_hint];

            // クライアント認証
            string authHeader = HttpContext.Current.Request.Headers[OAuth2AndOIDCConst.HttpHeader_Authorization];
            temp = authHeader.Split(' ');

            if (temp[0] == OAuth2AndOIDCConst.Basic)
            {
                temp = CustomEncode.ByteToString(
                    CustomEncode.FromBase64String(temp[1]), CustomEncode.us_ascii).Split(':');

                string clientId = temp[0];
                string clientSecret = temp[1];

                if (!(string.IsNullOrEmpty(clientId) && string.IsNullOrEmpty(clientSecret)))
                {
                    // *.config or OAuth2Dataテーブルを参照してクライアント認証を行なう。
                    if (clientSecret == ExtOAuth2.Helper.GetInstance().GetClientSecret(clientId))
                    {
                        // 検証完了
                        if (token_type_hint == OAuth2AndOIDCConst.AccessToken)
                        {
                            ClaimsIdentity identity = new ClaimsIdentity();
                            if (CmnAccessToken.Unprotect(token, identity))
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
                        else if (token_type_hint == OAuth2AndOIDCConst.RefreshToken)
                        {
                            // refresh_token参照
                            AuthenticationTicket ticket = RefreshTokenProvider.ReferDirectly(token);

                            if (ticket == null)
                            {
                                // 検証失敗
                                // 検証エラー
                                err.Add("error", "invalid_request");
                                err.Add("error_description", "invalid token");
                            }
                            else
                            {
                                // 検証成功
                                // メタデータの返却
                                ret.Add("active", "true");
                                ret.Add(OAuth2AndOIDCConst.token_type, token_type_hint);

                                string scopes = "";
                                foreach (Claim claim in ticket.Identity.Claims)
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

        #region /OAuth2BearerToken2 

        /// <summary>
        /// JWT bearer token authorizationグラント種別のTokenエンドポイント
        /// POST: /OAuth2BearerToken2
        /// </summary>
        /// <param name="formData">
        /// grant_type = urn:ietf:params:oauth:grant-type:jwt-bearer
        /// assertion  = jwt_assertion
        /// </param>
        /// <returns>Dictionary(string, string)</returns>
        [HttpPost]
        [Route("OAuth2BearerToken2")]
        public Dictionary<string, string> OAuth2BearerToken2(FormDataCollection formData)
        {   
            // 戻り値
            // ・正常
            Dictionary<string, string> ret = new Dictionary<string, string>();
            // ・異常
            Dictionary<string, string> err = new Dictionary<string, string>();

            // 変数
            string grant_type = formData[OAuth2AndOIDCConst.grant_type];
            string assertion = formData[OAuth2AndOIDCConst.assertion];

            // クライアント認証
            if (Config.EnableJwtBearerTokenFlowGrantType &&
                grant_type == OAuth2AndOIDCConst.JwtBearerTokenFlowGrantType)
            {
                Dictionary<string, string> dic = JsonConvert.DeserializeObject<Dictionary<string, string>>(
                    CustomEncode.ByteToString(CustomEncode.FromBase64UrlString(
                        assertion.Split('.')[1]), CustomEncode.us_ascii));

                string pubKey = ExtOAuth2.Helper.GetInstance().GetJwtAssertionPublickey(dic[OAuth2AndOIDCConst.iss]);
                pubKey = CustomEncode.ByteToString(CustomEncode.FromBase64UrlString(pubKey), CustomEncode.us_ascii);

                if (!string.IsNullOrEmpty(pubKey))
                {
                    string iss = "";
                    string aud = "";
                    string scopes = "";
                    JObject jobj = null;

                    if (JwtAssertion.VerifyJwtBearerTokenFlowAssertionJWK(
                        assertion, out iss, out aud, out scopes, out jobj, pubKey))
                    {
                        // aud 検証
                        if (aud == Config.OAuth2AuthorizationServerEndpointsRootURI
                            + Config.OAuth2BearerTokenEndpoint2)
                        {
                            // ここからは、JwtAssertionではなく、JwtTokenを作るので、属性設定に注意。
                            ClaimsIdentity identity = new ClaimsIdentity(OAuthDefaults.AuthenticationType);

                            bool isResourceOwner = false;
                            string sub = ExtOAuth2.Helper.GetInstance().GetClientName(iss, out isResourceOwner);

                            // Name Claimを追加
                            if (isResourceOwner)
                            {
                                identity.AddClaim(new Claim(ClaimTypes.Name, sub));
                            }
                            else
                            {
                                identity.AddClaim(new Claim(ClaimTypes.Name, ""));
                            }

                            // ClaimsIdentityに、その他、所定のClaimを追加する。
                            identity = ExtOAuth2.Helper.AddClaim(identity, iss, "", scopes.Split(' '), "");

                            AuthenticationProperties prop = new AuthenticationProperties();
                            prop.IssuedUtc = DateTimeOffset.UtcNow;
                            prop.ExpiresUtc = DateTimeOffset.Now.Add(Config.OAuth2AccessTokenExpireTimeSpanFromMinutes);

                            // token_type
                            ret.Add(OAuth2AndOIDCConst.token_type, OAuth2AndOIDCConst.Bearer.ToLower());

                            // access_token
                            string access_token = CmnAccessToken.Protect(
                                identity.Name, identity.Claims, 
                                prop.ExpiresUtc.Value, prop.IssuedUtc.Value);

                            ret.Add(OAuth2AndOIDCConst.AccessToken, access_token);
                            
                            // expires_in
                            jobj = (JObject)JsonConvert.DeserializeObject(
                                CustomEncode.ByteToString(CustomEncode.FromBase64UrlString(
                                    access_token.Split('.')[1]), CustomEncode.us_ascii));
                            ret.Add("expires_in", (long.Parse((string)jobj[OAuth2AndOIDCConst.exp]) - long.Parse((string)jobj[OAuth2AndOIDCConst.iat])).ToString());

                            // オペレーション・トレース・ログ出力
                            string clientName = ExtOAuth2.Helper.GetInstance().GetClientName(iss);
                            Logging.MyOperationTrace(string.Format(
                                "{0}({1}) passed the 'jwt bearer token flow' by {2}({3}).",
                                iss, clientName, iss, clientName));

                            return ret; // 成功
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
            else
            {
                // grant_type パラメタ・エラー
                err.Add("error", "invalid_request");
                err.Add("error_description", "invalid grant_type");
            }

            return err; // 失敗
        }

        #endregion
    }
}