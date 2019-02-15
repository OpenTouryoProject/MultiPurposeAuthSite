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
//* クラス名        ：OAuth2EndpointController
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
using System.Security.Cryptography.X509Certificates;
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
    /// <summary>OAuth2EndpointのApiController（ライブラリ）</summary>
    [EnableCors(
        // リソースへのアクセスを許可されている発生元
        origins: "*",
        // リソースによってサポートされているヘッダー
        headers: "*",
        // リソースによってサポートされているメソッド
        methods: "*",
        // 
        SupportsCredentials = true)]
    public class OAuth2EndpointController : ApiController
    {
        #region /token

        /// <summary>
        /// Tokenエンドポイント
        /// POST: /token
        /// </summary>
        /// <param name="formData">FormDataCollection</param>
        /// <returns>Dictionary(string, string)</returns>
        [HttpPost]
        public Dictionary<string, string> OAuth2Token(FormDataCollection formData)
        {
            Dictionary<string, string> ret = null;
            Dictionary<string, string> err = null;

            // Credentials(client_id, client_secret)
            AuthenticationHeader.GetCredentials(
                    HttpContext.Current.Request.Headers[OAuth2AndOIDCConst.HttpHeader_Authorization],
                    out string client_id, out string client_secret);

            // JWTアサーション
            string assertion = "";
            assertion = formData[OAuth2AndOIDCConst.assertion];

            // クライアント証明書
            X509Certificate2 x509 = Request.GetClientCertificate();
            //if (x509 != null)
            //{
            //    //string thumbprint = x509.Thumbprint;
            //    //string subject = x509.Subject;
            //    //string subjectName = x509.SubjectName.Name;                     // Subjectと同じ
            //    //string algFriendlyName = x509.SignatureAlgorithm.FriendlyName;　// sha256RSA, etc.
            //}

            string scope = "";

            string grant_type = "";
            grant_type = formData[OAuth2AndOIDCConst.grant_type];

            switch (grant_type.ToLower())
            {
                case OAuth2AndOIDCConst.AuthorizationCodeGrantType:
                    string code = formData[OAuth2AndOIDCConst.code];
                    string redirect_uri = formData[OAuth2AndOIDCConst.redirect_uri];
                    string code_verifier = formData[OAuth2AndOIDCConst.code_verifier];

                    if (CmnEndpoints.GrantAuthorizationCodeCredentials(
                        grant_type, client_id, client_secret, assertion, x509,
                        code, code_verifier, redirect_uri, out ret, out err))
                    {
                        return ret;
                    }
                    break;

                case OAuth2AndOIDCConst.RefreshTokenGrantType:
                    string refresh_token = formData[OAuth2AndOIDCConst.RefreshToken];
                    if (CmnEndpoints.GrantRefreshTokenCredentials(
                        grant_type, client_id, client_secret, x509, refresh_token, out ret, out err))
                    {
                        return ret;
                    }
                    break;

                case OAuth2AndOIDCConst.ResourceOwnerPasswordCredentialsGrantType:
                    string username = formData["username"];
                    string password = formData["password"];
                    scope = formData[OAuth2AndOIDCConst.scope];
                    if (CmnEndpoints.GrantResourceOwnerCredentials(
                        grant_type, client_id, client_secret, x509,
                        username, password, scope, out ret, out err))
                    {
                        return ret;
                    }
                    break;

                case OAuth2AndOIDCConst.ClientCredentialsGrantType:
                    scope = formData[OAuth2AndOIDCConst.scope];
                    if (CmnEndpoints.GrantClientCredentials(
                        grant_type, client_id, client_secret, x509, scope, out ret, out err))
                    {
                        return ret;
                    }
                    break;

                case OAuth2AndOIDCConst.JwtBearerTokenFlowGrantType:
                    if (CmnEndpoints.GrantJwtBearerTokenCredentials(
                    grant_type, assertion, x509, out ret, out err))
                    {
                        return ret;
                    }
                    break;

                default:
                    err.Add("error", "invalid_grant_type");
                    err.Add("error_description", "Invalid grant_type.");
                    break;
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
        public Dictionary<string, object> GetUserClaims()
        {
            // 戻り値（エラー）
            Dictionary<string, object> err = new Dictionary<string, object>();

            // クライアント認証
            if (AuthenticationHeader.GetCredentials(
                HttpContext.Current.Request.Headers[OAuth2AndOIDCConst.HttpHeader_Authorization], out string bearerToken))
            {
                if (CmnAccessToken.VerifyAccessToken(bearerToken, out ClaimsIdentity identity))
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
                    err.Add("error_description", "invalid token.");
                }
            }
            else
            {
                // クライアント認証エラー（ヘッダ不正
                err.Add("error", "invalid_request");
                err.Add("error_description", "Invalid authentication header.");
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
        public Dictionary<string, string> RevokeToken(FormDataCollection formData)
        {
            // 戻り値（エラー）
            Dictionary<string, string> err = new Dictionary<string, string>();

            // 変数
            string token = formData[OAuth2AndOIDCConst.token];
            string token_type_hint = formData[OAuth2AndOIDCConst.token_type_hint];

            // クライアント証明書
            X509Certificate2 x509 = Request.GetClientCertificate();

            // Credentials(client_id, client_secret)
            if (AuthenticationHeader.GetCredentials(
                HttpContext.Current.Request.Headers[OAuth2AndOIDCConst.HttpHeader_Authorization],
                out string client_id, out string client_secret))
            {
                // client_id & (client_secret or x509)
                if (CmnEndpoints.ClientAuthentication(client_id, client_secret,
                    ref x509, out OAuth2AndOIDCEnum.ClientMode permittedLevel))
                {
                    // 検証完了
                    if (token_type_hint == OAuth2AndOIDCConst.AccessToken)
                    {
                        // 検証
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
                            err.Add("error_description", "invalid token.");
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
                            err.Add("error_description", "invalid token.");
                        }
                    }
                    else
                    {
                        // token_type_hint パラメタ・エラー
                        err.Add("error", "invalid_request");
                        err.Add("error_description", "invalid token_type_hint.");
                    }
                }
                else
                {
                    // クライアント認証エラー（Credential不正
                    err.Add("error", "invalid_client");
                    err.Add("error_description", "Invalid credential.");
                }
            }
            else
            {
                // クライアント認証エラー（ヘッダ不正
                err.Add("error", "invalid_request");
                err.Add("error_description", "Invalid authentication header.");
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
        public Dictionary<string, object> IntrospectToken(FormDataCollection formData)
        {
            // 戻り値
            // ・正常
            Dictionary<string, object> ret = new Dictionary<string, object>();
            // ・異常
            Dictionary<string, object> err = new Dictionary<string, object>();

            // 変数
            string token = formData[OAuth2AndOIDCConst.token];
            string token_type_hint = formData[OAuth2AndOIDCConst.token_type_hint];

            // クライアント証明書
            X509Certificate2 x509 = Request.GetClientCertificate();

            // Credentials(client_id, client_secret)
            if (AuthenticationHeader.GetCredentials(
                HttpContext.Current.Request.Headers[OAuth2AndOIDCConst.HttpHeader_Authorization],
                out string client_id, out string client_secret))
            {
                // client_id & (client_secret or x509)
                if (CmnEndpoints.ClientAuthentication(client_id, client_secret,
                    ref x509, out OAuth2AndOIDCEnum.ClientMode permittedLevel))
                {

                    // 検証完了
                    if (token_type_hint == OAuth2AndOIDCConst.AccessToken)
                    {
                        // AccessToken
                        // ↓に続く
                    }
                    else if (token_type_hint == OAuth2AndOIDCConst.RefreshToken)
                    {
                        // RefreshToken
                        string tokenPayload = RefreshTokenProvider.Refer(token);
                        if (!string.IsNullOrEmpty(tokenPayload))
                        {
                            token = CmnAccessToken.ProtectFromPayload(tokenPayload, DateTimeOffset.Now,
                                null, OAuth2AndOIDCEnum.ClientMode.normal, out string aud, out string sub);
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
                        err.Add("error_description", "invalid token_type_hint.");
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
                                else if(claim.Type.StartsWith(OAuth2AndOIDCConst.Claim_CnfX5t))
                                {
                                    string temp = OAuth2AndOIDCConst.x5t + claim.Type.Substring(OAuth2AndOIDCConst.Claim_CnfX5t.Length);
                                    ret.Add(OAuth2AndOIDCConst.cnf, new Dictionary<string, string>()
                                    {
                                        { temp, claim.Value}
                                    });
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
                        err.Add("error_description", "invalid token.");
                    }
                }
                else
                {
                    // クライアント認証エラー（Credential不正
                    err.Add("error", "invalid_client");
                    err.Add("error_description", "Invalid credential.");
                }
            }
            else
            {
                // クライアント認証エラー（ヘッダ不正
                err.Add("error", "invalid_request");
                err.Add("error_description", "Invalid authentication header.");
            }

            return err; // 失敗
        }

        #endregion

        #region /jwks.json

        /// <summary>
        /// JWK Set documentを返すWebAPI
        /// GET: /jwkcerts
        /// </summary>
        /// <returns>HttpResponseMessage</returns>
        [HttpGet]
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

        #region /.well-known/openid-configuration

        /// <summary>
        /// OpenID Provider Configurationを返すWebAPI
        /// GET: /.well-known/openid-configuration
        /// </summary>
        /// <returns>HttpResponseMessage</returns>
        [HttpGet]
        [Route(".well-known/openid-configuration")]  // ココは固定
        public HttpResponseMessage OpenIDConfig()
        {
            // JsonSerializerSettingsを指定して、可読性の高いJSONを返す。
            return new HttpResponseMessage()
            {
                Content = new JsonContent(
                    CmnEndpoints.OpenIDConfig(),
                    new JsonSerializerSettings
                    {
                        Formatting = Formatting.Indented,
                        ContractResolver = new CamelCasePropertyNamesContractResolver()
                    })
            };
        }

        #endregion
    }
}