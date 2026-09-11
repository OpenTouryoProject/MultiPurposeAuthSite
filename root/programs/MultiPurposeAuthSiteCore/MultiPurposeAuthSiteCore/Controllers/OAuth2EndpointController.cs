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
//*  2019/02/18  西野 大介         FAPI2 CC対応実施
//*  2019/08/01  西野 大介         client_secret_postのサポートを追加
//*  2019/12/25  西野 大介         PPID対応による見直し（SamlMetadata）
//*  2020/01/07  西野 大介         PPID対応実施（GetUserClaims）
//*  2020/02/27  西野 大介         FAPI CIBA対応実施（CibaAuthorize, CibaPushResult）
//*  2020/03/09  西野 大介         FormDataCollectionチェック処理の強化
//*  2020/07/22  西野 大介         クリーンアーキテクチャ維持or放棄 → 放棄
//*  2020/12/18  西野 大介         Device AuthZ対応実施（DeviceAuthZAuthorize）
//*                                ・DeviceAuthZResponse画面 → HomeControllerに。
//*                                ・DeviceAuthZVerify画面 → AccountControllerに。
//*  2020/12/21  西野 大介         CIBAのTokenのsubを認可ユーザに変更
//*  2021/07/10  西野 大介         2FAにプッシュ通知を追加（AspNetCore.Identityのみ
//*  2026/09/07  玄人 幸道         JWTの数値・真偽値クレームの型を修正（#184）
//*  2026/09/07  玄人 幸道         不正な入力での未処理例外を修正（#185）
//*  2026/09/08  玄人 幸道         Device AuthZのクライアント認証を追加（#193）
//*  2026/09/08  玄人 幸道         revoke/introspectの所有者確認を追加（#194）
//*  2026/09/11  玄人 幸道         /revoke /introspect を RFC 7009 / 7662 に合わせて修正（#200）
//*  2026/09/11  玄人 幸道         /token のエラー応答を 400 / 401 で返す（#196）
//*  2026/09/11  玄人 幸道         /userinfo のエラー応答を 401 ＋ WWW-Authenticate: Bearer で返す（#196）
//*  2026/09/11  玄人 幸道         /revoke のエラー応答を 400 / 401 で返す。/token と共用するエラー応答を共通の region へ（#196）
//**********************************************************************************

using MultiPurposeAuthSite;
using MultiPurposeAuthSite.Co;
using MultiPurposeAuthSite.Data;
using MultiPurposeAuthSite.Util;

using Token = MultiPurposeAuthSite.TokenProviders;
using Sts = MultiPurposeAuthSite.Extensions.Sts;
using MultiPurposeAuthSite.Notifications;

using System;
using System.IO;
using System.Xml;
using System.Text;
using System.Linq;
using System.Collections.Generic;
using System.Collections.Specialized;
using System.Security.Claims;
using System.Security.Principal;
using System.Security.Cryptography.X509Certificates;
using System.Threading.Tasks;

using System.Net;

using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Cors;
using Microsoft.AspNetCore.Identity;

using Newtonsoft.Json;
using Newtonsoft.Json.Linq;
using Newtonsoft.Json.Serialization;

using Touryo.Infrastructure.Business.Presentation;
using Touryo.Infrastructure.Framework.Authentication;
using Touryo.Infrastructure.Framework.StdMigration;
using Touryo.Infrastructure.Framework.Presentation;
using Touryo.Infrastructure.Public.IO;
using Touryo.Infrastructure.Public.Str;
using Touryo.Infrastructure.Public.Security;

/// <summary>MultiPurposeAuthSite.Controllers</summary>
namespace MultiPurposeAuthSite.Controllers
{
    /// <summary>OAuth2EndpointのApiController（ライブラリ）</summary>
    [EnableCors]
    //[ApiController]
    [MyBaseAsyncApiController(httpAuthHeader: EnumHttpAuthHeader.None)] // 認証無し（自前）
    public class OAuth2EndpointController : ControllerBase
    {
        #region DI(CA)対応
        #region members & constructor

        #region members

        #region OwinContext
        /// <summary>UserManager</summary>
        private readonly UserManager<ApplicationUser> _userManager = null;
        /// <summary>UserManager</summary>
        private readonly RoleManager<ApplicationRole> _roleManager = null;
        #endregion

        #endregion

        #region constructor
        /// <summary>constructor</summary>
        /// <param name="userManager">UserManager</param>
        /// <param name="roleManager">RoleManager</param>
        public OAuth2EndpointController(
            UserManager<ApplicationUser> userManager,
            RoleManager<ApplicationRole> roleManager)
        {
            // UserManager
            this._userManager = userManager;
            // RoleManager
            this._roleManager = roleManager;
        }
        #endregion

        #endregion

        #region property

        #region GetOwinContext

        /// <summary>ApplicationUserManager</summary>
        private UserManager<ApplicationUser> UserManager
        {
            get
            {
                return this._userManager;
            }
        }

        /// <summary>ApplicationRoleManager</summary>
        private RoleManager<ApplicationRole> RoleManager
        {
            get
            {
                return this._roleManager;
            }
        }

        #endregion

        #endregion        

        #endregion

        #region /token

        /// <summary>
        /// Tokenエンドポイント
        /// POST: /token
        /// </summary>
        /// <param name="formData">FormDataCollection</param>
        /// <returns>成功は 200、エラーは 400 / 401（RFC 6749 5.1 / 5.2）（#196）</returns>
        [HttpPost]
        public IActionResult OAuth2Token(IFormCollection formData)
        {
            Dictionary<string, string> ret = null;
            // grant_typeが未知・未指定、フォームデータ無しの経路でも使うので初期化する（#185）。
            Dictionary<string, string> err = new Dictionary<string, string>();

            if (formData != null)
            {
                #region credentials

                // client_id, client_secret

                // client_secret_basic
                if (!AuthenticationHeader.GetCredentials(
                MyHttpContext.Current.Request.Headers[OAuth2AndOIDCConst.HttpHeader_Authorization],
                out string client_id, out string client_secret))
                {
                    // client_secret_post
                    client_id = formData[OAuth2AndOIDCConst.client_id];
                    client_secret = formData[OAuth2AndOIDCConst.client_secret];
                }

                // JWTアサーション
                string assertion = "";
                assertion = formData[OAuth2AndOIDCConst.assertion];

                // クライアント証明書

                // Azure Web App Client Certificate Authentication with ASP.NET Core | Kirk Evans Blog
                // https://blogs.msdn.microsoft.com/kaevans/2016/04/13/azure-web-app-client-certificate-authentication-with-asp-net-core-2/
                X509Certificate2 x509 = Request.HttpContext.Connection.ClientCertificate;
                //if (x509 != null)
                //{
                //    //string thumbprint = x509.Thumbprint;
                //    //string subject = x509.Subject;
                //    //string subjectName = x509.SubjectName.Name;                     // Subjectと同じ
                //    //string algFriendlyName = x509.SignatureAlgorithm.FriendlyName;　// sha256RSA, etc.
                //}

                #endregion

                #region grant_type

                string grant_type = formData[OAuth2AndOIDCConst.grant_type];
                if (!string.IsNullOrEmpty(grant_type))
                {
                    string scope = "";
                    switch (grant_type.ToLower())
                    {
                        case OAuth2AndOIDCConst.AuthorizationCodeGrantType:
                            string code = formData[OAuth2AndOIDCConst.code];
                            string redirect_uri = formData[OAuth2AndOIDCConst.redirect_uri];
                            string code_verifier = formData[OAuth2AndOIDCConst.code_verifier];

                            if (Token.CmnEndpoints.GrantAuthorizationCodeCredentials(
                                grant_type, client_id, client_secret, assertion, x509,
                                code, code_verifier, redirect_uri, out ret, out err))
                            {
                                return this.Ok(ret);
                            }
                            break;

                        case OAuth2AndOIDCConst.RefreshTokenGrantType:
                            string refresh_token = formData[OAuth2AndOIDCConst.RefreshToken];
                            if (Token.CmnEndpoints.GrantRefreshTokenCredentials(
                                grant_type, client_id, client_secret, x509, refresh_token, out ret, out err))
                            {
                                return this.Ok(ret);
                            }
                            break;

                        case OAuth2AndOIDCConst.ResourceOwnerPasswordCredentialsGrantType:
                            string username = formData["username"];
                            string password = formData["password"];
                            scope = formData[OAuth2AndOIDCConst.scope];
                            if (Token.CmnEndpoints.GrantResourceOwnerCredentials(
                                grant_type, client_id, client_secret, x509,
                                username, password, scope, out ret, out err))
                            {
                                return this.Ok(ret);
                            }
                            break;

                        case OAuth2AndOIDCConst.ClientCredentialsGrantType:
                            scope = formData[OAuth2AndOIDCConst.scope];
                            if (Token.CmnEndpoints.GrantClientCredentials(
                                grant_type, client_id, client_secret, x509, scope, out ret, out err))
                            {
                                return this.Ok(ret);
                            }
                            break;

                        case OAuth2AndOIDCConst.JwtBearerTokenFlowGrantType:
                            if (Token.CmnEndpoints.GrantJwtBearerTokenCredentials(
                            grant_type, assertion, x509, out ret, out err))
                            {
                                return this.Ok(ret);
                            }
                            break;

                        case OAuth2AndOIDCConst.DeviceAuthZGrantType:
                            string device_code = formData[OAuth2AndOIDCConst.device_code];
                            if (Token.CmnEndpoints.GrantDeviceAuthZ(grant_type,
                                client_id, client_secret, x509, device_code, out ret, out err))
                            {
                                return this.Ok(ret);
                            }
                            break;

                        case OAuth2AndOIDCConst.CibaGrantType:
                            string auth_req_id = formData[OAuth2AndOIDCConst.auth_req_id];
                            if (Token.CmnEndpoints.GrantCiba(grant_type,
                                client_id, client_secret, x509,
                                auth_req_id, out ret, out err))
                            {
                                return this.Ok(ret);
                            }
                            break;

                        default:
                            err.Add(OAuth2AndOIDCConst.error, OAuth2AndOIDCConst.invalid_grant);
                            err.Add(OAuth2AndOIDCConst.error_description, "Invalid grant_type.");
                            break;
                    }
                }
                else
                {
                    err.Add(OAuth2AndOIDCConst.error, OAuth2AndOIDCConst.invalid_grant);
                    err.Add(OAuth2AndOIDCConst.error_description, "grant_type is null or empty.");
                }

                #endregion
            }
            else
            {
                // FormDataCollection無し
                err.Add(OAuth2AndOIDCConst.error, OAuth2AndOIDCConst.invalid_request);
                err.Add(OAuth2AndOIDCConst.error_description, "Form data is null.");
            }

            return this.OAuth2Error(err, "token"); // 失敗（RFC 6749 5.2 : 400 / 401）（#196）
        }

        #endregion

        #region /userinfo

        /// <summary>
        /// OAuthで認可したユーザ情報のClaimを発行するWebAPI
        /// GET: /userinfo
        /// </summary>
        /// <returns>成功は 200、エラーは 401 と WWW-Authenticate: Bearer（RFC 6750 3）（#196）</returns>
        [HttpGet]
        public async Task<IActionResult> GetUserClaims()
        {
            // 戻り値（エラー）
            Dictionary<string, string> err = new Dictionary<string, string>();

            // クライアント認証
            if (AuthenticationHeader.GetCredentials(
                MyHttpContext.Current.Request.Headers[OAuth2AndOIDCConst.HttpHeader_Authorization], out string bearerToken))
            {
                if (Token.CmnAccessToken.VerifyAccessToken(bearerToken, out JObject claims, out ClaimsIdentity identity))
                {
                    // ClientIdの取り出し
                    Claim ClientId = identity.Claims.Where(
                        x => x.Type == OAuth2AndOIDCConst.UrnAudienceClaim).FirstOrDefault<Claim>();

                    ApplicationUser user =
                        //CmnUserStore.FindByName(identity.Name);
                        PPIDExtension.GetUserFromSub(ClientId.Value, identity.Name);

                    // Client認証、Resource Owner認証、何れの場合も...
                    string sub = identity.Name;

                    Dictionary<string, object> userinfoClaimSet = new Dictionary<string, object>();
                    userinfoClaimSet.Add(OAuth2AndOIDCConst.sub, sub);

                    // scope
                    IEnumerable<Claim> scopes = identity.Claims.Where(
                        x => x.Type == OAuth2AndOIDCConst.UrnScopesClaim);

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
                                    userinfoClaimSet.Add(OAuth2AndOIDCConst.email_verified, user.EmailConfirmed);
                                    break;
                                case OAuth2AndOIDCConst.Scope_Phone:
                                    userinfoClaimSet.Add(OAuth2AndOIDCConst.phone_number, user.PhoneNumber);
                                    userinfoClaimSet.Add(OAuth2AndOIDCConst.phone_number_verified, user.PhoneNumberConfirmed);
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
                                        await UserManager.GetRolesAsync(user));
                                    break;

                                    #endregion
                            }
                        }
                    }

                    // claims
                    if (claims != null)
                    {
                        foreach (KeyValuePair<string, JToken> item in claims)
                        {
                            if (item.Key == OAuth2AndOIDCConst.claims_userinfo)
                            {
                                // userinfoで追加する値
                            }
                            else if (item.Key == OAuth2AndOIDCConst.claims_id_token)
                            {
                                // ...
                            }
                        }
                    }

                    return this.Ok(userinfoClaimSet);

                }
                else
                {
                    // 無効なトークン（JWT でない、改竄・失効・期限切れなど）。
                    // RFC 6750 3.1 : invalid_token（401）。以前は invalid_request（400 に当たる）だった（#196）。
                    err.Add(OAuth2AndOIDCConst.error, Token.CmnEndpoints.invalid_token);
                    err.Add(OAuth2AndOIDCConst.error_description, "Invalid token.");
                }
            }

            // Bearer トークンが無い（Authorization ヘッダ無し、または他の方式）場合、err は空のまま。
            // RFC 6750 3.1 : エラー情報を付けず、Bearer が要ることだけを示す（#196）。

            return this.UserInfoError(err); // 失敗（RFC 6750 3 : 401 ＋ WWW-Authenticate）（#196）
        }

        /// <summary>/userinfo のエラー応答を作る（RFC 6750 3 / OIDC Core 5.3.3）</summary>
        /// <param name="err">error / error_description を持つ辞書（トークンが無かった場合は空）</param>
        /// <returns>401 と WWW-Authenticate: Bearer</returns>
        /// <remarks>
        /// 以前は Dictionary をそのまま返していたため、エラーでも HTTP 200 だった（#196）。
        /// トークンが無かった場合は、本文を返さない（RFC 6750 3.1 : エラー情報を含めない）。
        /// </remarks>
        private IActionResult UserInfoError(Dictionary<string, string> err)
        {
            this.Response.Headers["WWW-Authenticate"] =
                "Bearer " + Token.CmnEndpoints.GetBearerChallengeParameter("userinfo", err);

            if (err.Count == 0)
            {
                return new StatusCodeResult(401);
            }

            return new ObjectResult(err) { StatusCode = Token.CmnEndpoints.GetErrorStatusCode(err) };
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
        /// <returns>成功（無効なトークンを含む）は 200、エラーは 400 / 401（RFC 7009 2.2 / 2.2.1）（#196）</returns>
        [HttpPost]
        public IActionResult RevokeToken(IFormCollection formData)
        {
            // 戻り値（エラー）
            Dictionary<string, string> err = new Dictionary<string, string>();

            if (formData != null)
            {
                // 変数
                string token = formData[OAuth2AndOIDCConst.token];
                string token_type_hint = formData[OAuth2AndOIDCConst.token_type_hint];

                // token は必須、token_type_hint は任意（RFC 7009 2.1 / RFC 7662 2.1）（#200）
                if (!string.IsNullOrEmpty(token))
                {
                    // クライアント証明書
                    // Azure Web App Client Certificate Authentication with ASP.NET Core | Kirk Evans Blog
                    // https://blogs.msdn.microsoft.com/kaevans/2016/04/13/azure-web-app-client-certificate-authentication-with-asp-net-core-2/
                    // tls_client_authのクライアントも利用できるよう有効化（#194）。
                    X509Certificate2 x509 = Request.HttpContext.Connection.ClientCertificate;

                    // Credentials (client_id, client_secret)

                    // client_secret_basic
                    if (!AuthenticationHeader.GetCredentials(
                        MyHttpContext.Current.Request.Headers[OAuth2AndOIDCConst.HttpHeader_Authorization],
                        out string client_id, out string client_secret))
                    {
                        // client_secret_post
                        client_id = formData[OAuth2AndOIDCConst.client_id];
                        client_secret = formData[OAuth2AndOIDCConst.client_secret];
                    }

                    // client_id & (client_secret or x509)
                    if (Token.CmnEndpoints.ClientAuthentication(client_id, client_secret,
                        ref x509, out OAuth2AndOIDCEnum.ClientMode permittedLevel))
                    {
                        // 失効（#200）
                        // ・token_type_hint は探す順番の手掛かりにすぎない（RFC 7009 2.1）
                        // ・無効なトークンはエラーにしない（RFC 7009 2.2）
                        // ・成功は空の JSON（HTTP 200）で返し、両アプリで揃える
                        err = Token.CmnEndpoints.RevokeToken(client_id, token, token_type_hint);

                        if (err.Count == 0)
                        {
                            return this.Ok(err); // 成功（RFC 7009 2.2 : 200）
                        }

                        // 他のクライアントのトークン（invalid_grant）は、下でエラーとして返す（#196）。
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
                    // token が無い
                    err.Add(OAuth2AndOIDCConst.error, OAuth2AndOIDCConst.invalid_request);
                    err.Add(OAuth2AndOIDCConst.error_description, "token is null or empty.");
                }
            }
            else
            {
                // FormDataCollection無し
                err.Add(OAuth2AndOIDCConst.error, OAuth2AndOIDCConst.invalid_request);
                err.Add(OAuth2AndOIDCConst.error_description, "Form data is null.");
            }

            return this.OAuth2Error(err, "revoke"); // 失敗（RFC 7009 2.2.1 : RFC 6749 5.2 のとおり 400 / 401）（#196）
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
        public Dictionary<string, object> IntrospectToken(IFormCollection formData)
        {
            // 戻り値（エラー）
            Dictionary<string, object> err = new Dictionary<string, object>();

            if (formData != null)
            {
                // 変数
                string token = formData[OAuth2AndOIDCConst.token];
                string token_type_hint = formData[OAuth2AndOIDCConst.token_type_hint];

                // token は必須、token_type_hint は任意（RFC 7009 2.1 / RFC 7662 2.1）（#200）
                if (!string.IsNullOrEmpty(token))
                {
                    // クライアント証明書
                    // Azure Web App Client Certificate Authentication with ASP.NET Core | Kirk Evans Blog
                    // https://blogs.msdn.microsoft.com/kaevans/2016/04/13/azure-web-app-client-certificate-authentication-with-asp-net-core-2/
                    // tls_client_authのクライアントも利用できるよう有効化（#194）。
                    X509Certificate2 x509 = Request.HttpContext.Connection.ClientCertificate;

                    // Credentials (client_id, client_secret)

                    // client_secret_basic
                    if (!AuthenticationHeader.GetCredentials(
                        MyHttpContext.Current.Request.Headers[OAuth2AndOIDCConst.HttpHeader_Authorization],
                        out string client_id, out string client_secret))
                    {
                        // client_secret_post
                        client_id = formData[OAuth2AndOIDCConst.client_id];
                        client_secret = formData[OAuth2AndOIDCConst.client_secret];
                    }

                    // client_id & (client_secret or x509)
                    if (Token.CmnEndpoints.ClientAuthentication(client_id, client_secret,
                        ref x509, out OAuth2AndOIDCEnum.ClientMode permittedLevel))
                    {
                        // 問い合わせ（#200）
                        // ・token_type_hint は探す順番の手掛かりにすぎない（RFC 7662 2.1）
                        // ・無効なトークン（存在しない・失効済み・期限切れ）は active=false で答える（RFC 7662 2.2）
                        return Token.CmnEndpoints.IntrospectToken(client_id, token, token_type_hint);
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
                    // token が無い
                    err.Add(OAuth2AndOIDCConst.error, OAuth2AndOIDCConst.invalid_request);
                    err.Add(OAuth2AndOIDCConst.error_description, "token is null or empty.");
                }
            }
            else
            {
                // FormDataCollection無し
                err.Add(OAuth2AndOIDCConst.error, OAuth2AndOIDCConst.invalid_request);
                err.Add(OAuth2AndOIDCConst.error_description, "Form data is null.");
            }

            return err; // 失敗
        }

        #endregion

        #region /device

        /// <summary>
        /// Device AuthZの認可リクエストを受信
        /// POST: /device_authz
        /// </summary>
        /// <param name="formData">IFormCollection</param>
        /// <returns>Device AuthZの認可レスポンス</returns>
        [HttpPost]
        public Dictionary<string, string> DeviceAuthZAuthorize(IFormCollection formData)
        {
            string err = "";
            string errDescription = "";

            if (formData != null)
            {
                // client_id, client_secret

                // client_secret_basic
                if (!AuthenticationHeader.GetCredentials(
                    MyHttpContext.Current.Request.Headers[OAuth2AndOIDCConst.HttpHeader_Authorization],
                    out string client_id, out string client_secret))
                {
                    // client_secret_post
                    client_id = formData[OAuth2AndOIDCConst.client_id];
                    client_secret = formData[OAuth2AndOIDCConst.client_secret];
                }

                // クライアント認証（RFC 8628 3.1）（#193）
                // パブリック クライアントは、client_idの確認のみ。
                X509Certificate2 x509 = Request.HttpContext.Connection.ClientCertificate;
                if (!Token.CmnEndpoints.DeviceAuthZClientAuthentication(client_id, client_secret, ref x509))
                {
                    return new Dictionary<string, string>()
                    {
                        {OAuth2AndOIDCConst.error, "invalid_client"},
                        {OAuth2AndOIDCConst.error_description, "Invalid credential."}
                    };
                }

                // scopeパラメタ
                string scope = formData[OAuth2AndOIDCConst.scope];

                // codeの生成は先送り
                Dictionary<string, string> tempDic = new Dictionary<string, string>()
                {
                    {"client_id", client_id},
                    {"scope", scope}
                };

                //string code = Token.CmnEndpoints.CreateCodeInAuthZNRes(...);
                string tempData = JsonConvert.SerializeObject(tempDic);

                // authReqExp
                int requested_expiry = Config.DeviceAuthZExpireTimeSpanFromSeconds;
                long authReqExp = DateTimeOffset.Now.AddSeconds(
                    Config.DeviceAuthZExpireTimeSpanFromSeconds).ToUnixTimeSeconds();

                // 検証用エンドポイントの絶対URI
                string verificationUri =
                    Config.OAuth2AuthorizationServerEndpointsRootURI + Config.DeviceAuthZVerifyEndpoint;

                // DeviceAuthZ情報をストア
                string deviceCode;
                string userCode;
                Sts.DeviceAuthZProvider.Create(authReqExp, tempData, out deviceCode, out userCode);

                // ココまでの結果をレスポンス
                return new Dictionary<string, string>()
                {
                    {OAuth2AndOIDCConst.device_code, deviceCode},
                    {OAuth2AndOIDCConst.user_code, userCode},
                    // RFC 8628 3.2 : ユーザが辿れるURIを返す（#193）。
                    {OAuth2AndOIDCConst.verification_uri, verificationUri},
                    {OAuth2AndOIDCConst.verification_uri_complete, verificationUri + "?user_code=" + userCode},
                    {OAuth2AndOIDCConst.expires_in, requested_expiry.ToString()},
                    {OAuth2AndOIDCConst.PollingInterval, Config.DeviceAuthZPollingIntervalSeconds.ToString()}
                };
            }
            else
            {
                // フォームデータ無し（#193）
                err = OAuth2AndOIDCConst.invalid_request;
                errDescription = "Form data is null.";
            }

            // エラー
            return new Dictionary<string, string>()
            {
                {OAuth2AndOIDCConst.error, err},
                {OAuth2AndOIDCConst.error_description, errDescription}
            };
        }

        // DeviceAuthZResponse画面 → HomeControllerに。
        // DeviceAuthZVerify画面 → AccountControllerに。

        #endregion

        #region /ciba

        /// <summary>
        /// FAPI CIBAの認可リクエストを受信
        /// POST: /ciba_authz
        /// </summary>
        /// <param name="formData">
        /// request_uri
        /// </param>
        /// <returns>CIBAの認可レスポンス</returns>
        [HttpPost]
        public async Task<Dictionary<string, string>> CibaAuthorizeAsync(IFormCollection formData)
        {
            string err = "";
            string errDescription = "";

            if (formData != null)
            {
                string request_uri = formData[OAuth2AndOIDCConst.request_uri];

                string authReqId = "";

                if (!string.IsNullOrEmpty(request_uri))
                {
                    string jsonStr = Sts.RequestObjectProvider.Get(
                        request_uri.Replace(OAuth2AndOIDCConst.UrnRequestUriBase, ""));

                    // 存在しないrequest_uriではnullになる（#185）。
                    JObject jsonObj = (JObject)JsonConvert.DeserializeObject(jsonStr);

                    string client_id = "";
                    string scope = "";
                    string client_notification_token = "";
                    string binding_message = "";
                    string user_code = "";
                    string requested_expiry = "";
                    string login_hint = "";

                    if (jsonObj == null)
                    {
                        // 不正なrequest_uri
                        err = OAuth2AndOIDCConst.invalid_request;
                        errDescription = "Invalid request_uri.";
                    }
                    else if (Token.CmnEndpoints.ValidateCibaAuthZReqParam(
                        jsonObj, out client_id, out scope,
                        out client_notification_token, out binding_message,
                        out user_code, out requested_expiry, out login_hint,
                        out err, out errDescription))
                    {
                        // 検証成功

                        // AccountControllerからの移行なので...。
                        string name = Sts.Helper.GetInstance().GetClientName(client_id);

                        // scopeパラメタ
                        string[] scopes = (scope ?? "").Split(' ');

                        // login_hintから、userとsubを取得。
                        ApplicationUser user = null;
                        string sub = PPIDExtension.GetSubForOIDC(client_id, login_hint, out user);

                        if (user != null)
                        {
                            // codeの生成
                            string code = Token.CmnEndpoints.CreateCodeInAuthZNRes(
                                new ClaimsIdentity(new GenericIdentity(sub)),
                                new NameValueCollection(),
                                client_id, "", scopes, null, "");

                            // requested_expiry → UnixTime化
                            int _requested_expiry = Config.CibaExpireTimeSpanFromSeconds; // 初期値
                            if (!string.IsNullOrEmpty(requested_expiry))                  // requested_expiry値
                                int.TryParse(requested_expiry, out _requested_expiry);

                            long authReqExp = DateTimeOffset.Now.AddSeconds(_requested_expiry).ToUnixTimeSeconds();

                            // CIBA情報をストア
                            Sts.CibaProvider.Create(
                               client_notification_token,
                               authReqExp, code, binding_message, out authReqId);

#pragma warning disable 162

                            // プッシュ通知を、userに送信
                            if (!Sts.CibaProvider.DebugModeWithOutAD)
                            {
                                // - DeviceTokenを使用してプッシュ通知
                                await FcmService.GetInstance().SendAsync(
                                    user.DeviceToken, "CIBA", "Allow / Deny",
                                    new Dictionary<string, string>()
                                    {
                                        { OAuth2AndOIDCConst.auth_req_id, authReqId},
                                        { OAuth2AndOIDCConst.binding_message, binding_message}
                                    });
                            }
                            else
                            {
                                // テストを通すため追加
                                Sts.CibaProvider.ReceiveResult(authReqId, true);
                            }

#pragma warning restore 162

                            // ココまでの結果をレスポンス
                            return new Dictionary<string, string>()
                            {
                                {OAuth2AndOIDCConst.auth_req_id, authReqId},
                                {OAuth2AndOIDCConst.expires_in, _requested_expiry.ToString()},
                                {OAuth2AndOIDCConst.PollingInterval, Config.CibaPollingIntervalSeconds.ToString()}
                            };
                        }
                        // 以降で、下記を束ねる。
                        // - プッシュ通知の応答結果
                        // - Tokenリクエスト（polling）
                    }
                    else
                    {
                        // 検証失敗
                        // err, errDescriptionは設定済み。
                    }
                }
                else
                {
                    // 不正なRequest
                    err = OAuth2AndOIDCConst.invalid_request;
                    errDescription = "request_uri is null or empty.";
                }
            }
            else
            {
                // FormDataCollection無し
                err = OAuth2AndOIDCConst.invalid_request;
                errDescription = "Form data is null.";
            }

            // エラー
            return new Dictionary<string, string>()
            {
                {OAuth2AndOIDCConst.error, err},
                {OAuth2AndOIDCConst.error_description, errDescription}
            };
        }

        /// <summary>
        /// CIBAのプッッシュ結果を受信
        /// POST: /ciba_result
        /// </summary>
        /// <param name="formData">
        /// - result
        /// </param>
        /// <returns>string</returns>
        [HttpPost]
        public string CibaPushResult(IFormCollection formData)
        {
            // 戻り値（エラー）
            Dictionary<string, object> err = new Dictionary<string, object>();

            // クライアント認証
            if (AuthenticationHeader.GetCredentials(
                MyHttpContext.Current.Request.Headers[OAuth2AndOIDCConst.HttpHeader_Authorization], out string bearerToken))
            {
                if (Token.CmnAccessToken.VerifyAccessToken(bearerToken, out JObject claims, out ClaimsIdentity identity))
                {
                    // ClientIdの取り出し
                    Claim ClientId = identity.Claims.Where(
                        x => x.Type == OAuth2AndOIDCConst.UrnAudienceClaim).FirstOrDefault<Claim>();

                    ApplicationUser user =
                        //CmnUserStore.FindByName(identity.Name);
                        PPIDExtension.GetUserFromSub(ClientId.Value, identity.Name);

                    if (user != null)
                    {
                        // 変数
                        string auth_req_id = formData["auth_req_id"];
                        string temp = formData["result"];

                        bool result = false;
                        if (!string.IsNullOrEmpty(auth_req_id)
                            && bool.TryParse(temp, out result))
                        {
                            Sts.CibaProvider.ReceiveResult(auth_req_id, result);
                            return "OK";
                        }
                    }
                }
            }

            return "NG"; // 和製英語ですがｗ
        }

        #endregion

        #region /jwks.json

        /// <summary>
        /// JWK Set documentを返すWebAPI
        /// GET: /jwkcerts
        /// </summary>
        /// <returns>ContentResult</returns>
        [HttpGet]
        public ContentResult JwksUri()
        {
            return this.Content(
                ResourceLoader.LoadAsString(
                    OAuth2AndOIDCParams.JwkSetFilePath,
                    Encoding.GetEncoding(CustomEncode.UTF_8))
                    , "application/json");
        }

        #endregion

        #region /ros (RequestObject)

        /// <summary>
        /// RequestObjectを登録するWebAPI
        /// GET: /ros
        /// </summary>
        /// <returns>ActionResult</returns>
        [HttpPost]
        public async Task<ActionResult> RequestObjectUri()
        {
            // RequestObjectを取り出す。
            // Synchronous operations are disallowed.
            // Call WriteAsync or set AllowSynchronousIO to true instead.
            string body = await (new StreamReader(MyHttpContext.Current.Request.Body)).ReadToEndAsync();

            if (!string.IsNullOrEmpty(body))
            {
                // 公開鍵取得にissが必要。
                // - issを取り出す。
                string requestObjectString = CustomEncode.ByteToString(
                    CustomEncode.FromBase64UrlString(body.Split('.')[1]), CustomEncode.us_ascii);
                JObject requestObject = (JObject)JsonConvert.DeserializeObject(requestObjectString);

                string iss = "";
                string pubKey = "";
                bool result = false;
                if (requestObject.ContainsKey("client_notification_token"))
                {
                    // CIBA

                    // - 公開鍵取得を取り出す。
                    iss = (string)requestObject[OAuth2AndOIDCConst.iss];
                    pubKey = Sts.Helper.GetInstance().GetJwkECDsaPublickey(iss);
                    pubKey = CustomEncode.ByteToString(CustomEncode.FromBase64UrlString(pubKey), CustomEncode.us_ascii);

                    // 署名検証
                    result = RequestObject.VerifyCiba(body, out iss, pubKey);
                }
                else
                {
                    // F-API2 CC

                    // - 公開鍵取得を取り出す。
                    iss = (string)requestObject[OAuth2AndOIDCConst.iss];
                    pubKey = Sts.Helper.GetInstance().GetJwkRsaPublickey(iss);
                    pubKey = CustomEncode.ByteToString(CustomEncode.FromBase64UrlString(pubKey), CustomEncode.us_ascii);

                    // 署名検証
                    result = RequestObject.Verify(body, out iss, pubKey);
                }

                // 署名検証
                if (result)
                {
                    string urn = Guid.NewGuid().ToString("N");
                    string request_uri = OAuth2AndOIDCConst.UrnRequestUriBase + urn;

                    // RequestObjectの登録
                    Sts.RequestObjectProvider.Create(urn, requestObjectString);

                    // 成功
                    return this.Created("", // 第一引数...
                        JsonConvert.SerializeObject(new
                        {
                            iss = Config.IssuerId,
                            aud = iss,
                            request_uri = request_uri,
                            exp = "" // 有効期限（存続期間は短く、好ましくは一回限
                        }, Newtonsoft.Json.Formatting.None));
                }
            }

            // 失敗
            return new BadRequestResult();
        }

        #endregion

        #region /.well-known/openid-configuration

        /// <summary>
        /// OpenID Provider Configurationを返すWebAPI
        /// GET: /.well-known/openid-configuration
        /// </summary>
        /// <returns>ContentResult</returns>
        [HttpGet]
        [Route(".well-known/openid-configuration")] // ココは固定
        public ContentResult OpenIDConfig()
        {
            // JsonSerializerSettingsを指定して、可読性の高いJSONを返す。
            return this.Content(
                JsonConvert.SerializeObject(
                    Token.CmnEndpoints.OpenIDConfig(),
                    new JsonSerializerSettings
                    {
                        Formatting = Newtonsoft.Json.Formatting.Indented,
                        ContractResolver = new CamelCasePropertyNamesContractResolver()
                    })
                    , "application/json");
        }

        #endregion

        #region /samlmetadata

        /// <summary>
        /// SamlMetadataを返すWebAPI
        /// GET: /samlmetadata
        /// </summary>
        /// <returns>ContentResult</returns>
        [HttpGet]
        [Route("samlmetadata")]  // ココは固定
        public ContentResult SamlMetadata()
        {
            // XmlWriterSettingsを指定して、可読性の高いXMLを返す。
            string saml2RequestEndpoint = 
                Config.OAuth2AuthorizationServerEndpointsRootURI + Config.Saml2RequestEndpoint;

            XmlDocument samlMetadata = SAML2Bindings.CreateMetadata(
                Config.IssuerId,
                PrivacyEnhancedMail.GetBase64StringFromPemFilePath(
                    CmnClientParams.RsaCerFilePath,
                    PrivacyEnhancedMail.RFC7468Label.Certificate),
                new SAML2Enum.NameIDFormat[]
                {
                    SAML2Enum.NameIDFormat.Unspecified,
                    SAML2Enum.NameIDFormat.EmailAddress,
                    SAML2Enum.NameIDFormat.Persistent//,
                    //SAML2Enum.NameIDFormat.Transient
                },
                saml2RequestEndpoint,
                saml2RequestEndpoint);

            return this.Content(
                samlMetadata.XmlToString(
                    new XmlWriterSettings()
                    {
                        Encoding = Encoding.UTF8,
                        Indent = true
                    })
                    , "application/xml");
        }

        #endregion

        #region プッシュ通知

        /// <summary>
        /// ユーザ情報にデバイス・トークンを追加
        /// POST: /SetDeviceToken
        /// </summary>
        /// <param name="formData">
        /// - devicetoken
        /// </param>
        /// <returns>string</returns>
        [HttpPost]
        public async Task<string> SetDeviceToken(IFormCollection formData)
        {
            string device_token = formData["device_token"];

            if (!string.IsNullOrEmpty(device_token))
            {
                // クライアント認証
                if (AuthenticationHeader.GetCredentials(
                    MyHttpContext.Current.Request.Headers[OAuth2AndOIDCConst.HttpHeader_Authorization], out string bearerToken))
                {
                    if (Token.CmnAccessToken.VerifyAccessToken(bearerToken, out JObject claims, out ClaimsIdentity identity))
                    {
                        // ClientIdの取り出し
                        Claim ClientId = identity.Claims.Where(
                            x => x.Type == OAuth2AndOIDCConst.UrnAudienceClaim).FirstOrDefault<Claim>();

                        ApplicationUser user =
                            //CmnUserStore.FindByName(identity.Name);
                            PPIDExtension.GetUserFromSub(ClientId.Value, identity.Name);

                        if (user != null)
                        {
                            // デバイストークンの保存
                            user.DeviceToken = device_token;
                            await UserManager.UpdateAsync(user);

                            return "OK";
                        }
                    }
                }
            }

            return "NG"; // 和製英語ですがｗ
        }

        #endregion

        #region 共通のエラー応答（RFC 6749 5.2）

        /// <summary>
        /// クライアント認証を行うエンドポイント（/token・/revoke）のエラー応答を作る（RFC 6749 5.2）
        /// </summary>
        /// <param name="err">error / error_description を持つ辞書</param>
        /// <param name="realm">WWW-Authenticate の realm（エンドポイントの名前）</param>
        /// <returns>400、または 401（invalid_client）</returns>
        /// <remarks>
        /// 以前は Dictionary をそのまま返していたため、エラーでも HTTP 200 だった（#196）。
        /// 本文（error / error_description の JSON）は変えない。
        /// /revoke のエラーも RFC 6749 5.2 に従う（RFC 7009 2.2.1）ので、/token の region から移して共用する（#196）。
        /// </remarks>
        private IActionResult OAuth2Error(Dictionary<string, string> err, string realm)
        {
            int status = Token.CmnEndpoints.GetErrorStatusCode(err);

            if (status == 401)
            {
                // クライアント認証の失敗。受け付ける認証方式を示す。
                // Authorization ヘッダで認証を試みたクライアントには必須（RFC 6749 5.2）。
                this.Response.Headers["WWW-Authenticate"] = "Basic realm=\"" + realm + "\"";
            }

            return new ObjectResult(err) { StatusCode = status };
        }

        #endregion
    }
}