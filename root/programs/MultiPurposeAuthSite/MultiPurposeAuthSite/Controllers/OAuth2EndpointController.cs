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
//*  2020/02/27  西野 大介         CIBA対応実施（CibaAuthorize, CibaPushResult）
//*  2020/03/09  西野 大介         FormDataCollectionチェック処理の強化
//**********************************************************************************

using MultiPurposeAuthSite.Co;
using MultiPurposeAuthSite.Entity;
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

using System.Web;
using System.Web.Http;
using System.Web.Http.Cors;
using System.Net;
using System.Net.Http;
using System.Net.Http.Formatting;

using Newtonsoft.Json;
using Newtonsoft.Json.Linq;
using Newtonsoft.Json.Serialization;

using Touryo.Infrastructure.Business.Presentation;
using Touryo.Infrastructure.Framework.Authentication;
using Touryo.Infrastructure.Framework.Presentation;
using Touryo.Infrastructure.Public.IO;
using Touryo.Infrastructure.Public.Str;
using Touryo.Infrastructure.Public.Security;

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
    [MyBaseAsyncApiController(httpAuthHeader: EnumHttpAuthHeader.None)] // 認証無し（自前）
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
            //// エラーにならないことを確認
            //var v = formData["hoge"];

            Dictionary<string, string> ret = null;
            Dictionary<string, string> err = null;

            if (formData != null)
            {
                #region credentials

                // client_id, client_secret

                // client_secret_basic
                if (!AuthenticationHeader.GetCredentials(
                        HttpContext.Current.Request.Headers[OAuth2AndOIDCConst.HttpHeader_Authorization],
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
                X509Certificate2 x509 = Request.GetClientCertificate();
                //if (x509 != null)
                //{
                //    //string thumbprint = x509.Thumbprint;
                //    //string subject = x509.Subject;
                //    //string subjectName = x509.SubjectName.Name;                     // Subjectと同じ
                //    //string algFriendlyName = x509.SignatureAlgorithm.FriendlyName;　// sha256RSA, etc.
                //}

                #endregion

                #region grant_type

                string grant_type = "";
                grant_type = formData[OAuth2AndOIDCConst.grant_type];

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
                                return ret;
                            }
                            break;

                        case OAuth2AndOIDCConst.RefreshTokenGrantType:
                            string refresh_token = formData[OAuth2AndOIDCConst.RefreshToken];
                            if (Token.CmnEndpoints.GrantRefreshTokenCredentials(
                                grant_type, client_id, client_secret, x509, refresh_token, out ret, out err))
                            {
                                return ret;
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
                                return ret;
                            }
                            break;

                        case OAuth2AndOIDCConst.ClientCredentialsGrantType:
                            scope = formData[OAuth2AndOIDCConst.scope];
                            if (Token.CmnEndpoints.GrantClientCredentials(
                                grant_type, client_id, client_secret, x509, scope, out ret, out err))
                            {
                                return ret;
                            }
                            break;

                        case OAuth2AndOIDCConst.JwtBearerTokenFlowGrantType:
                            if (Token.CmnEndpoints.GrantJwtBearerTokenCredentials(
                            grant_type, assertion, x509, out ret, out err))
                            {
                                return ret;
                            }
                            break;

                        case OAuth2AndOIDCConst.CibaGrantType:
                            string auth_req_id = formData[OAuth2AndOIDCConst.auth_req_id];
                            if (Token.CmnEndpoints.GrantCiba(grant_type, 
                                client_id, client_secret, x509,
                                auth_req_id, out ret, out err))
                            {
                                return ret;
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

                    return userinfoClaimSet;

                }
                else
                {
                    // ユーザ認証エラー
                    err.Add(OAuth2AndOIDCConst.error, OAuth2AndOIDCConst.invalid_request);
                    err.Add(OAuth2AndOIDCConst.error_description, "Invalid token.");
                }
            }
            else
            {
                // クライアント認証エラー（ヘッダ不正
                err.Add(OAuth2AndOIDCConst.error, OAuth2AndOIDCConst.invalid_request);
                err.Add(OAuth2AndOIDCConst.error_description, "Invalid authentication header.");
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

            if (formData != null)
            {
                // 変数
                string token = formData[OAuth2AndOIDCConst.token];
                string token_type_hint = formData[OAuth2AndOIDCConst.token_type_hint];

                if (!(string.IsNullOrEmpty(token) && string.IsNullOrEmpty(token_type_hint)))
                {
                    // クライアント証明書
                    X509Certificate2 x509 = Request.GetClientCertificate();

                    // Credentials (client_id, client_secret)

                    // client_secret_basic
                    if (!AuthenticationHeader.GetCredentials(
                            HttpContext.Current.Request.Headers[OAuth2AndOIDCConst.HttpHeader_Authorization],
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
                        // 検証完了
                        if (token_type_hint == OAuth2AndOIDCConst.AccessToken)
                        {
                            // 検証
                            if (Token.CmnAccessToken.VerifyAccessToken(token, out ClaimsIdentity identity))
                            {
                                // 検証成功

                                // jtiの取り出し
                                Claim jti = identity.Claims.Where(
                                    x => x.Type == OAuth2AndOIDCConst.UrnJwtIdClaim).FirstOrDefault<Claim>();

                                // access_token取消
                                Sts.RevocationProvider.Create(jti.Value);
                                return null; // 成功
                            }
                            else
                            {
                                // 検証失敗
                                // 検証エラー
                                err.Add(OAuth2AndOIDCConst.error, OAuth2AndOIDCConst.invalid_request);
                                err.Add(OAuth2AndOIDCConst.error_description, "Invalid token.");
                            }
                        }
                        else if (token_type_hint == OAuth2AndOIDCConst.RefreshToken)
                        {
                            // refresh_token取消
                            if (Token.RefreshTokenProvider.Delete(token))
                            {
                                // 取り消し成功
                                return null; // 成功
                            }
                            else
                            {
                                // 取り消し失敗
                                err.Add(OAuth2AndOIDCConst.error, OAuth2AndOIDCConst.invalid_request);
                                err.Add(OAuth2AndOIDCConst.error_description, "Invalid token.");
                            }
                        }
                        else
                        {
                            // token_type_hint パラメタ・エラー
                            err.Add(OAuth2AndOIDCConst.error, OAuth2AndOIDCConst.invalid_request);
                            err.Add(OAuth2AndOIDCConst.error_description, "invalid token_type_hint.");
                        }
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
                    // token or token_type_hint are null or empty.
                    err.Add(OAuth2AndOIDCConst.error, OAuth2AndOIDCConst.invalid_request);
                    err.Add(OAuth2AndOIDCConst.error_description, "token or token_type_hint are null or empty.");
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

            if (formData != null)
            {
                // 変数
                string token = formData[OAuth2AndOIDCConst.token];
                string token_type_hint = formData[OAuth2AndOIDCConst.token_type_hint];

                if (!(string.IsNullOrEmpty(token) && string.IsNullOrEmpty(token_type_hint)))
                {
                    // クライアント証明書
                    X509Certificate2 x509 = Request.GetClientCertificate();

                    // Credentials (client_id, client_secret)

                    // client_secret_basic
                    if (!AuthenticationHeader.GetCredentials(
                        HttpContext.Current.Request.Headers[OAuth2AndOIDCConst.HttpHeader_Authorization],
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

                        // 検証完了
                        if (token_type_hint == OAuth2AndOIDCConst.AccessToken)
                        {
                            // AccessToken
                            // ↓に続く
                        }
                        else if (token_type_hint == OAuth2AndOIDCConst.RefreshToken)
                        {
                            // RefreshToken
                            string tokenPayload = Token.RefreshTokenProvider.Refer(token);
                            if (!string.IsNullOrEmpty(tokenPayload))
                            {
                                // AccessToken化して処理共通化
                                token = Token.CmnAccessToken.ProtectFromPayload(
                                    "", tokenPayload, DateTimeOffset.Now,
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
                            err.Add(OAuth2AndOIDCConst.error, OAuth2AndOIDCConst.invalid_request);
                            err.Add(OAuth2AndOIDCConst.error_description, "Invalid token_type_hint.");
                        }

                        // AccessToken化して共通化した処理
                        if (!string.IsNullOrEmpty(token)
                            && Token.CmnAccessToken.VerifyAccessToken(token, out ClaimsIdentity identity))
                        {
                            // 検証成功
                            // メタデータの返却
                            ret.Add("active", "true");
                            ret.Add(OAuth2AndOIDCConst.token_type, token_type_hint);

                            string scopes = "";
                            foreach (Claim claim in identity.Claims)
                            {
                                if (claim.Type.StartsWith(OAuth2AndOIDCConst.UrnClaimBase))
                                {
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
                                        { temp, claim.Value}
                                    });
                                    }
                                    else
                                    {
                                        ret.Add(claim.Type.Substring(
                                            OAuth2AndOIDCConst.UrnClaimBase.Length), claim.Value);
                                    }
                                }
                            }
                            ret.Add(OAuth2AndOIDCConst.UrnScopesClaim.Substring(
                                OAuth2AndOIDCConst.UrnClaimBase.Length), scopes.Trim());

                            return ret; // 成功
                        }
                        else
                        {
                            // 検証失敗
                            // 検証エラー
                            err.Add(OAuth2AndOIDCConst.error, OAuth2AndOIDCConst.invalid_request);
                            err.Add(OAuth2AndOIDCConst.error_description, "Invalid token.");
                        }
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
                    // token or token_type_hint are null or empty.
                    err.Add(OAuth2AndOIDCConst.error, OAuth2AndOIDCConst.invalid_request);
                    err.Add(OAuth2AndOIDCConst.error_description, "token or token_type_hint are null or empty.");
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

        #region /ciba

        /// <summary>
        /// CIBAの認可リクエストを受信
        /// POST: /ciba_authz
        /// </summary>
        /// <param name="formData">
        /// request_uri
        /// </param>
        /// <returns>CIBAの認可レスポンス</returns>
        [HttpPost]
        public async Task<Dictionary<string, string>> CibaAuthorize(FormDataCollection formData)
        {
            string err = "";
            string errDescription = "";

            if (formData != null)
            {
                string request_uri = formData[OAuth2AndOIDCConst.request_uri];

                string authReqId = "";

                JObject claims = null;
                if (!string.IsNullOrEmpty(request_uri))
                {
                    string jsonStr = Sts.RequestObjectProvider.Get(
                        request_uri.Replace(OAuth2AndOIDCConst.UrnRequestUriBase, ""));

                    JObject jsonObj = (JObject)JsonConvert.DeserializeObject(jsonStr);

                    string client_id = "";
                    string scope = "";
                    string client_notification_token = "";
                    string binding_message = "";
                    string user_code = "";
                    string requested_expiry = "";
                    string login_hint = "";

                    if (Token.CmnEndpoints.ValidateCibaAuthZReqParam(
                        jsonObj, out client_id, out scope,
                        out client_notification_token, out binding_message,
                        out user_code, out requested_expiry, out login_hint,
                        out err, out errDescription))
                    {
                        // 検証成功

                        // AccountControllerからの移行なので...。
                        string name = Sts.Helper.GetInstance().GetClientName(client_id);

                        // ClaimsIdentityを生成
                        ClaimsIdentity identity = new ClaimsIdentity(new GenericIdentity(name));

                        // NameValueCollectionを生成
                        NameValueCollection queryString = new NameValueCollection();

                        // scopeパラメタ
                        string[] scopes = (scope ?? "").Split(' ');

                        // codeの生成
                        string code = Token.CmnEndpoints.CreateCodeInAuthZNRes(
                            identity, queryString, client_id, "", scopes, claims, "");

                        // requested_expiry → UnixTime化
                        int _requested_expiry = Config.CibaExpireTimeSpanFromSeconds; // 初期値
                        if (!string.IsNullOrEmpty(requested_expiry))                  // requested_expiry値
                            int.TryParse(requested_expiry, out _requested_expiry);

                        long authReqExp = DateTimeOffset.Now.AddSeconds(_requested_expiry).ToUnixTimeSeconds();

                        // CIBA情報をストア
                        Sts.CibaProvider.Create(
                           client_notification_token,
                           authReqExp, code, binding_message, out authReqId);

                        // プッシュ通知を、login_hint（に記載のユーザ）に送信
                        if (!Sts.CibaProvider.DebugModeWithOutAD)
                        {
                            // - login_hint（UserName）でユーザ取得。
                            ApplicationUser user = PPIDExtension.GetUserFromSub(client_id, login_hint);
                            string deviceToken = user.DeviceToken;

                            // - DeviceTokenを使用してプッシュ通知
                            string temp = await FcmService.GetInstance().SendAsync(
                                user.DeviceToken, "CIBA", "Allow / Deny",
                                new Dictionary<string, string>()
                                {
                                    { "auth_req_id", authReqId},
                                    { "binding_message", binding_message}
                                });
                        }
                        else
                        {
                            // テストを通すため追加
                            Sts.CibaProvider.ReceiveResult(authReqId, true);
                        }

                        // ココまでの結果をレスポンス
                        return new Dictionary<string, string>()
                        {
                            {OAuth2AndOIDCConst.auth_req_id, authReqId},
                            {OAuth2AndOIDCConst.expires_in, _requested_expiry.ToString()},
                            {OAuth2AndOIDCConst.PollingInterval, Config.CibaPollingIntervalSeconds.ToString()}
                        };

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
        public string CibaPushResult(FormDataCollection formData)
        {
            // 戻り値（エラー）
            Dictionary<string, object> err = new Dictionary<string, object>();

            // クライアント認証
            if (AuthenticationHeader.GetCredentials(
                HttpContext.Current.Request.Headers[OAuth2AndOIDCConst.HttpHeader_Authorization], out string bearerToken))
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

        #region /ros (RequestObject)

        /// <summary>
        /// RequestObjectを登録するWebAPI
        /// GET: /ros
        /// </summary>
        /// <returns>HttpResponseMessage</returns>
        [HttpPost]
        public HttpResponseMessage RequestObjectUri()
        {
            // RequestObjectを取り出す。
            string body = new StreamReader(HttpContext.Current.Request.InputStream).ReadToEnd();

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

                if (result)
                {
                    string urn = Guid.NewGuid().ToString("N");
                    string request_uri = OAuth2AndOIDCConst.UrnRequestUriBase + urn;

                    // RequestObjectの登録
                    Sts.RequestObjectProvider.Create(urn, requestObjectString);

                    // 成功
                    return new HttpResponseMessage()
                    {
                        Content = new JsonContent(JsonConvert.SerializeObject(new
                        {
                            iss = Config.IssuerId,
                            aud = iss,
                            request_uri = request_uri,
                            exp = "" // 有効期限（存続期間は短く、好ましくは一回限
                        }, Newtonsoft.Json.Formatting.None)),
                        StatusCode = HttpStatusCode.Created
                    };
                }
            }

            // 失敗
            return new HttpResponseMessage(HttpStatusCode.BadRequest);
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
                    Token.CmnEndpoints.OpenIDConfig(),
                    new JsonSerializerSettings
                    {
                        Formatting = Newtonsoft.Json.Formatting.Indented,
                        ContractResolver = new CamelCasePropertyNamesContractResolver()
                    })
            };
        }

        #endregion

        #region /samlmetadata

        /// <summary>
        /// SamlMetadataを返すWebAPI
        /// GET: /samlmetadata
        /// </summary>
        /// <returns>HttpResponseMessage</returns>
        [HttpGet]
        [Route("samlmetadata")]  // ココは固定
        public HttpResponseMessage SamlMetadata()
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

            return new HttpResponseMessage()
            {
                Content = new StringContent(
                    samlMetadata.XmlToString(
                        new XmlWriterSettings()
                        {
                            Encoding = Encoding.UTF8,
                            Indent = true
                        }),
                    Encoding.UTF8,
                    "application/xml"),
            };
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
        public string SetDeviceToken(FormDataCollection formData)
        {
            string device_token = formData["device_token"];

            if (!string.IsNullOrEmpty(device_token))
            {
                // クライアント認証
                if (AuthenticationHeader.GetCredentials(
                    HttpContext.Current.Request.Headers[OAuth2AndOIDCConst.HttpHeader_Authorization], out string bearerToken))
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
                            CmnUserStore.Update(user);

                            return "OK";
                        }
                    }
                }
            }

            return "NG"; // 和製英語ですがｗ
        }

        #endregion
    }
}