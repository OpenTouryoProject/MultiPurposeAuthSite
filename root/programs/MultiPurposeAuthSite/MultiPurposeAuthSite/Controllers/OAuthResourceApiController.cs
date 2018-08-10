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
//* クラス名        ：OAuthResourceApiController
//* クラス日本語名  ：OAuthResourceServerのApiController
//*
//* 作成日時        ：－
//* 作成者          ：－
//* 更新履歴        ：－
//*
//*  日時        更新者            内容
//*  ----------  ----------------  -------------------------------------------------
//*  2017/04/24  西野 大介         新規
//**********************************************************************************

using MultiPurposeAuthSite.Models.Log;
using MultiPurposeAuthSite.Models.Util;
using MultiPurposeAuthSite.Models.ASPNETIdentity;
using MultiPurposeAuthSite.Models.ASPNETIdentity.Manager;
using MultiPurposeAuthSite.Models.ASPNETIdentity.Entity;
using MultiPurposeAuthSite.Models.ASPNETIdentity.TokenProviders;
using MultiPurposeAuthSite.Models.ASPNETIdentity.OAuth2Extension;

using System;
using System.Linq;
using System.Collections.Generic;
using System.Security.Claims;
using System.Threading.Tasks;

using System.Web;
using System.Web.Http;
using System.Web.Http.Cors;
using System.Net.Http.Formatting;

using Microsoft.Owin.Security;
using Microsoft.Owin.Security.OAuth;
using Microsoft.AspNet.Identity;
using Microsoft.AspNet.Identity.Owin;

using Newtonsoft.Json;
using Newtonsoft.Json.Linq;

using Touryo.Infrastructure.Framework.Authentication;
using Touryo.Infrastructure.Public.Str;

/// <summary>MultiPurposeAuthSite.Controllers</summary>
namespace MultiPurposeAuthSite.Controllers
{
    /// <summary>OAuthResourceServerのApiController（ライブラリ）</summary>
    [EnableCors(
        // リソースへのアクセスを許可されている発生元
        origins: "*",
        // リソースによってサポートされているヘッダー
        headers: "*",
        // リソースによってサポートされているメソッド
        methods: "*",
        // 
        SupportsCredentials = true)]
    public class OAuthResourceApiController : ApiController
    {
        #region constructor

        /// <summary>constructor</summary>
        public OAuthResourceApiController()
        {
        }

        #endregion

        #region property (GetOwinContext)

        /// <summary>ApplicationUserManager</summary>
        private ApplicationUserManager UserManager
        {
            get
            {
                return HttpContext.Current.GetOwinContext().GetUserManager<ApplicationUserManager>();
            }
        }

        #endregion

        #region WebAPI

        #region /userinfo

        /// <summary>
        /// OAuthで認可したユーザ情報のClaimを発行するWebAPI
        /// GET: /userinfo
        /// </summary>
        /// <returns>Dictionary(string, object)</returns>
        [HttpGet]
        [Route("userinfo")] // OpenID Connectライクなインターフェイスに変更した。
        [Authorize]
        public async Task<Dictionary<string, object>> GetUserClaims()
        {
            // Claim情報を参照する。
            // iss, aud, expのチェックは、AccessTokenFormatJwt.Unprotectで実施済。
            ClaimsIdentity id = (ClaimsIdentity)User.Identity;
            Claim claim_aud = id.FindFirst(OAuth2AndOIDCConst.Claim_Audience);
            
            // ユーザ認証を行なう。
            ApplicationUser user = await UserManager.FindByIdAsync(User.Identity.GetUserId());
            
            string subject = "";

            if (user == null)
            {
                // Client認証
                subject = OAuth2Helper.GetInstance().GetClientName(claim_aud.Value);
            }
            else
            {
                // Resource Owner認証
                subject = user.UserName;
            }

            Dictionary<string, object> userinfoClaimSet = new Dictionary<string, object>();
            userinfoClaimSet.Add("sub", subject);

            // Scope
            IEnumerable<Claim> claimScope = id.FindAll(OAuth2AndOIDCConst.Claim_Scope).AsEnumerable();

            // scope値によって、返す値を変更する。
            foreach (Claim scope in claimScope)
            {
                if (user != null)
                {
                    // user == null では NG な Resource（Resource Owner の Resource）
                    switch (scope.Value.ToLower())
                    {
                        #region OpenID Connect

                        case OAuth2AndOIDCConst.Scope_Profile:
                            // ・・・
                            break;
                        case OAuth2AndOIDCConst.Scope_Email:
                            userinfoClaimSet.Add("email", user.Email);
                            userinfoClaimSet.Add("email_verified", user.EmailConfirmed.ToString());
                            break;
                        case OAuth2AndOIDCConst.Scope_Phone:
                            userinfoClaimSet.Add("phone_number", user.PhoneNumber);
                            userinfoClaimSet.Add("phone_number_verified", user.PhoneNumberConfirmed.ToString());
                            break;
                        case OAuth2AndOIDCConst.Scope_Address:
                            // ・・・
                            break;

                        #endregion

                        #region Else

                        case ASPNETIdentityConst.Scope_Userid:
                            userinfoClaimSet.Add(ASPNETIdentityConst.Scope_Userid, user.Id);
                            break;
                        case ASPNETIdentityConst.Scope_Roles:
                            userinfoClaimSet.Add(
                                ASPNETIdentityConst.Scope_Roles,
                                await UserManager.GetRolesAsync(user.Id));
                            break;

                            #endregion
                    }
                }
                else
                {
                    // user == null でも OK な Resource
                }
            }

            return userinfoClaimSet;
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
        //[Authorize]
        public Dictionary<string, string> RevokeToken(FormDataCollection formData)
        {
            // 戻り値（エラー）
            Dictionary<string, string> err = new Dictionary<string, string>();

            // 変数
            string[] temp = null;
            string token = formData["token"];
            string token_type_hint = formData["token_type_hint"];

            // クライアント認証

            // クライアント識別子
            string authHeader = HttpContext.Current.Request.Headers["Authorization"];
            
            temp = authHeader.Split(' ');

            if (temp[0].ToLower() == "basic")
            {
                temp = CustomEncode.ByteToString(
                    CustomEncode.FromBase64String(temp[1]), CustomEncode.us_ascii).Split(':');

                string clientId = temp[0];
                string clientSecret = temp[1];

                if (!(string.IsNullOrEmpty(clientId) && string.IsNullOrEmpty(clientSecret)))
                {
                    // *.config or OAuth2Dataテーブルを参照してクライアント認証を行なう。
                    if (clientSecret == OAuth2Helper.GetInstance().GetClientSecret(clientId))
                    {
                        // 検証完了

                        if (token_type_hint == "access_token")
                        {
                            // 検証
                            AccessTokenFormatJwt verifier = new AccessTokenFormatJwt();
                            AuthenticationTicket ticket = verifier.Unprotect(token);

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

                                // jtiの取り出し
                                Claim jti = ticket.Identity.Claims.Where(
                                    x => x.Type == OAuth2AndOIDCConst.Claim_JwtId).FirstOrDefault<Claim>();

                                // access_token取消
                                OAuth2RevocationProvider.GetInstance().Create(jti.Value);
                                return null; // 成功
                            }
                        }
                        else if (token_type_hint == "refresh_token")
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
        //[Authorize]
        public Dictionary<string, string> IntrospectToken(FormDataCollection formData)
        {
            // 戻り値
            // ・正常
            Dictionary<string, string> ret = new Dictionary<string, string>();
            // ・異常
            Dictionary<string, string> err = new Dictionary<string, string>();

            // 変数
            string[] temp = null;
            string token = formData["token"];
            string token_type_hint = formData["token_type_hint"];

            // クライアント認証

            // クライアント識別子
            string authHeader = HttpContext.Current.Request.Headers["Authorization"];

            temp = authHeader.Split(' ');

            if (temp[0].ToLower() == "basic")
            {
                temp = CustomEncode.ByteToString(
                    CustomEncode.FromBase64String(temp[1]), CustomEncode.us_ascii).Split(':');

                string clientId = temp[0];
                string clientSecret = temp[1];

                if (!(string.IsNullOrEmpty(clientId) && string.IsNullOrEmpty(clientSecret)))
                {
                    // *.config or OAuth2Dataテーブルを参照してクライアント認証を行なう。
                    if (clientSecret == OAuth2Helper.GetInstance().GetClientSecret(clientId))
                    {
                        // 検証完了
                        AuthenticationTicket ticket = null;

                        if (token_type_hint == "access_token")
                        {
                            // 検証
                            AccessTokenFormatJwt verifier = new AccessTokenFormatJwt();
                            ticket = verifier.Unprotect(token);

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
                                ret.Add("token_type", token_type_hint);

                                string scopes = "";
                                foreach (Claim claim in ticket.Identity.Claims)
                                {
                                    if (claim.Type.StartsWith(OAuth2AndOIDCConst.Claim_Base))
                                    {
                                        if (claim.Type == OAuth2AndOIDCConst.Claim_Scope)
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
                                ret.Add(OAuth2AndOIDCConst.Claim_Scope.Substring(
                                    OAuth2AndOIDCConst.Claim_Base.Length), scopes.Trim());

                                return ret; // 成功
                            }
                        }
                        else if (token_type_hint == "refresh_token")
                        {
                            // refresh_token参照
                            ticket = RefreshTokenProvider.ReferDirectly(token);

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
                                ret.Add("token_type", token_type_hint);

                                string scopes = "";
                                foreach (Claim claim in ticket.Identity.Claims)
                                {
                                    if (claim.Type.StartsWith(OAuth2AndOIDCConst.Claim_Base))
                                    {
                                        if (claim.Type == OAuth2AndOIDCConst.Claim_Scope)
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
                                ret.Add(OAuth2AndOIDCConst.Claim_Scope.Substring(
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

        #region /OAuthBearerToken2 

        /// <summary>
        /// JWT bearer token authorizationグラント種別のTokenエンドポイント
        /// POST: /OAuthBearerToken2
        /// </summary>
        /// <param name="formData">
        /// grant_type = urn:ietf:params:oauth:grant-type:jwt-bearer
        /// assertion  = jwt_assertion
        /// </param>
        /// <returns>Dictionary(string, string)</returns>
        [HttpPost]
        [Route("OAuthBearerToken2")]
        //[Authorize]
        public Dictionary<string, string> OAuthBearerToken2(FormDataCollection formData)
        {
            // 戻り値
            // ・正常
            Dictionary<string, string> ret = new Dictionary<string, string>();
            // ・異常
            Dictionary<string, string> err = new Dictionary<string, string>();

            // 変数
            string grant_type = formData["grant_type"];
            string assertion = formData["assertion"];

            // クライアント認証
            if (grant_type == OAuth2AndOIDCConst.JwtBearerTokenFlowGrantType)
            {
                Dictionary<string, string> dic = JsonConvert.DeserializeObject<Dictionary<string, string>>(
                    CustomEncode.ByteToString(CustomEncode.FromBase64UrlString(
                        assertion.Split('.')[1]), CustomEncode.us_ascii));

                string pubKey = OAuth2Helper.GetInstance().GetJwtAssertionPublickey(dic["iss"]);
                pubKey = CustomEncode.ByteToString(CustomEncode.FromBase64String(pubKey), CustomEncode.us_ascii);

                if (!string.IsNullOrEmpty(pubKey))
                {
                    string iss = "";
                    string aud = "";
                    string scopes = "";
                    JObject jobj = null;

                    if (JwtAssertion.VerifyJwtBearerTokenFlowAssertion(assertion, out iss, out aud, out scopes, out jobj, pubKey))
                    {
                        // aud 検証
                        if (aud == ASPNETIdentityConfig.OAuthAuthorizationServerEndpointsRootURI
                            + ASPNETIdentityConfig.OAuthBearerTokenEndpoint2)
                        {
                            // ここからは、JwtAssertionではなく、JwtTokenを作るので、属性設定に注意。
                            ClaimsIdentity identity = OAuth2Helper.AddClaim(
                                new ClaimsIdentity(OAuthDefaults.AuthenticationType), iss, "", scopes.Split(' '), "");

                            AuthenticationProperties prop = new AuthenticationProperties();
                            prop.IssuedUtc = DateTimeOffset.UtcNow;
                            prop.ExpiresUtc = DateTimeOffset.Now.Add(ASPNETIdentityConfig.OAuthAccessTokenExpireTimeSpanFromMinutes);

                            // token_type
                            ret.Add("token_type", "bearer");

                            // access_token
                            AccessTokenFormatJwt verifier = new AccessTokenFormatJwt();
                            string access_token = verifier.Protect(new AuthenticationTicket(identity, prop));
                            ret.Add("access_token", access_token);
                            
                            // expires_in
                            jobj = (JObject)JsonConvert.DeserializeObject(
                                CustomEncode.ByteToString(CustomEncode.FromBase64UrlString(
                                    access_token.Split('.')[1]), CustomEncode.us_ascii));
                            ret.Add("expires_in", (long.Parse((string)jobj["exp"]) - long.Parse((string)jobj["iat"])).ToString());

                            // オペレーション・トレース・ログ出力
                            string clientName = OAuth2Helper.GetInstance().GetClientName(iss);
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

        #region Test

        #region Hybrid Flow

        /// <summary>
        /// Hybrid Flowのテスト用エンドポイント
        /// POST: /TestHybridFlow
        /// </summary>
        /// <param name="formData">code</param>
        /// <returns>Dictionary(string, string)</returns>
        [HttpPost]
        [Route("TestHybridFlow")]
        //[Authorize]
        public async Task<Dictionary<string, string>> TestHybridFlow(FormDataCollection formData)
        {
            // 変数
            string code = formData["code"];

            // Tokenエンドポイントにアクセス
            Uri tokenEndpointUri = new Uri(
            ASPNETIdentityConfig.OAuthAuthorizationServerEndpointsRootURI
            + ASPNETIdentityConfig.OAuthBearerTokenEndpoint);

            // 結果を格納する変数。
            Dictionary<string, string> dic = null;

            //  client_Idから、client_secretを取得。
            string client_id = OAuth2Helper.GetInstance().GetClientIdByName("TestClient");
            string client_secret = OAuth2Helper.GetInstance().GetClientSecret(client_id);

            // Hybridは、Implicitのredirect_uriを使用
            string redirect_uri 
                = ASPNETIdentityConfig.OAuthClientEndpointsRootURI
                + ASPNETIdentityConfig.OAuthImplicitGrantClient_Account;

            // Tokenエンドポイントにアクセス
            string response = await OAuth2Helper.GetInstance()
            .GetAccessTokenByCodeAsync(tokenEndpointUri, client_id, client_secret, redirect_uri, code, "");
            dic = JsonConvert.DeserializeObject<Dictionary<string, string>>(response);

            // UserInfoエンドポイントにアクセス
            dic = JsonConvert.DeserializeObject<Dictionary<string, string>>(
                await OAuth2Helper.GetInstance().GetUserInfoAsync(dic["access_token"]));

            return dic;
        }

        #endregion

        #region Chage

        /// <summary>
        /// 課金テスト用エンドポイント
        /// POST: /TestChageToUser
        /// </summary>
        /// <param name="formData">
        /// - currency
        /// - amount
        /// </param>
        /// <returns>string</returns>
        [HttpPost]
        [Route("TestChageToUser")]
        [Authorize]
        public async Task<string> TestChageToUser(FormDataCollection formData)
        {
            // 変数
            string currency = formData["currency"];
            string amount = formData["amount"];

            if (ASPNETIdentityConfig.CanEditPayment
                && ASPNETIdentityConfig.EnableEditingOfUserAttribute
                && ASPNETIdentityConfig.IsDebug)
            {
                // ユーザの検索
                ApplicationUser user = await UserManager.FindByIdAsync(User.Identity.GetUserId());
                // 課金のテスト処理
                JObject jobj = await WebAPIHelper.GetInstance().ChargeToOnlinePaymentCustomersAsync(user.PaymentInformation, currency, amount);

                return "OK";
            }
            else
            {
                return "NG";
            }
        }

        #endregion

        #endregion

        #endregion
    }
}