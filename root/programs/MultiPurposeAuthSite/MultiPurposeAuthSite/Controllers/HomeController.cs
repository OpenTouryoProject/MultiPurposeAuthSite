//**********************************************************************************
//* テンプレート
//**********************************************************************************

// 以下のLicenseに従い、このProjectをTemplateとして使用可能です。Release時にCopyright表示してSublicenseして下さい。
// https://github.com/OpenTouryoProject/MultiPurposeAuthSite/blob/master/license/LicenseForTemplates.txt

//**********************************************************************************
//* クラス名        ：HomeController
//* クラス日本語名  ：HomeController
//*
//* 作成日時        ：－
//* 作成者          ：生技
//* 更新履歴        ：
//*
//*  日時        更新者            内容
//*  ----------  ----------------  -------------------------------------------------
//*  2017/04/24  西野 大介         新規
//**********************************************************************************

using MultiPurposeAuthSite.Models.ASPNETIdentity;
using MultiPurposeAuthSite.Models.ASPNETIdentity.OAuth2Extension;

using System;
using System.Collections.Generic;
using System.Web.Mvc;
using System.Threading.Tasks;
using System.Diagnostics;

using Newtonsoft.Json;
using Newtonsoft.Json.Linq;

using Touryo.Infrastructure.Business.Presentation;
using Touryo.Infrastructure.Framework.Authentication;
using Touryo.Infrastructure.Public.Security;
using Touryo.Infrastructure.Public.Str;
using Touryo.Infrastructure.Public.Util;

namespace MultiPurposeAuthSite.Controllers
{
    /// <summary>HomeController</summary>
    public class HomeController : MyBaseMVController
    {
        #region Action Method

        /// <summary>
        /// GET: Home
        /// </summary>
        /// <returns>ActionResult</returns>
        [HttpGet]
        public ActionResult Index()
        {
            return View();
        }

        #endregion

        #region Test OAuth2

        #region Common

        /// <summary>認可エンドポイント</summary>
        private string OAuthAuthorizeEndpoint = "";

        /// <summary>client_id</summary>
        private string ClientId = "";

        /// <summary>state (nonce)</summary>
        private string State = "";

        /// <summary>nonce</summary>
        private string Nonce = "";

        /// <summary>code_verifier</summary>
        private string CodeVerifier = "";

        /// <summary>code_verifier</summary>
        private string CodeChallenge = "";

        /// <summary>OAuth2スターターを組み立てて返す</summary>
        /// <param name="response_type">string</param>
        /// <returns>組み立てたOAuth2スターター</returns>
        private string AssembleOAuth2Starter(string response_type)
        {
            return this.OAuthAuthorizeEndpoint +
                string.Format(
                    "?client_id={0}&response_type={1}&scope={2}&state={3}",
                    this.ClientId, response_type, ASPNETIdentityConst.StandardScopes, this.State);
        }

        /// <summary>OIDCスターターを組み立てて返す</summary>
        /// <param name="response_type">string</param>
        /// <returns>組み立てたOIDCスターター</returns>
        private string AssembleOidcStarter(string response_type)
        {
            return this.OAuthAuthorizeEndpoint +
                string.Format(
                    "?client_id={0}&response_type={1}&scope={2}&state={3}",
                    this.ClientId, response_type, ASPNETIdentityConst.OidcScopes, this.State)
                    + "&nonce=" + this.Nonce;
        }

        /// <summary>初期化</summary>
        private void Init()
        {
            this.OAuthAuthorizeEndpoint =
            ASPNETIdentityConfig.OAuthAuthorizationServerEndpointsRootURI
            + ASPNETIdentityConfig.OAuthAuthorizeEndpoint;

            this.ClientId = OAuth2Helper.GetInstance().GetClientIdByName("TestClient");
            this.State = GetPassword.Generate(10, 0); // 記号は入れない。
            this.Nonce = GetPassword.Generate(20, 0); // 記号は入れない。

            this.CodeVerifier = "";
            this.CodeChallenge = "";
        }

        /// <summary>保存</summary>
        private void Save()
        {
            // テスト用にstate, code_verifierを、Session, Cookieに保存
            // ・Session : サイト分割時
            // ・Cookie : 同一サイト時

            Session["test_state"] = this.State;
            if (Request.Cookies["test_state"] == null)
            {
                Response.Cookies["test_state"].Value = this.State;
            }
            else
            {
                if (string.IsNullOrEmpty(Request.Cookies["test_state"].Value))
                {
                    Response.Cookies["test_state"].Value = this.State;
                }
            }

            Session["test_code_verifier"] = this.CodeVerifier;
            if (Request.Cookies["test_code_verifier"] == null)
            {
                Response.Cookies["test_code_verifier"].Value = this.CodeVerifier;
            }
            else
            {
                if (string.IsNullOrEmpty(Request.Cookies["test_code_verifier"].Value))
                {
                    Response.Cookies["test_code_verifier"].Value = this.CodeVerifier;
                }
            }
        }

        #endregion

        #region Action Method

        /// <summary>OAuthStarters</summary>
        /// <returns>ActionResult</returns>
        [HttpGet]
        public ActionResult OAuthStarters()
        {
            return View();
        }

        #region Authorization Code Flow

        #region OAuth2

        /// <summary>Test Authorization Code Flow</summary>
        /// <returns>ActionResult</returns>
        [HttpGet]
        public ActionResult AuthorizationCode()
        {
            this.Init();
            this.Save();

            // Authorization Code Flow
            return Redirect(this.AssembleOAuth2Starter(
                ASPNETIdentityConst.AuthorizationCodeResponseType));
        }

        /// <summary>Test Authorization Code Flow (form_post)</summary>
        /// <returns>ActionResult</returns>
        [HttpGet]
        public ActionResult AuthorizationCode_FormPost()
        {
            this.Init();
            this.Save();

            // Authorization Code Flow (form_post)
            return Redirect(this.AssembleOAuth2Starter(
                ASPNETIdentityConst.AuthorizationCodeResponseType)
                + "&response_mode=form_post");
        }

        #endregion

        #region OIDC

        /// <summary>Test Authorization Code Flow (OIDC)</summary>
        /// <returns>ActionResult</returns>
        [HttpGet]
        public ActionResult AuthorizationCode_OIDC()
        {
            this.Init();
            this.Save();

            // Authorization Code Flow (OIDC)
            return Redirect(this.AssembleOidcStarter(
                ASPNETIdentityConst.AuthorizationCodeResponseType)
                + "&prompt=none");
        }

        /// <summary>Test Authorization Code Flow (OIDC, form_post)</summary>
        /// <returns>ActionResult</returns>
        [HttpGet]
        public ActionResult AuthorizationCode_OIDC_FormPost()
        {
            this.Init();
            this.Save();

            // Authorization Code Flow (OIDC, form_post)
            return Redirect(this.AssembleOidcStarter(
                ASPNETIdentityConst.AuthorizationCodeResponseType)
                + "&prompt=none"
                + "&response_mode=form_post");
        }

        #endregion

        #region PKCE

        /// <summary>Test Authorization Code Flow (PKCE plain)</summary>
        /// <returns>ActionResult</returns>
        [HttpGet]
        public ActionResult AuthorizationCode_PKCE_Plain()
        {
            this.Init();
            this.CodeVerifier = GetPassword.Base64UrlSecret(50);
            this.CodeChallenge = this.CodeVerifier;
            this.Save();

            // Authorization Code Flow (PKCE plain)
            return Redirect(this.AssembleOAuth2Starter(
                ASPNETIdentityConst.AuthorizationCodeResponseType)
                + "&code_challenge=" + this.CodeChallenge
                + "&code_challenge_method=plain");
        }

        /// <summary>Test Authorization Code Flow (PKCE S256)</summary>
        /// <returns>ActionResult</returns>
        [HttpGet]
        public ActionResult AuthorizationCode_PKCE_S256()
        {
            this.Init();
            this.CodeVerifier = GetPassword.Base64UrlSecret(50);
            this.CodeChallenge = OAuth2Helper.PKCE_S256_CodeChallengeMethod(this.CodeVerifier);
            this.Save();

            // Authorization Code Flow (PKCE S256)
            return Redirect(this.AssembleOAuth2Starter(
                ASPNETIdentityConst.AuthorizationCodeResponseType)
                + "&code_challenge=" + this.CodeChallenge
                + "&code_challenge_method=S256");
        }

        #endregion

        #endregion

        #region Implicit Flow

        #region OAuth2

        /// <summary>Test Implicit Flow</summary>
        /// <returns>ActionResult</returns>
        [HttpGet]
        public ActionResult Implicit()
        {
            this.Init();
            this.Save();

            // Implicit Flow
            return Redirect(this.AssembleOAuth2Starter(
                ASPNETIdentityConst.ImplicitResponseType));
        }

        #endregion

        #region OIDC

        /// <summary>Test Implicit Flow 'id_token'(OIDC)</summary>
        /// <returns>ActionResult</returns>
        [HttpGet]
        public ActionResult Implicit_OIDC1()
        {
            this.Init();
            this.Save();

            // Implicit Flow 'id_token'(OIDC)
            return Redirect(this.AssembleOidcStarter(
                ASPNETIdentityConst.ImplicitResponseType));
        }


        /// <summary>Test Implicit Flow 'id_token token'(OIDC)</summary>
        /// <returns>ActionResult</returns>
        [HttpGet]
        public ActionResult Implicit_OIDC2()
        {
            this.Init();
            this.Save();

            // Implicit Flow 'id_token token'(OIDC)
            return Redirect(this.AssembleOidcStarter(
                ASPNETIdentityConst.OidcImplicit2_ResponseType));
        }

        #endregion

        #endregion

        #region Hybrid Flow

        #region OIDC

        /// <summary>Test Hybrid Flow 'code id_token'(OIDC)</summary>
        /// <returns>ActionResult</returns>
        [HttpGet]
        public ActionResult Hybrid_OIDC1()
        {
            this.Init();
            this.Save();

            // Hybrid Flow 'code id_token'(OIDC)
            return Redirect(this.AssembleOidcStarter(
                ASPNETIdentityConst.OidcHybrid2_IdToken_ResponseType));
        }

        /// <summary>Test Hybrid Flow 'code token'(OIDC)</summary>
        /// <returns>ActionResult</returns>
        [HttpGet]
        public ActionResult Hybrid_OIDC2()
        {
            this.Init();
            this.Save();

            // Hybrid Flow 'code token'(OIDC)
            return Redirect(this.AssembleOidcStarter(
                ASPNETIdentityConst.OidcHybrid2_Token_ResponseType));
        }

        /// <summary>Test Hybrid Flow 'code id_token token'(OIDC)</summary>
        /// <returns>ActionResult</returns>
        [HttpGet]
        public ActionResult Hybrid_OIDC3()
        {
            this.Init();
            this.Save();

            // Hybrid Flow 'code id_token token'(OIDC)
            return Redirect(this.AssembleOidcStarter(
                ASPNETIdentityConst.OidcHybrid3_ResponseType));
        }

        #endregion

        #endregion

        #region Client Authentication Flow

        #region Client Credentials Flow

        /// <summary>TestClientCredentialsFlow</summary>
        /// <returns>ActionResult</returns>
        [HttpGet]
        public async Task<ActionResult> TestClientCredentialsFlow()
        {
            // Tokenエンドポイントにアクセス
            string aud = ASPNETIdentityConfig.OAuthAuthorizationServerEndpointsRootURI
                     + ASPNETIdentityConfig.OAuthBearerTokenEndpoint;

            // ClientNameから、client_id, client_secretを取得。
            string client_id = "";
            string client_secret = "";

            if (User.Identity.IsAuthenticated)
            {
                // User Accountの場合、
                client_id = OAuth2Helper.GetInstance().GetClientIdByName(User.Identity.Name);
                client_secret = OAuth2Helper.GetInstance().GetClientSecret(client_id);
            }
            else
            {
                // Client Accountの場合、
                client_id = OAuth2Helper.GetInstance().GetClientIdByName("TestClient");
                client_secret = OAuth2Helper.GetInstance().GetClientSecret(client_id);
            }

            string response = await OAuth2Helper.GetInstance()
                .ClientCredentialsFlowAsync(new Uri(
                    ASPNETIdentityConfig.OAuthAuthorizationServerEndpointsRootURI
                     + ASPNETIdentityConfig.OAuthBearerTokenEndpoint),
                     client_id, client_secret, ASPNETIdentityConst.StandardScopes);

            ViewBag.Response = response;
            ViewBag.AccessToken = ((JObject)JsonConvert.DeserializeObject(response))["access_token"];

            return View("OAuthClientAuthenticationFlow");
        }

        #endregion

        #region JWT Bearer Token Flow

        /// <summary>TestJWTBearerTokenFlow</summary>
        /// <returns>ActionResult</returns>
        [HttpGet]
        public async Task<ActionResult> TestJWTBearerTokenFlow()
        {
            // Token2エンドポイントにアクセス
            string aud = ASPNETIdentityConfig.OAuthAuthorizationServerEndpointsRootURI
                     + ASPNETIdentityConfig.OAuthBearerTokenEndpoint2;

            // ClientNameから、client_id(iss)を取得。
            string iss = "";

            if (User.Identity.IsAuthenticated)
            {
                // User Accountの場合、
                iss = OAuth2Helper.GetInstance().GetClientIdByName(User.Identity.Name);
            }
            else
            {
                // Client Accountの場合、
                iss = OAuth2Helper.GetInstance().GetClientIdByName("TestClient");
            }

            // テストなので秘密鍵は共通とする。
            string privateKey = GetConfigParameter.GetConfigValue("OAuth2JwtAssertionPrivatekey");
            privateKey = CustomEncode.ByteToString(CustomEncode.FromBase64String(privateKey), CustomEncode.us_ascii);

            string response = await OAuth2Helper.GetInstance()
                .JwtBearerTokenFlowAsync(new Uri(
                    ASPNETIdentityConfig.OAuthAuthorizationServerEndpointsRootURI
                     + ASPNETIdentityConfig.OAuthBearerTokenEndpoint2),
                     JwtAssertion.CreateJwtBearerTokenFlowAssertion(
                         iss, aud, new TimeSpan(0, 0, 30), ASPNETIdentityConst.StandardScopes, privateKey));

            ViewBag.Response = response;
            ViewBag.AccessToken = ((JObject)JsonConvert.DeserializeObject(response))["access_token"];

            return View("OAuthClientAuthenticationFlow");
        }

        #endregion

        #endregion

        #endregion

        #endregion
    }
}