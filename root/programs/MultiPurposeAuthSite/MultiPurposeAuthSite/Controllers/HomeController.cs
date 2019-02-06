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

using MultiPurposeAuthSite.Co;
using MultiPurposeAuthSite.Extensions.OAuth2;

using System;
using System.Collections.Generic;
using System.Web.Mvc;
using System.Threading.Tasks;
using System.Diagnostics;

using Newtonsoft.Json;
using Newtonsoft.Json.Linq;

using Touryo.Infrastructure.Business.Presentation;
using Touryo.Infrastructure.Framework.Authentication;
using Touryo.Infrastructure.Public.Str;
using Touryo.Infrastructure.Public.FastReflection;
using Touryo.Infrastructure.Public.Security.Pwd;

namespace MultiPurposeAuthSite.Controllers
{
    /// <summary>HomeController</summary>
    [Authorize]
    public class HomeController : MyBaseMVController
    {
        #region Test MVC

        /// <summary>
        /// GET: Home
        /// </summary>
        /// <returns>ActionResult</returns>
        [HttpGet]
        [AllowAnonymous]
        public ActionResult Index()
        {
            return View();
        }

        /// <summary>
        /// GET: Home/Scroll
        /// </summary>
        /// <returns>ActionResult</returns>
        [HttpGet]
        public ActionResult Scroll()
        {
            return View();
        }

        #endregion

        #region Test OAuth2

        #region Params

        /// <summary>認可エンドポイント</summary>
        private string OAuthAuthorizeEndpoint = "";

        /// <summary>client_id</summary>
        private string ClientId = "";

        /// <summary>client_id(fapi1)</summary>
        private string ClientId_1 = "";

        /// <summary>client_id(fapi2)</summary>
        private string ClientId_2 = "";

        /// <summary>state (nonce)</summary>
        private string State = "";

        /// <summary>nonce</summary>
        private string Nonce = "";

        /// <summary>code_verifier</summary>
        private string CodeVerifier = "";

        /// <summary>code_verifier</summary>
        private string CodeChallenge = "";

        #endregion

        #region Common

        #region Init

        /// <summary>初期化</summary>
        private void Init()
        {
            this.OAuthAuthorizeEndpoint =
            Config.OAuth2AuthorizationServerEndpointsRootURI
            + Config.OAuth2AuthorizeEndpoint;

            this.ClientId = Helper.GetInstance().GetClientIdByName("TestClient");
            this.ClientId_1 = Helper.GetInstance().GetClientIdByName("TestClient1");
            this.ClientId_2 = Helper.GetInstance().GetClientIdByName("TestClient2");

            this.State = GetPassword.Generate(10, 0); // 記号は入れない。
            this.Nonce = GetPassword.Generate(20, 0); // 記号は入れない。

            this.CodeVerifier = "";
            this.CodeChallenge = "";
        }

        /// <summary>保存</summary>
        private void Save()
        {
            // テスト用にstate, nonce, code_verifierを、Session, Cookieに保存
            // ・Session : サイト分割時
            // ・Cookie : 同一サイト時

            // state
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

            // nonce
            Session["test_nonce"] = this.Nonce;
            if (Request.Cookies["test_nonce"] == null)
            {
                Response.Cookies["test_nonce"].Value = this.Nonce;
            }
            else
            {
                if (string.IsNullOrEmpty(Request.Cookies["test_nonce"].Value))
                {
                    Response.Cookies["test_nonce"].Value = this.Nonce;
                }
            }

            // code_verifier
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

        #region Assemble

        /// <summary>OAuth2スターターを組み立てて返す</summary>
        /// <param name="response_type">string</param>
        /// <returns>組み立てたOAuth2スターター</returns>
        private string AssembleOAuth2Starter(string response_type)
        {
            return this.OAuthAuthorizeEndpoint +
                string.Format(
                    "?client_id={0}&response_type={1}&scope={2}&state={3}",
                    this.ClientId, response_type, Const.StandardScopes, this.State);
        }

        /// <summary>OIDCスターターを組み立てて返す</summary>
        /// <param name="response_type">string</param>
        /// <returns>組み立てたOIDCスターター</returns>
        private string AssembleOidcStarter(string response_type)
        {
            return this.OAuthAuthorizeEndpoint +
                string.Format(
                    "?client_id={0}&response_type={1}&scope={2}&state={3}",
                    this.ClientId, response_type, Const.OidcScopes, this.State)
                    + "&nonce=" + this.Nonce;
        }

        /// <summary>FAPI1スターターを組み立てて返す</summary>
        /// <param name="response_type">string</param>
        /// <returns>組み立てたFAPI1スターター</returns>
        private string AssembleFAPI1Starter(string response_type)
        {
            return this.OAuthAuthorizeEndpoint +
                string.Format(
                    "?client_id={0}&response_type={1}&scope={2}&state={3}",
                    this.ClientId_1, response_type, Const.StandardScopes,
                    OAuth2AndOIDCEnum.ClientMode.fapi1.ToStringFromEnum() + ":" + this.State);
            // テストコードで、clientを識別するために、Stateに細工する。
        }

        /// <summary>FAPI2スターターを組み立てて返す</summary>
        /// <param name="response_type">string</param>
        /// <returns>組み立てたFAPI2スターター</returns>
        private string AssembleFAPI2Starter(string response_type)
        {
            return this.OAuthAuthorizeEndpoint +
                string.Format(
                    "?client_id={0}&response_type={1}&scope={2}&state={3}",
                    this.ClientId_2, response_type, Const.StandardScopes,
                    OAuth2AndOIDCEnum.ClientMode.fapi2.ToStringFromEnum() + ":" + this.State);
            // テストコードで、clientを識別するために、Stateに細工する。
        }

        #endregion

        #endregion

        #region Action Method

        /// <summary>OAuthStarters</summary>
        /// <returns>ActionResult</returns>
        [HttpGet]
        [AllowAnonymous]
        public ActionResult OAuth2Starters()
        {
            return View();
        }

        #region Authorization Code Flow

        #region OAuth2

        /// <summary>Test Authorization Code Flow</summary>
        /// <returns>ActionResult</returns>
        [HttpGet]
        [AllowAnonymous]
        public ActionResult AuthorizationCode()
        {
            this.Init();
            this.Save();

            // Authorization Code Flow
            return Redirect(this.AssembleOAuth2Starter(
                OAuth2AndOIDCConst.AuthorizationCodeResponseType));
        }

        /// <summary>Test Authorization Code Flow (form_post)</summary>
        /// <returns>ActionResult</returns>
        [HttpGet]
        [AllowAnonymous]
        public ActionResult AuthorizationCode_FormPost()
        {
            this.Init();
            this.Save();

            // Authorization Code Flow (form_post)
            return Redirect(this.AssembleOAuth2Starter(
                OAuth2AndOIDCConst.AuthorizationCodeResponseType)
                + "&response_mode=form_post");
        }

        #endregion

        #region OIDC

        /// <summary>Test Authorization Code Flow (OIDC)</summary>
        /// <returns>ActionResult</returns>
        [HttpGet]
        [AllowAnonymous]
        public ActionResult AuthorizationCode_OIDC()
        {
            this.Init();
            this.Save();

            // Authorization Code Flow (OIDC)
            return Redirect(this.AssembleOidcStarter(
                OAuth2AndOIDCConst.AuthorizationCodeResponseType)
                + "&prompt=none");
        }

        /// <summary>Test Authorization Code Flow (OIDC, form_post)</summary>
        /// <returns>ActionResult</returns>
        [HttpGet]
        [AllowAnonymous]
        public ActionResult AuthorizationCode_OIDC_FormPost()
        {
            this.Init();
            this.Save();

            // Authorization Code Flow (OIDC, form_post)
            return Redirect(this.AssembleOidcStarter(
                OAuth2AndOIDCConst.AuthorizationCodeResponseType)
                + "&prompt=none"
                + "&response_mode=form_post");
        }

        #endregion

        #region PKCE(FAPI1)

        /// <summary>Test Authorization Code Flow (PKCE plain)</summary>
        /// <returns>ActionResult</returns>
        [HttpGet]
        [AllowAnonymous]
        public ActionResult AuthorizationCode_PKCE_Plain()
        {
            this.Init();
            this.CodeVerifier = GetPassword.Base64UrlSecret(50);
            this.CodeChallenge = this.CodeVerifier;
            this.Save();

            // Authorization Code Flow (PKCE plain)
            return Redirect(this.AssembleOAuth2Starter(
                OAuth2AndOIDCConst.AuthorizationCodeResponseType)
                + "&code_challenge=" + this.CodeChallenge
                + "&code_challenge_method=" + OAuth2AndOIDCConst.PKCE_plain);
        }

        /// <summary>Test Authorization Code Flow (PKCE S256)</summary>
        /// <returns>ActionResult</returns>
        [HttpGet]
        [AllowAnonymous]
        public ActionResult AuthorizationCode_PKCE_S256()
        {
            this.Init();
            this.CodeVerifier = GetPassword.Base64UrlSecret(50);
            this.CodeChallenge = OAuth2AndOIDCClient.PKCE_S256_CodeChallengeMethod(this.CodeVerifier);
            this.Save();

            // Authorization Code Flow (PKCE S256)
            return Redirect(this.AssembleOAuth2Starter(
                OAuth2AndOIDCConst.AuthorizationCodeResponseType)
                + "&code_challenge=" + this.CodeChallenge
                + "&code_challenge_method=" + OAuth2AndOIDCConst.PKCE_S256);
        }

        #endregion

        #endregion

        #region Implicit Flow

        #region OAuth2

        /// <summary>Test Implicit Flow</summary>
        /// <returns>ActionResult</returns>
        [HttpGet]
        [AllowAnonymous]
        public ActionResult Implicit()
        {
            this.Init();
            this.Save();

            // Implicit Flow
            return Redirect(this.AssembleOAuth2Starter(
                OAuth2AndOIDCConst.ImplicitResponseType));
        }

        #endregion

        #region OIDC

        /// <summary>Test Implicit Flow 'id_token'(OIDC)</summary>
        /// <returns>ActionResult</returns>
        [HttpGet]
        [AllowAnonymous]
        public ActionResult Implicit_OIDC1()
        {
            this.Init();
            this.Save();

            // Implicit Flow 'id_token'(OIDC)
            return Redirect(this.AssembleOidcStarter(
                OAuth2AndOIDCConst.OidcImplicit1_ResponseType));
        }


        /// <summary>Test Implicit Flow 'id_token token'(OIDC)</summary>
        /// <returns>ActionResult</returns>
        [HttpGet]
        [AllowAnonymous]
        public ActionResult Implicit_OIDC2()
        {
            this.Init();
            this.Save();

            // Implicit Flow 'id_token token'(OIDC)
            return Redirect(this.AssembleOidcStarter(
                OAuth2AndOIDCConst.OidcImplicit2_ResponseType));
        }

        #endregion

        #endregion

        #region Hybrid Flow

        #region OIDC

        /// <summary>Test Hybrid Flow 'code id_token'(OIDC)</summary>
        /// <returns>ActionResult</returns>
        [HttpGet]
        [AllowAnonymous]
        public ActionResult Hybrid_OIDC1()
        {
            this.Init();
            this.Save();

            // Hybrid Flow 'code id_token'(OIDC)
            return Redirect(this.AssembleOidcStarter(
                OAuth2AndOIDCConst.OidcHybrid2_IdToken_ResponseType));
        }

        /// <summary>Test Hybrid Flow 'code token'(OIDC)</summary>
        /// <returns>ActionResult</returns>
        [HttpGet]
        [AllowAnonymous]
        public ActionResult Hybrid_OIDC2()
        {
            this.Init();
            this.Save();

            // Hybrid Flow 'code token'(OIDC)
            return Redirect(this.AssembleOidcStarter(
                OAuth2AndOIDCConst.OidcHybrid2_Token_ResponseType));
        }

        /// <summary>Test Hybrid Flow 'code id_token token'(OIDC)</summary>
        /// <returns>ActionResult</returns>
        [HttpGet]
        [AllowAnonymous]
        public ActionResult Hybrid_OIDC3()
        {
            this.Init();
            this.Save();

            // Hybrid Flow 'code id_token token'(OIDC)
            return Redirect(this.AssembleOidcStarter(
                OAuth2AndOIDCConst.OidcHybrid3_ResponseType));
        }

        #endregion

        #region FAPI2

        #endregion

        #endregion

        #region Financial-grade API

        #region FAPI1

        /// <summary>Test Authorization Code Flow (FAPI1)</summary>
        /// <returns>ActionResult</returns>
        [HttpGet]
        [AllowAnonymous]
        public ActionResult FAPI1AuthorizationCode()
        {
            this.Init();
            this.Save();

            // Authorization Code Flow
            return Redirect(this.AssembleFAPI1Starter(
                OAuth2AndOIDCConst.AuthorizationCodeResponseType));
        }

        #endregion

        #region FAPI2

        /// <summary>Test Authorization Code Flow (FAPI2)</summary>
        /// <returns>ActionResult</returns>
        [HttpGet]
        [AllowAnonymous]
        public ActionResult FAPI2AuthorizationCode()
        {
            this.Init();
            this.Save();

            // Authorization Code Flow
            return Redirect(this.AssembleFAPI2Starter(
                OAuth2AndOIDCConst.AuthorizationCodeResponseType));
        }

        #endregion

        #endregion

        #region Another Flow

        #region Resource Owner Password Credentials Flow

        /// <summary>TestResourceOwnerPasswordCredentialsFlow</summary>
        /// <returns>ActionResult</returns>
        [HttpGet]
        [AllowAnonymous]
        public async Task<ActionResult> TestResourceOwnerPasswordCredentialsFlow()
        {
            // Tokenエンドポイントにアクセス
            string aud = Config.OAuth2AuthorizationServerEndpointsRootURI + Config.OAuth2TokenEndpoint;

            // ClientNameから、client_id, client_secretを取得。
            string client_id = "";
            string client_secret = "";

            client_id = Helper.GetInstance().GetClientIdByName("TestClient");
            client_secret = Helper.GetInstance().GetClientSecret(client_id);

            string response = await Helper.GetInstance()
                .ResourceOwnerPasswordCredentialsGrantAsync(new Uri(
                    Config.OAuth2AuthorizationServerEndpointsRootURI + Config.OAuth2TokenEndpoint),
                    client_id, client_secret, Config.AdministratorUID, Config.AdministratorPWD, Const.StandardScopes);

            ViewBag.Response = response;
            ViewBag.AccessToken = ((JObject)JsonConvert.DeserializeObject(response))[OAuth2AndOIDCConst.AccessToken];

            return View("OAuth2ClientAuthenticationFlow");
        }

        #endregion

        #region Client Credentials Flow

        /// <summary>TestClientCredentialsFlow</summary>
        /// <returns>ActionResult</returns>
        [HttpGet]
        [AllowAnonymous]
        public async Task<ActionResult> TestClientCredentialsFlow()
        {
            // Tokenエンドポイントにアクセス
            string aud = Config.OAuth2AuthorizationServerEndpointsRootURI + Config.OAuth2TokenEndpoint;

            // ClientNameから、client_id, client_secretを取得。
            string client_id = "";
            string client_secret = "";

            if (User.Identity.IsAuthenticated)
            {
                // User Accountの場合、
                client_id = Helper.GetInstance().GetClientIdByName(User.Identity.Name);
                client_secret = Helper.GetInstance().GetClientSecret(client_id);
            }
            else
            {
                // Client Accountの場合、
                client_id = Helper.GetInstance().GetClientIdByName("TestClient");
                client_secret = Helper.GetInstance().GetClientSecret(client_id);
            }

            string response = await Helper.GetInstance()
                .ClientCredentialsGrantAsync(new Uri(
                    Config.OAuth2AuthorizationServerEndpointsRootURI + Config.OAuth2TokenEndpoint),
                    client_id, client_secret, Const.StandardScopes);

            ViewBag.Response = response;
            ViewBag.AccessToken = ((JObject)JsonConvert.DeserializeObject(response))[OAuth2AndOIDCConst.AccessToken];

            return View("OAuth2ClientAuthenticationFlow");
        }

        #endregion

        #region JWT Bearer Token Flow

        /// <summary>TestJWTBearerTokenFlow</summary>
        /// <returns>ActionResult</returns>
        [HttpGet]
        [AllowAnonymous]
        public async Task<ActionResult> TestJWTBearerTokenFlow()
        {
            // Tokenエンドポイントにアクセス
            string aud = Config.OAuth2AuthorizationServerEndpointsRootURI + Config.OAuth2TokenEndpoint;

            // ClientNameから、client_id(iss)を取得。
            string iss = "";

            if (User.Identity.IsAuthenticated)
            {
                // User Accountの場合、
                iss = Helper.GetInstance().GetClientIdByName(User.Identity.Name);
            }
            else
            {
                // Client Accountの場合、
                iss = Helper.GetInstance().GetClientIdByName("TestClient");
            }

            // テストなので秘密鍵は共通とする。
            string privateKey = OAuth2AndOIDCParams.OAuth2JwtAssertionPrivatekey;
            privateKey = CustomEncode.ByteToString(CustomEncode.FromBase64UrlString(privateKey), CustomEncode.us_ascii);

            string response = await Helper.GetInstance().JwtBearerTokenFlowAsync(
                new Uri(Config.OAuth2AuthorizationServerEndpointsRootURI + Config.OAuth2TokenEndpoint),
                JwtAssertion.CreateJwtBearerTokenFlowAssertionJWK(iss, aud,
                Config.OAuth2AccessTokenExpireTimeSpanFromMinutes, Const.StandardScopes, privateKey));

            ViewBag.Response = response;
            ViewBag.AccessToken = ((JObject)JsonConvert.DeserializeObject(response))[OAuth2AndOIDCConst.AccessToken];

            return View("OAuth2ClientAuthenticationFlow");
        }

        #endregion

        #endregion

        #endregion

        #endregion
    }
}