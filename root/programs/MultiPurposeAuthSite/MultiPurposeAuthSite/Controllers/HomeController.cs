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
//*  2019/02/08  西野 大介         OAuth2Starters改造
//*  2019/02/18  西野 大介         FAPI2 CC対応実施
//**********************************************************************************

using MultiPurposeAuthSite.Co;
using MultiPurposeAuthSite.Entity;
using MultiPurposeAuthSite.Manager;
using MultiPurposeAuthSite.ViewModels;
using MultiPurposeAuthSite.Extensions.OAuth2;

using System;
using System.Web;
using System.Web.Mvc;
using System.Net.Http;
using System.Threading.Tasks;
using System.Security.Cryptography;

using Microsoft.Owin.Security;
using Microsoft.AspNet.Identity;
using Microsoft.AspNet.Identity.Owin;

using Newtonsoft.Json;
using Newtonsoft.Json.Linq;

using Touryo.Infrastructure.Business.Presentation;
using Touryo.Infrastructure.Framework.Authentication;
using Touryo.Infrastructure.Public.Str;
using Touryo.Infrastructure.Public.Security;
using Touryo.Infrastructure.Public.Security.Pwd;
using Touryo.Infrastructure.Public.FastReflection;

namespace MultiPurposeAuthSite.Controllers
{
    /// <summary>HomeController</summary>
    [Authorize]
    public class HomeController : MyBaseMVController
    {
        #region constructor

        /// <summary>constructor</summary>
        public HomeController() { }

        #endregion

        #region property

        #region GetOwinContext

        /// <summary>ApplicationUserManager</summary>
        private ApplicationUserManager UserManager
        {
            get
            {
                return HttpContext.GetOwinContext().GetUserManager<ApplicationUserManager>();
            }
        }

        /// <summary>ApplicationRoleManager</summary>
        private ApplicationRoleManager RoleManager
        {
            get
            {
                return HttpContext.GetOwinContext().GetUserManager<ApplicationRoleManager>();
            }
        }

        /// <summary>ApplicationSignInManager</summary>
        private ApplicationSignInManager SignInManager
        {
            get
            {
                return HttpContext.GetOwinContext().Get<ApplicationSignInManager>();
            }
        }

        /// <summary>AuthenticationManager</summary>
        private IAuthenticationManager AuthenticationManager
        {
            get
            {
                return HttpContext.GetOwinContext().Authentication;
            }
        }

        #endregion

        #endregion

        #region Test MVC

        #region Action Method

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

        #endregion

        #region WebAuthn

        /// <summary>
        /// GET: Home/WebAuthnStarters
        /// </summary>
        /// <returns>ActionResult</returns>
        [HttpGet]
        [AllowAnonymous]
        public ActionResult WebAuthnStarters()
        {
            return View();
        }

        #endregion

        #region OAuth2

        #region Params

        /// <summary>認可エンドポイント</summary>
        private string OAuthAuthorizeEndpoint = "";

        /// <summary>ClientName</summary>
        private string ClientName = "";

        /// <summary>ClientId</summary>
        private string ClientId = "";

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

            this.ClientId = Helper.GetInstance().GetClientIdByName(this.ClientName);

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

            // client_id
            Session["test_client_id"] = this.ClientId;
            if (Request.Cookies["test_client_id"] == null)
            {
                Response.Cookies["test_client_id"].Value = this.ClientId;
            }
            else
            {
                if (string.IsNullOrEmpty(Request.Cookies["test_client_id"].Value))
                {
                    Response.Cookies["test_client_id"].Value = this.ClientId;
                }
            }

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
                    this.ClientId, response_type, Const.StandardScopes,
                    OAuth2AndOIDCEnum.ClientMode.fapi1.ToStringByEmit() + ":" + this.State);
            // テストコードで、clientを識別するために、Stateに細工する。
        }

        /// <summary>FAPI1 + OIDCSスターターを組み立てて返す</summary>
        /// <param name="response_type">string</param>
        /// <returns>組み立てたFAPI1スターター</returns>
        private string AssembleFAPI1_OIDCStarter(string response_type)
        {
            return this.OAuthAuthorizeEndpoint +
                string.Format(
                    "?client_id={0}&response_type={1}&scope={2}&state={3}",
                    this.ClientId, response_type, Const.OidcScopes,
                    OAuth2AndOIDCEnum.ClientMode.fapi1.ToStringByEmit() + ":" + this.State)
                    + "&nonce=" + this.Nonce;
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
                    this.ClientId, response_type, Const.OidcScopes,
                    OAuth2AndOIDCEnum.ClientMode.fapi2.ToStringByEmit() + ":" + this.State)
                    + "&nonce=" + this.Nonce;
            // テストコードで、clientを識別するために、Stateに細工する。
        }

        #endregion

        #endregion

        #region Action Method

        #region Public

        /// <summary>
        /// OAuthStarters画面（初期表示）
        /// GET: /Home/OAuth2Starters
        /// </summary>
        /// <returns>ActionResult</returns>
        [HttpGet]
        [AllowAnonymous]
        public ActionResult OAuth2Starters()
        {
            if (Config.IsLockedDownRedirectEndpoint)
            {
                return View("Index");
            }
            else
            {
                return View(new HomeOAuth2StartersViewModel()); 
            }
        }

        /// <summary>
        /// OAuthStarters画面
        /// POST: /Home/OAuth2Starters
        /// </summary>
        /// <returns>ActionResult</returns>
        [HttpPost]
        [AllowAnonymous]
        public async Task<ActionResult> OAuth2Starters(HomeOAuth2StartersViewModel model)
        {
            if (Config.IsLockedDownRedirectEndpoint)
            {
                return View("Index");
            }
            else
            {
                // AccountLoginViewModelの検証
                if (ModelState.IsValid)
                {
                    #region Client選択
                    if (model.ClientType == OAuth2AndOIDCEnum.ClientMode.normal.ToStringByEmit())
                    {
                        // OAuth2.0 / OIDC用 Client
                        this.ClientName = "TestClient";
                    }
                    else if(model.ClientType == OAuth2AndOIDCEnum.ClientMode.fapi1.ToStringByEmit())
                    {
                        // Financial-grade API - Part1用 Client
                        this.ClientName = "TestClient1";
                    }
                    else if (model.ClientType == OAuth2AndOIDCEnum.ClientMode.fapi2.ToStringByEmit())
                    {
                        // Financial-grade API - Part2用 Client
                        this.ClientName = "TestClient2";
                    }
                    else
                    {
                        // ログイン・ユーザの Client
                        if (User.Identity.IsAuthenticated)
                        {
                            // ユーザの取得
                            ApplicationUser user = await UserManager.FindByIdAsync(User.Identity.GetUserId());
                            this.ClientName = user.UserName;
                        }
                    }
                    #endregion
                }

                if (!string.IsNullOrEmpty(this.ClientName))
                {
                    #region Starter

                    #region AuthorizationCode系
                    if (!string.IsNullOrEmpty(Request.Form.Get("submit.AuthorizationCode")))
                    {
                        return this.AuthorizationCode();
                    }
                    else if (!string.IsNullOrEmpty(Request.Form.Get("submit.AuthorizationCode_FormPost")))
                    {
                        return this.AuthorizationCode_FormPost();
                    }
                    else if (!string.IsNullOrEmpty(Request.Form.Get("submit.AuthorizationCode_OIDC")))
                    {
                        return this.AuthorizationCode_OIDC();
                    }
                    else if (!string.IsNullOrEmpty(Request.Form.Get("submit.AuthorizationCode_OIDC_FormPost")))
                    {
                        return this.AuthorizationCode_OIDC_FormPost();
                    }
                    else if (!string.IsNullOrEmpty(Request.Form.Get("submit.AuthorizationCode_PKCE_Plain")))
                    {
                        return this.AuthorizationCode_PKCE_Plain();
                    }
                    else if (!string.IsNullOrEmpty(Request.Form.Get("submit.AuthorizationCode_PKCE_S256")))
                    {
                        return this.AuthorizationCode_PKCE_S256();
                    }
                    #endregion

                    #region Implicit系
                    if (!string.IsNullOrEmpty(Request.Form.Get("submit.Implicit")))
                    {
                        return this.Implicit();
                    }
                    else if (!string.IsNullOrEmpty(Request.Form.Get("submit.Implicit_OIDC1")))
                    {
                        return this.Implicit_OIDC1();
                    }
                    else if (!string.IsNullOrEmpty(Request.Form.Get("submit.Implicit_OIDC2")))
                    {
                        return this.Implicit_OIDC2();
                    }
                    #endregion

                    #region Hybrid系
                    if (!string.IsNullOrEmpty(Request.Form.Get("submit.Hybrid_OIDC1")))
                    {
                        return this.Hybrid_OIDC1();
                    }
                    else if (!string.IsNullOrEmpty(Request.Form.Get("submit.Hybrid_OIDC2")))
                    {
                        return this.Hybrid_OIDC2();
                    }
                    else if (!string.IsNullOrEmpty(Request.Form.Get("submit.Hybrid_OIDC3")))
                    {
                        return this.Hybrid_OIDC3();
                    }
                    #endregion

                    #region F-API系
                    if (!string.IsNullOrEmpty(Request.Form.Get("submit.AuthorizationCodeFAPI1")))
                    {
                        return this.AuthorizationCodeFAPI1();
                    }
                    else if (!string.IsNullOrEmpty(Request.Form.Get("submit.AuthorizationCodeFAPI1_OIDC")))
                    {
                        return this.AuthorizationCodeFAPI1_OIDC();
                    }
                    else if (!string.IsNullOrEmpty(Request.Form.Get("submit.AuthorizationCodeFAPI1_OIDC_FormPost")))
                    {
                        return this.AuthorizationCodeFAPI1_OIDC_FormPost();
                    }
                    else if (!string.IsNullOrEmpty(Request.Form.Get("submit.AuthorizationCodeFAPI2")))
                    {
                        return this.AuthorizationCodeFAPI2();
                    }
                    #endregion

                    #region Another系
                    if (!string.IsNullOrEmpty(Request.Form.Get("submit.TestResourceOwnerPasswordCredentialsFlow")))
                    {
                        return await this.TestResourceOwnerPasswordCredentialsFlow();
                    }
                    else if (!string.IsNullOrEmpty(Request.Form.Get("submit.TestClientCredentialsFlow")))
                    {
                        return await this.TestClientCredentialsFlow();
                    }
                    else if (!string.IsNullOrEmpty(Request.Form.Get("submit.TestJWTBearerTokenFlow")))
                    {
                        return await this.TestJWTBearerTokenFlow();
                    }
                    #endregion

                    #endregion
                }

                // 再表示
                return View(model);
            }
        }

        #endregion

        #region Private

        #region Authorization Code Flow

        #region OAuth2

        /// <summary>Test Authorization Code Flow</summary>
        /// <returns>ActionResult</returns>
        private ActionResult AuthorizationCode()
        {
            this.Init();
            this.Save();

            // Authorization Code Flow
            return Redirect(this.AssembleOAuth2Starter(
                OAuth2AndOIDCConst.AuthorizationCodeResponseType));
        }

        /// <summary>Test Authorization Code Flow (form_post)</summary>
        /// <returns>ActionResult</returns>
        private ActionResult AuthorizationCode_FormPost()
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
        private ActionResult AuthorizationCode_OIDC()
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
        private ActionResult AuthorizationCode_OIDC_FormPost()
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

        #region PKCE

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
        private ActionResult AuthorizationCode_PKCE_S256()
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
        private ActionResult Implicit()
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
        private ActionResult Implicit_OIDC1()
        {
            this.Init();
            this.Save();

            // Implicit Flow 'id_token'(OIDC)
            return Redirect(this.AssembleOidcStarter(
                OAuth2AndOIDCConst.OidcImplicit1_ResponseType));
        }


        /// <summary>Test Implicit Flow 'id_token token'(OIDC)</summary>
        /// <returns>ActionResult</returns>
        private ActionResult Implicit_OIDC2()
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
        private ActionResult Hybrid_OIDC1()
        {
            this.Init();
            this.Save();

            // Hybrid Flow 'code id_token'(OIDC)
            return Redirect(this.AssembleOidcStarter(
                OAuth2AndOIDCConst.OidcHybrid2_IdToken_ResponseType));
        }

        /// <summary>Test Hybrid Flow 'code token'(OIDC)</summary>
        /// <returns>ActionResult</returns>
        private ActionResult Hybrid_OIDC2()
        {
            this.Init();
            this.Save();

            // Hybrid Flow 'code token'(OIDC)
            return Redirect(this.AssembleOidcStarter(
                OAuth2AndOIDCConst.OidcHybrid2_Token_ResponseType));
        }

        /// <summary>Test Hybrid Flow 'code id_token token'(OIDC)</summary>
        /// <returns>ActionResult</returns>
        private ActionResult Hybrid_OIDC3()
        {
            this.Init();
            this.Save();

            // Hybrid Flow 'code id_token token'(OIDC)
            return Redirect(this.AssembleOidcStarter(
                OAuth2AndOIDCConst.OidcHybrid3_ResponseType));
        }

        #endregion

        #endregion

        #region Financial-grade API

        #region FAPI1

        /// <summary>Test Authorization Code Flow (FAPI1)</summary>
        /// <returns>ActionResult</returns>
        private ActionResult AuthorizationCodeFAPI1()
        {
            this.Init();
            this.Save();

            // Authorization Code Flow (FAPI1)
            return Redirect(this.AssembleFAPI1Starter(
                OAuth2AndOIDCConst.AuthorizationCodeResponseType));
        }

        /// <summary>Test Authorization Code Flow (FAPI1, OIDC)</summary>
        /// <returns>ActionResult</returns>
        private ActionResult AuthorizationCodeFAPI1_OIDC()
        {
            this.Init();
            this.Save();

            // Authorization Code Flow (FAPI1, OIDC)
            return Redirect(this.AssembleFAPI1_OIDCStarter(
                OAuth2AndOIDCConst.AuthorizationCodeResponseType));
        }

        /// <summary>Test Authorization Code Flow (FAPI1, OIDC, form_post)</summary>
        /// <returns>ActionResult</returns>
        private ActionResult AuthorizationCodeFAPI1_OIDC_FormPost()
        {
            this.Init();
            this.Save();

            // Authorization Code Flow (FAPI1, OIDC, form_post)
            return Redirect(this.AssembleFAPI1_OIDCStarter(
                OAuth2AndOIDCConst.AuthorizationCodeResponseType)
                + "&prompt=none"
                + "&response_mode=form_post");
        }

        #endregion

        #region FAPI2

        /// <summary>Test Authorization Code Flow (FAPI2)</summary>
        /// <returns>ActionResult</returns>
        private ActionResult AuthorizationCodeFAPI2()
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
        private async Task<ActionResult> TestResourceOwnerPasswordCredentialsFlow()
        {
            // Tokenエンドポイントにアクセス
            string aud = Config.OAuth2AuthorizationServerEndpointsRootURI + Config.OAuth2TokenEndpoint;

            // ClientNameから、client_id, client_secretを取得。
            string client_id = Helper.GetInstance().GetClientIdByName(this.ClientName);
            string client_secret = Helper.GetInstance().GetClientSecret(client_id);

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
        private async Task<ActionResult> TestClientCredentialsFlow()
        {
            // Tokenエンドポイントにアクセス
            string aud = Config.OAuth2AuthorizationServerEndpointsRootURI + Config.OAuth2TokenEndpoint;

            // ClientNameから、client_id, client_secretを取得。
            string client_id = Helper.GetInstance().GetClientIdByName(this.ClientName);
            string client_secret = Helper.GetInstance().GetClientSecret(client_id);

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
        private async Task<ActionResult> TestJWTBearerTokenFlow()
        {
            // Tokenエンドポイントにアクセス
            string aud = Config.OAuth2AuthorizationServerEndpointsRootURI + Config.OAuth2TokenEndpoint;

            // ClientNameから、client_id(iss)を取得。
            string iss = Helper.GetInstance().GetClientIdByName(this.ClientName);

            // 秘密鍵
            DigitalSignX509 dsX509 = new DigitalSignX509(
                OAuth2AndOIDCParams.RS256Pfx,
                OAuth2AndOIDCParams.RS256Pwd, HashAlgorithmName.SHA256);

            string response = await Helper.GetInstance().JwtBearerTokenFlowAsync(
                new Uri(Config.OAuth2AuthorizationServerEndpointsRootURI + Config.OAuth2TokenEndpoint),
                JwtAssertion.CreateJwtBearerTokenFlowAssertion(iss, aud,
                Config.OAuth2AccessTokenExpireTimeSpanFromMinutes, Const.StandardScopes,
                ((RSA)dsX509.AsymmetricAlgorithm).ExportParameters(true)));

            ViewBag.Response = response;
            ViewBag.AccessToken = ((JObject)JsonConvert.DeserializeObject(response))[OAuth2AndOIDCConst.AccessToken];

            return View("OAuth2ClientAuthenticationFlow");
        }

        #endregion

        #endregion

        #endregion

        #endregion

        #endregion
    }
}