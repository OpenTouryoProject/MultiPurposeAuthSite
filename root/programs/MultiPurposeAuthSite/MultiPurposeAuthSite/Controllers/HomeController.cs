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
//*  2019/05/2*  西野 大介         SAML2対応実施
//**********************************************************************************

using MultiPurposeAuthSite.Co;
using MultiPurposeAuthSite.Entity;
using MultiPurposeAuthSite.Manager;
using MultiPurposeAuthSite.ViewModels;
using MultiPurposeAuthSite.Extensions.Sts;

using System;
using System.Web;
using System.Web.Mvc;
using System.Net.Http;
using System.Threading.Tasks;
using System.Collections.Generic;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

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

        #region Test WebAuthn

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

        #region Test STS

        #region Params

        /// <summary>Issuer</summary>
        private string Issuer = "";

        /// <summary>RedirectUri</summary>
        private string RedirectUri = "";

        /// <summary>ClarifyRedirectUri</summary>
        private bool ClarifyRedirectUri = false;

        #region Saml2

        /// <summary>認可エンドポイント</summary>
        private string Saml2RequestEndpoint = "";
                
        #endregion

        #region OAuth2
        /// <summary>認可エンドポイント</summary>
        private string OAuth2AuthorizeEndpoint = "";

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

        #endregion

        #region Common

        #region InitParams

        #region InitSaml2Params

        /// <summary>初期化</summary>
        private void InitSaml2Params()
        {
            this.Saml2RequestEndpoint =
            Config.OAuth2AuthorizationServerEndpointsRootURI + Config.Saml2RequestEndpoint;

            // Issuer (RootURI + ClientId) 
            this.ClientId = Helper.GetInstance().GetClientIdByName(this.ClientName);
            this.Issuer = "http://" + ClientId;

            if (this.ClarifyRedirectUri)
            {
                this.RedirectUri = Helper.GetInstance().GetAssertionConsumerServiceURL(this.ClientId);
            }

            // RelayStateに入れる（本来の用途と異なるが）。
            this.State = GetPassword.Generate(10, 0); // 記号は入れない。
        }

        /// <summary>保存</summary>
        private void SaveSaml2Params()
        {
            // テスト用にパラメタを、Session, Cookieに保存
            // ・Session : サイト分割時
            // ・Cookie : 同一サイト時

            // client_id → Issuer
            Session["test_client_id"] = this.ClientId;
            Response.Cookies["test_client_id"].Value = this.ClientId;

            // redirect_uri → AssertionConsumerService
            Session["test_redirect_uri"] = this.RedirectUri;
            Response.Cookies["test_redirect_uri"].Value = this.RedirectUri;

            // state → RelayState
            Session["test_state"] = this.State;
            Response.Cookies["test_state"].Value = this.State;
        }

        #endregion

        #region InitOAuth2Params

        /// <summary>初期化</summary>
        private void InitOAuth2Params()
        {
            this.OAuth2AuthorizeEndpoint =
            Config.OAuth2AuthorizationServerEndpointsRootURI
            + Config.OAuth2AuthorizeEndpoint;

            this.ClientId = Helper.GetInstance().GetClientIdByName(this.ClientName);
            // ココでは、まだ、response_typeが明確にならないので取得できない。
            //this.RedirectUri = Helper.GetInstance().GetClientsRedirectUri(this.ClientName, response_type);

            this.State = GetPassword.Generate(10, 0); // 記号は入れない。
            this.Nonce = GetPassword.Generate(20, 0); // 記号は入れない。

            this.CodeVerifier = "";
            this.CodeChallenge = "";
        }

        /// <summary>保存</summary>
        private void SaveOAuth2Params()
        {
            // テスト用にパラメタを、Session, Cookieに保存
            // ・Session : サイト分割時
            // ・Cookie : 同一サイト時

            // client_id
            Session["test_client_id"] = this.ClientId;
            Response.Cookies["test_client_id"].Value = this.ClientId;

            // state
            Session["test_state"] = this.State;
            Response.Cookies["test_state"].Value = this.State;

            // redirect_uri
            Session["test_redirect_uri"] = this.RedirectUri;
            Response.Cookies["test_redirect_uri"].Value = this.RedirectUri;

            // nonce
            Session["test_nonce"] = this.Nonce;
            Response.Cookies["test_nonce"].Value = this.Nonce;

            // code_verifier
            Session["test_code_verifier"] = this.CodeVerifier;
            Response.Cookies["test_code_verifier"].Value = this.CodeVerifier;
        }

        #endregion

        #endregion

        #region Assemble

        #region AssembleSaml2
        #endregion

        #region AssembleOAuth2

        /// <summary>OAuth2スターターを組み立てて返す</summary>
        /// <param name="response_type">string</param>
        /// <returns>組み立てたOAuth2スターター</returns>
        /// 
        /// <summary>OAuth2スターターにRedirectUriを組み込む</summary>
        /// <param name="redirect">string</param>
        /// <param name="response_type">string</param>
        /// <returns>OAuth2スターター</returns>
        private string AndAddRedirectUriToOAuth2Starter(string redirect, string response_type)
        {
            if (this.ClarifyRedirectUri)
            {
                this.RedirectUri = Helper.GetInstance().GetClientsRedirectUri(this.ClientId, response_type);
                return redirect + "&redirect_uri=" + this.RedirectUri;
            }
            else
            {
                return redirect;
            }
        }

        /// <summary>OAuth2スターターを組み立てて返す</summary>
        /// <param name="response_type">string</param>
        /// <returns>組み立てたOAuth2スターター</returns>
        private string AssembleOAuth2Starter(string response_type)
        {
            string temp = "";

            temp = this.OAuth2AuthorizeEndpoint +
                string.Format(
                    "?client_id={0}&response_type={1}&scope={2}&state={3}",
                    this.ClientId, response_type, Const.StandardScopes, this.State);

            temp = AndAddRedirectUriToOAuth2Starter(temp, response_type);

            return temp;
        }

        /// <summary>OIDCスターターを組み立てて返す</summary>
        /// <param name="response_type">string</param>
        /// <returns>組み立てたOIDCスターター</returns>
        private string AssembleOidcStarter(string response_type)
        {
            string temp = "";

            temp = this.OAuth2AuthorizeEndpoint +
                string.Format(
                    "?client_id={0}&response_type={1}&scope={2}&state={3}",
                    this.ClientId, response_type, Const.OidcScopes, this.State)
                    + "&nonce=" + this.Nonce;

            temp = AndAddRedirectUriToOAuth2Starter(temp, response_type);

            return temp;
        }

        /// <summary>FAPI1スターターを組み立てて返す</summary>
        /// <param name="response_type">string</param>
        /// <returns>組み立てたFAPI1スターター</returns>
        private string AssembleFAPI1Starter(string response_type)
        {
            string temp = "";

            temp = this.OAuth2AuthorizeEndpoint +
                string.Format(
                    "?client_id={0}&response_type={1}&scope={2}&state={3}",
                    this.ClientId, response_type, Const.StandardScopes,
                    OAuth2AndOIDCEnum.ClientMode.fapi1.ToStringByEmit() + ":" + this.State);
            // テストコードで、clientを識別するために、Stateに細工する。

            temp = AndAddRedirectUriToOAuth2Starter(temp, response_type);

            return temp;
        }

        /// <summary>FAPI1 + OIDCスターターを組み立てて返す</summary>
        /// <param name="response_type">string</param>
        /// <returns>組み立てたFAPI1スターター</returns>
        private string AssembleFAPI1_OIDCStarter(string response_type)
        {
            string temp = "";

            temp = this.OAuth2AuthorizeEndpoint +
                string.Format(
                    "?client_id={0}&response_type={1}&scope={2}&state={3}",
                    this.ClientId, response_type, Const.OidcScopes,
                    OAuth2AndOIDCEnum.ClientMode.fapi1.ToStringByEmit() + ":" + this.State)
                    + "&nonce=" + this.Nonce;
            // テストコードで、clientを識別するために、Stateに細工する。

            temp = AndAddRedirectUriToOAuth2Starter(temp, response_type);

            return temp;
        }

        /// <summary>FAPI2CCスターターを組み立てて返す</summary>
        /// <param name="response_type">string</param>
        /// <returns>組み立てたFAPI2CCスターター</returns>
        private async Task<string> AssembleFAPI2CCStarterAsync(string response_type)
        {
            //string temp = this.OAuth2AuthorizeEndpoint +
            //    string.Format(
            //        "?client_id={0}&response_type={1}&scope={2}&state={3}",
            //        this.ClientId, response_type, Const.OidcScopes,
            //        OAuth2AndOIDCEnum.ClientMode.fapi2.ToStringByEmit() + ":" + this.State)
            //        + "&nonce=" + this.Nonce;

            // 秘密鍵
            DigitalSignX509 dsX509 = new DigitalSignX509(
                CmnClientParams.RsaPfxFilePath,
                CmnClientParams.RsaPfxPassword,
                HashAlgorithmName.SHA256);

            if (this.ClarifyRedirectUri)
            {
                this.RedirectUri = Helper.GetInstance().GetClientsRedirectUri(this.ClientId, response_type);
            }

            // テストコードで、clientを識別するために、Stateに細工する。
            string requestObject = RequestObject.Create(this.ClientId,
                Config.OAuth2AuthorizationServerEndpointsRootURI + OAuth2AndOIDCParams.RequestObjectRegUri,
                response_type, "", this.RedirectUri, Const.OidcScopes,
                OAuth2AndOIDCEnum.ClientMode.fapi2.ToStringByEmit() + ":" + this.State, this.Nonce, "", "",
                new ClaimsInRO(
                    // userinfo > claims
                    new Dictionary<string, object>()
                    {
                        {
                            "hoge",
                            new
                            {
                                essential = true
                            }
                        }
                    },
                    // id_token > claims
                    new Dictionary<string, object>()
                    {
                        {
                            "hoge",
                            new
                            {
                                essential = true
                            }
                        }
                    },
                    // id_token > arc
                    new
                    {
                        essential = true,
                        values = new string[]
                        {
                            OAuth2AndOIDCConst.LoA1,
                            OAuth2AndOIDCConst.LoA2
                        }
                    }),
                ((RSA)dsX509.AsymmetricAlgorithm).ExportParameters(true));

            // 検証テスト
            if (RequestObject.Verify(requestObject, out string iss,
                ((RSA)dsX509.AsymmetricAlgorithm).ExportParameters(false)))
            {
                // 検証できた。

                // RequestObjectを登録する。
                string response = await Helper.GetInstance().RegisterRequestObjectAsync(
                    new Uri(Config.OAuth2AuthorizationServerEndpointsRootURI + OAuth2AndOIDCParams.RequestObjectRegUri), requestObject);

                // request_uriの認可リクエストを投げる。
                return this.OAuth2AuthorizeEndpoint + string.Format("?request_uri={0}", "request_uri");
            }
            else
            {
                // 検証できなかった。
                return null;
            }
        }

        #endregion

        #endregion

        #endregion

        #region Action Method

        #region Public

        /// <summary>
        /// SAML2OAuth2Starters画面（初期表示）
        /// GET: /Home/Saml2OAuth2Starters
        /// </summary>
        /// <returns>ActionResult</returns>
        [HttpGet]
        [AllowAnonymous]
        public ActionResult Saml2OAuth2Starters()
        {
            if (Config.IsLockedDownRedirectEndpoint)
            {
                return View("Index");
            }
            else
            {
                return View(new HomeSaml2OAuth2StartersViewModel()); 
            }
        }

        /// <summary>
        /// SAML2OAuth2Starters画面
        /// POST: /Home/Saml2OAuth2Starters
        /// </summary>
        /// <returns>ActionResult</returns>
        [HttpPost]
        [AllowAnonymous]
        public async Task<ActionResult> Saml2OAuth2Starters(HomeSaml2OAuth2StartersViewModel model)
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
                    // RedirectUriの扱い
                    this.ClarifyRedirectUri = model.ClarifyRedirectUri;

                    #region Client選択
                    if (model.ClientType == OAuth2AndOIDCEnum.ClientMode.normal.ToStringByEmit())
                    {
                        // OAuth2.0 / OIDC用 Client
                        this.ClientName = "TestClient";
                    }
                    else if (model.ClientType == OAuth2AndOIDCEnum.ClientMode.fapi1.ToStringByEmit())
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

                    #region Starterの実行
                    if (!string.IsNullOrEmpty(this.ClientName))
                    {
                        #region SAML2
                        if (!string.IsNullOrEmpty(Request.Form.Get("submit.Saml2RedirectRedirectBinding")))
                        {
                            return this.Saml2RedirectRedirectBinding();
                        }
                        else if (!string.IsNullOrEmpty(Request.Form.Get("submit.Saml2RedirectPostBinding")))
                        {
                            return this.Saml2RedirectPostBinding();
                        }
                        else if (!string.IsNullOrEmpty(Request.Form.Get("submit.Saml2PostPostBinding")))
                        {
                            return this.Saml2PostPostBinding();
                        }
                        #endregion

                        #region OAuth2

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
                            return await this.AuthorizationCodeFAPI2Async();
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
                    #endregion
                }

                // 再表示
                return View(model);
            }
        }

        #endregion

        #region Private

        #region SAML2

        /// <summary>Test Saml2 Redirect & Redirect Binding</summary>
        /// <returns>ActionResult</returns>
        private ActionResult Saml2RedirectRedirectBinding()
        {
            this.InitSaml2Params();

            string id = "";
            string queryString = SAML2Client.CreateRedirectRequest(
                SAML2Enum.RequestOrResponse.Request,
                SAML2Enum.ProtocolBinding.HttpRedirect,
                SAML2Enum.NameIDFormat.Unspecified,
                this.Issuer, this.RedirectUri, this.State, out id);

            this.SaveSaml2Params();

            // Redirect
            return Redirect(
                Config.OAuth2AuthorizationServerEndpointsRootURI
                + Config.Saml2RequestEndpoint + "?" + queryString);
        }

        /// <summary>Test Saml2 Redirect & Post Binding</summary>
        /// <returns>ActionResult</returns>
        private ActionResult Saml2RedirectPostBinding()
        {
            this.InitSaml2Params();

            string id = "";
            string queryString = SAML2Client.CreateRedirectRequest(
                SAML2Enum.RequestOrResponse.Request,
                SAML2Enum.ProtocolBinding.HttpPost,
                SAML2Enum.NameIDFormat.Unspecified,
                this.Issuer, this.RedirectUri, this.State, out id);

            this.SaveSaml2Params();

            // Redirect
            return Redirect(
                Config.OAuth2AuthorizationServerEndpointsRootURI
                + Config.Saml2RequestEndpoint + "?" + queryString);
        }

        /// <summary>Test Saml2 Post & Post Binding</summary>
        /// <returns>ActionResult</returns>
        private ActionResult Saml2PostPostBinding()
        {
            this.InitSaml2Params();

            string id = "";
            string samlRequest = SAML2Client.CreatePostRequest(
                SAML2Enum.ProtocolBinding.HttpPost,
                SAML2Enum.NameIDFormat.Unspecified,
                this.Issuer, this.RedirectUri, this.State, out id);

            this.SaveSaml2Params();

            // Post
            ViewData["RelayState"] = this.State;
            ViewData["SAMLRequest"] = samlRequest;
            ViewData["Action"] = Config.OAuth2AuthorizationServerEndpointsRootURI + Config.Saml2RequestEndpoint;

            return View("PostBinding");
        }

        #endregion

        #region OAuth2

        #region Authorization Code Flow

        #region OAuth2

        /// <summary>Test Authorization Code Flow</summary>
        /// <returns>ActionResult</returns>
        private ActionResult AuthorizationCode()
        {
            this.InitOAuth2Params();

            // Authorization Code Flow
            string redirect = this.AssembleOAuth2Starter(
                OAuth2AndOIDCConst.AuthorizationCodeResponseType);

            this.SaveOAuth2Params();

            return Redirect(redirect);
        }

        /// <summary>Test Authorization Code Flow (form_post)</summary>
        /// <returns>ActionResult</returns>
        private ActionResult AuthorizationCode_FormPost()
        {
            this.InitOAuth2Params();

            // Authorization Code Flow (form_post)
            string redirect = this.AssembleOAuth2Starter(
                OAuth2AndOIDCConst.AuthorizationCodeResponseType)
                + "&response_mode=form_post";

            this.SaveOAuth2Params();

            return Redirect(redirect);
        }

        #endregion

        #region OIDC

        /// <summary>Test Authorization Code Flow (OIDC)</summary>
        /// <returns>ActionResult</returns>
        private ActionResult AuthorizationCode_OIDC()
        {
            this.InitOAuth2Params();

            // Authorization Code Flow (OIDC)
            string redirect = this.AssembleOidcStarter(
                OAuth2AndOIDCConst.AuthorizationCodeResponseType)
                + "&prompt=none";

            this.SaveOAuth2Params();

            return Redirect(redirect);
        }

        /// <summary>Test Authorization Code Flow (OIDC, form_post)</summary>
        /// <returns>ActionResult</returns>
        private ActionResult AuthorizationCode_OIDC_FormPost()
        {
            this.InitOAuth2Params();

            // Authorization Code Flow (OIDC, form_post)
            string redirect = this.AssembleOidcStarter(
                OAuth2AndOIDCConst.AuthorizationCodeResponseType)
                + "&prompt=none"
                + "&response_mode=form_post";

            this.SaveOAuth2Params();

            return Redirect(redirect);
        }

        #endregion

        #region PKCE

        /// <summary>Test Authorization Code Flow (PKCE plain)</summary>
        /// <returns>ActionResult</returns>
        [HttpGet]
        [AllowAnonymous]
        public ActionResult AuthorizationCode_PKCE_Plain()
        {
            this.InitOAuth2Params();

            // 追加のパラメタ
            this.CodeVerifier = GetPassword.Base64UrlSecret(50);
            this.CodeChallenge = this.CodeVerifier;
            this.SaveOAuth2Params();

            // Authorization Code Flow (PKCE plain)
            string redirect = this.AssembleOAuth2Starter(
                OAuth2AndOIDCConst.AuthorizationCodeResponseType)
                + "&code_challenge=" + this.CodeChallenge
                + "&code_challenge_method=" + OAuth2AndOIDCConst.PKCE_plain;

            this.SaveOAuth2Params();

            return Redirect(redirect);
        }

        /// <summary>Test Authorization Code Flow (PKCE S256)</summary>
        /// <returns>ActionResult</returns>
        private ActionResult AuthorizationCode_PKCE_S256()
        {
            this.InitOAuth2Params();

            // 追加のパラメタ
            this.CodeVerifier = GetPassword.Base64UrlSecret(50);
            this.CodeChallenge = OAuth2AndOIDCClient.PKCE_S256_CodeChallengeMethod(this.CodeVerifier);
            this.SaveOAuth2Params();

            // Authorization Code Flow (PKCE S256)
            string redirect = this.AssembleOAuth2Starter(
                OAuth2AndOIDCConst.AuthorizationCodeResponseType)
                + "&code_challenge=" + this.CodeChallenge
                + "&code_challenge_method=" + OAuth2AndOIDCConst.PKCE_S256;

            this.SaveOAuth2Params();

            return Redirect(redirect);
        }

        #endregion

        #endregion

        #region Implicit Flow

        #region OAuth2

        /// <summary>Test Implicit Flow</summary>
        /// <returns>ActionResult</returns>
        private ActionResult Implicit()
        {
            this.InitOAuth2Params();

            // Implicit Flow
            string redirect = this.AssembleOAuth2Starter(
                OAuth2AndOIDCConst.ImplicitResponseType);

            this.SaveOAuth2Params();

            return Redirect(redirect);
        }

        #endregion

        #region OIDC

        /// <summary>Test Implicit Flow 'id_token'(OIDC)</summary>
        /// <returns>ActionResult</returns>
        private ActionResult Implicit_OIDC1()
        {
            this.InitOAuth2Params();

            // Implicit Flow 'id_token'(OIDC)
            string redirect = this.AssembleOidcStarter(
                OAuth2AndOIDCConst.OidcImplicit1_ResponseType);

            this.SaveOAuth2Params();

            return Redirect(redirect);
        }


        /// <summary>Test Implicit Flow 'id_token token'(OIDC)</summary>
        /// <returns>ActionResult</returns>
        private ActionResult Implicit_OIDC2()
        {
            this.InitOAuth2Params();

            // Implicit Flow 'id_token token'(OIDC)
            string redirect = this.AssembleOidcStarter(
                OAuth2AndOIDCConst.OidcImplicit2_ResponseType);

            this.SaveOAuth2Params();

            return Redirect(redirect);
        }

        #endregion

        #endregion

        #region Hybrid Flow

        #region OIDC

        /// <summary>Test Hybrid Flow 'code id_token'(OIDC)</summary>
        /// <returns>ActionResult</returns>
        private ActionResult Hybrid_OIDC1()
        {
            this.InitOAuth2Params();

            // Hybrid Flow 'code id_token'(OIDC)
            string redirect = this.AssembleOidcStarter(
                OAuth2AndOIDCConst.OidcHybrid2_IdToken_ResponseType);

            this.SaveOAuth2Params();

            return Redirect(redirect);
        }

        /// <summary>Test Hybrid Flow 'code token'(OIDC)</summary>
        /// <returns>ActionResult</returns>
        private ActionResult Hybrid_OIDC2()
        {
            this.InitOAuth2Params();

            // Hybrid Flow 'code token'(OIDC)
            string redirect = this.AssembleOidcStarter(
                OAuth2AndOIDCConst.OidcHybrid2_Token_ResponseType);

            this.SaveOAuth2Params();

            return Redirect(redirect);
        }

        /// <summary>Test Hybrid Flow 'code id_token token'(OIDC)</summary>
        /// <returns>ActionResult</returns>
        private ActionResult Hybrid_OIDC3()
        {
            this.InitOAuth2Params();

            // Hybrid Flow 'code id_token token'(OIDC)
            string redirect = this.AssembleOidcStarter(
                OAuth2AndOIDCConst.OidcHybrid3_ResponseType);

            this.SaveOAuth2Params();

            return Redirect(redirect);
        }

        #endregion

        #endregion

        #region Financial-grade API

        #region FAPI1

        /// <summary>Test Authorization Code Flow (FAPI1)</summary>
        /// <returns>ActionResult</returns>
        private ActionResult AuthorizationCodeFAPI1()
        {
            this.InitOAuth2Params();

            // Authorization Code Flow (FAPI1)
            string redirect = this.AssembleFAPI1Starter(
                OAuth2AndOIDCConst.AuthorizationCodeResponseType);

            this.SaveOAuth2Params();

            return Redirect(redirect);
        }

        /// <summary>Test Authorization Code Flow (FAPI1, OIDC)</summary>
        /// <returns>ActionResult</returns>
        private ActionResult AuthorizationCodeFAPI1_OIDC()
        {
            this.InitOAuth2Params();

            // Authorization Code Flow (FAPI1, OIDC)
            string redirect = this.AssembleFAPI1_OIDCStarter(
                OAuth2AndOIDCConst.AuthorizationCodeResponseType);

            this.SaveOAuth2Params();

            return Redirect(redirect);
        }

        /// <summary>Test Authorization Code Flow (FAPI1, OIDC, form_post)</summary>
        /// <returns>ActionResult</returns>
        private ActionResult AuthorizationCodeFAPI1_OIDC_FormPost()
        {
            this.InitOAuth2Params();

            // Authorization Code Flow (FAPI1, OIDC, form_post)
            string redirect = this.AssembleFAPI1_OIDCStarter(
                OAuth2AndOIDCConst.AuthorizationCodeResponseType)
                + "&prompt=none"
                + "&response_mode=form_post";

            this.SaveOAuth2Params();

            return Redirect(redirect);
        }

        #endregion

        #region FAPI2

        /// <summary>Test Authorization Code Flow (FAPI2)</summary>
        /// <returns>ActionResult</returns>
        private async Task<ActionResult> AuthorizationCodeFAPI2Async()
        {
            this.InitOAuth2Params();

            // Authorization Code Flow
            string redirect = await this.AssembleFAPI2CCStarterAsync(
                OAuth2AndOIDCConst.AuthorizationCodeResponseType);

            this.SaveOAuth2Params();

            return Redirect(redirect);
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
                CmnClientParams.RsaPfxFilePath,
                CmnClientParams.RsaPfxPassword,
                HashAlgorithmName.SHA256);

            string response = await Helper.GetInstance().JwtBearerTokenFlowAsync(
                new Uri(Config.OAuth2AuthorizationServerEndpointsRootURI + Config.OAuth2TokenEndpoint),
                JwtAssertion.Create(iss, aud, Config.OAuth2AccessTokenExpireTimeSpanFromMinutes,
                    Const.StandardScopes, ((RSA)dsX509.AsymmetricAlgorithm).ExportParameters(true)));

            ViewBag.Response = response;
            ViewBag.AccessToken = ((JObject)JsonConvert.DeserializeObject(response))[OAuth2AndOIDCConst.AccessToken];

            return View("OAuth2ClientAuthenticationFlow");
        }

        #endregion

        #endregion

        #endregion

        #endregion

        #endregion

        #endregion
    }
}