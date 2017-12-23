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

using System.Web.Mvc;

using Touryo.Infrastructure.Business.Presentation;
using Touryo.Infrastructure.Public.Security;

namespace MultiPurposeAuthSite.Controllers
{
    /// <summary>HomeController</summary>
    public class HomeController : MyBaseMVController
    {
        /// <summary>認可エンドポイント</summary>
        public string OAuthAuthorizeEndpoint = "";

        /// <summary>client_id</summary>
        public string ClientId = "";
        /// <summary>state (nonce)</summary>
        public string State = "";
        /// <summary>nonce</summary>
        public string Nonce = "";
        /// <summary>scope</summary>
        public string Scope = "";
        /// <summary>code_verifier</summary>
        public string CodeVerifier = "";
        /// <summary>code_verifier</summary>
        public string CodeChallenge = "";

        /// <summary>初期化</summary>
        private void Init()
        {
            this.OAuthAuthorizeEndpoint =
            ASPNETIdentityConfig.OAuthAuthorizationServerEndpointsRootURI
            + ASPNETIdentityConfig.OAuthAuthorizeEndpoint;

            this.ClientId = OAuth2Helper.GetInstance().GetClientIdByName("TestClient");
            this.State = GetPassword.Generate(10, 0); // 記号は入れない。
            this.Nonce = GetPassword.Generate(20, 0); // 記号は入れない。
            this.Scope = ASPNETIdentityConst.StandardScopes;
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

        /// <summary>
        /// GET: Home
        /// </summary>
        /// <returns>ActionResult</returns>
        [HttpGet]
        public ActionResult Index()
        {
            return View();
        }

        /// <summary>OAuthStarters</summary>
        /// <returns>ActionResult</returns>
        [HttpGet]
        public ActionResult OAuthStarters()
        {
            return View();
        }

        #region Code

        /// <summary>TestCode</summary>
        /// <returns>ActionResult</returns>
        [HttpGet]
        public ActionResult TestCode()
        {
            this.Init();
            this.Save();

            return Redirect(this.OAuthAuthorizeEndpoint + 
                "?client_id=" + this.ClientId + "&response_type=code&scope=" + this.Scope + 
                "&state=" + this.State);
        }

        /// <summary>TestCode_FormPost</summary>
        /// <returns>ActionResult</returns>
        [HttpGet]
        public ActionResult TestCode_FormPost()
        {
            this.Init();
            this.Save();

            return Redirect(this.OAuthAuthorizeEndpoint + 
                "?client_id=" + this.ClientId + "&response_type=code&scope=" + this.Scope + 
                "&state=" + this.State + "&response_mode=form_post");
        }

        #region OIDC

        /// <summary>TestCode_OIDC</summary>
        /// <returns>ActionResult</returns>
        [HttpGet]
        public ActionResult TestCode_OIDC()
        {
            this.Init();
            this.Save();

            return Redirect(this.OAuthAuthorizeEndpoint + 
                "?client_id=" + this.ClientId + "&response_type=code&scope=" + this.Scope + 
                "%20openid&prompt=none&state=" + this.State + "&nonce=" + this.Nonce);
        }

        /// <summary>TestCode_OIDC_FormPost</summary>
        /// <returns>ActionResult</returns>
        [HttpGet]
        public ActionResult TestCode_OIDC_FormPost()
        {
            this.Init();
            this.Save();

            return Redirect(this.OAuthAuthorizeEndpoint + 
                "?client_id=" + this.ClientId + "&response_type=code&scope=" + this.Scope + 
                "%20openid&prompt=none&state=" + this.State + "&nonce=" + this.Nonce + "&response_mode=form_post");
        }

        #endregion

        #region PKCE

        /// <summary>TestCode_PKCE_Plain</summary>
        /// <returns>ActionResult</returns>
        [HttpGet]
        public ActionResult TestCode_PKCE_Plain()
        {
            this.Init();
            this.CodeVerifier = GetPassword.Base64UrlSecret(50);
            this.CodeChallenge = this.CodeVerifier;
            this.Save();

            return Redirect(this.OAuthAuthorizeEndpoint + 
                "?client_id=" + this.ClientId + "&response_type=code&scope=" + this.Scope + 
                "&state=" + this.State + "&code_challenge=" + this.CodeChallenge + "&code_challenge_method=plain");
        }

        /// <summary>TestCode_PKCE_S256</summary>
        /// <returns>ActionResult</returns>
        [HttpGet]
        public ActionResult TestCode_PKCE_S256()
        {
            this.Init();
            this.CodeVerifier = GetPassword.Base64UrlSecret(50);
            this.CodeChallenge = OAuth2Helper.PKCE_S256_CodeChallengeMethod(this.CodeVerifier);
            this.Save();

            return Redirect(this.OAuthAuthorizeEndpoint + 
                "?client_id=" + this.ClientId + "&response_type=code&scope=" + this.Scope + 
                "&state=" + this.State + "&code_challenge=" + this.CodeChallenge + "&code_challenge_method=S256");
        }

        #endregion

        #endregion

        #region Token

        /// <summary>TestToken</summary>
        /// <returns>ActionResult</returns>
        [HttpGet]
        public ActionResult TestToken()
        {
            this.Init();
            this.Save();

            return Redirect(this.OAuthAuthorizeEndpoint + 
                "?client_id=" + this.ClientId + "&response_type=token&scope=" + this.Scope +
                "&state=" + this.State);
        }

        /// <summary>TestToken_OIDC1</summary>
        /// <returns>ActionResult</returns>
        [HttpGet]
        public ActionResult TestToken_OIDC1()
        {
            this.Init();
            this.Save();

            return Redirect(this.OAuthAuthorizeEndpoint + 
                "?client_id=" + this.ClientId + "&response_type=id_token&scope=" + this.Scope + "%20openid&state=" +
                this.State + "&nonce=" + this.Nonce);
        }

        /// <summary>TestToken_OIDC2</summary>
        /// <returns>ActionResult</returns>
        [HttpGet]
        public ActionResult TestToken_OIDC2()
        {
            this.Init();
            this.Save();

            return Redirect(this.OAuthAuthorizeEndpoint + 
                "?client_id=" + this.ClientId + "&response_type=id_token token&scope=" + this.Scope + "%20openid&state=" + 
                this.State + "&nonce=" + this.Nonce);
        }

        #endregion
    }
}