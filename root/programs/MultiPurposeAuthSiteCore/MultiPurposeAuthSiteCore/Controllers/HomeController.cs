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
//*  2020/01/07  西野 大介         PKCE for SPA対応実施
//*  2020/03/04  西野 大介         FAPI CIBA対応実施
//*  2020/07/24  西野 大介         OIDCではredirect_uriは必須。
//*  2020/11/12  西野 大介         redirect_uri、ROへの対策漏れ。
//*  2020/11/12  西野 大介         SameSiteCookie対応 (.NET Fx側は対策不要)
//*  2020/12/18  西野 大介         Device AuthZ対応実施
//*  2026/09/08  玄人 幸道         OIDCでもredirect_uriをcodeに紐付ける（#186）
//*  2026/09/18  玄人 幸道         require_pkce のクライアントを試す口を追加（#221）
//*  2026/09/25  玄人 幸道         CIBA の認証要求の aud を Issuer Identifier にした（#234 の段階 1）
//*  2026/09/27  玄人 幸道         自己テストに RP-Initiated Logout の口を追加（#232）
//*  2026/09/28  玄人 幸道         自己テストに PAR（/par）経路を追加（#246）
//*  2026/09/28  玄人 幸道         Device AuthZ の verification_uri のリンクが二重になっていたのを修正（#246）
//*  2026/09/29  玄人 幸道         OIDC ボタンの prompt=none を、画面の選択で上書きできるようにした（#247）
//*  2026/09/29  玄人 幸道         FAPI1 PKCE のボタンが S256 の値を plain と宣言していた（#245）
//*  2026/10/01  玄人 幸道         自己テストの宛先を、メアドではなく利用者名にした（#151 の段階 3）
//*  2026/10/06  玄人 幸道         OIDCボタンの固定のprompt=noneを外した（#272 の段階 2）
//*  2026/10/07  玄人 幸道         SAML2のAuthnRequestのIDを保存するようにした（#276）
//*  2026/10/08  玄人 幸道         自己テストで NameIDFormat / ResponseMode を選べるようにした（#277 の段階 4）
//*  2026/10/31  玄人 幸道         partial に分割した（Params / Starters / Saml2 / OAuth2 / Fapi / Another。#294）
//**********************************************************************************

using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;

using Touryo.Infrastructure.Business.Presentation;

namespace MultiPurposeAuthSite.Controllers
{
    /// <summary>HomeController</summary>
    [Authorize]
    public partial class HomeController : MyBaseMVControllerCore
    {
        #region constructor

        /// <summary>constructor</summary>
        /// <param name="userManager">UserManager</param>
        /// <param name="roleManager">RoleManager</param>
        /// <param name="signInManager">SignInManager</param>
        /// <param name="emailSender">IEmailSender</param>
        /// <param name="smsSender">ISmsSender</param>
        public HomeController(
            UserManager<ApplicationUser> userManager)
        {
            // UserManager
            this._userManager = userManager;
            
            // CookieOptions
            CookieOptions co = new CookieOptions();
            co.HttpOnly = true;
            co.Secure = true;
            co.SameSite = SameSiteMode.None;
            this._cookieOptions = co;
        }

        #endregion

        #region members

        /// <summary>UserManager</summary>
        private readonly UserManager<ApplicationUser> _userManager = null;

        //  <summary>CookieOptions</summary>
        private readonly CookieOptions _cookieOptions = null;

        #endregion

        #region property

        /// <summary>ApplicationUserManager</summary>
        private UserManager<ApplicationUser> UserManager
        {
            get
            {
                return this._userManager;
            }
        }

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
    }
}