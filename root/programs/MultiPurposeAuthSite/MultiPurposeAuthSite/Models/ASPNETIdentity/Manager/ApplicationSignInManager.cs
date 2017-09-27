//**********************************************************************************
//* テンプレート
//**********************************************************************************

// 以下のLicenseに従い、このProjectをTemplateとして使用可能です。Release時にCopyright表示してSublicenseして下さい。
// https://github.com/OpenTouryoProject/MultiPurposeAuthSite/blob/master/license/LicenseForTemplates.txt

//**********************************************************************************
//* クラス名        ：ApplicationSignInManager
//* クラス日本語名  ：サインイン・オペレーション管理クラス（テンプレート）
//*
//* 作成日時        ：－
//* 作成者          ：－
//* 更新履歴        ：－
//*
//*  日時        更新者            内容
//*  ----------  ----------------  -------------------------------------------------
//*  2017/04/24  西野 大介         新規
//**********************************************************************************

using System.Security.Claims;
using System.Threading.Tasks;
using Microsoft.AspNet.Identity;
using Microsoft.AspNet.Identity.Owin;
using Microsoft.Owin;
using Microsoft.Owin.Security;

using MultiPurposeAuthSite.Models.ASPNETIdentity.Entity;

/// <summary>MultiPurposeAuthSite.Models.ASPNETIdentity.Manager</summary>
namespace MultiPurposeAuthSite.Models.ASPNETIdentity.Manager

{
    /// <summary>
    /// Configure the application sign-in manager which is used in this application.
    /// このアプリケーションで使用されているsign-in managerを設定します。
    /// 
    /// SignInManager(TUser, TKey) Class (Microsoft.AspNet.Identity.Owin)
    /// https://msdn.microsoft.com/en-us/library/dn896559.aspx
    /// 　Manages Sign In operations for users
    ///   サインインのオペレーションを管理する。
    /// </summary>
    public class ApplicationSignInManager : SignInManager<ApplicationUser, string>
    {
        /// <summary>constructor</summary>
        /// <param name="userManager">userManager</param>
        /// <param name="authenticationManager">authenticationManager</param>
        public ApplicationSignInManager(
            ApplicationUserManager userManager,
            IAuthenticationManager authenticationManager)
            : base(userManager, authenticationManager)
        {
        }

        /// <summary>
        /// Called to generate the ClaimsIdentity for the user, override to add additional claims before SignIn
        /// ユーザのClaimsIdentityを生成するために呼び出され、クレームを追加してサインインする。
        /// </summary>
        /// <param name="user">user</param>
        /// <returns>ClaimsIdentityを非同期に返す</returns>
        public override Task<ClaimsIdentity> CreateUserIdentityAsync(ApplicationUser user)
        {
            // 0 個の参照だが、この method は、
            // サインインの際（SignInManager.PasswordSignInAsync）、
            // AspNet.Identityのフレームワーク経由で呼び出されている。

            // ApplicationUserManagerを使用して、クレームを追加してサインインする。
            // Task<ClaimsIdentity>をそのまま上に返すので、ここでawaitは不要。
            return user.GenerateUserIdentityAsync((ApplicationUserManager)UserManager);
        }

        /// <summary>Create</summary>
        /// <param name="options">options</param>
        /// <param name="context">context</param>
        /// <returns>ApplicationUserManager</returns>
        /// <remarks>
        /// ApplicationSignInManagerのOwinContext生成で利用されるdelegate
        /// </remarks>
        public static ApplicationSignInManager Create(
            IdentityFactoryOptions<ApplicationSignInManager> options, IOwinContext context)
        {
            // ApplicationSignInManagerを生成（シングルトン、自身を生成）
            return new ApplicationSignInManager(
                context.GetUserManager<ApplicationUserManager>(), context.Authentication);
        }
    }
}