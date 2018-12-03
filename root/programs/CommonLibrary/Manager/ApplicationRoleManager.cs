//**********************************************************************************
//* テンプレート
//**********************************************************************************

// 以下のLicenseに従い、このProjectをTemplateとして使用可能です。Release時にCopyright表示してSublicenseして下さい。
// https://github.com/OpenTouryoProject/MultiPurposeAuthSite/blob/master/license/LicenseForTemplates.txt

//**********************************************************************************
//* クラス名        ：ApplicationRoleManager
//* クラス日本語名  ：ユーザ・ロールの永続化管理クラス（テンプレート）
//*
//* 作成日時        ：－
//* 作成者          ：－
//* 更新履歴        ：－
//*
//*  日時        更新者            内容
//*  ----------  ----------------  -------------------------------------------------
//*  2017/04/24  西野 大介         新規
//**********************************************************************************

using MultiPurposeAuthSite.Data;
using MultiPurposeAuthSite.Entity;

using Microsoft.Owin;
using Microsoft.AspNet.Identity;
using Microsoft.AspNet.Identity.Owin;

/// <summary>MultiPurposeAuthSite.Manager</summary>
namespace MultiPurposeAuthSite.Manager
{
    /// <summary>ApplicationRoleManager</summary>
    public class ApplicationRoleManager : RoleManager<ApplicationRole>
    {
        /// <summary>constructor</summary>
        /// <param name="store">IRoleStore</param>
        /// <remarks>
        /// ApplicationSignInManagerのOwinContext生成で利用されている。
        /// </remarks> 
        public ApplicationRoleManager(IRoleStore<ApplicationRole, string> store) : base(store)
        {
        }

        /// <summary>Create</summary>
        /// <param name="options">options</param>
        /// <param name="context">context</param>
        /// <returns>ApplicationRoleManager</returns>
        /// <remarks>
        /// ApplicationSignInManagerのOwinContext生成で利用されるdelegate
        /// </remarks>
        public static ApplicationRoleManager Create(
            IdentityFactoryOptions<ApplicationRoleManager> options, IOwinContext context)
        {
            // ApplicationRoleManager（シングルトン、自身を生成）
            return new ApplicationRoleManager(context.Get<UserStore>());
        }
    }
}