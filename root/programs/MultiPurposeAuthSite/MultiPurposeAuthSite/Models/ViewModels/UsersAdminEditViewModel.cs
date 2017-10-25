//**********************************************************************************
//* テンプレート
//**********************************************************************************

// 以下のLicenseに従い、このProjectをTemplateとして使用可能です。Release時にCopyright表示してSublicenseして下さい。
// https://github.com/OpenTouryoProject/MultiPurposeAuthSite/blob/master/license/LicenseForTemplates.txt

//**********************************************************************************
//* クラス名        ：UsersAdminEditViewModel
//* クラス日本語名  ：ユーザ管理画面の編集処理用のVM（テンプレート）
//*
//* 作成日時        ：－
//* 作成者          ：－
//* 更新履歴        ：－
//*
//*  日時        更新者            内容
//*  ----------  ----------------  -------------------------------------------------
//*  2017/04/24  西野 大介         新規
//**********************************************************************************

using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;
using System.Web.Mvc;

using MultiPurposeAuthSite.Models.ASPNETIdentity;

/// <summary>MultiPurposeAuthSite.Models.ViewModels</summary>
namespace MultiPurposeAuthSite.Models.ViewModels
{
    /// <summary>ユーザ管理画面用のVM（テンプレート）</summary>
    public class UsersAdminEditViewModel : BaseViewModel
    {
        /// <summary>ユーザID</summary>
        [Required(AllowEmptyStrings = false)]
        // [StringLength( // ユーザ入力でないので不要
        public string Id { get; set; }

        /// <summary>Name</summary>
        [Display(Name = "UserName", ResourceType = typeof(Resources.CommonViewModels))]
        [StringLength(
            ASPNETIdentityConst.MaxLengthOfUserName,
            ErrorMessageResourceName = "MaxLengthErrMsg",
            ErrorMessageResourceType = typeof(Resources.CommonViewModels))]
        public string Name { get; set; }

        /// <summary>E-mail</summary>
        [EmailAddress]
        [Display(Name = "Email", ResourceType = typeof(Resources.CommonViewModels))]
        public string Email { get; set; }

        /// <summary>RolesList</summary>
        public IEnumerable<SelectListItem> RolesList { get; set; }
    }
}