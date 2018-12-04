//**********************************************************************************
//* テンプレート
//**********************************************************************************

// 以下のLicenseに従い、このProjectをTemplateとして使用可能です。Release時にCopyright表示してSublicenseして下さい。
// https://github.com/OpenTouryoProject/MultiPurposeAuthSite/blob/master/license/LicenseForTemplates.txt

//**********************************************************************************
//* クラス名        ：ManageEmailViewModel
//* クラス日本語名  ：E-mailの追加・編集画面用のVM（テンプレート）
//*
//* 作成日時        ：－
//* 作成者          ：－
//* 更新履歴        ：－
//*
//*  日時        更新者            内容
//*  ----------  ----------------  -------------------------------------------------
//*  2017/04/24  西野 大介         新規
//**********************************************************************************

using System.ComponentModel.DataAnnotations;

/// <summary>MultiPurposeAuthSite.ViewModels</summary>
namespace MultiPurposeAuthSite.ViewModels
{
    /// <summary>E-mailの追加・編集画面用のVM（テンプレート）</summary>
    public class ManageEmailViewModel : BaseViewModel
    {
        /// <summary>E-mail</summary>
        [Required(AllowEmptyStrings = false)]
        [EmailAddress]
        [Display(Name = "NewEmail", ResourceType =typeof(Resources.CommonViewModels))]
        public string Email { get; set; }

        /// <summary>Confirm password</summary>
        [Required(AllowEmptyStrings = false)]
        [EmailAddress]
        [Display(
            Name = "ConfirmNewEmail",
            ResourceType = typeof(Resources.CommonViewModels))]
        [Compare(
            "Email",
            ErrorMessageResourceName = "ConfirmNewEmailErrMsg",
            ErrorMessageResourceType = typeof(Resources.CommonViewModels))]
        public string ConfirmEmail { get; set; }

        /// <summary>Password</summary>
        [Required(AllowEmptyStrings = true)]
        [DataType(DataType.Password)]
        [Display(Name = "Password", ResourceType = typeof(Resources.CommonViewModels))]
        // [StringLength( // 検証用なので不要
        public string Password { get; set; }
    }
}