//**********************************************************************************
//* テンプレート
//**********************************************************************************

// 以下のLicenseに従い、このProjectをTemplateとして使用可能です。Release時にCopyright表示してSublicenseして下さい。
// https://github.com/OpenTouryoProject/MultiPurposeAuthSite/blob/master/license/LicenseForTemplates.txt

//**********************************************************************************
//* クラス名        ：AccountRegisterViewModel
//* クラス日本語名  ：サインアップ画面用のVM（テンプレート）
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

/// <summary>MultiPurposeAuthSite.Models.ViewModels</summary>
namespace MultiPurposeAuthSite.Models.ViewModels
{
    /// <summary>サインアップ画面用のVM（テンプレート）</summary>
    public class AccountRegisterViewModel : BaseViewModel
    {
        /// <summary>Name</summary>
        [Display(Name = "Name")]
        public string Name { get; set; }

        /// <summary>E-mail</summary>
        [EmailAddress]
        [Display(Name = "E-mail")]
        public string Email { get; set; }

        /// <summary>Password</summary>
        [Required(AllowEmptyStrings = false)]
        [DataType(DataType.Password)]
        [Display(Name = "Password")]
        [StringLength(
            100,
            ErrorMessageResourceName = "PasswordLengthErrMsg",
            ErrorMessageResourceType = typeof(Resources.CommonViewModels),
            MinimumLength = 8)]
        public string Password { get; set; }

        /// <summary>Confirm password</summary>
        [Required(AllowEmptyStrings = false)]
        [DataType(DataType.Password)]
        [Display(
            Name = "ConfirmPassword",
            ResourceType =typeof(Resources.CommonViewModels))] // 
        [Compare(
            "Password",
            ErrorMessageResourceName = "ConfirmPasswordErrMsg",
            ErrorMessageResourceType =typeof(Resources.CommonViewModels))] // 
        public string ConfirmPassword { get; set; }
    }
}