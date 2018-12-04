//**********************************************************************************
//* テンプレート
//**********************************************************************************

// 以下のLicenseに従い、このProjectをTemplateとして使用可能です。Release時にCopyright表示してSublicenseして下さい。
// https://github.com/OpenTouryoProject/MultiPurposeAuthSite/blob/master/license/LicenseForTemplates.txt

//**********************************************************************************
//* クラス名        ：AccountResetPasswordViewModel
//* クラス日本語名  ：パスワード・リセット用のVM（テンプレート）
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
using MultiPurposeAuthSite.Co;

/// <summary>MultiPurposeAuthSite.Models.ViewModels</summary>
namespace MultiPurposeAuthSite.Models.ViewModels
{
    /// <summary>パスワード・リセット用のVM</summary>
    public class AccountResetPasswordViewModel : BaseViewModel
    {
        /// <summary>ユーザID</summary>
        [Required(AllowEmptyStrings = false)]
        public string UserId { get; set; }

        /// <summary>E-mail</summary>
        [Required(AllowEmptyStrings = false)]
        [EmailAddress]
        [Display(Name = "Email", ResourceType = typeof(Resources.CommonViewModels))]
        public string Email { get; set; }

        /// <summary>Password</summary>
        [Required(AllowEmptyStrings = false)]
        [DataType(DataType.Password)]
        [Display(Name = "Password", ResourceType = typeof(Resources.CommonViewModels))]
        [StringLength(
            Const.MaxLengthOfPassword,
            ErrorMessageResourceName = "MaxLengthErrMsg",
            ErrorMessageResourceType = typeof(Resources.CommonViewModels))]
        public string Password { get; set; }

        /// <summary>Confirm password</summary>
        [Required(AllowEmptyStrings = false)]
        [DataType(DataType.Password)]
        [Display(
            Name = "ConfirmPassword",
            ResourceType = typeof(Resources.CommonViewModels))]
        [Compare(
            "Password",
            ErrorMessageResourceName = "ConfirmPasswordErrMsg",
            ErrorMessageResourceType = typeof(Resources.CommonViewModels))]
        public string ConfirmPassword { get; set; }

        /// <summary>Code</summary>
        public string Code { get; set; }
    }
}