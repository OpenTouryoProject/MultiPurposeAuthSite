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

using MultiPurposeAuthSite.Co;

using System.ComponentModel.DataAnnotations;

/// <summary>MultiPurposeAuthSite.ViewModels</summary>
namespace MultiPurposeAuthSite.ViewModels
{
    /// <summary>サインアップ画面用のVM（テンプレート）</summary>
    public class AccountRegisterViewModel : BaseViewModel
    {
        /// <summary>Name</summary>
        /// <remarks>
        /// **利用者名とメアドは、どちらも必須である**（#151 の段階 3）。
        /// **空欄を「`@` が使えません」と言わないため**に、ここで必須にする
        /// （以前はどちらか一方しか使わなかったので、必須にできなかった）。
        /// </remarks>
        [Required(AllowEmptyStrings = false)]
        [Display(Name = "UserName", ResourceType = typeof(Resources.CommonViewModels))]
        [StringLength(
            Const.MaxLengthOfUserName,
            ErrorMessageResourceName = "MaxLengthErrMsg",
            ErrorMessageResourceType = typeof(Resources.CommonViewModels))]
        public string Name { get; set; }

        /// <summary>E-mail</summary>
        /// <remarks>**必須である**（#151 の段階 3。メアドは常に在って一意）。</remarks>
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
            ResourceType =typeof(Resources.CommonViewModels))]
        [Compare(
            "Password",
            ErrorMessageResourceName = "ConfirmPasswordErrMsg",
            ErrorMessageResourceType =typeof(Resources.CommonViewModels))]
        public string ConfirmPassword { get; set; }
    }
}