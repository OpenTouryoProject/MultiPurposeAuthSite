//**********************************************************************************
//* テンプレート
//**********************************************************************************

// 以下のLicenseに従い、このProjectをTemplateとして使用可能です。Release時にCopyright表示してSublicenseして下さい。
// https://github.com/OpenTouryoProject/MultiPurposeAuthSite/blob/master/license/LicenseForTemplates.txt

//**********************************************************************************
//* クラス名        ：ManageChangePasswordViewModel
//* クラス日本語名  ：パスワードの変更画面用のVM（テンプレート）
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
    /// <summary>パスワードの変更画面用のVM（テンプレート）</summary>
    public class ManageChangePasswordViewModel : BaseViewModel
    {
        /// <summary>OldPassword</summary>
        [Required(AllowEmptyStrings = false)]
        [DataType(DataType.Password)]
        [Display(Name = "OldPassword", ResourceType =typeof(Resources.CommonViewModels))]
        public string OldPassword { get; set; }

        /// <summary>NewPassword</summary>
        [Required(AllowEmptyStrings = false)]
        [DataType(DataType.Password)]
        [Display(Name = "NewPassword", ResourceType = typeof(Resources.CommonViewModels))]
        [StringLength(
            100,
            ErrorMessageResourceName = "PasswordLengthErrMsg",
            ErrorMessageResourceType = typeof(Resources.CommonViewModels),
            MinimumLength = 8)]
        public string NewPassword { get; set; }

        /// <summary>
        /// Confirm new password
        /// 新しいパスワードの確認入力
        /// </summary>
        [Required(AllowEmptyStrings = false)]
        [DataType(DataType.Password)]
        [Display(
            Name = "ConfirmNewPassword",
            ResourceType = typeof(Resources.CommonViewModels))]
        [Compare(
            "NewPassword",
            ErrorMessageResourceName = "ConfirmNewPasswordErrMsg",
            ErrorMessageResourceType = typeof(Resources.CommonViewModels))]
        public string ConfirmPassword { get; set; }
    }
}