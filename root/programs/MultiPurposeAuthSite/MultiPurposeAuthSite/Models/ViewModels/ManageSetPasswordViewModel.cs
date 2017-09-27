//**********************************************************************************
//* テンプレート
//**********************************************************************************

// 以下のLicenseに従い、このProjectをTemplateとして使用可能です。Release時にCopyright表示してSublicenseして下さい。
// https://github.com/OpenTouryoProject/MultiPurposeAuthSite/blob/master/license/LicenseForTemplates.txt

//**********************************************************************************
//* クラス名        ：ManageSetPasswordViewModel
//* クラス日本語名  ：パスワード設定用のVM（テンプレート）
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
using MultiPurposeAuthSite.Models.ASPNETIdentity;

/// <summary>MultiPurposeAuthSite.Models.ViewModels</summary>
namespace MultiPurposeAuthSite.Models.ViewModels
{
    /// <summary>パスワード設定用のVM</summary>
    public class ManageSetPasswordViewModel : BaseViewModel
    {
        /// <summary>NewPassword</summary>
        [Required(AllowEmptyStrings = false)]
        [DataType(DataType.Password)]
        [Display(
            Name = "NewPassword",
            ResourceType = typeof(Resources.CommonViewModels))]
        [StringLength(
            ASPNETIdentityConst.MaxLengthOfPassword,
            ErrorMessageResourceName = "MaxLengthErrMsg",
            ErrorMessageResourceType = typeof(Resources.CommonViewModels))]
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