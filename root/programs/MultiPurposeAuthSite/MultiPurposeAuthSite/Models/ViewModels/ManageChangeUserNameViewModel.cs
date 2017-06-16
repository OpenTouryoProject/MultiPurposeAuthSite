//**********************************************************************************
//* テンプレート
//**********************************************************************************

// 以下のLicenseに従い、このProjectをTemplateとして使用可能です。Release時にCopyright表示してSublicenseして下さい。
// https://github.com/OpenTouryoProject/MultiPurposeAuthSite/blob/master/license/LicenseForTemplates.txt

//**********************************************************************************
//* クラス名        ：ManageChangeUserNameViewModel
//* クラス日本語名  ：UserNameの編集画面用のVM（テンプレート）
//*
//* 作成日時        ：－
//* 作成者          ：－
//* 更新履歴        ：－
//*
//*  日時        更新者            内容
//*  ----------  ----------------  -------------------------------------------------
//*  2017/06/05  西野 大介         新規
//**********************************************************************************

using System.ComponentModel.DataAnnotations;

/// <summary>MultiPurposeAuthSite.Models.ViewModels</summary>
namespace MultiPurposeAuthSite.Models.ViewModels
{
    /// <summary>UserNameの編集画面用のVM（テンプレート）</summary>
    public class ManageChangeUserNameViewModel : BaseViewModel
    {
        /// <summary>UserName</summary>
        [Required(AllowEmptyStrings = false)]
        [Display(Name = "NewUserName", ResourceType =typeof(Resources.CommonViewModels))]
        public string UserNameForEdit { get; set; }

        /// <summary>Password</summary>
        [Required(AllowEmptyStrings = true)]
        [DataType(DataType.Password)]
        [Display(Name = "Password", ResourceType = typeof(Resources.CommonViewModels))]
        public string Password { get; set; }
    }
}