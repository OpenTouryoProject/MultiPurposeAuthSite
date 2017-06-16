//**********************************************************************************
//* テンプレート
//**********************************************************************************

// 以下のLicenseに従い、このProjectをTemplateとして使用可能です。Release時にCopyright表示してSublicenseして下さい。
// https://github.com/OpenTouryoProject/MultiPurposeAuthSite/blob/master/license/LicenseForTemplates.txt

//**********************************************************************************
//* クラス名        ：AccountLoginViewModel
//* クラス日本語名  ：サインイン画面用のVM（テンプレート）
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
    /// <summary>サインイン画面用のVM</summary>
    public class AccountLoginViewModel : BaseViewModel
    {
        /// <summary>Name</summary>
        [Display(Name = "UserName", ResourceType = typeof(Resources.CommonViewModels))]
        public string Name { get; set; }

        /// <summary>E-mail</summary>
        [EmailAddress]
        [Display(Name = "Email", ResourceType = typeof(Resources.CommonViewModels))]
        public string Email { get; set; }

        /// <summary>Password</summary>
        [Required(AllowEmptyStrings = false)]
        [DataType(DataType.Password)]
        [Display(Name = "Password", ResourceType = typeof(Resources.CommonViewModels))]
        public string Password { get; set; }

        /// <summary>RememberMe（アカウント記憶）</summary>
        [Display(Name = "RememberMe", ResourceType = typeof(Resources.CommonViewModels))]
        public bool RememberMe { get; set; }
    }
}