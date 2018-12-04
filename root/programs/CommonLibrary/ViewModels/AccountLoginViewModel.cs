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

/// <summary>MultiPurposeAuthSite.ViewModels</summary>
namespace MultiPurposeAuthSite.ViewModels
{
    /// <summary>サインイン画面用のVM</summary>
    public class AccountLoginViewModel : BaseViewModel
    {
        /// <summary>Name</summary>
        [Display(Name = "UserName", ResourceType = typeof(Resources.CommonViewModels))]
        // [StringLength( // 検証用なので不要
        public string Name { get; set; }

        /// <summary>E-mail</summary>
        [EmailAddress]
        [Display(Name = "Email", ResourceType = typeof(Resources.CommonViewModels))]
        public string Email { get; set; }

        /// <summary>Password</summary>
        [DataType(DataType.Password)]
        [Display(Name = "Password", ResourceType = typeof(Resources.CommonViewModels))]
        // [StringLength( // 検証用なので不要
        public string Password { get; set; }

        /// <summary>RememberMe（アカウント記憶）</summary>
        [Display(Name = "RememberMe", ResourceType = typeof(Resources.CommonViewModels))]
        public bool RememberMe { get; set; }

        /// <summary>ReturnUrl</summary>
        public string ReturnUrl { get; set; }

        #region FIDO2

        /// <summary>Fido2Challenge</summary>
        public string Fido2Challenge { get; set; }

        /// <summary>Fido2UserId</summary>
        public string Fido2UserId { get; set; }

        /// <summary>Fido2Signature</summary>
        public string Fido2Signature { get; set; }

        /// <summary>Fido2AuthenticatorData</summary>
        public string Fido2AuthenticatorData { get; set; }

        /// <summary>Fido2ClientData</summary>
        public string Fido2ClientData { get; set; }

        #endregion
    }
}