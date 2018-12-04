//**********************************************************************************
//* テンプレート
//**********************************************************************************

// 以下のLicenseに従い、このProjectをTemplateとして使用可能です。Release時にCopyright表示してSublicenseして下さい。
// https://github.com/OpenTouryoProject/MultiPurposeAuthSite/blob/master/license/LicenseForTemplates.txt

//**********************************************************************************
//* クラス名        ：AccountVerifyCodeViewModel
//* クラス日本語名  ：2FA画面でコードの検証用のVM（テンプレート）
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

/// <summary>MultiPurposeAuthSite.Models.ViewModels</summary>
namespace MultiPurposeAuthSite.Models.ViewModels
{
    /// <summary>2FA画面でコードの検証用のVM</summary>
    public class AccountVerifyCodeViewModel : BaseViewModel
    {
        /// <summary>Provider</summary>
        [Required(AllowEmptyStrings = false)]
        public string Provider { get; set; }

        /// <summary>Code</summary>
        [Required(AllowEmptyStrings = false)]
        [Display(Name = "Code")]
        public string Code { get; set; }

        /// <summary>ReturnUrl</summary>
        public string ReturnUrl { get; set; }

        /// <summary>RememberMe（アカウント記憶）</summary>
        [Display(Name = "RememberMe", ResourceType = typeof(Resources.CommonViewModels))]
        public bool RememberMe { get; set; }

        /// <summary>RememberBrowser（ブラウザ記憶(2FA)）</summary>
        [Display(Name = "RememberBrowser", ResourceType = typeof(Resources.CommonViewModels))]
        public bool RememberBrowser { get; set; }
    }
}