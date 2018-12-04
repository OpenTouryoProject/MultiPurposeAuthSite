//**********************************************************************************
//* テンプレート
//**********************************************************************************

// 以下のLicenseに従い、このProjectをTemplateとして使用可能です。Release時にCopyright表示してSublicenseして下さい。
// https://github.com/OpenTouryoProject/MultiPurposeAuthSite/blob/master/license/LicenseForTemplates.txt

//**********************************************************************************
//* クラス名        ：ManageAddPaymentInformationViewModel
//* クラス日本語名  ：支払元情報設定用のVM（テンプレート）
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
    /// <summary>支払元情報設定用のVM</summary>
    public class ManageAddPaymentInformationViewModel : BaseViewModel
    {
        /// <summary>PaymentInformation</summary>
        [Required(AllowEmptyStrings = false)]
        [Display(Name = "PaymentInformation", ResourceType = typeof(Resources.CommonViewModels))]
        public string PaymentInformation { get; set; }
    }
}