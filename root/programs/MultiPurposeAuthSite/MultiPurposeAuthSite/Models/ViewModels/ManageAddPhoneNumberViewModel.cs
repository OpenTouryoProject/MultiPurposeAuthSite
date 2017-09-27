//**********************************************************************************
//* テンプレート
//**********************************************************************************

// 以下のLicenseに従い、このProjectをTemplateとして使用可能です。Release時にCopyright表示してSublicenseして下さい。
// https://github.com/OpenTouryoProject/MultiPurposeAuthSite/blob/master/license/LicenseForTemplates.txt

//**********************************************************************************
//* クラス名        ：ManageAddPhoneNumberViewModel
//* クラス日本語名  ：電話番号の追加画面用のVM（テンプレート）
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
    /// <summary>電話番号の追加画面用のVM（テンプレート）</summary>
    public class ManageAddPhoneNumberViewModel : BaseViewModel
    {
        /// <summary>Phone Number（電話番号）</summary>
        [Required(AllowEmptyStrings = false)]
        [Phone]
        [Display(Name = "PhoneNumber", ResourceType =typeof(Resources.CommonViewModels))]
        public string Number { get; set; }
    }
}