//**********************************************************************************
//* テンプレート
//**********************************************************************************

// 以下のLicenseに従い、このProjectをTemplateとして使用可能です。Release時にCopyright表示してSublicenseして下さい。
// https://github.com/OpenTouryoProject/MultiPurposeAuthSite/blob/master/license/LicenseForTemplates.txt

//**********************************************************************************
//* クラス名        ：ManageAddUnstructuredDataViewModel
//* クラス日本語名  ：非構造化データ設定用のVM（テンプレート）
//*
//* 作成日時        ：－
//* 作成者          ：－
//* 更新履歴        ：－
//*
//*  日時        更新者            内容
//*  ----------  ----------------  -------------------------------------------------
//*  2017/06/05  西野 大介         新規
//**********************************************************************************

using Newtonsoft.Json;
using System.ComponentModel.DataAnnotations;

/// <summary>MultiPurposeAuthSite.Models.ViewModels</summary>
namespace MultiPurposeAuthSite.Models.ViewModels
{
    /// <summary>非構造化データ設定用のVM</summary>
    public class ManageAddUnstructuredDataViewModel : BaseViewModel
    {
        /// <summary>UnstructuredData1 (FirstName)</summary>
        [Required(AllowEmptyStrings = false)]
        [Display(Name = "UnstructuredData1", ResourceType = typeof(Resources.CommonViewModels))]
        [StringLength(
            512,
            ErrorMessageResourceName = "MaxLengthErrMsg",
            ErrorMessageResourceType = typeof(Resources.CommonViewModels))]
        [JsonProperty(PropertyName = "fname")]
        public string FirstName { get; set; }

        /// <summary>UnstructuredData2 (LastName)</summary>
        [Required(AllowEmptyStrings = false)]
        [Display(Name = "UnstructuredData2", ResourceType = typeof(Resources.CommonViewModels))]
        [StringLength(
            512,
            ErrorMessageResourceName = "MaxLengthErrMsg",
            ErrorMessageResourceType = typeof(Resources.CommonViewModels))]
        [JsonProperty(PropertyName = "lname")]
        public string LastName { get; set; }
    }
}