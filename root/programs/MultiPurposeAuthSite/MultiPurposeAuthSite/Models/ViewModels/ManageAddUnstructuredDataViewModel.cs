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
        /// <summary>UnstructuredData1</summary>
        [Display(Name = "UnstructuredData1", ResourceType = typeof(Resources.CommonViewModels))]
        [JsonProperty(PropertyName = "usd1")]
        public string UnstructuredData1 { get; set; }

        [Display(Name = "UnstructuredData2", ResourceType = typeof(Resources.CommonViewModels))]
        [JsonProperty(PropertyName = "usd2")]
        public string UnstructuredData2 { get; set; }
    }
}