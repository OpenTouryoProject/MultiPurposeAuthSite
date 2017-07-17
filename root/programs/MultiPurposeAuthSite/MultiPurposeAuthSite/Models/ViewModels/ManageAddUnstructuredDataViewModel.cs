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
using MultiPurposeAuthSite.Models.ASPNETIdentity;

/// <summary>MultiPurposeAuthSite.Models.ViewModels</summary>
namespace MultiPurposeAuthSite.Models.ViewModels
{
    /// <summary>非構造化データ設定用のVM</summary>
    public class ManageAddUnstructuredDataViewModel : BaseViewModel
    {
        #region 英語名
        /// <summary>FirstName</summary>
        [Required(AllowEmptyStrings = false)]
        [Display(Name = "FirstName", ResourceType = typeof(Resources.CommonViewModels))]
        [StringLength(
            ASPNETIdentityConst.MaxLengthOfFirstName,
            ErrorMessageResourceName = "MaxLengthErrMsg",
            ErrorMessageResourceType = typeof(Resources.CommonViewModels))]
        [RegularExpression(
            @"[a-zA-Z]+",
            ErrorMessageResourceName = "HalfWidthAlphabetLettersOnlyErrMsg",
            ErrorMessageResourceType = typeof(Resources.CommonViewModels))]
        [JsonProperty(PropertyName = "fname")]
        public string FirstName { get; set; }

        /// <summary>LastName</summary>
        [Required(AllowEmptyStrings = false)]
        [Display(Name = "LastName", ResourceType = typeof(Resources.CommonViewModels))]
        [StringLength(
            ASPNETIdentityConst.MaxLengthOfLastName,
            ErrorMessageResourceName = "MaxLengthErrMsg",
            ErrorMessageResourceType = typeof(Resources.CommonViewModels))]
        [RegularExpression(
            @"[a-zA-Z]+",
            ErrorMessageResourceName = "HalfWidthAlphabetLettersOnlyErrMsg",
            ErrorMessageResourceType = typeof(Resources.CommonViewModels))]
        [JsonProperty(PropertyName = "lname")]
        public string LastName { get; set; }
        #endregion

        #region 日本語名
        /// <summary>Sei</summary>
        [Required(AllowEmptyStrings = false)]
        [Display(Name = "Sei", ResourceType = typeof(Resources.CommonViewModels))]
        [StringLength(
            ASPNETIdentityConst.MaxLengthOfSei,
            ErrorMessageResourceName = "MaxLengthErrMsg",
            ErrorMessageResourceType = typeof(Resources.CommonViewModels))]
        [RegularExpression(
            @"[^ -~｡-ﾟ]+",
            ErrorMessageResourceName = "FullWidthLettersOnlyErrMsg",
            ErrorMessageResourceType = typeof(Resources.CommonViewModels))]
        [JsonProperty(PropertyName = "sei")]
        public string Sei { get; set; }

        /// <summary>Mei</summary>
        [Required(AllowEmptyStrings = false)]
        [Display(Name = "Mei", ResourceType = typeof(Resources.CommonViewModels))]
        [StringLength(
            ASPNETIdentityConst.MaxLengthOfMei,
            ErrorMessageResourceName = "MaxLengthErrMsg",
            ErrorMessageResourceType = typeof(Resources.CommonViewModels))]
        [RegularExpression(
            @"[^ -~｡-ﾟ]+",
            ErrorMessageResourceName = "FullWidthLettersOnlyErrMsg",
            ErrorMessageResourceType = typeof(Resources.CommonViewModels))]
        [JsonProperty(PropertyName = "mei")]
        public string Mei { get; set; }
        #endregion

        #region その他
        /// <summary>CompanyName</summary>
        [Required(AllowEmptyStrings = false)]
        [Display(Name = "CompanyName", ResourceType = typeof(Resources.CommonViewModels))]
        [StringLength(
            ASPNETIdentityConst.MaxLengthOfCompanyName,
            ErrorMessageResourceName = "MaxLengthErrMsg",
            ErrorMessageResourceType = typeof(Resources.CommonViewModels))]
        [JsonProperty(PropertyName = "company")]
        public string CompanyName { get; set; }

        /// <summary>Industry</summary>
        [Required(AllowEmptyStrings = false)]
        [Display(Name = "Industry", ResourceType = typeof(Resources.CommonViewModels))]
        [StringLength(
            8,
            ErrorMessageResourceName = "MaxLengthErrMsg",
            ErrorMessageResourceType = typeof(Resources.CommonViewModels))]
        [JsonProperty(PropertyName = "industry")]
        public string Industry { get; set; }

        /// <summary>CountryName</summary>
        [Required(AllowEmptyStrings = false)]
        [Display(Name = "CountryName", ResourceType = typeof(Resources.CommonViewModels))]
        [StringLength(
            8,
            ErrorMessageResourceName = "MaxLengthErrMsg",
            ErrorMessageResourceType = typeof(Resources.CommonViewModels))]
        [JsonProperty(PropertyName = "country")]
        public string CountryName { get; set; }
        #endregion

        #region 制御用
        
        /// <summary>確認表示モード</summary>
        public bool ConfirmationDisplay { get; set; }

        #endregion
    }
}