//**********************************************************************************
//* テンプレート
//**********************************************************************************

// 以下のLicenseに従い、このProjectをTemplateとして使用可能です。Release時にCopyright表示してSublicenseして下さい。
// https://github.com/OpenTouryoProject/MultiPurposeAuthSite/blob/master/license/LicenseForTemplates.txt

//**********************************************************************************
//* クラス名        ：ManageAddOAuth2DataViewModel
//* クラス日本語名  ：OAuth2関連の非構造化データ設定用のVM（テンプレート）
//*
//* 作成日時        ：－
//* 作成者          ：－
//* 更新履歴        ：－
//*
//*  日時        更新者            内容
//*  ----------  ----------------  -------------------------------------------------
//*  2017/06/07  西野 大介         新規
//**********************************************************************************

using Newtonsoft.Json;
using System.ComponentModel.DataAnnotations;
using MultiPurposeAuthSite.Models.ASPNETIdentity;

/// <summary>MultiPurposeAuthSite.Models.ViewModels</summary>
namespace MultiPurposeAuthSite.Models.ViewModels
{
    /// <summary>OAuth2関連の非構造化データ設定用のVM</summary>
    public class ManageAddOAuth2DataViewModel : BaseViewModel
    {
        /// <summary>ClientID</summary>
        [Display(Name = "ClientID", ResourceType = typeof(Resources.CommonViewModels))]
        // [StringLength( // ユーザ入力でないので不要
        [JsonIgnore] // これはJsonConvertしない。
        public string ClientID { get; set; }

        /// <summary>ClientSecret</summary>
        [Display(Name = "ClientSecret", ResourceType = typeof(Resources.CommonViewModels))]
        // [StringLength( // ユーザ入力でないので不要
        [JsonProperty(PropertyName = "client_secret")]
        public string ClientSecret { get; set; }

        /// <summary>RedirectUriCode</summary>
        [Display(Name = "RedirectUriCode", ResourceType = typeof(Resources.CommonViewModels))]
        [StringLength(
            ASPNETIdentityConst.MaxLengthOfUri,
            ErrorMessageResourceName = "MaxLengthErrMsg",
            ErrorMessageResourceType = typeof(Resources.CommonViewModels))]
        [JsonProperty(PropertyName = "redirect_uri_code")]
        public string RedirectUriCode { get; set; }

        /// <summary>RedirectUriToken</summary>
        [Display(Name = "RedirectUriToken", ResourceType = typeof(Resources.CommonViewModels))]
        [StringLength(
            ASPNETIdentityConst.MaxLengthOfUri,
            ErrorMessageResourceName = "MaxLengthErrMsg",
            ErrorMessageResourceType = typeof(Resources.CommonViewModels))]
        [JsonProperty(PropertyName = "redirect_uri_token")]
        public string RedirectUriToken { get; set; }

        /// <summary>ClientName</summary>
        [Display(Name = "ClientName", ResourceType = typeof(Resources.CommonViewModels))]
        [StringLength(
            ASPNETIdentityConst.MaxLengthOfClientName,
            ErrorMessageResourceName = "MaxLengthErrMsg",
            ErrorMessageResourceType = typeof(Resources.CommonViewModels))]
        [JsonProperty(PropertyName = "sub")]
        public string ClientName { get; set; }
    }
}