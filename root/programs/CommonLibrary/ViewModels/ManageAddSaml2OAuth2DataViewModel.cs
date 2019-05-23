//**********************************************************************************
//* テンプレート
//**********************************************************************************

// 以下のLicenseに従い、このProjectをTemplateとして使用可能です。Release時にCopyright表示してSublicenseして下さい。
// https://github.com/OpenTouryoProject/MultiPurposeAuthSite/blob/master/license/LicenseForTemplates.txt

//**********************************************************************************
//* クラス名        ：ManageAddSaml2OAuth2DataViewModel
//* クラス日本語名  ：Saml2, OAuth2関連の非構造化データ設定用のVM（テンプレート）
//*
//* 作成日時        ：－
//* 作成者          ：－
//* 更新履歴        ：－
//*
//*  日時        更新者            内容
//*  ----------  ----------------  -------------------------------------------------
//*  2017/06/07  西野 大介         新規
//*  2019/05/2*  西野 大介         SAML2対応実施
//**********************************************************************************

using MultiPurposeAuthSite.Co;

#if NETFX
using System.Web.Mvc;
#elif NETCORE
using Microsoft.AspNetCore.Mvc.Rendering;
#endif

using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;

using Newtonsoft.Json;

using Touryo.Infrastructure.Framework.Authentication;
using Touryo.Infrastructure.Public.FastReflection;

/// <summary>MultiPurposeAuthSite.ViewModels</summary>
namespace MultiPurposeAuthSite.ViewModels
{
    /// <summary>Saml2, OAuth2関連の非構造化データ設定用のVM</summary>
    public class ManageAddSaml2OAuth2DataViewModel : BaseViewModel
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

        /// <summary>RedirectUriSaml</summary>
        [Display(Name = "RedirectUriSaml", ResourceType = typeof(Resources.CommonViewModels))]
        //[Url] localhost や IPアドレスが入力できない。
        [StringLength(
            Const.MaxLengthOfUri,
            ErrorMessageResourceName = "MaxLengthErrMsg",
            ErrorMessageResourceType = typeof(Resources.CommonViewModels))]
        [JsonProperty(PropertyName = "redirect_uri_saml")]
        public string RedirectUriSaml { get; set; }

        /// <summary>RedirectUriCode</summary>
        [Display(Name = "RedirectUriCode", ResourceType = typeof(Resources.CommonViewModels))]
        //[Url] localhost や IPアドレスが入力できない。
        [StringLength(
            Const.MaxLengthOfUri,
            ErrorMessageResourceName = "MaxLengthErrMsg",
            ErrorMessageResourceType = typeof(Resources.CommonViewModels))]
        [JsonProperty(PropertyName = "redirect_uri_code")]
        public string RedirectUriCode { get; set; }

        /// <summary>RedirectUriToken</summary>
        [Display(Name = "RedirectUriToken", ResourceType = typeof(Resources.CommonViewModels))]
        //[Url] localhost や IPアドレスが入力できない。
        [StringLength(
            Const.MaxLengthOfUri,
            ErrorMessageResourceName = "MaxLengthErrMsg",
            ErrorMessageResourceType = typeof(Resources.CommonViewModels))]
        [JsonProperty(PropertyName = "redirect_uri_token")]
        public string RedirectUriToken { get; set; }

        /// <summary>JwkRsaPublickey</summary>
        [Display(Name = "JwkRsaPublickey", ResourceType = typeof(Resources.CommonViewModels))]
        [JsonProperty(PropertyName = "jwk_rsa_publickey")]
        public string JwkRsaPublickey { get; set; }

        /// <summary>TlsClientAuthSubjectDn</summary>
        [Display(Name = "TlsClientAuthSubjectDn", ResourceType = typeof(Resources.CommonViewModels))]
        [JsonProperty(PropertyName = "tls_client_auth_subject_dn")]
        public string TlsClientAuthSubjectDn { get; set; }

        /// <summary>ClientMode</summary>
        [Display(Name = "ClientMode", ResourceType = typeof(Resources.CommonViewModels))]
        [JsonProperty(PropertyName = "oauth2_oidc_mode")]
        public string ClientMode { get; set; }

        /// <summary>ClientModeアイテムリスト</summary>
        public List<SelectListItem> DdlClientModeItems
        {
            get
            {
                return new List<SelectListItem>()
                {
                    new SelectListItem() {
                        Text = "Saml2, OAuth2.0 / OIDC",
                        Value = OAuth2AndOIDCEnum.ClientMode.normal.ToStringByEmit() },
                    new SelectListItem() {
                        Text = "Financial-grade API - Part1",
                        Value = OAuth2AndOIDCEnum.ClientMode.fapi1.ToStringByEmit() },
                    new SelectListItem() {
                        Text = "Financial-grade API - Part2",
                        Value = OAuth2AndOIDCEnum.ClientMode.fapi2.ToStringByEmit() }
                };
            }
        }

        /// <summary>ClientName</summary>
        [Display(Name = "ClientName", ResourceType = typeof(Resources.CommonViewModels))]
        [StringLength(
            Const.MaxLengthOfClientName,
            ErrorMessageResourceName = "MaxLengthErrMsg",
            ErrorMessageResourceType = typeof(Resources.CommonViewModels))]
        [JsonProperty(PropertyName = OAuth2AndOIDCConst.sub)]
        public string ClientName { get; set; }
    }
}