//**********************************************************************************
//* テンプレート
//**********************************************************************************

// 以下のLicenseに従い、このProjectをTemplateとして使用可能です。Release時にCopyright表示してSublicenseして下さい。
// https://github.com/OpenTouryoProject/MultiPurposeAuthSite/blob/master/license/LicenseForTemplates.txt

//**********************************************************************************
//* クラス名        ：HomeOAuth2StartersViewModel
//* クラス日本語名  ：Home > OAuth2StartersのVM（テンプレート）
//*
//* 作成日時        ：－
//* 作成者          ：－
//* 更新履歴        ：－
//*
//*  日時        更新者            内容
//*  ----------  ----------------  -------------------------------------------------
//*  2019/02/16  西野 大介         新規
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
    /// <summary>Home > OAuth2StartersのVM</summary>
    public class HomeOAuth2StartersViewModel : BaseViewModel
    {
        /// <summary>ClientType</summary>
        [Display(Name = "ClientType", ResourceType = typeof(Resources.CommonViewModels))]
        public string ClientType { get; set; }

        /// <summary>ClientTypeアイテムリスト</summary>
        public List<SelectListItem> DdlClientTypeItems
        {
            get
            {
                return new List<SelectListItem>()
                {
                    new SelectListItem() {
                        Text = "OAuth2.0 / OIDC用 Client",
                        Value = OAuth2AndOIDCEnum.ClientMode.normal.ToString1() },
                    new SelectListItem() {
                        Text = "Financial-grade API - Part1用 Client",
                        Value = OAuth2AndOIDCEnum.ClientMode.fapi1.ToString1() },
                    new SelectListItem() {
                        Text = "Financial-grade API - Part2用 Client",
                        Value = OAuth2AndOIDCEnum.ClientMode.fapi2.ToString1() },
                    new SelectListItem() {
                        Text = "ログイン・ユーザの Client",
                        Value = "login User" }
                };
            }
        }
    }
}