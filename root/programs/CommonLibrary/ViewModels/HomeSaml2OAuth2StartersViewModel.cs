//**********************************************************************************
//* テンプレート
//**********************************************************************************

// 以下のLicenseに従い、このProjectをTemplateとして使用可能です。Release時にCopyright表示してSublicenseして下さい。
// https://github.com/OpenTouryoProject/MultiPurposeAuthSite/blob/master/license/LicenseForTemplates.txt

//**********************************************************************************
//* クラス名        ：HomeSaml2OAuth2StartersViewModel
//* クラス日本語名  ：Home > Saml2OAuth2StartersのVM（テンプレート）
//*
//* 作成日時        ：－
//* 作成者          ：－
//* 更新履歴        ：－
//*
//*  日時        更新者            内容
//*  ----------  ----------------  -------------------------------------------------
//*  2019/02/16  西野 大介         新規
//*  2019/05/2*  西野 大介         SAML2対応実施
//*  2020/12/21  西野 大介         Enum追加対応実施
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
    /// <summary>Home > Saml2OAuth2StartersのVM</summary>
    public class HomeSaml2OAuth2StartersViewModel : BaseViewModel
    {
        /// <summary>ClarifyRedirectUri</summary>
        [Display(Name = "ClarifyRedirectUri", ResourceType = typeof(Resources.CommonViewModels))]
        public bool ClarifyRedirectUri { get; set; }

        /// <summary>
        /// クライアント単位で PKCE を必須にした Client を選ぶときの値（#221）
        /// </summary>
        /// <remarks>
        /// **ClientMode（列挙型）ではない。** require_pkce は登録の 1 項目であって、
        /// クライアントの種別ではないため。"login User" と同じく、文字列で持つ。
        /// </remarks>
        public const string RequirePkceClientType = "require_pkce";

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
                        Text = "Saml2 / OAuth2.0 / OIDC用 Client",
                        Value = OAuth2AndOIDCEnum.ClientMode.normal.ToStringByEmit() },
                    new SelectListItem() {
                        Text = "Financial-grade API - Part1用 Client",
                        Value = OAuth2AndOIDCEnum.ClientMode.fapi1.ToStringByEmit() },
                    new SelectListItem() {
                        Text = "Financial-grade API - Part2用 Client",
                        Value = OAuth2AndOIDCEnum.ClientMode.fapi2.ToStringByEmit() },
                    new SelectListItem() {
                        Text = "Device Authorization Grant用 Client",
                        Value = OAuth2AndOIDCEnum.ClientMode.device.ToStringByEmit() },
                    new SelectListItem() {
                        Text = "Financial-grade API - CIBA用 Client",
                        Value = OAuth2AndOIDCEnum.ClientMode.fapi_ciba.ToStringByEmit() },
                    // **クライアント単位で PKCE を必須にした Client（#221）。**
                    //   ClientMode（列挙型）ではないので、値は文字列で持つ（"login User" と同じ扱い）。
                    //   これを選ぶと、**下のボタンはどれも TestClient6 で動く。**
                    //   PKCE を付けないフローは invalid_request になる（それが正しい）。
                    new SelectListItem() {
                        Text = "クライアント単位で PKCE 必須の Client (require_pkce)",
                        Value = HomeSaml2OAuth2StartersViewModel.RequirePkceClientType },
                    new SelectListItem() {
                        Text = "ログイン・ユーザの Client",
                        Value = "login User" }
                };
            }
        }

        /// <summary>ResponseMode</summary>
        [Display(Name = "ResponseMode", ResourceType = typeof(Resources.CommonViewModels))]
        public string ResponseMode { get; set; }

        /// <summary>ResponseModeアイテムリスト</summary>
        public List<SelectListItem> DdlResponseModeItems
        {
            get
            {
                return new List<SelectListItem>()
                {
                    new SelectListItem() {
                        Text = "default",
                        Value = "" },
                    new SelectListItem() {
                        Text = OAuth2AndOIDCEnum.ResponseMode.query.ToStringByEmit(),
                        Value = OAuth2AndOIDCEnum.ResponseMode.query.ToStringByEmit() },
                    new SelectListItem() {
                        Text = OAuth2AndOIDCEnum.ResponseMode.fragment.ToStringByEmit(),
                        Value = OAuth2AndOIDCEnum.ResponseMode.fragment.ToStringByEmit() },
                    new SelectListItem() {
                        Text = OAuth2AndOIDCEnum.ResponseMode.form_post.ToStringByEmit(),
                        Value = OAuth2AndOIDCEnum.ResponseMode.form_post.ToStringByEmit() },
                                        new SelectListItem() {
                        Text = OAuth2AndOIDCEnum.ResponseMode.query_jwt.ToStringByEmit(),
                        Value = OAuth2AndOIDCEnum.ResponseMode.query_jwt.ToStringByEmit() },
                    new SelectListItem() {
                        Text = OAuth2AndOIDCEnum.ResponseMode.fragment_jwt.ToStringByEmit(),
                        Value = OAuth2AndOIDCEnum.ResponseMode.fragment_jwt.ToStringByEmit() },
                    new SelectListItem() {
                        Text = OAuth2AndOIDCEnum.ResponseMode.form_post_jwt.ToStringByEmit(),
                        Value = OAuth2AndOIDCEnum.ResponseMode.form_post_jwt.ToStringByEmit() }
                };
            }
        }
    }
}