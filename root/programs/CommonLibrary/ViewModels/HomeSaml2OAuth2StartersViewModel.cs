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
//*  2026/09/28  玄人 幸道         prompt / max_age を画面から選べるようにした（#246 の項目 3）
//*  2026/10/06  玄人 幸道         promptの選択肢から「未対応」を外した（#272 の段階 2）
//*  2026/10/09  玄人 幸道         各オプションの説明を追加（#277 の段階 2）
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
        [Display(Name = "ClarifyRedirectUri", Description = "ClarifyRedirectUriDescription",
            ResourceType = typeof(Resources.CommonViewModels))]
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
        [Display(Name = "ClientType", Description = "ClientTypeDescription",
            ResourceType = typeof(Resources.CommonViewModels))]
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
                        Text = "PKCE 必須 (require_pkce) の Client (OAuth2.1)",
                        Value = HomeSaml2OAuth2StartersViewModel.RequirePkceClientType },                    
                    new SelectListItem() {
                        Text = "Device Authorization Grant用 Client",
                        Value = OAuth2AndOIDCEnum.ClientMode.device.ToStringByEmit() },
                    new SelectListItem() {
                        Text = "Financial-grade API - Part1用 Client",
                        Value = OAuth2AndOIDCEnum.ClientMode.fapi1.ToStringByEmit() },
                    new SelectListItem() {
                        Text = "Financial-grade API - Part2用 Client",
                        Value = OAuth2AndOIDCEnum.ClientMode.fapi2.ToStringByEmit() },
                    new SelectListItem() {
                        Text = "Financial-grade API - CIBA用 Client",
                        Value = OAuth2AndOIDCEnum.ClientMode.fapi_ciba.ToStringByEmit() },
                    new SelectListItem() {
                        Text = "ログイン・ユーザの Client",
                        Value = "login User" }
                };
            }
        }


        /// <summary>prompt（OIDC Core 3.1.2.1。#246 の項目 3）</summary>
        /// <remarks>
        /// **認可画面（同意）の出方を、画面から試せるようにするためにある。**
        ///
        /// | 値 | この実装の振る舞い |
        /// |---|---|
        /// | `none` | **UI を出さない。** 同意の記録が在れば code、無ければ `consent_required`（#272 の段階 2）。**他の値と併記すると `invalid_request`**（段階 1） |
        /// | `login` | **再認証を求める**（サインアウトして同じ URL に戻る。`max_age` の再認証と同じ経路） |
        /// | `consent` | **同意済みでも、必ず同意画面を出す** |
        /// | `select_account` | **同意画面を出す**（その画面に「別のアカウントでログイン」が在る）。**アカウントの一覧から選ぶ仕組みは持っていない** |
        ///
        /// **以前は `none` だけを扱っていた**（他の値は無視。`ANALYSIS-IdP.md` C-3）。
        /// </remarks>
        [Display(Name = "Prompt", Description = "PromptDescription",
            ResourceType = typeof(Resources.CommonViewModels))]
        public string Prompt { get; set; }

        /// <summary>promptアイテムリスト</summary>
        public List<SelectListItem> DdlPromptItems
        {
            get
            {
                return new List<SelectListItem>()
                {
                    new SelectListItem() { Text = "指定しない", Value = "" },
                    new SelectListItem() { Text = "none（UI を出さない）", Value = "none" },
                    new SelectListItem() { Text = "login（再認証）", Value = "login" },
                    new SelectListItem() { Text = "consent（再同意）", Value = "consent" },
                    new SelectListItem() { Text = "select_account（同意画面を出す）", Value = "select_account" }
                };
            }
        }

        /// <summary>max_age（OIDC Core 3.1.2.1。秒。#246 の項目 3）</summary>
        /// <remarks>
        /// **前回の認証からの経過時間の上限。** 超えていれば、OP は再認証を求めるべきもの。
        /// 画面から試せるようにして、**効き方を観測できる**ようにした。
        /// </remarks>
        [Display(Name = "MaxAge", Description = "MaxAgeDescription",
            ResourceType = typeof(Resources.CommonViewModels))]
        public string MaxAge { get; set; }

        /// <summary>max_ageアイテムリスト</summary>
        public List<SelectListItem> DdlMaxAgeItems
        {
            get
            {
                return new List<SelectListItem>()
                {
                    new SelectListItem() { Text = "指定しない", Value = "" },
                    new SelectListItem() { Text = "0（毎回、再認証）", Value = "0" },
                    new SelectListItem() { Text = "60（1 分）", Value = "60" },
                    new SelectListItem() { Text = "600（10 分。OIDC のボタンの既定）", Value = "600" }
                };
            }
        }
        /// <summary>ResponseMode</summary>
        [Display(Name = "ResponseMode", Description = "ResponseModeDescription",
            ResourceType = typeof(Resources.CommonViewModels))]
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