//**********************************************************************************
//* テンプレート
//**********************************************************************************

// 以下のLicenseに従い、このProjectをTemplateとして使用可能です。Release時にCopyright表示してSublicenseして下さい。
// https://github.com/OpenTouryoProject/MultiPurposeAuthSite/blob/master/license/LicenseForTemplates.txt

//**********************************************************************************
//* クラス名        ：ManageConfigureTwoFactorViewModel
//* クラス日本語名  ：2FA設定画面用のVM（テンプレート）
//*
//* 作成日時        ：－
//* 作成者          ：－
//* 更新履歴        ：－
//*
//*  日時        更新者            内容
//*  ----------  ----------------  -------------------------------------------------
//*  2017/04/24  西野 大介         新規
//**********************************************************************************

using System.Collections.Generic;

#if NETFX
using System.Web.Mvc;
#else
using Microsoft.AspNetCore.Mvc.Rendering;
#endif

/// <summary>MultiPurposeAuthSite.Models.ViewModels</summary>
namespace MultiPurposeAuthSite.Models.ViewModels
{
    /// <summary>2FA設定画面用のVM（テンプレート）</summary>
    public class ManageConfigureTwoFactorViewModel : BaseViewModel
    {
        /// <summary>SelectedProvider（選択された2FA設定のprovider）</summary>
        public string SelectedProvider { get; set; }

        /// <summary>2FA設定のproviderの選択肢（Providers）</summary>
        public ICollection<SelectListItem> Providers { get; set; }
    }
}