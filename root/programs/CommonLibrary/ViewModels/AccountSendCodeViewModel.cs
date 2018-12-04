//**********************************************************************************
//* テンプレート
//**********************************************************************************

// 以下のLicenseに従い、このProjectをTemplateとして使用可能です。Release時にCopyright表示してSublicenseして下さい。
// https://github.com/OpenTouryoProject/MultiPurposeAuthSite/blob/master/license/LicenseForTemplates.txt

//**********************************************************************************
//* クラス名        ：AccountSendCodeViewModel
//* クラス日本語名  ：2FA画面でコードの送信用のVM（テンプレート）
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
    /// <summary>2FA画面でコードの送信用のVM</summary>
    public class AccountSendCodeViewModel : BaseViewModel
    {
        /// <summary>SelectedProvider（選択されたプロバイダ）</summary>
        public string SelectedProvider { get; set; }

        /// <summary>Providers（プロバイダの選択肢）</summary>
        public ICollection<SelectListItem> Providers { get; set; }

        /// <summary>RememberMe（アカウント記憶）</summary>
        public bool RememberMe { get; set; }

        /// <summary>ReturnUrl</summary>
        public string ReturnUrl { get; set; }
    }
}
