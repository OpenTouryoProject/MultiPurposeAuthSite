﻿//**********************************************************************************
//* テンプレート
//**********************************************************************************

// 以下のLicenseに従い、このProjectをTemplateとして使用可能です。Release時にCopyright表示してSublicenseして下さい。
// https://github.com/OpenTouryoProject/MultiPurposeAuthSite/blob/master/license/LicenseForTemplates.txt

//**********************************************************************************
//* クラス名        ：ManageIndexViewModel
//* クラス日本語名  ：ManageIndexViewModel（テンプレート）
//*
//* 作成日時        ：－
//* 作成者          ：－
//* 更新履歴        ：－
//*
//*  日時        更新者            内容
//*  ----------  ----------------  -------------------------------------------------
//*  2017/04/24  西野 大介         新規
//*  2019/05/2*  西野 大介         SAML2対応実施
//**********************************************************************************

using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;

#if NETFX
using Microsoft.AspNet.Identity;
#else
using Microsoft.AspNetCore.Identity;
#endif

/// <summary>MultiPurposeAuthSite.ViewModels</summary>
namespace MultiPurposeAuthSite.ViewModels
{
    /// <summary>ManageIndexViewModel</summary>
    public class ManageIndexViewModel : BaseViewModel
    {
        /// <summary>HasPassword（パスワードの有無）</summary>
        public bool HasPassword { get; set; }

        /// <summary>Logins（外部ログイン）</summary>
        public IList<UserLoginInfo> Logins { get; set; }

        /// <summary>E-mail</summary>
        [EmailAddress]
        public string Email { get; set; }

        /// <summary>PhoneNumber（電話番号）</summary>
        public string PhoneNumber { get; set; }

        /// <summary>TwoFactorAuthentication(2FA)</summary>
        public bool TwoFactor { get; set; }

#if NETFX
#else
        /// <summary>TOTP TwoFactorAuthentication(2FA)</summary>
        public bool TwoFactorTOTP { get; set; }
#endif

        /// <summary>HasPaymentInformation（支払元情報の有無）</summary>
        public bool HasPaymentInformation { get; set; }

        /// <summary>HasUnstructuredData（非構造化データの有無）</summary>
        public bool HasUnstructuredData { get; set; }

        /// <summary>HasSaml2OAuth2Data</summary>
        public bool HasSaml2OAuth2Data { get; set; }

        /// <summary>HasFIDO2Data</summary>
        public bool HasFIDO2Data { get; set; }

        /// <summary>Scopes</summary>
        public string Scopes { get; set; }
    }
}