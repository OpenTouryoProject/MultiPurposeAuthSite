//**********************************************************************************
//* テンプレート
//**********************************************************************************

// 以下のLicenseに従い、このProjectをTemplateとして使用可能です。Release時にCopyright表示してSublicenseして下さい。
// https://github.com/OpenTouryoProject/MultiPurposeAuthSite/blob/master/license/LicenseForTemplates.txt

//**********************************************************************************
//* クラス名        ：AccountAgreementViewModel
//* クラス日本語名  ：約款画面用のVM（テンプレート）
//*
//* 作成日時        ：－
//* 作成者          ：－
//* 更新履歴        ：－
//*
//*  日時        更新者            内容
//*  ----------  ----------------  -------------------------------------------------
//*  2017/04/24  西野 大介         新規
//**********************************************************************************

using System.ComponentModel.DataAnnotations;
using MultiPurposeAuthSite.Models.ASPNETIdentity;

/// <summary>MultiPurposeAuthSite.Models.ViewModels</summary>
namespace MultiPurposeAuthSite.Models.ViewModels
{
    /// <summary>サインアップ画面用のVM（テンプレート）</summary>
    public class AccountAgreementViewModel : BaseViewModel
    {
        /// <summary>ユーザID</summary>
        [Required(AllowEmptyStrings = true)]
        // [StringLength( // ユーザ入力でないので不要
        public string UserId { get; set; }

        /// <summary>Code</summary>
        [Required(AllowEmptyStrings = true)]
        // [StringLength( // ユーザ入力でないので不要
        public string Code { get; set; }

        /// <summary>約款本文</summary>
        [Display(Name = "Agreement", ResourceType = typeof(Resources.AccountViews))]
        public string Agreement { get; set; }

        /// <summary>約款画面で同意したかどうか</summary>
        [Display(Name = "AgreementCheck", ResourceType = typeof(Resources.AccountViews))]
        public bool AcceptedAgreement { get; set; }

        /// <summary>招待機能</summary>
        public string ReturnUrl { get; set; }
    }
}