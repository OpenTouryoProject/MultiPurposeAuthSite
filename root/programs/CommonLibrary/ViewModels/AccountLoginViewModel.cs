//**********************************************************************************
//* テンプレート
//**********************************************************************************

// 以下のLicenseに従い、このProjectをTemplateとして使用可能です。Release時にCopyright表示してSublicenseして下さい。
// https://github.com/OpenTouryoProject/MultiPurposeAuthSite/blob/master/license/LicenseForTemplates.txt

//**********************************************************************************
//* クラス名        ：AccountLoginViewModel
//* クラス日本語名  ：サインイン画面用のVM（テンプレート）
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

/// <summary>MultiPurposeAuthSite.ViewModels</summary>
namespace MultiPurposeAuthSite.ViewModels
{
    /// <summary>サインイン画面用のVM</summary>
    public class AccountLoginViewModel : BaseViewModel
    {
        /// <summary>Name</summary>
        [Display(Name = "UserName", ResourceType = typeof(Resources.CommonViewModels))]
        // [StringLength( // 検証用なので不要
        public string Name { get; set; }

        /// <summary>E-mail（サインインでは「利用者名またはメアド」）</summary>
        /// <remarks>
        /// **メアド形式の検証（[EmailAddress]）を外した**（#151 の段階 3）。
        /// **この欄は利用者名も受ける**ので、メアド形式を強いると利用者名で入れなくなる
        /// （`ModelState` が不正になり、画面が出し戻される）。
        ///
        /// **どちらとして扱うかは `Const.LooksLikeEmail` が決める**（`@` を含むか）。
        /// **欄の名前は変えていない。** ビュー・リソース・E2E・ID 連携の `login_hint` に
        /// 波及するため、名前の整理は後の段階に回す。
        /// </remarks>
        [Display(Name = "UserNameOrEmail", ResourceType = typeof(Resources.CommonViewModels))]
        public string Email { get; set; }

        /// <summary>Password</summary>
        [DataType(DataType.Password)]
        [Display(Name = "Password", ResourceType = typeof(Resources.CommonViewModels))]
        // [StringLength( // 検証用なので不要
        public string Password { get; set; }

        /// <summary>RememberMe（アカウント記憶）</summary>
        [Display(Name = "RememberMe", ResourceType = typeof(Resources.CommonViewModels))]
        public bool RememberMe { get; set; }

        /// <summary>ReturnUrl</summary>
        public string ReturnUrl { get; set; }

        #region FIDO2
        /// <summary>Fido2Data</summary>
        public string Fido2Data { get; set; }

        /// <summary>SequenceNo</summary>
        public string SequenceNo { get; set; }
        #endregion
    }
}