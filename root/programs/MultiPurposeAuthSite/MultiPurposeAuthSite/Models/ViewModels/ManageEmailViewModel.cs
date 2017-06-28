//**********************************************************************************
//* テンプレート
//**********************************************************************************

// 以下のLicenseに従い、このProjectをTemplateとして使用可能です。Release時にCopyright表示してSublicenseして下さい。
// https://github.com/OpenTouryoProject/MultiPurposeAuthSite/blob/master/license/LicenseForTemplates.txt

//**********************************************************************************
//* クラス名        ：ManageEmailViewModel
//* クラス日本語名  ：E-mailの追加・編集画面用のVM（テンプレート）
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
    /// <summary>E-mailの追加・編集画面用のVM（テンプレート）</summary>
    public class ManageEmailViewModel : BaseViewModel
    {
        /// <summary>E-mail</summary>
        [Required(AllowEmptyStrings = false)]
        [EmailAddress]
        [Display(Name = "NewEmail", ResourceType =typeof(Resources.CommonViewModels))]
        public string Email { get; set; }

        /// <summary>Password</summary>
        [Required(AllowEmptyStrings = true)]
        [DataType(DataType.Password)]
        [Display(Name = "Password", ResourceType = typeof(Resources.CommonViewModels))]
        // [StringLength( // 検証用なので不要
        public string Password { get; set; }

        /// <summary>UnstructuredData1 (FirstName)</summary>
        [Required(AllowEmptyStrings = false)]
        [Display(Name = "UnstructuredData1", ResourceType = typeof(Resources.CommonViewModels))]
        [StringLength(
            ASPNETIdentityConst.MaxLengthOfFirstName,
            ErrorMessageResourceName = "MaxLengthErrMsg",
            ErrorMessageResourceType = typeof(Resources.CommonViewModels))]
        public string FirstName { get; set; }

        /// <summary>UnstructuredData2 (LastName)</summary>
        [Required(AllowEmptyStrings = false)]
        [Display(Name = "UnstructuredData2", ResourceType = typeof(Resources.CommonViewModels))]
        [StringLength(
            ASPNETIdentityConst.MaxLengthOfLastName,
            ErrorMessageResourceName = "MaxLengthErrMsg",
            ErrorMessageResourceType = typeof(Resources.CommonViewModels))]
        public string LastName { get; set; }
    }
}