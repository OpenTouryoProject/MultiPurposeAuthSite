//**********************************************************************************
//* テンプレート
//**********************************************************************************

// 以下のLicenseに従い、このProjectをTemplateとして使用可能です。Release時にCopyright表示してSublicenseして下さい。
// https://github.com/OpenTouryoProject/MultiPurposeAuthSite/blob/master/license/LicenseForTemplates.txt

//**********************************************************************************
//* クラス名        ：UsersAdminSearchViewModel
//* クラス日本語名  ：ユーザ管理画面の検索用のVM（テンプレート）
//*
//* 作成日時        ：－
//* 作成者          ：－
//* 更新履歴        ：－
//*
//*  日時        更新者            内容
//*  ----------  ----------------  -------------------------------------------------
//*  2017/05/24  西野 大介         新規
//**********************************************************************************

using MultiPurposeAuthSite.Entity;

using MultiPurposeAuthSite.Co;

using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;

/// <summary>MultiPurposeAuthSite.ViewModels</summary>
namespace MultiPurposeAuthSite.ViewModels
{
    /// <summary>ユーザ管理画面用のVM（テンプレート）</summary>
    public class UsersAdminSearchViewModel : BaseViewModel
    {
        /// <summary>ユーザ名（検索条件）</summary>
        [Display(Name = "UserNameforSearch", ResourceType = typeof(Resources.CommonViewModels))]
        [StringLength(
            Const.MaxLengthOfUserName,
            ErrorMessageResourceName = "MaxLengthErrMsg",
            ErrorMessageResourceType = typeof(Resources.CommonViewModels))]
        public string UserNameforSearch { get; set; }

        /// <summary>ユーザ一覧</summary>
        public IEnumerable<ApplicationUser> Users { get; set; }
    }
}