//**********************************************************************************
//* テンプレート
//**********************************************************************************

// 以下のLicenseに従い、このProjectをTemplateとして使用可能です。Release時にCopyright表示してSublicenseして下さい。
// https://github.com/OpenTouryoProject/MultiPurposeAuthSite/blob/master/license/LicenseForTemplates.txt

//**********************************************************************************
//* クラス名        ：EditRoleViewModel
//* クラス日本語名  ：ロール管理画面用のVM（テンプレート）
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
using System.ComponentModel.DataAnnotations;
using System.Web.Mvc;

/// <summary>MultiPurposeAuthSite.Models.ViewModels</summary>
namespace MultiPurposeAuthSite.Models.ViewModels
{
    /// <summary>ロール管理画面用のVM（テンプレート）</summary>
    public class EditRoleViewModel : BaseViewModel
    {
        /// <summary>ロールID</summary>
        public string Id { get; set; }

        /// <summary>ParentId(UI制御用)</summary>
        public string ParentId { get; set; }

        /// <summary>ロール名</summary>
        [Required(AllowEmptyStrings = false)]
        [Display(Name = "RoleName", ResourceType = typeof(Resources.CommonViewModels))]
        public string Name { get; set; }
    }
}