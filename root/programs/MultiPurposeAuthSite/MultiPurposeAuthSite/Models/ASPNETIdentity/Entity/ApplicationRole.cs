//**********************************************************************************
//* テンプレート
//**********************************************************************************

// 以下のLicenseに従い、このProjectをTemplateとして使用可能です。Release時にCopyright表示してSublicenseして下さい。
// https://github.com/OpenTouryoProject/MultiPurposeAuthSite/blob/master/license/LicenseForTemplates.txt

//**********************************************************************************
//* クラス名        ：ApplicationRole
//* クラス日本語名  ：IRoleを拡張したApplicationRole（テンプレート）
//*
//* 作成日時        ：－
//* 作成者          ：－
//* 更新履歴        ：－
//*
//*  日時        更新者            内容
//*  ----------  ----------------  -------------------------------------------------
//*  2017/04/24  西野 大介         新規
//**********************************************************************************

using System;
using Microsoft.AspNet.Identity;

/// <summary>MultiPurposeAuthSite.Models.ASPNETIdentity.Entity</summary>
namespace MultiPurposeAuthSite.Models.ASPNETIdentity.Entity
{
    /// <summary>ApplicationRole</summary>
    public class ApplicationRole : IRole<string>
    {
        #region constructor

        /// <summary>constructor</summary>
        public ApplicationRole()
        {
            // 引数なしのpublic default constructor以外 NGっぽい。
        }

        #region CreateFor

        /// <summary>システム共通のApplicationRoleを生成</summary>
        /// <param name="name">string</param>
        /// <returns>ApplicationRole</returns>
        public static ApplicationRole CreateForCommon(string name)
        {
            // ApplicationRole
            return new ApplicationRole
            {
                ParentId = "", // システム共通の場合は空文字列
                Name = name
            };
        }

        /// <summary>テナントのApplicationRoleを生成</summary>
        /// <param name="parentId">string</param>
        /// <param name="name">string</param>
        /// <returns>ApplicationRole</returns>
        public static ApplicationRole CreateForTenant(string parentId, string name)
        {
            // ApplicationRole
            ApplicationRole role = new ApplicationRole
            {
                Name = name,
            };

            // ParentId（実質的に分割キー）
            if (ASPNETIdentityConfig.MultiTenant)
            {
                // マルチテナントの場合、テナントの管理者ユーザが管理者ユーザになる。
                role.ParentId = parentId;
            }
            else
            {
                // マルチテナントでない場合、"".
                role.ParentId = "";
            }

            return role;
        }

        #endregion

        #endregion

        #region properties

        #region RoleInfo

        /// <summary>Id</summary>
        public string Id { get; set; } = Guid.NewGuid().ToString();

        /// <summary>Name</summary>
        public string Name { get; set; }

        #endregion

        #region Additional properties

        /// <summary>
        /// Gets or sets the parent user identifier.
        /// </summary>
        /// <remarks>
        /// このフィールドはマルチテナント処理のために使用されます。
        /// </remarks>
        public string ParentId { get; set; } = null;

        #endregion

        #endregion
    }
}