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
#if NETFX
using Microsoft.AspNet.Identity;
#else
using Microsoft.AspNetCore.Identity;
#endif

#if NETFX
/// <summary>MultiPurposeAuthSite.Entity</summary>
namespace MultiPurposeAuthSite.Entity
#else
/// <summary>MultiPurposeAuthSite</summary>
namespace MultiPurposeAuthSite // ルートでないとダメ？
#endif
{
    /// <summary>ApplicationRole</summary>
#if NETFX
    public class ApplicationRole : IRole<string>
#else
    public class ApplicationRole
#endif
    {
        /// <summary>constructor</summary>
        public ApplicationRole()
        {
            // 引数なしのpublic default constructor以外 NGっぽい。
        }

        #region properties

        #region RoleInfo

        /// <summary>Id</summary>
        public string Id { get; set; } = Guid.NewGuid().ToString();

        /// <summary>Name</summary>
        public string Name { get; set; }

        /// <summary>
        /// NormalizedName
        /// Nameを大文字化した値が自動的にセットされる。
        /// これをUserStoreに登録しておけば、検索し易くなる。
        /// </summary>
        /// <remarks>
        /// 本プロパティは、検索条件用に、Nameプロパティを大文字化したプロパティですが、
        /// 本システムではNameプロパティを軸にするため、.NET Framework 上で実行する場合は指定された値を無視します。
        /// </remarks> 
        public string NormalizedName
        {
#if NETFX
            set
            {
                // 捨て
            }
            get
            {
                return this.Name.ToUpper();
            }
#else
            set; get;
#endif
        }

        #endregion

        #endregion
    }
}