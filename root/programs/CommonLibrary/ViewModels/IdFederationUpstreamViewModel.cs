//**********************************************************************************
//* テンプレート
//**********************************************************************************

// 以下のLicenseに従い、このProjectをTemplateとして使用可能です。Release時にCopyright表示してSublicenseして下さい。
// https://github.com/OpenTouryoProject/MultiPurposeAuthSite/blob/master/license/LicenseForTemplates.txt

//**********************************************************************************
//* クラス名        ：IdFederationUpstreamViewModel
//* クラス日本語名  ：ID 連携の上流 IdP の登録（画面・DB で授受する型）
//*
//* 作成日時        ：－
//* 作成者          ：－
//* 更新履歴        ：－
//*
//*  日時        更新者            内容
//*  ----------  ----------------  -------------------------------------------------
//*  2026/10/14  玄人 幸道         新規（#292 の段階 2）
//**********************************************************************************

using System.ComponentModel.DataAnnotations;

/// <summary>MultiPurposeAuthSite.ViewModels</summary>
namespace MultiPurposeAuthSite.ViewModels
{
    /// <summary>
    /// ID 連携の上流 IdP の登録（画面・DB で授受する型。#292 の段階 2）
    /// </summary>
    /// <remarks>
    /// **項目は設定（`IdFederationUpstreams`）と同じ**である
    /// （**同じものを、設定ファイルでも DB でも書ける**ようにするため）。
    ///
    /// **列名は属性名と同じ**なので、Dapper が別名なしで対応付けられる
    /// （`ManageAddSaml2OAuth2DataViewModel` と同じ流儀。#270）。
    /// **`UpstreamKey` だけ、設定の「鍵」に当たる**（`Key` は方言の予約語なので避けた）。
    ///
    /// **`ClientSecret` は平文で入る**（`Saml2OAuth2Data.ClientSecret` と同じ扱い）。
    /// **上流へ送る値なので、元に戻せる形でなければならず、ハッシュは取れない。**
    /// **表に入る秘密をまとめて暗号化するかは、別の課題**である。
    /// </remarks>
    public class IdFederationUpstreamViewModel
    {
        /// <summary>鍵（設定の名前に当たる）</summary>
        [Required]
        [StringLength(128)]
        [RegularExpression(@"^[A-Za-z0-9_\-]+$")]
        [Display(Name = "UpstreamKey")]
        public string UpstreamKey { get; set; }

        /// <summary>画面に出す名前（空なら鍵）</summary>
        [StringLength(256)]
        [Display(Name = "DisplayName")]
        public string DisplayName { get; set; }

        /// <summary>protocol（oidc / saml2）</summary>
        [Required]
        [StringLength(16)]
        [Display(Name = "Protocol")]
        public string Protocol { get; set; }

        /// <summary>有効か</summary>
        [Display(Name = "Enabled")]
        public bool Enabled { get; set; }

        /// <summary>期待する Issuer（OIDC の iss / SAML2 の entityID）</summary>
        [StringLength(256)]
        [Display(Name = "Issuer")]
        public string Issuer { get; set; }

        /// <summary>上流に登録された、自分の client_id</summary>
        [StringLength(256)]
        [Display(Name = "ClientID")]
        public string ClientID { get; set; }

        /// <summary>上流に登録された、自分の client_secret（OIDC）</summary>
        [StringLength(256)]
        [Display(Name = "ClientSecret")]
        public string ClientSecret { get; set; }

        /// <summary>上流の discovery の URL（OIDC）</summary>
        [StringLength(512)]
        [Display(Name = "DiscoveryUrl")]
        public string DiscoveryUrl { get; set; }

        /// <summary>上流の JWK Set の URL（OIDC）</summary>
        [StringLength(512)]
        [Display(Name = "JwkSetUri")]
        public string JwkSetUri { get; set; }

        /// <summary>上流のメタデータの URL（SAML2）</summary>
        [StringLength(512)]
        [Display(Name = "MetadataUrl")]
        public string MetadataUrl { get; set; }

        /// <summary>上流の署名証明書（倒れ先）</summary>
        [StringLength(512)]
        [Display(Name = "CerFilePath")]
        public string CerFilePath { get; set; }

        /// <summary>上流の認可エンドポイント（OIDC）</summary>
        [StringLength(512)]
        [Display(Name = "AuthorizeEndpoint")]
        public string AuthorizeEndpoint { get; set; }

        /// <summary>上流のトークン エンドポイント（OIDC）</summary>
        [StringLength(512)]
        [Display(Name = "TokenEndpoint")]
        public string TokenEndpoint { get; set; }

        /// <summary>上流の UserInfo エンドポイント（OIDC）</summary>
        [StringLength(512)]
        [Display(Name = "UserInfoEndpoint")]
        public string UserInfoEndpoint { get; set; }

        /// <summary>上流の SSO の口（SAML2。倒れ先）</summary>
        [StringLength(512)]
        [Display(Name = "SsoEndpoint")]
        public string SsoEndpoint { get; set; }
    }
}
