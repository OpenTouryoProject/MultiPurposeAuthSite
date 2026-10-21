//**********************************************************************************
//* Copyright (C) 2026 Hitachi Solutions,Ltd.
//**********************************************************************************

#region Apache License
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
#endregion

//**********************************************************************************
//* クラス名        ：SoftwareStatementIssuerViewModel
//* クラス日本語名  ：software_statement の発行者（ベンダ）の登録のVM
//*
//* 作成日時        ：－
//* 作成者          ：－
//* 更新履歴        ：－
//*
//*  日時        更新者            内容
//*  ----------  ----------------  -------------------------------------------------
//*  2026/10/21  玄人 幸道         新規（#308 の段階 1）
//**********************************************************************************

using System.ComponentModel.DataAnnotations;

/// <summary>MultiPurposeAuthSite.ViewModels</summary>
namespace MultiPurposeAuthSite.ViewModels
{
    /// <summary>
    /// `software_statement` の発行者（ベンダ）の登録のVM（#308 の段階 1）
    /// </summary>
    /// <remarks>
    /// **「どのベンダを信じ、どこまで任せるか」の台帳**である。
    /// **クライアントの登録ではない**（あちらは `ManageAddSaml2OAuth2DataViewModel`。
    /// **件数も、変わり方も違う** — **クライアントは RP の数だけ増え、
    /// 発行者は提携先の数しか無い**）。
    ///
    /// **列は専用列に切り出してある**（`ManageAddSaml2OAuth2DataViewModel` と同じ流儀。#270）。
    /// **`IssuerKey` だけ、設定の「鍵」に当たる**（`Key` は方言の予約語なので避けた）。
    ///
    /// **設定（`appSettings` の `SoftwareStatementIssuers`）と同じ項目**を持つ。
    /// **読み出しの入口は `Co.SoftwareStatementIssuers`** で、**設定 → DB の順に見る**
    /// （**`IdFederationUpstreams` と同じ流儀**。#292 の段階 2）。
    ///
    /// **暗号化する列は無い。** **持っているのは公開鍵と上限だけ**で、
    /// **`client_secret` や `.pfx` のパスワードのような秘密は入らない**
    /// （**だから `SecretProtector` を通さない**。#297 の対象外）。
    /// </remarks>
    public class SoftwareStatementIssuerViewModel
    {
        /// <summary>鍵（設定の名前に当たる）</summary>
        /// <remarks>
        /// **`iss` そのものを鍵にはしない** — **`iss` は URL で `:` を含み**、
        /// **net10.0 の構成では `:` が階層の区切り**である（`Co.SoftwareStatementIssuer` の注）。
        /// </remarks>
        [Required]
        [StringLength(128)]
        [RegularExpression(@"^[A-Za-z0-9_\-]+$")]
        [Display(Name = "IssuerKey")]
        public string IssuerKey { get; set; }

        /// <summary>画面・ログに出す名前（空なら鍵）</summary>
        [StringLength(256)]
        [Display(Name = "DisplayName")]
        public string DisplayName { get; set; }

        /// <summary>有効か</summary>
        /// <remarks>**鍵を消さずに止められる**ようにしてある（提携を一時的に切るとき）。</remarks>
        [Display(Name = "Enabled")]
        public bool Enabled { get; set; }

        /// <summary>期待する `iss`（RFC 7591 §2.3。完全一致）</summary>
        [StringLength(256)]
        [Display(Name = "Issuer")]
        public string Issuer { get; set; }

        /// <summary>検証鍵の `.cer` のパス（空白かカンマ区切りで n 本）</summary>
        /// <remarks>
        /// **n 本書けるのは、発行者の鍵の入れ替えのため**（#307 の段階 6）。
        /// **本文（<see cref="CerBody"/>）が在れば、そちらを先に見る。**
        /// </remarks>
        [StringLength(512)]
        [Display(Name = "CerFilePath")]
        public string CerFilePath { get; set; }

        /// <summary>検証鍵の本文（PEM / Base64。空白かカンマ区切り、または PEM を並べて n 本）</summary>
        /// <remarks>
        /// **ファイルを置かずに済ませるため**に在る（#308 の段階 1）。
        /// **公開鍵なので平文で持つ** — **暗号化しない**（#297 の対象外）。
        ///
        /// | 書き方 | |
        /// |---|---|
        /// | **PEM** | `-----BEGIN CERTIFICATE-----` 〜 `-----END CERTIFICATE-----`。**並べて n 本** |
        /// | **Base64（DER）** | **1 行 1 本**（空白・カンマ・改行で区切る） |
        ///
        /// **空なら <see cref="CerFilePath"/> を見る**（**既存の配備は無改変で動く**）。
        /// </remarks>
        [Display(Name = "CerBody")]
        public string CerBody { get; set; }

        /// <summary>署名の alg（空なら `RS256`）</summary>
        [StringLength(16)]
        [Display(Name = "Alg")]
        public string Alg { get; set; }

        /// <summary>この発行者に許す `scope` の上限（空白区切り。空なら絞らない）</summary>
        /// <remarks>**#307 の段階 6。** **提携の範囲を、技術的な上限として持つ。**</remarks>
        [StringLength(2000)]
        [Display(Name = "AllowedScope")]
        public string AllowedScope { get; set; }

        /// <summary>この発行者に許す `grant_types` の上限（空白区切り。空なら絞らない）</summary>
        /// <remarks>**#307 の段階 6。**</remarks>
        [StringLength(2000)]
        [Display(Name = "AllowedGrantTypes")]
        public string AllowedGrantTypes { get; set; }
    }
}
