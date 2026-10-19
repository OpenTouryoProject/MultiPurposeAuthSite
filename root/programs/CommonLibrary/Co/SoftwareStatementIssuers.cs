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
//* クラス名        ：SoftwareStatementIssuers
//* クラス日本語名  ：software_statement の発行者の登録（n 件）
//*
//* 作成日時        ：－
//* 作成者          ：－
//* 更新履歴        ：－
//*
//*  日時        更新者            内容
//*  ----------  ----------------  -------------------------------------------------
//*  2026/10/20  玄人 幸道         新規（#307 の段階 4）
//**********************************************************************************

using MultiPurposeAuthSite.TokenProviders;

using System.Collections.Generic;

using Touryo.Infrastructure.Public.Security.Jwt;

namespace MultiPurposeAuthSite.Co
{
    /// <summary>
    /// `software_statement`（RFC 7591 §2.3）の発行者 1 件分の登録。
    /// </summary>
    /// <remarks>
    /// **「発行者ごと」である。** **クライアントごとではない。**
    ///
    /// | | 誰の鍵か | 件数 | どこに持つか |
    /// |---|---|---|---|
    /// | `jwks` / `tls_client_auth_subject_dn`（段階 3） | **そのクライアント自身** | クライアントごとに 1 件 | **`Saml2OAuth2Data` の列** |
    /// | **この証明書**（段階 4） | **主張を書いた側**（ソフトウェアの発行元・エコシステムの名簿） | **発行者ごとに 1 件**（配備全体で数件） | **設定ファイル** |
    ///
    /// **`software_statement` は 1 つのソフトウェアに 1 枚配られ、
    /// その全ての配置が同じものを提示する**（RFC 7591 §2 の `software_id`）。
    /// **登録されるクライアントが何件になっても、検証鍵は発行者 1 件につき 1 つ**である。
    ///
    /// **設定ファイルに置く理由**（#307 の段階 4 の決定）。
    ///
    /// | | |
    /// |---|---|
    /// | **件数が数件で、増減が稀** | **提携先が増えたときだけ。** クライアント登録（API から作る）とは変わり方が違う |
    /// | **`.cer` がファイルとして要る** | 管理画面にするなら、ファイルを受け取る仕掛けが別途要る |
    /// | **配備全体の信頼の決め** | **1 利用者の持ち物ではない。** 画面にするなら `UsersAdmin` 系の話になる |
    ///
    /// > **ID 連携の上流は、#292 の段階 1 で設定ファイル、段階 2 で DB ＋ 管理画面になった。**
    /// > **同じ道は通せる**が、**それは DDL ＋ 両アプリの画面**である（別段階）。
    /// </remarks>
    public class SoftwareStatementIssuer
    {
        /// <summary>鍵（設定の名前。ログに出る値）</summary>
        /// <remarks>
        /// **`iss` そのものを鍵にはしない。** **`iss` は URL で `:` を含み**、
        /// **net10.0 の構成では `:` が階層の区切り**である（`appSettings:...`）。
        /// **環境変数での上書き（`__`）も同じ事情**なので、**短い名前を鍵にして
        /// `iss` は属性で持つ**（`IdFederationUpstreams` と同じ流儀）。
        /// </remarks>
        public string Key { get; set; }

        /// <summary>画面・ログに出す名前（空なら <see cref="Key"/>）</summary>
        public string DisplayName { get; set; }

        /// <summary>有効か（設定が空・未設定なら有効）</summary>
        public bool Enabled { get; set; }

        /// <summary>期待する `iss`（RFC 7591 §2.3 : software_statement は `iss` を必須とする）</summary>
        public string Issuer { get; set; }

        /// <summary>署名を検証する証明書（`.cer` のパス）</summary>
        /// <remarks>
        /// **公開鍵だけで足りる**（検証しかしない）。
        /// **`jwks_uri` のように URL から引く形は採らない** —
        /// **登録の口は同期で、取得を差し込めない**（`jwks_uri` を断っているのと同じ理由。別 Issue）。
        /// </remarks>
        public string CerFilePath { get; set; }

        /// <summary>署名の alg（空なら `RS256`）</summary>
        /// <remarks>
        /// **ヘッダの `alg` と照合する**（**外から alg を選ばせない**。#262 と同じ方針）。
        ///
        /// **扱うのは `SigningKeys.SupportedAlgs` の範囲**である。
        /// **あれは「この配備が署名に使う alg」の一覧**だが、
        /// **`.cer` から検証用の JWS を作れる alg の一覧でもある**
        /// （`SigningKeys.CreateJwsFromCer`）。**一覧を 2 つ持たない。**
        /// </remarks>
        public string Alg { get; set; }

        /// <summary>ログに出す名前（空なら鍵）</summary>
        public string Label
        {
            get
            {
                return string.IsNullOrEmpty(this.DisplayName) ? this.Key : this.DisplayName;
            }
        }

        /// <summary>この行で検証が成立するか</summary>
        /// <remarks>
        /// **成立しない行は、無いものとして扱う** — **`iss` か証明書が欠けた行で
        /// 「信頼している」ことにはしない。**
        /// </remarks>
        public bool IsUsable
        {
            get
            {
                return this.Enabled
                    && !string.IsNullOrEmpty(this.Issuer)
                    && !string.IsNullOrEmpty(this.CerFilePath)
                    && SigningKeys.IsSupported(this.Alg);
            }
        }
    }

    /// <summary>
    /// `software_statement` の発行者の登録（n 件）を、設定から読む（#307 の段階 4）。
    /// </summary>
    /// <remarks>
    /// **設定は `SoftwareStatementIssuers`**（`IdFederationUpstreams` と同じ流儀。
    /// net48 は JSON 文字列 1 本、net10.0 は節）。
    ///
    /// ```jsonc
    /// "SoftwareStatementIssuers": {
    ///   "vendor1": {
    ///     "display_name": "Vendor 1", "enabled": "true",
    ///     "issuer": "https://vendor1.example.com",
    ///     "cer_file_path": "C:/root/files/resource/X509/SHA256RSA_Client.cer",
    ///     "alg": "RS256"
    ///   }
    /// }
    /// ```
    ///
    /// **1 件も無い配備では、`software_statement` を断る**（従来どおり
    /// `unapproved_software_statement`）。**既定の配備の振る舞いは変わらない。**
    /// </remarks>
    public static class SoftwareStatementIssuers
    {
        /// <summary>`alg` を書かなかったときの既定</summary>
        public const string DefaultAlg = JwtConst.RS256;

        /// <summary>登録されている発行者（使えない行は返さない）</summary>
        /// <returns>発行者の列（無ければ空の列）</returns>
        public static List<SoftwareStatementIssuer> List()
        {
            List<SoftwareStatementIssuer> ret = new List<SoftwareStatementIssuer>();

            Dictionary<string, Dictionary<string, string>> issuers =
                Config.SoftwareStatementIssuers;

            if (issuers == null)
            {
                return ret;
            }

            foreach (KeyValuePair<string, Dictionary<string, string>> entry in issuers)
            {
                SoftwareStatementIssuer issuer =
                    SoftwareStatementIssuers.FromSetting(entry.Key, entry.Value);

                if (issuer.IsUsable)
                {
                    ret.Add(issuer);
                }
            }

            return ret;
        }

        /// <summary>信頼する発行者が 1 件でも在るか</summary>
        /// <returns>在れば true</returns>
        /// <remarks>
        /// **0 件なら、`software_statement` は受け付けない**
        /// （**検証する材料が無いものを「通った」ことにはしない**）。
        /// </remarks>
        public static bool Any()
        {
            return 0 < SoftwareStatementIssuers.List().Count;
        }

        /// <summary>`iss` で 1 件引く（信頼していなければ null）</summary>
        /// <param name="iss">software_statement の `iss`</param>
        /// <returns>発行者（無ければ null）</returns>
        /// <remarks>**完全一致**である（部分一致・前方一致は見ない）。</remarks>
        public static SoftwareStatementIssuer Find(string iss)
        {
            if (string.IsNullOrEmpty(iss))
            {
                return null;
            }

            foreach (SoftwareStatementIssuer issuer in SoftwareStatementIssuers.List())
            {
                if (issuer.Issuer == iss)
                {
                    return issuer;
                }
            }

            return null;
        }

        /// <summary>設定の 1 行から作る</summary>
        /// <param name="key">鍵</param>
        /// <param name="attributes">属性</param>
        /// <returns>発行者</returns>
        private static SoftwareStatementIssuer FromSetting(
            string key, Dictionary<string, string> attributes)
        {
            return new SoftwareStatementIssuer()
            {
                Key = key,
                DisplayName = SoftwareStatementIssuers.Value(attributes, "display_name"),
                Enabled = SoftwareStatementIssuers.Flag(attributes, "enabled"),
                Issuer = SoftwareStatementIssuers.Value(attributes, "issuer"),
                CerFilePath = SoftwareStatementIssuers.Value(attributes, "cer_file_path"),
                Alg = SoftwareStatementIssuers.Alg(attributes)
            };
        }

        /// <summary>属性を読む（無ければ空）</summary>
        /// <param name="attributes">属性</param>
        /// <param name="name">属性名</param>
        /// <returns>値</returns>
        private static string Value(Dictionary<string, string> attributes, string name)
        {
            string value = null;

            return (attributes != null && attributes.TryGetValue(name, out value) && value != null)
                ? value : "";
        }

        /// <summary>`alg` を読む（空なら既定）</summary>
        /// <param name="attributes">属性</param>
        /// <returns>alg</returns>
        private static string Alg(Dictionary<string, string> attributes)
        {
            string alg = SoftwareStatementIssuers.Value(attributes, "alg");

            return string.IsNullOrEmpty(alg) ? SoftwareStatementIssuers.DefaultAlg : alg;
        }

        /// <summary>真偽の属性を読む（空・未設定は true）</summary>
        /// <param name="attributes">属性</param>
        /// <param name="name">属性名</param>
        /// <returns>値</returns>
        /// <remarks>
        /// **書かなければ有効**にする（`IdFederationUpstreams` の `enabled` と同じ）。
        /// **「書き忘れたら黙って無効」は、気づけない。**
        /// </remarks>
        private static bool Flag(Dictionary<string, string> attributes, string name)
        {
            string value = SoftwareStatementIssuers.Value(attributes, name);

            if (string.IsNullOrEmpty(value))
            {
                return true;
            }

            bool flag = false;

            return bool.TryParse(value, out flag) ? flag : true;
        }
    }
}
