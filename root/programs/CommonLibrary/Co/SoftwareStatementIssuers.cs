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
//*  2026/10/20  玄人 幸道         発行者ごとの上限と、鍵の入れ替えを追加（#307 の段階 6）
//*  2026/10/21  玄人 幸道         DBの登録も読む（本文の列を追加。#308 の段階 1）
//**********************************************************************************

using MultiPurposeAuthSite.TokenProviders;

using System;
using System.Collections.Generic;
using System.Linq;

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

        /// <summary>署名を検証する証明書（`.cer` のパス。**空白かカンマ区切りで n 本**）</summary>
        /// <remarks>
        /// **公開鍵だけで足りる**（検証しかしない）。
        /// **`jwks_uri` のように URL から引く形は採らない** —
        /// **登録の口は同期で、取得を差し込めない**（`jwks_uri` を断っているのと同じ理由。#309）。
        ///
        /// **n 本書ける**（#307 の段階 6）。**発行者の鍵の入れ替えのため**である。
        ///
        /// | | |
        /// |---|---|
        /// | **入れ替えの間** | **新旧を並べて書く**（**どちらで署名された statement も通る**） |
        /// | **試す順** | **書いた順。** **最初に検証できた鍵で通す** |
        /// | **入れ替えが済んだら** | **古い方を消す**（**消すまでは古い鍵も有効**である） |
        ///
        /// **区切りは空白・カンマ・タブ**（`PreviousSigningCerFilePaths`（#292 の段階 3）と同じ流儀）。
        /// **空白を含むパスは、この形では書けない**（**同じ限界**である）。
        ///
        /// **`alg` は行で 1 つ**（<see cref="Alg"/>）。
        /// **鍵の種類（RSA / EC）や alg まで変える入れ替えは、この形では扱えない** —
        /// **行を 2 つに分け、`iss` を別にする**しかない（**同じ `iss` の行は 1 つしか引かない**）。
        /// </remarks>
        public string CerFilePath { get; set; }

        /// <summary>検証鍵の本文（PEM / Base64。n 本）</summary>
        /// <remarks>
        /// **DB の登録だけが持つ**（#308 の段階 1）。**設定ファイルは持たない** —
        /// **設定は人が書く物で、PEM を貼るのに向かない**（**DB は画面から貼れる**）。
        ///
        /// **ファイルを置かずに済む**ので、**配備間で台帳を複製しやすい。**
        /// **公開鍵なので平文で持つ**（**暗号化しない**。#297 の対象外）。
        ///
        /// **本文とパスは、両方書いてよい** — **本文を先に試し、次にパスを試す**
        /// （**入れ替えの途中で、片方だけ本文に移す**こともできる）。
        /// </remarks>
        public string CerBody { get; set; }

        /// <summary>検証鍵の本文（Base64 の DER。n 本。書いた順）</summary>
        /// <remarks>
        /// **PEM でも Base64 でも受ける**（#308 の段階 1）。
        ///
        /// | 書き方 | 読み方 |
        /// |---|---|
        /// | **PEM** | `-----BEGIN CERTIFICATE-----` 〜 `-----END CERTIFICATE-----` を**並べて n 本**。**中身の Base64 だけを取る** |
        /// | **Base64（DER）** | **空白・カンマ・改行で区切って n 本** |
        ///
        /// **`.cer` を貼るときの揺れを吸収する**のが役目である
        /// （**PEM の改行や、ヘッダの有無で落とさない**）。
        /// </remarks>
        public List<string> CerBodies
        {
            get
            {
                List<string> ret = new List<string>();

                if (string.IsNullOrWhiteSpace(this.CerBody))
                {
                    return ret;
                }

                string body = this.CerBody;

                if (body.Contains(SoftwareStatementIssuer.PemBegin))
                {
                    //  **PEM。** **BEGIN 〜 END の中身だけを取る**（**並べて n 本**）。
                    foreach (string block in body.Split(
                        new string[] { SoftwareStatementIssuer.PemBegin },
                        StringSplitOptions.RemoveEmptyEntries))
                    {
                        int end = block.IndexOf(SoftwareStatementIssuer.PemEnd);

                        if (end < 0)
                        {
                            //  **END が無い** ＝ 途中で切れている。**その先は使わない。**
                            continue;
                        }

                        string base64 = new string(block.Substring(0, end)
                            .Where(c => !char.IsWhiteSpace(c)).ToArray());

                        if (!string.IsNullOrEmpty(base64) && !ret.Contains(base64))
                        {
                            ret.Add(base64);
                        }
                    }

                    return ret;
                }

                //  **Base64（DER）。** **区切りで n 本。**
                foreach (string token in body.Split(
                    new char[] { ' ', ',', '\t', '\r', '\n' },
                    StringSplitOptions.RemoveEmptyEntries))
                {
                    if (!ret.Contains(token))
                    {
                        ret.Add(token);
                    }
                }

                return ret;
            }
        }

        /// <summary>PEM の始まり</summary>
        private const string PemBegin = "-----BEGIN CERTIFICATE-----";

        /// <summary>PEM の終わり</summary>
        private const string PemEnd = "-----END CERTIFICATE-----";

        /// <summary>証明書のパス（n 本。書いた順）</summary>
        /// <remarks>**空の要素は落とす。** **1 本も無ければ、この行は使えない**（<see cref="IsUsable"/>）。</remarks>
        public List<string> CerFilePaths
        {
            get
            {
                List<string> ret = new List<string>();

                if (string.IsNullOrWhiteSpace(this.CerFilePath))
                {
                    return ret;
                }

                foreach (string path in this.CerFilePath.Split(
                    new char[] { ' ', ',', '\t' }, StringSplitOptions.RemoveEmptyEntries))
                {
                    if (!ret.Contains(path))
                    {
                        ret.Add(path);
                    }
                }

                return ret;
            }
        }

        /// <summary>この発行者の保証で作れる `scope` の上限（空白区切り。空なら絞らない）</summary>
        /// <remarks>
        /// **この発行者の statement で作られる登録の `scope` の上限**である（#307 の段階 6）。
        ///
        /// **絞るのは「受け入れる側」の決め**である。
        /// **ベンダが自分で絞る分は、statement の中身に書けば済む**（**署名されているので、
        /// 配置側が広げられない**。段階 4）。**実際に登録に入るのは、2 つの積**になる。
        ///
        /// | | |
        /// |---|---|
        /// | **空（未設定）** | **絞らない**（**段階 4 までと同じ振る舞い**） |
        /// | **書いたら** | **範囲外を主張されたら `unapproved_software_statement` で断る** — **黙って狭めない** |
        ///
        /// **効くのは、statement 由来の値だけではない** —
        /// **本文（plain JSON）に書かれた値も、この上限に収める。**
        /// **「その発行者の保証で作られる登録」全体の上限**だからである。
        ///
        /// **`client_registration` は、ここに書いても意味を持たない** —
        /// **動的登録では配れない**（段階 1 の決め。`ClientRegistrationProvider.Validate` が断る）。
        /// </remarks>
        public string AllowedScope { get; set; }

        /// <summary>この発行者の保証で作れる `grant_types` の上限（空白区切り。空なら絞らない）</summary>
        /// <remarks>
        /// **`AllowedScope` と同じ扱い**である（#307 の段階 6）。
        ///
        /// **強いグラント**（`password` / `implicit` / `client_credentials` /
        /// `urn:ietf:params:oauth:grant-type:device_code`）**を、特定の発行者にだけ許す**ために在る。
        ///
        /// **`response_types` は書かない** — **`grant_types` と対応が決まる**（RFC 7591 §2）ので、
        /// **上限を 2 か所に持たない。**
        /// </remarks>
        public string AllowedGrantTypes { get; set; }

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
                    && (0 < this.CerBodies.Count || 0 < this.CerFilePaths.Count)
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
    ///     "alg": "RS256",
    ///     // **この発行者に許す範囲**（#307 の段階 6。**空なら絞らない**）
    ///     "allowed_scope": "openid email",
    ///     "allowed_grant_types": "authorization_code refresh_token"
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
            List<string> keys = new List<string>();

            //  **設定を先に読む**（#308 の段階 1）。
            Dictionary<string, Dictionary<string, string>> issuers =
                Config.SoftwareStatementIssuers;

            if (issuers != null)
            {
                foreach (KeyValuePair<string, Dictionary<string, string>> entry in issuers)
                {
                    SoftwareStatementIssuer issuer =
                        SoftwareStatementIssuers.FromSetting(entry.Key, entry.Value);

                    keys.Add(entry.Key);

                    if (issuer.IsUsable)
                    {
                        ret.Add(issuer);
                    }
                }
            }

            //  **次に DB を読む**（#308 の段階 1）。**同じ鍵なら設定が勝つ** —
            //    **`IdFederationUpstreams` と同じ流儀**（#292 の段階 2）。
            //
            //  **使えない行は返さない**のは、設定と同じ扱いである
            //    （**`iss` か鍵が欠けた行で「信頼している」ことにはしない**）。
            //
            //  **DB を読めない配備**（表を作っていない・user store が落ちている）**でも、
            //    設定の分は返す** — **動的登録ごと止めない**ためである。
            try
            {
                foreach (ViewModels.SoftwareStatementIssuerViewModel model
                    in Extensions.Sts.SoftwareStatementIssuerProvider.GetAll())
                {
                    if (keys.Contains(model.IssuerKey))
                    {
                        //  **設定が勝つ。**
                        continue;
                    }

                    SoftwareStatementIssuer issuer =
                        SoftwareStatementIssuers.FromViewModel(model);

                    if (issuer.IsUsable)
                    {
                        ret.Add(issuer);
                    }
                }
            }
            catch (Exception ex)
            {
                // オペレーション・トレース・ログ出力
                //   **理由を残す**（#253 の方針）。**設定の分は、そのまま返す。**
                Log.Logging.MyOperationTrace(string.Format(
                    "The software_statement issuers could not be read from the user store. ({0})",
                    ex.GetType().Name));
            }

            return ret;
        }

        /// <summary>DB の 1 行から作る（#308 の段階 1）</summary>
        /// <param name="model">SoftwareStatementIssuerViewModel</param>
        /// <returns>発行者</returns>
        /// <remarks>**設定の 1 行から作る版**（<see cref="FromSetting"/>）**と対**である。</remarks>
        private static SoftwareStatementIssuer FromViewModel(
            ViewModels.SoftwareStatementIssuerViewModel model)
        {
            return new SoftwareStatementIssuer()
            {
                Key = model.IssuerKey,
                DisplayName = model.DisplayName,
                Enabled = model.Enabled,
                Issuer = model.Issuer,
                CerFilePath = model.CerFilePath,
                CerBody = model.CerBody,
                Alg = string.IsNullOrEmpty(model.Alg)
                    ? SoftwareStatementIssuers.DefaultAlg : model.Alg,
                AllowedScope = model.AllowedScope,
                AllowedGrantTypes = model.AllowedGrantTypes
            };
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
                Alg = SoftwareStatementIssuers.Alg(attributes),

                //  **この発行者に許す範囲**（#307 の段階 6。**空なら絞らない**）。
                AllowedScope = SoftwareStatementIssuers.Value(attributes, "allowed_scope"),
                AllowedGrantTypes =
                    SoftwareStatementIssuers.Value(attributes, "allowed_grant_types")
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
