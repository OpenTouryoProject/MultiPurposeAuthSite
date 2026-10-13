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
//* クラス名        ：IdFederationUpstreams
//* クラス日本語名  ：ID 連携の上流 IdP の登録（n 件）
//*
//* 作成日時        ：－
//* 作成者          ：－
//* 更新履歴        ：－
//*
//*  日時        更新者            内容
//*  ----------  ----------------  -------------------------------------------------
//*  2026/10/13  玄人 幸道         新規（#292 の段階 1）
//*  2026/10/14  玄人 幸道         user store の登録も読むようにした（#292 の段階 2）
//**********************************************************************************

using MultiPurposeAuthSite.ViewModels;

using System.Collections.Generic;

using Touryo.Infrastructure.Framework.Authentication;

namespace MultiPurposeAuthSite.Co
{
    /// <summary>
    /// ID 連携の上流 IdP 1 件分の登録。
    /// </summary>
    /// <remarks>
    /// **「相手ごとの値」だけを持つ**（#290 で決めた分け方）。
    /// **「この配備の値」は共通設定のまま**である。
    ///
    /// | | どこに在るか |
    /// |---|---|
    /// | **相手ごとの値** | **この型**（`IdFederationUpstreams` が設定から作る） |
    /// | **折り返し口** | **共通設定**（`IdFederationRedirectEndpoint` / `IdFederationSaml2ResponseEndpoint`）。**自分の URL なので相手ごとに変わらない** |
    /// | 自分の署名鍵 | 共通設定（`SpRp_RsaPfxFilePath` ほか） |
    /// </remarks>
    public class IdFederationUpstream
    {
        /// <summary>OIDC を表す `protocol` の値</summary>
        public const string Oidc = "oidc";

        /// <summary>SAML2 を表す `protocol` の値</summary>
        public const string Saml2 = "saml2";

        /// <summary>鍵（設定の名前。導線の値・Session に控える値・ログに出る値）</summary>
        public string Key { get; set; }

        /// <summary>画面に出す名前（空なら <see cref="Key"/> を出す）</summary>
        public string DisplayName { get; set; }

        /// <summary>protocol（`oidc` / `saml2`）</summary>
        public string Protocol { get; set; }

        /// <summary>有効か（設定が空・未設定なら有効）</summary>
        public bool Enabled { get; set; }

        /// <summary>
        /// 期待する Issuer（OIDC の `iss` / SAML2 の `entityID`）
        /// </summary>
        /// <remarks>
        /// **メタデータ・discovery の照合に使う**（#289 / #291）。
        /// **設定の URL を差し替えられた配備で、別の相手の口と鍵を信じないため。**
        /// </remarks>
        public string Issuer { get; set; }

        /// <summary>上流に登録された、自分の `client_id`</summary>
        /// <remarks>
        /// **SAML2 でも要る。** **SP の `Issuer` は `http://&lt;client_id&gt;`** である
        /// （上流はこれで SP の登録を引く）。
        /// </remarks>
        public string ClientId { get; set; }

        /// <summary>上流に登録された、自分の `client_secret`（OIDC）</summary>
        public string ClientSecret { get; set; }

        /// <summary>上流の discovery の URL（OIDC）</summary>
        public string DiscoveryUrl { get; set; }

        /// <summary>上流の JWK Set の URL（OIDC。discovery より先に見る。#290）</summary>
        public string JwkSetUri { get; set; }

        /// <summary>上流のメタデータの URL（SAML2。#291）</summary>
        public string MetadataUrl { get; set; }

        /// <summary>上流の署名証明書（倒れ先）</summary>
        public string CerFilePath { get; set; }

        /// <summary>上流の認可エンドポイント（OIDC）</summary>
        public string AuthorizeEndpoint { get; set; }

        /// <summary>上流のトークン エンドポイント（OIDC）</summary>
        public string TokenEndpoint { get; set; }

        /// <summary>上流の UserInfo エンドポイント（OIDC）</summary>
        public string UserInfoEndpoint { get; set; }

        /// <summary>上流の SSO の口（SAML2。倒れ先）</summary>
        public string SsoEndpoint { get; set; }

        /// <summary>画面に出す名前（空なら鍵）</summary>
        public string Label
        {
            get
            {
                return string.IsNullOrEmpty(this.DisplayName) ? this.Key : this.DisplayName;
            }
        }

        /// <summary>この行で ID 連携が成立するか（protocol ごとに要る値が違う）</summary>
        /// <remarks>
        /// **押しても成立しない導線を出さない**（#286 の段階 2 と同じ方針）。
        ///
        /// | | 要るもの |
        /// |---|---|
        /// | OIDC | 認可・トークン・UserInfo の 3 本 ＋ 折り返し口（共通設定） |
        /// | SAML2 | 期待する `entityID` ＋ 折り返し口（共通設定） ＋ **メタデータ** または **口と鍵の両方** |
        /// </remarks>
        public bool IsUsable
        {
            get
            {
                if (!this.Enabled)
                {
                    return false;
                }

                if (this.Protocol == IdFederationUpstream.Saml2)
                {
                    if (string.IsNullOrEmpty(this.Issuer)
                        || string.IsNullOrEmpty(Config.IdFederationSaml2ResponseEndpoint))
                    {
                        return false;
                    }

                    return !string.IsNullOrEmpty(this.MetadataUrl)
                        || (!string.IsNullOrEmpty(this.SsoEndpoint)
                            && !string.IsNullOrEmpty(this.CerFilePath));
                }

                return !string.IsNullOrEmpty(this.AuthorizeEndpoint)
                    && !string.IsNullOrEmpty(this.TokenEndpoint)
                    && !string.IsNullOrEmpty(this.UserInfoEndpoint)
                    && !string.IsNullOrEmpty(Config.IdFederationRedirectEndpoint);
            }
        }
    }

    /// <summary>
    /// ID 連携の上流 IdP の登録（n 件）を、設定から読む（#292 の段階 1）。
    /// </summary>
    /// <remarks>
    /// **設定の読み方と、従来のキーとの互換を、ここ 1 か所で吸収する。**
    /// **呼ぶ側（`AccountController` / 画面）は、常に「n 件の列」として扱う。**
    ///
    /// **設定は `IdFederationUpstreams`**（`OAuth2ClientsInformation` と同じ流儀。
    /// net48 は JSON 文字列 1 本、net10.0 は節）。
    ///
    /// ```jsonc
    /// "IdFederationUpstreams": {
    ///   "upstream1": {
    ///     "display_name": "Upstream IdP (OIDC)", "protocol": "oidc", "enabled": "true",
    ///     "issuer": "https://ssoauth.opentouryo.com",
    ///     "client_id": "...", "client_secret": "...",
    ///     "discovery_url": "...", "jwk_set_uri": "", "cer_file_path": "...",
    ///     "authorize_endpoint": "...", "token_endpoint": "...", "userinfo_endpoint": "..."
    ///   },
    ///   "upstream1_saml2": {
    ///     "protocol": "saml2", "issuer": "...", "client_id": "...",
    ///     "metadata_url": "...", "sso_endpoint": "...", "cer_file_path": "..."
    ///   }
    /// }
    /// ```
    ///
    /// **空なら、従来の単数キーから 1〜2 件を組み立てる**（`default` / `default_saml2`）。
    /// **既存の配備は、設定を 1 行も書かずに従来どおり動く。**
    ///
    /// **user store の登録（`IdFederationUpstreams` 表）も読む**（#292 の段階 2）。
    /// **順は 設定 → DB** で、**同じ鍵なら設定が勝つ**
    /// （**クライアント登録と同じ流儀**。`Helper` が構成ファイル → `Saml2OAuth2Data` の順に見る）。
    /// </remarks>
    public static class IdFederationUpstreams
    {
        /// <summary>従来の単数キーから作る OIDC の行の鍵</summary>
        public const string DefaultOidcKey = "default";

        /// <summary>従来の単数キーから作る SAML2 の行の鍵</summary>
        public const string DefaultSaml2Key = "default_saml2";

        /// <summary>登録されている上流（protocol で絞る。使えない行は返さない）</summary>
        /// <param name="protocol">`oidc` / `saml2`</param>
        /// <returns>上流の列（無ければ空の列）</returns>
        /// <remarks>
        /// **並びは設定の順**（net48 の JSON も net10.0 の節も、書いた順で読める）。
        /// **既定の上流は、その先頭**である。
        /// </remarks>
        public static List<IdFederationUpstream> List(string protocol)
        {
            List<IdFederationUpstream> ret = new List<IdFederationUpstream>();

            foreach (IdFederationUpstream upstream in IdFederationUpstreams.All())
            {
                if (upstream.Protocol == protocol && upstream.IsUsable)
                {
                    ret.Add(upstream);
                }
            }

            return ret;
        }

        /// <summary>鍵で 1 件引く（使えない行・無い鍵は null）</summary>
        /// <param name="key">鍵</param>
        /// <returns>上流（無ければ null）</returns>
        public static IdFederationUpstream Get(string key)
        {
            if (string.IsNullOrEmpty(key))
            {
                return null;
            }

            foreach (IdFederationUpstream upstream in IdFederationUpstreams.All())
            {
                if (upstream.Key == key && upstream.IsUsable)
                {
                    return upstream;
                }
            }

            return null;
        }

        /// <summary>
        /// 鍵で 1 件引く。**鍵が空なら、その protocol の既定（先頭）を返す。**
        /// </summary>
        /// <param name="key">鍵（空でよい）</param>
        /// <param name="protocol">`oidc` / `saml2`</param>
        /// <returns>上流（決まらなければ null）</returns>
        /// <remarks>
        /// **鍵を送ってこない要求は、従来どおり 1 件目へ**（**既存の E2E と画面がそれ**）。
        /// **鍵が在るのに引けないときは null** — **呼ぶ側はエラー画面に落とし、理由を残す**（#253）。
        /// </remarks>
        public static IdFederationUpstream GetOrDefault(string key, string protocol)
        {
            if (!string.IsNullOrEmpty(key))
            {
                return IdFederationUpstreams.Get(key);
            }

            List<IdFederationUpstream> list = IdFederationUpstreams.List(protocol);

            return (list.Count == 0) ? null : list[0];
        }

        /// <summary>設定の全行（protocol も使えるかも問わない）</summary>
        /// <returns>上流の列</returns>
        private static List<IdFederationUpstream> FromConfig()
        {
            List<IdFederationUpstream> ret = new List<IdFederationUpstream>();

            Dictionary<string, Dictionary<string, string>> upstreams = Config.IdFederationUpstreams;

            if (upstreams != null && 0 < upstreams.Count)
            {
                foreach (KeyValuePair<string, Dictionary<string, string>> entry in upstreams)
                {
                    ret.Add(IdFederationUpstreams.FromSetting(entry.Key, entry.Value));
                }

                return ret;
            }

            //  **設定が無ければ、従来の単数キーから組み立てる**（互換）。
            //    **1 件のときの振る舞いを変えない**ため、ここを通る配備が既定である。
            ret.Add(IdFederationUpstreams.FromLegacyOidc());
            ret.Add(IdFederationUpstreams.FromLegacySaml2());

            return ret;
        }

        /// <summary>設定の全行 ＋ user store の全行（#292 の段階 2）</summary>
        /// <returns>上流の列</returns>
        /// <remarks>
        /// **順は 設定 → DB。** **同じ鍵なら設定が勝つ**
        /// （**設定ファイルで固定した配備が、DB の行で黙って変わらない**ようにする）。
        ///
        /// **DB が使えないときは、設定だけで動く。**
        /// **`mem` の配備でも読める**（プロセス内の辞書）。
        /// </remarks>
        private static List<IdFederationUpstream> All()
        {
            List<IdFederationUpstream> ret = IdFederationUpstreams.FromConfig();

            foreach (IdFederationUpstreamViewModel row
                in Extensions.Sts.IdFederationUpstreamProvider.GetAll())
            {
                if (row == null || string.IsNullOrEmpty(row.UpstreamKey))
                {
                    continue;
                }

                if (ret.Exists(u => u.Key == row.UpstreamKey))
                {
                    // **設定が勝つ**（DB の行は足さない）。
                    continue;
                }

                ret.Add(IdFederationUpstreams.FromStore(row));
            }

            return ret;
        }

        /// <summary>user store の 1 行から作る（#292 の段階 2）</summary>
        /// <param name="row">IdFederationUpstreamViewModel</param>
        /// <returns>上流</returns>
        private static IdFederationUpstream FromStore(IdFederationUpstreamViewModel row)
        {
            return new IdFederationUpstream()
            {
                Key = row.UpstreamKey,
                DisplayName = row.DisplayName,
                Protocol = (row.Protocol != null
                    && row.Protocol.ToLower() == IdFederationUpstream.Saml2)
                        ? IdFederationUpstream.Saml2 : IdFederationUpstream.Oidc,
                Enabled = row.Enabled,
                Issuer = row.Issuer,
                ClientId = row.ClientID,
                ClientSecret = row.ClientSecret,
                DiscoveryUrl = row.DiscoveryUrl,
                JwkSetUri = row.JwkSetUri,
                MetadataUrl = row.MetadataUrl,
                CerFilePath = row.CerFilePath,
                AuthorizeEndpoint = row.AuthorizeEndpoint,
                TokenEndpoint = row.TokenEndpoint,
                UserInfoEndpoint = row.UserInfoEndpoint,
                SsoEndpoint = row.SsoEndpoint
            };
        }

        /// <summary>設定の 1 行から作る</summary>
        /// <param name="key">鍵</param>
        /// <param name="attributes">属性</param>
        /// <returns>上流</returns>
        private static IdFederationUpstream FromSetting(
            string key, Dictionary<string, string> attributes)
        {
            return new IdFederationUpstream()
            {
                Key = key,
                DisplayName = IdFederationUpstreams.Value(attributes, "display_name"),
                //  **protocol は小文字で見る**（`OIDC` と書かれても通す）。
                //    **空なら OIDC**（OIDC の方が項目が多く、取り違えたときに気付きやすい）。
                Protocol = IdFederationUpstreams.Protocol(attributes),
                Enabled = IdFederationUpstreams.Enabled(attributes),
                Issuer = IdFederationUpstreams.Value(attributes, "issuer"),
                ClientId = IdFederationUpstreams.Value(attributes, "client_id"),
                ClientSecret = IdFederationUpstreams.Value(attributes, "client_secret"),
                DiscoveryUrl = IdFederationUpstreams.Value(attributes, "discovery_url"),
                JwkSetUri = IdFederationUpstreams.Value(attributes, "jwk_set_uri"),
                MetadataUrl = IdFederationUpstreams.Value(attributes, "metadata_url"),
                CerFilePath = IdFederationUpstreams.Value(attributes, "cer_file_path"),
                AuthorizeEndpoint = IdFederationUpstreams.Value(attributes, "authorize_endpoint"),
                TokenEndpoint = IdFederationUpstreams.Value(attributes, "token_endpoint"),
                UserInfoEndpoint = IdFederationUpstreams.Value(attributes, "userinfo_endpoint"),
                SsoEndpoint = IdFederationUpstreams.Value(attributes, "sso_endpoint")
            };
        }

        /// <summary>従来の単数キーから、OIDC の行を作る（互換）</summary>
        /// <returns>上流</returns>
        /// <remarks>
        /// **期待する `iss` は `SpRp_Isser`**（Open棟梁 のクライアント役の設定）。
        /// **`client_id` / `client_secret` も Open棟梁 の設定**（`OAuth2AndOidcClientID` / `…Secret`）である。
        /// **相手ごとに持つなら、設定の行へ移す**（#290 と同じ「自分の値 / 相手の値」の整理）。
        /// </remarks>
        private static IdFederationUpstream FromLegacyOidc()
        {
            return new IdFederationUpstream()
            {
                Key = IdFederationUpstreams.DefaultOidcKey,
                Protocol = IdFederationUpstream.Oidc,
                Enabled = true,
                Issuer = CmnClientParams.Isser,
                ClientId = OAuth2AndOIDCParams.ClientID,
                ClientSecret = OAuth2AndOIDCParams.ClientSecret,
                DiscoveryUrl = Config.IdFederationOidcDiscoveryUrl,
                JwkSetUri = Config.IdFederationJwkSetUri,
                CerFilePath = Config.IdFederationOidcCerFilePath,
                AuthorizeEndpoint = Config.IdFederationAuthorizeEndpoint,
                TokenEndpoint = Config.IdFederationTokenEndpoint,
                UserInfoEndpoint = Config.IdFederationUserInfoEndpoint
            };
        }

        /// <summary>従来の単数キーから、SAML2 の行を作る（互換）</summary>
        /// <returns>上流</returns>
        private static IdFederationUpstream FromLegacySaml2()
        {
            return new IdFederationUpstream()
            {
                Key = IdFederationUpstreams.DefaultSaml2Key,
                Protocol = IdFederationUpstream.Saml2,
                Enabled = true,
                Issuer = Config.IdFederationSaml2IssuerId,
                ClientId = OAuth2AndOIDCParams.ClientID,
                MetadataUrl = Config.IdFederationSaml2MetadataUrl,
                CerFilePath = Config.IdFederationSaml2CerFilePath,
                SsoEndpoint = Config.IdFederationSaml2RequestEndpoint
            };
        }

        /// <summary>属性を読む（無ければ空）</summary>
        /// <param name="attributes">属性</param>
        /// <param name="name">名前</param>
        /// <returns>値（無ければ空）</returns>
        private static string Value(Dictionary<string, string> attributes, string name)
        {
            string value;

            if (attributes != null && attributes.TryGetValue(name, out value) && value != null)
            {
                return value;
            }

            return "";
        }

        /// <summary>protocol を読む（空なら `oidc`）</summary>
        /// <param name="attributes">属性</param>
        /// <returns>`oidc` / `saml2`</returns>
        private static string Protocol(Dictionary<string, string> attributes)
        {
            string protocol = IdFederationUpstreams.Value(attributes, "protocol").ToLower();

            return (protocol == IdFederationUpstream.Saml2)
                ? IdFederationUpstream.Saml2 : IdFederationUpstream.Oidc;
        }

        /// <summary>enabled を読む（空・未設定は有効）</summary>
        /// <param name="attributes">属性</param>
        /// <returns>有効なら true</returns>
        private static bool Enabled(Dictionary<string, string> attributes)
        {
            string enabled = IdFederationUpstreams.Value(attributes, "enabled");

            if (string.IsNullOrEmpty(enabled))
            {
                return true;
            }

            bool parsed;

            //  **読めない値は「無効」にしない**（綴り違いで黙って消えるより、出た方が気付く）。
            return !bool.TryParse(enabled, out parsed) || parsed;
        }
    }
}
