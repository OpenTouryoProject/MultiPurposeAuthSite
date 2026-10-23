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
//* クラス名        ：Config
//* クラス日本語名  ：ASP.NET IdentityのConfigクラス（ライブラリ）の ID 連携
//*
//* 作成日時        ：－
//* 作成者          ：－
//* 更新履歴        ：－
//*
//*  日時        更新者            内容
//*  ----------  ----------------  -------------------------------------------------
//*  2026/10/23  玄人 幸道         新規（Config.cs から partial に分割。#294）
//**********************************************************************************

using System.Collections.Generic;

#if NETFX
using Newtonsoft.Json;
#else
using Microsoft.Extensions.Configuration;
#endif

using Touryo.Infrastructure.Public.Util;

/// <summary>MultiPurposeAuthSite.Co</summary>
namespace MultiPurposeAuthSite.Co
{
    /// <summary>Config（ID 連携）</summary>
    public partial class Config
    {
        #region ID 連携

        #region 上流の登録（n 件。#292 の段階 1）

        /// <summary>
        /// ID 連携の上流 IdP の登録（n 件）
        /// </summary>
        /// <remarks>
        /// **読み方は `OAuth2ClientsInformation` と同じ**（net48 は JSON 文字列、net10.0 は節）。
        /// **値はすべて文字列**で、**鍵 → 属性の辞書**である。
        ///
        /// **解釈と、従来の単数キーとの互換は <see cref="IdFederationUpstreams"/> が持つ。**
        /// **ここは「設定を読むだけ」**にしてある（`Config` に判断を増やさない）。
        ///
        /// **空なら、従来の単数キーから 1〜2 件が組み立てられる**ので、
        /// **既存の配備は、このキーを書かなくても従来どおり動く。**
        /// </remarks>
        public static Dictionary<string, Dictionary<string, string>> IdFederationUpstreams
        {
            get
            {
#if NETFX
                string json = GetConfigParameter.GetConfigValue("IdFederationUpstreams");

                if (string.IsNullOrEmpty(json))
                {
                    return null;
                }

                return JsonConvert.DeserializeObject<
                    Dictionary<string, Dictionary<string, string>>>(json);
#else
                IConfigurationSection section = GetConfigParameter
                    .GetAnyConfigSection("appSettings:IdFederationUpstreams");

                if (section == null)
                {
                    return null;
                }

                return section.Get<Dictionary<string, Dictionary<string, string>>>();
#endif
            }
        }

        #endregion

        #region OIDC

        /// <summary>
        /// OIDCのID連携で、上流のdiscovery（OpenID Provider Metadata）のURL
        /// </summary>
        /// <remarks>
        /// **書けば、上流の `jwks_uri` を、ここから引く**（#289 の段階 2）。
        /// **空なら `IdFederationAuthorizeEndpoint` の基底から組み立てる**
        /// （`https://host/authorize` → `https://host/.well-known/openid-configuration`）。
        ///
        /// **SAML2 側の `IdFederationSaml2MetadataUrl` と対称**である。
        /// **「相手のメタデータの在り処」は、どちらも設定で与えられる。**
        ///
        /// **組み立てでは足りない配備がある。**
        ///
        /// | | |
        /// |---|---|
        /// | **パスの下に discovery を置く OP** | `https://host/tenant/v2.0/.well-known/openid-configuration` のような形。**基底だけでは当たらない** |
        /// | 口とメタデータでホストが違う配備 | 同上 |
        ///
        /// **`iss` そのものからは引かない**（`IdFederationOidcCerFilePath` の説明）。
        /// </remarks>
        public static string IdFederationOidcDiscoveryUrl
        {
            get
            {
                return GetConfigParameter.GetConfigValue("IdFederationOidcDiscoveryUrl");
            }
        }

        /// <summary>
        /// IDフェデレーション時の認可エンドポイント
        /// </summary>
        public static string IdFederationAuthorizeEndpoint
        {
            get
            {
                return Config.GetRenamedConfigValue("IdFederationAuthorizeEndpoint");
            }
        }

        /// <summary>
        /// IDフェデレーション時のRedirectエンドポイント
        /// </summary>
        public static string IdFederationRedirectEndpoint
        {
            get
            {
                return Config.GetRenamedConfigValue("IdFederationRedirectEndpoint");
            }
        }

        /// <summary>
        /// IDフェデレーション時のTokenエンドポイント
        /// </summary>
        public static string IdFederationTokenEndpoint
        {
            get
            {
                return Config.GetRenamedConfigValue("IdFederationTokenEndpoint");
            }
        }

        /// <summary>
        /// IDフェデレーション時のUserInfoエンドポイント
        /// </summary>
        public static string IdFederationUserInfoEndpoint
        {
            get
            {
                return Config.GetRenamedConfigValue("IdFederationUserInfoEndpoint");
            }
        }

        /// <summary>OIDCのID連携が有効か（設定が揃っているか）</summary>
        /// <remarks>
        /// **4 本すべてが要る。** **1 本でも欠けていれば、導線を出さない**（#286 の段階 2）。
        ///
        /// **以前は、サインイン画面に無条件でボタンが出ていた。**
        /// **口を設定していない配備でも押せた**ので、**押すとエラー画面に着いた。**
        /// </remarks>
        public static bool CanIdFederationByOidc
        {
            get
            {
                return !string.IsNullOrEmpty(Config.IdFederationAuthorizeEndpoint)
                    && !string.IsNullOrEmpty(Config.IdFederationRedirectEndpoint)
                    && !string.IsNullOrEmpty(Config.IdFederationTokenEndpoint)
                    && !string.IsNullOrEmpty(Config.IdFederationUserInfoEndpoint);
            }
        }

        /// <summary>
        /// OIDCのID連携で、上流のJWK SetのURL
        /// </summary>
        /// <remarks>
        /// **書けば、ここから直に引く**（discovery を読まない）。
        /// **空なら discovery の `jwks_uri` から引く**（`IdFederationOidcDiscoveryUrl`。#289 の段階 2）。
        ///
        /// | 順 | 鍵の出どころ | |
        /// |---|---|---|
        /// | 1 | **このキー**（上流の JWK Set） | **discovery を出さない OP でも、`kid` で引ける** |
        /// | 2 | discovery → `jwks_uri` → `kid` | **ロールオーバーに追随する** |
        /// | 3 | 設定の `.cer`（`IdFederationOidcCerFilePath`） | 1 本。倒れ先 |
        ///
        /// **`JwkSetUri` とは役が違う。**
        /// **`JwkSetUri` は「この配備の JWK Set の口」**（クライアント・サーバの共通設定）であり、
        /// **自分の `/jwkcerts` のパスとして読む**（ルート登録・discovery の `jwks_uri`）。
        /// **`jku` には使わない**（#302 で、ヘッダに `jku` を入れるのをやめた）。
        /// **上流（相手）の JWK Set は別の値**なので、このキーで持つ。
        ///
        /// > **信頼の根拠は、このキーを書いた人である**（discovery のような `issuer` の照合が無い）。
        /// > **`issuer` と結び付けたいなら、discovery（2 番目）を使うこと。**
        /// </remarks>
        public static string IdFederationJwkSetUri
        {
            get
            {
                return GetConfigParameter.GetConfigValue("IdFederationJwkSetUri");
            }
        }

        /// <summary>
        /// OIDCのID連携で、上流の id_token の署名を検証する証明書（.cer のパス）
        /// </summary>
        /// <remarks>
        /// **空なら、従来どおり** discovery（`jwks_uri`）から引く形は、#289 の段階 2**。
        /// </remarks>
        public static string IdFederationOidcCerFilePath
        {
            get
            {
                return GetConfigParameter.GetConfigValue("IdFederationOidcCerFilePath");
            }
        }

        #endregion

        #region SAML2

        /// <summary>
        /// SAML2のID連携で、上流のメタデータ（EntityDescriptor）のURL
        /// </summary>
        /// <remarks>
        /// **書けば、上流の SSO の口と署名証明書を、ここから引く**（#291）。
        /// **空なら従来どおり**（`IdFederationSaml2RequestEndpoint` と
        /// `IdFederationSaml2CerFilePath` を読む）。**引けなかったときも、そちらに倒れる。**
        ///
        /// | メタデータから引くもの | 設定で与える形（従来） |
        /// |---|---|
        /// | `SingleSignOnService`（HTTP-Redirect）の `Location` | `IdFederationSaml2RequestEndpoint` |
        /// | `KeyDescriptor use="signing"` の証明書 | `IdFederationSaml2CerFilePath` |
        ///
        /// **`entityID` は引かない。** **`IdFederationSaml2IssuerId` と照合する**ために使う
        /// （**一致しなければ、メタデータの値を使わない**）。
        /// **自分の ACS（`IdFederationSaml2ResponseEndpoint`）も、設定のまま**である。
        ///
        /// **SAML2 には、メタデータの既知のパスが無い**（OIDC の `/.well-known/…` に当たるものが無い）。
        /// **だから、OIDC 側（#289）のように口の URL から組み立てる形にはしていない** —
        /// **URL を設定で与える。**
        /// </remarks>
        public static string IdFederationSaml2MetadataUrl
        {
            get
            {
                return GetConfigParameter.GetConfigValue("IdFederationSaml2MetadataUrl");
            }
        }

        //  **上の 4 本は OIDC 用である。** ここは SAML2 用で、別に持つ。
        //
        //  **OIDC と SAML2 で、要る設定の数が違う。**
        //    OIDC は口が 3 つ（authorize / token / userinfo）あり、鍵は discovery から引ける前提。
        //    SAML2 は口が 1 つ（SSO）で、**鍵と EntityID を設定で与える**（#286）。
        //
        //  **1 本でも空なら、SAML2 の ID 連携は無効**（`CanIdFederationBySaml2`）。
        //    **導線（サインイン画面のボタン）も出さない。**
        //    **押しても成立しないボタンを出さないため**である。

        /// <summary>
        /// SAML2のID連携で、AuthnRequestを送る先（上流IdPのSSOの口）
        /// </summary>
        /// <remarks>
        /// **上流の `/samlmetadata` の `SingleSignOnService`（HTTP-Redirect）の値**である。
        /// </remarks>
        public static string IdFederationSaml2RequestEndpoint
        {
            get
            {
                return GetConfigParameter.GetConfigValue("IdFederationSaml2RequestEndpoint");
            }
        }

        /// <summary>
        /// SAML2のID連携で、応答（アサーション）を受け取る口（自分のACS）
        /// </summary>
        /// <remarks>
        /// **上流のクライアント登録（`redirect_uri_saml`）に、この値を登録する。**
        /// **自己テストの ACS（`Saml2ResponseEndpoint`）とは別の口**である
        /// （あちらは `IsLockedDownTestEndpoints` で閉じる）。
        /// </remarks>
        public static string IdFederationSaml2ResponseEndpoint
        {
            get
            {
                return GetConfigParameter.GetConfigValue("IdFederationSaml2ResponseEndpoint");
            }
        }

        /// <summary>
        /// SAML2のID連携で、期待する上流のIssuer（EntityID）
        /// </summary>
        /// <remarks>
        /// **上流の `/samlmetadata` の `entityID` の値**である。
        /// **OIDC の `SpRp_Isser` に当たるもの**だが、**あちらは Open棟梁 の設定**なので分けてある。
        /// </remarks>
        public static string IdFederationSaml2IssuerId
        {
            get
            {
                return GetConfigParameter.GetConfigValue("IdFederationSaml2IssuerId");
            }
        }

        /// <summary>
        /// SAML2のID連携で、上流の署名を検証する証明書（.cer のパス）
        /// </summary>
        /// <remarks>
        /// **上流の `/samlmetadata` の `KeyDescriptor use="signing"` の証明書**である。
        ///
        /// **`SpRp_RsaCerFilePath` は使えない。**
        /// **あのキーは、この配備では「自分の証明書」として読まれている**
        /// （`/samlmetadata` の広告・`JwkSet.json` の素・検証の控え）ので、
        /// **上流のものに差し替えると、そちらが壊れる**（`CmnSaml2Response` の説明）。
        /// </remarks>
        public static string IdFederationSaml2CerFilePath
        {
            get
            {
                return GetConfigParameter.GetConfigValue("IdFederationSaml2CerFilePath");
            }
        }

        /// <summary>SAML2のID連携が有効か（設定が揃っているか）</summary>
        /// <remarks>
        /// **自分の ACS と、期待する上流の EntityID は、必ず要る。**
        ///
        /// **上流の口と鍵は、2 通りのどちらかで揃っていればよい**（#291）。
        ///
        /// | | |
        /// |---|---|
        /// | **メタデータの URL** | そこから口と鍵を引く |
        /// | **口（`…RequestEndpoint`）と鍵（`…CerFilePath`）** | 従来の形 |
        ///
        /// **どちらも無ければ、導線を出さない**（押しても成立しないため）。
        /// </remarks>
        public static bool CanIdFederationBySaml2
        {
            get
            {
                if (string.IsNullOrEmpty(Config.IdFederationSaml2ResponseEndpoint)
                    || string.IsNullOrEmpty(Config.IdFederationSaml2IssuerId))
                {
                    return false;
                }

                return !string.IsNullOrEmpty(Config.IdFederationSaml2MetadataUrl)
                    || (!string.IsNullOrEmpty(Config.IdFederationSaml2RequestEndpoint)
                        && !string.IsNullOrEmpty(Config.IdFederationSaml2CerFilePath));
            }
        }

        #endregion

        #endregion
    }
}