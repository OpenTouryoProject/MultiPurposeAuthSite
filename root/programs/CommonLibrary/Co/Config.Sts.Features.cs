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
//* クラス日本語名  ：ASP.NET IdentityのConfigクラス（ライブラリ）の STS（機能の有効 / 無効）
//*
//* 作成日時        ：－
//* 作成者          ：－
//* 更新履歴        ：－
//*
//*  日時        更新者            内容
//*  ----------  ----------------  -------------------------------------------------
//*  2026/10/23  玄人 幸道         新規（Config.cs から partial に分割。#294）
//**********************************************************************************

using System;
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
    /// <summary>Config（STS（機能の有効 / 無効））</summary>
    public partial class Config
    {
        #region STS（機能の有効 / 無効）

        #region Grant Type

        /// <summary>EnableAuthorizationCodeGrantType</summary>
        public static bool EnableAuthorizationCodeGrantType
        {
            get
            {
                return Convert.ToBoolean(GetConfigParameter.GetConfigValue("EnableAuthorizationCodeGrantType"));
            }
        }

        /// <summary>EnableImplicitGrantType</summary>
        public static bool EnableImplicitGrantType
        {
            get
            {
                return Convert.ToBoolean(GetConfigParameter.GetConfigValue("EnableImplicitGrantType"));
            }
        }

        /// <summary>EnableResourceOwnerPasswordCredentialsGrantType</summary>
        public static bool EnableResourceOwnerPasswordCredentialsGrantType
        {
            get
            {
                return Convert.ToBoolean(GetConfigParameter.GetConfigValue("EnableResourceOwnerPasswordCredentialsGrantType"));
            }
        }

        /// <summary>EnableClientCredentialsGrantType</summary>
        public static bool EnableClientCredentialsGrantType
        {
            get
            {
                return Convert.ToBoolean(GetConfigParameter.GetConfigValue("EnableClientCredentialsGrantType"));
            }
        }

        /// <summary>EnableRefreshToken</summary>
        public static bool EnableRefreshToken
        {
            get
            {
                return Convert.ToBoolean(GetConfigParameter.GetConfigValue("EnableRefreshToken"));
            }
        }

        /// <summary>EnableJwtBearerTokenFlowGrantType</summary>
        public static bool EnableJwtBearerTokenFlowGrantType
        {
            get
            {
                return Convert.ToBoolean(GetConfigParameter.GetConfigValue("EnableJwtBearerTokenFlowGrantType"));
            }
        }

        /// <summary>EnableDeviceAuthZGrantType</summary>
        public static bool EnableDeviceAuthZGrantType
        {
            get
            {
                return Convert.ToBoolean(GetConfigParameter.GetConfigValue("EnableDeviceAuthZGrantType"));
            }
        }

        /// <summary>EnableCibaGrantType</summary>
        public static bool EnableCibaGrantType
        {
            get
            {
                return Convert.ToBoolean(GetConfigParameter.GetConfigValue("EnableCibaGrantType"));
            }
        }

        #endregion

        #region OpenID Connect

        /// <summary>EnableOpenIDConnect</summary>
        public static bool EnableOpenIDConnect
        {
            get
            {
                return Convert.ToBoolean(GetConfigParameter.GetConfigValue("EnableOpenIDConnect"));
            }
        }

        #endregion

        #region PKCE

        /// <summary>
        /// 認可コード フローで code_challenge（PKCE）を必須にするかどうか（#220）
        /// </summary>
        /// <remarks>
        /// OAuth 2.1 は、クライアントの種別によらず PKCE を必須とする。
        /// **既定は false（従来どおり PKCE 無しでも通る）。** 下位互換のため。
        ///
        /// **RequirePkceS256 とは別のもの。**
        /// - RequirePkce     : PKCE 自体を求める（認可エンドポイントで判定）
        /// - RequirePkceS256 : 使うなら S256 に限る（トークン エンドポイントで判定）
        ///
        /// Device AuthZ / CIBA は認可エンドポイントを通らないので、この判定に掛からない。
        /// </remarks>
        public static bool RequirePkce
        {
            get
            {
                return Convert.ToBoolean(GetConfigParameter.GetConfigValue("RequirePkce"));
            }
        }

        #endregion

        #region DPoP（#311）

        /// <summary>DPoP の証明に `nonce` を要求するか（#311 の段階 4）</summary>
        /// <remarks>
        /// **RFC 9449 §8 / §9 : サーバは `nonce` を要求してよい**（MAY）。
        /// **要求すると、クライアントは 1 往復多く掛かる**
        /// （**`use_dpop_nonce` で断られ、`DPoP-Nonce` で受け取った値を入れて出し直す**）。
        ///
        /// **既定は false** — **要求すると、`nonce` を知らないクライアントが全部止まる。**
        /// **使い回しの拒否（段階 3）は、この設定とは無関係に効いている。**
        /// </remarks>
        public static bool EnableDPoPNonce
        {
            get
            {
                return Convert.ToBoolean(GetConfigParameter.GetConfigValue("EnableDPoPNonce"));
            }
        }

        /// <summary>DPoP の `nonce` を作る鍵（#311 の段階 4）</summary>
        /// <remarks>
        /// **`nonce` は、この値から計算する**（**台帳を持たない**）。
        /// **同じ値を持つインスタンスなら、互いの `nonce` を受け付けられる。**
        ///
        /// **空なら、プロセスごとのランダムな値を使う** —
        /// **単一のインスタンスなら、それで足りる**
        /// （**再起動すると、前の `nonce` は通らなくなる** ＝ **1 往復増えるだけ**）。
        ///
        /// **インスタンスを増やす配備では、設定すること** —
        /// **設定しないと、要求が別のインスタンスへ行くたびに断られ、やり直しが終わらない。**
        /// </remarks>
        public static string DPoPNonceSecret
        {
            get
            {
                return GetConfigParameter.GetConfigValue("DPoPNonceSecret");
            }
        }

        #endregion

        #region 動的クライアント登録（#307）

        /// <summary>動的クライアント登録（RFC 7591）を開けるか（#307 の段階 1）</summary>
        /// <remarks>
        /// **既定は false**（**口そのものを張らない**）。
        ///
        /// **`Convert.ToBoolean` ではなく `bool.TryParse` で読む** —
        /// **既存の配備にはこのキーが無く、`Convert.ToBoolean("")` は例外になる**
        /// （`EnableOpenIDConnect` などの既存キーは、どちらの雛形にも在る）。
        ///
        /// **この口は `IsLockedDownTestEndpoints` の対象ではない**
        /// （**本番で使う口**であり、テスト用の口とは別に、このキーで開閉する）。
        /// </remarks>
        public static bool EnableDynamicClientRegistration
        {
            get
            {
                bool.TryParse(
                    GetConfigParameter.GetConfigValue("EnableDynamicClientRegistration"),
                    out bool enable);

                return enable;
            }
        }

        /// <summary>
        /// `software_statement`（RFC 7591 §2.3）の発行者の登録（n 件。#307 の段階 4）
        /// </summary>
        /// <remarks>
        /// **読み方は `OAuth2ClientsInformation` / `IdFederationUpstreams` と同じ**
        /// （net48 は JSON 文字列、net10.0 は節）。**値はすべて文字列**で、
        /// **鍵 → 属性の辞書**である。
        ///
        /// **解釈は <see cref="SoftwareStatementIssuers"/> が持つ。**
        /// **ここは「設定を読むだけ」**にしてある（`Config` に判断を増やさない）。
        ///
        /// **空なら、`software_statement` は受け付けない**
        /// （**従来どおり `unapproved_software_statement`**）。
        /// **既存の配備は、このキーを書かなくても従来どおり動く。**
        ///
        /// **「発行者ごと」である。** **クライアントごとではない**
        /// （クライアント自身の鍵は `Saml2OAuth2Data` の列。段階 3）。
        /// </remarks>
        public static Dictionary<string, Dictionary<string, string>> SoftwareStatementIssuers
        {
            get
            {
#if NETFX
                string json = GetConfigParameter.GetConfigValue("SoftwareStatementIssuers");

                if (string.IsNullOrEmpty(json))
                {
                    return null;
                }

                return JsonConvert.DeserializeObject<
                    Dictionary<string, Dictionary<string, string>>>(json);
#else
                IConfigurationSection section = GetConfigParameter
                    .GetAnyConfigSection("appSettings:SoftwareStatementIssuers");

                if (section == null)
                {
                    return null;
                }

                return section.Get<Dictionary<string, Dictionary<string, string>>>();
#endif
            }
        }

        /// <summary>
        /// 動的クライアント登録に `software_statement` を必須とするか（#307 の段階 4）
        /// </summary>
        /// <remarks>
        /// **既定は false**（**従来どおり、添えなくても登録できる**）。
        ///
        /// **true にすると、「審査を通したソフトウェアだけ登録させる」配備になる。**
        /// **`POST /register` と `PUT`（RFC 7592）の両方に効く。**
        ///
        /// > **`PUT` にも効かせるのが要点である。**
        /// > **効かせないと、`PUT` で statement を省いて
        /// > 「主張されていた値」を自分の値に書き換えられる**
        /// > （**statement は保管しないので、省かれたことしか分からない**）。
        ///
        /// **信頼する発行者（`SoftwareStatementIssuers`）を 1 件も書かずに true にすると、
        /// 動的登録は通らなくなる**（**必須なのに、どの statement も approved にならない**）。
        /// </remarks>
        public static bool RequireSoftwareStatement
        {
            get
            {
                bool.TryParse(
                    GetConfigParameter.GetConfigValue("RequireSoftwareStatement"),
                    out bool require);

                return require;
            }
        }

        #endregion

        #region Discovery

        /// <summary>
        /// Discovery の service_documentation（この IdP の使い方を書いた文書の URL）（#228）
        /// </summary>
        /// <remarks>
        /// **任意の項目**（OIDC Discovery 1.0 §3）。**既定は空で、空なら Discovery に出さない。**
        /// 以前は "・・・" というプレースホルダを配っていた。
        /// </remarks>
        public static string ServiceDocumentation
        {
            get
            {
                return GetConfigParameter.GetConfigValue("ServiceDocumentation");
            }
        }

        #endregion

        #endregion
    }
}