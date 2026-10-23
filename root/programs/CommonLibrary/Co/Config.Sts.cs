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
//* クラス日本語名  ：ASP.NET IdentityのConfigクラス（ライブラリ）の STS（鍵・有効期間）
//*
//* 作成日時        ：－
//* 作成者          ：－
//* 更新履歴        ：－
//*
//*  日時        更新者            内容
//*  ----------  ----------------  -------------------------------------------------
//*  2026/10/23  玄人 幸道         新規（Config.cs から partial に分割。#294）
//*  2026/10/23  玄人 幸道         SaltParameter を秘密の region に入れ、有効期間の並びと説明を直した（#294）
//**********************************************************************************

using System;

using Touryo.Infrastructure.Public.Util;

/// <summary>MultiPurposeAuthSite.Co</summary>
namespace MultiPurposeAuthSite.Co
{
    /// <summary>Config（STS（鍵・有効期間））</summary>
    public partial class Config
    {
        #region 秘密（PPID ほか）

        /// <summary>
        /// 本サイトでSaltとして機能する値
        /// - PPID生成に使用するSalt
        /// - 外部ログイン追加時のXSRF防止
        /// </summary>
        public static string SaltParameter
        {
            get
            {
                return GetConfigParameter.GetConfigValue("SaltParameter");
            }
        }

        #endregion

        #region 鍵（ECDSA）

        /// <summary>
        /// ECDSA署名用証明書（*.pfx）のパスワード
        /// </summary>
        public static string EcdsaPfxPassword
        {
            get
            {
                return GetConfigParameter.GetConfigValue("EcdsaPfxPassword");
            }
        }

        /// <summary>
        /// ECDSA署名用証明書（*.pfx）のパス
        /// </summary>
        public static string EcdsaPfxFilePath
        {
            get
            {
                return GetConfigParameter.GetConfigValue("EcdsaPfxFilePath");
            }
        }

        #endregion

        #region 有効期間

        //  **並びは、SAML2 → 認可の流れ（Request Object → 認可コード → access_token → refresh_token → id_token）
        //  → 拡張（Device AuthZ → CIBA → 動的クライアント登録）**の順。

        /// <summary>
        /// SAML2 Assertionの有効期限（分）
        /// </summary>
        /// <remarks>
        /// **専用のキーを読む**（#276）。
        /// **以前は `OidcIdTokenExpireTimeSpanFromMinutes` を読んでいた**が、
        /// **この名前のキーはどちらの雛形にも在らなかった**。
        ///
        /// **キーが無ければ、従来どおり id_token の値を使う**
        /// （**既存の配備を壊さないため**）。
        ///
        /// > **単位に注意。** `SAML2Client.CreateRedirectResponse` / `CreatePostResponse` の引数は
        /// > **`double expiresInSeconds`（秒）** である。
        /// > **渡すときに 60 を掛けること**（`SamlProviders/CmnEndpoints`。#294）。
        /// </remarks>
        public static double Saml2AssertionExpireTimeSpanFromMinutes
        {
            get
            {
                string temp = GetConfigParameter.GetConfigValue("Saml2AssertionExpireTimeSpanFromMinutes");

                if (string.IsNullOrEmpty(temp))
                {
                    // **従来の振る舞い**（id_token の値を流用）。
                    temp = GetConfigParameter.GetConfigValue("OidcIdTokenExpireTimeSpanFromMinutes");
                }

                return double.Parse(temp);
            }
        }

        /// <summary>
        /// Request Object（/ros に預けたもの）の有効期限（秒）（#188）
        /// </summary>
        /// <remarks>
        /// **預けてから認可要求に使うまでの短い時間だけ有効にする。**
        /// 以前は CreatedDate を書くだけで読んでおらず、事実上の無期限だった。
        /// </remarks>
        public static TimeSpan RequestObjectExpireTimeSpanFromSeconds
        {
            get
            {
                return TimeSpan.FromSeconds(int.Parse(
                    GetConfigParameter.GetConfigValue("RequestObjectExpireTimeSpanFromSeconds")));
            }
        }

        /// <summary>
        /// OAuth2の認可コードの有効期限（秒）（#188）
        /// </summary>
        /// <remarks>
        /// **RFC 6749 §4.1.2 は「短命（10 分以内を推奨）」を求めている。**
        /// 以前は CreatedDate を書くだけで読んでおらず、事実上の無期限だった。
        /// </remarks>
        public static TimeSpan OAuth2AuthorizationCodeExpireTimeSpanFromSeconds
        {
            get
            {
                return TimeSpan.FromSeconds(int.Parse(
                    GetConfigParameter.GetConfigValue("OAuth2AuthorizationCodeExpireTimeSpanFromSeconds")));
            }
        }

        /// <summary>
        /// OAuth2のAccessTokenの有効期限（分）
        /// </summary>
        public static TimeSpan OAuth2AccessTokenExpireTimeSpanFromMinutes
        {
            get
            {
                return TimeSpan.FromMinutes(int.Parse(GetConfigParameter.GetConfigValue("OAuth2AccessTokenExpireTimeSpanFromMinutes")));
            }
        }

        /// <summary>
        /// OAuth2のRefreshTokenの有効期限（日）
        /// </summary>
        public static TimeSpan OAuth2RefreshTokenExpireTimeSpanFromDays
        {
            get
            {
                return TimeSpan.FromDays(int.Parse(GetConfigParameter.GetConfigValue("OAuth2RefreshTokenExpireTimeSpanFromDays")));
            }
        }

        /// <summary>
        /// OIDCのIdTokenの有効期限（分）
        /// </summary>
        public static TimeSpan OidcIdTokenExpireTimeSpanFromMinutes
        {
            get
            {
                return TimeSpan.FromMinutes(int.Parse(GetConfigParameter.GetConfigValue("OidcIdTokenExpireTimeSpanFromMinutes")));
            }
        }

        /// <summary>
        /// Device AuthZのdevice_codeの有効期限（秒）
        /// </summary>
        public static int DeviceAuthZExpireTimeSpanFromSeconds
        {
            get
            {
                return int.Parse(GetConfigParameter.GetConfigValue("DeviceAuthZExpireTimeSpanFromSeconds"));
            }
        }

        /// <summary>
        /// CIBAのauth_req_idの有効期限（秒）
        /// </summary>
        public static int CibaExpireTimeSpanFromSeconds
        {
            get
            {
                return int.Parse(GetConfigParameter.GetConfigValue("CibaExpireTimeSpanFromSeconds"));
            }
        }

        /// <summary>
        /// DCRの管理 API 専用のアクセス トークンの有効期限（秒）（#307 の段階 1）
        /// </summary>
        /// <remarks>
        /// **`Const.ScopeClientRegistration` を要求したときだけ、この期限で出す。**
        /// **配備ぜんたいの `OAuth2AccessTokenExpireTimeSpanFromMinutes`（既定 360 分）では長すぎる** —
        /// **この口は、人の操作より CI から叩く想定**で、長く持たせる理由が無い。
        ///
        /// **未設定・空なら既定値（300 秒）に倒す**（**既存の配備にはこのキーが無い**）。
        /// **倒れ先を読む先例は `Saml2AssertionExpireTimeSpanFromMinutes`**（#276）。
        ///
        /// > **0 以下を書いたときも既定値に倒す。**
        /// > **0 は「発行した瞬間に切れるトークン」であり、設定の誤りとしか考えられない。**
        /// </remarks>
        public static TimeSpan DcrAccessTokenExpireTimeSpanFromSeconds
        {
            get
            {
                string temp = GetConfigParameter.GetConfigValue(
                    "DcrAccessTokenExpireTimeSpanFromSeconds");

                if (!int.TryParse(temp, out int seconds) || seconds <= 0)
                {
                    //  **既定値**（キーが無い配備でも動く）。
                    seconds = 300;
                }

                return TimeSpan.FromSeconds(seconds);
            }
        }

        #endregion

        #region ポーリングの間隔

        /// <summary>
        /// Device AuthZのPollingのInterval（秒）
        /// </summary>
        public static int DeviceAuthZPollingIntervalSeconds
        {
            get
            {
                return int.Parse(GetConfigParameter.GetConfigValue("DeviceAuthZPollingIntervalSeconds"));
            }
        }

        /// <summary>
        /// CIBAのPollingのInterval（秒）
        /// </summary>
        public static int CibaPollingIntervalSeconds
        {
            get
            {
                return int.Parse(GetConfigParameter.GetConfigValue("CibaPollingIntervalSeconds"));
            }
        }

        #endregion

        #region /jwkcerts のキャッシュ（#303。E-7）

        /// <summary>
        /// `/jwkcerts` の応答に付ける `Cache-Control: public, max-age=` の秒数
        /// </summary>
        /// <remarks>
        /// **`/jwkcerts` は、トークンを検証する相手が必ず読む口**である。
        /// **内容は鍵を入れ替えるまで変わらない**ので、**持ち回らせてよい。**
        ///
        /// | 値 | |
        /// |---|---|
        /// | **0（または未設定）** | **`no-store`**（**従来どおり**。毎回取りに来る） |
        /// | 正の秒数 | **`public, max-age=<秒>`** ＋ `ETag`（`If-None-Match` に `304`） |
        ///
        /// **鍵を入れ替えた直後は、この秒数の間だけ古い鍵を見る相手が居る。**
        /// **出す側は新旧 2 本を広告する**作りにしてある（#291 / #292 の段階 3）ので、
        /// **入れ替えの最中も検証は通る。** **入れ替えの周期より短くすること。**
        ///
        /// **サーバ側で覚える分は、この値に関係なく効く**
        /// （Open棟梁 の `JwkSetDocument`。**ファイルの更新を見て読み直す**）。
        /// </remarks>
        public static int JwkSetCacheMaxAgeSeconds
        {
            get
            {
                string value = GetConfigParameter.GetConfigValue("JwkSetCacheMaxAgeSeconds");

                if (string.IsNullOrEmpty(value))
                {
                    //  **未設定なら 0**（従来どおり `no-store`）。
                    return 0;
                }

                int seconds = 0;
                return int.TryParse(value, out seconds) ? seconds : 0;
            }
        }

        #endregion
    }
}