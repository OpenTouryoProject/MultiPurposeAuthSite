//**********************************************************************************
//* Copyright (C) 2017 Hitachi Solutions,Ltd.
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
//* クラス日本語名  ：ASP.NET IdentityのConfigクラス（ライブラリ）
//*
//* 作成日時        ：－
//* 作成者          ：－
//* 更新履歴        ：－
//*
//*  日時        更新者            内容
//*  ----------  ----------------  -------------------------------------------------
//*  2017/04/24  西野 大介         新規
//*  2019/05/2*  西野 大介         SAML2対応実施
//*  2020/02/27  西野 大介         プッシュ通知、FAPI CIBA対応実施
//*  2020/06/19  西野 大介         GetConfigSectionメソッドを廃止に伴う変更
//*                                GetConfigSection → GetAnyConfigSection
//*  2020/08/04  西野 大介         コンテナ化対応実施
//*  2020/12/18  西野 大介         Device AuthZ対応実施
//*  2026/09/12  玄人 幸道         FcmOutboxDirectory（プッシュ通知の送信箱。テスト用）を追加（#196）
//*  2026/09/16  玄人 幸道         TwoFactorAuthPushResultWebAPI を削除（未実装のため）（#203）
//*  2026/09/16  玄人 幸道         TwoFactorPushResultEndpoint を追加（#213）
//*  2026/09/17  玄人 幸道         IsLockedDownRedirectEndpoint を IsLockedDownTestEndpoints に改名（#219）
//*  2026/09/17  玄人 幸道         PKCE で S256 だけを受け付ける設定を追加（#220）
//*  2026/09/18  玄人 幸道         PKCE（code_challenge）を必須にする設定を追加（#220）
//*  2026/09/24  玄人 幸道         Discovery の service_documentation を設定値にする（#228）
//*  2026/09/24  玄人 幸道         認可コードと Request Object の有効期限の設定を追加（#188）
//*  2026/09/24  玄人 幸道         PAR の口（PushedAuthorizationRequestEndpoint）を追加（#229）
//*  2026/09/25  玄人 幸道         設定キーの改名と、旧キーの読み替え（#236）
//*  2026/09/25  玄人 幸道         UserClaimsMapping（profile / address のクレームの対応付け）を追加（#230）
//*  2026/09/27  玄人 幸道         AuthRequestPushUri は Open棟梁 側で読むようにした（#236 の宿題）
//*  2026/09/27  玄人 幸道         OAuth2EndSessionEndpoint（RP-Initiated Logout）を追加（#232）
//*  2026/09/29  玄人 幸道         RequireVerifiedEmailForAccountLinking を追加（#140 の段階 1）
//*  2026/09/30  玄人 幸道         DataProtectionKeyPath を追加（#251）
//*  2026/09/30  玄人 幸道         AuthCookieName を追加（#250 の段階 4）
//*  2026/09/30  玄人 幸道         CookieNamePrefix を追加（#255）
//*  2026/10/01  玄人 幸道         RequireUniqueEmail の設定を削除（#151 の段階 3）
//*  2026/10/03  玄人 幸道         TestUserSuffix を追加（#260）
//*  2026/10/04  玄人 幸道         CorsAllowedOrigins を追加（#265）
//*  2026/10/06  玄人 幸道         SessionStoreType / SessionStoreConnectionString を追加（#256）
//*  2026/10/07  玄人 幸道         FIDOServerModeをnet10.0版だけで復活（#137）
//*  2026/10/07  玄人 幸道         Saml2AssertionExpireTimeSpanFromMinutesを専用キーにした（#276）
//*  2026/10/07  玄人 幸道         配備で切り替える設定を 4 つ追加（#279）
//*  2026/10/09  西野 大介         オンライン決済サービス系処理の削除
//*  2026/10/09  玄人 幸道         ChageToUserWebAPI（課金の口）の設定を削除
//*  2026/10/09  玄人 幸道         OAuth2AuthorizationCodeGrantClient_Manage を削除
//*  2026/10/10  玄人 幸道         SAML2のID連携の設定を追加（#286の段階1）
//*  2026/10/10  玄人 幸道         ID連携の導線を設定の有無で出す（#286の段階2）
//*  2026/10/13  玄人 幸道         自分の値と上流の値を、別の設定キーに分けた（#290）
//*  2026/10/13  玄人 幸道         上流の SAML2 メタデータの URL を設定で与えられるようにした（#291）
//*  2026/10/14  玄人 幸道         ID 連携の上流を n 件持てるようにした（IdFederationUpstreams）（#292 の段階 1）
//*  2026/10/14  玄人 幸道         user store の秘密を暗号化する鍵を追加（#297）
//*  2026/10/16  玄人 幸道         slow_down・失敗回数・レート制限の設定を追加（#305）
//*  2026/10/16  玄人 幸道         /jwkcerts のキャッシュの秒数を追加（#303。E-7）
//*  2026/10/18  玄人 幸道         動的クライアント登録の設定を追加（#307 の段階 1）
//*  2026/10/20  玄人 幸道         software_statement の設定を追加（#307 の段階 4）
//*  2026/10/21  玄人 幸道         OP のセッションの Cookie 名を追加（#310 の段階 1）
//*  2026/10/22  玄人 幸道         DPoP の nonce の設定を追加（#311 の段階 4）
//*  2026/10/22  玄人 幸道         IssuerId などを Open棟梁 の CmnServerParams に移した（#294）
//*  2026/10/22  玄人 幸道         region を処理区分ごとに並べ替えた（#294）
//*  2026/10/23  玄人 幸道         partial クラスに分割した（#294）
//**********************************************************************************

using MultiPurposeAuthSite.Data;

using System;
using System.Collections.Generic;

using Touryo.Infrastructure.Public.Util;

/// <summary>MultiPurposeAuthSite.Co</summary>
namespace MultiPurposeAuthSite.Co
{
    /// <summary>Config</summary>
    public partial class Config
    {
        #region ストア

        /// <summary>UserStoreのTypeを返す。</summary>
        public static EnumUserStoreType UserStoreType
        {
            get
            {
                switch (GetConfigParameter.GetConfigValue("UserStoreType").ToUpper())
                {
                    case "MEM":
                        return EnumUserStoreType.Memory;
                    case "SQL":
                        return EnumUserStoreType.SqlServer;
                    case "ORA":
                        return EnumUserStoreType.ODPManagedDriver;
                    case "NPG":
                        return EnumUserStoreType.PostgreSQL;
                    default:
                        return EnumUserStoreType.Memory;
                }
            }
        }

        #endregion

        #region デバッグ

        /// <summary>Debugかどうか</summary>
        public static bool IsDebug
        {
            get
            {
                if (Config.UserStoreType == EnumUserStoreType.Memory)
                {
                    return true; // Memory Provider 利用時は = Debug 扱い。
                }
                else
                {
                    return Convert.ToBoolean(GetConfigParameter.GetConfigValue("IsDebug"));
                }
            }
        }

        /// <summary>DebugTraceLogを有効にする</summary>
        /// <remarks>**改名した**（綴りが `Enabe` だった。#236）。旧いキー名も読む。</remarks>
        public static bool EnableDebugTraceLog
        {
            get
            {
                return Convert.ToBoolean(Config.GetRenamedConfigValue("EnableDebugTraceLog"));
            }
        }

        #endregion

        #region Open棟梁 に移行（キー名は同じ）

        // CmnServerParams
        // - IssuerId
        // - RsaPfxPassword / RsaPfxFilePath
        // - RequirePkceS256
        // - PreviousSigningCerFilePaths

        // OAuth2AndOIDCParams
        // - AuthRequestPushUri（PAR（RFC 9126）のエンドポイント
        // - その他、移行前からSPRPで使用するパラメタを定義している。

        #endregion

        #region 改名した設定キー（#236）

        /// <summary>改名した設定キー（新しい名前 → 改名前の名前。#236）</summary>
        /// <remarks>
        /// **改名しても、旧いキー名を読み続ける**（#219 で始めた扱い）。
        /// 設定ファイルは配備済みのものがあり、**改名だけで黙って既定値に戻ると危ない**ため。
        /// 旧いキー名だけが設定されている場合は、起動時に ProductionCheck が警告する。
        ///
        /// **ここに載せたキーは、Config 側も新しい名前で読むこと**
        /// （<see cref="GetRenamedConfigValue"/> を通す）。
        /// </remarks>
        public static readonly Dictionary<string, string> RenamedKeys =
            new Dictionary<string, string>()
            {
                // テスト用の口をまとめて閉じるキー（#219）
                { "IsLockedDownTestEndpoints", "IsLockedDownRedirectEndpoint" },
                // 綴りの誤り（Enabe → Enable。#236）
                { "EnableDebugTraceLog", "EnabeDebugTraceLog" },
                // EndPoint → Endpoint（この実装の他のキーに揃えた。#236）
                { "IdFederationAuthorizeEndpoint", "IdFederationAuthorizeEndPoint" },
                { "IdFederationRedirectEndpoint", "IdFederationRedirectEndPoint" },
                { "IdFederationTokenEndpoint", "IdFederationTokenEndPoint" },
                { "IdFederationUserInfoEndpoint", "IdFederationUserInfoEndPoint" },
            };

        /// <summary>改名した設定キーの値を読む（新しい名前を優先し、無ければ旧い名前）</summary>
        /// <param name="key">新しいキー名（<see cref="RenamedKeys"/> に載っているもの）</param>
        /// <returns>値</returns>
        private static string GetRenamedConfigValue(string key)
        {
            string value = GetConfigParameter.GetConfigValue(key);

            if (string.IsNullOrEmpty(value))
            {
                value = GetConfigParameter.GetConfigValue(Config.RenamedKeys[key]);
            }

            return value;
        }

        /// <summary>
        /// 旧いキー名だけが設定されているものを返す（起動時の警告に使う）
        /// </summary>
        /// <returns>「旧いキー名 → 新しいキー名」の一覧（無ければ空）</returns>
        public static List<KeyValuePair<string, string>> OldKeysStillUsed()
        {
            List<KeyValuePair<string, string>> used = new List<KeyValuePair<string, string>>();

            foreach (KeyValuePair<string, string> renamed in Config.RenamedKeys)
            {
                if (string.IsNullOrEmpty(GetConfigParameter.GetConfigValue(renamed.Key))
                    && !string.IsNullOrEmpty(GetConfigParameter.GetConfigValue(renamed.Value)))
                {
                    used.Add(new KeyValuePair<string, string>(renamed.Value, renamed.Key));
                }
            }

            return used;
        }

        #endregion
    }
}