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
//* クラス日本語名  ：ASP.NET IdentityのConfigクラス（ライブラリ）の STS（口）
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
    /// <summary>Config（STS（口））</summary>
    public partial class Config
    {
        #region STS（口）

        #region 基底

        /// <summary>
        /// OAuth2のAuthorizationServerのEndpointのRootのURI
        /// </summary>
        public static string OAuth2AuthorizationServerEndpointsRootURI
        {
            get
            {
                return GetConfigParameter.GetConfigValue("OAuth2AuthorizationServerEndpointsRootURI");
            }
        }

        /// <summary>
        /// OAuth2ContainerizatedAuthSvrFqdnAndPort
        /// </summary>
        public static string OAuth2ContainerizatedAuthSvrFqdnAndPort
        {
            get
            {
                return GetConfigParameter.GetConfigValue("OAuth2ContainerizatedAuthSvrFqdnAndPort");
            }
        }

        /// <summary>
        /// OAuth2ContainerizatedAuthSvrEPRootURI
        /// </summary>
        public static string OAuth2ContainerizatedAuthSvrEPRootURI
        {
            get
            {
                return GetConfigParameter.GetConfigValue("OAuth2ContainerizatedAuthSvrEPRootURI");
            }
        }

        #endregion

        #region 既定

        /// <summary>
        /// OAuth2のAuthorizeエンドポイント 
        /// </summary>
        public static string OAuth2AuthorizeEndpoint
        {
            get
            {
                return GetConfigParameter.GetConfigValue("OAuth2AuthorizeEndpoint");
            }
        }

        /// <summary>
        /// OAuth2のTokenエンドポイント 
        /// </summary>
        public static string OAuth2TokenEndpoint
        {
            get
            {
                return GetConfigParameter.GetConfigValue("OAuth2TokenEndpoint");
            }
        }

        /// <summary>
        /// RP-Initiated Logout のエンドポイント（#232）
        /// </summary>
        /// <remarks>
        /// **新しいキーなので、既に配備された設定ファイルには無い。**
        /// 無ければ既定値（/end_session）を使う。**設定ファイルを直さなくても動く。**
        /// ルートの組み立て（.Substring(1)）で空文字列を渡さないためでもある。
        /// </remarks>
        public static string OAuth2EndSessionEndpoint
        {
            get
            {
                string value = GetConfigParameter.GetConfigValue("OAuth2EndSessionEndpoint");
                return string.IsNullOrEmpty(value) ? "/end_session" : value;
            }
        }

        #endregion

        #region Device AuthZ

        /// <summary>
        /// Device AuthZのAuthorizeエンドポイント 
        /// </summary>
        public static string DeviceAuthZAuthorizeEndpoint
        {
            get
            {
                return GetConfigParameter.GetConfigValue("DeviceAuthZAuthorizeEndpoint");
            }
        }

        /// <summary>
        /// Device AuthZの検証用エンドポイント
        /// </summary>
        public static string DeviceAuthZVerifyEndpoint
        {
            get
            {
                return GetConfigParameter.GetConfigValue("DeviceAuthZVerifyEndpoint");
            }
        }

        // Tokenエンドポイントは共用。

        #endregion

        #region CIBA

        /// <summary>
        /// CIBAのAuthorizeエンドポイント 
        /// </summary>
        public static string CibaAuthorizeEndpoint
        {
            get
            {
                return GetConfigParameter.GetConfigValue("CibaAuthorizeEndpoint");
            }
        }

        /// <summary>
        /// CIBAのプッッシュ結果を受信するエンドポイント
        /// </summary>
        public static string CibaPushResultEndpoint
        {
            get
            {
                return GetConfigParameter.GetConfigValue("CibaPushResultEndpoint");
            }
        }

        // Tokenエンドポイントは共用。

        #endregion

        #region WebAPI

        /// <summary>
        /// 動的クライアント登録のエンドポイント（RFC 7591 / OIDC Discovery §3 の registration_endpoint）（#307 の段階 1）
        /// </summary>
        /// <remarks>
        /// **`EnableDynamicClientRegistration` が false なら、この口は張らない。**
        /// **未設定・空なら `/register` に倒す**（**既存の配備にはこのキーが無い**）。
        /// **広告（Discovery）も、張ったときだけ行う。**
        /// </remarks>
        public static string DcrRegistrationEndpoint
        {
            get
            {
                string temp = GetConfigParameter.GetConfigValue("DcrRegistrationEndpoint");

                return string.IsNullOrEmpty(temp) ? "/register" : temp;
            }
        }

        /// <summary>
        /// OAuth2/OIDCのUserInfoエンドポイント 
        /// </summary>
        public static string OAuth2UserInfoEndpoint
        {
            get
            {
                return GetConfigParameter.GetConfigValue("OAuth2UserInfoEndpoint");
            }
        }

        /// <summary>
        /// OAuth2のRevokeエンドポイント 
        /// </summary>
        public static string OAuth2RevokeTokenEndpoint
        {
            get
            {
                return GetConfigParameter.GetConfigValue("OAuth2RevokeTokenEndpoint");
            }
        }

        /// <summary>
        /// OAuth2のIntrospectエンドポイント 
        /// </summary>
        public static string OAuth2IntrospectTokenEndpoint
        {
            get
            {
                return GetConfigParameter.GetConfigValue("OAuth2IntrospectTokenEndpoint");
            }
        }

        #endregion

        #region SAML2

        // 基本的に、OAuth2/OIDCインフラを流用

        /// <summary>
        /// Saml2のRequestエンドポイント 
        /// </summary>
        public static string Saml2RequestEndpoint
        {
            get
            {
                return GetConfigParameter.GetConfigValue("Saml2RequestEndpoint");
            }
        }

        /// <summary>
        /// Saml2のResponseエンドポイント 
        /// </summary>
        public static string Saml2ResponseEndpoint
        {
            get
            {
                return GetConfigParameter.GetConfigValue("Saml2ResponseEndpoint");
            }
        }

        #endregion

        #region その他の WebAPI

        /// <summary>
        /// Hybrid Flowのテスト用WebAPI
        /// </summary>
        public static string TestHybridFlowWebAPI
        {
            get
            {
                return GetConfigParameter.GetConfigValue("TestHybridFlowWebAPI");
            }
        }

        /// <summary>
        /// ユーザ情報にデバイス・トークンを追加するWebAPI
        /// </summary>
        public static string SetDeviceTokenWebAPI
        {
            get
            {
                return GetConfigParameter.GetConfigValue("SetDeviceTokenWebAPI");
            }
        }

        /// <summary>
        /// 2FAのプッシュ承認を受信するWebAPI（#213）
        /// </summary>
        public static string TwoFactorPushResultEndpoint
        {
            get
            {
                return GetConfigParameter.GetConfigValue("TwoFactorPushResultEndpoint");
            }
        }

        #endregion

        #region クライアント

        /// <summary>
        /// OAuth2のClientのInformation
        /// </summary>
        public static Dictionary<string, Dictionary<string, string>> OAuth2ClientsInformation
        {
            get
            {
#if NETFX
                return JsonConvert.DeserializeObject<Dictionary<string, Dictionary<string, string>>>(
                    GetConfigParameter.GetConfigValue("OAuth2ClientsInformation"));
#else
                IConfigurationSection section = GetConfigParameter
                    .GetAnyConfigSection("appSettings:OAuth2ClientsInformation");

                return section.Get<Dictionary<string, Dictionary<string, string>>>();
#endif
            }
        }

        /// <summary>
        /// profile / address のクレームの対応付け（#230）
        /// </summary>
        /// <remarks>
        /// **「どのキーを、どのクレームとして返すか」だけを持つ。**
        /// 値の在り処は `ApplicationUser.UnstructuredData`（JSON）の中のパス、
        /// または `user:&lt;項目&gt;`（白名簿。<see cref="Extensions.Sts.UserClaims"/>）。
        ///
        /// **既定は空で、何も返らない**（従来どおり）。設定した分だけ返る。
        /// どのクレームがどの scope に属するかは**仕様が決めている**ので、ここには書かせない
        /// （OIDC Core §5.4。表は `UserClaims`）。
        ///
        /// 読み方は `OAuth2ClientsInformation` と同じ（net48 は JSON 文字列、net10.0 は節）。
        /// </remarks>
        public static Dictionary<string, string> UserClaimsMapping
        {
            get
            {
                Dictionary<string, string> mapping = null;

#if NETFX
                string json = GetConfigParameter.GetConfigValue("UserClaimsMapping");

                if (!string.IsNullOrEmpty(json))
                {
                    mapping = JsonConvert.DeserializeObject<Dictionary<string, string>>(json);
                }
#else
                IConfigurationSection section = GetConfigParameter
                    .GetAnyConfigSection("appSettings:UserClaimsMapping");

                if (section != null)
                {
                    mapping = section.Get<Dictionary<string, string>>();
                }
#endif
                // **未設定・空は「対応付け無し」として扱う。** null を返して呼び先を壊さない。
                return mapping ?? new Dictionary<string, string>();
            }
        }

        /// <summary>
        /// OAuth2のClientのEndpointのRootURI
        /// </summary>
        public static string OAuth2ClientEndpointsRootURI
        {
            get
            {
                return GetConfigParameter.GetConfigValue("OAuth2ClientEndpointsRootURI");
            }
        }

        /// <summary>
        /// AccountController.OAuth2AuthorizationCodeGrantClientのRedirectエンドポイント
        /// </summary>
        public static string OAuth2AuthorizationCodeGrantClient_Account
        {
            get
            {
                return GetConfigParameter.GetConfigValue("OAuth2AuthorizationCodeGrantClient_Account");
            }
        }

        /// <summary>
        /// AccountController.OAuth2ImplicitGrantClientのRedirectエンドポイント
        /// </summary>
        public static string OAuth2ImplicitGrantClient_Account
        {
            get
            {
                return GetConfigParameter.GetConfigValue("OAuth2ImplicitGrantClient_Account");
            }
        }

        #endregion

        #region テスト用の口

        /// <summary>
        /// テスト用のエンドポイントがロックダウンされているかどうか。
        /// </summary>
        public static bool IsLockedDownTestEndpoints
        {
            get
            {
                // **旧いキー名も読む（#219）。**
                //   未設定は false（＝「開く」）なので、改名しただけだと
                //   既存の設定ファイル（旧キーしか無い）で、本番が黙って開いてしまう。
                return Convert.ToBoolean(
                    Config.GetRenamedConfigValue("IsLockedDownTestEndpoints"));
            }
        }

        #endregion

        #endregion
    }
}