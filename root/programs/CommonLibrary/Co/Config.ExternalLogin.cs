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
//* クラス日本語名  ：ASP.NET IdentityのConfigクラス（ライブラリ）の 外部ログイン
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

using Touryo.Infrastructure.Public.Util;

/// <summary>MultiPurposeAuthSite.Co</summary>
namespace MultiPurposeAuthSite.Co
{
    /// <summary>Config（外部ログイン）</summary>
    public partial class Config
    {
        #region 共通

        /// <summary>
        /// 外部 ID を既存アカウントに結び付けるとき、検証済みのメアドを要求するかどうか（#140 の段階 1）
        /// </summary>
        /// <remarks>
        /// **既定は true（要求する）。**
        /// 他の Require* と違い、**未設定を false（従来どおり）にしない。**
        /// 未検証のメアドで既存アカウントに結び付けられるのは弱点であり、
        /// **下位互換のために穴を開けたままにする既定にはしない**（#140 の段階 1）。
        ///
        /// false にすると従来どおりになる。**上流が `email_verified` を返さない場合に、
        /// それでもメアドで結び付けたいとき**の逃げ道である
        /// （その場合の代替は、ローカルでサインインしてから `/Manage/ManageLogins` で追加すること）。
        ///
        /// 判定は `Extensions.Sts.AccountLink` にある。
        /// </remarks>
        public static bool RequireVerifiedEmailForAccountLinking
        {
            get
            {
                string value = GetConfigParameter.GetConfigValue(
                    "RequireVerifiedEmailForAccountLinking");

                // **未設定は true（安全側）。** 他のキーと既定の向きが違うので、明示的に書く。
                return string.IsNullOrEmpty(value) ? true : Convert.ToBoolean(value);
            }
        }

        #endregion

        #region MicrosoftAccountAuthentication

        /// <summary>
        /// MicrosoftAccountAuthentication
        /// </summary>
        public static bool MicrosoftAccountAuthentication
        {
            get
            {
                return Convert.ToBoolean(GetConfigParameter.GetConfigValue("MicrosoftAccountAuthentication"));
            }
        }

        /// <summary>
        /// MicrosoftAccountAuthenticationのClientId
        /// </summary>
        public static string MicrosoftAccountAuthenticationClientId
        {
            get
            {
                return GetConfigParameter.GetConfigValue("MicrosoftAccountAuthenticationClientId");
            }
        }

        /// <summary>
        /// MicrosoftAccountAuthenticationのClientSecret
        /// </summary>
        public static string MicrosoftAccountAuthenticationClientSecret
        {
            get
            {
                return GetConfigParameter.GetConfigValue("MicrosoftAccountAuthenticationClientSecret");
            }
        }

        #endregion

        #region GoogleAuthentication

        /// <summary>
        /// GoogleAuthentication
        /// </summary>
        public static bool GoogleAuthentication
        {
            get
            {
                return Convert.ToBoolean(GetConfigParameter.GetConfigValue("GoogleAuthentication"));
            }
        }

        /// <summary>
        /// GoogleAuthenticationのClientId
        /// </summary>
        public static string GoogleAuthenticationClientId
        {
            get
            {
                return GetConfigParameter.GetConfigValue("GoogleAuthenticationClientId");
            }
        }

        /// <summary>
        /// GoogleAuthenticationのClientSecret
        /// </summary>
        public static string GoogleAuthenticationClientSecret
        {
            get
            {
                return GetConfigParameter.GetConfigValue("GoogleAuthenticationClientSecret");
            }
        }

        #endregion

        #region FacebookAuthentication

        /// <summary>
        /// FacebookAuthentication
        /// </summary>
        public static bool FacebookAuthentication
        {
            get
            {
                return Convert.ToBoolean(GetConfigParameter.GetConfigValue("FacebookAuthentication"));
            }
        }

        /// <summary>
        /// FacebookAuthenticationのClientId
        /// </summary>
        public static string FacebookAuthenticationClientId
        {
            get
            {
                return GetConfigParameter.GetConfigValue("FacebookAuthenticationClientId");
            }
        }

        /// <summary>
        /// FacebookAuthenticationのClientSecret
        /// </summary>
        public static string FacebookAuthenticationClientSecret
        {
            get
            {
                return GetConfigParameter.GetConfigValue("FacebookAuthenticationClientSecret");
            }
        }

        #endregion

        #region TwitterAuthentication

        /// <summary>
        /// TwitterAuthentication
        /// </summary>
        public static bool TwitterAuthentication
        {
            get
            {
                return Convert.ToBoolean(GetConfigParameter.GetConfigValue("TwitterAuthentication"));
            }
        }

        /// <summary>
        /// TwitterAuthenticationのClientId
        /// </summary>
        public static string TwitterAuthenticationClientId
        {
            get
            {
                return GetConfigParameter.GetConfigValue("TwitterAuthenticationClientId");
            }
        }

        /// <summary>
        /// TwitterAuthenticationのClientSecret
        /// </summary>
        public static string TwitterAuthenticationClientSecret
        {
            get
            {
                return GetConfigParameter.GetConfigValue("TwitterAuthenticationClientSecret");
            }
        }

        #endregion
    }
}