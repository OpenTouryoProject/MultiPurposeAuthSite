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
//* クラス日本語名  ：ASP.NET IdentityのConfigクラス（ライブラリ）の 通知
//*
//* 作成日時        ：－
//* 作成者          ：－
//* 更新履歴        ：－
//*
//*  日時        更新者            内容
//*  ----------  ----------------  -------------------------------------------------
//*  2026/10/23  玄人 幸道         新規（Config.cs から partial に分割。#294）
//*  2026/10/29  玄人 幸道         MailOutboxDirectory（メールの送信箱。テスト用）を追加（#294）
//**********************************************************************************

using System;

using Touryo.Infrastructure.Public.Util;

/// <summary>MultiPurposeAuthSite.Co</summary>
namespace MultiPurposeAuthSite.Co
{
    /// <summary>Config（通知）</summary>
    public partial class Config
    {
        #region SMTP (Eメール)

        /// <summary>SmtpHostName</summary>
        public static string SmtpHostName
        {
            get
            {
                return GetConfigParameter.GetConfigValue("SmtpHostName");
            }
        }

        /// <summary>SmtpPortNo</summary>
        public static int SmtpPortNo
        {
            get
            {
                return Convert.ToInt32(GetConfigParameter.GetConfigValue("SmtpPortNo"));
            }
        }

        /// <summary>SmtpSSL</summary>
        public static bool SmtpSSL
        {
            get
            {
                return Convert.ToBoolean(GetConfigParameter.GetConfigValue("SmtpSSL"));
            }
        }

        /// <summary>SmtpAccountUID</summary>
        public static string SmtpAccountUID
        {
            get
            {
                return GetConfigParameter.GetConfigValue("SmtpAccountUID");
            }
        }

        /// <summary>SmtpAccountPWD</summary>
        public static string SmtpAccountPWD
        {
            get
            {
                return GetConfigParameter.GetConfigValue("SmtpAccountPWD");
            }
        }

        #endregion

        #region SMS (Twilio)

        /// <summary>TwilioAccountSid</summary>
        public static string TwilioAccountSid
        {
            get
            {
                return GetConfigParameter.GetConfigValue("TwilioAccountSid");
            }
        }

        /// <summary>TwilioAuthToken</summary>
        public static string TwilioAuthToken
        {
            get
            {
                return GetConfigParameter.GetConfigValue("TwilioAuthToken");
            }
        }

        /// <summary>TwilioFromPhoneNumber</summary>
        public static string TwilioFromPhoneNumber
        {
            get
            {
                return GetConfigParameter.GetConfigValue("TwilioFromPhoneNumber");
            }
        }

        #endregion

        #region PushNotification (FCM)

        /// <summary>FirebaseServiceAccountKey</summary>
        public static string FirebaseServiceAccountKey
        {
            get
            {
                return GetConfigParameter.GetConfigValue("FirebaseServiceAccountKey");
            }
        }

        /// <summary>
        /// FcmOutboxDirectory（テスト用）。
        /// 設定すると、プッシュ通知を FCM に送らず、このディレクトリにファイルとして書く（#196）。
        /// E2E テスト（test.ps1 -Launch）が環境変数で設定する。本番では空のままにする。
        /// </summary>
        public static string FcmOutboxDirectory
        {
            get
            {
                return GetConfigParameter.GetConfigValue("FcmOutboxDirectory");
            }
        }

        /// <summary>
        /// MailOutboxDirectory（テスト用。#294）。
        /// 設定すると、メールをこのディレクトリにファイルとして書く（`IsDebug` のときだけ。そのときは、もともと SMTP に送らない）。
        /// E2E テスト（test.ps1 -Launch）が環境変数で設定する。本番では空のままにする。
        /// **メールでしか届かない値**（メアドの確認・パスワードのリセットのリンク、2FA のコード）**を、E2E が読むために在る。**
        /// </summary>
        public static string MailOutboxDirectory
        {
            get
            {
                return GetConfigParameter.GetConfigValue("MailOutboxDirectory");
            }
        }

        #endregion
    }
}