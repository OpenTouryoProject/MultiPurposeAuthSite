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
//* クラス名        ：EmailService
//* クラス日本語名  ：EmailService（ライブラリ）
//*
//* 作成日時        ：－
//* 作成者          ：－
//* 更新履歴        ：－
//*
//*  日時        更新者            内容
//*  ----------  ----------------  -------------------------------------------------
//*  2017/04/24  西野 大介         新規
//**********************************************************************************

using System.Threading.Tasks;
using Microsoft.AspNet.Identity;

using System.Net;
using System.Net.Mail;
using System.Diagnostics;

/// <summary>MultiPurposeAuthSite.Models.ASPNETIdentity.NotificationProvider</summary>
namespace MultiPurposeAuthSite.Models.ASPNETIdentity.NotificationProvider
{
    /// <summary>EmailService</summary>
    public class EmailService : IIdentityMessageService
    {
        /// <summary>
        /// Plug in your email service here to send an email.
        /// 電子メールを送信するには、電子メール サービスをここにプラグインします。
        /// </summary>
        /// <param name="message">message</param>
        /// <returns>非同期操作</returns>
        public Task SendAsync(IdentityMessage message)
        {
            if (ASPNETIdentityConfig.IsDebug)
            {
                // Debug.WriteLine
                Debug.WriteLine("< EmailService >");
                Debug.WriteLine("Destination : " + message.Destination);
                Debug.WriteLine("Subject     : " + message.Subject);
                Debug.WriteLine("Body        : " + message.Body);
            }
            else
            {
                // Smtp client
                using (SmtpClient smtp = new SmtpClient())
                {
                    // Smtp clientの初期化
                    smtp.Host = ASPNETIdentityConfig.SmtpHostName;
                    smtp.Port = ASPNETIdentityConfig.SmtpPortNo;
                    smtp.EnableSsl = ASPNETIdentityConfig.SmtpSSL;

                    // Network credentialの設定
                    smtp.Credentials = new NetworkCredential(
                        ASPNETIdentityConfig.SmtpAccountUID,
                        ASPNETIdentityConfig.SmtpAccountPWD);

                    // Send e-mail message
                    smtp.Send(new MailMessage(
                        ASPNETIdentityConfig.SmtpAccountUID,
                        message.Destination, message.Subject, message.Body));
                }
            }

            return Task.FromResult(0);
        }
    }
}