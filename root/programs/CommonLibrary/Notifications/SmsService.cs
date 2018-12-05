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
//* クラス名        ：SmsService
//* クラス日本語名  ：SmsService（ライブラリ）
//*
//* 作成日時        ：－
//* 作成者          ：－
//* 更新履歴        ：－
//*
//*  日時        更新者            内容
//*  ----------  ----------------  -------------------------------------------------
//*  2017/04/24  西野 大介         新規
//**********************************************************************************

using MultiPurposeAuthSite.Co;

using System.Threading.Tasks;
using System.Diagnostics;

using Microsoft.AspNet.Identity;

using Twilio;
using Twilio.Types;
using Twilio.Rest.Api.V2010.Account;

/// <summary>MultiPurposeAuthSite.Notifications</summary>
namespace MultiPurposeAuthSite.Notifications
{
    /// <summary>SmsService</summary>
    /// <see cref="http://www.asp.net/identity/overview/features-api/two-factor-authentication-using-sms-and-email-with-aspnet-identity"/>
    public class SmsService : IIdentityMessageService
    {
        /// <summary>
        /// Plug in your SMS service here to send a text message.
        /// テキスト メッセージを送信するための SMS サービスをここにプラグインします。</summary>
        /// <param name="message">message</param>
        /// <returns>非同期操作</returns>
        public Task SendAsync(IdentityMessage message)
        {
            if (Config.IsDebug)
            {
                // Debug.WriteLine
                Debug.WriteLine("< SmsService >");
                Debug.WriteLine("Destination : " + message.Destination);
                Debug.WriteLine("Subject     : " + message.Subject);
                Debug.WriteLine("Body        : " + message.Body);
            }
            else
            {
                TwilioClient.Init(
                    Config.TwilioAccountSid,
                    Config.TwilioAuthToken);

                MessageResource mr = MessageResource.Create(
                    to: new PhoneNumber("+" + message.Destination), // "+819074322014"
                    from: new PhoneNumber(Config.TwilioFromPhoneNumber),
                    body: message.Body);
            }

            return Task.FromResult(0);
        }
    }
}