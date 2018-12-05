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
//* クラス名        ：CmnSms
//* クラス日本語名  ：CmnSms（ライブラリ）
//*
//* 作成日時        ：－
//* 作成者          ：－
//* 更新履歴        ：－
//*
//*  日時        更新者            内容
//*  ----------  ----------------  -------------------------------------------------
//*  2018/12/05  西野 大介         新規
//**********************************************************************************

using MultiPurposeAuthSite.Co;

using System.Threading.Tasks;
using System.Diagnostics;

using Twilio;
using Twilio.Types;
using Twilio.Rest.Api.V2010.Account;

/// <summary>MultiPurposeAuthSite.Notifications</summary>
namespace MultiPurposeAuthSite.Notifications
{
    /// <summary>CmnSms</summary>
    public class CmnSms
    {
        /// <summary>SMS送信</summary>
        /// <param name="destination">string</param>
        /// <param name="body">string</param>
        /// <returns>非同期操作</returns>
        public static Task SendAsync(string destination, string body)
        {
            if (Config.IsDebug)
            {
                // Debug.WriteLine
                Debug.WriteLine("< SmsService >");
                Debug.WriteLine("Destination : " + destination);
                Debug.WriteLine("Body        : " + body);
            }
            else
            {
                TwilioClient.Init(
                    Config.TwilioAccountSid,
                    Config.TwilioAuthToken);

                MessageResource mr = MessageResource.Create(
                    to: new PhoneNumber("+" + destination), // "+819074322014"
                    from: new PhoneNumber(Config.TwilioFromPhoneNumber),
                    body: body);
            }

            return Task.FromResult(0);
        }
    }
}