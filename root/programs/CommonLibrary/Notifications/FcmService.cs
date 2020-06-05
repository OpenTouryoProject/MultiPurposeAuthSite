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
//* クラス名        ：FcmService
//* クラス日本語名  ：FcmService（ライブラリ）
//*
//* 作成日時        ：－
//* 作成者          ：－
//* 更新履歴        ：－
//*
//*  日時        更新者            内容
//*  ----------  ----------------  -------------------------------------------------
//*  2020/03/12  西野 大介         新規
//**********************************************************************************

using System.Collections.Generic;
using System.Threading.Tasks;

using FirebaseAdmin;
using FirebaseAdmin.Messaging;
using Google.Apis.Auth.OAuth2;

/// <summary>MultiPurposeAuthSite.Notifications</summary>
namespace MultiPurposeAuthSite.Notifications
{
    /// <summary>FcmService</summary>
    public class FcmService //: IIdentityMessageService
    {
        /// <summary>FcmService</summary>
        private static FcmService _FcmService = null;

        /// <summary>GetInstance</summary>
        /// <returns>FcmService</returns>
        public static FcmService GetInstance()
        {
            if (FcmService._FcmService == null)
            {
                FcmService._FcmService = new FcmService();
            }

            return FcmService._FcmService;
        }
        
        /// <summary>FirebaseApp</summary>
        private FirebaseApp _FirebaseApp = null;

        /// <summary>Constructor</summary>
        public FcmService()
        {
            this._FirebaseApp = FirebaseApp.Create(new AppOptions()
            {
                Credential = GoogleCredential.FromFile(Co.Config.FirebaseServiceAccountKey)
            });
        }

        /// <summary>
        /// Plug in your FCM service here to send a text message.
        /// テキスト メッセージを送信するための FCM サービスをここにプラグインします。</summary>
        /// <param name="destination">string</param>
        /// <param name="subject">string</param>
        /// <param name="body">string</param> 
        /// <param name="data">Dictionary(string, string)</param>
        /// <returns>非同期操作</returns>
        public async Task<string> SendAsync(
            string destination, string subject, string body, Dictionary<string, string> data)
        {
            FirebaseMessaging fcmMsging = FirebaseMessaging.GetMessaging(this._FirebaseApp);

            Message fcmMsg = new Message()
            {
                // コレは、バナーに出る内容
                Notification = new Notification
                {
                    Title = subject,
                    Body = body
                },

                // コレは、JSが受け取るデータ
                Data = data,

                // デバイス・トークン
                Token = destination,

                // 以下は不明
                //Condition,
                //Topic,
                //Webpush,
                //FcmOptions,
                //Android,
                //Apns,
            };

            return await fcmMsging.SendAsync(fcmMsg);
        }
    }
}