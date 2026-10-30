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
//* クラス名        ：CmnEmail
//* クラス日本語名  ：CmnEmail（ライブラリ）
//*
//* 作成日時        ：－
//* 作成者          ：－
//* 更新履歴        ：－
//*
//*  日時        更新者            内容
//*  ----------  ----------------  -------------------------------------------------
//*  2018/12/05  西野 大介         新規
//*  2026/10/28  玄人 幸道         IsDebug のとき、試験用のドメイン宛ての送信を失敗させる（#294）
//*  2026/10/29  玄人 幸道         IsDebug のとき、送信箱（MailOutboxDirectory）が在れば、ファイルとして書く（#294）
//**********************************************************************************

using MultiPurposeAuthSite.Co;

using System;
using System.Collections.Generic;
using System.IO;
using System.Threading.Tasks;

using System.Net;
using System.Net.Mail;
using System.Diagnostics;

using Newtonsoft.Json;

/// <summary>MultiPurposeAuthSite.Notifications</summary>
namespace MultiPurposeAuthSite.Notifications
{
    /// <summary>CmnEmail</summary>
    public class CmnEmail
    {
        /// <summary>
        /// 送信を失敗させるドメイン（`IsDebug` のときだけ。#294）
        /// </summary>
        /// <remarks>**E2E が、送信の失敗でサイトが落ちないことを測るために使う**（`RT-294.14`）。</remarks>
        public const string FailureDomainForTest = "e2e-mail-failure.invalid";

        /// <summary>送信箱（テスト用）にメールを書く（#294）</summary>
        /// <param name="outbox">ディレクトリ</param>
        /// <param name="destination">宛先</param>
        /// <param name="subject">件名</param>
        /// <param name="body">本文</param>
        /// <remarks>**書き終えてから名前を付け替える**（読む側が、書きかけのファイルを読まないように。FcmService と同じ）。</remarks>
        private static void WriteToOutbox(string outbox, string destination, string subject, string body)
        {
            Directory.CreateDirectory(outbox);

            string name = DateTime.UtcNow.ToString("yyyyMMddHHmmssfff") + "_" + Guid.NewGuid().ToString("N");
            string temp = Path.Combine(outbox, name + ".tmp");

            File.WriteAllText(temp, JsonConvert.SerializeObject(new Dictionary<string, string>()
            {
                { "destination", destination },
                { "subject", subject },
                { "body", body }
            }, Formatting.Indented));

            File.Move(temp, Path.Combine(outbox, name + ".json"));
        }

        /// <summary>電子メール送信</summary>
        /// <param name="destination">string</param>
        /// <param name="subject">string</param>
        /// <param name="body">string</param>
        /// <returns>非同期操作</returns>
        public static Task SendAsync(string destination, string subject, string body)
        {
            if (Config.IsDebug)
            {
                //  **送信の失敗を、E2E から起こせるようにする**（#294。`IsDebug` のときだけ）。
                //    **このドメイン宛ては、SMTP の失敗と同じく例外にする**（RFC 2606 の `.invalid`。実在しない）。
                //    **失敗してもサイトが落ちないこと**を `RT-294.14` が測る。
                if (!string.IsNullOrEmpty(destination)
                    && destination.EndsWith("@" + CmnEmail.FailureDomainForTest, StringComparison.OrdinalIgnoreCase))
                {
                    throw new SmtpException("The mail to the test failure domain was refused. (IsDebug)");
                }

                //  **送信箱（テスト用）が設定されていれば、ファイルとして書く**（#294。FcmOutboxDirectory と同じ形）。
                //    **メールでしか届かない値**（確認・リセットのリンク、2FA のコード）**を、E2E が読む。**
                string outbox = Config.MailOutboxDirectory;

                if (!string.IsNullOrEmpty(outbox))
                {
                    CmnEmail.WriteToOutbox(outbox, destination, subject, body);
                }

                // Debug.WriteLine
                Debug.WriteLine("< EmailService >");
                Debug.WriteLine("Destination : " + destination);
                Debug.WriteLine("Subject     : " + subject);
                Debug.WriteLine("Body        : " + body);
            }
            else
            {
                // Smtp client
                using (SmtpClient smtp = new SmtpClient())
                {
                    // Smtp clientの初期化
                    smtp.Host = Config.SmtpHostName;
                    smtp.Port = Config.SmtpPortNo;
                    smtp.EnableSsl = Config.SmtpSSL;

                    // Network credentialの設定
                    smtp.Credentials = new NetworkCredential(
                        Config.SmtpAccountUID,
                        Config.SmtpAccountPWD);

                    // Send e-mail message
                    smtp.Send(new MailMessage(
                        Config.SmtpAccountUID,
                        destination, subject, body));
                }
            }

            return Task.FromResult(0);
        }
    }
}