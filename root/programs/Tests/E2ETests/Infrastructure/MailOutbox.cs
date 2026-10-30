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
//* クラス名        ：MailOutbox
//* クラス日本語名  ：メールの送信箱（テスト用）を読む
//*
//* 作成日時        ：－
//* 作成者          ：－
//* 更新履歴        ：－
//*
//*  日時        更新者            内容
//*  ----------  ----------------  -------------------------------------------------
//*  2026/10/29  玄人 幸道         新規（#294）
//**********************************************************************************

using System;
using System.IO;
using System.Net;
using System.Text.Json;
using System.Text.RegularExpressions;
using System.Threading.Tasks;

using Xunit;

namespace MultiPurposeAuthSite.Tests.E2E.Infrastructure
{
    /// <summary>
    /// メールの送信箱（テスト用）を読む（#294）。
    /// </summary>
    /// <remarks>
    /// **サイトは、IsDebug で構成の MailOutboxDirectory が設定されているとき、**
    /// **メールを送信箱にファイル（JSON）として書く**（`CmnEmail`。プッシュ通知の `FcmOutbox` と同じ形）。
    /// **メールでしか届かない値**（メアドの確認・パスワードのリセットのリンク、2FA のコード）**を、ここから読む。**
    ///
    /// **test.ps1 -Launch が、サイトごとに送信箱を作って渡す**（MPAS_CORE_MAIL_OUTBOX / MPAS_NETFX_MAIL_OUTBOX）。
    /// **渡されていなければ Skip する**（起動済みのサイトを叩くときは、読めない）。
    /// </remarks>
    public static class MailOutbox
    {
        /// <summary>送信箱のメール</summary>
        public sealed class Message
        {
            /// <summary>宛先</summary>
            public string Destination { get; set; }

            /// <summary>件名</summary>
            public string Subject { get; set; }

            /// <summary>本文</summary>
            public string Body { get; set; }
        }

        /// <summary>送信箱が無ければ Skip する</summary>
        /// <param name="target">TargetInfo</param>
        public static void SkipIfUnavailable(TargetInfo target)
        {
            Skip.If(string.IsNullOrEmpty(target.MailOutbox),
                "メールの送信箱が設定されていません（test.ps1 -Launch で起動したときだけ測る）。");
        }

        /// <summary>宛先と条件に合うメールが届くまで待つ</summary>
        /// <param name="target">TargetInfo</param>
        /// <param name="destination">宛先（大文字小文字は区別しない）</param>
        /// <param name="contains">本文に含まれる文字列（null なら問わない）</param>
        /// <param name="timeout">待つ長さ</param>
        /// <returns>メール（届かなければ null）</returns>
        /// <remarks>**送信は要求から切り離してある**（#294）ので、応答の後に届く。**少し待つ。**</remarks>
        public static async Task<Message> WaitForAsync(
            TargetInfo target, string destination, string contains, TimeSpan timeout)
        {
            DateTime limit = DateTime.UtcNow + timeout;

            while (true)
            {
                if (Directory.Exists(target.MailOutbox))
                {
                    foreach (string path in Directory.GetFiles(target.MailOutbox, "*.json"))
                    {
                        Message message = MailOutbox.Read(path);

                        if (string.Equals(message.Destination, destination, StringComparison.OrdinalIgnoreCase)
                            && (contains == null || (message.Body ?? "").Contains(contains)))
                        {
                            return message;
                        }
                    }
                }

                if (limit < DateTime.UtcNow)
                {
                    return null;
                }

                await Task.Delay(200);
            }
        }

        /// <summary>宛先と条件に合うメールの数（今、届いている分）</summary>
        /// <param name="target">TargetInfo</param>
        /// <param name="destination">宛先（大文字小文字は区別しない）</param>
        /// <param name="contains">本文に含まれる文字列（null なら問わない）</param>
        /// <returns>数</returns>
        /// <remarks>**送らないこと**を確かめるときに使う（送信は要求から切り離してあるので、呼ぶ前に少し待つ）。</remarks>
        public static int Count(TargetInfo target, string destination, string contains)
        {
            if (!Directory.Exists(target.MailOutbox))
            {
                return 0;
            }

            int count = 0;

            foreach (string path in Directory.GetFiles(target.MailOutbox, "*.json"))
            {
                Message message = MailOutbox.Read(path);

                if (string.Equals(message.Destination, destination, StringComparison.OrdinalIgnoreCase)
                    && (contains == null || (message.Body ?? "").Contains(contains)))
                {
                    count++;
                }
            }

            return count;
        }

        /// <summary>本文から、パスを含む URL を取り出す</summary>
        /// <param name="message">メール</param>
        /// <param name="pathPart">URL に含まれるパス（/Account/EmailConfirmation など）</param>
        /// <returns>URL（無ければ null）</returns>
        public static string FindUrl(Message message, string pathPart)
        {
            string body = WebUtility.HtmlDecode(message.Body ?? "");

            foreach (Match m in Regex.Matches(body, "https?://[^\\s\"'<>]+"))
            {
                if (m.Value.IndexOf(pathPart, StringComparison.OrdinalIgnoreCase) >= 0)
                {
                    return m.Value;
                }
            }

            return null;
        }

        /// <summary>本文から、6 桁のコードを取り出す（2FA）</summary>
        /// <param name="message">メール</param>
        /// <returns>コード（無ければ null）</returns>
        public static string FindCode(Message message)
        {
            Match m = Regex.Match(message.Body ?? "", "(?<![0-9])[0-9]{6}(?![0-9])");
            return m.Success ? m.Value : null;
        }

        /// <summary>ファイルを読む</summary>
        /// <param name="path">パス</param>
        /// <returns>メール</returns>
        private static Message Read(string path)
        {
            using (JsonDocument doc = JsonDocument.Parse(File.ReadAllText(path)))
            {
                JsonElement root = doc.RootElement;

                return new Message()
                {
                    Destination = MailOutbox.StringOf(root, "destination"),
                    Subject = MailOutbox.StringOf(root, "subject"),
                    Body = MailOutbox.StringOf(root, "body")
                };
            }
        }

        /// <summary>文字列の値を読む</summary>
        /// <param name="root">JsonElement</param>
        /// <param name="name">名前</param>
        /// <returns>値（無ければ null）</returns>
        private static string StringOf(JsonElement root, string name)
        {
            JsonElement value;

            return (root.TryGetProperty(name, out value) && value.ValueKind == JsonValueKind.String)
                ? value.GetString() : null;
        }
    }
}
