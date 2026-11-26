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
//*  2026/11/26  玄人 幸道         ほかのプロセスが開いていて読めないファイルは、待ちでは次の周回で読み直し、数えるときは読み直してから落とす（#373）
//**********************************************************************************

using System;
using System.IO;
using System.Net;
using System.Text.Json;
using System.Text.RegularExpressions;
using System.Threading;
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
    ///
    /// **ほかのプロセスがファイルを開いていると、読めないことがある**（#373。書く側は `.tmp` に書き終えてから名前を付け替えるので、
    /// 書きかけではない。付け替えた直後に、ウイルス対策・インデクサが開いたとみている）。
    /// **待つ口は、その周回では飛ばして次の周回で読み直す。** **数える口（`Count`）は、読み直してから落とす**（飛ばすと数え漏らし、「送らない」を誤って通す）。
    /// </remarks>
    public static class MailOutbox
    {
        /// <summary>数えるときに読み直す回数（#373）</summary>
        private const int CountReadAttempts = 10;

        /// <summary>数えるときに読み直す間隔（ミリ秒。#373）</summary>
        private const int CountReadIntervalMs = 100;

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
                        //  **読めなければ、この周回では飛ばす**（次の周回で読み直す。#373）。
                        if (!MailOutbox.TryRead(path, out Message message))
                        {
                            continue;
                        }

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
                //  **飛ばさない**（数え漏らすと、「送らない」を誤って通す。#373）。
                Message message = MailOutbox.ReadWithRetry(path);

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

        /// <summary>ファイルを読む（ほかのプロセスが開いていて読めなければ false。#373）</summary>
        /// <param name="path">パス</param>
        /// <param name="message">メール（読めなければ null）</param>
        /// <returns>読めたら true</returns>
        private static bool TryRead(string path, out Message message)
        {
            try
            {
                message = MailOutbox.Read(path);
                return true;
            }
            catch (IOException)
            {
                message = null;
                return false;
            }
        }

        /// <summary>ファイルを読む（読めなければ、少し待って読み直す。それでも読めなければ例外。#373）</summary>
        /// <param name="path">パス</param>
        /// <returns>メール</returns>
        private static Message ReadWithRetry(string path)
        {
            for (int i = 1; ; i++)
            {
                try
                {
                    return MailOutbox.Read(path);
                }
                catch (IOException) when (i < MailOutbox.CountReadAttempts)
                {
                    Thread.Sleep(MailOutbox.CountReadIntervalMs);
                }
            }
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
