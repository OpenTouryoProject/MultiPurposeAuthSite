//**********************************************************************************
//* クラス名        ：TestOutbox
//* クラス日本語名  ：送信箱（E2E 用）
//*
//* 作成日時        ：－
//* 作成者          ：－
//* 更新履歴        ：－
//*
//*  日時        更新者            内容
//*  ----------  ----------------  -------------------------------------------------
//*  2026/11/03  玄人 幸道         新規（CmnEmail・FcmService から切り出し。#294）
//**********************************************************************************

using MultiPurposeAuthSite.Co;

using System;
using System.Collections.Generic;
using System.IO;
using System.Net.Mail;

using Newtonsoft.Json;

/// <summary>MultiPurposeAuthSite.Util.Test</summary>
namespace MultiPurposeAuthSite.Util.Test
{
    /// <summary>送信箱（E2E 用）</summary>
    /// <remarks>
    /// **メールとプッシュ通知でしか届かない値を、E2E が読むために、ファイルへ書く。**
    /// **`IsDebug` のときだけ働く。**
    /// **製品の経路（`CmnEmail`・`FcmService`）から呼ばれる例外である**（`QUALITY.md` 1 節）。
    /// </remarks>
    public static class TestOutbox
    {
        /// <summary>送信を失敗させるドメイン</summary>
        /// <remarks>**E2E が、送信の失敗でサイトが落ちないことを測るために使う**（`RT-294.14`）。</remarks>
        public const string MailFailureDomain = "e2e-mail-failure.invalid";

        /// <summary>FCM の送信箱を使うか</summary>
        /// <remarks>**`IsDebug` でなければ、設定があっても使わない**（#294。2FA のコードをファイルに書かない）。</remarks>
        public static bool UsesFcmOutbox
        {
            get
            {
                return Config.IsDebug && !string.IsNullOrEmpty(Config.FcmOutboxDirectory);
            }
        }

        /// <summary>メールを受け取る（呼ぶ側が IsDebug を確かめる）</summary>
        /// <param name="destination">宛先</param>
        /// <param name="subject">件名</param>
        /// <param name="body">本文</param>
        public static void CaptureMail(string destination, string subject, string body)
        {
            //  **このドメイン宛ては、SMTP の失敗と同じく例外にする**（RFC 2606 の `.invalid`）。
            if (!string.IsNullOrEmpty(destination)
                && destination.EndsWith("@" + TestOutbox.MailFailureDomain, StringComparison.OrdinalIgnoreCase))
            {
                throw new SmtpException("The mail to the test failure domain was refused. (IsDebug)");
            }

            string outbox = Config.MailOutboxDirectory;

            if (!string.IsNullOrEmpty(outbox))
            {
                TestOutbox.Write(outbox, new Dictionary<string, string>()
                {
                    { "destination", destination },
                    { "subject", subject },
                    { "body", body }
                });
            }
        }

        /// <summary>プッシュ通知を受け取る（呼ぶ側が UsesFcmOutbox を確かめる）</summary>
        /// <param name="destination">デバイス トークン</param>
        /// <param name="subject">件名</param>
        /// <param name="body">本文</param>
        /// <param name="data">データ</param>
        /// <returns>送信の結果の代わりの値</returns>
        public static string CaptureFcm(
            string destination, string subject, string body, Dictionary<string, string> data)
        {
            return "outbox:" + TestOutbox.Write(Config.FcmOutboxDirectory, new Dictionary<string, object>()
            {
                { "token", destination },
                { "title", subject },
                { "body", body },
                { "data", data }
            });
        }

        /// <summary>送信箱に書く</summary>
        /// <param name="outbox">ディレクトリ</param>
        /// <param name="content">内容</param>
        /// <returns>ファイル名（拡張子なし）</returns>
        /// <remarks>**書き終えてから名前を付け替える**（読む側が、書きかけを読まないように）。</remarks>
        private static string Write(string outbox, object content)
        {
            Directory.CreateDirectory(outbox);

            string name = DateTime.UtcNow.ToString("yyyyMMddHHmmssfff") + "_" + Guid.NewGuid().ToString("N");
            string temp = Path.Combine(outbox, name + ".tmp");

            File.WriteAllText(temp, JsonConvert.SerializeObject(content, Formatting.Indented));
            File.Move(temp, Path.Combine(outbox, name + ".json"));

            return name;
        }
    }
}
