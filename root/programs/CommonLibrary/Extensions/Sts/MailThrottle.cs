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
//* クラス名        ：MailThrottle
//* クラス日本語名  ：メアド検証・パスワード リセットのメールを、送り過ぎない
//*
//* 作成日時        ：－
//* 作成者          ：－
//* 更新履歴        ：－
//*
//*  日時        更新者            内容
//*  ----------  ----------------  -------------------------------------------------
//*  2026/10/28  玄人 幸道         新規（#294）
//**********************************************************************************

using MultiPurposeAuthSite.Co;
using MultiPurposeAuthSite.Log;

using System;
using System.Collections.Generic;
using System.Collections.Concurrent;

/// <summary>MultiPurposeAuthSite.Extensions.Sts</summary>
namespace MultiPurposeAuthSite.Extensions.Sts
{
    /// <summary>
    /// メアド検証・パスワード リセットのメールを、送り過ぎない（#294）。
    /// </summary>
    /// <remarks>
    /// **サインアップ・パスワードの失念は、利用者名かメアドが分かれば、誰でも何度でも押せる。**
    /// **押すたびにメールが飛ぶので、他人の受信箱をメールで埋められた。**
    /// **口ごとのレート制限**（`RateLimitProvider`）**は送信元ごとに数えるので、**
    /// **宛先が 1 つでも、送信元を変えれば止まらない。** **ここは宛先（利用者）ごとに数える。**
    ///
    /// | 鍵 | 何に効くか |
    /// |---|---|
    /// | **用途 ＋ 利用者の id** | **1 人に、同じ用途のメールを `MailResendIntervalSeconds` 秒に 1 通まで** |
    ///
    /// **断っても、画面は変えない**（**送ったかどうかを、画面から分からせない**）。
    /// **ログには残す**（最初の 1 回だけ。洪水をログの洪水にしない）。
    ///
    /// **プロセスの中に覚える**（`RateLimitProvider` と同じ。**インスタンスを増やすと、その数だけ緩くなる**）。
    /// **0（または未設定）なら、何もしない**（従来どおり）。
    /// </remarks>
    public static class MailThrottle
    {
        #region 内部の入れ物

        /// <summary>1 つの鍵の、最後に送った時刻と、断った回数</summary>
        private sealed class Entry
        {
            /// <summary>最後に送った時刻（UNIX 時刻）</summary>
            public long SentAt;

            /// <summary>その後に断った回数</summary>
            public int Refused;
        }

        /// <summary>鍵ごとの入れ物</summary>
        private static readonly ConcurrentDictionary<string, Entry> Entries
            = new ConcurrentDictionary<string, Entry>();

        /// <summary>覚えておく鍵の数の目安（超えたら、間隔を過ぎた分を捨てる）</summary>
        private const int MaxKeys = 100000;

        #endregion

        #region 用途

        /// <summary>メアド検証</summary>
        public const string PurposeEmailConfirmation = "EmailConfirmation";

        /// <summary>パスワード リセット</summary>
        public const string PurposePasswordReset = "PasswordReset";

        #endregion

        /// <summary>このメールを送ってよいか</summary>
        /// <param name="purpose">用途（`Purpose*`）</param>
        /// <param name="userId">宛先の利用者の id</param>
        /// <returns>送ってよいなら true（送ったものとして時刻を覚える）</returns>
        public static bool TryAcquire(string purpose, string userId)
        {
            int interval = Config.MailResendIntervalSeconds;

            if (interval <= 0 || string.IsNullOrEmpty(userId))
            {
                return true;
            }

            long now = MailThrottle.NowUnixSeconds();
            string key = purpose + "|" + userId;

            if (MailThrottle.MaxKeys < MailThrottle.Entries.Count)
            {
                MailThrottle.Prune(now - interval);
            }

            Entry entry = MailThrottle.Entries.GetOrAdd(key, _ => new Entry() { SentAt = long.MinValue });

            int refused = 0;

            lock (entry)
            {
                if (entry.SentAt == long.MinValue || interval <= now - entry.SentAt)
                {
                    entry.SentAt = now;
                    entry.Refused = 0;
                    return true;
                }

                entry.Refused++;
                refused = entry.Refused;
            }

            if (refused == 1)
            {
                //  **断った最初の 1 回だけ記録する**（利用者の id だけ。メアドは書かない）。
                Logging.MyOperationTrace(string.Format(
                    "The {0} mail to {1} was not sent. (within {2} seconds of the last one)",
                    purpose, userId, interval));
            }

            return false;
        }

        /// <summary>間隔を過ぎた分を捨てる</summary>
        /// <param name="threshold">これより前に送った分を捨てる（UNIX 時刻）</param>
        private static void Prune(long threshold)
        {
            foreach (KeyValuePair<string, Entry> item in MailThrottle.Entries)
            {
                bool stale = false;

                lock (item.Value)
                {
                    stale = item.Value.SentAt < threshold;
                }

                if (stale)
                {
                    Entry removed = null;
                    MailThrottle.Entries.TryRemove(item.Key, out removed);
                }
            }
        }

        /// <summary>いまの UNIX 時刻（秒）</summary>
        /// <returns>秒</returns>
        private static long NowUnixSeconds()
        {
            return DateTimeOffset.UtcNow.ToUnixTimeSeconds();
        }
    }
}
