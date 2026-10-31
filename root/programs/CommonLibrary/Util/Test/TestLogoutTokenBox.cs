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
//* クラス名        ：TestLogoutTokenBox
//* クラス日本語名  ：自己テスト用の logout_token の受信箱
//*
//* 作成日時        ：－
//* 作成者          ：－
//* 更新履歴        ：－
//*
//*  日時        更新者            内容
//*  ----------  ----------------  -------------------------------------------------
//*  2026/10/21  玄人 幸道         新規（#310 の段階 2）
//*  2026/10/31  玄人 幸道         Extensions/Sts から Util/Test へ移した（配置の見直し。#294）
//**********************************************************************************

using System.Collections.Generic;
using MultiPurposeAuthSite.Extensions.Sts;

namespace MultiPurposeAuthSite.Util.Test
{
    /// <summary>
    /// TestLogoutTokenBox
    /// **自己テストの RP が受け取った `logout_token` を、覚えておく**（#310 の段階 2）。
    /// </summary>
    /// <remarks>
    /// **測るためだけに在る。**
    /// **Back-Channel Logout は「OP が RP を叩く」**ので、**RP の側に口が無いと測れない。**
    /// **このサイトは自分の RP も兼ねている**（`test_self_code` / `test_self_logout` と同じ考え方）。
    ///
    /// | | |
    /// |---|---|
    /// | **口** | 両アプリの `/Account/BackChannelLogoutClient`（**`IsLockedDownTestEndpoints` で閉じる**） |
    /// | **持ち方** | **プロセス内の一覧**（**DB にも Session にも置かない**。再起動で消える） |
    /// | **上限** | **20 件**（**古いものから捨てる**。溜め込まない） |
    ///
    /// **E2E は net48 版と net10.0 版を別に測る**ので、**プロセス内で足りる**
    /// （**それぞれのサイトが、自分宛ての通知を覚える**）。
    ///
    /// **値はログに出さない**（`logout_token` には `sub` と `sid` が入っている）。
    /// </remarks>
    public class TestLogoutTokenBox
    {
        /// <summary>覚えておく件数の上限</summary>
        private const int Capacity = 20;

        /// <summary>_tokens の排他</summary>
        private static readonly object _lock = new object();

        /// <summary>受け取った logout_token（**新しいものが後ろ**）</summary>
        private static readonly List<string> _tokens = new List<string>();

        /// <summary>受け取った logout_token を覚える</summary>
        /// <param name="logoutToken">logout_token</param>
        public static void Add(string logoutToken)
        {
            if (string.IsNullOrEmpty(logoutToken))
            {
                return;
            }

            lock (TestLogoutTokenBox._lock)
            {
                TestLogoutTokenBox._tokens.Add(logoutToken);

                while (TestLogoutTokenBox.Capacity < TestLogoutTokenBox._tokens.Count)
                {
                    TestLogoutTokenBox._tokens.RemoveAt(0);
                }
            }
        }

        /// <summary>覚えている logout_token を全部返す</summary>
        /// <returns>logout_token の一覧（新しいものが後ろ）</returns>
        public static List<string> GetAll()
        {
            lock (TestLogoutTokenBox._lock)
            {
                return new List<string>(TestLogoutTokenBox._tokens);
            }
        }

        /// <summary>覚えているものを捨てる</summary>
        /// <remarks>**測る前に空にする**ために在る（前のケースの通知が混ざらないように）。</remarks>
        public static void Clear()
        {
            lock (TestLogoutTokenBox._lock)
            {
                TestLogoutTokenBox._tokens.Clear();
            }
        }
    }
}
