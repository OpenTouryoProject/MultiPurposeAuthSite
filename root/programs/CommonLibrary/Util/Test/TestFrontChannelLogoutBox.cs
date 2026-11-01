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
//* クラス名        ：TestFrontChannelLogoutBox
//* クラス日本語名  ：自己テスト用の Front-Channel Logout の受信箱
//*
//* 作成日時        ：－
//* 作成者          ：－
//* 更新履歴        ：－
//*
//*  日時        更新者            内容
//*  ----------  ----------------  -------------------------------------------------
//*  2026/10/21  玄人 幸道         新規（#310 の段階 3）
//*  2026/10/31  玄人 幸道         Extensions/Sts から Util/Test へ移した（配置の見直し。#294）
//**********************************************************************************

using System.Collections.Generic;
using MultiPurposeAuthSite.Extensions.Sts;

namespace MultiPurposeAuthSite.Util.Test
{
    /// <summary>
    /// TestFrontChannelLogoutBox
    /// **自己テストの RP が `iframe` で叩かれたことを、覚えておく**（#310 の段階 3）。
    /// </summary>
    /// <remarks>
    /// **測るためだけに在る**（`TestLogoutTokenBox` と同じ立ち位置。段階 2）。
    /// **別の箱にしてある** — **Front-Channel にはトークンが無い**（`iss` と `sid` だけ）ため。
    ///
    /// | | |
    /// |---|---|
    /// | **口** | 両アプリの `/Account/FrontChannelLogoutClient`（**`IsLockedDownTestEndpoints` で閉じる**） |
    /// | **覚える形** | **`iss=…&sid=…`**（**受け取った通りの並び**） |
    /// | **上限** | **20 件**（古いものから捨てる） |
    ///
    /// **E2E のクライアントは `iframe` を開かない**ので、
    /// **テストが画面から URL を取り出して、自分で叩く**（**ブラウザの代わりをする**）。
    /// </remarks>
    public class TestFrontChannelLogoutBox
    {
        /// <summary>覚えておく件数の上限</summary>
        private const int Capacity = 20;

        /// <summary>_hits の排他</summary>
        private static readonly object _lock = new object();

        /// <summary>叩かれた記録（**新しいものが後ろ**）</summary>
        private static readonly List<string> _hits = new List<string>();

        /// <summary>叩かれたことを覚える</summary>
        /// <param name="iss">iss（どの OP か）</param>
        /// <param name="sid">sid（どのセッションか）</param>
        public static void Add(string iss, string sid)
        {
            lock (TestFrontChannelLogoutBox._lock)
            {
                TestFrontChannelLogoutBox._hits.Add(
                    "iss=" + (iss ?? "") + "&sid=" + (sid ?? ""));

                while (TestFrontChannelLogoutBox.Capacity < TestFrontChannelLogoutBox._hits.Count)
                {
                    TestFrontChannelLogoutBox._hits.RemoveAt(0);
                }
            }
        }

        /// <summary>覚えているものを全部返す</summary>
        /// <returns>記録の一覧（新しいものが後ろ）</returns>
        public static List<string> GetAll()
        {
            lock (TestFrontChannelLogoutBox._lock)
            {
                return new List<string>(TestFrontChannelLogoutBox._hits);
            }
        }

        /// <summary>覚えているものを捨てる</summary>
        /// <remarks>**測る前に空にする**ために在る。</remarks>
        public static void Clear()
        {
            lock (TestFrontChannelLogoutBox._lock)
            {
                TestFrontChannelLogoutBox._hits.Clear();
            }
        }
    }
}
