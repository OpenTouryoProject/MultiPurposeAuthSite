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
//* クラス名        ：LockoutWindow
//* クラス日本語名  ：ロックアウトの窓の中で確かめられたか
//*
//* 作成日時        ：－
//* 作成者          ：－
//* 更新履歴        ：－
//*
//*  日時        更新者            内容
//*  ----------  ----------------  -------------------------------------------------
//*  2026/11/04  玄人 幸道         新規（ロックアウトのテストの時間依存。#331）
//**********************************************************************************

using System;

namespace MultiPurposeAuthSite.Tests.E2E.Infrastructure
{
    /// <summary>
    /// **「正しい資格情報でも断られる」を、ロックアウトの窓の中で確かめられたか**を決める（#331）。
    /// </summary>
    /// <remarks>
    /// **通しの窓は短い**（`test.ps1` が 5 秒にしている）。**応答が遅れて窓を過ぎてから確かめると、
    /// 断りが解けていて通り、「少なく数えられた」と取り違えて落ちていた**（`ora` の net48 版の `RT-316.2` で、
    /// 上限に届いてから 7.2 秒後に確かめていた）。
    ///
    /// **時間は、上限に届かせる要求を送る直前から、確かめる要求の応答までで測る**（実際より長く測る側）。
    ///
    /// | 結果 | 扱い |
    /// |---|---|
    /// | 断られた | **時間に関係なく正しい**（合格） |
    /// | 窓の中で通った | **少なく数えられた**（不合格） |
    /// | 窓を過ぎてから通った | **判定できない。** 通ったことで数えは消えているので、**同じ利用者で数え直す**（`MaxAttempts` 回まで。尽きたら不合格） |
    ///
    /// **窓は 1 秒短く見る。** `AuthFailureProvider` は時刻を秒で切り捨てるので、窓が最大 1 秒短くなる。
    /// </remarks>
    public static class LockoutWindow
    {
        /// <summary>数え直す上限（初回を含む）</summary>
        public const int MaxAttempts = 3;

        /// <summary>窓の中で確かめられたか</summary>
        /// <param name="elapsed">上限に届かせる要求を送る直前から、確かめる要求の応答まで</param>
        /// <param name="lockoutSeconds">ロックアウトの長さ（秒）</param>
        /// <returns>窓の中なら true</returns>
        public static bool CanJudge(TimeSpan elapsed, int lockoutSeconds)
        {
            return elapsed.TotalSeconds < lockoutSeconds - 1;
        }

        /// <summary>数え直すか（窓を過ぎてから通り、まだ回数が残っている）</summary>
        /// <param name="blocked">断られたか</param>
        /// <param name="elapsed">上限に届かせる要求を送る直前から、確かめる要求の応答まで</param>
        /// <param name="lockoutSeconds">ロックアウトの長さ（秒）</param>
        /// <param name="attempt">何回目か（1 から）</param>
        /// <returns>数え直すなら true</returns>
        public static bool Retry(bool blocked, TimeSpan elapsed, int lockoutSeconds, int attempt)
        {
            return !blocked && !LockoutWindow.CanJudge(elapsed, lockoutSeconds)
                && attempt < LockoutWindow.MaxAttempts;
        }

        /// <summary>実測の文面（窓に対して、いつ確かめたかを添える）</summary>
        /// <param name="blocked">断られたか</param>
        /// <param name="blockedText">断られたときの文面</param>
        /// <param name="passedText">通ったときの文面</param>
        /// <param name="elapsed">上限に届かせる要求を送る直前から、確かめる要求の応答まで</param>
        /// <param name="lockoutSeconds">ロックアウトの長さ（秒）</param>
        /// <param name="attempt">何回目か（1 から）</param>
        /// <returns>文面</returns>
        public static string Describe(bool blocked, string blockedText, string passedText,
            TimeSpan elapsed, int lockoutSeconds, int attempt)
        {
            string timing = "上限に届かせてから " + elapsed.TotalSeconds.ToString("0.0")
                + " 秒 / 窓 " + lockoutSeconds + " 秒" + ((1 < attempt) ? " / " + attempt + " 回目" : "");

            if (blocked)
            {
                return blockedText + "（" + timing + "）";
            }

            return LockoutWindow.CanJudge(elapsed, lockoutSeconds)
                ? "**" + passedText + "（窓の中で通った。少なく数えられた。" + timing + "）**"
                : "**判定できない（" + LockoutWindow.MaxAttempts + " 回とも、窓を過ぎてから確かめた。" + timing + "）**";
        }
    }
}
