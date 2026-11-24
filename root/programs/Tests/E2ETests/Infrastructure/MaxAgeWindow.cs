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
//* クラス名        ：MaxAgeWindow
//* クラス日本語名  ：max_age の窓の中で確かめられたか
//*
//* 作成日時        ：－
//* 作成者          ：－
//* 更新履歴        ：－
//*
//*  日時        更新者            内容
//*  ----------  ----------------  -------------------------------------------------
//*  2026/11/24  玄人 幸道         新規（max_age のテストの時間依存。#409）
//**********************************************************************************

using System;

namespace MultiPurposeAuthSite.Tests.E2E.Infrastructure
{
    /// <summary>
    /// **認証してから認可要求の応答までが、`max_age` の窓の中に収まったか**を決める（#409）。
    /// </summary>
    /// <remarks>
    /// **`max_age` のテストは、「認証の直後に送れば、窓の中に収まる」前提に立ちやすい。**
    /// **通しの負荷で応答が遅れると、窓を越える**（`ora` の net48 版の `RT-294.63` で、
    /// パスワードを確かめた直後の `max_age=2` が、OP に正しく再認証を求められて落ちた）。
    ///
    /// **時間は、認証の要求を送る直前から、認可要求の応答までで測る**（実際より長く測る側）。
    ///
    /// | 確かめること | 結果 | 扱い |
    /// |---|---|---|
    /// | 再認証を求めない（先へ進む） | 進んだ | **時間に関係なく正しい**（合格） |
    /// | | 窓の中で再認証を求めた | 不合格 |
    /// | | 窓を過ぎてから再認証を求めた | **判定できない**（数え直す） |
    /// | 再認証を求める | 進んだ | **時間に関係なく誤り**（不合格） |
    /// | | 窓の中で再認証を求めた | 合格 |
    /// | | 窓を過ぎてから再認証を求めた | **判定できない**（直す前の振る舞いでも再認証になるので、空振りの合格になる。数え直す） |
    ///
    /// - **数え直すときは、利用者とクライアント（Cookie）を作り直す。** 再認証を求めると、OP はサインアウトさせ、
    ///   **再認証の印の Cookie を残す**（印が新しいうちは、`max_age` を越えても通す。`CmnEndpoints.CheckAuthTime`）
    /// - **窓は 1 秒短く見る。** OP は `auth_time` を秒で切り捨てて残し、秒で比べるので、窓が最大 1 秒短くなる
    ///   （`LockoutWindow` と同じ）
    /// - **数え直したことは、実測の文面（`Timing` の「何回目」）に書く。** 回ごとに `Note` を書かない
    ///   （`Note` は `TESTCASES.md` に載るので、通しのたびに原本が揺れる）
    /// </remarks>
    public static class MaxAgeWindow
    {
        /// <summary>数え直す上限（初回を含む）</summary>
        public const int MaxAttempts = 3;

        /// <summary>窓の中で確かめられたか</summary>
        /// <param name="elapsed">認証の要求を送る直前から、認可要求の応答まで</param>
        /// <param name="maxAgeSeconds">max_age（秒）</param>
        /// <returns>窓の中なら true</returns>
        public static bool CanJudge(TimeSpan elapsed, int maxAgeSeconds)
        {
            return elapsed.TotalSeconds < maxAgeSeconds - 1;
        }

        /// <summary>時間の文面（窓に対して、いつ確かめたかを添える）</summary>
        /// <param name="elapsed">認証の要求を送る直前から、認可要求の応答まで</param>
        /// <param name="maxAgeSeconds">max_age（秒）</param>
        /// <param name="attempt">何回目か（1 から）</param>
        /// <returns>文面</returns>
        public static string Timing(TimeSpan elapsed, int maxAgeSeconds, int attempt)
        {
            return "認証から " + elapsed.TotalSeconds.ToString("0.0") + " 秒 / max_age " + maxAgeSeconds + " 秒"
                + ((1 < attempt) ? " / " + attempt + " 回目" : "");
        }

        /// <summary>判定できなかったときの文面</summary>
        /// <param name="elapsed">最後の回の、認証の要求を送る直前から、認可要求の応答まで</param>
        /// <param name="maxAgeSeconds">max_age（秒）</param>
        /// <returns>文面</returns>
        public static string Unjudged(TimeSpan elapsed, int maxAgeSeconds)
        {
            return "**判定できない（" + MaxAgeWindow.MaxAttempts + " 回とも、窓を過ぎてから確かめた。"
                + MaxAgeWindow.Timing(elapsed, maxAgeSeconds, MaxAgeWindow.MaxAttempts) + "）**";
        }
    }
}
