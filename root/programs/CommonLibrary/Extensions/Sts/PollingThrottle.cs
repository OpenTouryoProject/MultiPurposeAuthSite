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
//* クラス名        ：PollingThrottle
//* クラス日本語名  ：ポーリングが速すぎるかを判定する（slow_down）
//*
//* 作成日時        ：－
//* 作成者          ：－
//* 更新履歴        ：－
//*
//*  日時        更新者            内容
//*  ----------  ----------------  -------------------------------------------------
//*  2026/10/16  玄人 幸道         新規（#305 の段階 1）
//**********************************************************************************

using MultiPurposeAuthSite.Co;

using System;

/// <summary>MultiPurposeAuthSite.Extensions.Sts</summary>
namespace MultiPurposeAuthSite.Extensions.Sts
{
    /// <summary>
    /// ポーリングが速すぎるかを判定する（`slow_down`。#305 の段階 1）。
    /// </summary>
    /// <remarks>
    /// **Device Authorization Grant と CIBA は、クライアントが `/token` を繰り返し叩く。**
    /// **間隔は `interval` で伝えてある**が、**守らなくても何も起きなかった。**
    ///
    /// | | |
    /// |---|---|
    /// | RFC 8628 §3.5 | **速すぎる要求には `slow_down` を返す**（クライアントは間隔を 5 秒伸ばす） |
    /// | CIBA §11 | 同じ |
    ///
    /// **判定に使うのは「最後にポーリングされた時刻」だけ**である
    /// （`DeviceAuthZData` / `CibaData` の `LastPolledAt`。**UNIX 時刻**）。
    /// **表に持たせているので、インスタンスを増やしても効く**
    /// （プロセス内に覚えると、別のインスタンスへ投げれば抜けられる）。
    ///
    /// **初回は `slow_down` にしない**（`LastPolledAt` が無い ＝ まだ 1 度も来ていない）。
    /// **`EnablePollingSlowDown` が false なら、何もしない**（従来どおり）。
    /// </remarks>
    public static class PollingThrottle
    {
        /// <summary>この配備で slow_down を返すか</summary>
        public static bool Enabled
        {
            get
            {
                return Config.EnablePollingSlowDown;
            }
        }

        /// <summary>いまの UNIX 時刻（秒）</summary>
        /// <returns>UNIX 時刻</returns>
        public static long NowUnixSeconds()
        {
            return DateTimeOffset.UtcNow.ToUnixTimeSeconds();
        }

        /// <summary>前回から `interval` 未満なら true（= slow_down）</summary>
        /// <param name="lastPolledAt">前回の UNIX 時刻（無ければ null）</param>
        /// <param name="intervalSeconds">広告している interval（秒）</param>
        /// <returns>速すぎれば true</returns>
        /// <remarks>
        /// **`interval` ちょうどは許す**（クライアントは「`interval` 秒待つ」ので、
        /// **ちょうどで落とすと、正しいクライアントが詰まる**）。
        /// **`interval` が 0 以下の配備では、判定しない。**
        /// </remarks>
        public static bool TooFast(long? lastPolledAt, int intervalSeconds)
        {
            if (!PollingThrottle.Enabled
                || intervalSeconds <= 0
                || !lastPolledAt.HasValue)
            {
                return false;
            }

            return (PollingThrottle.NowUnixSeconds() - lastPolledAt.Value) < intervalSeconds;
        }
    }
}
