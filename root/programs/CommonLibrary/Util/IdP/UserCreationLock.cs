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
//* クラス名        ：UserCreationLock
//* クラス日本語名  ：外部ログイン・ID 連携で、同じ利用者を同時に作らない
//*
//* 作成日時        ：－
//* 作成者          ：－
//* 更新履歴        ：－
//*
//*  日時        更新者            内容
//*  ----------  ----------------  -------------------------------------------------
//*  2026/10/29  玄人 幸道         新規（#294）
//*  2026/10/31  玄人 幸道         Extensions/Sts から Util/IdP へ移した（配置の見直し。#294）
//**********************************************************************************

using System;
using System.Threading;
using System.Threading.Tasks;
using MultiPurposeAuthSite.Extensions.Sts;

/// <summary>MultiPurposeAuthSite.Extensions.Sts</summary>
namespace MultiPurposeAuthSite.Util.IdP
{
    /// <summary>
    /// 外部ログイン・ID 連携で、同じ利用者を同時に作らない（#294）。
    /// </summary>
    /// <remarks>
    /// **「引いて、無ければ作る」は、同時に来ると 2 件作る**（引いた時点では、どちらも無い）。
    /// **初めての連携が同時に来ると、同じメアドの利用者が 2 件できていた**
    /// （E2E の並列のテストで実際に起きた。SA-6.6）。
    ///
    /// **利用者の鍵（メアド）ごとに、引いてから作るまでを 1 本にする。**
    /// **後から来た方は、先の方が作った利用者を引く**（既存の利用者として扱われる）。
    ///
    /// | | |
    /// |---|---|
    /// | 範囲 | **プロセスの中だけ**（**インスタンスを増やした配備（#256）では、インスタンスをまたいでは防げない**） |
    /// | 形 | **64 本のロックを、鍵のハッシュで割り当てる**（鍵が増えても、覚える物が増えない。**別の鍵が同じロックに当たっても、待つだけ**） |
    /// </remarks>
    public static class UserCreationLock
    {
        /// <summary>ロックの本数</summary>
        private const int Stripes = 64;

        /// <summary>ロック</summary>
        private static readonly SemaphoreSlim[] Locks = UserCreationLock.CreateLocks();

        /// <summary>ロックを作る</summary>
        /// <returns>ロック</returns>
        private static SemaphoreSlim[] CreateLocks()
        {
            SemaphoreSlim[] locks = new SemaphoreSlim[Stripes];

            for (int i = 0; i < Stripes; i++)
            {
                locks[i] = new SemaphoreSlim(1, 1);
            }

            return locks;
        }

        /// <summary>鍵のロックを取る（`using` で返す）</summary>
        /// <param name="key">利用者の鍵（メアド。大文字小文字は区別しない）</param>
        /// <returns>返すときに Dispose するもの</returns>
        public static async Task<IDisposable> AcquireAsync(string key)
        {
            int hash = StringComparer.OrdinalIgnoreCase.GetHashCode(key ?? "");
            SemaphoreSlim gate = UserCreationLock.Locks[(hash & 0x7fffffff) % Stripes];

            await gate.WaitAsync().ConfigureAwait(false);

            return new Releaser(gate);
        }

        /// <summary>ロックを返す</summary>
        private sealed class Releaser : IDisposable
        {
            /// <summary>ロック</summary>
            private SemaphoreSlim _gate;

            /// <summary>コンストラクタ</summary>
            /// <param name="gate">ロック</param>
            public Releaser(SemaphoreSlim gate)
            {
                this._gate = gate;
            }

            /// <summary>返す（2 度目は何もしない）</summary>
            public void Dispose()
            {
                SemaphoreSlim gate = Interlocked.Exchange(ref this._gate, null);

                if (gate != null)
                {
                    gate.Release();
                }
            }
        }
    }
}
