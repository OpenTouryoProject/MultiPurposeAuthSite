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
//* クラス名        ：TwoFactorPushProvider
//* クラス日本語名  ：2FAのプッシュ承認（認証デバイスからの返答）を保持する
//*
//* 作成日時        ：－
//* 作成者          ：－
//* 更新履歴        ：－
//*
//*  日時        更新者            内容
//*  ----------  ----------------  -------------------------------------------------
//*  2026/09/16  玄人 幸道         新規（#213）
//**********************************************************************************

using MultiPurposeAuthSite.Co;

using System;
using System.Collections.Concurrent;

namespace MultiPurposeAuthSite.Extensions.Sts
{
    /// <summary>
    /// 2FA のプッシュ承認（認証デバイスからの返答）を保持する。
    ///
    /// **保持はメモリのみ**（#213）。2FA の承認は、ブラウザが `VerifyCode` で待っている
    /// 数分の間だけ必要な一時データなので、CibaProvider のように 4 つのストアへは持たない。
    /// そのため、**複数のサーバで分散する構成では動かない**
    /// （もっとも、2FA のセッション自体がブラウザの Cookie に依存しており、
    /// その構成では別途の手当て（データ保護キーの共有など）が要る）。
    ///
    /// 記録するのは「どの利用者が、どのコードを承認したか」だけ。
    /// コードの検証は、認証サイト側が `VerifyTwoFactorTokenAsync` で行ってから登録する。
    /// </summary>
    public class TwoFactorPushProvider
    {
        /// <summary>
        /// 承認（利用者のId → 承認したコードと時刻）
        /// ConcurrentDictionaryは、.NET 4.0の新しいスレッドセーフなHashtable
        /// </summary>
        private static ConcurrentDictionary<string, Tuple<string, DateTime>>
            Approvals = new ConcurrentDictionary<string, Tuple<string, DateTime>>();

        /// <summary>承認を保持する時間（分）</summary>
        /// <remarks>
        /// ブラウザが待っている間だけ生きていればよい。
        /// 2FA のコード自体の有効期間（既定 3 分）より少し長くしておく。
        /// </remarks>
        private const int ExpireMinutes = 5;

        #region Create

        /// <summary>承認を登録する</summary>
        /// <param name="userId">承認した利用者の ApplicationUser.Id</param>
        /// <param name="code">認証デバイスが返してきた 2FA のコード（検証済み）</param>
        public static void Create(string userId, string code)
        {
            if (string.IsNullOrEmpty(userId) || string.IsNullOrEmpty(code))
            {
                return;
            }

            TwoFactorPushProvider.Approvals[userId] =
                new Tuple<string, DateTime>(code, DateTime.Now);
        }

        #endregion

        #region Receive

        /// <summary>承認を取り出す（1 回だけ取り出せる）</summary>
        /// <param name="userId">待っている利用者の ApplicationUser.Id</param>
        /// <returns>承認済みならコード。無い・期限切れなら null</returns>
        /// <remarks>
        /// **取り出したら消す。** 同じ承認で 2 回サインインできないようにする。
        /// </remarks>
        public static string Receive(string userId)
        {
            if (string.IsNullOrEmpty(userId))
            {
                return null;
            }

            Tuple<string, DateTime> approval = null;

            if (!TwoFactorPushProvider.Approvals.TryRemove(userId, out approval))
            {
                return null;
            }

            if (approval.Item2.AddMinutes(TwoFactorPushProvider.ExpireMinutes) < DateTime.Now)
            {
                // 期限切れ（取り出して消えているので、そのまま捨てる）
                return null;
            }

            return approval.Item1;
        }

        #endregion
    }
}
