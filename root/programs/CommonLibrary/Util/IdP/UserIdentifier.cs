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
//* クラス名        ：UserIdentifier
//* クラス日本語名  ：利用者名とメアドの規則（ライブラリ）
//*
//* 作成日時        ：－
//* 作成者          ：－
//* 更新履歴        ：－
//*
//*  日時        更新者            内容
//*  ----------  ----------------  -------------------------------------------------
//*  2026/10/24  玄人 幸道         新規（Const から移した。#294）
//**********************************************************************************

/// <summary>MultiPurposeAuthSite.Util.IdP</summary>
namespace MultiPurposeAuthSite.Util.IdP
{
    /// <summary>利用者名とメアドの規則（#151 の段階 3）</summary>
    /// <remarks>
    /// サインインの入力の見分け、利用者名の検査、メアドからの既定値の生成。
    /// 利用者名を運ぶクレームの名前は定数なので <c>Const.PreferredUserNameClaim</c> に在る。
    /// </remarks>
    public static class UserIdentifier
    {
        /// <summary>
        /// 入力された識別子が、メアドの形かどうか
        /// </summary>
        /// <param name="identifier">サインイン画面に入力された値</param>
        /// <returns>メアドの形なら true</returns>
        /// <remarks>
        /// **利用者名とメアドの両方でサインインできる。**
        /// どちらとして引くかを、**`@` を含むかどうか**で決める。
        ///
        /// **新しい利用者名に `@` を禁じている**ので（<see cref="IsValidUserName"/>）、
        /// **この判定は曖昧にならない。**
        ///
        /// > **既存の利用者名は書き換えていない。** 以前は「利用者名＝メアド」だったため、
        /// > **`@` を含む利用者名が残っている。**
        /// > その利用者は**メアドとして引かれる**が、**値が同じなので同じ利用者に当たる。**
        /// </remarks>
        public static bool LooksLikeEmail(string identifier)
        {
            return !string.IsNullOrEmpty(identifier) && identifier.Contains("@");
        }

        /// <summary>
        /// 利用者名として使える値かどうか（#151 の段階 3）
        /// </summary>
        /// <param name="userName">利用者名</param>
        /// <returns>使えるなら true</returns>
        /// <remarks>
        /// **`@` を含む利用者名を認めない。**
        /// 認めると、**サインインの入力がメアドなのか利用者名なのか決まらない。**
        ///
        /// **新しく作る・変えるときだけ掛ける。**
        /// **既存の利用者名（以前の「利用者名＝メアド」）は、そのまま使い続けられる。**
        /// </remarks>
        public static bool IsValidUserName(string userName)
        {
            return !string.IsNullOrWhiteSpace(userName) && !userName.Contains("@");
        }

        /// <summary>
        /// メアドから、利用者名の既定値を作る（#151 の段階 3）
        /// </summary>
        /// <param name="email">メアド</param>
        /// <returns>`@` より前の部分（`@` が無ければ、そのまま）</returns>
        /// <remarks>
        /// **利用者名を別に決められない場面で使う。**
        ///
        /// | 使う場所 | なぜ |
        /// |---|---|
        /// | 管理者・テスト利用者の生成 | 設定にあるのは**メアドだけ**（`AdministratorUID`） |
        /// | 外部ログイン・ID 連携での新規作成 | 上流が返すのは `sub` と**メアド**で、利用者名は無い |
        ///
        /// **一意性は呼び出し側が確かめる。** ここは形を整えるだけ。
        /// </remarks>
        public static string UserNameFromEmail(string email)
        {
            if (string.IsNullOrEmpty(email))
            {
                return email;
            }

            int at = email.IndexOf('@');

            return (at > 0) ? email.Substring(0, at) : email;
        }
    }
}
