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
//* クラス名        ：AccountLink
//* クラス日本語名  ：外部 ID をローカル アカウントに結び付けてよいかの判定
//*
//* 作成日時        ：－
//* 作成者          ：－
//* 更新履歴        ：－
//*
//*  日時        更新者            内容
//*  ----------  ----------------  -------------------------------------------------
//*  2026/09/29  玄人 幸道         新規（#140 の段階 1）
//*  2026/10/01  玄人 幸道         鍵が常にメアドになったので、判定の引数を 1 つにした（#151 の段階 3）
//**********************************************************************************

using MultiPurposeAuthSite.Co;

namespace MultiPurposeAuthSite.Extensions.Sts
{
    /// <summary>外部 ID を既存アカウントに結び付けてよいか（#140 の段階 1）</summary>
    public enum AccountLinkCheck
    {
        /// <summary>結び付けてよい</summary>
        Ok,

        /// <summary>上流が「検証済み」と言っていないメアドでは結び付けない</summary>
        NeedsVerifiedEmail
    }

    /// <summary>
    /// 外部 ID（外部ログイン / ID フェデレーション）を、
    /// **既存のローカル アカウントに結び付けてよいか**を判定する（#140 の段階 1）。
    /// </summary>
    /// <remarks>
    /// **「連携キー」と「初回の突き合わせ」は別の話である。**
    ///
    /// | | 何をするか | 何を使うか |
    /// |---|---|---|
    /// | 連携キー | 上流の人とローカルの人を**恒久的に対応づける**（`UserLogins`） | 上流の識別子（`sub` / `userid`） |
    /// | **初回の突き合わせ** | リンクが無いとき、**既存アカウントに結ぶか**を決める | **ここでメアドを使っている** |
    ///
    /// **この判定は後者だけを扱う。** 前者（識別子）は `public` / `pairwise` のどちらでも
    /// 受け取った値をそのまま保存すればよく、判断の余地が無い。
    ///
    /// **メアドを鍵にして結ぶなら、上流が検証したメアドでなければならない。**
    /// 上流が利用者の申告をそのまま返す場合、**他人のメアドを名乗って既存アカウントに入り込める。**
    /// アカウント リンクに未検証のメアドを使わないのは OIDC の定石であり、
    /// **この実装に固有の事情ではない。**
    ///
    /// **既定は安全側（要求する）。** `RequireVerifiedEmailForAccountLinking` を false にすると
    /// 従来どおりになるが、**下位互換のために穴を開けたままにする既定にはしない。**
    /// </remarks>
    public static class AccountLink
    {
        /// <summary>
        /// 既存アカウントに結び付けてよいかを判定する。
        /// </summary>
        /// <param name="emailVerified">
        /// 上流が返した `email_verified`（クレームの値、または JSON の値を文字列にしたもの）。
        /// **無い場合は null / 空**を渡す（「返さない」と「false」は同じ扱いにする）。
        /// </param>
        /// <returns>AccountLinkCheck</returns>
        /// <remarks>
        /// **引数から `emailIsMatchingKey` を落とした**（#151 の段階 3）。
        /// 以前は `RequireUniqueEmail` が false の配備で**鍵が上流の識別子**になり、
        /// メアドは一致の確認にしか使っていなかったため、判定の対象外にしていた。
        /// **メアドは常に在って一意になったので、常に鍵である。**
        /// </remarks>
        public static AccountLinkCheck CheckLinkToExistingUser(string emailVerified)
        {
            if (!Config.RequireVerifiedEmailForAccountLinking)
            {
                // 従来どおり（設定で明示的に戻した場合）。
                return AccountLinkCheck.Ok;
            }

            return AccountLink.IsVerified(emailVerified)
                ? AccountLinkCheck.Ok : AccountLinkCheck.NeedsVerifiedEmail;
        }

        /// <summary>
        /// 新規に作るアカウントの `EmailConfirmed` に何を入れるか。
        /// </summary>
        /// <param name="emailVerified">上流が返した `email_verified`</param>
        /// <returns>確認済みとして扱うなら true</returns>
        /// <remarks>
        /// **以前は、上流の言い値に関わらず true を入れていた。**
        /// そのままだと、**未検証のメアドが「確認済み」としてローカルに定着**し、
        /// 後の突き合わせ（この後にサインアップする正当な利用者との衝突）に影響する。
        /// **設定で従来どおりにも戻せる。**
        /// </remarks>
        public static bool EmailConfirmedForNewUser(string emailVerified)
        {
            if (!Config.RequireVerifiedEmailForAccountLinking)
            {
                // 従来どおり（設定で明示的に戻した場合）。
                return true;
            }

            return AccountLink.IsVerified(emailVerified);
        }

        /// <summary>`email_verified` の値を読む（無い / 読めない は false）</summary>
        /// <param name="emailVerified">値</param>
        /// <returns>true と読めれば true</returns>
        /// <remarks>
        /// **クレームなら文字列の "true"、JSON なら真偽値**で来る。
        /// **どちらも文字列にしてから見る。** 大文字小文字は問わない。
        /// </remarks>
        private static bool IsVerified(string emailVerified)
        {
            if (string.IsNullOrEmpty(emailVerified))
            {
                return false;
            }

            return bool.TryParse(emailVerified, out bool verified) && verified;
        }
    }
}
