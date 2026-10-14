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
//* クラス名        ：TestCredentials
//* クラス日本語名  ：E2E 専用の WebAuthn 資格情報の種データ
//*
//* 作成日時        ：－
//* 作成者          ：－
//* 更新履歴        ：－
//*
//*  日時        更新者            内容
//*  ----------  ----------------  -------------------------------------------------
//*  2026/10/10  玄人 幸道         新規（#277 の段階 7）
//**********************************************************************************

using MultiPurposeAuthSite.Co;

using System;
using System.Security.Cryptography;
using System.Text;

/// <summary>MultiPurposeAuthSite.Extensions.FIDO</summary>
namespace MultiPurposeAuthSite.Extensions.FIDO
{
    /// <summary>
    /// E2E 専用の WebAuthn 資格情報を作る（#277 の段階 7）。
    /// </summary>
    /// <remarks>
    /// **なぜ要るか。** **資格情報を作れるのは認証器だけ**で、
    /// **`navigator.credentials` を呼ぶのはブラウザ**である。
    /// **E2E は HttpClient だけ**なので、**自分では 1 件も作れない。**
    /// **そのため、削除（`/Manage/RemoveWebAuthnData`）を測れなかった。**
    ///
    /// **#277 の段階 6 で直した不具合**（**複数選んでも 1 件しか消えない**）には、
    /// **いま回帰テストが無い。** その前提をここで用意する。
    ///
    /// **種データの流儀は `Sts.TestClients` と同じ**（#264）。
    /// **`IsDebug` ＋ `TestUserPWD` のときだけ**作られ、**本番では一度も呼ばれない。**
    ///
    /// **専用の利用者（`webauthn_tanaka`）にだけ付ける。**
    /// **テスト利用者（`super_tanaka` / `tanaka`）には付けない。**
    /// **`RT-137.1` / `RT-137.2` が「この利用者は認証器を登録していない」ことを前提に書かれている**ため。
    ///
    /// **何度呼んでも増えない**（`CredentialId` が利用者名から決まる）。
    /// **E2E が消した分を、次のサインインで作り直す**ために、そうしてある。
    ///
    /// **net10.0 版だけ**である（net48 版には WebAuthn の口が無い。#137）。
    /// </remarks>
    public static class TestCredentials
    {
        #region 定数

        /// <summary>種として作る件数</summary>
        /// <remarks>
        /// **3 件。** **2 件を選んで消し、1 件が残ること**を測るため
        /// （**選んだ数だけ消える**／**選んでいないものは残る**の両方を 1 回で見る）。
        /// </remarks>
        public const int Count = 3;

        /// <summary>資格情報の長さ（バイト）</summary>
        /// <remarks>**本物の credentialId に近い長さにする**（base64url で 43 文字）。</remarks>
        private const int CredentialIdLength = 32;

        #endregion

        #region メソッド

        /// <summary>種をまく（既に在る分は触らない）</summary>
        /// <param name="userName">利用者名</param>
        public static void Seed(string userName)
        {
            if (string.IsNullOrEmpty(userName)
                || Config.FIDOServerMode != EnumFidoType.WebAuthn)
            {
                return;
            }

            byte[] userId = Encoding.UTF8.GetBytes(userName);

            for (int i = 1; i <= TestCredentials.Count; i++)
            {
                byte[] credentialId = TestCredentials.CredentialId(userName, i);

                if (DataProvider.GetCredentialById(credentialId) != null)
                {
                    // 既に在る。
                    continue;
                }

                DataProvider.Create(new StoredCredential()
                {
                    UserId = userId,
                    CredentialId = credentialId,
                    // **公開鍵は使われない。** 署名の検証まで進む経路が無いため
                    //   （assertion を作れるのは認証器だけ）。
                    PublicKey = TestCredentials.CredentialId(userName + "#key", i),
                    UserHandle = userId,
                    SignatureCounter = 0,
                    AttestationFormat = "none",
                    RegDate = DateTime.UtcNow,
                    AaGuid = Guid.Empty,
                    Transports = new string[] { "internal" },
                    IsBackupEligible = false,
                    IsBackedUp = false
                });
            }
        }

        /// <summary>利用者名と番号から credentialId を決める</summary>
        /// <param name="userName">利用者名</param>
        /// <param name="no">番号</param>
        /// <returns>credentialId</returns>
        /// <remarks>
        /// **乱数にしない。** **同じ利用者には、いつも同じ値**にして、
        /// **消した分だけを作り直せる**ようにする。
        /// </remarks>
        private static byte[] CredentialId(string userName, int no)
        {
            using (SHA256 sha = SHA256.Create())
            {
                byte[] hash = sha.ComputeHash(
                    Encoding.UTF8.GetBytes("MPAS/WebAuthn/" + userName + "/" + no));

                byte[] id = new byte[TestCredentials.CredentialIdLength];
                Array.Copy(hash, id, TestCredentials.CredentialIdLength);

                return id;
            }
        }

        #endregion
    }
}
