//**********************************************************************************
//* Copyright (C) 2017 Hitachi Solutions,Ltd.
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
//* クラス名        ：StoredCredential
//* クラス日本語名  ：StoredCredential（ライブラリ）
//*
//* 作成日時        ：－
//* 作成者          ：－
//* 更新履歴        ：－
//*
//*  日時        更新者            内容
//*  ----------  ----------------  -------------------------------------------------
//*  2026/10/07  玄人 幸道         新規（#137）
//**********************************************************************************

using System;
using System.Collections.Generic;

using Fido2NetLib.Objects;

namespace MultiPurposeAuthSite.Extensions.FIDO
{
    /// <summary>
    /// FIDO2Data 表に入れる、登録済みの資格情報。
    /// </summary>
    //  **この型は自前で持つ**（#137）。
    //    **以前は `Fido2NetLib.Development.StoredCredential` を直列化していた**が、
    //    **`Development` 名前空間は 3.0 で消えた**（名前のとおり、元々デモ用の型だった）。
    //
    //    **ライブラリの型を保存に使わない**こと自体が正しい。
    //    **保存した JSON は版を跨いで読む**ので、**ライブラリの都合で形が変わると読めなくなる。**
    //    ここは**自分で決めた形**なので、版を上げても壊れない。
    //
    //    **列挙型は名前（`ToString()`）で入れる。** 数値だと、
    //    **ライブラリ側で値が挿入されたときに意味がズレる。**
    public class StoredCredential
    {
        /// <summary>利用者（＝利用者名の UTF-8。Fido2User.Id と同じもの）</summary>
        public byte[] UserId { get; set; }

        /// <summary>資格情報の ID（＝ credentialId）</summary>
        public byte[] CredentialId { get; set; }

        /// <summary>公開鍵（COSE_Key）</summary>
        public byte[] PublicKey { get; set; }

        /// <summary>userHandle（この実装では UserId と同じ）</summary>
        public byte[] UserHandle { get; set; }

        /// <summary>署名カウンタ</summary>
        public uint SignatureCounter { get; set; }

        /// <summary>attestation の形式（"none" / "packed" など）</summary>
        public string AttestationFormat { get; set; }

        /// <summary>登録日時</summary>
        public DateTime RegDate { get; set; }

        /// <summary>認証器の型番（AAGUID）</summary>
        public Guid AaGuid { get; set; }

        /// <summary>認証器との接続方法（列挙型の名前で持つ）</summary>
        public string[] Transports { get; set; }

        /// <summary>複製され得る資格情報か（パスキー）</summary>
        public bool IsBackupEligible { get; set; }

        /// <summary>複製済みか（パスキー）</summary>
        public bool IsBackedUp { get; set; }

        /// <summary>PublicKeyCredentialDescriptor に変換する</summary>
        /// <returns>PublicKeyCredentialDescriptor</returns>
        public PublicKeyCredentialDescriptor ToDescriptor()
        {
            List<AuthenticatorTransport> transports = new List<AuthenticatorTransport>();

            if (this.Transports != null)
            {
                foreach (string transport in this.Transports)
                {
                    AuthenticatorTransport parsed;
                    // **読めない名前は黙って落とす。** 版を跨いで読むため、
                    // **知らない接続方法が入っていても、資格情報ごと使えなくしない。**
                    if (Enum.TryParse(transport, out parsed))
                    {
                        transports.Add(parsed);
                    }
                }
            }

            return new PublicKeyCredentialDescriptor(
                PublicKeyCredentialType.PublicKey, this.CredentialId, transports.ToArray());
        }

        /// <summary>RegisteredPublicKeyCredential から作る</summary>
        /// <param name="credential">RegisteredPublicKeyCredential</param>
        /// <returns>StoredCredential</returns>
        public static StoredCredential FromRegistered(RegisteredPublicKeyCredential credential)
        {
            List<string> transports = new List<string>();

            if (credential.Transports != null)
            {
                foreach (AuthenticatorTransport transport in credential.Transports)
                {
                    transports.Add(transport.ToString());
                }
            }

            return new StoredCredential
            {
                UserId = credential.User.Id,
                CredentialId = credential.Id,
                PublicKey = credential.PublicKey,
                UserHandle = credential.User.Id,
                SignatureCounter = credential.SignCount,
                AttestationFormat = credential.AttestationFormat,
                RegDate = DateTime.UtcNow,
                AaGuid = credential.AaGuid,
                Transports = transports.ToArray(),
                IsBackupEligible = credential.IsBackupEligible,
                IsBackedUp = credential.IsBackedUp
            };
        }
    }
}
