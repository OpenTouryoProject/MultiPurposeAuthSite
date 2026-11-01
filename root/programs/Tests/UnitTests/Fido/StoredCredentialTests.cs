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
//* クラス名        ：StoredCredentialTests
//* クラス日本語名  ：保存する資格情報の形
//*
//* 作成者          ：玄人 幸道
//* 更新履歴        ：
//*
//*  日時        更新者            内容
//*  ----------  ----------------  -------------------------------------------------
//*  2026/11/02  玄人 幸道         新規作成（#324）
//**********************************************************************************

using System;
using System.Linq;

using Fido2NetLib;
using Fido2NetLib.Objects;

using MultiPurposeAuthSite.Extensions.FIDO;

using Xunit;

namespace MultiPurposeAuthSite.Tests.Unit.Fido
{
    /// <summary>StoredCredential（E2E の通しでは FromRegistered を通らない）</summary>
    public class StoredCredentialTests
    {
        /// <summary>登録した値が、そのまま保存の形に移る</summary>
        [Fact]
        [Basis("WebAuthn Level 2 §7.1（登録で保存するもの : credentialId・公開鍵・signCount）")]
        public void 登録した値が保存の形に移る()
        {
            byte[] userId = new byte[] { 1, 2, 3 };
            byte[] credentialId = new byte[] { 4, 5, 6 };
            byte[] publicKey = new byte[] { 7, 8, 9 };
            Guid aaGuid = Guid.NewGuid();

            StoredCredential stored = StoredCredential.FromRegistered(new RegisteredPublicKeyCredential
            {
                Type = PublicKeyCredentialType.PublicKey,
                Id = credentialId,
                PublicKey = publicKey,
                SignCount = 42,
                User = new Fido2User { Id = userId, Name = "n", DisplayName = "d" },
                AttestationFormat = "none",
                AaGuid = aaGuid,
                Transports = new[] { AuthenticatorTransport.Usb, AuthenticatorTransport.Internal },
                IsBackupEligible = true,
                IsBackedUp = false
            });

            Assert.Equal(credentialId, stored.CredentialId);
            Assert.Equal(publicKey, stored.PublicKey);
            Assert.Equal(42u, stored.SignatureCounter);
            Assert.Equal(userId, stored.UserId);
            Assert.Equal(userId, stored.UserHandle);
            Assert.Equal("none", stored.AttestationFormat);
            Assert.Equal(aaGuid, stored.AaGuid);
            Assert.True(stored.IsBackupEligible);
            Assert.False(stored.IsBackedUp);
            Assert.Equal(new[] { "Usb", "Internal" }, stored.Transports);
        }

        /// <summary>接続方法が無くても作れる</summary>
        [Fact]
        [Basis("WebAuthn Level 2 §5.8.3（transports は省略できる）")]
        public void 接続方法が無くても作れる()
        {
            StoredCredential stored = StoredCredential.FromRegistered(new RegisteredPublicKeyCredential
            {
                Type = PublicKeyCredentialType.PublicKey,
                Id = new byte[] { 1 },
                PublicKey = new byte[] { 2 },
                User = new Fido2User { Id = new byte[] { 3 }, Name = "n", DisplayName = "d" }
            });

            Assert.Empty(stored.Transports);
        }

        /// <summary>読めない接続方法は落とし、資格情報は使える</summary>
        [Fact]
        [Basis("設計：StoredCredential.ToDescriptor のコメント（版を跨いで読む）")]
        public void 読めない接続方法は落として資格情報は使える()
        {
            StoredCredential stored = new StoredCredential
            {
                CredentialId = new byte[] { 1, 2 },
                Transports = new[] { "Usb", "no-such-transport" }
            };

            PublicKeyCredentialDescriptor descriptor = stored.ToDescriptor();

            Assert.Equal(new byte[] { 1, 2 }, descriptor.Id);
            Assert.Equal(new[] { AuthenticatorTransport.Usb }, descriptor.Transports.ToArray());
        }
    }
}
