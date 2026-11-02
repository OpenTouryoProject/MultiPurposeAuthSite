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
//* クラス名        ：WebAuthnAssertionTests
//* クラス日本語名  ：WebAuthn のアサーションの検証
//*
//* 作成者          ：玄人 幸道
//* 更新履歴        ：
//*
//*  日時        更新者            内容
//*  ----------  ----------------  -------------------------------------------------
//*  2026/11/02  玄人 幸道         新規作成（#324）
//**********************************************************************************

using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

using Fido2NetLib;
using Fido2NetLib.Objects;

using MultiPurposeAuthSite.Extensions.FIDO;

using Xunit;

namespace MultiPurposeAuthSite.Tests.Unit.Fido
{
    /// <summary>
    /// WebAuthnHelper.AuthenticatorAssertion（E2E の通しでは通らない）。
    /// **本物の ES256 の鍵で署名したアサーションを作って確かめる。**
    /// </summary>
    public class WebAuthnAssertionTests : IDisposable
    {
        private const string Origin = "https://localhost:44300";
        private const string RpId = "localhost";

        private readonly ECDsa _key = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        private readonly byte[] _credentialId = Guid.NewGuid().ToByteArray();
        private readonly byte[] _userId = Encoding.UTF8.GetBytes("user_" + Guid.NewGuid().ToString("N"));
        private readonly byte[] _challenge = RandomNumberGenerator.GetBytes(32);

        /// <summary>設定と、保存した資格情報を用意する</summary>
        public WebAuthnAssertionTests()
        {
            TestConfig.Set(new Dictionary<string, string>
            {
                { "UserStoreType", "mem" },
                { "OAuth2AuthorizationServerEndpointsRootURI", Origin }
            });

            DataProvider.Create(new StoredCredential
            {
                UserId = this._userId,
                UserHandle = this._userId,
                CredentialId = this._credentialId,
                PublicKey = this.CosePublicKey(),
                SignatureCounter = 10,
                AttestationFormat = "none",
                RegDate = DateTime.UtcNow,
                Transports = new string[0]
            });
        }

        /// <summary>後片付け</summary>
        public void Dispose()
        {
            DataProvider.DeleteByUser(Encoding.UTF8.GetString(this._userId));
            this._key.Dispose();
        }

        /// <summary>正しいアサーションを受け、署名カウンタを進める</summary>
        [Fact]
        [Basis("WebAuthn Level 2 §7.2（検証の手順と signCount の更新）")]
        public async Task 正しいアサーションを受けて署名カウンタを進める()
        {
            VerifyAssertionResult result = await new WebAuthnHelper()
                .AuthenticatorAssertion(this.Assertion(), this.Options());

            Assert.Equal(11u, result.SignCount);
            Assert.Equal(11u, this.Stored().SignatureCounter);
        }

        /// <summary>署名が違えば断り、署名カウンタを進めない</summary>
        [Fact]
        [Basis("WebAuthn Level 2 §7.2（署名の検証）")]
        public async Task 署名が違えば断る()
        {
            using (ECDsa other = ECDsa.Create(ECCurve.NamedCurves.nistP256))
            {
                await Assert.ThrowsAsync<Fido2VerificationException>(() => new WebAuthnHelper().AuthenticatorAssertion(
                    this.Assertion(signer: other), this.Options()));
            }

            Assert.Equal(10u, this.Stored().SignatureCounter);
        }

        /// <summary>チャレンジが違えば断る</summary>
        [Fact]
        [Basis("WebAuthn Level 2 §7.2（challenge の照合）")]
        public async Task チャレンジが違えば断る()
        {
            AssertionOptions options = this.Options();
            options.Challenge = RandomNumberGenerator.GetBytes(32);

            await Assert.ThrowsAsync<Fido2VerificationException>(
                () => new WebAuthnHelper().AuthenticatorAssertion(this.Assertion(), options));

            Assert.Equal(10u, this.Stored().SignatureCounter);
        }

        /// <summary>origin が違えば断る</summary>
        [Fact]
        [Basis("WebAuthn Level 2 §7.2（origin の照合）")]
        public async Task originが違えば断る()
        {
            await Assert.ThrowsAsync<Fido2VerificationException>(() => new WebAuthnHelper().AuthenticatorAssertion(
                this.Assertion(origin: "https://evil.example"), this.Options()));

            Assert.Equal(10u, this.Stored().SignatureCounter);
        }

        /// <summary>rpIdHash が違えば断る</summary>
        [Fact]
        [Basis("WebAuthn Level 2 §7.2（rpIdHash の照合）")]
        public async Task rpIdHashが違えば断る()
        {
            await Assert.ThrowsAsync<Fido2VerificationException>(() => new WebAuthnHelper().AuthenticatorAssertion(
                this.Assertion(rpId: "evil.example"), this.Options()));

            Assert.Equal(10u, this.Stored().SignatureCounter);
        }

        /// <summary>userHandle が持ち主でなければ断る</summary>
        [Fact]
        [Basis("WebAuthn Level 2 §7.2（userHandle と資格情報の持ち主の照合）")]
        public async Task userHandleが持ち主でなければ断る()
        {
            await Assert.ThrowsAsync<Fido2VerificationException>(() => new WebAuthnHelper().AuthenticatorAssertion(
                this.Assertion(userHandle: Encoding.UTF8.GetBytes("someone_else")), this.Options()));

            Assert.Equal(10u, this.Stored().SignatureCounter);
        }

        /// <summary>登録されていない資格情報は断る</summary>
        [Fact]
        [Basis("WebAuthn Level 2 §7.2（credential.id から公開鍵を引く）")]
        public async Task 登録されていない資格情報は断る()
        {
            await Assert.ThrowsAnyAsync<Exception>(() => new WebAuthnHelper().AuthenticatorAssertion(
                this.Assertion(rawId: Guid.NewGuid().ToByteArray()), this.Options()));
        }

        /// <summary>署名カウンタが巻き戻っていれば断り、保存した値を変えない</summary>
        [Fact]
        [Basis("WebAuthn Level 2 §7.2（signCount が保存した値以下なら、複製の兆候。断るかは RP の判断で、ここでは断る）")]
        public async Task 署名カウンタが巻き戻っていれば断る()
        {
            await Assert.ThrowsAsync<Fido2VerificationException>(() => new WebAuthnHelper().AuthenticatorAssertion(
                this.Assertion(signCount: 5), this.Options()));

            Assert.Equal(10u, this.Stored().SignatureCounter);
        }

        /// <summary>資格情報から、持ち主の利用者を引く</summary>
        [Fact]
        [Basis("設計：DataProvider.GetUserByCredential（AccountController のサインインが、この利用者でサインインさせる）")]
        public void 資格情報から持ち主を引く()
        {
            Fido2User user = DataProvider.GetUserByCredential(this._credentialId);

            Assert.Equal(this._userId, user.Id);
            Assert.Equal(Encoding.UTF8.GetString(this._userId), user.Name);
        }

        /// <summary>登録されていない資格情報の持ち主は居ない</summary>
        [Fact]
        [Basis("設計：DataProvider.GetUserByCredential（AccountController のサインインが、この利用者でサインインさせる）")]
        public void 登録されていない資格情報の持ち主は居ない()
        {
            Assert.Null(DataProvider.GetUserByCredential(Guid.NewGuid().ToByteArray()));
        }

        /// <summary>保存してある資格情報</summary>
        private StoredCredential Stored()
        {
            return DataProvider.GetCredentialById(this._credentialId);
        }

        /// <summary>要求の内容</summary>
        private AssertionOptions Options()
        {
            return new AssertionOptions
            {
                Challenge = this._challenge,
                RpId = RpId,
                UserVerification = UserVerificationRequirement.Discouraged,
                AllowCredentials = new[] { new PublicKeyCredentialDescriptor(this._credentialId) }
            };
        }

        /// <summary>本物の鍵で署名したアサーション（既定で、すべて正しい値）</summary>
        private AuthenticatorAssertionRawResponse Assertion(
            string origin = Origin, string rpId = RpId, uint signCount = 11,
            ECDsa signer = null, byte[] userHandle = null, byte[] rawId = null)
        {
            byte[] clientData = Encoding.UTF8.GetBytes(
                "{\"type\":\"webauthn.get\",\"challenge\":\""
                + Base64Url(this._challenge) + "\",\"origin\":\"" + origin + "\"}");

            //  rpIdHash(32) ＋ flags(1 : UP) ＋ signCount(4、ビッグ エンディアン)
            byte[] authData = SHA256.HashData(Encoding.UTF8.GetBytes(rpId))
                .Concat(new byte[] { 0x01 })
                .Concat(new[] {
                    (byte)(signCount >> 24), (byte)(signCount >> 16),
                    (byte)(signCount >> 8), (byte)signCount })
                .ToArray();

            byte[] signature = (signer ?? this._key).SignData(
                authData.Concat(SHA256.HashData(clientData)).ToArray(),
                HashAlgorithmName.SHA256, DSASignatureFormat.Rfc3279DerSequence);

            return new AuthenticatorAssertionRawResponse
            {
                Id = Base64Url(rawId ?? this._credentialId),
                RawId = rawId ?? this._credentialId,
                Type = PublicKeyCredentialType.PublicKey,
                Response = new AuthenticatorAssertionRawResponse.AssertionResponse
                {
                    AuthenticatorData = authData,
                    ClientDataJson = clientData,
                    Signature = signature,
                    UserHandle = userHandle ?? this._userId
                }
            };
        }

        /// <summary>COSE_Key（RFC 8152。EC2・P-256・ES256）を CBOR で作る</summary>
        private byte[] CosePublicKey()
        {
            ECParameters p = this._key.ExportParameters(false);

            return new byte[] { 0xA5, 0x01, 0x02, 0x03, 0x26, 0x20, 0x01, 0x21, 0x58, 0x20 }
                .Concat(p.Q.X)
                .Concat(new byte[] { 0x22, 0x58, 0x20 })
                .Concat(p.Q.Y)
                .ToArray();
        }

        /// <summary>base64url</summary>
        private static string Base64Url(byte[] value)
        {
            return Convert.ToBase64String(value).TrimEnd('=').Replace('+', '-').Replace('/', '_');
        }
    }
}
