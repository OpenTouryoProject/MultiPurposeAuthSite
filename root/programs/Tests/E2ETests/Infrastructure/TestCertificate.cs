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
//* クラス名        ：TestCertificate
//* クラス日本語名  ：mTLS 用の、自己署名のクライアント証明書（テスト用）
//*
//* 作成日時        ：－
//* 作成者          ：－
//* 更新履歴        ：－
//*
//*  日時        更新者            内容
//*  ----------  ----------------  -------------------------------------------------
//*  2026/09/22  玄人 幸道         新規（#226 : mTLS の経路を E2E で確かめる）
//*  2026/10/10  玄人 幸道         PEM で渡す版を追加（#277 の段階 7：ブラウザに渡す）
//**********************************************************************************

using System;
using System.Linq;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace MultiPurposeAuthSite.Tests.E2E.Infrastructure
{
    /// <summary>
    /// mTLS 用の、自己署名のクライアント証明書を作る（#226）。
    /// </summary>
    /// <remarks>
    /// **証明書ストアには入れない。** その場で作り、使い終わったら Dispose する。
    ///
    /// ・Subject は CN だけ。**文字列の DN を渡すと \ がエスケープとして解釈される**ので、
    ///   CN の値を X500DistinguishedNameBuilder で組み立てる
    /// ・秘密鍵は PFX を経由して読み直す。Windows の TLS（SChannel）は、一時鍵（EphemeralKeySet）を使えない。
    ///   PersistKeySet は付けないので、Dispose で鍵も消える
    /// ・拡張キー使用法に clientAuth を入れる
    /// </remarks>
    public static class TestCertificate
    {
        /// <summary>
        /// テスト対象に合わせて、クライアント証明書を用意する
        /// </summary>
        /// <param name="target">テスト対象</param>
        /// <param name="subjectDn">Subject（"CN=..." の形）</param>
        /// <returns>秘密鍵つきの証明書（呼び出し元が Dispose する）</returns>
        /// <remarks>
        /// ・net10.0 版 : その場で自己署名の証明書を作る（テスト専用のフックが、発行元を問わず受け付ける）
        /// ・net48 版   : **CurrentUser\My に用意した証明書を使う**（-NetFxMtls のとき）。
        ///   IIS は信頼できない証明書をアプリより前で 403.16 として断るので、
        ///   テスト用 CA が発行し、その CA をコンピューターの信頼されたルートに入れたものが要る（TESTING.md）
        /// </remarks>
        public static X509Certificate2 ForTarget(TargetInfo target, string subjectDn)
        {
            if (target.Key != TestEnv.NetFxKey)
            {
                return TestCertificate.CreateClientCertificate(subjectDn);
            }

            using (X509Store store = new X509Store(StoreName.My, StoreLocation.CurrentUser))
            {
                store.Open(OpenFlags.ReadOnly);

                X509Certificate2 found = store.Certificates
                    .Find(X509FindType.FindBySubjectDistinguishedName, subjectDn, false)
                    .Cast<X509Certificate2>()
                    .Where(c => c.HasPrivateKey
                        && c.NotBefore <= DateTime.Now && DateTime.Now <= c.NotAfter)
                    .OrderByDescending(c => c.NotAfter)
                    .FirstOrDefault();

                if (found == null)
                {
                    throw new InvalidOperationException(
                        "CurrentUser\\My に " + subjectDn + " の証明書（秘密鍵つき・有効期間内）がありません。"
                        + "-NetFxMtls の準備（TESTING.md「net48 版の mTLS」）を行ってください。");
                }

                return found;
            }
        }

        /// <summary>自己署名のクライアント証明書を作る</summary>
        /// <param name="subjectDn">Subject（"CN=..." の形だけを受け付ける）</param>
        /// <returns>秘密鍵つきの証明書（呼び出し元が Dispose する）</returns>
        public static X509Certificate2 CreateClientCertificate(string subjectDn)
        {
            if (string.IsNullOrEmpty(subjectDn) || !subjectDn.StartsWith("CN=", StringComparison.Ordinal))
            {
                throw new ArgumentException("CN=... の形だけを受け付ける。", nameof(subjectDn));
            }

            X500DistinguishedNameBuilder builder = new X500DistinguishedNameBuilder();
            builder.AddCommonName(subjectDn.Substring(3));

            using (RSA rsa = RSA.Create(2048))
            {
                CertificateRequest request = new CertificateRequest(
                    builder.Build(), rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);

                request.CertificateExtensions.Add(new X509EnhancedKeyUsageExtension(
                    new OidCollection() { new Oid("1.3.6.1.5.5.7.3.2") }, false)); // clientAuth

                using (X509Certificate2 created = request.CreateSelfSigned(
                    DateTimeOffset.Now.AddMinutes(-5), DateTimeOffset.Now.AddHours(1)))
                {
                    return X509CertificateLoader.LoadPkcs12(
                        created.Export(X509ContentType.Pfx), null, X509KeyStorageFlags.UserKeySet);
                }
            }
        }

        /// <summary>自己署名のクライアント証明書を PEM で作る</summary>
        /// <param name="subjectDn">Subject（"CN=..." の形だけを受け付ける）</param>
        /// <param name="privateKeyPem">秘密鍵（PKCS#8 の PEM）</param>
        /// <returns>証明書（PEM）</returns>
        /// <remarks>
        /// **ブラウザに渡すためのもの**（`WebUi`。#277 の段階 7）。
        ///
        /// **上の `CreateClientCertificate` と別にしてある。**
        /// **あちらが返す証明書の鍵は書き出せない**
        /// （`UserKeySet` で読むので、`Export` が
        /// 「指定された状態で使用するには無効なキーです」で落ちる。**実測**）。
        /// **PKCS#12 を経由しない**のも意図である
        /// （**渡す先は Node なので、古い暢号の PKCS#12 を読むとは限らない**）。
        /// </remarks>
        public static string CreateClientCertificatePem(string subjectDn, out string privateKeyPem)
        {
            if (string.IsNullOrEmpty(subjectDn) || !subjectDn.StartsWith("CN=", StringComparison.Ordinal))
            {
                throw new ArgumentException("CN=... の形だけを受け付ける。", nameof(subjectDn));
            }

            X500DistinguishedNameBuilder builder = new X500DistinguishedNameBuilder();
            builder.AddCommonName(subjectDn.Substring(3));

            using (RSA rsa = RSA.Create(2048))
            {
                CertificateRequest request = new CertificateRequest(
                    builder.Build(), rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);

                request.CertificateExtensions.Add(new X509EnhancedKeyUsageExtension(
                    new OidCollection() { new Oid("1.3.6.1.5.5.7.3.2") }, false)); // clientAuth

                using (X509Certificate2 created = request.CreateSelfSigned(
                    DateTimeOffset.Now.AddMinutes(-5), DateTimeOffset.Now.AddHours(1)))
                {
                    privateKeyPem = rsa.ExportPkcs8PrivateKeyPem();

                    return created.ExportCertificatePem();
                }
            }
        }
    }
}
