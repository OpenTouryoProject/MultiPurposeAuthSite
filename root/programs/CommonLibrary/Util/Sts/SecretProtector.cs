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
//* クラス名        ：SecretProtector
//* クラス日本語名  ：user store に入る秘密を、暗号化して保管する
//*
//* 作成日時        ：－
//* 作成者          ：－
//* 更新履歴        ：－
//*
//*  日時        更新者            内容
//*  ----------  ----------------  -------------------------------------------------
//*  2026/10/14  玄人 幸道         新規（#297）
//*  2026/10/31  玄人 幸道         Extensions/Sts から Util/Sts へ移した（配置の見直し。#294）
//**********************************************************************************

using MultiPurposeAuthSite.Co;
using MultiPurposeAuthSite.Log;

using System;
using System.Collections.Concurrent;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using MultiPurposeAuthSite.Extensions.Sts;

namespace MultiPurposeAuthSite.Util.Sts
{
    /// <summary>
    /// user store に入る秘密を、暗号化して保管する（#297）。
    /// </summary>
    /// <remarks>
    /// **対象は「元に戻せる形でなければならない秘密」**である。
    ///
    /// | 表 | 列 | なぜ戻せる形が要るか |
    /// |---|---|---|
    /// | `Saml2OAuth2Data` | `ClientSecret` | **クライアント認証で照合し、管理画面で再表示する** |
    /// | `IdFederationUpstreams` | `ClientSecret` | **上流へ送る**（`/token` のクライアント認証） |
    ///
    /// **だからハッシュは取れない。** **対称鍵で暗号化する。**
    ///
    /// | | |
    /// |---|---|
    /// | 暗号 | **AES-CBC（PKCS7）** ＋ **PBKDF2(SHA-256, 10 万回)** で鍵を導く |
    /// | 鍵 | **設定キー `UserStoreSecretPassword`**（**`DataProtectionKeyPath`（#251）とは別物**） |
    /// | 形 | **`enc:v1:` ＋ base64(salt 16 ＋ IV 16 ＋ 暗号文)** |
    /// | 印 | **先頭の `enc:v1:`**（**暗号文か平文かを、見れば分かるようにする**） |
    ///
    /// **salt と IV は 1 件ごとに作る**（**同じ秘密でも、毎回違う暗号文になる**）。
    ///
    /// > **Open棟梁 の `SymmetricCryptography` は使っていない。** **理由は暗号の形である。**
    /// >
    /// > | | `SymmetricCryptography`（実測） | **ここ** |
    /// > |---|---|---|
    /// > | salt / IV | **持たない**（**同じ平文が毎回同じ暗号文**になる） | **1 件ごとに作る** |
    /// > | 同じ秘密を使う登録 | **暗号文が一致するので、外から分かる** | **分からない** |
    /// >
    /// > **秘密を保管する用途では、1 件ごとに salt と IV を持つ方がよい**ので、
    /// > **標準 API（`Aes` ＋ `Rfc2898DeriveBytes`）で組んでいる**（net48 / net10.0 とも同じ形）。
    ///
    /// **鍵が空なら、何もしない**（**平文のまま入る** ＝ 従来どおり）。
    /// **鍵を配らない配備を動かなくしない**ためである。
    ///
    /// **印が無い値は、そのまま返す。**
    /// **既存の平文の行の移行は、この Issue では扱わない**（#297 の決め事。移行は別途）。
    ///
    /// > **設定ファイル（`appSettings`）の秘密は平文のまま**である。
    /// > **そこはファイルの権限で守る前提**で、**ここで扱うのは DB に入る分だけ**である。
    /// </remarks>
    public static class SecretProtector
    {
        /// <summary>暗号文の印（**版を含める** — 替えるときに見分けるため）</summary>
        public const string Prefix = "enc:v1:";

        /// <summary>暗号化するか（鍵が設定されているか）</summary>
        public static bool Enabled
        {
            get
            {
                return !string.IsNullOrEmpty(Config.UserStoreSecretPassword);
            }
        }

        /// <summary>保管する形にする（暗号化）</summary>
        /// <param name="plain">平文（空ならそのまま）</param>
        /// <returns>保管する値</returns>
        /// <remarks>
        /// **鍵が無ければ、平文のまま返す**（従来どおり）。
        /// **すでに印が付いている値は、二重に暗号化しない。**
        /// </remarks>
        public static string Protect(string plain)
        {
            if (string.IsNullOrEmpty(plain) || !SecretProtector.Enabled)
            {
                return plain;
            }

            if (plain.StartsWith(SecretProtector.Prefix, StringComparison.Ordinal))
            {
                // **二重に暗号化しない**（保存を 2 度通る経路があっても壊れないように）。
                return plain;
            }

            try
            {
                return SecretProtector.Prefix + SecretProtector.Encrypt(
                    plain, Config.UserStoreSecretPassword);
            }
            catch (Exception ex)
            {
                //  **暗号化できなければ、保存しない方が安全である。**
                //    **平文で入れてしまうと、暗号化しているつもりで平文が残る。**
                Logging.MyOperationTrace(string.Format(
                    "A secret could not be encrypted. ({0})", ex.GetType().Name));

                throw;
            }
        }

        /// <summary>使う形にする（復号）</summary>
        /// <param name="stored">保管されている値</param>
        /// <returns>平文</returns>
        /// <remarks>
        /// **印が無ければ、そのまま返す**（暗号化していない行。移行は別途）。
        /// **復号に失敗したら、空を返す**（**鍵を取り違えた値を、平文として使わせない**）。
        /// </remarks>
        public static string Unprotect(string stored)
        {
            if (string.IsNullOrEmpty(stored))
            {
                return stored;
            }

            if (!stored.StartsWith(SecretProtector.Prefix, StringComparison.Ordinal))
            {
                // **暗号化していない値**（鍵を設定していない配備で入れた行）。
                return stored;
            }

            if (!SecretProtector.Enabled)
            {
                //  **暗号文が在るのに鍵が無い。** **理由を残す**（#253 と同じ方針）。
                Logging.MyOperationTrace(
                    "An encrypted secret was found but UserStoreSecretPassword is not set.");

                return "";
            }

            try
            {
                return SecretProtector.Decrypt(
                    stored.Substring(SecretProtector.Prefix.Length),
                    Config.UserStoreSecretPassword);
            }
            catch (Exception ex)
            {
                //  **鍵が違う・値が壊れている。** **平文として使わせない。**
                Logging.MyOperationTrace(string.Format(
                    "A secret could not be decrypted. ({0})", ex.GetType().Name));

                return "";
            }
        }

        #region 暗号（AES-CBC ＋ PBKDF2）

        /// <summary>salt の長さ（バイト）</summary>
        private const int SaltSize = 16;

        /// <summary>鍵の導出の繰り返し回数</summary>
        /// <remarks>
        /// **10 万回**（OWASP の目安に合わせた）。
        /// **導いた鍵はキャッシュする**（下の `KeyCache`） — **でなければ遅すぎる。**
        ///
        /// **実測（2026/10/14）** : キャッシュが無いと、**E2E の通しが 137 秒 → 922 秒**になった。
        /// **`client_secret` はクライアント認証のたびに読む**ので、
        /// **1 回の読み出しごとに 10 万回の導出が走っていた。**
        /// </remarks>
        private const int Iterations = 100000;

        /// <summary>導いた鍵の控え（**同じ salt なら使い回す**）</summary>
        /// <remarks>
        /// **鍵は「パスワード ＋ salt ＋ 長さ」で決まる**ので、それを鍵にする
        /// （**パスワードそのものは鍵に入れない** — ハッシュにして混ぜる）。
        ///
        /// **salt は 1 件ごとに違う**ので、**控えは登録の件数くらいで収まる。**
        /// **膨れたら捨てる**（`MaxCacheSize`。**攻撃者が増やせる口ではない** —
        /// **行を作れるのは管理者だけ**である）。
        /// </remarks>
        private static readonly ConcurrentDictionary<string, byte[]> KeyCache
            = new ConcurrentDictionary<string, byte[]>();

        /// <summary>控えの上限</summary>
        private const int MaxCacheSize = 1024;

        /// <summary>暗号化する（salt と IV を 1 件ごとに作る）</summary>
        /// <param name="plain">平文</param>
        /// <param name="password">パスワード</param>
        /// <returns>base64(salt ＋ IV ＋ 暗号文)</returns>
        private static string Encrypt(string plain, string password)
        {
            byte[] salt = new byte[SecretProtector.SaltSize];

            using (RandomNumberGenerator rng = RandomNumberGenerator.Create())
            {
                rng.GetBytes(salt);
            }

            using (Aes aes = Aes.Create())
            {
                aes.Mode = CipherMode.CBC;
                aes.Padding = PaddingMode.PKCS7;
                aes.Key = SecretProtector.DeriveKey(password, salt, aes.KeySize / 8);
                aes.GenerateIV();

                using (MemoryStream ms = new MemoryStream())
                {
                    //  **salt と IV を、暗号文の前に置く**（復号に要る。秘密ではない）。
                    ms.Write(salt, 0, salt.Length);
                    ms.Write(aes.IV, 0, aes.IV.Length);

                    using (ICryptoTransform encryptor = aes.CreateEncryptor())
                    using (CryptoStream cs = new CryptoStream(ms, encryptor, CryptoStreamMode.Write))
                    {
                        byte[] bytes = Encoding.UTF8.GetBytes(plain);
                        cs.Write(bytes, 0, bytes.Length);
                        cs.FlushFinalBlock();
                    }

                    return Convert.ToBase64String(ms.ToArray());
                }
            }
        }

        /// <summary>復号する</summary>
        /// <param name="encoded">base64(salt ＋ IV ＋ 暗号文)</param>
        /// <param name="password">パスワード</param>
        /// <returns>平文</returns>
        private static string Decrypt(string encoded, string password)
        {
            byte[] all = Convert.FromBase64String(encoded);

            using (Aes aes = Aes.Create())
            {
                aes.Mode = CipherMode.CBC;
                aes.Padding = PaddingMode.PKCS7;

                int ivSize = aes.BlockSize / 8;

                if (all.Length <= SecretProtector.SaltSize + ivSize)
                {
                    //  **形が合わない。** **呼び出し側が空を返す**（平文として使わせない）。
                    throw new CryptographicException("The encrypted secret is too short.");
                }

                byte[] salt = new byte[SecretProtector.SaltSize];
                byte[] iv = new byte[ivSize];

                Buffer.BlockCopy(all, 0, salt, 0, salt.Length);
                Buffer.BlockCopy(all, salt.Length, iv, 0, iv.Length);

                aes.Key = SecretProtector.DeriveKey(password, salt, aes.KeySize / 8);
                aes.IV = iv;

                int offset = salt.Length + iv.Length;

                using (ICryptoTransform decryptor = aes.CreateDecryptor())
                using (MemoryStream ms = new MemoryStream(all, offset, all.Length - offset))
                using (CryptoStream cs = new CryptoStream(ms, decryptor, CryptoStreamMode.Read))
                using (StreamReader sr = new StreamReader(cs, Encoding.UTF8))
                {
                    return sr.ReadToEnd();
                }
            }
        }

        /// <summary>パスワードから鍵を導く（PBKDF2。SHA-256）</summary>
        /// <param name="password">パスワード</param>
        /// <param name="salt">salt</param>
        /// <param name="length">鍵の長さ（バイト）</param>
        /// <returns>鍵</returns>
        /// <remarks>
        /// **ターゲットで API が違う**（`Extensions/Sts/Helper.cs` と同じ分け方）。
        /// **net48 に `Rfc2898DeriveBytes.Pbkdf2`（静的）が無く**、
        /// **net10.0 では constructor が旧式**（`SYSLIB0060`）である。
        /// </remarks>
        private static byte[] DeriveKey(string password, byte[] salt, int length)
        {
            //  **同じ salt なら、導いた鍵を使い回す**（PBKDF2 は重い）。
            string cacheKey = SecretProtector.CacheKeyOf(password, salt, length);
            byte[] cached;

            if (SecretProtector.KeyCache.TryGetValue(cacheKey, out cached))
            {
                return cached;
            }

            byte[] derived = SecretProtector.DeriveKeyCore(password, salt, length);

            if (SecretProtector.KeyCache.Count < SecretProtector.MaxCacheSize)
            {
                SecretProtector.KeyCache.TryAdd(cacheKey, derived);
            }
            else
            {
                //  **膨れたら、ひとまず捨てる**（**次からまた溜める**）。
                SecretProtector.KeyCache.Clear();
            }

            return derived;
        }

        /// <summary>控えの鍵（パスワードそのものは入れない）</summary>
        /// <param name="password">パスワード</param>
        /// <param name="salt">salt</param>
        /// <param name="length">鍵の長さ（バイト）</param>
        /// <returns>控えの鍵</returns>
        private static string CacheKeyOf(string password, byte[] salt, int length)
        {
            using (SHA256 sha = SHA256.Create())
            {
                byte[] pw = Encoding.UTF8.GetBytes(password);
                byte[] all = new byte[pw.Length + salt.Length];

                Buffer.BlockCopy(pw, 0, all, 0, pw.Length);
                Buffer.BlockCopy(salt, 0, all, pw.Length, salt.Length);

                return Convert.ToBase64String(sha.ComputeHash(all)) + ":" + length;
            }
        }

        /// <summary>パスワードから鍵を導く（キャッシュを通さない）</summary>
        /// <param name="password">パスワード</param>
        /// <param name="salt">salt</param>
        /// <param name="length">鍵の長さ（バイト）</param>
        /// <returns>鍵</returns>
        private static byte[] DeriveKeyCore(string password, byte[] salt, int length)
        {
#if NETFX
            using (Rfc2898DeriveBytes kdf = new Rfc2898DeriveBytes(
                password, salt, SecretProtector.Iterations, HashAlgorithmName.SHA256))
            {
                return kdf.GetBytes(length);
            }
#else
            return Rfc2898DeriveBytes.Pbkdf2(
                password, salt, SecretProtector.Iterations, HashAlgorithmName.SHA256, length);
#endif
        }

        #endregion
    }
}
