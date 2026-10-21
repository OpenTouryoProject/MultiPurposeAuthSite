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
//* クラス名        ：JwkSetDocument
//* クラス日本語名  ：/jwkcerts が返す JWK Set（覚えて返す）
//*
//* 作成日時        ：－
//* 作成者          ：－
//* 更新履歴        ：－
//*
//*  日時        更新者            内容
//*  ----------  ----------------  -------------------------------------------------
//*  2026/10/16  玄人 幸道         新規（#303。E-7）
//**********************************************************************************

using MultiPurposeAuthSite.Co;

using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;

using Touryo.Infrastructure.Framework.Authentication;
using Touryo.Infrastructure.Public.IO;
using Touryo.Infrastructure.Public.Str;
using Touryo.Infrastructure.Public.Util;

/// <summary>MultiPurposeAuthSite.Extensions.Sts</summary>
namespace MultiPurposeAuthSite.Extensions.Sts
{
    /// <summary>
    /// `/jwkcerts` が返す JWK Set を、**覚えて返す**（#303。E-7）。
    /// </summary>
    /// <remarks>
    /// **この口は、トークンを検証する相手が必ず読む。**
    /// **内容は鍵を入れ替えるまで変わらない**のに、**要求ごとにファイルを開いて読んでいた。**
    ///
    /// | | |
    /// |---|---|
    /// | 覚える単位 | **ファイルの最終更新時刻 ＋ 長さ**（`File.GetLastWriteTimeUtc` / `Length`） |
    /// | 入れ替え | **作り直せば、刻印が変わるので読み直す**（`CreateJwkSetJson`。#129 の段階 3） |
    /// | `ETag` | **中身の SHA-256**（base64url。**同じ中身なら同じ値**） |
    ///
    /// **起動時に 1 度だけ読む形にはしない。**
    /// **鍵の入れ替え（ロールオーバー）に追随できなくなる** — **出す側は新旧 2 本を広告する**
    /// 作りにしてある（#291 / #292 の段階 3。`SA-2.2`）。
    ///
    /// **構成の絶対パスにファイルが無ければ、覚えない**（`ResourceLoader` が別の場所から
    /// 解決することがあるため。**そのときは従来どおり、毎回読む**）。
    /// </remarks>
    public static class JwkSetDocument
    {
        #region 覚えている分

        /// <summary>覚えている内容の鍵（パス ＋ 最終更新時刻 ＋ 長さ）</summary>
        private static string _stamp = null;

        /// <summary>覚えている本文</summary>
        private static string _content = null;

        /// <summary>覚えている ETag</summary>
        private static string _etag = null;

        /// <summary>覚えている分の入れ替えを直列化する</summary>
        private static readonly object _lock = new object();

        #endregion

        #region メソッド

        /// <summary>JWK Set の本文と ETag を返す</summary>
        /// <param name="etag">out ETag（`"..."` の形。引用符を含む）</param>
        /// <returns>JWK Set の本文（JSON）</returns>
        /// <remarks>
        /// **ファイルが変わっていなければ、覚えている分を返す。**
        /// **変わっていれば読み直す**（鍵の入れ替えに追随する）。
        /// </remarks>
        public static string Get(out string etag)
        {
            string path = OAuth2AndOIDCParams.JwkSetFilePath;
            string stamp = JwkSetDocument.StampOf(path);

            if (stamp != null)
            {
                lock (JwkSetDocument._lock)
                {
                    if (stamp == JwkSetDocument._stamp)
                    {
                        etag = JwkSetDocument._etag;
                        return JwkSetDocument._content;
                    }
                }
            }

            string content = ResourceLoader.LoadAsString(
                path, Encoding.GetEncoding(CustomEncode.UTF_8));

            etag = JwkSetDocument.ETagOf(content);

            if (stamp != null)
            {
                lock (JwkSetDocument._lock)
                {
                    JwkSetDocument._stamp = stamp;
                    JwkSetDocument._content = content;
                    JwkSetDocument._etag = etag;
                }
            }

            return content;
        }

        /// <summary>`Cache-Control` に入れる秒数（0 なら付けない）</summary>
        /// <returns>秒数</returns>
        public static int MaxAgeSeconds
        {
            get
            {
                return Config.JwkSetCacheMaxAgeSeconds;
            }
        }

        #endregion

        #region 補助

        /// <summary>ファイルの刻印（変わったかどうかだけを見る）</summary>
        /// <param name="path">構成に書かれたパス</param>
        /// <returns>刻印（そのパスにファイルが無ければ null ＝ 覚えない）</returns>
        /// <remarks>
        /// **中身は読まない。** **`stat` だけで済ませる**のが狙いである。
        /// </remarks>
        private static string StampOf(string path)
        {
            try
            {
                if (string.IsNullOrEmpty(path) || !File.Exists(path))
                {
                    return null;
                }

                FileInfo info = new FileInfo(path);

                return path + "|" + info.LastWriteTimeUtc.Ticks.ToString() + "|" + info.Length.ToString();
            }
            catch (Exception)
            {
                // **刻印が取れないときは、覚えない**（毎回読む。従来どおり）。
                return null;
            }
        }

        /// <summary>中身から ETag を作る</summary>
        /// <param name="content">本文</param>
        /// <returns>ETag（`"..."` の形）</returns>
        /// <remarks>**同じ中身なら同じ値**になる（弱い ETag にはしない）。</remarks>
        private static string ETagOf(string content)
        {
            using (SHA256 sha = SHA256.Create())
            {
                byte[] hash = sha.ComputeHash(
                    CustomEncode.StringToByte(content ?? "", CustomEncode.UTF_8));

                return "\"" + CustomEncode.ToBase64UrlString(hash) + "\"";
            }
        }

        #endregion
    }
}
