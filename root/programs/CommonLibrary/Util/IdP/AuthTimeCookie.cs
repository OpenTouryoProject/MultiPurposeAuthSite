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
//* クラス名        ：AuthTimeCookie
//* クラス日本語名  ：auth_time と再認証の印の Cookie を、改ざんできない形で読み書きする
//*
//* 作成日時        ：－
//* 作成者          ：－
//* 更新履歴        ：－
//*
//*  日時        更新者            内容
//*  ----------  ----------------  -------------------------------------------------
//*  2026/10/28  玄人 幸道         新規（#294）
//*  2026/10/31  玄人 幸道         Extensions/Sts から Util/IdP へ移した（配置の見直し。#294）
//**********************************************************************************

using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;

#if NETFX
using System.Web;
using System.Web.Security;
#else
using Microsoft.AspNetCore.DataProtection;
using Microsoft.Extensions.DependencyInjection;
using Touryo.Infrastructure.Framework.StdMigration;
#endif

// OpenTouryo
using Touryo.Infrastructure.Framework.Authentication;
using Touryo.Infrastructure.Public.Str;
using MultiPurposeAuthSite.Extensions.Sts;

/// <summary>MultiPurposeAuthSite.Extensions.Sts</summary>
namespace MultiPurposeAuthSite.Util.IdP
{
    /// <summary>
    /// auth_time と再認証の印の Cookie を、改ざんできない形で読み書きする（#294）。
    /// </summary>
    /// <remarks>
    /// **以前は、平文の Cookie だった**（W3C 形式の時刻をそのまま入れていた）。
    /// **ブラウザ側で書き換えられる**ので、次が成り立たなかった。
    ///
    /// | Cookie | 何に使うか | 書き換えると |
    /// |---|---|---|
    /// | `auth_time` | **`max_age` の判定**と、**id_token の `auth_time`** | **再認証を飛ばし、偽の時刻を RP に保証する** |
    /// | 再認証の印 | **`prompt=login` / `max_age` の繰り返しを止める** | **再認証を飛ばす** |
    ///
    /// **値は、基盤の改ざん検出付きの仕組みで包む**（net10.0 : DataProtection（#251 で鍵を永続化）／net48 : `MachineKey.Protect`）。
    /// **開けなければ（書き換え・壊れ・鍵の交換）、無いものとして扱う**（例外にしない）。
    ///
    /// **再認証の印は、どの認可要求のものかに結び付ける**（要求の指紋。下の `RequestKey`）。
    /// **途中でやめた再認証の印が残っても、別の RP の `prompt=login` を通さない**ためである。
    /// </remarks>
    public static class AuthTimeCookie
    {
        /// <summary>auth_time の用途（包む鍵を分ける）</summary>
        private const string PurposeAuthTime = "MultiPurposeAuthSite.AuthTime.v1";

        /// <summary>再認証の印の用途（包む鍵を分ける）</summary>
        private const string PurposeReAuthenticatedAt = "MultiPurposeAuthSite.ReAuthenticatedAt.v1";

        #region auth_time

        /// <summary>auth_time の Cookie の値を作る</summary>
        /// <param name="authTimeUtc">認証した時刻（UTC）</param>
        /// <returns>Cookie の値</returns>
        public static string ProtectAuthTime(DateTime authTimeUtc)
        {
            return AuthTimeCookie.Protect(PurposeAuthTime,
                FormatConverter.ToW3cTimestamp(authTimeUtc));
        }

        /// <summary>auth_time の Cookie の値を開く</summary>
        /// <param name="cookieValue">Cookie の値</param>
        /// <returns>W3C 形式の時刻（開けなければ null）</returns>
        public static string UnprotectAuthTime(string cookieValue)
        {
            return AuthTimeCookie.Unprotect(PurposeAuthTime, cookieValue);
        }

        #endregion

        #region 再認証の印

        /// <summary>再認証の印の Cookie の値を作る</summary>
        /// <param name="askedAtUtc">再認証を求めた時刻（UTC）</param>
        /// <param name="requestKey">要求の指紋（`RequestKey`）</param>
        /// <returns>Cookie の値</returns>
        public static string ProtectReAuthenticatedAt(DateTime askedAtUtc, string requestKey)
        {
            return AuthTimeCookie.Protect(PurposeReAuthenticatedAt,
                FormatConverter.ToW3cTimestamp(askedAtUtc) + "|" + requestKey);
        }

        /// <summary>再認証の印の Cookie の値を開く</summary>
        /// <param name="cookieValue">Cookie の値</param>
        /// <param name="requestKey">いまの要求の指紋（`RequestKey`）</param>
        /// <returns>
        /// W3C 形式の時刻（**開けない、または別の要求の印なら null**）
        /// </returns>
        public static string UnprotectReAuthenticatedAt(string cookieValue, string requestKey)
        {
            string value = AuthTimeCookie.Unprotect(PurposeReAuthenticatedAt, cookieValue);

            if (string.IsNullOrEmpty(value))
            {
                return null;
            }

            int bar = value.IndexOf('|');

            if (bar < 0 || value.Substring(bar + 1) != requestKey)
            {
                //  **別の要求の印**（途中でやめた再認証の印が残っている）。
                return null;
            }

            return value.Substring(0, bar);
        }

        /// <summary>認可要求の指紋（再認証の印を、その要求に結び付ける）</summary>
        /// <param name="query">クエリのパラメタ（名前と値）</param>
        /// <param name="excludeKeys">除くパラメタ（自分で足す印など）</param>
        /// <returns>指紋（base64url の SHA-256）</returns>
        /// <remarks>
        /// **名前で並べ替えてから束ねる**（**サインインの往復で順序が変わっても、同じ指紋になる**）。
        /// **自分で足す印（`Const.OpSessionRetry`）は除く**（送り返しで足されるため）。
        /// </remarks>
        public static string RequestKey(
            IEnumerable<KeyValuePair<string, string>> query, params string[] excludeKeys)
        {
            HashSet<string> excluded = new HashSet<string>(excludeKeys ?? new string[0], StringComparer.Ordinal);

            string canonical = string.Join("&", query
                .Where(kv => !string.IsNullOrEmpty(kv.Key) && !excluded.Contains(kv.Key))
                .OrderBy(kv => kv.Key, StringComparer.Ordinal)
                .ThenBy(kv => kv.Value ?? "", StringComparer.Ordinal)
                .Select(kv => Uri.EscapeDataString(kv.Key) + "=" + Uri.EscapeDataString(kv.Value ?? "")));

            using (SHA256 sha = SHA256.Create())
            {
                return Convert.ToBase64String(sha.ComputeHash(Encoding.UTF8.GetBytes(canonical)))
                    .TrimEnd('=').Replace('+', '-').Replace('/', '_');
            }
        }

        #endregion

        #region 包む・開く

        /// <summary>包む</summary>
        /// <param name="purpose">用途</param>
        /// <param name="plain">平文</param>
        /// <returns>包んだ値</returns>
        private static string Protect(string purpose, string plain)
        {
#if NETFX
            byte[] protectedBytes = MachineKey.Protect(Encoding.UTF8.GetBytes(plain), purpose);
            return HttpServerUtility.UrlTokenEncode(protectedBytes);
#else
            return AuthTimeCookie.Protector(purpose).Protect(plain);
#endif
        }

        /// <summary>開く（開けなければ null）</summary>
        /// <param name="purpose">用途</param>
        /// <param name="protectedValue">包んだ値</param>
        /// <returns>平文（開けなければ null）</returns>
        private static string Unprotect(string purpose, string protectedValue)
        {
            if (string.IsNullOrEmpty(protectedValue))
            {
                return null;
            }

            try
            {
#if NETFX
                byte[] protectedBytes = HttpServerUtility.UrlTokenDecode(protectedValue);

                if (protectedBytes == null)
                {
                    return null;
                }

                return Encoding.UTF8.GetString(MachineKey.Unprotect(protectedBytes, purpose));
#else
                return AuthTimeCookie.Protector(purpose).Unprotect(protectedValue);
#endif
            }
            catch
            {
                //  **書き換え・壊れ・鍵の交換**。**無いものとして扱う**（例外にしない）。
                return null;
            }
        }

#if !NETFX
        /// <summary>DataProtection の Protector（要求のサービスから引く）</summary>
        /// <param name="purpose">用途</param>
        /// <returns>IDataProtector</returns>
        private static IDataProtector Protector(string purpose)
        {
            return MyHttpContext.Current.RequestServices
                .GetRequiredService<IDataProtectionProvider>()
                .CreateProtector(purpose);
        }
#endif

        #endregion
    }
}
