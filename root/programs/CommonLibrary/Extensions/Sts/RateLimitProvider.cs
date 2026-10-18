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
//* クラス名        ：RateLimitProvider
//* クラス日本語名  ：口ごとのレート制限（固定窓）
//*
//* 作成日時        ：－
//* 作成者          ：－
//* 更新履歴        ：－
//*
//*  日時        更新者            内容
//*  ----------  ----------------  -------------------------------------------------
//*  2026/10/16  玄人 幸道         新規（#305 の段階 3）
//*  2026/10/18  玄人 幸道         動的クライアント登録の口を対象に足した（#307 の段階 1）
//**********************************************************************************

using MultiPurposeAuthSite.Co;
using MultiPurposeAuthSite.Log;

using System;
using System.Collections.Generic;
using System.Collections.Concurrent;
using System.Text;

// OpenTouryo
using Touryo.Infrastructure.Framework.Authentication;

/// <summary>MultiPurposeAuthSite.Extensions.Sts</summary>
namespace MultiPurposeAuthSite.Extensions.Sts
{
    /// <summary>
    /// 口ごとのレート制限（#305 の段階 3）。
    /// </summary>
    /// <remarks>
    /// **段階 2 は「失敗の回数」、ここは「要求の回数」**である（**成否を問わない**）。
    /// **数える単位は「口 × 鍵」**（`ANALYSIS-IdP.md` の D-13）。
    ///
    /// | 鍵 | 設定 | 何に効くか |
    /// |---|---|---|
    /// | **`client:&lt;client_id&gt;`** | `RateLimitPerClientPermits` | **1 つのクライアントからの洪水** |
    /// | **`ip:&lt;アドレス&gt;`** | `RateLimitPerIpPermits` | **1 つの送信元からの洪水**（**`client_id` を毎回変えても効く**） |
    ///
    /// **両方が有効なら、両方を数える**（**どちらかが超えていれば断る**）。
    /// **どちらも 0（未設定）なら、何もしない**（従来どおり）。
    ///
    /// **断るときの応答は `429` ＋ `Retry-After`**（RFC 6585 §4）。
    /// **OAuth のエラー応答にはしない** — **段階 1 の `slow_down` はプロトコルの層の話**で、
    /// **こちらは HTTP の層の話**である（`/token` のエラー符号は RFC 6749 §5.2 で閉じている）。
    ///
    /// **窓は固定窓で、プロセスの中に覚える。**
    ///
    /// | | |
    /// |---|---|
    /// | **固定窓** | **窓の境目では、瞬間的に上限の 2 倍まで通り得る**（滑る窓にはしていない） |
    /// | **プロセスの中** | **インスタンスを増やすと、その数だけ緩くなる**（**段階 2 は表に持たせたが、ここは要求ごとに触るので表には置かない**） |
    ///
    /// **両アプリで同じ判断にするため、判定はここに 1 つだけ置く。**
    /// **net10.0 版には組み込みのレート制限ミドルウェアが在る**が、
    /// **net48 版には無い** — **別々に作ると、E2E が両方で同じことを測れない。**
    /// **呼ぶ側は、入口でこのクラスに聞いて `429` を返すだけ**である
    /// （net10.0 : `Startup.Configure` の `app.Use(...)` ／ net48 : `Global.asax` の `BeginRequest`）。
    /// </remarks>
    public static class RateLimitProvider
    {
        #region 内部の入れ物

        /// <summary>1 つの鍵の、いまの窓と回数</summary>
        private sealed class Counter
        {
            /// <summary>窓の開始（UNIX 時刻）</summary>
            public long WindowStart;

            /// <summary>この窓で数えた回数</summary>
            public int Count;
        }

        /// <summary>鍵 → 回数</summary>
        private static ConcurrentDictionary<string, Counter> Counters
            = new ConcurrentDictionary<string, Counter>();

        /// <summary>
        /// 覚える鍵の上限
        /// </summary>
        /// <remarks>
        /// **鍵は要求から作る**ので、**送信元を変え続けられると増え続ける。**
        /// **この数を超えたら、古い窓の分を捨てる**（捨てても、その鍵は次の要求で作り直される）。
        /// </remarks>
        private const int MaxKeys = 100000;

        #endregion

        #region 口の表

        /// <summary>
        /// 制限する口（パス → 口の名前）
        /// </summary>
        /// <remarks>
        /// **口の名前が、数える単位**になる（**`/token` の洪水で `/revoke` を止めない**ため）。
        /// **パスは設定から引く**（配備で変えられる。`Config` / `OAuth2AndOIDCParams`）。
        /// **起動後は変わらないので、1 度だけ作る。**
        ///
        /// **ここに無い口は、制限しない**（画面・`/userinfo` ほか）。
        /// **画面は認証とセッションで守られており、**
        /// **総当たりの的になるのは、ここに挙げた口である**（#305）。
        /// </remarks>
        private static Dictionary<string, string> endpoints = null;

        /// <summary>endpoints の初期化に使う</summary>
        private static object endpointsLock = new object();

        /// <summary>制限する口の表</summary>
        private static Dictionary<string, string> Endpoints
        {
            get
            {
                if (RateLimitProvider.endpoints != null)
                {
                    return RateLimitProvider.endpoints;
                }

                lock (RateLimitProvider.endpointsLock)
                {
                    if (RateLimitProvider.endpoints == null)
                    {
                        Dictionary<string, string> map =
                            new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);

                        RateLimitProvider.Add(map, Config.OAuth2TokenEndpoint, "token");
                        RateLimitProvider.Add(map, Config.OAuth2RevokeTokenEndpoint, "revoke");
                        RateLimitProvider.Add(map, Config.OAuth2IntrospectTokenEndpoint, "introspect");
                        RateLimitProvider.Add(map, Config.DeviceAuthZAuthorizeEndpoint, "device_authz");
                        RateLimitProvider.Add(map, Config.DeviceAuthZVerifyEndpoint, "device_verify");
                        RateLimitProvider.Add(map, Config.CibaAuthorizeEndpoint, "ciba_authz");
                        RateLimitProvider.Add(map, OAuth2AndOIDCParams.AuthRequestPushUri, "par");
                        RateLimitProvider.Add(map, OAuth2AndOIDCParams.JwkSetUri, "jwkcerts");

                        //  **動的クライアント登録**（#307 の段階 1）。
                        //    **開けていない配備でも表には入る**（口が無ければ、そもそも来ない）。
                        RateLimitProvider.Add(map, Config.DcrRegistrationEndpoint, "register");

                        RateLimitProvider.endpoints = map;
                    }
                }

                return RateLimitProvider.endpoints;
            }
        }

        /// <summary>口の表に 1 つ足す</summary>
        /// <param name="map">口の表</param>
        /// <param name="path">パス（設定値）</param>
        /// <param name="name">口の名前</param>
        /// <remarks>**設定が空の配備では、その口を足さない。**</remarks>
        private static void Add(Dictionary<string, string> map, string path, string name)
        {
            string normalized = RateLimitProvider.Normalize(path);

            if (!string.IsNullOrEmpty(normalized) && !map.ContainsKey(normalized))
            {
                map.Add(normalized, name);
            }
        }

        /// <summary>パスを突き合わせる形に揃える</summary>
        /// <param name="path">パス</param>
        /// <returns>揃えたパス（空なら空）</returns>
        /// <remarks>**先頭の `/` を 1 つにし、末尾の `/` を落とす。**</remarks>
        private static string Normalize(string path)
        {
            if (string.IsNullOrEmpty(path))
            {
                return "";
            }

            string normalized = path.Trim();

            if (!normalized.StartsWith("/"))
            {
                normalized = "/" + normalized;
            }

            while (1 < normalized.Length && normalized.EndsWith("/"))
            {
                normalized = normalized.Substring(0, normalized.Length - 1);
            }

            return normalized;
        }

        #endregion

        #region 公開

        /// <summary>この配備で制限するか</summary>
        /// <remarks>**どちらの上限も 0（未設定）なら、呼ぶ側は何もしなくてよい。**</remarks>
        public static bool Enabled
        {
            get
            {
                return 0 < Config.RateLimitPerClientPermits
                    || 0 < Config.RateLimitPerIpPermits;
            }
        }

        /// <summary>制限する口か</summary>
        /// <param name="path">要求のパス（アプリからの相対）</param>
        /// <returns>制限する口なら true</returns>
        /// <remarks>
        /// **呼ぶ側が、本体（`client_id`）を読む前に聞く**ためにある
        /// （**制限しない口で、要求の本体を読みたくない**）。
        /// </remarks>
        public static bool IsLimitedPath(string path)
        {
            return RateLimitProvider.EndpointOf(path) != null;
        }

        /// <summary>この要求を通すか</summary>
        /// <param name="path">要求のパス（アプリからの相対）</param>
        /// <param name="clientId">client_id（分からなければ空）</param>
        /// <param name="ipAddress">送信元アドレス（分からなければ空）</param>
        /// <returns>通すなら null、断るなら待つ秒数（`Retry-After`）</returns>
        /// <remarks>
        /// **断るときも数える** — **断られた分を数えないと、**
        /// **窓の中で叩き続けるかぎり、いつまでも上限の際で通ってしまう。**
        ///
        /// **両方の鍵で数え、どちらかが超えていれば断る**
        /// （**長い方の待ち時間を返す**）。
        /// </remarks>
        public static int? Check(string path, string clientId, string ipAddress)
        {
            string endpoint = RateLimitProvider.EndpointOf(path);

            if (endpoint == null)
            {
                return null;
            }

            int window = Config.RateLimitWindowSeconds;

            if (window <= 0)
            {
                return null;
            }

            int? retryAfter = null;

            //  **クライアントごと**（`client_id` が分かるときだけ）。
            int perClient = Config.RateLimitPerClientPermits;

            if (0 < perClient && !string.IsNullOrEmpty(clientId))
            {
                retryAfter = RateLimitProvider.Max(retryAfter, RateLimitProvider.Count(
                    endpoint, "client:" + RateLimitProvider.Shorten(clientId), perClient, window));
            }

            //  **送信元ごと**（**`client_id` が分かる要求も、ここでも数える**。
            //    **`client_id` を毎回変える攻撃を、これで止める**）。
            int perIp = Config.RateLimitPerIpPermits;

            if (0 < perIp && !string.IsNullOrEmpty(ipAddress))
            {
                retryAfter = RateLimitProvider.Max(retryAfter, RateLimitProvider.Count(
                    endpoint, "ip:" + RateLimitProvider.Shorten(ipAddress), perIp, window));
            }

            return retryAfter;
        }

        /// <summary>`Authorization: Basic` から client_id を取り出す</summary>
        /// <param name="authorizationHeader">Authorization ヘッダ</param>
        /// <returns>client_id（取り出せなければ空）</returns>
        /// <remarks>
        /// **Basic 認証が優先**（RFC 6749 §2.3.1）。
        /// **本体を読まずに済む**ので、**先にこちらを見る。**
        /// **値は form-urlencoded されている**（同§）ので、戻す。
        /// </remarks>
        public static string ClientIdFromAuthorizationHeader(string authorizationHeader)
        {
            if (string.IsNullOrEmpty(authorizationHeader))
            {
                return "";
            }

            try
            {
                string header = authorizationHeader.Trim();

                if (!header.StartsWith("Basic ", StringComparison.OrdinalIgnoreCase))
                {
                    return "";
                }

                string decoded = Encoding.UTF8.GetString(
                    Convert.FromBase64String(header.Substring("Basic ".Length).Trim()));

                int separator = decoded.IndexOf(':');
                string clientId = (separator < 0) ? decoded : decoded.Substring(0, separator);

                return Uri.UnescapeDataString(clientId);
            }
            catch
            {
                //  **壊れた値は「分からない」として扱う**（ここで落とさない）。
                //    **認証そのものは、この後の口で行われる。**
                return "";
            }
        }

        #endregion

        #region 内部

        /// <summary>パスから口の名前を引く（制限しない口なら null）</summary>
        /// <param name="path">要求のパス</param>
        /// <returns>口の名前</returns>
        private static string EndpointOf(string path)
        {
            string normalized = RateLimitProvider.Normalize(path);

            if (string.IsNullOrEmpty(normalized))
            {
                return null;
            }

            string endpoint = null;
            return RateLimitProvider.Endpoints.TryGetValue(normalized, out endpoint)
                ? endpoint : null;
        }

        /// <summary>1 つの鍵で数えて、超えていれば待つ秒数を返す</summary>
        /// <param name="endpoint">口の名前</param>
        /// <param name="partition">鍵（`client:` / `ip:`）</param>
        /// <param name="permits">窓あたりの上限</param>
        /// <param name="window">窓の長さ（秒）</param>
        /// <returns>通すなら null、断るなら待つ秒数</returns>
        private static int? Count(string endpoint, string partition, int permits, int window)
        {
            long now = RateLimitProvider.NowUnixSeconds();
            long windowStart = now - (now % window);

            string key = endpoint + "|" + partition;

            if (RateLimitProvider.MaxKeys < RateLimitProvider.Counters.Count)
            {
                RateLimitProvider.Prune(windowStart);
            }

            Counter counter = RateLimitProvider.Counters.GetOrAdd(key, _ => new Counter());

            int count = 0;

            lock (counter)
            {
                if (counter.WindowStart != windowStart)
                {
                    //  **窓が変わった。** 回数は 0 から数え直す。
                    counter.WindowStart = windowStart;
                    counter.Count = 0;
                }

                counter.Count++;
                count = counter.Count;
            }

            if (count <= permits)
            {
                return null;
            }

            if (count == permits + 1)
            {
                //  **超えた最初の 1 回だけ記録する**
                //    （**断るたびに書くと、洪水がそのままログの洪水になる**）。
                Logging.MyOperationTrace(string.Format(
                    "The rate limit of {0} was exceeded. ({1} requests in {2} seconds)",
                    key, count, window));
            }

            int retryAfter = (int)((windowStart + window) - now);

            return (retryAfter <= 0) ? 1 : retryAfter;
        }

        /// <summary>古い窓の分を捨てる</summary>
        /// <param name="windowStart">いまの窓の開始</param>
        /// <remarks>
        /// **いまの窓より前の分だけを捨てる**（**捨てても、次の要求で作り直される**）。
        /// **捨てる途中に増えるのは構わない**（**上限は目安である**）。
        /// </remarks>
        private static void Prune(long windowStart)
        {
            foreach (KeyValuePair<string, Counter> entry in RateLimitProvider.Counters)
            {
                Counter counter = entry.Value;
                bool stale = false;

                lock (counter)
                {
                    stale = counter.WindowStart < windowStart;
                }

                if (stale)
                {
                    Counter removed = null;
                    RateLimitProvider.Counters.TryRemove(entry.Key, out removed);
                }
            }
        }

        /// <summary>鍵に使う文字列を、長さで切る</summary>
        /// <param name="value">値</param>
        /// <returns>切った値</returns>
        /// <remarks>**要求から作る鍵なので、長さは相手任せ**である。</remarks>
        private static string Shorten(string value)
        {
            return (value.Length <= 128) ? value : value.Substring(0, 128);
        }

        /// <summary>長い方の待ち時間</summary>
        /// <param name="left">待ち時間</param>
        /// <param name="right">待ち時間</param>
        /// <returns>長い方（どちらも null なら null）</returns>
        private static int? Max(int? left, int? right)
        {
            if (!left.HasValue) { return right; }
            if (!right.HasValue) { return left; }

            return (left.Value < right.Value) ? right : left;
        }

        /// <summary>いまの UNIX 時刻（秒）</summary>
        /// <returns>UNIX 時刻</returns>
        private static long NowUnixSeconds()
        {
            return DateTimeOffset.UtcNow.ToUnixTimeSeconds();
        }

        #endregion
    }
}
