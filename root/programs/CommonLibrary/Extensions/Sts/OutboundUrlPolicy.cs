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
//* クラス名        ：OutboundUrlPolicy
//* クラス日本語名  ：クライアントが登録した URL へ、OP が取りに行ってよいかの判定（#376）
//*
//* 作成者          ：玄人 幸道
//* 更新履歴        ：
//*
//*  日時        更新者            内容
//*  ----------  ----------------  -------------------------------------------------
//*  2026/11/18  玄人 幸道         新規（#376）
//**********************************************************************************

using MultiPurposeAuthSite.Co;
using MultiPurposeAuthSite.Network;

using System;
using System.Collections.Concurrent;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Net.Sockets;
using System.Threading.Tasks;
#if NETCORE
using System.Threading;
#endif

namespace MultiPurposeAuthSite.Extensions.Sts
{
    /// <summary>
    /// **クライアントが登録した URL（`jwks_uri`・`sector_identifier_uri`）へ、OP が取りに行ってよいか**（#376）
    /// </summary>
    /// <remarks>
    /// **動的登録では、誰でも（専用 scope のトークンを持つ相手が）OP に取りに行かせる URL を書ける。**
    /// **以前はスキーム（`https` か、ループバックの `http`）しか見ておらず、OP の内側のアドレスへ要求を出させられた。**
    ///
    /// | 判定 | 既定 | 設定 |
    /// |---|---|---|
    /// | **スキーム** | **`https` だけ** | `OutboundUrlAllowLoopbackHttp=true` で、**ループバックの `http`** も許す（開発・試験。OIDC Registration 1.0 §2・§5 の `https` の MUST からの逸脱） |
    /// | **行き先のアドレス** | **名前解決した結果が 1 つでも内部のアドレスなら断る**（ループバック・プライベート・リンクローカル・CGNAT・未指定・マルチキャストなど） | `OutboundUrlAllowLoopbackHttp=true` でループバックを、`OutboundUrlAllowedHosts` に挙げたホスト名で、そのホストの内部のアドレスを許す |
    ///
    /// - **名前解決できなければ断る**
    /// - **取りに行くときは `HttpClient`（このクラスの）を使う。** リダイレクトを追わず、**net10.0 版は接続の時点のアドレスでも判定する**
    ///   （判定の後に名前解決をやり直して、行き先を変えられないように）。**net48 版の `HttpClientHandler` には接続の時点の口が無い**ので、名前解決した結果の判定に留まる
    /// - **`jwks_uri` の取得は Open棟梁 の `RemoteJwkSetStore`（共有の HttpClient）が行う**ので、取りに行く前の判定だけを掛ける
    ///   （接続の時点の判定・リダイレクトは、Open棟梁 で HttpClient を渡せるようにしてから）
    /// </remarks>
    public static class OutboundUrlPolicy
    {
        #region 判定

        /// <summary>判定の結果を控える時間（`RemoteJwkSetStore` の取り直しの下限と同じ 1 分）</summary>
        public static readonly TimeSpan DecisionLifetime = TimeSpan.FromMinutes(1);

        /// <summary>控えの数の上限（超えたら、寿命の過ぎたものを消してから控える）</summary>
        private const int MaxDecisions = 1000;

        /// <summary>URL → 判定の結果と、判定した時刻（UTC）</summary>
        private static readonly ConcurrentDictionary<string, Tuple<bool, DateTime>> _decisions
            = new ConcurrentDictionary<string, Tuple<bool, DateTime>>(StringComparer.Ordinal);

        /// <summary>取りに行ってよい URL か（設定と名前解決で判定する）</summary>
        /// <param name="url">URL</param>
        /// <returns>取りに行ってよければ true</returns>
        /// <remarks>
        /// **判定の結果を、URL ごとに 1 分控える**（断った結果も。別モデルのレビューの指摘）。
        /// **クライアント認証では、控えに鍵が無いたびに呼ばれる**ので、知らない `kid` の要求を並べられても、名前解決を毎回は引かない。
        /// </remarks>
        public static bool IsAllowed(string url)
        {
            if (string.IsNullOrEmpty(url))
            {
                return false;
            }

            DateTime now = DateTime.UtcNow;

            if (OutboundUrlPolicy._decisions.TryGetValue(url, out Tuple<bool, DateTime> kept)
                && now - kept.Item2 < OutboundUrlPolicy.DecisionLifetime)
            {
                return kept.Item1;
            }

            bool allowed = OutboundUrlPolicy.IsAllowed(
                url, Config.OutboundUrlAllowLoopbackHttp, Config.OutboundUrlAllowedHosts, OutboundUrlPolicy.Resolve);

            if (OutboundUrlPolicy.MaxDecisions <= OutboundUrlPolicy._decisions.Count)
            {
                foreach (var pair in OutboundUrlPolicy._decisions)
                {
                    if (OutboundUrlPolicy.DecisionLifetime <= now - pair.Value.Item2)
                    {
                        OutboundUrlPolicy._decisions.TryRemove(pair.Key, out Tuple<bool, DateTime> removed);
                    }
                }
            }

            if (OutboundUrlPolicy._decisions.Count < OutboundUrlPolicy.MaxDecisions)
            {
                OutboundUrlPolicy._decisions[url] = Tuple.Create(allowed, now);
            }

            return allowed;
        }

        /// <summary>取りに行ってよい URL か（設定と名前解決を渡す。単体テスト用）</summary>
        /// <param name="url">URL</param>
        /// <param name="allowLoopbackHttp">ループバック（`http` を含む）を許すか</param>
        /// <param name="allowedHosts">内部のアドレスに解決されても許すホスト名</param>
        /// <param name="resolve">名前解決（失敗なら null か空）</param>
        /// <returns>取りに行ってよければ true</returns>
        public static bool IsAllowed(string url, bool allowLoopbackHttp, string[] allowedHosts, Func<string, IPAddress[]> resolve)
        {
            if (!Uri.TryCreate(url, UriKind.Absolute, out Uri uri))
            {
                return false;
            }

            //  **スキーム**：`https` だけ。**ループバックの `http` は、設定で開けたときだけ。**
            if (uri.Scheme == Uri.UriSchemeHttp)
            {
                if (!(allowLoopbackHttp && uri.IsLoopback))
                {
                    return false;
                }
            }
            else if (uri.Scheme != Uri.UriSchemeHttps)
            {
                return false;
            }

            //  **許可の一覧のホストは、アドレスを問わない**（配備が内部のアドレスを正しい行き先と決めたもの）。
            string host = uri.IdnHost;

            if (allowedHosts != null && allowedHosts.Contains(host, StringComparer.OrdinalIgnoreCase))
            {
                return true;
            }

            IPAddress[] addresses = null;

            try
            {
                addresses = resolve(host);
            }
            catch (Exception)
            {
                addresses = null;
            }

            //  **名前解決できなければ断る。** **1 つでも内部のアドレスなら断る**（どれに繋がるかは選べない）。
            if (addresses == null || addresses.Length == 0)
            {
                return false;
            }

            return addresses.All(a => OutboundUrlPolicy.IsAllowedAddress(a, allowLoopbackHttp));
        }

        /// <summary>繋いでよいアドレスか</summary>
        /// <param name="address">アドレス</param>
        /// <param name="allowLoopback">ループバックを許すか</param>
        /// <returns>繋いでよければ true</returns>
        public static bool IsAllowedAddress(IPAddress address, bool allowLoopback)
        {
            if (address == null)
            {
                return false;
            }

            //  **IPv4 を写した IPv6（::ffff:a.b.c.d）は、IPv4 として見る。**
            if (address.IsIPv4MappedToIPv6)
            {
                address = address.MapToIPv4();
            }

            if (IPAddress.IsLoopback(address))
            {
                return allowLoopback;
            }

            return !OutboundUrlPolicy.IsInternalAddress(address);
        }

        /// <summary>内部のアドレス（ループバック以外）か</summary>
        /// <param name="address">アドレス（IPv4 を写した IPv6 は、写す前に IPv4 にしておく）</param>
        /// <returns>内部のアドレスなら true</returns>
        /// <remarks>
        /// **主な範囲を並べた**（特殊用途の範囲をすべて網羅してはいない）。
        ///
        /// | IPv4 | |
        /// |---|---|
        /// | `0.0.0.0/8` | 「この網」（RFC 1122） |
        /// | `10.0.0.0/8`・`172.16.0.0/12`・`192.168.0.0/16` | プライベート（RFC 1918 §3） |
        /// | `100.64.0.0/10` | CGNAT（RFC 6598） |
        /// | `169.254.0.0/16` | リンクローカル（RFC 3927。クラウドのメタデータの口もここ） |
        /// | `192.0.0.0/24` | IETF の割り当て（RFC 6890 §2.2.2） |
        /// | `198.18.0.0/15` | ベンチマーク（RFC 2544） |
        /// | `192.0.2.0/24`・`198.51.100.0/24`・`203.0.113.0/24` | 文書化用（RFC 5737） |
        /// | `224.0.0.0/4` 以上 | マルチキャスト・予約・ブロードキャスト |
        ///
        /// | IPv6 | |
        /// |---|---|
        /// | `::`（未指定）・`fc00::/7`（ユニーク ローカル。RFC 4193 §3.1）・`fe80::/10`（リンクローカル）・`fec0::/10`（サイトローカル）・`ff00::/8`（マルチキャスト） | |
        /// | `::/96`（IPv4 互換。RFC 4291 で廃止）・`2001::/32`（Teredo。RFC 4380）・`2001:db8::/32`（文書化用。RFC 3849）・`64:ff9b:1::/48`（NAT64 の局所用。RFC 8215）・`100::/64`（破棄用。RFC 6666）など | |
        /// | `64:ff9b::/96`（NAT64。RFC 6052）・`2002::/16`（6to4。RFC 3056） | **中に持つ IPv4 が内部のアドレスなら**（内部の IPv4 に届きうる。別モデルのレビューの指摘） |
        /// </remarks>
        public static bool IsInternalAddress(IPAddress address)
        {
            byte[] b = address.GetAddressBytes();

            if (address.AddressFamily == AddressFamily.InterNetwork)
            {
                return b[0] == 0
                    || b[0] == 10
                    || b[0] == 127
                    || (b[0] == 172 && 16 <= b[1] && b[1] <= 31)
                    || (b[0] == 192 && b[1] == 168)
                    || (b[0] == 100 && 64 <= b[1] && b[1] <= 127)
                    || (b[0] == 169 && b[1] == 254)
                    || (b[0] == 192 && b[1] == 0 && b[2] == 0)
                    || (b[0] == 198 && (b[1] == 18 || b[1] == 19))
                    || (b[0] == 192 && b[1] == 0 && b[2] == 2)
                    || (b[0] == 198 && b[1] == 51 && b[2] == 100)
                    || (b[0] == 203 && b[1] == 0 && b[2] == 113)
                    || 224 <= b[0];
            }

            if (address.AddressFamily == AddressFamily.InterNetworkV6)
            {
                //  **IPv4 を中に持つ形**：NAT64（`64:ff9b::/96`）は末尾 4 バイト、6to4（`2002::/16`）は 3〜6 バイト目が IPv4。
                if (b[0] == 0x00 && b[1] == 0x64 && b[2] == 0xff && b[3] == 0x9b && b.Skip(4).Take(8).All(x => x == 0))
                {
                    return OutboundUrlPolicy.IsInternalOrLoopbackV4(b.Skip(12).Take(4).ToArray());
                }

                if (b[0] == 0x20 && b[1] == 0x02)
                {
                    return OutboundUrlPolicy.IsInternalOrLoopbackV4(b.Skip(2).Take(4).ToArray());
                }

                return address.Equals(IPAddress.IPv6None)
                    || address.Equals(IPAddress.IPv6Loopback)
                    || b.Take(12).All(x => x == 0)                                         // ::/96（IPv4 互換）
                    || (b[0] == 0x20 && b[1] == 0x01 && b[2] == 0x00 && b[3] == 0x00)     // 2001::/32（Teredo）
                    || (b[0] == 0x20 && b[1] == 0x01 && b[2] == 0x0d && b[3] == 0xb8)     // 2001:db8::/32（文書化用）
                    || (b[0] == 0x00 && b[1] == 0x64 && b[2] == 0xff && b[3] == 0x9b && b[4] == 0x00 && b[5] == 0x01) // 64:ff9b:1::/48
                    || (b[0] == 0x01 && b[1] == 0x00 && b.Skip(2).Take(6).All(x => x == 0))                          // 100::/64（破棄用）
                    || (b[0] & 0xfe) == 0xfc
                    || address.IsIPv6LinkLocal
                    || address.IsIPv6SiteLocal
                    || address.IsIPv6Multicast;
            }

            //  **知らない種類のアドレスは、内部とみなす**（倒すなら断る側）。
            return true;
        }

        /// <summary>IPv6 の中に持つ IPv4 が、内部のアドレス（ループバックを含む）か</summary>
        /// <param name="v4">IPv4 の 4 バイト</param>
        /// <returns>内部のアドレスなら true</returns>
        private static bool IsInternalOrLoopbackV4(byte[] v4)
        {
            return OutboundUrlPolicy.IsInternalAddress(new IPAddress(v4));
        }

        /// <summary>名前解決の時間の上限（過ぎたら、名前解決できないとして断る）</summary>
        public static readonly TimeSpan ResolveTimeout = TimeSpan.FromSeconds(5);

        /// <summary>名前解決（IP アドレスの文字列なら、そのまま返す）</summary>
        /// <param name="host">ホスト名</param>
        /// <returns>アドレス（時間の上限を過ぎたら null）</returns>
        /// <remarks>
        /// **時間の上限を付ける**（別モデルのレビューの指摘。登録の検査・クライアント認証の取り直しの前に、要求のスレッドで呼ばれる）。
        /// **スレッド プールで引いて待つ**（net48 の同期コンテキストに継続を戻さない。#309 のクライアント認証と同じ理由）。
        /// </remarks>
        private static IPAddress[] Resolve(string host)
        {
            if (IPAddress.TryParse(host.Trim('[', ']'), out IPAddress literal))
            {
                return new IPAddress[] { literal };
            }

            Task<IPAddress[]> lookup = Task.Run(() => Dns.GetHostAddresses(host));

            return lookup.Wait(OutboundUrlPolicy.ResolveTimeout) ? lookup.Result : null;
        }

        #endregion

        #region 取りに行く HttpClient

        /// <summary>クライアントが登録した URL を取りに行く HttpClient（リダイレクトを追わない）</summary>
        private static readonly Lazy<HttpClient> _httpClient = new Lazy<HttpClient>(OutboundUrlPolicy.CreateHttpClient);

        /// <summary>クライアントが登録した URL を取りに行く HttpClient（#376）</summary>
        /// <remarks>
        /// **共有の `OAuth2AndOIDCClient.HttpClient` は使わない**（ID 連携・自己テスト（localhost）などの正規の行き先も通るので、絞れない）。
        /// - **リダイレクトを追わない**（追えば、判定した後で別の行き先に移れる）
        /// - **net10.0 版は、接続の時点のアドレスでも判定する**（判定の後に名前解決をやり直して、行き先を変えられないように）
        /// - **プロキシ**（`UseIntranetProxy`）は共有の HttpClient と同じ。**プロキシを通すときは、接続の時点の判定はプロキシへの接続に掛からない**（名前解決はプロキシが行う）ので、取りに行く前の判定だけになる
        /// - **クライアント証明書は持たない**（クライアントが決めた行き先に、OP の証明書を出さない）
        /// </remarks>
        public static HttpClient HttpClient
        {
            get
            {
                return OutboundUrlPolicy._httpClient.Value;
            }
        }

        /// <summary>HttpClient を作る</summary>
        /// <returns>HttpClient</returns>
        private static HttpClient CreateHttpClient()
        {
            IWebProxy proxy = CreateProxy.GetIntranetProxy();

#if NETCORE
            SocketsHttpHandler handler = new SocketsHttpHandler()
            {
                AllowAutoRedirect = false,
                Proxy = proxy,
                UseProxy = proxy != null
            };

            if (proxy == null)
            {
                //  **接続の時点のアドレスで判定する。** 名前解決をここでやり直し、繋ぐ先のアドレスそのものを確かめる。
                handler.ConnectCallback = OutboundUrlPolicy.ConnectAsync;
            }

            return new HttpClient(handler);
#else
            HttpClientHandler handler = new HttpClientHandler()
            {
                AllowAutoRedirect = false,
                Proxy = proxy,
                UseProxy = proxy != null
            };

            return new HttpClient(handler);
#endif
        }

#if NETCORE
        /// <summary>接続の時点で、繋ぐ先のアドレスを判定してから繋ぐ（net10.0）</summary>
        /// <param name="context">SocketsHttpConnectionContext</param>
        /// <param name="cancellationToken">CancellationToken</param>
        /// <returns>Stream</returns>
        private static async ValueTask<System.IO.Stream> ConnectAsync(
            SocketsHttpConnectionContext context, CancellationToken cancellationToken)
        {
            string host = context.DnsEndPoint.Host;
            bool allowLoopback = Config.OutboundUrlAllowLoopbackHttp;
            string[] allowedHosts = Config.OutboundUrlAllowedHosts;

            IPAddress[] addresses = IPAddress.TryParse(host.Trim('[', ']'), out IPAddress literal)
                ? new IPAddress[] { literal }
                : await Dns.GetHostAddressesAsync(host, cancellationToken).ConfigureAwait(false);

            bool listed = allowedHosts != null && allowedHosts.Contains(host, StringComparer.OrdinalIgnoreCase);

            IPAddress[] usable = addresses.Where(a => listed || OutboundUrlPolicy.IsAllowedAddress(a, allowLoopback)).ToArray();

            if (usable.Length == 0 || usable.Length != addresses.Length)
            {
                //  **1 つでも内部のアドレスなら繋がない**（`IsAllowed` と同じ規則）。
                throw new HttpRequestException("The destination address is not allowed.");
            }

            Socket socket = new Socket(SocketType.Stream, ProtocolType.Tcp) { NoDelay = true };

            try
            {
                await socket.ConnectAsync(usable, context.DnsEndPoint.Port, cancellationToken).ConfigureAwait(false);
                return new NetworkStream(socket, true);
            }
            catch
            {
                socket.Dispose();
                throw;
            }
        }
#endif

        #endregion
    }
}
