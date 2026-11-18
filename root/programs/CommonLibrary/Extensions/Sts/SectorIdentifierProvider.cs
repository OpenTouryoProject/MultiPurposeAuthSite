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
//* クラス名        ：SectorIdentifierProvider
//* クラス日本語名  ：動的登録の sector_identifier_uri を取りに行き、中身（redirect_uri の一覧）を控える
//*
//* 作成日時        ：－
//* 作成者          ：－
//* 更新履歴        ：－
//*
//*  日時        更新者            内容
//*  ----------  ----------------  -------------------------------------------------
//*  2026/11/12  玄人 幸道         新規（#364）
//*  2026/11/18  玄人 幸道         sector_identifier_uri の判定に行き先のアドレスを足し、専用の HttpClient（リダイレクトを追わない）で取りに行くようにした（#376）
//**********************************************************************************

using MultiPurposeAuthSite.Log;
using MultiPurposeAuthSite.Util.Sts;

using System;
using System.Collections.Concurrent;
using System.IO;
using System.Linq;
using System.Net.Http;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

using Newtonsoft.Json.Linq;

using Touryo.Infrastructure.Framework.Authentication;
using Touryo.Infrastructure.Public.Str;

namespace MultiPurposeAuthSite.Extensions.Sts
{
    /// <summary>
    /// **動的登録の `sector_identifier_uri` を取りに行き、中身を控える**（#364）。
    /// </summary>
    /// <remarks>
    /// **OIDC Registration 1.0 §5**：OP は `sector_identifier_uri` を取りに行き、
    /// **中身（JSON の配列）に、登録する `redirect_uris` がすべて含まれていることを確かめる**（MUST）。
    /// **確かめずに受けると、別の RP のホストを名乗って、その RP と同じ pairwise の `sub` を得られる**
    /// （Sector を `sector_identifier_uri` のホストにする場合。OIDC Core 1.0 §8.1）。
    ///
    /// **取りに行くのは、登録の口の検査の手前である**（`ClientRegistrationProvider.WarmUpAsync`）。
    /// **登録の口は `async` なので待てる。** **判定は `Validate` が、ここに控えた結果を見て決める**（判定は 1 か所）。
    /// `jwks_uri`（`RemoteJwkSetStore`）と同じ流儀である。
    ///
    /// | | |
    /// |---|---|
    /// | **行き先** | **`https` だけで、内部のアドレスでないこと**（`OutboundUrlPolicy.IsAllowed`。#376。ループバックの `http` は設定 `OutboundUrlAllowLoopbackHttp` で開けたときだけ） |
    /// | **HttpClient** | **`OutboundUrlPolicy.HttpClient`**（専用。リダイレクトを追わず、net10.0 版は接続の時点のアドレスも判定する。#376。以前は共有の `OAuth2AndOIDCClient.HttpClient`） |
    /// | **上限** | **時間は `Timeout`、大きさは `MaxResponseBytes`**（超えたら「読めない」） |
    /// | **リダイレクト** | **追わない**（3xx は「読めない」。#376）。**別の URL から返った中身も「読めない」**（念のための守り。#364） |
    /// | **控えの寿命** | **`Freshness`**（同じ要求の中で読む前提。古い控えでは通さない）。**件数は `MaxEntries` まで** |
    /// | **仕様との差** | **既定ではない**（`https` だけ。#376）。**`OutboundUrlAllowLoopbackHttp=true` でループバックの `http` を許すのは、§2・§5 の "https" の MUST からの逸脱**（開発と試験の配備だけ） |
    /// </remarks>
    public static class SectorIdentifierProvider
    {
        #region 定数

        /// <summary>取りに行くときの時間の上限</summary>
        private static readonly TimeSpan Timeout = TimeSpan.FromSeconds(10);

        /// <summary>応答の大きさの上限（バイト）</summary>
        /// <remarks>**中身は `redirect_uri` の一覧**なので、これを超える応答は登録の材料として扱わない。</remarks>
        private const int MaxResponseBytes = 64 * 1024;

        /// <summary>控えを使ってよい時間</summary>
        /// <remarks>
        /// **取りに行くのは、その登録の要求の中**（検査の直前）なので、短くてよい。
        /// **古い控えで通さない**（相手が一覧から外した後に、以前の控えで登録できないように）。
        /// </remarks>
        private static readonly TimeSpan Freshness = TimeSpan.FromMinutes(1);

        /// <summary>控えの件数の上限</summary>
        /// <remarks>
        /// **寿命の間に控える URL の数を絞る**（1 件は最大 `MaxResponseBytes` の一覧）。
        /// **超えたら控えない**ので、その登録は「読めない」で断られる（断る側に倒す）。
        /// </remarks>
        private const int MaxEntries = 256;

        #endregion

        #region 控え

        /// <summary>控え（取得の結果）</summary>
        private class Entry
        {
            /// <summary>中身の一覧（読めなければ null）</summary>
            public string[] Uris;

            /// <summary>取った時刻（UTC）</summary>
            public DateTime FetchedAt;
        }

        /// <summary>URL → 控え</summary>
        /// <remarks>**取るたびに、寿命の過ぎた控えを消す**ので、増え方は「寿命の間に登録された URL の数」までである。</remarks>
        private static readonly ConcurrentDictionary<string, Entry> _fetched
            = new ConcurrentDictionary<string, Entry>(StringComparer.Ordinal);

        #endregion

        #region 判定・取得

        /// <summary>取りに行ってよい URL か</summary>
        /// <param name="url">sector_identifier_uri</param>
        /// <returns>`https` で、内部のアドレスでなければ true（`OutboundUrlPolicy`）</returns>
        /// <remarks>
        /// **以前はスキーム（`https` か、ループバックの `http`）しか見ていなかった**（#376）。
        /// **行き先のアドレスも見る**（内部のアドレスを断る。ループバックの `http` は設定で開けたときだけ）。
        /// </remarks>
        public static bool IsUsable(string url)
        {
            return OutboundUrlPolicy.IsAllowed(url);
        }

        /// <summary>**取りに行って控える**（判定はしない）</summary>
        /// <param name="url">sector_identifier_uri</param>
        /// <returns>Task</returns>
        /// <remarks>
        /// **取れなくても例外にしない。** **「読めない」を控え**、`Validate` が断る。
        /// **理由は型だけをログに残す**（URL は配備の情報なので出さない）。
        /// </remarks>
        public static async Task WarmUpAsync(string url)
        {
            if (string.IsNullOrEmpty(url) || !SectorIdentifierProvider.IsUsable(url))
            {
                return;
            }

            string[] uris = null;

            try
            {
                string json = await SectorIdentifierProvider.GetStringAsync(url).ConfigureAwait(false);

                //  **中身は文字列の JSON の配列**（§5 : "a JSON array of redirect_uri values"）。
                //    **配列でない・文字列でない要素が在る**なら、読めないとして扱う。
                JArray array = string.IsNullOrEmpty(json) ? null : JToken.Parse(json) as JArray;

                if (array != null && array.All(t => t.Type == JTokenType.String))
                {
                    uris = array.Select(t => (string)t).ToArray();
                }
            }
            catch (Exception ex)
            {
                //  **URL は出さない**（配備の情報）。**型だけ残す。**
                Logging.MyOperationTrace(string.Format(
                    "The sector_identifier_uri could not be read. ({0})", ex.GetType().Name));
            }

            SectorIdentifierProvider.Prune();

            if (SectorIdentifierProvider.MaxEntries <= _fetched.Count && !_fetched.ContainsKey(url))
            {
                Logging.MyOperationTrace("The sector_identifier_uri was not kept because too many were fetched recently.");
                return;
            }

            _fetched[url] = new Entry()
            {
                Uris = uris,
                FetchedAt = DateTime.UtcNow
            };
        }

        /// <summary>**控えた中身を返す**（無い・古い・読めなかったなら null）</summary>
        /// <param name="url">sector_identifier_uri</param>
        /// <returns>中身の一覧</returns>
        public static string[] GetFetched(string url)
        {
            Entry entry;

            if (string.IsNullOrEmpty(url)
                || !_fetched.TryGetValue(url, out entry)
                || SectorIdentifierProvider.Freshness < DateTime.UtcNow - entry.FetchedAt)
            {
                return null;
            }

            return entry.Uris;
        }

        #endregion

        #region private

        /// <summary>寿命の過ぎた控えを消す</summary>
        private static void Prune()
        {
            DateTime now = DateTime.UtcNow;

            foreach (var pair in _fetched)
            {
                if (SectorIdentifierProvider.Freshness < now - pair.Value.FetchedAt)
                {
                    Entry removed;
                    _fetched.TryRemove(pair.Key, out removed);
                }
            }
        }

        /// <summary>URL を GET して、本文を文字列で読む（大きさと時間に上限を付ける）</summary>
        /// <param name="url">URL</param>
        /// <returns>本文（2xx でなければ null）</returns>
        /// <remarks>**大きさの上限を超えたら `InvalidDataException`**（`WarmUpAsync` が「読めない」にする）。</remarks>
        private static async Task<string> GetStringAsync(string url)
        {
            //  **専用の HttpClient で取りに行く**（#376）。**リダイレクトを追わず、net10.0 版は接続の時点のアドレスでも判定する。**
            //    **以前は共有の `OAuth2AndOIDCClient.HttpClient` で、追うかどうかはその設定によっていた。**
            HttpClient client = OutboundUrlPolicy.HttpClient;

            using (CancellationTokenSource cts = new CancellationTokenSource(SectorIdentifierProvider.Timeout))
            using (HttpResponseMessage response = await client.GetAsync(
                new Uri(url), HttpCompletionOption.ResponseHeadersRead, cts.Token).ConfigureAwait(false))
            {
                //  **リダイレクトは追わない**ので、3xx は 2xx でないとして読めない（#376）。
                if (!response.IsSuccessStatusCode)
                {
                    return null;
                }

                //  **リダイレクトで別の URL に移っていたら、読めないとして扱う**（専用の HttpClient は追わないので、念のための守り）（§5 が見るのは、その URL に置かれた中身）。
                //    **共有の HttpClient が追うかどうかに頼らない** —
                //    **追っていれば、そのホストの開いたリダイレクトから、別の場所の中身で Sector を名乗れてしまう。**
                Uri finalUri = response.RequestMessage?.RequestUri;

                if (finalUri == null || !string.Equals(finalUri.AbsoluteUri, new Uri(url).AbsoluteUri, StringComparison.Ordinal))
                {
                    throw new InvalidDataException("The response came from another URL.");
                }

                using (Stream stream = await response.Content.ReadAsStreamAsync().ConfigureAwait(false))
                using (MemoryStream buffer = new MemoryStream())
                {
                    byte[] chunk = new byte[8192];
                    int read;

                    while ((read = await stream.ReadAsync(chunk, 0, chunk.Length, cts.Token).ConfigureAwait(false)) > 0)
                    {
                        if (SectorIdentifierProvider.MaxResponseBytes < buffer.Length + read)
                        {
                            throw new InvalidDataException("The response is too large.");
                        }

                        buffer.Write(chunk, 0, read);
                    }

                    return Encoding.UTF8.GetString(buffer.ToArray());
                }
            }
        }

        #endregion
    }
}
