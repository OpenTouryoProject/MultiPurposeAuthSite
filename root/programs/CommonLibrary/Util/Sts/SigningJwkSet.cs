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
//* クラス名        ：SigningJwkSet
//* クラス日本語名  ：自分の署名鍵の表（JwkSet.json）を読む（#407）
//*
//* 作成者          ：玄人 幸道
//* 更新履歴        ：
//*
//*  日時        更新者            内容
//*  ----------  ----------------  -------------------------------------------------
//*  2026/11/18  玄人 幸道         新規（#407）
//**********************************************************************************

using MultiPurposeAuthSite.Log;

using System;
using System.IO;
using System.Threading;

using Newtonsoft.Json;
using Newtonsoft.Json.Linq;

using Touryo.Infrastructure.Framework.Authentication;
using Touryo.Infrastructure.Public.Security.Jwt;

namespace MultiPurposeAuthSite.Util.Sts
{
    /// <summary>
    /// **自分の署名鍵の表（`JwkSet.json`）を読む**（アクセス トークンの検証・`/jwkcerts`。#407）
    /// </summary>
    /// <remarks>
    /// **以前は、検証が要求のたびに `JwkSet.LoadJwkSet` でファイルを読み、解析していた。**
    /// **鍵の入れ替えでファイルを置き換える瞬間に重なった要求は、`IOException` で HTTP 500 になった**（`/jwkcerts` も同じ）。
    ///
    /// | | |
    /// |---|---|
    /// | **読み方** | Open棟梁 の `JwkSetDocument`（**ファイルが変わっていなければ控えた中身**。#303） |
    /// | **読めない・壊れているとき** | **短く待って、`MaxAttempts` 回までやり直す。** それでも読めなければ、**前に読めた（解析できた）中身で続ける**（ログに残す）。**ただし最後に読めてから `FallbackLifetime`（1 分）まで。** 一度も読めていなければ、例外のまま（設定の誤りを黙って通さない） |
    /// | **待ち** | **やり直す前に、要求のスレッドで `RetryWait`（50 ミリ秒）待つ。** 読めない間は、鍵を引く要求ごとに最大約 100 ミリ秒（2 回）かかる（読めない状態は `FallbackLifetime` で打ち切る） |
    /// | **ファイル・フォルダが無いとき** | **やり直さず、例外のまま**（意図して撤去したなら、古い表を出し続けない） |
    /// | **解析** | **中身が変わったときだけ**（ETag で見る）。**`/jwkcerts` も、解析できた中身だけを返す** |
    /// </remarks>
    public static class SigningJwkSet
    {
        #region 既定の読み手（設定の JwkSetFilePath）

        /// <summary>設定の `JwkSetFilePath` を読む読み手</summary>
        private static readonly Reader _default = new Reader(
            () =>
            {
                string content = JwkSetDocument.Get(OAuth2AndOIDCParams.JwkSetFilePath, out string etag);
                return Tuple.Create(content, etag);
            },
            SigningJwkSet.RetryWait);

        /// <summary>`/jwkcerts` の本文と ETag</summary>
        /// <param name="etag">ETag</param>
        /// <returns>本文</returns>
        public static string GetDocument(out string etag)
        {
            return SigningJwkSet._default.Get(out etag);
        }

        /// <summary>`kid` の JWK（無ければ null）</summary>
        /// <param name="kid">kid</param>
        /// <returns>JWK</returns>
        public static JObject GetJwkObject(string kid)
        {
            return SigningJwkSet._default.GetJwkObject(kid);
        }

        #endregion

        #region 読み手

        /// <summary>やり直す回数（最初の 1 回を含む）</summary>
        public const int MaxAttempts = 3;

        /// <summary>やり直す前に待つ時間</summary>
        public static readonly TimeSpan RetryWait = TimeSpan.FromMilliseconds(50);

        /// <summary>
        /// 前に読めた中身で続けてよい時間（最後に読めてから。過ぎたら例外にする）
        /// </summary>
        /// <remarks>
        /// **置き換えの瞬間（ミリ秒の単位）は救い、読めない状態が続く誤り（権限・壊れたまま）は、1 分で表に出す**
        /// （#407 の別モデルのレビューの指摘。上限が無いと、再起動まで前の表で検証と `/jwkcerts` を続けた）。
        /// </remarks>
        public static readonly TimeSpan FallbackLifetime = TimeSpan.FromMinutes(1);

        /// <summary>読み手（読む関数と、前に読めた中身を持つ。単体テストで読む関数を差し替える）</summary>
        public class Reader
        {
            /// <summary>読む関数（中身と ETag）</summary>
            private readonly Func<Tuple<string, string>> _read;

            /// <summary>やり直す前に待つ時間</summary>
            private readonly TimeSpan _wait;

            /// <summary>排他</summary>
            private readonly object _lock = new object();

            /// <summary>前に読めて、解析もできた中身・ETag・表</summary>
            private Tuple<string, string, JwkSet> _last = null;

            /// <summary>最後に読めた時刻（UTC）</summary>
            private DateTime _lastReadAt = DateTime.MinValue;

            /// <summary>今の時刻（UTC。単体テストで差し替える）</summary>
            private readonly Func<DateTime> _utcNow;

            /// <summary>constructor</summary>
            /// <param name="read">読む関数（中身と ETag）</param>
            /// <param name="wait">やり直す前に待つ時間</param>
            public Reader(Func<Tuple<string, string>> read, TimeSpan wait)
                : this(read, wait, () => DateTime.UtcNow)
            {
            }

            /// <summary>constructor（今の時刻を差し替える。単体テスト用）</summary>
            /// <param name="read">読む関数（中身と ETag）</param>
            /// <param name="wait">やり直す前に待つ時間</param>
            /// <param name="utcNow">今の時刻（UTC）</param>
            public Reader(Func<Tuple<string, string>> read, TimeSpan wait, Func<DateTime> utcNow)
            {
                this._read = read;
                this._wait = wait;
                this._utcNow = utcNow;
            }

            /// <summary>中身と ETag を返す</summary>
            /// <param name="etag">ETag</param>
            /// <returns>中身</returns>
            public string Get(out string etag)
            {
                Tuple<string, string, JwkSet> read = this.Read();
                etag = read.Item2;
                return read.Item1;
            }

            /// <summary>`kid` の JWK（無ければ null）</summary>
            /// <param name="kid">kid</param>
            /// <returns>JWK</returns>
            public JObject GetJwkObject(string kid)
            {
                return JwkSet.GetJwkObject(this.Read().Item3, kid);
            }

            /// <summary>読んで解析する（読めない・壊れていれば、やり直し、前に読めた中身で続ける）</summary>
            /// <returns>中身・ETag・表</returns>
            /// <remarks>
            /// - **読めない**（`IOException`・`UnauthorizedAccessException`）と、**壊れている**（直接上書きの書きかけ。`JsonException`）は、同じに扱う
            /// - **ファイル・フォルダが無い**（`FileNotFoundException`・`DirectoryNotFoundException`）は、**やり直さず、例外のまま**（意図して撤去したなら、古い表を出し続けない）
            /// - **前の中身として覚えるのは、解析できたものだけ**（壊れた中身で上書きしない）
            /// - **解析は、ETag が変わったときだけ**
            /// </remarks>
            private Tuple<string, string, JwkSet> Read()
            {
                for (int attempt = 1; ; attempt++)
                {
                    try
                    {
                        Tuple<string, string> read = this._read();
                        Tuple<string, string, JwkSet> last;

                        lock (this._lock)
                        {
                            last = this._last;
                        }

                        if (last != null && last.Item2 == read.Item2)
                        {
                            lock (this._lock)
                            {
                                this._lastReadAt = this._utcNow();
                            }

                            return last;
                        }

                        JwkSet jwkSet = JsonConvert.DeserializeObject<JwkSet>(read.Item1);

                        if (jwkSet == null || jwkSet.keys == null)
                        {
                            throw new JsonSerializationException("The JWK Set has no keys.");
                        }

                        Tuple<string, string, JwkSet> parsed = Tuple.Create(read.Item1, read.Item2, jwkSet);

                        lock (this._lock)
                        {
                            this._last = parsed;
                            this._lastReadAt = this._utcNow();
                        }

                        return parsed;
                    }
                    catch (Exception ex) when (SigningJwkSet.IsTransient(ex))
                    {
                        if (attempt < SigningJwkSet.MaxAttempts)
                        {
                            Thread.Sleep(this._wait);
                            continue;
                        }

                        Tuple<string, string, JwkSet> last;
                        DateTime lastReadAt;

                        lock (this._lock)
                        {
                            last = this._last;
                            lastReadAt = this._lastReadAt;
                        }

                        //  **一度も読めていない・最後に読めてから `FallbackLifetime` を過ぎたなら、例外のまま**
                        //    （設定の誤り・読めない状態が続く障害を、黙って通し続けない）。
                        if (last == null || SigningJwkSet.FallbackLifetime < this._utcNow() - lastReadAt)
                        {
                            throw;
                        }

                        //  **前に読めた中身で続ける。** **理由は型だけ残す**（パスは配備の情報）。
                        //    **ログを書けなくても、続ける**（ここで例外にすると、助けるための分岐が 500 になる）。
                        try
                        {
                            Logging.MyOperationTrace(string.Format(
                                "The signing JWK Set could not be read; the last one was used. ({0})", ex.GetType().Name));
                        }
                        catch (Exception)
                        {
                            // ログの失敗は握る
                        }

                        return last;
                    }
                }
            }
        }

        /// <summary>やり直す・前の中身で続ける例外か（ファイル・フォルダが無いのは含めない）</summary>
        /// <param name="ex">例外</param>
        /// <returns>やり直すなら true</returns>
        private static bool IsTransient(Exception ex)
        {
            if (ex is FileNotFoundException || ex is DirectoryNotFoundException)
            {
                return false;
            }

            return ex is IOException || ex is UnauthorizedAccessException || ex is JsonException;
        }

        #endregion
    }
}
