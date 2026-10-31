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
//* クラス名        ：AuthFailureProvider
//* クラス日本語名  ：認証の失敗を数えて、一定回数で一定時間断る
//*
//* 作成日時        ：－
//* 作成者          ：－
//* 更新履歴        ：－
//*
//*  日時        更新者            内容
//*  ----------  ----------------  -------------------------------------------------
//*  2026/10/16  玄人 幸道         新規（#305 の段階 2）
//*  2026/10/31  玄人 幸道         Extensions/Sts から Util/Sts へ移した（配置の見直し。#294）
//**********************************************************************************

using MultiPurposeAuthSite.Co;
using MultiPurposeAuthSite.Data;

using System;
using System.Collections.Concurrent;
using System.Data;

#if NETFX
using System.Web;
#else
using Touryo.Infrastructure.Framework.StdMigration;
#endif

using Dapper;
using MultiPurposeAuthSite.Extensions.Sts;
using MultiPurposeAuthSite.Util.IdP;

/// <summary>MultiPurposeAuthSite.Extensions.Sts</summary>
namespace MultiPurposeAuthSite.Util.Sts
{
    /// <summary>
    /// 認証の失敗を数えて、**一定回数で一定時間断る**（#305 の段階 2）。
    /// </summary>
    /// <remarks>
    /// **総当たりを「回数」で止める**（`ANALYSIS-IdP.md` の D-13）。
    ///
    /// | 鍵 | 何の失敗か |
    /// |---|---|
    /// | **`client:<client_id>` ＋ `ip:<送信元>`** | **クライアント認証**（`client_secret` / mTLS） |
    /// | **`device_verify:<利用者>`** | **`user_code` の投入**（RFC 8628 §5.2） |
    ///
    /// | 設定 | |
    /// |---|---|
    /// | `AuthFailureMaxAttempts` | **この回数で断る**（**0 なら数えない** ＝ 従来どおり） |
    /// | `AuthFailureLockoutSeconds` | **断る長さ**（秒） |
    /// | `AuthFailureWindowSeconds` | **数えた分を覚えている長さ**（秒。段階 4） |
    ///
    /// **成功したら消す**（連続した失敗だけを数える。ASP.NET Identity のロックアウトと同じ考え）。
    /// **表に持つ**ので、**インスタンスを増やしても効く。**
    ///
    /// **断っている間は、正しい資格情報でも通さない。**
    /// **それが「効いている」ことの見え方**である（`RT-305.3` / `RT-305.4`）。
    ///
    /// **サインインのロックアウトとは別**である（あちらは ASP.NET Identity の
    /// `MaxFailedAccessAttemptsBeforeLockout`。**利用者のパスワード**が対象。
    /// **`/token` の `grant_type=password` も、段階 4 でそちらに合流させた**）。
    ///
    /// **段階 4 で変えたこと。**
    ///
    /// | | |
    /// |---|---|
    /// | **送信元を鍵に混ぜた** | **断るのは、その送信元だけ**になった（`ClientKey`）。**段階 2 は `client_id` だけで数えていたので、誰でもそのクライアントを止められた** |
    /// | **行に寿命を入れた** | **どの行も `LockoutEndAt` を持つ**ようにし、**期限の切れた行を掃除する**（`PruneExpired`）。**古い失敗は数に積まれない** |
    /// | **登録の無いクライアントでは数えない** | **要求の `client_id` で行を作らせない**（`CmnEndpoints.ClientAuthentication`） |
    ///
    /// **多数の送信元から分散して試す経路は、ここでは止まらない。**
    /// **口ごとのレート制限が、その頭を打つ**（段階 3 の `RateLimitProvider`）。
    /// </remarks>
    public class AuthFailureProvider
    {
        #region mem の入れ物

        /// <summary>mem のときの入れ物（鍵 → 回数と期限）</summary>
        private static ConcurrentDictionary<string, Tuple<int, long?>> Failures
            = new ConcurrentDictionary<string, Tuple<int, long?>>();

        #endregion

        #region 公開

        /// <summary>いま断っているか</summary>
        /// <param name="key">鍵</param>
        /// <returns>断っていれば true</returns>
        public static bool IsLockedOut(string key)
        {
            if (!AuthFailureProvider.Enabled || string.IsNullOrEmpty(key))
            {
                return false;
            }

            Tuple<int, long?> current = AuthFailureProvider.Get(key);

            //  **回数が 0 で、期限が未来なら、断っている**（#305 の段階 4）。
            //    **回数が正のときの期限は「数えた分の寿命」**であって、**断る期限ではない。**
            //    **上限に達したときだけ回数を 0 に戻す**ので、この 2 つは混ざらない。
            return current.Item1 == 0
                && current.Item2.HasValue
                && AuthFailureProvider.NowUnixSeconds() < current.Item2.Value;
        }

        /// <summary>失敗を 1 回数える（上限に達したら断り始める）</summary>
        /// <param name="key">鍵</param>
        /// <returns>断り始めたら true</returns>
        public static bool Record(string key)
        {
            if (!AuthFailureProvider.Enabled || string.IsNullOrEmpty(key))
            {
                return false;
            }

            long now = AuthFailureProvider.NowUnixSeconds();
            Tuple<int, long?> current = AuthFailureProvider.Get(key);

            //  **断っている間は、数え直さない**（#305 の段階 4）。
            //    **呼ぶ側は先に `IsLockedOut` を見ている**が、**見ない呼び出しが増えたときに、
            //    ここで期限を上書きして断りを解いてしまわないようにする。**
            if (current.Item1 == 0 && current.Item2.HasValue && now < current.Item2.Value)
            {
                return true;
            }

            //  **期限が切れていたら、数えた分は忘れる**（#305 の段階 4）。
            //    **断っていた期限でも、数えの寿命でも、同じ扱いでよい** —
            //    **どちらも「やり直し」である。**
            int count = (current.Item2.HasValue && current.Item2.Value <= now)
                ? 0 : current.Item1;

            count++;

            long lockoutEndAt = 0;

            if (Config.AuthFailureMaxAttempts <= count)
            {
                //  **上限に達した。** **断る期限を入れ、回数を 0 に戻す**
                //    （**期限が切れたら、また同じ回数だけ試せる**）。
                lockoutEndAt = now + Config.AuthFailureLockoutSeconds;
                count = 0;
            }
            else
            {
                //  **まだ断らない。** **期限は「数えた分の寿命」として入れる**（#305 の段階 4）。
                //    **これで、どの行も期限を持つ**ので、**期限の切れた行をまとめて消せる。**
                //    **間隔を空けた失敗は数に積まれない** — `AuthFailureWindowSeconds` がその猶予。
                lockoutEndAt = now + Config.AuthFailureWindowSeconds;
            }

            AuthFailureProvider.Save(key, count, lockoutEndAt);

            //  **回数が 0 に戻っていれば、いま断り始めた。**
            return count == 0;
        }

        /// <summary>成功したので消す</summary>
        /// <param name="key">鍵</param>
        public static void Clear(string key)
        {
            if (!AuthFailureProvider.Enabled || string.IsNullOrEmpty(key))
            {
                return;
            }

            switch (Config.UserStoreType)
            {
                case EnumUserStoreType.Memory:

                    Tuple<int, long?> temp = null;
                    AuthFailureProvider.Failures.TryRemove(key, out temp);

                    break;

                case EnumUserStoreType.SqlServer:
                case EnumUserStoreType.ODPManagedDriver:
                case EnumUserStoreType.PostgreSQL: // DMBMS

                    using (IDbConnection cnn = DataAccess.CreateConnection())
                    {
                        cnn.Open();

                        cnn.Execute(
                            "DELETE FROM " + AuthFailureProvider.TableName()
                            + AuthFailureProvider.WhereKey(),
                            new { FailureKey = key });
                    }

                    break;
            }
        }

        #endregion

        #region 内部

        /// <summary>この配備で数えるか（`AuthFailureMaxAttempts` が正のときだけ）</summary>
        private static bool Enabled
        {
            get
            {
                return 0 < Config.AuthFailureMaxAttempts;
            }
        }

        /// <summary>いまの UNIX 時刻（秒）</summary>
        private static long NowUnixSeconds()
        {
            return DateTimeOffset.UtcNow.ToUnixTimeSeconds();
        }

        /// <summary>いまの回数と期限（無ければ 0 と null）</summary>
        /// <param name="key">鍵</param>
        /// <returns>回数と期限</returns>
        private static Tuple<int, long?> Get(string key)
        {
            switch (Config.UserStoreType)
            {
                case EnumUserStoreType.Memory:

                    Tuple<int, long?> value = null;
                    return AuthFailureProvider.Failures.TryGetValue(key, out value)
                        ? value : new Tuple<int, long?>(0, null);

                case EnumUserStoreType.SqlServer:
                case EnumUserStoreType.ODPManagedDriver:
                case EnumUserStoreType.PostgreSQL: // DMBMS

                    using (IDbConnection cnn = DataAccess.CreateConnection())
                    {
                        cnn.Open();

                        dynamic dyn = cnn.QueryFirstOrDefault(
                            "SELECT " + AuthFailureProvider.SelectColumnList()
                            + " FROM " + AuthFailureProvider.TableName()
                            + AuthFailureProvider.WhereKey(),
                            new { FailureKey = key });

                        if (dyn == null)
                        {
                            return new Tuple<int, long?>(0, null);
                        }

                        //  **Oracle の NUMBER は decimal で返る**ので、Convert を通す（#207 の教訓）。
                        int count = Convert.ToInt32(dyn.FailedCount);
                        long? lockoutEndAt = (dyn.LockoutEndAt == null)
                            ? (long?)null : Convert.ToInt64(dyn.LockoutEndAt);

                        return new Tuple<int, long?>(count, lockoutEndAt);
                    }
            }

            return new Tuple<int, long?>(0, null);
        }

        /// <summary>回数と期限を書く（無ければ足す）</summary>
        /// <param name="key">鍵</param>
        /// <param name="count">回数</param>
        /// <param name="lockoutEndAt">期限</param>
        private static void Save(string key, int count, long? lockoutEndAt)
        {
            switch (Config.UserStoreType)
            {
                case EnumUserStoreType.Memory:

                    AuthFailureProvider.Failures[key] = new Tuple<int, long?>(count, lockoutEndAt);

                    break;

                case EnumUserStoreType.SqlServer:
                case EnumUserStoreType.ODPManagedDriver:
                case EnumUserStoreType.PostgreSQL: // DMBMS

                    using (IDbConnection cnn = DataAccess.CreateConnection())
                    {
                        cnn.Open();

                        //  **更新 → 0 件なら挿入**（方言ごとの UPSERT を書かない）。
                        int updated = cnn.Execute(
                            "UPDATE " + AuthFailureProvider.TableName()
                            + " SET " + AuthFailureProvider.SetList()
                            + AuthFailureProvider.WhereKey(),
                            new { FailureKey = key, FailedCount = count, LockoutEndAt = lockoutEndAt });

                        if (updated == 0)
                        {
                            cnn.Execute(
                                "INSERT INTO " + AuthFailureProvider.TableName()
                                + " (" + AuthFailureProvider.InsertColumnList() + ")"
                                + " VALUES (" + AuthFailureProvider.ParameterList() + ")",
                                new { FailureKey = key, FailedCount = count, LockoutEndAt = lockoutEndAt });
                        }
                    }

                    break;
            }

            //  **ついでに、期限の切れた行を掃除する**（#305 の段階 4）。
            AuthFailureProvider.PruneExpired();
        }

        #endregion

        #region 掃除

        /// <summary>掃除を、書き込み何回に 1 回やるか</summary>
        private const int PruneInterval = 100;

        /// <summary>書き込んだ回数（掃除の間隔を決めるため）</summary>
        private static int SaveCount = 0;

        /// <summary>期限の切れた行を掃除する</summary>
        /// <remarks>
        /// **行は放っておくと増える**（#305 の段階 4）。
        /// **鍵に送信元が入るので、行は「クライアント × 送信元」の数**になる。
        /// **成功すれば消える**（`Clear`）が、**一度も成功しない送信元の行は残る。**
        ///
        /// **どの行も期限を持つ**ようにしたので、**期限の過ぎた行は意味を持たない** —
        /// **まとめて消せる。**
        ///
        /// **書き込み `PruneInterval` 回に 1 回だけ**行う（**要求ごとに DELETE を撃たない**）。
        /// **掃除に失敗しても、認証は続ける**（次の機会に消せばよい）。
        /// </remarks>
        private static void PruneExpired()
        {
            //  **間隔を空ける。**
            if (0 != (System.Threading.Interlocked.Increment(
                ref AuthFailureProvider.SaveCount) % AuthFailureProvider.PruneInterval))
            {
                return;
            }

            long now = AuthFailureProvider.NowUnixSeconds();

            try
            {
                switch (Config.UserStoreType)
                {
                    case EnumUserStoreType.Memory:

                        foreach (string key in AuthFailureProvider.Failures.Keys)
                        {
                            Tuple<int, long?> value = null;

                            if (AuthFailureProvider.Failures.TryGetValue(key, out value)
                                && value.Item2.HasValue && value.Item2.Value <= now)
                            {
                                Tuple<int, long?> temp = null;
                                AuthFailureProvider.Failures.TryRemove(key, out temp);
                            }
                        }

                        break;

                    case EnumUserStoreType.SqlServer:
                    case EnumUserStoreType.ODPManagedDriver:
                    case EnumUserStoreType.PostgreSQL: // DMBMS

                        using (IDbConnection cnn = DataAccess.CreateConnection())
                        {
                            cnn.Open();

                            cnn.Execute(
                                "DELETE FROM " + AuthFailureProvider.TableName()
                                + AuthFailureProvider.WhereExpired(),
                                new { Now = now });
                        }

                        break;
                }
            }
            catch
            {
                //  **掃除は、落ちても構わない。**
            }
        }

        #endregion

        #region 方言

        /// <summary>テーブル名</summary>
        private static string TableName()
        {
            switch (Config.UserStoreType)
            {
                case EnumUserStoreType.SqlServer:
                    return "[AuthFailure]";
                case EnumUserStoreType.ODPManagedDriver:
                    return "\"AuthFailure\"";
                default:
                    return "\"authfailure\"";
            }
        }

        /// <summary>SELECT の列の並び</summary>
        /// <remarks>
        /// **PostgreSQL は引用符なしの識別子が小文字に畳まれる**ので、
        /// **小文字で引き、別名を付けて属性名で受け取る**（`IdFederationUpstreamProvider` と同じ）。
        /// **別名は SELECT だけ** — **INSERT の列に別名は書けない**
        /// （実測 : 共用して PostgreSQL の INSERT が落ち、`RT-305.3` / `RT-305.4` が落ちた）。
        /// </remarks>
        private static string SelectColumnList()
        {
            switch (Config.UserStoreType)
            {
                case EnumUserStoreType.SqlServer:
                    return "[FailureKey], [FailedCount], [LockoutEndAt]";
                case EnumUserStoreType.ODPManagedDriver:
                    return "\"FailureKey\", \"FailedCount\", \"LockoutEndAt\"";
                default:
                    return "\"failurekey\" AS \"FailureKey\", \"failedcount\" AS \"FailedCount\""
                        + ", \"lockoutendat\" AS \"LockoutEndAt\"";
            }
        }

        /// <summary>INSERT の列の並び（別名を付けない）</summary>
        private static string InsertColumnList()
        {
            switch (Config.UserStoreType)
            {
                case EnumUserStoreType.SqlServer:
                    return "[FailureKey], [FailedCount], [LockoutEndAt]";
                case EnumUserStoreType.ODPManagedDriver:
                    return "\"FailureKey\", \"FailedCount\", \"LockoutEndAt\"";
                default:
                    return "\"failurekey\", \"failedcount\", \"lockoutendat\"";
            }
        }

        /// <summary>パラメタの並び（Oracle だけ「:」）</summary>
        private static string ParameterList()
        {
            string p = (Config.UserStoreType == EnumUserStoreType.ODPManagedDriver) ? ":" : "@";

            return p + "FailureKey, " + p + "FailedCount, " + p + "LockoutEndAt";
        }

        /// <summary>UPDATE の SET 句</summary>
        private static string SetList()
        {
            switch (Config.UserStoreType)
            {
                case EnumUserStoreType.SqlServer:
                    return "[FailedCount] = @FailedCount, [LockoutEndAt] = @LockoutEndAt";
                case EnumUserStoreType.ODPManagedDriver:
                    return "\"FailedCount\" = :FailedCount, \"LockoutEndAt\" = :LockoutEndAt";
                default:
                    return "\"failedcount\" = @FailedCount, \"lockoutendat\" = @LockoutEndAt";
            }
        }

        /// <summary>期限の切れた行の条件句</summary>
        /// <remarks>**期限が無い行は消さない**（段階 2 が書いた行。次の失敗で期限が入る）。</remarks>
        private static string WhereExpired()
        {
            switch (Config.UserStoreType)
            {
                case EnumUserStoreType.SqlServer:
                    return " WHERE [LockoutEndAt] IS NOT NULL AND [LockoutEndAt] <= @Now";
                case EnumUserStoreType.ODPManagedDriver:
                    return " WHERE \"LockoutEndAt\" IS NOT NULL AND \"LockoutEndAt\" <= :Now";
                default:
                    return " WHERE \"lockoutendat\" IS NOT NULL AND \"lockoutendat\" <= @Now";
            }
        }

        /// <summary>鍵の条件句</summary>
        private static string WhereKey()
        {
            switch (Config.UserStoreType)
            {
                case EnumUserStoreType.SqlServer:
                    return " WHERE [FailureKey] = @FailureKey";
                case EnumUserStoreType.ODPManagedDriver:
                    return " WHERE \"FailureKey\" = :FailureKey";
                default:
                    return " WHERE \"failurekey\" = @FailureKey";
            }
        }

        #endregion

        #region 鍵の作り方

        /// <summary>クライアント認証の鍵（クライアント ＋ 送信元）</summary>
        /// <param name="clientId">client_id</param>
        /// <returns>鍵（client_id が空なら空）</returns>
        /// <remarks>
        /// **送信元を鍵に混ぜる**（#305 の段階 4）。
        ///
        /// **段階 2 は `client:<client_id>` だけだった。**
        /// **`client_id` は authorize の URL に載る、外から見える値**なので、
        /// **誰でも、間違った秘密を上限まで送るだけで、そのクライアントを止められた。**
        /// **同じ `client_id` の利用者が多数いる配備では、被害がその人数分になる**
        /// （**ロックアウトが、そのまま妨害の手段になる**）。
        ///
        /// **送信元ごとに数えれば、断るのはその送信元だけ**になる。
        /// **正しい秘密を持つ他の送信元は、通ったままである。**
        ///
        /// **送信元が取れないときは `client:<client_id>` だけ**になる（段階 2 と同じ）。
        /// </remarks>
        public static string ClientKey(string clientId)
        {
            if (string.IsNullOrEmpty(clientId))
            {
                return "";
            }

            string ip = AuthFailureProvider.SourceIp();

            return AuthFailureProvider.Truncate(string.IsNullOrEmpty(ip)
                ? ("client:" + clientId)
                : ("client:" + clientId + "|ip:" + ip));
        }

        /// <summary>いまの要求の送信元（取れなければ空）</summary>
        /// <returns>送信元のアドレス</returns>
        /// <remarks>
        /// **既存の流儀に合わせる**（`CmnUserStore` の `HttpContext.Current` /
        /// `MyHttpContext.Current`）。**引数で引き回さない** —
        /// **クライアント認証は `/token` `/revoke` `/introspect` ほか多くの口から通る**ため。
        ///
        /// | | |
        /// |---|---|
        /// | net10.0 版 | **`UseForwardedHeaders` を通した後の値**（`Startup` の先頭で取り込む。**設定が off なら接続元そのまま**） |
        /// | net48 版 | **`Request.UserHostAddress` そのまま**（転送ヘッダを戻さない） |
        ///
        /// **プロキシの後ろで `UseForwardedHeaders` を使うなら、
        /// `ForwardedHeadersKnownProxies` を必ず指定すること。**
        /// **指定しないと、クライアントが `X-Forwarded-For` を詐称でき、鍵を変えられる。**
        ///
        /// **取れなければ空を返す**（要求の外から呼ばれたときのため）。
        /// </remarks>
        private static string SourceIp()
        {
            try
            {
#if NETFX
                HttpContext context = HttpContext.Current;

                return (context == null || context.Request == null)
                    ? "" : (context.Request.UserHostAddress ?? "");
#else
                Microsoft.AspNetCore.Http.HttpContext context = MyHttpContext.Current;

                return (context == null || context.Connection == null
                    || context.Connection.RemoteIpAddress == null)
                    ? "" : context.Connection.RemoteIpAddress.ToString();
#endif
            }
            catch
            {
                //  **送信元が取れないこと自体で、認証を落とさない。**
                return "";
            }
        }

        /// <summary>鍵の長さを、列の幅に収める</summary>
        /// <param name="key">鍵</param>
        /// <returns>収めた鍵</returns>
        /// <remarks>**`FailureKey` は 256 文字**（`Create_UserStore.sql`）。</remarks>
        private static string Truncate(string key)
        {
            return (key.Length <= 256) ? key : key.Substring(0, 256);
        }

        /// <summary>`user_code` の投入の鍵（投入した利用者ごと）</summary>
        /// <param name="userName">利用者名</param>
        /// <returns>鍵（利用者名が空なら空）</returns>
        /// <remarks>
        /// **間違えた `user_code` では、どの要求を狙ったか分からない。**
        /// **だから「投入した人」で数える**（RFC 8628 §5.2 が求めるのは、投入の制限である）。
        ///
        /// **ここには送信元を混ぜない**（#305 の段階 4）。
        /// **投入はサインイン済みの画面から行う**ので、
        /// **その人以外が、この数を増やせない** — **妨害の手段にならない。**
        /// </remarks>
        public static string DeviceVerifyKey(string userName)
        {
            return string.IsNullOrEmpty(userName)
                ? "" : AuthFailureProvider.Truncate("device_verify:" + userName);
        }

        #endregion
    }
}
