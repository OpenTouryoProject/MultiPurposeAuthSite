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
//* クラス名        ：DPoPProofProvider
//* クラス日本語名  ：使った DPoP の証明を記録して、使い回しを断る（ライブラリ）
//*
//* 作成日時        ：－
//* 作成者          ：－
//* 更新履歴        ：－
//*
//*  日時        更新者            内容
//*  ----------  ----------------  -------------------------------------------------
//*  2026/10/22  玄人 幸道         新規（#311 の段階 3）
//*  2026/10/22  玄人 幸道         台帳の鍵を Open棟梁 の DPoPProof.CreateProofId にした（#294）
//**********************************************************************************

using MultiPurposeAuthSite.Co;
using MultiPurposeAuthSite.Data;
using MultiPurposeAuthSite.Log;
using MultiPurposeAuthSite.TokenProviders;

using System;
using System.Collections.Generic;
using System.Collections.Concurrent;
using System.Data;

using Dapper;

/// <summary>MultiPurposeAuthSite.Extensions.Sts</summary>
namespace MultiPurposeAuthSite.Extensions.Sts
{
    /// <summary>
    /// 使った DPoP の証明を記録して、**使い回しを断る**（#311 の段階 3）。
    /// </summary>
    /// <remarks>
    /// **段階 1・2 は、証明が「正しいこと」しか見ていなかった** —
    /// **正しい証明を横から写し取れば、そのまま通せた**（RFC 9449 §11.1）。
    /// **ここで「一度使った証明は二度と通らない」ようにする。**
    ///
    /// | | |
    /// |---|---|
    /// | **何を記録するか** | **証明の指紋**（`DPoPProof.CreateProofId` ＝ **鍵の指紋（`jkt`）と `jti` を組にしてハッシュしたもの**） |
    /// | **いつ記録するか** | **検証に通った後**（`CmnDPoP.Verify` の最後）。**壊れた証明で `jti` を焼かせない** |
    /// | **どう判定するか** | **記録できたら初回、できなかったら 2 回目。** **読んでから書くと競走に負ける**（下の節） |
    /// | **どこで効くか** | **`/token` と保護されたリソースの両方**（**同じ `Verify` を通る**ので、口ごとの抜けが無い） |
    ///
    /// ### 鍵と組にしてから指紋にする
    ///
    /// **`jti` だけを鍵にすると、クライアントが互いを塞げる** —
    /// **`jti` の値はクライアントが決める**ので、**先に使われた値は、他の相手が使えなくなる。**
    /// **`jkt` と組にすれば、台帳は「鍵ごと」になる**（RFC 9449 §11.1 も、
    /// **証明の公開鍵と組にして持つ**ことを挙げている）。
    ///
    /// **組にしてから指紋にする**のは、次の 2 つのため。
    ///
    /// | | |
    /// |---|---|
    /// | **長さが決まる** | **`jti` は相手が決める値**で、**長さに上限が無い**（列に収まらない） |
    /// | **値を持たない** | **`jkt` は、そのクライアントを辿れる値**である（ログに出さないのと同じ理由） |
    ///
    /// ### 記録できたかどうかで決める（読んでから書かない）
    ///
    /// **「在るか読む → 無ければ書く」は、同時に 2 本来たときに両方とも通る。**
    /// **主キーの一意性に判定させる** — **挿入できた方だけが初回**である。
    /// **`mem` では `ConcurrentDictionary.TryAdd` が同じ役目**を果たす。
    ///
    /// **挿入が別の理由で失敗したときも、通さない**（**記録できない ＝ 使い回しを止められない**）。
    /// **表が無い配備では、DPoP が使えなくなる** — **`Create_UserStore.sql` の表を足すこと**
    /// （`CONFIGURATION.md`）。
    ///
    /// ### 行は短命である
    ///
    /// **`iat` の窓を過ぎた証明は、記録が無くても通らない**（`CmnDPoP` の窓）。
    /// **だから、窓の長さだけ持てばよい**（`CmnDPoP.ProofReplayWindow`）。
    /// **掃除は書き込みのついでに行う**（常駐の仕組みは増やさない。
    /// `RequestObjectProvider` / `AuthFailureProvider` と同じ流儀）。
    /// </remarks>
    public class DPoPProofProvider
    {
        #region mem の入れ物

        /// <summary>mem のときの入れ物（証明の指紋 → 記録した時刻）</summary>
        private static ConcurrentDictionary<string, DateTime>
            Proofs = new ConcurrentDictionary<string, DateTime>();

        #endregion

        #region 公開

        /// <summary>この証明を初めて使ったことを記録する（#311 の段階 3）</summary>
        /// <param name="proofId">証明の指紋（`DPoPProof.CreateProofId`）</param>
        /// <returns>**初めてなら true。** **2 回目、または記録できなければ false**</returns>
        /// <remarks>
        /// **記録できたかどうかで判定する**（この型の注を参照）。
        /// **断る理由は呼び出し側が文にする**（`CmnDPoP.Verify`）。
        /// </remarks>
        public static bool TryRecord(string proofId)
        {
            if (string.IsNullOrEmpty(proofId))
            {
                // **指紋が作れなかった** ＝ **記録できない**ので、通さない。
                return false;
            }

            // 窓を過ぎた行を、間隔を空けてまとめて消す
            DPoPProofProvider.SweepIfNeeded();

            switch (Config.UserStoreType)
            {
                case EnumUserStoreType.Memory:

                    return DPoPProofProvider.Proofs.TryAdd(proofId, DateTime.Now);

                case EnumUserStoreType.SqlServer:
                case EnumUserStoreType.ODPManagedDriver:
                case EnumUserStoreType.PostgreSQL: // DMBMS

                    using (IDbConnection cnn = DataAccess.CreateConnection())
                    {
                        cnn.Open();

                        try
                        {
                            cnn.Execute(
                                "INSERT INTO " + DPoPProofProvider.TableName()
                                + " (" + DPoPProofProvider.ColumnList() + ")"
                                + " VALUES (" + DPoPProofProvider.ParameterList() + ")",
                                new { ProofId = proofId, CreatedDate = DateTime.Now });

                            return true;
                        }
                        catch (Exception ex)
                        {
                            //  **主キーの違反なら 2 回目**である（**狙いどおり**）。
                            //    **方言ごとの例外の型で見分けない** — **行が在るかで見分ける。**
                            if (DPoPProofProvider.Exists(cnn, proofId))
                            {
                                return false;
                            }

                            //  **それ以外の失敗**（表が無い・繋がらない）。
                            //    **記録できない ＝ 使い回しを止められない**ので、**通さない。**
                            Logging.MyOperationTrace(string.Format(
                                "The DPoP proof could not be recorded. ({0})", ex.GetType().Name));

                            return false;
                        }
                    }
            }

            return false;
        }

        #endregion

        #region 掃除

        /// <summary>この時刻より古い行は、もう使い回しに使えない</summary>
        /// <remarks>
        /// **`iat` の窓を過ぎた証明は、記録が無くても通らない。**
        /// **窓は「過去 ＋ 未来」の分だけ必要**である — **`iat` が未来の証明は、
        /// その分だけ長く通る**ため（`CmnDPoP.ProofReplayWindow`）。
        ///
        /// **ここを短くすると、消した分だけ使い回しが通る** —
        /// **窓から引く**ことで、**片方だけ直して食い違うことを防ぐ。**
        /// </remarks>
        private static DateTime KeepLimit
        {
            get { return DateTime.Now - CmnDPoP.ProofReplayWindow; }
        }

        /// <summary>前回まとめて消した時刻</summary>
        private static DateTime LastSweep = DateTime.MinValue;

        /// <summary>まとめて消す間隔</summary>
        /// <remarks>
        /// **常駐の仕組み（バッチ・タイマ）を増やさず、書き込みのついでに消す**
        /// （`RequestObjectProvider` と同じ流儀）。
        ///
        /// **掃除が遅れて行が残っても、断りが増える方に転ぶだけ**である
        /// （**取りこぼしにはならない**）。**`jti` は要求ごとに新しくする値**なので、
        /// **残った行で困る相手は居ない。**
        /// </remarks>
        private static readonly TimeSpan SweepInterval = TimeSpan.FromMinutes(5);

        /// <summary>掃除の間隔を測るための錠</summary>
        private static readonly object SweepLock = new object();

        /// <summary>間隔を過ぎていたら、窓を過ぎた行をまとめて消す</summary>
        private static void SweepIfNeeded()
        {
            DateTime now = DateTime.Now;

            lock (DPoPProofProvider.SweepLock)
            {
                if (now - DPoPProofProvider.LastSweep < DPoPProofProvider.SweepInterval)
                {
                    return;
                }

                DPoPProofProvider.LastSweep = now;
            }

            DateTime limit = DPoPProofProvider.KeepLimit;

            try
            {
                switch (Config.UserStoreType)
                {
                    case EnumUserStoreType.Memory:

                        foreach (KeyValuePair<string, DateTime> kv in DPoPProofProvider.Proofs)
                        {
                            if (kv.Value < limit)
                            {
                                DPoPProofProvider.Proofs.TryRemove(kv.Key, out DateTime _);
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
                                "DELETE FROM " + DPoPProofProvider.TableName()
                                + " WHERE " + DPoPProofProvider.CreatedDateColumn()
                                + " <= " + DPoPProofProvider.Prefix() + "Limit",
                                new { Limit = limit });
                        }

                        break;
                }
            }
            catch (Exception ex)
            {
                //  **掃除に失敗しても、要求は止めない**（次の機会に消せばよい）。
                //    **消えないことで緩くなる判定は無い**（残った行は「2 回目」と言うだけ）。
                Logging.MyOperationTrace(string.Format(
                    "The DPoP proof ledger could not be swept. ({0})", ex.GetType().Name));
            }
        }

        #endregion

        #region private（方言）

        /// <summary>行が在るか</summary>
        /// <param name="cnn">接続（**挿入に失敗した接続をそのまま使う**）</param>
        /// <param name="proofId">証明の指紋</param>
        /// <returns>在れば true</returns>
        private static bool Exists(IDbConnection cnn, string proofId)
        {
            try
            {
                return cnn.ExecuteScalar<int?>(
                    "SELECT 1 FROM " + DPoPProofProvider.TableName()
                    + " WHERE " + DPoPProofProvider.ProofIdColumn()
                    + " = " + DPoPProofProvider.Prefix() + "ProofId",
                    new { ProofId = proofId }).HasValue;
            }
            catch
            {
                // **読めないなら、在ることを確かめられない**（呼び出し側が通さない）。
                return false;
            }
        }

        /// <summary>表の名前（方言）</summary>
        /// <returns>表の名前</returns>
        private static string TableName()
        {
            switch (Config.UserStoreType)
            {
                case EnumUserStoreType.SqlServer: return "[DPoPProof]";
                case EnumUserStoreType.ODPManagedDriver: return "\"DPoPProof\"";
                case EnumUserStoreType.PostgreSQL: return "\"dpopproof\"";
            }

            return "";
        }

        /// <summary>証明の指紋の列（方言）</summary>
        /// <returns>列の名前</returns>
        private static string ProofIdColumn()
        {
            switch (Config.UserStoreType)
            {
                case EnumUserStoreType.SqlServer: return "[ProofId]";
                case EnumUserStoreType.ODPManagedDriver: return "\"ProofId\"";
                case EnumUserStoreType.PostgreSQL: return "\"proofid\"";
            }

            return "";
        }

        /// <summary>記録した時刻の列（方言）</summary>
        /// <returns>列の名前</returns>
        private static string CreatedDateColumn()
        {
            switch (Config.UserStoreType)
            {
                case EnumUserStoreType.SqlServer: return "[CreatedDate]";
                case EnumUserStoreType.ODPManagedDriver: return "\"CreatedDate\"";
                case EnumUserStoreType.PostgreSQL: return "\"createddate\"";
            }

            return "";
        }

        /// <summary>挿入する列（方言）</summary>
        /// <returns>列の一覧</returns>
        private static string ColumnList()
        {
            return DPoPProofProvider.ProofIdColumn()
                + ", " + DPoPProofProvider.CreatedDateColumn();
        }

        /// <summary>パラメタの接頭辞（方言）</summary>
        /// <returns>接頭辞</returns>
        /// <remarks>
        /// **Oracle だけ `:` である**（他は `@`）。
        /// **1 か所に寄せる** — **口ごとに書くと、どれか 1 つを直し忘れる**
        /// （**`mem` と SQL Server では動くので、気付かない**）。
        /// </remarks>
        private static string Prefix()
        {
            return (Config.UserStoreType == EnumUserStoreType.ODPManagedDriver) ? ":" : "@";
        }

        /// <summary>挿入するパラメタ（方言）</summary>
        /// <returns>パラメタの一覧</returns>
        private static string ParameterList()
        {
            string p = DPoPProofProvider.Prefix();

            return p + "ProofId, " + p + "CreatedDate";
        }

        #endregion
    }
}
