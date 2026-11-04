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
//* クラス名        ：CmnUserStore
//* クラス日本語名  ：CmnUserStore（ライブラリ）
//*
//* 作成日時        ：－
//* 作成者          ：－
//* 更新履歴        ：－
//*
//*  日時        更新者            内容
//*  ----------  ----------------  -------------------------------------------------
//*  2018/12/04  西野 大介         新規
//*  2020/02/27  西野 大介         DeviceToken追加(プッシュ通知)
//*  2020/07/22  西野 大介         クリーンアーキテクチャ維持or放棄 → 放棄
//*  2020/12/23  西野 大介         NormalizedUserNamenの所、userName.ToUpper()
//*  2026/09/30  玄人 幸道         利用者の削除で、発行した sub の対応表も消すようにした（#151 の段階 2）
//*  2026/10/02  玄人 幸道         ロール名を正規化名で突き合わせる（ora / npg で付かなかった）（#257 で判明）
//*  2026/10/07  玄人 幸道         Users.FIDO2PublicKey（MsPass専用）を削除（#137）
//*  2026/10/09  玄人 幸道         Users.PaymentInformation を削除（オンライン決済の取り下げ）
//*  2026/10/15  玄人 幸道         書き込みの失敗を握らずに投げ直す（#300）
//*  2026/10/20  玄人 幸道         Users から ClientID 列を落とした（#307 の段階 5-a-1）
//*  2026/10/21  玄人 幸道         利用者の削除で、セッション × クライアントの台帳も消す（#310 の段階 1）
//*  2026/10/28  玄人 幸道         mem ストアで TOTP のトークンの更新が DB の枝へ落ちていた（回復コードで 500。#294）
//*  2026/10/29  玄人 幸道         利用者の削除で、同意（mem）と、持っていたクライアントへの全利用者の同意も消す（#294）
//*  2026/10/30  玄人 幸道         partial に分割（Find / Roles / UserAttributes / LoginAttributes / Logins / Claims / Tokens。#294）
//*  2026/10/30  玄人 幸道         利用者の削除で、同意の取り消しを削除の後へ・メアド変更の確認待ちも消す・子の表を親より先に消す（#294）
//*  2026/10/30  玄人 幸道         消した UpdateRoles などを指すコメントを直した（#294）
//*  2026/11/02  玄人 幸道         利用者名の変更で、WebAuthn の資格情報を同じトランザクションで移す（外部キーで 500。#327）
//*  2026/11/02  玄人 幸道         Users の更新を楽観排他にした（読んだ時点から行が変わっていたら断る。#316）
//**********************************************************************************

using MultiPurposeAuthSite.Co;
#if NETFX
using MultiPurposeAuthSite.Entity;
#else
using MultiPurposeAuthSite;
#endif
using MultiPurposeAuthSite.Log;
using MultiPurposeAuthSite.Util.Sts;
using MultiPurposeAuthSite.Util.IdP;
using MultiPurposeAuthSite.Extensions.Sts;

using System;
using System.Data;
using System.Linq;
using System.Collections.Generic;

using System.Reflection;

using Dapper;

using Newtonsoft.Json;
using Newtonsoft.Json.Linq;

/// <summary>MultiPurposeAuthSite.Data</summary>
namespace MultiPurposeAuthSite.Data
{
    /// <summary>CmnUserStore</summary>
    /// <remarks>
    /// **例外の扱い**（#300）。
    ///
    /// | | |
    /// |---|---|
    /// | **書き込み**（`Create` / `Update` / `Delete` / `Add*` / `Remove*`） | **握らない。** **ログに書いてから投げ直す** |
    /// | 読み取り（`Find*` / `Get*`） | **握って既定値を返す**（従来どおり。**「居ない」と同じ扱い**になる） |
    ///
    /// **以前は書き込みも握っていた。**
    /// **`IdentityResult` は成功になり、画面はリダイレクトし、データは変わらない** —
    /// **「静かに失敗する」**状態だった。
    /// **実例**（#299） : **GDPR の消去が Oracle で落ちていた**のに、**画面は成功に見えていた。**
    ///
    /// **`StopUserStoreException` は、以前から投げ直している**
    /// （`Logging.MySQLLogForEx` の中。**STS 専用の配備で user store を止める**ための例外）。
    ///
    /// **読み取りを握るのを止めるかは、この Issue の外**である。
    /// **Skip や「居ない」で成り立っている経路**（種データの作成など）が在るため、
    /// **1 件ずつ意味を決める必要がある。**
    ///
    /// **mem ストアの入れ物（`CmnStore._users` など）は `MemoryStoreList` で、1 回の読み書きだけを排他する**（#325）。
    /// **開発・試験用**であり、複数の操作をまとめた排他はしていない。
    /// </remarks>
    internal partial class CmnUserStore : CmnStore
    {
        #region CRUD(共通)

        #region C (Create)

        /// <summary>新規ユーザーの追加</summary>
        /// <param name="user">ApplicationUser</param>
        public static void Create(ApplicationUser user)
        {
            // 更新系の機能のため、
            OnlySts.STSOnly_M();

            // Debug
            Logging.MyDebugSQLTrace("★ : " +
                MethodBase.GetCurrentMethod().DeclaringType.FullName +
                "." + MethodBase.GetCurrentMethod().Name +
                Logging.GetParametersString(MethodBase.GetCurrentMethod().GetParameters()));

            //  **読み直した行と区別するための、最初の値**（#316）。
            user.ConcurrencyStamp = Guid.NewGuid().ToString();

            try
            {
                // 新規ユーザーの追加
                switch (Config.UserStoreType)
                {
                    case EnumUserStoreType.Memory:

                        CmnStore._users.Add(user);

                        break;

                    case EnumUserStoreType.SqlServer:
                    case EnumUserStoreType.ODPManagedDriver:
                    case EnumUserStoreType.PostgreSQL: // DMBMS Provider

                        using (IDbConnection cnn = DataAccess.CreateConnection())
                        {
                            cnn.Open();

                            switch (Config.UserStoreType)
                            {
                                case EnumUserStoreType.SqlServer:

                                    cnn.Execute(
                                        "INSERT INTO [Users] ( " +
                                        "    [Id], [UserName], [NormalizedUserName], [PasswordHash], " +
                                        "    [Email], [NormalizedEmail], [EmailConfirmed], [PhoneNumber], [PhoneNumberConfirmed], " +
                                        "    [LockoutEnabled], [AccessFailedCount], [LockoutEndDateUtc], [SecurityStamp], [TwoFactorEnabled], [TotpAuthenticatorKey], " +
                                        "    [UnstructuredData], [DeviceToken], [CreatedDate], [PasswordChangeDate], [ConcurrencyStamp])" +
                                        "    VALUES ( " +
                                        "        @Id, @UserName, @NormalizedUserName, @PasswordHash, " +
                                        "        @Email, @NormalizedEmail, @EmailConfirmed, @PhoneNumber, @PhoneNumberConfirmed, " +
                                        "        @LockoutEnabled, @AccessFailedCount, @LockoutEndDateUtc, @SecurityStamp, @TwoFactorEnabled, @TotpAuthenticatorKey, " +
                                        "        @UnstructuredData, @DeviceToken, @CreatedDate, @PasswordChangeDate, @ConcurrencyStamp)", user);

                                    break;

                                case EnumUserStoreType.ODPManagedDriver:

                                    cnn.Execute(
                                        "INSERT INTO \"Users\" ( " +
                                        "    \"Id\", \"UserName\", \"NormalizedUserName\", \"PasswordHash\", " +
                                        "    \"Email\", \"NormalizedEmail\", \"EmailConfirmed\", \"PhoneNumber\", \"PhoneNumberConfirmed\", " +
                                        "    \"LockoutEnabled\", \"AccessFailedCount\", \"LockoutEndDateUtc\", \"SecurityStamp\", \"TwoFactorEnabled\", \"TotpAuthenticatorKey\", " +
                                        "    \"UnstructuredData\", \"DeviceToken\", \"CreatedDate\", \"PasswordChangeDate\", \"ConcurrencyStamp\")" +
                                        "    VALUES ( " +
                                        "        :Id, :UserName, :NormalizedUserName, :PasswordHash, " +
                                        "        :Email, :NormalizedEmail, :EmailConfirmed, :PhoneNumber, :PhoneNumberConfirmed, " +
                                        "        :LockoutEnabled, :AccessFailedCount, :LockoutEndDateUtc, :SecurityStamp, :TwoFactorEnabled, :TotpAuthenticatorKey, " +
                                        "        :UnstructuredData, :DeviceToken, :CreatedDate, :PasswordChangeDate, :ConcurrencyStamp)",
                                        new // 拡張メソッドで対策できる。
                                        {
                                            Id = user.Id,
                                            UserName = user.UserName,
                                            NormalizedUserName = user.NormalizedUserName,
                                            PasswordHash = user.PasswordHash,
                                            Email = user.Email,
                                            NormalizedEmail = user.NormalizedEmail,
                                            EmailConfirmed = user.EmailConfirmed ? -1 : 0,
                                            PhoneNumber = user.PhoneNumber,
                                            PhoneNumberConfirmed = user.PhoneNumberConfirmed ? -1 : 0,
                                            LockoutEnabled = user.LockoutEnabled ? -1 : 0,
                                            AccessFailedCount = user.AccessFailedCount,
                                            LockoutEndDateUtc = user.LockoutEndDateUtc,
                                            SecurityStamp = user.SecurityStamp,
                                            TwoFactorEnabled = user.TwoFactorEnabled ? -1 : 0,
                                            TotpAuthenticatorKey = user.TotpAuthenticatorKey,
                                            UnstructuredData = user.UnstructuredData,
                                            DeviceToken = user.DeviceToken,
                                            CreatedDate = user.CreatedDate,
                                            PasswordChangeDate = user.PasswordChangeDate,
                                            ConcurrencyStamp = user.ConcurrencyStamp
                                        });

                                    break;

                                case EnumUserStoreType.PostgreSQL:

                                    cnn.Execute(
                                        "INSERT INTO \"users\" ( " +
                                        "    \"id\", \"username\", \"normalizedusername\", \"passwordhash\", " +
                                        "    \"email\", \"normalizedemail\", \"emailconfirmed\", \"phonenumber\", \"phonenumberconfirmed\", " +
                                        "    \"lockoutenabled\", \"accessfailedcount\", \"lockoutenddateutc\", \"securitystamp\", \"twofactorenabled\", \"totpauthenticatorkey\", " +
                                        "    \"unstructureddata\", \"devicetoken\", \"createddate\", \"passwordchangedate\", \"concurrencystamp\")" +
                                        "    VALUES ( " +
                                        "        @Id, @UserName, @NormalizedUserName, @PasswordHash, " +
                                        "        @Email, @NormalizedEmail, @EmailConfirmed, @PhoneNumber, @PhoneNumberConfirmed, " +
                                        "        @LockoutEnabled, @AccessFailedCount, @LockoutEndDateUtc, @SecurityStamp, @TwoFactorEnabled, @TotpAuthenticatorKey, " +
                                        "        @UnstructuredData, @DeviceToken, @CreatedDate, @PasswordChangeDate, @ConcurrencyStamp)", user);

                                    break;
                            }

                            // ユーザの関連情報は、このタイミングで追加しない（Roles, Logins, Claims）
                        }

                        break;

                }

                //  **UserName はメアドのことがある**（ログに個人情報が残る。Update / Delete も同じ。扱いは別に決める）。
                Logging.MyOperationTrace(string.Format("{0}({1}) was created.", user.Id, user.UserName));
            }
            catch (Exception ex)
            {
                //  **書き込みの失敗は、握らない**（#300）。**ログに書いてから投げ直す。**
                Logging.MySQLLogForEx(ex);
                throw;
            }

            return;
        }

        #endregion

        #region U (Update)

        /// <summary>読んだ時点から行が変わっていて、更新しなかった（#316）</summary>
        /// <remarks>
        /// **利用者が消えていた場合も、これになる**（更新した行が 0 件であることしか分からない）。
        /// </remarks>
        internal sealed class ConcurrencyException : Exception
        {
            /// <summary>constructor</summary>
            /// <param name="userId">利用者の Id</param>
            public ConcurrencyException(string userId)
                : base(CmnUserStore.ConcurrencyFailureMessage + " (" + userId + ")") { }
        }

        /// <summary>競合の失敗の文面（net48 の IdentityResult 用。net10.0 の既定の文面に揃える）</summary>
        internal const string ConcurrencyFailureMessage = "Optimistic concurrency failure, object has been modified.";

        /// <summary>競合したときに、読み直してやり直す回数</summary>
        /// <remarks>
        /// **1 周で書けるのは 1 要求だけ**なので、**同時に N 要求なら N 周要る。**
        /// **足りないと数えが消える**（10 回では、同時に 20 回の失敗を数えきれなかった。`RT-316.1`）。
        /// </remarks>
        internal const int ConcurrencyRetryCount = 50;

        /// <summary>やり直す前に待つ時間（同時に走る要求が、また揃わないように散らす）</summary>
        /// <returns>ミリ秒</returns>
        internal static int ConcurrencyRetryDelayMilliseconds()
        {
            return new Random(Guid.NewGuid().GetHashCode()).Next(1, 30);
        }

        /// <summary>ユーザー情報を更新</summary>
        /// <param name="user">ApplicationUser</param>
        /// <remarks>
        /// **読んだ時点から行が変わっていたら、`ConcurrencyException` を投げる**（#316）。
        /// **以前は後勝ちで、並行した要求の書き込みが消えていた。**
        /// **mem ストアは同じ実体を共有するので、確かめない。**
        /// </remarks>
        public static void Update(ApplicationUser user)
        {
            // 更新系の機能のため、
            //OnlySts.STSOnly_M();
            if (OnlySts.STSOnly_P)
            {
                // 何も更新しない。
                // IUserLockoutStore機能などで使用するため。
                return;
            }
            // Debug
            Logging.MyDebugSQLTrace("★ : " +
                MethodBase.GetCurrentMethod().DeclaringType.FullName +
                "." + MethodBase.GetCurrentMethod().Name +
                Logging.GetParametersString(MethodBase.GetCurrentMethod().GetParameters()));

            try
            {
                // MemoryStore同一インスタンス問題。
                // SerializeできないMemberもあり、DeepCloneもできず。

                // ユーザー情報を更新
                switch (Config.UserStoreType)
                {
                    case EnumUserStoreType.Memory:

                        // MemoryStore同一インスタンスなので何もしない。

                        break;

                    case EnumUserStoreType.SqlServer:
                    case EnumUserStoreType.ODPManagedDriver:
                    case EnumUserStoreType.PostgreSQL: // DMBMS Provider

                        using (IDbConnection cnn = DataAccess.CreateConnection())
                        {
                            cnn.Open();

                            using (IDbTransaction tr = cnn.BeginTransaction())
                            {
                                // **利用者名が変わるなら、資格情報を一度外す**（#327）。
                                List<Fido2DataRow> fido2Data = CmnUserStore.TakeFido2DataForRename(cnn, tr, user);

                                //  **読んだ値が一致するときだけ更新する**（#316）。
                                //    **列を足す前からの行は NULL** なので、`=` では一致しない。
                                string newStamp = Guid.NewGuid().ToString();
                                bool stampIsNull = user.ConcurrencyStamp == null;
                                int rows = 0;

                                // ユーザー情報を更新
                                switch (Config.UserStoreType)
                                {
                                    case EnumUserStoreType.SqlServer:

                                        rows = cnn.Execute(
                                            "UPDATE [Users] " +
                                            "SET [UserName] = @UserName, [NormalizedUserName] = @NormalizedUserName, [PasswordHash] = @PasswordHash, " +
                                            "    [Email] = @Email, [NormalizedEmail] = @NormalizedEmail, [EmailConfirmed] = @EmailConfirmed, [PhoneNumber] = @PhoneNumber, [PhoneNumberConfirmed] = @PhoneNumberConfirmed, " +
                                            "    [LockoutEnabled] = @LockoutEnabled, [AccessFailedCount] = @AccessFailedCount, [LockoutEndDateUtc] = @LockoutEndDateUtc, " +
                                            "    [SecurityStamp] = @SecurityStamp, [TwoFactorEnabled] = @TwoFactorEnabled, [TotpAuthenticatorKey] = @TotpAuthenticatorKey, " +
                                            "    [UnstructuredData] = @UnstructuredData, " + 
                                            "    [DeviceToken] = @DeviceToken, [PasswordChangeDate] = @PasswordChangeDate, [ConcurrencyStamp] = @NewStamp " +
                                            "WHERE [Id] = @Id AND " +
                                            (stampIsNull ? "[ConcurrencyStamp] IS NULL" : "[ConcurrencyStamp] = @OldStamp"),
                                            CmnUserStore.UpdateParameters(user, newStamp), tr);

                                        break;

                                    case EnumUserStoreType.ODPManagedDriver:

                                        rows = cnn.Execute(
                                            "UPDATE \"Users\" " +
                                            "SET \"UserName\" = :UserName, \"NormalizedUserName\" = :NormalizedUserName, \"PasswordHash\" = :PasswordHash, " +
                                            "    \"Email\" = :Email, \"NormalizedEmail\" = :NormalizedEmail, \"EmailConfirmed\" = :EmailConfirmed, \"PhoneNumber\" = :PhoneNumber, \"PhoneNumberConfirmed\" = :PhoneNumberConfirmed, " +
                                            "    \"LockoutEnabled\" = :LockoutEnabled, \"AccessFailedCount\" = :AccessFailedCount, \"LockoutEndDateUtc\" = :LockoutEndDateUtc, " +
                                            "    \"SecurityStamp\" = :SecurityStamp, \"TwoFactorEnabled\" = :TwoFactorEnabled, \"TotpAuthenticatorKey\" = :TotpAuthenticatorKey, " +
                                            "    \"UnstructuredData\" = :UnstructuredData, " +
                                            "    \"DeviceToken\" = :DeviceToken, \"PasswordChangeDate\" = :PasswordChangeDate, \"ConcurrencyStamp\" = :NewStamp " +
                                            "WHERE \"Id\" = :Id AND " +
                                            (stampIsNull ? "\"ConcurrencyStamp\" IS NULL" : "\"ConcurrencyStamp\" = :OldStamp"),
                                            new // 拡張メソッドで対策できる。
                                            {
                                                Id = user.Id,
                                                UserName = user.UserName,
                                                NormalizedUserName = user.NormalizedUserName,
                                                PasswordHash = user.PasswordHash,
                                                Email = user.Email,
                                                NormalizedEmail = user.NormalizedEmail,
                                                EmailConfirmed = user.EmailConfirmed ? -1 : 0,
                                                PhoneNumber = user.PhoneNumber,
                                                PhoneNumberConfirmed = user.PhoneNumberConfirmed ? -1 : 0,
                                                LockoutEnabled = user.LockoutEnabled ? -1 : 0,
                                                AccessFailedCount = user.AccessFailedCount,
                                                LockoutEndDateUtc = user.LockoutEndDateUtc,
                                                SecurityStamp = user.SecurityStamp,
                                                TwoFactorEnabled = user.TwoFactorEnabled ? -1 : 0,
                                                TotpAuthenticatorKey = user.TotpAuthenticatorKey,
                                                UnstructuredData = user.UnstructuredData,
                                                DeviceToken = user.DeviceToken,
                                                //CreatedDate = user.CreatedDate,
                                                PasswordChangeDate = user.PasswordChangeDate,
                                                NewStamp = newStamp,
                                                OldStamp = user.ConcurrencyStamp
                                            }, tr);

                                        break;

                                    case EnumUserStoreType.PostgreSQL:

                                        rows = cnn.Execute(
                                           "UPDATE \"users\" " +
                                           "SET \"username\" = @UserName, \"normalizedusername\" = @NormalizedUserName, \"passwordhash\" = @PasswordHash, " +
                                           "    \"email\" = @Email, \"normalizedemail\" = @NormalizedEmail, \"emailconfirmed\" = @EmailConfirmed, \"phonenumber\" = @PhoneNumber, \"phonenumberconfirmed\" = @PhoneNumberConfirmed, " +
                                           "    \"lockoutenabled\" = @LockoutEnabled, \"accessfailedcount\" = @AccessFailedCount, \"lockoutenddateutc\" = @LockoutEndDateUtc, " +
                                           "    \"securitystamp\" = @SecurityStamp, \"twofactorenabled\" = @TwoFactorEnabled, \"totpauthenticatorkey\" = @TotpAuthenticatorKey, " +
                                           "    \"unstructureddata\" = @UnstructuredData, " +
                                           "    \"devicetoken\" = @DeviceToken, \"passwordchangedate\" = @PasswordChangeDate, \"concurrencystamp\" = @NewStamp " +
                                           "WHERE \"id\" = @Id AND " +
                                           (stampIsNull ? "\"concurrencystamp\" IS NULL" : "\"concurrencystamp\" = @OldStamp"),
                                           CmnUserStore.UpdateParameters(user, newStamp), tr);

                                        break;
                                }

                                //  **更新できなければ、ここで投げる**（#316）。
                                //    **コミットしないので、外した資格情報も戻る。**
                                if (rows == 0)
                                {
                                    throw new CmnUserStore.ConcurrencyException(user.Id);
                                }

                                // **外した資格情報を、新しい名前で戻す**（#327）。
                                CmnUserStore.PutFido2DataForRename(cnn, tr, user, fido2Data);

                                tr.Commit();

                                //  **同じ物で続けて更新しても、自分の更新と競合しない**ように、持ち替える。
                                user.ConcurrencyStamp = newStamp;

                                // ★ 基本的に、以下のプロパティ更新には、プロパティ更新メソッド（UserManager.XXXX[PropertyName]Async）を使用する。
                                //    この際、ASP.NET Identity Frameworkにより、本メソッド（UserStore.UpdateAsync）が呼び出されることがあるもよう。
                                //    その際、二重実行により二重登録（制約により例外になる）が起き得るので、以下は、ココに実装しないことにした。
                                //    （Roles / Logins / Claims は、それぞれの口（AddToRole / AddLogin / AddClaim など）で更新する。
                                //      以前ここに在った UpdateRoles などの呼び出しは、#294 で UpdateRoles ごと消した）
                            }
                        }

                        break;
                }

                Logging.MyOperationTrace(string.Format("{0}({1}) was updated.", user.Id, user.UserName));
                //}
            }
            catch (CmnUserStore.ConcurrencyException)
            {
                //  **障害ではない**ので、SQL のエラーとしてログに書かない。呼ぶ側が決める。
                throw;
            }
            catch (Exception ex)
            {
                //  **書き込みの失敗は、握らない**（#300）。**ログに書いてから投げ直す。**
                Logging.MySQLLogForEx(ex);
                throw;
            }

            return;
        }

        /// <summary>Update のパラメタ（SQL Server・PostgreSQL。真偽をそのまま渡せる方言）</summary>
        /// <param name="user">ApplicationUser</param>
        /// <param name="newStamp">新しい ConcurrencyStamp</param>
        /// <returns>パラメタ</returns>
        private static object UpdateParameters(ApplicationUser user, string newStamp)
        {
            return new
            {
                user.Id,
                user.UserName,
                user.NormalizedUserName,
                user.PasswordHash,
                user.Email,
                user.NormalizedEmail,
                user.EmailConfirmed,
                user.PhoneNumber,
                user.PhoneNumberConfirmed,
                user.LockoutEnabled,
                user.AccessFailedCount,
                user.LockoutEndDateUtc,
                user.SecurityStamp,
                user.TwoFactorEnabled,
                user.TotpAuthenticatorKey,
                user.UnstructuredData,
                user.DeviceToken,
                user.PasswordChangeDate,
                NewStamp = newStamp,
                OldStamp = user.ConcurrencyStamp
            };
        }

        /// <summary>利用者名の変更で動かす、FIDO2Data の行</summary>
        internal sealed class Fido2DataRow
        {
            /// <summary>PublicKeyId</summary>
            public string PublicKeyId { get; set; }

            /// <summary>UnstructuredData</summary>
            public string UnstructuredData { get; set; }
        }

        /// <summary>利用者名が変わるなら、その利用者の FIDO2Data の行を読んで消す</summary>
        /// <param name="cnn">IDbConnection</param>
        /// <param name="tr">IDbTransaction</param>
        /// <param name="user">ApplicationUser（新しい利用者名を持つ）</param>
        /// <returns>消した行（利用者名が変わらなければ null）</returns>
        //  **`FIDO2Data.UserName` は `Users.UserName` への外部キーで、`ON UPDATE` が無い**（#327）。
        //    **親を先に変えても、子を先に変えても、制約に当たる。**
        //    **`ON UPDATE CASCADE` は Oracle に無い**ので、3 方言で同じ手順にする：
        //    **子を消す → 親を変える → 子を入れ直す**（1 つのトランザクション）。
        //    **途中で失敗すれば全部戻る**ので、資格情報は失われない。DDL は変えない。
        //
        //    **net48 版も通る。** `Extensions\FIDO` は net10.0 版だけがビルドするので、
        //    **ここでは `StoredCredential` を使わない。**
        private static List<Fido2DataRow> TakeFido2DataForRename(
            IDbConnection cnn, IDbTransaction tr, ApplicationUser user)
        {
            string selectUserName = "";
            string selectRows = "";
            string delete = "";

            switch (Config.UserStoreType)
            {
                case EnumUserStoreType.SqlServer:
                    selectUserName = "SELECT [UserName] FROM [Users] WHERE [Id] = @Id";
                    selectRows = "SELECT [PublicKeyId], [UnstructuredData] FROM [FIDO2Data] WHERE [UserName] = @UserName";
                    delete = "DELETE FROM [FIDO2Data] WHERE [UserName] = @UserName";
                    break;

                case EnumUserStoreType.ODPManagedDriver:
                    selectUserName = "SELECT \"UserName\" FROM \"Users\" WHERE \"Id\" = :Id";
                    selectRows = "SELECT \"PublicKeyId\", \"UnstructuredData\" FROM \"FIDO2Data\" WHERE \"UserName\" = :UserName";
                    delete = "DELETE FROM \"FIDO2Data\" WHERE \"UserName\" = :UserName";
                    break;

                case EnumUserStoreType.PostgreSQL:
                    selectUserName = "SELECT \"username\" FROM \"users\" WHERE \"id\" = @Id";
                    selectRows = "SELECT \"publickeyid\", \"unstructureddata\" FROM \"fido2data\" WHERE \"username\" = @UserName";
                    delete = "DELETE FROM \"fido2data\" WHERE \"username\" = @UserName";
                    break;
            }

            string oldUserName = cnn.QueryFirstOrDefault<string>(selectUserName, new { Id = user.Id }, tr);

            if (string.IsNullOrEmpty(oldUserName) || oldUserName == user.UserName)
            {
                return null;
            }

            List<Fido2DataRow> rows = cnn.Query<Fido2DataRow>(selectRows, new { UserName = oldUserName }, tr).ToList();

            if (0 < rows.Count)
            {
                cnn.Execute(delete, new { UserName = oldUserName }, tr);
            }

            return rows;
        }

        /// <summary>消した FIDO2Data の行を、新しい利用者名で入れ直す</summary>
        /// <param name="cnn">IDbConnection</param>
        /// <param name="tr">IDbTransaction</param>
        /// <param name="user">ApplicationUser（新しい利用者名を持つ）</param>
        /// <param name="rows">TakeFido2DataForRename の戻り値</param>
        //  **`UserName` 列と、JSON の `UserId`（利用者名の UTF-8 の base64）を変える。**
        //    **`UserHandle` は変えない。** 認証器が持っている値で、サインインで照合する（#294）。
        //    **`DateParseHandling.None` で読む。** 触らない項目（`RegDate`）の形を変えないため。
        private static void PutFido2DataForRename(
            IDbConnection cnn, IDbTransaction tr, ApplicationUser user, List<Fido2DataRow> rows)
        {
            if (rows == null)
            {
                return;
            }

            string insert = "";

            switch (Config.UserStoreType)
            {
                case EnumUserStoreType.SqlServer:
                    insert = "INSERT INTO [FIDO2Data] ([PublicKeyId], [UserName], [UnstructuredData]) "
                        + "VALUES (@PublicKeyId, @UserName, @UnstructuredData)";
                    break;

                case EnumUserStoreType.ODPManagedDriver:
                    insert = "INSERT INTO \"FIDO2Data\" (\"PublicKeyId\", \"UserName\", \"UnstructuredData\") "
                        + "VALUES (:PublicKeyId, :UserName, :UnstructuredData)";
                    break;

                case EnumUserStoreType.PostgreSQL:
                    insert = "INSERT INTO \"fido2data\" (\"publickeyid\", \"username\", \"unstructureddata\") "
                        + "VALUES (@PublicKeyId, @UserName, @UnstructuredData)";
                    break;
            }

            string newUserId = Convert.ToBase64String(System.Text.Encoding.UTF8.GetBytes(user.UserName));

            foreach (Fido2DataRow row in rows)
            {
                JObject credential = JsonConvert.DeserializeObject<JObject>(row.UnstructuredData,
                    new JsonSerializerSettings() { DateParseHandling = DateParseHandling.None });

                credential["UserId"] = newUserId;

                cnn.Execute(insert, new
                {
                    PublicKeyId = row.PublicKeyId,
                    UserName = user.UserName,
                    UnstructuredData = credential.ToString(Formatting.None)
                }, tr);
            }
        }

        #endregion

        #region D (Delete)

        /// <summary>ユーザの論理削除</summary>
        /// <param name="user">ApplicationUser</param>
        /// <remarks>
        /// 削除するエンティティにマークを付けます
        /// </remarks>
        public static void Delete(ApplicationUser user)
        {
            // 更新系の機能のため、
            OnlySts.STSOnly_M();

            // Debug
            Logging.MyDebugSQLTrace("★ : " +
                MethodBase.GetCurrentMethod().DeclaringType.FullName +
                "." + MethodBase.GetCurrentMethod().Name +
                Logging.GetParametersString(MethodBase.GetCurrentMethod().GetParameters()));

            // AccountControllerのメアド検証の再送で利用するため。
            // UsersAdminControllerではチェックしている。

            try
            {
                // **その人が持つクライアントを、先に控える**（#294）。
                //   **登録の行は下で消える**（mem は `DeleteByOwner`、DB は外部キー）ので、消す前に読む。
                List<string> ownedClientIds = Saml2OAuth2DataProvider.GetByOwner(user.Id)
                    .Select(x => x.ClientID).ToList();

                // ユーザの論理削除
                switch (Config.UserStoreType)
                {
                    case EnumUserStoreType.Memory:

                        // ユーザを削除
                        CmnStore._users.Remove(CmnStore._users.First(x => x.Id == user.Id));
                        // ユーザの関連情報を削除
                        CmnStore._userRoleMap.RemoveAll(x => x.Item1 == user.Id);

                        // **sub の対応表も消す**（#151 の段階 2）。
                        //   **DB では外部キー（ON DELETE CASCADE）が消す**ので、mem だけ。
                        SubjectIdProvider.DeleteByUserId(user.Id);

                        // **その人のクライアント登録も消す**（#307 の段階 5-a）。
                        //   **DB では外部キー（OwnerUserId → Users.Id の ON DELETE CASCADE）が消す**
                        //   ので、**ここも mem だけ**である（上の sub と同じ事情）。
                        //
                        //   **この不整合は、段階 5-a より前から在った** —
                        //   **旧い外部キー（Saml2OAuth2Data.ClientID → Users.ClientID）も
                        //   ON DELETE CASCADE** で、**DB では消えて、mem では残っていた。**
                        //   **1 利用者 n クライアントになり、`RT-307.3` の (6) が
                        //   正面から当たるので、ここで揃えた。**
                        Saml2OAuth2DataProvider.DeleteByOwner(user.Id);

                        // **セッション × クライアントの台帳も消す**（#310 の段階 1）。
                        //   **DB では外部キー（UserId → Users.Id の ON DELETE CASCADE）が消す**
                        //   ので、**ここも mem だけ**である（上の 2 つと同じ事情）。
                        SessionClientProvider.DeleteByUser(user.Id);

                        // **その人の同意も消す**（#294）。
                        //   **DB では外部キー（UserId → Users.Id の ON DELETE CASCADE）が消す**
                        //   ので、**ここも mem だけ**である（上の 3 つと同じ事情）。
                        ConsentProvider.DeleteByUser(user.Id);

                        // **メアド変更の確認待ち（新しいメアド）も消す**（#294）。
                        //   **外部キーが無い**ので、mem でも DB でも残っていた（DB は下で消す）。
                        CustomizedConfirmationProvider.GetInstance().DeleteCustomizedConfirmationData(user.Id);

                        break;

                    case EnumUserStoreType.SqlServer:
                    case EnumUserStoreType.ODPManagedDriver:
                    case EnumUserStoreType.PostgreSQL: // DMBMS Provider

                        using (IDbConnection cnn = DataAccess.CreateConnection())
                        {
                            cnn.Open();
                            using (IDbTransaction tr = cnn.BeginTransaction())
                            {
                                switch (Config.UserStoreType)
                                {
                                    case EnumUserStoreType.SqlServer:

                                        // ユーザの関連情報を削除（**子を親より先に**。以前は親の後で、CASCADE の後の空振りだった）
                                        cnn.Execute("DELETE FROM [UserRoles]  WHERE [UserId] = @UserId", new { UserId = user.Id }, tr);
                                        cnn.Execute("DELETE FROM [UserLogins] WHERE [UserId] = @UserId", new { UserId = user.Id }, tr);
                                        cnn.Execute("DELETE FROM [UserClaims] WHERE [UserId] = @UserId", new { UserId = user.Id }, tr);
                                        cnn.Execute("DELETE FROM [CustomizedConfirmation] WHERE [UserId] = @UserId", new { UserId = user.Id }, tr);

                                        // ユーザの情報を削除
                                        cnn.Execute("DELETE FROM [Users] WHERE [Id] = @UserId", new { UserId = user.Id }, tr);

                                        break;

                                    case EnumUserStoreType.ODPManagedDriver:

                                        // ユーザの関連情報を削除（子を親より先に）
                                        cnn.Execute("DELETE FROM \"UserRoles\"  WHERE \"UserId\" = :UserId", new { UserId = user.Id }, tr);
                                        cnn.Execute("DELETE FROM \"UserLogins\" WHERE \"UserId\" = :UserId", new { UserId = user.Id }, tr);
                                        cnn.Execute("DELETE FROM \"UserClaims\" WHERE \"UserId\" = :UserId", new { UserId = user.Id }, tr);
                                        cnn.Execute("DELETE FROM \"CustomizedConfirmation\" WHERE \"UserId\" = :UserId", new { UserId = user.Id }, tr);

                                        // ユーザの情報を削除
                                        cnn.Execute("DELETE FROM \"Users\" WHERE \"Id\" = :UserId", new { UserId = user.Id }, tr);

                                        break;

                                    case EnumUserStoreType.PostgreSQL:

                                        // ユーザの関連情報を削除（子を親より先に）
                                        cnn.Execute("DELETE FROM \"userroles\"  WHERE \"userid\" = @UserId", new { UserId = user.Id }, tr);
                                        cnn.Execute("DELETE FROM \"userlogins\" WHERE \"userid\" = @UserId", new { UserId = user.Id }, tr);
                                        cnn.Execute("DELETE FROM \"userclaims\" WHERE \"userid\" = @UserId", new { UserId = user.Id }, tr);
                                        cnn.Execute("DELETE FROM \"customizedconfirmation\" WHERE \"userid\" = @UserId", new { UserId = user.Id }, tr);

                                        // ユーザの情報を削除
                                        cnn.Execute("DELETE FROM \"users\" WHERE \"id\" = @UserId", new { UserId = user.Id }, tr);

                                        break;
                                }

                                tr.Commit();
                            }
                        }

                        break;
                }

                // **その人が持っていたクライアントへの同意を、全利用者の分消す**（#294）。
                //   **同意の ClientID には外部キーが無い**ので、ほかの利用者の同意が残っていた。
                //   **管理画面でクライアントを消すときと同じ扱いにする**（`ManageController.OAuth2Data`）。
                //   **利用者を消せた後に回す**（以前は先に回していて、削除が失敗しても同意は戻らなかった）。
                foreach (string clientId in ownedClientIds)
                {
                    ConsentProvider.RevokeByClient(clientId);
                }

                Logging.MyOperationTrace(string.Format("{0}({1}) was deleted.", user.Id, user.UserName));
            }
            catch (Exception ex)
            {
                //  **書き込みの失敗は、握らない**（#300）。**ログに書いてから投げ直す。**
                Logging.MySQLLogForEx(ex);
                throw;
            }

            return;
        }

        #endregion

        #endregion
    }
}