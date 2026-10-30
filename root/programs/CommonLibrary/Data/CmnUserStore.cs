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
    /// **mem ストアの入れ物（`CmnStore._users` など）は `List` で、排他していない。**
    /// **開発・試験用**であり、同時に書き込む使い方は想定していない。
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
                                        "    [UnstructuredData], [DeviceToken], [CreatedDate], [PasswordChangeDate])" +
                                        "    VALUES ( " +
                                        "        @Id, @UserName, @NormalizedUserName, @PasswordHash, " +
                                        "        @Email, @NormalizedEmail, @EmailConfirmed, @PhoneNumber, @PhoneNumberConfirmed, " +
                                        "        @LockoutEnabled, @AccessFailedCount, @LockoutEndDateUtc, @SecurityStamp, @TwoFactorEnabled, @TotpAuthenticatorKey, " +
                                        "        @UnstructuredData, @DeviceToken, @CreatedDate, @PasswordChangeDate)", user);

                                    break;

                                case EnumUserStoreType.ODPManagedDriver:

                                    cnn.Execute(
                                        "INSERT INTO \"Users\" ( " +
                                        "    \"Id\", \"UserName\", \"NormalizedUserName\", \"PasswordHash\", " +
                                        "    \"Email\", \"NormalizedEmail\", \"EmailConfirmed\", \"PhoneNumber\", \"PhoneNumberConfirmed\", " +
                                        "    \"LockoutEnabled\", \"AccessFailedCount\", \"LockoutEndDateUtc\", \"SecurityStamp\", \"TwoFactorEnabled\", \"TotpAuthenticatorKey\", " +
                                        "    \"UnstructuredData\", \"DeviceToken\", \"CreatedDate\", \"PasswordChangeDate\")" +
                                        "    VALUES ( " +
                                        "        :Id, :UserName, :NormalizedUserName, :PasswordHash, " +
                                        "        :Email, :NormalizedEmail, :EmailConfirmed, :PhoneNumber, :PhoneNumberConfirmed, " +
                                        "        :LockoutEnabled, :AccessFailedCount, :LockoutEndDateUtc, :SecurityStamp, :TwoFactorEnabled, :TotpAuthenticatorKey, " +
                                        "        :UnstructuredData, :DeviceToken, :CreatedDate, :PasswordChangeDate)",
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
                                            PasswordChangeDate = user.PasswordChangeDate
                                        });

                                    break;

                                case EnumUserStoreType.PostgreSQL:

                                    cnn.Execute(
                                        "INSERT INTO \"users\" ( " +
                                        "    \"id\", \"username\", \"normalizedusername\", \"passwordhash\", " +
                                        "    \"email\", \"normalizedemail\", \"emailconfirmed\", \"phonenumber\", \"phonenumberconfirmed\", " +
                                        "    \"lockoutenabled\", \"accessfailedcount\", \"lockoutenddateutc\", \"securitystamp\", \"twofactorenabled\", \"totpauthenticatorkey\", " +
                                        "    \"unstructureddata\", \"devicetoken\", \"createddate\", \"passwordchangedate\")" +
                                        "    VALUES ( " +
                                        "        @Id, @UserName, @NormalizedUserName, @PasswordHash, " +
                                        "        @Email, @NormalizedEmail, @EmailConfirmed, @PhoneNumber, @PhoneNumberConfirmed, " +
                                        "        @LockoutEnabled, @AccessFailedCount, @LockoutEndDateUtc, @SecurityStamp, @TwoFactorEnabled, @TotpAuthenticatorKey, " +
                                        "        @UnstructuredData, @DeviceToken, @CreatedDate, @PasswordChangeDate)", user);

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

        /// <summary>ユーザー情報を更新</summary>
        /// <param name="user">ApplicationUser</param>
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

                            // ユーザー情報を更新
                            switch (Config.UserStoreType)
                            {
                                case EnumUserStoreType.SqlServer:

                                    cnn.Execute(
                                        "UPDATE [Users] " +
                                        "SET [UserName] = @UserName, [NormalizedUserName] = @NormalizedUserName, [PasswordHash] = @PasswordHash, " +
                                        "    [Email] = @Email, [NormalizedEmail] = @NormalizedEmail, [EmailConfirmed] = @EmailConfirmed, [PhoneNumber] = @PhoneNumber, [PhoneNumberConfirmed] = @PhoneNumberConfirmed, " +
                                        "    [LockoutEnabled] = @LockoutEnabled, [AccessFailedCount] = @AccessFailedCount, [LockoutEndDateUtc] = @LockoutEndDateUtc, " +
                                        "    [SecurityStamp] = @SecurityStamp, [TwoFactorEnabled] = @TwoFactorEnabled, [TotpAuthenticatorKey] = @TotpAuthenticatorKey, " +
                                        "    [UnstructuredData] = @UnstructuredData, " + 
                                        "    [DeviceToken] = @DeviceToken, [PasswordChangeDate] = @PasswordChangeDate " +
                                        "WHERE [Id] = @Id", user);

                                    break;

                                case EnumUserStoreType.ODPManagedDriver:

                                    cnn.Execute(
                                        "UPDATE \"Users\" " +
                                        "SET \"UserName\" = :UserName, \"NormalizedUserName\" = :NormalizedUserName, \"PasswordHash\" = :PasswordHash, " +
                                        "    \"Email\" = :Email, \"NormalizedEmail\" = :NormalizedEmail, \"EmailConfirmed\" = :EmailConfirmed, \"PhoneNumber\" = :PhoneNumber, \"PhoneNumberConfirmed\" = :PhoneNumberConfirmed, " +
                                        "    \"LockoutEnabled\" = :LockoutEnabled, \"AccessFailedCount\" = :AccessFailedCount, \"LockoutEndDateUtc\" = :LockoutEndDateUtc, " +
                                        "    \"SecurityStamp\" = :SecurityStamp, \"TwoFactorEnabled\" = :TwoFactorEnabled, \"TotpAuthenticatorKey\" = :TotpAuthenticatorKey, " +
                                        "    \"UnstructuredData\" = :UnstructuredData, " +
                                        "    \"DeviceToken\" = :DeviceToken, \"PasswordChangeDate\" = :PasswordChangeDate " +
                                        "WHERE \"Id\" = :Id",
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
                                            PasswordChangeDate = user.PasswordChangeDate
                                        });

                                    break;

                                case EnumUserStoreType.PostgreSQL:

                                    cnn.Execute(
                                       "UPDATE \"users\" " +
                                       "SET \"username\" = @UserName, \"normalizedusername\" = @NormalizedUserName, \"passwordhash\" = @PasswordHash, " +
                                       "    \"email\" = @Email, \"normalizedemail\" = @NormalizedEmail, \"emailconfirmed\" = @EmailConfirmed, \"phonenumber\" = @PhoneNumber, \"phonenumberconfirmed\" = @PhoneNumberConfirmed, " +
                                       "    \"lockoutenabled\" = @LockoutEnabled, \"accessfailedcount\" = @AccessFailedCount, \"lockoutenddateutc\" = @LockoutEndDateUtc, " +
                                       "    \"securitystamp\" = @SecurityStamp, \"twofactorenabled\" = @TwoFactorEnabled, \"totpauthenticatorkey\" = @TotpAuthenticatorKey, " +
                                       "    \"unstructureddata\" = @UnstructuredData, " +
                                       "    \"devicetoken\" = @DeviceToken, \"passwordchangedate\" = @PasswordChangeDate " +
                                       "WHERE \"id\" = @Id", user);

                                    break;
                            }

                            // ★ 基本的に、以下のプロパティ更新には、プロパティ更新メソッド（UserManager.XXXX[PropertyName]Async）を使用する。
                            //    この際、ASP.NET Identity Frameworkにより、本メソッド（UserStore.UpdateAsync）が呼び出されることがあるもよう。
                            //    その際、二重実行により二重登録（制約により例外になる）が起き得るので、以下は、ココに実装しないことにした。
                            // await this.UpdateRoles(user, tgtUser);    
                            // await this.UpdateLogins(user, tgtUser);
                            // await this.UpdateClaims(user, tgtUser);
                        }

                        break;
                }

                Logging.MyOperationTrace(string.Format("{0}({1}) was updated.", user.Id, user.UserName));
                //}
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