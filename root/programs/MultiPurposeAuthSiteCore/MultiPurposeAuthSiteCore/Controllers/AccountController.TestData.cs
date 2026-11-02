//**********************************************************************************
//* クラス名        ：AccountController
//* クラス日本語名  ：テスト データの作成（テンプレート）
//*
//* 作成日時        ：－
//* 作成者          ：－
//* 更新履歴        ：－
//*
//*  日時        更新者            内容
//*  ----------  ----------------  -------------------------------------------------
//*  2026/11/03  玄人 幸道         新規（Helper から切り出し。#294）
//**********************************************************************************

using MultiPurposeAuthSite.Co;
using MultiPurposeAuthSite.Data;
using MultiPurposeAuthSite.Log;
using MultiPurposeAuthSite.Notifications;
using MultiPurposeAuthSite.Util.IdP;
using MultiPurposeAuthSite.Util.Sts;
using MultiPurposeAuthSite.Util.Test;
using FIDO = MultiPurposeAuthSite.Extensions.FIDO;
using Sts = MultiPurposeAuthSite.Extensions.Sts;
using System;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Touryo.Infrastructure.Public.Str;

namespace MultiPurposeAuthSite.Controllers
{
    // **テスト データの作成**（partial。本体は AccountController.cs）。
    //   **`SeedsTestData` が false の配備（本番）では、何もしない。**
    //   **`UserManager` の呼び方が両版で違うので、利用者を作る処理は各サイトに置く。**
    //   **それを使わない処理は `Util/Test` に置く**（`TestClients`・`TestCredentials`）。
    public partial class AccountController
    {
        /// <summary>テスト データを撒く配備か（IsDebug ＋ TestUserPWD）</summary>
        private static bool SeedsTestData
        {
            get
            {
                return Config.IsDebug
                    && !string.IsNullOrWhiteSpace(Config.TestUserPWD);
            }
        }

        /// <summary>
        /// 2 人目のテスト利用者に仕込む、標準クレームのサンプル（#261）。
        /// </summary>
        /// <remarks>
        /// **OIDC Core 5.1 の標準クレームを、`UnstructuredData`（JSON）に入れた例**である。
        /// **`UserClaimsMapping` で対応付けると、`/userinfo` と id_token に出る**（#230）。
        /// 雛形の対応付けは `_appsettings.json` / `_app.config` にコメントで置いてある。
        ///
        /// **`name` と `address.locality` は、わざと入れていない。**
        /// 雛形の対応付けは、その 2 つを **`usd1` / `usd2`（管理画面で入れられる 2 欄）**に
        /// 向けてある（**画面から入れた値が返ることを E2E で測り続けるため**。`RT-230.*`）。
        ///
        /// **`preferred_username` / `email` / `phone_number` も入れていない。**
        /// **`user:` で `ApplicationUser` から直に取れる**ので、二重に持たない（#151）。
        ///
        /// > **この JSON は、管理画面で保存すると消える。**
        /// > 画面（`ManageAddUnstructuredDataViewModel`）は `usd1` / `usd2` しか持たないので、
        /// > **読み込みで他のキーが捨てられ、保存で JSON ごと置き換わる。**
        /// > **仕込み先を 2 人目にしてあるのは、そのため**である
        /// > （`RT-230.*` は 1 人目の画面を叩く）。
        /// </remarks>
        private const string SampleUnstructuredData =
            "{"
            + "\"given_name\":\"Taro\","
            + "\"family_name\":\"Tanaka\","
            + "\"nickname\":\"taro\","
            + "\"profile\":\"https://example.com/taro\","
            + "\"picture\":\"https://example.com/taro.png\","
            + "\"website\":\"https://example.com/\","
            + "\"gender\":\"male\","
            + "\"birthdate\":\"1990-01-23\","
            + "\"zoneinfo\":\"Asia/Tokyo\","
            + "\"locale\":\"ja-JP\","
            + "\"updated_at\":1759449600,"
            + "\"address\":{"
            + "\"formatted\":\"100-0001 1-1 Chiyoda, Chiyoda-ku, Tokyo, JP\","
            + "\"street_address\":\"1-1 Chiyoda, Chiyoda-ku\","
            + "\"region\":\"Tokyo\","
            + "\"postal_code\":\"100-0001\","
            + "\"country\":\"JP\""
            + "}"
            + "}";

        /// <summary>テスト利用者のメアドのドメイン（#294）</summary>
        /// <remarks>
        /// **RFC 2606 の `example.com` にする**（以前は `@gmail.com` で、実在するドメインだった）。
        /// **テスト利用者は IsDebug のときだけ作られ、そのときはメールを送らない**が、
        /// **DB ストアで作った後に本番の設定へ切り替えると、第三者に届きうる。**
        /// **E2E の `TestEnv.TestUserEmail` も同じ値で揃える。**
        /// </remarks>
        private const string TestUserEmailDomain = "@example.com";

        /// <summary>
        /// この接尾辞のテスト利用者を、初期化済みか（#294）
        /// </summary>
        /// <returns>初期化済みなら true</returns>
        /// <remarks>
        /// **最初に作る利用者（super_tanaka ＋ 接尾辞）が居れば、初期化済みとみなす。**
        /// IsDBMSInitialized が、最初に入れる [Roles] の件数で判定するのと同じ考え方。
        ///
        /// - **ストアに聞く**ので、メモリと DB の両方で使え、起動し直しても答えが変わらない。
        /// - **接尾辞を変えた・DB を共有する後発のサイト**では居ないので、作る（#260）。
        /// - **super_tanaka 自身を消すと、その接尾辞の利用者は全部作り直す**
        ///   （ロールを全部消すと、IsDBMSInitialized が初期化し直すのと同じ）。
        /// </remarks>
        private async Task<bool> IsTestUsersInitialized()
        {
            return await this.UserManager.FindByNameAsync(
                "super_tanaka" + Config.TestUserSuffix) != null;
        }

        /// <summary>
        /// テスト利用者を作る（呼ぶ側が SeedsTestData を確かめる）。
        /// </summary>
        /// <returns>Task</returns>
        /// <remarks>
        /// **名前に接尾辞を付けられる**（`TestUserSuffix`。#260）。**空なら付けない。**
        ///
        /// **E2E は net48 版と net10.0 版を同時に立てて、同じケースを両方に流す。**
        /// **DB ストアでは 1 つの DB を共有する**ため、分けないと
        /// **同じ利用者の属性（`DeviceToken` / `UnstructuredData`）を書き換え合う。**
        ///
        /// **この接尾辞の利用者が初期化済みなら、何もしない**（IsTestUsersInitialized。#294）。
        /// **接尾辞を変えても、DB を作り直さなくてよい**（#260）。
        /// **デバッグで消したテスト利用者を、起動し直しても戻さない**（#294）。
        /// </remarks>
        private async Task CreateTestUsers()
        {
            if (await this.IsTestUsersInitialized())
            {
                // 接尾辞のテスト利用者を、初期化済み
                return;
            }

            // 接尾辞のテスト利用者を、初期化する。
            string password = Config.TestUserPWD;
            string suffix = Config.TestUserSuffix;
            string superName = "super_tanaka" + suffix;
            string normalName = "tanaka" + suffix;

            #region ユーザを作成

            // 管理者ユーザを作成
            if (await this.UserManager.FindByNameAsync(superName) == null)
            {
                ApplicationUser user = ApplicationUser.CreateUser(
                    superName, superName + TestUserEmailDomain, true);

                if ((await this.UserManager.CreateAsync(user, password)).Succeeded)
                {
                    await this.UserManager.AddToRoleAsync(
                        await this.UserManager.FindByNameAsync(superName), Const.Role_User);
                    await this.UserManager.AddToRoleAsync(
                        await this.UserManager.FindByNameAsync(superName), Const.Role_Admin);
                }
            }

            // 一般ユーザを作成
            if (await this.UserManager.FindByNameAsync(normalName) == null)
            {
                ApplicationUser user = ApplicationUser.CreateUser(
                    normalName, normalName + TestUserEmailDomain, true);

                // **標準クレームのサンプルを持たせる**（#261）。
                user.UnstructuredData = SampleUnstructuredData;

                if ((await this.UserManager.CreateAsync(user, password)).Succeeded)
                {
                    await this.UserManager.AddToRoleAsync(
                        await this.UserManager.FindByNameAsync(normalName), Const.Role_User);
                }
            }
            else
            {
                // **既に居る利用者にも、空なら入れる**（#261）。
                //   **ここに来るのは、super_tanaka を消して tanaka だけが残っている場合だけ**
                //   （両方居れば、IsTestUsersInitialized で先に戻る）。
                //   **空のときだけ**なので、利用者が自分で入れた値は上書きしない。
                ApplicationUser user = await this.UserManager.FindByNameAsync(normalName);

                if (user != null
                    && string.IsNullOrEmpty(user.UnstructuredData))
                {
                    user.UnstructuredData = SampleUnstructuredData;
                    await this.UserManager.UpdateAsync(user);
                }
            }
            
            #endregion
        }

        /// <summary>
        /// WebAuthn の資格情報を持つテスト利用者を、まき直す（呼ぶ側が SeedsTestData を確かめる）。
        /// </summary>
        /// <returns>Task</returns>
        /// <remarks>
        /// **その利用者のサインインの度に通す**（#277）。**E2E が途中で資格情報を消す**ので、次のテストの前に戻す。
        /// **サインイン画面を開いただけでは通さない**（#325）。別のテストが開くと、消している最中に作り直していた。
        /// **触るのは専用の利用者（webauthn_tanaka）だけ**なので、
        /// デバッグで他のテスト利用者を触っても戻されない（#294）。
        /// </remarks>
        private async Task SeedWebAuthnTestUser()
        {
            string password = Config.TestUserPWD;

            #region WebAuthn の資格情報（#277）

            //  **専用の利用者に、資格情報を 3 件持たせる。**
            //    **資格情報を作れるのは認証器だけ**なので、**E2E では 1 件も作れない。**
            //    **削除（/Manage/RemoveWebAuthnData）を測るための前提**である（`RT-277.3`）。
            //
            //    **テスト利用者（super_tanaka / tanaka）には付けない。**
            //    **`RT-137.1` / `RT-137.2` が「この利用者は認証器を登録していない」ことを
            //    前提に書かれている**ため。
            //
            //    **何度通っても増えない**（`TestCredentials` が、消えた分だけ作り直す）。
            if (Config.FIDOServerMode == FIDO.EnumFidoType.WebAuthn)
            {
                string webAuthnName = "webauthn_tanaka" + Config.TestUserSuffix;

                if (await this.UserManager.FindByNameAsync(webAuthnName) == null)
                {
                    ApplicationUser user = ApplicationUser.CreateUser(
                        webAuthnName, webAuthnName + TestUserEmailDomain, true);

                    if ((await this.UserManager.CreateAsync(user, password)).Succeeded)
                    {
                        await this.UserManager.AddToRoleAsync(
                            await this.UserManager.FindByNameAsync(webAuthnName), Const.Role_User);
                    }
                }

                if (await this.UserManager.FindByNameAsync(webAuthnName) != null)
                {
                    TestCredentials.Seed(webAuthnName);
                }
            }

            #endregion
        }

        /// <summary>
        /// WebAuthn のテスト利用者でのサインインなら、資格情報をまき直す（#325）。
        /// </summary>
        /// <param name="uid">サインインの画面に入力された値</param>
        /// <returns>Task</returns>
        private async Task SeedWebAuthnTestUserOnSignIn(string uid)
        {
            // **本番（テスト データを撒かない配備）では、何もしない。**
            if (!AccountController.SeedsTestData
                || uid != "webauthn_tanaka" + Config.TestUserSuffix)
            {
                return;
            }

            await _semaphoreSlim.WaitAsync();

            try
            {
                await this.SeedWebAuthnTestUser();
            }
            finally
            {
                _semaphoreSlim.Release();
            }
        }
    }
}
