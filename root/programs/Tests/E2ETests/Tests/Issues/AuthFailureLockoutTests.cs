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
//* クラス名        ：AuthFailureLockoutTests
//* クラス日本語名  ：RT-305 認証の失敗を数えて断る（段階 2）
//*
//* 作成日時        ：－
//* 作成者          ：－
//* 更新履歴        ：－
//*
//*  日時        更新者            内容
//*  ----------  ----------------  -------------------------------------------------
//*  2026/10/16  玄人 幸道         新規（#305 の段階 2）
//**********************************************************************************

using System;
using System.Collections.Generic;
using System.Net;
using System.Threading.Tasks;

using MultiPurposeAuthSite.Tests.E2E.Infrastructure;
using MultiPurposeAuthSite.Tests.E2E.Tests.Extended;

using Xunit;
using Xunit.Abstractions;

namespace MultiPurposeAuthSite.Tests.E2E.Tests.Issues
{
    /// <summary>
    /// RT-305（段階 2）. **認証の失敗を数えて、一定回数で一定時間断る**（#305）。
    /// </summary>
    /// <remarks>
    /// | 鍵 | 何の失敗か | 測るケース |
    /// |---|---|---|
    /// | `device_verify:<利用者>` | **`user_code` の投入**（RFC 8628 §5.2） | **`RT-305.3`** |
    /// | `client:<client_id>` | **クライアント認証** | **`RT-305.4`** |
    ///
    /// **断っていることは、応答では区別できない**（`invalid_client` のまま。教えない）。
    /// **見える形は「正しい資格情報でも通らない」**こと — **それをこの 2 件で測る。**
    ///
    /// **使い捨ての利用者とクライアントで測る。**
    /// **共用のテスト利用者やクライアントを断ると、並行して走る他のテストが落ちる。**
    ///
    /// **既定の通しは、`test.ps1` が `AuthFailureMaxAttempts=20` /
    /// `AuthFailureLockoutSeconds=5` を渡して回る**
    /// （**上限を低くすると、負の経路のケースが共用のクライアントを断ってしまう**。`TESTING.md`）。
    /// **数えない配備（0）では Skip する。**
    /// </remarks>
    public class AuthFailureLockoutTests : TargetTestBase
    {
        /// <summary>コンストラクタ</summary>
        /// <param name="output">ITestOutputHelper</param>
        public AuthFailureLockoutTests(ITestOutputHelper output) : base(output)
        {
        }

        #region RT-305.3

        /// <summary>RT-305.3 user_code を続けて間違えると、その利用者は断られる</summary>
        /// <param name="targetKey">core / netfx</param>
        /// <returns>Task</returns>
        [SkippableTheory]
        [MemberData(nameof(AllTargets))]
        public async Task RT30503_user_codeを続けて間違えると断られる(string targetKey)
        {
            using (IdPClient admin = this.Client(targetKey))
            {
                int max = AuthFailureLockoutTests.SettingOf(admin, "AuthFailureMaxAttempts", 0);
                int lockoutSeconds = AuthFailureLockoutTests.SettingOf(
                    admin, "AuthFailureLockoutSeconds", 300);

                Skip.If(max <= 0, "AuthFailureMaxAttempts が 0（数えない配備）です。");
                Skip.If(30 < lockoutSeconds,
                    "AuthFailureLockoutSeconds が " + lockoutSeconds + " 秒で、待つには長すぎます。");

                await admin.SignInAsAdministratorAsync();
                await UsersAdmin.SkipIfLockedDownAsync(admin);

                string name = "e2e_rt3053_" + Guid.NewGuid().ToString("N").Substring(0, 8);
                string email = name + "@example.com";
                string password = admin.Config.Get("TestUserPWD");

                TestReport r = this.Report("RT-305.3",
                    "`user_code` を続けて間違えると、その利用者は一定時間断られる",
                    "**機器の `user_code` は、画面から人が打ち込む。**"
                    + "**間違えた回数を数えていなかった**ので、**当て続けられた**"
                    + "（`ANALYSIS-IdP.md` の D-13。RFC 8628 §5.2 は制限を要求する）。"
                    + "**断っている間は、正しい `user_code` でも通さない** — "
                    + "**それが「効いている」ことの見え方**である。",
                    "RFC 8628 §5.2 / #305 の段階 2");

                r.Target("POST /device_verify（使い捨ての利用者。上限 " + max
                    + " 回 / " + lockoutSeconds + " 秒）");

                try
                {
                    r.Step("(1) 使い捨ての利用者を作る（共用のテスト利用者を断らないため）");

                    Assert.True(AuthFailureLockoutTests.IsRedirect(
                        await UsersAdmin.CreateAsync(admin, name, email, "User")),
                        "前提: 利用者を作れること");

                    r.Step("(2) 機器 : POST /device_authz で user_code を得る");

                    ClientRegistration reg = Flows.Registration(admin, KnownClients.TestClient3);
                    JsonResponse start = await DeviceAuthorizationTests.StartAsync(admin, reg.ClientId);
                    string userCode = start.String("user_code");

                    Assert.False(string.IsNullOrEmpty(userCode), "前提: user_code が発行されること");

                    using (IdPClient user = this.Client(targetKey))
                    {
                        Assert.True(await user.TrySignInAsync(name, password),
                            "前提: 使い捨ての利用者でサインインできること");

                        r.Step("(3) 間違った user_code を " + max + " 回送る");

                        for (int i = 0; i < max; i++)
                        {
                            bool wrong = await user.SubmitDeviceUserCodeAsync(
                                "wrong" + i.ToString(), true);

                            r.Verify("間違いは受け付けない（" + (i + 1) + " 回目）", !wrong,
                                "受け付けない", wrong ? "**受け付けた**" : "受け付けなかった");
                        }

                        r.Step("(4) 正しい user_code を送っても、断られる");

                        bool duringLockout = await user.SubmitDeviceUserCodeAsync(userCode, true);

                        r.Verify("正しい user_code でも通らない", !duringLockout,
                            "通らない", duringLockout ? "**通ってしまった**" : "通らなかった");

                        r.Step("(5) " + lockoutSeconds + " ＋ 1 秒待つと、また通る");

                        await Task.Delay(TimeSpan.FromSeconds(lockoutSeconds + 1));

                        bool afterLockout = await user.SubmitDeviceUserCodeAsync(userCode, true);

                        r.Verify("待てば通る", afterLockout,
                            "通る", afterLockout ? "通った" : "**通らない（断りが解けていない）**");

                        r.Note("**断りは「その利用者」に効く**（`device_verify:<利用者>`）。"
                            + "**間違えた `user_code` では、どの要求を狙ったか分からない**ので、"
                            + "**投入した人で数えている。**");
                    }
                }
                finally
                {
                    await UsersAdmin.DeleteByUserNameAsync(admin, name);
                }

                r.Done();
            }
        }

        #endregion

        #region RT-305.4

        /// <summary>RT-305.4 クライアント認証を続けて失敗すると断られる</summary>
        /// <param name="targetKey">core / netfx</param>
        /// <returns>Task</returns>
        [SkippableTheory]
        [MemberData(nameof(AllTargets))]
        public async Task RT30504_クライアント認証を続けて失敗すると断られる(string targetKey)
        {
            using (IdPClient admin = this.Client(targetKey))
            {
                int max = AuthFailureLockoutTests.SettingOf(admin, "AuthFailureMaxAttempts", 0);
                int lockoutSeconds = AuthFailureLockoutTests.SettingOf(
                    admin, "AuthFailureLockoutSeconds", 300);

                Skip.If(max <= 0, "AuthFailureMaxAttempts が 0（数えない配備）です。");
                Skip.If(30 < lockoutSeconds,
                    "AuthFailureLockoutSeconds が " + lockoutSeconds + " 秒で、待つには長すぎます。");

                TestReport r = this.Report("RT-305.4",
                    "クライアント認証を続けて失敗すると、その `client_id` は一定時間断られる",
                    "**`client_secret` は何回でも試せた**（`ANALYSIS-IdP.md` の D-13）。"
                    + "**連続した失敗を数え、上限で断る。**"
                    + "**断っている間は、正しい `client_secret` でも通さない。**"
                    + "**応答は従来どおり `invalid_client`** で、"
                    + "**断っていること自体は教えない。**",
                    "#305 の段階 2 / RFC 6749 §5.2（invalid_client）");

                r.Target("POST /revoke（使い捨ての利用者のクライアント登録。上限 " + max
                    + " 回 / " + lockoutSeconds + " 秒）");

                r.Step("(1) 使い捨ての利用者を作り、その利用者でクライアントを登録する");

                await admin.SignInAsAdministratorAsync();
                await UsersAdmin.SkipIfLockedDownAsync(admin);

                string name = "e2e_rt3054_" + Guid.NewGuid().ToString("N").Substring(0, 8);
                string email = name + "@example.com";
                string password = admin.Config.Get("TestUserPWD");

                //  **ロールは Admin**（#299 と同じ事情）。
                //    **クライアント登録の画面（`/Manage/AddSaml2OAuth2Data`）は
                //    `SystemAdmin` か `Admin` でなければ開かない。**
                Assert.True(AuthFailureLockoutTests.IsRedirect(
                    await UsersAdmin.CreateAsync(admin, name, email, "Admin")),
                    "前提: 利用者を作れること");

                try
                {
                    using (IdPClient client = this.Client(targetKey))
                    {
                        Assert.True(await client.TrySignInAsync(name, password),
                            "前提: 使い捨ての利用者でサインインできること");

                        (string ClientId, string ClientSecret) registered =
                            await ManageClientRegistration.RegisterWithSecretAsync(client);

                        string clientId = registered.ClientId;
                        string secret = registered.ClientSecret;

                        Assert.False(string.IsNullOrEmpty(clientId), "前提: クライアントを登録できること");
                        Assert.False(string.IsNullOrEmpty(secret), "前提: client_secret が発行されること");

                        r.Step("(2) 正しい秘密なら通る（断る前の確認）");

                        JsonResponse before = await AuthFailureLockoutTests.RevokeAsync(
                            client, clientId, secret);

                        r.VerifyEqual("HTTP 200", "200", ((int)before.StatusCode).ToString());

                        r.Step("(3) 間違った秘密で " + max + " 回失敗する");

                        for (int i = 0; i < max; i++)
                        {
                            JsonResponse wrong = await AuthFailureLockoutTests.RevokeAsync(
                                client, clientId, "wrong-secret-" + i.ToString());

                            r.VerifyEqual("invalid_client（" + (i + 1) + " 回目）",
                                "invalid_client", wrong.Error);
                        }

                        r.Step("(4) 正しい秘密でも断られる");

                        JsonResponse duringLockout = await AuthFailureLockoutTests.RevokeAsync(
                            client, clientId, secret);

                        r.VerifyEqual("正しい秘密でも invalid_client", "invalid_client", duringLockout.Error);

                        r.Step("(5) " + lockoutSeconds + " ＋ 1 秒待つと、また通る");

                        await Task.Delay(TimeSpan.FromSeconds(lockoutSeconds + 1));

                        JsonResponse afterLockout = await AuthFailureLockoutTests.RevokeAsync(
                            client, clientId, secret);

                        r.VerifyEqual("待てば HTTP 200", "200", ((int)afterLockout.StatusCode).ToString());

                        r.Note("**断りは `client_id` ごと**である。"
                            + "**他のクライアントは影響を受けない。** "
                            + "**使い捨ての利用者で登録している** — "
                            + "**クライアント登録は 1 人 1 件**なので、"
                            + "**共用の利用者で登録すると、`RT-277.1` と登録を奪い合う**"
                            + "（実測で踏んだ。`TESTING.md`）。");
                    }
                }
                finally
                {
                    await UsersAdmin.DeleteByUserNameAsync(admin, name);
                }

                r.Done();
            }
        }

        #endregion

        #region 補助

        /// <summary>この配備の設定値（環境変数が構成ファイルより強い）</summary>
        /// <param name="key">設定キー</param>
        /// <param name="fallback">読めなかったときの値</param>
        /// <returns>値</returns>
        private static int SettingOf(IdPClient client, string key, int fallback)
        {
            string value = Environment.GetEnvironmentVariable(key);

            if (string.IsNullOrEmpty(value))
            {
                value = client.Config.Get(key);
            }

            int parsed = 0;
            return int.TryParse(value ?? "", out parsed) ? parsed : fallback;
        }

        /// <summary>`/revoke` を、指定の資格情報で叩く</summary>
        /// <param name="client">IdPClient</param>
        /// <param name="clientId">client_id</param>
        /// <param name="clientSecret">client_secret</param>
        /// <returns>JsonResponse</returns>
        /// <remarks>
        /// **`/revoke` はクライアント認証だけを見る口**である
        /// （**知らないトークンでも、認証が通れば HTTP 200**。RFC 7009 §2.2）。
        /// **だから「認証が通ったか」だけを測れる。**
        /// </remarks>
        private static Task<JsonResponse> RevokeAsync(
            IdPClient client, string clientId, string clientSecret)
        {
            return client.RevokeAsync(new Dictionary<string, string>()
            {
                { "token", "rt3054-dummy-token" },
                { "client_id", clientId },
                { "client_secret", clientSecret }
            });
        }

        /// <summary>リダイレクトか（UsersAdmin の作成が成功したか）</summary>
        /// <param name="res">応答</param>
        /// <returns>リダイレクトなら true</returns>
        private static bool IsRedirect(System.Net.Http.HttpResponseMessage res)
        {
            return res.StatusCode == HttpStatusCode.Found
                || res.StatusCode == HttpStatusCode.Redirect
                || res.StatusCode == HttpStatusCode.SeeOther;
        }

        #endregion
    }
}
