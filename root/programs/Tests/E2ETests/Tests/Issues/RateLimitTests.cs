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
//* クラス名        ：RateLimitTests
//* クラス日本語名  ：RT-305 口ごとのレート制限（段階 3）
//*
//* 作成日時        ：－
//* 作成者          ：－
//* 更新履歴        ：－
//*
//*  日時        更新者            内容
//*  ----------  ----------------  -------------------------------------------------
//*  2026/10/16  玄人 幸道         新規（#305 の段階 3）
//*  2026/10/20  玄人 幸道         Noteの文面を1利用者nクライアントに合わせた（#307の段階5-a-1）
//**********************************************************************************

using System;
using System.Collections.Generic;
using System.Net;
using System.Net.Http;
using System.Threading.Tasks;

using MultiPurposeAuthSite.Tests.E2E.Infrastructure;

using Xunit;
using Xunit.Abstractions;

namespace MultiPurposeAuthSite.Tests.E2E.Tests.Issues
{
    /// <summary>
    /// RT-305（段階 3）. **口ごとのレート制限**（#305）。
    /// </summary>
    /// <remarks>
    /// | 鍵 | 設定 | 測るケース |
    /// |---|---|---|
    /// | `client:<client_id>` | `RateLimitPerClientPermits` | **`RT-305.5`** |
    /// | `ip:<アドレス>` | `RateLimitPerIpPermits` | **`RT-305.6`** |
    ///
    /// **段階 2 は「失敗の回数」、ここは「要求の回数」**である（成否を問わない）。
    /// **断るときは `429` ＋ `Retry-After`**（RFC 6585 §4）。
    ///
    /// **`RT-305.5` は、使い捨てのクライアント登録で測る。**
    /// **共用のクライアントを断ると、並行して走る他のテストが落ちる。**
    ///
    /// **`RT-305.6` は、既定の通しでは Skip する。**
    /// **送信元ごとの上限は、通しの全ケースが `127.0.0.1` を共有する**ため、
    /// **`test.ps1` が 0（制限しない）を渡している。**
    /// **単独で回して測る**（`TESTING.md`）。
    /// </remarks>
    public class RateLimitTests : TargetTestBase
    {
        /// <summary>コンストラクタ</summary>
        /// <param name="output">ITestOutputHelper</param>
        public RateLimitTests(ITestOutputHelper output) : base(output)
        {
        }

        #region RT-305.5

        /// <summary>RT-305.5 クライアントごとの上限を超えると 429 になる</summary>
        /// <param name="targetKey">core / netfx</param>
        /// <returns>Task</returns>
        [SkippableTheory]
        [MemberData(nameof(AllTargets))]
        public async Task RT30505_クライアントごとの上限を超えると429(string targetKey)
        {
            using (IdPClient admin = this.Client(targetKey))
            {
                int permits = RateLimitTests.SettingOf(admin, "RateLimitPerClientPermits", 0);
                int window = RateLimitTests.SettingOf(admin, "RateLimitWindowSeconds", 60);

                Skip.If(permits <= 0, "RateLimitPerClientPermits が 0（制限しない配備）です。");
                Skip.If(1000 < permits,
                    "RateLimitPerClientPermits が " + permits + " 回で、叩き切るには多すぎます。");
                Skip.If(30 < window,
                    "RateLimitWindowSeconds が " + window + " 秒で、待つには長すぎます。");

                TestReport r = this.Report("RT-305.5",
                    "クライアントごとの上限を超えた要求は 429（Retry-After）になる",
                    "**口に対する要求の回数が、どこにも制限されていなかった**"
                    + "（`ANALYSIS-IdP.md` の D-13）。"
                    + "**段階 2 は「失敗の回数」を数えるが、"
                    + "成功する要求を浴びせる形の負荷は止まらない。**"
                    + "**窓の中の要求の回数を数え、超えた分を `429` で断る。**"
                    + "**数えるのは口ごと**なので、**ある口の洪水で別の口は止まらない。**",
                    "#305 の段階 3 / RFC 6585 §4（429 Too Many Requests）");

                r.Target("POST /revoke（使い捨ての利用者のクライアント登録。上限 " + permits
                    + " 回 / " + window + " 秒）");

                r.Step("(1) 使い捨ての利用者を作り、その利用者でクライアントを登録する");

                await admin.SignInAsAdministratorAsync();
                await UsersAdmin.SkipIfLockedDownAsync(admin);

                string name = "e2e_rt3055_" + Guid.NewGuid().ToString("N").Substring(0, 8);
                string email = name + "@example.com";
                string password = admin.Config.Get("TestUserPWD");

                //  **ロールは Admin**（#299 と同じ事情）。
                //    **クライアント登録の画面（`/Manage/AddSaml2OAuth2Data`）は
                //    `SystemAdmin` か `Admin` でなければ開かない。**
                Assert.True(RateLimitTests.IsRedirect(
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

                        r.Step("(2) 上限までは通る（1 回目の確認）");

                        JsonResponse before = await RateLimitTests.RevokeAsync(client, clientId, secret);

                        r.VerifyEqual("HTTP 200", "200", ((int)before.StatusCode).ToString());

                        r.Step("(3) 上限を超えるまで叩く（10 本ずつ並べて、窓の中で叩き切る）");

                        JsonResponse limited = await RateLimitTests.BurstUntilLimitedAsync(
                            client, clientId, secret, permits + 30);

                        r.Verify("429 が返る", limited != null, "429", (limited == null)
                            ? "上限 " + permits + " ＋ 30 回まで叩いても 429 にならなかった" : "429");

                        Assert.NotNull(limited);

                        r.VerifyEqual("HTTP 429", "429", ((int)limited.StatusCode).ToString());

                        string retryAfter = limited.Header("Retry-After");
                        int seconds = 0;

                        r.Verify("Retry-After が付く（秒）",
                            int.TryParse(retryAfter ?? "", out seconds) && 0 < seconds && seconds <= window,
                            "1 〜 " + window + " 秒", retryAfter ?? "（無し）");

                        r.Step("(4) 別の口は止まらない（数えるのは口ごと）");

                        JsonResponse otherEndpoint = await client.IntrospectAsync(
                            new Dictionary<string, string>()
                            {
                                { "token", "rt3055-dummy-token" },
                                { "client_id", clientId },
                                { "client_secret", secret }
                            });

                        r.Verify("/introspect は 429 にならない",
                            (int)otherEndpoint.StatusCode != 429,
                            "429 以外", ((int)otherEndpoint.StatusCode).ToString());

                        r.Step("(5) 窓が変わると、また通る（最大 " + (window + 3) + " 秒待つ）");

                        JsonResponse recovered = await RateLimitTests.WaitUntilAllowedAsync(
                            client, clientId, secret, window + 3);

                        r.Verify("待てば HTTP 200", recovered != null && recovered.StatusCode == HttpStatusCode.OK,
                            "200", (recovered == null)
                                ? "窓が変わっても 429 のままだった" : ((int)recovered.StatusCode).ToString());

                        r.Note("**断りは「口 × クライアント」ごと**である。"
                            + "**他のクライアントも、他の口も、影響を受けない。** "
                            + "**使い捨ての利用者で登録している** — "
                            + "**管理画面が扱うのは、その利用者の 1 件**なので、"
                            + "**共用の利用者で登録すると、同じ `client_id` を"
                            + "他のケースと分け合ってしまう**（実測で踏んだ。"
                            + "**当時は DB 側も 1 人 1 件だった** — "
                            + "**#307 の段階 5-a-1 で、画面だけがこの形になった**）。"
                            + "**窓は固定窓**なので、**境目では瞬間的に上限の 2 倍まで通り得る。**");
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

        #region RT-305.6

        /// <summary>RT-305.6 送信元ごとの上限を超えると 429 になる</summary>
        /// <param name="targetKey">core / netfx</param>
        /// <returns>Task</returns>
        /// <remarks>
        /// **既定の通しでは Skip する**（`test.ps1` が `RateLimitPerIpPermits=0` を渡す）。
        /// **通しの全ケースが `127.0.0.1` を共有する**ので、
        /// **有効にすると、無関係なケースが 429 を受ける。**
        /// **単独で回して測る**（`TESTING.md`）。
        /// </remarks>
        [SkippableTheory]
        [MemberData(nameof(AllTargets))]
        public async Task RT30506_送信元ごとの上限を超えると429(string targetKey)
        {
            using (IdPClient client = this.Client(targetKey))
            {
                int permits = RateLimitTests.SettingOf(client, "RateLimitPerIpPermits", 0);
                int window = RateLimitTests.SettingOf(client, "RateLimitWindowSeconds", 60);

                Skip.If(permits <= 0,
                    "RateLimitPerIpPermits が 0（制限しない配備）です。"
                    + "既定の通しは、全ケースが同じ送信元になるため 0 で回しています。");
                Skip.If(1000 < permits,
                    "RateLimitPerIpPermits が " + permits + " 回で、叩き切るには多すぎます。");
                Skip.If(30 < window,
                    "RateLimitWindowSeconds が " + window + " 秒で、待つには長すぎます。");

                TestReport r = this.Report("RT-305.6",
                    "送信元ごとの上限を超えた要求は 429（Retry-After）になる",
                    "**`client_id` を名乗らない読み出し**（`/jwkcerts` など）**も、"
                    + "無制限に叩けた**（`ANALYSIS-IdP.md` の D-13）。"
                    + "**`client_id` ごとの上限だけでは、"
                    + "`client_id` を毎回変える相手を止められない。**"
                    + "**送信元アドレスごとにも数える。**",
                    "#305 の段階 3 / RFC 6585 §4（429 Too Many Requests）");

                r.Target("GET /jwkcerts（上限 " + permits + " 回 / " + window + " 秒）");

                r.Step("(1) 上限を超えるまで読み出す");

                HttpResponseMessage limited = null;
                int sent = 0;

                for (int i = 0; i < permits + 30 && limited == null; i++)
                {
                    HttpResponseMessage res = await client.GetAsync("/jwkcerts");
                    sent++;

                    if ((int)res.StatusCode == 429)
                    {
                        limited = res;
                    }
                    else
                    {
                        res.Dispose();
                    }
                }

                r.Verify("429 が返る", limited != null, "429",
                    (limited == null) ? sent + " 回叩いても 429 にならなかった" : "429");

                Assert.NotNull(limited);

                using (limited)
                {
                    r.Observe("429 までに要した回数", sent.ToString(),
                        "**上限は " + permits + " 回**（窓の境目を挟むと、これより多くなる）");

                    IEnumerable<string> values = null;
                    string retryAfter = limited.Headers.TryGetValues("Retry-After", out values)
                        ? string.Join(", ", values) : null;

                    int seconds = 0;

                    r.Verify("Retry-After が付く（秒）",
                        int.TryParse(retryAfter ?? "", out seconds) && 0 < seconds && seconds <= window,
                        "1 〜 " + window + " 秒", retryAfter ?? "（無し）");
                }

                r.Note("**この上限は、送信元アドレスで数える。** "
                    + "**リバース プロキシの後ろでは、見えるアドレスがプロキシのものになる**"
                    + "（`CONFIGURATION.md`）。");

                r.Done();
            }
        }

        #endregion

        #region 補助

        /// <summary>リダイレクトか（UsersAdmin の作成が成功したか）</summary>
        /// <param name="res">応答</param>
        /// <returns>リダイレクトなら true</returns>
        private static bool IsRedirect(HttpResponseMessage res)
        {
            return res.StatusCode == HttpStatusCode.Found
                || res.StatusCode == HttpStatusCode.Redirect
                || res.StatusCode == HttpStatusCode.SeeOther;
        }

        /// <summary>この配備の設定値（環境変数が構成ファイルより強い）</summary>
        /// <param name="client">IdPClient</param>
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

        /// <summary>429 が返るまで `/revoke` を叩く（並べて叩く）</summary>
        /// <param name="client">IdPClient</param>
        /// <param name="clientId">client_id</param>
        /// <param name="clientSecret">client_secret</param>
        /// <param name="maxRequests">叩く上限（これを超えたら諦める）</param>
        /// <returns>429 の応答（返らなければ null）</returns>
        /// <remarks>
        /// **窓の中で叩き切る必要がある**（**窓が変わると回数は 0 に戻る**）ので、
        /// **10 本ずつ並べて叩く。**
        /// </remarks>
        private static async Task<JsonResponse> BurstUntilLimitedAsync(
            IdPClient client, string clientId, string clientSecret, int maxRequests)
        {
            const int Parallel = 10;

            for (int sent = 0; sent < maxRequests; sent += Parallel)
            {
                List<Task<JsonResponse>> wave = new List<Task<JsonResponse>>();

                for (int i = 0; i < Parallel; i++)
                {
                    wave.Add(RateLimitTests.RevokeAsync(client, clientId, clientSecret));
                }

                JsonResponse[] responses = await Task.WhenAll(wave);

                foreach (JsonResponse res in responses)
                {
                    if ((int)res.StatusCode == 429)
                    {
                        return res;
                    }
                }
            }

            return null;
        }

        /// <summary>また通るようになるまで待つ</summary>
        /// <param name="client">IdPClient</param>
        /// <param name="clientId">client_id</param>
        /// <param name="clientSecret">client_secret</param>
        /// <param name="waitSeconds">待つ上限（秒）</param>
        /// <returns>通った応答（通らなければ null）</returns>
        /// <remarks>
        /// **窓の境目は、サーバ側の時計で決まる**（こちらからは分からない）。
        /// **だから「通るまで待つ」形で測る**（1 秒ごとに 1 回試す）。
        /// </remarks>
        private static async Task<JsonResponse> WaitUntilAllowedAsync(
            IdPClient client, string clientId, string clientSecret, int waitSeconds)
        {
            for (int i = 0; i < waitSeconds; i++)
            {
                await Task.Delay(TimeSpan.FromSeconds(1));

                JsonResponse res = await RateLimitTests.RevokeAsync(client, clientId, clientSecret);

                if (res.StatusCode == HttpStatusCode.OK)
                {
                    return res;
                }
            }

            return null;
        }

        /// <summary>`/revoke` を、指定の資格情報で叩く</summary>
        /// <param name="client">IdPClient</param>
        /// <param name="clientId">client_id</param>
        /// <param name="clientSecret">client_secret</param>
        /// <returns>JsonResponse</returns>
        /// <remarks>
        /// **`/revoke` は、知らないトークンでも認証が通れば HTTP 200**（RFC 7009 §2.2）。
        /// **だから「通ったか、断られたか」だけを測れる。**
        /// </remarks>
        private static Task<JsonResponse> RevokeAsync(
            IdPClient client, string clientId, string clientSecret)
        {
            return client.RevokeAsync(new Dictionary<string, string>()
            {
                { "token", "rt3055-dummy-token" },
                { "client_id", clientId },
                { "client_secret", clientSecret }
            });
        }

        #endregion
    }
}
