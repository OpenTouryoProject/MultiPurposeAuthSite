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
//* クラス名        ：UserClaimsTests
//* クラス日本語名  ：RT-230 profile / address のクレームを設定で対応付ける（#230）
//*
//* 作成日時        ：－
//* 作成者          ：－
//* 更新履歴        ：－
//*
//*  日時        更新者            内容
//*  ----------  ----------------  -------------------------------------------------
//*  2026/09/25  玄人 幸道         新規（#230）
//**********************************************************************************

using System;
using System.Collections.Generic;
using System.Text.Json;
using System.Threading.Tasks;

using MultiPurposeAuthSite.Tests.E2E.Infrastructure;

using Xunit;
using Xunit.Abstractions;

namespace MultiPurposeAuthSite.Tests.E2E.Tests.Issues
{
    /// <summary>
    /// RT-230. `profile` / `address` のクレームを、設定の対応付けで返す。
    /// </summary>
    /// <remarks>
    /// **この実装は氏名・住所の項目を持たない。**
    /// 利用者情報の入れ物は `ApplicationUser.UnstructuredData`（JSON）で、
    /// **中身は導入する側が決める**ため、項目を作り込まず、
    /// **「どのキーを、どのクレームとして返すか」だけを設定で持つ**（`UserClaimsMapping`）。
    ///
    /// **`test.ps1 -Launch` が、両サイトへ同じ対応付けを差し込む**（環境変数）。
    ///   name → usd1 / address.locality → usd2 / preferred_username → user:UserName
    ///
    /// usd1 / usd2 は `/Manage/AddUnstructuredData` から入れられる値なので、
    /// **テストは画面から値を入れて、`/userinfo` に出ることを確かめられる。**
    ///
    /// **値は既定の利用者に入るので、最後に消す**（他のテストへ持ち越さない）。
    /// </remarks>
    public class UserClaimsTests : TargetTestBase
    {
        /// <summary>コンストラクタ</summary>
        /// <param name="output">ITestOutputHelper</param>
        public UserClaimsTests(ITestOutputHelper output) : base(output)
        {
        }

        /// <summary>対応付けが差し込まれていなければ Skip する</summary>
        /// <param name="client">IdPClient</param>
        /// <returns>Task</returns>
        private static async Task SkipIfNotMappedAsync(IdPClient client)
        {
            JsonResponse res = await client.GetJsonAsync("/.well-known/openid-configuration");

            Skip.IfNot(res.IsJson
                && res.Json.TryGetProperty("claims_supported", out JsonElement claims)
                && claims.ToString().Contains("\"name\""),
                "クレームの対応付けが差し込まれていない（test.ps1 -Launch で回すこと）。");
        }

        /// <summary>RT-230.1 対応付けたクレームが /userinfo に出る</summary>
        /// <param name="targetKey">core / netfx</param>
        /// <returns>Task</returns>
        [SkippableTheory]
        [MemberData(nameof(AllTargets))]
        public async Task RT23001_対応付けたクレームがuserinfoに出る(string targetKey)
        {
            using (IdPClient client = await this.SignedInClientAsync(targetKey))
            {
                await UserClaimsTests.SkipIfNotMappedAsync(client);

                TestReport r = this.Report("RT-230.1",
                    "UserClaimsMapping で対応付けたクレームが、profile / address スコープで /userinfo に出る",
                    "**`scopes_supported` に profile / address が載っているのに、空実装で何も返らなかった**"
                    + "（ANALYSIS-IdP.md の D-7）。RP から見ると「要求できるのに返ってこない」状態だった。"
                    + "**この実装は氏名・住所の項目を持たない**ので、"
                    + "入れ物（UnstructuredData）の**どのキーをどのクレームとして返すかを設定で対応付ける**。",
                    "OIDC Core §5.1 / §5.1.1 / §5.4 / #230");

                string fullName = "E2E-" + Guid.NewGuid().ToString("N").Substring(0, 8);
                string locality = "Yokohama-" + Guid.NewGuid().ToString("N").Substring(0, 4);

                r.Target("name ← usd1 / address.locality ← usd2 / preferred_username ← user:UserName");

                r.Step("(1) 利用者 : 画面から非構造化データを入れる（POST /Manage/AddUnstructuredData）");

                bool saved = await client.SetUnstructuredDataAsync(fullName, locality);

                r.Verify("非構造化データを保存できる", saved, "保存できる", saved ? "保存した" : "**失敗**");

                Assert.True(saved, "前提: 非構造化データを保存できること");

                try
                {
                    r.Step("(2) クライアント : profile と address を要求してトークンを取る");

                    JsonResponse token = await Flows.RunAuthorizationCodeFlowAsync(
                        client, KnownClients.MvcSample, "openid profile address");

                    Assert.False(string.IsNullOrEmpty(token.AccessToken), "前提: access_token が返ること");

                    r.Step("(3) /userinfo を呼ぶ");

                    JsonResponse userInfo = await client.UserInfoAsync(token.AccessToken);

                    r.VerifyEqual("HTTP 200", "200", ((int)userInfo.StatusCode).ToString());

                    r.VerifyEqual("name が、usd1 に入れた値で返る", fullName, userInfo.String("name") ?? "（無し）");

                    r.VerifyEqual("preferred_username が、UserName で返る",
                        TestEnv.TestUserName, userInfo.String("preferred_username") ?? "（無し）");

                    r.Step("(4) address が、副フィールドを持つオブジェクトで返る");

                    string addressLocality = "（無し）";

                    if (userInfo.IsJson
                        && userInfo.Json.TryGetProperty("address", out JsonElement address)
                        && address.ValueKind == JsonValueKind.Object
                        && address.TryGetProperty("locality", out JsonElement value))
                    {
                        addressLocality = value.GetString();
                    }

                    r.VerifyEqual("address.locality が、usd2 に入れた値で返る", locality, addressLocality);

                    r.Note("**address は JSON オブジェクト**（OIDC Core §5.1.1）。"
                        + "設定に `address.locality` と書くと、副フィールドとして組み立てる。");

                    r.Done();
                }
                finally
                {
                    // **後片付け。** 既定の利用者に入るので、他のテストへ持ち越さない。
                    await client.SetUnstructuredDataAsync("", "");
                }
            }
        }

        /// <summary>RT-230.2 スコープを要求しなければ返らない</summary>
        /// <param name="targetKey">core / netfx</param>
        /// <returns>Task</returns>
        [SkippableTheory]
        [MemberData(nameof(AllTargets))]
        public async Task RT23002_スコープを要求しなければ返らない(string targetKey)
        {
            using (IdPClient client = await this.SignedInClientAsync(targetKey))
            {
                await UserClaimsTests.SkipIfNotMappedAsync(client);

                TestReport r = this.Report("RT-230.2",
                    "profile / address を要求しなければ、対応付けたクレームは返らない",
                    "**どのクレームがどのスコープに属するかは、仕様が決めている**（OIDC Core §5.4）。"
                    + "設定にはスコープを書かせず、**クレーム名から仕様の表で引く。**"
                    + "対応付けただけで無条件に返すと、**利用者が許可していない情報を渡す**ことになる。",
                    "OIDC Core §5.4 / #230");

                string fullName = "E2E-" + Guid.NewGuid().ToString("N").Substring(0, 8);

                r.Step("(1) 利用者 : 画面から非構造化データを入れる");

                Assert.True(await client.SetUnstructuredDataAsync(fullName, "Kawasaki"),
                    "前提: 非構造化データを保存できること");

                try
                {
                    r.Step("(2) openid email だけを要求してトークンを取り、/userinfo を呼ぶ");

                    JsonResponse token = await Flows.RunAuthorizationCodeFlowAsync(
                        client, KnownClients.MvcSample, "openid email");

                    JsonResponse userInfo = await client.UserInfoAsync(token.AccessToken);

                    r.VerifyEqual("HTTP 200", "200", ((int)userInfo.StatusCode).ToString());

                    string name = userInfo.String("name");

                    r.Verify("name は返らない", string.IsNullOrEmpty(name),
                        "返らない", string.IsNullOrEmpty(name) ? "返らなかった" : "**返した**");

                    bool hasAddress = userInfo.IsJson
                        && userInfo.Json.TryGetProperty("address", out JsonElement _);

                    r.Verify("address も返らない", !hasAddress,
                        "返らない", hasAddress ? "**返した**" : "返らなかった");

                    r.Verify("email は返る（要求したので）",
                        !string.IsNullOrEmpty(userInfo.String("email")),
                        "返る", string.IsNullOrEmpty(userInfo.String("email")) ? "**返らない**" : "返った");

                    r.Done();
                }
                finally
                {
                    await client.SetUnstructuredDataAsync("", "");
                }
            }
        }

        /// <summary>RT-230.3 値が空なら、そのクレームは返らない</summary>
        /// <param name="targetKey">core / netfx</param>
        /// <returns>Task</returns>
        [SkippableTheory]
        [MemberData(nameof(AllTargets))]
        public async Task RT23003_値が空ならクレームを返さない(string targetKey)
        {
            using (IdPClient client = await this.SignedInClientAsync(targetKey))
            {
                await UserClaimsTests.SkipIfNotMappedAsync(client);

                TestReport r = this.Report("RT-230.3",
                    "対応付けた先が空なら、そのクレームは返さない",
                    "**空の項目を並べても RP の役に立たない**（`\"name\": \"\"` を返すより、返さない方が正しい）。"
                    + "入れ物の中身は導入する側が決めるので、**一部だけ埋まっている状態が普通にある。**",
                    "OIDC Core §5.3.2 / #230");

                r.Step("(1) 利用者 : usd1 を空、usd2 だけ入れる");

                string locality = "Chiba-" + Guid.NewGuid().ToString("N").Substring(0, 4);

                Assert.True(await client.SetUnstructuredDataAsync("", locality),
                    "前提: 非構造化データを保存できること");

                try
                {
                    r.Step("(2) profile と address を要求して /userinfo を呼ぶ");

                    JsonResponse token = await Flows.RunAuthorizationCodeFlowAsync(
                        client, KnownClients.MvcSample, "openid profile address");

                    JsonResponse userInfo = await client.UserInfoAsync(token.AccessToken);

                    string name = userInfo.String("name");

                    r.Verify("空の name は返らない（キーごと出さない）", string.IsNullOrEmpty(name),
                        "返らない", string.IsNullOrEmpty(name) ? "返らなかった" : "**返した**");

                    string addressLocality = "（無し）";

                    if (userInfo.IsJson
                        && userInfo.Json.TryGetProperty("address", out JsonElement address)
                        && address.ValueKind == JsonValueKind.Object
                        && address.TryGetProperty("locality", out JsonElement value))
                    {
                        addressLocality = value.GetString();
                    }

                    r.VerifyEqual("入っている address.locality は返る", locality, addressLocality);

                    r.Done();
                }
                finally
                {
                    await client.SetUnstructuredDataAsync("", "");
                }
            }
        }

        /// <summary>RT-230.4 claims_supported が対応付けから作られる</summary>
        /// <param name="targetKey">core / netfx</param>
        /// <returns>Task</returns>
        [SkippableTheory]
        [MemberData(nameof(AllTargets))]
        public async Task RT23004_claims_supportedが対応付けから作られる(string targetKey)
        {
            using (IdPClient client = this.Client(targetKey))
            {
                await UserClaimsTests.SkipIfNotMappedAsync(client);

                TestReport r = this.Report("RT-230.4",
                    "Discovery の claims_supported に、対応付けたクレームが載る",
                    "**固定の一覧にすると、設定と食い違う**（#228 の 13 : profile / address のクレームが"
                    + "`claims_supported` に無かった）。**対応付けから作れば、設定を変えても追随する。**"
                    + "`address.<副フィールド>` は、クレームとしては `address` ひとつにまとめる。",
                    "OIDC Discovery / #228 / #230");

                r.Step("(1) Discovery を読む");

                JsonResponse res = await client.GetJsonAsync("/.well-known/openid-configuration");

                Assert.True(res.IsJson, "前提: Discovery が JSON であること");

                List<string> claims = new List<string>();

                if (res.Json.TryGetProperty("claims_supported", out JsonElement supported)
                    && supported.ValueKind == JsonValueKind.Array)
                {
                    foreach (JsonElement item in supported.EnumerateArray())
                    {
                        claims.Add(item.GetString());
                    }
                }

                r.Verify("name が載る（対応付けたので）", claims.Contains("name"),
                    "載る", claims.Contains("name") ? "載った" : "**無い**");

                r.Verify("preferred_username が載る", claims.Contains("preferred_username"),
                    "載る", claims.Contains("preferred_username") ? "載った" : "**無い**");

                r.Verify("address が載る（副フィールドではなく address）", claims.Contains("address"),
                    "載る", claims.Contains("address") ? "載った" : "**無い**");

                r.Verify("address.locality は載らない（クレーム名ではない）",
                    !claims.Contains("address.locality"),
                    "載らない", claims.Contains("address.locality") ? "**載った**" : "載らなかった");

                r.Verify("元からの項目（sub / email）も残る",
                    claims.Contains("sub") && claims.Contains("email"),
                    "残る", claims.Contains("sub") && claims.Contains("email") ? "残った" : "**消えた**");

                r.Observe("claims_supported", string.Join(" ", claims), "対応付けと固定の項目の合成。");

                r.Done();
            }
        }
    }
}
