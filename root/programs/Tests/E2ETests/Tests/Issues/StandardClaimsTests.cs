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
//* クラス名        ：StandardClaimsTests
//* クラス日本語名  ：RT-261 標準クレームのサンプル
//*
//* 作成日時        ：－
//* 作成者          ：－
//* 更新履歴        ：－
//*
//*  日時        更新者            内容
//*  ----------  ----------------  -------------------------------------------------
//*  2026/10/03  玄人 幸道         新規（#261）
//**********************************************************************************

using System.Text.Json;
using System.Threading.Tasks;

using MultiPurposeAuthSite.Tests.E2E.Infrastructure;

using Xunit;
using Xunit.Abstractions;

namespace MultiPurposeAuthSite.Tests.E2E.Tests.Issues
{
    /// <summary>
    /// RT-261 標準クレームのサンプルが、仕様の形で返る（#261）。
    /// </summary>
    /// <remarks>
    /// **この実装は氏名・住所の項目を持たない。**
    /// 入れ物は `UnstructuredData`（JSON）で、**中身は導入する側が決める**という方針である
    /// （`Extensions/Sts/UserClaims.cs` の注記）。
    /// **その方針を変えずに、サンプルを持たせた**のが #261 である。
    ///
    /// | | |
    /// |---|---|
    /// | 仕込み先 | **2 人目のテスト利用者**（`tanaka` ＋ 接尾辞）。`IsDebug` のときだけ |
    /// | 仕込む内容 | `AccountController.SampleUnstructuredData`（OIDC Core 5.1 の標準クレーム） |
    /// | 対応付け | `UserClaimsMapping`（E2E は `test.ps1` が差し込む） |
    ///
    /// **1 人目（既定の利用者）には仕込まない。**
    /// **`RT-230.*` が管理画面から `usd1` / `usd2` を保存する**ので、
    /// **画面は `usd1` / `usd2` しか持たない＝保存のたびに他のキーが消える**ためである。
    /// **測る経路を分けている**（`RT-230.*` は画面から入れた値、こちらは仕込んだ値）。
    /// </remarks>
    public class StandardClaimsTests : TargetTestBase
    {
        /// <summary>コンストラクタ</summary>
        /// <param name="output">ITestOutputHelper</param>
        public StandardClaimsTests(ITestOutputHelper output) : base(output)
        {
        }

        /// <summary>RT-261.1 仕込んだ標準クレームが /userinfo に出る</summary>
        /// <param name="targetKey">core / netfx</param>
        /// <returns>Task</returns>
        [SkippableTheory]
        [MemberData(nameof(AllTargets))]
        public async Task RT26101_標準クレームのサンプルがuserinfoに出る(string targetKey)
        {
            // **2 人目の利用者でサインインする**（仕込み先。#261）。
            using (IdPClient client = await this.SignedInClientAsync(
                targetKey, TestEnv.SecondUserName(targetKey)))
            {
                TestReport r = this.Report("RT-261.1",
                    "仕込んだ標準クレームが、profile / address スコープで /userinfo に出る",
                    "**IdP として何を返せるのかが、触っても分からなかった**（#261）。"
                    + "入力画面は `usd1` / `usd2` の 2 欄で、`UserClaimsMapping` の既定は空だった。"
                    + "**入れ物（`UnstructuredData`）は JSON のまま**にしつつ、"
                    + "**`IsDebug` のときに標準クレームのサンプルを仕込む**ようにした。"
                    + "**雛形の対応付けも、設定ファイルにコメントで示してある。**",
                    "OIDC Core §5.1 / §5.1.1 / §5.4 / #261");

                r.Target("利用者 = " + TestEnv.SecondUserName(targetKey)
                    + "（2 人目。IsDebug のときにサンプルが入る）");

                r.Step("(1) profile と address を要求してトークンを取り、/userinfo を呼ぶ");

                JsonResponse token = await Flows.RunAuthorizationCodeFlowAsync(
                    client, KnownClients.MvcSample, "openid profile address");

                Assert.False(string.IsNullOrEmpty(token.AccessToken), "前提: access_token が返ること");

                JsonResponse userInfo = await client.UserInfoAsync(token.AccessToken);

                r.VerifyEqual("HTTP 200", "200", ((int)userInfo.StatusCode).ToString());

                Skip.If(string.IsNullOrEmpty(userInfo.String("given_name")),
                    "標準クレームのサンプルが入っていない"
                    + "（test.ps1 -Launch で回すこと。対応付けを差し込む）。");

                r.Step("(2) profile のクレームが、仕込んだ値で返る");

                foreach (string[] c in new string[][] {
                    new string[] { "given_name", "Taro" },
                    new string[] { "family_name", "Tanaka" },
                    new string[] { "nickname", "taro" },
                    new string[] { "profile", "https://example.com/taro" },
                    new string[] { "picture", "https://example.com/taro.png" },
                    new string[] { "website", "https://example.com/" },
                    new string[] { "gender", "male" },
                    new string[] { "birthdate", "1990-01-23" },
                    new string[] { "zoneinfo", "Asia/Tokyo" },
                    new string[] { "locale", "ja-JP" } })
                {
                    r.VerifyEqual(c[0], c[1], userInfo.String(c[0]) ?? "（無し）");
                }

                r.Step("(3) updated_at は数値で返る（NumericDate。OIDC Core §5.1）");

                r.VerifyEqual("updated_at の型が数値",
                    JsonValueKind.Number.ToString(), userInfo.KindOf("updated_at").ToString());

                r.VerifyEqual("updated_at の値", "1759449600", userInfo.String("updated_at") ?? "（無し）");

                r.Step("(4) address は、副フィールドを持つオブジェクトで返る（OIDC Core §5.1.1）");

                JsonElement address;

                bool isObject = userInfo.IsJson
                    && userInfo.Json.TryGetProperty("address", out address)
                    && address.ValueKind == JsonValueKind.Object;

                r.Verify("address が JSON オブジェクト", isObject,
                    "オブジェクト", isObject ? "オブジェクト" : "**違う**");

                Assert.True(isObject, "前提: address がオブジェクトで返ること");

                userInfo.Json.TryGetProperty("address", out address);

                foreach (string[] c in new string[][] {
                    new string[] { "formatted", "100-0001 1-1 Chiyoda, Chiyoda-ku, Tokyo, JP" },
                    new string[] { "street_address", "1-1 Chiyoda, Chiyoda-ku" },
                    new string[] { "region", "Tokyo" },
                    new string[] { "postal_code", "100-0001" },
                    new string[] { "country", "JP" } })
                {
                    JsonElement value;
                    string actual = address.TryGetProperty(c[0], out value)
                        ? (value.GetString() ?? "（無し）") : "（無し）";

                    r.VerifyEqual("address." + c[0], c[1], actual);
                }

                r.Step("(5) 入れていないキーは返らない");

                r.Verify("middle_name は返らない（サンプルに入れていない）",
                    string.IsNullOrEmpty(userInfo.String("middle_name")),
                    "返らない",
                    string.IsNullOrEmpty(userInfo.String("middle_name")) ? "返らなかった" : "**返した**");

                r.Note("**`name` と `address.locality` は、ここでは見ない。**"
                    + "雛形の対応付けは、その 2 つを **`usd1` / `usd2`（管理画面で入れられる 2 欄）**へ"
                    + "向けてある。**画面から入れた値が返ることは `RT-230.*` で測る**ので、"
                    + "**サンプルと二重に持たせていない**（#261 の判断）。");

                r.Note("**`preferred_username` / `email` / `phone_number` もサンプルに入れていない。**"
                    + "**`user:` で `ApplicationUser` から直に取れる**ため（#151 の段階 1）。");

                r.Note("**管理画面で入れられるのは `usd1` / `usd2` の 2 欄だけ**である。"
                    + "**このサンプルは、管理画面で保存すると消える**"
                    + "（画面が持たないキーは、読み込みで捨てられ、保存で JSON ごと置き換わる）。"
                    + "**1 人目ではなく 2 人目に仕込んでいるのは、そのため**である。");

                r.Done();
            }
        }
    }
}
