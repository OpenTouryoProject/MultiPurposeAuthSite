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
//* クラス名        ：AlgPinningTests
//* クラス日本語名  ：RT-129 受ける alg を固定する（C-8）
//*
//* 作成日時        ：－
//* 作成者          ：－
//* 更新履歴        ：－
//*
//*  日時        更新者            内容
//*  ----------  ----------------  -------------------------------------------------
//*  2026/10/02  玄人 幸道         新規（C-8。#129 の段階 1）
//*  2026/10/02  玄人 幸道         RS384 / RS512 を受けるようになったので一覧を直した（#129 の段階 2）
//**********************************************************************************

using System.Text.Json;
using System.Threading.Tasks;

using MultiPurposeAuthSite.Tests.E2E.Infrastructure;

using Xunit;
using Xunit.Abstractions;

namespace MultiPurposeAuthSite.Tests.E2E.Tests.Issues
{
    /// <summary>
    /// RT-129.2 受ける alg を、自分が発行する 2 つに固定する（C-8。#129 の段階 1）。
    /// </summary>
    /// <remarks>
    /// **この認可サーバが署名に使うのは `RS256` / `RS384` / `RS512` / `ES256`** である
    /// （`CmnAccessToken.SupportedAlgs`）。
    /// **以前は、ヘッダの `alg` を読んで検証器を選び、知らない値は RS256 として扱っていた。**
    /// 署名は自分の公開鍵で確かめるので**偽造はできなかった**が、
    /// **サーバが期待する alg を決めていなかった**（アルゴリズム混同の温床。C-8）。
    ///
    /// **このテストは「受ける集合」を固定するためのもの**である。
    /// **#129 の段階 2 以降で `RS384` などを増やすときは、ここも併せて直す**
    /// （黙って増えないようにするのが目的）。
    ///
    /// **署名はそのまま**にして、**ヘッダの `alg` だけを書き換える**
    /// （`kid` は残すので、鍵は引ける。`alg` の判定だけが効く）。
    /// </remarks>
    public class AlgPinningTests : TargetTestBase
    {
        /// <summary>コンストラクタ</summary>
        /// <param name="output">ITestOutputHelper</param>
        public AlgPinningTests(ITestOutputHelper output) : base(output)
        {
        }

        /// <summary>RT-129.2 受ける alg は RS256 / ES256 だけ</summary>
        /// <param name="targetKey">core / netfx</param>
        /// <returns>Task</returns>
        [SkippableTheory]
        [MemberData(nameof(AllTargets))]
        public async Task RT12902_受けるalgはRS256とES256だけ(string targetKey)
        {
            using (IdPClient client = await this.SignedInClientAsync(targetKey))
            {
                TestReport r = this.Report("RT-129.2",
                    "ヘッダの alg を書き換えたトークンを、認可サーバが受け付けない",
                    "**この認可サーバが発行する alg は RS256 / RS384 / RS512 / ES256**で、"
                    + "`jwkcerts` と Discovery もその 2 つを広告している。"
                    + "**以前は、知らない alg を RS256 として扱っていた**（C-8）。"
                    + "**受ける集合を固定する**ことで、"
                    + "**alg の選択肢を増やすとき（#129 の段階 2 以降）に、黙って広がらない**ようにする。",
                    "JWT BCP（RFC 8725）§3.1 / OIDC Core §3.1.3.7 / C-8");

                r.Target(client.Target.DisplayName);

                r.Step("(1) 正規の access_token を取得する（対照）");

                JsonResponse token = await Flows.RunAuthorizationCodeFlowAsync(client);

                Assert.False(string.IsNullOrEmpty(token.AccessToken), "前提: access_token が返ること");

                JsonResponse ok = await client.UserInfoAsync(token.AccessToken);

                r.Verify("正規のトークンでは /userinfo が応答する",
                    ok.IsJson && ok.KindOf("sub") != JsonValueKind.Undefined,
                    "sub を含む JSON", ok.ToString());

                r.Step("(2) ヘッダの alg だけを書き換えて叩く（署名と kid は、そのまま）");

                foreach (string alg in new string[] { "HS256", "ES384", "PS256", "none" })
                {
                    JsonResponse res = await client.UserInfoAsync(
                        Jwks.WithAlg(token.AccessToken, alg));

                    bool accepted = res.IsJson && res.KindOf("sub") != JsonValueKind.Undefined;

                    r.Verify("alg=" + alg + " のトークンでユーザ情報を返さない",
                        !accepted,
                        "返さない",
                        accepted ? "**受理してしまった**" : "拒否した");
                }

                r.Note("**`HS256` は、公開鍵を共通鍵として使わせる古典的な混同**である。"
                    + "**`ES384` / `PS256` は、この実装がまだ発行しない**"
                    + "（#129 の段階 3〜4 で増える予定の値）。"
                    + "**`RS384` / `RS512` は、段階 2 で受けるようになったので、ここから外した**"
                    + "（**増やしたら、このテストの一覧も直すこと**）。");

                r.Note("**`alg=none` は `TC-6.4` でも見ている。**"
                    + "あちらは**ヘッダを丸ごと作り替えて署名を落とす**（`kid` も消える）。"
                    + "**こちらは `kid` を残す**ので、**鍵が引けたうえで alg だけが違う**形になり、"
                    + "**alg の判定そのもの**を測れる。");

                r.Done();
            }
        }
    }
}
