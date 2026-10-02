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
//*  2026/10/02  玄人 幸道         ES384 / ES512 を発行するようになったので関門を 2 つに分けた（#129 の段階 3）
//*  2026/10/03  玄人 幸道         PS* を発行するようになったので関門を 3 つに分けた（#129 の段階 4）
//**********************************************************************************

using System.Text.Json;
using System.Threading.Tasks;

using MultiPurposeAuthSite.Tests.E2E.Infrastructure;

using Xunit;
using Xunit.Abstractions;

namespace MultiPurposeAuthSite.Tests.E2E.Tests.Issues
{
    /// <summary>
    /// RT-129.2 受ける alg を、自分が発行するものに固定する（C-8。#129 の段階 1）。
    /// </summary>
    /// <remarks>
    /// **この認可サーバが署名に使うのは `SigningKeys.SupportedAlgs`** である
    /// （`RS256` / `RS384` / `RS512` / `PS256` / `PS384` / `PS512` / `ES256` / `ES384` / `ES512`）。
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

        /// <summary>RT-129.2 受ける alg は、自分が発行するものだけ</summary>
        /// <param name="targetKey">core / netfx</param>
        /// <returns>Task</returns>
        [SkippableTheory]
        [MemberData(nameof(AllTargets))]
        public async Task RT12902_受けるalgは自分が発行するものだけ(string targetKey)
        {
            using (IdPClient client = await this.SignedInClientAsync(targetKey))
            {
                TestReport r = this.Report("RT-129.2",
                    "ヘッダの alg を書き換えたトークンを、認可サーバが受け付けない",
                    "**この認可サーバが発行する alg は `SigningKeys.SupportedAlgs`** で、"
                    + "`jwkcerts` と Discovery も、その一覧から作っている。"
                    + "**以前は、知らない alg を RS256 として扱っていた**（C-8）。"
                    + "**関門は 3 つ**で、**発行しない alg は即、拒否**し、"
                    + "**発行する alg でも、鍵（kty / crv）が合わなければ拒否**し（#129 の段階 3）、"
                    + "**鍵まで合っても、署名が合わなければ拒否**する（#129 の段階 4）。",
                    "JWT BCP（RFC 8725）§3.1 / OIDC Core §3.1.3.7 / C-8");

                r.Target(client.Target.DisplayName);

                r.Step("(1) 正規の access_token を取得する（対照）");

                JsonResponse token = await Flows.RunAuthorizationCodeFlowAsync(client);

                Assert.False(string.IsNullOrEmpty(token.AccessToken), "前提: access_token が返ること");

                JsonResponse ok = await client.UserInfoAsync(token.AccessToken);

                r.Verify("正規のトークンでは /userinfo が応答する",
                    ok.IsJson && ok.KindOf("sub") != JsonValueKind.Undefined,
                    "sub を含む JSON", ok.ToString());

                r.Step("(2) **発行しない alg** に書き換えて叩く（署名と kid は、そのまま）");

                foreach (string alg in new string[] { "HS256", "HS384", "none" })
                {
                    JsonResponse res = await client.UserInfoAsync(
                        Jwks.WithAlg(token.AccessToken, alg));

                    bool accepted = res.IsJson && res.KindOf("sub") != JsonValueKind.Undefined;

                    r.Verify("alg=" + alg + " のトークンでユーザ情報を返さない",
                        !accepted,
                        "返さない",
                        accepted ? "**受理してしまった**" : "拒否した");
                }

                r.Step("(3) **発行するが、鍵の種類が合わない alg** に書き換えて叩く（#129 の段階 3）");

                foreach (string alg in new string[] { "ES256", "ES384", "ES512" })
                {
                    JsonResponse res = await client.UserInfoAsync(
                        Jwks.WithAlg(token.AccessToken, alg));

                    bool accepted = res.IsJson && res.KindOf("sub") != JsonValueKind.Undefined;

                    r.Verify("alg=" + alg + "（RSA の kid なのに EC の alg）でユーザ情報を返さない",
                        !accepted,
                        "返さない",
                        accepted ? "**受理してしまった**" : "拒否した");
                }

                r.Step("(4) **鍵までは合うが、パディングが違う alg** に書き換えて叩く（#129 の段階 4）");

                foreach (string alg in new string[] { "PS256", "PS384", "PS512" })
                {
                    JsonResponse res = await client.UserInfoAsync(
                        Jwks.WithAlg(token.AccessToken, alg));

                    bool accepted = res.IsJson && res.KindOf("sub") != JsonValueKind.Undefined;

                    r.Verify("alg=" + alg + "（RSA の鍵は合うが PKCS #1 v1.5 の署名）でユーザ情報を返さない",
                        !accepted,
                        "返さない",
                        accepted ? "**受理してしまった**" : "拒否した");
                }

                r.Note("**`HS256` / `HS384` は、公開鍵を共通鍵として使わせる古典的な混同**である。"
                    + "**`RS384` / `RS512` は段階 2、`ES384` / `ES512` は段階 3、`PS*` は段階 4 で"
                    + "発行するようになった**ので、**(2) の一覧からは外した**"
                    + "（**増やしたら、このテストの一覧も直すこと**）。");

                r.Note("**(2) 〜 (4) は、別々の関門である。** トークンは `RS256` で署名してあり、"
                    + "`kid` は RSA の鍵を指す。"
                    + "**(2)** は `SupportedAlgs` に無いので**即、拒否**。"
                    + "**(3)** は `ES*` なので**鍵の種類（`kty`）が食い違って拒否**。"
                    + "**(4)** は `PS*` で**鍵は同じ RSA の 1 本**だから `kty` では弾けず、"
                    + "**パディング（RSASSA-PSS）が違うので署名の検証で落ちる。**"
                    + "**`ES*` 同士の食い違い（曲線）は `RT-129.5`**、"
                    + "**`PS*` が正しく通ること自体は `RT-129.7`** で見る。");

                r.Note("**`alg=none` は `TC-6.4` でも見ている。**"
                    + "あちらは**ヘッダを丸ごと作り替えて署名を落とす**（`kid` も消える）。"
                    + "**こちらは `kid` を残す**ので、**鍵が引けたうえで alg だけが違う**形になり、"
                    + "**alg の判定そのもの**を測れる。");

                r.Done();
            }
        }
    }
}
