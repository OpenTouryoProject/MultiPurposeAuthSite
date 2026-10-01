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
//* クラス名        ：SubjectTypesTests
//* クラス日本語名  ：RT-151 subject_types の既定値（public）
//*
//* 作成日時        ：－
//* 作成者          ：－
//* 更新履歴        ：－
//*
//*  日時        更新者            内容
//*  ----------  ----------------  -------------------------------------------------
//*  2026/10/01  玄人 幸道         新規（#151 の段階 4）
//**********************************************************************************

using System;
using System.Threading.Tasks;

using MultiPurposeAuthSite.Tests.E2E.Infrastructure;

using Xunit;
using Xunit.Abstractions;

namespace MultiPurposeAuthSite.Tests.E2E.Tests.Issues
{
    /// <summary>
    /// RT-151.1 / .2 `subject_types` の既定値（#151 の段階 4）。
    /// </summary>
    /// <remarks>
    /// **既定は `uname`（独自値）から `public` に変わった。**
    ///
    /// `uname` は **`sub` に利用者名をそのまま入れる。**
    /// 以前は「利用者名＝メアド」だったので、**メアドが全ての RP に渡っていた。**
    /// `sub` は「その RP の中で利用者を指す識別子」であって、表示用の属性ではない。
    /// **利用者名が要る RP は `preferred_username`**（`UserClaimsMapping`。段階 1）を使う。
    ///
    /// **測るには、新しい client_id が要る。**
    /// 発行済みの `sub` は**対応表から返る**ので（段階 2）、
    /// **既に使った client_id では「既定が変わったこと」が見えない**
    /// （それこそが段階 2 の目的である）。
    /// そこで **TestClient_6 / TestClient_7**（test.ps1 -Launch が差し込む）を使う。
    /// </remarks>
    public class SubjectTypesTests : TargetTestBase
    {
        /// <summary>コンストラクタ</summary>
        /// <param name="output">ITestOutputHelper</param>
        public SubjectTypesTests(ITestOutputHelper output) : base(output)
        {
        }

        /// <summary>RT-151.1 subject_types を書かないクライアントの sub は利用者 ID</summary>
        /// <param name="targetKey">core / netfx</param>
        /// <returns>Task</returns>
        [SkippableTheory]
        [MemberData(nameof(AllTargets))]
        public async Task RT15101_既定のsubは利用者名ではなく利用者ID(string targetKey)
        {
            using (IdPClient client = await this.SignedInClientAsync(targetKey))
            {
                // **TestClient_6 は構成ファイルに無い**（test.ps1 -Launch が差し込む）。
                ClientRegistration reg = Flows.InjectedRegistration(client, KnownClients.TestClient_6);

                TestReport r = this.Report("RT-151.1",
                    "subject_types を書かないクライアントの sub は、利用者名ではなく利用者 ID",
                    "**既定を uname から public に変えた**（#151 の段階 4）。"
                    + "uname は独自値で、**`sub` に利用者名がそのまま入る。**"
                    + "以前は「利用者名＝メアド」だったため、**メアドが全ての RP に渡っていた。**"
                    + "**`sub` は RP の中で利用者を指す識別子**であって、表示用の属性ではない。",
                    "OIDC Core §8（Subject Identifier Types）/ §5.1（preferred_username）/ #151 の段階 4");

                r.Target("client_name=" + KnownClients.TestClient_6 + "（subject_types を書いていない）");

                r.Step("(1) 認可コードを取ってトークンに交換する");

                AuthZResponse authz = await Flows.AuthorizeCodeAsync(
                    client, reg, scope: "openid email", redirectUri: reg.RedirectUri);

                Assert.False(string.IsNullOrEmpty(authz.Code), "前提: 認可コードが返ること");

                JsonResponse token = await Flows.ExchangeCodeAsync(
                    client, reg, authz.Code, redirectUri: reg.RedirectUri);

                Assert.False(string.IsNullOrEmpty(token.AccessToken), "前提: access_token が返ること");

                string sub = Jwt.String(Jwt.Payload(token.AccessToken), "sub");

                r.Step("(2) sub を見る");

                r.Verify("sub が返る", !string.IsNullOrEmpty(sub),
                    "返る", string.IsNullOrEmpty(sub) ? "**返らない**" : "返った（値は伏せる）");

                r.Verify("sub が利用者名ではない（＝ uname ではない）",
                    sub != TestEnv.TestUserName,
                    "利用者名ではない",
                    (sub == TestEnv.TestUserName)
                        ? "**利用者名がそのまま出ている**（既定が uname のまま）" : "利用者名ではない");

                r.Verify("sub がメアドでもない",
                    sub != TestEnv.TestUserEmail,
                    "メアドではない",
                    (sub == TestEnv.TestUserEmail)
                        ? "**メアドが全ての RP に渡っている**" : "メアドではない");

                r.Verify("sub が利用者 ID の形（GUID）である（＝ public）",
                    Guid.TryParse(sub, out Guid _),
                    "GUID",
                    Guid.TryParse(sub, out Guid _) ? "GUID" : "**GUID ではない**");

                r.Step("(3) /userinfo が、その sub から利用者を引けている");

                JsonResponse userinfo = await client.UserInfoAsync(token.AccessToken);

                r.VerifyEqual("HTTP 200", "200", ((int)userinfo.StatusCode).ToString());

                r.VerifyEqual("sub は access_token と同じ", sub, userinfo.String("sub") ?? "（無し）");

                r.Verify("**sub 以外のクレームが返る**（email）",
                    !string.IsNullOrEmpty(userinfo.String("email")),
                    "返る",
                    string.IsNullOrEmpty(userinfo.String("email"))
                        ? "**sub しか返らない**（sub から利用者を引けていない）" : "返った");

                r.Step("(4) もう一度取っても、同じ sub になる");

                AuthZResponse authz2 = await Flows.AuthorizeCodeAsync(
                    client, reg, scope: "openid email", redirectUri: reg.RedirectUri);

                JsonResponse token2 = await Flows.ExchangeCodeAsync(
                    client, reg, authz2.Code, redirectUri: reg.RedirectUri);

                r.VerifyEqual("2 回とも同じ sub",
                    sub, Jwt.String(Jwt.Payload(token2.AccessToken), "sub"));

                r.Note("**RP は `sub` を利用者の主キーとして保存する**ので、"
                    + "**同じ利用者・同じクライアントなら毎回同じ値**でなければならない。"
                    + "**発行した値は対応表に記録される**ので（#151 の段階 2）、"
                    + "**この後で既定を変えても、この値は動かない。**");

                r.Done();
            }
        }

        /// <summary>RT-151.2 public の sub は、クライアントが違っても同じ</summary>
        /// <param name="targetKey">core / netfx</param>
        /// <returns>Task</returns>
        [SkippableTheory]
        [MemberData(nameof(AllTargets))]
        public async Task RT15102_publicのsubはクライアントが違っても同じ(string targetKey)
        {
            using (IdPClient client = await this.SignedInClientAsync(targetKey))
            {
                ClientRegistration six = Flows.InjectedRegistration(client, KnownClients.TestClient_6);
                ClientRegistration seven = Flows.InjectedRegistration(client, KnownClients.TestClient_7);
                ClientRegistration pairwise = Flows.InjectedRegistration(client, KnownClients.TestClient_5);

                TestReport r = this.Report("RT-151.2",
                    "public の sub は、同じ利用者なら RP が違っても同じ（pairwise との対照）",
                    "**public と pairwise の違いは、ここに出る。**"
                    + "public は **RP をまたいで同じ値**なので、**RP 同士が突き合わせられる。**"
                    + "突き合わせを嫌うなら pairwise を選ぶ（#140 の段階 2）。"
                    + "**既定を public にしたので、何も書かなければ「同じ値」になる**"
                    + "（#151 の段階 4）。",
                    "OIDC Core §8（public / pairwise）/ #151 の段階 4");

                r.Target(KnownClients.TestClient_6 + " と " + KnownClients.TestClient_7
                    + "（どちらも subject_types を書いていない）/ "
                    + KnownClients.TestClient_5 + "（pairwise）");

                r.Step("(1) 既定のクライアント 2 つで、それぞれ sub を取る");

                string subSix = await SubjectTypesTests.SubOfAsync(client, six);
                string subSeven = await SubjectTypesTests.SubOfAsync(client, seven);

                r.VerifyEqual("クライアントが違っても同じ sub", subSix, subSeven);

                r.Step("(2) pairwise のクライアントで取る（対照）");

                string subPairwise = await SubjectTypesTests.SubOfAsync(client, pairwise);

                r.Verify("pairwise だけは違う sub",
                    !string.IsNullOrEmpty(subPairwise) && subPairwise != subSix,
                    "違う",
                    (subPairwise == subSix) ? "**同じ**（pairwise になっていない）" : "違う");

                r.Note("**public は「隠さない」選択である。**"
                    + "`sub` は利用者 ID なので、**RP 同士が突き合わせれば同じ人だと分かる。**"
                    + "**それが困る RP には pairwise を登録する。**"
                    + "**uname も「同じ値」になる**が、**値が利用者名（＝個人を示す文字列）である点が違う。**");

                r.Done();
            }
        }

        #region 補助

        /// <summary>認可コード フローを 1 往復して、access_token の sub を返す</summary>
        /// <param name="client">IdPClient</param>
        /// <param name="registration">クライアント</param>
        /// <returns>sub</returns>
        private static async Task<string> SubOfAsync(IdPClient client, ClientRegistration registration)
        {
            AuthZResponse authz = await Flows.AuthorizeCodeAsync(
                client, registration, scope: "openid email", redirectUri: registration.RedirectUri);

            JsonResponse token = await Flows.ExchangeCodeAsync(
                client, registration, authz.Code, redirectUri: registration.RedirectUri);

            return Jwt.String(Jwt.Payload(token.AccessToken), "sub");
        }

        #endregion
    }
}
