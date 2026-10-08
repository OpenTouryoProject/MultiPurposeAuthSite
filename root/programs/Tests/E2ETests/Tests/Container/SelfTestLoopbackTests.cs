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
//* クラス名        ：SelfTestLoopbackTests
//* クラス日本語名  ：CN-3 自己テストの折り返し（#284）
//*
//* 作成日時        ：－
//* 作成者          ：－
//* 更新履歴        ：－
//*
//*  日時        更新者            内容
//*  ----------  ----------------  -------------------------------------------------
//*  2026/10/08  玄人 幸道         新規（#284）
//**********************************************************************************

using System.Net.Http;
using System.Text.RegularExpressions;
using System.Threading.Tasks;

using MultiPurposeAuthSite.Tests.E2E.Infrastructure;

using Xunit;
using Xunit.Abstractions;

namespace MultiPurposeAuthSite.Tests.E2E.Tests.Container
{
    /// <summary>
    /// CN-3. 自己テストの折り返しが、コンテナの中で届くこと。
    /// </summary>
    /// <remarks>
    /// **自己テストは「サーバが自分自身を WebAPI で呼ぶ」**（#250）。
    /// **コンテナの中から、外向けのホスト名・ポートには届かない**
    /// （実測 : コンテナ内から `localhost:44301` は CLOSED。待ち受けは 8080 / 8081）。
    ///
    /// **`OAuth2ContainerizatedAuthSvrEPRootURI` が宛先を差し替えている**
    /// （`Helper.GetContainerizatedAuthZServerUri`。**Windows でないときだけ働く**）。
    /// **この設定が無い／誤っていると、自己テストが落ちる。**
    ///
    /// **下流コンテナで測る**（#284）。
    /// **上流コンテナは `OAuth2ClientEndpointsRootURI` を与えていない**ので、
    /// **自己テストの主体としては下流が正しい。** 上流は「相手役」に専念させる。
    ///
    /// **画面遷移を伴うフロー**（認可エンドポイントへブラウザが飛ぶもの）と
    /// **mTLS を使う FAPI2** は、ここでは測らない（`TESTING.md` 1 節）。
    /// </remarks>
    public class SelfTestLoopbackTests : TargetTestBase
    {
        /// <summary>コンストラクタ</summary>
        /// <param name="output">ITestOutputHelper</param>
        public SelfTestLoopbackTests(ITestOutputHelper output) : base(output)
        {
        }

        /// <summary>CN-3.1 自己テストの client_credentials が通る</summary>
        /// <param name="containerKey">downstream</param>
        /// <returns>Task</returns>
        [SkippableTheory]
        [MemberData(nameof(ContainerTargets.DownstreamOnly), MemberType = typeof(ContainerTargets))]
        public async Task CN0301_自己テストのclient_credentialsが通る(string containerKey)
        {
            using (IdPClient client = ContainerTargets.Client(containerKey))
            {
                TestReport r = this.Report("CN-3.1",
                    "自己テストの `ClientCredentialsFlow` が通る（折り返しが届いている）",
                    "**サーバが自分自身を呼ぶ**ので、**コンテナの中から届く宛先が要る**（#250）。"
                    + "**`OAuth2ContainerizatedAuthSvrEPRootURI` に HTTP のループバックを与えている**"
                    + "（HTTPS にすると、コンテナの中でホストの開発用証明書を検証できない）。"
                    + "**この設定が欠けると、画面は出るのに結果が `ABNORMAL_END` になる。**",
                    "#250 / #284");

                r.Target(client.Target.DisplayName + "（自己テスト画面）");

                r.Step("(1) サインインして、自己テストのボタンを押す");

                await client.SignInAsync();

                HttpResponseMessage res = await client.StartSelfTestAsync("ClientCredentialsFlow");
                string html = await res.Content.ReadAsStringAsync();

                r.Step("(2) 応答に access_token がある");

                //  **この画面には NORMAL_END の印が無い**（Device AuthZ / CIBA の結果画面とは別）。
                //    **生のトークン応答をそのまま表示する**ので、**キーの有無で見る。**
                //    `TESTING.md` 1 節の目視も「`access_token` が返る」で判ている。
                bool hasKey = html.Contains("access_token");

                r.Verify("応答に access_token がある", hasKey,
                    "ある", hasKey ? "ある" : "**無い**");

                r.Step("(3) トークンが空でない");

                //  **値は出さない。** 長さだけを見る（`TESTING.md` 9 節）。
                //    画面は `token = '<値>';` として埋め込むので、
                //    **失敗しているとここが空になる。**
                Match m = Regex.Match(html, @"token\s*=\s*'([^']*)'");

                int length = m.Success ? m.Groups[1].Value.Length : 0;

                r.Verify("トークンが空でない", 0 < length,
                    "1 文字以上", (0 < length) ? (length + " 文字（値は伏せる）") : "**空**");

                r.Note("**値は出さない。** 有無と長さだけを見る（`TESTING.md` 9 節）。"
                    + "**折り返しが届いていなければ、ここが空になる。**");

                r.Done();
            }
        }
    }
}
