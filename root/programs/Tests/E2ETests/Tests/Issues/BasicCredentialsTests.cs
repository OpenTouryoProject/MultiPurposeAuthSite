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
//* クラス名        ：BasicCredentialsTests
//* クラス日本語名  ：RT-237 Basic の資格情報の符号化（#237）
//*
//* 作成日時        ：－
//* 作成者          ：－
//* 更新履歴        ：－
//*
//*  日時        更新者            内容
//*  ----------  ----------------  -------------------------------------------------
//*  2026/09/27  玄人 幸道         新規（#237）
//*  2026/10/31  玄人 幸道         RT-237.3 を、Basic を最初の「:」で分ける振る舞いに合わせた（Open棟梁 #643。#294）
//**********************************************************************************

using System.Collections.Generic;
using System.Threading.Tasks;

using MultiPurposeAuthSite.Tests.E2E.Infrastructure;

using Xunit;
using Xunit.Abstractions;

namespace MultiPurposeAuthSite.Tests.E2E.Tests.Issues
{
    /// <summary>
    /// RT-237. `client_secret_basic` の資格情報を、RFC 6749 §2.3.1 のとおり復号して照合する。
    /// </summary>
    /// <remarks>
    /// **RFC 6749 §2.3.1 は、`client_id` と `client_secret` を
    /// `application/x-www-form-urlencoded` で符号化してから `:` で繋ぎ、Base64 にする**ことを求めている。
    /// 受け側は、復号してから照合しなければならない。
    ///
    /// 以前は復号していなかったため、**記号を含む秘密では、仕様に従うクライアントが認証できなかった**。
    /// **英数字だけの秘密では符号化しても同じ文字列になる**ので、
    /// 既存のテスト（雛形の秘密は base64url の英数字）では現れない。
    /// **記号を含む秘密のクライアントを差し込んで測る**（#224 の仕組み）。
    ///
    /// | | 送り方 | 期待 |
    /// |---|---|---|
    /// | RT-237.1 | 符号化した Basic（仕様どおり） | 通る |
    /// | RT-237.2 | 符号化しない Basic（配備済みのクライアント） | **通る**（互換） |
    /// | RT-237.3 | 秘密に `:` を含む | **符号化してもしなくても通る**（最初の `:` で分ける） |
    ///
    /// RT-237.2 が通るのは、**復号後で認証できなければ復号前の値でも照合する**ため
    /// （`CmnEndpoints.GetBasicCredentials`）。
    /// RT-237.3 で符号化しない側も通るのは、**Basic を最初の `:` で `id` と秘密に分ける**ためである
    /// （RFC 7617 §2。`:` を含められないのは user-id の側だけ）。
    /// **Open棟梁 #643 より前は、ヘッダが 3 つに割れて資格情報として読めなかった**（そのときは「符号化したときだけ通る」を測っていた）。
    /// </remarks>
    public class BasicCredentialsTests : TargetTestBase
    {
        /// <summary>コンストラクタ</summary>
        /// <param name="output">ITestOutputHelper</param>
        public BasicCredentialsTests(ITestOutputHelper output) : base(output)
        {
        }

        /// <summary>クライアント認証だけを測るためのフォーム（client_credentials）</summary>
        /// <returns>フォーム</returns>
        /// <remarks>
        /// **client_id / client_secret はフォームに入れない**（Authorization ヘッダだけで認証する）。
        /// グラント自体に引数が要らないので、**クライアント認証の成否だけが結果に出る**。
        /// </remarks>
        private static Dictionary<string, string> Form()
        {
            return new Dictionary<string, string>()
            {
                { "grant_type", "client_credentials" },
                { "scope", "profile" }
            };
        }

        /// <summary>RT-237.1 符号化した Basic（仕様どおり）</summary>
        /// <param name="targetKey">core / netfx</param>
        /// <returns>Task</returns>
        [SkippableTheory]
        [MemberData(nameof(AllTargets))]
        public async Task RT23701_符号化したBasicで記号を含む秘密のクライアントが認証できる(string targetKey)
        {
            using (IdPClient client = this.Client(targetKey))
            {
                TestReport r = this.Report("RT-237.1",
                    "form-urlencode した Basic で、記号を含む client_secret のクライアントが認証できる",
                    "**RFC 6749 §2.3.1 に従うクライアントが認証できない**という不整合だった。"
                    + "秘密が base64（`+` `/` `=` を含む）で生成されることは普通にあるため、"
                    + "**仕様どおりに送る相手ほど繋がらない**という状態になっていた（#237）。",
                    "RFC 6749 §2.3.1 / Appendix B");

                ClientRegistration reg = Flows.InjectedRegistration(client, KnownClients.TestClient_2);

                r.Target("client_name=" + KnownClients.TestClient_2
                    + "（TestClient を写し、client_secret を記号を含む値にしたもの。test.ps1 が差し込む）");

                r.Note("秘密は `+` `/` `=` を含む。"
                    + "符号化すると `%2B` `%2F` `%3D` になるので、**復号しないと一致しない**。");

                r.Step("POST /token に、符号化した Basic（Authorization ヘッダ）で client_credentials を送る");

                JsonResponse token = await client.TokenWithBasicAuthAsync(
                    Form(), reg.ClientId, reg.ClientSecret, true);

                r.VerifyEqual("HTTP 200", "200", ((int)token.StatusCode).ToString());

                r.Verify("エラーにならない", string.IsNullOrEmpty(token.Error),
                    "error なし",
                    token.Error == null ? "error なし"
                                        : "error=" + token.Error + " / " + token.ErrorDescription);

                r.Verify("access_token が返る", !string.IsNullOrEmpty(token.AccessToken),
                    "access_token あり", token.AccessToken == null ? "なし" : "あり（値は伏せる）");

                r.Done();
            }
        }

        /// <summary>RT-237.2 符号化しない Basic（互換）</summary>
        /// <param name="targetKey">core / netfx</param>
        /// <returns>Task</returns>
        [SkippableTheory]
        [MemberData(nameof(AllTargets))]
        public async Task RT23702_符号化しないBasicでも認証できる(string targetKey)
        {
            using (IdPClient client = this.Client(targetKey))
            {
                TestReport r = this.Report("RT-237.2",
                    "符号化しない Basic でも、記号を含む client_secret のクライアントが認証できる",
                    "**符号化しないクライアントは配備済みである**（Open棟梁 の従来のクライアントを含む）。"
                    + "復号だけを入れると、そちらが繋がらなくなる。"
                    + "**復号後で認証できなければ復号前の値でも照合する**ことで、どちらも受ける（#237）。",
                    "RFC 6749 §2.3.1");

                ClientRegistration reg = Flows.InjectedRegistration(client, KnownClients.TestClient_2);

                r.Target("client_name=" + KnownClients.TestClient_2 + "（符号化せずに送る）");

                r.Note("この秘密は `+` を含むので、**復号すると空白に変わる**（`WebUtility.UrlDecode`）。"
                    + "つまり復号後の値では一致せず、**復号前で照合して初めて通る**。"
                    + "ここが通ることが、互換が保たれている証拠になる。");

                r.Step("POST /token に、符号化しない Basic で client_credentials を送る");

                JsonResponse token = await client.TokenWithBasicAuthAsync(
                    Form(), reg.ClientId, reg.ClientSecret, false);

                r.VerifyEqual("HTTP 200", "200", ((int)token.StatusCode).ToString());

                r.Verify("エラーにならない", string.IsNullOrEmpty(token.Error),
                    "error なし",
                    token.Error == null ? "error なし"
                                        : "error=" + token.Error + " / " + token.ErrorDescription);

                r.Verify("access_token が返る", !string.IsNullOrEmpty(token.AccessToken),
                    "access_token あり", token.AccessToken == null ? "なし" : "あり（値は伏せる）");

                r.Done();
            }
        }

        /// <summary>RT-237.3 秘密に「:」を含む</summary>
        /// <param name="targetKey">core / netfx</param>
        /// <returns>Task</returns>
        [SkippableTheory]
        [MemberData(nameof(AllTargets))]
        public async Task RT23703_コロンを含む秘密は符号化してもしなくても通る(string targetKey)
        {
            using (IdPClient client = this.Client(targetKey))
            {
                TestReport r = this.Report("RT-237.3",
                    "client_secret に `:` を含む場合も、符号化してもしなくても認証できる",
                    "**Basic は最初の `:` で `id` と秘密に分ける**（`:` を含められないのは user-id の側だけ）ので、"
                    + "**符号化しなくても、`:` を含む秘密を送れる。** 符号化した側は復号で通る（#237）。"
                    + "**Open棟梁 #643 で分け方が直った**（以前は 3 つに割れて読めなかった）。",
                    "RFC 6749 §2.3.1 / RFC 7617 §2");

                ClientRegistration reg = Flows.InjectedRegistration(client, KnownClients.TestClient_3);

                r.Target("client_name=" + KnownClients.TestClient_3
                    + "（client_secret に `:` を含む。test.ps1 が差し込む）");

                r.Step("(1) 符号化した Basic（`:` は `%3A` になる）");

                JsonResponse encoded = await client.TokenWithBasicAuthAsync(
                    Form(), reg.ClientId, reg.ClientSecret, true);

                r.VerifyEqual("HTTP 200", "200", ((int)encoded.StatusCode).ToString());

                r.Verify("access_token が返る", !string.IsNullOrEmpty(encoded.AccessToken),
                    "access_token あり", encoded.AccessToken == null ? "なし" : "あり（値は伏せる）");

                r.Step("(2) 符号化しない Basic（`:` がそのまま載る）");

                JsonResponse raw = await client.TokenWithBasicAuthAsync(
                    Form(), reg.ClientId, reg.ClientSecret, false);

                r.VerifyEqual("HTTP 200", "200", ((int)raw.StatusCode).ToString());

                r.Verify("access_token が返る", !string.IsNullOrEmpty(raw.AccessToken),
                    "access_token あり", raw.AccessToken == null ? "なし" : "あり（値は伏せる）");

                r.Note("**最初の `:` で分ける**ので、秘密は `e2e:ab+cd` のまま照合される（RFC 7617 §2）。"
                    + "**Open棟梁 #643 より前は、ヘッダが 3 つに割れて断っていた**（このケースは「符号化したときだけ通る」を測っていた）。");

                r.Done();
            }
        }
    }
}
