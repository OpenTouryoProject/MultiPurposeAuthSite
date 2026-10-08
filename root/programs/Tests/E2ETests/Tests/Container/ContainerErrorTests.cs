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
//* クラス名        ：ContainerErrorTests
//* クラス日本語名  ：CN-6 コンテナの異常系（#284）
//*
//* 作成日時        ：－
//* 作成者          ：－
//* 更新履歴        ：－
//*
//*  日時        更新者            内容
//*  ----------  ----------------  -------------------------------------------------
//*  2026/10/08  玄人 幸道         新規（#284）
//**********************************************************************************

using System.Collections.Generic;
using System.Net;
using System.Net.Http;
using System.Threading.Tasks;

using MultiPurposeAuthSite.Tests.E2E.Infrastructure;

using Xunit;
using Xunit.Abstractions;

namespace MultiPurposeAuthSite.Tests.E2E.Tests.Container
{
    /// <summary>
    /// CN-6. コンテナの異常系（配備に固有のもの）。
    /// </summary>
    /// <remarks>
    /// **プロトコルとして間違った要求は、ここでは測らない。**
    /// **ホストの core / netfx で測っている**（`EX-*` / `RT-185` / `RT-186` など）。
    /// **コンテナは「同じコードの別の配備」**なので、**重ねても同じコードの再計測になる。**
    ///
    /// **ここで測るのは、配備だから起きるものだけである。**
    /// </remarks>
    public class ContainerErrorTests : TargetTestBase
    {
        /// <summary>コンストラクタ</summary>
        /// <param name="output">ITestOutputHelper</param>
        public ContainerErrorTests(ITestOutputHelper output) : base(output)
        {
        }

        /// <summary>CN-6.1 仮想ディレクトリ付きのパスでは開かない（root 配信である）</summary>
        /// <param name="containerKey">upstream / downstream</param>
        /// <returns>Task</returns>
        [SkippableTheory]
        [MemberData(nameof(ContainerTargets.BothContainers), MemberType = typeof(ContainerTargets))]
        public async Task CN0601_仮想ディレクトリ付きのパスでは開かない(string containerKey)
        {
            using (IdPClient client = ContainerTargets.Client(containerKey))
            {
                TestReport r = this.Report("CN-6.1",
                    "`/MultiPurposeAuthSite/...` では開かない（コンテナは root 配信である）",
                    "**コンテナは `UsePathBase` を呼んでいないので root で配信する**（#250 の段階 2）。"
                    + "**Visual Studio は `/MultiPurposeAuthSite` の仮想アプリ**であり、"
                    + "**「VS と同じ設定」のうち、ここだけは同じにできない**（#281 で決めた）。"
                    + "**どちらの形なのかを取り違えると、`redirect_uri` の照合が合わなくなる**ので、"
                    + "**root 配信であることを固定する。**",
                    "#250 の段階 2 / #281 / #284");

                r.Target(client.Target.DisplayName);

                r.Step("(1) 仮想ディレクトリ付きのパスを叩く");

                HttpResponseMessage res = await client.GetAsync(
                    "/MultiPurposeAuthSite/Account/Login");

                r.Step("(2) 開かない（404。リダイレクトもしない）");

                bool notFound = res.StatusCode == HttpStatusCode.NotFound;

                r.Verify("HTTP 404 である", notFound, "404", ((int)res.StatusCode).ToString());

                r.Step("(3) root のパスなら開く");

                HttpResponseMessage root = await client.GetAsync("/Account/Login");

                r.Verify("`/Account/Login` は開く", root.StatusCode == HttpStatusCode.OK,
                    "200", ((int)root.StatusCode).ToString());

                r.Done();
            }
        }

        /// <summary>CN-6.2 同意の記録が無いクライアントは、prompt=none で consent_required</summary>
        /// <returns>Task</returns>
        /// <remarks>
        /// **#280 の裏返しである。**
        /// **上流は `mem` なので、作り直すと同意の記録が消える。**
        /// **その状態で `prompt=none` を送ると `consent_required` になる**（OIDC Core §3.1.2.6）。
        ///
        /// **専用のクライアントを使う。**
        /// **`CN-5` が使うクライアントは同意を記録してしまう**ので、
        /// **どのテストも「許可」を押さないクライアント**を上流に 1 件置いてある
        /// （`TestClient_19`（#272 の段階 2）と同じ考え方）。
        /// </remarks>
        [SkippableFact]
        public async Task CN0602_同意の記録が無ければconsent_requiredになる()
        {
            using (IdPClient client = ContainerTargets.Client(ContainerTargets.UpstreamKey))
            {
                TestReport r = this.Report("CN-6.2",
                    "同意の記録が無いクライアントは、`prompt=none` で `consent_required` になる",
                    "**上流は `mem` なので、作り直すと同意の記録が消える**（#280）。"
                    + "**`prompt=none` では UI を出せない**ので、"
                    + "**記録が無ければ `consent_required` を返すのが正しい**（OIDC Core §3.1.2.6）。"
                    + "**どのテストも「許可」を押さない専用のクライアント**で測る"
                    + "（他のクライアントは `CN-5` が同意を記録してしまう）。",
                    "OIDC Core §3.1.2.6 / #272 の段階 2 / #280 / #284");

                r.Target(client.Target.DisplayName + "（認可エンドポイント）");

                r.Step("(1) 専用のクライアント（同意を押さない）を構成から引く");

                string clientId = client.Config.FindClientIdByName("IdFederationNoConsent");

                Skip.If(string.IsNullOrEmpty(clientId),
                    "上流に IdFederationNoConsent のクライアントが登録されていません（#284）。");

                string redirectUri = client.Config.GetClientAttribute(clientId, "redirect_uri_code");

                r.Verify("`redirect_uri` が登録されている", !string.IsNullOrEmpty(redirectUri),
                    "登録されている",
                    string.IsNullOrEmpty(redirectUri) ? "**無い**" : redirectUri);

                Assert.False(string.IsNullOrEmpty(redirectUri), "前提: redirect_uri が登録されていること");

                r.Step("(2) サインインして、prompt=none で認可を要求する");

                await client.SignInAsync();

                Dictionary<string, string> query = new Dictionary<string, string>()
                {
                    { "client_id", clientId },
                    { "response_type", "code" },
                    { "scope", "openid email" },
                    { "state", "cn602-state" },
                    { "nonce", "cn602-nonce" },
                    { "redirect_uri", redirectUri },
                    { "prompt", "none" }
                };

                AuthZResponse authz = await client.AuthorizeAsync(query);

                r.Step("(3) consent_required が返る");

                r.Verify("リダイレクトで返る", authz.Redirected,
                    "リダイレクト", authz.Redirected ? "リダイレクト" : "**画面が出た**");

                r.Verify("error が consent_required", authz.Error == "consent_required",
                    "consent_required",
                    string.IsNullOrEmpty(authz.Error) ? "**エラーが無い**" : authz.Error);

                r.Note("**同意画面を出さないのが肝である。** `prompt=none` は「UI を出すな」であり、"
                    + "**記録が無いときに黙って code を出してはならない**（#272 の段階 2 ＝ C-3）。");

                r.Done();
            }
        }

        /// <summary>CN-6.3 未登録の client_id では認可しない</summary>
        /// <param name="containerKey">upstream / downstream</param>
        /// <returns>Task</returns>
        /// <remarks>
        /// **プロトコルの確認としては、ホスト側で測っている。**
        /// **ここで見たいのは「エラーの画面がコンテナで出せること」**である
        /// （ビュー・リソース・ログの設定が届いていなければ、500 になる）。
        /// </remarks>
        [SkippableTheory]
        [MemberData(nameof(ContainerTargets.BothContainers), MemberType = typeof(ContainerTargets))]
        public async Task CN0603_未登録のclient_idでは認可しない(string containerKey)
        {
            using (IdPClient client = ContainerTargets.Client(containerKey))
            {
                TestReport r = this.Report("CN-6.3",
                    "未登録の `client_id` では認可せず、エラーの画面が出せる",
                    "**プロトコルの確認はホスト側で済んでいる。**"
                    + "**ここで見たいのは「コンテナでエラーの画面が出せること」**である — "
                    + "**ビューや資源のパスが届いていなければ、ここが 500 になる。**",
                    "#284");

                r.Target(client.Target.DisplayName + "（認可エンドポイント）");

                r.Step("(1) 未登録の client_id で認可を要求する");

                Dictionary<string, string> query = new Dictionary<string, string>()
                {
                    { "client_id", "cn603000000000000000000000000000" },
                    { "response_type", "code" },
                    { "scope", "openid" },
                    { "state", "cn603-state" },
                    { "redirect_uri", "https://cn603.e2e.example/cb" }
                };

                AuthZResponse authz = await client.AuthorizeAsync(query);

                r.Step("(2) code は出ない。500 でもない");

                r.Verify("code が出ない", string.IsNullOrEmpty(authz.Code),
                    "出ない", string.IsNullOrEmpty(authz.Code) ? "出ない" : "**出た**");

                r.Verify("500 ではない", (int)authz.StatusCode != 500,
                    "500 以外", ((int)authz.StatusCode).ToString());

                r.Done();
            }
        }
    }
}
