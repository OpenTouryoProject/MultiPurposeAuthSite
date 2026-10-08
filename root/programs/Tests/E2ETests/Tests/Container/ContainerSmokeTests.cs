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
//* クラス名        ：ContainerSmokeTests
//* クラス日本語名  ：CN-1 コンテナの疎通（#284）
//*
//* 作成日時        ：－
//* 作成者          ：－
//* 更新履歴        ：－
//*
//*  日時        更新者            内容
//*  ----------  ----------------  -------------------------------------------------
//*  2026/10/08  玄人 幸道         新規（#284）
//**********************************************************************************

using System.Net;
using System.Net.Http;
using System.Text.Json;
using System.Threading.Tasks;

using MultiPurposeAuthSite.Tests.E2E.Infrastructure;

using Xunit;
using Xunit.Abstractions;

namespace MultiPurposeAuthSite.Tests.E2E.Tests.Container
{
    /// <summary>
    /// CN-1. コンテナが「配備として」成立していること。
    /// </summary>
    /// <remarks>
    /// **土台の確認である。** ここが倒れていたら、他の `CN-*` の合否は読む意味がない。
    ///
    /// **測るのは配備の差**（マウント・`IssuerId`・待ち受け）であって、
    /// **プロトコルの適合性ではない**（それはホストの core / netfx で測っている）。
    /// </remarks>
    public class ContainerSmokeTests : TargetTestBase
    {
        /// <summary>コンストラクタ</summary>
        /// <param name="output">ITestOutputHelper</param>
        public ContainerSmokeTests(ITestOutputHelper output) : base(output)
        {
        }

        /// <summary>CN-1.1 Discovery が返り、issuer が構成と一致する</summary>
        /// <param name="containerKey">upstream / downstream</param>
        /// <returns>Task</returns>
        [SkippableTheory]
        [MemberData(nameof(ContainerTargets.BothContainers), MemberType = typeof(ContainerTargets))]
        public async Task CN0101_Discoveryが返りissuerが構成と一致する(string containerKey)
        {
            using (IdPClient client = ContainerTargets.Client(containerKey))
            {
                TestReport r = this.Report("CN-1.1",
                    "コンテナの Discovery が返り、`issuer` が構成の `IssuerId` と一致する",
                    "**コンテナは `appsettings.json` と compose の環境変数で構成される**（#284）。"
                    + "**`issuer` は待ち受けている URL とは別の値**（`IssuerId`）であり、"
                    + "**compose が上書きしている**ので、**重ね読みが効いていなければ合わない。**",
                    "#281 / #284");

                r.Target(client.Target.DisplayName + "（" + client.Target.BaseUrl + "）");

                r.Step("(1) Discovery を引く");

                JsonResponse res = await client.GetJsonAsync("/.well-known/openid-configuration");

                r.Verify("JSON が返る", res.IsJson, "JSON", res.IsJson ? "JSON" : "**JSON でない**");

                Assert.True(res.IsJson, "前提: Discovery が JSON を返すこと");

                r.Step("(2) issuer が構成の IssuerId と一致する");

                string expected = client.Config.Get("IssuerId");
                string actual = res.String("issuer");

                r.Verify("issuer が一致する", expected == actual, expected, actual);

                r.Done();
            }
        }

        /// <summary>CN-1.2 上流と下流の issuer が違う</summary>
        /// <returns>Task</returns>
        /// <remarks>
        /// **2 つの IdP が同じ `iss` を名乗らないこと**（#281 で決めた）。
        /// **同じだと、連携キー `(iss, sub)` の意味が曖昧になる。**
        /// </remarks>
        [SkippableFact]
        public async Task CN0102_上流と下流のissuerが違う()
        {
            using (IdPClient up = ContainerTargets.Client(ContainerTargets.UpstreamKey))
            using (IdPClient down = ContainerTargets.Client(ContainerTargets.DownstreamKey))
            {
                TestReport r = this.Report("CN-1.2",
                    "上流コンテナと下流コンテナの `issuer` が違う",
                    "**ハイブリッド構成では、2 つの IdP が建つ**（#281）。"
                    + "**同じ `iss` を名乗ると、連携キー `(iss, sub)` の意味が曖昧になる。**"
                    + "**`IssuerId` は URL に依らない固定値**なので、**設定で分けるしかない。**",
                    "#281");

                r.Target("上流コンテナ ＋ 下流コンテナ");

                r.Step("(1) 両方の issuer を引く");

                string upIssuer = await up.IssuerAsync();
                string downIssuer = await down.IssuerAsync();

                r.Verify("上流の issuer が取れる", !string.IsNullOrEmpty(upIssuer),
                    "取れる", string.IsNullOrEmpty(upIssuer) ? "**取れない**" : upIssuer);

                r.Verify("下流の issuer が取れる", !string.IsNullOrEmpty(downIssuer),
                    "取れる", string.IsNullOrEmpty(downIssuer) ? "**取れない**" : downIssuer);

                r.Step("(2) 違う値である");

                r.Verify("issuer が違う", upIssuer != downIssuer,
                    "違う", (upIssuer == downIssuer) ? "**同じ（" + upIssuer + "）**" : "違う");

                r.Done();
            }
        }

        /// <summary>CN-1.3 jwkcerts が鍵を返す（マウントした署名鍵を読めている）</summary>
        /// <param name="containerKey">upstream / downstream</param>
        /// <returns>Task</returns>
        [SkippableTheory]
        [MemberData(nameof(ContainerTargets.BothContainers), MemberType = typeof(ContainerTargets))]
        public async Task CN0103_jwkcertsが鍵を返す(string containerKey)
        {
            using (IdPClient client = ContainerTargets.Client(containerKey))
            {
                TestReport r = this.Report("CN-1.3",
                    "`jwkcerts` が鍵を返す（マウントした署名鍵まで読めている）",
                    "**署名鍵はイメージに入れず、ホストの `C:\\root\\files\\resource` をマウントしている**"
                    + "（#250 の段階 2）。**資源のパスは 19 件を環境変数で振り替えており、"
                    + "1 つでも漏らすと、その設定を使った瞬間に落ちる。**"
                    + "**`jwkcerts` が返れば、少なくとも署名鍵までは届いている。**",
                    "#250 の段階 2 / #284");

                r.Target(client.Target.DisplayName);

                r.Step("(1) jwkcerts を引く");

                JsonElement jwks = await Flows.JwkSetAsync(client);

                JsonElement keys;
                bool hasKeys = jwks.TryGetProperty("keys", out keys)
                    && keys.ValueKind == JsonValueKind.Array;

                int count = hasKeys ? keys.GetArrayLength() : 0;

                r.Verify("鍵が 1 つ以上ある", 0 < count, "1 つ以上", count + " 件");

                r.Done();
            }
        }

        /// <summary>CN-1.4 死活監視の口が開いている</summary>
        /// <param name="containerKey">upstream / downstream</param>
        /// <returns>Task</returns>
        [SkippableTheory]
        [MemberData(nameof(ContainerTargets.BothContainers), MemberType = typeof(ContainerTargets))]
        public async Task CN0104_Pingが応答する(string containerKey)
        {
            using (IdPClient client = ContainerTargets.Client(containerKey))
            {
                TestReport r = this.Report("CN-1.4",
                    "`/Ping` が応答する（死活監視の口）",
                    "**`IsLockedDownTestEndpoints` でも閉じない口である**"
                    + "（`CONFIGURATION.md` 11 節の注意 3）。"
                    + "**コンテナを監視するなら、ここを見ることになる。**",
                    "#219 / #284");

                r.Target(client.Target.DisplayName);

                r.Step("(1) /Ping を叩く");

                HttpResponseMessage res = await client.GetAsync("/Ping");

                r.Verify("HTTP 200 が返る", res.StatusCode == HttpStatusCode.OK,
                    "200", ((int)res.StatusCode).ToString());

                r.Done();
            }
        }
    }
}
