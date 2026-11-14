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
//* クラス名        ：RequestDestinationTests
//* クラス日本語名  ：RT-391 SP の役で作る SAML2 の要求に、送り先の Destination を入れる（SAML Bindings §3.4.5.2・§3.5.5.2）
//*
//* 作成日時        ：－
//* 作成者          ：－
//* 更新履歴        ：－
//*
//*  日時        更新者            内容
//*  ----------  ----------------  -------------------------------------------------
//*  2026/11/14  玄人 幸道         新規（#391）
//**********************************************************************************

using System.Collections.Generic;
using System.Net.Http;
using System.Text.RegularExpressions;
using System.Threading.Tasks;

using MultiPurposeAuthSite.Tests.E2E.Infrastructure;

using Xunit;
using Xunit.Abstractions;

namespace MultiPurposeAuthSite.Tests.E2E.Tests.Saml
{
    /// <summary>
    /// RT-391. **SP の役で作る SAML2 の要求に、送り先の `Destination` を入れる**（SAML Bindings §3.4.5.2・§3.5.5.2）。
    /// </summary>
    /// <remarks>
    /// **署名した要求には `Destination` が要る**（「If the message is signed, the Destination XML attribute ... MUST contain
    /// the URL to which the sender has instructed the user agent to deliver the message.」）。
    /// **以前は、Open棟梁 の従来の版（OpenTouryo#693 で `[Obsolete]`）を使っていて、`Destination` を入れていなかった。**
    ///
    /// | | 測ること |
    /// |---|---|
    /// | **`RT-391.1`** | **自己テストの SP の 4 通りの要求**（Redirect・POST）の `Destination` が、**要求を送った先と同じ** |
    ///
    /// **ID 連携の SP（上流へ送る要求）は、`SA-6.1` で測る**（上流のコンテナが要るため、そちらの前提に乗せた）。
    /// **流れが最後まで通ること**は `SA-1.1`〜`.4` が測る（MPAS の IdP は `Destination` を照合しない）。
    /// </remarks>
    public class RequestDestinationTests : TargetTestBase
    {
        /// <summary>コンストラクタ</summary>
        /// <param name="output">ITestOutputHelper</param>
        public RequestDestinationTests(ITestOutputHelper output) : base(output)
        {
        }

        #region RT-391.1

        /// <summary>RT-391.1 自己テストの SP の要求の Destination は、送った先と同じ</summary>
        /// <param name="targetKey">core / netfx</param>
        /// <returns>Task</returns>
        [SkippableTheory]
        [MemberData(nameof(AllTargets))]
        public async Task RT39101_自己テストのSPの要求のDestinationは送った先と同じ(string targetKey)
        {
            using (IdPClient client = await this.SignedInClientAsync(targetKey))
            {
                TestReport r = this.Report("RT-391.1",
                    "**自己テストの SP の 4 通りの SAML2 の要求（Redirect・POST）に、送った先と同じ Destination が入る**",
                    "**SAML Bindings §3.4.5.2（Redirect）・§3.5.5.2（POST）は、署名した要求の Destination を、"
                    + "送り先の URL にすることを求める（MUST）。**"
                    + "**以前は Open棟梁 の従来の版（OpenTouryo#693 で Obsolete）を使い、Destination を入れていなかった。**",
                    "SAML Bindings §3.4.5.2 / §3.5.5.2 / #391");

                r.Target("POST /Home/Saml2OAuth2Starters（submit.Saml2RedirectRedirectBinding など 4 つ）");

                foreach (KeyValuePair<string, bool> button in new Dictionary<string, bool>()
                {
                    { "Saml2RedirectRedirectBinding", false },
                    { "Saml2RedirectPostBinding", false },
                    { "Saml2PostPostBinding", true },
                    { "Saml2PostRedirectBinding", true }
                })
                {
                    r.Step("submit." + button.Key + "（要求は " + (button.Value ? "POST" : "Redirect") + "）");

                    HttpResponseMessage started = await client.StartSelfTestAsync(button.Key, "normal");

                    string sentTo;
                    string xml;

                    if (button.Value)
                    {
                        string form = await started.Content.ReadAsStringAsync();
                        Dictionary<string, string> hidden = Html.HiddenInputs(form);

                        sentTo = Html.FormAttribute(form, "action");
                        xml = hidden.ContainsKey("SAMLRequest") ? Saml2.FromPostValue(hidden["SAMLRequest"]) : null;
                    }
                    else
                    {
                        string location = (started.Headers.Location == null) ? null : started.Headers.Location.ToString();

                        sentTo = (location == null) ? null : location.Split('?')[0];
                        xml = (location == null) ? null : Saml2.FromRedirectQuery(location, "SAMLRequest");
                    }

                    Assert.False(string.IsNullOrEmpty(sentTo) || string.IsNullOrEmpty(xml),
                        "前提: 要求が組み立てられ、送り先が分かること（" + button.Key + "）");

                    r.VerifyEqual("Destination が、要求を送った先と同じ", sentTo,
                        RequestDestinationTests.DestinationOf(xml) ?? "（無い）");
                }

                r.Done();
            }
        }

        #endregion

        #region 補助

        /// <summary>要求の XML の、最初の要素の Destination 属性（無ければ null）</summary>
        /// <param name="xml">要求の XML</param>
        /// <returns>Destination</returns>
        internal static string DestinationOf(string xml)
        {
            if (string.IsNullOrEmpty(xml))
            {
                return null;
            }

            // **最初の要素（AuthnRequest）の開始タグだけを見る**（中の要素の属性を拾わない）。
            Match root = Regex.Match(xml, @"<(?!\?)[^>]*>");

            if (!root.Success)
            {
                return null;
            }

            Match destination = Regex.Match(root.Value, "\\sDestination=\"([^\"]*)\"");

            return destination.Success ? System.Net.WebUtility.HtmlDecode(destination.Groups[1].Value) : null;
        }

        #endregion
    }
}
