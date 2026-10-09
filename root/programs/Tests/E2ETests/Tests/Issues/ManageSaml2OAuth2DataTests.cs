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
//* クラス名        ：ManageSaml2OAuth2DataTests
//* クラス日本語名  ：RT-277 管理画面のクライアント登録（#277 の段階 1・3）
//*
//* 作成日時        ：－
//* 作成者          ：－
//* 更新履歴        ：－
//*
//*  日時        更新者            内容
//*  ----------  ----------------  -------------------------------------------------
//*  2026/10/09  玄人 幸道         新規（#277 の段階 7）
//**********************************************************************************

using System.Collections.Generic;
using System.Net.Http;
using System.Text.RegularExpressions;
using System.Threading.Tasks;

using MultiPurposeAuthSite.Tests.E2E.Infrastructure;

using Xunit;
using Xunit.Abstractions;

/// <summary>MultiPurposeAuthSite.Tests.E2E.Tests.Issues</summary>
namespace MultiPurposeAuthSite.Tests.E2E.Tests.Issues
{
    /// <summary>
    /// RT-277 管理画面のクライアント登録（`/Manage/AddSaml2OAuth2Data`）。
    /// </summary>
    /// <remarks>
    /// **#277 の段階 1（項目の説明）・段階 3（折り返し先の候補）で手を入れた画面**である。
    /// **画面そのものを駆動する E2E が無かった**ので、段階 7 で足した。
    ///
    /// **この画面は、3 回押さないと登録できない。**
    /// `client_id` の発行 → `client_secret` の発行 → 登録、の順である。
    /// **1 回目で「登録」を押しても、黙って何も起きない**
    /// （`ManageController` の `submit.Add` は、`model.ClientID` が空なら素通りする）。
    /// **この「黙って」が、画面を触る人を迷わせる**ので、測って残しておく。
    ///
    /// **測るのは、サインイン中の利用者自身の登録**である。
    /// 利用者は**ターゲットごとに分かれている**（`TestUserSuffix`。#260）ので、
    /// core と netfx が同じ行を奪い合うことはない。
    /// **測り終えたら消す**（DB ストアでは次回に持ち越されるため）。
    /// </remarks>
    public class ManageSaml2OAuth2DataTests : TargetTestBase
    {
        /// <summary>コンストラクタ</summary>
        /// <param name="output">ITestOutputHelper</param>
        public ManageSaml2OAuth2DataTests(ITestOutputHelper output) : base(output) { }

        #region RT-277.1

        /// <summary>RT-277.1 クライアント登録は 3 回押しで入る</summary>
        /// <param name="targetKey">core / netfx</param>
        /// <returns>Task</returns>
        [SkippableTheory]
        [MemberData(nameof(AllTargets))]
        public async Task RT27701_クライアント登録は3回押しで入る(string targetKey)
        {
            using (IdPClient client = await this.SignedInClientAsync(targetKey))
            {
                TestReport r = this.Report("RT-277.1",
                    "クライアント登録は client_id → client_secret → 登録 の 3 回押しで入る",
                    "**`/Manage/AddSaml2OAuth2Data` は、`client_id` が空のままでは登録できない。**"
                    + "**1 回目で「登録」を押しても、黙って何も起きない**"
                    + "（`submit.Add` は `model.ClientID` が空なら素通りする）。"
                    + "**#277 の段階 1・3 で手を入れた画面**なので、"
                    + "**登録の経路そのものを測って残す**（段階 7）。",
                    "#277 / ManageController.AddSaml2OAuth2Data");

                await ManageSaml2OAuth2DataTests.RemoveRegistrationAsync(client);

                r.Target("POST /Manage/AddSaml2OAuth2Data（submit.ClientID → submit.ClientSecret → submit.Add）");

                r.Step("(0) 画面を開く");

                string html = await client.GetStringAsync("/Manage/AddSaml2OAuth2Data");

                Assert.False(string.IsNullOrEmpty(html), "前提: 登録画面が開くこと");

                Dictionary<string, string> form = ManageSaml2OAuth2DataTests.Harvest(html);

                r.Verify("client_id は空から始まる",
                    string.IsNullOrEmpty(Value(form, "ClientID")),
                    "空", string.IsNullOrEmpty(Value(form, "ClientID"))
                        ? "空" : "**" + Value(form, "ClientID") + "**");

                r.Step("(1) この時点で「登録」を押しても、入らない");

                Dictionary<string, string> add0 =
                    new Dictionary<string, string>(form) { { "submit.Add", "x" } };

                await client.PostFormAsync("/Manage/AddSaml2OAuth2Data", add0);

                bool registered0 = await ManageSaml2OAuth2DataTests.IsRegisteredAsync(client);

                r.Verify("登録されない", !registered0,
                    "登録されない", registered0 ? "**登録された**" : "登録されない");

                r.Note("**エラーも出ない。** 画面が出し直されるだけである。"
                    + "**「押したのに何も起きない」ので、3 回押しだと気付けない。**");

                r.Step("(2) client_id を発行する");

                form = ManageSaml2OAuth2DataTests.Harvest(
                    await PostAsync(client, form, "submit.ClientID"));

                string clientId = Value(form, "ClientID");

                r.Verify("client_id が入る",
                    Regex.IsMatch(clientId ?? "", "^[0-9a-f]{32}$"),
                    "32 桁の 16 進", string.IsNullOrEmpty(clientId)
                        ? "**空のまま**" : clientId);

                r.Step("(3) client_secret を発行する");

                form = ManageSaml2OAuth2DataTests.Harvest(
                    await PostAsync(client, form, "submit.ClientSecret"));

                string secret = Value(form, "ClientSecret");

                r.Verify("client_secret が入る",
                    !string.IsNullOrEmpty(secret),
                    "空でない", string.IsNullOrEmpty(secret) ? "**空のまま**" : "入った");

                r.Verify("client_id は変わらない",
                    Value(form, "ClientID") == clientId,
                    clientId, Value(form, "ClientID"));

                r.Step("(4) 登録する");

                await PostAsync(client, form, "submit.Add");

                bool registered = await ManageSaml2OAuth2DataTests.IsRegisteredAsync(client);

                r.Verify("登録される", registered,
                    "登録される", registered ? "登録された" : "**登録されない**");

                // **測り終えたら消す。** DB ストアでは次回に持ち越される。
                await ManageSaml2OAuth2DataTests.RemoveRegistrationAsync(client);

                bool removed = !await ManageSaml2OAuth2DataTests.IsRegisteredAsync(client);

                r.Verify("消せる（後片付け）", removed,
                    "消える", removed ? "消えた" : "**残った**");

                r.Done();
            }
        }

        #endregion

        #region RT-277.2

        /// <summary>RT-277.2 折り返し先の候補が datalist に出る</summary>
        /// <param name="targetKey">core / netfx</param>
        /// <returns>Task</returns>
        [SkippableTheory]
        [MemberData(nameof(AllTargets))]
        public async Task RT27702_折り返し先の候補がdatalistに出る(string targetKey)
        {
            using (IdPClient client = await this.SignedInClientAsync(targetKey))
            {
                TestReport r = this.Report("RT-277.2",
                    "折り返し先の記号が、画面の候補（datalist）から選べる",
                    "**`redirect_uri_*` には記号（`test_self_code` など）を書ける**が、"
                    + "**画面には何も出ておらず、知っている人しか書けなかった**（#277 の段階 3）。"
                    + "**`<input>` ＋ `<datalist>` にして、候補を画面に出した。**"
                    + "**新規登録の `redirect_uri_code` の既定も `test_self_code`** である"
                    + "（**以前は `test_self_code_manage`**。管理画面のトークン取得の廃止で戻した）。",
                    "#277 / ManageAddSaml2OAuth2DataViewModel の *Candidates");

                await ManageSaml2OAuth2DataTests.RemoveRegistrationAsync(client);

                r.Target("GET /Manage/AddSaml2OAuth2Data");

                string html = await client.GetStringAsync("/Manage/AddSaml2OAuth2Data");

                Assert.False(string.IsNullOrEmpty(html), "前提: 登録画面が開くこと");

                r.Step("(1) 入力欄に datalist が結び付いている");

                foreach (string name in new string[] {
                    "RedirectUriSaml", "RedirectUriCode", "RedirectUriToken", "PostLogoutRedirectUri" })
                {
                    bool linked = Regex.IsMatch(html,
                        "name=\"" + name + "\"[^>]*list=\"list-" + name + "\"")
                        || Regex.IsMatch(html,
                        "list=\"list-" + name + "\"[^>]*name=\"" + name + "\"");

                    bool listed = html.Contains("<datalist id=\"list-" + name + "\"");

                    r.Verify(name + " に候補が付いている", linked && listed,
                        "input の list と datalist が在る",
                        (linked ? "" : "**list が無い** ") + (listed ? "" : "**datalist が無い**")
                            + ((linked && listed) ? "在る" : ""));
                }

                r.Step("(2) 候補の中身");

                foreach (KeyValuePair<string, string> pair in new Dictionary<string, string>() {
                    { "RedirectUriSaml", "test_self_saml" },
                    { "RedirectUriCode", "test_self_code" },
                    { "RedirectUriToken", "test_self_token" },
                    { "PostLogoutRedirectUri", "test_self_logout" } })
                {
                    string list = ManageSaml2OAuth2DataTests.DataList(html, pair.Key);

                    r.Verify(pair.Key + " の候補に " + pair.Value + " が在る",
                        list != null && list.Contains(pair.Value),
                        pair.Value, (list == null) ? "**datalist が無い**"
                            : (list.Contains(pair.Value) ? "在る" : "**無い : " + list + "**"));
                }

                r.Step("(3) 新規登録の redirect_uri_code の既定");

                string code = Value(ManageSaml2OAuth2DataTests.Harvest(html), "RedirectUriCode");

                r.VerifyEqual("既定は test_self_code", "test_self_code", code ?? "");

                r.Note("**`test_self_code_manage` は削除した。** "
                    + "**管理画面の「トークンを取る」（＝ その記号の行き先）ごと廃止した**ため。");

                r.Done();
            }
        }

        #endregion

        #region 道具

        /// <summary>フォームの入力値を拾う（input / select）</summary>
        /// <param name="html">画面の HTML</param>
        /// <returns>name と value</returns>
        /// <remarks>
        /// **submit は入れない**（押すボタンは、送る側で 1 つだけ足す）。
        /// **checkbox は checked のときだけ入れる**（ブラウザと同じ扱い）。
        /// </remarks>
        private static Dictionary<string, string> Harvest(string html)
        {
            Dictionary<string, string> form = new Dictionary<string, string>();

            foreach (Match m in Regex.Matches(html ?? "", "<input\\b[^>]*>"))
            {
                string tag = m.Value;
                Match name = Regex.Match(tag, "name=\"(?<name>[^\"]+)\"");

                if (!name.Success) { continue; }
                if (Regex.IsMatch(tag, "type=\"submit\"")) { continue; }
                if (Regex.IsMatch(tag, "type=\"(checkbox|radio)\"")
                    && !Regex.IsMatch(tag, "\\bchecked\\b")) { continue; }

                Match value = Regex.Match(tag, "value=\"(?<value>[^\"]*)\"");

                form[name.Groups["name"].Value] = value.Success
                    ? System.Net.WebUtility.HtmlDecode(value.Groups["value"].Value) : "";
            }

            foreach (Match m in Regex.Matches(html ?? "",
                "<select\\b[^>]*name=\"(?<name>[^\"]+)\"[^>]*>(?<body>.*?)</select>",
                RegexOptions.Singleline))
            {
                string body = m.Groups["body"].Value;
                Match selected = Regex.Match(body, "value=\"(?<value>[^\"]*)\"[^>]*\\bselected\\b");
                Match first = Regex.Match(body, "value=\"(?<value>[^\"]*)\"");

                if (selected.Success)
                {
                    form[m.Groups["name"].Value] = selected.Groups["value"].Value;
                }
                else if (first.Success)
                {
                    form[m.Groups["name"].Value] = first.Groups["value"].Value;
                }
            }

            return form;
        }

        /// <summary>datalist の中身を返す</summary>
        /// <param name="html">画面の HTML</param>
        /// <param name="name">入力欄の name</param>
        /// <returns>datalist の中身（無ければ null）</returns>
        private static string DataList(string html, string name)
        {
            Match m = Regex.Match(html ?? "",
                "<datalist id=\"list-" + name + "\">(?<body>.*?)</datalist>",
                RegexOptions.Singleline);

            return m.Success ? m.Groups["body"].Value : null;
        }

        /// <summary>フォームの値を返す（無ければ null）</summary>
        /// <param name="form">フォーム</param>
        /// <param name="name">name</param>
        /// <returns>値</returns>
        private static string Value(Dictionary<string, string> form, string name)
        {
            return form.ContainsKey(name) ? form[name] : null;
        }

        /// <summary>ボタンを 1 つ押して、返ってきた画面を返す</summary>
        /// <param name="client">IdPClient</param>
        /// <param name="form">いまの入力値</param>
        /// <param name="submit">押すボタンの name</param>
        /// <returns>画面の HTML</returns>
        private static async Task<string> PostAsync(
            IdPClient client, Dictionary<string, string> form, string submit)
        {
            Dictionary<string, string> sending = new Dictionary<string, string>(form)
            {
                { submit, "x" }
            };

            HttpResponseMessage res = await client.PostFormAsync(
                "/Manage/AddSaml2OAuth2Data", sending);

            return await res.Content.ReadAsStringAsync();
        }

        /// <summary>登録が在るか（管理画面の表示で見る）</summary>
        /// <param name="client">IdPClient</param>
        /// <returns>在れば true</returns>
        private static async Task<bool> IsRegisteredAsync(IdPClient client)
        {
            string html = await client.GetStringAsync("/Manage/Index");

            // **登録が在るときだけ「削除」のフォームが出る。**
            return (html ?? "").Contains("RemoveSaml2OAuth2Data");
        }

        /// <summary>登録を消す（前提を揃える・後片付け）</summary>
        /// <param name="client">IdPClient</param>
        /// <returns>Task</returns>
        private static async Task RemoveRegistrationAsync(IdPClient client)
        {
            string html = await client.GetStringAsync("/Manage/Index");

            if (!(html ?? "").Contains("RemoveSaml2OAuth2Data"))
            {
                return;
            }

            Match token = Regex.Match(html,
                "name=\"__RequestVerificationToken\"[^>]*value=\"(?<value>[^\"]+)\"");

            if (!token.Success)
            {
                return;
            }

            await client.PostFormAsync("/Manage/RemoveSaml2OAuth2Data",
                new Dictionary<string, string>()
                {
                    { "__RequestVerificationToken", token.Groups["value"].Value }
                });
        }

        #endregion
    }
}
