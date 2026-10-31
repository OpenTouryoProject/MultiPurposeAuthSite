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
//*  2026/10/14  玄人 幸道         RT-297.1（秘密の往復）を足した（#297）
//*  2026/10/16  玄人 幸道         登録の後始末を Infrastructure に出した（#305 の段階 2）
//*  2026/10/20  玄人 幸道         RT-277.9〜.11（一覧）を足した（#307 の段階 5-a-2）
//*  2026/10/21  玄人 幸道         backchannel_logout_uri の入力欄も見る（#310 の段階 2）
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
                    "RedirectUriSaml", "RedirectUriCode", "RedirectUriToken", "PostLogoutRedirectUri",
                    "BackChannelLogoutUri", "FrontChannelLogoutUri" })
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
                    { "PostLogoutRedirectUri", "test_self_logout" },
                    { "BackChannelLogoutUri", "test_self_bclogout" },
                    { "FrontChannelLogoutUri", "test_self_fclogout" } })
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
            //  **実体は Infrastructure に在る**（#299 で共有に出した）。
            //    **`RT-277.8` も「登録が在る利用者」を作るのに使う。**
            return ManageClientRegistration.Harvest(html);
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
            return ManageClientRegistration.Value(form, name);
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
        private static Task<bool> IsRegisteredAsync(IdPClient client)
        {
            //  **実体は Infrastructure に在る**（#307 の段階 5-a-2 で一覧の画面に向け直した）。
            //    **以前は `/Manage/Index` に「削除」のフォームが在るかで見ていた。**
            return ManageClientRegistration.IsRegisteredAsync(client);
        }

        /// <summary>登録を消す（前提を揃える・後片付け）</summary>
        /// <param name="client">IdPClient</param>
        /// <returns>Task</returns>
        private static Task RemoveRegistrationAsync(IdPClient client)
        {
            //  **実体は Infrastructure に在る**（#305 の段階 2 で共有に出した）。
            return ManageClientRegistration.RemoveAsync(client);
        }

        #region RT-277.9

        /// <summary>RT-277.9 一覧に n 件出て、別々に編集できる</summary>
        /// <param name="targetKey">core / netfx</param>
        /// <returns>Task</returns>
        /// <remarks>
        /// **1 利用者 n クライアント**（#307 の段階 5-a-1）を、**画面の側から測る。**
        ///
        /// **段階 5-a-1 の時点では、画面は「所有者の先頭 1 件」だけを扱っていた** —
        /// **2 件目を保存すると、古い行を消していた**（画面が 1 件を前提にしていたため）。
        /// **段階 5-a-2 で一覧にしたので、消さずに並ぶ。**
        /// </remarks>
        [SkippableTheory]
        [MemberData(nameof(AllTargets))]
        public async Task RT27709_一覧にn件出て別々に編集できる(string targetKey)
        {
            using (IdPClient client = await this.SignedInClientAsync(targetKey))
            {
                string opened = await client.GetStringAsync("/Manage/AddSaml2OAuth2Data");

                Skip.IfNot(Html.HasField(opened, "ClientSecret"),
                    "クライアント登録の画面が開きません"
                    + "（CanEditSaml2OAuth2Data / EnableEditingOfUserAttribute を確認）。");

                TestReport r = this.Report("RT-277.9",
                    "管理画面の一覧に n 件出て、**別々に編集できる**",
                    "**1 利用者 n クライアント**になった（#307 の段階 5-a-1）が、"
                    + "**画面は「所有者の先頭 1 件」しか扱えなかった** — "
                    + "**2 件目は、動的登録で作れても画面に出てこなかった。**"
                    + "**段階 5-a-2 で一覧にした**ので、"
                    + "**並ぶこと・どれを編集するか指せること・取り違えないこと**を測る。",
                    "#307 の段階 5-a-2 / ManageController.Saml2OAuth2DataList");

                r.Target("GET /Manage/Saml2OAuth2DataList");

                //  **前の回の残りを消しておく**（落ちた回の後始末）。
                await ManageSaml2OAuth2DataTests.RemoveRegistrationAsync(client);

                r.Step("(1) 画面から 2 件登録する");

                string first = await ManageClientRegistration.RegisterAsync(client);
                string second = await ManageClientRegistration.RegisterAsync(client);

                r.Verify("1 件目が登録できる", !string.IsNullOrEmpty(first),
                    "登録できる", string.IsNullOrEmpty(first) ? "**登録できない**" : first);

                r.Verify("2 件目も登録できる", !string.IsNullOrEmpty(second),
                    "登録できる", string.IsNullOrEmpty(second) ? "**登録できない**" : second);

                r.Verify("別の client_id である", first != second,
                    "違う", (first == second) ? "**同じ**" : "違う");

                r.Note("**段階 5-a-2 より前は、2 件目の保存で 1 件目が消えていた** — "
                    + "**画面が 1 件だけを扱うために、古い行を消していた**ためである。");

                r.Step("(2) 一覧に 2 件とも出る");

                List<string> listed = await ManageClientRegistration.ListAsync(client);

                r.VerifyEqual("一覧は 2 件", "2", listed.Count.ToString());

                r.Verify("1 件目が出る", listed.Contains(first),
                    "出る", listed.Contains(first) ? "出た" : "**出ない**");

                r.Verify("2 件目が出る", listed.Contains(second),
                    "出る", listed.Contains(second) ? "出た" : "**出ない**");

                r.Step("(3) 並びは client_id の昇順");

                List<string> sorted = new List<string>(listed);
                sorted.Sort(System.StringComparer.Ordinal);

                r.Verify("昇順である",
                    string.Join(",", listed) == string.Join(",", sorted),
                    "昇順", (string.Join(",", listed) == string.Join(",", sorted))
                        ? "昇順だった" : "**並びが違う**");

                r.Note("**並びを決めたのは段階 5-a-2**（`Saml2OAuth2DataProvider.GetByOwner` の `ORDER BY`）。"
                    + "**`mem` も方言 3 つも同じ順**にしてある — "
                    + "**決めていないと、一覧の行が毎回入れ替わる。**");

                r.Step("(4) 2 件目を指して編集の画面を開く");

                string edit = await ManageClientRegistration.OpenEditAsync(client, second);

                r.VerifyEqual("その client_id が出る", second,
                    Html.FieldValue(edit, "ClientID") ?? "（無い）");

                r.VerifyEqual("編集中の印が付く", "1",
                    Html.FieldValue(edit, "Editing") ?? "（無い）");

                r.Verify("client_id を作り直すボタンは出ない",
                    !edit.Contains("submit.ClientID"),
                    "出ない", edit.Contains("submit.ClientID") ? "**出る**" : "出ない");

                r.Note("**作り直すと別のクライアントになり、更新ではなく新規の登録になる。**"
                    + "**`registration_access_token` も引き継げない**ので、"
                    + "**動的登録で作られた行は、管理 API（RFC 7592）から触れなくなる。**");

                r.Step("(5) 2 件目だけを直しても、1 件目は変わらない");

                Dictionary<string, string> form = ManageClientRegistration.Harvest(edit);

                form["RedirectUriCode"] = "https://localhost:44305/edited";

                await ManageClientRegistration.PostAsync(client, form, "submit.Add");

                string reopenedSecond = await ManageClientRegistration.OpenEditAsync(client, second);
                string reopenedFirst = await ManageClientRegistration.OpenEditAsync(client, first);

                r.VerifyEqual("2 件目は直った", "https://localhost:44305/edited",
                    Html.FieldValue(reopenedSecond, "RedirectUriCode") ?? "（無い）");

                r.Verify("1 件目は変わっていない",
                    (Html.FieldValue(reopenedFirst, "RedirectUriCode") ?? "")
                        != "https://localhost:44305/edited",
                    "変わらない",
                    ((Html.FieldValue(reopenedFirst, "RedirectUriCode") ?? "")
                        == "https://localhost:44305/edited")
                        ? "**1 件目まで直った**" : "変わらなかった");

                r.VerifyEqual("一覧は 2 件のまま", "2",
                    (await ManageClientRegistration.ListAsync(client)).Count.ToString());

                r.Step("(6) 後片付け");

                await ManageSaml2OAuth2DataTests.RemoveRegistrationAsync(client);

                r.VerifyEqual("全部消える", "0",
                    (await ManageClientRegistration.ListAsync(client)).Count.ToString());

                r.Done();
            }
        }

        #endregion

        #region RT-277.10

        /// <summary>RT-277.10 他人の client_id は、画面から触れない</summary>
        /// <param name="targetKey">core / netfx</param>
        /// <returns>Task</returns>
        /// <remarks>
        /// **一覧から `clientId` を受けるようにした**（#307 の段階 5-a-2）ので、
        /// **書き換えて送られたときに、他人の登録を読み書きできてはならない。**
        ///
        /// **使い捨ての利用者に、本物の登録を 1 件作らせて測る。**
        ///
        /// **最初は「種データのクライアント」で測ろうとして、失敗した**（実測）。
        /// **あれは構成ファイル発で、`Saml2OAuth2Data` に行が無い** —
        /// **所有者を照合しない歯抜けを入れても、行が無いので null になり、
        /// 1 件も落ちなかった。** **「他人の行」は、本当に行が在る物でなければ測れない。**
        /// </remarks>
        [SkippableTheory]
        [MemberData(nameof(AllTargets))]
        public async Task RT27710_他人のclient_idは画面から触れない(string targetKey)
        {
            using (IdPClient admin = this.Client(targetKey))
            using (IdPClient client = await this.SignedInClientAsync(targetKey))
            {
                string opened = await client.GetStringAsync("/Manage/AddSaml2OAuth2Data");

                Skip.IfNot(Html.HasField(opened, "ClientSecret"),
                    "クライアント登録の画面が開きません"
                    + "（CanEditSaml2OAuth2Data / EnableEditingOfUserAttribute を確認）。");

                await admin.SignInAsAdministratorAsync();
                await UsersAdmin.SkipIfLockedDownAsync(admin);

                TestReport r = this.Report("RT-277.10",
                    "**他人の `client_id` は、画面から編集も削除もできない**",
                    "**一覧から `clientId` を受ける**ようにした（#307 の段階 5-a-2）。"
                    + "**URL もフォームも書き換えられる**ので、**所有者の照合はサーバ側で行う。**"
                    + "**動的登録の側は `registration_access_token` で守っている**（RFC 7592 §2）が、"
                    + "**画面の側は「サインインしている利用者が所有者か」だけが頼り**である。",
                    "#307 の段階 5-a-2 / Saml2OAuth2DataProvider.GetByOwnerAndClientID");

                r.Target("GET /Manage/AddSaml2OAuth2Data?clientId=（他人の client_id）");

                await ManageSaml2OAuth2DataTests.RemoveRegistrationAsync(client);

                //  **使い捨ての利用者を作り、その人に 1 件登録させる。**
                //    **ロールは `Admin`** — **この画面は `SystemAdmin` か `Admin` でなければ開かない。**
                string name = "e2e_rt27704_"
                    + System.Guid.NewGuid().ToString("N").Substring(0, 8);

                await UsersAdmin.CreateAsync(admin, name, name + "@example.com", "Admin");

                try
                {
                    string othersId = null;

                    using (IdPClient other = this.Client(targetKey))
                    {
                        Assert.True(
                            await other.TrySignInAsync(name, admin.Config.Get("TestUserPWD")),
                            "前提: 使い捨ての利用者でサインインできること");

                        othersId = await ManageClientRegistration.RegisterAsync(other);

                        Assert.False(string.IsNullOrEmpty(othersId),
                            "前提: 他人の登録を作れること");
                    }

                    r.Step("(1) 他人の client_id を指して、編集の画面を開く");

                    string denied = await ManageClientRegistration.OpenEditAsync(client, othersId);

                    r.Verify("編集の画面にならない",
                        !Html.HasField(denied, "ClientSecret"),
                        "ならない", Html.HasField(denied, "ClientSecret")
                            ? "**開いてしまった**" : "エラー画面になった");

                    r.Verify("その client_id が画面に出ない",
                        !(denied ?? "").Contains(othersId),
                        "出ない", (denied ?? "").Contains(othersId)
                            ? "**出てしまった**" : "出ない");

                    r.Step("(2) 自分の一覧にも出ない");

                    List<string> mine = await ManageClientRegistration.ListAsync(client);

                    r.Verify("一覧に他人の登録が出ない", !mine.Contains(othersId),
                        "出ない", mine.Contains(othersId) ? "**出てしまった**" : "出ない");

                    r.VerifyEqual("自分の一覧は 0 件", "0", mine.Count.ToString());

                    r.Step("(3) 在りもしない client_id でも、同じように断る");

                    string unknown = await ManageClientRegistration.OpenEditAsync(
                        client, "ffffffffffffffffffffffffffffffff");

                    r.Verify("編集の画面にならない",
                        !Html.HasField(unknown, "ClientSecret"),
                        "ならない", Html.HasField(unknown, "ClientSecret")
                            ? "**開いてしまった**" : "エラー画面になった");

                    r.Note("**「在るが自分の物でない」と「無い」を撃ち分けない** — "
                        + "**他人の `client_id` を当てられたかどうかを、外から分からせない**ためである"
                        + "（**動的登録の `404` と同じ倒し方**。RFC 7592 §2.1）。");

                    r.Step("(4) 削除も通らない（他人の登録は残る）");

                    //  **一覧に無い行は、ヘルパでは送れない**ので、直に送る。
                    string list = await client.GetStringAsync("/Manage/Saml2OAuth2DataList");

                    await client.PostFormAsync("/Manage/RemoveSaml2OAuth2Data",
                        new Dictionary<string, string>()
                        {
                            { "__RequestVerificationToken", Html.Antiforgery(list) },
                            { "clientId", othersId }
                        });

                    using (IdPClient other = this.Client(targetKey))
                    {
                        Assert.True(
                            await other.TrySignInAsync(name, admin.Config.Get("TestUserPWD")),
                            "前提: 使い捨ての利用者でサインインできること");

                        List<string> theirs = await ManageClientRegistration.ListAsync(other);

                        r.Verify("他人の登録は残っている", theirs.Contains(othersId),
                            "残る", theirs.Contains(othersId) ? "残った" : "**消えてしまった**");
                    }

                    r.Done();
                }
                finally
                {
                    //  **利用者を消すと、その人の登録も消える**
                    //    （`OwnerUserId` → `Users.Id` の `ON DELETE CASCADE`。段階 5-a-1）。
                    await UsersAdmin.DeleteByUserNameAsync(admin, name);
                }
            }
        }

        #endregion

        #region RT-277.11

        /// <summary>RT-277.11 一覧から 1 件だけ消せる</summary>
        /// <param name="targetKey">core / netfx</param>
        /// <returns>Task</returns>
        [SkippableTheory]
        [MemberData(nameof(AllTargets))]
        public async Task RT27711_一覧から1件だけ消せる(string targetKey)
        {
            using (IdPClient client = await this.SignedInClientAsync(targetKey))
            {
                string opened = await client.GetStringAsync("/Manage/AddSaml2OAuth2Data");

                Skip.IfNot(Html.HasField(opened, "ClientSecret"),
                    "クライアント登録の画面が開きません"
                    + "（CanEditSaml2OAuth2Data / EnableEditingOfUserAttribute を確認）。");

                TestReport r = this.Report("RT-277.11",
                    "一覧から **1 件だけ**消せる（残りは残る）",
                    "**削除は一覧の行から行う**ようにした（#307 の段階 5-a-2）。"
                    + "**段階 5-a-1 までは「所有者の先頭 1 件」を黙って消していた** — "
                    + "**n 件になると、どれが消えるのか押す側に分からない。**"
                    + "**行から `clientId` を渡す**ので、**指した 1 件だけが消える。**",
                    "#307 の段階 5-a-2 / ManageController.RemoveSaml2OAuth2Data");

                r.Target("POST /Manage/RemoveSaml2OAuth2Data（clientId を渡す）");

                await ManageSaml2OAuth2DataTests.RemoveRegistrationAsync(client);

                r.Step("(1) 2 件登録する");

                await ManageClientRegistration.RegisterAsync(client);
                await ManageClientRegistration.RegisterAsync(client);

                List<string> listed = await ManageClientRegistration.ListAsync(client);

                r.VerifyEqual("一覧は 2 件", "2", listed.Count.ToString());

                Assert.Equal(2, listed.Count);

                //  **消すのは「一覧の 2 行目」**（**1 行目ではない**）。
                //    **`clientId` を見ない歯抜けは「所有者の先頭 1 件」を消す**ので、
                //    **先頭を消す形で測ると、たまたま一致して気付けない**
                //    （**登録した順と、`client_id` の昇順は別物**である。実測で踏んだ）。
                string keep = listed[0];
                string target = listed[1];

                r.Step("(2) 一覧の 2 行目だけを消す");

                bool sent = await ManageClientRegistration.RemoveOneAsync(client, target);

                r.Verify("一覧の行から送れた", sent,
                    "送れた", sent ? "送れた" : "**その行が無い**");

                List<string> remained = await ManageClientRegistration.ListAsync(client);

                r.VerifyEqual("一覧は 1 件になる", "1", remained.Count.ToString());

                r.Verify("残っているのは 1 行目",
                    remained.Count == 1 && remained[0] == keep,
                    keep, (remained.Count == 1) ? remained[0] : "**件数が違う**");

                r.Step("(3) 残った 1 行目は、まだ編集できる");

                string edit = await ManageClientRegistration.OpenEditAsync(client, keep);

                r.VerifyEqual("編集の画面が開く", keep,
                    Html.FieldValue(edit, "ClientID") ?? "（無い）");

                r.Step("(4) 消した行は、もう開けない");

                string gone = await ManageClientRegistration.OpenEditAsync(client, target);

                r.Verify("編集の画面にならない",
                    !Html.HasField(gone, "ClientSecret"),
                    "ならない", Html.HasField(gone, "ClientSecret")
                        ? "**開いてしまった**" : "エラー画面になった");

                r.Step("(5) 後片付け");

                await ManageSaml2OAuth2DataTests.RemoveRegistrationAsync(client);

                r.VerifyEqual("全部消える", "0",
                    (await ManageClientRegistration.ListAsync(client)).Count.ToString());

                r.Done();
            }
        }

        #endregion

        #region RT-297.1

        /// <summary>RT-297.1 クライアント登録の client_secret が、暗号化しても往復する</summary>
        /// <param name="targetKey">core / netfx</param>
        /// <returns>Task</returns>
        /// <remarks>
        /// **user store に入る秘密を暗号化した**（#297）。
        /// **`client_secret` は「元に戻せる形」でなければならない** —
        /// **クライアント認証で照合し、画面で再表示する**ためである。
        ///
        /// **だから、保存して読み直したときに、同じ値が出なければならない。**
        /// **暗号化して保管し、使うときに復号する**（`SecretProtector`）。
        ///
        /// | | |
        /// |---|---|
        /// | 鍵が在る配備 | **DB には暗号文**（`enc:v1:…`）。**画面には平文** |
        /// | 鍵が空の配備 | **平文のまま**（従来どおり） |
        ///
        /// **E2E は鍵を設定した状態で回している**（`test.ps1` の `UserStoreSecretPassword`）。
        /// **DB に平文が残っていないこと**は、`-UserStoreType sql` で SELECT して確かめる
        /// （手順は `TESTING.md`）。
        /// </remarks>
        [SkippableTheory]
        [MemberData(nameof(AllTargets))]
        public async Task RT29701_クライアント登録の秘密が暗号化しても往復する(string targetKey)
        {
            using (IdPClient client = await this.SignedInClientAsync(targetKey))
            {
                //  **画面が閉じている配備では測れない**（`CanEditSaml2OAuth2Data` ほか）。
                string opened = await client.GetStringAsync("/Manage/AddSaml2OAuth2Data");

                Skip.IfNot(Html.HasField(opened, "ClientSecret"),
                    "クライアント登録の画面が開きません"
                    + "（CanEditSaml2OAuth2Data / EnableEditingOfUserAttribute を確認）。");

                TestReport r = this.Report("RT-297.1",
                    "クライアント登録の `client_secret` が、暗号化しても往復する",
                    "**user store の秘密を暗号化した**（#297）。"
                    + "**`client_secret` は上流へ送る・画面で再表示する**ので、"
                    + "**元に戻せる形でなければならない**（ハッシュは取れない）。"
                    + "**保存して読み直したときに同じ値が出ること**を測る — "
                    + "**ここが崩れると、クライアント認証が通らなくなる。**",
                    "#297 / #270");

                r.Target("POST /Manage/AddSaml2OAuth2Data（登録 → 読み直し）");

                //  **前の回の残りを消しておく**（落ちた回の後始末）。
                await ManageSaml2OAuth2DataTests.RemoveRegistrationAsync(client);

                r.Step("(1) client_id と client_secret を発行して、登録する");

                Dictionary<string, string> form = ManageSaml2OAuth2DataTests.Harvest(opened);

                form = ManageSaml2OAuth2DataTests.Harvest(
                    await PostAsync(client, form, "submit.ClientID"));

                form = ManageSaml2OAuth2DataTests.Harvest(
                    await PostAsync(client, form, "submit.ClientSecret"));

                string secret = Value(form, "ClientSecret");
                string clientId = Value(form, "ClientID");

                r.Verify("client_secret が入る", !string.IsNullOrEmpty(secret),
                    "空でない", string.IsNullOrEmpty(secret) ? "**空のまま**" : "入った（値は伏せる）");

                Assert.False(string.IsNullOrEmpty(secret), "前提: client_secret が発行されること");
                Assert.False(string.IsNullOrEmpty(clientId), "前提: client_id が発行されること");

                await PostAsync(client, form, "submit.Add");

                bool registered = await ManageSaml2OAuth2DataTests.IsRegisteredAsync(client);

                r.Verify("登録される", registered,
                    "登録される", registered ? "登録された" : "**登録されない**");

                Assert.True(registered, "前提: 登録できること");

                r.Step("(2) 画面を開き直すと、同じ client_secret が出る");

                //  **ここが往復である。**
                //    **保存で暗号化し、読み出しで復号している**（`SecretProtector`）。
                //    **復号できていなければ、空か、別の値になる。**
                //
                //  **開き直すときは、どの登録かを指す**（#307 の段階 5-a-2）。
                //    **引数なしの画面は「新規」になった** —
                //    **1 利用者 n クライアントなので、黙って 1 件を出さない。**
                string reloaded = Html.FieldValue(
                    await ManageClientRegistration.OpenEditAsync(client, clientId), "ClientSecret");

                r.Verify("発行した値と同じである", reloaded == secret,
                    "同じ（値は伏せる）",
                    (reloaded == secret) ? "同じだった"
                        : (string.IsNullOrEmpty(reloaded)
                            ? "**空になった**（復号できていない）" : "**別の値**"));

                r.Verify("暗号文がそのまま出ていない",
                    !(reloaded ?? "").StartsWith("enc:"),
                    "平文", (reloaded ?? "").StartsWith("enc:") ? "**暗号文のまま**" : "平文");

                r.Step("(3) 後片付け");

                await ManageSaml2OAuth2DataTests.RemoveRegistrationAsync(client);

                bool removed = !await ManageSaml2OAuth2DataTests.IsRegisteredAsync(client);

                r.Verify("消せる", removed, "消える", removed ? "消えた" : "**残った**");

                r.Done();
            }
        }

        #endregion

        #endregion
    }
}
