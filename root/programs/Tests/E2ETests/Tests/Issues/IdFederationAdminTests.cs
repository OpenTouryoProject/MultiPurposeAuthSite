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
//* クラス名        ：IdFederationAdminTests
//* クラス日本語名  ：RT-292 上流 IdP の登録を、DB と管理画面で扱う
//*
//* 作成日時        ：－
//* 作成者          ：－
//* 更新履歴        ：－
//*
//*  日時        更新者            内容
//*  ----------  ----------------  -------------------------------------------------
//*  2026/10/14  玄人 幸道         新規（#292 の段階 2）
//*  2026/10/14  玄人 幸道         RT-297.2（秘密の往復）を足した（#297）
//**********************************************************************************

using System.Collections.Generic;
using System.Net;
using System.Net.Http;
using System.Threading.Tasks;

using MultiPurposeAuthSite.Tests.E2E.Infrastructure;

using Xunit;
using Xunit.Abstractions;

namespace MultiPurposeAuthSite.Tests.E2E.Tests.Issues
{
    /// <summary>
    /// RT-292. **上流 IdP の登録を、user store と管理画面で扱う**（#292 の段階 2）。
    /// </summary>
    /// <remarks>
    /// **段階 1 で、設定（`IdFederationUpstreams`）から n 件読めるようになった。**
    /// **段階 2 は、同じものを user store に置き、管理画面から足せるようにしたもの**である。
    ///
    /// | | |
    /// |---|---|
    /// | 読む順 | **設定 → user store**（同じ鍵なら設定が勝つ） |
    /// | 画面が編む範囲 | **user store の行だけ**（設定ファイルの行は編めない） |
    /// | 認可 | **`UsersAdmin` と同じ**（`EnableAdministrationOfUsersAndRoles` ＋ `SystemAdmin`） |
    ///
    /// **既定の通しは `mem`** なので、**プロセス内の辞書**を測る。
    /// **DB ストア（`-UserStoreType sql` など）では、表を測る**（DDL は 3 方言）。
    ///
    /// **足した行は、同じテストの中で消す**（DB ストアでは積み上がるため。`UsersAdmin` と同じ）。
    /// </remarks>
    public class IdFederationAdminTests : TargetTestBase
    {
        /// <summary>コンストラクタ</summary>
        /// <param name="output">ITestOutputHelper</param>
        public IdFederationAdminTests(ITestOutputHelper output) : base(output)
        {
        }

        /// <summary>この一巡で使う鍵（**他のテストと混ざらない名前**にする）</summary>
        private const string TestKey = "e2e_rt292_saml2";

        /// <summary>RT-297.2 で使う鍵（**他のテストと混ざらない名前**にする）</summary>
        private const string SecretKey = "e2e_rt297_oidc";

        /// <summary>RT-292.4 で使う鍵（**他のテストと混ざらない名前**にする）</summary>
        private const string SigningKey = "e2e_rt292b_saml2";

        #region RT-292.1

        /// <summary>RT-292.1 管理画面で、上流を足して・直して・消せる</summary>
        /// <param name="targetKey">core / netfx</param>
        /// <returns>Task</returns>
        /// <remarks>
        /// **1 本で CRUD を通す。** **足した行は消して戻す**ので、
        /// **DB ストアでも、次の回に積み上がらない。**
        /// </remarks>
        [SkippableTheory]
        [MemberData(nameof(AllTargets))]
        public async Task RT29201_管理画面で上流を足して直して消せる(string targetKey)
        {
            using (IdPClient client = this.Client(targetKey))
            {
                await client.SignInAsAdministratorAsync();

                string index = await IdFederationAdmin.SkipIfLockedDownAsync(client);

                TestReport r = this.Report("RT-292.1",
                    "上流 IdP の管理画面で、登録を足して・直して・消せる",
                    "**上流の登録を、運用で足せるようにする**（#292 の段階 2）。"
                    + "**設定ファイルを書き換えずに増やせる**ことが、この段階の値打ちである。"
                    + "**上流の登録は配備全体のもの**なので、**画面は `UsersAdmin` の隣**に置き、"
                    + "**認可も同じ**（`EnableAdministrationOfUsersAndRoles` ＋ `SystemAdmin`）。",
                    "#292 の段階 2");

                r.Target("GET/POST /IdFederationAdmin（管理者でサインイン）");

                //  **前の回の残りが在れば消しておく**（落ちた回の後始末）。
                if (IdFederationAdmin.Contains(index, IdFederationAdminTests.TestKey))
                {
                    await IdFederationAdmin.DeleteAsync(client, IdFederationAdminTests.TestKey);
                }

                r.Step("(1) 一覧が開く");

                r.Verify("一覧に「追加」の導線が在る",
                    0 <= index.IndexOf("/IdFederationAdmin/Create"),
                    "在る", "在る");

                r.Step("(2) 上流を足す（SAML2 の行）");

                //  **SAML2 の行にする。** **OIDC の導線の数を変えない**ため
                //    （`RT-140.*` が押すボタンは 1 件目で、そこは動かない）。
                HttpResponseMessage create = await IdFederationAdmin.CreateAsync(
                    client, IdFederationAdminTests.TestKey, "saml2",
                    "E2E RT-292 Upstream", "https://rt292.e2e.example",
                    new Dictionary<string, string>()
                    {
                        { "ClientID", "e2e0rt292000000000000000000000z1" },
                        { "MetadataUrl", "https://rt292.e2e.example/samlmetadata" },
                        { "SsoEndpoint", "https://rt292.e2e.example/saml2request" },
                        { "CerFilePath", "C:/root/files/resource/X509/SHA256RSA_Server.cer" }
                    });

                bool created = create.StatusCode == HttpStatusCode.Found
                    || create.StatusCode == HttpStatusCode.Redirect
                    || create.StatusCode == HttpStatusCode.SeeOther;

                r.Verify("追加すると一覧へ戻る", created,
                    "リダイレクト", created ? "した" : "**しない（" + create.StatusCode + "）**");

                Assert.True(created, "前提: 追加できること");

                index = await (await IdFederationAdmin.IndexAsync(client)).Content.ReadAsStringAsync();

                r.Verify("一覧に出る",
                    IdFederationAdmin.Contains(index, IdFederationAdminTests.TestKey),
                    "出る",
                    IdFederationAdmin.Contains(index, IdFederationAdminTests.TestKey)
                        ? "出た" : "**出ない**");

                r.Verify("表示名も出る", 0 <= index.IndexOf("E2E RT-292 Upstream"),
                    "出る", (0 <= index.IndexOf("E2E RT-292 Upstream")) ? "出た" : "**出ない**");

                r.Step("(3) 表示名を直す");

                HttpResponseMessage edit = await IdFederationAdmin.EditDisplayNameAsync(
                    client, IdFederationAdminTests.TestKey, "E2E RT-292 Renamed",
                    new Dictionary<string, string>()
                    {
                        { "Protocol", "saml2" },
                        { "Issuer", "https://rt292.e2e.example" },
                        { "MetadataUrl", "https://rt292.e2e.example/samlmetadata" }
                    });

                bool edited = edit.StatusCode == HttpStatusCode.Found
                    || edit.StatusCode == HttpStatusCode.Redirect
                    || edit.StatusCode == HttpStatusCode.SeeOther;

                r.Verify("編集すると一覧へ戻る", edited,
                    "リダイレクト", edited ? "した" : "**しない（" + edit.StatusCode + "）**");

                index = await (await IdFederationAdmin.IndexAsync(client)).Content.ReadAsStringAsync();

                r.Verify("新しい表示名が出る", 0 <= index.IndexOf("E2E RT-292 Renamed"),
                    "出る", (0 <= index.IndexOf("E2E RT-292 Renamed")) ? "出た" : "**出ない**");

                r.Step("(4) 消す");

                bool deleted = await IdFederationAdmin.DeleteAsync(
                    client, IdFederationAdminTests.TestKey);

                r.Verify("削除できる", deleted, "できる", deleted ? "できた" : "**できない**");

                index = await (await IdFederationAdmin.IndexAsync(client)).Content.ReadAsStringAsync();

                r.Verify("一覧から消える",
                    !IdFederationAdmin.Contains(index, IdFederationAdminTests.TestKey),
                    "消える",
                    IdFederationAdmin.Contains(index, IdFederationAdminTests.TestKey)
                        ? "**残っている**" : "消えた");

                r.Done();
            }
        }

        #endregion

        #region RT-292.2

        /// <summary>RT-292.2 DB に足した上流が、サインイン画面の導線に出る</summary>
        /// <param name="targetKey">core / netfx</param>
        /// <returns>Task</returns>
        /// <remarks>
        /// **段階 2 の値打ちそのもの**である。
        /// **設定ファイルを書き換えずに、上流を増やせる**ことを、画面で見る。
        ///
        /// **読む順は 設定 → user store** なので、
        /// **設定の行（既定の 1 件）と、DB の行が、両方とも導線に出る。**
        /// </remarks>
        [SkippableTheory]
        [MemberData(nameof(AllTargets))]
        public async Task RT29202_DBに足した上流がサインイン画面に出る(string targetKey)
        {
            using (IdPClient client = this.Client(targetKey))
            {
                await client.SignInAsAdministratorAsync();

                string index = await IdFederationAdmin.SkipIfLockedDownAsync(client);

                TestReport r = this.Report("RT-292.2",
                    "user store に足した上流が、サインイン画面の導線に出る",
                    "**設定ファイルを書き換えずに、上流を増やせること**（#292 の段階 2）。"
                    + "**読む順は 設定 → user store** なので、"
                    + "**設定の行と DB の行が、両方とも導線に出る。**"
                    + "**出なければ、画面は登録を見ていない** — "
                    + "**管理画面だけ在っても、連携は増えない。**",
                    "#292 の段階 1・2");

                r.Target("POST /IdFederationAdmin/Create → GET /Account/Login");

                if (IdFederationAdmin.Contains(index, IdFederationAdminTests.TestKey))
                {
                    await IdFederationAdmin.DeleteAsync(client, IdFederationAdminTests.TestKey);
                }

                r.Step("(1) 足す前のサインイン画面を見る");

                string before = await client.GetStringAsync("/Account/Login");

                bool beforeHas = 0 <= (before ?? "").IndexOf(
                    "data-idp-key=\"" + IdFederationAdminTests.TestKey + "\"");

                r.Verify("足す前は、その導線が無い", !beforeHas,
                    "無い", beforeHas ? "**在る（前の回の残り？）**" : "無い");

                r.Step("(2) user store に 1 件足す");

                HttpResponseMessage create = await IdFederationAdmin.CreateAsync(
                    client, IdFederationAdminTests.TestKey, "saml2",
                    "E2E RT-292 Upstream", "https://rt292.e2e.example",
                    new Dictionary<string, string>()
                    {
                        { "ClientID", "e2e0rt292000000000000000000000z1" },
                        { "MetadataUrl", "https://rt292.e2e.example/samlmetadata" },
                        { "SsoEndpoint", "https://rt292.e2e.example/saml2request" },
                        { "CerFilePath", "C:/root/files/resource/X509/SHA256RSA_Server.cer" }
                    });

                Assert.True(
                    create.StatusCode == HttpStatusCode.Found
                    || create.StatusCode == HttpStatusCode.Redirect
                    || create.StatusCode == HttpStatusCode.SeeOther,
                    "前提: 追加できること");

                r.Step("(3) サインイン画面に、その導線が出る");

                string after = await client.GetStringAsync("/Account/Login");

                bool afterHas = 0 <= (after ?? "").IndexOf(
                    "data-idp-key=\"" + IdFederationAdminTests.TestKey + "\"");

                r.Verify("足した上流の導線が出る", afterHas,
                    "出る", afterHas ? "出た" : "**出ない**");

                //  **設定の行も残っている**（**DB が設定を上書きしない**）。
                bool defaultStillThere = 0 <= (after ?? "").IndexOf(
                    "id=\"id_federation_saml2_signin\"");

                r.Verify("設定の行（既定の導線）も残っている", defaultStillThere,
                    "残る", defaultStillThere ? "残った" : "**消えた**");

                r.Step("(4) 後片付け（消して、導線も消える）");

                Assert.True(await IdFederationAdmin.DeleteAsync(
                    client, IdFederationAdminTests.TestKey), "前提: 消せること");

                string cleaned = await client.GetStringAsync("/Account/Login");

                bool cleanedHas = 0 <= (cleaned ?? "").IndexOf(
                    "data-idp-key=\"" + IdFederationAdminTests.TestKey + "\"");

                r.Verify("消すと導線も消える", !cleanedHas,
                    "消える", cleanedHas ? "**残っている**" : "消えた");

                r.Done();
            }
        }

        #endregion

        #region RT-292.3

        /// <summary>RT-292.3 管理者でなければ、上流の管理画面は開かない</summary>
        /// <param name="targetKey">core / netfx</param>
        /// <returns>Task</returns>
        /// <remarks>
        /// **`UsersAdmin` と同じ認可**である（`SystemAdmin` を要求する）。
        /// **雛形のテスト利用者（`super_tanaka…`）は `User` / `Admin` しか持たない。**
        /// </remarks>
        [SkippableTheory]
        [MemberData(nameof(AllTargets))]
        public async Task RT29203_管理者でなければ上流の管理画面は開かない(string targetKey)
        {
            //  **管理者と、そうでない利用者を、別の Cookie の入れ物で測る**。
            //    **1 つの入れ物で入り直す形にしていたが、
            //    入り直しが失敗したときに「開けた」と出てしまう**（実測。sql ストアの通しで踏んだ）。
            using (IdPClient admin = this.Client(targetKey))
            using (IdPClient client = this.Client(targetKey))
            {
                //  **まず管理者で開けることを確かめる**（画面が閉じている配備では Skip）。
                await admin.SignInAsAdministratorAsync();
                await IdFederationAdmin.SkipIfLockedDownAsync(admin);

                TestReport r = this.Report("RT-292.3",
                    "管理者でなければ、上流 IdP の管理画面は開かない",
                    "**上流の登録は配備全体のもの**なので、**`SystemAdmin` だけが編める**"
                    + "（`UsersAdmin` / `RolesAdmin` と同じ認可）。"
                    + "**雛形のテスト利用者は `User` / `Admin` しか持たない**ので、"
                    + "**その利用者では開かないこと**を見る。",
                    "#292 の段階 2 / #258");

                r.Target("GET /IdFederationAdmin（テスト利用者でサインイン）");

                r.Step("(1) テスト利用者でサインインする（管理者とは別の入れ物）");

                await client.SignInAsync();

                //  **本当にテスト利用者で入れているか**を先に見る
                //    （**入れていなければ、この後の「開かない」は何も測っていない**）。
                bool signedIn = client.IsSignedIn;

                r.Verify("テスト利用者でサインインできている", signedIn,
                    "サインインしている", signedIn ? "している" : "**していない**");

                Assert.True(signedIn, "前提: テスト利用者でサインインできること");

                r.Step("(2) 一覧を開く");

                HttpResponseMessage res = await IdFederationAdmin.IndexAsync(client);
                string body = await res.Content.ReadAsStringAsync();

                bool hasCreateLink = 0 <= (body ?? "").IndexOf("/IdFederationAdmin/Create");

                r.Verify("一覧の画面にならない", !hasCreateLink,
                    "開かない", hasCreateLink ? "**開いた**" : "開かなかった");

                r.Observe("応答", ((int)res.StatusCode).ToString(),
                    "**門番が例外を投げる**ので、エラー画面か 500 になる"
                    + "（`UsersAdmin` と同じ振る舞い）。");

                r.Done();
            }
        }

        #region RT-297.2

        /// <summary>RT-297.2 上流の登録の client_secret が、暗号化しても往復する</summary>
        /// <param name="targetKey">core / netfx</param>
        /// <returns>Task</returns>
        /// <remarks>
        /// **上流の `client_secret` は、上流へ送る値**である（`/token` のクライアント認証）。
        /// **必ず平文に戻せなければならない**（#297）。
        ///
        /// **`RT-297.1`（クライアント登録）と対**である。
        /// **表が 2 つあり、どちらも同じ扱いにした**ので、**両方を測る。**
        /// </remarks>
        [SkippableTheory]
        [MemberData(nameof(AllTargets))]
        public async Task RT29702_上流の登録の秘密が暗号化しても往復する(string targetKey)
        {
            using (IdPClient client = this.Client(targetKey))
            {
                await client.SignInAsAdministratorAsync();

                string index = await IdFederationAdmin.SkipIfLockedDownAsync(client);

                TestReport r = this.Report("RT-297.2",
                    "上流の登録の `client_secret` が、暗号化しても往復する",
                    "**上流の `client_secret` は上流へ送る値**（`/token` のクライアント認証）なので、"
                    + "**必ず平文に戻せなければならない**（#297）。"
                    + "**保存して読み直したときに同じ値が出ること**を測る — "
                    + "**ここが崩れると、上流と連携できなくなる。**",
                    "#297 / #292 の段階 2");

                r.Target("POST /IdFederationAdmin/Create → GET /IdFederationAdmin/Edit");

                if (IdFederationAdmin.Contains(index, IdFederationAdminTests.SecretKey))
                {
                    await IdFederationAdmin.DeleteAsync(client, IdFederationAdminTests.SecretKey);
                }

                r.Step("(1) client_secret 付きで足す");

                //  **値はテストの中だけで使う**（**構成ファイルの秘密ではない**）。
                string secret = "E2E_rt297_" + Saml2.NewId().Replace("_", "");

                HttpResponseMessage create = await IdFederationAdmin.CreateAsync(
                    client, IdFederationAdminTests.SecretKey, "oidc",
                    "E2E RT-297 Upstream", "https://rt297.e2e.example",
                    new Dictionary<string, string>()
                    {
                        { "ClientID", "e2e0rt297000000000000000000000z2" },
                        { "ClientSecret", secret },
                        { "AuthorizeEndpoint", "https://rt297.e2e.example/authorize" },
                        { "TokenEndpoint", "https://rt297.e2e.example/token" },
                        { "UserInfoEndpoint", "https://rt297.e2e.example/userinfo" }
                    });

                bool created = create.StatusCode == HttpStatusCode.Found
                    || create.StatusCode == HttpStatusCode.Redirect
                    || create.StatusCode == HttpStatusCode.SeeOther;

                r.Verify("追加できる", created,
                    "リダイレクト", created ? "した" : "**しない（" + create.StatusCode + "）**");

                Assert.True(created, "前提: 追加できること");

                r.Step("(2) 編集画面を開くと、同じ client_secret が出る");

                string edit = await (await IdFederationAdmin.EditAsync(
                    client, IdFederationAdminTests.SecretKey)).Content.ReadAsStringAsync();

                string reloaded = Html.FieldValue(edit, "ClientSecret");

                r.Verify("入れた値と同じである", reloaded == secret,
                    "同じ（値は伏せる）",
                    (reloaded == secret) ? "同じだった"
                        : (string.IsNullOrEmpty(reloaded)
                            ? "**空になった**（復号できていない）" : "**別の値**"));

                r.Verify("暗号文がそのまま出ていない",
                    !(reloaded ?? "").StartsWith("enc:"),
                    "平文", (reloaded ?? "").StartsWith("enc:") ? "**暗号文のまま**" : "平文");

                r.Step("(3) 後片付け");

                bool deleted = await IdFederationAdmin.DeleteAsync(
                    client, IdFederationAdminTests.SecretKey);

                r.Verify("消せる", deleted, "消える", deleted ? "消えた" : "**残った**");

                r.Note("**DB に平文が残っていないこと**は、`-UserStoreType sql` で SELECT して"
                    + "確かめる（手順は `TESTING.md`）。**E2E からは DB を見ない**"
                    + "（テストに接続文字列を持たせない。`TESTING.md` 9 節）。");

                r.Done();
            }
        }

        #endregion

        #region RT-292.4

        /// <summary>RT-292.4 上流ごとの署名鍵が、user store でも往復する</summary>
        /// <param name="targetKey">core / netfx</param>
        /// <returns>Task</returns>
        /// <remarks>
        /// **段階 4-a で、(2)（下流 → 上流の要求）の署名鍵を、設定の行で指定できるようにした。**
        /// **段階 4-b は、同じものを user store にも置けるようにしたもの**である。
        ///
        /// | | |
        /// |---|---|
        /// | `SigningPfxFilePath` | **そのまま往復する**（パス） |
        /// | `SigningPfxPassword` | **暗号化して保管し、読むときに戻す**（#297 の対象。`ClientSecret` と同じ） |
        ///
        /// **指定した鍵で署名していることは、`CN-5.5`（コンテナ。設定の行）で測っている。**
        /// **ここで測るのは、入れ物（表と画面）を通しても値が壊れないこと**である。
        /// </remarks>
        [SkippableTheory]
        [MemberData(nameof(AllTargets))]
        public async Task RT29204_上流ごとの署名鍵がuser_storeでも往復する(string targetKey)
        {
            using (IdPClient client = this.Client(targetKey))
            {
                await client.SignInAsAdministratorAsync();

                string index = await IdFederationAdmin.SkipIfLockedDownAsync(client);

                TestReport r = this.Report("RT-292.4",
                    "上流ごとの署名鍵（`.pfx`）が、user store でも往復する",
                    "**(2) の署名鍵を、上流ごとに替えられるようにした**（#292 の段階 4-a）。"
                    + "**段階 4-b は、それを DB と画面からも扱えるようにしたもの**である。"
                    + "**`.pfx` のパスワードは暗号化して保管する**（#297）ので、"
                    + "**読み直したときに平文に戻ること**を測る — "
                    + "**戻らなければ `.pfx` を開けず、黙って共通設定に倒れる。**",
                    "#292 の段階 4-b / #297");

                r.Target("POST /IdFederationAdmin/Create → GET /IdFederationAdmin/Edit");

                if (IdFederationAdmin.Contains(index, IdFederationAdminTests.SigningKey))
                {
                    await IdFederationAdmin.DeleteAsync(client, IdFederationAdminTests.SigningKey);
                }

                r.Step("(1) 署名鍵付きで足す");

                //  **パスワードはテストの中だけの値**
                //    （**配備の `.pfx` のパスワードをテストに持たせない**。`TESTING.md` 9 節）。
                string pfxPassword = "E2E_rt292b_" + Saml2.NewId().Replace("_", "");
                const string pfxPath = "C:/root/files/resource/X509/SHA256RSA_Client.pfx";

                HttpResponseMessage create = await IdFederationAdmin.CreateAsync(
                    client, IdFederationAdminTests.SigningKey, "saml2",
                    "E2E RT-292 Signing", "https://rt292b.e2e.example",
                    new Dictionary<string, string>()
                    {
                        { "ClientID", "e2e0rt292b00000000000000000000z3" },
                        { "MetadataUrl", "https://rt292b.e2e.example/samlmetadata" },
                        { "SsoEndpoint", "https://rt292b.e2e.example/saml2request" },
                        { "CerFilePath", "C:/root/files/resource/X509/SHA256RSA_Server.cer" },
                        { "SigningPfxFilePath", pfxPath },
                        { "SigningPfxPassword", pfxPassword }
                    });

                bool created = create.StatusCode == HttpStatusCode.Found
                    || create.StatusCode == HttpStatusCode.Redirect
                    || create.StatusCode == HttpStatusCode.SeeOther;

                r.Verify("追加できる", created,
                    "リダイレクト",
                    created ? "した" : "**しない（" + create.StatusCode + "）**");

                Assert.True(created, "前提: 追加できること");

                r.Step("(2) 編集画面を開くと、同じ値が出る");

                string edit = await (await IdFederationAdmin.EditAsync(
                    client, IdFederationAdminTests.SigningKey)).Content.ReadAsStringAsync();

                string reloadedPath = Html.FieldValue(edit, "SigningPfxFilePath");
                string reloadedPassword = Html.FieldValue(edit, "SigningPfxPassword");

                r.Verify("`.pfx` のパスが往復する", reloadedPath == pfxPath,
                    pfxPath,
                    (reloadedPath == pfxPath) ? "同じだった"
                        : "**" + (string.IsNullOrEmpty(reloadedPath) ? "空" : "別の値") + "**");

                r.Verify("パスワードが平文に戻る", reloadedPassword == pfxPassword,
                    "同じ（値は伏せる）",
                    (reloadedPassword == pfxPassword) ? "同じだった"
                        : (string.IsNullOrEmpty(reloadedPassword)
                            ? "**空になった**（復号できていない）" : "**別の値**"));

                r.Verify("暗号文がそのまま出ていない",
                    !(reloadedPassword ?? "").StartsWith("enc:"),
                    "平文",
                    (reloadedPassword ?? "").StartsWith("enc:") ? "**暗号文のまま**" : "平文");

                r.Step("(3) 後片付け");

                bool deleted = await IdFederationAdmin.DeleteAsync(
                    client, IdFederationAdminTests.SigningKey);

                r.Verify("消せる", deleted, "消える", deleted ? "消えた" : "**残った**");

                r.Note("**このケースが測るのは、入れ物（表・辞書）と画面である。**"
                    + "**DB の行の鍵で実際に署名するところまでは測っていない** — "
                    + "**配備の `.pfx` のパスワードをテストに持たせない**ためである"
                    + "（`TESTING.md` 9 節）。**指定した鍵で署名していることは、"
                    + "`CN-5.5`（コンテナ。設定の行）とその歯抜けで測っている。**");

                r.Done();
            }
        }

        #endregion

        #endregion
    }
}
