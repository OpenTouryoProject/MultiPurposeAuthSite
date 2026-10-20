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
//* クラス名        ：SoftwareStatementAdminTests
//* クラス日本語名  ：RT-308 発行者（ベンダ）の台帳を DB ＋ 画面で持つ
//*
//* 作成日時        ：－
//* 作成者          ：－
//* 更新履歴        ：－
//*
//*  日時        更新者            内容
//*  ----------  ----------------  -------------------------------------------------
//*  2026/10/21  玄人 幸道         新規（#308 の段階 3）
//**********************************************************************************

using System;
using System.Collections.Generic;
using System.IO;
using System.Net;
using System.Net.Http;
using System.Threading.Tasks;

using MultiPurposeAuthSite.Tests.E2E.Infrastructure;

using Xunit;
using Xunit.Abstractions;

/// <summary>MultiPurposeAuthSite.Tests.E2E.Tests.Issues</summary>
namespace MultiPurposeAuthSite.Tests.E2E.Tests.Issues
{
    /// <summary>
    /// RT-308 発行者（ベンダ）の台帳を DB ＋ 画面で持つ（#308）。
    /// </summary>
    /// <remarks>
    /// **`software_statement` の発行者は、設定ファイルにしか置けなかった**（#307 の段階 4）。
    /// **提携先が増えるたびに配備のファイルを触り、再起動していた。**
    ///
    /// | | |
    /// |---|---|
    /// | **段階 1** | **表 ＋ Provider ＋ 本文（`CerBody`）からの検証** |
    /// | **段階 2** | **管理画面**（`/SoftwareStatementAdmin`。`SystemAdmin`） |
    /// | **段階 3** | **ここ**（測り） |
    ///
    /// **読み出しは 設定 → DB の順**で、**同じ鍵なら設定が勝つ**
    /// （`IdFederationUpstreams` と同じ流儀。#292 の段階 2）。
    ///
    /// **鍵（`IssuerKey`）は対象ごとに分ける** —
    /// **DB ストアでは 2 つのサイトが 1 つの DB を共有する**ので、
    /// **同じ鍵を使うと奪い合う**（#260 と同じ事情）。
    /// </remarks>
    public class SoftwareStatementAdminTests : TargetTestBase
    {
        /// <summary>コンストラクタ</summary>
        /// <param name="output">ITestOutputHelper</param>
        public SoftwareStatementAdminTests(ITestOutputHelper output) : base(output) { }

        #region RT-308.1

        /// <summary>RT-308.1 画面から発行者を足して、直して、消せる</summary>
        /// <param name="targetKey">core / netfx</param>
        /// <returns>Task</returns>
        [SkippableTheory]
        [MemberData(nameof(AllTargets))]
        public async Task RT30801_画面から発行者を足して直して消せる(string targetKey)
        {
            using (IdPClient admin = this.Client(targetKey))
            {
                await admin.SignInAsAdministratorAsync();
                await SoftwareStatementAdmin.SkipIfLockedDownAsync(admin);

                TestReport r = this.Report("RT-308.1",
                    "**発行者（ベンダ）の台帳を、画面から足して・直して・消せる**",
                    "**発行者は設定ファイルにしか置けなかった**（#307 の段階 4）。"
                    + "**提携先が増えるたびに配備のファイルを触り、再起動していた。**"
                    + "**段階 6 で「許す範囲」（`allowed_scope`）が増えて、"
                    + "台帳としての性格が強くなった**ので、**画面で動かせるようにした**（#308）。",
                    "#308 の段階 2 / SoftwareStatementAdminController");

                r.Target("GET/POST /SoftwareStatementAdmin（Index / Create / Edit / Delete）");

                string key = "e2e_rt308_" + targetKey;

                //  **前の回の残りを消しておく**（落ちた回の後始末）。
                await SoftwareStatementAdmin.DeleteAsync(admin, key);

                try
                {
                    r.Step("(1) 足す");

                    HttpResponseMessage created = await SoftwareStatementAdmin.CreateAsync(
                        admin, key, "https://e2e-rt308.example.com/" + targetKey,
                        new Dictionary<string, string>()
                        {
                            { "CerFilePath", "C:/root/files/resource/X509/SHA256RSA_Server.cer" },
                            { "AllowedScope", "openid email" }
                        });

                    r.Verify("一覧へ戻る（追加の成功）",
                        SoftwareStatementAdminTests.IsRedirect(created),
                        "リダイレクト", ((int)created.StatusCode).ToString());

                    string index = await (await SoftwareStatementAdmin.IndexAsync(admin))
                        .Content.ReadAsStringAsync();

                    r.Verify("一覧に出る", SoftwareStatementAdmin.Contains(index, key),
                        "出る", SoftwareStatementAdmin.Contains(index, key) ? "出た" : "**出ない**");

                    r.Step("(2) 直す");

                    HttpResponseMessage edited = await SoftwareStatementAdmin.EditDisplayNameAsync(
                        admin, key, "E2E Vendor (edited)",
                        new Dictionary<string, string>()
                        {
                            { "Issuer", "https://e2e-rt308.example.com/" + targetKey },
                            { "Alg", "RS256" },
                            { "CerFilePath", "C:/root/files/resource/X509/SHA256RSA_Server.cer" },
                            { "AllowedScope", "openid" }
                        });

                    r.Verify("一覧へ戻る（更新の成功）",
                        SoftwareStatementAdminTests.IsRedirect(edited),
                        "リダイレクト", ((int)edited.StatusCode).ToString());

                    string reopened = await (await SoftwareStatementAdmin.EditAsync(admin, key))
                        .Content.ReadAsStringAsync();

                    r.VerifyEqual("直した表示名が出る", "E2E Vendor (edited)",
                        Html.FieldValue(reopened, "DisplayName") ?? "（無い）");

                    r.VerifyEqual("直した上限が出る", "openid",
                        Html.FieldValue(reopened, "AllowedScope") ?? "（無い）");

                    r.Step("(3) 消す");

                    bool deleted = await SoftwareStatementAdmin.DeleteAsync(admin, key);

                    r.Verify("一覧へ戻る（削除の成功）", deleted,
                        "リダイレクト", deleted ? "リダイレクト" : "**違う応答**");

                    string after = await (await SoftwareStatementAdmin.IndexAsync(admin))
                        .Content.ReadAsStringAsync();

                    r.Verify("一覧から消える", !SoftwareStatementAdmin.Contains(after, key),
                        "消える", SoftwareStatementAdmin.Contains(after, key)
                            ? "**残った**" : "消えた");

                    r.Note("**鍵（`IssuerKey`）は追加のときだけ入れられる**（PK なので後から変えない）。"
                        + "**編集では hidden で持ち回る。**");

                    r.Done();
                }
                finally
                {
                    await SoftwareStatementAdmin.DeleteAsync(admin, key);
                }
            }
        }

        #endregion

        #region RT-308.2

        /// <summary>RT-308.2 DB に入れた発行者（本文の鍵）で、登録が通る</summary>
        /// <param name="targetKey">core / netfx</param>
        /// <returns>Task</returns>
        /// <remarks>
        /// **`.cer` を本文（`CerBody`）で持てる**ことの肝である（#308 の段階 1）。
        /// **ファイルを置かずに、台帳だけで検証が成立する**ことを測る。
        /// </remarks>
        [SkippableTheory]
        [MemberData(nameof(AllTargets))]
        public async Task RT30802_DBに入れた発行者の本文の鍵で登録が通る(string targetKey)
        {
            using (IdPClient admin = this.Client(targetKey))
            {
                await admin.SignInAsAdministratorAsync();
                await SoftwareStatementAdmin.SkipIfLockedDownAsync(admin);

                await Flows.SkipIfGrantTypeNotSupportedAsync(admin, "password");
                string endpoint = await DynamicClientRegistration.SkipIfNotSupportedAsync(admin);

                //  **署名する鍵と、その証明書**（**構成ファイルに在る対**を使う）。
                //    `RsaPfxFilePath` ↔ `SpRp_RsaCerFilePath`（どちらも SHA256RSA_Server）。
                string cerPath = admin.Config.Get("SpRp_RsaCerFilePath");

                Skip.If(string.IsNullOrEmpty(cerPath) || !File.Exists(cerPath),
                    "証明書（SpRp_RsaCerFilePath）が読めません。");

                TestReport r = this.Report("RT-308.2",
                    "**DB に入れた発行者**（**証明書を本文で持つ**）**の `software_statement` で、"
                    + "登録が通る**",
                    "**設定ファイルに書くには `.cer` をサーバへ配る必要があった**（#307 の段階 4）。"
                    + "**本文（`CerBody`）で持てるようにした**（#308 の段階 1）ので、"
                    + "**台帳を複製するだけで、提携先を増やせる。**"
                    + "**Open棟梁 の X509 の口はファイル パスだけ**なので、"
                    + "**本文からはパラメタ渡しで検証している**（`JWS_*_Param`）。",
                    "#308 の段階 1 / SoftwareStatementProvider.JwsFromCerBody");

                r.Target("POST registration_endpoint（DB の発行者。本文の鍵で検証）");

                string key = "e2e_rt308body_" + targetKey;
                string iss = "https://e2e-rt308-body.example.com/" + targetKey;

                await SoftwareStatementAdmin.DeleteAsync(admin, key);

                try
                {
                    r.Step("(1) 画面から、証明書の本文で発行者を足す");

                    //  **PEM をそのまま貼る**（**画面に貼るのと同じ形**）。
                    string pem = SoftwareStatementAdminTests.ToPem(cerPath);

                    HttpResponseMessage created = await SoftwareStatementAdmin.CreateAsync(
                        admin, key, iss,
                        new Dictionary<string, string>() { { "CerBody", pem } });

                    r.Verify("一覧へ戻る（追加の成功）",
                        SoftwareStatementAdminTests.IsRedirect(created),
                        "リダイレクト", ((int)created.StatusCode).ToString());

                    r.Note("**`CerFilePath` は空**である（**ファイルを指していない**）。"
                        + "**検証に使うのは、貼った本文だけ。**");

                    r.Step("(2) その発行者の statement で登録できる");

                    await this.WithDcrAsync(admin, targetKey, async (client, token) =>
                    {
                        Dictionary<string, object> claims = new Dictionary<string, object>()
                        {
                            { "iss", iss },
                            { "jti", Guid.NewGuid().ToString("N") },
                            { "iat", DateTimeOffset.UtcNow.ToUnixTimeSeconds() },
                            { "software_id", "e2e-rt308" },
                            { "redirect_uris", new string[] { SoftwareStatementAdminTests.UriA } }
                        };

                        //  **構成ファイルの `RsaPfxFilePath` で署名する**
                        //    （**上で貼った `.cer` と対**である）。
                        JsonResponse res = await DynamicClientRegistration.RegisterAsync(
                            client, endpoint, token,
                            "{\"software_statement\":\""
                            + JwsSigner.SignRS256(client, claims,
                                "RsaPfxFilePath", "RsaPfxPassword") + "\"}");

                        r.VerifyEqual("HTTP の状態は 201", "201",
                            ((int)res.StatusCode).ToString());

                        r.VerifyEqual("主張した折り返し先が入る", "True",
                            res.ArrayContains(
                                "redirect_uris", SoftwareStatementAdminTests.UriA).ToString());
                    });

                    r.Step("(3) 発行者を消すと、同じ statement は通らなくなる");

                    Assert.True(await SoftwareStatementAdmin.DeleteAsync(admin, key),
                        "前提: 発行者を消せること");

                    await this.WithDcrAsync(admin, targetKey, async (client, token) =>
                    {
                        Dictionary<string, object> claims = new Dictionary<string, object>()
                        {
                            { "iss", iss },
                            { "jti", Guid.NewGuid().ToString("N") },
                            { "iat", DateTimeOffset.UtcNow.ToUnixTimeSeconds() },
                            { "software_id", "e2e-rt308" },
                            { "redirect_uris", new string[] { SoftwareStatementAdminTests.UriA } }
                        };

                        JsonResponse res = await DynamicClientRegistration.RegisterAsync(
                            client, endpoint, token,
                            "{\"software_statement\":\""
                            + JwsSigner.SignRS256(client, claims,
                                "RsaPfxFilePath", "RsaPfxPassword") + "\"}");

                        r.VerifyEqual("HTTP の状態は 400", "400",
                            ((int)res.StatusCode).ToString());

                        r.VerifyEqual("error は unapproved_software_statement",
                            "unapproved_software_statement", res.String("error") ?? "（無い）");
                    });

                    r.Note("**台帳から消すと、その発行者の保証は、その場で効かなくなる** — "
                        + "**設定ファイルを触って再起動する必要が無い**（これが #308 の値打ち）。");

                    r.Done();
                }
                finally
                {
                    await SoftwareStatementAdmin.DeleteAsync(admin, key);
                }
            }
        }

        #endregion

        #region RT-308.3

        /// <summary>RT-308.3 同じ鍵なら設定が勝つ（画面からは足せない）</summary>
        /// <param name="targetKey">core / netfx</param>
        /// <returns>Task</returns>
        [SkippableTheory]
        [MemberData(nameof(AllTargets))]
        public async Task RT30803_同じ鍵なら設定が勝つ(string targetKey)
        {
            using (IdPClient admin = this.Client(targetKey))
            {
                await admin.SignInAsAdministratorAsync();
                await SoftwareStatementAdmin.SkipIfLockedDownAsync(admin);

                string settingKey = Environment.GetEnvironmentVariable(
                    "MPAS_SOFTWARE_STATEMENT_KEY") ?? "";

                Skip.If(string.IsNullOrEmpty(settingKey),
                    "この配備は、設定ファイルの発行者の鍵をテストへ渡していません"
                    + "（test.ps1 -Launch が渡す。#308 の段階 3）。");

                TestReport r = this.Report("RT-308.3",
                    "**設定ファイルに在る鍵は、画面から足せない**（**同じ鍵なら設定が勝つ**）",
                    "**読み出しは 設定 → DB の順**で、**同じ鍵なら設定が勝つ**"
                    + "（`IdFederationUpstreams` と同じ流儀。#292 の段階 2）。"
                    + "**使われない行を台帳に増やさない**ために、**追加の時点で断る。**",
                    "#308 の段階 2 / SoftwareStatementAdminController.IsInSetting");

                r.Target("POST /SoftwareStatementAdmin/Create（設定に在る鍵）");

                r.Step("(1) 設定の鍵と同じ鍵では足せない");

                try
                {
                    HttpResponseMessage denied = await SoftwareStatementAdmin.CreateAsync(
                        admin, settingKey, "https://e2e-rt308-dup.example.com",
                        new Dictionary<string, string>()
                        {
                            { "CerFilePath", "C:/root/files/resource/X509/SHA256RSA_Server.cer" }
                        });

                    r.VerifyEqual("一覧へ戻らない（再表示）", "200",
                        ((int)denied.StatusCode).ToString());

                    string body = await denied.Content.ReadAsStringAsync();

                    r.Verify("誤りが出る", Html.HasValidationError(body),
                        "出る", Html.HasValidationError(body) ? "出た" : "**出ない**");

                    r.Observe("誤りの文面", Html.ErrorSummary(body) ?? "（無い）");

                    r.Step("(2) 設定の発行者は、そのまま効いている");

                    string index = await (await SoftwareStatementAdmin.IndexAsync(admin))
                        .Content.ReadAsStringAsync();

                    r.Verify("設定の行は、この画面に出ない",
                        !SoftwareStatementAdmin.Contains(index, settingKey),
                        "出ない", SoftwareStatementAdmin.Contains(index, settingKey)
                            ? "**出てしまった**" : "出ない");

                    r.Note("**この画面が編むのは user store の行だけ**である。"
                        + "**設定ファイルの行は、画面からは触れない** — "
                        + "**設定を直して再起動する**のが、その行の直し方になる。");

                    r.Done();
                }
                finally
                {
                    //  **足せてしまったときの後片付け**（#308 の段階 3）。
                    //    **歯抜け（重複を見ない）を入れると、実際に行が作られる** —
                    //    **`mem` では消えるが、DB ストアでは残る**ので、ここで消す
                    //    （**作ったテストが、同じテストの中で消す**）。
                    await SoftwareStatementAdmin.DeleteAsync(admin, settingKey);
                }
            }
        }

        #endregion

        #region 補助

        /// <summary>折り返し先（登録に使う）</summary>
        private const string UriA = "https://localhost:44300/e2e/rt308/cb";

        /// <summary>リダイレクトか</summary>
        /// <param name="res">応答</param>
        /// <returns>リダイレクトなら true</returns>
        private static bool IsRedirect(HttpResponseMessage res)
        {
            return res.StatusCode == HttpStatusCode.Found
                || res.StatusCode == HttpStatusCode.Redirect
                || res.StatusCode == HttpStatusCode.SeeOther;
        }

        /// <summary>`.cer` を PEM の文字列にする（#308 の段階 3）</summary>
        /// <param name="cerFilePath">`.cer` のパス</param>
        /// <returns>PEM</returns>
        /// <remarks>
        /// **画面に貼るのと同じ形**にする（**人がやることを、そのまま測る**）。
        /// **`.cer` は DER でも PEM でも在り得る**ので、**読んでから作り直す。**
        /// </remarks>
        private static string ToPem(string cerFilePath)
        {
            byte[] der = File.ReadAllBytes(cerFilePath);
            string text = System.Text.Encoding.ASCII.GetString(der);

            if (0 <= text.IndexOf("-----BEGIN CERTIFICATE-----"))
            {
                //  **既に PEM**（そのまま貼れる）。
                return text;
            }

            return "-----BEGIN CERTIFICATE-----\n"
                + Convert.ToBase64String(der, Base64FormattingOptions.InsertLineBreaks)
                + "\n-----END CERTIFICATE-----";
        }

        /// <summary>管理 API を叩けるトークンを用意して渡す（#308 の段階 3）</summary>
        /// <param name="admin">管理者のクライアント</param>
        /// <param name="targetKey">core / netfx</param>
        /// <param name="body">測る本体（client / access_token）</param>
        /// <returns>Task</returns>
        /// <remarks>
        /// **`ClientRegistrationTests.WithDcrAsync` と同じ形**だが、
        /// **こちらは「所有者」を測らない**ので、**使い捨ての利用者 1 人で足りる。**
        /// **専用 scope は画面から登録する**（**動的登録では配れない**。#307 の段階 1）。
        /// </remarks>
        private async Task WithDcrAsync(
            IdPClient admin, string targetKey, Func<IdPClient, string, Task> body)
        {
            string name = "e2e_rt308_" + Guid.NewGuid().ToString("N").Substring(0, 8);
            string password = admin.Config.Get("TestUserPWD");

            await UsersAdmin.CreateAsync(admin, name, name + "@example.com", "Admin");

            try
            {
                using (IdPClient client = this.Client(targetKey))
                {
                    Assert.True(await client.TrySignInAsync(name, password),
                        "前提: 使い捨ての利用者でサインインできること");

                    (string ClientId, string ClientSecret) registered =
                        await ManageClientRegistration.RegisterWithSecretAsync(client,
                            new Dictionary<string, string>()
                            {
                                { "Scopes", DynamicClientRegistration.Scope }
                            });

                    Assert.False(string.IsNullOrEmpty(registered.ClientId),
                        "前提: 管理 API 用のクライアントを登録できること");

                    JsonResponse token = await DynamicClientRegistration.TokenAsync(
                        client, registered.ClientId, registered.ClientSecret, name, password);

                    string accessToken = token.String("access_token");

                    Assert.False(string.IsNullOrEmpty(accessToken),
                        "前提: 専用 scope のトークンが取れること");

                    await body(client, accessToken);
                }
            }
            finally
            {
                //  **利用者を消すと、その人の登録も消える**（cascade。#307 の段階 5-a-1）。
                await UsersAdmin.DeleteByUserNameAsync(admin, name);
            }
        }

        #endregion
    }
}
