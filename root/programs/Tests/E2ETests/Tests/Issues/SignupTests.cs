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
//* クラス名        ：SignupTests
//* クラス日本語名  ：RT-257 サインアップ画面（/Account/Register）
//*
//* 作成日時        ：－
//* 作成者          ：－
//* 更新履歴        ：－
//*
//*  日時        更新者            内容
//*  ----------  ----------------  -------------------------------------------------
//*  2026/10/02  玄人 幸道         新規（#257）
//**********************************************************************************

using System;
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
    /// RT-257.1 〜 .4 サインアップ画面（#257）。
    /// </summary>
    /// <remarks>
    /// **この画面は、一度も叩いていなかった。**
    /// 利用者は**種データ**（`CreateData`）で作られるので、
    /// **テストが自分で作る機会が無かった**ためである。
    /// その結果、**#151 の段階 3 で入れた不具合（空欄に「`@` は使えません」と出る）が、
    /// 目視まで出てこなかった。**
    ///
    /// **判定は、文言に依存させない。**
    /// 画面の言語は配備（サーバの既定カルチャ）で変わるため、
    /// **「どの欄が間違っていると言われたか」**で見る。
    ///
    /// | 出方 | 何を意味するか |
    /// |---|---|
    /// | 欄に `input-validation-error` が付く | **その欄のエラー**（`[Required]` / `[EmailAddress]`） |
    /// | 付かず、要約だけに出る | **モデル全体のエラー**（`ModelState.AddModelError("", …)`） |
    ///
    /// **利用者名の `@` は、モデル全体のエラー**である（コントローラが足す）。
    /// **空欄は、それぞれの欄のエラー**である（属性が足す）。
    /// **この 2 つが入れ替わっていたのが、あの不具合だった。**
    /// </remarks>
    public class SignupTests : TargetTestBase
    {
        /// <summary>コンストラクタ</summary>
        /// <param name="output">ITestOutputHelper</param>
        public SignupTests(ITestOutputHelper output) : base(output)
        {
        }

        /// <summary>RT-257.1 利用者名とメアドを入れると、サインアップできる</summary>
        /// <param name="targetKey">core / netfx</param>
        /// <returns>Task</returns>
        [SkippableTheory]
        [MemberData(nameof(AllTargets))]
        public async Task RT25701_利用者名とメアドでサインアップできる(string targetKey)
        {
            using (IdPClient client = this.Client(targetKey))
            {
                string userName = SignupTests.UniqueName();
                string email = userName + "@example.com";

                TestReport r = this.Report("RT-257.1",
                    "利用者名とメアドを入れると、サインアップできる",
                    "**利用者を作る唯一の口**（種データ以外）。"
                    + "**#151 の段階 3 で、利用者名とメアドを別々に受け取る形に変えた**ので、"
                    + "**両方を入れて通ることを押さえる。**"
                    + "成功すると**メアド検証の画面**へ進む（リダイレクトではない）。",
                    "#151 の段階 3 / #257");

                r.Target("利用者名 = " + userName + " / メアド = " + email);

                r.Step("(1) サインアップ画面を開く");

                string form = await SignupTests.GetRegisterAsync(client, r);

                r.Step("(2) 利用者名・メアド・パスワードを送る");

                HttpResponseMessage post = await SignupTests.PostRegisterAsync(
                    client, form, userName, email);
                string body = await post.Content.ReadAsStringAsync();

                r.VerifyEqual("HTTP 200", "200", ((int)post.StatusCode).ToString());

                r.Verify("**サインアップ画面が再表示されない**（＝ 検証エラーが無い）",
                    !Html.HasField(body, "ConfirmPassword"),
                    "入力欄は無い",
                    Html.HasField(body, "ConfirmPassword")
                        ? "**入力欄が在る**（弾かれた）: " + Html.ErrorSummary(body) : "入力欄は無い");

                r.Verify("メアド検証の画面へ進む（入力欄が無く、エラーも無い）",
                    !Html.HasValidationError(body),
                    "エラー無し",
                    Html.HasValidationError(body) ? "**エラーが出ている**" : "エラー無し");

                r.Observe("作った利用者の状態",
                    "EmailConfirmed = false（メアド検証のリンクを踏むまで）",
                    "**この利用者ではサインインできない**（サインインは EmailConfirmed を見る）。"
                    + "**メールは送られる**が、`IsDebug` のときは送信せずデバッグ出力に書くだけである。");

                r.Step("(3) 後片付け : 管理画面から削除する");

                bool deleted = await SignupTests.DeleteUserAsync(client, userName);

                r.Verify("作った利用者を削除できた（DB ストアに残さない）",
                    deleted, "削除できた", deleted ? "削除できた" : "**削除できなかった**");

                r.Note("**後片付けを、同じテストの中で行う。** `mem` では再起動で消えるが、"
                    + "**DB ストアでは残る**ので、**次の回の一覧に積み上がる。**"
                    + "削除には**管理者のサインイン**が要る（`SystemAdmin` ロール）。");

                r.Done();
            }
        }

        /// <summary>RT-257.2 利用者名に「@」を入れると弾かれる</summary>
        /// <param name="targetKey">core / netfx</param>
        /// <returns>Task</returns>
        [SkippableTheory]
        [MemberData(nameof(AllTargets))]
        public async Task RT25702_利用者名にアットマークは使えない(string targetKey)
        {
            using (IdPClient client = this.Client(targetKey))
            {
                string email = SignupTests.UniqueName() + "@example.com";

                TestReport r = this.Report("RT-257.2",
                    "利用者名に「@」を入れると弾かれる（モデル全体のエラーになる）",
                    "**サインインは 1 つの欄で受け、`@` を含むならメアドとして引く**（#151 の段階 3）。"
                    + "**利用者名に `@` を許すと、入力がどちらなのか決まらなくなる。**"
                    + "**欄のエラーではなくモデル全体のエラー**になることまで見るのは、"
                    + "**空欄のときと入れ替わらない**ことを押さえるためである。",
                    "#151 の段階 3 / #257");

                r.Target("利用者名 = \"bad@name\"（メアドの形）");

                string form = await SignupTests.GetRegisterAsync(client, r);

                r.Step("利用者名に「@」を入れて送る");

                HttpResponseMessage post = await SignupTests.PostRegisterAsync(
                    client, form, "bad@name", email);
                string body = await post.Content.ReadAsStringAsync();

                r.VerifyEqual("HTTP 200（再表示。500 にならない）",
                    "200", ((int)post.StatusCode).ToString());

                r.Verify("サインアップ画面が再表示される（入力欄が在る）",
                    Html.HasField(body, "ConfirmPassword"),
                    "入力欄が在る",
                    Html.HasField(body, "ConfirmPassword") ? "入力欄が在る" : "**入力欄が無い**（通ってしまった）");

                r.Verify("エラーが出ている",
                    Html.HasValidationError(body),
                    "出ている", Html.HasValidationError(body) ? "出ている" : "**出ていない**");

                r.Verify("**モデル全体のエラーである**（利用者名の欄のエラーではない）",
                    !Html.HasFieldError(body, "Name"),
                    "欄のエラーではない",
                    Html.HasFieldError(body, "Name")
                        ? "**利用者名の欄のエラーになっている**（空欄のときと区別が付かない）"
                        : "欄のエラーではない");

                r.Note("**入力した値は出力しない方針だが、ここは例外にしている。**"
                    + "`bad@name` は**テストが作った値**で、秘密ではない。");

                r.Done();
            }
        }

        /// <summary>RT-257.3 利用者名が空／メアドが空のとき、それぞれの欄のエラーになる</summary>
        /// <param name="targetKey">core / netfx</param>
        /// <returns>Task</returns>
        [SkippableTheory]
        [MemberData(nameof(AllTargets))]
        public async Task RT25703_空欄はそれぞれの欄のエラーになる(string targetKey)
        {
            using (IdPClient client = this.Client(targetKey))
            {
                TestReport r = this.Report("RT-257.3",
                    "利用者名が空／メアドが空のとき、それぞれの欄のエラーになる",
                    "**ここが「あべこべ」だった。**"
                    + "**空欄なのに「利用者名に `@` は使えません」と出ていた**"
                    + "（#151 の段階 3 で、空と `@` 入りを区別していなかった）。"
                    + "**両方を `[Required]` にして、属性に言わせる形に直した。**"
                    + "**欄のエラーとして出ること**が、その直し方が効いている証拠になる。",
                    "#151 の段階 3（目視で見つかった不具合）/ #257");

                r.Target("利用者名 = 空 / メアド = 空（それぞれ別に送る）");

                r.Step("(1) 利用者名だけ空で送る");

                string form = await SignupTests.GetRegisterAsync(client, r);
                HttpResponseMessage post = await SignupTests.PostRegisterAsync(
                    client, form, "", SignupTests.UniqueName() + "@example.com");
                string body = await post.Content.ReadAsStringAsync();

                r.VerifyEqual("HTTP 200（再表示）", "200", ((int)post.StatusCode).ToString());

                r.Verify("**利用者名の欄のエラーになる**",
                    Html.HasFieldError(body, "Name"),
                    "利用者名の欄",
                    Html.HasFieldError(body, "Name") ? "利用者名の欄" : "**利用者名の欄ではない**");

                r.Verify("メアドの欄のエラーにはならない",
                    !Html.HasFieldError(body, "Email"),
                    "ならない",
                    Html.HasFieldError(body, "Email") ? "**なっている**" : "ならない");

                r.Step("(2) メアドだけ空で送る");

                form = await SignupTests.GetRegisterAsync(client, r);
                post = await SignupTests.PostRegisterAsync(
                    client, form, SignupTests.UniqueName(), "");
                body = await post.Content.ReadAsStringAsync();

                r.VerifyEqual("HTTP 200（再表示）", "200", ((int)post.StatusCode).ToString());

                r.Verify("**メアドの欄のエラーになる**",
                    Html.HasFieldError(body, "Email"),
                    "メアドの欄",
                    Html.HasFieldError(body, "Email") ? "メアドの欄" : "**メアドの欄ではない**");

                r.Verify("利用者名の欄のエラーにはならない",
                    !Html.HasFieldError(body, "Name"),
                    "ならない",
                    Html.HasFieldError(body, "Name") ? "**なっている**" : "ならない");

                r.Note("**文言は見ない。** 画面の言語は配備で変わる。"
                    + "**「どの欄が間違っていると言われたか」**で判定している（`input-validation-error`）。");

                r.Done();
            }
        }

        /// <summary>RT-257.4 メアドの形式が不正なら弾かれる</summary>
        /// <param name="targetKey">core / netfx</param>
        /// <returns>Task</returns>
        [SkippableTheory]
        [MemberData(nameof(AllTargets))]
        public async Task RT25704_メアドの形式が不正なら弾かれる(string targetKey)
        {
            using (IdPClient client = this.Client(targetKey))
            {
                TestReport r = this.Report("RT-257.4",
                    "メアドの形式が不正なら弾かれる（メアドの欄のエラー）",
                    "**メアドは、サインインの識別子であり、ID 連携の鍵でもある**（#151 の段階 3）。"
                    + "**形になっていない値を入れさせない。**",
                    "#151 の段階 3 / #257");

                r.Target("メアド = \"not-an-email\"");

                string form = await SignupTests.GetRegisterAsync(client, r);

                r.Step("メアドの形になっていない値を送る");

                HttpResponseMessage post = await SignupTests.PostRegisterAsync(
                    client, form, SignupTests.UniqueName(), "not-an-email");
                string body = await post.Content.ReadAsStringAsync();

                r.VerifyEqual("HTTP 200（再表示）", "200", ((int)post.StatusCode).ToString());

                r.Verify("**メアドの欄のエラーになる**",
                    Html.HasFieldError(body, "Email"),
                    "メアドの欄",
                    Html.HasFieldError(body, "Email") ? "メアドの欄" : "**メアドの欄ではない**");

                r.Verify("利用者は作られない（入力欄が残る）",
                    Html.HasField(body, "ConfirmPassword"),
                    "入力欄が在る",
                    Html.HasField(body, "ConfirmPassword") ? "入力欄が在る" : "**入力欄が無い**（通ってしまった）");

                r.Done();
            }
        }

        #region 補助

        /// <summary>この回だけの利用者名を作る（DB ストアでも衝突しない）</summary>
        /// <returns>利用者名</returns>
        private static string UniqueName()
        {
            return "e2e_signup_" + Guid.NewGuid().ToString("N").Substring(0, 8);
        }

        /// <summary>サインアップ画面を開き、本文を返す</summary>
        /// <param name="client">IdPClient</param>
        /// <param name="r">TestReport</param>
        /// <returns>本文</returns>
        private static async Task<string> GetRegisterAsync(IdPClient client, TestReport r)
        {
            HttpResponseMessage get = await client.GetAsync("/Account/Register");
            string body = await get.Content.ReadAsStringAsync();

            // **サインアップが閉じていれば Error 画面になる**（EnableSignupProcess）。
            Skip.IfNot(get.StatusCode == HttpStatusCode.OK && Html.HasField(body, "ConfirmPassword"),
                "サインアップ画面が開きません（EnableSignupProcess を確認）。");

            return body;
        }

        /// <summary>サインアップ画面に送る</summary>
        /// <param name="client">IdPClient</param>
        /// <param name="formBody">GET で受けた本文（トークンを取る）</param>
        /// <param name="userName">利用者名</param>
        /// <param name="email">メアド</param>
        /// <returns>応答</returns>
        private static Task<HttpResponseMessage> PostRegisterAsync(
            IdPClient client, string formBody, string userName, string email)
        {
            // **パスワードは構成ファイルの値を使う**（配備の方針を満たすため。値は出力しない）。
            string password = client.Config.Get("TestUserPWD");

            Dictionary<string, string> form = new Dictionary<string, string>()
            {
                { "__RequestVerificationToken", Html.Antiforgery(formBody) },
                { "Name", userName },
                { "Email", email },
                { "Password", password },
                { "ConfirmPassword", password }
            };

            return client.PostFormAsync("/Account/Register", form);
        }

        /// <summary>作った利用者を、管理画面から削除する（後片付け）</summary>
        /// <param name="client">IdPClient</param>
        /// <param name="userName">利用者名</param>
        /// <returns>削除できたか</returns>
        /// <remarks>
        /// **管理者で入り直す**（管理画面は `SystemAdmin` を要求する）。
        /// **この client は、この後サインアップに使わない**ので、入り直して構わない。
        /// </remarks>
        private static async Task<bool> DeleteUserAsync(IdPClient client, string userName)
        {
            await client.SignInAsAdministratorAsync();
            return await UsersAdmin.DeleteByUserNameAsync(client, userName);
        }

        #endregion
    }
}
