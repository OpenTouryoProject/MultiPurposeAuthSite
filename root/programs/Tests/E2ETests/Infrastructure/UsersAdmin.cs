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
//* クラス名        ：UsersAdmin
//* クラス日本語名  ：利用者管理の画面を駆動する（テスト用）
//*
//* 作成日時        ：－
//* 作成者          ：－
//* 更新履歴        ：－
//*
//*  日時        更新者            内容
//*  ----------  ----------------  -------------------------------------------------
//*  2026/10/02  玄人 幸道         新規（#257）
//**********************************************************************************

using System.Collections.Generic;
using System.Net;
using System.Net.Http;
using System.Text.RegularExpressions;
using System.Threading.Tasks;

namespace MultiPurposeAuthSite.Tests.E2E.Infrastructure
{
    /// <summary>
    /// 利用者管理の画面（`/UsersAdmin`）を、HTTP で駆動する（#257）。
    /// </summary>
    /// <remarks>
    /// **サインインが要る。** 画面は **`SystemAdmin` ロール**を要求するので、
    /// **`IdPClient.SignInAsAdministratorAsync`** で入っておくこと
    /// （雛形のテスト利用者は `User` / `Admin` しか持たない）。
    ///
    /// **`EnableAdministrationOfUsersAndRoles` が false なら、画面は開かない**
    /// （`SkipIfLockedDownAsync` で判定できる）。
    ///
    /// **net48 版と net10.0 版の両方に在る**（#258 で移植した）。
    /// </remarks>
    public static class UsersAdmin
    {
        /// <summary>一覧の行（利用者名・メアド・id）</summary>
        private static readonly Regex RowRegex = new Regex(
            "<tr[^>]*>\\s*<td[^>]*>\\s*(?<name>[^<]*?)\\s*</td>\\s*"
            + "<td[^>]*>\\s*(?<email>[^<]*?)\\s*</td>\\s*"
            + "<td[^>]*>.*?/UsersAdmin/Edit/(?<id>[^\"]+)\"",
            RegexOptions.Compiled | RegexOptions.IgnoreCase | RegexOptions.Singleline);

        /// <summary>一覧を開く</summary>
        /// <param name="client">IdPClient</param>
        /// <returns>応答</returns>
        public static Task<HttpResponseMessage> IndexAsync(IdPClient client)
        {
            return client.GetAsync("/UsersAdmin");
        }

        /// <summary>
        /// 画面が閉じていれば Skip する（`EnableAdministrationOfUsersAndRoles`）。
        /// </summary>
        /// <param name="client">IdPClient</param>
        /// <returns>一覧の本文</returns>
        public static async Task<string> SkipIfLockedDownAsync(IdPClient client)
        {
            HttpResponseMessage get = await UsersAdmin.IndexAsync(client);
            string body = await get.Content.ReadAsStringAsync();

            // **ロックダウンされていると、エラー画面になる**（門番が例外を投げる）。
            //   一覧の画面なら、検索の欄（UserNameforSearch）が在る。
            Xunit.Skip.IfNot(
                get.StatusCode == HttpStatusCode.OK && Html.HasField(body, "UserNameforSearch"),
                "利用者管理の画面が開きません"
                + "（EnableAdministrationOfUsersAndRoles と、管理者のサインインを確認）。");

            return body;
        }

        /// <summary>一覧から、利用者名で id を引く（無ければ null）</summary>
        /// <param name="indexBody">一覧の本文</param>
        /// <param name="userName">利用者名</param>
        /// <returns>id</returns>
        public static string FindId(string indexBody, string userName)
        {
            foreach (Match m in UsersAdmin.RowRegex.Matches(indexBody ?? ""))
            {
                if (WebUtility.HtmlDecode(m.Groups["name"].Value) == userName)
                {
                    return m.Groups["id"].Value;
                }
            }

            return null;
        }

        /// <summary>一覧から、利用者名でメアドを引く（無ければ null）</summary>
        /// <param name="indexBody">一覧の本文</param>
        /// <param name="userName">利用者名</param>
        /// <returns>メアド</returns>
        /// <remarks>
        /// **利用者名とメアドが別の列に出ていること**を見るために使う（#151 の段階 3）。
        /// </remarks>
        public static string FindEmail(string indexBody, string userName)
        {
            foreach (Match m in UsersAdmin.RowRegex.Matches(indexBody ?? ""))
            {
                if (WebUtility.HtmlDecode(m.Groups["name"].Value) == userName)
                {
                    return WebUtility.HtmlDecode(m.Groups["email"].Value);
                }
            }

            return null;
        }

        /// <summary>利用者を作る（画面から）</summary>
        /// <param name="client">IdPClient</param>
        /// <param name="userName">利用者名</param>
        /// <param name="email">メアド</param>
        /// <param name="role">付けるロール（null なら付けない）</param>
        /// <returns>応答</returns>
        public static async Task<HttpResponseMessage> CreateAsync(
            IdPClient client, string userName, string email, string role)
        {
            HttpResponseMessage get = await client.GetAsync("/UsersAdmin/Create");
            string body = await get.Content.ReadAsStringAsync();

            // **パスワードは構成ファイルの値を使う**（値は出力しない）。
            string password = client.Config.Get("TestUserPWD");

            Dictionary<string, string> form = new Dictionary<string, string>()
            {
                { "__RequestVerificationToken", Html.Antiforgery(body) },
                { "Name", userName },
                { "Email", email },
                { "Password", password },
                { "ConfirmPassword", password }
            };

            if (!string.IsNullOrEmpty(role))
            {
                // 画面のチェックボックスと同じ名前（ビューは SelectedRoles）
                form.Add("SelectedRoles", role);
            }

            return await client.PostFormAsync("/UsersAdmin/Create", form);
        }

        /// <summary>編集画面を開く</summary>
        /// <param name="client">IdPClient</param>
        /// <param name="id">利用者の id</param>
        /// <returns>応答</returns>
        public static Task<HttpResponseMessage> EditAsync(IdPClient client, string id)
        {
            return client.GetAsync("/UsersAdmin/Edit/" + id);
        }

        /// <summary>利用者を編集する（画面から）</summary>
        /// <param name="client">IdPClient</param>
        /// <param name="id">利用者の id</param>
        /// <param name="userName">利用者名</param>
        /// <param name="email">メアド</param>
        /// <param name="role">付けるロール（null なら付けない）</param>
        /// <returns>応答</returns>
        public static async Task<HttpResponseMessage> EditAsync(
            IdPClient client, string id, string userName, string email, string role)
        {
            HttpResponseMessage get = await UsersAdmin.EditAsync(client, id);
            string body = await get.Content.ReadAsStringAsync();

            Dictionary<string, string> form = new Dictionary<string, string>()
            {
                { "__RequestVerificationToken", Html.Antiforgery(body) },
                { "Id", id },
                { "Name", userName },
                { "Email", email }
            };

            if (!string.IsNullOrEmpty(role))
            {
                // 画面のチェックボックスと同じ名前（ビューは SelectedRole）
                form.Add("SelectedRole", role);
            }

            return await client.PostFormAsync("/UsersAdmin/Edit/" + id, form);
        }

        /// <summary>利用者を、利用者名を指定して削除する（後片付け）</summary>
        /// <param name="client">IdPClient</param>
        /// <param name="userName">利用者名</param>
        /// <returns>削除できたか（居なければ false）</returns>
        /// <remarks>
        /// **DB ストアでは、作った利用者が残る。** 次の回の一覧に積み上がるので、
        /// **作ったテストが、同じテストの中で消す。**
        /// </remarks>
        public static async Task<bool> DeleteByUserNameAsync(IdPClient client, string userName)
        {
            HttpResponseMessage index = await UsersAdmin.IndexAsync(client);
            string indexBody = await index.Content.ReadAsStringAsync();

            string id = UsersAdmin.FindId(indexBody, userName);

            if (string.IsNullOrEmpty(id))
            {
                return false;
            }

            HttpResponseMessage get = await client.GetAsync("/UsersAdmin/Delete/" + id);
            string body = await get.Content.ReadAsStringAsync();

            Dictionary<string, string> form = new Dictionary<string, string>()
            {
                { "__RequestVerificationToken", Html.Antiforgery(body) }
            };

            HttpResponseMessage post = await client.PostFormAsync("/UsersAdmin/Delete/" + id, form);

            // 成功すると一覧へリダイレクトする。
            return post.StatusCode == HttpStatusCode.Found
                || post.StatusCode == HttpStatusCode.Redirect
                || post.StatusCode == HttpStatusCode.SeeOther;
        }
    }
}
