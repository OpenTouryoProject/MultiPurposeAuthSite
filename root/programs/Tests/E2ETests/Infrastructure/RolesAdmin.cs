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
//* クラス名        ：RolesAdmin
//* クラス日本語名  ：ロール管理の画面を駆動する（テスト用）
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
    /// ロール管理の画面（`/RolesAdmin`）を、HTTP で駆動する（#257）。
    /// </summary>
    /// <remarks>
    /// **`UsersAdmin` と同じ前提**（管理者でサインインしていること。
    /// `EnableAdministrationOfUsersAndRoles` が有効であること）。
    ///
    /// **net48 版と net10.0 版の両方に在る**（#258 で移植した）。
    /// </remarks>
    public static class RolesAdmin
    {
        /// <summary>一覧の行（ロール名・id）</summary>
        private static readonly Regex RowRegex = new Regex(
            "<tr[^>]*>\\s*<td[^>]*>\\s*(?<name>[^<]*?)\\s*</td>\\s*"
            + "<td[^>]*>.*?/RolesAdmin/Edit/(?<id>[^\"]+)\"",
            RegexOptions.Compiled | RegexOptions.IgnoreCase | RegexOptions.Singleline);

        /// <summary>一覧を開く</summary>
        /// <param name="client">IdPClient</param>
        /// <returns>応答</returns>
        public static Task<HttpResponseMessage> IndexAsync(IdPClient client)
        {
            return client.GetAsync("/RolesAdmin");
        }

        /// <summary>
        /// 画面が閉じていれば Skip する（`EnableAdministrationOfUsersAndRoles`）。
        /// </summary>
        /// <param name="client">IdPClient</param>
        /// <returns>一覧の本文</returns>
        public static async Task<string> SkipIfLockedDownAsync(IdPClient client)
        {
            HttpResponseMessage get = await RolesAdmin.IndexAsync(client);
            string body = await get.Content.ReadAsStringAsync();

            // 一覧の画面なら、作成への導線が在る。
            Xunit.Skip.IfNot(
                get.StatusCode == HttpStatusCode.OK && body.Contains("/RolesAdmin/Create"),
                "ロール管理の画面が開きません"
                + "（EnableAdministrationOfUsersAndRoles と、管理者のサインインを確認）。");

            return body;
        }

        /// <summary>一覧に、そのロールが在るか</summary>
        /// <param name="indexBody">一覧の本文</param>
        /// <param name="roleName">ロール名</param>
        /// <returns>在れば true</returns>
        public static bool Contains(string indexBody, string roleName)
        {
            return RolesAdmin.FindId(indexBody, roleName) != null;
        }

        /// <summary>一覧から、ロール名で id を引く（無ければ null）</summary>
        /// <param name="indexBody">一覧の本文</param>
        /// <param name="roleName">ロール名</param>
        /// <returns>id</returns>
        public static string FindId(string indexBody, string roleName)
        {
            foreach (Match m in RolesAdmin.RowRegex.Matches(indexBody ?? ""))
            {
                if (WebUtility.HtmlDecode(m.Groups["name"].Value) == roleName)
                {
                    return m.Groups["id"].Value;
                }
            }

            return null;
        }

        /// <summary>ロールを作る（画面から）</summary>
        /// <param name="client">IdPClient</param>
        /// <param name="roleName">ロール名</param>
        /// <returns>応答</returns>
        public static async Task<HttpResponseMessage> CreateAsync(IdPClient client, string roleName)
        {
            HttpResponseMessage get = await client.GetAsync("/RolesAdmin/Create");
            string body = await get.Content.ReadAsStringAsync();

            Dictionary<string, string> form = new Dictionary<string, string>()
            {
                { "__RequestVerificationToken", Html.Antiforgery(body) },
                { "Name", roleName }
            };

            return await client.PostFormAsync("/RolesAdmin/Create", form);
        }

        /// <summary>詳細を開く</summary>
        /// <param name="client">IdPClient</param>
        /// <param name="id">ロールの id</param>
        /// <returns>応答</returns>
        public static Task<HttpResponseMessage> DetailsAsync(IdPClient client, string id)
        {
            return client.GetAsync("/RolesAdmin/Details/" + id);
        }

        /// <summary>ロールを、ロール名を指定して削除する（後片付け）</summary>
        /// <param name="client">IdPClient</param>
        /// <param name="roleName">ロール名</param>
        /// <returns>削除できたか（無ければ false）</returns>
        public static async Task<bool> DeleteByNameAsync(IdPClient client, string roleName)
        {
            HttpResponseMessage index = await RolesAdmin.IndexAsync(client);
            string id = RolesAdmin.FindId(await index.Content.ReadAsStringAsync(), roleName);

            if (string.IsNullOrEmpty(id))
            {
                return false;
            }

            HttpResponseMessage get = await client.GetAsync("/RolesAdmin/Delete/" + id);
            string body = await get.Content.ReadAsStringAsync();

            Dictionary<string, string> form = new Dictionary<string, string>()
            {
                { "__RequestVerificationToken", Html.Antiforgery(body) }
            };

            HttpResponseMessage post = await client.PostFormAsync("/RolesAdmin/Delete/" + id, form);

            // 成功すると一覧へリダイレクトする。
            return post.StatusCode == HttpStatusCode.Found
                || post.StatusCode == HttpStatusCode.Redirect
                || post.StatusCode == HttpStatusCode.SeeOther;
        }
    }
}
