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
//* クラス名        ：IdFederationAdmin
//* クラス日本語名  ：上流 IdP の管理画面を駆動する
//*
//* 作成日時        ：－
//* 作成者          ：－
//* 更新履歴        ：－
//*
//*  日時        更新者            内容
//*  ----------  ----------------  -------------------------------------------------
//*  2026/10/14  玄人 幸道         新規（#292 の段階 2）
//**********************************************************************************

using System;
using System.Collections.Generic;
using System.Net;
using System.Net.Http;
using System.Threading.Tasks;

/// <summary>MultiPurposeAuthSite.Tests.E2E.Infrastructure</summary>
namespace MultiPurposeAuthSite.Tests.E2E.Infrastructure
{
    /// <summary>
    /// 上流 IdP の管理画面（`/IdFederationAdmin`）を駆動する（#292 の段階 2）。
    /// </summary>
    /// <remarks>
    /// **`UsersAdmin` / `RolesAdmin` のヘルパと同じ流儀**である
    /// （一覧を開く → AntiForgery を取る → フォームを POST する）。
    ///
    /// **この画面が編むのは user store の行だけ**である。
    /// **設定ファイル（`appSettings` の `IdFederationUpstreams`）の行は出ない。**
    /// </remarks>
    public static class IdFederationAdmin
    {
        /// <summary>一覧を開く</summary>
        /// <param name="client">IdPClient</param>
        /// <returns>応答</returns>
        public static Task<HttpResponseMessage> IndexAsync(IdPClient client)
        {
            return client.GetAsync("/IdFederationAdmin");
        }

        /// <summary>画面が開かなければ Skip する</summary>
        /// <param name="client">IdPClient</param>
        /// <returns>一覧の本文</returns>
        /// <remarks>
        /// **ロックダウン（`EnableAdministrationOfUsersAndRoles`）されていると、
        /// 門番が例外を投げてエラー画面になる**（`UsersAdmin` と同じ）。
        /// </remarks>
        public static async Task<string> SkipIfLockedDownAsync(IdPClient client)
        {
            HttpResponseMessage get = await IdFederationAdmin.IndexAsync(client);
            string body = await get.Content.ReadAsStringAsync();

            Xunit.Skip.IfNot(
                get.StatusCode == HttpStatusCode.OK
                    && 0 <= (body ?? "").IndexOf("/IdFederationAdmin/Create"),
                "上流 IdP の管理画面が開きません"
                + "（EnableAdministrationOfUsersAndRoles と、管理者のサインインを確認）。");

            return body;
        }

        /// <summary>一覧に、その鍵の行が在るか</summary>
        /// <param name="indexBody">一覧の本文</param>
        /// <param name="key">鍵</param>
        /// <returns>在れば true</returns>
        public static bool Contains(string indexBody, string key)
        {
            return 0 <= (indexBody ?? "").IndexOf(
                "/IdFederationAdmin/Edit?key=" + key, StringComparison.OrdinalIgnoreCase);
        }

        /// <summary>上流を足す（画面から）</summary>
        /// <param name="client">IdPClient</param>
        /// <param name="key">鍵</param>
        /// <param name="protocol">oidc / saml2</param>
        /// <param name="displayName">表示名</param>
        /// <param name="issuer">期待する Issuer</param>
        /// <param name="extra">他の欄（protocol ごとに要るもの）</param>
        /// <returns>応答</returns>
        public static async Task<HttpResponseMessage> CreateAsync(
            IdPClient client, string key, string protocol, string displayName,
            string issuer, Dictionary<string, string> extra = null)
        {
            HttpResponseMessage get = await client.GetAsync("/IdFederationAdmin/Create");
            string body = await get.Content.ReadAsStringAsync();

            Dictionary<string, string> form = new Dictionary<string, string>()
            {
                { "__RequestVerificationToken", Html.Antiforgery(body) },
                { "UpstreamKey", key },
                { "Protocol", protocol },
                { "Enabled", "true" },
                { "DisplayName", displayName },
                { "Issuer", issuer }
            };

            if (extra != null)
            {
                foreach (KeyValuePair<string, string> kv in extra)
                {
                    form[kv.Key] = kv.Value;
                }
            }

            return await client.PostFormAsync("/IdFederationAdmin/Create", form);
        }

        /// <summary>編集画面を開く</summary>
        /// <param name="client">IdPClient</param>
        /// <param name="key">鍵</param>
        /// <returns>応答</returns>
        public static Task<HttpResponseMessage> EditAsync(IdPClient client, string key)
        {
            return client.GetAsync("/IdFederationAdmin/Edit?key=" + key);
        }

        /// <summary>表示名だけを変える（画面から）</summary>
        /// <param name="client">IdPClient</param>
        /// <param name="key">鍵</param>
        /// <param name="displayName">新しい表示名</param>
        /// <param name="otherFields">表示名以外に送る欄（編集画面の値）</param>
        /// <returns>応答</returns>
        /// <remarks>
        /// **ブラウザは画面に出ている値をそのまま送り直す。**
        /// **ここでは、鍵と protocol と表示名を送る**
        /// （**他の欄は、呼ぶ側が渡した分だけ**）。
        /// </remarks>
        public static async Task<HttpResponseMessage> EditDisplayNameAsync(
            IdPClient client, string key, string displayName,
            Dictionary<string, string> otherFields = null)
        {
            HttpResponseMessage get = await IdFederationAdmin.EditAsync(client, key);
            string body = await get.Content.ReadAsStringAsync();

            Dictionary<string, string> form = new Dictionary<string, string>()
            {
                { "__RequestVerificationToken", Html.Antiforgery(body) },
                { "UpstreamKey", key },
                { "Enabled", "true" },
                { "DisplayName", displayName }
            };

            if (otherFields != null)
            {
                foreach (KeyValuePair<string, string> kv in otherFields)
                {
                    form[kv.Key] = kv.Value;
                }
            }

            return await client.PostFormAsync("/IdFederationAdmin/Edit", form);
        }

        /// <summary>上流を消す（後片付け）</summary>
        /// <param name="client">IdPClient</param>
        /// <param name="key">鍵</param>
        /// <returns>消せたら true</returns>
        /// <remarks>
        /// **DB ストアでは、作った行が残る**（`UsersAdmin` と同じ事情）。
        /// **作ったテストが、同じテストの中で消す。**
        /// </remarks>
        public static async Task<bool> DeleteAsync(IdPClient client, string key)
        {
            HttpResponseMessage index = await IdFederationAdmin.IndexAsync(client);
            string body = await index.Content.ReadAsStringAsync();

            HttpResponseMessage post = await client.PostFormAsync(
                "/IdFederationAdmin/Delete",
                new Dictionary<string, string>()
                {
                    { "__RequestVerificationToken", Html.Antiforgery(body) },
                    { "key", key }
                });

            return post.StatusCode == HttpStatusCode.Found
                || post.StatusCode == HttpStatusCode.Redirect
                || post.StatusCode == HttpStatusCode.SeeOther;
        }
    }
}
