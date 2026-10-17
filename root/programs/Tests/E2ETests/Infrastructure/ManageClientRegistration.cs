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
//* クラス名        ：ManageClientRegistration
//* クラス日本語名  ：自分のクライアント登録（/Manage/AddSaml2OAuth2Data）を駆動する
//*
//* 作成日時        ：－
//* 作成者          ：－
//* 更新履歴        ：－
//*
//*  日時        更新者            内容
//*  ----------  ----------------  -------------------------------------------------
//*  2026/10/14  玄人 幸道         新規（#299。RT-277.1 の私的ヘルパを共有に出した）
//*  2026/10/16  玄人 幸道         client_secret も返す口を足した（#305 の段階 2）
//**********************************************************************************

using System.Collections.Generic;
using System.Net.Http;
using System.Text.RegularExpressions;
using System.Threading.Tasks;

/// <summary>MultiPurposeAuthSite.Tests.E2E.Infrastructure</summary>
namespace MultiPurposeAuthSite.Tests.E2E.Infrastructure
{
    /// <summary>
    /// 自分のクライアント登録（`/Manage/AddSaml2OAuth2Data`）を駆動する。
    /// </summary>
    /// <remarks>
    /// **この画面は「3 回押し」で登録する**
    /// （`submit.ClientID` → `submit.ClientSecret` → `submit.Add`。#277 の段階 5）。
    /// **画面の値をそのまま送り直す**ので、**毎回フォームを拾い直す。**
    ///
    /// **流れそのものを測るのは `RT-277.1`** である。
    /// **ここは「登録が在る利用者」を前提として作るための口**
    /// （`RT-277.8` が、**クライアントを登録した人を消去できるか**を測るのに使う。#299）。
    /// </remarks>
    public static class ManageClientRegistration
    {
        /// <summary>画面のフォームを拾う（送り直すため）</summary>
        /// <param name="html">画面の HTML</param>
        /// <returns>name → value</returns>
        /// <remarks>
        /// **submit は入れない**（押すボタンは呼ぶ側が足す）。
        /// **チェックの付いていない checkbox / radio も入れない**（ブラウザと同じ）。
        /// **select は選択されている値**（無ければ先頭）。
        /// </remarks>
        public static Dictionary<string, string> Harvest(string html)
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

        /// <summary>拾ったフォームの値（無ければ null）</summary>
        /// <param name="form">拾ったフォーム</param>
        /// <param name="name">欄の名前</param>
        /// <returns>値</returns>
        public static string Value(Dictionary<string, string> form, string name)
        {
            return (form != null && form.ContainsKey(name)) ? form[name] : null;
        }

        /// <summary>フォームを送って、返ってきた画面を返す</summary>
        /// <param name="client">IdPClient</param>
        /// <param name="form">拾ったフォーム</param>
        /// <param name="submit">押すボタンの name</param>
        /// <returns>返ってきた画面の HTML</returns>
        public static async Task<string> PostAsync(
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
        /// <remarks>**登録が在るときだけ「削除」のフォームが出る。**</remarks>
        public static async Task<bool> IsRegisteredAsync(IdPClient client)
        {
            string html = await client.GetStringAsync("/Manage/Index");

            return (html ?? "").Contains("RemoveSaml2OAuth2Data");
        }

        /// <summary>登録を消す（前提を揃える・後片付け）</summary>
        /// <param name="client">IdPClient（その利用者でサインイン済み）</param>
        /// <returns>Task</returns>
        /// <remarks>**登録が無ければ何もしない。**</remarks>
        public static async Task RemoveAsync(IdPClient client)
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

        /// <summary>サインイン済みの利用者に、クライアントを 1 件登録する</summary>
        /// <param name="client">IdPClient（その利用者でサインイン済み）</param>
        /// <returns>発行された client_id（登録できなければ空）</returns>
        /// <remarks>
        /// **3 回押しの順に送る**（`submit.ClientID` → `submit.ClientSecret` → `submit.Add`）。
        /// **`client_id` は画面が発行する**（32 桁の 16 進）。
        /// </remarks>
        public static async Task<string> RegisterAsync(IdPClient client)
        {
            (string ClientId, string ClientSecret) registered =
                await ManageClientRegistration.RegisterWithSecretAsync(client);

            return registered.ClientId;
        }

        /// <summary>サインイン済みの利用者に、クライアントを 1 件登録する（秘密も返す）</summary>
        /// <param name="client">IdPClient（その利用者でサインイン済み）</param>
        /// <returns>発行された client_id と client_secret（登録できなければ client_id は空）</returns>
        /// <remarks>
        /// **3 回押しの順に送る**（`submit.ClientID` → `submit.ClientSecret` → `submit.Add`）。
        /// **`client_id` と `client_secret` は画面が発行する。**
        /// **秘密は報告に出さない**（`TESTING.md` 9 節）。
        /// **`async` に `out` は付けられない**ので、組で返す（`RegisterDeviceAsync` と同じ形）。
        /// </remarks>
        public static Task<(string ClientId, string ClientSecret)> RegisterWithSecretAsync(
            IdPClient client)
        {
            return ManageClientRegistration.RegisterWithSecretAsync(client, null);
        }

        /// <summary>クライアントを登録し、client_id と client_secret を得る（項目を差し込める。#306）</summary>
        /// <param name="client">IdPClient</param>
        /// <param name="fields">最後の「追加」の直前に差し込む項目（null なら画面のまま）</param>
        /// <returns>発行された client_id と client_secret（登録できなければ client_id は空）</returns>
        /// <remarks>
        /// **`redirect_uri_code` などを登録するために使う**（#306 は n 件を測る）。
        /// **画面から拾ったフォームの値を上書きする**だけなので、
        /// **画面が出していない項目は差し込めない。**
        /// </remarks>
        public static async Task<(string ClientId, string ClientSecret)> RegisterWithSecretAsync(
            IdPClient client, IDictionary<string, string> fields)
        {
            string clientSecret = "";

            Dictionary<string, string> form = ManageClientRegistration.Harvest(
                await client.GetStringAsync("/Manage/AddSaml2OAuth2Data"));

            form = ManageClientRegistration.Harvest(
                await ManageClientRegistration.PostAsync(client, form, "submit.ClientID"));

            string clientId = ManageClientRegistration.Value(form, "ClientID") ?? "";

            form = ManageClientRegistration.Harvest(
                await ManageClientRegistration.PostAsync(client, form, "submit.ClientSecret"));

            clientSecret = ManageClientRegistration.Value(form, "ClientSecret") ?? "";

            //  **「追加」の直前に差し込む**（#306）。
            //    **画面が出している項目の値を、そのまま置き換える。**
            if (fields != null)
            {
                foreach (KeyValuePair<string, string> item in fields)
                {
                    form[item.Key] = item.Value;
                }
            }

            await ManageClientRegistration.PostAsync(client, form, "submit.Add");

            bool registered = await ManageClientRegistration.IsRegisteredAsync(client);

            //　タプル：(clientId, clientSecret) or ("", clientSecret)を返す。
            return (registered ? clientId : "", clientSecret);
        }
    }
}
