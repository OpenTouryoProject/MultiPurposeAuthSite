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
//* クラス名        ：AppConfig
//* クラス日本語名  ：テスト対象アプリの構成ファイル読み取り
//*
//* 作成日時        ：－
//* 作成者          ：－
//* 更新履歴        ：－
//*
//*  日時        更新者            内容
//*  ----------  ----------------  -------------------------------------------------
//*  2026/09/08  玄人 幸道         新規（E2Eテスト基盤）
//**********************************************************************************

using System;
using System.Collections.Generic;
using System.IO;
using System.Text.Json;
using System.Text.RegularExpressions;
using System.Xml.Linq;

namespace MultiPurposeAuthSite.Tests.E2E.Infrastructure
{
    /// <summary>
    /// テスト対象アプリの構成ファイルを読む。
    ///
    /// appsettings.json（net10.0）と app.config（net48）は .gitignore 済みで、
    /// 実際の資格情報を含む。テスト側で値を持たず常にここから読み出すことで、
    /// リポジトリに秘密情報を持ち込まない。
    ///
    /// ※ 読み取った値をコンソールへ出力しないこと。
    /// </summary>
    public sealed class AppConfig
    {
        /// <summary>appSettings 相当のキー・値</summary>
        private readonly Dictionary<string, string> _appSettings =
            new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);

        /// <summary>OAuth2ClientsInformation（client_id → 属性）</summary>
        private readonly Dictionary<string, Dictionary<string, string>> _clients =
            new Dictionary<string, Dictionary<string, string>>(StringComparer.OrdinalIgnoreCase);

        /// <summary>読み込んだ構成ファイルのパス</summary>
        public string Path { get; }

        /// <summary>コンストラクタ</summary>
        /// <param name="path">構成ファイルのパス</param>
        private AppConfig(string path)
        {
            this.Path = path;
        }

        #region 読み込み

        /// <summary>構成ファイルを読み込む（拡張子で形式を判定）</summary>
        /// <param name="path">構成ファイルのパス</param>
        /// <returns>AppConfig</returns>
        public static AppConfig Load(string path)
        {
            if (!File.Exists(path))
            {
                throw new FileNotFoundException(
                    "テスト対象アプリの構成ファイルが見つかりません。"
                    + "testsettings.json の configPath を確認してください。", path);
            }

            AppConfig cfg = new AppConfig(path);

            if (path.EndsWith(".json", StringComparison.OrdinalIgnoreCase))
            {
                cfg.LoadFromAppSettingsJson(path);
            }
            else
            {
                cfg.LoadFromAppConfigXml(path);
            }

            return cfg;
        }

        /// <summary>コメント・末尾カンマを許容する読み取りオプション</summary>
        private static readonly JsonDocumentOptions JsoncOptions = new JsonDocumentOptions()
        {
            CommentHandling = JsonCommentHandling.Skip,
            AllowTrailingCommas = true
        };

        /// <summary>appsettings.json（JSONC）から読む</summary>
        /// <param name="path">構成ファイルのパス</param>
        private void LoadFromAppSettingsJson(string path)
        {
            using (JsonDocument doc = JsonDocument.Parse(File.ReadAllText(path), JsoncOptions))
            {
                JsonElement appSettings;
                if (!doc.RootElement.TryGetProperty("appSettings", out appSettings))
                {
                    return;
                }

                foreach (JsonProperty p in appSettings.EnumerateObject())
                {
                    if (p.Name == "OAuth2ClientsInformation")
                    {
                        // net10.0 では入れ子のオブジェクト。
                        this.LoadClients(p.Value);
                    }
                    else if (p.Value.ValueKind == JsonValueKind.String)
                    {
                        this._appSettings[p.Name] = p.Value.GetString();
                    }
                }
            }
        }

        /// <summary>app.config（XML）から読む</summary>
        /// <param name="path">構成ファイルのパス</param>
        private void LoadFromAppConfigXml(string path)
        {
            XDocument doc = XDocument.Load(path);

            if (doc.Root == null)
            {
                return;
            }

            // net48版の app.config は、Web.config から configSource で取り込まれるため、
            // ルート要素そのものが <appSettings>。
            // 通常の <configuration><appSettings> 形式にも対応しておく。
            XElement appSettings = (doc.Root.Name.LocalName == "appSettings")
                ? doc.Root : doc.Root.Element("appSettings");

            if (appSettings == null)
            {
                return;
            }

            foreach (XElement add in appSettings.Elements("add"))
            {
                XAttribute key = add.Attribute("key");
                XAttribute value = add.Attribute("value");

                if (key == null || value == null)
                {
                    continue;
                }

                if (key.Value == "OAuth2ClientsInformation")
                {
                    // net48 では JSON 文字列。しかも // コメント付き。
                    //
                    // XML の属性値は、パーサが改行を空白へ正規化する（XML 1.0 3.3.3）。
                    // XDocument から取ると 1 行になり、// コメントが以降を全部飲む。
                    // そのため、ここだけは生のファイル テキストから取り直す。
                    this.LoadClientsFromRawAttribute(path);
                }
                else
                {
                    this._appSettings[key.Value] = value.Value;
                }
            }
        }

        /// <summary>
        /// app.config の OAuth2ClientsInformation を、改行を保ったまま取り込む。
        /// </summary>
        /// <param name="path">構成ファイルのパス</param>
        private void LoadClientsFromRawAttribute(string path)
        {
            Match m = ClientsAttributeRegex.Match(File.ReadAllText(path));

            if (!m.Success)
            {
                return;
            }

            string json = m.Groups["json"].Value
                .Replace("&quot;", "\"")
                .Replace("&apos;", "'")
                .Replace("&lt;", "<")
                .Replace("&gt;", ">")
                .Replace("&amp;", "&");

            using (JsonDocument clients = JsonDocument.Parse(json, JsoncOptions))
            {
                this.LoadClients(clients.RootElement);
            }
        }

        /// <summary>OAuth2ClientsInformation の生の属性値</summary>
        private static readonly Regex ClientsAttributeRegex = new Regex(
            "<add\\s+key=\"OAuth2ClientsInformation\"\\s+value=(?<q>[\"'])(?<json>.*?)\\k<q>\\s*/>",
            RegexOptions.Compiled | RegexOptions.Singleline);

        /// <summary>OAuth2ClientsInformation を取り込む</summary>
        /// <param name="clients">client_id をキーとするオブジェクト</param>
        private void LoadClients(JsonElement clients)
        {
            if (clients.ValueKind != JsonValueKind.Object)
            {
                return;
            }

            foreach (JsonProperty client in clients.EnumerateObject())
            {
                Dictionary<string, string> attrs =
                    new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);

                foreach (JsonProperty attr in client.Value.EnumerateObject())
                {
                    if (attr.Value.ValueKind == JsonValueKind.String)
                    {
                        attrs[attr.Name] = attr.Value.GetString();
                    }
                }

                this._clients[client.Name] = attrs;
            }
        }

        #endregion

        #region 参照

        /// <summary>appSettings の値を返す（無ければ null）</summary>
        /// <param name="key">キー</param>
        /// <returns>値</returns>
        public string Get(string key)
        {
            string value;
            return this._appSettings.TryGetValue(key, out value) ? value : null;
        }

        /// <summary>登録済み client_id の一覧</summary>
        public IEnumerable<string> ClientIds
        {
            get { return this._clients.Keys; }
        }

        /// <summary>client_id を client_name から引く（無ければ null）</summary>
        /// <param name="clientName">client_name</param>
        /// <returns>client_id</returns>
        public string FindClientIdByName(string clientName)
        {
            foreach (KeyValuePair<string, Dictionary<string, string>> client in this._clients)
            {
                string name;
                if (client.Value.TryGetValue("client_name", out name) && name == clientName)
                {
                    return client.Key;
                }
            }

            return null;
        }

        /// <summary>クライアントの属性を返す（無ければ null）</summary>
        /// <param name="clientId">client_id</param>
        /// <param name="attribute">属性名（client_secret, redirect_uri_code, ...）</param>
        /// <returns>属性値</returns>
        public string GetClientAttribute(string clientId, string attribute)
        {
            Dictionary<string, string> attrs;
            if (!this._clients.TryGetValue(clientId, out attrs))
            {
                return null;
            }

            string value;
            return attrs.TryGetValue(attribute, out value) ? value : null;
        }

        #endregion
    }
}
