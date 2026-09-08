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
//* クラス名        ：TestEnv, TargetInfo
//* クラス日本語名  ：E2Eテストの実行環境
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
using System.Net;
using System.Net.Http;
using System.Text.Json;

namespace MultiPurposeAuthSite.Tests.E2E.Infrastructure
{
    /// <summary>テスト対象（net10.0版 / net48版）</summary>
    public sealed class TargetInfo
    {
        /// <summary>キー（core / netfx）。Theory のデータに使うので文字列。</summary>
        public string Key { get; set; }

        /// <summary>表示名</summary>
        public string DisplayName { get; set; }

        /// <summary>テスト対象とするか</summary>
        public bool Enabled { get; set; }

        private string _baseUrl = null;

        /// <summary>
        /// サイトのルートURL（末尾に / を付けない）。
        ///
        /// 明示していないときは、構成ファイルの
        /// OAuth2AuthorizationServerEndpointsRootURI を使う。
        ///
        /// アプリ同梱の自己テスト（FAPI2 / CIBA / Device AuthZ）は、
        /// サーバ自身が「構成ファイルに書かれたURL」へHTTPで折り返す。
        /// テストの叩き先がそれと違うと、折り返しが接続不能になり HTTP 500 になる。
        /// そのため、既定では両者を一致させる。
        /// </summary>
        public string BaseUrl
        {
            get
            {
                if (this._baseUrl != null)
                {
                    return this._baseUrl;
                }

                string root = this.Config.Get("OAuth2AuthorizationServerEndpointsRootURI");

                if (string.IsNullOrEmpty(root))
                {
                    throw new InvalidOperationException(
                        "baseUrl が指定されておらず、構成ファイルにも "
                        + "OAuth2AuthorizationServerEndpointsRootURI がありません: "
                        + this.ConfigPath);
                }

                return root.TrimEnd('/');
            }

            set { this._baseUrl = (value == null) ? null : value.TrimEnd('/'); }
        }

        /// <summary>構成ファイルのパス（絶対パス）</summary>
        public string ConfigPath { get; set; }

        /// <summary>net48版か</summary>
        public bool IsNetFx
        {
            get { return this.Key == TestEnv.NetFxKey; }
        }

        private AppConfig _config = null;

        /// <summary>構成ファイル（初回参照時に読む）</summary>
        public AppConfig Config
        {
            get
            {
                if (this._config == null)
                {
                    this._config = AppConfig.Load(this.ConfigPath);
                }

                return this._config;
            }
        }

        /// <summary>URL を組み立てる</summary>
        /// <param name="path">/ で始まるパス</param>
        /// <returns>絶対URL</returns>
        public string Url(string path)
        {
            return this.BaseUrl + path;
        }

        #region 到達性

        private bool? _reachable = null;

        /// <summary>起動していないときの理由</summary>
        public string UnavailableReason { get; private set; }

        /// <summary>
        /// サイトが起動しているか（1度だけ確認して覚える）。
        /// 起動していない対象のテストは Skip する。落とさないのは、
        /// net48版はIIS Expressでの手動起動が前提で、常に起動しているとは限らないため。
        /// </summary>
        /// <returns>起動していれば true</returns>
        public bool IsReachable()
        {
            if (this._reachable.HasValue)
            {
                return this._reachable.Value;
            }

            if (!this.Enabled)
            {
                this.UnavailableReason = this.DisplayName + " は testsettings.json で無効化されています。";
                this._reachable = false;
                return false;
            }

            if (!File.Exists(this.ConfigPath))
            {
                this.UnavailableReason = this.DisplayName
                    + " の構成ファイルがありません: " + this.ConfigPath;
                this._reachable = false;
                return false;
            }

            try
            {
                string baseUrl = this.BaseUrl;

                using (HttpClientHandler handler = new HttpClientHandler())
                {
                    handler.AllowAutoRedirect = false;
                    handler.ServerCertificateCustomValidationCallback =
                        HttpClientHandler.DangerousAcceptAnyServerCertificateValidator;

                    using (HttpClient http = new HttpClient(handler))
                    {
                        http.Timeout = TimeSpan.FromSeconds(10);

                        // ルート("/")ではなく Discovery文書で確かめる。
                        // net10.0版とnet48版は同じホスト・ポートで構成されることがあり、
                        // 「何かが応答した」だけでは、目的のアプリとは限らないため。
                        HttpResponseMessage res = http.GetAsync(
                            baseUrl + "/.well-known/openid-configuration").GetAwaiter().GetResult();

                        if (res.StatusCode != HttpStatusCode.OK)
                        {
                            this.UnavailableReason = this.DisplayName + " が " + baseUrl
                                + " にいません（/.well-known/openid-configuration が HTTP "
                                + (int)res.StatusCode + "）。";
                            this._reachable = false;
                            return false;
                        }
                    }
                }

                this._reachable = true;
            }
            catch (Exception ex)
            {
                this.UnavailableReason = this.DisplayName + " が "
                    + this.BaseUrl + " で応答しません（" + ex.GetType().Name + "）。"
                    + "先にサイトを起動してください。";
                this._reachable = false;
            }

            return this._reachable.Value;
        }

        #endregion
    }

    /// <summary>
    /// テストの実行環境（testsettings.json / 環境変数 / 既定値）。
    /// </summary>
    public static class TestEnv
    {
        /// <summary>net10.0版のキー</summary>
        public const string CoreKey = "core";

        /// <summary>net48版のキー</summary>
        public const string NetFxKey = "netfx";

        private static readonly Dictionary<string, TargetInfo> _targets =
            new Dictionary<string, TargetInfo>(StringComparer.OrdinalIgnoreCase);

        /// <summary>root/programs の絶対パス</summary>
        public static string ProgramsDir { get; private set; }

        /// <summary>テスト ユーザ名</summary>
        public static string TestUserName { get; private set; }

        /// <summary>静的コンストラクタ</summary>
        static TestEnv()
        {
            ProgramsDir = FindProgramsDir();
            TestUserName = "super_tanaka@gmail.com";

            // 既定値（baseUrl は null ＝ 構成ファイルから導出）
            Register(CoreKey, "net10.0版 (MultiPurposeAuthSiteCore)", null,
                "MultiPurposeAuthSiteCore/MultiPurposeAuthSiteCore/appsettings.json");

            Register(NetFxKey, "net48版 (MultiPurposeAuthSite)", null,
                "MultiPurposeAuthSite/MultiPurposeAuthSite/app.config");

            // testsettings.json による上書き
            ApplySettingsFile();

            // 環境変数による上書き（CI / エージェント実行向け）
            ApplyEnvironmentVariables();
        }

        /// <summary>テスト対象を登録する</summary>
        private static void Register(string key, string displayName, string baseUrl, string configPath)
        {
            _targets[key] = new TargetInfo()
            {
                Key = key,
                DisplayName = displayName,
                Enabled = true,
                BaseUrl = baseUrl,
                ConfigPath = Path.GetFullPath(Path.Combine(ProgramsDir, configPath))
            };
        }

        /// <summary>キーからテスト対象を返す</summary>
        /// <param name="key">core / netfx</param>
        /// <returns>TargetInfo</returns>
        public static TargetInfo Target(string key)
        {
            return _targets[key];
        }

        /// <summary>全テスト対象</summary>
        public static IEnumerable<TargetInfo> Targets
        {
            get { return _targets.Values; }
        }

        #region 設定の読み込み

        /// <summary>
        /// root/programs を探す。
        /// テストの実行ディレクトリは Tests/E2ETests/bin/&lt;構成&gt;/net10.0 なので、
        /// 親を辿って MultiPurposeAuthSiteCore を含むディレクトリを探す。
        /// </summary>
        /// <returns>root/programs の絶対パス</returns>
        private static string FindProgramsDir()
        {
            DirectoryInfo dir = new DirectoryInfo(AppContext.BaseDirectory);

            while (dir != null)
            {
                if (Directory.Exists(Path.Combine(dir.FullName, "MultiPurposeAuthSiteCore"))
                    && Directory.Exists(Path.Combine(dir.FullName, "CommonLibrary")))
                {
                    return dir.FullName;
                }

                dir = dir.Parent;
            }

            throw new DirectoryNotFoundException(
                "root/programs が見つかりません（探索の起点: " + AppContext.BaseDirectory + "）。");
        }

        /// <summary>testsettings.json があれば読む</summary>
        private static void ApplySettingsFile()
        {
            string path = Path.Combine(AppContext.BaseDirectory, "testsettings.json");

            if (!File.Exists(path))
            {
                return;
            }

            JsonDocumentOptions options = new JsonDocumentOptions()
            {
                CommentHandling = JsonCommentHandling.Skip,
                AllowTrailingCommas = true
            };

            using (JsonDocument doc = JsonDocument.Parse(File.ReadAllText(path), options))
            {
                JsonElement root = doc.RootElement;

                JsonElement user;
                if (root.TryGetProperty("testUserName", out user)
                    && user.ValueKind == JsonValueKind.String)
                {
                    TestUserName = user.GetString();
                }

                JsonElement targets;
                if (!root.TryGetProperty("targets", out targets))
                {
                    return;
                }

                foreach (JsonProperty t in targets.EnumerateObject())
                {
                    TargetInfo target;
                    if (!_targets.TryGetValue(t.Name, out target))
                    {
                        continue;
                    }

                    JsonElement value;

                    if (t.Value.TryGetProperty("enabled", out value)
                        && (value.ValueKind == JsonValueKind.True || value.ValueKind == JsonValueKind.False))
                    {
                        target.Enabled = value.GetBoolean();
                    }

                    if (t.Value.TryGetProperty("baseUrl", out value)
                        && value.ValueKind == JsonValueKind.String)
                    {
                        target.BaseUrl = value.GetString().TrimEnd('/');
                    }

                    if (t.Value.TryGetProperty("configPath", out value)
                        && value.ValueKind == JsonValueKind.String)
                    {
                        target.ConfigPath = Path.GetFullPath(
                            Path.Combine(ProgramsDir, value.GetString()));
                    }
                }
            }
        }

        /// <summary>環境変数があれば読む</summary>
        private static void ApplyEnvironmentVariables()
        {
            Override(CoreKey, "MPAS_CORE_BASEURL", "MPAS_CORE_CONFIG");
            Override(NetFxKey, "MPAS_NETFX_BASEURL", "MPAS_NETFX_CONFIG");

            string user = Environment.GetEnvironmentVariable("MPAS_TESTUSER");
            if (!string.IsNullOrEmpty(user))
            {
                TestUserName = user;
            }
        }

        /// <summary>環境変数1組でテスト対象を上書きする</summary>
        private static void Override(string key, string baseUrlVar, string configVar)
        {
            TargetInfo target = _targets[key];

            string baseUrl = Environment.GetEnvironmentVariable(baseUrlVar);
            if (!string.IsNullOrEmpty(baseUrl))
            {
                target.BaseUrl = baseUrl.TrimEnd('/');
            }

            string config = Environment.GetEnvironmentVariable(configVar);
            if (!string.IsNullOrEmpty(config))
            {
                target.ConfigPath = Path.GetFullPath(Path.Combine(ProgramsDir, config));
            }
        }

        #endregion
    }
}
