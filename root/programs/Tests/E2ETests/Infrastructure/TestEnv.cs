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
//*  2026/09/12  玄人 幸道         プッシュ通知の送信箱（MPAS_CORE_FCM_OUTBOX / MPAS_NETFX_FCM_OUTBOX）を受け取る（#196）
//*  2026/10/01  玄人 幸道         テスト利用者の利用者名とメアドを分けた（#151 の段階 3）
//*  2026/10/03  玄人 幸道         テスト利用者をターゲットごとに分けた（#260）
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

        /// <summary>
        /// テスト利用者の名前に付く接尾辞（#260）。
        /// </summary>
        /// <remarks>
        /// **サイトごとにテスト利用者を分けるためのもの**（`_core` / `_netfx`）。
        ///
        /// **E2E は 2 つのサイトを同時に立てて、同じケースを両方に流す。**
        /// **DB ストアでは 1 つの DB を共有する**ので、分けないと
        /// **両サイトが同じ利用者の属性（`DeviceToken` / `UnstructuredData`）を書き換え合う。**
        /// **`mem` では各サイトが自前のストアを持つので、以前から起きていない。**
        ///
        /// **サイト側は `TestUserSuffix` で同じ値を読む**（`test.ps1` が両方へ渡す）。
        /// **空なら従来どおり**（`super_tanaka` / `tanaka`）。
        /// </remarks>
        public string TestUserSuffix { get; set; }

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

        /// <summary>
        /// プッシュ通知の送信箱（テスト用）のディレクトリ。設定されていなければ null。
        /// test.ps1 -Launch が、サイトごとに設定する（MPAS_CORE_FCM_OUTBOX / MPAS_NETFX_FCM_OUTBOX）（#196）。
        /// </summary>
        public string FcmOutbox { get; set; }

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

        /// <summary>種データを作らせたか（#264）</summary>
        private bool _seeded = false;

        /// <summary>_seeded の番をする錠（テスト クラスは並行して走る）</summary>
        private readonly object _seedLock = new object();

        /// <summary>起動していないときの理由</summary>
        public string UnavailableReason { get; private set; }

        /// <summary>
        /// 応答したアプリの種類（"net48（IIS）" / "net10.0（Kestrel）" / "不明"）。
        /// **どちらを測ったのかを報告に残すために要る。**
        /// </summary>
        public string DetectedServer { get; private set; }

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

                        // **応答したのが、期待したアプリかを確かめる。**
                        //
                        // net48版と net10.0版は、既定ではどちらも
                        // https://localhost:44300/MultiPurposeAuthSite で構成されている。
                        // 到達性だけを見ると、**片方しか動いていないのに両方が通り、
                        // 同じアプリを 2 回測って「両方 OK」と報告してしまう。**
                        //
                        //   net48   : ASP.NET Framework → X-AspNet-Version が付く
                        //   net10.0 : Kestrel           → Server: Kestrel
                        //
                        // どちらとも確証が持てないときは拒否しない（判定を壊さない）。
                        bool hasAspNetVersion = res.Headers.Contains("X-AspNet-Version");

                        string server = (res.Headers.Server == null)
                            ? "" : res.Headers.Server.ToString();

                        bool isKestrel = server.IndexOf(
                            "Kestrel", StringComparison.OrdinalIgnoreCase) >= 0;

                        if (hasAspNetVersion)
                        {
                            this.DetectedServer = "net48（ASP.NET Framework / " + server + "）";
                        }
                        else if (isKestrel)
                        {
                            this.DetectedServer = "net10.0（Kestrel）";
                        }
                        else
                        {
                            this.DetectedServer = "不明（Server: "
                                + (string.IsNullOrEmpty(server) ? "なし" : server) + "）";
                        }

                        if (this.IsNetFx && isKestrel)
                        {
                            this.UnavailableReason = this.DisplayName + " のはずの " + baseUrl
                                + " に、net10.0版（Kestrel）が応答しました。"
                                + "同じURLで構成されているため取り違えます。"
                                + "片方を別のURLにするか、順番に実行してください。";
                            this._reachable = false;
                            return false;
                        }

                        if (!this.IsNetFx && hasAspNetVersion)
                        {
                            this.UnavailableReason = this.DisplayName + " のはずの " + baseUrl
                                + " に、net48版（ASP.NET Framework）が応答しました。"
                                + "同じURLで構成されているため取り違えます。"
                                + "片方を別のURLにするか、順番に実行してください。";
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

        #region EnsureSeedData

        /// <summary>種データを作らせる（#264）</summary>
        /// <remarks>
        /// **サイトは `GET /Account/Login`（と `/Account/Register`）でしか種データを作らない**
        /// （`AccountController.CreateData`。#210 で踏んだ）。
        ///
        /// **#264 で、E2E 専用のクライアント登録も種データに移した。**
        /// そのため、**サインインしないテストが差し込みのクライアントを使うと、
        /// まだ登録が無くて 401 になりうる**（`RT-237.*` で踏んだ。**先に走る他のクラスに依存する**）。
        /// **以前は環境変数で渡していたので、プロセス開始から在った。**
        ///
        /// **そこで、クライアントを作る時点で 1 度だけ呼ぶ。**
        /// **錠を取るのは、テスト クラスが並行して走るため**
        /// （印だけ先に立てると、2 本目が種データの出来上がりを待たずに進む）。
        ///
        /// **失敗しても繰り返さない。** ここで測りたいのは種データではなく、
        /// 足りなければテスト自身が落ちて分かる。
        /// </remarks>
        public void EnsureSeedData()
        {
            if (this._seeded)
            {
                return;
            }

            lock (this._seedLock)
            {
                if (this._seeded)
                {
                    return;
                }

                try
                {
                    using (HttpClientHandler handler = new HttpClientHandler())
                    {
                        handler.AllowAutoRedirect = false;
                        handler.ServerCertificateCustomValidationCallback =
                            HttpClientHandler.DangerousAcceptAnyServerCertificateValidator;

                        using (HttpClient http = new HttpClient(handler))
                        {
                            http.Timeout = TimeSpan.FromSeconds(30);

                            // **応答は見ない。** 呼ぶこと自体が目的（CreateData が走る）。
                            http.GetAsync(this.BaseUrl + "/Account/Login")
                                .GetAwaiter().GetResult();
                        }
                    }
                }
                catch
                {
                    // 取れなくても、ここでは落とさない。
                }

                this._seeded = true;
            }
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

        /// <summary>テスト ユーザ名の土台（接尾辞を付ける前）</summary>
        private const string TestUserBase = "super_tanaka";

        /// <summary>2 人目のテスト ユーザ名の土台（接尾辞を付ける前）</summary>
        private const string SecondUserBase = "tanaka";

        /// <summary>`MPAS_TESTUSER` による上書き（両ターゲットに効く）</summary>
        private static string _testUserOverride = null;

        /// <summary>テスト ユーザ名（**ターゲットごとに違う**。#260）</summary>
        /// <param name="targetKey">core / netfx</param>
        /// <returns>利用者名</returns>
        /// <remarks>
        /// **利用者名とメアドは別の値である**（#151 の段階 3）。
        /// 以前は「利用者名＝メアド」だったため、1 つで足りていた。
        /// **サインインはどちらでも通る**ので、既定はこちら（利用者名）を使う。
        ///
        /// **ターゲットごとに分かれている**（#260）。
        /// **2 つのサイトが同じ DB を共有すると、同じ利用者の属性を書き換え合う**ため。
        /// </remarks>
        public static string TestUserName(string targetKey)
        {
            if (!string.IsNullOrEmpty(_testUserOverride))
            {
                return _testUserOverride;
            }

            return TestUserBase + Suffix(targetKey);
        }

        /// <summary>テスト ユーザのメアド（#151 の段階 3 / #260）</summary>
        /// <param name="targetKey">core / netfx</param>
        /// <returns>メアド</returns>
        /// <remarks>**メアドでのサインインを測るときに使う**（`SM-4.2`）。</remarks>
        public static string TestUserEmail(string targetKey)
        {
            return TestUserName(targetKey) + "@gmail.com";
        }

        /// <summary>
        /// 2 人目のテスト ユーザ（認証サイトが IsDebug のときに作る一般ユーザ）。
        /// **テスト ユーザと同じ TestUserPWD で作られる。**
        /// 「別の利用者」を要するテスト（EX-8.4）で使う。
        /// **この利用者には端末（device_token）を登録しないこと。**
        /// RT-210.1 が「端末が無い利用者」として使っている。
        /// **ターゲットごとに分かれている**（#260）。
        /// </summary>
        /// <param name="targetKey">core / netfx</param>
        /// <returns>利用者名</returns>
        public static string SecondUserName(string targetKey)
        {
            return SecondUserBase + Suffix(targetKey);
        }

        /// <summary>上流（ID フェデレーションの IdP）のテスト ユーザ名</summary>
        /// <remarks>
        /// **接尾辞を付けない**（#260）。
        ///
        /// **上流は `store/` のコンテナ 1 つで、自分のストアを持つ。**
        /// 下流（net48 版 / net10.0 版）とは**別の DB** なので、**分ける必要が無い。**
        /// **`docker-compose.yml` に `TestUserSuffix` を与えていない**ので、
        /// **上流の種データは `super_tanaka` である。**
        ///
        /// **下流の接尾辞を上流へ渡してはならない**（その利用者は上流に居ない）。
        /// </remarks>
        public static string UpstreamUserName
        {
            get { return TestUserBase; }
        }

        /// <summary>ターゲットの接尾辞（未登録のキーでは空）</summary>
        /// <param name="targetKey">core / netfx</param>
        /// <returns>接尾辞</returns>
        private static string Suffix(string targetKey)
        {
            TargetInfo target;
            return (targetKey != null && _targets.TryGetValue(targetKey, out target))
                ? (target.TestUserSuffix ?? "") : "";
        }

        /// <summary>静的コンストラクタ</summary>
        static TestEnv()
        {
            ProgramsDir = FindProgramsDir();

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
                // **既定は空**（＝ 従来どおりの super_tanaka / tanaka）。
                //   test.ps1 -Launch が、サイトごとの接尾辞を環境変数で渡す（#260）。
                TestUserSuffix = "",
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

                // **両ターゲットに効く上書き**（#260 より前からある口）。
                //   **接尾辞より強い**ので、DB ストアでは書き換え合いが起きうる。
                JsonElement user;
                if (root.TryGetProperty("testUserName", out user)
                    && user.ValueKind == JsonValueKind.String)
                {
                    _testUserOverride = user.GetString();
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
            Override(CoreKey, "MPAS_CORE_BASEURL", "MPAS_CORE_CONFIG", "MPAS_CORE_FCM_OUTBOX",
                "MPAS_CORE_TESTUSER_SUFFIX");
            Override(NetFxKey, "MPAS_NETFX_BASEURL", "MPAS_NETFX_CONFIG", "MPAS_NETFX_FCM_OUTBOX",
                "MPAS_NETFX_TESTUSER_SUFFIX");

            // **両ターゲットに効く上書き**（手で 1 人の利用者を指すとき）。
            //   **接尾辞より強い**ので、DB ストアでは書き換え合いが起きうる（#260）。
            _testUserOverride = Environment.GetEnvironmentVariable("MPAS_TESTUSER");
        }

        /// <summary>環境変数1組でテスト対象を上書きする</summary>
        private static void Override(string key, string baseUrlVar, string configVar,
            string fcmOutboxVar, string testUserSuffixVar)
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

            string outbox = Environment.GetEnvironmentVariable(fcmOutboxVar);
            if (!string.IsNullOrEmpty(outbox))
            {
                target.FcmOutbox = outbox;
            }

            // **接尾辞は空文字も意味を持つ**ので、null かどうかで判定する（#260）。
            string suffix = Environment.GetEnvironmentVariable(testUserSuffixVar);
            if (suffix != null)
            {
                target.TestUserSuffix = suffix;
            }
        }

        #endregion
    }
}
