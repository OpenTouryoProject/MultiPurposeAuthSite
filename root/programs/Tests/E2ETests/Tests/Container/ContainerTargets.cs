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
//* クラス名        ：ContainerTargets
//* クラス日本語名  ：コンテナ配備のテスト対象（#284）
//*
//* 作成日時        ：－
//* 作成者          ：－
//* 更新履歴        ：－
//*
//*  日時        更新者            内容
//*  ----------  ----------------  -------------------------------------------------
//*  2026/10/08  玄人 幸道         新規（#284）
//**********************************************************************************

using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Text.Json;

using MultiPurposeAuthSite.Tests.E2E.Infrastructure;

using Xunit;

namespace MultiPurposeAuthSite.Tests.E2E.Tests.Container
{
    /// <summary>
    /// `store/` のコンテナ（上流 / 下流）を、テスト対象として扱う（#284）。
    /// </summary>
    /// <remarks>
    /// **ホストの core / netfx（`TestEnv`）とは別に持つ。**
    /// **`AllTargets` に混ぜない** — 混ぜると既存の全テストが増え、
    /// **その大半は同じコードの再計測**になる。**ここで測るのは配備の差だけである。**
    ///
    /// **実効設定は「`store/app/publish/appsettings.json` ＋ compose の環境変数」**である。
    /// **ファイルだけ読むと、compose が上書きした分が分からない**ので、
    /// **`docker inspect` で稼働中コンテナの環境変数を読み、重ねる**（`AppConfig.Overlay`）。
    ///
    /// | 読む先 | 何が取れるか |
    /// |---|---|
    /// | `publish/appsettings.json` | `TestUserPWD`、自己テスト用のクライアント（`TestClient`〜） |
    /// | `docker inspect` の `Env` | 自分の URL、`IssuerId`、ID 連携の宛先、ID 連携のクライアント |
    ///
    /// **テストにも、テスト設定にも秘密を書かない**（`TESTING.md` 9 節）。
    ///
    /// **ストアは両方とも `mem` 固定**（compose。切り替えない）。
    /// **測るのは配備の差であり、どれもストアに依存しない。**
    ///
    /// **建っていなければ Skip する**（DB ストアや IIS Express と同じ扱い）。
    /// </remarks>
    public static class ContainerTargets
    {
        /// <summary>上流コンテナのキー</summary>
        public const string UpstreamKey = "upstream";

        /// <summary>下流コンテナのキー</summary>
        public const string DownstreamKey = "downstream";

        /// <summary>compose のプロジェクト名（`store/` ディレクトリの名前）</summary>
        private const string ComposeProject = "store";

        private static readonly object _lock = new object();

        private static readonly Dictionary<string, TargetInfo> _targets =
            new Dictionary<string, TargetInfo>(StringComparer.OrdinalIgnoreCase);

        private static readonly Dictionary<string, string> _unavailable =
            new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);

        /// <summary>両方のコンテナ</summary>
        public static IEnumerable<object[]> BothContainers
        {
            get
            {
                yield return new object[] { ContainerTargets.UpstreamKey };
                yield return new object[] { ContainerTargets.DownstreamKey };
            }
        }

        /// <summary>下流コンテナのみ</summary>
        public static IEnumerable<object[]> DownstreamOnly
        {
            get
            {
                yield return new object[] { ContainerTargets.DownstreamKey };
            }
        }

        /// <summary>
        /// テスト対象（コンテナ）を返す。**使えなければ Skip する。**
        /// </summary>
        /// <param name="key">upstream / downstream</param>
        /// <returns>TargetInfo</returns>
        public static TargetInfo Target(string key)
        {
            lock (ContainerTargets._lock)
            {
                TargetInfo target;

                if (ContainerTargets._targets.TryGetValue(key, out target))
                {
                    return target;
                }

                string reason;

                if (ContainerTargets._unavailable.TryGetValue(key, out reason))
                {
                    Skip.If(true, reason);
                }

                target = ContainerTargets.Build(key, out reason);

                if (target == null)
                {
                    ContainerTargets._unavailable[key] = reason;
                    Skip.If(true, reason);
                }

                ContainerTargets._targets[key] = target;
                return target;
            }
        }

        /// <summary>
        /// テスト対象（コンテナ）のクライアントを返す。**使えなければ Skip する。**
        /// </summary>
        /// <param name="key">upstream / downstream</param>
        /// <returns>IdPClient</returns>
        public static IdPClient Client(string key)
        {
            TargetInfo target = ContainerTargets.Target(key);

            Skip.IfNot(target.IsReachable(),
                target.UnavailableReason ?? "コンテナが起動していません。");

            // **種データを作らせる**（`GET /Account/Login` で `CreateData` が走る。#264）。
            //   **`mem` なので、作り直すたびに要る。**
            target.EnsureSeedData();

            return new IdPClient(target);
        }

        /// <summary>テスト対象を組み立てる（できなければ null と理由を返す）</summary>
        /// <param name="key">upstream / downstream</param>
        /// <param name="reason">使えない理由</param>
        /// <returns>TargetInfo。使えなければ null</returns>
        private static TargetInfo Build(string key, out string reason)
        {
            reason = null;

            // **publish の成果物を構成として読む**（`3_PublishUpstream.ps1` が作る）。
            string configPath = Path.GetFullPath(Path.Combine(
                TestEnv.ProgramsDir, "..", "..", "store", "app", "publish", "appsettings.json"));

            if (!File.Exists(configPath))
            {
                reason = "コンテナの構成が見つかりません（" + configPath + "）。"
                    + "store\\3_PublishUpstream.ps1 を実行してください（#284）。";
                return null;
            }

            string containerName = ContainerTargets.FindContainerName(key);

            if (string.IsNullOrEmpty(containerName))
            {
                reason = key + " のコンテナが起動していません。"
                    + "store\\1_DockerComposeUp.bat で建ててください（#284）。";
                return null;
            }

            List<string> env = ContainerTargets.ReadEnv(containerName);

            if (env == null || env.Count == 0)
            {
                reason = containerName + " の環境変数を読めませんでした（docker inspect）。";
                return null;
            }

            TargetInfo target = new TargetInfo()
            {
                Key = key,
                DisplayName = (key == ContainerTargets.UpstreamKey)
                    ? "上流コンテナ" : "下流コンテナ",
                Enabled = true,
                // **コンテナは接尾辞を使わない**（自分のストアを持つ。#260 と同じ考え方）。
                TestUserSuffix = "",
                ConfigPath = configPath
            };

            // **compose の環境変数を重ねる。** **BaseUrl もここから決まる**
            //   （`OAuth2AuthorizationServerEndpointsRootURI`）。**テストに URL を書かない。**
            target.Config.Overlay(env);

            return target;
        }

        /// <summary>compose のラベルから、コンテナ名を引く</summary>
        /// <param name="service">サービス名（upstream / downstream）</param>
        /// <returns>コンテナ名。無ければ null</returns>
        /// <remarks>
        /// **名前（`store-upstream-1`）を直書きしない。**
        /// **compose が付けるラベルで引く**ので、プロジェクト名の付け方が変わっても動く。
        /// </remarks>
        private static string FindContainerName(string service)
        {
            string output = ContainerTargets.RunDocker(
                "ps",
                "--filter", "label=com.docker.compose.project=" + ContainerTargets.ComposeProject,
                "--filter", "label=com.docker.compose.service=" + service,
                "--format", "{{.Names}}");

            if (string.IsNullOrEmpty(output))
            {
                return null;
            }

            string[] names = output.Split(
                new char[] { '\r', '\n' }, StringSplitOptions.RemoveEmptyEntries);

            return (names.Length == 0) ? null : names[0].Trim();
        }

        /// <summary>コンテナの環境変数を読む</summary>
        /// <param name="containerName">コンテナ名</param>
        /// <returns>`KEY=VALUE` の列。読めなければ null</returns>
        private static List<string> ReadEnv(string containerName)
        {
            string json = ContainerTargets.RunDocker(
                "inspect", containerName, "--format", "{{json .Config.Env}}");

            if (string.IsNullOrEmpty(json))
            {
                return null;
            }

            try
            {
                List<string> entries = new List<string>();

                using (JsonDocument doc = JsonDocument.Parse(json))
                {
                    foreach (JsonElement item in doc.RootElement.EnumerateArray())
                    {
                        entries.Add(item.GetString());
                    }
                }

                return entries;
            }
            catch (JsonException)
            {
                return null;
            }
        }

        /// <summary>docker を叩いて標準出力を返す（失敗したら null）</summary>
        /// <param name="arguments">引数（1 つずつ渡す）</param>
        /// <returns>標準出力。失敗したら null</returns>
        /// <remarks>
        /// **docker が無い環境でも落とさない。** 読めなければ Skip の理由にする。
        ///
        /// **引数は `ArgumentList` で 1 つずつ渡す。**
        /// **1 本の文字列にすると、`{{json .Config.Env}}` が空白で割れる**（実測。#284）。
        /// </remarks>
        private static string RunDocker(params string[] arguments)
        {
            try
            {
                ProcessStartInfo info = new ProcessStartInfo("docker")
                {
                    RedirectStandardOutput = true,
                    RedirectStandardError = true,
                    UseShellExecute = false,
                    CreateNoWindow = true
                };

                foreach (string argument in arguments)
                {
                    info.ArgumentList.Add(argument);
                }

                using (Process process = Process.Start(info))
                {
                    string output = process.StandardOutput.ReadToEnd();
                    process.StandardError.ReadToEnd();

                    if (!process.WaitForExit(30000))
                    {
                        return null;
                    }

                    return (process.ExitCode == 0) ? output : null;
                }
            }
            catch (Exception)
            {
                return null;
            }
        }
    }
}
