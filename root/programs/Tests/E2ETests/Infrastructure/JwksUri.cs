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
//* クラス名        ：JwksUri
//* クラス日本語名  ：相手（RP）の jwks_uri を、静的配信のコンテナで用意する
//*
//* 作成日時        ：－
//* 作成者          ：－
//* 更新履歴        ：－
//*
//*  日時        更新者            内容
//*  ----------  ----------------  -------------------------------------------------
//*  2026/10/21  玄人 幸道         新規（#309 の段階 1）
//**********************************************************************************

using System;
using System.IO;
using System.Net.Http;
using System.Threading.Tasks;

using Xunit;

/// <summary>MultiPurposeAuthSite.Tests.E2E.Infrastructure</summary>
namespace MultiPurposeAuthSite.Tests.E2E.Infrastructure
{
    /// <summary>
    /// 相手（RP）の `jwks_uri` を、静的配信のコンテナ（`store/jwks`）で用意する。
    /// </summary>
    /// <remarks>
    /// **`jwks_uri` が指す先は、本来クライアントが公開する**（#309）。
    /// **E2E のクライアントは `HttpClient` のコードで、HTTP サーバを持たない**ので、
    /// **配るだけのものを 1 つ置いてある**（`store/docker-compose.yml` の `jwks`。44305）。
    ///
    /// | | |
    /// |---|---|
    /// | **中身を書くのはテスト** | **ホストの `store/jwks` に `.json` を置く**（**同じテストの中で消す**） |
    /// | **鍵の入れ替えを測れる** | **同じ URL の中身を書き替えられる**（`RT-309.3`） |
    /// | **既存の `/jwkcerts` は使わない** | **あれは `RT-140.*` / `CN-5.*` も見ている共有のファイル**である |
    ///
    /// **コンテナが上がっていなければ Skip する**（`SkipIfNotAvailableAsync`）。
    /// **既定の通し（`-Launch` だけ）では Skip になる** —
    /// **`store\1_DockerComposeUp.bat` を回してあれば測れる。**
    ///
    /// **平文の http で配っている。** **実装は `https` を要求するが、
    /// ループバックだけは `http` を許している**
    /// （`ClientRegistrationProvider.IsSecureKeySource`。RFC 8252 §7.3 と同じ扱い）。
    /// </remarks>
    public static class JwksUri
    {
        /// <summary>配信の URL（`store/docker-compose.yml` の `jwks`）</summary>
        public const string BaseUrl = "http://localhost:44305/";

        /// <summary>中身を置く場所（`store/jwks`）</summary>
        /// <remarks>
        /// **`TestEnv.ProgramsDir`（`root/programs`）から 2 つ上が repo の根**である。
        /// </remarks>
        public static string DirectoryPath
        {
            get
            {
                return Path.GetFullPath(Path.Combine(
                    TestEnv.ProgramsDir, "..", "..", "store", "jwks"));
            }
        }

        /// <summary>その名前の JWK Set の URL</summary>
        /// <param name="name">名前（拡張子は付けない）</param>
        /// <returns>URL</returns>
        public static string Url(string name)
        {
            return JwksUri.BaseUrl + name + ".json";
        }

        /// <summary>JWK Set を置く（既に在れば書き替える）</summary>
        /// <param name="name">名前（拡張子は付けない）</param>
        /// <param name="jwks">JWK（JSON の文字列。1 本ずつ）</param>
        /// <remarks>
        /// **`keys` に並べて置くだけ**である（RFC 7517 §5）。
        /// **公開鍵しか置かない**（`JwsSigner.PublicRsaJwk` / `PublicEcJwk`）。
        /// </remarks>
        public static void Write(string name, params string[] jwks)
        {
            Directory.CreateDirectory(JwksUri.DirectoryPath);

            File.WriteAllText(
                Path.Combine(JwksUri.DirectoryPath, name + ".json"),
                "{\"keys\":[" + string.Join(",", jwks) + "]}");
        }

        /// <summary>置いた JWK Set を消す（後片付け）</summary>
        /// <param name="name">名前（拡張子は付けない）</param>
        /// <remarks>**無ければ何もしない。**</remarks>
        public static void Delete(string name)
        {
            string path = Path.Combine(JwksUri.DirectoryPath, name + ".json");

            if (File.Exists(path))
            {
                File.Delete(path);
            }
        }

        /// <summary>配信のコンテナが上がっていなければ Skip する</summary>
        /// <returns>Task</returns>
        /// <remarks>
        /// **返ってくる状態は問わない**（`403` でも `404` でも、上がっていれば通る）。
        /// **繋がらないときだけ Skip する。**
        /// </remarks>
        public static async Task SkipIfNotAvailableAsync()
        {
            bool up = false;

            try
            {
                using (HttpClient probe = new HttpClient())
                {
                    probe.Timeout = TimeSpan.FromSeconds(5);

                    HttpResponseMessage res = await probe.GetAsync(JwksUri.BaseUrl);

                    up = res != null;
                }
            }
            catch (Exception)
            {
                up = false;
            }

            Skip.IfNot(up,
                "jwks のコンテナ（" + JwksUri.BaseUrl + "）が上がっていません"
                + "（store\\1_DockerComposeUp.bat で起動します）。");
        }
    }
}
