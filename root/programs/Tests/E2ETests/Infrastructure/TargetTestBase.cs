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
//* クラス名        ：TargetTestBase
//* クラス日本語名  ：net10.0版 / net48版 の双方に同じテストを流す基底クラス
//*
//* 作成日時        ：－
//* 作成者          ：－
//* 更新履歴        ：－
//*
//*  日時        更新者            内容
//*  ----------  ----------------  -------------------------------------------------
//*  2026/09/08  玄人 幸道         新規（E2Eテスト基盤）
//**********************************************************************************

using System.Collections.Generic;
using System.Threading.Tasks;

using Xunit;
using Xunit.Abstractions;

namespace MultiPurposeAuthSite.Tests.E2E.Infrastructure
{
    /// <summary>
    /// テスト対象（net10.0版 / net48版）をパラメタにして、同じテストを両方に流す。
    ///
    /// このリポジトリはクロスコンパイルで下位互換版を維持しているため、
    /// 「片方だけ直っている」状態を検出できることを最優先にしている。
    ///
    /// 起動していない対象は Skip する（net48版はIIS Expressでの手動起動が前提のため）。
    /// </summary>
    public abstract class TargetTestBase
    {
        /// <summary>テストの出力</summary>
        protected ITestOutputHelper Output { get; }

        /// <summary>コンストラクタ</summary>
        /// <param name="output">ITestOutputHelper</param>
        protected TargetTestBase(ITestOutputHelper output)
        {
            this.Output = output;
        }

        /// <summary>両方のテスト対象</summary>
        public static IEnumerable<object[]> AllTargets
        {
            get
            {
                yield return new object[] { TestEnv.CoreKey };
                yield return new object[] { TestEnv.NetFxKey };
            }
        }

        /// <summary>net10.0版のみ</summary>
        public static IEnumerable<object[]> CoreOnly
        {
            get
            {
                yield return new object[] { TestEnv.CoreKey };
            }
        }

        /// <summary>
        /// テストの内容と結果を書き出すレポータを作る。
        /// **何を・何を根拠に確かめたのかを残す**（TestReport の説明を参照）。
        /// </summary>
        /// <param name="id">識別子（TC-1.1 など）</param>
        /// <param name="title">何を確かめるテストか</param>
        /// <param name="viewpoint">観点</param>
        /// <param name="basis">根拠（RFC / OIDC の該当箇所）</param>
        /// <returns>TestReport</returns>
        protected TestReport Report(string id, string title, string viewpoint, string basis)
        {
            return new TestReport(this.Output, id, title, viewpoint, basis);
        }

        /// <summary>
        /// テスト対象のクライアントを返す。
        /// 対象が起動していなければ、テストを Skip する。
        /// </summary>
        /// <param name="targetKey">core / netfx</param>
        /// <returns>IdPClient</returns>
        protected IdPClient Client(string targetKey)
        {
            TargetInfo target = TestEnv.Target(targetKey);

            Skip.IfNot(target.IsReachable(), target.UnavailableReason ?? "対象が起動していません。");

            this.Output.WriteLine("対象: " + target.DisplayName + " (" + target.BaseUrl + ")");

            return new IdPClient(target);
        }

        /// <summary>
        /// サインイン済みのクライアントを返す。
        /// </summary>
        /// <param name="targetKey">core / netfx</param>
        /// <returns>IdPClient</returns>
        protected async Task<IdPClient> SignedInClientAsync(string targetKey)
        {
            IdPClient client = this.Client(targetKey);
            await client.SignInAsync();
            return client;
        }
    }
}
