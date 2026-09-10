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
//* クラス名        ：TestReport
//* クラス日本語名  ：テストの内容と結果を、それ自体で読めるように書き出す
//*
//* 作成日時        ：－
//* 作成者          ：－
//* 更新履歴        ：－
//*
//*  日時        更新者            内容
//*  ----------  ----------------  -------------------------------------------------
//*  2026/09/09  玄人 幸道         新規（基本テストの追加に伴う）
//**********************************************************************************

using System;
using System.Collections.Generic;

using Xunit;
using Xunit.Abstractions;

namespace MultiPurposeAuthSite.Tests.E2E.Infrastructure
{
    /// <summary>
    /// テストの「何を・何を根拠に・どう試して・何を期待し・何が起きたか」を書き出す。
    ///
    /// ＜なぜ要るか＞
    ///   テスト名と OK / NG だけでは、**そのテストが妥当かどうかを外から判断できない。**
    ///   期待値の根拠が仕様のどこにあるのか、実際に何を送って何が返ったのかが
    ///   残っていなければ、通っていること自体が信用に値しない。
    ///
    ///   出力は TRX の StdOut に入り、2_RunAllTests.ps1 が
    ///   E2ETests.report.md にまとめ直す。
    ///
    /// ＜検証と観測を分ける＞
    ///   Verify... は**合否を判定する**（失敗すればテストが落ちる）。
    ///   Observe は**記録だけ**して判定しない。
    ///
    ///   仕様が「拒否されるか、または警告されるか」のように幅を持つ項目や、
    ///   実装の現状を残しておきたい項目は Observe にする。
    ///   **観測を検証と混ぜると、「通った」の意味が薄まる。**
    /// </summary>
    public sealed class TestReport
    {
        private readonly ITestOutputHelper _output;
        private readonly List<string> _verified = new List<string>();
        private readonly List<string> _observed = new List<string>();
        private int _no;

        /// <summary>テストの識別子（TC-1.1 など）</summary>
        public string Id { get; }

        /// <summary>
        /// コンストラクタ
        /// </summary>
        /// <param name="output">ITestOutputHelper</param>
        /// <param name="id">識別子（TC-1.1 など。報告の並び順に使う）</param>
        /// <param name="title">何を確かめるテストか</param>
        /// <param name="viewpoint">観点（何が満たされていれば良いのか）</param>
        /// <param name="basis">根拠（RFC / OIDC の該当箇所）</param>
        public TestReport(
            ITestOutputHelper output, string id, string title, string viewpoint, string basis)
        {
            this._output = output;
            this.Id = id;

            this.Write("");
            this.Write("[" + id + "] " + title);
            this.Write("  観点 : " + viewpoint);
            this.Write("  根拠 : " + basis);
        }

        #region 経過

        /// <summary>対象（どのサイト・どのクライアントで試したか）</summary>
        /// <param name="text">説明</param>
        public void Target(string text)
        {
            this.Write("  対象 : " + text);
        }

        /// <summary>手順（何を送ったか）</summary>
        /// <param name="text">説明</param>
        public void Step(string text)
        {
            this.Write("  手順 : " + text);
        }

        /// <summary>補足（読み手が判断に使う前提や注意）</summary>
        /// <param name="text">説明</param>
        public void Note(string text)
        {
            this.Write("  補足 : " + text);
        }

        #endregion

        #region 検証（合否を判定する）

        /// <summary>値が期待どおりか</summary>
        /// <param name="what">何を確かめるか</param>
        /// <param name="expected">期待値</param>
        /// <param name="actual">実測値</param>
        public void VerifyEqual(string what, string expected, string actual)
        {
            bool ok = string.Equals(expected, actual, StringComparison.Ordinal);

            this.WriteCheck(what, Show(expected), Show(actual), ok);

            if (!ok)
            {
                Assert.Fail(this.Id + " " + what
                    + " / 期待=" + Show(expected) + " 実測=" + Show(actual));
            }

            this._verified.Add(what);
        }

        /// <summary>条件が成り立つか</summary>
        /// <param name="what">何を確かめるか</param>
        /// <param name="condition">成り立つべき条件</param>
        /// <param name="expected">期待の説明</param>
        /// <param name="actual">実測の説明</param>
        public void Verify(string what, bool condition, string expected, string actual)
        {
            this.WriteCheck(what, expected, actual, condition);

            if (!condition)
            {
                Assert.Fail(this.Id + " " + what + " / 期待=" + expected + " 実測=" + actual);
            }

            this._verified.Add(what);
        }

        #endregion

        #region 観測（判定しない）

        /// <summary>
        /// 実装の挙動を記録するだけ。**合否には数えない。**
        /// </summary>
        /// <param name="what">何を見たか</param>
        /// <param name="actual">実測</param>
        /// <param name="comment">読み手向けの注記（仕様上どう解釈すべきか）</param>
        public void Observe(string what, string actual, string comment = null)
        {
            this._no++;

            this.Write("  観測" + this._no + " : " + what);
            this.Write("      実測 = " + Show(actual));

            if (!string.IsNullOrEmpty(comment))
            {
                this.Write("      注記 = " + comment);
            }

            this.Write("      判定 = しない（記録のみ）");

            this._observed.Add(what);
        }

        #endregion

        /// <summary>締め。検証した件数を残す。</summary>
        public void Done()
        {
            this.Write("  結果 : OK（検証 " + this._verified.Count + " 件成立"
                + (this._observed.Count > 0 ? " / 観測 " + this._observed.Count + " 件" : "")
                + "）");
        }

        #region Private

        /// <summary>検証 1 件を書き出す</summary>
        /// <param name="what">何を確かめるか</param>
        /// <param name="expected">期待</param>
        /// <param name="actual">実測</param>
        /// <param name="ok">成立したか</param>
        private void WriteCheck(string what, string expected, string actual, bool ok)
        {
            this._no++;

            this.Write("  検証" + this._no + " : " + what);
            this.Write("      期待 = " + expected);
            this.Write("      実測 = " + actual);
            this.Write("      判定 = " + (ok ? "OK" : "NG  ← ここで失敗"));
        }

        /// <summary>値を読める形にする（null と空文字を区別する）</summary>
        /// <param name="value">値</param>
        /// <returns>表示用の文字列</returns>
        private static string Show(string value)
        {
            if (value == null)
            {
                return "(なし)";
            }

            if (value.Length == 0)
            {
                return "(空文字)";
            }

            return "\"" + value + "\"";
        }

        /// <summary>1 行書く</summary>
        /// <param name="line">行</param>
        private void Write(string line)
        {
            this._output.WriteLine(line);
        }

        #endregion
    }
}
