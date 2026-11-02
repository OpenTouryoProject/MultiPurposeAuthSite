//**********************************************************************************
//* Copyright (C) 2017 Hitachi Solutions,Ltd.
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
//* クラス名        ：UserStoreDdlTests
//* クラス日本語名  ：UserStore の DDL の検査
//*
//* 作成者          ：玄人 幸道
//* 更新履歴        ：
//*
//*  日時        更新者            内容
//*  ----------  ----------------  -------------------------------------------------
//*  2026/11/02  玄人 幸道         新規作成（#329）
//**********************************************************************************

using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text.RegularExpressions;

using Xunit;

namespace MultiPurposeAuthSite.Tests.Unit.Data
{
    /// <summary>
    /// 外部キーの子の列に、その列が先頭のインデックスがあること。
    /// 無いと親の削除が子の表を全件走査し、同時に走る削除とデッドロックする（#329）。
    /// デッドロックは断続的にしか起きないので、原因の形を DDL で確かめる。
    /// </summary>
    public class UserStoreDdlTests
    {
        /// <summary>外部キーの子の列に、その列が先頭のインデックスか主キーがある</summary>
        [Theory]
        [InlineData("sqlserver")]
        [InlineData("oracle")]
        [InlineData("pstgrs")]
        [Basis("#329")]
        public void 外部キーの子の列にインデックスがある(string dialect)
        {
            string ddl = Regex.Replace(File.ReadAllText(FindDdl(dialect)), @"--[^\n]*", "");
            ddl = ddl.Replace("[", "").Replace("]", "").Replace("\"", "");

            HashSet<string> leading = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

            // インデックスの先頭の列
            foreach (Match m in Regex.Matches(ddl,
                @"CREATE\s+(?:UNIQUE\s+)?(?:NONCLUSTERED\s+)?INDEX\s+\S+\s+ON\s+(\w+)\s*\(\s*(\w+)"))
            {
                leading.Add(m.Groups[1].Value + "." + m.Groups[2].Value);
            }

            // 主キーの先頭の列
            foreach (Match m in Regex.Matches(ddl, @"CREATE\s+TABLE\s+(\w+)\s*\((.*?)\n\s*\)", RegexOptions.Singleline))
            {
                Match pk = Regex.Match(m.Groups[2].Value, @"PRIMARY\s+KEY\s+(?:NONCLUSTERED\s+|CLUSTERED\s+)?\(\s*(\w+)");
                if (pk.Success)
                {
                    leading.Add(m.Groups[1].Value + "." + pk.Groups[1].Value);
                }
            }

            List<string> foreignKeys = Regex.Matches(ddl,
                @"ALTER\s+TABLE\s+(\w+)\s+(?:WITH\s+CHECK\s+)?ADD\s+CONSTRAINT\s+\S+\s+FOREIGN\s+KEY\s*\(\s*(\w+)")
                .Cast<Match>()
                .Select(m => m.Groups[1].Value + "." + m.Groups[2].Value)
                .ToList();

            // 正規表現が外れて、何も調べずに通るのを防ぐ
            Assert.True(foreignKeys.Count >= 10, dialect + " の外部キーが読めていない : " + foreignKeys.Count);

            Assert.Empty(foreignKeys.Where(x => !leading.Contains(x)));
        }

        /// <summary>DDL のファイルを、実行フォルダから上へたどって探す</summary>
        private static string FindDdl(string dialect)
        {
            string relative = Path.Combine("root", "files", "resource", "MultiPurposeAuthSite", "Sql", dialect, "Create_UserStore.sql");

            for (DirectoryInfo dir = new DirectoryInfo(AppContext.BaseDirectory); dir != null; dir = dir.Parent)
            {
                string path = Path.Combine(dir.FullName, relative);
                if (File.Exists(path))
                {
                    return path;
                }
            }

            throw new FileNotFoundException(relative);
        }
    }
}
