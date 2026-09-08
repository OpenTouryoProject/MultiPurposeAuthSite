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
//* クラス名        ：Html
//* クラス日本語名  ：HTML応答の要約（診断用）
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
using System.Text.RegularExpressions;

namespace MultiPurposeAuthSite.Tests.E2E.Infrastructure
{
    /// <summary>
    /// リダイレクトせずHTMLが返ってきたときに、何の画面かを言い当てるための要約。
    ///
    /// 本文をそのまま出すと長く、値も含むため、
    /// タイトルと入力項目の「名前」だけを取り出す。
    /// </summary>
    public static class Html
    {
        private static readonly Regex TitleRegex = new Regex(
            "<title[^>]*>(?<value>.*?)</title>",
            RegexOptions.Compiled | RegexOptions.IgnoreCase | RegexOptions.Singleline);

        private static readonly Regex NameRegex = new Regex(
            "<(?:input|button|select|textarea)[^>]*\\bname=\"(?<value>[^\"]+)\"",
            RegexOptions.Compiled | RegexOptions.IgnoreCase);

        private static readonly Regex HeadingRegex = new Regex(
            "<h[1-4][^>]*>(?<value>.*?)</h[1-4]>",
            RegexOptions.Compiled | RegexOptions.IgnoreCase | RegexOptions.Singleline);

        /// <summary>HTMLを1行で要約する（値は含めない）</summary>
        /// <param name="body">HTML</param>
        /// <returns>要約</returns>
        public static string Describe(string body)
        {
            if (string.IsNullOrEmpty(body))
            {
                return "(本文なし)";
            }

            List<string> names = new List<string>();

            foreach (Match m in NameRegex.Matches(body))
            {
                string name = m.Groups["value"].Value;

                if (!names.Contains(name))
                {
                    names.Add(name);
                }
            }

            Match title = TitleRegex.Match(body);
            Match heading = HeadingRegex.Match(body);

            return string.Format("title=\"{0}\" / h=\"{1}\" / fields=[{2}] / {3} bytes",
                title.Success ? Squash(title.Groups["value"].Value) : "-",
                heading.Success ? Squash(heading.Groups["value"].Value) : "-",
                string.Join(", ", names),
                body.Length);
        }

        /// <summary>タグと連続空白を潰して1行にする</summary>
        /// <param name="value">文字列</param>
        /// <returns>1行にした文字列</returns>
        private static string Squash(string value)
        {
            string text = Regex.Replace(value, "<[^>]*>", " ");
            text = Regex.Replace(text, "\\s+", " ").Trim();

            return (text.Length > 120) ? text.Substring(0, 120) + "…" : text;
        }
    }
}
