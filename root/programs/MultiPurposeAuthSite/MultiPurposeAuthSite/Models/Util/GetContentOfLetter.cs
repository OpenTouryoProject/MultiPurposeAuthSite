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
//* クラス名        ：GetContentOfLetter
//* クラス日本語名  ：GetContentOfLetter（ライブラリ）
//*
//* 作成日時        ：－
//* 作成者          ：－
//* 更新履歴        ：－
//*
//*  日時        更新者            内容
//*  ----------  ----------------  -------------------------------------------------
//*  2017/06/18  西野 大介         新規
//**********************************************************************************

using System.Text;
using System.Threading;
using System.Globalization;

using Touryo.Infrastructure.Public.Util;
using Touryo.Infrastructure.Public.IO;

namespace MultiPurposeAuthSite.Models.Util
{
    /// <summary>Log</summary>
    public class GetContentOfLetter
    {
        /// <summary>Get</summary>
        /// <param name="fileName">
        /// CurrentUICulture等の拡張子を除くテキスト・ファイル名
        /// </param>
        /// <param name="codePage"></param>
        /// <param name="resourcesString">
        /// テキスト・ファイルが見つからない場合に使用するリソース文字列
        /// </param>
        /// <returns>文字列</returns>
        public static string Get(string fileName, int codePage, string resourcesString)
        {
            CultureInfo currentUICulture = null;
            string uICultureName = "";
            string contentOfLetter = "";

            // テキスト・ファイル文字列の利用
            do
            {
                if (currentUICulture == null)
                {
                    // 初回
                    currentUICulture = Thread.CurrentThread.CurrentUICulture;
                }
                else
                {
                    // フォールバック
                    currentUICulture = currentUICulture.Parent;
                }

                uICultureName = currentUICulture.Name;

                string path = GetConfigParameter.GetConfigValue("ContentOfLetterFilePath") + "\\" + fileName + string.Format(".{0}.txt", uICultureName);
                if (ResourceLoader.Exists(path, false))
                {
                    contentOfLetter = ResourceLoader.LoadAsString(path, Encoding.GetEncoding(codePage));
                }
            }
            while (
                !string.IsNullOrEmpty(uICultureName)      // フォールバックが終わった。
                && string.IsNullOrEmpty(contentOfLetter)  // ファイルを読み取れなかった。
            );
            
            if(string.IsNullOrEmpty(contentOfLetter)) // 既定（英語）
            {
                string path = GetConfigParameter.GetConfigValue("ContentOfLetterFilePath") + "\\" + fileName + ".txt";
                if (ResourceLoader.Exists(path, false))
                {
                    contentOfLetter = ResourceLoader.LoadAsString(path, Encoding.GetEncoding(codePage));
                }
            }

            // リソース文字列の利用
            if (string.IsNullOrEmpty(contentOfLetter) && !string.IsNullOrEmpty(resourcesString))
            {
                contentOfLetter = resourcesString;
            }

            return contentOfLetter;
        }
    }
}