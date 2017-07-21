//**********************************************************************************
//* Copyright (C) 2007,2016 Hitachi Solutions,Ltd.
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
//* クラス名        ：TraceDbProfiler
//* クラス日本語名  ：TraceDbProfiler（ライブラリ）
//*
//* 作成日時        ：－
//* 作成者          ：－
//* 更新履歴        ：－
//*
//*  日時        更新者            内容
//*  ----------  ----------------  -------------------------------------------------
//*  2017/06/14  西野 大介         新規
//**********************************************************************************

using System;
using System.Text;
using System.Data;
using System.Data.Common;
using System.Collections.Generic;
using System.Diagnostics;

using Newtonsoft.Json;
using StackExchange.Profiling.Data;

namespace MultiPurposeAuthSite.Models.Log
{
    public class TraceDbProfiler : IDbProfiler
    {
        public bool IsActive
        {
            get { return true; }
        }

        public void OnError(IDbCommand profiledDbCommand, SqlExecuteType executeType, System.Exception exception)
        {
            // 何も記録しない
        }
        
        Stopwatch _stopwatch;
        string _commandText;
        string _commandParameters;

        // コマンドが開始された時に呼ばれる(ExecuteReaderとかExecuteNonQueryとか)
        public void ExecuteStart(IDbCommand profiledDbCommand, SqlExecuteType executeType)
        {
            this._stopwatch = Stopwatch.StartNew();
        }

        // コマンドが完了された時に呼ばれる
        public void ExecuteFinish(IDbCommand profiledDbCommand, SqlExecuteType executeType, DbDataReader reader)
        {
            Dictionary<string, string> dic = new Dictionary<string, string>();

            foreach (IDataParameter p in profiledDbCommand.Parameters)
            {
                if (p.Value == null)
                {
                    dic.Add(p.ParameterName, "null");
                }
                else
                {
                    dic.Add(p.ParameterName, p.Value.ToString());
                }
            }

            this._commandText = profiledDbCommand.CommandText;
            this._commandParameters = JsonConvert.SerializeObject(dic, Formatting.None);

            if (executeType != SqlExecuteType.Reader)
            {
                this._stopwatch.Stop();

                Logging.MyDebugSQLTrace(
                    JsonConvert.SerializeObject(new
                    {
                        date = DateTime.Now,
                        command = executeType,
                        text = this.ClearText(this._commandText),
                        param = this._commandParameters,
                        ms = this._stopwatch.ElapsedMilliseconds
                    }, Formatting.None));
            }
        }

        // Readerが完了した時に呼ばれる
        public void ReaderFinish(IDataReader reader)
        {
            this._stopwatch.Stop();
            
            Logging.MyDebugSQLTrace(
                   JsonConvert.SerializeObject(new
                   {
                       date = DateTime.Now,
                       command = SqlExecuteType.Reader,
                       text = this.ClearText(this._commandText),
                       param = this._commandParameters,
                       ms = this._stopwatch.ElapsedMilliseconds
                   }, Formatting.None));
        }

        /// <summary>
        /// ClearText
        /// https://github.com/OpenTouryoProject/OpenTouryo/blob/develop/root/programs/C%23/Frameworks/Infrastructure/Public/Db/BaseDam.cs#L3067
        /// </summary>
        /// <param name="text">string</param>
        /// <returns>string</returns>
        private string ClearText(string text)
        {
            // StringBuilderを使用して
            // インナーテキストをキレイにする。
            StringBuilder sb = new StringBuilder();

            // キャリッジリターン文字とラインフィード文字
            // '\r\n'
            // キャリッジリターン文字
            // '\r'
            // ラインフィード文字
            // '\n'
            //// タブ文字
            //// '\t'
            // を取り除く
            text = text.Replace("\r\n", " ");
            text = text.Replace('\r', ' ');
            text = text.Replace('\n', ' ');
            //text = text.Replace('\t', ' ');

            // & → &amp;置換
            text = text.Replace("&", "&amp;");
            // エスケープされているシングルクォートを置換
            text = text.Replace("''", "&SingleQuote2;");

            // 連続した空白は、詰める
            bool isConsecutive = false;

            // 文字列中は、詰めない
            bool isString = false;

            foreach (char ch in text)
            {
                if (ch == '\'')
                {
                    // 出たり入ったり（文字列）。
                    isString = !isString;
                }

                if (ch == ' ')
                {
                    if (isConsecutive && !isString)
                    {
                        // 空白（半角スペース）が連続＆文字列外。
                        // → アペンドしない。
                    }
                    else
                    {
                        // 空白（半角スペース）が初回 or 文字列中。
                        // → アペンドする。
                        sb.Append(ch);

                        // 空白（半角スペース）が連続しているフラグを立てる。
                        isConsecutive = true;
                    }
                }
                else if (ch == '\t')
                {
                    if (isConsecutive && !isString)
                    {
                        // 空白（タブ文字）が連続＆文字列外。
                        // → アペンドしない。
                    }
                    else
                    {
                        // 空白（タブ文字）が初回 or 文字列中。
                        // → アペンドする。
                        sb.Append(ch);

                        // 空白（タブ文字）が連続しているフラグを立てる。
                        isConsecutive = true;
                    }
                }
                else
                {
                    // アペンドする。
                    sb.Append(ch);

                    // 連続した空白が途切れたので、フラグを倒す。
                    isConsecutive = false;
                }
            }

            // 戻し（エスケープされているシングルクォートを置換）。
            text = sb.ToString().Replace("&SingleQuote2;", "''");

            // 戻し（& → &amp;置換）
            text = text.Replace("&amp;", "&");

            // 結果を返す
            return text;
        }
    }
}