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
using System.Data;
using System.Data.Common;
using System.Collections.Generic;
using System.Diagnostics;

using Newtonsoft.Json;
using StackExchange.Profiling.Data;

using Touryo.Infrastructure.Public.Str;

namespace MultiPurposeAuthSite.Log
{
    /// <summary>TraceDbProfiler</summary>
    public class TraceDbProfiler : IDbProfiler
    {
        /// <summary>StopWatch</summary>
        Stopwatch _stopwatch;

        /// <summary>Command Text</summary>
        string _commandText;
        /// <summary>Command Parameters</summary>
        string _commandParameters;

        /// <summary>IsActive</summary>
        public bool IsActive
        {
            get { return true; }
        }

        /// <summary>
        /// コマンドが開始された時に呼ばれる
        /// (ExecuteReaderとかExecuteNonQueryとか)
        /// </summary>
        /// <param name="profiledDbCommand">IDbCommand</param>
        /// <param name="executeType">SqlExecuteType</param>
        public void ExecuteStart(IDbCommand profiledDbCommand, SqlExecuteType executeType)
        {
            this._stopwatch = Stopwatch.StartNew();
        }

        /// <summary>OnError</summary>
        /// <param name="profiledDbCommand">IDbCommand</param>
        /// <param name="executeType">SqlExecuteType</param>
        /// <param name="exception">Exception</param>
        public void OnError(IDbCommand profiledDbCommand, SqlExecuteType executeType, System.Exception exception)
        {
            // 何も記録しない
        }

        /// <summary>
        /// コマンドが完了された時に呼ばれる
        /// </summary>
        /// <param name="profiledDbCommand">IDbCommand</param>
        /// <param name="executeType">SqlExecuteType</param>
        /// <param name="reader">DbDataReader</param>
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
                        text = StringConverter.FormattingForOneLineLog(this._commandText),
                        param = this._commandParameters,
                        ms = this._stopwatch.ElapsedMilliseconds
                    }, Formatting.None));
            }
        }

        /// <summary>
        /// Readerが完了した時に呼ばれる
        /// </summary>
        /// <param name="reader">IDataReader</param>
        public void ReaderFinish(IDataReader reader)
        {
            this._stopwatch.Stop();
            
            Logging.MyDebugSQLTrace(
                   JsonConvert.SerializeObject(new
                   {
                       date = DateTime.Now,
                       command = SqlExecuteType.Reader,
                       text = StringConverter.FormattingForOneLineLog(this._commandText),
                       param = this._commandParameters,
                       ms = this._stopwatch.ElapsedMilliseconds
                   }, Formatting.None));
        }
    }
}