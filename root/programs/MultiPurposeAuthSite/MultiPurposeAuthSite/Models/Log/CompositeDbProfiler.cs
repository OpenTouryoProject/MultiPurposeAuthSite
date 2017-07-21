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
//* クラス名        ：CompositeDbProfiler
//* クラス日本語名  ：CompositeDbProfiler（ライブラリ）
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

using StackExchange.Profiling.Data;

namespace MultiPurposeAuthSite.Models.Log
{
    /// <summary>CompositeDbProfiler</summary>
    public class CompositeDbProfiler : IDbProfiler
    {
        readonly IDbProfiler[] profilers;

        public CompositeDbProfiler(params IDbProfiler[] dbProfilers)
        {
            this.profilers = dbProfilers;
        }

        public void ExecuteFinish(IDbCommand profiledDbCommand, SqlExecuteType executeType, DbDataReader reader)
        {
            foreach (var item in profilers)
            {
                if (item != null && item.IsActive)
                {
                    item.ExecuteFinish(profiledDbCommand, executeType, reader);
                }
            }
        }

        public void ExecuteStart(IDbCommand profiledDbCommand, SqlExecuteType executeType)
        {
            foreach (var item in profilers)
            {
                if (item != null && item.IsActive)
                {
                    item.ExecuteStart(profiledDbCommand, executeType);
                }
            }
        }

        public bool IsActive
        {
            get
            {
                return true;
            }
        }

        public void OnError(IDbCommand profiledDbCommand, SqlExecuteType executeType, Exception exception)
        {
            foreach (var item in profilers)
            {
                if (item != null && item.IsActive)
                {
                    item.OnError(profiledDbCommand, executeType, exception);
                }
            }
        }

        public void ReaderFinish(IDataReader reader)
        {
            foreach (var item in profilers)
            {
                if (item != null && item.IsActive)
                {
                    item.ReaderFinish(reader);
                }
            }
        }
    }
}