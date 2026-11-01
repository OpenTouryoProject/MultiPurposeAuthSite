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
//* クラス名        ：TestConfig
//* クラス日本語名  ：テストの設定
//*
//* 作成者          ：玄人 幸道
//* 更新履歴        ：
//*
//*  日時        更新者            内容
//*  ----------  ----------------  -------------------------------------------------
//*  2026/11/02  玄人 幸道         新規作成（#324）
//**********************************************************************************

using System.Collections.Generic;

using Microsoft.Extensions.Configuration;

using Touryo.Infrastructure.Public.Util;

using Xunit;

//  **設定（GetConfigParameter）はプロセスで 1 つ**なので、テストを並べない。
[assembly: CollectionBehavior(DisableTestParallelization = true)]

namespace MultiPurposeAuthSite.Tests.Unit
{
    /// <summary>テストの設定を入れる</summary>
    public static class TestConfig
    {
        /// <summary>設定を置き換える</summary>
        /// <param name="values">キーと値</param>
        public static void Set(Dictionary<string, string> values)
        {
            Dictionary<string, string> settings = new Dictionary<string, string>();

            foreach (KeyValuePair<string, string> item in values)
            {
                settings["appSettings:" + item.Key] = item.Value;
            }

            GetConfigParameter.InitConfiguration(
                new ConfigurationBuilder().AddInMemoryCollection(settings).Build());
        }
    }
}
