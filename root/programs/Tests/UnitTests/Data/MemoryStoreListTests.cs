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
//* クラス名        ：MemoryStoreListTests
//* クラス日本語名  ：mem ストアの入れ物のテスト
//*
//* 作成者          ：玄人 幸道
//* 更新履歴        ：
//*
//*  日時        更新者            内容
//*  ----------  ----------------  -------------------------------------------------
//*  2026/11/02  玄人 幸道         新規作成（#325）
//**********************************************************************************

using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

using MultiPurposeAuthSite.Data;

using Xunit;

namespace MultiPurposeAuthSite.Tests.Unit.Data
{
    /// <summary>MemoryStoreList（列挙の途中で書き換えても例外にならない）</summary>
    public class MemoryStoreListTests
    {
        /// <summary>列挙の途中で消しても例外にならず、列挙は始めた時点の中身を返す</summary>
        [Fact]
        [Basis("#325")]
        public void 列挙の途中で書き換えても例外にならない()
        {
            MemoryStoreList<int> list = new MemoryStoreList<int>();
            list.Add(1);
            list.Add(2);
            list.Add(3);

            List<int> seen = new List<int>();

            foreach (int x in list)
            {
                seen.Add(x);
                list.Remove(x);
            }

            Assert.Equal(new[] { 1, 2, 3 }, seen);
            Assert.Empty(list);
        }

        /// <summary>並行に読み書きしても、要素は増減の分だけになる</summary>
        [Fact]
        [Basis("#325")]
        public async Task 並行に読み書きしても壊れない()
        {
            MemoryStoreList<int> list = new MemoryStoreList<int>();
            list.Add(-1);

            Task writer = Task.Run(() =>
            {
                for (int i = 0; i < 20000; i++)
                {
                    list.Add(i);
                    list.RemoveAll(x => x == i);
                }
            });

            Task[] readers = Enumerable.Range(0, 4).Select(_ => Task.Run(() =>
            {
                for (int i = 0; i < 20000; i++)
                {
                    Assert.Contains(-1, list.Where(x => x < 0));
                }
            })).ToArray();

            await writer;
            await Task.WhenAll(readers);

            Assert.Equal(new[] { -1 }, list.ToArray());
        }
    }
}
