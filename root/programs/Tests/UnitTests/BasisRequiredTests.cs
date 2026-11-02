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
//* クラス名        ：BasisRequiredTests
//* クラス日本語名  ：すべてのテストに根拠がある
//*
//* 作成者          ：玄人 幸道
//* 更新履歴        ：
//*
//*  日時        更新者            内容
//*  ----------  ----------------  -------------------------------------------------
//*  2026/11/02  玄人 幸道         新規作成（#324）
//**********************************************************************************

using System.Linq;
using System.Reflection;

using Xunit;

namespace MultiPurposeAuthSite.Tests.Unit
{
    /// <summary>すべてのテストに `[Basis]` がある</summary>
    public class BasisRequiredTests
    {
        /// <summary>根拠の無いテストが無い</summary>
        [Fact]
        [Basis("QUALITY.md 7 節")]
        public void すべてのテストに根拠がある()
        {
            string[] missing = Assembly.GetExecutingAssembly().GetTypes()
                .SelectMany(t => t.GetMethods(BindingFlags.Public | BindingFlags.Instance | BindingFlags.DeclaredOnly))
                .Where(m => m.GetCustomAttributes<FactAttribute>().Any())
                .Where(m => !m.GetCustomAttributes<BasisAttribute>().Any(b => !string.IsNullOrWhiteSpace(b.Source)))
                .Select(m => m.DeclaringType.Name + "." + m.Name)
                .ToArray();

            Assert.Empty(missing);
        }
    }
}
