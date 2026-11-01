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
//* クラス名        ：BasisAttribute
//* クラス日本語名  ：期待値の根拠
//*
//* 作成者          ：玄人 幸道
//* 更新履歴        ：
//*
//*  日時        更新者            内容
//*  ----------  ----------------  -------------------------------------------------
//*  2026/11/02  玄人 幸道         新規作成（#324）
//**********************************************************************************

using System;

namespace MultiPurposeAuthSite.Tests.Unit
{
    /// <summary>
    /// **期待値が、何に基づくかを書く**（QUALITY.md 7 節）。Open棟梁 の同名の属性に倣った。
    /// </summary>
    /// <remarks>
    /// **単体テストは、判定できる値だけを書く。観測（`[Observation]`）は流用しない**（#324）。
    /// **すべてのテストに必須**（`BasisRequiredTests` が確かめる）。**消すと期待値の変更になる。**
    /// </remarks>
    [AttributeUsage(AttributeTargets.Method, AllowMultiple = true, Inherited = false)]
    public sealed class BasisAttribute : Attribute
    {
        /// <summary>コンストラクタ</summary>
        /// <param name="source">根拠（出典と節、Issue、設計の文書）</param>
        public BasisAttribute(string source)
        {
            this.Source = source;
        }

        /// <summary>根拠</summary>
        public string Source { get; private set; }
    }
}
