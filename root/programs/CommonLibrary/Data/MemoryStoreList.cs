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
//* クラス名        ：MemoryStoreList
//* クラス日本語名  ：mem ストアの入れ物
//*
//* 作成者          ：玄人 幸道
//* 更新履歴        ：
//*
//*  日時        更新者            内容
//*  ----------  ----------------  -------------------------------------------------
//*  2026/11/02  玄人 幸道         新規作成（#325）
//**********************************************************************************

using System;
using System.Collections;
using System.Collections.Generic;

namespace MultiPurposeAuthSite.Data
{
    /// <summary>並行に読み書きできる、mem ストアの入れ物</summary>
    /// <remarks>
    /// `List` のままだと、読んでいる間に別の要求が書き換えると例外になる。
    /// `GetRoles` はその例外で空の一覧を返すので、管理者が権限なしとして断られた（#325 の `RT-257.13`）。
    ///
    /// 列挙は、その時点の写しに対して行う。LINQ も foreach も、呼び出し元を変えずに安全になる。
    /// 「無ければ足す」のような複数の操作をまとめて 1 回にはしない。入っている要素自体の変更も守らない。
    /// </remarks>
    /// <typeparam name="T">要素の型</typeparam>
    public sealed class MemoryStoreList<T> : IEnumerable<T>
    {
        /// <summary>排他に使う</summary>
        private readonly object _lock = new object();

        /// <summary>中身</summary>
        private readonly List<T> _items = new List<T>();

        /// <summary>足す</summary>
        /// <param name="item">要素</param>
        public void Add(T item)
        {
            lock (this._lock)
            {
                this._items.Add(item);
            }
        }

        /// <summary>消す</summary>
        /// <param name="item">要素</param>
        /// <returns>消したら true</returns>
        public bool Remove(T item)
        {
            lock (this._lock)
            {
                return this._items.Remove(item);
            }
        }

        /// <summary>条件に合うものを消す</summary>
        /// <param name="match">条件</param>
        /// <returns>消した件数</returns>
        public int RemoveAll(Predicate<T> match)
        {
            lock (this._lock)
            {
                return this._items.RemoveAll(match);
            }
        }

        /// <summary>その時点の写しを列挙する</summary>
        /// <returns>IEnumerator</returns>
        public IEnumerator<T> GetEnumerator()
        {
            T[] snapshot;

            lock (this._lock)
            {
                snapshot = this._items.ToArray();
            }

            return ((IEnumerable<T>)snapshot).GetEnumerator();
        }

        /// <summary>その時点の写しを列挙する</summary>
        /// <returns>IEnumerator</returns>
        IEnumerator IEnumerable.GetEnumerator()
        {
            return this.GetEnumerator();
        }
    }
}
