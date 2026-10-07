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
//* クラス名        ：EnumSessionStoreType
//* クラス日本語名  ：EnumSessionStoreType列挙型
//*
//* 作成日時        ：－
//* 作成者          ：－
//* 更新履歴        ：－
//*
//*  日時        更新者            内容
//*  ----------  ----------------  -------------------------------------------------
//*  2026/10/06  玄人 幸道         新規（#256）
//**********************************************************************************

namespace MultiPurposeAuthSite.Data
{
    /// <summary>セッションの置き場（#256）</summary>
    /// <remarks>
    /// **net10.0 版だけが読む。**
    /// **net48 版は `Web.config` の `sessionState` で選ぶ**（`InProc` / `StateServer` / `SQLServer`）。
    ///
    /// **`IDistributedCache` の実装を選ぶ**ためのもので、
    /// **`UserStoreType` と同じ流儀**にしてある。
    ///
    /// | | |
    /// |---|---|
    /// | `Memory` | **プロセス内。** 複数インスタンスでは共有されない（開発・単一インスタンス向け） |
    /// | `SqlServer` | **SQL Server のテーブル。** `Create_SessionCache.sql` を流しておく |
    /// | `Redis` | **Redis。** **方言に依らない**ので、`UserStoreType` が `ora` / `npg` でも使える |
    ///
    /// **Oracle / PostgreSQL 用の `IDistributedCache` は標準に無い。**
    /// **そのため 3 方言は揃わない。** これらのストアで複数インスタンスにするなら `Redis` を使う。
    /// </remarks>
    public enum EnumSessionStoreType
    {
        /// <summary>プロセス内のメモリ（既定）</summary>
        Memory,
        /// <summary>SQL Server のテーブル</summary>
        SqlServer,
        /// <summary>Redis</summary>
        Redis
    }
}
