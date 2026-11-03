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
//* クラス名        ：StoreReadFailureTests
//* クラス日本語名  ：ユーザ ストアとロール ストアの読み取りの失敗のテスト
//*
//* 作成者          ：玄人 幸道
//* 更新履歴        ：
//*
//*  日時        更新者            内容
//*  ----------  ----------------  -------------------------------------------------
//*  2026/11/03  玄人 幸道         新規作成（#331）
//**********************************************************************************

using System;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;

using Microsoft.Data.SqlClient;
using Microsoft.Extensions.Configuration;

using MultiPurposeAuthSite;
using MultiPurposeAuthSite.Data;

using Touryo.Infrastructure.Public.Util;

using Xunit;

namespace MultiPurposeAuthSite.Tests.Unit.Data
{
    /// <summary>DB を読めないときに「無い」として返さない</summary>
    /// <remarks>
    /// **接続できない SQL Server を指して、障害を起こす。**
    /// DB のコンテナが無くても回る。
    /// </remarks>
    public class StoreReadFailureTests : IDisposable
    {
        /// <summary>接続できない DB を指す</summary>
        public StoreReadFailureTests()
        {
            GetConfigParameter.InitConfiguration(
                new ConfigurationBuilder().AddInMemoryCollection(new Dictionary<string, string>()
                {
                    { "appSettings:UserStoreType", "sql" },
                    { "appSettings:EnableAdministrationOfUsersAndRoles", "true" },
                    { "ConnectionStrings:ConnectionString_SQL",
                        "Data Source=localhost,1;Initial Catalog=UserStore;Connect Timeout=1;Encrypt=false;" }
                }).Build());
        }

        /// <summary>設定を戻す</summary>
        public void Dispose()
        {
            TestConfig.Set(new Dictionary<string, string>() { { "UserStoreType", "mem" } });
        }

        /// <summary>利用者の読み取りは、DB の例外を投げる</summary>
        [Fact]
        [Basis("#331")]
        public async Task 利用者の読み取りの失敗を無いとして返さない()
        {
            UserStoreCore store = new UserStoreCore();
            CancellationToken none = CancellationToken.None;
            ApplicationUser user = ApplicationUser.CreateUser("name", "name@example.com", true);

            await Assert.ThrowsAsync<SqlException>(() => store.FindByIdAsync("id", none));
            await Assert.ThrowsAsync<SqlException>(() => store.FindByNameAsync("NAME", none));
            await Assert.ThrowsAsync<SqlException>(() => store.FindByEmailAsync("NAME@EXAMPLE.COM", none));
            await Assert.ThrowsAsync<SqlException>(() => store.FindByLoginAsync("provider", "key", none));
            await Assert.ThrowsAsync<SqlException>(() => store.GetRolesAsync(user, none));
            await Assert.ThrowsAsync<SqlException>(() => store.GetTokenAsync(user, "provider", "name", none));
        }

        /// <summary>ロールの読み取りは、DB の例外を投げる</summary>
        [Fact]
        [Basis("#331")]
        public async Task ロールの読み取りの失敗を無いとして返さない()
        {
            RoleStoreCore store = new RoleStoreCore();
            CancellationToken none = CancellationToken.None;

            await Assert.ThrowsAsync<SqlException>(() => store.FindByIdAsync("id", none));
            await Assert.ThrowsAsync<SqlException>(() => store.FindByNameAsync("NAME", none));
        }

        /// <summary>読み直すのはデッドロックの犠牲だけで、ほかの失敗は 1 回で投げる</summary>
        [Fact]
        [Basis("#331")]
        public void デッドロック以外の失敗は読み直さない()
        {
            int calls = 0;

            Assert.Throws<InvalidOperationException>(() => DataAccess.RetryOnDeadlock<int>(() =>
            {
                calls++;
                throw new InvalidOperationException();
            }));

            Assert.Equal(1, calls);
            Assert.Equal(7, DataAccess.RetryOnDeadlock(() => 7));
        }
    }
}
