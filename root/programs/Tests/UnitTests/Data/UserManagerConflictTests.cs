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
//* クラス名        ：UserManagerConflictTests
//* クラス日本語名  ：子の行を書いた後の、利用者の行の更新の競合のテスト
//*
//* 作成者          ：玄人 幸道
//* 更新履歴        ：
//*
//*  日時        更新者            内容
//*  ----------  ----------------  -------------------------------------------------
//*  2026/11/04  玄人 幸道         新規作成（#331。RT-294.23 の原因）
//**********************************************************************************

using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;
using System.Threading;
using System.Threading.Tasks;

using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;

using MultiPurposeAuthSite;
using MultiPurposeAuthSite.Data;

using Xunit;

namespace MultiPurposeAuthSite.Tests.Unit.Data
{
    /// <summary>外部ログインやクレームの行を書いた後で、利用者の行の更新が競合しても、失敗にしない</summary>
    /// <remarks>
    /// **`AddLoginAsync` などは、子の行をその場で書いてから、利用者の行を楽観排他で更新する。**
    /// **後の更新だけが同じ利用者の別の更新に負けると、行は書けているのに失敗が返っていた**
    /// （ID 連携がエラー画面で終わった。`RT-294.23` が、ときどき落ちた原因）。
    /// **ストアに、他の要求が先に書いたことを 1 回だけ起こさせて測る。**
    /// </remarks>
    public class UserManagerConflictTests
    {
        /// <summary>外部ログインの追加は、競合しても成功し、行が残る</summary>
        [Fact]
        [Basis("#331")]
        public async Task 外部ログインの追加は競合しても成功する()
        {
            ConflictStore store = new ConflictStore();
            UserManagerCore manager = UserManagerConflictTests.Manager(store);
            ApplicationUser user = await manager.FindByIdAsync(store.Row.Id);

            store.PendingConflicts = 1;

            IdentityResult result = await manager.AddLoginAsync(
                user, new UserLoginInfo("https://upstream.example.com", "sub-1", ""));

            Assert.True(result.Succeeded, UserManagerConflictTests.Describe(result));
            Assert.Single(store.Logins);
            Assert.Equal(0, store.PendingConflicts);
        }

        /// <summary>クレームの追加は、競合しても成功し、行が残る</summary>
        [Fact]
        [Basis("#331")]
        public async Task クレームの追加は競合しても成功する()
        {
            ConflictStore store = new ConflictStore();
            UserManagerCore manager = UserManagerConflictTests.Manager(store);
            ApplicationUser user = await manager.FindByIdAsync(store.Row.Id);

            store.PendingConflicts = 1;

            IdentityResult result = await manager.AddClaimAsync(
                user, new Claim("urn:example:email", "user@example.com"));

            Assert.True(result.Succeeded, UserManagerConflictTests.Describe(result));
            Assert.Single(store.Claims);
            Assert.Equal(0, store.PendingConflicts);
        }

        /// <summary>外部ログインの解除は、競合しても成功し、SecurityStamp も新しくなる</summary>
        [Fact]
        [Basis("#331")]
        public async Task 外部ログインの解除は競合してもスタンプを新しくする()
        {
            ConflictStore store = new ConflictStore();
            store.Logins.Add(new UserLoginInfo("https://upstream.example.com", "sub-1", ""));
            UserManagerCore manager = UserManagerConflictTests.Manager(store);
            ApplicationUser user = await manager.FindByIdAsync(store.Row.Id);
            string before = store.Row.SecurityStamp;

            store.PendingConflicts = 1;

            IdentityResult result = await manager.RemoveLoginAsync(
                user, "https://upstream.example.com", "sub-1");

            Assert.True(result.Succeeded, UserManagerConflictTests.Describe(result));
            Assert.Empty(store.Logins);
            Assert.NotEqual(before, store.Row.SecurityStamp);
        }

        /// <summary>UserManagerCore を作る</summary>
        /// <param name="store">ストア</param>
        /// <returns>UserManagerCore</returns>
        private static UserManagerCore Manager(ConflictStore store)
        {
            return new UserManagerCore(
                store,
                Options.Create(new IdentityOptions()),
                new PasswordHasher<ApplicationUser>(),
                new IUserValidator<ApplicationUser>[0],
                new IPasswordValidator<ApplicationUser>[0],
                new UpperInvariantLookupNormalizer(),
                new IdentityErrorDescriber(),
                null,
                NullLogger<UserManager<ApplicationUser>>.Instance);
        }

        /// <summary>失敗の理由（Assert の文面）</summary>
        /// <param name="result">IdentityResult</param>
        /// <returns>文面</returns>
        private static string Describe(IdentityResult result)
        {
            return string.Join(" / ", result.Errors.Select(x => x.Code));
        }

        /// <summary>利用者の行を 1 つだけ持ち、楽観排他で更新するストア（競合を起こせる）</summary>
        private sealed class ConflictStore :
            IUserLoginStore<ApplicationUser>,
            IUserClaimStore<ApplicationUser>,
            IUserSecurityStampStore<ApplicationUser>
        {
            /// <summary>保存してある利用者の行</summary>
            public ApplicationUser Row { get; } = new ApplicationUser()
            {
                UserName = "user",
                NormalizedUserName = "USER",
                Email = "user@example.com",
                SecurityStamp = "stamp-0",
                ConcurrencyStamp = Guid.NewGuid().ToString()
            };

            /// <summary>外部ログインの行（その場で書かれる）</summary>
            public List<UserLoginInfo> Logins { get; } = new List<UserLoginInfo>();

            /// <summary>クレームの行（その場で書かれる）</summary>
            public List<Claim> Claims { get; } = new List<Claim>();

            /// <summary>この回数だけ、更新の直前に他の要求が行を書いたことにする</summary>
            public int PendingConflicts { get; set; }

            /// <summary>行を楽観排他で更新する（CmnUserStore.Update と同じ判定）</summary>
            public Task<IdentityResult> UpdateAsync(ApplicationUser user, CancellationToken cancellationToken)
            {
                if (0 < this.PendingConflicts)
                {
                    //  **他の要求が先に書いた**（スタンプだけが変わる）。
                    this.PendingConflicts--;
                    this.Row.ConcurrencyStamp = Guid.NewGuid().ToString();
                }

                if (user.ConcurrencyStamp != this.Row.ConcurrencyStamp)
                {
                    return Task.FromResult(IdentityResult.Failed(new IdentityErrorDescriber().ConcurrencyFailure()));
                }

                ConflictStore.Copy(user, this.Row);
                this.Row.ConcurrencyStamp = Guid.NewGuid().ToString();
                user.ConcurrencyStamp = this.Row.ConcurrencyStamp;

                return Task.FromResult(IdentityResult.Success);
            }

            /// <summary>FindByIdAsync（行の複製を返す）</summary>
            public Task<ApplicationUser> FindByIdAsync(string userId, CancellationToken cancellationToken)
            {
                ApplicationUser copy = new ApplicationUser() { Id = this.Row.Id };
                ConflictStore.Copy(this.Row, copy);
                copy.ConcurrencyStamp = this.Row.ConcurrencyStamp;

                return Task.FromResult(userId == this.Row.Id ? copy : null);
            }

            /// <summary>FindByNameAsync</summary>
            public Task<ApplicationUser> FindByNameAsync(string normalizedUserName, CancellationToken cancellationToken)
            {
                return this.FindByIdAsync(this.Row.Id, cancellationToken);
            }

            /// <summary>FindByLoginAsync</summary>
            public Task<ApplicationUser> FindByLoginAsync(string loginProvider, string providerKey, CancellationToken cancellationToken)
            {
                return this.Logins.Any(x => x.LoginProvider == loginProvider && x.ProviderKey == providerKey)
                    ? this.FindByIdAsync(this.Row.Id, cancellationToken)
                    : Task.FromResult<ApplicationUser>(null);
            }

            /// <summary>AddLoginAsync（その場で書く）</summary>
            public Task AddLoginAsync(ApplicationUser user, UserLoginInfo login, CancellationToken cancellationToken)
            {
                this.Logins.Add(login);
                return Task.CompletedTask;
            }

            /// <summary>RemoveLoginAsync（その場で書く）</summary>
            public Task RemoveLoginAsync(ApplicationUser user, string loginProvider, string providerKey, CancellationToken cancellationToken)
            {
                this.Logins.RemoveAll(x => x.LoginProvider == loginProvider && x.ProviderKey == providerKey);
                return Task.CompletedTask;
            }

            /// <summary>GetLoginsAsync</summary>
            public Task<IList<UserLoginInfo>> GetLoginsAsync(ApplicationUser user, CancellationToken cancellationToken)
            {
                return Task.FromResult<IList<UserLoginInfo>>(this.Logins.ToList());
            }

            /// <summary>AddClaimsAsync（その場で書く）</summary>
            public Task AddClaimsAsync(ApplicationUser user, IEnumerable<Claim> claims, CancellationToken cancellationToken)
            {
                this.Claims.AddRange(claims);
                return Task.CompletedTask;
            }

            /// <summary>GetClaimsAsync</summary>
            public Task<IList<Claim>> GetClaimsAsync(ApplicationUser user, CancellationToken cancellationToken)
            {
                return Task.FromResult<IList<Claim>>(this.Claims.ToList());
            }

            /// <summary>RemoveClaimsAsync</summary>
            public Task RemoveClaimsAsync(ApplicationUser user, IEnumerable<Claim> claims, CancellationToken cancellationToken)
            {
                foreach (Claim claim in claims.ToList())
                {
                    this.Claims.RemoveAll(x => x.Type == claim.Type && x.Value == claim.Value);
                }

                return Task.CompletedTask;
            }

            /// <summary>ReplaceClaimAsync（使わない）</summary>
            public Task ReplaceClaimAsync(ApplicationUser user, Claim claim, Claim newClaim, CancellationToken cancellationToken)
            {
                throw new NotSupportedException();
            }

            /// <summary>GetUsersForClaimAsync（使わない）</summary>
            public Task<IList<ApplicationUser>> GetUsersForClaimAsync(Claim claim, CancellationToken cancellationToken)
            {
                throw new NotSupportedException();
            }

            /// <summary>SetSecurityStampAsync</summary>
            public Task SetSecurityStampAsync(ApplicationUser user, string stamp, CancellationToken cancellationToken)
            {
                user.SecurityStamp = stamp;
                return Task.CompletedTask;
            }

            /// <summary>GetSecurityStampAsync</summary>
            public Task<string> GetSecurityStampAsync(ApplicationUser user, CancellationToken cancellationToken)
            {
                return Task.FromResult(user.SecurityStamp);
            }

            /// <summary>GetUserIdAsync</summary>
            public Task<string> GetUserIdAsync(ApplicationUser user, CancellationToken cancellationToken)
            {
                return Task.FromResult(user.Id);
            }

            /// <summary>GetUserNameAsync</summary>
            public Task<string> GetUserNameAsync(ApplicationUser user, CancellationToken cancellationToken)
            {
                return Task.FromResult(user.UserName);
            }

            /// <summary>SetUserNameAsync</summary>
            public Task SetUserNameAsync(ApplicationUser user, string userName, CancellationToken cancellationToken)
            {
                user.UserName = userName;
                return Task.CompletedTask;
            }

            /// <summary>GetNormalizedUserNameAsync</summary>
            public Task<string> GetNormalizedUserNameAsync(ApplicationUser user, CancellationToken cancellationToken)
            {
                return Task.FromResult(user.NormalizedUserName);
            }

            /// <summary>SetNormalizedUserNameAsync</summary>
            public Task SetNormalizedUserNameAsync(ApplicationUser user, string normalizedName, CancellationToken cancellationToken)
            {
                user.NormalizedUserName = normalizedName;
                return Task.CompletedTask;
            }

            /// <summary>CreateAsync（使わない）</summary>
            public Task<IdentityResult> CreateAsync(ApplicationUser user, CancellationToken cancellationToken)
            {
                throw new NotSupportedException();
            }

            /// <summary>DeleteAsync（使わない）</summary>
            public Task<IdentityResult> DeleteAsync(ApplicationUser user, CancellationToken cancellationToken)
            {
                throw new NotSupportedException();
            }

            /// <summary>Dispose</summary>
            public void Dispose()
            {
            }

            /// <summary>行の値を写す（スタンプは写さない）</summary>
            /// <param name="from">元</param>
            /// <param name="to">先</param>
            private static void Copy(ApplicationUser from, ApplicationUser to)
            {
                to.UserName = from.UserName;
                to.NormalizedUserName = from.NormalizedUserName;
                to.Email = from.Email;
                to.SecurityStamp = from.SecurityStamp;
            }
        }
    }
}
