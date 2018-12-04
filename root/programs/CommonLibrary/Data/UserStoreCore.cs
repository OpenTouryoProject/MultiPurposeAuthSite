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
//* クラス名        ：UserStoreCore
//* クラス日本語名  ：UserStoreCore（ライブラリ）
//*
//* 作成日時        ：－
//* 作成者          ：－
//* 更新履歴        ：－
//*
//*  日時        更新者            内容
//*  ----------  ----------------  -------------------------------------------------
//*  2018/12/04  西野 大介         新規
//**********************************************************************************

#if NETFX
using MultiPurposeAuthSite.Entity;
#else
using MultiPurposeAuthSite;
#endif

using System;
using System.Collections.Generic;
using System.Collections.Concurrent;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Identity;

// http://mrgchr.hatenablog.com/entry/2016/11/29/000000
// https://blog.nextscape.net/archives/Date/2017/12/aspnetidentity1

/// <summary>MultiPurposeAuthSite.Data</summary>
namespace MultiPurposeAuthSite.Data
{
    /// <summary>
    /// UserStoreCoreでApplicationUserを永続化する。
    /// </summary>
    public class UserStoreCore :
        IUserStore<ApplicationUser>,
        IUserPasswordStore<ApplicationUser>

    {
        #region CRUD(共通)

        #region C (Create)

        /// <summary>CreateAsync</summary>
        /// <param name="user">ApplicationUser</param>
        /// <param name="cancellationToken">CancellationToken</param>
        /// <returns>IdentityResult</returns>
        public Task<IdentityResult> CreateAsync(ApplicationUser user, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();

            CmnStore.Users.Add(user);
            return Task.FromResult(IdentityResult.Success);
        }

        #endregion

        #region R (Read)

        /// <summary>FindByIdAsync</summary>
        /// <param name="userId">string</param>
        /// <param name="cancellationToken">CancellationToken</param>
        /// <returns>ApplicationUser</returns>
        public Task<ApplicationUser> FindByIdAsync(string userId, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();

            return Task.FromResult(CmnStore.Users.FirstOrDefault(a => a.Id.ToString() == userId));
        }

        /// <summary>FindByNameAsync</summary>
        /// <param name="normalizedUserName">string</param>
        /// <param name="cancellationToken">CancellationToken</param>
        /// <returns>ApplicationUser</returns>
        public Task<ApplicationUser> FindByNameAsync(string normalizedUserName, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();

            return Task.FromResult(CmnStore.Users.FirstOrDefault(a => a.NormalizedUserName == normalizedUserName));
        }

        #endregion

        #region U (Update)

        /// <summary>UpdateAsync</summary>
        /// <param name="user">ApplicationUser</param>
        /// <param name="cancellationToken">CancellationToken</param>
        /// <returns>IdentityResult</returns>
        public Task<IdentityResult> UpdateAsync(ApplicationUser user, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();

            int index = CmnStore.Users.FindIndex(a => a.Id == user.Id);
            CmnStore.Users[index] = user;
            return Task.FromResult(IdentityResult.Success);
        }

        #endregion

        #region D (Delete)

        /// <summary>DeleteAsync</summary>
        /// <param name="user">ApplicationUser</param>
        /// <param name="cancellationToken">CancellationToken</param>
        /// <returns>IdentityResult</returns>
        public Task<IdentityResult> DeleteAsync(ApplicationUser user, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();

            int index = CmnStore.Users.FindIndex(a => a.Id == user.Id);
            CmnStore.Users.RemoveAt(index);
            return Task.FromResult(IdentityResult.Success);
        }

        #endregion

        #endregion

        #region プロパティ操作

        /// <summary>GetUserIdAsync</summary>
        /// <param name="user">ApplicationUser</param>
        /// <param name="cancellationToken">CancellationToken</param>
        /// <returns>UserId</returns>
        public Task<string> GetUserIdAsync(ApplicationUser user, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();

            return Task.FromResult(user.Id);
        }

        #region Name

        /// <summary>SetUserNameAsync</summary>
        /// <param name="user">ApplicationUser</param>
        /// <param name="userName">string</param>
        /// <param name="cancellationToken">CancellationToken</param>
        /// <returns>－</returns>
        public Task SetUserNameAsync(ApplicationUser user, string userName, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();

            user.UserName = userName;
            return Task.FromResult(0);
        }

        /// <summary>GetUserNameAsync</summary>
        /// <param name="user">ApplicationUser</param>
        /// <param name="cancellationToken">CancellationToken</param>
        /// <returns>UserName</returns>
        public Task<string> GetUserNameAsync(ApplicationUser user, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();

            return Task.FromResult(user.UserName);
        }

        #endregion

        #region NormalizedName

        /// <summary>SetNormalizedUserNameAsync</summary>
        /// <param name="user"></param>
        /// <param name="normalizedName"></param>
        /// <param name="cancellationToken"></param>
        /// <returns>－</returns>
        public Task SetNormalizedUserNameAsync(ApplicationUser user, string normalizedName, CancellationToken cancellationToken)
        {
            user.NormalizedUserName = normalizedName;
            return Task.FromResult(0);
        }

        /// <summary>GetNormalizedUserNameAsync</summary>
        /// <param name="user"></param>
        /// <param name="cancellationToken"></param>
        /// <returns>NormalizedName</returns>
        public Task<string> GetNormalizedUserNameAsync(ApplicationUser user, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();

            return Task.FromResult(user.NormalizedUserName);
        }

        #endregion

        #endregion

        #region ユーザ属性

        #region IUserPasswordStore

        /// <summary>HasPasswordAsync</summary>
        /// <param name="user">ApplicationUser</param>
        /// <param name="cancellationToken">CancellationToken</param>
        /// <returns>bool</returns>
        public Task<bool> HasPasswordAsync(ApplicationUser user, CancellationToken cancellationToken)
        {
            return Task.FromResult(true);
        }

        /// <summary>SetPasswordHashAsync</summary>
        /// <param name="user">ApplicationUser</param>
        /// <param name="passwordHash">string</param>
        /// <param name="cancellationToken">CancellationToken</param>
        /// <returns>－</returns>
        public Task SetPasswordHashAsync(ApplicationUser user, string passwordHash, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();

            user.PasswordHash = passwordHash;
            return Task.FromResult(0);
        }

        /// <summary>GetPasswordHashAsync</summary>
        /// <param name="user">ApplicationUser</param>
        /// <param name="cancellationToken">CancellationToken</param>
        /// <returns>PasswordHash</returns>
        public Task<string> GetPasswordHashAsync(ApplicationUser user, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();

            return Task.FromResult(user.PasswordHash);
        }

        #endregion

        #endregion


        #region IDisposable
        public void Dispose() { }
        #endregion
    }
}