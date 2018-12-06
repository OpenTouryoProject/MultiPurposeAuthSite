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
//* クラス名        ：RoleStoreCore
//* クラス日本語名  ：RoleStoreCore（ライブラリ）
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
    /// RoleStoreCoreでApplicationRoleを永続化する。
    /// </summary>
    public class RoleStoreCore : IRoleStore<ApplicationRole>
    {
        #region CRUD(共通)

        #region C (Create)

        /// <summary>CreateAsync</summary>
        /// <param name="role">ApplicationRole</param>
        /// <param name="cancellationToken">CancellationToken</param>
        /// <returns></returns>
        public Task<IdentityResult> CreateAsync(ApplicationRole role, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();

            CmnRoleStore.Create(role);
            return Task.FromResult(IdentityResult.Success);
        }

        #endregion

        #region R (Read)

        /// <summary>FindByIdAsync</summary>
        /// <param name="roleId">string</param>
        /// <param name="cancellationToken">CancellationToken</param>
        /// <returns></returns>
        public Task<ApplicationRole> FindByIdAsync(string roleId, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();

            return Task.FromResult(CmnRoleStore.FindById(roleId));
        }

        /// <summary>FindByNameAsync</summary>
        /// <param name="normalizedRoleName">string</param>
        /// <param name="cancellationToken">CancellationToken</param>
        /// <returns></returns>
        public Task<ApplicationRole> FindByNameAsync(string normalizedRoleName, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();

            return Task.FromResult(CmnRoleStore.FindByName(normalizedRoleName));
        }

        #endregion

        #region U (Update)

        /// <summary>UpdateAsync</summary>
        /// <param name="role">ApplicationRole</param>
        /// <param name="cancellationToken">CancellationToken</param>
        /// <returns></returns>
        public Task<IdentityResult> UpdateAsync(ApplicationRole role, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();

            CmnRoleStore.Update(role);
            return Task.FromResult(IdentityResult.Success);
        }

        #endregion

        #region D (Delete)

        /// <summary>DeleteAsync</summary>
        /// <param name="role">ApplicationRole</param>
        /// <param name="cancellationToken">CancellationToken</param>
        /// <returns></returns>
        public Task<IdentityResult> DeleteAsync(ApplicationRole role, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();

            CmnRoleStore.Delete(role);
            return Task.FromResult(IdentityResult.Success);
        }

        #endregion

        #endregion

        #region プロパティ操作

        /// <summary>GetRoleIdAsync</summary>
        /// <param name="role">ApplicationRole</param>
        /// <param name="cancellationToken">CancellationToken</param>
        /// <returns></returns>
        public Task<string> GetRoleIdAsync(ApplicationRole role, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();

            return Task.FromResult(role.Id);
        }

        #region Name

        /// <summary>SetRoleNameAsync</summary>
        /// <param name="role">ApplicationRole</param>
        /// <param name="roleName">string</param>
        /// <param name="cancellationToken">CancellationToken</param>
        /// <returns></returns>
        public Task SetRoleNameAsync(ApplicationRole role, string roleName, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();

            role.Name = roleName;
            return Task.FromResult(0);
        }

        /// <summary>GetRoleNameAsync</summary>
        /// <param name="role">ApplicationRole</param>
        /// <param name="cancellationToken">CancellationToken</param>
        /// <returns></returns>
        public Task<string> GetRoleNameAsync(ApplicationRole role, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();

            return Task.FromResult(role.Name);
        }

        #endregion

        #region NormalizedName

        /// <summary>SetNormalizedRoleNameAsync</summary>
        /// <param name="role">ApplicationRole</param>
        /// <param name="normalizedName">string</param>
        /// <param name="cancellationToken">CancellationToken</param>
        /// <returns></returns>
        public Task SetNormalizedRoleNameAsync(ApplicationRole role, string normalizedName, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();

            role.Name = normalizedName;
            return Task.FromResult(0);
        }

        /// <summary>GetNormalizedRoleNameAsync</summary>
        /// <param name="role">ApplicationRole</param>
        /// <param name="cancellationToken">CancellationToken</param>
        /// <returns></returns>
        public Task<string> GetNormalizedRoleNameAsync(ApplicationRole role, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();

            return Task.FromResult(role.NormalizedName);
        }

        #endregion

        #endregion

        #region IDisposable
        public void Dispose() { }
        #endregion
    }
}