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
using System.Linq;
using System.Collections.Generic;
using System.Security.Claims;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Identity;

// ASP.NET Core MVC にて、Entity Frameworkを使わずにASP.NET Identityを利用する Part.2 - 時が癒す
// http://mrgchr.hatenablog.com/entry/2016/11/29/000000
// ASP.NET Core Identity をテンプレートからカスタマイズ|ネスケラボ
// https://blog.nextscape.net/archives/Date/2017/12/aspnetidentity1

// ASP.NET Core Identity 用のカスタム ストレージ プロバイダー | Microsoft Docs
// https://docs.microsoft.com/ja-jp/aspnet/core/security/authentication/identity-custom-storage-providers?view=aspnetcore-2.2
// at master · aspnet/Identity
// - UserStoreBase.cs
//   https://github.com/aspnet/Identity/blob/master/src/Stores/UserStoreBase.cs
// - EF/UserStore.cs
//   https://github.com/aspnet/Identity/blob/master/src/EF/UserStore.cs#L96

// << 基本 >>
// - 済 IUserStore
// - 済 IQueryableUserStore

// << ユーザ属性 >>
// - 済 IUserPasswordStore
// - 済 IUserEmailStore
// - 済 IUserPhoneNumberStore
// - 済 IUserRoleStore

// << ログイン属性 >>
// - 済 IUserSecurityStampStore
// - 済 IUserLockoutStore
// - 済IUserTwoFactor...
//   - SMS
//     - 済 IUserTwoFactorStore
//     - 済 IUserAuthenticatorKeyStore
//   - TOTP（新）
//     済 IUserAuthenticationTokenStore
//     済 IUserTwoFactorRecoveryCodeStore
// - 済 IUserLoginStore
// - 済 IUserClaimStore

// << その他、UserStore以外 >>
// - IUserValidator
//   UserValidatorが継承。
// - IUserClaimsPrincipalFactory
//   UserClaimsPrincipalFactoryが継承。
// - IUserTwoFactorTokenProvider
//   TotpSecurityStampBasedTokenProviderが継承。

/// <summary>MultiPurposeAuthSite.Data</summary>
namespace MultiPurposeAuthSite.Data
{
    /// <summary>
    /// UserStoreCoreでApplicationUserを永続化する。
    /// </summary>
    public class UserStoreCore :
        IUserStore<ApplicationUser>,
        IQueryableUserStore<ApplicationUser>,
        IUserPasswordStore<ApplicationUser>,
        IUserEmailStore<ApplicationUser>,
        IUserPhoneNumberStore<ApplicationUser>,
        IUserRoleStore<ApplicationUser>,
        IUserSecurityStampStore<ApplicationUser>,
        IUserLockoutStore<ApplicationUser>,
        IUserTwoFactorStore<ApplicationUser>,
        IUserAuthenticatorKeyStore<ApplicationUser>,
        IUserAuthenticationTokenStore<ApplicationUser>,
        IUserTwoFactorRecoveryCodeStore<ApplicationUser>,
        IUserLoginStore<ApplicationUser>,
        IUserClaimStore<ApplicationUser>
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
            this.ThrowIfDisposed();

            CmnUserStore.Create(user);
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
            this.ThrowIfDisposed();

            return Task.FromResult(CmnUserStore.FindById(userId));
        }

        /// <summary>FindByNameAsync</summary>
        /// <param name="normalizedUserName">string</param>
        /// <param name="cancellationToken">CancellationToken</param>
        /// <returns>ApplicationUser</returns>
        public Task<ApplicationUser> FindByNameAsync(string normalizedUserName, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            this.ThrowIfDisposed();

            return Task.FromResult(CmnUserStore.FindByName(normalizedUserName)); // UserName or NormalizedUserName ?
        }

        /// <summary>Users</summary>
        public IQueryable<ApplicationUser> Users
        {
            get { return CmnUserStore.Users; }
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
            this.ThrowIfDisposed();

            CmnUserStore.Update(user);
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
            this.ThrowIfDisposed();

            CmnUserStore.Delete(user);
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
            this.ThrowIfDisposed();

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
            this.ThrowIfDisposed();

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
            this.ThrowIfDisposed();

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
            cancellationToken.ThrowIfCancellationRequested();
            this.ThrowIfDisposed();

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
            this.ThrowIfDisposed();

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
            cancellationToken.ThrowIfCancellationRequested();
            this.ThrowIfDisposed();

            return Task.FromResult(CmnUserStore.HasPassword(user));
        }

        /// <summary>SetPasswordHashAsync</summary>
        /// <param name="user">ApplicationUser</param>
        /// <param name="passwordHash">string</param>
        /// <param name="cancellationToken">CancellationToken</param>
        /// <returns>－</returns>
        public Task SetPasswordHashAsync(ApplicationUser user, string passwordHash, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            this.ThrowIfDisposed();

            CmnUserStore.SetPasswordHash(user, passwordHash);
            return Task.FromResult(0);
        }

        /// <summary>GetPasswordHashAsync</summary>
        /// <param name="user">ApplicationUser</param>
        /// <param name="cancellationToken">CancellationToken</param>
        /// <returns>PasswordHash</returns>
        public Task<string> GetPasswordHashAsync(ApplicationUser user, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            this.ThrowIfDisposed();

            return Task.FromResult(CmnUserStore.GetPasswordHash(user));
        }

        #endregion

        #region IUserEmailStore

        /// <summary>FindByEmailAsync</summary>
        /// <param name="normalizedEmail">string</param>
        /// <param name="cancellationToken">CancellationToken</param>
        /// <returns>ApplicationUser</returns>
        public Task<ApplicationUser> FindByEmailAsync(string normalizedEmail, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            this.ThrowIfDisposed();

            return Task.FromResult(CmnUserStore.FindByEmail(normalizedEmail));
        }

        /// <summary>SetEmailAsync</summary>
        /// <param name="user">ApplicationUser</param>
        /// <param name="email">email</param>
        /// <param name="cancellationToken">CancellationToken</param>
        /// <returns>－</returns>
        public Task SetEmailAsync(ApplicationUser user, string email, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            this.ThrowIfDisposed();

            CmnUserStore.SetEmail(user, email);
            return Task.FromResult(0);
        }

        /// <summary>GetEmailAsync</summary>
        /// <param name="user">ApplicationUser</param>
        /// <param name="cancellationToken">CancellationToken</param>
        /// <returns>Email</returns>
        public Task<string> GetEmailAsync(ApplicationUser user, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            this.ThrowIfDisposed();

            return Task.FromResult(CmnUserStore.GetEmail(user));
        }

        /// <summary>SetEmailConfirmedAsync</summary>
        /// <param name="user">ApplicationUser</param>
        /// <param name="confirmed">bool</param>
        /// <param name="cancellationToken">CancellationToken</param>
        /// <returns>－</returns>
        public Task SetEmailConfirmedAsync(ApplicationUser user, bool confirmed, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            this.ThrowIfDisposed();

            CmnUserStore.SetEmailConfirmed(user, confirmed);
            return Task.FromResult(0);
        }

        /// <summary>GetEmailConfirmedAsync</summary>
        /// <param name="user">ApplicationUser</param>
        /// <param name="cancellationToken">CancellationToken</param>
        /// <returns>EmailConfirmed</returns>
        public Task<bool> GetEmailConfirmedAsync(ApplicationUser user, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            this.ThrowIfDisposed();

            return Task.FromResult(CmnUserStore.GetEmailConfirmed(user));
        }

        /// <summary>SetNormalizedEmailAsync</summary>
        /// <param name="user">ApplicationUser</param>
        /// <param name="normalizedEmail">string</param>
        /// <param name="cancellationToken">CancellationToken</param>
        /// <returns>－</returns>
        public Task SetNormalizedEmailAsync(ApplicationUser user, string normalizedEmail, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            this.ThrowIfDisposed();

            CmnUserStore.SetNormalizedEmail(user, normalizedEmail);
            return Task.FromResult(0);
        }

        /// <summary>GetNormalizedEmailAsync</summary>
        /// <param name="user">ApplicationUser</param>
        /// <param name="cancellationToken">CancellationToken</param>
        /// <returns>NormalizedEmail</returns>
        public Task<string> GetNormalizedEmailAsync(ApplicationUser user, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            this.ThrowIfDisposed();

            return Task.FromResult(CmnUserStore.GetNormalizedEmail(user));
        }

        #endregion

        #region IUserPhoneNumberStore

        /// <summary>SetPhoneNumberAsync</summary>
        /// <param name="user">ApplicationUser</param>
        /// <param name="phoneNumber">string</param>
        /// <param name="cancellationToken">CancellationToken</param>
        /// <returns>－</returns>
        public Task SetPhoneNumberAsync(ApplicationUser user, string phoneNumber, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            this.ThrowIfDisposed();

            CmnUserStore.SetPhoneNumber(user, phoneNumber);
            return Task.FromResult(0);
        }

        /// <summary>GetPhoneNumberAsync</summary>
        /// <param name="user">ApplicationUser</param>
        /// <param name="cancellationToken">CancellationToken</param>
        /// <returns>PhoneNumber</returns>
        public Task<string> GetPhoneNumberAsync(ApplicationUser user, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            this.ThrowIfDisposed();

            return Task.FromResult(CmnUserStore.GetPhoneNumber(user));
        }

        /// <summary>SetPhoneNumberConfirmedAsync</summary>
        /// <param name="user">ApplicationUser</param>
        /// <param name="confirmed">bool</param>
        /// <param name="cancellationToken">CancellationToken</param>
        /// <returns>－</returns>
        public Task SetPhoneNumberConfirmedAsync(ApplicationUser user, bool confirmed, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            this.ThrowIfDisposed();

            CmnUserStore.SetPhoneNumberConfirmed(user, confirmed);
            return Task.FromResult(0);
        }

        /// <summary>GetPhoneNumberConfirmedAsync</summary>
        /// <param name="user">ApplicationUser</param>
        /// <param name="cancellationToken">CancellationToken</param>
        /// <returns>PhoneNumberConfirmed</returns>
        public Task<bool> GetPhoneNumberConfirmedAsync(ApplicationUser user, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            this.ThrowIfDisposed();

            return Task.FromResult(CmnUserStore.GetPhoneNumberConfirmed(user));
        }

        #endregion

        #region IUserRoleStore

        /// <summary>AddToRoleAsync</summary>
        /// <param name="user">ApplicationUser</param>
        /// <param name="roleName">string</param>
        /// <param name="cancellationToken">CancellationToken</param>
        /// <returns>－</returns>
        public Task AddToRoleAsync(ApplicationUser user, string roleName, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            this.ThrowIfDisposed();

            CmnUserStore.AddToRole(user, roleName);
            return Task.FromResult(0);
        }

        /// <summary>IsInRoleAsync</summary>
        /// <param name="user">ApplicationUser</param>
        /// <param name="roleName">string</param>
        /// <param name="cancellationToken">CancellationToken</param>
        /// <returns>bool</returns>
        public Task<bool> IsInRoleAsync(ApplicationUser user, string roleName, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            this.ThrowIfDisposed();

            return Task.FromResult(CmnUserStore.IsInRole(user, roleName));
        }

        /// <summary>GetUsersInRoleAsync</summary>
        /// <param name="roleName">string</param>
        /// <param name="cancellationToken">CancellationToken</param>
        /// <returns>IList(ApplicationUser)</returns>
        public Task<IList<ApplicationUser>> GetUsersInRoleAsync(string roleName, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            this.ThrowIfDisposed();

            throw new NotImplementedException();
        }

        /// <summary>GetRolesAsync</summary>
        /// <param name="user">ApplicationUser</param>
        /// <param name="cancellationToken">CancellationToken</param>
        /// <returns>RoleNames</returns>
        public Task<IList<string>> GetRolesAsync(ApplicationUser user, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            this.ThrowIfDisposed();

            return Task.FromResult(CmnUserStore.GetRoles(user));
        }

        /// <summary>RemoveFromRoleAsync</summary>
        /// <param name="user">ApplicationUser</param>
        /// <param name="roleName">string</param>
        /// <param name="cancellationToken">CancellationToken</param>
        /// <returns>－</returns>
        public Task RemoveFromRoleAsync(ApplicationUser user, string roleName, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            this.ThrowIfDisposed();

            CmnUserStore.RemoveFromRole(user, roleName);
            return Task.FromResult(0);
        }

        #endregion

        #endregion

        #region ログイン属性

        #region IUserSecurityStampStore

        /// <summary>SetSecurityStampAsync</summary>
        /// <param name="user">ApplicationUser</param>
        /// <param name="stamp">string</param>
        /// <param name="cancellationToken">CancellationToken</param>
        /// <returns>－</returns>
        public Task SetSecurityStampAsync(ApplicationUser user, string stamp, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            this.ThrowIfDisposed();

            CmnUserStore.SetSecurityStamp(user, stamp);
            return Task.FromResult(0);
        }

        /// <summary>GetSecurityStampAsync</summary>
        /// <param name="user">ApplicationUser</param>
        /// <param name="cancellationToken">CancellationToken</param>
        /// <returns>SecurityStamp</returns>
        public Task<string> GetSecurityStampAsync(ApplicationUser user, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            this.ThrowIfDisposed();

            return Task.FromResult(CmnUserStore.GetSecurityStamp(user));
        }

        #endregion

        #region IUserLockoutStore

        /// <summary>SetLockoutEnabledAsync</summary>
        /// <param name="user">ApplicationUser</param>
        /// <param name="enabled">bool</param>
        /// <param name="cancellationToken">CancellationToken</param>
        /// <returns>－</returns>
        public Task SetLockoutEnabledAsync(ApplicationUser user, bool enabled, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            this.ThrowIfDisposed();

            CmnUserStore.SetLockoutEnabled(user, enabled);
            return Task.FromResult(0);
        }

        /// <summary>GetLockoutEnabledAsync</summary>
        /// <param name="user">ApplicationUser</param>
        /// <param name="cancellationToken">CancellationToken</param>
        /// <returns>LockoutEnabled</returns>
        public Task<bool> GetLockoutEnabledAsync(ApplicationUser user, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            this.ThrowIfDisposed();

            return Task.FromResult(CmnUserStore.GetLockoutEnabled(user));
        }

        /// <summary>IncrementAccessFailedCountAsync</summary>
        /// <param name="user">ApplicationUser</param>
        /// <param name="cancellationToken">CancellationToken</param>
        /// <returns>FailedCount</returns>
        public Task<int> IncrementAccessFailedCountAsync(ApplicationUser user, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            this.ThrowIfDisposed();

            return Task.FromResult(CmnUserStore.IncrementAccessFailedCount(user));
        }

        /// <summary>GetAccessFailedCountAsync</summary>
        /// <param name="user">ApplicationUser</param>
        /// <param name="cancellationToken">CancellationToken</param>
        /// <returns>FailedCount</returns>
        public Task<int> GetAccessFailedCountAsync(ApplicationUser user, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();

            return Task.FromResult(CmnUserStore.GetAccessFailedCount(user));
        }

        /// <summary>ResetAccessFailedCountAsync</summary>
        /// <param name="user">ApplicationUser</param>
        /// <param name="cancellationToken"></param>
        /// <returns>－</returns>
        public Task ResetAccessFailedCountAsync(ApplicationUser user, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            this.ThrowIfDisposed();

            CmnUserStore.ResetAccessFailedCount(user);
            return Task.FromResult(0);
        }

        /// <summary>SetLockoutEndDateAsync</summary>
        /// <param name="user">ApplicationUser</param>
        /// <param name="lockoutEnd">DateTimeOffset?</param>
        /// <param name="cancellationToken">CancellationToken</param>
        /// <returns></returns>
        public Task SetLockoutEndDateAsync(ApplicationUser user, DateTimeOffset? lockoutEnd, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            this.ThrowIfDisposed();

            CmnUserStore.SetLockoutEndDate(user, lockoutEnd);
            return Task.FromResult(0);
        }

        /// <summary>GetLockoutEndDateAsync</summary>
        /// <param name="user">ApplicationUser</param>
        /// <param name="cancellationToken">CancellationToken</param>
        /// <returns>LockoutEndDate</returns>
        public Task<DateTimeOffset?> GetLockoutEndDateAsync(ApplicationUser user, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            this.ThrowIfDisposed();

            return Task.FromResult(CmnUserStore.GetLockoutEndDate(user));
        }

        #endregion

        #region IUserTwoFactor...

        #region SMS

        #region IUserTwoFactorStore

        /// <summary>SetTwoFactorEnabledAsync</summary>
        /// <param name="user">ApplicationUser</param>
        /// <param name="enabled">bool</param>
        /// <param name="cancellationToken">CancellationToken</param>
        /// <returns>－</returns>
        public Task SetTwoFactorEnabledAsync(ApplicationUser user, bool enabled, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            this.ThrowIfDisposed();

            CmnUserStore.SetTwoFactorEnabled(user, enabled);
            return Task.FromResult(0);
        }

        /// <summary>GetTwoFactorEnabledAsync</summary>
        /// <param name="user">ApplicationUser</param>
        /// <param name="cancellationToken">CancellationToken</param>
        /// <returns>bool</returns>
        public Task<bool> GetTwoFactorEnabledAsync(ApplicationUser user, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            this.ThrowIfDisposed();

            return Task.FromResult(CmnUserStore.GetTwoFactorEnabled(user));
        }

        #endregion

        #region UserAuthenticatorKeyStore

        /// <summary>SetAuthenticatorKeyAsync</summary>
        /// <param name="user">ApplicationUser</param>
        /// <param name="key">string</param>
        /// <param name="cancellationToken">CancellationToken</param>
        /// <returns>－</returns>
        public Task SetAuthenticatorKeyAsync(ApplicationUser user, string key, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            this.ThrowIfDisposed();

            CmnUserStore.SetAuthenticatorKey(user, key);
            return Task.FromResult(0);
        }

        /// <summary>GetAuthenticatorKeyAsync</summary>
        /// <param name="user">ApplicationUser</param>
        /// <param name="cancellationToken">CancellationToken</param>
        /// <returns>key string</returns>
        public Task<string> GetAuthenticatorKeyAsync(ApplicationUser user, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            this.ThrowIfDisposed();

            return Task.FromResult(CmnUserStore.GetAuthenticatorKey(user));
        }

        #endregion

        #endregion

        #region TOTP

        #region IUserAuthenticationTokenStore

        /// <summary>SetTokenAsync</summary>
        /// <param name="user">ApplicationUser</param>
        /// <param name="loginProvider">string</param>
        /// <param name="name">string</param>
        /// <param name="value">string</param>
        /// <param name="cancellationToken">CancellationToken</param>
        /// <returns>－</returns>
        public Task SetTokenAsync(ApplicationUser user, string loginProvider, string name, string value, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            ThrowIfDisposed();

            CmnUserStore.SetToken(user, loginProvider, name, value);
            return Task.FromResult(0);
        }

        /// <summary>GetTokenAsync</summary>
        /// <param name="user">ApplicationUser</param>
        /// <param name="loginProvider">string</param>
        /// <param name="name">string</param>
        /// <param name="cancellationToken">CancellationToken</param>
        /// <returns>－</returns>
        public Task<string> GetTokenAsync(ApplicationUser user, string loginProvider, string name, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            ThrowIfDisposed();

            string token = CmnUserStore.GetToken(user, loginProvider, name);
            return Task.FromResult(token);
        }

        /// <summary>RemoveTokenAsync</summary>
        /// <param name="user">ApplicationUser</param>
        /// <param name="loginProvider">string</param>
        /// <param name="name">string</param>
        /// <param name="cancellationToken">CancellationToken</param>
        /// <returns>－</returns>
        public Task RemoveTokenAsync(ApplicationUser user, string loginProvider, string name, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            ThrowIfDisposed();

            CmnUserStore.RemoveToken(user, loginProvider, name);
            return Task.FromResult(0);
        }

        #endregion

        #region IUserTwoFactorRecoveryCodeStore

        /// <summary>CountCodesAsync</summary>
        /// <param name="user">ApplicationUser</param>
        /// <param name="cancellationToken">CancellationToken</param>
        /// <returns>int</returns>
        public Task<int> CountCodesAsync(ApplicationUser user, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            this.ThrowIfDisposed();

            return Task.FromResult(CmnUserStore.CountCodes(user));
        }

        /// <summary>ReplaceCodesAsync</summary>
        /// <param name="user">ApplicationUser</param>
        /// <param name="recoveryCodes">IEnumerable(string)</param>
        /// <param name="cancellationToken">CancellationToken</param>
        /// <returns>The new recovery codes for the user.</returns>
        public Task ReplaceCodesAsync(ApplicationUser user, IEnumerable<string> recoveryCodes, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            this.ThrowIfDisposed();

            CmnUserStore.ReplaceCodes(user, recoveryCodes);
            return Task.FromResult(0);
        }

        /// <summary>RedeemCodeAsync</summary>
        /// <param name="user">ApplicationUser</param>
        /// <param name="code">string</param>
        /// <param name="cancellationToken">CancellationToken</param>
        /// <returns>bool</returns>
        public Task<bool> RedeemCodeAsync(ApplicationUser user, string code, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            this.ThrowIfDisposed();

            return Task.FromResult(CmnUserStore.RedeemCode(user, code));
        }

        #endregion

        #endregion

        #endregion

        #endregion

        #region Collection (Logins, Claims)

        #region IUserLoginStore

        /// <summary>AddLoginAsync</summary>
        /// <param name="user">ApplicationUser</param>
        /// <param name="login">UserLoginInfo</param>
        /// <param name="cancellationToken">CancellationToken</param>
        /// <returns>－</returns>
        public Task AddLoginAsync(ApplicationUser user, UserLoginInfo login, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            this.ThrowIfDisposed();

            CmnUserStore.AddLogin(user, login);
            return Task.FromResult(0);
        }

        /// <summary>FindByLoginAsync</summary>
        /// <param name="loginProvider">string</param>
        /// <param name="providerKey">string</param>
        /// <param name="cancellationToken">CancellationToken</param>
        /// <returns></returns>
        public Task<ApplicationUser> FindByLoginAsync(string loginProvider, string providerKey, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            this.ThrowIfDisposed();

            return Task.FromResult(CmnUserStore.Find(new UserLoginInfo(loginProvider, providerKey, "")));
        }

        /// <summary>GetLoginsAsync</summary>
        /// <param name="user">ApplicationUser</param>
        /// <param name="cancellationToken">CancellationToken</param>
        /// <returns>IList(UserLoginInfo)</returns>
        public Task<IList<UserLoginInfo>> GetLoginsAsync(ApplicationUser user, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();

            return Task.FromResult(CmnUserStore.GetLogins(user));
        }

        /// <summary>RemoveLoginAsync</summary>
        /// <param name="user">ApplicationUser</param>
        /// <param name="loginProvider">string</param>
        /// <param name="providerKey">string</param>
        /// <param name="cancellationToken">CancellationToken</param>
        /// <returns>－</returns>
        public Task RemoveLoginAsync(ApplicationUser user, string loginProvider, string providerKey, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            this.ThrowIfDisposed();

            CmnUserStore.RemoveLogin(user, new UserLoginInfo(loginProvider, providerKey, ""));
            return Task.FromResult(0);
        }

        #endregion

        #region IUserClaimStore

        /// <summary></summary>
        /// <param name="user">ApplicationUser</param>
        /// <param name="claims"></param>
        /// <param name="cancellationToken">CancellationToken</param>
        /// <returns>－</returns>
        public Task AddClaimsAsync(ApplicationUser user, IEnumerable<Claim> claims, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            this.ThrowIfDisposed();

            foreach (Claim claim in claims)
            {
                CmnUserStore.AddClaim(user, claim);
            }
            return Task.FromResult(0);
        }

        /// <summary>GetClaimsAsync</summary>
        /// <param name="user">ApplicationUser</param>
        /// <param name="cancellationToken">CancellationToken</param>
        /// <returns>Claims</returns>
        public Task<IList<Claim>> GetClaimsAsync(ApplicationUser user, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            this.ThrowIfDisposed();

            return Task.FromResult(CmnUserStore.GetClaims(user));
        }

        /// <summary>GetUsersForClaimAsync</summary>
        /// <param name="claim">Claim</param>
        /// <param name="cancellationToken">CancellationToken</param>
        /// <returns>Users</returns>
        public Task<IList<ApplicationUser>> GetUsersForClaimAsync(Claim claim, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();

            throw new NotImplementedException();
        }

        /// <summary>ReplaceClaimAsync</summary>
        /// <param name="user">ApplicationUser</param>
        /// <param name="claim">Claim</param>
        /// <param name="newClaim">Claim</param>
        /// <param name="cancellationToken">CancellationToken</param>
        /// <returns>－</returns>
        public Task ReplaceClaimAsync(ApplicationUser user, Claim claim, Claim newClaim, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            this.ThrowIfDisposed();

            throw new NotImplementedException();
        }

        /// <summary>RemoveClaimsAsync</summary>
        /// <param name="user">ApplicationUser</param>
        /// <param name="claims">IEnumerable(Claim)</param>
        /// <param name="cancellationToken">CancellationToken</param>
        /// <returns>－</returns>
        public Task RemoveClaimsAsync(ApplicationUser user, IEnumerable<Claim> claims, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            this.ThrowIfDisposed();

            foreach (Claim claim in claims)
            {
                CmnUserStore.RemoveClaim(user, claim);
            }
            return Task.FromResult(0);
        }

        #endregion

        #endregion

        #region IDisposable

        /// <summary>_disposed</summary>
        private bool _disposed;

        /// <summary>Dispose the store</summary>
        public void Dispose()
        {
            this._disposed = true;
        }

        /// <summary>Throws if this class has been disposed.</summary>
        protected void ThrowIfDisposed()
        {
            if (this._disposed)
            {
                throw new ObjectDisposedException(GetType().Name);
            }
        }
        
        #endregion
    }
}