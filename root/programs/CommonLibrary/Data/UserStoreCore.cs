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

// <<ユーザ属性>>
// 済 IUserPasswordStore
// 済 IUserEmailStore
// 済 IUserPhoneNumberStore
// 済 IUserRoleStore

// <<ログイン属性>>
// 済 IUserSecurityStampStore
// 済 IUserLockoutStore
// IUserTwoFactor...
// - IUserTwoFactorStore
// - IUserTwoFactorTokenProvider
// - IUserTwoFactorRecoveryCodeStore
// 済 IUserLoginStore
// 済 IUserClaimStore

// <<その他、追加>>
// IUserValidator
// IQueryableUserStore
// IUserAuthenticationTokenStore
// IUserAuthenticatorKeyStore
// IUserClaimsPrincipalFactory

/// <summary>MultiPurposeAuthSite.Data</summary>
namespace MultiPurposeAuthSite.Data
{
    /// <summary>
    /// UserStoreCoreでApplicationUserを永続化する。
    /// </summary>
    public class UserStoreCore :
        IUserStore<ApplicationUser>,
        IUserPasswordStore<ApplicationUser>,
        IUserEmailStore<ApplicationUser>,
        IUserPhoneNumberStore<ApplicationUser>,
        IUserRoleStore<ApplicationUser>,
        IUserSecurityStampStore<ApplicationUser>,
        //IUserTwoFactor...,
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

            return Task.FromResult(CmnUserStore.FindByIdAsync(userId));
        }

        /// <summary>FindByNameAsync</summary>
        /// <param name="normalizedUserName">string</param>
        /// <param name="cancellationToken">CancellationToken</param>
        /// <returns>ApplicationUser</returns>
        public Task<ApplicationUser> FindByNameAsync(string normalizedUserName, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();

            return Task.FromResult(CmnUserStore.FindByNameAsync(normalizedUserName)); // UserName or NormalizedUserName ?
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

            CmnUserStore.UpdateAsync(user);
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

            CmnUserStore.DeleteAsync(user);
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
            return Task.FromResult(CmnUserStore.HasPasswordAsync(user));
        }

        /// <summary>SetPasswordHashAsync</summary>
        /// <param name="user">ApplicationUser</param>
        /// <param name="passwordHash">string</param>
        /// <param name="cancellationToken">CancellationToken</param>
        /// <returns>－</returns>
        public Task SetPasswordHashAsync(ApplicationUser user, string passwordHash, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();

            CmnUserStore.SetPasswordHashAsync(user, passwordHash);
            return Task.FromResult(0);
        }

        /// <summary>GetPasswordHashAsync</summary>
        /// <param name="user">ApplicationUser</param>
        /// <param name="cancellationToken">CancellationToken</param>
        /// <returns>PasswordHash</returns>
        public Task<string> GetPasswordHashAsync(ApplicationUser user, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();

            return Task.FromResult(CmnUserStore.GetPasswordHashAsync(user));
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

            return Task.FromResult(CmnUserStore.FindByEmailAsync(normalizedEmail));
        }

        /// <summary>SetEmailAsync</summary>
        /// <param name="user">ApplicationUser</param>
        /// <param name="email">email</param>
        /// <param name="cancellationToken">CancellationToken</param>
        /// <returns>－</returns>
        public Task SetEmailAsync(ApplicationUser user, string email, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();

            CmnUserStore.SetEmailAsync(user, email);
            return Task.FromResult(0);
        }

        /// <summary>GetEmailAsync</summary>
        /// <param name="user">ApplicationUser</param>
        /// <param name="cancellationToken">CancellationToken</param>
        /// <returns>Email</returns>
        public Task<string> GetEmailAsync(ApplicationUser user, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();

            return Task.FromResult(CmnUserStore.GetEmailAsync(user));
        }

        /// <summary>SetEmailConfirmedAsync</summary>
        /// <param name="user">ApplicationUser</param>
        /// <param name="confirmed">bool</param>
        /// <param name="cancellationToken">CancellationToken</param>
        /// <returns>－</returns>
        public Task SetEmailConfirmedAsync(ApplicationUser user, bool confirmed, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();

            CmnUserStore.SetEmailConfirmedAsync(user, confirmed);
            return Task.FromResult(0);
        }

        /// <summary>GetEmailConfirmedAsync</summary>
        /// <param name="user">ApplicationUser</param>
        /// <param name="cancellationToken">CancellationToken</param>
        /// <returns>EmailConfirmed</returns>
        public Task<bool> GetEmailConfirmedAsync(ApplicationUser user, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();

            return Task.FromResult(CmnUserStore.GetEmailConfirmedAsync(user));
        }

        /// <summary>SetNormalizedEmailAsync</summary>
        /// <param name="user">ApplicationUser</param>
        /// <param name="normalizedEmail">string</param>
        /// <param name="cancellationToken">CancellationToken</param>
        /// <returns>－</returns>
        public Task SetNormalizedEmailAsync(ApplicationUser user, string normalizedEmail, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();

            CmnUserStore.SetNormalizedEmailAsync(user, normalizedEmail);
            return Task.FromResult(0);
        }

        /// <summary>GetNormalizedEmailAsync</summary>
        /// <param name="user">ApplicationUser</param>
        /// <param name="cancellationToken">CancellationToken</param>
        /// <returns>NormalizedEmail</returns>
        public Task<string> GetNormalizedEmailAsync(ApplicationUser user, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();

            return Task.FromResult(CmnUserStore.GetNormalizedEmailAsync(user));
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

            CmnUserStore.SetPhoneNumberAsync(user, phoneNumber);
            return Task.FromResult(0);
        }

        /// <summary>GetPhoneNumberAsync</summary>
        /// <param name="user">ApplicationUser</param>
        /// <param name="cancellationToken">CancellationToken</param>
        /// <returns>PhoneNumber</returns>
        public Task<string> GetPhoneNumberAsync(ApplicationUser user, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();

            return Task.FromResult(CmnUserStore.GetPhoneNumberAsync(user));
        }

        /// <summary>SetPhoneNumberConfirmedAsync</summary>
        /// <param name="user">ApplicationUser</param>
        /// <param name="confirmed">bool</param>
        /// <param name="cancellationToken">CancellationToken</param>
        /// <returns>－</returns>
        public Task SetPhoneNumberConfirmedAsync(ApplicationUser user, bool confirmed, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();

            CmnUserStore.SetPhoneNumberConfirmedAsync(user, confirmed);
            return Task.FromResult(0);
        }

        /// <summary>GetPhoneNumberConfirmedAsync</summary>
        /// <param name="user">ApplicationUser</param>
        /// <param name="cancellationToken">CancellationToken</param>
        /// <returns>PhoneNumberConfirmed</returns>
        public Task<bool> GetPhoneNumberConfirmedAsync(ApplicationUser user, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();

            return Task.FromResult(CmnUserStore.GetPhoneNumberConfirmedAsync(user));
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

            CmnUserStore.AddToRoleAsync(user, roleName);
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

            return Task.FromResult(CmnUserStore.IsInRoleAsync(user, roleName));
        }

        /// <summary>GetUsersInRoleAsync</summary>
        /// <param name="roleName">string</param>
        /// <param name="cancellationToken">CancellationToken</param>
        /// <returns>IList(ApplicationUser)</returns>
        public Task<IList<ApplicationUser>> GetUsersInRoleAsync(string roleName, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();

            throw new NotImplementedException();
        }

        /// <summary>GetRolesAsync</summary>
        /// <param name="user">ApplicationUser</param>
        /// <param name="cancellationToken">CancellationToken</param>
        /// <returns>RoleNames</returns>
        public Task<IList<string>> GetRolesAsync(ApplicationUser user, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();

            return Task.FromResult(CmnUserStore.GetRolesAsync(user));
        }

        /// <summary>RemoveFromRoleAsync</summary>
        /// <param name="user">ApplicationUser</param>
        /// <param name="roleName">string</param>
        /// <param name="cancellationToken">CancellationToken</param>
        /// <returns>－</returns>
        public Task RemoveFromRoleAsync(ApplicationUser user, string roleName, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();

            CmnUserStore.RemoveFromRoleAsync(user, roleName);
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

            CmnUserStore.SetSecurityStampAsync(user, stamp);
            return Task.FromResult(0);
        }

        /// <summary>GetSecurityStampAsync</summary>
        /// <param name="user">ApplicationUser</param>
        /// <param name="cancellationToken">CancellationToken</param>
        /// <returns>SecurityStamp</returns>
        public Task<string> GetSecurityStampAsync(ApplicationUser user, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();

            return Task.FromResult(CmnUserStore.GetSecurityStampAsync(user));
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

            CmnUserStore.SetLockoutEnabledAsync(user, enabled);
            return Task.FromResult(0);
        }

        /// <summary>GetLockoutEnabledAsync</summary>
        /// <param name="user">ApplicationUser</param>
        /// <param name="cancellationToken">CancellationToken</param>
        /// <returns>LockoutEnabled</returns>
        public Task<bool> GetLockoutEnabledAsync(ApplicationUser user, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();

            return Task.FromResult(CmnUserStore.GetLockoutEnabledAsync(user));
        }
                
        /// <summary>IncrementAccessFailedCountAsync</summary>
        /// <param name="user">ApplicationUser</param>
        /// <param name="cancellationToken">CancellationToken</param>
        /// <returns>FailedCount</returns>
        public Task<int> IncrementAccessFailedCountAsync(ApplicationUser user, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();

            return Task.FromResult(CmnUserStore.IncrementAccessFailedCountAsync(user));
        }

        /// <summary>GetAccessFailedCountAsync</summary>
        /// <param name="user">ApplicationUser</param>
        /// <param name="cancellationToken">CancellationToken</param>
        /// <returns>FailedCount</returns>
        public Task<int> GetAccessFailedCountAsync(ApplicationUser user, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();

            return Task.FromResult(CmnUserStore.GetAccessFailedCountAsync(user));
        }

        /// <summary>ResetAccessFailedCountAsync</summary>
        /// <param name="user">ApplicationUser</param>
        /// <param name="cancellationToken"></param>
        /// <returns>－</returns>
        public Task ResetAccessFailedCountAsync(ApplicationUser user, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();

            CmnUserStore.ResetAccessFailedCountAsync(user);
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

            CmnUserStore.SetLockoutEndDateAsync(user, lockoutEnd);
            return Task.FromResult(0);
        }

        /// <summary>GetLockoutEndDateAsync</summary>
        /// <param name="user">ApplicationUser</param>
        /// <param name="cancellationToken">CancellationToken</param>
        /// <returns>LockoutEndDate</returns>
        public Task<DateTimeOffset?> GetLockoutEndDateAsync(ApplicationUser user, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();

            return Task.FromResult(CmnUserStore.GetLockoutEndDateAsync(user));
        }

        #endregion

        #region IUserTwoFactor（大幅強化）

        #region IUserTwoFactorStore
        #endregion

        #region IUserTwoFactorTokenProvider
        #endregion

        #region IUserTwoFactorRecoveryCodeStore
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

            CmnUserStore.AddLoginAsync(user, login);
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

            return Task.FromResult(CmnUserStore.FindAsync(new UserLoginInfo(loginProvider, providerKey, "")));
        }

        /// <summary>GetLoginsAsync</summary>
        /// <param name="user">ApplicationUser</param>
        /// <param name="cancellationToken">CancellationToken</param>
        /// <returns>IList(UserLoginInfo)</returns>
        public Task<IList<UserLoginInfo>> GetLoginsAsync(ApplicationUser user, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();

            return Task.FromResult(CmnUserStore.GetLoginsAsync(user));
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

            CmnUserStore.RemoveLoginAsync(user, new UserLoginInfo(loginProvider, providerKey, ""));
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

            foreach (Claim claim in claims)
            {
                CmnUserStore.AddClaimAsync(user, claim);
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

            return Task.FromResult(CmnUserStore.GetClaimsAsync(user));
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

            foreach (Claim claim in claims)
            {
                CmnUserStore.RemoveClaimAsync(user, claim);
            }
            return Task.FromResult(0);
        }

        #endregion

        #endregion

        #region IDisposable
        public void Dispose() { }
        #endregion
    }
}