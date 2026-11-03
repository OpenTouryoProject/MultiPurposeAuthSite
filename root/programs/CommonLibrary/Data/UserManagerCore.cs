//**********************************************************************************
//* クラス名        ：UserManagerCore
//* クラス日本語名  ：UserManager（net10.0 版。楽観排他の競合をやり直す）
//*
//* 作成日時        ：－
//* 作成者          ：－
//* 更新履歴        ：－
//*
//*  日時        更新者            内容
//*  ----------  ----------------  -------------------------------------------------
//*  2026/11/02  玄人 幸道         新規（#316）
//*  2026/11/03  玄人 幸道         変更を当て直してやり直す UpdateWithRetryAsync を足した（#331）
//**********************************************************************************

using System;
using System.Collections.Generic;
using System.Threading.Tasks;

using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

/// <summary>MultiPurposeAuthSite.Data</summary>
namespace MultiPurposeAuthSite.Data
{
    /// <summary>
    /// UserManager（net10.0 版）。
    /// **数えやスタンプの更新は、競合したら読み直してやり直す**（#316）。
    /// net48 版は `ApplicationUserManager` が同じことをする。
    /// </summary>
    public class UserManagerCore : UserManager<ApplicationUser>
    {
        /// <summary>constructor</summary>
        public UserManagerCore(
            IUserStore<ApplicationUser> store,
            IOptions<IdentityOptions> optionsAccessor,
            IPasswordHasher<ApplicationUser> passwordHasher,
            IEnumerable<IUserValidator<ApplicationUser>> userValidators,
            IEnumerable<IPasswordValidator<ApplicationUser>> passwordValidators,
            ILookupNormalizer keyNormalizer,
            IdentityErrorDescriber errors,
            IServiceProvider services,
            ILogger<UserManager<ApplicationUser>> logger)
            : base(store, optionsAccessor, passwordHasher, userValidators,
                  passwordValidators, keyNormalizer, errors, services, logger)
        {
        }

        /// <summary>AccessFailedAsync</summary>
        /// <param name="user">ApplicationUser</param>
        /// <returns>IdentityResult</returns>
        /// <remarks>**競合で数えが消えると、ロックアウトに届きにくくなる**（`ANALYSIS-IdP.md` の E-14）。</remarks>
        public override Task<IdentityResult> AccessFailedAsync(ApplicationUser user)
        {
            return this.RetryOnConflictAsync(user, () => base.AccessFailedAsync(user));
        }

        /// <summary>ResetAccessFailedCountAsync</summary>
        /// <param name="user">ApplicationUser</param>
        /// <returns>IdentityResult</returns>
        /// <remarks>**競合で失敗すると、正しいパスワードでもサインインが失敗する。**</remarks>
        public override Task<IdentityResult> ResetAccessFailedCountAsync(ApplicationUser user)
        {
            return this.RetryOnConflictAsync(user, () => base.ResetAccessFailedCountAsync(user));
        }

        /// <summary>UpdateSecurityStampAsync</summary>
        /// <param name="user">ApplicationUser</param>
        /// <returns>IdentityResult</returns>
        /// <remarks>**結果を見ない呼び出しがあり、競合で更新が消えると、古いセッションが生き残る。**</remarks>
        public override Task<IdentityResult> UpdateSecurityStampAsync(ApplicationUser user)
        {
            return this.RetryOnConflictAsync(user, () => base.UpdateSecurityStampAsync(user));
        }

        /// <summary>SetTwoFactorEnabledAsync</summary>
        /// <param name="user">ApplicationUser</param>
        /// <param name="enabled">有効にするか</param>
        /// <returns>IdentityResult</returns>
        /// <remarks>**結果を見ない呼び出しがある。**</remarks>
        public override Task<IdentityResult> SetTwoFactorEnabledAsync(ApplicationUser user, bool enabled)
        {
            return this.RetryOnConflictAsync(user, () => base.SetTwoFactorEnabledAsync(user, enabled));
        }

        /// <summary>変更を当てて書き、競合したら読み直して当て直す（#331）</summary>
        /// <param name="user">ApplicationUser（変更は、この物に当てる）</param>
        /// <param name="change">変更（**読み直すたびに当て直す**ので、前の値から計算しない）</param>
        /// <returns>IdentityResult</returns>
        /// <remarks>
        /// **送り直す人がいない要求**（端末からの `/SetDeviceToken` など）のためにある。
        /// **画面からの更新には使わない**（見ていない値の上に書くことになる。競合なら、失敗を見せて送り直させる）。
        /// </remarks>
        public Task<IdentityResult> UpdateWithRetryAsync(ApplicationUser user, Action<ApplicationUser> change)
        {
            return this.RetryOnConflictAsync(user, () =>
            {
                change(user);
                return this.UpdateAsync(user);
            });
        }

        /// <summary>競合したら、物を読み直して、やり直す</summary>
        /// <param name="user">ApplicationUser</param>
        /// <param name="operation">操作</param>
        /// <returns>IdentityResult</returns>
        private async Task<IdentityResult> RetryOnConflictAsync(
            ApplicationUser user, Func<Task<IdentityResult>> operation)
        {
            string concurrencyFailure = new IdentityErrorDescriber().ConcurrencyFailure().Code;
            IdentityResult result = null;

            for (int i = 0; i < CmnUserStore.ConcurrencyRetryCount; i++)
            {
                result = await operation();

                bool conflicted = false;
                foreach (IdentityError error in result.Errors)
                {
                    conflicted |= error.Code == concurrencyFailure;
                }

                if (!conflicted)
                {
                    return result;
                }

                await Task.Delay(CmnUserStore.ConcurrencyRetryDelayMilliseconds());

                ApplicationUser fresh = await this.FindByIdAsync(user.Id);

                if (fresh == null)
                {
                    return result;
                }

                UserManagerCore.CopyRow(fresh, user);
            }

            return result;
        }

        /// <summary>読み直した行の値を、呼び出し元が持っている物へ写す</summary>
        /// <param name="from">読み直した物</param>
        /// <param name="to">呼び出し元の物</param>
        /// <remarks>**`Update` は行全体を書く**ので、**古い値を残すと、やり直しが他の更新を消す。**</remarks>
        private static void CopyRow(ApplicationUser from, ApplicationUser to)
        {
            to.UserName = from.UserName;
            to.NormalizedUserName = from.NormalizedUserName;
            to.PasswordHash = from.PasswordHash;
            to.Email = from.Email;
            to.NormalizedEmail = from.NormalizedEmail;
            to.EmailConfirmed = from.EmailConfirmed;
            to.PhoneNumber = from.PhoneNumber;
            to.PhoneNumberConfirmed = from.PhoneNumberConfirmed;
            to.LockoutEnabled = from.LockoutEnabled;
            to.AccessFailedCount = from.AccessFailedCount;
            to.LockoutEndDateUtc = from.LockoutEndDateUtc;
            to.SecurityStamp = from.SecurityStamp;
            to.TwoFactorEnabled = from.TwoFactorEnabled;
            to.TotpAuthenticatorKey = from.TotpAuthenticatorKey;
            to.UnstructuredData = from.UnstructuredData;
            to.DeviceToken = from.DeviceToken;
            to.PasswordChangeDate = from.PasswordChangeDate;
            to.ConcurrencyStamp = from.ConcurrencyStamp;
        }
    }
}
