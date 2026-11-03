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
//*  2026/11/03  玄人 幸道         回復コードの作成も、競合したら読み直して作り直す（#331）
//*  2026/11/04  玄人 幸道         外部ログイン・クレームの追加と外部ログインの解除も、後の更新が競合したらやり直す（#331。RT-294.23 の原因）
//**********************************************************************************

using System;
using System.Collections.Generic;
using System.Security.Claims;
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

        /// <summary>GenerateNewTwoFactorRecoveryCodesAsync</summary>
        /// <param name="user">ApplicationUser</param>
        /// <param name="number">作る数</param>
        /// <returns>回復コード（作れなければ null）</returns>
        /// <remarks>
        /// **基底は、コードを保存した後で利用者の行を書き、書けなければ null を返す。**
        /// **同じ利用者の別の更新と重なるだけで null になり、呼ぶ側が 500 になっていた**（認証アプリの登録を同時に送ったとき。#331）。
        /// **競合したら、読み直して作り直す**（作り直したコードで上書きするので、前のコードは残らない）。
        /// </remarks>
        public override async Task<IEnumerable<string>> GenerateNewTwoFactorRecoveryCodesAsync(
            ApplicationUser user, int number)
        {
            IEnumerable<string> codes = null;

            //  **null の理由は、基底からは分からない**（行の更新の失敗だけが null になる）。競合として扱い、回数で止める。
            await this.RetryOnConflictAsync(user, async () =>
            {
                codes = await base.GenerateNewTwoFactorRecoveryCodesAsync(user, number);

                return (codes != null)
                    ? IdentityResult.Success
                    : IdentityResult.Failed(new IdentityErrorDescriber().ConcurrencyFailure());
            });

            return codes;
        }

        /// <summary>AddLoginAsync</summary>
        /// <param name="user">ApplicationUser</param>
        /// <param name="login">外部ログイン</param>
        /// <returns>IdentityResult</returns>
        /// <remarks>
        /// **基底は、外部ログインの行をその場で書いてから、利用者の行を更新する。**
        /// **後の更新だけが競合に負けると、行は書けているのに失敗が返り、ID 連携がエラー画面で終わっていた**（#331。`RT-294.23`）。
        /// **後の更新は中身を変えない**ので、**競合したら読み直して書き直す。**
        /// </remarks>
        public override async Task<IdentityResult> AddLoginAsync(ApplicationUser user, UserLoginInfo login)
        {
            IdentityResult result = await base.AddLoginAsync(user, login);

            return UserManagerCore.IsConflict(result)
                ? await this.UpdateWithRetryAsync(user, x => { })
                : result;
        }

        /// <summary>AddClaimsAsync（AddClaimAsync も、ここを通る）</summary>
        /// <param name="user">ApplicationUser</param>
        /// <param name="claims">クレーム</param>
        /// <returns>IdentityResult</returns>
        /// <remarks>**`AddLoginAsync` と同じ**（クレームの行をその場で書いてから、利用者の行を更新する。#331）。</remarks>
        public override async Task<IdentityResult> AddClaimsAsync(ApplicationUser user, IEnumerable<Claim> claims)
        {
            IdentityResult result = await base.AddClaimsAsync(user, claims);

            return UserManagerCore.IsConflict(result)
                ? await this.UpdateWithRetryAsync(user, x => { })
                : result;
        }

        /// <summary>RemoveLoginAsync</summary>
        /// <param name="user">ApplicationUser</param>
        /// <param name="loginProvider">LoginProvider</param>
        /// <param name="providerKey">ProviderKey</param>
        /// <returns>IdentityResult</returns>
        /// <remarks>
        /// **基底は、外部ログインの行を消してから、`SecurityStamp` を新しくして利用者の行を更新する。**
        /// **後の更新が競合に負けると、解除できているのに失敗が返り、スタンプも古いまま残る**（#331）。
        /// **競合したら、スタンプの更新をやり直す**（`UpdateSecurityStampAsync` は、読み直してやり直す）。
        /// </remarks>
        public override async Task<IdentityResult> RemoveLoginAsync(
            ApplicationUser user, string loginProvider, string providerKey)
        {
            IdentityResult result = await base.RemoveLoginAsync(user, loginProvider, providerKey);

            return UserManagerCore.IsConflict(result)
                ? await this.UpdateSecurityStampAsync(user)
                : result;
        }

        /// <summary>変更を当てて書き、競合したら読み直して当て直す（#331）</summary>
        /// <param name="user">ApplicationUser（変更は、この物に当てる）</param>
        /// <param name="change">変更（**読み直すたびに当て直す**ので、前の値から計算しない）</param>
        /// <returns>IdentityResult</returns>
        /// <remarks>
        /// **`change` には、この要求で変える項目だけを書く。** 読み直した行に当て直すので、**ほかの項目は新しい値のまま残る。**
        /// 端末からの要求（`/SetDeviceToken`）と、画面からの更新（利用者名・メアド・非構造化データなど）が使う。
        /// **同じ項目を同時に変えたときは、後から書いた方が残る。**
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
            IdentityResult result = null;

            for (int i = 0; i < CmnUserStore.ConcurrencyRetryCount; i++)
            {
                result = await operation();

                if (!UserManagerCore.IsConflict(result))
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

        /// <summary>競合で失敗したか</summary>
        /// <param name="result">IdentityResult</param>
        /// <returns>競合なら true</returns>
        private static bool IsConflict(IdentityResult result)
        {
            string concurrencyFailure = new IdentityErrorDescriber().ConcurrencyFailure().Code;

            foreach (IdentityError error in result.Errors)
            {
                if (error.Code == concurrencyFailure)
                {
                    return true;
                }
            }

            return false;
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
