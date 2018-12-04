﻿//**********************************************************************************
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
//* クラス名        ：UserStore
//* クラス日本語名  ：UserStore（ライブラリ）
//*
//* 作成日時        ：－
//* 作成者          ：－
//* 更新履歴        ：－
//*
//*  日時        更新者            内容
//*  ----------  ----------------  -------------------------------------------------
//*  2017/04/24  西野 大介         新規
//**********************************************************************************

using MultiPurposeAuthSite.Co;
using MultiPurposeAuthSite.Entity;
using MultiPurposeAuthSite.Password;
using MultiPurposeAuthSite.Log;
using MultiPurposeAuthSite.Util.Sts;

using System;
using System.Data;
using System.Linq;
using System.Collections.Generic;

using System.Reflection;
using System.Threading.Tasks;
using System.Security.Claims;

using System.Web;

using Dapper;
using Microsoft.AspNet.Identity;

// --------------------------------------------------
// UserStoreのTransaction管理について。
// --------------------------------------------------
// 制御の反転で実装されているので、
// ASP.NET Identity側が（Entityの外から）Transaction管理しない以上、
// UserStoreのmethodレベルでTransactionalに実装することは難しい。
// ただし、LDAP、NoSQLなどと実装を共通化していくにはメリットになる。
// 
// --------------------------------------------------
// DBMS ProviderとMemory Providerとの動作の差異
// --------------------------------------------------
// DBMS Providerを使用する際、性能向上のため、
// Userの参照処理では、Roles, Logins, Claimsなどの情報はロードしない仕様とした。
// 別途、GetRoles, Logins, Claimsなどのmethodを使用してロードする。
// Memory Providerを使用する際と、動作が異なるのでテストの際は注意が必要。
// --------------------------------------------------

/// <summary>MultiPurposeAuthSite.Data</summary>
namespace MultiPurposeAuthSite.Data
{
    /// <summary>
    /// UserStoreでApplicationUserを永続化する。
    /// </summary>
    public class UserStore :

        IUserStore<ApplicationUser>,
        IUserStore<ApplicationUser, string>,
        IUserPasswordStore<ApplicationUser, string>,
        IUserEmailStore<ApplicationUser, string>,
        IUserPhoneNumberStore<ApplicationUser, string>,
        IUserRoleStore<ApplicationUser, string>,
        IUserSecurityStampStore<ApplicationUser>,
        IUserLockoutStore<ApplicationUser, string>,
        IUserTwoFactorStore<ApplicationUser, string>,
        IUserLoginStore<ApplicationUser, string>,
        IUserClaimStore<ApplicationUser, string>,
        IRoleStore<ApplicationRole, string>,
        IQueryableUserStore<ApplicationUser, string>,
        IQueryableRoleStore<ApplicationRole, string>,
        IDisposable

    {
        #region constructor

        /// <summary>constructor</summary>
        public UserStore() { }

        #endregion
        
        #region CRUD(共通)

        #region C (Create)

        /// <summary>新規ユーザーの追加</summary>
        /// <param name="user">ApplicationUser</param>
        /// <returns>－</returns>
        public Task CreateAsync(ApplicationUser user)
        {
            return CmnUserStore.CreateAsync(user);
        }

        #endregion

        #region R (Read)

        /// <summary>ユーザを（Id指定で）検索</summary>
        /// <param name="userId">string</param>
        /// <returns>ApplicationUser</returns>
        public Task<ApplicationUser> FindByIdAsync(string userId)
        {
            return CmnUserStore.FindByIdAsync(userId);
        }

        /// <summary>ユーザを（ユーザ名指定で）検索</summary>
        /// <param name="userName">string</param>
        /// <returns>ApplicationUser</returns>
        public Task<ApplicationUser> FindByNameAsync(string userName)
        {
            return CmnUserStore.FindByNameAsync(userName);
        }

        /// <summary>ユーザ一覧を返す。</summary>
        /// <remarks>
        /// ★ マルチテナント化対応を施した
        /// （場合によってはページングも必要になる）
        /// </remarks>
        public IQueryable<ApplicationUser> Users
        {
            get
            {
                return CmnUserStore.Users;
            }
        }

        #endregion

        #region U (Update)

        /// <summary>ユーザー情報を更新</summary>
        /// <param name="user">ApplicationUser</param>
        /// <returns>－</returns>
        public Task UpdateAsync(ApplicationUser user)
        {
            return CmnUserStore.UpdateAsync(user);
        }

        #region ユーザの関連情報の更新（ Roles, Logins, Claims ）

        /// <summary>Rolesの更新</summary>
        /// <param name="user">更新</param>
        /// <param name="tgtUser">ターゲット</param>
        private Task UpdateRoles(ApplicationUser user, ApplicationUser tgtUser)
        {
            return CmnUserStore.UpdateRoles(user, tgtUser);
        }

        //Logins, ClaimsはDel-Insで対応するため、UpdateLogins, UpdateClaimsのメソッドは不要

        #endregion

        #endregion

        #region D (Delete)

        /// <summary>ユーザの論理削除</summary>
        /// <param name="user">ApplicationUser</param>
        /// <returns>－</returns>
        /// <remarks>
        /// 削除するエンティティにマークを付けます
        /// </remarks>
        public Task DeleteAsync(ApplicationUser user)
        {
            return CmnUserStore.DeleteAsync(user);
        }

        #endregion

        #endregion

        #region ユーザ属性

        #region IUserPasswordStore

        /// <summary>ユーザがパスワードを持っているか</summary>
        /// <param name="user">ApplicationUser</param>
        /// <returns>真・偽：ユーザがパスワードを持っているか</returns>
        public Task<bool> HasPasswordAsync(ApplicationUser user)
        {
            return CmnUserStore.HasPasswordAsync(user);
        }

        /// <summary>ユーザーにハッシュ化されたパスワードを設定</summary>
        /// <param name="user">ApplicationUser</param>
        /// <param name="passwordHash">string</param>
        /// <returns>－</returns>
        public Task SetPasswordHashAsync(ApplicationUser user, string passwordHash)
        {
            return CmnUserStore.SetPasswordHashAsync(user, passwordHash);
        }

        /// <summary>ユーザのパスワードのハッシュを取得</summary>
        /// <param name="user">ApplicationUser</param>
        /// <returns>パスワードのハッシュ</returns>
        public Task<string> GetPasswordHashAsync(ApplicationUser user)
        {
            return CmnUserStore.GetPasswordHashAsync(user);
        }

        #endregion

        #region IUserEmailStore

        /// <summary>ユーザを（email指定で）検索して取得</summary>
        /// <param name="email">string</param>
        /// <returns>ApplicationUser</returns>
        public Task<ApplicationUser> FindByEmailAsync(string email)
        {
            return CmnUserStore.FindByEmailAsync(email);
        }

        /// <summary>メアドの設定</summary>
        /// <param name="user">ApplicationUser</param>
        /// <param name="email">string</param>
        /// <returns>－</returns>
        public Task SetEmailAsync(ApplicationUser user, string email)
        {
            return CmnUserStore.SetEmailAsync(user, email);
        }

        /// <summary>メアドの取得</summary>
        /// <param name="user">ApplicationUser</param>
        /// <returns>Email</returns>
        public Task<string> GetEmailAsync(ApplicationUser user)
        {
            return CmnUserStore.GetEmailAsync(user);
        }

        /// <summary>メアド確認の設定</summary>
        /// <param name="user">ApplicationUser</param>
        /// <param name="confirmed">bool</param>
        /// <returns>－</returns>
        public Task SetEmailConfirmedAsync(ApplicationUser user, bool confirmed)
        {
            return CmnUserStore.SetEmailConfirmedAsync(user, confirmed);
        }

        /// <summary>メアド確認の取得</summary>
        /// <param name="user">ApplicationUser</param>
        /// <returns>EmailConfirmed</returns>
        public Task<bool> GetEmailConfirmedAsync(ApplicationUser user)
        {
            return CmnUserStore.GetEmailConfirmedAsync(user);
        }

        #endregion

        #region IUserPhoneNumberStore

        /// <summary>電話番号の設定</summary>
        /// <param name="user">ApplicationUser</param>
        /// <param name="phoneNumber">string</param>
        /// <returns>－</returns>
        public Task SetPhoneNumberAsync(ApplicationUser user, string phoneNumber)
        {
            return CmnUserStore.SetPhoneNumberAsync(user, phoneNumber);
        }

        /// <summary>電話番号の取得</summary>
        /// <param name="user">ApplicationUser</param>
        /// <returns>phone number</returns>
        public Task<string> GetPhoneNumberAsync(ApplicationUser user)
        {
            return CmnUserStore.GetPhoneNumberAsync(user);
        }

        /// <summary>電話番号確認の設定</summary>
        /// <param name="user">ApplicationUser</param>
        /// <param name="confirmed">bool</param>
        /// <returns>－</returns>
        public Task SetPhoneNumberConfirmedAsync(ApplicationUser user, bool confirmed)
        {
            return CmnUserStore.SetPhoneNumberConfirmedAsync(user, confirmed);
        }

        /// <summary>電話番号確認の取得</summary>
        /// <param name="user">ApplicationUser</param>
        /// <returns>phone number is confirmed</returns>
        public Task<bool> GetPhoneNumberConfirmedAsync(ApplicationUser user)
        {
            return CmnUserStore.GetPhoneNumberConfirmedAsync(user);
        }

        #endregion

        #region IUserRoleStore

        /// <summary>ロールにユーザを追加</summary>
        /// <param name="user">ApplicationUser</param>
        /// <param name="roleName">string</param>
        /// <returns>－</returns>
        public Task AddToRoleAsync(ApplicationUser user, string roleName)
        {
            return CmnUserStore.AddToRoleAsync(user, roleName);
        }

        /// <summary>ユーザがロールに所属するか？</summary>
        /// <param name="user">ApplicationUser</param>
        /// <param name="roleName">ロール名</param>
        /// <returns>真・偽：ユーザがロールに所属するか</returns>
        public async Task<bool> IsInRoleAsync(ApplicationUser user, string roleName)
        {
            return await CmnUserStore.IsInRoleAsync(user, roleName);
        }

        /// <summary>ユーザのロール一覧を取得</summary>
        /// <param name="user">ApplicationUser</param>
        /// <returns>ユーザのロール一覧</returns>
        public Task<IList<string>> GetRolesAsync(ApplicationUser user)
        {
            return CmnUserStore.GetRolesAsync(user);
        }

        /// <summary>ユーザをロールから削除</summary>
        /// <param name="user">ApplicationUser</param>
        /// <param name="roleName">ロール名</param>
        /// <returns>－</returns>
        public Task RemoveFromRoleAsync(ApplicationUser user, string roleName)
        {
            return CmnUserStore.RemoveFromRoleAsync(user, roleName);
        }

        #endregion

        #endregion

        #region ログイン属性

        #region IUserSecurityStampStore

        /// <summary>セキュリティスタンプを設定</summary>
        /// <param name="user">ApplicationUser</param>
        /// <param name="stamp">string</param>
        /// <returns>－</returns>
        public Task SetSecurityStampAsync(ApplicationUser user, string stamp)
        {
            return CmnUserStore.SetSecurityStampAsync(user, stamp);
        }

        /// <summary>セキュリティスタンプを取得</summary>
        /// <param name="user">ApplicationUser</param>
        /// <returns>SecurityStamp</returns>
        public Task<string> GetSecurityStampAsync(ApplicationUser user)
        {
            return CmnUserStore.GetSecurityStampAsync(user);
        }

        #endregion

        #region IUserLockoutStore

        /// <summary>ユーザがロックアウト可能かどうかを設定</summary>
        /// <param name="user">ApplicationUser</param>
        /// <param name="enabled">真・偽：ユーザがロックアウト可能かどうか</param>
        /// <returns>－</returns>
        public Task SetLockoutEnabledAsync(ApplicationUser user, bool enabled)
        {
            return CmnUserStore.SetLockoutEnabledAsync(user, enabled);
        }

        /// <summary>ユーザがロックアウト可能かどうかを取得</summary>
        /// <param name="user">ApplicationUser</param>
        /// <returns>真・偽：ユーザがロックアウト可能かどうか</returns>
        public Task<bool> GetLockoutEnabledAsync(ApplicationUser user)
        {
            return CmnUserStore.GetLockoutEnabledAsync(user);
        }

        /// <summary>サインインに失敗した試行回数を記録</summary>
        /// <param name="user">ApplicationUser</param>
        /// <returns>サインインに失敗した試行回数</returns>
        public Task<int> IncrementAccessFailedCountAsync(ApplicationUser user)
        {
            return CmnUserStore.IncrementAccessFailedCountAsync(user);
        }

        /// <summary>失敗したサインインの試行回数を取得</summary>
        /// <param name="user">ApplicationUser</param>
        /// <returns>現在の失敗したサインインの試行回数</returns>
        /// <remarks>パスワードが確認されるか、アカウントがロックアウトされるたびに、この数は、リセットされる。</remarks>
        public Task<int> GetAccessFailedCountAsync(ApplicationUser user)
        {
            return CmnUserStore.GetAccessFailedCountAsync(user);
        }

        /// <summary>失敗したサインインの試行回数をリセット</summary>
        /// <param name="user">ApplicationUser</param>
        /// <returns>－</returns>
        /// <remarks>
        /// 慣例的に、サインインが成功した場合にリセットされる。
        /// </remarks>
        public Task ResetAccessFailedCountAsync(ApplicationUser user)
        {
            return CmnUserStore.ResetAccessFailedCountAsync(user);
        }

        /// <summary>
        /// ロックアウト終了日を設定
        /// （指定された終了日まで、ユーザをロックアウト）
        /// </summary>
        /// <param name="user">ApplicationUser</param>
        /// <param name="lockoutEnd">ロックアウト終了日</param>
        /// <returns>－</returns>
        /// <remarks>
        /// 過去の日付に設定すると、ロックアウトを解除する。
        /// </remarks>
        public Task SetLockoutEndDateAsync(ApplicationUser user, DateTimeOffset lockoutEnd)
        {
            return CmnUserStore.SetLockoutEndDateAsync(user, lockoutEnd);
        }

        /// <summary>
        /// ロックアウト終了日を取得
        /// （指定された終了日まで、ユーザをロックアウト）</summary>
        /// <param name="user">ApplicationUser</param>
        /// <returns>ロックアウト終了日</returns>
        /// <remarks>
        /// 過去の日付を返すときは既にロックアウトされていない。
        /// </remarks>
        public Task<DateTimeOffset> GetLockoutEndDateAsync(ApplicationUser user)
        {
            return CmnUserStore.GetLockoutEndDateAsync(user);
        }

        #endregion

        #region IUserTwoFactorStore

        /// <summary>2FAの有効・無効を設定</summary>
        /// <param name="user">ApplicationUser</param>
        /// <param name="enabled">真・偽：2FAが有効かどうか</param>
        /// <returns>－</returns>
        public Task SetTwoFactorEnabledAsync(ApplicationUser user, bool enabled)
        {
            return CmnUserStore.SetTwoFactorEnabledAsync(user, enabled);
        }

        /// <summary>2FAの有効・無効を取得</summary>
        /// <param name="user">ApplicationUser</param>
        /// <returns>真・偽：2FAが有効かどうか</returns>
        public Task<bool> GetTwoFactorEnabledAsync(ApplicationUser user)
        {
            return CmnUserStore.GetTwoFactorEnabledAsync(user);
        }

        #endregion

        #region Collection (Roles, Logins, Claims)

        #region IRoleStore

        #region CRUD(共通)

        #region C (Create)

        /// <summary>ロールを追加</summary>
        /// <param name="role">ApplicationRole</param>
        /// <returns>－</returns>
        public Task CreateAsync(ApplicationRole role)
        {
            return CmnRoleStore.CreateAsync(role);
        }

        #endregion

        #region R (Read)

        /// <summary>ロールを ID から検索</summary>
        /// <param name="roleId">string</param>
        /// <returns>ApplicationRole</returns>
        Task<ApplicationRole> IRoleStore<ApplicationRole, string>.FindByIdAsync(string roleId)
        {
            return CmnRoleStore.FindByIdAsync(roleId);
        }

        /// <summary>ロールを（ロール名指定で）検索</summary>
        /// <param name="roleName">string</param>
        /// <returns>ApplicationRole</returns>
        /// <remarks>
        /// （マルチテナント化のため）一意ではないので、
        /// ・グローバル ロールを優先して返す。
        /// ・無ければ自テナントを検索して返す。
        /// </remarks>
        Task<ApplicationRole> IRoleStore<ApplicationRole, string>.FindByNameAsync(string roleName)
        {
            return CmnRoleStore.FindByNameAsync(roleName);
        }

        /// <summary>
        /// ロール一覧を返す。
        /// </summary>
        /// <remarks>
        /// ★ マルチテナント化対応を施した
        /// （場合によってはページングも必要になる）
        /// </remarks>
        public IQueryable<ApplicationRole> Roles
        {
            get
            {
                return CmnRoleStore.Roles;
            }
        }

        #endregion

        #region U (Update)

        /// <summary>ロールを更新する</summary>
        /// <param name="role">ApplicationRole</param>
        /// <returns>－</returns>
        public Task UpdateAsync(ApplicationRole role)
        {
            return CmnRoleStore.UpdateAsync(role);
        }

        #endregion

        #region D (Delete)

        /// <summary>ロールを削除する</summary>
        /// <param name="role">ApplicationRole</param>
        /// <returns>－</returns>
        public Task DeleteAsync(ApplicationRole role)
        {
            return CmnRoleStore.DeleteAsync(role);
        }

        #endregion

        #endregion

        #endregion

        #region IUserLoginStore

        /// <summary>ユーザーに外部ログインを追加</summary>
        /// <param name="user">ApplicationUser</param>
        /// <param name="login">UserLoginInfo</param>
        /// <returns>－</returns>
        public Task AddLoginAsync(ApplicationUser user, UserLoginInfo login)
        {
            return CmnUserStore.AddLoginAsync(user, login);
        }

        /// <summary>外部ログインでユーザーを検索</summary>
        /// <param name="user">ApplicationUser</param>
        /// <returns>ApplicationUser</returns>
        public Task<ApplicationUser> FindAsync(UserLoginInfo login)
        {
            return CmnUserStore.FindAsync(login);
        }

        /// <summary>ユーザの外部ログイン一覧を取得</summary>
        /// <param name="user">ApplicationUser</param>
        /// <returns>IList<UserLoginInfo></returns>>
        public Task<IList<UserLoginInfo>> GetLoginsAsync(ApplicationUser user)
        {
            return CmnUserStore.GetLoginsAsync(user);
        }

        /// <summary>ユーザーから外部ログインを削除</summary>
        /// <param name="user">ApplicationUser</param>
        /// <param name="login">UserLoginInfo</param>
        /// <returns>－</returns>
        public Task RemoveLoginAsync(ApplicationUser user, UserLoginInfo login)
        {
            return CmnUserStore.RemoveLoginAsync(user, login);
        }

        #endregion

        #region IUserClaimStore

        /// <summary>ユーザに外部ログインのクレームを追加</summary>
        /// <param name="user">ApplicationUser</param>
        /// <param name="claim">Claim</param>
        /// <returns>－</returns>
        public Task AddClaimAsync(ApplicationUser user, Claim claim)
        {
            return CmnUserStore.AddClaimAsync(user, claim);
        }

        /// <summary>ユーザの（外部ログインの）クレーム一覧を取得</summary>
        /// <param name="user">ApplicationUser</param>
        /// <returns>IList<Claim></returns>
        public Task<IList<Claim>> GetClaimsAsync(ApplicationUser user)
        {
            return CmnUserStore.GetClaimsAsync(user);
        }

        /// <summary>ユーザの（外部ログインの）クレームを削除</summary>
        /// <param name="user">ApplicationUser</param>
        /// <param name="claim">Claim</param>
        /// <returns>－</returns>
        public Task RemoveClaimAsync(ApplicationUser user, Claim claim)
        {
            return CmnUserStore.RemoveClaimAsync(user, claim);
        }

        #endregion

        #endregion

        #endregion

        #region IDisposable

        /// <summary>Disposeが呼ばれたかどうかを追跡する</summary>
        /// <remarks>SharedMemory.csを参考に実装</remarks>
        private bool IsDisposed = false;

        /// <summary>Close（→ Dispose）</summary>
        /// <remarks>SharedMemory.csを参考に実装</remarks>
        public void Close()
        {
            this.Dispose();
        }

        /// <summary>IDisposable.Dispose（１）</summary>
        /// <remarks>SharedMemory.csを参考に実装</remarks>
        public void Dispose()
        {
            // trueはユーザからの直接・間接的実行を意味する。
            this.Dispose(true);

            // このクラスのデストラクタ（Finalizeメソッド）を呼び出さないようGCに命令。
            GC.SuppressFinalize(this);
        }

        /// <summary>IDisposable.Dispose（２）</summary>
        /// <param name="disposing">
        /// true：ユーザからの直接・間接的実行を意味する。
        /// false：デストラクタ（Finalizeメソッド）からの実行を意味する。
        /// </param>
        /// <remarks>SharedMemory.csを参考に実装</remarks>
        protected virtual void Dispose(bool disposing)
        {
            // Disposeが既に呼ばれたかチェック
            if (!this.IsDisposed)
            {
                // まだ呼ばれていない場合、
                // 全てのリソースをクリーンナップ

                if (disposing)
                {
                    // ユーザからの直接・間接的実行
                    this.DisposeManagedResources();
                    this.DisposeUnManagedResources();
                }
                else
                {
                    // デストラクタ（Finalizeメソッド）からの実行
                    this.DisposeUnManagedResources();
                }

                // Disposeが既に呼ばれたとフラグを立てる。
                this.IsDisposed = true;
            }
            else
            {
                // 既に呼ばれている場合、
                // なにもしない。
            }
        }

        /// <summary>マネージ リソースをクリーンナップ</summary>
        /// <remarks>SharedMemory.csを参考に実装</remarks>
        private void DisposeManagedResources()
        {
            // マネージ リソースをクリーンナップ
        }

        /// <summary>アンマネージ リソースをクリーンナップ</summary>
        /// <remarks>SharedMemory.csを参考に実装</remarks>
        private void DisposeUnManagedResources()
        {
            // アンマネージ リソースをクリーンナップ
        }
        /// <summary>デストラクタ（Finalizeメソッド）を実装</summary>
        /// <remarks>SharedMemory.csを参考に実装</remarks>
        ~UserStore() // アクセス修飾子はない（ユーザから呼べない）
        {
            // falseはデストラクタ（Finalizeメソッド）からの実行を意味する。
            this.Dispose(false);
        }
        #endregion
    }
}