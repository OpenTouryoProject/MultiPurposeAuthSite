//**********************************************************************************
//* テンプレート
//**********************************************************************************

// 以下のLicenseに従い、このProjectをTemplateとして使用可能です。Release時にCopyright表示してSublicenseして下さい。
// https://github.com/OpenTouryoProject/MultiPurposeAuthSite/blob/master/license/LicenseForTemplates.txt

//**********************************************************************************
//* クラス名        ：RolesAdminController
//* クラス日本語名  ：RolesAdminのController（テンプレート）
//*
//* 作成日時        ：－
//* 作成者          ：－
//* 更新履歴        ：－
//*
//*  日時        更新者            内容
//*  ----------  ----------------  -------------------------------------------------
//*  2026/10/02  玄人 幸道         新規（net48 版から移植。#258）
//**********************************************************************************

using MultiPurposeAuthSite.Co;
using MultiPurposeAuthSite.ViewModels;

using System.Linq;
using System.Collections.Generic;
using System.Security;
using System.Threading.Tasks;

using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;

using Touryo.Infrastructure.Business.Presentation;

/// <summary>MultiPurposeAuthSite.Controllers</summary>
namespace MultiPurposeAuthSite.Controllers
{
    /// <summary>RolesAdminController</summary>
    /// <remarks>
    /// **net48 版からの移植**（#258）。**画面と導線は net48 版と同じ**にしてある。
    /// 読み替えたところは `UsersAdminController` の注記のとおり。
    /// </remarks>
    //[Authorize(Roles = Const.Role_Admin)] // 切替可能な実装箇所に移動
    public class RolesAdminController : MyBaseMVControllerCore
    {
        /// <summary>列挙型</summary>
        public enum EnumAdminMessageId
        {
            /// <summary>DoNotHaveOwnershipOfTheObject</summary>
            DoNotHaveOwnershipOfTheObject,
            /// <summary>AddSuccess</summary>
            AddSuccess,
            /// <summary>EditSuccess</summary>
            EditSuccess,
            /// <summary>DeleteSuccess</summary>
            DeleteSuccess,
            /// <summary>Error</summary>
            Error
        }

        #region members & constructor

        /// <summary>UserManager</summary>
        private readonly UserManager<ApplicationUser> _userManager = null;

        /// <summary>RoleManager</summary>
        private readonly RoleManager<ApplicationRole> _roleManager = null;

        /// <summary>constructor</summary>
        /// <param name="userManager">UserManager</param>
        /// <param name="roleManager">RoleManager</param>
        public RolesAdminController(
            UserManager<ApplicationUser> userManager,
            RoleManager<ApplicationRole> roleManager)
        {
            this._userManager = userManager;
            this._roleManager = roleManager;
        }

        #endregion

        #region property

        /// <summary>UserManager</summary>
        private UserManager<ApplicationUser> UserManager
        {
            get
            {
                return this._userManager;
            }
        }

        /// <summary>RoleManager</summary>
        private RoleManager<ApplicationRole> RoleManager
        {
            get
            {
                return this._roleManager;
            }
        }

        #endregion

        #region 認証・認可系

        /// <summary>
        /// [Authorize(Roles = Const.Role_Admin)]の代替
        /// ※ constructorでは動かないので、このように実装することになった。
        /// </summary>
        /// <returns>Task</returns>
        private async Task AuthorizeAsync()
        {
            if (Config.EnableAdministrationOfUsersAndRoles)
            {
                ApplicationUser user = await UserManager.GetUserAsync(User);

                if (user == null)
                {
                    // 未認証
                    throw new SecurityException(Resources.AdminController.UnAuthenticate);
                }
                else
                {
                    IList<string> roles = await UserManager.GetRolesAsync(user);
                    if (roles.Any(x => x == Const.Role_SystemAdmin))
                    {
                        return;
                    }
                    else
                    {
                        // 認証されない。
                        throw new SecurityException(Resources.AdminController.UnAuthorized);
                    }
                }
            }
            else
            {
                // ロックダウンされている。
                throw new SecurityException(Resources.AdminController.LockedDown);
            }
        }

        #endregion

        #region Action Method

        #region Reference

        /// <summary>
        /// ロール一覧表示画面
        /// GET: /RolesAdmin/Index
        /// </summary>
        /// <param name="message">EnumAdminMessageId?</param>
        /// <returns>ActionResultを非同期に返す</returns>
        [HttpGet]
        public async Task<ActionResult> Index(EnumAdminMessageId? message)
        {
            await this.AuthorizeAsync();

            // 色々な結果メッセージの設定
            ViewBag.StatusMessage =
                message == EnumAdminMessageId.DoNotHaveOwnershipOfTheObject ? Resources.AdminController.DoNotHaveOwnershipOfTheObject
                : message == EnumAdminMessageId.AddSuccess ? Resources.AdminController.AddSuccess
                : message == EnumAdminMessageId.Error ? Resources.AdminController.Error
                : message == EnumAdminMessageId.EditSuccess ? Resources.AdminController.EditSuccess
                : message == EnumAdminMessageId.DeleteSuccess ? Resources.AdminController.DeleteSuccess
                : "";

            // ロール一覧表示
            return View(RoleManager.Roles.AsEnumerable());
        }

        /// <summary>
        /// ロール詳細表示画面
        /// GET: /RolesAdmin/Details/5
        /// </summary>
        /// <param name="id">string</param>
        /// <returns>ActionResultを非同期に返す</returns>
        [HttpGet]
        public async Task<ActionResult> Details(string id)
        {
            await this.AuthorizeAsync();

            // ロールを取得
            ApplicationRole role = await RoleManager.FindByIdAsync(id);

            // ロールに属するユーザを取得
            List<string> userNames = new List<string>();

            foreach (ApplicationUser user in UserManager.Users.AsEnumerable())
            {
                //　ユーザがロールに属するかどうか。
                if (await UserManager.IsInRoleAsync(user, role.Name))
                {
                    // ロールに含まれるユーザ
                    userNames.Add(user.UserName);
                }
                else
                {
                    // ロールに含まれないユーザ
                }
            }

            // ロール詳細表示
            ViewBag.UserNames = userNames;
            ViewBag.UserCount = userNames.Count();

            return View(role);
        }

        #endregion

        #region Create

        /// <summary>
        /// ロール登録画面（初期表示）
        /// GET: /RolesAdmin/Create
        /// </summary>
        /// <returns>ActionResultを非同期に返す</returns>
        [HttpGet]
        public async Task<ActionResult> Create()
        {
            await this.AuthorizeAsync();
            return View();
        }

        /// <summary>
        /// ロール登録画面（登録処理）
        /// POST: /RolesAdmin/Create
        /// </summary>
        /// <param name="roleViewModel">RolesAdminEditViewModel</param>
        /// <returns>ActionResultを非同期に返す</returns>
        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<ActionResult> Create(RolesAdminEditViewModel roleViewModel)
        {
            await this.AuthorizeAsync();

            if (ModelState.IsValid)
            {
                // RolesAdminEditViewModelの検証に成功

                // ロールを追加
                ApplicationRole role = new ApplicationRole() { Name = roleViewModel.Name };
                IdentityResult result = await RoleManager.CreateAsync(role);

                if (result.Succeeded)
                {
                    // ロールの追加に成功

                    // リダイレクト（一覧へ）
                    return RedirectToAction("Index", new { Message = EnumAdminMessageId.AddSuccess });
                }
                else
                {
                    // ロールの追加に失敗
                    ModelState.AddModelError("", result.Errors.First().Description);
                }
            }
            else
            {
                // RolesAdminEditViewModelの検証に失敗
            }

            // 再表示
            return View(roleViewModel);
        }

        #endregion

        #region Update

        /// <summary>
        /// ロール編集画面（初期表示）
        /// GET: /RolesAdmin/Edit/Admin
        /// </summary>
        /// <param name="id">string</param>
        /// <returns>ActionResultを非同期に返す</returns>
        [HttpGet]
        public async Task<ActionResult> Edit(string id)
        {
            await this.AuthorizeAsync();

            // 選択したロールを表示
            ApplicationRole role = await RoleManager.FindByIdAsync(id);

            RolesAdminEditViewModel roleModel = new RolesAdminEditViewModel
            {
                Id = role.Id,
                Name = role.Name
            };

            return View(roleModel);
        }

        /// <summary>
        /// ロール編集画面（更新処理）
        /// POST: /RolesAdmin/Edit/5
        /// </summary>
        /// <param name="roleModel">RolesAdminEditViewModel</param>
        /// <returns>ActionResultを非同期に返す</returns>
        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<ActionResult> Edit([Bind("Id,Name")] RolesAdminEditViewModel roleModel)
        {
            await this.AuthorizeAsync();

            // 選択したロールを更新
            if (ModelState.IsValid)
            {
                // RolesAdminEditViewModelの検証に成功

                // 選択したロールを取得
                ApplicationRole role = await RoleManager.FindByIdAsync(roleModel.Id);

                // 選択したロールを更新
                role.Name = roleModel.Name;
                IdentityResult result = await RoleManager.UpdateAsync(role);

                if (result.Succeeded)
                {
                    // 更新の成功

                    // リダイレクト（一覧へ）
                    return RedirectToAction("Index", new { Message = EnumAdminMessageId.EditSuccess });
                }
                else
                {
                    // 更新の失敗
                    ModelState.AddModelError("", result.Errors.First().Description);
                }
            }
            else
            {
                // RolesAdminEditViewModelの検証に失敗
            }

            // 再表示
            return View(roleModel);
        }

        #endregion

        #region Delete

        /// <summary>
        /// ロール削除画面（初期表示）
        /// GET: /RolesAdmin/Delete/5
        /// </summary>
        /// <param name="id">string</param>
        /// <returns>ActionResultを非同期に返す</returns>
        [HttpGet]
        public async Task<ActionResult> Delete(string id)
        {
            await this.AuthorizeAsync();

            // 選択したロールを表示
            ApplicationRole role = await RoleManager.FindByIdAsync(id);

            return View(role);
        }

        /// <summary>
        /// ロール削除画面（削除処理）
        /// POST: /RolesAdmin/Delete/5
        /// </summary>
        /// <param name="id">string</param>
        /// <param name="deleteUser">string</param>
        /// <returns>ActionResultを非同期に返す</returns>
        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<ActionResult> Delete(string id, string deleteUser)
        {
            await this.AuthorizeAsync();

            // 選択したロールを削除
            // ロールを取得して削除（少々冗長な気がするが）
            ApplicationRole role = await RoleManager.FindByIdAsync(id);
            IdentityResult result = await RoleManager.DeleteAsync(role);

            if (result.Succeeded)
            {
                // 削除の成功

                // リダイレクト（一覧へ）
                return RedirectToAction("Index", new { Message = EnumAdminMessageId.DeleteSuccess });
            }
            else
            {
                // 削除の失敗
                ModelState.AddModelError("", result.Errors.First().Description);
            }

            // 再表示
            return View(role);
        }

        #endregion

        #endregion
    }
}
