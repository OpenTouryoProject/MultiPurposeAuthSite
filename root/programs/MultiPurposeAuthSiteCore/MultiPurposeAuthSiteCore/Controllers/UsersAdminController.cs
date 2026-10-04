//**********************************************************************************
//* テンプレート
//**********************************************************************************

// 以下のLicenseに従い、このProjectをTemplateとして使用可能です。Release時にCopyright表示してSublicenseして下さい。
// https://github.com/OpenTouryoProject/MultiPurposeAuthSite/blob/master/license/LicenseForTemplates.txt

//**********************************************************************************
//* クラス名        ：UsersAdminController
//* クラス日本語名  ：UsersAdminのController（テンプレート）
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

using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.Rendering;

using Touryo.Infrastructure.Business.Presentation;

/// <summary>MultiPurposeAuthSite.Controllers</summary>
namespace MultiPurposeAuthSite.Controllers
{
    /// <summary>UsersAdminController</summary>
    /// <remarks>
    /// **net48 版からの移植**（#258）。**画面と導線は net48 版と同じ**にしてある。
    ///
    /// **Identity の API が違うところだけを読み替えた。**
    ///
    /// | | net48（Identity 2.x） | ここ（Identity Core） |
    /// |---|---|---|
    /// | 利用者 | `User.Identity.GetUserId()` | `UserManager.GetUserAsync(User)` |
    /// | ロール | `GetRolesAsync(user.Id)` | `GetRolesAsync(user)` |
    /// | エラー | `result.Errors.First()`（`string`） | `IdentityError.Description` |
    /// | 検索条件 | `Session["..."]` | `HttpContext.Session.SetString(...)` |
    /// </remarks>
    //[Authorize(Roles = Const.Role_Admin)] // 切替可能な実装箇所に移動
    public class UsersAdminController : MyBaseMVControllerCore
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
        public UsersAdminController(
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

        /// <summary>利用可能なロールのみを返す。</summary>
        /// <returns>利用可能なロールの一覧</returns>
        private List<ApplicationRole> GetSelectableRoles()
        {
            List<ApplicationRole> selectableRoles = new List<ApplicationRole>();

            foreach (ApplicationRole role in RoleManager.Roles)
            {
                selectableRoles.Add(role);
            }

            return selectableRoles;
        }

        #endregion

        #region Action Method

        #region Reference

        /// <summary>
        /// ユーザ一覧表示画面
        /// GET: /UsersAdmin/Index
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

            // ユーザ一覧表示
            // Usersへのアクセスを非同期化出来ず
            UsersAdminSearchViewModel model = new UsersAdminSearchViewModel
            {
                UserNameforSearch = "",
                Users = UserManager.Users.AsEnumerable()
            };

            return View(model);
        }

        /// <summary>
        /// ユーザ一覧表示画面
        /// POST: /UsersAdmin/List
        /// </summary>
        /// <param name="model">UsersAdminSearchViewModel</param>
        /// <returns>ActionResultを非同期に返す</returns>
        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<ActionResult> List(UsersAdminSearchViewModel model)
        {
            await this.AuthorizeAsync();

            // ユーザ一覧表示
            // ASP.NET Identity上に検索条件を渡すI/Fが無いので已む無くSession。
            HttpContext.Session.SetString(
                "SearchConditionOfUsers", model.UserNameforSearch ?? ""); // ユーザ一覧の検索条件

            // Usersへのアクセスを非同期化出来ず
            model.Users = UserManager.Users.AsEnumerable();

            return View("Index", model);
        }

        /// <summary>
        /// ユーザ詳細表示画面
        /// GET: /UsersAdmin/Details/5
        /// </summary>
        /// <param name="id">string</param>
        /// <returns>ActionResultを非同期に返す</returns>
        [HttpGet]
        public async Task<ActionResult> Details(string id)
        {
            await this.AuthorizeAsync();

            // ユーザの取得
            ApplicationUser user = await UserManager.FindByIdAsync(id);

            // ユーザ詳細表示
            //   **配列で渡す**（ビューが Length で件数を見るため）。
            ViewBag.RoleNames = (await UserManager.GetRolesAsync(user)).ToArray();
            return View(user);
        }

        #endregion

        #region Create

        /// <summary>
        /// ユーザ登録画面（初期表示）
        /// GET: /UsersAdmin/Create
        /// </summary>
        /// <returns>ActionResultを非同期に返す</returns>
        [HttpGet]
        public async Task<ActionResult> Create()
        {
            await this.AuthorizeAsync();

            ViewBag.RoleId = new SelectList(this.GetSelectableRoles(), "Name", "Name");

            return View();
        }

        /// <summary>
        /// ユーザ登録画面（登録処理）
        /// POST: /UsersAdmin/Create
        /// </summary>
        /// <param name="userViewModel">AccountRegisterViewModel</param>
        /// <param name="selectedRoles">string[]</param>
        /// <returns>ActionResultを非同期に返す</returns>
        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<ActionResult> Create(
            AccountRegisterViewModel userViewModel, params string[] selectedRoles)
        {
            await this.AuthorizeAsync();

            if (ModelState.IsValid)
            {
                // AccountRegisterViewModelの検証に成功

                // 作成されたユーザ
                ApplicationUser user = null;

                // （一般）ユーザを作成
                //   **利用者名とメアドの両方を渡す**（#151 の段階 3）。
                //   **利用者名に `@` は使えない**（サインインの入力がどちらなのか決まらなくなる）。
                if (!Const.IsValidUserName(userViewModel.Name))
                {
                    ModelState.AddModelError("", Resources.AccountController.Register_InvalidUserName);

                    // **この画面は ViewBag.RoleId を使う。** 詰めずに返すとビューで落ちる。
                    //   dataValueField, dataTextField = "Name"
                    ViewBag.RoleId = new SelectList(this.GetSelectableRoles(), "Name", "Name");

                    // 再表示（入力値は残す）
                    return View(userViewModel);
                }

                user = ApplicationUser.CreateUser(
                    userViewModel.Name, userViewModel.Email, true);

                // UserManagerのCreateAsync
                IdentityResult userResult = await UserManager.CreateAsync(
                        user,
                        userViewModel.Password // Passwordはハッシュ化される。
                    );

                if (userResult.Succeeded)
                {
                    // ユーザ登録の成功

                    // ロールの確認
                    if (selectedRoles != null)
                    {
                        // ロールがある

                        // ロールの登録
                        IdentityResult rolesResult = await UserManager.AddToRolesAsync(user, selectedRoles);

                        if (rolesResult.Succeeded)
                        {
                            // ロール登録の成功

                            // リダイレクト（一覧へ）
                            return RedirectToAction("Index", new { Message = EnumAdminMessageId.AddSuccess });
                        }
                        else
                        {
                            // ロール登録の失敗
                            ModelState.AddModelError("", rolesResult.Errors.First().Description);
                        }
                    }
                    else
                    {
                        // ロールがない
                    }
                }
                else
                {
                    // ユーザ登録の失敗
                    ModelState.AddModelError("", userResult.Errors.First().Description);
                }
            }
            else
            {
                // AccountRegisterViewModelの検証に失敗
            }

            // dataValueField, dataTextField = "Name"
            ViewBag.RoleId = new SelectList(this.GetSelectableRoles(), "Name", "Name");

            // 再表示
            return View(userViewModel);
        }

        #endregion

        #region Update

        /// <summary>
        /// ユーザ編集画面（初期表示）
        /// GET: /UsersAdmin/Edit/1
        /// </summary>
        /// <param name="id">string</param>
        /// <returns>ActionResultを非同期に返す</returns>
        [HttpGet]
        public async Task<ActionResult> Edit(string id)
        {
            await this.AuthorizeAsync();

            // 選択したユーザを表示

            // ユーザとロールの情報を取得
            ApplicationUser user = await UserManager.FindByIdAsync(id);

            // ユーザとロールの情報を表示
            return View(await this.CreateEditViewModelAsync(user));
        }

        /// <summary>
        /// ユーザ編集画面（更新処理）
        /// POST: /UsersAdmin/Edit/5
        /// </summary>
        /// <param name="editUser">UsersAdminEditViewModel</param>
        /// <param name="selectedRole">string[]</param>
        /// <returns>ActionResultを非同期に返す</returns>
        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<ActionResult> Edit(
            [Bind("Id,Name,Email")] UsersAdminEditViewModel editUser, params string[] selectedRole)
        {
            await this.AuthorizeAsync();

            IdentityResult result = null;

            // 選択したユーザを更新
            if (ModelState.IsValid)
            {
                // UsersAdminEditViewModelの検証に成功

                #region ユーザーの更新

                ApplicationUser user = await UserManager.FindByIdAsync(editUser.Id);

                // 編集結果を反映
                //   **利用者名とメアドを、それぞれ反映する**（#151 の段階 3）。
                //   **ここで return しない。**
                //   この画面は RolesList を持つモデルを要するので、
                //   **下の「再表示」に落として、そこで作らせる**（詰めずに返すとビューで落ちる）。
                bool userNameIsValid = Const.IsValidUserName(editUser.Name);

                if (!userNameIsValid)
                {
                    ModelState.AddModelError("", Resources.AccountController.Register_InvalidUserName);
                }
                else
                {
                    user.UserName = editUser.Name;
                    user.Email = editUser.Email;
                }

                // ユーザーの更新
                if (!userNameIsValid || string.IsNullOrWhiteSpace(user.UserName))
                {
                    // 入力値が無い（または利用者名が不正な）ので更新しない。
                }
                else
                {
                    // 入力値で更新する。
                    result = await UserManager.UpdateAsync(user);

                    if (result.Succeeded)
                    {
                        #region ロールの更新

                        IList<string> roles = await UserManager.GetRolesAsync(user);

                        //?? : nullだったら右
                        selectedRole = selectedRole ?? new string[] { };

                        // ロールの削除
                        // selectedRoleに含まれないroleNameは削除対象。
                        result = await UserManager.RemoveFromRolesAsync(
                            user, roles.Except(selectedRole).ToArray<string>());

                        if (result.Succeeded)
                        {
                            // ロールの削除の成功

                            // ロールの追加
                            string[] selectedRoles = selectedRole.Except(roles).ToArray<string>();
                            result = await UserManager.AddToRolesAsync(user, selectedRoles);

                            if (result.Succeeded)
                            {
                                // ロールの追加の成功

                                // リダイレクト（一覧へ）
                                return RedirectToAction("Index", new { Message = EnumAdminMessageId.EditSuccess });
                            }
                            else
                            {
                                // ロールの追加の失敗
                                ModelState.AddModelError("", result.Errors.First().Description);
                            }
                        }
                        else
                        {
                            // ロールの削除の失敗
                            ModelState.AddModelError("", result.Errors.First().Description);
                        }

                        #endregion
                    }
                }

                // 再表示
                return View(await this.CreateEditViewModelAsync(user));

                #endregion
            }
            else
            {
                // UsersAdminEditViewModelの検証に失敗
                ModelState.AddModelError("", "Something failed.");
            }

            // 再表示
            // リダイレクト（編集へ）
            return RedirectToAction("Edit", new { id = editUser.Id });
        }

        /// <summary>編集画面のモデルを作る（「選択可能なロール」に「現在のロール」のチェックを入れる）</summary>
        /// <param name="user">ApplicationUser</param>
        /// <returns>UsersAdminEditViewModel</returns>
        private async Task<UsersAdminEditViewModel> CreateEditViewModelAsync(ApplicationUser user)
        {
            List<ApplicationRole> selectableRoles = this.GetSelectableRoles();
            IList<string> usersRoles = await UserManager.GetRolesAsync(user);

            return new UsersAdminEditViewModel()
            {
                Id = user.Id,

                Name = user.UserName,
                Email = user.Email,

                RolesList = selectableRoles.Select(
                    x => new SelectListItem()
                    {
                        Selected = usersRoles.Contains(x.Name),
                        Text = x.Name,
                        Value = x.Name
                    })
            };
        }

        #endregion

        #region Delete

        /// <summary>
        /// ユーザ削除画面（初期表示）
        /// GET: /UsersAdmin/Delete/5
        /// </summary>
        /// <param name="id">string</param>
        /// <returns>ActionResultを非同期に返す</returns>
        [HttpGet]
        public async Task<ActionResult> Delete(string id)
        {
            await this.AuthorizeAsync();

            // 選択したユーザを表示
            ApplicationUser user = await UserManager.FindByIdAsync(id);

            return View(user);
        }

        /// <summary>
        /// ユーザ削除画面（削除処理）
        /// POST: /UsersAdmin/Delete/5
        /// </summary>
        /// <param name="id">string</param>
        /// <returns>ActionResultを非同期に返す</returns>
        [HttpPost]
        [ValidateAntiForgeryToken]
        [ActionName("Delete")]
        public async Task<ActionResult> DeleteConfirmed(string id)
        {
            await this.AuthorizeAsync();

            // 選択したユーザを削除

            // ユーザを取得して削除（少々冗長な気がするが）
            ApplicationUser user = await UserManager.FindByIdAsync(id);
            IdentityResult result = await UserManager.DeleteAsync(user);

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

                // 再表示
                return View(user);
            }
        }

        #endregion

        #endregion
    }
}
