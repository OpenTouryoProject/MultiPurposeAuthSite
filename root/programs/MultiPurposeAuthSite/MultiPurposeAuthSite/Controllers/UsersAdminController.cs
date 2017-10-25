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
//*  2017/04/24  西野 大介         新規
//**********************************************************************************

using MultiPurposeAuthSite.Models.ViewModels;
using MultiPurposeAuthSite.Models.ASPNETIdentity;
using MultiPurposeAuthSite.Models.ASPNETIdentity.Util;
using MultiPurposeAuthSite.Models.ASPNETIdentity.Manager;
using MultiPurposeAuthSite.Models.ASPNETIdentity.Entity;

using System.Linq;
using System.Collections.Generic;
using System.Threading.Tasks;
using System.Security;

using System.Web;
using System.Web.Mvc;

using Microsoft.Owin.Security;
using Microsoft.AspNet.Identity;
using Microsoft.AspNet.Identity.Owin;

using Touryo.Infrastructure.Business.Presentation;

/// <summary>MultiPurposeAuthSite.Controllers</summary>
namespace MultiPurposeAuthSite.Controllers
{
    /// <summary>UsersAdminController</summary>
    //[Authorize(Roles = ASPNETIdentityConst.Role_Admin)] // 切替可能な実装箇所に移動
    public class UsersAdminController : MyBaseMVController
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

        #region 認証・認可系

        /// <summary>
        /// [Authorize(Roles = ASPNETIdentityConst.Role_Admin)]の代替
        /// ※ constructorでは動かないので、このように実装することになった。
        /// </summary>
        private void Authorize()
        {
            if (ASPNETIdentityConfig.EnableAdministrationOfUsersAndRoles)
            {
                string uid = User.Identity.GetUserId();

                if (string.IsNullOrEmpty(uid))
                {
                    // 未認証
                    throw new SecurityException(Resources.AdminController.UnAuthenticate);
                }
                else
                {
                    IList<string> roles = UserManager.GetRoles(User.Identity.GetUserId());
                    if (roles.Any(x => x == ASPNETIdentityConst.Role_SystemAdmin))
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

        #region constructor

        /// <summary>constructor</summary>
        public UsersAdminController() { }

        #endregion

        #region property (GetOwinContext)

        /// <summary>ApplicationUserManager</summary>
        private ApplicationUserManager UserManager
        {
            get
            {
                return HttpContext.GetOwinContext().GetUserManager<ApplicationUserManager>();
            }
        }

        /// <summary>ApplicationRoleManager</summary>
        private ApplicationRoleManager RoleManager
        {
            get
            {
                return HttpContext.GetOwinContext().GetUserManager<ApplicationRoleManager>();
            }
        }

        /// <summary>ApplicationSignInManager</summary>
        private ApplicationSignInManager SignInManager
        {
            get
            {
                return HttpContext.GetOwinContext().Get<ApplicationSignInManager>();
            }
        }

        /// <summary>AuthenticationManager</summary>
        private IAuthenticationManager AuthenticationManager
        {
            get
            {
                return HttpContext.GetOwinContext().Authentication;
            }
        }

        #endregion

        #region Action Method

        #region Reference

        /// <summary>
        /// ユーザ一覧表示画面
        /// GET: /UsersAdmin/Index
        /// </summary>
        /// <returns>ActionResult</returns>
        [HttpGet]
        public async Task<ActionResult> Index(EnumAdminMessageId? message)
        {
            this.Authorize();

            // 色々な結果メッセージの設定
            ViewBag.StatusMessage =
                message == EnumAdminMessageId.DoNotHaveOwnershipOfTheObject ? Resources.AdminController.DoNotHaveOwnershipOfTheObject
                : message == EnumAdminMessageId.AddSuccess ? Resources.AdminController.AddSuccess
                : message == EnumAdminMessageId.Error ? Resources.AdminController.Error
                : message == EnumAdminMessageId.EditSuccess ? Resources.AdminController.EditSuccess
                : message == EnumAdminMessageId.DeleteSuccess ? Resources.AdminController.DeleteSuccess
                : "";

            // ユーザ一覧表示
            // マルチテナント化 : ASP.NET Identity上に分割キーを渡すI/Fが無いので已む無くSession。
            ApplicationUser user = await UserManager.FindByIdAsync(User.Identity.GetUserId());
            
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
        /// GET: /UsersAdmin/List
        /// </summary>
        /// <returns>ActionResult</returns>
        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<ActionResult> List(UsersAdminSearchViewModel model)
        {
            this.Authorize();

            // ユーザ一覧表示
            // マルチテナント化 : ASP.NET Identity上に分割キーを渡すI/Fが無いので已む無くSession。
            ApplicationUser user = await UserManager.FindByIdAsync(User.Identity.GetUserId());
            
            Session["SearchConditionOfUsers"] = model.UserNameforSearch; // ユーザ一覧の検索条件

            // Usersへのアクセスを非同期化出来ず
            model.Users = UserManager.Users.AsEnumerable();

            return View("Index", model);
        }

        /// <summary>
        /// ユーザ詳細表示画面
        /// GET: /UsersAdmin/Details/5
        /// </summary>
        /// <param name="id">string</param>
        /// <returns>>ActionResultを非同期に返す</returns>
        [HttpGet]
        public async Task<ActionResult> Details(string id)
        {
            this.Authorize();

            // ユーザの取得
            ApplicationUser user = await UserManager.FindByIdAsync(id);
            
            // ユーザ詳細表示
            ViewBag.RoleNames = await UserManager.GetRolesAsync(user.Id);
            return View(user);
        }

        #endregion

        #region Create

        /// <summary>
        /// ユーザ登録画面（初期表示）
        /// GET: /UsersAdmin/Create
        /// </summary>
        /// <returns>ActionResult</returns>
        [HttpGet]
        public ActionResult Create()
        {
            this.Authorize();

            ViewBag.RoleId = new SelectList(this.GetSelectableRoles(), "Name", "Name");

            return View();
        }

        /// <summary>
        /// ユーザ登録画面（登録処理）
        /// POST: /UsersAdmin/Create
        /// </summary>
        /// <param name="userViewModel">RegisterViewModel</param>
        /// <param name="selectedRoles">string[]</param>
        /// <returns>ActionResultを非同期に返す</returns>
        [HttpPost]
        [ValidateAntiForgeryToken] // 追加
        public async Task<ActionResult> Create(
            AccountRegisterViewModel userViewModel, params string[] selectedRoles)
        {
            this.Authorize();

            if (ModelState.IsValid)
            {
                // RegisterViewModelの検証に成功

                // 認証された（管理者）ユーザを取得
                ApplicationUser adminUser = await UserManager.FindByIdAsync(User.Identity.GetUserId());

                // 作成されたユーザ
                ApplicationUser user = null;

                // （一般）ユーザを作成
                if (ASPNETIdentityConfig.RequireUniqueEmail)
                {
                    // userViewModel.Emailはチェック済み。
                    user = ApplicationUser.CreateByRegister(userViewModel.Email);
                }
                else
                {
                    // userViewModel.Nameのカスタムのチェック処理は必要か？
                    user = ApplicationUser.CreateByRegister(userViewModel.Name);
                }

                // ApplicationUserManagerのCreateAsync
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
                        IdentityResult rolesResult = await UserManager.AddToRolesAsync(user.Id, selectedRoles);

                        if (rolesResult.Succeeded)
                        {
                            // ロール登録の成功

                            // リダイレクト（一覧へ）
                            return RedirectToAction("Index", new { Message = EnumAdminMessageId.AddSuccess });
                        }
                        else
                        {
                            // ロール登録の失敗
                            ModelState.AddModelError("", rolesResult.Errors.First());
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
                    ModelState.AddModelError("", userResult.Errors.First());
                }
            }
            else
            {
                // RegisterViewModelの検証に失敗
            }

            // dataValueField, dataTextField = "Name"
            ViewBag.RoleId = new SelectList(RoleManager.Roles, "Name", "Name");

            // 再表示
            return View();
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
            this.Authorize();

            // 選択したユーザを表示

            // ユーザとロールの情報を取得
            ApplicationUser user = await UserManager.FindByIdAsync(id);
            
            // 「選択可能なロール」に「現在のロール」のチェックを入れる。
            List<ApplicationRole> selectableRoles = this.GetSelectableRoles();
            IList<string> usersRoles = await UserManager.GetRolesAsync(user.Id);

            // ユーザとロールの情報を表示
            return View(new UsersAdminEditViewModel()
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
            });
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
            [Bind(Include = "Id,Name,Email")] UsersAdminEditViewModel editUser, params string[] selectedRole)
        {
            this.Authorize();

            IdentityResult result = null;

            // 選択したユーザを更新
            if (ModelState.IsValid)
            {
                // UsersAdminEditViewModelの検証に成功

                #region ユーザーの更新

                ApplicationUser user = await UserManager.FindByIdAsync(editUser.Id);                

                // 編集結果を反映
                if (ASPNETIdentityConfig.RequireUniqueEmail)
                {
                    // userViewModel.Emailはチェック済み。
                    user.UserName = editUser.Email;
                    user.Email = editUser.Email;
                }
                else
                {
                    // userViewModel.Nameのカスタムのチェック処理は必要か？
                    user.UserName = editUser.Name;
                }

                // ユーザーの更新
                if (string.IsNullOrEmpty(user.UserName))
                {
                    // 入力値が無いので更新しない。
                }
                else
                {
                    // 入力値で更新する。
                    result = await UserManager.UpdateAsync(user);

                    if (result.Succeeded)
                    {
                        #region ロールの更新

                        IList<string> roles = await UserManager.GetRolesAsync(user.Id);

                        //?? : nullだったら右
                        selectedRole = selectedRole ?? new string[] { };

                        // ロールの削除
                        // selectedRoleに含まれないroleNameは削除対象。
                        result = await UserManager.RemoveFromRolesAsync(
                            user.Id, roles.Except(selectedRole).ToArray<string>());

                        if (result.Succeeded)
                        {
                            // ロールの削除の成功

                            // ロールの追加
                            string[] selectedRoles = selectedRole.Except(roles).ToArray<string>();
                            result = await UserManager.AddToRolesAsync(user.Id, selectedRoles);

                            if (result.Succeeded)
                            {
                                // ロールの追加の成功

                                // リダイレクト（一覧へ）
                                return RedirectToAction("Index", new { Message = EnumAdminMessageId.EditSuccess });
                            }
                            else
                            {
                                // ロールの追加の失敗
                                ModelState.AddModelError("", result.Errors.First());
                            }
                        }
                        else
                        {
                            // ロールの削除の失敗
                            ModelState.AddModelError("", result.Errors.First());
                        }

                        #endregion
                    }
                }
                

                // 再表示
                // 「選択可能なロール」に「現在のロール」のチェックを入れる。
                List<ApplicationRole> selectableRoles = this.GetSelectableRoles();
                IList<string> usersRoles = await UserManager.GetRolesAsync(user.Id);

                return View(new UsersAdminEditViewModel()
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
                });

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

        #endregion

        #region Delete

        /// <summary>
        /// ユーザ削除画面（初期表示）
        /// GET: /UsersAdmin/Delete/5
        /// </summary>
        /// <param name="id"></param>
        /// <returns>ActionResultを非同期に返す</returns>
        [HttpGet]
        public async Task<ActionResult> Delete(string id)
        {
            this.Authorize();

            // 選択したユーザを示表
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
            this.Authorize();

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
                ModelState.AddModelError("", result.Errors.First());

                // 再表示
                return View();
            }
        }

        #endregion

        #endregion

        #region Dispose

        /// <summary>Dispose</summary>
        /// <param name="disposing">bool</param>
        protected override void Dispose(bool disposing)
        {
            // メンバのdisposingを実装しているらしい。
            if (disposing)
            {
            }

            base.Dispose(disposing);
        }

        #endregion
    }
}