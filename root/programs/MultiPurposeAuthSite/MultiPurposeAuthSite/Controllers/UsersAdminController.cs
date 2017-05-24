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
    //[Authorize(Roles = ASPNETIdentityConst.Role_Admin)]
    public class UsersAdminController : MyBaseMVController
    {
        /// <summary>
        /// [Authorize(Roles = ASPNETIdentityConst.Role_Admin)]の代替
        /// ※ constructorでは動かないので、このように実装することになった。
        /// </summary>
        private void Authorize()
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
                foreach (string roleName in roles)
                {
                    if (ASPNETIdentityConfig.MultiTenant)
                    {
                        if (roleName == ASPNETIdentityConst.Role_Admin) return;
                    }
                    else
                    {
                        if (roleName == ASPNETIdentityConst.Role_SystemAdmin) return;
                    }
                }

                // 認証されない。
                throw new SecurityException(Resources.AdminController.UnAuthorized);
            }
        }

        #region constructor

        /// <summary>constructor</summary>
        public UsersAdminController() { }

        #endregion

        #region property (GetOwinContext)

        /// <summary>ApplicationUserManager</summary>
        public ApplicationUserManager UserManager
        {
            get
            {
                return　HttpContext.GetOwinContext().GetUserManager<ApplicationUserManager>();
            }
        }

        /// <summary>ApplicationRoleManager</summary>
        public ApplicationRoleManager RoleManager
        {
            get
            {
                return HttpContext.GetOwinContext().GetUserManager<ApplicationRoleManager>();
            }
        }

        /// <summary>ApplicationSignInManager</summary>
        public ApplicationSignInManager SignInManager
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
        public async Task<ActionResult> Index()
        {
            this.Authorize();

            // ユーザ一覧表示

            // マルチテナント化 : ASP.NET Identity上に分割キーを渡すI/Fが無いので已む無くSession。
            ApplicationUser user = await UserManager.FindByIdAsync(User.Identity.GetUserId());
            Session["CurrentUserId"] = user.Id; // 分割キー

            // Usersへのアクセスを非同期化出来ず
            UsersAdminSearchViewModel model = new UsersAdminSearchViewModel();
            model.UserNameforSearch = "";
            model.Users = UserManager.Users.AsEnumerable();
            
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
            Session["CurrentUserId"] = user.Id; // 分割キー
            Session["SearchConditionOfUsers"] = model.UserNameforSearch; // ユーザ一覧の検索条件

            // Usersへのアクセスを非同期化出来ず
            //model.UserNameforSearch = "";
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

            //Get the list of Roles
            //ViewBag.RoleId = new SelectList(await RoleManager.Roles.ToListAsync(), "Name", "Name");

            // Rolesへのアクセスを非同期化出来ず ( dataValueField, dataTextField = "Name" )
            ViewBag.RoleId = new SelectList(RoleManager.Roles, "Name", "Name");

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
                ApplicationUser user = await UserManager.FindByIdAsync(User.Identity.GetUserId());
                // （一般）ユーザを作成
                user = await ApplicationUser.CreateByRegister(user.Id, userViewModel.Email);

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
                            return RedirectToAction("Index");
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
            IList<string> roles = await UserManager.GetRolesAsync(user.Id);

            // ユーザとロールの情報を表示
            return View(new UsersAdminEditViewModel()
            {
                Id = user.Id,
                ParentId = user.ParentId,

                Email = user.Email,
                RolesList = RoleManager.Roles.ToList().Select(
                    x => new SelectListItem()
                    {
                        Selected = roles.Contains(x.Name),
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
            [Bind(Include = "Email,Id")] UsersAdminEditViewModel editUser, params string[] selectedRole)
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
                if (user.Id == user.ParentId)
                {
                    // サインアップした管理者ユーザ
                    //UserName & Emailは変更不可能。
                }
                else
                {
                    // 上記以外のユーザの編集は可能
                    user.UserName = editUser.Email;
                    user.Email = editUser.Email;

                    // ユーザーの更新
                    result = await UserManager.UpdateAsync(user);
                }

                #endregion

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
                    result = await UserManager.AddToRolesAsync(
                        user.Id, selectedRole.Except(roles).ToArray<string>());

                    if (result.Succeeded)
                    {
                        // ロールの追加の成功

                        // リダイレクト（一覧へ）
                        return RedirectToAction("Index");
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
            else
            {
                // UsersAdminEditViewModelの検証に失敗
                ModelState.AddModelError("", "Something failed.");
            }

            // 再表示
            return View();
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
            this.Authorize();

            // 選択したユーザを削除

            // ユーザを取得して削除（少々冗長な気がするが）
            ApplicationUser user = await UserManager.FindByIdAsync(id);

            if (user.Id == user.ParentId)
            {
                // サインアップした管理者ユーザは、削除不可能。
                // （ボタンを表示しないのでココには来ない）

                // リダイレクト（一覧へ）
                return RedirectToAction("Index");
            }
            else
            {
                IdentityResult result = await UserManager.DeleteAsync(user);

                if (result.Succeeded)
                {
                    // 削除の成功

                    // リダイレクト（一覧へ）
                    return RedirectToAction("Index");
                }
                else
                {
                    // 削除の失敗
                    ModelState.AddModelError("", result.Errors.First());

                    // 再表示
                    return View();
                }
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
