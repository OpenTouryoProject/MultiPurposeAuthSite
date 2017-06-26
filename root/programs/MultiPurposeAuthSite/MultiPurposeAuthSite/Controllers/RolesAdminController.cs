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
using System.Net.Http;

using Microsoft.Owin.Security;
using Microsoft.AspNet.Identity;
using Microsoft.AspNet.Identity.Owin;

using Touryo.Infrastructure.Business.Presentation;

/// <summary>MultiPurposeAuthSite.Controllers</summary>
namespace MultiPurposeAuthSite.Controllers
{
    /// <summary>UsersAdminController</summary>
    //[Authorize(Roles = ASPNETIdentityConst.Role_Admin)] // 切替可能な実装箇所に移動
    public class RolesAdminController : MyBaseMVController
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

                    if (roleName == ASPNETIdentityConst.Role_SystemAdmin) return;
                }

                // 認証されない。
                throw new SecurityException(Resources.AdminController.UnAuthorized);
            }
        }

        /// <summary>マルチテナント時の所有権を確認するユーティリティ・メソッド</summary>
        /// <param name="objParentId">string</param>
        /// <returns>所有権の有・無</returns>
        private async Task<bool> CheckOwnershipInMultitenantMode(string objParentId)
        {
            if (ASPNETIdentityConfig.MultiTenant)
            {
                // マルチテナントの場合、

                ApplicationUser adminUser = await UserManager.FindByIdAsync(User.Identity.GetUserId());
                IList<string> roles = await UserManager.GetRolesAsync(adminUser.Id);
                //if (adminUser.UserName == ASPNETIdentityConfig.AdministratorUID)
                if (CheckRole.IsSystemAdmin(roles))
                {
                    // 「既定の管理者ユーザ」の場合。
                }
                else
                {
                    // 「既定の管理者ユーザ」で無い場合、
                    // 配下のobjectかどうか、チェックをする。
                    return (objParentId == adminUser.Id);
                }
            }
            else
            {
                // マルチテナントでない場合。
            }

            return true;
        }

        #endregion

        #region constructor

        /// <summary>constructor</summary>
        public RolesAdminController() { }

        #endregion

        #region property (GetOwinContext)

        /// <summary>ApplicationUserManager</summary>
        public ApplicationUserManager UserManager
        {
            get
            {
                return HttpContext.GetOwinContext().GetUserManager<ApplicationUserManager>();
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
        /// ロール一覧表示画面
        /// GET: /RolesAdmin/Index
        /// </summary>
        /// <returns>ActionResult</returns>
        [HttpGet]
        public async Task<ActionResult> Index(EnumAdminMessageId? message)
        {
            // 色々な結果メッセージの設定
            ViewBag.StatusMessage =
                message == EnumAdminMessageId.DoNotHaveOwnershipOfTheObject ? Resources.AdminController.DoNotHaveOwnershipOfTheObject
                : message == EnumAdminMessageId.AddSuccess ? Resources.AdminController.AddSuccess
                : message == EnumAdminMessageId.Error ? Resources.AdminController.Error
                : message == EnumAdminMessageId.EditSuccess ? Resources.AdminController.EditSuccess
                : message == EnumAdminMessageId.DeleteSuccess ? Resources.AdminController.DeleteSuccess
                : "";

            this.Authorize();

            // マルチテナント化 : ASP.NET Identity上に分割キーを渡すI/Fが無いので已む無くSession。
            ApplicationUser user = await UserManager.FindByIdAsync(User.Identity.GetUserId());

            Session["ParentId"] = user.ParentId; // 分割キー
            Session["IsSystemAdmin"] = CheckRole.IsSystemAdmin(await UserManager.GetRolesAsync(user.Id)); // 「管理者ユーザ」か否か。
            //(user.UserName == ASPNETIdentityConfig.AdministratorUID); // 「既定の管理者ユーザ」か否か。

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
            this.Authorize();

            // ロールを取得
            ApplicationRole role = await RoleManager.FindByIdAsync(id);

            // マルチテナントの場合、所有権を確認する。
            if (await this.CheckOwnershipInMultitenantMode(role.ParentId))
            {
                // 配下のobjectである。
            }
            else
            {
                // 配下のobjectでない。
                // エラー → リダイレクト（一覧へ）
                return RedirectToAction("Index", new { Message = EnumAdminMessageId.DoNotHaveOwnershipOfTheObject });
            }

            // ロールに属するユーザを取得
            List<string> userNames = new List<string>();

            // マルチテナント化 : ASP.NET Identity上に分割キーを渡すI/Fが無いので已む無くSession。
            ApplicationUser temp = await UserManager.FindByIdAsync(User.Identity.GetUserId());

            Session["ParentId"] = temp.ParentId; // 分割キー
            Session["IsSystemAdmin"] = CheckRole.IsSystemAdmin(await UserManager.GetRolesAsync(temp.Id)); // 「管理者ユーザ」か否か。
            //(temp.UserName == ASPNETIdentityConfig.AdministratorUID); // 「既定の管理者ユーザ」か否か。

            foreach (ApplicationUser user in UserManager.Users.AsEnumerable())
            {
                //　ユーザがロールに属するかどうか。
                if (await UserManager.IsInRoleAsync(user.Id, role.Name))
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
        /// <returns>ActionResult</returns>
        [HttpGet]
        public ActionResult Create()
        {
            this.Authorize();
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
            this.Authorize();

            if (ModelState.IsValid)
            {
                // RolesAdminEditViewModelの検証に成功

                // テナントのロールを追加
                ApplicationUser user = await UserManager.FindByIdAsync(User.Identity.GetUserId());
                ApplicationRole role = ApplicationRole.CreateForIndividual(user, roleViewModel.Name);
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
                    ModelState.AddModelError("", result.Errors.First());
                }
            }
            else
            {
                // RolesAdminEditViewModelの検証に失敗
            }

            // 再表示
            return View();
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
            this.Authorize();

            // 選択したロールを表示
            ApplicationRole role = await RoleManager.FindByIdAsync(id);

            // マルチテナントの場合、所有権を確認する。
            if (await this.CheckOwnershipInMultitenantMode(role.ParentId))
            {
                // 配下のobjectである。
            }
            else
            {
                // 配下のobjectでない。
                // エラー → リダイレクト（一覧へ）
                return RedirectToAction("Index", new { Message = EnumAdminMessageId.DoNotHaveOwnershipOfTheObject });
            }

            RolesAdminEditViewModel roleModel = new RolesAdminEditViewModel
            {
                Id = role.Id,
                ParentId = role.ParentId,
                Name = role.Name
            };

            return View(roleModel);
        }

        /// <summary>
        /// ロール編集画面（更新処理）
        /// POST: /RolesAdmin/Edit/5
        /// </summary>
        /// <param name="roleModel"></param>
        /// <returns>ActionResultを非同期に返す</returns>
        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<ActionResult> Edit([Bind(Include = "Id,ParentId,Name")] RolesAdminEditViewModel roleModel)
        {
            this.Authorize();

            // 選択したロールを更新
            if (ModelState.IsValid)
            {
                // RolesAdminEditViewModelの検証に成功

                // 選択したロールを取得
                ApplicationRole role = await RoleManager.FindByIdAsync(roleModel.Id);

                // マルチテナントの場合、所有権を確認する。
                if (await this.CheckOwnershipInMultitenantMode(role.ParentId))
                {
                    // 配下のobjectである。
                }
                else
                {
                    // 配下のobjectでない。
                    // エラー → リダイレクト（一覧へ）
                    return RedirectToAction("Index", new { Message = EnumAdminMessageId.DoNotHaveOwnershipOfTheObject });
                }

                if (string.IsNullOrEmpty(role.ParentId))
                {
                    // グローバル ロールは更新しない。
                    // （ボタンを表示しないのでココには来ない）
                }
                else
                {
                    // 選択したテナント ロールを更新
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
                        ModelState.AddModelError("", result.Errors.First());
                    }
                }
            }
            else
            {
                // RoleViewModelの検証に失敗
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
            this.Authorize();

            // 選択したロールを表示
            ApplicationRole role = await RoleManager.FindByIdAsync(id);

            // マルチテナントの場合、所有権を確認する。
            if (await this.CheckOwnershipInMultitenantMode(role.ParentId))
            {
                // 配下のobjectである。
            }
            else
            {
                // 配下のobjectでない。
                // エラー → リダイレクト（一覧へ）
                return RedirectToAction("Index", new { Message = EnumAdminMessageId.DoNotHaveOwnershipOfTheObject });
            }

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
            this.Authorize();

            // 選択したロールを削除
            // ロールを取得して削除（少々冗長な気がするが）
            ApplicationRole role = await RoleManager.FindByIdAsync(id);

            // マルチテナントの場合、所有権を確認する。
            if (await this.CheckOwnershipInMultitenantMode(role.ParentId))
            {
                // 配下のobjectである。
            }
            else
            {
                // 配下のobjectでない。
                // エラー → リダイレクト（一覧へ）
                return RedirectToAction("Index", new { Message = EnumAdminMessageId.DoNotHaveOwnershipOfTheObject });
            }

            if (string.IsNullOrEmpty(role.ParentId))
            {
                // グローバル ロールは削除しない。
                // （ボタンを表示しないのでココには来ない）
            }
            else
            {
                // 選択したテナント ロールを削除
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
                    ModelState.AddModelError("", result.Errors.First());
                }
            }

            // 再表示
            return View();
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
