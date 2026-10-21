//**********************************************************************************
//* テンプレート
//**********************************************************************************

// 以下のLicenseに従い、このProjectをTemplateとして使用可能です。Release時にCopyright表示してSublicenseして下さい。
// https://github.com/OpenTouryoProject/MultiPurposeAuthSite/blob/master/license/LicenseForTemplates.txt

//**********************************************************************************
//* クラス名        ：SoftwareStatementAdminController
//* クラス日本語名  ：software_statement の発行者（ベンダ）の管理画面
//*
//* 作成日時        ：－
//* 作成者          ：－
//* 更新履歴        ：－
//*
//*  日時        更新者            内容
//*  ----------  ----------------  -------------------------------------------------
//*  2026/10/21  玄人 幸道         新規（#308 の段階 2）
//**********************************************************************************

using MultiPurposeAuthSite.Co;
using MultiPurposeAuthSite.Extensions.Sts;
using MultiPurposeAuthSite.Log;
using MultiPurposeAuthSite.ViewModels;

using MultiPurposeAuthSite.Entity;
using MultiPurposeAuthSite.Manager;

using System.Collections.Generic;
using System.Linq;
using System.Security;
using System.Web;
using System.Web.Mvc;

using Microsoft.AspNet.Identity;
using Microsoft.AspNet.Identity.Owin;

using Touryo.Infrastructure.Business.Presentation;

namespace MultiPurposeAuthSite.Controllers
{
    /// <summary>
    /// `software_statement` の発行者（ベンダ）の管理画面（#308 の段階 2）
    /// </summary>
    /// <remarks>
    /// **「どのベンダを信じ、どこまで任せるか」の台帳**である。
    /// **クライアントの登録ではない** — **あちらは `Saml2OAuth2Data`** で、
    /// **`Manage/Saml2OAuth2DataList` が編むのは「その利用者の分」**である。
    /// **発行者は配備全体の決め**なので、**`UsersAdmin` / `RolesAdmin` / `IdFederationAdmin`
    /// と同じ位置**に置いた。
    ///
    /// **認可も同じ**（`EnableAdministrationOfUsersAndRoles` ＋ `SystemAdmin`）。
    ///
    /// | | |
    /// |---|---|
    /// | 読む先 | **設定 → user store の順**（`Co.SoftwareStatementIssuers`。**同じ鍵は設定が勝つ**） |
    /// | **この画面が編むのは user store の行だけ** | **設定ファイルの行は、ここからは触れない** |
    ///
    /// **暗号化する列は無い**（**公開鍵と上限だけ**。#297 の対象外）。
    /// **`.cer` はファイルで置く**（`CerFilePath`）**か、本文を貼る**（`CerBody`）。
    /// **アップロードの口は作っていない** — **サーバにファイルを書く口を増やさない**ためである。
    /// </remarks>
    [Authorize]
    public class SoftwareStatementAdminController : MyBaseMVController
    {
        /// <summary>列挙型</summary>
        public enum EnumAdminMessageId
        {
            /// <summary>AddSuccess</summary>
            AddSuccess,
            /// <summary>EditSuccess</summary>
            EditSuccess,
            /// <summary>DeleteSuccess</summary>
            DeleteSuccess,
            /// <summary>Error</summary>
            Error
        }

        #region constructor & property

        /// <summary>constructor</summary>
        public SoftwareStatementAdminController() { }

        /// <summary>ApplicationUserManager</summary>
        private ApplicationUserManager UserManager
        {
            get
            {
                return HttpContext.GetOwinContext().GetUserManager<ApplicationUserManager>();
            }
        }

        #endregion

        #region 認証・認可系

        /// <summary>
        /// [Authorize(Roles = Const.Role_Admin)]の代替
        /// ※ constructorでは動かないので、このように実装することになった。
        /// </summary>
        /// <remarks>**`IdFederationAdminController.Authorize` と同じ**（#308 の段階 2）。</remarks>
        private void Authorize()
        {
            if (Config.EnableAdministrationOfUsersAndRoles)
            {
                string uid = User.Identity.GetUserId();

                if (string.IsNullOrWhiteSpace(uid))
                {
                    // 未認証
                    throw new SecurityException(Resources.AdminController.UnAuthenticate);
                }
                else
                {
                    IList<string> roles = UserManager.GetRoles(uid);

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
        /// 発行者の一覧表示画面
        /// GET: /SoftwareStatementAdmin/Index
        /// </summary>
        /// <param name="message">EnumAdminMessageId?</param>
        /// <returns>ActionResultを返す</returns>
        [HttpGet]
        public ActionResult Index(EnumAdminMessageId? message)
        {
            this.Authorize();

            // 色々な結果メッセージの設定
            ViewBag.StatusMessage =
                message == EnumAdminMessageId.AddSuccess ? Resources.AdminController.AddSuccess
                : message == EnumAdminMessageId.EditSuccess ? Resources.AdminController.EditSuccess
                : message == EnumAdminMessageId.DeleteSuccess ? Resources.AdminController.DeleteSuccess
                : message == EnumAdminMessageId.Error ? Resources.AdminController.Error
                : "";

            return View(SoftwareStatementIssuerProvider.GetAll());
        }

        #endregion

        #region Create

        /// <summary>
        /// 発行者の追加画面（初期表示）
        /// GET: /SoftwareStatementAdmin/Create
        /// </summary>
        /// <returns>ActionResultを返す</returns>
        [HttpGet]
        public ActionResult Create()
        {
            this.Authorize();

            //  **既定は有効 ＋ RS256**（**よく足す方を既定にする**）。
            return View(new SoftwareStatementIssuerViewModel()
            {
                Enabled = true,
                Alg = SoftwareStatementIssuers.DefaultAlg
            });
        }

        /// <summary>
        /// 発行者の追加画面（追加）
        /// POST: /SoftwareStatementAdmin/Create
        /// </summary>
        /// <param name="model">SoftwareStatementIssuerViewModel</param>
        /// <returns>ActionResultを返す</returns>
        [HttpPost]
        [ValidateAntiForgeryToken]
        public ActionResult Create(SoftwareStatementIssuerViewModel model)
        {
            this.Authorize();

            if (!ModelState.IsValid)
            {
                return View(model);
            }

            //  **同じ鍵は足せない**（設定ファイル側も含めて見る）。
            //    **設定が勝つ規則**なので、**設定に在る鍵を DB に入れても使われない。**
            if (SoftwareStatementIssuerProvider.Get(model.IssuerKey) != null
                || SoftwareStatementAdminController.IsInSetting(model.IssuerKey))
            {
                //  **文面は #292 の段階 2 と同じ**（「その鍵は既に使われています」）なので、
                //    **同じ資源を使い回す**（**同じ文字列を 2 つ持たない**）。
                ModelState.AddModelError("", Resources.AdminController.IdFederationKeyAlreadyExists);

                return View(model);
            }

            SoftwareStatementIssuerProvider.Create(model);

            // オペレーション・トレース・ログ出力
            //   **値は出さない。鍵と iss だけ**（**鍵の本文は公開鍵だが、ログを太らせない**）。
            Logging.MyOperationTrace(string.Format(
                "A software_statement issuer was added. (key: {0}, iss: {1})",
                model.IssuerKey, model.Issuer));

            return RedirectToAction("Index", new { message = EnumAdminMessageId.AddSuccess });
        }

        #endregion

        #region Edit

        /// <summary>
        /// 発行者の編集画面（初期表示）
        /// GET: /SoftwareStatementAdmin/Edit
        /// </summary>
        /// <param name="key">鍵</param>
        /// <returns>ActionResultを返す</returns>
        [HttpGet]
        public ActionResult Edit(string key)
        {
            this.Authorize();

            SoftwareStatementIssuerViewModel model = SoftwareStatementIssuerProvider.Get(key);

            if (model == null)
            {
                //  **設定ファイルの行は編めない**（この画面は user store の行だけを編む）。
                return RedirectToAction("Index", new { message = EnumAdminMessageId.Error });
            }

            return View(model);
        }

        /// <summary>
        /// 発行者の編集画面（更新）
        /// POST: /SoftwareStatementAdmin/Edit
        /// </summary>
        /// <param name="model">SoftwareStatementIssuerViewModel</param>
        /// <returns>ActionResultを返す</returns>
        [HttpPost]
        [ValidateAntiForgeryToken]
        public ActionResult Edit(SoftwareStatementIssuerViewModel model)
        {
            this.Authorize();

            if (!ModelState.IsValid)
            {
                return View(model);
            }

            if (SoftwareStatementIssuerProvider.Get(model.IssuerKey) == null)
            {
                return RedirectToAction("Index", new { message = EnumAdminMessageId.Error });
            }

            SoftwareStatementIssuerProvider.Update(model);

            Logging.MyOperationTrace(string.Format(
                "A software_statement issuer was updated. (key: {0}, iss: {1})",
                model.IssuerKey, model.Issuer));

            return RedirectToAction("Index", new { message = EnumAdminMessageId.EditSuccess });
        }

        #endregion

        #region Delete

        /// <summary>
        /// 発行者の削除
        /// POST: /SoftwareStatementAdmin/Delete
        /// </summary>
        /// <param name="key">鍵</param>
        /// <returns>ActionResultを返す</returns>
        /// <remarks>**POST で受ける**（GET で消さない）。**画面は一覧の行から押す。**</remarks>
        [HttpPost]
        [ValidateAntiForgeryToken]
        public ActionResult Delete(string key)
        {
            this.Authorize();

            if (SoftwareStatementIssuerProvider.Get(key) == null)
            {
                return RedirectToAction("Index", new { message = EnumAdminMessageId.Error });
            }

            SoftwareStatementIssuerProvider.Delete(key);

            Logging.MyOperationTrace(string.Format(
                "A software_statement issuer was deleted. (key: {0})", key));

            return RedirectToAction("Index", new { message = EnumAdminMessageId.DeleteSuccess });
        }

        #endregion

        #endregion

        #region Private

        /// <summary>設定ファイルに、その鍵が在るか（#308 の段階 2）</summary>
        /// <param name="key">鍵</param>
        /// <returns>在れば true</returns>
        /// <remarks>
        /// **設定が勝つ規則**なので、**設定に在る鍵を DB に入れても使われない** —
        /// **入れさせない**（**使われない行が増えると、台帳として読めなくなる**）。
        /// </remarks>
        private static bool IsInSetting(string key)
        {
            Dictionary<string, Dictionary<string, string>> issuers =
                Config.SoftwareStatementIssuers;

            return issuers != null && !string.IsNullOrEmpty(key) && issuers.ContainsKey(key);
        }

        #endregion
    }
}
