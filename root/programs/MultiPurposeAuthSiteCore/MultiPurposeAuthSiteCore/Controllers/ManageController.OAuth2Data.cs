//**********************************************************************************
//* テンプレート
//**********************************************************************************

// 以下のLicenseに従い、このProjectをTemplateとして使用可能です。Release時にCopyright表示してSublicenseして下さい。
// https://github.com/OpenTouryoProject/MultiPurposeAuthSite/blob/master/license/LicenseForTemplates.txt

//**********************************************************************************
//* クラス名        ：ManageController
//* クラス日本語名  ：ManageのController のクライアント登録
//*
//* 作成日時        ：－
//* 作成者          ：－
//* 更新履歴        ：－
//*
//*  日時        更新者            内容
//*  ----------  ----------------  -------------------------------------------------
//*  2026/10/29  玄人 幸道         新規（ManageController.cs から partial に分割。#294）
//*  2026/10/30  玄人 幸道         ほかで使われている client_id では、登録を作らない（#294）
//**********************************************************************************

/*
利用者が持つクライアント（SAML2 / OAuth2）の登録の一覧・追加・削除を担うManageControllerの一部
*/

using MultiPurposeAuthSite.Co;
using MultiPurposeAuthSite.ViewModels;
using MultiPurposeAuthSite.Log;
using MultiPurposeAuthSite.Util.Sts;
using Sts = MultiPurposeAuthSite.Extensions.Sts;

using System;
using System.Collections.Generic;
using System.Threading.Tasks;

using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

using Touryo.Infrastructure.Public.Security.Pwd;

namespace MultiPurposeAuthSite.Controllers
{
    // **ManageController のクライアント登録**（partial。本体は ManageController.cs）
    public partial class ManageController
    {
        #region OAuth2 Data

        #region Create

        /// <summary>
        /// 自分のクライアント登録の一覧（#307 の段階 5-a-2）
        /// GET: /Manage/Saml2OAuth2DataList
        /// </summary>
        /// <param name="message">ManageMessageId</param>
        /// <returns>ActionResultを非同期に返す</returns>
        /// <remarks>
        /// **1 利用者 n クライアント**（段階 5-a-1）になったので、**並べて選べる画面が要る。**
        /// **段階 5-a-1 までは、画面から触れるのは「所有者の先頭 1 件」だけだった** —
        /// **動的登録で 2 件目を作れても、画面には出てこなかった。**
        ///
        /// **出すのは自分の登録だけ**（`Saml2OAuth2DataProvider.GetByOwner`。**`client_id` の昇順**）。
        /// **所有者の無い登録**（構成ファイル発の種データ）**は出ない。**
        ///
        /// **`client_secret` と `registration_access_token` は、行の VM が持たない** —
        /// **一覧に出さない値を View へ渡さない**（**出し忘れでは防げない**ため、器ごと分ける）。
        /// </remarks>
        [HttpGet]
        [Authorize(Roles = Const.Role_SystemAdminOrAdmin)]
        public async Task<ActionResult> Saml2OAuth2DataList(EnumManageMessageId? message)
        {
            if (Config.CanEditSaml2OAuth2Data
                && Config.EnableEditingOfUserAttribute)
            {
                ViewBag.StatusMessage =
                      message == EnumManageMessageId.AddSaml2OAuth2DataSuccess ? Resources.ManageController.AddSaml2OAuth2DataSuccess
                    : message == EnumManageMessageId.RemoveSaml2OAuth2DataSuccess ? Resources.ManageController.RemoveSaml2OAuth2DataSuccess
                    : message == EnumManageMessageId.Error ? Resources.ManageController.Error
                    : "";

                // ユーザの検索
                ApplicationUser user = await UserManager.GetUserAsync(User);

                List<Saml2OAuth2DataRowViewModel> rows = new List<Saml2OAuth2DataRowViewModel>();

                foreach (ManageAddSaml2OAuth2DataViewModel owned
                    in Sts.Saml2OAuth2DataProvider.GetByOwner(user.Id))
                {
                    rows.Add(new Saml2OAuth2DataRowViewModel()
                    {
                        ClientID = owned.ClientID,
                        ClientMode = owned.ClientMode,
                        RedirectUriCode = owned.RedirectUriCode,

                        //  **動的登録（RFC 7591）で作られたか。**
                        //    **`registration_access_token` を持っているかで見る**（段階 2）。
                        //    **トークンそのものは出さない**（**保管しているのはハッシュ**）。
                        IsDynamic = !string.IsNullOrEmpty(owned.RegistrationAccessToken)
                    });
                }

                return View(new ManageSaml2OAuth2DataListViewModel() { Registrations = rows });
            }
            else
            {
                // エラー画面
                return View("Error");
            }
        }

        /// <summary>
        /// OAuth2関連の非構造化データの追加・編集画面（初期表示）
        /// GET: /Manage/AddSaml2OAuth2Data
        /// </summary>
        /// <returns>ActionResultを非同期に返す</returns>
        [HttpGet]
        [Authorize(Roles = Const.Role_SystemAdminOrAdmin)]
        public async Task<ActionResult> AddSaml2OAuth2Data(string clientId)
        {
            if (Config.CanEditSaml2OAuth2Data
                && Config.EnableEditingOfUserAttribute)
            {
                // ユーザの検索
                ApplicationUser user = await UserManager.GetUserAsync(User);

                ManageAddSaml2OAuth2DataViewModel model = null;

                //  **どの登録を編集するかは、一覧から渡される**（#307 の段階 5-a-2）。
                //    **段階 5-a-1 までは「所有者の先頭 1 件」を黙って出していた** —
                //    **n 件になると、どれが出たのかが押す側に分からない。**
                if (!string.IsNullOrEmpty(clientId))
                {
                    //  **所有者で照合する。**
                    //    **他人の（または無い）`client_id` では開かない** —
                    //    **新規として開くと、他人の行を上書きできてしまう。**
                    //    **動的登録の側は `registration_access_token` で守っている**（RFC 7592 §2）。
                    model = Sts.Saml2OAuth2DataProvider.GetByOwnerAndClientID(user.Id, clientId);

                    if (model == null)
                    {
                        // エラー画面
                        return View("Error");
                    }

                    //  **編集中の印**（**`client_id` を作り直すボタンを出さない**）。
                    //    **作り直すと別のクライアントになり**、
                    //    **`registration_access_token` も引き継げない**ためである。
                    model.Editing = "1";
                }
                else
                {
                    // 初期
                    model = new ManageAddSaml2OAuth2DataViewModel();

                    // **折り返し先の既定は、自己テストの受け口**（`test_self_code`）。
                    //   **そのまま動作確認でき、済んだら自分の RP の折り返し先に書き換える。**
                    //
                    //   **以前は `test_self_code_manage`（管理画面の「トークンを取る」）だった**が、
                    //   **その画面は廃止されたので、記号ごと落とした。**
                    model.RedirectUriCode = Const.TestSelfCode;
                }

                return View(model);
            }
            else
            {
                // エラー画面
                return View("Error");
            }
        }

        /// <summary>
        /// OAuth2関連の非構造化データの追加・編集画面（OAuth2関連の非構造化データ設定）
        /// POST: /Manage/AddSaml2OAuth2Data
        /// </summary>
        /// <param name="model">ManageAddSaml2OAuth2DataViewModel</param>
        /// <returns>ActionResultを非同期に返す</returns>
        [HttpPost]
        [ValidateAntiForgeryToken]
        [Authorize(Roles = Const.Role_SystemAdminOrAdmin)]
        public async Task<ActionResult> AddSaml2OAuth2Data(ManageAddSaml2OAuth2DataViewModel model)
        {
            if (Config.CanEditSaml2OAuth2Data
                && Config.EnableEditingOfUserAttribute)
            {
                // ManageAddSaml2OAuth2DataViewModelの検証
                if (ModelState.IsValid)
                {
                    // ManageAddSaml2OAuth2DataViewModelの検証に成功
                    if (!string.IsNullOrEmpty(Request.Form["submit.ClientID"]))
                    {
                        ModelState.Clear();
                        model.ClientID = Guid.NewGuid().ToString("N");
                    }
                    else if (!string.IsNullOrEmpty(Request.Form["submit.ClientSecret"]))
                    {
                        ModelState.Clear();
                        model.ClientSecret = GetPassword.Base64UrlSecret(32);
                    }
                    else if (!string.IsNullOrEmpty(Request.Form["submit.Add"]))
                    {
                        // ユーザの検索
                        ApplicationUser user = await UserManager.GetUserAsync(User);

                        if (user != null)
                        {
                            // ユーザを取得できた。
                            model.ClientName = user.UserName; // ClientNameはUser入力ではない。

                            //  **所有者を列に書く**（#307 の段階 5-a）。
                            //    **`Users.Id` を指す**（**名前ではない**）。
                            //    **以前は利用者の行の `ClientID` を書き換えていた。**
                            model.OwnerUserId = user.Id;

                            //  **その `client_id` が自分の持ち物か**（#307 の段階 5-a-2）。
                            //    **在れば更新、無ければ作成**である。
                            //    **他人の `client_id` を送られても null になる**ので、
                            //    **更新ではなく「作成」に落ちる** —
                            //    **他人の行は、この経路でも書き換えられない**
                            //    （**`Create` は、既に在る `client_id` では通らない**）。
                            ManageAddSaml2OAuth2DataViewModel owned
                                = Sts.Saml2OAuth2DataProvider.GetByOwnerAndClientID(user.Id, model.ClientID);

                            if (owned != null)
                            {
                                // ClientIDに変更がない場合、更新操作

                                //  **registration_access_token のハッシュを持ち越す**
                                //    （RFC 7592。#307 の段階 2）。
                                //    **画面の保存は、行を丸ごと上書きする**ので、
                                //    **持ち越さないと消える** —
                                //    **動的登録した RP が、管理 API を使えなくなる。**
                                //    **画面には出さない**（照合にしか使わない値である）。
                                //
                                //  **client_id を作り直した場合は、持ち越さない**
                                //    （下の分岐。**別のクライアントになる**ので、
                                //      **そのトークンは、もう効いてはならない**）。
                                model.RegistrationAccessToken = owned.RegistrationAccessToken;

                                //  **画面に欄の無い列も持ち越す**（行を丸ごと上書きするので、**持ち越さないと消える**）。
                                //    **EC の公開鍵**は、動的登録の `jwks` か構成ファイルから入る（`RT-307.28`）。
                                model.JwkECDsaPublickey = owned.JwkECDsaPublickey;

                                //  **動的登録で作られた行を、画面から書き替えた**（#307 の段階 6）。
                                //    **記録に残す** —
                                //    **`software_statement` の保証から外れた点が、後から分かる**ようにする
                                //    （**ベンダの保証どおりの登録です、と言えなくなる所**である）。
                                //
                                //  **権限の昇格ではない。**
                                //    **この利用者は、好きな `scope` の登録を画面から新規にも作れる**
                                //    （段階 1 の決め : **専用 scope を配るのは画面か構成ファイルだけ**）。
                                //    **禁止しても、作り直して同じ所に行ける**ので、壁にはならない。
                                //
                                //  **閉じたい配備は、画面そのものを閉じる**
                                //    （`CanEditSaml2OAuth2Data` / `EnableEditingOfUserAttribute`）。
                                //    **`RequireSoftwareStatement` は API 側の扉だけ**で、
                                //    **この画面には効かない。**
                                if (!string.IsNullOrEmpty(owned.RegistrationAccessToken))
                                {
                                    // オペレーション・トレース・ログ出力
                                    Logging.MyOperationTrace(string.Format(
                                        "{0}({1}) edited the dynamically registered client {2} "
                                        + "on the management screen.",
                                        user.Id, user.UserName, model.ClientID));
                                }

                                Sts.Saml2OAuth2DataProvider.Update(model.ClientID, model);

                                // 再ログイン
                                await this.ReSignInAsync(user.Id);

                                //  **戻り先は一覧**（#307 の段階 5-a-2）。
                                //    **直した行が、その場で見える。**
                                return RedirectToAction("Saml2OAuth2DataList", new { Message = EnumManageMessageId.AddSaml2OAuth2DataSuccess });
                            }
                            else if (!string.IsNullOrEmpty(model.ClientID)
                                && (Sts.Saml2OAuth2DataProvider.Get(model.ClientID) != null
                                    || !string.IsNullOrEmpty(Helper.GetInstance().GetClientName(model.ClientID))))
                            {
                                //  **ほかで使われている `client_id` では作らない**（#294）。
                                //    **以前は、mem では何もせずに「成功」と出し、DB では主キーの違反で 500 になっていた。**
                                //    **構成ファイルのクライアントとも重ねない**（引くときは構成ファイルが勝つので、作っても効かない）。
                                ModelState.AddModelError("ClientID", Resources.ManageController.ClientIdAlreadyExists);
                            }
                            else if (!string.IsNullOrEmpty(model.ClientID))
                            {
                                //  **新しい登録を作る**（#307 の段階 5-a-2）。
                                //    **利用者の行には触らない**（所有者は列が持つ）。
                                //    **古い登録は消さない** — **1 人が n 件持てる**ようになった
                                //    （**段階 5-a-1 までは、この画面が 1 件だけを扱うために消していた**）。
                                Sts.Saml2OAuth2DataProvider.Create(model.ClientID, model);

                                // 再ログイン
                                await this.ReSignInAsync(user.Id);

                                //  **戻り先は一覧**（#307 の段階 5-a-2）。
                                //    **足した行が、その場で見える。**
                                return RedirectToAction("Saml2OAuth2DataList", new { Message = EnumManageMessageId.AddSaml2OAuth2DataSuccess });
                            }
                            else
                            {
                                // ClientIDが入力されていない（model.ClientID）。
                            }
                        }
                        else
                        {
                            // ユーザを取得できなかった。
                        }
                    }
                    else
                    {
                        // 不明なSubmit
                    }
                }
                else
                {
                    // ManageAddSaml2OAuth2DataViewModelの検証に失敗
                }

                // 再表示
                return View(model);
            }
            else
            {
                // エラー画面
                return View("Error");
            }
        }

        #endregion

        #region Delete

        /// <summary>
        /// OAuth2関連の非構造化データの削除
        /// POST: /Manage/RemoveSaml2OAuth2Data
        /// </summary>
        /// <returns>ActionResultを非同期に返す</returns>
        [HttpPost]
        [ValidateAntiForgeryToken]
        [Authorize(Roles = Const.Role_SystemAdminOrAdmin)]
        public async Task<ActionResult> RemoveSaml2OAuth2Data(string clientId)
        {
            if (Config.CanEditSaml2OAuth2Data
                && Config.EnableEditingOfUserAttribute)
            {
                // ユーザの検索
                ApplicationUser user = await UserManager.GetUserAsync(User);

                //  **一覧の行から渡された 1 件を消す**（#307 の段階 5-a-2）。
                //    **所有者で照合する** — **他人の `client_id` では、何も消さない。**
                //    **空でも何も消さない** —
                //    **「先頭 1 件を黙って消す」をしない**ためである
                //    （**どれが消えるのかは、押す側に見えていなければならない**）。
                ManageAddSaml2OAuth2DataViewModel owned
                    = Sts.Saml2OAuth2DataProvider.GetByOwnerAndClientID(user.Id, clientId);

                if (owned == null)
                {
                    // 一覧 - Error
                    return RedirectToAction("Saml2OAuth2DataList",
                        new { Message = EnumManageMessageId.Error });
                }

                // UserのClientデータを更新
                Sts.Saml2OAuth2DataProvider.Delete(owned.ClientID);

                //  **同意も消す**（全利用者の分。**動的登録の `DELETE` と同じ扱い**。`RT-307.29`）。
                //    **同意の表の `ClientID` には外部キーが無い**ので、登録の行を消しても残る。
                Sts.ConsentProvider.RevokeByClient(owned.ClientID);

                //  **利用者の行は触らない**（#307 の段階 5-a-1）。
                //    **以前は `UserManager.UpdateAsync` を呼んでいた** —
                //    **`Users.ClientID` を持っていた頃の名残**で、いまは何も変わらない。
                //    **呼ばないので、その失敗を見る分岐も要らない。**
                //
                //  **再ログインはする** — **追加の側と揃える**
                //    （**この画面の操作の後は、資格情報を取り直す**作りである）。
                await this.ReSignInAsync(user.Id);

                return RedirectToAction("Saml2OAuth2DataList",
                    new { Message = EnumManageMessageId.RemoveSaml2OAuth2DataSuccess });
            }
            else
            {
                // エラー画面
                return View("Error");
            }
        }

        #endregion

        #endregion
    }
}
