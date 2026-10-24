//**********************************************************************************
//* テンプレート
//**********************************************************************************

// 以下のLicenseに従い、このProjectをTemplateとして使用可能です。Release時にCopyright表示してSublicenseして下さい。
// https://github.com/OpenTouryoProject/MultiPurposeAuthSite/blob/master/license/LicenseForTemplates.txt

//**********************************************************************************
//* クラス名        ：AccountController
//* クラス日本語名  ：AccountのController（テンプレート）
//*
//* 作成日時        ：－
//* 作成者          ：－
//* 更新履歴        ：－
//*
//*  日時        更新者            内容
//*  ----------  ----------------  -------------------------------------------------
//*  2018/11/30  西野 大介         新規
//*  2019/02/18  西野 大介         FAPI2 CC対応実施
//*  2019/05/2*  西野 大介         SAML2対応実施
//*  2020/01/07  西野 大介         PPID対応実施
//*  2020/01/08  西野 大介         #126（Feedback）対応実施
//*  2020/02/28  西野 大介         エラーメッセージ通知の改善
//*  2020/03/04  西野 大介         CIBA対応実施
//*  2020/07/24  西野 大介         OIDCではredirect_uriは必須。
//*  2020/07/24  西野 大介         ID連携（Hybrid-IdP）実装の見直し
//*  2020/11/12  西野 大介         SameSiteCookie対応 (.NET Fx側は対策不要)
//*  2020/12/21  西野 大介         Device AuthZ対応実施
//*  2021/07/10  西野 大介         2FAにプッシュ通知を追加（AspNetCore.Identityのみ
//*  2026/09/07  玄人 幸道         不正な入力での未処理例外を修正（#185）
//*  2026/09/07  玄人 幸道         expires_inが常に0になる不具合を修正（#182）
//*  2026/09/08  玄人 幸道         エラー応答とRedirect URLをRFC 6749に合わせる（#187）
//*  2026/09/16  玄人 幸道         2FAのプッシュ承認の待ち受け（TwoFactorPushStatus）を追加（#213）
//*  2026/09/16  玄人 幸道         2FAのコード送信の失敗を、画面に戻して伝える（#214）
//*  2026/09/17  玄人 幸道         IsLockedDownRedirectEndpoint を IsLockedDownTestEndpoints に改名（#219）
//*  2026/09/18  玄人 幸道         認可リクエストの code_challenge を検証に渡す（#220）
//*  2026/09/24  玄人 幸道         クエリ文字列の request_uri / code_challenge を、デコードされた値で読む（#229）
//*  2026/09/25  玄人 幸道         設定キーの改名（IdFederation*Endpoint）に追随（#236）
//*  2026/09/27  玄人 幸道         RP-Initiated Logout（/end_session）を追加（#232）
//*  2026/09/28  玄人 幸道         FAPI2 の自己テストのトークン交換を private_key_jwt にした（#246）
//*  2026/09/28  玄人 幸道         アサーションの組み立てを SelfTestClient へ寄せた（#246）
//*  2026/09/28  玄人 幸道         SAML2 の応答（アサーション）を画面に出す（#246 の項目 3）
//*  2026/09/28  玄人 幸道         認可画面に、確かめる内容（prompt / max_age など）を出す（#246 の項目 3）
//*  2026/09/28  玄人 幸道         max_age の超過で再認証し、prompt=none なら login_required を返す（#247）
//*  2026/09/28  玄人 幸道         「別のアカウントでログイン」がサインアウトしていなかったのを修正（#247 で気付いた）
//*  2026/09/30  玄人 幸道         ID 連携の Error に理由のトレースを足す（#253）
//*  2026/09/30  玄人 幸道         未サインイン＋prompt=none で login_required を返す（#254）
//*  2026/09/30  玄人 幸道         自身が書く Cookie の名前に接頭辞を付けられるようにした（#255）
//*  2026/09/30  玄人 幸道         既存アカウントへメアドで結ぶとき email_verified を確かめるようにした（#140 の段階 1）
//*  2026/09/30  玄人 幸道         ID 連携の鍵を (iss, sub) にし、iss の検証と PKCE(S256) を追加（#140 の段階 3）
//*  2026/10/01  玄人 幸道         利用者名とメアドの両方でサインインできるようにし、サインアップを見直した（#151 の段階 3）
//*  2026/10/01  玄人 幸道         ID 連携の新規作成で preferred_username を優先（#151 の段階 4）
//*  2026/10/03  玄人 幸道         テスト利用者の名前に接尾辞を付けられるようにした（#260）
//*  2026/10/03  玄人 幸道         E2E専用のクライアント登録を種データにした（#264）
//*  2026/10/03  玄人 幸道         2人目のテスト利用者に標準クレームのサンプルを仕込む（#261）
//*  2026/10/04  玄人 幸道         response_typeを正規化して受ける（#267）
//*  2026/10/06  玄人 幸道         種データのクライアント登録を専用列で作る（#270）
//*  2026/10/06  玄人 幸道         promptの照合を集合に寄せた（#272 の段階 1）
//*  2026/10/06  玄人 幸道         同意を記録し、promptの各値を処理（#272 の段階 2）
//*  2026/10/07  玄人 幸道         WebAuthnのサインインをFido2 4.2.0で復活、MsPassを削除（#137）
//*  2026/10/07  玄人 幸道         SAML2の応答を3分岐にし、SP側の照合に期待値を渡した（#276）
//*  2026/10/10  玄人 幸道         WebAuthn の資格情報の種データを足した（#277 の段階 7）
//*  2026/10/10  玄人 幸道         ID連携からprompt=noneを外し、エラー応答を受け取る（#287）
//*  2026/10/10  玄人 幸道         SAML2のID連携を追加（#286の段階2）
//*  2026/10/11  玄人 幸道         OIDCのID連携も開始とサインインに分けた（#286の段階2）
//*  2026/10/12  玄人 幸道         上流の id_token を、上流の鍵で検証するようにした（#289 の段階 1）
//*  2026/10/13  玄人 幸道         上流の SSO の口を、メタデータから引くようにした（#291）
//*  2026/10/14  玄人 幸道         ID 連携の上流を、設定の n 件から選べるようにした（#292 の段階 1）
//*  2026/10/16  玄人 幸道         user_code の投入の失敗を数える（#305 の段階 2）
//*  2026/10/20  玄人 幸道         クライアントごとの利用者を作らなくした（#307 の段階 5-a-1）
//*  2026/10/21  玄人 幸道         OP のセッションの識別子と sid クレームを追加（#310 の段階 1）
//*  2026/10/21  玄人 幸道         ログアウトを RP へ伝え、台帳へ書くのを発行の直前に移した（#310 の段階 2）
//*  2026/10/21  玄人 幸道         ブラウザ経由（iframe）でもログアウトを伝える（#310 の段階 3）
//*  2026/10/22  玄人 幸道         汎用部品を Open棟梁 の実装に置き換えた（#294）
//*  2026/10/24  玄人 幸道         利用者名とメアドの規則の呼び先を Util.IdP.UserIdentifier にした（#294）
//*  2026/10/24  玄人 幸道         ID 連携の旧い鍵（userid）からの移行の枝を削除した（上流へ userid を要求しないので通らない。#140 の段階 3）
//*  2026/10/24  玄人 幸道         Const.StandardScopes を Const.SelfTestScopes にリネームした（#294）
//*  2026/10/24  玄人 幸道         文字列リテラルを Const / OAuth2AndOIDCConst の定数にした（#294）
//*  2026/10/24  玄人 幸道         自己テストの認証方式の表示と検証エラーの文言を resx にした（#294）
//*  2026/10/25  玄人 幸道         文字列リテラルを定数にした（2 回目の洗い出し。#294）
//*  2026/10/25  玄人 幸道         認可エンドポイントと SAML2 のエラーを OPERATION に記録する（障害対応のため。#294）
//*  2026/10/25  玄人 幸道         追加した OPERATION ログの文言を resx に、長さの上限を Const にした（#294）
//*  2026/10/25  玄人 幸道         サインイン・認可エンドポイントなどを partial（AccountController.*.cs）に分けた（#294）
//**********************************************************************************

/*
- ASP.NET Identity を用いた認証・認可およびアカウント管理機能（ユーザー管理、ロール管理、サインイン管理、通知送信など）の基盤や共通処理を提供するコントローラーの一部。
- 属性 (Attributes): [Authorize]（原則として認証済みのユーザーのみアクセス可能）
- コンストラクター・インジェクションを通じて、以下の主要なサービス・マネージャーを受け取り保持。
  - UserManager<ApplicationUser> _userManager: ユーザー管理のためのマネージャー。
  - RoleManager<ApplicationRole> _roleManager: ロール管理のためのマネージャー。
  - SignInManager<ApplicationUser> _signInManager: サインイン管理のためのマネージャー。
  - IEmailSender _emailSender: メール送信サービス。
  - ISmsSender _smsSender: SMS送信サービス。
*/

using MultiPurposeAuthSite.Co;
using MultiPurposeAuthSite.ViewModels;
using MultiPurposeAuthSite.Data;
using MultiPurposeAuthSite.Network;
using MultiPurposeAuthSite.Notifications;
using MultiPurposeAuthSite.Log;
using MultiPurposeAuthSite.Util;
using MultiPurposeAuthSite.Util.IdP;
using MultiPurposeAuthSite.Util.Sts;
using Token = MultiPurposeAuthSite.TokenProviders;
using Saml = MultiPurposeAuthSite.SamlProviders;
using FIDO = MultiPurposeAuthSite.Extensions.FIDO;
using Sts = MultiPurposeAuthSite.Extensions.Sts;

using System;
using System.Collections.Generic;
using System.Xml;
using System.Linq;
using System.Text.RegularExpressions;
using System.Threading;
using System.Threading.Tasks;
using System.Security.Claims;
using System.Security.Cryptography;
using Stj = System.Text.Json;

using System.Web;

using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Http.Extensions;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.Rendering;
using AspNetId = Microsoft.AspNetCore.Identity;

using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

using Newtonsoft.Json;
using Newtonsoft.Json.Linq;

using Fido2NetLib;
using Fido2NetLib.Objects;

using Touryo.Infrastructure.Business.Presentation;
using Touryo.Infrastructure.Framework.StdMigration;
using Touryo.Infrastructure.Framework.Authentication;
using Touryo.Infrastructure.Public.Str;
using Touryo.Infrastructure.Public.Util;
using Touryo.Infrastructure.Public.Security;
using Touryo.Infrastructure.Public.Security.Jwt;
using Touryo.Infrastructure.Public.Security.Pwd;
using Touryo.Infrastructure.Public.FastReflection;
using Touryo.Infrastructure.Public.Log;

namespace MultiPurposeAuthSite.Controllers
{
    /// <summary>AccountController</summary>
    [Authorize]
    public partial class AccountController : MyBaseMVControllerCore
    {
        #region members & constructor

        #region members

        /// <summary>ErrorMessage</summary>
        [TempData]
        public string ErrorMessage { get; set; }

        #region OwinContext
        /// <summary>UserManager</summary>
        private readonly UserManager<ApplicationUser> _userManager = null;
        /// <summary>UserManager</summary>
        private readonly RoleManager<ApplicationRole> _roleManager = null;
        /// <summary>SignInManager</summary>
        private readonly SignInManager<ApplicationUser> _signInManager = null;
        #endregion

        #region IXXXSender
        /// <summary>IEmailSender</summary>
        private readonly IEmailSender _emailSender = null;
        /// <summary>ISmsSender</summary>
        private readonly ISmsSender _smsSender = null;
        #endregion

        //  <summary>CookieOptions</summary>
        private readonly CookieOptions _cookieOptions = null;

        #endregion

        #region constructor
        /// <summary>constructor</summary>
        /// <param name="userManager">UserManager</param>
        /// <param name="roleManager">RoleManager</param>
        /// <param name="signInManager">SignInManager</param>
        /// <param name="emailSender">IEmailSender</param>
        /// <param name="smsSender">ISmsSender</param>
        public AccountController(
            UserManager<ApplicationUser> userManager,
            RoleManager<ApplicationRole> roleManager,
            SignInManager<ApplicationUser> signInManager,
            IEmailSender emailSender,
            ISmsSender smsSender)
        {
            // UserManager
            this._userManager = userManager;
            // RoleManager
            this._roleManager = roleManager;
            // SignInManager
            this._signInManager = signInManager;

            // IEmailSender
            this._emailSender = emailSender;
            // ISmsSender
            this._smsSender = smsSender;

            // CookieOptions
            CookieOptions co = new CookieOptions();
            co.HttpOnly = true;
            co.Secure = true;
            co.SameSite = SameSiteMode.None;
            this._cookieOptions = co;
        }
        #endregion

        #endregion

        #region property

        /// <summary>SessionCookieName</summary>
        /// <remarks>
        /// **接頭辞を掛ける**（#255）。**`Startup` が同じ規則で名前を付けている**ので、
        /// ここで掛けないと、**セッションを捨てるときに別の名前を消しに行く。**
        ///
        /// **net48 版は掛けない。** あちらのセッション Cookie は ASP.NET のもので
        /// （`system.web/sessionState` の `cookieName`）、**接頭辞の対象外**である。
        /// </remarks>
        private string SessionCookieName
        {
            get
            {
                return Config.PrefixedCookieName(
                    GetConfigParameter.GetAnyConfigValue("sessionState:SessionCookieName"));
            }
        }

        #region GetOwinContext

        /// <summary>ApplicationUserManager</summary>
        private UserManager<ApplicationUser> UserManager
        {
            get
            {
                return this._userManager;
            }
        }

        /// <summary>ApplicationRoleManager</summary>
        private RoleManager<ApplicationRole> RoleManager
        {
            get
            {
                return this._roleManager;
            }
        }

        /// <summary>ApplicationSignInManager</summary>
        private SignInManager<ApplicationUser> SignInManager
        {
            get
            {
                return this._signInManager;
            }
        }

        #endregion

        #region Else

        /// <summary>IEmailSender</summary>
        private IEmailSender EmailSender
        {
            get
            {
                return this._emailSender;
            }
        }

        /// <summary>ISmsSender</summary>
        private ISmsSender SmsSender
        {
            get
            {
                return this._smsSender;
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

        #region Helper

        #region Controller → View

        /// <summary>
        /// ModelStateDictionaryに
        /// IdentityResult.Errorsの情報を移送
        /// </summary>
        /// <param name="result">IdentityResult</param>
        private void AddErrors(IdentityResult result)
        {
            foreach (IdentityError error in result.Errors)
            {
                ModelState.AddModelError("", error.Code + ": " + error.Description);
            }
        }

        /// <summary>
        /// ModelStateDictionaryに
        /// IEnumerable(string)の情報を移送
        /// </summary>
        /// <param name="errors">IEnumerable<string></param>
        private void AddErrors(IEnumerable<string> errors)
        {
            foreach (string error in errors)
            {
                ModelState.AddModelError("", error);
            }
        }

        /// <summary>RedirectToActionする。</summary>
        /// <param name="returnUrl">returnUrl</param>
        /// <returns>ActionResult</returns>
        private ActionResult RedirectToLocal(string returnUrl)
        {
            if (this.Url.IsLocalUrl(returnUrl))
            {
                return Redirect(returnUrl);
            }
            else
            {
                return RedirectToAction(nameof(HomeController.Index), "Home");
            }
        }

        #endregion

        #endregion
    }
}