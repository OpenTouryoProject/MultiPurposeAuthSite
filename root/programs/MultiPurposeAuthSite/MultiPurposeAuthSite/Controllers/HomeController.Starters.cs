//**********************************************************************************
//* テンプレート
//**********************************************************************************

// 以下のLicenseに従い、このProjectをTemplateとして使用可能です。Release時にCopyright表示してSublicenseして下さい。
// https://github.com/OpenTouryoProject/MultiPurposeAuthSite/blob/master/license/LicenseForTemplates.txt

//**********************************************************************************
//* クラス名        ：HomeController
//* クラス日本語名  ：HomeController の 自己テストの開始（Saml2OAuth2Starters の振り分け）
//*
//* 作成日時        ：－
//* 作成者          ：－
//* 更新履歴        ：－
//*
//*  日時        更新者            内容
//*  ----------  ----------------  -------------------------------------------------
//*  2026/10/31  玄人 幸道         新規（HomeController.cs から partial に分割。#294）
//*  2026/10/31  玄人 幸道         AntiForgery トークンを確かめる。クライアントが無い・Request Object を預けられないときは再表示（#294）
//*  2026/10/31  玄人 幸道         response_mode の比較を ToLowerInvariant に。コメントの誤り（#294）
//*  2026/10/31  玄人 幸道         「ログイン・ユーザの Client」をログインせずに選んだら、理由を出す（#294）
//*  2026/10/31  玄人 幸道         「ログイン・ユーザの Client」は利用者名として client_id を引く（#294）
//*  2026/11/04  玄人 幸道         自己テストのクライアント（normal 以外）を、名前ではなく client_mode で選ぶ
//**********************************************************************************

using MultiPurposeAuthSite.Co;
using MultiPurposeAuthSite.Entity;
using MultiPurposeAuthSite.ViewModels;
using MultiPurposeAuthSite.Extensions.Sts;
using MultiPurposeAuthSite.Util.Sts;

using System.Web.Mvc;
using System.Threading.Tasks;

using Microsoft.AspNet.Identity;

using Touryo.Infrastructure.Framework.Authentication;
using Touryo.Infrastructure.Public.FastReflection;

namespace MultiPurposeAuthSite.Controllers
{
    /// <summary>HomeController（自己テストの開始（Saml2OAuth2Starters の振り分け））</summary>
    public partial class HomeController
    {
        #region Action Method

        #region Starters

        /// <summary>
        /// SAML2OAuth2Starters画面（初期表示）
        /// GET: /Home/Saml2OAuth2Starters
        /// </summary>
        /// <returns>ActionResult</returns>
        [HttpGet]
        [AllowAnonymous]
        public ActionResult Saml2OAuth2Starters()
        {
            if (Config.IsLockedDownTestEndpoints)
            {
                return View("Index");
            }
            else
            {
                return View(new HomeSaml2OAuth2StartersViewModel()); 
            }
        }

        /// <summary>
        /// SAML2OAuth2Starters画面
        /// POST: /Home/Saml2OAuth2Starters
        /// </summary>
        /// <returns>ActionResult</returns>
        /// <remarks>
        /// **AntiForgery トークンを確かめる**（#294。画面は出していたが、確かめていなかった）。
        /// </remarks>
        [HttpPost]
        [AllowAnonymous]
        [ValidateAntiForgeryToken]
        public async Task<ActionResult> Saml2OAuth2Starters(HomeSaml2OAuth2StartersViewModel model)
        {
            if (Config.IsLockedDownTestEndpoints)
            {
                return View("Index");
            }
            else
            {
                // HomeSaml2OAuth2StartersViewModel の検証
                if (ModelState.IsValid)
                {
                    // RedirectUriの扱い
                    this.ClarifyRedirectUri = model.ClarifyRedirectUri;

                    #region Client選択
                    if (model.ClientType == OAuth2AndOIDCEnum.ClientMode.normal.ToStringByEmit())
                    {
                        // OAuth2.0 / OIDC用 Client
                        this.ClientName = "TestClient";
                    }
                    else if (model.ClientType == OAuth2AndOIDCEnum.ClientMode.fapi1.ToStringByEmit()
                        || model.ClientType == OAuth2AndOIDCEnum.ClientMode.fapi2.ToStringByEmit()
                        || model.ClientType == OAuth2AndOIDCEnum.ClientMode.device.ToStringByEmit()
                        || model.ClientType == OAuth2AndOIDCEnum.ClientMode.fapi_ciba.ToStringByEmit())
                    {
                        // Financial-grade API - Part1 / Part2・Device Authorization Grant・CIBA 用 Client
                        //   **名前ではなく、登録の client_mode で選ぶ**（構成ファイルの最初の 1 件）。
                        //   **名前を変えても、配備済みの構成ファイルで選べなくならない**ため
                        //   （以前は TestClient1〜4 を直に書いていた。雛形の名前は FAPI1_Client・FAPI2_Client・
                        //   Device_Client・FAPI_CIBA_Client）。
                        this.ClientName = Helper.GetInstance().GetClientNameByClientMode(model.ClientType, false);
                    }
                    else if (model.ClientType == HomeSaml2OAuth2StartersViewModel.RequirePkceClientType)
                    {
                        // **クライアント単位で PKCE を必須にした Client（#221）。**
                        //   登録（OAuth2ClientsInformation）で require_pkce = true。
                        //   これを選ぶと、**下のボタンはどれもこのクライアントで動く。**
                        //   PKCE を付けないフローは、認可エンドポイントで invalid_request になる。
                        //   **名前ではなく、normal で require_pkce = true の登録を選ぶ**（雛形の名前は RequirePKCE_Client）。
                        this.ClientName = Helper.GetInstance().GetClientNameByClientMode(
                            OAuth2AndOIDCEnum.ClientMode.normal.ToStringByEmit(), true);
                    }
                    else
                    {
                        // ログイン・ユーザの Client
                        if (User.Identity.IsAuthenticated)
                        {
                            // ユーザの取得
                            //   **消された利用者の Cookie が残っていると null**（#294。以前は NRE で 500）。
                            ApplicationUser user = await UserManager.FindByIdAsync(User.Identity.GetUserId());
                            this.ClientName = (user == null) ? "" : user.UserName;

                            //  **利用者名として引く**（#294。クライアント名と同じ名前でも、その人の登録を使う）。
                            this.IsOwnClient = true;
                        }
                        else
                        {
                            // **理由を出す**（#294。以前は何も起きずに再表示されるだけだった）。
                            ModelState.AddModelError("", "Sign in to use your own client.");
                        }
                    }

                    // **クライアントの登録が無ければ、始めない**（#294）。
                    //   以前は client_id が null のまま進み、Session への保存で 500 になっていた。
                    if (!string.IsNullOrEmpty(this.ClientName)
                        && string.IsNullOrEmpty(this.ResolveClientId()))
                    {
                        ModelState.AddModelError("", "No client is registered for the selected client type.");
                        this.ClientName = "";
                    }
                    #endregion

                    #region ResponseMode選択
                    if(string.IsNullOrEmpty(model.ResponseMode))
                    {
                        this.ResponseMode = "";
                    }
                    else if (model.ResponseMode.ToLowerInvariant().Replace('.', '_')
                        == OAuth2AndOIDCEnum.ResponseMode.query_jwt.ToStringByEmit())
                    {
                        this.ResponseMode = Const.ResponseModeQueryJwt;
                    }
                    else if (model.ResponseMode.ToLowerInvariant().Replace('.', '_')
                        == OAuth2AndOIDCEnum.ResponseMode.fragment_jwt.ToStringByEmit())
                    {
                        this.ResponseMode = Const.ResponseModeFragmentJwt;
                    }
                    else if (model.ResponseMode.ToLowerInvariant().Replace('.', '_')
                        == OAuth2AndOIDCEnum.ResponseMode.form_post_jwt.ToStringByEmit())
                    {
                        this.ResponseMode = Const.ResponseModeFormPostJwt;
                    }
                    else
                    {
                        this.ResponseMode = model.ResponseMode;
                    }
                    #endregion

                    // **prompt と max_age は、そのまま渡す**（#246 の項目 3）。
                    //   値の妥当性はサーバ側が判断する（未対応の値を選んだときの振る舞いも見たいため）。
                    this.Prompt = model.Prompt ?? "";
                    this.MaxAge = model.MaxAge ?? "";

                    // **NameIDFormat も、そのまま渡す**（#277 の段階 4）。
                    //   選ばなければ Unspecified（IdP 側の既定と同じ）。
                    this.NameIdFormat = model.NameIdFormat ?? "";

                    #region Starterの実行

                    // **ログアウトは、クライアントの選択に依らない**（#232）。
                    if (!string.IsNullOrEmpty(Request.Form.Get("submit.EndSession")))
                    {
                        return this.EndSession();
                    }

                    if (!string.IsNullOrEmpty(this.ClientName))
                    {
                        #region SAML2
                        if (!string.IsNullOrEmpty(Request.Form.Get("submit.Saml2RedirectRedirectBinding")))
                        {
                            return this.Saml2RedirectRedirectBinding();
                        }
                        else if (!string.IsNullOrEmpty(Request.Form.Get("submit.Saml2RedirectPostBinding")))
                        {
                            return this.Saml2RedirectPostBinding();
                        }
                        else if (!string.IsNullOrEmpty(Request.Form.Get("submit.Saml2PostPostBinding")))
                        {
                            return this.Saml2PostPostBinding();
                        }
                        else if (!string.IsNullOrEmpty(Request.Form.Get("submit.Saml2PostRedirectBinding")))
                        {
                            // **4 つ目の組み合わせ**（#246 の項目 2）
                            return this.Saml2PostRedirectBinding();
                        }
                        #endregion

                        #region OAuth2

                        #region AuthorizationCode系
                        if (!string.IsNullOrEmpty(Request.Form.Get("submit.AuthorizationCode")))
                        {
                            return this.AuthorizationCode();
                        }
                        else if (!string.IsNullOrEmpty(Request.Form.Get("submit.AuthorizationCode_OIDC")))
                        {
                            return this.AuthorizationCode_OIDC();
                        }
                        #endregion

                        #region Implicit系
                        if (!string.IsNullOrEmpty(Request.Form.Get("submit.Implicit")))
                        {
                            return this.Implicit();
                        }
                        else if (!string.IsNullOrEmpty(Request.Form.Get("submit.Implicit_OIDC1")))
                        {
                            return this.Implicit_OIDC1();
                        }
                        else if (!string.IsNullOrEmpty(Request.Form.Get("submit.Implicit_OIDC2")))
                        {
                            return this.Implicit_OIDC2();
                        }
                        #endregion

                        #region Hybrid系
                        if (!string.IsNullOrEmpty(Request.Form.Get("submit.Hybrid_OIDC1")))
                        {
                            return this.Hybrid_OIDC1();
                        }
                        else if (!string.IsNullOrEmpty(Request.Form.Get("submit.Hybrid_OIDC2")))
                        {
                            return this.Hybrid_OIDC2();
                        }
                        else if (!string.IsNullOrEmpty(Request.Form.Get("submit.Hybrid_OIDC3")))
                        {
                            return this.Hybrid_OIDC3();
                        }
                        #endregion

                        #region PKCE系
                        if (!string.IsNullOrEmpty(Request.Form["submit.PKCE_Plain"]))
                        {
                            return this.PKCE_Plain();
                        }
                        else if (!string.IsNullOrEmpty(Request.Form["submit.PKCE_S256"]))
                        {
                            return this.PKCE_S256();
                        }
                        else if (!string.IsNullOrEmpty(Request.Form["submit.PKCE_Plain_4SPA"]))
                        {
                            return this.PKCE_Plain(toSpa: true);
                        }
                        else if (!string.IsNullOrEmpty(Request.Form["submit.PKCE_S256_4SPA"]))
                        {
                            return this.PKCE_S256(toSpa: true);
                        }
                        #endregion

                        #region F-API系
                        if (!string.IsNullOrEmpty(Request.Form.Get("submit.AuthorizationCodeFAPI1")))
                        {
                            return this.AuthorizationCodeFAPI1();
                        }
                        else if (!string.IsNullOrEmpty(Request.Form.Get("submit.AuthorizationCodeFAPI1_OIDC")))
                        {
                            return this.AuthorizationCodeFAPI1_OIDC();
                        }
                        else if (!string.IsNullOrEmpty(Request.Form.Get("submit.AuthorizationCodeFAPI1_PKCE")))
                        {
                            return this.AuthorizationCodeFAPI1_PKCE();
                        }
                        else if (!string.IsNullOrEmpty(Request.Form.Get("submit.AuthorizationCodeFAPI2")))
                        {
                            // **預けられなければ null**（理由は ModelState。下で再表示する。#294）
                            ActionResult fapi2 = await this.AuthorizationCodeFAPI2Async();

                            if (fapi2 != null)
                            {
                                return fapi2;
                            }
                        }
                        else if (!string.IsNullOrEmpty(Request.Form.Get("submit.AuthorizationCodeFAPI2_PAR")))
                        {
                            return await this.AuthorizationCodeFAPI2ParAsync();
                        }
                        else if (!string.IsNullOrEmpty(Request.Form.Get("submit.FAPI_CIBA_Profile")))
                        {
                            return await this.FAPICibaProfileAsync();
                        }
                        #endregion

                        #region Another系
                        if (!string.IsNullOrEmpty(Request.Form.Get("submit.ResourceOwnerPasswordCredentialsFlow")))
                        {
                            return await this.ResourceOwnerPasswordCredentialsFlow();
                        }
                        else if (!string.IsNullOrEmpty(Request.Form.Get("submit.ClientCredentialsFlow")))
                        {
                            return await this.ClientCredentialsFlow();
                        }
                        else if (!string.IsNullOrEmpty(Request.Form.Get("submit.JWTBearerTokenFlow")))
                        {
                            return await this.JWTBearerTokenFlow();
                        }
                        else if (!string.IsNullOrEmpty(Request.Form.Get("submit.DeviceAuthZGrant")))
                        {
                            return await this.DeviceAuthZAsync();
                        }
                        #endregion

                        #endregion
                    }
                    #endregion
                }

                // 再表示
                return View(model);
            }
        }

        #endregion

        #endregion
    }
}