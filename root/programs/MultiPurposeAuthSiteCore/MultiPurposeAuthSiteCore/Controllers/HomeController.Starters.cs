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
//**********************************************************************************

using MultiPurposeAuthSite.Co;
using MultiPurposeAuthSite.ViewModels;
using MultiPurposeAuthSite.Extensions.Sts;

using System.Threading.Tasks;

using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

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
                    else if (model.ClientType == OAuth2AndOIDCEnum.ClientMode.fapi1.ToStringByEmit())
                    {
                        // Financial-grade API - Part1用 Client
                        this.ClientName = "TestClient1";
                    }
                    else if (model.ClientType == OAuth2AndOIDCEnum.ClientMode.fapi2.ToStringByEmit())
                    {
                        // Financial-grade API - Part2用 Client
                        this.ClientName = "TestClient2";
                    }
                    else if (model.ClientType == OAuth2AndOIDCEnum.ClientMode.device.ToStringByEmit())
                    {
                        // Device Authorization Grant用 Client
                        this.ClientName = "TestClient3";
                    }
                    else if (model.ClientType == OAuth2AndOIDCEnum.ClientMode.fapi_ciba.ToStringByEmit())
                    {
                        // Financial-grade API - CIBA用 Client
                        this.ClientName = "TestClient4";
                    }
                    else if (model.ClientType == HomeSaml2OAuth2StartersViewModel.RequirePkceClientType)
                    {
                        // **クライアント単位で PKCE を必須にした Client（#221）。**
                        //   登録（OAuth2ClientsInformation）で require_pkce = true。
                        //   これを選ぶと、**下のボタンはどれもこのクライアントで動く。**
                        //   PKCE を付けないフローは、認可エンドポイントで invalid_request になる。
                        this.ClientName = "TestClient6";
                    }
                    else
                    {
                        // ログイン・ユーザの Client
                        if (User.Identity.IsAuthenticated)
                        {
                            // ユーザの取得
                            //   **消された利用者の Cookie が残っていると null**（#294。以前は NRE で 500）。
                            ApplicationUser user = await UserManager.GetUserAsync(User);
                            this.ClientName = (user == null) ? "" : user.UserName;
                        }
                    }

                    // **クライアントの登録が無ければ、始めない**（#294）。
                    //   以前は client_id が null のまま進み、Session への保存で 500 になっていた。
                    if (!string.IsNullOrEmpty(this.ClientName)
                        && string.IsNullOrEmpty(Helper.GetInstance().GetClientIdByName(this.ClientName)))
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
                    if (!string.IsNullOrEmpty(Request.Form["submit.EndSession"]))
                    {
                        return this.EndSession();
                    }

                    if (!string.IsNullOrEmpty(this.ClientName))
                    {
                        #region SAML2
                        if (!string.IsNullOrEmpty(Request.Form["submit.Saml2RedirectRedirectBinding"]))
                        {
                            return this.Saml2RedirectRedirectBinding();
                        }
                        else if (!string.IsNullOrEmpty(Request.Form["submit.Saml2RedirectPostBinding"]))
                        {
                            return this.Saml2RedirectPostBinding();
                        }
                        else if (!string.IsNullOrEmpty(Request.Form["submit.Saml2PostPostBinding"]))
                        {
                            return this.Saml2PostPostBinding();
                        }
                        else if (!string.IsNullOrEmpty(Request.Form["submit.Saml2PostRedirectBinding"]))
                        {
                            // **4 つ目の組み合わせ**（#246 の項目 2）
                            return this.Saml2PostRedirectBinding();
                        }
                        #endregion

                        #region OAuth2

                        #region AuthorizationCode系
                        if (!string.IsNullOrEmpty(Request.Form["submit.AuthorizationCode"]))
                        {
                            return this.AuthorizationCode();
                        }
                        else if (!string.IsNullOrEmpty(Request.Form["submit.AuthorizationCode_OIDC"]))
                        {
                            return this.AuthorizationCode_OIDC();
                        }
                        #endregion

                        #region Implicit系
                        if (!string.IsNullOrEmpty(Request.Form["submit.Implicit"]))
                        {
                            return this.Implicit();
                        }
                        else if (!string.IsNullOrEmpty(Request.Form["submit.Implicit_OIDC1"]))
                        {
                            return this.Implicit_OIDC1();
                        }
                        else if (!string.IsNullOrEmpty(Request.Form["submit.Implicit_OIDC2"]))
                        {
                            return this.Implicit_OIDC2();
                        }
                        #endregion

                        #region Hybrid系
                        if (!string.IsNullOrEmpty(Request.Form["submit.Hybrid_OIDC1"]))
                        {
                            return this.Hybrid_OIDC1();
                        }
                        else if (!string.IsNullOrEmpty(Request.Form["submit.Hybrid_OIDC2"]))
                        {
                            return this.Hybrid_OIDC2();
                        }
                        else if (!string.IsNullOrEmpty(Request.Form["submit.Hybrid_OIDC3"]))
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
                        if (!string.IsNullOrEmpty(Request.Form["submit.AuthorizationCodeFAPI1"]))
                        {
                            return this.AuthorizationCodeFAPI1();
                        }
                        else if (!string.IsNullOrEmpty(Request.Form["submit.AuthorizationCodeFAPI1_OIDC"]))
                        {
                            return this.AuthorizationCodeFAPI1_OIDC();
                        }
                        else if (!string.IsNullOrEmpty(Request.Form["submit.AuthorizationCodeFAPI1_PKCE"]))
                        {
                            return this.AuthorizationCodeFAPI1_PKCE();
                        }
                        else if (!string.IsNullOrEmpty(Request.Form["submit.AuthorizationCodeFAPI2"]))
                        {
                            // **預けられなければ null**（理由は ModelState。下で再表示する。#294）
                            ActionResult fapi2 = await this.AuthorizationCodeFAPI2Async();

                            if (fapi2 != null)
                            {
                                return fapi2;
                            }
                        }
                        else if (!string.IsNullOrEmpty(Request.Form["submit.AuthorizationCodeFAPI2_PAR"]))
                        {
                            return await this.AuthorizationCodeFAPI2ParAsync();
                        }
                        else if (!string.IsNullOrEmpty(Request.Form["submit.FAPI_CIBA_Profile"]))
                        {
                            return await this.FAPICibaProfileAsync();
                        }
                        #endregion

                        #region Another系
                        if (!string.IsNullOrEmpty(Request.Form["submit.ResourceOwnerPasswordCredentialsFlow"]))
                        {
                            return await this.ResourceOwnerPasswordCredentialsFlow();
                        }
                        else if (!string.IsNullOrEmpty(Request.Form["submit.ClientCredentialsFlow"]))
                        {
                            return await this.ClientCredentialsFlow();
                        }
                        else if (!string.IsNullOrEmpty(Request.Form["submit.JWTBearerTokenFlow"]))
                        {
                            return await this.JWTBearerTokenFlow();
                        }
                        else if (!string.IsNullOrEmpty(Request.Form["submit.DeviceAuthZGrant"]))
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