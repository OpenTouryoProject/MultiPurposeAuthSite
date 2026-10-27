//**********************************************************************************
//* テンプレート
//**********************************************************************************

// 以下のLicenseに従い、このProjectをTemplateとして使用可能です。Release時にCopyright表示してSublicenseして下さい。
// https://github.com/OpenTouryoProject/MultiPurposeAuthSite/blob/master/license/LicenseForTemplates.txt

//**********************************************************************************
//* クラス名        ：AccountController
//* クラス日本語名  ：AccountのController（テンプレート）の ID 連携
//*
//* 作成日時        ：－
//* 作成者          ：－
//* 更新履歴        ：－
//*
//*  日時        更新者            内容
//*  ----------  ----------------  -------------------------------------------------
//*  2026/10/25  玄人 幸道         新規（AccountController.cs から partial に分割。#294）
//**********************************************************************************

/*
 * 上流の IdP との ID 連携（OIDC と SAML2）の開始とコールバック、
 * トークン・アサーションの検証、利用者の登録・更新を担うAccountControllerの一部
 *
 * - OIDC と SAML2 は、同じ 3 段の形に揃えてある（#286）。
 *   → 開始（StartIdFederationByOidc / StartIdFederationBySaml2）
 *   → 受け口（IDFederationRedirectEndPoint / IDFederationAssertionConsumerService。応答の検証まで）
 *   → 利用者の結び付け（SignInByIdFederationOidc / SignInByIdFederationSaml2）
 *
 * - 上流は複数持てる（#292）。どの上流へ送ったかを Session に控え、受け口（各 1 本）はそれで相手を引く。
 * - 連携キーは (上流の Issuer, 主体の識別子)。OIDC は (iss, sub)、SAML2 は (EntityID, NameID)（#140 / #286）。
 * - 利用者の鍵はメアド（#151）。既存の利用者に結ぶのは、メアドが検証済みのときだけ（#140）。
 * - OIDC の認可要求には PKCE（S256）と 32 文字の state を付け、prompt=none は付けない（#140 / #287）。認可応答の iss を検証する（RFC 9207）。
 * - SAML2 の応答の検証の本体は Open棟梁 の SAML2Client.VerifyResponseWithReason。鍵は、メタデータ → 設定の .cer の順で決める（#291）。
 * - 完了しなかった理由は、OPERATION ログに残す（#253）。
*/

using MultiPurposeAuthSite.Co;
using MultiPurposeAuthSite.Entity;
using MultiPurposeAuthSite.ViewModels;
using MultiPurposeAuthSite.Log;
using MultiPurposeAuthSite.Util.IdP;
using Sts = MultiPurposeAuthSite.Extensions.Sts;

using System;
using System.Collections.Generic;
using System.Threading.Tasks;
using System.Security.Claims;
using System.Security.Cryptography;

using System.Web.Mvc;

using Microsoft.AspNet.Identity;
using Microsoft.AspNet.Identity.Owin;

using Newtonsoft.Json;
using Newtonsoft.Json.Linq;

using Touryo.Infrastructure.Framework.Authentication;
using Touryo.Infrastructure.Public.Str;
using Touryo.Infrastructure.Public.Security.Jwt;
using Touryo.Infrastructure.Public.Security.Pwd;
using Touryo.Infrastructure.Public.Log;

namespace MultiPurposeAuthSite.Controllers
{
    // **AccountController の ID 連携**（partial。本体は AccountController.cs）
    public partial class AccountController
    {
        #region OIDC

        // StartIdFederationByOidcは、新設のStartIdFederationBySaml2に合わせて切り出された（#286）。

        /// <summary>OIDC の ID 連携を始める（上流へ認可要求を送る）</summary>
        /// <param name="uid">サインイン画面に入力された値（`login_hint` にそのまま渡す）</param>
        /// <returns>ActionResult（上流の認可エンドポイントへのリダイレクト）</returns>
        /// <remarks>
        /// **SAML2 側（`StartIdFederationBySaml2`）と同じ位置づけ**である（#286）。
        ///
        /// | | |
        /// |---|---|
        /// | 宛先 | `IdFederationAuthorizeEndpoint`（上流の認可エンドポイント） |
        /// | 応答の受け取り | `response_mode=form_post`（`IdFederationRedirectEndpoint`） |
        /// | PKCE | **S256 を付ける**（#140） |
        /// | `prompt` | **付けない**（#287。利用者が押す導線で UI を禁じない） |
        /// | `login_hint` | **画面の入力値をそのまま渡す**（#151） |
        /// </remarks>
        private ActionResult StartIdFederationByOidc(string uid, IdFederationUpstream upstream)
        {
            // upstream には、ID連携の1件設定、n件設定の、いずれかの1件が入る。どちらも null なら、上流が引けない。
            if (upstream == null)
            {
                //  **指定された上流が引けない**（登録が無い・無効・値が足りない）。
                //    **理由を残す**（#253）。**鍵は設定の名前なので、そのまま出してよい。**
                Logging.MyOperationTrace(
                    "The OIDC ID federation has no usable upstream. (IdFederationUpstreams)");

                return View("Error");
            }

            //  **入力された値を、そのまま `login_hint` として上流へ渡す**（#151）。
            //    利用者名でもメアドでもよい（上流がどう解釈するかは上流しだい）。
            //
            //  **自分の認可エンドポイントを組み立てていた行は落とした**（#286）。
            //    **参照されていなかった** — **宛先は上流の方**（`IdFederationAuthorizeEndpoint`）である。

            //  **client_id は、その上流に登録された自分の値**（#292）。
            string client_id = upstream.ClientId;

            // state // 記号は入れない。
            //   **32 文字にした**（#140）。10 文字では短い。
            //   PKCE があるので CSRF は守られるが、**推測しにくい方がよい。**
            string state = GetPassword.Generate(32, 0);
            Session[Const.IdFederationSigninState] = state;

            //  **どの上流へ送ったかを控える**（#292）。
            //    **折り返し口は 1 本**なので、**戻ってきた側はこれで相手を引く。**
            Session[Const.IdFederationSigninUpstream] = upstream.Key;

            // redirect_uri
            string redirect_uri = Config.IdFederationRedirectEndpoint;

            // nonce // 記号は入れない。
            string nonce = GetPassword.Generate(20, 0);
            Session[Const.IdFederationSigninNonce] = nonce;

            // ID連携に必要なscope
            string scope = Const.IdFederationScopes;

            // **PKCE を付ける**（#140）。
            //   これまで client_secret だけだった。**OAuth 2.1 は、秘密を持つ
            //   クライアントでも PKCE を付けることを求める**（コードの横取りに備える）。
            //   相手が PKCE を見ない OP でも、**余分なパラメタとして無視されるだけ**なので壊れない。
            string codeVerifier = GetPassword.Base64UrlSecret(50);
            Session[Const.IdFederationSigninVerifier] = codeVerifier;

            return Redirect(
                upstream.AuthorizeEndpoint +
                "?client_id=" + client_id +
                "&response_type=code" +
                "&scope=" + scope +
                "&state=" + state +
                "&nonce=" + nonce +
                "&redirect_uri=" + CustomEncode.UrlEncode(redirect_uri) +
                "&response_mode=form_post" +
                "&code_challenge="
                    + OAuth2AndOIDCClient.PKCE_S256_CodeChallengeMethod(codeVerifier) +
                "&code_challenge_method=" + OAuth2AndOIDCConst.PKCE_S256 +
                // `prompt=none` も `IsPassive` も送らない（手動の導線ではない）
                "&login_hint=" + uid); // + "&prompt=none");
        }

        /// <summary>
        /// IDFederationRedirectEndPoint
        /// OIDC, response_type=code, response_mode=form_post
        /// </summary>
        /// <param name="code">仲介コード</param>
        /// <param name="state">state</param>
        /// <param name="iss">issuer（RFC 9207）</param>
        /// <param name="error">エラー コード（エラー応答のとき）</param>
        /// <param name="error_description">エラーの説明（同上）</param>
        /// <returns>ActionResultを非同期に返す</returns>
        /// <see cref="http://openid-foundation-japan.github.io/rfc6749.ja.html#code-authz-resp"/>
        /// <seealso cref="http://openid-foundation-japan.github.io/rfc6749.ja.html#token-req"/>
        [AllowAnonymous]
        public async Task<ActionResult> IDFederationRedirectEndPoint(
            string code, string state, string iss,
            string error, string error_description)
        {
            if (!Config.IsLockedDownTestEndpoints)
            {
                #region どの上流から戻ってきたか

                // **開始処理が Session に控えた鍵**で引く（折り返し口は 1 本）。
                // **Session が切れていれば、既定の上流**（1 件の配備では、その 1 件）。
                IdFederationUpstream upstream = IdFederationUpstreams.GetOrDefault(
                    (string)Session[Const.IdFederationSigninUpstream],
                    IdFederationUpstream.Oidc);

                Session[Const.IdFederationSigninUpstream] = ""; // 誤動作防止

                if (upstream == null)
                {
                    // **相手が分からなければ、検証できない。** **理由を残す**（#253）。
                    Logging.MyOperationTrace(
                        "The OIDC ID federation could not resolve the upstream. (IdFederationUpstreams)");

                    return View("Error");
                }

                // エラー応答を受け取る（#287）。
                if (!string.IsNullOrEmpty(error))
                {
                    Logging.MyOperationTrace(string.Format(
                        "The ID federation ended with an error response. (error: {0}, description: {1})",
                        LogSanitizer.Sanitize(error),
                        LogSanitizer.Describe(error_description)));

                    return View("Error");
                }

                // **認可応答の `iss` を検証する**（RFC 9207。#140）。
                //   **Mix-Up 攻撃への対策**で、OAuth 2.1 が挙げているのはこの応答パラメタである。
                //   `id_token` の `iss` も照合しているが（IdToken.Verify → SpRp_Isser）、
                //   **応答そのものを見ていなかった。**
                //
                //   **来なければ通す。** RFC 9207 を実装していない OP があるため
                //   （この IdP 自身は #231 で出すようになった）。
                if (!string.IsNullOrEmpty(iss)
                    && !string.Equals(iss, upstream.Issuer, StringComparison.Ordinal))
                {
                    Logging.MyOperationTrace(
                        "The iss of the authorization response did not match the expected issuer.");

                    return View("Error");
                }

                #endregion

                // 結果を格納する変数。
                Dictionary<string, string> dic = null;
                OAuth2AuthorizationCodeGrantClientViewModel model = new OAuth2AuthorizationCodeGrantClientViewModel
                {
                    State = state,
                    Code = code
                };

                //  **その上流に登録された、自分の client_id / client_secret**（#292）。
                string client_id = upstream.ClientId;
                string client_secret = upstream.ClientSecret;

                // stateの検証
                if (state == (string)Session[Const.IdFederationSigninState])
                {
                    // state正常
                    Session[Const.IdFederationSigninState] = ""; // 誤動作防止

                    #region Code → Token

                    // codeからAccess Tokenを取得する。
                    string redirect_uri = Config.IdFederationRedirectEndpoint;

                    // PKCE の code_verifier を渡す（#140）。
                    string codeVerifier = (string)Session[Const.IdFederationSigninVerifier];
                    Session[Const.IdFederationSigninVerifier] = ""; // 誤動作防止

                    // Tokenエンドポイントにアクセス。Sts.Helper の WebAPI 呼び出しは使わない（#140）。
                    //   Sts.Helper は、自己ホストをコンテナ化した配備（Windows 以外で OAuth2Containerizated* を設定）では、
                    //   宛先のホストを自分の認可サーバへ書き換える。相手は上流の IdP なので、その配備では宛先が変わって壊れる。
                    model.Response = await OAuth2AndOIDCClient.GetAccessTokenByCodeAsync(
                            new Uri(upstream.TokenEndpoint),
                            client_id, client_secret, redirect_uri, code, codeVerifier);

                    dic = JsonConvert.DeserializeObject<Dictionary<string, string>>(model.Response);

                    #endregion

                    #region id_token検証

                    string sub = "";
                    string nonce = "";
                    JObject jobj = null;

                    // **id_token の payload を取っておく**（#140）。
                    //   jobj は、この後 /userinfo の応答で上書きされる。
                    //   **連携キー（iss / sub）は、署名を検証した id_token 側から取る。**
                    JObject idTokenPayload = null;

                    if (dic.ContainsKey(OAuth2AndOIDCConst.IDToken))
                    {
                        // id_tokenがある。
                        string id_token = dic[OAuth2AndOIDCConst.IDToken];
                        string access_token = dic[OAuth2AndOIDCConst.AccessToken];

                        // OIDCのID連携で、上流の id_token の署名を検証する鍵
                        //   上流の値は n 件設定（IdFederationUpstreams の行・管理画面の行）から来る。
                        //   **n 件設定が無いときだけ**、1 件設定（IdFederation* の単数キー）から組み立てる（下位互換。#292）。
                        //
                        //   | 順 | 鍵 | n 件設定 | 1 件設定 |
                        //   |---|---|---|---|
                        //   | 1 | 上流の JWK Set を kid で引く（ロールオーバーに追随。#289 / #290） | jwk_set_uri、無ければ discovery_url → jwks_uri | IdFederationJwkSetUri、無ければ IdFederationOidcDiscoveryUrl → jwks_uri |
                        //   | 2 | 上流の証明書（1 が引けなかったときの受け皿） | cer_file_path | IdFederationOidcCerFilePath |
                        //   | 3 | 渡さない（この配備の設定の鍵で検証する。下の if） | － | － |
                        //
                        //   **期待する iss** は、n 件設定は issuer、1 件設定は SpRp_Isser。**空なら 1・2 は使えない**（3 に進む）。
                        //   **自分の /jwkcerts（JwkSetUri）は、自分が発行するトークンの鍵を広告する口**で、ここでは使わない。
                        JWS upstreamKey = null;

                        if (!string.IsNullOrEmpty(upstream.Issuer))
                        {
                            // 上流の JWK Set（上の表の 1）から kid で引き、RS256 の鍵にする（#289 / #290）。
                            upstreamKey = await Sts.IdFederationJwks.GetKeyAsync(id_token, upstream);

                            // 引けなければ（届かない・kid が無い）、上流の証明書（上の表の 2）に倒す。
                            if (upstreamKey == null
                                && !string.IsNullOrEmpty(upstream.CerFilePath))
                            {
                                upstreamKey = new JWS_RS256_X509(upstream.CerFilePath, "");
                            }
                        }
                        else if (!string.IsNullOrEmpty(upstream.CerFilePath))
                        {
                            // **証明書だけ在って期待する `iss` が空**なら、渡せない。
                            //   iss に対応する証明書である確証がなく、
                            //   鍵を指定する版の IdToken.Verify は iss が空なら例外にする（Open棟梁 #601）。
                            //   この後は、鍵を指定しない版に進む。**理由を残す**（#253）。
                            Logging.MyOperationTrace("The ID federation has a certificate but no expected issuer.");
                        }
                        else
                        {
                            // iss も .cer も無い。鍵を指定しない版の IdToken.Verify に進む（1:1 の構成）。
                            //   **理由を残す**（#253）。一般の OP ならこの後の検証で必ず落ちるので、
                            //   **設定漏れ（issuer / cer_file_path、1 件設定では SpRp_Isser / IdFederationOidcCerFilePath）と区別できるようにする。**
                            Logging.MyOperationTrace(
                                "The ID federation has neither an expected issuer nor a certificate. (verified with the client settings)");
                        }

                        // **結果を控えておく**（#253）。**失敗したときに、どちらで落ちたかを残すため。**
                        bool idTokenVerified = false;

                        if (upstreamKey == null)
                        {
                            // 鍵を指定しない版（1:1のテスト構成の名残）
                            //   上流の鍵ではなく、この配備の設定の鍵で検証するので、通るのは上流・下流が同じ鍵を持つ構成のときだけ。
                            //   - 鍵：kid があれば、自分の JWK Set ファイル（JwkSetFilePath）から kid で引く。
                            //         kid が無い・引けなければ CmnClientParams.RsaCerFilePath (SpRp_RsaCerFilePath) を使う。
                            //   - iss：SpRp_Isser
                            //   **n 件設定でも、上流の鍵が決まらなければここに来る**（上の表の 3）。
                            idTokenVerified = IdToken.Verify(
                                id_token, access_token, code, state,
                                out sub, out nonce, out jobj);
                        }
                        else
                        {
                            // 鍵を指定する版
                            idTokenVerified = IdToken.Verify(
                                id_token, access_token, code, state,
                                upstreamKey, upstream.Issuer, upstream.ClientId,
                                out sub, out nonce, out jobj);
                        }

                        bool nonceMatched =
                            (nonce == (string)Session[Const.IdFederationSigninNonce]);

                        //  **`aud` は、呼び出し側で確認する**（#286）。
                        //    **`IdToken.Verify` は、この配備では `aud` を見ない** —
                        //    **「自分は認可サーバか」で分岐しており**（`JwkSetFilePath` の有無）、
                        //    **設定済みの側では `iss` と `exp` だけで通す**（Open棟梁 #601）。
                        //    **`out jobj` でペイロードが返る**ので、ここで確認できる。
                        //
                        //    **期待値は、開始処理が `client_id` に使った値**（自分のクライアント ID）。
                        bool audMatched =
                            Sts.IdTokenAudience.Matches(jobj, upstream.ClientId);

                        if (idTokenVerified && nonceMatched && audMatched)
                        {
                            // id_token検証OK。
                            idTokenPayload = jobj;
                        }
                        else
                        {
                            // id_token検証NG。
                            // **理由を残す**（#253）。署名・クレームの検証と nonce / aud の照合を分けて出す。
                            Logging.MyOperationTrace(string.Format(
                                "The id_token of the ID federation was not accepted. "
                                    + "(verified: {0}, nonce matched: {1}, aud matched: {2})",
                                idTokenVerified, nonceMatched, audMatched));

                            return View("Error");
                        }

                        Session[Const.IdFederationSigninNonce] = ""; // 誤動作防止
                    }
                    else
                    {
                        // id_tokenがない。
                        // **理由を残す**（#253）
                        Logging.MyOperationTrace(
                            "The token response of the ID federation had no id_token.");

                        return View("Error");
                    }

                    #endregion

                    #region Userinfo処理

                    // Userinfoエンドポイントにアクセス。Sts.Helper の WebAPI 呼び出しは使わない（#246）。
                    //   Sts.Helper は、自己ホストをコンテナ化した配備（Windows 以外で OAuth2Containerizated* を設定）では、
                    //   宛先のホストを自分の認可サーバへ書き換える。相手は上流の IdP なので、その配備では宛先が変わって壊れる。
                    string response = await OAuth2AndOIDCClient.GetUserInfoAsync(
                        new Uri(upstream.UserInfoEndpoint), dic[OAuth2AndOIDCConst.AccessToken]);

                    // クレーム情報（ID情報とe-mail, name情報）を抽出
                    jobj = (JObject)JsonConvert.DeserializeObject(response);

                    // **連携キーは (issuer, sub)**（#140）。
                    //   `sub` は OIDC の標準なので、**どの OP とも連携できる。**
                    //   **`iss` と `sub` は、署名を検証した id_token から取る**
                    //   （/userinfo の値は、この後で一致を確かめるだけに使う）。
                    string idpIssuer = (string)idTokenPayload[OAuth2AndOIDCConst.iss];
                    string federationKey = sub;

                    string name = (string)jobj[OAuth2AndOIDCConst.sub];
                    string email = (string)jobj[OAuth2AndOIDCConst.Scope_Email];

                    // **上流が「検証済み」と言っているか**（#140）。
                    //   相手が汎用認証サイトなら、/userinfo が email_verified を返す
                    //   （user.EmailConfirmed。#184 で真偽値に直してある）。
                    //   **JSON の真偽値なので、文字列にしてから渡す**（無ければ null）。
                    string emailVerified = (string)jobj[OAuth2AndOIDCConst.email_verified];

                    // **/userinfo の sub は、id_token の sub と一致しなければならない**
                    //   （OIDC Core §5.3.2。一致しなければトークンの取り違えを疑う）。
                    if (!string.Equals(name, sub, StringComparison.Ordinal))
                    {
                        Logging.MyOperationTrace(
                            "The sub of /userinfo did not match the sub of the id_token.");

                        return View("Error");
                    }

                    if (string.IsNullOrEmpty(idpIssuer))
                    {
                        // **iss が無い id_token は受けない**（連携キーが決まらない）。
                        Logging.MyOperationTrace("The id_token had no iss claim.");

                        return View("Error");
                    }

                    //  **`preferred_username` は、ここで取り出して渡す**（#286）。
                    //    **JSON を読むのは口の側**で、メソッドは値だけを受け取る。
                    string preferredUserName = (string)jobj[Const.PreferredUserNameClaim];

                    //  **ここから先は、利用者の結び付けとサインイン**（#286 で分けた）。
                    //    **SAML2 側と同じ形**である（`SignInByIdFederationSaml2`）。
                    return await this.SignInByIdFederationOidc(
                        idpIssuer, federationKey,
                        email, name, preferredUserName, emailVerified);

                    #endregion
                }
                else
                {
                    // **合わないときに理由を残す**（#253）。**値そのものは出さない**（有無と長さだけ）。
                    Logging.MyOperationTrace(string.Format(
                        "The state of the authorization response did not match the session. (response: {0}, session: {1})",
                        LogSanitizer.Describe(state),
                        LogSanitizer.Describe((string)Session[Const.IdFederationSigninState])));
                }
            }
            else
            {
                // **塞いである**（#253）。**理由が残らないと、設定ミスと区別が付かない。**
                Logging.MyOperationTrace(
                    "The ID federation redirect endpoint is locked down. (IsLockedDownTestEndpoints)");
            }

            // **ここに来た理由を残す**（#253）。
            //   **上で個別のトレースを出していれば、その次の行として出る**（経路の終わりを示す）。
            //   **出ていなければ、利用者の作成や外部ログインの追加に失敗している。**
            Logging.MyOperationTrace("The ID federation did not complete. (the error view was returned)");

            return View("Error");
        }

        /// <summary>検証できた id_token と /userinfo で、利用者を結び付けてサインインする</summary>
        /// <param name="idpIssuer">上流の Issuer（`id_token` の `iss`）</param>
        /// <param name="federationKey">連携キー（`id_token` の `sub`）</param>
        /// <param name="email">メアド（`/userinfo` の `email`）</param>
        /// <param name="name">`/userinfo` の `sub`</param>
        /// <param name="preferredUserName">`preferred_username`（新規作成時の名前に使う）</param>
        /// <param name="emailVerified">上流が返した `email_verified`</param>
        /// <returns>ActionResultを非同期に返す</returns>
        /// <remarks>
        /// **SAML2 側（`SignInByIdFederationSaml2`）と同じ位置づけ**である（#286）。
        /// **「protocol の往復」と「利用者の結び付け」を分けてある。**
        ///
        /// | | OIDC（ここ） | SAML2 |
        /// |---|---|---|
        /// | 連携キー | `(id_token の iss, sub)` | `(上流の EntityID, NameID)` |
        /// | 利用者の鍵 | メアド | メアド（＝ `NameID`） |
        /// | 新規作成時の名前 | `preferred_username` → メアドの `@` より前 | メアドの `@` より前 |
        /// | 検証済みのメアドか | **上流の `email_verified`** | **`NameIDFormat=emailAddress` を検証済みとして扱う** |
        /// </remarks>
        private async Task<ActionResult> SignInByIdFederationOidc(
            string idpIssuer, string federationKey,
            string email, string name, string preferredUserName, string emailVerified)
        {
            IdentityResult result = null;
            SignInStatus signInStatus = SignInStatus.Failure;

            //  **クレームは、ここで組み立てる**（#286）。
            //    **口は値を渡すだけ**にして、SAML2 側と同じ形にしてある。
            Claim nameClaim = new Claim(OAuth2AndOIDCConst.UrnSubjectClaim, name);
            Claim emailClaim = new Claim(OAuth2AndOIDCConst.UrnEmailClaim, email);

            // **新規に作るときの利用者名**（#151）。
            //   **上流の sub は利用者名ではない**（既定が public = 利用者 ID）。
            //   **利用者名は preferred_username で受け取る**（上流が UserClaimsMapping で出す。#151）。
            //   **無ければメアドの「@」より前**（利用者名に `@` は禁じている）。
            //   **sub は見ない**（利用者を指す識別子であって、名前ではない）。
            //   **鍵はメアド**なので、**名前がどちらになっても同じ利用者に結び付く**（下の FindByEmailAsync はメアドで引く）。
            //   ここで決まるのは、**新規に作るときの名前だけ**である。

            string newUserName = UserIdentifier.IsValidUserName(preferredUserName)
                ? preferredUserName : UserIdentifier.UserNameFromEmail(email);

            // **連携キーは (issuer, sub)**（#140）。**新しい鍵（iss, sub）で登録する。**
            //   ASP.NET Identity 2 は、検索（FindAsync）・追加（AddLoginAsync）・サインイン（ExternalSignInAsync）で
            //   同じ login を使うので、先に作る（net10.0 版は、使う枝の中で UserLoginInfo を作る）。
            UserLoginInfo login = new UserLoginInfo(idpIssuer, federationKey);
            ExternalLoginInfo externalLoginInfo = new ExternalLoginInfo();
            externalLoginInfo.Login = login;
            externalLoginInfo.Email = email;

            if (!string.IsNullOrWhiteSpace(email) && !string.IsNullOrWhiteSpace(name))
            {
                // クレーム情報（e-mail, name情報）を取得できた。

                // 既存の外部ログインを確認する。**新しい鍵（iss, sub）で引く**（#140。sub = federationKey）
                ApplicationUser user = await UserManager.FindAsync(login);

                if (user != null)
                {
                    // 既存の外部ログインがある場合。

                    // ユーザーが既に外部ログインしている場合は、クレームをRemove, Addで更新し、
                    result = await UserManager.RemoveClaimAsync(user.Id, emailClaim); // del-ins
                    result = await UserManager.AddClaimAsync(user.Id, emailClaim);
                    result = await UserManager.RemoveClaimAsync(user.Id, nameClaim); // del-ins
                    result = await UserManager.AddClaimAsync(user.Id, nameClaim);

                    // SignInAsyncより、ExternalSignInAsyncが適切。
                    // 既存の外部ログインでサインイン。**新しい鍵（iss, sub）で**（#140。sub = federationKey）
                    signInStatus = await SignInManager.ExternalSignInAsync(
                                         loginInfo: externalLoginInfo,
                                         isPersistent: false); // 外部ログインの Cookie 永続化は常に false.

                    // セッションの初期化
                    this.InitSessionAfterlogin();

                    // オペレーション・トレース・ログ出力
                    Logging.MyOperationTrace(string.Format("{0}({1}) has signed in with a verified external account.", user.Id, user.UserName));
                    // ルートにリダイレクト
                    return RedirectToLocal(Config.OAuth2AuthorizationServerEndpointsRootURI);
                }
                else
                {
                    // 既存の外部ログインがない。

                    // AccountControllerで、ユーザーが既に外部ログインしていない場合は、
                    // 外部ログインだけで済むか、サインアップからかを確認する必要がある。

                    // サインアップ済みの可能性を探る。**鍵はメアド**（#151。メアドは常に在って一意）。
                    user = await UserManager.FindByEmailAsync(email);

                    if (user != null)
                    {
                        // サインアップ済み → 外部ログイン追加だけで済む

                        // **メアドを鍵にして既存アカウントに結ぶなら、検証済みでなければならない**（#140）。
                        if (Sts.AccountLink.CheckLinkToExistingUser(emailVerified)
                                == Sts.AccountLinkCheck.NeedsVerifiedEmail)
                        {
                            // **結び付けない。** 画面に理由を出し、明示的な追加へ誘導する。
                            Logging.MyOperationTrace(string.Format(
                                "Rejected linking an ID federation login to {0}({1}) "
                                + "because the upstream did not assert email_verified.",
                                user.Id, user.UserName));

                            ViewBag.Reason = Resources.AccountViews.ExternalLoginNeedsVerifiedEmail;

                            return View("ExternalLoginFailure");
                        }

                        // 外部ログイン（ = UserLoginInfo ）の追加
                        // **メアドで引いているので、メアドの一致は自明**（#151）。
                        result = await UserManager.AddLoginAsync(user.Id, login);

                        // クレーム（emailClaim, nameClaim, etc.）の追加
                        if (result.Succeeded)
                        {
                            result = await UserManager.AddClaimAsync(user.Id, emailClaim);
                            result = await UserManager.AddClaimAsync(user.Id, nameClaim);
                            // 保存するクレームを足すなら、ここ
                            // ・・・
                            // ・・・
                            // ・・・
                        }

                        // 上記の結果の確認
                        if (result.Succeeded)
                        {
                            // SignInAsync、ExternalSignInAsync
                            // 通常のサインイン（外部ログイン「追加」時はSignInAsyncを使用する）
                            await SignInManager.SignInAsync(
                                user,
                                isPersistent: false,    // rememberMe は false 固定（外部ログインの場合）
                                rememberBrowser: true); // rememberBrowser は true 固定

                            // セッションの初期化
                            this.InitSessionAfterlogin();

                            // オペレーション・トレース・ログ出力
                            Logging.MyOperationTrace(string.Format("{0}({1}) has signed in with a verified external account.", user.Id, user.UserName));

                            // リダイレクトしてルートに戻る。
                            return RedirectToLocal(Config.OAuth2AuthorizationServerEndpointsRootURI);
                        }
                        else
                        {
                            // 外部ログインの追加に失敗した場合

                            // 結果のエラー情報を追加
                            this.AddErrors(result);
                        }
                    }
                    else
                    {
                        // サインアップ済みでない → サインアップから行なう。
                        // If the user does not have an account, then prompt the user to create an account
                        // ユーザがアカウントを持っていない場合、アカウントを作成するようにユーザに促します。

                        // 外部ログイン プロバイダのユーザー情報でユーザを作成
                        // **利用者名とメアドを別に渡す**（#151）。
                        user = ApplicationUser.CreateUser(newUserName, email, true);

                        // **上流が検証していないメアドを「確認済み」として定着させない**（#140）。
                        user.EmailConfirmed = Sts.AccountLink.EmailConfirmedForNewUser(emailVerified);

                        // ユーザの新規作成（パスワードは不要）
                        result = await UserManager.CreateAsync(user);

                        // 結果の確認
                        if (result.Succeeded)
                        {
                            // ユーザの新規作成が成功した場合

                            // ロールに追加。
                            await this.UserManager.AddToRoleAsync(user.Id, Const.Role_User);
                            await this.UserManager.AddToRoleAsync(user.Id, Const.Role_Admin);

                            // 外部ログイン（ = idClaim）の追加
                            result = await UserManager.AddLoginAsync(user.Id, login);

                            // クレーム（emailClaim, nameClaim, etc.）の追加
                            if (result.Succeeded)
                            {
                                result = await UserManager.AddClaimAsync(user.Id, emailClaim);
                                result = await UserManager.AddClaimAsync(user.Id, nameClaim);
                                // 保存するクレームを足すなら、ここ
                                // ・・・
                                // ・・・
                                // ・・・
                            }

                            // 結果の確認
                            if (result.Succeeded)
                            {
                                // 外部ログインの追加に成功した場合 → サインイン

                                // SignInAsync、ExternalSignInAsync
                                // 通常のサインイン（外部ログイン「追加」時はSignInAsyncを使用する）
                                await SignInManager.SignInAsync(
                                   user: user,
                                   isPersistent: false,    // rememberMe は false 固定（外部ログインの場合）
                                   rememberBrowser: true); // rememberBrowser は true 固定

                                // セッションの初期化
                                this.InitSessionAfterlogin();

                                // オペレーション・トレース・ログ出力
                                Logging.MyOperationTrace(string.Format("{0}({1}) has signed up with a verified external account.", user.Id, user.UserName));

                                // リダイレクトしてルートに戻る。
                                return RedirectToLocal(Config.OAuth2AuthorizationServerEndpointsRootURI);
                            }
                            else
                            {
                                // 外部ログインの追加に失敗した場合

                                // 結果のエラー情報を追加
                                this.AddErrors(result);
                            }
                        }
                        else
                        {
                            // ユーザの新規作成が失敗した場合

                            // 結果のエラー情報を追加
                            this.AddErrors(result);
                        } // else処理済
                    } // else処理済
                } // else処理済
            } // クレーム情報（e-mail, name情報）を取得できなかった。

            // **ここに来た理由を残す**（#253）。
            //   **上で個別のトレースを出していれば、その次の行として出る**（経路の終わりを示す）。
            //   **出ていなければ、利用者の作成や外部ログインの追加に失敗している。**
            Logging.MyOperationTrace("The ID federation did not complete. (the error view was returned)");

            return View("Error");
        }
        
        #endregion
        
        #region SAML2

        /// <summary>SAML2 の ID 連携を始める（上流へ AuthnRequest を送る）</summary>
        /// <returns>ActionResult（上流の SSO へのリダイレクト）</returns>
        /// <remarks>
        /// **OIDC の ID 連携（`id_federation_signin`）と同じ位置づけ**である。
        ///
        /// | | |
        /// |---|---|
        /// | 宛先 | **メタデータの `SingleSignOnService`（HTTP-Redirect）** → `IdFederationSaml2RequestEndpoint`（#291） |
        /// | `Issuer` | **`http://` ＋ 上流に登録された `client_id`** — **上流はこれで SP を引く**（`CmnEndpoints.VerifySamlRequest`） |
        /// | `NameIDFormat` | **`EmailAddress`**（#286 の決め事）。**`NameID` をメアドとして受け取る** |
        /// | ACS URL | **入れない。** **上流が登録値（`redirect_uri_saml`）から解決する**（#276 の照合と食い違わせない） |
        /// | `RelayState` | **state を入れる。** 応答で照合する |
        ///
        /// **`IsPassive` は送らない**（#287 で OIDC の `prompt=none` を外したのと同じ理由）。
        /// **利用者が押している導線なので、上流が画面を出してよい。**
        ///
        /// **サインイン画面の入力値は使わない**（#286 の決め事）。
        /// **SAML に `login_hint` 相当は無く、独自の方法は作らないと決めてある。**
        /// </remarks>
        private async Task<ActionResult> StartIdFederationBySaml2(IdFederationUpstream upstream)
        {
            // upstream には、ID連携の1件設定、n件設定の、いずれかの1件が入る。どちらも null なら、上流が引けない。
            if (upstream == null)
            {
                //  **指定された上流が引けない**（#292）。**理由を残す**（#253）。
                Logging.MyOperationTrace(
                    "The SAML2 ID federation has no usable upstream. (IdFederationUpstreams)");

                return View("Error");
            }

            //  **上流の SSO の口は、メタデータ → 設定の順で決める**（#291）。**メタデータが引けなければ、設定の値。**
            string ssoUrl = await SamlProviders.IdFederationSaml2Metadata.GetSsoUrlAsync(upstream);

            if (string.IsNullOrEmpty(ssoUrl))
            {
                // **宛先が分からなければ、送れない。** **理由を残す**（#253）。
                Logging.MyOperationTrace(
                    "The SAML2 ID federation has no SSO endpoint. (metadata and setting are both empty)");

                return View("Error");
            }

            // **RelayState に入れる state**（#140 と同じ 32 文字）。記号は入れない。
            string state = GetPassword.Generate(32, 0);

            // **要求の組み立ては `IdFederationSaml2Request` に 1 か所だけ置いてある**（#292。**両アプリに同文で置かない**）。
            // **署名鍵は、行に `signing_pfx_file_path` が在れば、その鍵**（無ければ共通設定。Open棟梁 #606 の口で渡している）。
            string id = "";
            string queryString = SamlProviders.IdFederationSaml2Request
                .CreateRedirectRequest(upstream, state, out id);

            Session[Const.IdFederationSaml2State] = state;

            //  **どの上流へ送ったかを控える**（#292。ACS は 1 本）。
            Session[Const.IdFederationSaml2Upstream] = upstream.Key;

            // **応答の InResponseTo と照合する**（#276 と同じ）。
            Session[Const.IdFederationSaml2RequestId] = id;

            return Redirect(ssoUrl + "?" + queryString);
        }

        /// <summary>
        /// IDFederationAssertionConsumerService
        /// SAML2 の ID 連携で、上流のアサーションを受け取る口
        /// </summary>
        /// <param name="samlResponse">SAMLResponse</param>
        /// <param name="relayState">RelayState（送った state）</param>
        /// <param name="sigAlg">SigAlg（Redirect Binding のときだけ付く）</param>
        /// <returns>ActionResultを非同期に返す</returns>
        /// <remarks>
        /// **自己テストの ACS（`AssertionConsumerService`）とは別の口**である。
        ///
        /// | | |
        /// |---|---|
        /// | 自己テストの ACS | **`IsLockedDownTestEndpoints` で閉じる。** 結果を画面に出すだけ |
        /// | **この口** | **閉じない**（本番の導線）。**検証できたらサインインさせる** |
        ///
        /// **検証の本体は Open棟梁 の `SAML2Client.VerifyResponseWithReason`**（#286 / #294）。
        /// **自己テストと同じ本体に、上流の鍵と EntityID を渡す。**
        /// **鍵は、メタデータ → 設定の `.cer` の順で決める**（#291）。
        /// </remarks>
        [AllowAnonymous]
        public async Task<ActionResult> IDFederationAssertionConsumerService(
            string samlResponse, string relayState, string sigAlg)
        {
            #region どの上流から戻ってきたか

            // **開始処理が Session に控えた鍵**で引く（ACS は 1 本）。
            IdFederationUpstream upstream = IdFederationUpstreams.GetOrDefault(
                (string)Session[Const.IdFederationSaml2Upstream], IdFederationUpstream.Saml2);

            Session[Const.IdFederationSaml2Upstream] = ""; // 誤動作防止

            if (upstream == null)
            {
                // **設定が揃っていない。** **理由を残す**（#253 と同じ方針）。
                Logging.MyOperationTrace(
                    "The SAML2 ID federation has no usable upstream. (IdFederationUpstreams)");

                return View("Error");
            }

            #endregion

            #region 応答の検証

            bool isGet = (Request.HttpMethod.ToLower() == "get");
            string queryString = "";

            if (isGet)
            {
                // **Redirect Binding は、クエリ文字列そのものが署名の対象**である。
                string rawUrl = Request.RawUrl;
                queryString = rawUrl.Substring(rawUrl.IndexOf('?') + 1);
            }

            string state = (string)Session[Const.IdFederationSaml2State];
            string requestId = (string)Session[Const.IdFederationSaml2RequestId];

            // 誤動作防止（1 度しか使わない）。
            Session[Const.IdFederationSaml2State] = "";
            Session[Const.IdFederationSaml2RequestId] = "";

            //  上流の署名を検証する鍵（**全部集めて、順に試す**。#291 / #292）
            //    上流の値は n 件設定（IdFederationUpstreams の行・管理画面の行）から来る。
            //    **n 件設定が無いときだけ**、1 件設定（IdFederationSaml2* の単数キー）から組み立てる（下位互換。#292）。
            //
            //    | 順 | 鍵 | n 件設定 | 1 件設定 |
            //    |---|---|---|---|
            //    | 1 | 上流のメタデータの署名鍵（ロールオーバー中は 2 本以上並ぶ） | metadata_url | IdFederationSaml2MetadataUrl |
            //    | 2 | 上流の証明書（いつでも最後の受け皿） | cer_file_path | IdFederationSaml2CerFilePath |
            //
            //    **期待する Issuer（entityID）** は、n 件設定は issuer、1 件設定は IdFederationSaml2IssuerId（無ければ上流として使えない）。
            //    **SAML2 の署名には kid に当たるものが無く、選べない**ので、全部渡して試させる。
            //    **1 本も無ければ通さない**（NoKey で落ち、理由が下のログに残る）。
            //    **OIDC の「鍵を指定しない版」に当たる経路は無い。**
            //    **自分の /samlmetadata は、自分が IdP として署名鍵を広告する口**で、ここでは使わない。
            List<RSA> upstreamKeys =
                await SamlProviders.IdFederationSaml2Metadata.GetSigningKeysAsync(upstream);

            //  **POST Binding のときは、クエリ文字列を渡さない**（空なら POST として検証する）。
            SAML2VerifyResult result = SAML2Client.VerifyResponseWithReason(
                queryString, isGet ? null : samlResponse, upstreamKeys, upstream.Issuer,
                Config.IdFederationSaml2ResponseEndpoint, requestId, relayState, state);

            if (!result.IsValid)
            {
                //  **理由を残す**（#253 / #287 と同じ方針）。**理由は自分で組み立てた文言**なので、そのまま出してよい。
                Logging.MyOperationTrace(string.Format(
                    "The SAML2 ID federation was not accepted. (reason: {0})",
                    SamlProviders.CmnSaml2Response.ReasonOf(
                        result, upstream.Issuer, Config.IdFederationSaml2ResponseEndpoint, requestId)));

                return View("Error");
            }

            if (0 < result.VerifiedKeyIndex)
            {
                //  **ロールオーバー中**（2 本目以降の鍵で通った。#292）。
                Logging.MyOperationTrace(string.Format(
                    "The SAML2 response was verified with key #{0}.", result.VerifiedKeyIndex + 1));
            }

            #endregion

            #region NameID・メアド・email_verified

            //  **連携キーは `NameID`**（上流の EntityID と組で使う）。
            //    **`Transient` は受けない**（#286）**毎回変わる値を連携キーにできない**（SAML Core 8.3.8）。
            if (string.IsNullOrEmpty(result.NameId)
                || result.NameIdFormat == SAML2Enum.NameIDFormat.Transient)
            {
                Logging.MyOperationTrace(string.Format(
                    "The SAML2 ID federation needs a stable NameID. (format: {0}, nameId: {1})",
                    LogSanitizer.Sanitize(result.NameIdFormat?.ToString()),
                    LogSanitizer.Describe(result.NameId)));

                return View("Error");
            }

            //  **メアドは、属性 → `NameID` の順で決める**（#286）。
            //    **属性（`mail`）が在れば、それを使う。**
            //    **`NameIDFormat` が `emailAddress` 以外でも利用者を作れる**ようになる
            //    （`Persistent` の `NameID` を返す上流）。
            //    **無ければ、`emailAddress` の `NameID` をメアドとして扱う。**
            string email = SAML2Attributes.GetEmail(result.Attributes);

            if (string.IsNullOrEmpty(email)
                && result.NameIdFormat == SAML2Enum.NameIDFormat.EmailAddress)
            {
                email = result.NameId;
            }

            if (string.IsNullOrEmpty(email))
            {
                //  **メアドが分からなければ、利用者を引けない**（鍵はメアド。#151）。
                //    **属性の数だけを出す**（値は出さない）。
                Logging.MyOperationTrace(string.Format(
                    "The SAML2 ID federation could not determine the email. "
                        + "(format: {0}, attributes: {1})",
                    LogSanitizer.Sanitize(result.NameIdFormat?.ToString()),
                    result.Attributes.Count));

                return View("Error");
            }

            //  **上流が「検証済み」と言っているか**（#286）。**属性（`email_verified`）が在れば、それに従う。**
            //    **無ければ、`emailAddress` の `NameID` だけを検証済みとして扱う**
            //    （**上流が署名して主張した主体の識別子**である。SAML Core 8.3.2）。
            //    **それ以外は空のまま** — **既存アカウントには結ばず**（`AccountLink`）、
            //    **新規に作る利用者の `EmailConfirmed` も false になる。**
            string emailVerified = SAML2Attributes.GetEmailVerified(result.Attributes);

            if (string.IsNullOrEmpty(emailVerified)
                && result.NameIdFormat == SAML2Enum.NameIDFormat.EmailAddress
                && email == result.NameId)
            {
                emailVerified = "true";
            }

            #endregion

            //  **ここから先は、利用者の結び付けとサインイン**（#286 で分けた。OIDC 側と同じ形）。
            return await this.SignInByIdFederationSaml2(
                result.Issuer, result.NameId, email, SAML2Attributes.GetUserName(result.Attributes), emailVerified);
        }

        /// <summary>検証できたアサーションで、利用者を結び付けてサインインする</summary>
        /// <param name="idpIssuer">上流の Issuer（EntityID）</param>
        /// <param name="federationKey">連携キー（`NameID`）</param>
        /// <param name="email">メアド（属性の `mail`、または `emailAddress` の `NameID`）</param>
        /// <param name="preferredUserName">属性の `uid`（新規作成時の名前に使う。無ければ空）</param>
        /// <param name="emailVerified">上流が言った `email_verified`（言っていなければ空）</param>
        /// <returns>ActionResultを非同期に返す</returns>
        /// <remarks>
        /// **OIDC の ID 連携と同じ形に揃えてある**（#286）。
        ///
        /// | | OIDC | SAML2 |
        /// |---|---|---|
        /// | 連携キー | `(id_token の iss, sub)` | **`(上流の EntityID, NameID)`** |
        /// | 利用者の鍵 | メアド | **メアド**（**属性 → `NameID`**） |
        /// | 新規作成時の名前 | `preferred_username` → メアドの `@` より前 | **属性の `uid`** → メアドの `@` より前 |
        /// | 検証済みのメアドか | 上流の `email_verified` | **属性の `email_verified`** → `emailAddress` の `NameID` |
        ///
        /// **3 つとも属性から受け取る**（Open棟梁 の `SAML2Attributes`）。
        /// **値を決めるのは、呼び出し側（ACS の口）である**（倒し方をそこに置いてある）。
        /// **このメソッドは、受け取った値で結び付けるだけ**で、OIDC 側と同じ形になる。
        /// </remarks>
        private async Task<ActionResult> SignInByIdFederationSaml2(
            string idpIssuer, string federationKey,
            string email, string preferredUserName, string emailVerified)
        {
            IdentityResult result = null;

            //  **新規に作るときの名前は、属性の `uid` → メアドの `@` より前**（#286）。
            //    **OIDC 側の `preferred_username` と同じ扱い**である。
            //    **鍵はメアド**なので、**名前がどちらになっても同じ利用者に結び付く。**
            string newUserName = UserIdentifier.IsValidUserName(preferredUserName)
                ? preferredUserName : UserIdentifier.UserNameFromEmail(email);

            Claim nameClaim = new Claim(OAuth2AndOIDCConst.UrnSubjectClaim, federationKey);
            Claim emailClaim = new Claim(OAuth2AndOIDCConst.UrnEmailClaim, email);

            // **連携キーは (EntityID, NameID)**（#286）。**新しい鍵で登録する**（#140）。
            //   ASP.NET Identity 2 は、検索・追加・サインインで同じ login を使うので、先に作る（OIDC 側と同じ）。
            UserLoginInfo login = new UserLoginInfo(idpIssuer, federationKey);
            ExternalLoginInfo externalLoginInfo = new ExternalLoginInfo();
            externalLoginInfo.Login = login;
            externalLoginInfo.Email = email;

            // 既存の外部ログインを確認する。**連携キー（EntityID, NameID）で引く**（#286。federationKey = NameID）
            ApplicationUser user = await UserManager.FindAsync(login);

            if (user != null)
            {
                // 既存の外部ログインがある場合。
                result = await UserManager.RemoveClaimAsync(user.Id, emailClaim); // del-ins
                result = await UserManager.AddClaimAsync(user.Id, emailClaim);
                result = await UserManager.RemoveClaimAsync(user.Id, nameClaim); // del-ins
                result = await UserManager.AddClaimAsync(user.Id, nameClaim);
                // 保存するクレームを足すなら、ここ
                // ・・・
                // ・・・
                // ・・・

                await SignInManager.ExternalSignInAsync(
                    loginInfo: externalLoginInfo,
                    isPersistent: false);

                this.InitSessionAfterlogin();

                Logging.MyOperationTrace(string.Format(
                    "{0}({1}) has signed in with a SAML2 ID federation.", user.Id, user.UserName));

                return RedirectToLocal(Config.OAuth2AuthorizationServerEndpointsRootURI);
            }

            // サインアップ済みの可能性を探る。**鍵はメアド**（#151。OIDC 側と同じ）。
            user = await UserManager.FindByEmailAsync(email);

            if (user != null)
            {
                // サインアップ済み → 外部ログイン追加だけで済む。

                // **メアドを鍵にして既存アカウントに結ぶなら、検証済みでなければならない**（#140）。
                if (Sts.AccountLink.CheckLinkToExistingUser(emailVerified)
                        == Sts.AccountLinkCheck.NeedsVerifiedEmail)
                {
                    // **結び付けない。** 画面に理由を出し、明示的な追加へ誘導する。
                    Logging.MyOperationTrace(string.Format(
                        "Rejected linking a SAML2 ID federation login to {0}({1}) "
                        + "because the assertion did not assert a verified email.",
                        user.Id, user.UserName));

                    ViewBag.Reason = Resources.AccountViews.ExternalLoginNeedsVerifiedEmail;

                    return View("ExternalLoginFailure");
                }

                // 外部ログイン（ = UserLoginInfo ）の追加
                // **メアドで引いているので、メアドの一致は自明**（#151）。
                result = await UserManager.AddLoginAsync(user.Id, login);

                // クレーム（emailClaim, nameClaim, etc.）の追加
                if (result.Succeeded)
                {
                    result = await UserManager.AddClaimAsync(user.Id, emailClaim);
                    result = await UserManager.AddClaimAsync(user.Id, nameClaim);
                    // 保存するクレームを足すなら、ここ
                    // ・・・
                    // ・・・
                    // ・・・
                }

                if (result.Succeeded)
                {
                    // SignInAsync、ExternalSignInAsync
                    // 通常のサインイン（外部ログイン「追加」時は SignInAsync を使用する）。
                    await SignInManager.SignInAsync(user, isPersistent: false, rememberBrowser: true);

                    // セッションの初期化
                    this.InitSessionAfterlogin();

                    // オペレーション・トレース・ログ出力
                    Logging.MyOperationTrace(string.Format(
                        "{0}({1}) has signed in with a SAML2 ID federation.", user.Id, user.UserName));

                    // リダイレクトしてルートに戻る。
                    return RedirectToLocal(Config.OAuth2AuthorizationServerEndpointsRootURI);
                }
                else
                {
                    // 外部ログインの追加に失敗した場合

                    // 結果のエラー情報を追加
                    this.AddErrors(result);
                }
            }
            else
            {
                // サインアップ済みでない → サインアップから行なう。

                // 外部ログイン プロバイダのユーザー情報でユーザを作成
                // **利用者名とメアドを別に渡す**（#151）。
                user = ApplicationUser.CreateUser(newUserName, email, true);

                // **上流が検証していないメアドを「確認済み」として定着させない**（#140）。
                user.EmailConfirmed = Sts.AccountLink.EmailConfirmedForNewUser(emailVerified);

                // ユーザの新規作成（パスワードは不要）
                result = await UserManager.CreateAsync(user);


                // 結果の確認
                if (result.Succeeded)
                {
                    // ユーザの新規作成が成功した場合

                    // ロールに追加。
                    await this.UserManager.AddToRoleAsync(user.Id, Const.Role_User);
                    await this.UserManager.AddToRoleAsync(user.Id, Const.Role_Admin);

                    // 外部ログイン（ = idClaim）の追加
                    result = await UserManager.AddLoginAsync(user.Id, login);

                    // クレーム（emailClaim, nameClaim, etc.）の追加
                    if (result.Succeeded)
                    {
                        result = await UserManager.AddClaimAsync(user.Id, emailClaim);
                        result = await UserManager.AddClaimAsync(user.Id, nameClaim);
                        // 保存するクレームを足すなら、ここ
                        // ・・・
                        // ・・・
                        // ・・・
                    }

                    if (result.Succeeded)
                    {
                        // 外部ログインの追加に成功した場合 → サインイン

                        // SignInAsync、ExternalSignInAsync
                        // 通常のサインイン（外部ログイン「追加」時はSignInAsyncを使用する）
                        await SignInManager.SignInAsync(user, isPersistent: false, rememberBrowser: true);

                        // セッションの初期化
                        this.InitSessionAfterlogin();

                        // オペレーション・トレース・ログ出力
                        Logging.MyOperationTrace(string.Format(
                            "{0}({1}) has signed in with a SAML2 ID federation.",
                            user.Id, user.UserName));

                        // リダイレクトしてルートに戻る。
                        return RedirectToLocal(Config.OAuth2AuthorizationServerEndpointsRootURI);
                    }
                    else
                    {
                        // 外部ログインの追加に失敗した場合

                        // 結果のエラー情報を追加
                        this.AddErrors(result);
                    }
                }
                else
                {
                    // 結果のエラー情報を追加
                    this.AddErrors(result);
                }
            }

            // **ここに来た理由を残す**（#253 と同じ方針）。
            Logging.MyOperationTrace(
                "The SAML2 ID federation did not complete. (the error view was returned)");

            return View("Error");
        }

        #endregion
    }
}
