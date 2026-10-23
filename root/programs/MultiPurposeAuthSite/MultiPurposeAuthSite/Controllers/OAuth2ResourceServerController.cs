//**********************************************************************************
//* Copyright (C) 2017 Hitachi Solutions,Ltd.
//**********************************************************************************

#region Apache License
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License. 
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
#endregion

//**********************************************************************************
//* クラス名        ：OAuth2ResourceServerController
//* クラス日本語名  ：OAuth2ResourceServerのApiController
//*
//* 作成日時        ：－
//* 作成者          ：－
//* 更新履歴        ：－
//*
//*  日時        更新者            内容
//*  ----------  ----------------  -------------------------------------------------
//*  2017/04/24  西野 大介         新規
//*  2018/12/26  西野 大介         分割
//*  2020/02/27  西野 大介         課金エンドポイント（テスト用→解放）
//*  2020/07/22  西野 大介         クリーンアーキテクチャ維持or放棄 → 放棄
//*  2026/10/04  玄人 幸道         CORSを口ごとの属性にし、資格情報付きを止めた
//*  2026/10/09  西野 大介         オンライン決済サービス処理の削除
//*  2026/10/18  玄人 幸道         動的クライアント登録の口を追加（#307 の段階 1）
//*  2026/10/18  玄人 幸道         管理 API（RFC 7592）の口を追加（#307 の段階 2）
//*  2026/10/21  玄人 幸道         jwks_uri を登録の前に取りに行く（#309 の段階 1）
//*  2026/10/22  玄人 幸道         チャレンジを DPoP にし、DPoP-Nonce を返す（#311 の段階 4）
//*  2026/10/22  玄人 幸道         Authorization ヘッダの読み取りを Open棟梁 に移した（#294）
//**********************************************************************************

using MultiPurposeAuthSite.Co;
using MultiPurposeAuthSite.Entity;
using MultiPurposeAuthSite.Manager;
using MultiPurposeAuthSite.Network;

using MultiPurposeAuthSite.Extensions.Sts;

using Token = MultiPurposeAuthSite.TokenProviders;

using System;
using System.Collections.Generic;
using System.Security.Claims;
using System.Threading.Tasks;

using System.Net;
using System.Net.Http;
using System.Web;
using System.Web.Http;
using System.Web.Http.Cors;
using System.Net.Http.Formatting;

using Microsoft.AspNet.Identity.Owin;

using Newtonsoft.Json;
using Newtonsoft.Json.Linq;

using Touryo.Infrastructure.Business.Presentation;
using Touryo.Infrastructure.Framework.Authentication;
using Touryo.Infrastructure.Public.Security;

/// <summary>MultiPurposeAuthSite.Controllers</summary>
namespace MultiPurposeAuthSite.Controllers
{
    /// <summary>OAuth2ResourceServerのApiController（ライブラリ）</summary>
    //  **CORS はクラスに付けない。** **口ごとに属性で選ぶ**（net10.0 版の #265 と揃える）。
    //  以前はここに origins: "*" ＋ SupportsCredentials = true が付いていた
    //    （**任意のオリジンから、利用者の Cookie を伴った要求が許されていた**）。
    [MyBaseAsyncApiController(httpAuthHeader:
        EnumHttpAuthHeader.None // 認証無くても通すので、
        | EnumHttpAuthHeader.Bearer)] // Bearer認証の結果をGetClaimsで検証。
    public class OAuth2ResourceServerController : ApiController
    {
        #region constructor

        /// <summary>constructor</summary>
        public OAuth2ResourceServerController() { }

        #endregion

        #region property (GetOwinContext)

        /// <summary>ApplicationUserManager</summary>
        private ApplicationUserManager UserManager
        {
            get
            {
                return HttpContext.Current.GetOwinContext().GetUserManager<ApplicationUserManager>();
            }
        }

        /// <summary>ApplicationRoleManager</summary>
        private ApplicationRoleManager RoleManager
        {
            get
            {
                return HttpContext.Current.GetOwinContext().GetUserManager<ApplicationRoleManager>();
            }
        }
        #endregion

        #region テスト用

        #region Hybrid Flow

        /// <summary>
        /// Hybrid Flowのテスト用エンドポイント
        /// POST: /TestHybridFlow
        /// </summary>
        /// <param name="formData">code</param>
        /// <returns>Dictionary(string, string)</returns>
        [HttpPost]
        // **自己テストの画面（OAuth2ImplicitGrantClient）が jQuery で叩く。**
        //   **既定では同一オリジン**（OAuth2AuthorizationServerEndpointsRootURI と
        //   OAuth2ClientEndpointsRootURI が同じ値）なので、本来 CORS は要らない。
        //   **2 つを別ホストにした配備では、クロス オリジンになる**ので開けておく。
        //   **この口は IsLockedDownTestEndpoints で経路ごと閉じる**（WebApiConfig）ため、
        //   **本番では、このポリシーも届かない。**
        //   **資格情報は許さない**（SupportsCredentials を付けない）。
        [EnableCors(origins: "*", headers: "*", methods: "*")]
        public async Task<Dictionary<string, object>> TestHybridFlow(FormDataCollection formData)
        {
            // 変数
            string code = formData[OAuth2AndOIDCConst.code];

            // Tokenエンドポイントにアクセス
            Uri tokenEndpointUri = new Uri(
                Config.OAuth2AuthorizationServerEndpointsRootURI + Config.OAuth2TokenEndpoint);

            // 結果を格納する変数。
            Dictionary<string, object> dic = null;

            //  client_Idから、client_secretを取得。
            string client_id = Helper.GetInstance().GetClientIdByName("TestClient");
            string client_secret = Helper.GetInstance().GetClientSecret(client_id);

            // Hybridは、Implicitのredirect_uriを使用
            string redirect_uri 
                = Config.OAuth2ClientEndpointsRootURI
                + Config.OAuth2ImplicitGrantClient_Account;

            // Tokenエンドポイントにアクセス
            string response = await Helper.GetInstance()
            .GetAccessTokenByCodeAsync(tokenEndpointUri, client_id, client_secret, redirect_uri, code, "");
            dic = JsonConvert.DeserializeObject<Dictionary<string, object>>(response);

            // UserInfoエンドポイントにアクセス
            dic = JsonConvert.DeserializeObject<Dictionary<string, object>>(
                await Helper.GetInstance().GetUserInfoAsync((string)dic[OAuth2AndOIDCConst.AccessToken]));

            return dic;
        }

        #endregion

        #endregion

        #region Dynamic Client Registration（#307 の段階 1 / 段階 2）

        /// <summary>
        /// 動的クライアント登録（RFC 7591 §3.1）
        /// POST: /register
        /// </summary>
        /// <returns>成功は 201、誤りは 400 / 401 / 403（RFC 7591 §3.2）</returns>
        /// <remarks>
        /// **判定と保存は `ClientRegistrationProvider`**（CommonLibrary）**に置いてある** —
        /// **net48 版と net10.0 版で振る舞いを食い違わせないため。**
        /// **ここは「HTTP の口」だけ**である。
        ///
        /// **この口は、`EnableDynamicClientRegistration` が true の配備にしか張られない**
        /// （`WebApiConfig` の経路）。**本番で使う口**なので、
        /// **`IsLockedDownTestEndpoints` の対象ではない。**
        ///
        /// **CORS は開けない** — **サーバ間で叩く口**であり、
        /// **ブラウザから `client_secret` を受け取らせる必要が無い。**
        /// </remarks>
        [HttpPost]
        public async Task<IHttpActionResult> Register()
        {
            // **client_secret を返すので、キャッシュに残さない**（#218 と同じ理由）。
            this.SetNoStore();

            //  **要求の本体**（RFC 7591 §3.1 : `application/json`）。
            string body = await this.Request.Content.ReadAsStringAsync();

            //  **Bearer トークン**（RFC 6750 §2.1）。
            if (!AuthenticationHeader.GetAccessToken(
                HttpContext.Current.Request.Headers[OAuth2AndOIDCConst.HttpHeader_Authorization],
                out string bearerToken, out string authScheme))
            {
                // **トークンが無い**（RFC 6750 §3.1 : エラー コードを付けない）。
                return this.RegistrationError(401, null);
            }

            ClaimsIdentity identity = null;

            //  **`out` の変数は、条件の前で宣言する**（#311 の段階 4。`&&` の短絡）。
            //    **この口の error は登録の側が決める**ので、ここでは使わない —
            //    **チャレンジのスキームと `DPoP-Nonce` は、応答を作る所で付く。**
            string dpopError = null;

            //  **証明書に紐づくトークンは、その証明書を提示した要求でしか使えない**（RFC 8705 §3）。
            if (Token.CmnAccessToken.VerifyAccessToken(bearerToken, out JObject _, out ClaimsIdentity verified)
                && Token.CmnAccessToken.VerifyCertificateBinding(
                    verified, this.Request.GetClientCertificate())
                //  **DPoP に縛られたトークンは、その鍵の証明と一緒でしか使えない**
                //    （RFC 9449 §7.1。#311 の段階 2）。
                && this.VerifyDPoP(verified, bearerToken, authScheme == OAuth2AndOIDCConst.DPoP, out dpopError))
            {
                identity = verified;
            }

            //  **本文の `jwks_uri` は、ここで 1 回取りに行く**（#309 の段階 1）。
            //    **この口は async**。**クライアント認証の経路は同期で待てない**ので、
            //    **登録の時点でキャッシュへ載せる**（**取れなければ `Validate` が `400`**）。
            await ClientRegistrationProvider.WarmUpJwksUriAsync(body);

            int status = ClientRegistrationProvider.Register(
                body, identity, out Dictionary<string, object> ret,
                out Dictionary<string, string> err);

            if (status == 201)
            {
                return this.ResponseMessage(
                    this.Request.CreateResponse(HttpStatusCode.Created, ret));
            }

            return this.RegistrationError(status, err);
        }

        /// <summary>
        /// 登録を読む（RFC 7592 §2.1）
        /// GET: /register/{client_id}
        /// </summary>
        /// <param name="client_id">client_id（`registration_client_uri` の末尾）</param>
        /// <returns>成功は 200、誤りは 401 / 404</returns>
        /// <remarks>
        /// **叩けるのは `registration_access_token` だけ**である（RFC 7592 §2）。
        /// **段階 1 の専用 scope のアクセス トークンでは叩けない** —
        /// **作る権限と、直す権限は別物**である。
        ///
        /// **知らない `client_id` も、他人のトークンも `401`**（§2.1 の MUST。**`404` にしない**）。
        /// </remarks>
        [HttpGet]
        public IHttpActionResult ReadClient(string client_id)
        {
            this.SetNoStore();

            int status = ClientRegistrationProvider.Read(
                client_id, this.GetRegistrationAccessToken(),
                out Dictionary<string, object> ret, out Dictionary<string, string> err);

            if (status == 200)
            {
                return this.ResponseMessage(
                    this.Request.CreateResponse(HttpStatusCode.OK, ret));
            }

            return this.RegistrationError(status, err);
        }

        /// <summary>
        /// 登録を直す（RFC 7592 §2.2。**全置換**）
        /// PUT: /register/{client_id}
        /// </summary>
        /// <param name="client_id">client_id（`registration_client_uri` の末尾）</param>
        /// <returns>成功は 200、誤りは 400 / 401 / 404</returns>
        /// <remarks>
        /// **全置換である**（§2.2）。**省いた項目は消える**ので、
        /// **`GET` で読んで、直して返す**のが前提である（**差分更新は仕様に無い**）。
        /// </remarks>
        [HttpPut]
        public async Task<IHttpActionResult> UpdateClient(string client_id)
        {
            this.SetNoStore();

            string body = await this.Request.Content.ReadAsStringAsync();

            //  **本文の `jwks_uri` は、ここで 1 回取りに行く**（#309 の段階 1）。
            //    **この口は async**。**クライアント認証の経路は同期で待てない**ので、
            //    **登録の時点でキャッシュへ載せる**（**取れなければ `Validate` が `400`**）。
            await ClientRegistrationProvider.WarmUpJwksUriAsync(body);

            int status = ClientRegistrationProvider.Update(
                client_id, body, this.GetRegistrationAccessToken(),
                out Dictionary<string, object> ret, out Dictionary<string, string> err);

            if (status == 200)
            {
                return this.ResponseMessage(
                    this.Request.CreateResponse(HttpStatusCode.OK, ret));
            }

            return this.RegistrationError(status, err);
        }

        /// <summary>
        /// 登録を消す（RFC 7592 §2.3）
        /// DELETE: /register/{client_id}
        /// </summary>
        /// <param name="client_id">client_id（`registration_client_uri` の末尾）</param>
        /// <returns>成功は 204（本体なし）、誤りは 401 / 404</returns>
        /// <remarks>
        /// **`204 No Content`**（§2.3 の MUST）。**本体は付けない。**
        /// **消すと、同じ利用者が登録し直せる**（**`Users.ClientID` は空にしない**。
        /// 一意制約に当たるため。**登録の行が無ければ、`Register` が通す**）。
        /// </remarks>
        [HttpDelete]
        public IHttpActionResult DeleteClient(string client_id)
        {
            this.SetNoStore();

            int status = ClientRegistrationProvider.Delete(
                client_id, this.GetRegistrationAccessToken(),
                out Dictionary<string, string> err);

            if (status == 204)
            {
                return this.ResponseMessage(
                    this.Request.CreateResponse(HttpStatusCode.NoContent));
            }

            return this.RegistrationError(status, err);
        }


        #region DPoP の照合（#311 の段階 2）

        /// <summary>DPoP に縛られたトークンなら、証明を照合する（#311 の段階 2）</summary>
        /// <param name="identity">検証済みの ClaimsIdentity</param>
        /// <param name="accessToken">提示された access_token</param>
        /// <param name="isDPoP">**`DPoP` スキームで来たか**</param>
        /// <param name="dpopError">out : error（**`use_dpop_nonce` のときだけ**。#311 の段階 4）</param>
        /// <returns>使ってよければ true</returns>
        /// <remarks>
        /// **縛っていないトークン（`cnf.jkt` 無し）は、これまでどおり通る**
        /// （**DPoP を知らないクライアントに影響しない**）。
        ///
        /// **`Bearer` スキームで来た要求には、証明を渡さない** ＝
        /// **縛られたトークンなら断る**（RFC 9449 §7.1）。
        /// **縛りを「使う側の出し方」で外せてはいけない。**
        ///
        /// **`htu` は、要求のパスから設定の URL を引く**（`CmnDPoP.EndpointUriOf`。
        /// **`Host` ヘッダは見ない**）。**`htm` は、実際のメソッド**である。
        ///
        /// **`registration_access_token`（RFC 7592）には関わらない** —
        /// **あちらは JWT ではなく、登録の行に突き合わせる資格情報**である。
        /// </remarks>
        private bool VerifyDPoP(
            ClaimsIdentity identity, string accessToken, bool isDPoP, out string dpopError)
        {
            return Token.CmnAccessToken.VerifyDPoPBinding(
                identity, accessToken,
                isDPoP ? HttpContext.Current.Request.Headers[OAuth2AndOIDCConst.HttpHeader_DPoP] : null,
                HttpContext.Current.Request.HttpMethod,
                Token.CmnDPoP.EndpointUriOf(HttpContext.Current.Request.Path),
                out dpopError);
        }

        #endregion

        /// <summary>registration_access_token を取り出す（RFC 6750 §2.1）</summary>
        /// <returns>トークン（無ければ null。出力しないこと）</returns>
        /// <remarks>
        /// **検証はしない** — **JWT ではなく、登録の行に突き合わせるトークン**である
        /// （`ClientRegistrationProvider` が照合する）。
        /// </remarks>
        private string GetRegistrationAccessToken()
        {
            return AuthenticationHeader.GetCredentials(
                HttpContext.Current.Request.Headers[OAuth2AndOIDCConst.HttpHeader_Authorization],
                out string bearerToken) ? bearerToken : null;
        }

        /// <summary>登録の失敗の応答を作る</summary>
        /// <param name="status">HTTP の状態（400 / 401 / 403 / 404）</param>
        /// <param name="err">error / error_description を持つ辞書（無ければ null）</param>
        /// <returns>IHttpActionResult</returns>
        /// <remarks>
        /// **401 / 403 には `WWW-Authenticate: Bearer` を付ける**（RFC 6750 §3）。
        /// **本文は RFC 7591 §3.2.2 の形**（`error` / `error_description`）である。
        /// </remarks>
        private IHttpActionResult RegistrationError(int status, Dictionary<string, string> err)
        {
            HttpResponseMessage res = (err == null)
                ? this.Request.CreateResponse((HttpStatusCode)status)
                : this.Request.CreateResponse((HttpStatusCode)status, err);

            if (status == 401 || status == 403)
            {
                //  **`DPoP` スキームで来た要求には、`DPoP` で答える**（RFC 9449 §7.1。#311 の段階 4）。
                string scheme = AuthenticationHeader.GetChallengeScheme(HttpContext.Current.Request.Headers[OAuth2AndOIDCConst.HttpHeader_Authorization]);

                res.Headers.WwwAuthenticate.Add(
                    new System.Net.Http.Headers.AuthenticationHeaderValue(
                        scheme, Token.CmnEndpoints.GetChallengeParameter(scheme, "register", err)));

                string nonce = Token.CmnDPoP.NonceForChallenge(scheme == OAuth2AndOIDCConst.DPoP);

                if (nonce != null)
                {
                    res.Headers.Add(OAuth2AndOIDCConst.HttpHeader_DPoPNonce, nonce);
                }
            }

            return this.ResponseMessage(res);
        }

        /// <summary>
        /// トークンを含む応答が、キャッシュに残らないようにする（#218 と同じ）
        /// </summary>
        /// <remarks>
        /// **System.Web の Response.Cache を使う。** ヘッダを直接書いても、
        /// ASP.NET のキャッシュ モジュールに上書きされることがあるため。
        /// </remarks>
        private void SetNoStore()
        {
            HttpResponse response = HttpContext.Current.Response;

            response.Cache.SetCacheability(HttpCacheability.NoCache);
            response.Cache.SetNoStore();
        }

        #endregion
    }
}