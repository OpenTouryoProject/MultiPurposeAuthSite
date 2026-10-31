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
//* クラス名        ：CmnEndpoints
//* クラス日本語名  ：CmnEndpoints（ライブラリ）の トークン エンドポイント
//*
//* 作成日時        ：－
//* 作成者          ：－
//* 更新履歴        ：－
//*
//*  日時        更新者            内容
//*  ----------  ----------------  -------------------------------------------------
//*  2026/10/29  玄人 幸道         新規（CmnEndpoints.cs から partial に分割。#294）
//*  2026/10/29  玄人 幸道         Device の refresh_token を返し、異常系・CIBA の client_assertion・refresh_token の照合を直した（#294）
//*  2026/10/29  玄人 幸道         PKCE と private_key_jwt / mTLS を併用できるようにし、PKCE だけの引き換えを登録で絞る。client_credentials / JWT Bearer の sub をクライアントにする。Device の登録種別・ROPC の時間差を直した（#294）
//*  2026/10/29  玄人 幸道         code_verifier の不一致を invalid_grant で返す（RFC 7636 §4.6。#294）
//*  2026/10/30  玄人 幸道         消された利用者・SecurityStamp が変わった利用者の refresh_token を断る（#294）
//*  2026/10/30  玄人 幸道         device_code の引き換えで client_assertion（private_key_jwt）も受ける（#294）
//**********************************************************************************

using MultiPurposeAuthSite.Co;
#if NETFX
using MultiPurposeAuthSite.Entity;
#endif
using MultiPurposeAuthSite.Data;
using MultiPurposeAuthSite.Util;

using MultiPurposeAuthSite.Password;
using MultiPurposeAuthSite.Log;
using MultiPurposeAuthSite.Extensions.Sts;
using MultiPurposeAuthSite.Util.Sts;

using System;
using System.Linq;
using System.Collections.Generic;
using System.Security.Claims;
using System.Security.Cryptography.X509Certificates;

#if NETFX
using Microsoft.AspNet.Identity;
#else
using Microsoft.AspNetCore.Identity;
# endif

using Newtonsoft.Json.Linq;

using Touryo.Infrastructure.Framework.Authentication;
using Touryo.Infrastructure.Public.FastReflection;
using Touryo.Infrastructure.Public.Security.Jwt;

namespace MultiPurposeAuthSite.TokenProviders
{
    /// <summary>CmnEndpoints（トークン エンドポイント）</summary>
    public partial class CmnEndpoints
    {
        #region TokenEndpoint

        #region GrantAuthorizationCodeCredentials

        /// <summary>
        /// GrantAuthorizationCodeCredentials
        /// Authorization Codeグラント種別
        /// </summary>
        /// <param name="grant_type">string</param>
        /// <param name="client_id">string</param>
        /// <param name="client_secret">string</param>
        /// <param name="assertion">string</param>
        /// <param name="x509">X509Certificate2</param>
        /// <param name="code">string</param>
        /// <param name="code_verifier">string</param>
        /// <param name="redirect_uri">string</param>
        /// <param name="dPoPProof">DPoP の証明（#311 の段階 1。無ければ空）</param>
        /// <param name="ret">Dictionary(string, string)</param>
        /// <param name="err">Dictionary(string, string)</param>
        /// <returns>成否</returns>
        public static bool GrantAuthorizationCodeCredentials(
            string grant_type, string client_id, string client_secret,
            string assertion, X509Certificate2 x509, string dPoPProof,
            string code, string code_verifier, string redirect_uri,
            out Dictionary<string, string> ret, out Dictionary<string, string> err)
        {
            ret = null;

            string jwkString = "";
            err = new Dictionary<string, string>();

            //  **DPoP の証明が在れば検証する**（#311 の段階 1）。
            //    **ここで見るのは、code を使う前**である — **断った後に retry できるように。**
            if (!CmnEndpoints.CheckDPoP(dPoPProof, out string jkt, err))
            {
                return false;
            }

            if (Config.EnableAuthorizationCodeGrantType)
            {
                // この要求で、クライアントが何を証明したか（#224）。
                //   以前は水準（permittedLevel）を持ち、登録種別との大小で判定していた。
                //   いまは「経路 × 証明 → 通す登録種別」を ClientModePolicy の表で引く。
                ClientModePolicy.Proof proof = ClientModePolicy.Proof.None;

                #region 認証

                bool authned = false;
                if (grant_type.ToLower() == OAuth2AndOIDCConst.AuthorizationCodeGrantType)
                {
                    //  **まず、送られてきた資格情報でクライアントを認証する。PKCE は、その後で別に検証する**（#294）。
                    //    **以前は「code_verifier が在り、client_secret が無い」を先に見て、PKCE だけで認証していた**ので、
                    //    **client_assertion（private_key_jwt）と mTLS が無視された**（FAPI 2.0 は PKCE と、そのどちらかを両方求める）。
                    //
                    //    | 送られてきたもの | 認証 | 証明（ClientModePolicy） |
                    //    |---|---|---|
                    //    | client_assertion | private_key_jwt | PrivateKeyJwt |
                    //    | client_secret | 秘密 | ClientSecret（PKCE も在れば ClientSecretAndPkce） |
                    //    | 証明書（登録が tls_client_auth） | mTLS | Mtls |
                    //    | code_verifier だけ | **PKCE だけ**（登録が空か none のときだけ。C-40） | PkceS256 / PkcePlain |
                    //
                    //    **証明書は、登録が tls_client_auth のときだけ見る** — 他の登録で証明書を出しても、
                    //    **以前と同じく、PKCE だけの経路に進める**（証明書を出すかどうかは、TLS の設定次第のため）。
                    bool pkceVerified = false;

                    //  **PKCE の検証に落ちたか**（F1。#294）。**クライアント認証の失敗とは分けて返す**（下）。
                    bool pkceFailed = false;

                    if (!string.IsNullOrEmpty(assertion))
                    {
                        // private_key_jwt（client_id はアサーションから得る）
                        authned = CmnEndpoints.ClientAuthentication(
                            assertion, out client_id, ref x509, out proof);
                    }
                    else if (!string.IsNullOrEmpty(client_secret)
                        || (x509 != null
                            && Helper.GetInstance().GetTokenEndpointAuthMethod(client_id)
                                == OAuth2AndOIDCEnum.AuthMethods.tls_client_auth.ToStringByEmit()))
                    {
                        // client_secret（basic / post）または mTLS
                        authned = CmnEndpoints.ClientAuthentication(
                            client_id, client_secret, ref x509, out proof);
                    }
                    else if (!string.IsNullOrEmpty(code_verifier))
                    {
                        // **パブリック クライアント : PKCE だけで認証する**（client_id & code_verifier）
                        //   **登録で認証の方法を明示したクライアントには許さない**（C-40。#294）。
                        //   **空（明示しない）は、従来どおり許す**（`MayUsePkceOnly`）。
                        if (CmnEndpoints.MayUsePkceOnly(client_id))
                        {
                            authned = CmnEndpoints.VerifyPkce(
                                code, client_id, redirect_uri, code_verifier, out bool usedS256);

                            pkceFailed = !authned;

                            // S256 か plain か（#224）。通す登録種別は ClientModePolicy の表で決まる。
                            //   以前は S256 のとき水準を fapi1 に格上げしていた。表では
                            //   「認可コード × PKCE S256 → normal / fapi1 / device」の 1 行にあたる。
                            proof = usedS256
                                ? ClientModePolicy.Proof.PkceS256 : ClientModePolicy.Proof.PkcePlain;

                            pkceVerified = true;
                        }
                        else
                        {
                            Logging.MyOperationTrace(string.Format(
                                "The client authentication of {0} was refused. "
                                + "(PKCE alone is not allowed for the registered token_endpoint_auth_method)",
                                client_id));
                        }
                    }
                    else
                    {
                        // 資格情報が何も無い（従来どおり、認証の失敗として扱う）
                        authned = CmnEndpoints.ClientAuthentication(
                            client_id, client_secret, ref x509, out proof);
                    }

                    //  **認証に加えて、PKCE を検証する**（#220 / #294）。
                    //    **PKCE は種別によらない標準的な防壁**で、クライアント認証と併用される（OAuth 2.1 / FAPI 2.0）。
                    //    **認証は資格情報、PKCE はそれとは別に検証する。両方が通ること。**
                    if (authned && !pkceVerified && !string.IsNullOrEmpty(code_verifier))
                    {
                        authned = CmnEndpoints.VerifyPkce(
                            code, client_id, redirect_uri, code_verifier, out bool _);

                        pkceFailed = !authned;

                        if (proof == ClientModePolicy.Proof.ClientSecret)
                        {
                            proof = ClientModePolicy.Proof.ClientSecretAndPkce;
                        }
                    }

                    //  **code_verifier が合わなければ invalid_grant**（RFC 7636 §4.6。F1。#294）。
                    //    **以前は invalid_client で返していた**（クライアント認証の失敗と区別できなかった）。
                    //    **使用済み・別のクライアントの code・code_challenge の無い code に code_verifier を送った場合も、ここになる**
                    //    （どれも grant の側の誤りである）。
                    if (pkceFailed)
                    {
                        err.Add(OAuth2AndOIDCConst.error, OAuth2AndOIDCConst.invalid_grant);
                        err.Add(OAuth2AndOIDCConst.error_description, "Invalid code_verifier.");
                        return false;
                    }
                }

                #endregion

                // **認可要求で code_challenge を送っていたなら、code_verifier は必須**（RFC 7636 §4.6）。
                //   上の分岐は「**クライアントが何を送ってきたか**」で選ばれるため、
                //   **code_verifier を省くと VerifyPkce を通らずに済んでしまう。**
                //   認可要求の側（code に紐づく code_challenge）から見て、必須性を決める。
                //
                //   **逆向き（code_challenge 無しで code_verifier だけ送る）は VerifyPkce が拒否する。**
                if (authned && string.IsNullOrEmpty(code_verifier)
                    && CmnEndpoints.UsedPkce(code, client_id, redirect_uri))
                {
                    err.Add(OAuth2AndOIDCConst.error, OAuth2AndOIDCConst.invalid_grant);
                    err.Add(OAuth2AndOIDCConst.error_description, "code_verifier is required.");
                    return false;
                }

                //  **認可要求で `dpop_jkt` を送っていたなら、その鍵の証明でしか引き換えられない**
                //    （RFC 9449 §10。#311 の段階 4）。
                //    **PKCE の必須性を code 側から決めるのと同じ考え**である
                //    （**クライアントが何を送ってきたかでは決めない**）。
                //    **code を消費する前に断る** — **断られた後、同じ code でやり直せる。**
                if (authned && !CmnEndpoints.CheckDPoPJktOfCode(code, jkt, err))
                {
                    return false;
                }

                if (authned)
                {
                    string tokenPayload = AuthorizationCodeProvider.Receive(code, client_id, redirect_uri);

                    #region CheckClientMode

                    // このフローが認められるか？
                    if (CmnEndpoints.CheckClientMode(client_id,
                        ClientModePolicy.Flow.AuthorizationCode, proof,
                        out OAuth2AndOIDCEnum.ClientMode clientMode, out jwkString, out err))
                    {
                        // 継続可
                    }
                    else
                    {
                        // 継続不可
                        // err設定済み
                        return false;
                    }

                    #endregion

                    #region 発行

                    // codeが不正（存在しない・使用済み・別Clientのもの）ならpayloadは空になる（#185）。
                    if (string.IsNullOrEmpty(tokenPayload))
                    {
                        err.Add(OAuth2AndOIDCConst.error, OAuth2AndOIDCConst.invalid_grant);
                        err.Add(OAuth2AndOIDCConst.error_description, "Invalid code.");
                        return false;
                    }

                    // access_token
                    // **クレームは、登録された種別（clientMode）で書く**（#220）。
                    //   経路や証明（ClientModePolicy の表。#224）は、トークンの名乗りには使わない。
                    string access_token = CmnAccessToken.ProtectFromPayload(
                        client_id, tokenPayload,
                        DateTimeOffset.Now.Add(Config.OAuth2AccessTokenExpireTimeSpanFromMinutes),
                        x509, clientMode, out string aud, out string sub,
                        // **登録された署名 alg で署名する**（#129 の段階 2）
                        Helper.GetInstance().GetIdTokenSignedResponseAlg(client_id),
                        // **DPoP の鍵に縛る**（#311 の段階 1。**証明が無ければ空**）
                        jkt);

                    // Client認証のclient_idとToken類のaudをチェック
                    if (client_id != aud)
                    {
                        err.Add(OAuth2AndOIDCConst.error, OAuth2AndOIDCConst.invalid_grant);
                        err.Add(OAuth2AndOIDCConst.error_description, "The code was not issued to this client.");
                        return false;
                    }

                    // refresh_token
                    // **登録種別で refresh_token の経路を使えないなら、発行しない**（#224 の段階 2）。
                    //   以前は発行していたが、使うと必ず拒否された（受け取ったのに使えない資格情報）。
                    //   **登録で `refresh_token` を申告していないクライアントにも、発行しない**
                    //     （RFC 7591 §2 の `grant_types`。#307 の段階 1。**登録が無ければ絞らない**）。
                    string refresh_token = "";
                    if (Config.EnableRefreshToken
                        && ClientModePolicy.MayUse(clientMode, ClientModePolicy.Flow.RefreshToken)
                        && CmnEndpoints.CheckClientGrantType(client_id, ClientModePolicy.Flow.RefreshToken))
                    {
                        // **access_token を縛ったなら、refresh_token も同じ鍵に縛る**
                        //   （RFC 9449 §5。#311 の段階 4）。
                        //   **access_token だけを縛っても、更新で縛りの無いものに乗り換えられる。**
                        // **利用者の SecurityStamp も書く**（#294。更新のときに照合する）。
                        refresh_token = RefreshTokenProvider.Create(
                            CmnEndpoints.BindUserOfRefreshToken(client_id, sub,
                                CmnAccessToken.BindJkt(tokenPayload, jkt)));
                    }

                    // オペレーション・トレース・ログ出力
                    string name = Helper.GetInstance().GetClientName(client_id);
                    Logging.MyOperationTrace(string.Format(
                        "{0}({1}) passed the 'Authorization Code flow' by {2}({3}).",
                        client_id, name,                                         // Client Account
                        PPIDExtension.GetUserNameFromSub(client_id, sub), sub)); // User Account (PPID化により...)

                    ret = CmnEndpoints.CreateAccessTokenResponse(
                        access_token, refresh_token, jwkString, jkt);

                    return true;

                    #endregion
                }
                else
                {
                    // クライアント認証エラー（Credential不正
                    err.Add(OAuth2AndOIDCConst.error, OAuth2AndOIDCConst.invalid_client);
                    err.Add(OAuth2AndOIDCConst.error_description, "Invalid credential.");
                }
            }
            else
            {
                // サポートされていない
                err.Add(OAuth2AndOIDCConst.error, OAuth2AndOIDCConst.unsupported_grant_type);
                err.Add(OAuth2AndOIDCConst.error_description, Resources.ApplicationOAuthBearerTokenProvider.EnableAuthorizationCodeGrantType);
            }

            return false;
        }

        #endregion

        // Implicit / Hybrid は、認可エンドポイントで発行する（CmnEndpoints.AuthorizeResponse.cs）。
        // CreateAuthZRes4ImplicitFlow
        // CreateAuthNRes4HybridFlow

        #region GrantRefreshTokenCredentials

        /// <summary>
        /// GrantRefreshTokenCredentials
        /// Authorization Codeグラント種別
        /// </summary>
        /// <param name="grant_type">string</param>
        /// <param name="client_id">string</param>
        /// <param name="client_secret">string</param>
        /// <param name="x509">X509Certificate2</param>
        /// <param name="refresh_token">string</param>
        /// <param name="dPoPProof">DPoP の証明（#311 の段階 1。無ければ空）</param>
        /// <param name="ret">Dictionary(string, string)</param>
        /// <param name="err">Dictionary(string, string)</param>
        /// <returns>成否</returns>
        public static bool GrantRefreshTokenCredentials(
            string grant_type, string client_id, string client_secret, string clientAssertion,
            X509Certificate2 x509, string dPoPProof,
            string refresh_token, out Dictionary<string, string> ret, out Dictionary<string, string> err)
        {
            ret = null;

            string jwkString = "";
            err = new Dictionary<string, string>();

            //  **DPoP の証明が在れば検証する**（#311 の段階 1）。
            //    **ここで見るのは、code を使う前**である — **断った後に retry できるように。**
            if (!CmnEndpoints.CheckDPoP(dPoPProof, out string jkt, err))
            {
                return false;
            }

            if (Config.EnableRefreshToken)
            {
                #region 認証

                bool authned = false;
                ClientModePolicy.Proof proof = ClientModePolicy.Proof.None; // 何を証明したか（#224）
                if (grant_type.ToLower() == OAuth2AndOIDCConst.RefreshTokenGrantType)
                {
                    // client_secret / mTLS / private_key_jwt（#239）
                    authned = CmnEndpoints.ClientAuthentication(
                        client_id, client_secret, clientAssertion,
                        ref x509, out client_id, out proof);
                }

                #endregion

                //  **縛られた refresh_token は、その鍵の証明と一緒でしか使えない**
                //    （RFC 9449 §5。#311 の段階 4）。
                //    **消費する前に断る** — **断られた後、同じ refresh_token でやり直せる**
                //    （**ローテーションで一族ごと失効させてしまわない**。#188 の段階 3）。
                if (authned && !CmnEndpoints.CheckDPoPJktOfRefreshToken(refresh_token, jkt, err))
                {
                    return false;
                }

                //  **他のクライアントの refresh_token なら、消費する前に断る**（#294）。
                //    **以前は `Receive`（消費）の後で `aud` を見ていた**ので、
                //    **他のクライアントが出しただけで使用済みになり**、
                //    **持ち主が次に使うと「再利用」として一族ごと失効した。**
                //    **使用済み・存在しないものは空で通り、後の `Receive` が断る**（断り方は変えない）。
                if (authned)
                {
                    string referred = RefreshTokenProvider.Refer(refresh_token);

                    if (!string.IsNullOrEmpty(referred)
                        && !CmnEndpoints.CheckRefreshTokenOwner(client_id, referred))
                    {
                        err.Add(OAuth2AndOIDCConst.error, OAuth2AndOIDCConst.invalid_grant);
                        err.Add(OAuth2AndOIDCConst.error_description, "The refresh_token was not issued to this client.");
                        return false;
                    }
                }

                if (authned)
                {
                    #region CheckClientMode

                    // このフローが認められるか？
                    //   **登録種別を受け取る**（#245）。トークンのクレームに書くため。
                    if (CmnEndpoints.CheckClientMode(client_id,
                        ClientModePolicy.Flow.RefreshToken, proof,
                        out OAuth2AndOIDCEnum.ClientMode clientMode, out jwkString, out err))
                    {
                        // 継続可
                    }
                    else
                    {
                        // 継続不可
                        // err設定済み
                        return false;
                    }

                    #endregion

                    #region 発行

                    // **一族（FamilyId）を引き継ぐ**（#188 の段階 3）。
                    //   使用済みが再び提示されたら、Receive の中で一族ごと失効させ、空を返す。
                    string tokenPayload = RefreshTokenProvider.Receive(refresh_token, out string familyId);

                    //  **利用者が消された・SecurityStamp が変わった（パスワードの変更など）なら、断る**（#294）。
                    //    **以前は確かめず、預けた payload から作り直していた**ので、
                    //    **利用者を消しても、パスワードを変えても、取り続けられた。**
                    //    **消費（`Receive`）の後で断る** — **新しいものを出さないので、一族はここで終わる。**
                    if (!string.IsNullOrEmpty(tokenPayload)
                        && !CmnEndpoints.CheckUserOfRefreshToken(client_id, ref tokenPayload))
                    {
                        err.Add(OAuth2AndOIDCConst.error, OAuth2AndOIDCConst.invalid_grant);
                        err.Add(OAuth2AndOIDCConst.error_description, "The refresh_token is no longer valid for the user.");
                        return false;
                    }

                    if (!string.IsNullOrEmpty(tokenPayload))
                    {
                        // access_token
                        // **クレームは、登録された種別（clientMode）で書く**（#245）。
                        //   以前は `ClientMode.normal` を固定で渡しており、
                        //   **更新すると fapi クレームが消えていた**（認可コードで得たトークンには載る）。
                        //   **#239 の段階 3 で fapi1 / fapi2 に refresh を開くまでは、
                        //   normal しか通らなかったので無害だった。** 開いたときの取り残し。
                        //   E2E : FA-6.5（mTLS）/ RT-239.5（private_key_jwt）。
                        string access_token = CmnAccessToken.ProtectFromPayload(
                            client_id, tokenPayload,
                            DateTimeOffset.Now.Add(Config.OAuth2AccessTokenExpireTimeSpanFromMinutes),
                            x509, clientMode, out string aud, out string sub,
                            // **登録された署名 alg で署名する**（#129 の段階 2）
                            Helper.GetInstance().GetIdTokenSignedResponseAlg(client_id),
                            // **DPoP の鍵に縛る**（#311 の段階 1。**証明が無ければ空**）
                            jkt);

                        // Client認証のclient_idとToken類のaudをチェック
                        if (client_id != aud)
                        {
                            err.Add(OAuth2AndOIDCConst.error, OAuth2AndOIDCConst.invalid_grant);
                            err.Add(OAuth2AndOIDCConst.error_description, "The refresh_token was not issued to this client.");
                            return false;
                        }

                        // **縛りは、ローテーションしても引き継ぐ**（#311 の段階 4）。
                        //   **引き継がないと、1 回更新するだけで縛りが外れる。**
                        //   （`EnableRefreshToken` は、この関数の入口で見ている）
                        string new_refresh_token = RefreshTokenProvider.Create(
                            CmnEndpoints.BindUserOfRefreshToken(client_id, sub,
                                CmnAccessToken.BindJkt(tokenPayload, jkt)), familyId);

                        // オペレーション・トレース・ログ出力
                        string name = Helper.GetInstance().GetClientName(client_id);
                        Logging.MyOperationTrace(string.Format(
                            "{0}({1}) passed the 'Refresh Token flow' by {2}({3}).",
                            client_id, name,                                         // Client Account
                            PPIDExtension.GetUserNameFromSub(client_id, sub), sub)); // User Account (PPID化により...)

                        ret = CmnEndpoints.CreateAccessTokenResponse(
                            access_token, new_refresh_token, jwkString, jkt);

                        return true;
                    }
                    else
                    {
                        // refresh_tokenが不正（ローテーション済み・存在しない）（#185）。
                        err.Add(OAuth2AndOIDCConst.error, OAuth2AndOIDCConst.invalid_grant);
                        err.Add(OAuth2AndOIDCConst.error_description, "Invalid refresh_token.");
                    }

                    #endregion
                }
                else
                {
                    // クライアント認証エラー（Credential不正
                    err.Add(OAuth2AndOIDCConst.error, OAuth2AndOIDCConst.invalid_client);
                    err.Add(OAuth2AndOIDCConst.error_description, "Invalid credential.");
                }
            }
            else
            {
                // サポートされていない
                err.Add(OAuth2AndOIDCConst.error, OAuth2AndOIDCConst.unsupported_grant_type);
                err.Add(OAuth2AndOIDCConst.error_description, Resources.ApplicationOAuthBearerTokenProvider.EnableRefreshToken);
            }

            return false;
        }

        #endregion

        #region GrantResourceOwnerCredentials

        /// <summary>GrantResourceOwnerCredentials</summary>
        /// <param name="grant_type">string</param>
        /// <param name="client_id">string</param>
        /// <param name="client_secret">string</param>
        /// <param name="x509">X509Certificate2</param>
        /// <param name="dPoPProof">DPoP の証明（#311 の段階 1。無ければ空）</param>
        /// <param name="username">string</param>
        /// <param name="password">string</param>
        /// <param name="scopes">string</param>
        /// <param name="ret">Dictionary(string, string)</param>
        /// <param name="err">Dictionary(string, string)</param>
        /// <returns>成否</returns>
        /// <remarks>
        /// **このグラントは、利用者のパスワードを `/token` に流す**（RFC 6749 §4.3）。
        /// **雛形の既定では無効**（`EnableResourceOwnerPasswordCredentialsGrantType`）。
        ///
        /// **パスワードの失敗を数える**（#305 の段階 4）。
        ///
        /// **段階 4 より前は、ここだけ数えていなかった。**
        /// **`VerifyHashedPassword` を直に呼んでいて、`SignInManager` を通らない**ため、
        /// **画面のサインインのロックアウトが効かず、何回でも試せた**
        /// （クライアント認証の失敗は数えていたが、**それはクライアントの秘密の話**であって、
        /// **同じ `client_id` の下で利用者名を変えながら試す経路は止まらなかった**）。
        ///
        /// **画面のサインインと同じ数えに合流させた** —
        /// `MaxFailedAccessAttemptsBeforeLockout` /
        /// `DefaultAccountLockoutTimeSpanFromSeconds` /
        /// `UserLockoutEnabledByDefault`（`Users` 表の `AccessFailedCount` と
        /// `LockoutEndDateUtc`）。**別の数えを作らない** —
        /// **口を変えれば回数が戻る、という抜けを作らないため。**
        ///
        /// **応答は、どの場合も `access_denied` のまま。**
        /// **「利用者が居ない」「パスワードが違う」「断っている」を区別させない**
        /// （`TC-4.2` が、この区別が付かないことを測っている）。
        ///
        /// **利用者名が見つからないときは数えられない**（鍵が無い）。
        /// **利用者名を変えながら試す経路は、口ごとのレート制限が頭を打つ**（段階 3）。
        /// </remarks>
        public static bool GrantResourceOwnerCredentials(
            string grant_type, string client_id,
            string client_secret, string clientAssertion, X509Certificate2 x509,
            string dPoPProof, string username, string password, string scopes,
            out Dictionary<string, string> ret, out Dictionary<string, string> err)
        {
            ret = null;

            string jwkString = "";
            err = new Dictionary<string, string>();

            //  **DPoP の証明が在れば検証する**（#311 の段階 1）。
            //    **ここで見るのは、code を使う前**である — **断った後に retry できるように。**
            if (!CmnEndpoints.CheckDPoP(dPoPProof, out string jkt, err))
            {
                return false;
            }

            if (Config.EnableResourceOwnerPasswordCredentialsGrantType)
            {
                #region 認証

                bool authned = false;
                ClientModePolicy.Proof proof = ClientModePolicy.Proof.None; // 何を証明したか（#224）
                if (grant_type.ToLower() == OAuth2AndOIDCConst.ResourceOwnerPasswordCredentialsGrantType)
                {
                    // client_secret / mTLS / private_key_jwt（#239）
                    authned = CmnEndpoints.ClientAuthentication(
                        client_id, client_secret, clientAssertion,
                        ref x509, out client_id, out proof);
                }

                #endregion

                if (authned)
                {
                    #region CheckClientMode

                    // このフローが認められるか？
                    if (CmnEndpoints.CheckClientMode(client_id,
                        ClientModePolicy.Flow.ResourceOwnerPassword, proof,
                        out OAuth2AndOIDCEnum.ClientMode _, out jwkString, out err))
                    {
                        // 継続可
                    }
                    else
                    {
                        // 継続不可
                        // err設定済み
                        return false;
                    }

                    #endregion

                    #region 発行

                    // username=ユーザ名&password=パスワードとして送付されたクレデンシャルを検証する。
                    ApplicationUser user = CmnUserStore.FindByName(username);

                    if (user != null)
                    {
                        //  **断っている間は、正しいパスワードでも通さない**（#305 の段階 4）。
                        //    **画面のサインインと同じ数え**（ASP.NET Identity のロックアウト）。
                        //    **応答は誤パスワードと同じ `access_denied`**
                        //    （**断っていること自体を教えない**）。
                        if (CmnEndpoints.IsUserLockedOut(user))
                        {
                            err.Add(OAuth2AndOIDCConst.error, OAuth2AndOIDCConst.access_denied);
                            err.Add(OAuth2AndOIDCConst.error_description,
                                Resources.ApplicationOAuthBearerTokenProvider.access_denied);

                            return false;
                        }

                        // ユーザーが見つかった場合。
#if NETFX
                        PasswordVerificationResult pvRet = (new CustomPasswordHasher()).VerifyHashedPassword(user.PasswordHash, password);
#else
                        PasswordVerificationResult pvRet = (new CustomPasswordHasher<ApplicationUser>()).VerifyHashedPassword(user, user.PasswordHash, password);
#endif
                        if (pvRet.HasFlag(PasswordVerificationResult.Success))
                        {
                            //  **成功したので、数えた分は消す**（#305 の段階 4）。
                            CmnEndpoints.ResetUserAccessFailed(user);

                            // ClaimsIdentityにClaimを追加する。
                            ClaimsIdentity identity = new ClaimsIdentity(OAuth2AndOIDCConst.Bearer);

                            // Name Claimを追加
                            identity.AddClaim(new Claim(ClaimTypes.Name, user.UserName));

                            // scopes_supported に無いスコープと、クライアントに許されていないスコープは発行しない（#198）
                            //   **`scope` は省略できる**（RFC 6749 §4.3.2。#294 で null を受けるようにした）。
                            List<string> issuedScopes = new List<string>(
                                Helper.FilterSupportedScopes((scopes ?? "").Split(' '), client_id));

                            //  **クライアント登録の管理 API 専用のトークンは、scope も期限も絞る**
                            //    （#307 の段階 1）。
                            //
                            //  **他の scope と混ぜない** — **登録を作れる権限を持ったトークンが、**
                            //    **利用者の属性を読む用途でも使い回されると、寿命を短くした意味が薄れる。**
                            //    **要求に `client_registration` が入っていたら、それ 1 本のトークンにする。**
                            //
                            //  **この scope は、登録に明記したクライアントにしか付かない**
                            //    （`Helper.FilterSupportedScopes`）。
                            TimeSpan expires = Config.OAuth2AccessTokenExpireTimeSpanFromMinutes;

                            if (issuedScopes.Contains(Const.ScopeClientRegistration))
                            {
                                issuedScopes = new List<string>() { Const.ScopeClientRegistration };
                                expires = Config.DcrAccessTokenExpireTimeSpanFromSeconds;
                            }

                            // ClaimsIdentityに、その他、所定のClaimを追加する。
                            identity = Helper.AddClaim(identity, client_id, issuedScopes, null, "");

                            // access_token
                            string access_token = CmnAccessToken.CreateFromClaims(
                            	client_id, identity.Name, identity.Claims,
                                DateTimeOffset.Now.Add(expires),
                                // **登録された署名 alg で署名する**（#129 の段階 2）
                                Helper.GetInstance().GetIdTokenSignedResponseAlg(client_id),
                                // **DPoP の鍵に縛る**（#311 の段階 1）
                                jkt);

                            // オペレーション・トレース・ログ出力
                            string name = Helper.GetInstance().GetClientName(client_id);
                            Logging.MyOperationTrace(string.Format(
                                "{0}({1}) passed the 'resource owner password credentials flow' by {2}({3}).",
                                user.Id, user.UserName, // User Account
                                client_id, name));      // Client Account

                            // **`expires_in` は、実際に付けた期限で返す**（#294。専用 scope のトークンは短い）。
                            ret = CmnEndpoints.CreateAccessTokenResponse(
                                access_token, "", jwkString, jkt, expires);
                            return true;
                        }
                        else
                        {
                            //  **失敗を 1 回数える**（#305 の段階 4）。
                            //    **上限に達したら、一定時間断る。**
                            CmnEndpoints.RecordUserAccessFailed(user);

                            // パスワードが一致しない場合。
                            err.Add(OAuth2AndOIDCConst.error, OAuth2AndOIDCConst.access_denied);
                            err.Add(OAuth2AndOIDCConst.error_description, Resources.ApplicationOAuthBearerTokenProvider.access_denied);
                        }
                    }
                    else
                    {
                        // ユーザーが見つからない場合。
                        //   **パスワードの照合と同じだけ時間を掛ける**（#294）。
                        //   **掛けないと、応答の速さで利用者が居るかどうかが分かる**（応答の文面は揃えてある。TC-4.2）。
                        CmnEndpoints.VerifyDummyPassword(password);

                        err.Add(OAuth2AndOIDCConst.error, OAuth2AndOIDCConst.access_denied);
                        err.Add(OAuth2AndOIDCConst.error_description, Resources.ApplicationOAuthBearerTokenProvider.access_denied);
                    }

                    #endregion
                }
                else
                {
                    // クライアント認証エラー（Credential不正
                    err.Add(OAuth2AndOIDCConst.error, OAuth2AndOIDCConst.invalid_client);
                    err.Add(OAuth2AndOIDCConst.error_description, "Invalid credential.");
                }
            }
            else
            {
                // サポートされていない
                err.Add(OAuth2AndOIDCConst.error, OAuth2AndOIDCConst.unsupported_grant_type);
                err.Add(OAuth2AndOIDCConst.error_description, Resources.ApplicationOAuthBearerTokenProvider.EnableResourceOwnerCredentialsGrantType);
            }

            return false;
        }

        /// <summary>照合に使うだけの、誰のものでもないハッシュ（#294）</summary>
        /// <remarks>**最初に要るときに 1 回だけ作る**（ストレッチを掛けるので安くない）。</remarks>
        private static readonly Lazy<string> DummyPasswordHash = new Lazy<string>(() =>
#if NETFX
            (new CustomPasswordHasher()).HashPassword(Guid.NewGuid().ToString("N")));
#else
            (new CustomPasswordHasher<ApplicationUser>()).HashPassword(null, Guid.NewGuid().ToString("N")));
#endif

        /// <summary>利用者が居ないときにも、パスワードの照合と同じだけ時間を掛ける（#294）</summary>
        /// <param name="password">送られてきたパスワード</param>
        /// <remarks>
        /// **結果は使わない。** **応答の速さで「利用者が居るか」を分からせないため**だけに照合する。
        /// </remarks>
        private static void VerifyDummyPassword(string password)
        {
#if NETFX
            (new CustomPasswordHasher()).VerifyHashedPassword(
                CmnEndpoints.DummyPasswordHash.Value, password ?? "");
#else
            (new CustomPasswordHasher<ApplicationUser>()).VerifyHashedPassword(
                null, CmnEndpoints.DummyPasswordHash.Value, password ?? "");
#endif
        }

        #endregion

        #region GrantClientCredentials

        /// <summary>
        /// GrantClientCredentials
        /// Client Credentialsグラント種別
        /// </summary>
        /// <param name="grant_type">string</param>
        /// <param name="client_id">string</param>
        /// <param name="client_secret">string</param>
        /// <param name="x509">X509Certificate2</param>
        /// <param name="dPoPProof">DPoP の証明（#311 の段階 1。無ければ空）</param>
        /// <param name="scopes">string</param>
        /// <param name="ret">Dictionary(string, string)</param>
        /// <param name="err">Dictionary(string, string)</param>
        /// <returns>成否</returns>
        public static bool GrantClientCredentials(
            string grant_type, string client_id, string client_secret, string clientAssertion,
            X509Certificate2 x509, string dPoPProof,
            string scopes, out Dictionary<string, string> ret, out Dictionary<string, string> err)
        {
            ret = null;

            string jwkString = "";
            err = new Dictionary<string, string>();

            //  **DPoP の証明が在れば検証する**（#311 の段階 1）。
            //    **ここで見るのは、code を使う前**である — **断った後に retry できるように。**
            if (!CmnEndpoints.CheckDPoP(dPoPProof, out string jkt, err))
            {
                return false;
            }

            //  **動的登録のための細い道**（#307 の段階 5-b）。
            //    **`EnableClientCredentialsGrantType` が false でも、
            //    専用 scope（`client_registration`）を要求したときだけ通す。**
            //
            //  **なぜ分けるか** : **「CI から登録を作りたい」だけなのに、
            //    `client_credentials` を配備全体で開けさせるのは広すぎる**
            //    （**この経路は利用者の居ないトークンを出す**）。
            //
            //  **要求の scope で判断する**（**発行の段で、実際に出る scope をもう一度見る**）。
            bool dcrOnly = !Config.EnableClientCredentialsGrantType
                && Config.EnableDynamicClientRegistration
                && (scopes ?? "").Split(new char[] { ' ' },
                        StringSplitOptions.RemoveEmptyEntries)
                    .Contains(Const.ScopeClientRegistration);

            if (Config.EnableClientCredentialsGrantType || dcrOnly)
            {
                #region 認証

                bool authned = false;
                ClientModePolicy.Proof proof = ClientModePolicy.Proof.None; // 何を証明したか（#224）
                if (grant_type.ToLower() == OAuth2AndOIDCConst.ClientCredentialsGrantType)
                {
                    // client_secret / mTLS / private_key_jwt（#239）
                    authned = CmnEndpoints.ClientAuthentication(
                        client_id, client_secret, clientAssertion,
                        ref x509, out client_id, out proof);
                }

                #endregion

                if (authned)
                {
                    #region CheckClientMode

                    // このフローが認められるか？
                    if (CmnEndpoints.CheckClientMode(client_id,
                        ClientModePolicy.Flow.ClientCredentials, proof,
                        out OAuth2AndOIDCEnum.ClientMode _, out jwkString, out err))
                    {
                        // 継続可
                    }
                    else
                    {
                        // 継続不可
                        // err設定済み
                        return false;
                    }

                    #endregion

                    #region 発行

                    // client_idに対応するsubを取得する。
                    string sub = Helper.GetInstance().GetClientName(client_id);

                    // ClaimsIdentityにClaimを追加する。
                    ClaimsIdentity identity = new ClaimsIdentity(OAuth2AndOIDCConst.Bearer);

                    // ClaimsIdentityに、その他、所定のClaimを追加する。
                    identity.AddClaim(new Claim(ClaimTypes.Name, sub));

                    // scopes_supported に無いスコープと、クライアントに許されていないスコープは発行しない（#198）
                    //   **`scope` は省略できる**（RFC 6749 §4.4.2。#294 で null を受けるようにした）。
                    List<string> issuedScopes = new List<string>(
                        Helper.FilterSupportedScopes((scopes ?? "").Split(' '), client_id));

                    //  **クライアント登録の管理 API 専用のトークンは、scope も期限も絞る**
                    //    （#307 の段階 5-b。**ROPC と同じ規則**。段階 1）。
                    //
                    //  **他の scope と混ぜない** — **登録を作れる権限を持ったトークンを、
                    //    他の用途でも使い回されると、寿命を短くした意味が薄れる。**
                    //
                    //  **この scope は、登録に明記したクライアントにしか付かない**
                    //    （`Helper.FilterSupportedScopes`）。
                    TimeSpan expires = Config.OAuth2AccessTokenExpireTimeSpanFromMinutes;

                    if (issuedScopes.Contains(Const.ScopeClientRegistration))
                    {
                        issuedScopes = new List<string>() { Const.ScopeClientRegistration };
                        expires = Config.DcrAccessTokenExpireTimeSpanFromSeconds;
                    }
                    else if (dcrOnly)
                    {
                        //  **この経路を開けたのは、専用 scope のためだけ**である。
                        //    **その scope が出ないなら、グラントを開けていないのと同じ**に倒す
                        //    （**クライアントに `client_registration` を登録していないとき**）。
                        //    **断り方を変えない** — **「scope を持っているか」を外から探らせない。**
                        err.Add(OAuth2AndOIDCConst.error, OAuth2AndOIDCConst.unsupported_grant_type);
                        err.Add(OAuth2AndOIDCConst.error_description,
                            Resources.ApplicationOAuthBearerTokenProvider.EnableClientCredentialsGrantType);
                        return false;
                    }

                    identity = Helper.AddClaim(identity, client_id, issuedScopes, null, "");

                    // access_token
                    //   **利用者名を渡さない**（S3。#294）。**sub はクライアント（ClientName）になる。**
                    //   **以前は ClientName と同じ名前の利用者を引き、居ればその利用者の sub にしていた。**
                    //   **ClientName はラベル**（登録の時点の所有者の利用者名）なので、
                    //   **名前を付け替えた後に同じ名前を取った別の利用者に、トークンが結び付いた。**
                    //   **資源所有者の居ないトークン**（RFC 6749 §4.4）である。所有者が要る口は OwnerUserId から引く。
                    string access_token = CmnAccessToken.CreateFromClaims(
                        client_id, "", identity.Claims,
                        DateTimeOffset.Now.Add(expires),
                        // **登録された署名 alg で署名する**（#129 の段階 2）
                        Helper.GetInstance().GetIdTokenSignedResponseAlg(client_id),
                        // **DPoP の鍵に縛る**（#311 の段階 1）
                        jkt);

                    // オペレーション・トレース・ログ出力
                    Logging.MyOperationTrace(string.Format(
                        "Passed the 'client credentials flow' by {0}({1}).",
                        client_id, sub)); // Client Account

                    // **`expires_in` は、実際に付けた期限で返す**（#294。専用 scope のトークンは短い）。
                    ret = CmnEndpoints.CreateAccessTokenResponse(
                        access_token, "", jwkString, jkt, expires);
                    return true;

                    #endregion
                }
                else
                {
                    // クライアント認証エラー（Credential不正
                    err.Add(OAuth2AndOIDCConst.error, OAuth2AndOIDCConst.invalid_client);
                    err.Add(OAuth2AndOIDCConst.error_description, "Invalid credential.");
                }
            }
            else
            {
                // サポートされていない
                err.Add(OAuth2AndOIDCConst.error, OAuth2AndOIDCConst.unsupported_grant_type);
                err.Add(OAuth2AndOIDCConst.error_description, Resources.ApplicationOAuthBearerTokenProvider.EnableClientCredentialsGrantType);
            }

            return false;
        }

        #endregion

        #region GrantJwtBearerTokenCredentials

        /// <summary>
        /// GrantJwtBearerTokenCredentials
        /// Authorization Codeグラント種別
        /// </summary>
        /// <param name="grant_type">string</param>
        /// <param name="assertion">string</param>
        /// <param name="x509">X509Certificate2</param>
        /// <param name="scope">string（トークン要求の scope。RFC 7521 4.1 / RFC 7523 2.1）</param>
        /// <param name="dPoPProof">DPoP の証明（#311 の段階 1。無ければ空）</param>
        /// <param name="ret">Dictionary(string, string)</param>
        /// <param name="err">Dictionary(string, string)</param>
        /// <returns>成否</returns>
        public static bool GrantJwtBearerTokenCredentials(
            string grant_type, string assertion, X509Certificate2 x509, string dPoPProof,
            string scope,
            out Dictionary<string, string> ret, out Dictionary<string, string> err)
        {
            ret = null;

            string jwkString = "";
            err = new Dictionary<string, string>();

            //  **DPoP の証明が在れば検証する**（#311 の段階 1）。
            //    **ここで見るのは、code を使う前**である — **断った後に retry できるように。**
            if (!CmnEndpoints.CheckDPoP(dPoPProof, out string jkt, err))
            {
                return false;
            }

            if (Config.EnableJwtBearerTokenFlowGrantType &&
                grant_type.ToLower() == OAuth2AndOIDCConst.JwtBearerTokenFlowGrantType)
            {
                //  **外から来た値なので、読めなくても例外にしない**（#241 と同じ方針。#294）。
                //    **以前は `Split('.')[1]`・`dic[iss]`・未登録の鍵の復号で 500 になっていた。**
                JObject assertionPayload =
                    string.IsNullOrEmpty(assertion) ? null : JwtReader.TryReadPayload(assertion);

                string assertionIss = CmnEndpoints.StringClaimOf(assertionPayload, OAuth2AndOIDCConst.iss);

                string pubKey = string.IsNullOrEmpty(assertionIss)
                    ? "" : CmnEndpoints.DecodeRegisteredJwk(Helper.GetInstance().GetJwkRsaPublickey(assertionIss));

                if (!string.IsNullOrEmpty(pubKey))
                {
                    //  **ヘッダの alg も、受ける集合に入っていること**（#294）。
                    //    `JwtAssertion.Verify` は **JWK の `kty` で検証器を選び、ヘッダの alg を見ない。**
                    //    **鍵は RSA だけ**なので、**RS256 以外を名乗る JWT は通さない**（名乗りと検証を揃える）。
                    bool algOk = Array.IndexOf(
                        CmnEndpoints.JwtBearerSigningAlgs, JwtReader.TryReadAlg(assertion)) >= 0;

                    //  **読めない形（配列の aud など）でも例外にしない**（#294。`TryVerifyAssertion`）。
                    //    scope は、要求に無ければ assertion の値を使う（下）ので、ここで読んでおく。
                    if (algOk && CmnEndpoints.TryVerifyAssertion(assertion, pubKey, out string iss))
                    {
                        string scopes = CmnEndpoints.StringClaimOf(assertionPayload, OAuth2AndOIDCConst.scope);

                        // aud 検証
                        //   **トークン エンドポイントの URL か issuer**（RFC 7523 §3。#294）。配列は受けない（`IsAssertionAudience`）。
                        if (CmnEndpoints.IsAssertionAudience(assertionPayload))
                        {
                            // このフローが認められるか？
                            if (CmnEndpoints.CheckClientMode(iss,
                                ClientModePolicy.Flow.JwtBearer, ClientModePolicy.Proof.None,
                                out OAuth2AndOIDCEnum.ClientMode _, out jwkString, out err))
                            {
                                // JwtTokenを作る

                                // issに対応するsubを取得する。
                                string sub = Helper.GetInstance().GetClientName(iss);

                                // ClaimsIdentityにClaimを追加する。
                                ClaimsIdentity identity = new ClaimsIdentity(OAuth2AndOIDCConst.Bearer);

                                // ClaimsIdentityに、その他、所定のClaimを追加する。
                                identity.AddClaim(new Claim(ClaimTypes.Name, sub));
                                // **scope は、トークン要求のパラメタが優先**
                                //   （RFC 7521 4.1 / RFC 7523 2.1。#218）。
                                //   要求に無ければ、これまでどおり assertion の値を使う
                                //   （要求に scope を付けていない利用者を壊さないため）。
                                //   **どちらにも無ければ空**（#294。以前は null の `Split` で 500 だった）。
                                string requested = (string.IsNullOrEmpty(scope) ? scopes : scope) ?? "";

                                // scopes_supported に無いスコープと、クライアントに許されていないスコープは発行しない（#198）
                                identity = Helper.AddClaim(identity, iss, Helper.FilterSupportedScopes(requested.Split(' '), iss), null, "");

                                // access_token
                                //   **利用者名を渡さない**（S3。#294。client_credentials と同じ理由）。
                                string access_token = CmnAccessToken.CreateFromClaims(
                                    iss, "", identity.Claims,
                                    DateTimeOffset.Now.Add(Config.OAuth2AccessTokenExpireTimeSpanFromMinutes),
                                    // **登録された署名 alg で署名する**（#129 の段階 2。client_id は iss）
                                    Helper.GetInstance().GetIdTokenSignedResponseAlg(iss),
                                    // **DPoP の鍵に縛る**（#311 の段階 1）
                                    jkt);

                                // オペレーション・トレース・ログ出力
                                Logging.MyOperationTrace(string.Format(
                                    "Passed the 'jwt bearer token flow' by {0}({1}).", iss, sub)); // Client Account

                                ret = CmnEndpoints.CreateAccessTokenResponse(
                                    access_token, "", jwkString, jkt);
                                return true;
                            }
                            else
                            {
                                // 設定済み
                            }
                        }
                        else
                        {
                            // クライアント認証エラー（Credential（aud）不正
                            err.Add(OAuth2AndOIDCConst.error, OAuth2AndOIDCConst.invalid_client);
                            err.Add(OAuth2AndOIDCConst.error_description, "Invalid credential.");
                        }
                    }
                    else
                    {
                        // クライアント認証エラー（Credential（署名）不正
                        err.Add(OAuth2AndOIDCConst.error, OAuth2AndOIDCConst.invalid_client);
                        err.Add(OAuth2AndOIDCConst.error_description, "Invalid credential.");
                    }
                }
                else
                {
                    // クライアント認証エラー（Credential（iss or pubKey）不正
                    err.Add(OAuth2AndOIDCConst.error, OAuth2AndOIDCConst.invalid_client);
                    err.Add(OAuth2AndOIDCConst.error_description, "Invalid credential or pubkey is not set.");
                }
            }
            else if (!Config.EnableJwtBearerTokenFlowGrantType)
            {
                // サポートされていない
                //   **以前は error を入れずに返していた**（#294。応答の `error` が空だった）。
                err.Add(OAuth2AndOIDCConst.error, OAuth2AndOIDCConst.unsupported_grant_type);
                err.Add(OAuth2AndOIDCConst.error_description, Resources.ApplicationOAuthBearerTokenProvider.EnableJwtBearerTokenFlowGrantType);
            }

            return false;
        }

        #endregion

        #region GrantDeviceAuthZ

        /// <summary>GrantDeviceAuthZ（OAuth 2.0 Device Authorization Grant）</summary>
        /// <param name="grant_type">string</param>
        /// <param name="client_id">string</param>
        /// <param name="device_code">string</param>
        /// <param name="dPoPProof">DPoP の証明（#311 の段階 1。無ければ空）</param>
        /// <param name="ret">Dictionary(string, string)</param>
        /// <param name="err">Dictionary(string, string)</param>
        /// <returns>成否</returns>
        public static bool GrantDeviceAuthZ(
            string grant_type, string client_id, string client_secret, string clientAssertion,
            X509Certificate2 x509, string dPoPProof, string device_code,
            out Dictionary<string, string> ret, out Dictionary<string, string> err)
        {
            ret = null;
            err = new Dictionary<string, string>();

            //  **DPoP の証明が在れば検証する**（#311 の段階 1）。
            //    **ここで見るのは、code を使う前**である — **断った後に retry できるように。**
            if (!CmnEndpoints.CheckDPoP(dPoPProof, out string jkt, err))
            {
                return false;
            }

            if (Config.EnableDeviceAuthZGrantType)
            {
                #region 認証

                // RFC 8628 3.4 : コンフィデンシャル クライアントは認証する（#193）。
                // ※ device_codeとclient_idの紐付けは、この先の
                //    AuthorizationCodeProvider.Receive(code, client_id, "")で確認される。
                //  **`client_assertion`（private_key_jwt）も受ける**（#294）。**client_id は認証できたもの**を使う。
                if (!CmnEndpoints.DeviceAuthZClientAuthentication(
                    client_id, client_secret, clientAssertion, ref x509, out client_id))
                {
                    // クライアント認証エラー（Credential不正
                    err.Add(OAuth2AndOIDCConst.error, OAuth2AndOIDCConst.invalid_client);
                    err.Add(OAuth2AndOIDCConst.error_description, "Invalid credential.");
                    return false;
                }

                // **登録種別で、このグラントを許すか。** 許すのは normal と device だけ。
                //   fapi1 / fapi2 / fapi_ciba の登録は、このグラントでは発行しない。
                //   RFC 6749 5.2 : 認証済みのクライアントに許されていないグラントは unauthorized_client。
                if (!CmnEndpoints.IsDeviceAuthZAllowed(client_id))
                {
                    err.Add(OAuth2AndOIDCConst.error, OAuth2AndOIDCConst.unauthorized_client);
                    err.Add(OAuth2AndOIDCConst.error_description,
                        "This client is not allowed to use the device authorization grant.");
                    return false;
                }

                #endregion

                #region 発行

                // Tokenレスポンスを生成する。
                string code = "";
                OAuth2AndOIDCEnum.DeviceAuthZState deviceState = OAuth2AndOIDCEnum.DeviceAuthZState.not_found;

                // device_code は必須（RFC 8628 §3.4）。無ければ invalid_request（#199）。
                if (string.IsNullOrEmpty(device_code))
                {
                    err.Add(OAuth2AndOIDCConst.error, OAuth2AndOIDCConst.invalid_request);
                    err.Add(OAuth2AndOIDCConst.error_description, "device_code is required.");
                    return false;
                }

                if (DeviceAuthZProvider.ReceiveTokenReq(device_code, out code, out deviceState))
                {
                    // = OAuth2AndOIDCEnum.CibaState.access_permitted
                    // Tokenレスポンス（正常）
                    string tokenPayload = AuthorizationCodeProvider.Receive(code, client_id, "");

                    // codeが不正（別Clientのものなど）ならpayloadは空になる（#185）。
                    if (string.IsNullOrEmpty(tokenPayload))
                    {
                        err.Add(OAuth2AndOIDCConst.error, OAuth2AndOIDCConst.invalid_grant);
                        err.Add(OAuth2AndOIDCConst.error_description, "Invalid device_code.");
                        return false;
                    }

                    // access_token
                    //   **クレームは、登録された種別で書く**（#220 と同じ。#294）。
                    //   **以前は device を固定で書いていた**ので、normal の登録のトークンも device を名乗った。
                    //   （`IsDeviceAuthZAllowed` が normal / device だけを通しているので、読めなければ device に倒す）
                    if (!ClientModePolicy.TryParse(
                        Helper.GetInstance().GetClientMode(client_id), out OAuth2AndOIDCEnum.ClientMode deviceClientMode))
                    {
                        deviceClientMode = OAuth2AndOIDCEnum.ClientMode.device;
                    }

                    string access_token = CmnAccessToken.ProtectFromPayload(
                        client_id, tokenPayload,
                        DateTimeOffset.Now.Add(Config.OAuth2AccessTokenExpireTimeSpanFromMinutes),
                        null, deviceClientMode, out string aud, out string sub,
                        // **登録された署名 alg で署名する**（#129 の段階 2）
                        Helper.GetInstance().GetIdTokenSignedResponseAlg(client_id),
                        // **DPoP の鍵に縛る**（#311 の段階 1）
                        jkt);

                    // Client認証のclient_idとToken類のaudをチェック
                    if (client_id != aud)
                    {
                        err.Add(OAuth2AndOIDCConst.error, OAuth2AndOIDCConst.invalid_grant);
                        err.Add(OAuth2AndOIDCConst.error_description, "The device_code was not issued to this client.");
                        return false;
                    }

                    // refresh_token
                    // **登録種別で refresh_token の経路を使えないなら、発行しない**（#224 の段階 2）。
                    //   device の登録は refresh_token の経路を使えない（normal の登録は従来どおり発行する）。
                    //   **登録で `refresh_token` を申告していないクライアントにも、発行しない**
                    //     （RFC 7591 §2 の `grant_types`。#307 の段階 1。**登録が無ければ絞らない**）。
                    string refresh_token = "";
                    if (Config.EnableRefreshToken
                        && ClientModePolicy.MayUse(
                            Helper.GetInstance().GetClientMode(client_id), ClientModePolicy.Flow.RefreshToken)
                        && CmnEndpoints.CheckClientGrantType(client_id, ClientModePolicy.Flow.RefreshToken))
                    {
                        // **この経路でも、縛ったなら refresh_token も縛る**（#311 の段階 4）。
                        //   **デバイスの経路に `dpop_jkt` は無い**（認可要求がブラウザを通らない）が、
                        //   **`/token` で証明を受けていれば、access_token は縛られている** —
                        //   **refresh_token だけ縛られないのは、穴になる。**
                        // **利用者の SecurityStamp も書く**（#294。更新のときに照合する）。
                        refresh_token = RefreshTokenProvider.Create(
                            CmnEndpoints.BindUserOfRefreshToken(client_id, sub,
                                CmnAccessToken.BindJkt(tokenPayload, jkt)));
                    }

                    // オペレーション・トレース・ログ出力
                    string name = Helper.GetInstance().GetClientName(client_id);
                    Logging.MyOperationTrace(string.Format(
                        "{0}({1}) passed the 'Device Authorization Grant' by {2}({3}).",
                        client_id, name,                                         // Client Account
                        PPIDExtension.GetUserNameFromSub(client_id, sub), sub)); // User Account (PPID化により...)

                    // **作った refresh_token を返す**（#294）。
                    //   **以前は作って保存するだけで、応答に入れていなかった**（使われない行が溜まっていた）。
                    ret = CmnEndpoints.CreateAccessTokenResponse(access_token, refresh_token, "", jkt);

                    return true;
                }
                else
                {
                    // ≠ OAuth2AndOIDCEnum.DeviceAuthZState.access_permitted
                    // Tokenレスポンス（異常）
                    switch (deviceState)
                    {
                        case OAuth2AndOIDCEnum.DeviceAuthZState.authorization_pending:
                            err.Add(OAuth2AndOIDCConst.error, OAuth2AndOIDCEnum.DeviceAuthZState.authorization_pending.ToStringByEmit());
                            break;

                        case OAuth2AndOIDCEnum.DeviceAuthZState.slow_down:

                            //  **速すぎるポーリング**（#305 の段階 1。RFC 8628 §3.5）。
                            //    **まだ承認されていない**（pending と同じ状態）が、
                            //    **間隔を伸ばさせる**ために別の値を返す
                            //    （クライアントは interval を 5 秒伸ばす）。
                            //    **判定は `DeviceAuthZProvider`**（`LastPolledAt` を見る）。
                            err.Add(OAuth2AndOIDCConst.error, OAuth2AndOIDCEnum.DeviceAuthZState.slow_down.ToStringByEmit());
                            break;

                        case OAuth2AndOIDCEnum.DeviceAuthZState.access_denied:
                        case OAuth2AndOIDCEnum.DeviceAuthZState.expired_token:
                            // RFC 8628 §3.5 の値そのもの
                            err.Add(OAuth2AndOIDCConst.error, deviceState.ToStringByEmit());
                            break;

                        default:
                            // not_found（使用済み・発行していない）/ irregularity_data は仕様外の値。
                            // enum 名をそのまま返さず、RFC 6749 §5.2 の invalid_grant で返す（#199）。
                            err.Add(OAuth2AndOIDCConst.error, OAuth2AndOIDCConst.invalid_grant);
                            err.Add(OAuth2AndOIDCConst.error_description, "Invalid device_code.");
                            break;
                    }
                }

                #endregion
                //}
                //else
                //{
                //    // クライアント認証エラー（Credential不正
                //    err.Add(OAuth2AndOIDCConst.error, OAuth2AndOIDCConst.invalid_client);
                //    err.Add(OAuth2AndOIDCConst.error_description, "Invalid credential.");
                //}
            }
            else
            {
                // サポートされていない
                err.Add(OAuth2AndOIDCConst.error, OAuth2AndOIDCConst.unsupported_grant_type);
                err.Add(OAuth2AndOIDCConst.error_description, Resources.ApplicationOAuthBearerTokenProvider.EnableDeviceAuthZGrantType);
            }

            return false;
        }

        #endregion

        #region GrantCiba

        /// <summary>GrantCiba（CIBA）</summary>
        /// <param name="grant_type">string</param>
        /// <param name="client_id">string</param>
        /// <param name="client_secret">string</param>
        /// <param name="clientAssertion">client_assertion（private_key_jwt。#294）</param>
        /// <param name="x509">X509Certificate2</param>
        /// <param name="auth_req_id">string</param>
        /// <param name="dPoPProof">DPoP の証明（#311 の段階 1。無ければ空）</param>
        /// <param name="ret">Dictionary(string, string)</param>
        /// <param name="err">Dictionary(string, string)</param>
        /// <returns>成否</returns>
        public static bool GrantCiba(
            string grant_type, string client_id, string client_secret, string clientAssertion,
            X509Certificate2 x509, string dPoPProof, string auth_req_id,
            out Dictionary<string, string> ret, out Dictionary<string, string> err)
        {
            ret = null;

            string jwkString = "";
            err = new Dictionary<string, string>();

            //  **DPoP の証明が在れば検証する**（#311 の段階 1）。
            //    **ここで見るのは、code を使う前**である — **断った後に retry できるように。**
            if (!CmnEndpoints.CheckDPoP(dPoPProof, out string jkt, err))
            {
                return false;
            }

            if (Config.EnableCibaGrantType)
            {
                #region 認証

                bool authned = false;
                ClientModePolicy.Proof proof = ClientModePolicy.Proof.None; // 何を証明したか（#224）
                if (grant_type.ToLower() == OAuth2AndOIDCConst.CibaGrantType)
                {
                    // client_secret / mTLS / private_key_jwt（#294）
                    //   **以前は `client_assertion` を読んでいなかった。**
                    //   **`/ciba_authz` は受けるのに、ここで断られた**（FAPI-CIBA は private_key_jwt か mTLS を求める）。
                    authned = CmnEndpoints.ClientAuthentication(
                        client_id, client_secret, clientAssertion,
                        ref x509, out client_id, out proof);
                }

                #endregion

                if (authned)
                {
                    #region CheckClientMode

                    // このフローが認められるか？（fapi2に設定
                    if (CmnEndpoints.CheckClientMode(client_id,
                        ClientModePolicy.Flow.Ciba, proof,
                        out OAuth2AndOIDCEnum.ClientMode _, out jwkString, out err))
                    {
                        // 継続可
                    }
                    else
                    {
                        // 継続不可
                        // err設定済み
                        return false;
                    }

                    #endregion

                    #region 発行

                    // Tokenレスポンスを生成する。
                    string code = ""; 
                    OAuth2AndOIDCEnum.CibaState cibaState = OAuth2AndOIDCEnum.CibaState.not_found;

                    if (CibaProvider.ReceiveTokenReq(auth_req_id, out code,  out cibaState))
                    {
                        // = OAuth2AndOIDCEnum.CibaState.access_permitted
                        // Tokenレスポンス（正常）
                        string tokenPayload = AuthorizationCodeProvider.Receive(code, client_id, "");

                        // codeが不正（別Clientのものなど）ならpayloadは空になる（#185）。
                        if (string.IsNullOrEmpty(tokenPayload))
                        {
                            err.Add(OAuth2AndOIDCConst.error, OAuth2AndOIDCConst.invalid_grant);
                            err.Add(OAuth2AndOIDCConst.error_description, "Invalid auth_req_id.");
                            return false;
                        }

                        // access_token
                        string access_token = CmnAccessToken.ProtectFromPayload(
                            client_id, tokenPayload,
                            DateTimeOffset.Now.Add(Config.OAuth2AccessTokenExpireTimeSpanFromMinutes),
                            x509, OAuth2AndOIDCEnum.ClientMode.fapi_ciba, out string aud, out string sub,
                            JwtConst.ES256,
                            // **DPoP の鍵に縛る**（#311 の段階 1）
                            jkt);

                        // Client認証のclient_idとToken類のaudをチェック
                        if (client_id != aud)
                        {
                            err.Add(OAuth2AndOIDCConst.error, OAuth2AndOIDCConst.invalid_grant);
                            err.Add(OAuth2AndOIDCConst.error_description, "The auth_req_id was not issued to this client.");
                            return false;
                        }

                        #region refresh_token
                        // 発行しないことに。
                        // ・単純に要らんのと、
                        // ・現状、refresh_token使った際、ES256にできない。
                        // ので。

                        //// refresh_token
                        //string refresh_token = "";
                        //if (Config.EnableRefreshToken)
                        //{
                        //    refresh_token = RefreshTokenProvider.Create(tokenPayload);
                        //}
                        #endregion

                        // オペレーション・トレース・ログ出力
                        string name = Helper.GetInstance().GetClientName(client_id);
                        Logging.MyOperationTrace(string.Format(
                            "{0}({1}) passed the 'CIBA flow' by {2}({3}).",
                            client_id, name,                                         // Client Account
                            PPIDExtension.GetUserNameFromSub(client_id, sub), sub)); // User Account (PPID化により...)

                        ret = CmnEndpoints.CreateAccessTokenResponse(access_token, "", "", jkt);

                        return true;
                    }
                    else
                    {
                        // ≠ OAuth2AndOIDCEnum.CibaState.access_permitted
                        // Tokenレスポンス（異常）
                        switch (cibaState)
                        {
                            case OAuth2AndOIDCEnum.CibaState.authorization_pending:
                                err.Add(OAuth2AndOIDCConst.error, OAuth2AndOIDCEnum.CibaState.authorization_pending.ToStringByEmit());
                                break;

                            case OAuth2AndOIDCEnum.CibaState.slow_down:

                                //  **速すぎるポーリング**（#305 の段階 1。CIBA §11）。
                                //    **判定は `CibaProvider`**（`LastPolledAt` を見る）。
                                err.Add(OAuth2AndOIDCConst.error, OAuth2AndOIDCEnum.CibaState.slow_down.ToStringByEmit());
                                break;

                            case OAuth2AndOIDCEnum.CibaState.access_denied:
                            case OAuth2AndOIDCEnum.CibaState.expired_token:
                                // CIBA Core §11 の値そのもの
                                err.Add(OAuth2AndOIDCConst.error, cibaState.ToStringByEmit());
                                break;

                            default:
                                // not_found（使用済み・発行していない）/ irregularity_data は仕様外の値。
                                // enum 名をそのまま返さず、RFC 6749 §5.2 の invalid_grant で返す（#294。Device は #199 で直した）。
                                err.Add(OAuth2AndOIDCConst.error, OAuth2AndOIDCConst.invalid_grant);
                                err.Add(OAuth2AndOIDCConst.error_description, "Invalid auth_req_id.");
                                break;
                        }
                    }

                    #endregion
                }
                else
                {
                    // クライアント認証エラー（Credential不正
                    err.Add(OAuth2AndOIDCConst.error, OAuth2AndOIDCConst.invalid_client);
                    err.Add(OAuth2AndOIDCConst.error_description, "Invalid credential.");
                }
            }
            else
            {
                // サポートされていない
                err.Add(OAuth2AndOIDCConst.error, OAuth2AndOIDCConst.unsupported_grant_type);
                err.Add(OAuth2AndOIDCConst.error_description, Resources.ApplicationOAuthBearerTokenProvider.EnableCibaGrantType);
            }

            return false;
        }

        #endregion

        #endregion
    }
}