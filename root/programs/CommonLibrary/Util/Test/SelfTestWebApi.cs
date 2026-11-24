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
//* クラス名        ：SelfTestWebApi
//* クラス日本語名  ：自己テスト用の WebAPI の呼び出し（この認可サーバを RP として呼ぶ）
//*
//* 作成日時        ：－
//* 作成者          ：－
//* 更新履歴        ：－
//*
//*  日時        更新者            内容
//*  ----------  ----------------  -------------------------------------------------
//*  2026/10/31  玄人 幸道         新規（Helper.cs から partial に分割。#294）
//*  2026/10/31  玄人 幸道         CIBA の認証要求で、要求と応答を Dispose する（#294）
//*  2026/11/01  玄人 幸道         Util/Sts/Helper.WebApi.cs から移し、static クラスにした（配置の見直し。#321）
//*  2026/10/31  玄人 幸道         IntrospectTokenAsync の要約を直した（#294）
//*  2026/11/06  玄人 幸道         CIBA の要求を Open棟梁 の CibaAuthZRequestAsync（資格情報を受ける版。OpenTouryo#592）で送る（#337）
//*  2026/11/07  玄人 幸道         FAPI1 で PKCE も送る GetAccessTokenByCodeWithPkceAsync を足した（OpenTouryo#670。#341）
//*  2026/11/08  玄人 幸道         FAPI2 の引き換え・PAR・更新・取り消し・照会を、登録の方法で送る版にした（OpenTouryo#676。#345）
//*  2026/11/24  玄人 幸道         fapi2 の登録（tls_client_auth 以外）の引き換え・更新に DPoP の証明を添え、縛られた access_token の /userinfo を DPoP で呼ぶ（#429）
//**********************************************************************************

using MultiPurposeAuthSite.Co;
using MultiPurposeAuthSite.Util.Sts;

using System;
using System.Collections.Generic;
using System.Net.Http;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

using Newtonsoft.Json.Linq;

using Touryo.Infrastructure.Framework.Authentication;
using Touryo.Infrastructure.Public.FastReflection;
using Touryo.Infrastructure.Public.Security.Jwt;
using Touryo.Infrastructure.Public.Str;

namespace MultiPurposeAuthSite.Util.Test
{
    /// <summary>自己テスト用の WebAPI の呼び出し</summary>
    /// <remarks>
    /// **クライアント（RP）として、この認可サーバを呼ぶ**（各フローの WebAPI）。
    /// **呼ぶのは自己テスト（`SelfTestClient`・HomeController・AccountController.SelfTest）と、テスト用の口だけ**で、
    /// **本番の処理からは呼ばない**（ID 連携は Open棟梁 の `OAuth2AndOIDCClient` を直接使う。#140）。
    ///
    /// **以前は `Util/Sts/Helper` の partial（`Helper.WebApi.cs`）だった**（#321 で移した）。
    /// **`HttpClient` とコンテナ化への対応は `Helper` に残してある**
    /// （**本番の処理も使う** — `OAuth2AndOIDCClient.HttpClient` を Back-Channel Logout や ID 連携が使う）。
    /// </remarks>
    public static class SelfTestWebApi
    {
        #region staticメソッド

        #region コンテナ化サポート

        /// <summary>宛先をコンテナから届く形にする（`Helper.GetContainerizatedAuthZServerUri`）</summary>
        /// <param name="uri">Uri</param>
        /// <returns>Uri</returns>
        /// <remarks>
        /// **先に `Helper` を作る** — **コンストラクタが `OAuth2AndOIDCClient.HttpClient` を設定する**
        /// （クライアント証明書を持つ `HttpClient`）。**static のメソッドを呼ぶだけでは作られないことがある**
        /// （`Helper` の static フィールドに触れないため）。**以前は `Helper` のインスタンス メソッドだった**ので、要らなかった。
        /// </remarks>
        private static Uri ToContainerUri(Uri uri)
        {
            Helper.GetInstance();
            return Helper.GetContainerizatedAuthZServerUri(uri);
        }

        #endregion

        #region DPoP（#429）

        /// <summary>自己テストの DPoP の鍵（プロセスごとに 1 つ。EC の P-256）</summary>
        /// <remarks>
        /// **DPoP の鍵は、登録が要らない**（その場で作り、トークンはその鍵の指紋に縛られる。RFC 9449 §1）。
        /// **プロセスが続く間は同じ鍵**なので、結果の画面のボタン（`/userinfo`・更新）も同じ鍵で証明できる。
        /// </remarks>
        private static readonly Lazy<Tuple<JWS, JObject>> DPoPKey =
            new Lazy<Tuple<JWS, JObject>>(SelfTestWebApi.CreateDPoPKey);

        /// <summary>DPoP の鍵を作る</summary>
        /// <returns>署名する JWS と、公開鍵の JWK</returns>
        private static Tuple<JWS, JObject> CreateDPoPKey()
        {
            using (ECDsa ecdsa = ECDsa.Create(ECCurve.NamedCurves.nistP256))
            {
                JObject privateJwk = JObject.Parse(
                    new EccPrivateKeyConverter().ParamToJwk(ecdsa.ExportParameters(true)));

                JWS signer = JwsFactory.CreateFromPrivateJwk("ES256", privateJwk);

                //  **公開鍵は必須の項目だけ**（RFC 7638 の指紋の材料。秘密の `d` を出さない）。
                JObject publicJwk = new JObject()
                {
                    { "kty", privateJwk["kty"] },
                    { "crv", privateJwk["crv"] },
                    { "x", privateJwk["x"] },
                    { "y", privateJwk["y"] }
                };

                return Tuple.Create(signer, publicJwk);
            }
        }

        /// <summary>このクライアントの要求に、DPoP の証明を添えるか</summary>
        /// <param name="credential">送るクライアント認証</param>
        /// <returns>添えるなら true</returns>
        /// <remarks>
        /// **fapi2 の登録は、送信者に縛れないトークン要求を断る**（FAPI 2.0 Security Profile §5.3.2.1 の 4。#429）。
        /// **`tls_client_auth` の登録（MTLS のボタン）は、証明書に縛られる**ので、添えない（今までどおり）。
        /// </remarks>
        private static bool UsesDPoP(SelfTestClient.ClientCredential credential)
        {
            return credential.AuthMethod != OAuth2AndOIDCEnum.AuthMethods.tls_client_auth
                && Helper.GetInstance().GetClientMode(credential.ClientId)
                    == OAuth2AndOIDCEnum.ClientMode.fapi2.ToStringByEmit();
        }

        /// <summary>DPoP の証明を添えて、トークン エンドポイントへ要求する（private_key_jwt で認証する）</summary>
        /// <param name="tokenEndpointUri">TokenエンドポイントのUri（**コンテナ化の対応をする前のもの**。`htu` に入れる）</param>
        /// <param name="credential">送るクライアント認証（`UsesDPoP` が true のもの。fapi2 の private_key_jwt）</param>
        /// <param name="body">grant_type などの本文</param>
        /// <returns>結果のJSON文字列</returns>
        private static async Task<string> TokenRequestWithDPoPAsync(
            Uri tokenEndpointUri, SelfTestClient.ClientCredential credential, Dictionary<string, string> body)
        {
            //  **fapi2 で DPoP を添えるのは private_key_jwt のときだけ**（`UsesDPoP`。fapi2 は client_secret を許さない）。
            Dictionary<string, string> form = new Dictionary<string, string>(body)
            {
                { "client_id", credential.ClientId },
                { "client_assertion_type", "urn:ietf:params:oauth:client-assertion-type:jwt-bearer" },
                { "client_assertion", credential.ClientAssertion }
            };

            return await SelfTestWebApi.SendWithDPoPAsync(
                HttpMethod.Post, tokenEndpointUri, () => new FormUrlEncodedContent(form), null);
        }

        /// <summary>DPoP の証明を添えて送る</summary>
        /// <param name="method">HTTP メソッド</param>
        /// <param name="uri">宛先（**コンテナ化の対応をする前のもの**。`htu` に入れる）</param>
        /// <param name="createContent">本文を作る（送り直すときに作り直すため。無ければ null）</param>
        /// <param name="accessToken">資源への要求なら access_token（`Authorization: DPoP` と `ath`。トークン要求なら null）</param>
        /// <returns>応答の本文</returns>
        /// <remarks>
        /// **`htu` は、設定から作った宛先（コンテナ化の対応をする前）にする。** **要求は、コンテナ化の対応をした宛先へ送る。**
        /// **サーバは `htu` の期待値を設定から作る**（`CmnDPoP.TokenEndpointUri`。要求の `Host` を信じない）ので、
        /// **書き換えた宛先を `htu` に入れると、コンテナの配備（`OAuth2ContainerizatedAuthSvr*`）で断られる**（#429 の別モデルのレビューの指摘）。
        /// **Open棟梁 の `TokenRequestWithDPoPAsync`・`SendWithDPoPAsync` は、`htu` を送る宛先から取る**ので、ここでは使わない。
        /// **`use_dpop_nonce` で断られたら、受け取った nonce を入れて 1 回だけ送り直す**（RFC 9449 §8・§9。Open棟梁 の口と同じ振る舞い）。
        /// </remarks>
        private static async Task<string> SendWithDPoPAsync(
            HttpMethod method, Uri uri, Func<HttpContent> createContent, string accessToken)
        {
            Tuple<JWS, JObject> key = SelfTestWebApi.DPoPKey.Value;
            Uri sendUri = SelfTestWebApi.ToContainerUri(uri);
            string htu = uri.GetLeftPart(UriPartial.Path);
            string nonce = null;

            for (int attempt = 0; ; attempt++)
            {
                using (HttpRequestMessage req = new HttpRequestMessage(method, sendUri))
                {
                    if (createContent != null)
                    {
                        req.Content = createContent();
                    }

                    req.Headers.Add(OAuth2AndOIDCConst.HttpHeader_DPoP,
                        DPoPProof.Create(key.Item1, key.Item2, method.Method, htu, accessToken, nonce));

                    if (accessToken != null)
                    {
                        req.Headers.Authorization = new System.Net.Http.Headers.AuthenticationHeaderValue(
                            OAuth2AndOIDCConst.DPoP, accessToken);
                    }

                    using (HttpResponseMessage res = await OAuth2AndOIDCClient.HttpClient.SendAsync(req))
                    {
                        string responseBody = await res.Content.ReadAsStringAsync();

                        //  **`use_dpop_nonce`**：Token エンドポイントは本文（400）で、資源は `WWW-Authenticate`（401）で返す（RFC 9449 §8・§9）。
                        //    **新しい nonce は `DPoP-Nonce` ヘッダ**で来る。
                        if (attempt == 0
                            && (responseBody.Contains("use_dpop_nonce")
                                || res.Headers.WwwAuthenticate.ToString().Contains("use_dpop_nonce"))
                            && res.Headers.TryGetValues(OAuth2AndOIDCConst.HttpHeader_DPoPNonce, out IEnumerable<string> nonces))
                        {
                            nonce = System.Linq.Enumerable.FirstOrDefault(nonces);

                            if (!string.IsNullOrEmpty(nonce))
                            {
                                continue;
                            }
                        }

                        return responseBody;
                    }
                }
            }
        }

        /// <summary>access_token が DPoP の鍵に縛られているか（payload の `cnf.jkt`）</summary>
        /// <param name="accessToken">access_token</param>
        /// <returns>縛られていれば true（読めなければ false）</returns>
        private static bool IsDPoPBound(string accessToken)
        {
            try
            {
                string[] parts = (accessToken ?? "").Split('.');

                if (parts.Length < 2)
                {
                    return false;
                }

                JObject payload = JObject.Parse(
                    Encoding.UTF8.GetString(CustomEncode.FromBase64UrlString(parts[1])));

                return payload[OAuth2AndOIDCConst.cnf] is JObject cnf
                    && cnf["jkt"] != null;
            }
            catch (Exception)
            {
                //  **自己テストの表示のための判定**（読めなければ、従来どおり Bearer で送る）。
                return false;
            }
        }

        #endregion

        #region HTTP

        #region 基本 4 フローのWebAPI

        /// <summary>
        /// Authentication Code : codeからAccess Tokenを取得する。
        /// </summary>
        /// <param name="tokenEndpointUri">TokenエンドポイントのUri</param>
        /// <param name="client_id">client_id</param>
        /// <param name="client_secret">client_secret</param>
        /// <param name="redirect_uri">redirect_uri</param>
        /// <param name="code">code</param>
        /// <returns>結果のJSON文字列</returns>
        public static async Task<string> GetAccessTokenByCodeAsync(
            Uri tokenEndpointUri, string client_id, string client_secret, string redirect_uri, string code)
        {
            // コンテナ化サポート
            tokenEndpointUri = SelfTestWebApi.ToContainerUri(tokenEndpointUri);

            // WebAPI呼び出し。
            return await OAuth2AndOIDCClient.GetAccessTokenByCodeAsync(
                tokenEndpointUri, client_id, client_secret, redirect_uri, code);
        }

        /// <summary>
        /// Resource Owner Password Credentials Grant
        /// </summary>
        /// <param name="tokenEndpointUri">TokenエンドポイントのUri</param>
        /// <param name="client_id">string</param>
        /// <param name="client_secret">string</param>
        /// <param name="username">string</param>
        /// <param name="password">string</param>
        /// <param name="scopes">string</param>
        /// <returns>結果のJSON文字列</returns>
        public static async Task<string> ResourceOwnerPasswordCredentialsGrantAsync(
            Uri tokenEndpointUri, string client_id, string client_secret,
            string username, string password, string scopes)
        {
            // コンテナ化サポート
            tokenEndpointUri = SelfTestWebApi.ToContainerUri(tokenEndpointUri);

            // WebAPI呼び出し。
            return await OAuth2AndOIDCClient.ResourceOwnerPasswordCredentialsGrantAsync(
                tokenEndpointUri, client_id, client_secret, username, password, scopes);
        }

        /// <summary>
        /// Client Credentials Grant
        /// </summary>
        /// <param name="tokenEndpointUri">TokenエンドポイントのUri</param>
        /// <param name="client_id">string</param>
        /// <param name="client_secret">string</param>
        /// <param name="scopes">string</param>
        /// <returns>結果のJSON文字列</returns>
        public static async Task<string> ClientCredentialsGrantAsync(
            Uri tokenEndpointUri, string client_id, string client_secret, string scopes)
        {
            // コンテナ化サポート
            tokenEndpointUri = SelfTestWebApi.ToContainerUri(tokenEndpointUri);

            // WebAPI呼び出し。
            return await OAuth2AndOIDCClient.ClientCredentialsGrantAsync(
                tokenEndpointUri, client_id, client_secret, scopes);
        }

        /// <summary>Refresh Tokenを使用してAccess Tokenを更新する。</summary>
        /// <param name="tokenEndpointUri">tokenEndpointUri</param>
        /// <param name="credential">送るクライアント認証（`SelfTestClient.CredentialOf`）</param>
        /// <param name="refreshToken">refreshToken</param>
        /// <returns>結果のJSON文字列</returns>
        /// <remarks>
        /// **登録の方法で送る**（OpenTouryo#676 の版。#345）。
        /// 以前は Basic だけの版で、**FAPI の登録では断られていた**（refresh_token は、秘密では normal だけ。`ClientModePolicy`）。
        /// </remarks>
        public static async Task<string> UpdateAccessTokenByRefreshTokenAsync(
            Uri tokenEndpointUri, SelfTestClient.ClientCredential credential, string refreshToken)
        {
            //  **fapi2 の登録（tls_client_auth 以外）は、DPoP の証明を添える**（#429）。
            //    **コンテナ化の対応は、送る側で行う**（`htu` は対応する前の宛先。`SendWithDPoPAsync`）。
            if (SelfTestWebApi.UsesDPoP(credential))
            {
                return await SelfTestWebApi.TokenRequestWithDPoPAsync(tokenEndpointUri, credential,
                    new Dictionary<string, string>()
                    {
                        { "grant_type", OAuth2AndOIDCConst.RefreshTokenGrantType },
                        { OAuth2AndOIDCConst.RefreshToken, refreshToken }
                    });
            }

            // コンテナ化サポート
            tokenEndpointUri = SelfTestWebApi.ToContainerUri(tokenEndpointUri);

            // WebAPI呼び出し。
            return await OAuth2AndOIDCClient.UpdateAccessTokenByRefreshTokenAsync(
                tokenEndpointUri,
                client_id: credential.ClientId,
                client_secret: credential.ClientSecret,
                client_assertion: credential.ClientAssertion,
                refreshToken: refreshToken,
                authMethod: credential.AuthMethod);
        }

        #endregion

        #region その他の 基本 WebAPI

        /// <summary>UserInfoエンドポイントで、認可ユーザのClaim情報を取得する。</summary>
        /// <param name="accessToken">accessToken</param>
        /// <returns>結果のJSON文字列（認可したユーザのClaim情報）</returns>
        public static async Task<string> GetUserInfoAsync(string accessToken)
        {
            // 通信用の変数

            // 認可したユーザのClaim情報を取得するWebAPI
            Uri userInfoUri = new Uri(
                Config.OAuth2AuthorizationServerEndpointsRootURI + Config.OAuth2UserInfoEndpoint);

            //  **DPoP の鍵に縛られた access_token は、DPoP の証明（ath 付き）で送る**（RFC 9449 §7。#429）。
            //    **Bearer で送ると断られる。** 縛ったのは、自己テストの鍵（`DPoPKey`）である。
            //    **コンテナ化の対応は、送る側で行う**（`htu` は対応する前の宛先。`SendWithDPoPAsync`）。
            if (SelfTestWebApi.IsDPoPBound(accessToken))
            {
                return await SelfTestWebApi.SendWithDPoPAsync(HttpMethod.Get, userInfoUri, null, accessToken);
            }

            // コンテナ化サポート
            userInfoUri = SelfTestWebApi.ToContainerUri(userInfoUri);

            // WebAPI呼び出し。
            return await OAuth2AndOIDCClient.GetUserInfoAsync(userInfoUri, accessToken);
        }

        #endregion

        #region 拡張フローのWebAPI

        #region PKCE

        /// <summary>
        /// PKCE : code, code_verifierからAccess Tokenを取得する。
        /// </summary>
        /// <param name="tokenEndpointUri">TokenエンドポイントのUri</param>
        /// <param name="client_id">client_id</param>
        /// <param name="client_secret">client_secret</param>
        /// <param name="redirect_uri">redirect_uri</param>
        /// <param name="code">code</param>
        /// <param name="code_verifier">code_verifier</param>
        /// <returns>結果のJSON文字列</returns>
        public static async Task<string> GetAccessTokenByCodeAsync(
            Uri tokenEndpointUri, string client_id, string client_secret, string redirect_uri, string code, string code_verifier)
        {
            // コンテナ化サポート
            tokenEndpointUri = SelfTestWebApi.ToContainerUri(tokenEndpointUri);

            // WebAPI呼び出し。
            return await OAuth2AndOIDCClient.GetAccessTokenByCodeAsync(
                tokenEndpointUri, client_id, client_secret, redirect_uri, code, code_verifier);
        }

        #endregion

        #region Revoke & Introspect

        /// <summary>Revokeエンドポイントで、Tokenを無効化する。</summary>
        /// <param name="revokeTokenEndpointUri">RevokeエンドポイントのUri</param>
        /// <param name="credential">送るクライアント認証（`SelfTestClient.CredentialOf`）</param>
        /// <param name="token">token</param>
        /// <param name="token_type_hint">token_type_hint</param>
        /// <returns>結果のJSON文字列</returns>
        /// <remarks>**登録の方法で送る**（OpenTouryo#676 の版。#345）。以前は Basic・Post だけだった。</remarks>
        public static async Task<string> RevokeTokenAsync(
            Uri revokeTokenEndpointUri, SelfTestClient.ClientCredential credential, string token, string token_type_hint)
        {
            // コンテナ化サポート
            revokeTokenEndpointUri = SelfTestWebApi.ToContainerUri(revokeTokenEndpointUri);

            // WebAPI呼び出し。
            return await OAuth2AndOIDCClient.RevokeTokenAsync(
                revokeTokenEndpointUri,
                client_id: credential.ClientId,
                client_secret: credential.ClientSecret,
                client_assertion: credential.ClientAssertion,
                token: token,
                token_type_hint: token_type_hint,
                authMethod: credential.AuthMethod);
        }

        /// <summary>Introspectエンドポイントで、Tokenの状態を照会する。</summary>
        /// <param name="introspectTokenEndpointUri">IntrospectエンドポイントのUri</param>
        /// <param name="credential">送るクライアント認証（`SelfTestClient.CredentialOf`）</param>
        /// <param name="token">token</param>
        /// <param name="token_type_hint">token_type_hint</param>
        /// <returns>結果のJSON文字列</returns>
        /// <remarks>**登録の方法で送る**（OpenTouryo#676 の版。#345）。以前は Basic・Post だけだった。</remarks>
        public static async Task<string> IntrospectTokenAsync(
            Uri introspectTokenEndpointUri, SelfTestClient.ClientCredential credential, string token, string token_type_hint)
        {
            // コンテナ化サポート
            introspectTokenEndpointUri = SelfTestWebApi.ToContainerUri(introspectTokenEndpointUri);

            // WebAPI呼び出し。
            return await OAuth2AndOIDCClient.IntrospectTokenAsync(
                introspectTokenEndpointUri,
                client_id: credential.ClientId,
                client_secret: credential.ClientSecret,
                client_assertion: credential.ClientAssertion,
                token: token,
                token_type_hint: token_type_hint,
                authMethod: credential.AuthMethod);
        }

        #endregion

        #region JWT Bearer Token Flow

        /// <summary>
        /// Tokenエンドポイントで、
        /// JWT bearer token authorizationグラント種別の要求を行う。</summary>
        /// <param name="tokenEndpointUri">TokenエンドポイントのUri</param>
        /// <param name="assertion">string</param>
        /// <returns>結果のJSON文字列</returns>
        public static async Task<string> JwtBearerTokenFlowAsync(Uri tokenEndpointUri, string assertion)
        {
            // コンテナ化サポート
            tokenEndpointUri = SelfTestWebApi.ToContainerUri(tokenEndpointUri);

            // WebAPI呼び出し。
            return await OAuth2AndOIDCClient.JwtBearerTokenFlowAsync(tokenEndpointUri, assertion);
        }

        #endregion

        #region Device AuthZ
        /// <summary>
        /// Device AuthZの認可リクエスト（WebAPI）
        /// </summary>
        /// <param name="deviceAuthZUri">Uri</param>
        /// <param name="clientId">string</param>
        /// <returns>結果のJSON文字列</returns>
        public static async Task<string> DeviceAuthZRequestAsync(Uri deviceAuthZUri, string clientId)
        {
            // コンテナ化サポート
            deviceAuthZUri = SelfTestWebApi.ToContainerUri(deviceAuthZUri);

            // WebAPI呼び出し。
            return await OAuth2AndOIDCClient.DeviceAuthZRequestAsync(deviceAuthZUri, clientId);
        }

        /// <summary>
        /// Device AuthZのTokenリクエスト（WebAPI）
        /// </summary>
        /// <param name="tokenEndpointUri">TokenエンドポイントのUri</param>
        /// <param name="client_id">client_id</param>
        /// <param name="device_code">string</param>
        /// <returns>結果のJSON文字列</returns>
        public static async Task<string> GetAccessTokenByDeviceAuthZAsync(
            Uri tokenEndpointUri, string client_id, string device_code)
        {
            // コンテナ化サポート
            tokenEndpointUri = SelfTestWebApi.ToContainerUri(tokenEndpointUri);

            // WebAPI呼び出し。
            return await OAuth2AndOIDCClient.GetAccessTokenByDeviceAuthZAsync(
                tokenEndpointUri, client_id, device_code);
        }
        #endregion

        #region FAPI (Financial-grade API) 

        /// <summary>
        /// FAPI1 : code, assertionからAccess Tokenを取得する。
        /// </summary>
        /// <param name="tokenEndpointUri">TokenエンドポイントのUri</param>
        /// <param name="redirect_uri">redirect_uri</param>
        /// <param name="code">code</param>
        /// <param name="assertion">assertion</param>
        /// <returns>結果のJSON文字列</returns>
        public static async Task<string> GetAccessTokenByCodeAsync(
            Uri tokenEndpointUri, string redirect_uri, string code, string assertion)
        {
            // コンテナ化サポート
            tokenEndpointUri = SelfTestWebApi.ToContainerUri(tokenEndpointUri);

            // WebAPI呼び出し。
            return await OAuth2AndOIDCClient.GetAccessTokenByCodeAsync(
                tokenEndpointUri, redirect_uri, code, assertion);
        }

        /// <summary>
        /// FAPI1 + PKCE : code, code_verifier, assertionからAccess Tokenを取得する（#341）。
        /// </summary>
        /// <param name="tokenEndpointUri">TokenエンドポイントのUri</param>
        /// <param name="redirect_uri">redirect_uri</param>
        /// <param name="code">code</param>
        /// <param name="code_verifier">code_verifier</param>
        /// <param name="assertion">assertion</param>
        /// <returns>結果のJSON文字列</returns>
        /// <remarks>
        /// **`private_key_jwt`（RFC 7523 §2.2）で認証し、PKCE の `code_verifier`（RFC 7636 §4.5）も送る。**
        /// **`code_challenge` を付けて認可を求めたコードは、`code_verifier` が無いと引き換えられない**（#245）。
        /// Open棟梁 の `GetAccessTokenByCodeWithPkceAsync`（OpenTouryo#670）を呼ぶ
        /// （アサーションの版は `code_verifier` を送らない。名前が違うのは、既存の版と型の並びが同じになるため）。
        /// </remarks>
        public static async Task<string> GetAccessTokenByCodeWithPkceAsync(
            Uri tokenEndpointUri, string redirect_uri, string code, string code_verifier, string assertion)
        {
            // コンテナ化サポート
            tokenEndpointUri = SelfTestWebApi.ToContainerUri(tokenEndpointUri);

            // WebAPI呼び出し。
            return await OAuth2AndOIDCClient.GetAccessTokenByCodeWithPkceAsync(
                tokenEndpointUri, redirect_uri, code, code_verifier, assertion);
        }

        /// <summary>
        /// FAPI2 : code（と code_verifier）からAccess Tokenを取得する。認証は登録の方法で送る（#345）。
        /// </summary>
        /// <param name="tokenEndpointUri">TokenエンドポイントのUri</param>
        /// <param name="credential">送るクライアント認証（`SelfTestClient.CredentialOf`）</param>
        /// <param name="redirect_uri">redirect_uri</param>
        /// <param name="code">code</param>
        /// <param name="code_verifier">code_verifier（空なら送らない）</param>
        /// <returns>結果のJSON文字列</returns>
        /// <remarks>
        /// **Open棟梁 の方式を問わない版（OpenTouryo#676）を呼ぶ。** `private_key_jwt` も `tls_client_auth` も、この 1 つで送れる。
        /// **`tls_client_auth` のときは、本文に `client_id` だけが載り、証明書は `OAuth2AndOIDCClient.HttpClient` が載せる**
        /// （`Helper` が `SpRp_ClientCertPfxFilePath` で設定する）。
        /// **引数はすべて名前付きで渡す**（どれも `string` で、既存の版と順が違うため）。
        /// </remarks>
        public static async Task<string> GetAccessTokenByCodeAsync(
            Uri tokenEndpointUri, SelfTestClient.ClientCredential credential,
            string redirect_uri, string code, string code_verifier)
        {
            //  **fapi2 の登録（tls_client_auth 以外）は、DPoP の証明を添える**（FAPI 2.0 Security Profile §5.3.2.1 の 4。#429）。
            //    **コンテナ化の対応は、送る側で行う**（`htu` は対応する前の宛先。`SendWithDPoPAsync`）。
            if (SelfTestWebApi.UsesDPoP(credential))
            {
                Dictionary<string, string> body = new Dictionary<string, string>()
                {
                    { "grant_type", OAuth2AndOIDCConst.AuthorizationCodeGrantType },
                    { "code", code },
                    { "redirect_uri", redirect_uri }
                };

                if (!string.IsNullOrEmpty(code_verifier))
                {
                    body.Add("code_verifier", code_verifier);
                }

                return await SelfTestWebApi.TokenRequestWithDPoPAsync(tokenEndpointUri, credential, body);
            }

            // コンテナ化サポート
            tokenEndpointUri = SelfTestWebApi.ToContainerUri(tokenEndpointUri);

            // WebAPI呼び出し。
            return await OAuth2AndOIDCClient.GetAccessTokenByCodeAsync(
                tokenEndpointUri,
                client_id: credential.ClientId,
                client_secret: credential.ClientSecret,
                client_assertion: credential.ClientAssertion,
                redirect_uri: redirect_uri,
                code: code,
                code_verifier: code_verifier,
                authMethod: credential.AuthMethod);
        }

        /// <summary>
        /// FAPI2 : RequestObjectを登録する。
        /// </summary>
        /// <param name="requestObjectRegUri">Uri</param>
        /// <param name="requestObject">string</param>
        /// <returns>結果のJSON文字列</returns>
        public static async Task<string> RegisterRequestObjectAsync(Uri requestObjectRegUri, string requestObject)
        {
            // コンテナ化サポート
            requestObjectRegUri = SelfTestWebApi.ToContainerUri(requestObjectRegUri);

            // WebAPI呼び出し。
            return await OAuth2AndOIDCClient.RegisterRequestObjectAsync(requestObjectRegUri, requestObject);
        }

        /// <summary>
        /// 認可リクエストを PAR（RFC 9126）に預ける（WebAPI）（#246）
        /// </summary>
        /// <param name="authRequestPushUri">PAR エンドポイント</param>
        /// <param name="requestObject">Request Object（署名付き JWT）</param>
        /// <param name="credential">送るクライアント認証（`SelfTestClient.CredentialOf`）</param>
        /// <returns>結果の JSON 文字列（request_uri と expires_in）</returns>
        /// <remarks>
        /// **`/ros`（独自）との違いは、クライアント認証があること**（RFC 9126 §2）。
        /// **FAPI 2.0 はこの認証を private_key_jwt か MTLS に限っている。**
        /// **方法は登録で決まる**（`SelfTestClient.CredentialOf`。#345）。
        /// `client_assertion` の `aud` は `SelfTestClient.CreateClientAssertion` が決める。
        /// **PAR は、方法によらず `client_id` を送る**（RFC 9126 §2.1。Open棟梁 も空なら送る前に断る。OpenTouryo#678）。
        ///
        /// 送るのは `request`（JAR）1 つ。**認可エンドポイントのパラメタを、
        /// フォームで直接預ける形も RFC 9126 は許している**（Open棟梁 の別のオーバーロード）。
        /// </remarks>
        public static async Task<string> PushAuthorizationRequestAsync(
            Uri authRequestPushUri, string requestObject, SelfTestClient.ClientCredential credential)
        {
            // コンテナ化サポート
            authRequestPushUri = SelfTestWebApi.ToContainerUri(authRequestPushUri);

            // WebAPI呼び出し。
            return await OAuth2AndOIDCClient.PushAuthorizationRequestAsync(
                authRequestPushUri, requestObject,
                credential.ClientId, credential.ClientSecret, credential.ClientAssertion,
                credential.AuthMethod);
        }

        #region CIBA
        /// <summary>
        /// FAPI CIBA : RequestObjectを使用した認可リクエスト（WebAPI）
        /// </summary>
        /// <param name="cibaAuthZUri">Uri</param>
        /// <param name="requestObjectUri">string</param>
        /// <returns>結果のJSON文字列</returns>
        /// <remarks>
        /// **request_uri を渡す独自拡張の形**（CIBA Core には無い）。
        /// **クライアント認証もしない**ので、#234 の段階 3 以降は認可サーバに断られる。
        /// 新しい呼び出しは <see cref="SelfTestWebApi.CibaAuthZRequestAsync(Uri, string, string, string)"/> を使う。
        /// </remarks>
        public static async Task<string> CibaAuthZRequestAsync(Uri cibaAuthZUri, string requestObjectUri)
        {
            // コンテナ化サポート
            cibaAuthZUri = SelfTestWebApi.ToContainerUri(cibaAuthZUri);

            // WebAPI呼び出し。
            return await OAuth2AndOIDCClient.CibaAuthZRequestAsync(cibaAuthZUri, requestObjectUri);
        }

        /// <summary>
        /// FAPI CIBA : 署名した認証要求（request）を、クライアント認証を添えて送る（WebAPI）
        /// </summary>
        /// <param name="cibaAuthZUri">Uri</param>
        /// <param name="requestObject">署名付きJWT</param>
        /// <param name="client_id">client_id</param>
        /// <param name="client_secret">client_secret</param>
        /// <returns>結果のJSON文字列</returns>
        /// <remarks>
        /// **CIBA Core が定めている形**（§7.1 : クライアント認証は MUST、§7.1.1 : 要求は request パラメタ）。
        ///
        /// **Open棟梁 の `OAuth2AndOIDCClient.CibaAuthZRequestAsync`（資格情報を受ける版）で送る**（#337）。
        /// 以前は、資格情報を渡す引数が無かった（OpenTouryoProject/OpenTouryo#592）ので、自前で組み立てていた。
        /// **送るものは同じ**（client_secret_basic。id と秘密を符号化してから Base64 にする。本文は `request` だけ）。
        /// </remarks>
        public static async Task<string> CibaAuthZRequestAsync(
            Uri cibaAuthZUri, string requestObject, string client_id, string client_secret)
        {
            // コンテナ化サポート
            cibaAuthZUri = SelfTestWebApi.ToContainerUri(cibaAuthZUri);

            // WebAPI呼び出し。
            return await OAuth2AndOIDCClient.CibaAuthZRequestAsync(
                cibaAuthZUri, requestObject, client_id, client_secret,
                OAuth2AndOIDCEnum.AuthMethods.client_secret_basic);
        }

        /// <summary>
        /// FAPI2 CIBAのTokenリクエスト（WebAPI）
        /// </summary>
        /// <param name="tokenEndpointUri">TokenエンドポイントのUri</param>
        /// <param name="client_id">client_id</param>
        /// <param name="client_secret">client_secret</param>
        /// <param name="auth_req_id">string</param>
        /// <returns>結果のJSON文字列</returns>
        public static async Task<string> GetAccessTokenByCibaAsync(
            Uri tokenEndpointUri, string client_id, string client_secret, string auth_req_id)
        {
            // コンテナ化サポート
            tokenEndpointUri = SelfTestWebApi.ToContainerUri(tokenEndpointUri);

            // WebAPI呼び出し。
            return await OAuth2AndOIDCClient.GetAccessTokenByCibaAsync(
                tokenEndpointUri, client_id, client_secret, auth_req_id);
        }
        #endregion

        #endregion

        #endregion

        #endregion

        #endregion
    }
}