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
//* クラス日本語名  ：CmnEndpoints（ライブラリ）の ディスカバリ（.well-known/openid-configuration）
//*
//* 作成日時        ：－
//* 作成者          ：－
//* 更新履歴        ：－
//*
//*  日時        更新者            内容
//*  ----------  ----------------  -------------------------------------------------
//*  2026/10/29  玄人 幸道         新規（CmnEndpoints.cs から partial に分割。#294）
//*  2026/10/29  玄人 幸道         広告の一覧を 1 か所から作り、region の入れ子と using を直した（#294）
//**********************************************************************************

using MultiPurposeAuthSite.Co;
using MultiPurposeAuthSite.Extensions.Sts;

using System.Collections.Generic;

using Touryo.Infrastructure.Framework.Authentication;
using Touryo.Infrastructure.Public.FastReflection;
using Touryo.Infrastructure.Public.Security.Jwt;

namespace MultiPurposeAuthSite.TokenProviders
{
    /// <summary>CmnEndpoints（ディスカバリ（.well-known/openid-configuration））</summary>
    public partial class CmnEndpoints
    {
        #region .well-known/openid-configuration

        /// <summary>OpenIDConfig</summary>
        /// <returns>Dictionary(string, object)</returns>
        public static Dictionary<string, object> OpenIDConfig()
        {
            Dictionary<string, object> OpenIDConfig = new Dictionary<string, object>();

            #region 基本

            OpenIDConfig.Add("issuer", CmnServerParams.IssuerId);

            OpenIDConfig.Add("authorization_endpoint",
                Config.OAuth2AuthorizationServerEndpointsRootURI + Config.OAuth2AuthorizeEndpoint);

            OpenIDConfig.Add("token_endpoint",
                Config.OAuth2AuthorizationServerEndpointsRootURI + Config.OAuth2TokenEndpoint);

            OpenIDConfig.Add("userinfo_endpoint",
                Config.OAuth2AuthorizationServerEndpointsRootURI + Config.OAuth2UserInfoEndpoint);

            #endregion

            #region オプション

            List<string> scopes_supported = new List<string>();
            List<string> grant_types_supported = new List<string>();
            List<string> response_types_supported = new List<string>();
            List<string> response_modes_supported = new List<string>();

            OpenIDConfig.Add("scopes_supported", scopes_supported);
            OpenIDConfig.Add("grant_types_supported", grant_types_supported);
            OpenIDConfig.Add("response_types_supported", response_types_supported);
            OpenIDConfig.Add("response_modes_supported", response_modes_supported);

            #region token
            // **一覧は 1 か所から作る**（#262 と同じ考え方。#307 の段階 3 で揃えた）。
            //   **広告・登録値の検証・画面の選択肢**が、同じ `TokenEndpointAuthMethods` を見る。
            OpenIDConfig.Add("token_endpoint_auth_methods_supported",
                new List<string>(CmnEndpoints.TokenEndpointAuthMethods));

            // **ES256 も通る**（#129 の段階 2）。
            //   `client_assertion` の検証で、**登録された RSA / ECDSA の公開鍵を順に試す**
            //   ようにしたため（`CmnEndpoints.ClientAuthentication`）。
            //   **クライアントが ECDSA の公開鍵（jwk_ecdsa_publickey）を登録していれば ES256 が通る。**
            //   **一覧は 1 か所から作る**（#262）。広告と、登録値の検証が同じものを見る。
            OpenIDConfig.Add("token_endpoint_auth_signing_alg_values_supported", new List<string> {
                "RS256", "ES256"
            });
            #endregion

            #region scopes
            // 発行時の絞り込み（Helper.FilterSupportedScopes）と同じ一覧を使う（#198）。
            // openid は OIDC が有効なときだけ含まれる。
            scopes_supported.AddRange(Helper.GetScopesSupported());
            #endregion

            #region grant and response_types
            //  **扱うグラントの一覧は 1 か所から作る**（#294。動的登録の検査と同じ一覧）。
            grant_types_supported.AddRange(CmnEndpoints.SupportedGrantTypes(true));

            //  **受け付ける response_type だけを広告する**（#314）。
            //    **Hybrid / OIDC の Implicit も、`code` / `token` を含むなら同じ設定に従う。**
            response_types_supported.AddRange(CmnEndpoints.SupportedResponseTypes());

            // **Device Authorization Grant は、広告していなかった**（#189 の 6・7）。
            //   実装済み（/device_authz と device_code のグラント）なのに Discovery から
            //   Config.EnableDeviceAuthZGrantType を一度も見ていなかったため、
            //   RP の自動設定が通らなかった。
            if (Config.EnableDeviceAuthZGrantType)
            {
                // RFC 8628 §4
                OpenIDConfig.Add("device_authorization_endpoint",
                    Config.OAuth2AuthorizationServerEndpointsRootURI + Config.DeviceAuthZAuthorizeEndpoint);
            }
            #endregion

            #region response_modes
            response_modes_supported.Add(OAuth2AndOIDCEnum.ResponseMode.query.ToStringByEmit());
            response_modes_supported.Add(OAuth2AndOIDCEnum.ResponseMode.fragment.ToStringByEmit());
            response_modes_supported.Add(OAuth2AndOIDCEnum.ResponseMode.form_post.ToStringByEmit());
            #endregion

            #region OpenID Connect

            // openid は、上の Helper.GetScopesSupported で追加済み（#198）
            // response_types は、上の SupportedResponseTypes で追加済み（#314）

            #region id_token
            // **一覧は JwsFactory.SupportedAlgs が持つ**（#129 の段階 2）。
            //   **発行・検証・広告が同じ一覧を見る**ので、増やしても食い違わない。
            OpenIDConfig.Add("id_token_signing_alg_values_supported",
                new List<string>(JwsFactory.SupportedAlgs));

            // **alg と enc は対で広告する**（OIDC Discovery 1.0 §3。#189 の 5）。
            //   実装は JWE_RsaOaepAesGcm（Open棟梁）で、鍵の暗号化が RSA-OAEP、本文が A256GCM。
            OpenIDConfig.Add("id_token_encryption_alg_values_supported", new List<string> {
                "RSA-OAEP"
            });

            OpenIDConfig.Add("id_token_encryption_enc_values_supported", new List<string> {
                "A256GCM"
            });
            #endregion

            #region subject_types
            // **OIDC の登録値だけを扱う**（既定は public）。
            //   利用者名が要る RP は、**preferred_username**（UserClaimsMapping）を使う。
            OpenIDConfig.Add("subject_types_supported", new List<string> {
                OAuth2AndOIDCEnum.SubjectTypes.@public.ToStringByEmit(),
                OAuth2AndOIDCEnum.SubjectTypes.pairwise.ToStringByEmit()
            });
            #endregion

            #region claims
            OpenIDConfig.Add("claims_parameter_supported", false); // RequestObjectでのみサポート
            // **profile / address のクレームは、対応付けから作る**（#230）。
            //   固定の一覧にすると「広告しているのに返らない」が起きる（#228 の 13）。
            List<string> claimsSupported = new List<string> {
                //Jwt
                OAuth2AndOIDCConst.iss,
                OAuth2AndOIDCConst.aud,
                OAuth2AndOIDCConst.sub,
                OAuth2AndOIDCConst.exp,
                OAuth2AndOIDCConst.nbf,
                OAuth2AndOIDCConst.iat,
                OAuth2AndOIDCConst.jti,
                // scope
                // 標準
                OAuth2AndOIDCConst.Scope_Email,
                OAuth2AndOIDCConst.email_verified,
                OAuth2AndOIDCConst.phone_number,
                OAuth2AndOIDCConst.phone_number_verified,
                // 拡張
                OAuth2AndOIDCConst.scopes,
                OAuth2AndOIDCConst.Scope_Roles,
                // OIDC, FAPI1
                OAuth2AndOIDCConst.nonce,
                OAuth2AndOIDCConst.at_hash,
                OAuth2AndOIDCConst.c_hash,
                OAuth2AndOIDCConst.s_hash //,
                //OAuth2AndOIDCConst.auth
            };

            claimsSupported.AddRange(UserClaims.GetSupportedClaims());

            OpenIDConfig.Add("claims_supported", claimsSupported);
            #endregion

            #region RequestObject
            //   **一覧は 1 か所から作る**（#262）。**以前は、ここに値を直に書いていた**（#294 で揃えた）。
            OpenIDConfig.Add("request_object_signing_alg_values_supported",
                new List<string>(CmnEndpoints.RequestObjectSigningAlgs));
            OpenIDConfig.Add("request_parameter_supported", false);
            OpenIDConfig.Add("request_uri_parameter_supported", true);
            OpenIDConfig.Add("request_object_endpoint",
                Config.OAuth2AuthorizationServerEndpointsRootURI + OAuth2AndOIDCParams.RequestObjectRegUri);

            // **PAR（RFC 9126）の口**（#229）。
            //   request_object_endpoint（独自の /ros）は、後方互換のため残している。
            //   こちらは RFC のとおり、フォーム形式＋クライアント認証で受ける。
            OpenIDConfig.Add("pushed_authorization_request_endpoint",
                Config.OAuth2AuthorizationServerEndpointsRootURI + OAuth2AndOIDCParams.AuthRequestPushUri);

            // **PAR を必須にはしていない**（RFC 9126 §5。既定は false）。
            OpenIDConfig.Add("require_pushed_authorization_requests", false);
            #endregion

            #region ResponseObject(JARM)
            // 「.」がね...。
            response_modes_supported.Add(Const.ResponseModeQueryJwt);
            response_modes_supported.Add(Const.ResponseModeFragmentJwt);
            response_modes_supported.Add(Const.ResponseModeFormPostJwt);

            // **応答の署名アルゴリズムを広告していなかった**（JARM §7。#189 の 8）。
            //   *.jwt の response_mode を出しているのに、RP は何で検証すればよいか分からなかった。
            //   実装は CmnResponseObject の JWS(RS256)。
            OpenIDConfig.Add("authorization_signing_alg_values_supported", new List<string> {
                "RS256"
            });
            #endregion

            #region RP-Initiated Logout（#232）

            // **RP からのログアウトの口**（RP-Initiated Logout 1.0 §2.1）。
            //   **実装しているなら、Discovery に出すことが REQUIRED。**
            OpenIDConfig.Add("end_session_endpoint",
                Config.OAuth2AuthorizationServerEndpointsRootURI + Config.OAuth2EndSessionEndpoint);

            //  **Back-Channel Logout に対応したことを広告する**（#310 の段階 2）。
            //    | 項目 | 意味 |
            //    |---|---|
            //    | `backchannel_logout_supported` | **登録した `backchannel_logout_uri` を叩く** |
            //    | `backchannel_logout_session_supported` | **`logout_token` に `sid` を入れる** |
            //
            //    **`sid` は必ず入れる**ので、後者も true である（段階 1 で `id_token` にも出した）。
            //    **Front-Channel Logout（段階 3）と Session Management（見送り）は、まだ出さない**
            //    （**出すと「できる」と読まれる**）。
            OpenIDConfig.Add("backchannel_logout_supported", true);
            OpenIDConfig.Add("backchannel_logout_session_supported", true);

            //  **Front-Channel Logout に対応したことを広告する**（#310 の段階 3）。
            //    | 項目 | 意味 |
            //    |---|---|
            //    | `frontchannel_logout_supported` | **登録した `frontchannel_logout_uri` を `iframe` で開く** |
            //    | `frontchannel_logout_session_supported` | **その URL に `iss` と `sid` を付ける** |
            //
            //    **`sid` は必ず付ける**ので、後者も true である。
            //    **Session Management（`check_session_iframe`）は見送った**ので、出さない
            //    （**third-party cookie を読む仕組み**で、現代のブラウザでは効かなくなりつつある）。
            OpenIDConfig.Add("frontchannel_logout_supported", true);
            OpenIDConfig.Add("frontchannel_logout_session_supported", true);

            #endregion

            // **認可応答に iss を付けることを広告する**（RFC 9207 §3。#231）
            OpenIDConfig.Add("authorization_response_iss_parameter_supported", true);

            OpenIDConfig.Add("jwks_uri",
                    Config.OAuth2AuthorizationServerEndpointsRootURI + OAuth2AndOIDCParams.JwkSetUri);

            #endregion

            #region OAuth2拡張

            #region Dynamic Client Registration（#307 の段階 1）

            //  **動的クライアント登録を開けた配備だけ広告する**
            //    （OIDC Discovery §3 の `registration_endpoint` / RFC 7591 §3）。
            //    **閉じている配備では口そのものが張られていない**ので、広告してはならない。
            if (Config.EnableDynamicClientRegistration)
            {
                OpenIDConfig.Add("registration_endpoint",
                    Config.OAuth2AuthorizationServerEndpointsRootURI + Config.DcrRegistrationEndpoint);
            }

            #endregion

            #region Revocation
            OpenIDConfig.Add("revocation_endpoint",
                Config.OAuth2AuthorizationServerEndpointsRootURI + Config.OAuth2RevokeTokenEndpoint);

            //  **トークン エンドポイントと同じ一覧**（RFC 7009 §2.1 / RFC 7662 §2.1。#294）。
            //    **#239 から private_key_jwt / mTLS でも通る**のに、秘密の 2 つしか広告していなかった。
            OpenIDConfig.Add("revocation_endpoint_auth_methods_supported",
                new List<string>(CmnEndpoints.TokenEndpointAuthMethods));
            #endregion

            #region Introspect
            OpenIDConfig.Add("introspection_endpoint",
                Config.OAuth2AuthorizationServerEndpointsRootURI + Config.OAuth2IntrospectTokenEndpoint);

            //  **トークン エンドポイントと同じ一覧**（RFC 7009 §2.1 / RFC 7662 §2.1。#294）。
            //    **#239 から private_key_jwt / mTLS でも通る**のに、秘密の 2 つしか広告していなかった。
            OpenIDConfig.Add("introspection_endpoint_auth_methods_supported",
                new List<string>(CmnEndpoints.TokenEndpointAuthMethods));
            #endregion

            #region OAuth PKCE

            // **広告は、実装に合わせる**（#228 の 9）。
            //   plain を受けるかどうかは RequirePkceS256（サーバ全体の設定）だけで決まる。
            //   締めた配置では plain を広告しない。
            //   ※ クライアント単位の require_pkce（#221）は「PKCE を必須にするか」であって、
            //     ここ（対応するメソッド）とは別。Discovery にクライアント別の項目は無い。
            List<string> code_challenge_methods_supported = new List<string>();

            if (!CmnServerParams.RequirePkceS256)
            {
                code_challenge_methods_supported.Add(OAuth2AndOIDCConst.PKCE_plain);
            }

            code_challenge_methods_supported.Add(OAuth2AndOIDCConst.PKCE_S256);

            OpenIDConfig.Add("code_challenge_methods_supported", code_challenge_methods_supported);

            #endregion

            #endregion

            #region FAPI

            //  **DPoP に対応したことを広告する**（RFC 9449 §5.1。#311 の段階 1）。
            //    **証明の署名に使える alg** を出す。
            //    **一覧は `JwsFactory.SupportedAlgs` が持つ**（発行・検証・広告が同じ一覧を見る。#129 の段階 3 / #294）。
            //    **非対称の alg だけ**であり、**`none` は入っていない。**
            OpenIDConfig.Add("dpop_signing_alg_values_supported", JwsFactory.SupportedAlgs);

            // **RFC 8705 §3.3 の名前は tls_client_certificate_bound_access_tokens、値は boolean**（#189 の 2）。
            //   以前は mutual_tls_sender_constrained_access_tokens（草案の名前）に文字列の "true" を入れていた。
            OpenIDConfig.Add("tls_client_certificate_bound_access_tokens", true);

            #endregion

            #region CIBA

            OpenIDConfig.Add("backchannel_authentication_endpoint",
                Config.OAuth2AuthorizationServerEndpointsRootURI + Config.CibaAuthorizeEndpoint);

            OpenIDConfig.Add("backchannel_token_delivery_modes_supported", new List<string> {
               OAuth2AndOIDCEnum.CibaMode.poll.ToStringByEmit(),
               //OAuth2AndOIDCEnum.CibaMode.ping.ToStringByEmit(),
               //OAuth2AndOIDCEnum.CibaMode.push.ToStringByEmit()
            });

            // **FAPI-CIBA が求める Request Object の署名は ES256 または PS256 だが、
            //   この実装は ES256 だけを受け付ける**（#129 の段階 0 で、記述を実装に合わせた）。
            //
            //   **以前は「ES256 と PS256のみ許可」と書いてあったが、PS256 は通らない。**
            //   `RequestObject.VerifyCiba` は ES256 に固定されており、
            //   **Open棟梁 に `JWS_PS*` が無い**（`JWS_RS256/384/512` と `JWS_ES256/384/512` は在る）。
            //   PS256 を通すには上流の対応が要る（#129）。
            //
            //   ちなみに、Tokenの署名は、FAPI2に準拠する。
            //
            // **配列と boolean で広告する**（CIBA Core §4。#189 の 3・4）。
            //   以前は文字列だったため、素直に読む RP は型で落ちる。
            OpenIDConfig.Add("backchannel_authentication_request_signing_alg_values_supported", new List<string> {
                "ES256"
            });
            OpenIDConfig.Add("backchannel_user_code_parameter_supported", false);

            #endregion

            #region その他
            OpenIDConfig.Add("display_values_supported", new List<string> {
                "page"
            });

            // **プレースホルダを配らない**（#228 の 12）。
            //   任意の項目なので、設定が空なら出さない。
            if (!string.IsNullOrEmpty(Config.ServiceDocumentation))
            {
                OpenIDConfig.Add("service_documentation", Config.ServiceDocumentation);
            }
            #endregion

            #endregion

            return OpenIDConfig;
        }

        #endregion
    }
}