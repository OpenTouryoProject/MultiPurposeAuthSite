//**********************************************************************************
//* Copyright (C) 2026 Hitachi Solutions,Ltd.
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
//* クラス名        ：ClientRegistrationProvider
//* クラス日本語名  ：動的クライアント登録（RFC 7591）の 管理 API の部品
//*
//* 作成日時        ：－
//* 作成者          ：－
//* 更新履歴        ：－
//*
//*  日時        更新者            内容
//*  ----------  ----------------  -------------------------------------------------
//*  2026/10/26  玄人 幸道         新規（ClientRegistrationProvider.cs から partial に分割。#294）
//**********************************************************************************

using MultiPurposeAuthSite.Co;
using MultiPurposeAuthSite.TokenProviders;
using MultiPurposeAuthSite.ViewModels;

using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;

using Newtonsoft.Json;
using Newtonsoft.Json.Linq;

using Touryo.Infrastructure.Framework.Authentication;
using Touryo.Infrastructure.Public.FastReflection;
using Touryo.Infrastructure.Public.Security.Jwt;
using Touryo.Infrastructure.Public.Security.Pwd;

namespace MultiPurposeAuthSite.Extensions.Sts
{
    /// <summary>ClientRegistrationProvider（管理 API の部品）</summary>
    public static partial class ClientRegistrationProvider
    {
        // 管理 API の部品（RFC 7592）

        #region registration_access_token

        /// <summary>registration_access_token を作る</summary>
        /// <returns>トークン（**平文。登録の応答で 1 回だけ返す**）</returns>
        /// <remarks>
        /// **`client_secret` と同じ作り方**（**256 bit の乱数**）。
        /// **JWT にしていない** — **期限が必ず付き、切れたら管理できなくなる。**
        /// **RFC 7592 は、クライアントの一生もののトークンを前提にしている**（§2 / A.1）。
        /// </remarks>
        private static string GenerateToken()
        {
            return GetPassword.Base64UrlSecret(32);
        }

        /// <summary>保管する形にする（ハッシュ）</summary>
        /// <param name="token">トークン（平文）</param>
        /// <returns>ハッシュ（base64）</returns>
        /// <remarks>
        /// **暗号化（`SecretProtector`）ではなくハッシュである** —
        /// **照合しかしない**（**再表示する口が無い**）ので、**元に戻せる必要が無い。**
        /// **トークンは 256 bit の乱数**なので、**鍵の導出（PBKDF2）は要らない。**
        /// </remarks>
        private static string Hash(string token)
        {
            if (string.IsNullOrEmpty(token))
            {
                return "";
            }

            using (SHA256 sha256 = SHA256.Create())
            {
                return Convert.ToBase64String(
                    sha256.ComputeHash(Encoding.UTF8.GetBytes(token)));
            }
        }

        /// <summary>突き合わせる（長さが違えば false）</summary>
        /// <param name="a">値</param>
        /// <param name="b">値</param>
        /// <returns>同じなら true</returns>
        /// <remarks>
        /// **先頭から 1 文字ずつ比べて、違った所で止めてはならない** —
        /// **掛かった時間から、どこまで合っていたかが分かる。**
        /// **最後まで数えてから返す。**（タイミング攻撃防止）
        /// </remarks>
        private static bool FixedTimeEquals(string a, string b)
        {
            if (a == null || b == null || a.Length != b.Length)
            {
                return false;
            }

            int diff = 0;

            for (int i = 0; i < a.Length; i++)
            {
                diff |= a[i] ^ b[i];
            }

            return diff == 0;
        }

        #endregion

        #region 応答（RFC 7592 §3）

        /// <summary>空でなければ、応答に足す</summary>
        /// <param name="ret">応答</param>
        /// <param name="name">名前</param>
        /// <param name="value">値</param>
        private static void AddIfNotEmpty(
            Dictionary<string, object> ret, string name, string value)
        {
            if (!string.IsNullOrEmpty(value))
            {
                ret.Add(name, value);
            }
        }

        /// <summary>この登録の `registration_client_uri`（RFC 7592 §3）</summary>
        /// <param name="client_id">client_id</param>
        /// <returns>絶対 URI</returns>
        /// <remarks>
        /// **絶対 URI で返す**（RFC 7592 Appendix B :
        /// **サーバが URL を渡すこと。クライアントに組み立てさせない**）。
        /// </remarks>
        private static string RegistrationClientUri(string client_id)
        {
            return Config.OAuth2AuthorizationServerEndpointsRootURI
                + Config.DcrRegistrationEndpoint + "/" + client_id;
        }

        /// <summary>登録された鍵を `jwks` にして返す（無ければ null）</summary>
        /// <param name="model">登録</param>
        /// <returns>JWK Set（鍵が 1 本も無ければ null）</returns>
        /// <remarks>
        /// **`ParseJwks`（`#region metadataの読み書き`）の逆である。** **列に在る鍵だけを `keys` に並べる。**
        /// **壊れた登録値は、黙って飛ばす**（**応答を 500 にしない**。
        /// **登録の時点で形は確かめている**ので、ここに来るのは運用で壊した値である）。
        ///
        /// ※ クライアント認証に使う、クライアントの公開鍵（サーバの鍵・software_statement の発行者の鍵とは別）
        /// </remarks>
        private static JObject BuildJwks(ManageAddSaml2OAuth2DataViewModel model)
        {
            JArray keys = new JArray();

            foreach (string registered in new string[]
                { model.JwkRsaPublickey, model.JwkECDsaPublickey })
            {
                string json = CmnEndpoints.DecodeRegisteredJwk(registered);

                if (string.IsNullOrEmpty(json))
                {
                    continue;
                }

                try
                {
                    keys.Add(JsonConvert.DeserializeObject<JObject>(json));
                }
                catch (JsonException)
                {
                    // 登録の値が壊れている（運用の誤り）。
                }
            }

            if (!keys.Any())
            {
                return null;
            }

            JObject jwks = new JObject();
            jwks.Add(JwtConst.keys, keys);

            return jwks;
        }

        /// <summary>クライアント情報の応答を作る（RFC 7592 §3）</summary>
        /// <param name="client_id">client_id</param>
        /// <param name="model">登録</param>
        /// <param name="registrationAccessToken">registration_access_token（平文）</param>
        /// <returns>応答</returns>
        /// <remarks>
        /// **3 つの口（`POST` / `GET` / `PUT`）で同じ形**である（RFC 7592 §3）。
        ///
        /// | | |
        /// |---|---|
        /// | **必ず入れる** | `client_id` / `redirect_uris` / `grant_types` / `response_types` / `token_endpoint_auth_method` / **`registration_access_token`** / **`registration_client_uri`**（**後の 2 つは §3 で REQUIRED**） |
        /// | **入れない** | **`client_secret`**（**`POST` だけが、呼ぶ側で足す**）／**`client_name`**（**保存しているのは利用者名**で、要求された値でもない。**返すと利用者名を漏らす**）／**`client_id_issued_at`**（**保管していない**。§3.2.1 で任意） |
        ///
        /// **`registration_access_token` は、提示されたものをそのまま返す** —
        /// **こちらはハッシュしか持たない**ので、**これで §3 の REQUIRED を満たす。**
        /// **回さない**（§5 / A.1 の MAY。**回すと、取り違えた RP が管理できなくなる**）。
        /// </remarks>
        private static Dictionary<string, object> BuildClientInformation(
            string client_id, ManageAddSaml2OAuth2DataViewModel model,
            string registrationAccessToken)
        {
            Dictionary<string, object> ret = new Dictionary<string, object>();

            ret.Add(OAuth2AndOIDCConst.client_id, client_id);

            //  **列は `response_type` で分かれている**ので、**両方を合わせて返す**
            //    （**同じ値が入っている**ことが多い。Hybrid の登録では両方に入れている）。
            List<string> redirectUris = OAuth2AndOIDCSpec.ToDistinctList(model.RedirectUriCode);

            foreach (string redirectUri in OAuth2AndOIDCSpec.ToDistinctList(model.RedirectUriToken))
            {
                if (!redirectUris.Contains(redirectUri))
                {
                    redirectUris.Add(redirectUri);
                }
            }

            ret.Add(OAuth2AndOIDCConst.redirect_uris, redirectUris);

            ret.Add(Const.ClientGrantTypes, OAuth2AndOIDCSpec.ToDistinctList(model.GrantTypes));

            //  **`response_types` は、要素の中の空白を「+」にして保管している。**
            ret.Add(Const.ClientResponseTypes, Helper.ToDistinctList(model.ResponseTypes, true));

            //  **登録された `token_endpoint_auth_method` を返す。**
            //    **空（明示なし）は `client_secret_basic`** — **RFC 7591 §2 の既定**であり、
            //    **実際に通る方法**でもある（`CmnEndpoints.AllowsAuthMethod`）。
            ret.Add(Const.ClientTokenEndpointAuthMethod,
                string.IsNullOrEmpty(model.TokenEndpointAuthMethod)
                    ? OAuth2AndOIDCEnum.AuthMethods.client_secret_basic.ToStringByEmit()
                    : model.TokenEndpointAuthMethod);

            //  **`client_secret` に期限は設けていない** — **0 は「期限なし」**（RFC 7591 §3.2.1）。
            ret.Add(Const.ClientSecretExpiresAt, 0);

            ClientRegistrationProvider.AddIfNotEmpty(ret, OAuth2AndOIDCConst.scope, model.Scopes);
            ClientRegistrationProvider.AddIfNotEmpty(ret, Const.ClientUri, model.ClientUri);
            ClientRegistrationProvider.AddIfNotEmpty(ret, Const.ClientLogoUri, model.LogoUri);
            ClientRegistrationProvider.AddIfNotEmpty(ret, Const.ClientTosUri, model.TosUri);
            ClientRegistrationProvider.AddIfNotEmpty(ret, Const.ClientPolicyUri, model.PolicyUri);
            ClientRegistrationProvider.AddIfNotEmpty(ret, Const.ClientSoftwareId, model.SoftwareId);
            ClientRegistrationProvider.AddIfNotEmpty(ret, Const.ClientSoftwareVersion, model.SoftwareVersion);
            ClientRegistrationProvider.AddIfNotEmpty(ret, Const.ClientSubjectType, model.SubjectTypes);
            ClientRegistrationProvider.AddIfNotEmpty(ret, Const.ClientIdTokenSignedResponseAlg, model.IdTokenSignedResponseAlg);
            ClientRegistrationProvider.AddIfNotEmpty(ret, Const.ClientTlsClientAuthSubjectDn, model.TlsClientAuthSubjectDn);
            ClientRegistrationProvider.AddIfNotEmpty(ret, Const.ClientTokenEndpointAuthSigningAlg, model.TokenEndpointAuthSigningAlg);

            //  **登録された鍵を `jwks` に戻して返す。**
            //    **列は 2 本に分かれている**ので、**在るものだけを `keys` に並べる。**
            JObject jwks = ClientRegistrationProvider.BuildJwks(model);

            if (jwks != null)
            {
                ret.Add(Const.ClientJwks, jwks);
            }

            //  **`jwks_uri` は、そのまま返す**（**`jwks` とは排他**）。
            ClientRegistrationProvider.AddIfNotEmpty(ret, OAuth2AndOIDCConst.jwks_uri, model.JwksUri);

            if (!string.IsNullOrEmpty(model.Contacts))
            {
                ret.Add(Const.ClientContacts, OAuth2AndOIDCSpec.ToDistinctList(model.Contacts));
            }

            //  **RFC 7592 §3 : どちらも REQUIRED**（**管理の口と、その鍵**）。
            ret.Add(Const.ClientRegistrationAccessToken, registrationAccessToken);
            ret.Add(Const.ClientRegistrationClientUri,
                ClientRegistrationProvider.RegistrationClientUri(client_id));

            return ret;
        }

        #endregion
    }
}
