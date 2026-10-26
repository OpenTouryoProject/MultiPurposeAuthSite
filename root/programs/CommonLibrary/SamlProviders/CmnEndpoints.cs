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
//* クラス日本語名  ：CmnEndpoints（ライブラリ）
//*
//* 作成日時        ：－
//* 作成者          ：－
//* 更新履歴        ：－
//*
//*  日時        更新者            内容
//*  ----------  ----------------  -------------------------------------------------
//*  2019/06/03  西野 大介         新規
//*  2020/01/07  西野 大介         PPID対応実施
//*  2026/10/07  玄人 幸道         ACS URL の不一致を登録値へのエラー応答にした（#276）
//*  2026/10/07  玄人 幸道         アサーションの有効期限の単位を直した（分→秒。#276）
//*  2026/10/07  玄人 幸道         エラー応答にAssertionを組み込まないようにした（#278）
//*  2026/10/12  玄人 幸道         アサーションにAttributeStatementを足した（#286 の段階 4）
//**********************************************************************************

#if NETFX
using MultiPurposeAuthSite.Entity;
#else
//
#endif

using MultiPurposeAuthSite.Co;
using MultiPurposeAuthSite.Util;
using Sts = MultiPurposeAuthSite.Extensions.Sts;

using System;
using System.Collections.Generic;
using System.Xml;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

using Touryo.Infrastructure.Framework.Authentication;
using Touryo.Infrastructure.Public.Str;
using Touryo.Infrastructure.Public.Security;
using Touryo.Infrastructure.Public.Security.Jwt;

namespace MultiPurposeAuthSite.SamlProviders
{
    /// <summary>CmnEndpoints</summary>
    public class CmnEndpoints
    {
        /// <summary>VerifySamlRequest</summary>
        /// <param name="queryString">string（Redirect Binding のときのクエリ文字列。POST なら空）</param>
        /// <param name="samlRequest">string（POST Binding のときの SAMLRequest）</param>
        /// <param name="iss">out string（要求の Issuer。この製品では client_id）</param>
        /// <param name="inResponseTo">out string（要求の ID）</param>
        /// <param name="samlRequest2">out XmlDocument（要求。読めなければ null）</param>
        /// <returns>検証できたか</returns>
        /// <remarks>
        /// **検証は Open棟梁 の `SAML2Client.VerifyRequest`**（署名と XML の構造。#294）。
        /// **鍵は、要求の Issuer（＝ client_id）の登録から引く。**
        ///
        /// **鍵が無い SP の要求は、従来どおり通す**（この製品の決め）。
        /// **Open棟梁 は通さない**（鍵を返す処理が null を返せば false）ので、
        /// **その判断はここで行う**（Open棟梁 #634 の補足 3-5）。
        /// </remarks>
        public static bool VerifySamlRequest(
            string queryString, string samlRequest,
            out string iss, out string inResponseTo, out XmlDocument samlRequest2)
        {
            bool hasNoKey = false;

            bool verified = SAML2Client.VerifyRequest(queryString, samlRequest,
                requestIss =>
                {
                    RSA rsa = CmnEndpoints.RsaOf(CmnEndpoints.ClientIdOf(requestIss));
                    hasNoKey = (rsa == null);
                    return hasNoKey ? null : new RSA[] { rsa };
                },
                out iss, out inResponseTo, out samlRequest2);

            // - iss : 当該IdP/Stsの仕様（client_idを流用するので）
            iss = CmnEndpoints.ClientIdOf(iss);

            if (!verified && hasNoKey)
            {
                // 鍵がない場合は、通す。
                verified = true;
            }

            return verified;
        }

        /// <summary>レスポンス作成</summary>
        /// <param name="identity">ClaimsIdentity</param>
        /// <param name="authnContextClassRef">SAML2Enum.AuthnContextClassRef</param>
        /// <param name="statusCode">SAML2Enum.StatusCode</param>
        /// <param name="iss">string ※ Requestのissを指定</param>
        /// <param name="relayState">string</param>
        /// <param name="inResponseTo">string</param>
        /// <param name="rtnUrl">out string</param>
        /// <param name="samlResponse">out string</param>
        /// <param name="queryString">out string</param>
        /// <param name="samlRequest">XmlDocument</param>
        /// <param name="samlNsMgr">XmlNamespaceManager</param>
        /// <param name="hashAlgorithmName">HashAlgorithmName</param>
        /// <returns>
        /// SAML2Enum.ProtocolBinding（返す先のバインディング）。
        /// **null は「応答を返す先が決まらない」**ことを表す（#276）。
        /// </returns>
        public static SAML2Enum.ProtocolBinding? CreateSamlResponse(
            ClaimsIdentity identity,
            SAML2Enum.AuthnContextClassRef authnContextClassRef,
            SAML2Enum.StatusCode statusCode,
            string iss, string relayState, string inResponseTo,
            out string rtnUrl, out string samlResponse, out string queryString,
            XmlDocument samlRequest, XmlNamespaceManager samlNsMgr,
            HashAlgorithmName? hashAlgorithmName = null) // 既定値の変更 SHA1 → SHA256
        {
            string rtnProtocol = "";
            string nameIdPolicy = "";

            rtnUrl = "";
            samlResponse = "";
            queryString = "";

            // DigitalSignX509
            HashAlgorithmName han = hashAlgorithmName ?? HashAlgorithmName.SHA256;
            DigitalSignX509 dsX509 = new DigitalSignX509(CmnServerParams.RsaPfxFilePath, CmnServerParams.RsaPfxPassword, han);

            // rtnUrl
            //  **返す先は、常に事前登録の値である**（#276）。
            //    **要求に書かれた ACS URL は、登録値との照合にしか使わない。**
            //    （要求の値をそのまま使うと、任意の URL へアサーションを飛ばせられる。）
            string temp1 = SAML2Bindings.GetAssertionConsumerServiceURLInRequest(samlRequest, samlNsMgr);
            string temp2 = Sts.Helper.GetInstance().GetAssertionConsumerServiceURL(iss);

            if (string.IsNullOrEmpty(temp2))
            {
                // **事前登録が無い**（iss が未登録、または ACS URL を登録していない）。
                //   **応答を返す先が決まらないので、応答しない**（SAML Core 3.2.1）。
                return null;
            }

            if (!string.IsNullOrEmpty(temp1) && temp1 != temp2)
            {
                // **要求の ACS URL が登録値と違う。**
                //   **登録値へ Requester のエラー応答を返す。**
                //
                //   **以前は null を返していた**が、**呼び出し側は
                //   `== HttpRedirect` で分岐していた**ので、
                //   **null が POST 側に落ち、action も SAMLResponse も空の
                //   自動送信フォームが返っていた**（#276）。
                statusCode = SAML2Enum.StatusCode.Requester;
            }

            rtnUrl = temp2; // 事前登録の値

            // 事前登録されている。
            if (rtnUrl.ToLower() == Const.TestSelfSaml)
            {
                // Authorization Codeグラント種別のテスト用のセルフRedirectエンドポイント
                rtnUrl = Config.OAuth2ClientEndpointsRootURI + Config.Saml2ResponseEndpoint;
            }

            // NameIDPolicyFormat
            nameIdPolicy = SAML2Bindings.GetNameIDPolicyFormatInRequest(samlRequest, samlNsMgr);
            
            // 文字列から配列に変換
            SAML2Enum.NameIDFormat? nameIDFormat = null;
            SAML2Enum.StringToEnum(nameIdPolicy, out nameIDFormat);
            if (!nameIDFormat.HasValue) nameIDFormat = SAML2Enum.NameIDFormat.Unspecified;

            // rtnProtocol
            rtnProtocol = SAML2Bindings.GetProtocolBindingInRequest(samlRequest, samlNsMgr);
            SAML2Enum.ProtocolBinding? protocolBinding = null;
            SAML2Enum.StringToEnum(rtnProtocol, out protocolBinding);
            if (!protocolBinding.HasValue) protocolBinding = SAML2Enum.ProtocolBinding.HttpRedirect;

            // nameIDFormat.Valueに合わせて処理（PPID）
            //  **sub の算出も属性も、エラー応答では要らない値**（Assertion を組み込まない。#278）。
            string sub = "";
            List<Tuple<string, string, string, string>> attributes = null;

            if (statusCode == SAML2Enum.StatusCode.Success)
            {
                //  **利用者も受け取る**（#286 の段階 4）。**属性に入れる値を、引き直さずに使う。**
                ApplicationUser user = null;
                sub = PPIDExtension.GetSubForSAML2(
                    iss, identity.Name, nameIDFormat.Value, out user);

                // **メアドと利用者名を属性で返す**（#286 の段階 4）。
                if (user != null)
                {
                    attributes = CmnEndpoints.AttributesOf(user.Email, user.UserName, user.EmailConfirmed);
                }
            }

            //  **応答の組み立てと署名は Open棟梁 の `SAML2Client`**（#294）。
            //    **返す先・NameID・属性・Binding の決めは、ここに残る。**
            //    **有効期間は `Config` の値を渡す**（無ければ id_token の期間に倒す。Open棟梁 #634 の補足 3-4）。
            double expiresInSeconds = Config.Saml2AssertionExpireTimeSpanFromMinutes * 60;

            // 返しのProtocol Binding
            switch (protocolBinding)
            {
                case SAML2Enum.ProtocolBinding.HttpRedirect:
                    // SamlResponseのエンコと、QueryStringを生成（ + 署名）
                    queryString = SAML2Client.CreateRedirectResponse(
                        CmnServerParams.IssuerId, rtnUrl, inResponseTo, statusCode,
                        sub, nameIDFormat.Value, authnContextClassRef,
                        expiresInSeconds, attributes, relayState, dsX509);
                    break;
                case SAML2Enum.ProtocolBinding.HttpPost:
                    // SamlResponseのエンコと署名
                    samlResponse = SAML2Client.CreatePostResponse(
                        CmnServerParams.IssuerId, rtnUrl, inResponseTo, statusCode,
                        sub, nameIDFormat.Value, authnContextClassRef,
                        expiresInSeconds, attributes, dsX509.X509Certificate.GetRSAPrivateKey());
                    break;
            }

            return protocolBinding;
        }

        #region private

        /// <summary>要求の Issuer から、client_id を作る</summary>
        /// <param name="iss">要求の Issuer</param>
        /// <returns>client_id</returns>
        /// <remarks>当該IdP/Stsの仕様（client_idを流用するので）</remarks>
        private static string ClientIdOf(string iss)
        {
            return (iss ?? "").Replace("http://", "");
        }

        /// <summary>client_id に登録された、署名を検証する鍵（RSA）</summary>
        /// <param name="clientId">client_id</param>
        /// <returns>RSA（登録が無ければ null）</returns>
        private static RSA RsaOf(string clientId)
        {
            // rsa from iss
            string pubKey = Sts.Helper.GetInstance().GetJwkRsaPublickey(clientId);

            if (string.IsNullOrEmpty(pubKey))
            {
                return null;
            }

            pubKey = CustomEncode.ByteToString(
                CustomEncode.FromBase64UrlString(pubKey), CustomEncode.us_ascii);

            // 鍵変換
            return new RsaPublicKeyConverter(JWS_RSA.RS._256).JwkToProvider(pubKey);
        }

        /// <summary>アサーションに入れる属性（メアド・email_verified・利用者名）</summary>
        /// <param name="email">メアド</param>
        /// <param name="userName">利用者名</param>
        /// <param name="emailVerified">メアドを確かめたか</param>
        /// <returns>属性の並び（Name, FriendlyName, NameFormat, 値）</returns>
        /// <remarks>
        /// **名前は Open棟梁 の `SAML2Const` が持つ**（読む側の `SAML2Attributes` と同じもの）。
        /// **`email_verified` は、メアドを出すときだけ添える。**
        /// </remarks>
        private static List<Tuple<string, string, string, string>> AttributesOf(
            string email, string userName, bool emailVerified)
        {
            List<Tuple<string, string, string, string>> ret = new List<Tuple<string, string, string, string>>();

            if (!string.IsNullOrEmpty(email))
            {
                ret.Add(Tuple.Create(SAML2Const.UrnOidMail,
                    SAML2Const.FriendlyNameMail, SAML2Const.UrnAttrNameFormatUri, email));
                ret.Add(Tuple.Create(OAuth2AndOIDCConst.email_verified,
                    "", SAML2Const.UrnAttrNameFormatBasic, emailVerified ? "true" : "false"));
            }

            if (!string.IsNullOrEmpty(userName))
            {
                ret.Add(Tuple.Create(SAML2Const.UrnOidUid,
                    SAML2Const.FriendlyNameUid, SAML2Const.UrnAttrNameFormatUri, userName));
            }

            return ret;
        }

        #endregion

        // VerifySamlResponseはクライアントライブラリなので、
        // Touryo.Infrastructure.Framework.Authenticationに実装
    }
}
