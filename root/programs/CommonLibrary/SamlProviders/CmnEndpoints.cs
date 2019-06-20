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
//**********************************************************************************

using MultiPurposeAuthSite.Co;
using Sts = MultiPurposeAuthSite.Extensions.Sts;

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
        /// <param name="queryString">string</param>
        /// <param name="decodeSaml">string</param>
        /// <param name="iss">out string</param>
        /// <param name="inResponseTo">out string</param>
        /// <param name="samlRequest2">XmlDocument</param>
        /// <param name="samlNsMgr">XmlNamespaceManager</param>
        /// <returns></returns>
        public static bool VerifySamlRequest(
            string queryString, string decodeSaml,
            out string iss, out string inResponseTo,
            XmlDocument samlRequest, XmlNamespaceManager samlNsMgr)
        {
            bool verified = false;

            // iss, id

            // - iss : 当該IdP/Stsの仕様（client_idを流用するので）
            iss = SAML2Bindings.GetIssuerInRequest(
                samlRequest, samlNsMgr).Replace("http://", "");

            // - id
            inResponseTo = SAML2Bindings.GetIdInRequest(samlRequest, samlNsMgr);

            // rsa from iss
            string pubKey = Sts.Helper.GetInstance().GetJwkRsaPublickey(iss);

            if (string.IsNullOrEmpty(pubKey))
            {
                // 鍵がない場合は、通す。
                verified = true;
            }
            else
            {
                // 鍵がある場合は、検証。
                pubKey = CustomEncode.ByteToString(
                    CustomEncode.FromBase64UrlString(pubKey), CustomEncode.us_ascii);

                if (!string.IsNullOrEmpty(queryString))
                {
                    // VerifyRedirect
                    DigitalSignParam dsParam = new DigitalSignParam(
                        RsaPublicKeyConverter.JwkToParam(pubKey),
                        EnumDigitalSignAlgorithm.RsaCSP_SHA1);

                    if (SAML2Bindings.VerifyRedirect(queryString, dsParam))
                    {
                        // XSDスキーマによる検証
                        // https://developers.onelogin.com/saml/online-tools/validate/xml-against-xsd-schema
                        // The XML is valid.

                        // XPathによる検証
                        verified = SAML2Bindings.VerifyByXPath(
                            samlRequest, SAML2Enum.SamlSchema.Request, samlNsMgr);
                    }
                }
                else
                {
                    // VerifyPost
                    RSA rsa = RsaPublicKeyConverter.JwkToProvider(pubKey);

                    if (SAML2Bindings.VerifyPost(decodeSaml, inResponseTo, rsa))
                    {
                        // XSDスキーマによる検証
                        // https://developers.onelogin.com/saml/online-tools/validate/xml-against-xsd-schema
                        // The XML is valid. (ただし、Signature要素は外す。

                        // XPathによる検証
                        verified = SAML2Bindings.VerifyByXPath(
                            samlRequest, SAML2Enum.SamlSchema.Request, samlNsMgr);
                    }
                }
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
        /// <returns>SAML2Enum.ProtocolBinding?</returns>
        public static SAML2Enum.ProtocolBinding? CreateSamlResponse(
            ClaimsIdentity identity,
            SAML2Enum.AuthnContextClassRef authnContextClassRef,
            SAML2Enum.StatusCode statusCode,
            string iss, string relayState, string inResponseTo,
            out string rtnUrl, out string samlResponse, out string queryString,
            XmlDocument samlRequest, XmlNamespaceManager samlNsMgr)
        {
            string rtnProtocol = "";
            string nameIdPolicy = "";

            rtnUrl = "";
            samlResponse = "";
            queryString = "";

            // DigitalSignX509
            DigitalSignX509 dsX509 = new DigitalSignX509(
                Config.RsaPfxFilePath,
                Config.RsaPfxPassword,
                HashAlgorithmName.SHA1);

            // rtnUrl
            string temp1 = SAML2Bindings.GetAssertionConsumerServiceURLInRequest(samlRequest, samlNsMgr);
            string temp2 = Sts.Helper.GetInstance().GetAssertionConsumerServiceURL(iss);
            if (string.IsNullOrEmpty(temp1))
            {
                rtnUrl = temp2; // 事前登録の値
            }
            else if (temp1 == temp2)
            {
                rtnUrl = temp2; // 完全一致
            }
            else
            {
                return null; // エラーレスポンス
            }

            // 事前登録されている。
            if (rtnUrl.ToLower() == "test_self_saml")
            {
                // Authorization Codeグラント種別のテスト用のセルフRedirectエンドポイント
                rtnUrl = Config.OAuth2ClientEndpointsRootURI + Config.Saml2ResponseEndpoint;
            }

            // NameIDPolicyFormat
            nameIdPolicy = SAML2Bindings.GetNameIDPolicyFormatInRequest(samlRequest, samlNsMgr);
            SAML2Enum.NameIDFormat? nameIDFormat = null;
            SAML2Enum.StringToEnum(nameIdPolicy, out nameIDFormat);
            if (!nameIDFormat.HasValue) nameIDFormat = SAML2Enum.NameIDFormat.Unspecified;

            // rtnProtocol
            rtnProtocol = SAML2Bindings.GetProtocolBindingInRequest(samlRequest, samlNsMgr);
            SAML2Enum.ProtocolBinding? protocolBinding = null;
            SAML2Enum.StringToEnum(rtnProtocol, out protocolBinding);
            if (!protocolBinding.HasValue) protocolBinding = SAML2Enum.ProtocolBinding.HttpRedirect;

            string id1 = "";
            string id2 = "";

            // SamlResponseを作成する。
            XmlDocument samlResponse2 = SAML2Bindings.CreateResponse(
                Config.IssuerId, rtnUrl, inResponseTo, statusCode, out id1);

            // SamlAssertionを作成する（nameIDFormat.Valueに合わせて処理）。
            XmlDocument samlAssertion = SAML2Bindings.CreateAssertion(
                inResponseTo, Config.IssuerId,
                identity.Name, nameIDFormat.Value, authnContextClassRef,
                Config.Saml2AssertionExpireTimeSpanFromMinutes, rtnUrl, out id2);

            // 必要に応じて、identity.Claimsを使用して、様々なクレームを追加できる。
            //  > Assertion > AttributeStatement > Attribute > AttributeValue

            // ResponseにAssertionを組込
            XmlNode newNode = samlResponse2.ImportNode( // 御呪い
                samlAssertion.GetElementsByTagName("saml:Assertion")[0], true);
            samlResponse2.GetElementsByTagName("samlp:Response")[0].AppendChild(newNode);

            // 返しのProtocol Binding
            switch (protocolBinding)
            {
                case SAML2Enum.ProtocolBinding.HttpRedirect:
                    // SamlResponseのエンコと、QueryStringを生成（ + 署名）
                    queryString = SAML2Bindings.EncodeAndSignRedirect(
                        SAML2Enum.RequestOrResponse.Response,
                        samlResponse2.OuterXml, relayState, dsX509);
                    break;
                case SAML2Enum.ProtocolBinding.HttpPost:
                    // SamlRequestのエンコと署名
                    samlResponse = SAML2Bindings.EncodeAndSignPost(
                        samlResponse2.OuterXml, id1, dsX509.X509Certificate.GetRSAPrivateKey());
                    break;
            }

            return protocolBinding;
        }

        // VerifySamlResponseはクライアントライブラリなので、
        // Touryo.Infrastructure.Framework.Authenticationに実装

    }
}
