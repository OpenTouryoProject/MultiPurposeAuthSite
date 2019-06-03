﻿//**********************************************************************************
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

using System;
using System.Xml;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

using System.Web.Mvc;

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
        /// <param name="id">out string</param>
        /// <param name="samlRequest2">XmlDocument</param>
        /// <param name="samlNsMgr">XmlNamespaceManager</param>
        /// <returns></returns>
        public static bool VerifySamlRequest(
            string queryString, string decodeSaml,
            out string iss, out string id,
            XmlDocument samlRequest, XmlNamespaceManager samlNsMgr)
        {
            bool verified = false;

            // iss, id

            // - iss : 当該IdP/Stsの仕様（client_idを使用すので）
            iss = SAML2Bindings.GetIssuerInRequest(samlRequest, samlNsMgr);
            iss = iss.Replace("http://", "");

            // - id
            id = SAML2Bindings.GetIdInRequest(samlRequest, samlNsMgr);

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

                    if (SAML2Bindings.VerifyPost(decodeSaml, id, rsa))
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
        /// <param name="relayState">string</param>
        /// <param name="iss">string</param>
        /// <param name="rtnUrl">out string</param>
        /// <param name="samlResponse">out string</param>
        /// <param name="queryString">out string</param>
        /// <param name="samlRequest">XmlDocument</param>
        /// <param name="samlNsMgr">XmlNamespaceManager</param>
        /// <returns>SAML2Enum.ProtocolBinding?</returns>
        public static SAML2Enum.ProtocolBinding? CreateSamlResponse(
            string relayState, string iss,
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
                Config.OAuth2JwsRs256Pfx, Config.OAuth2JwsRs256Pwd, HashAlgorithmName.SHA1,
                X509KeyStorageFlags.Exportable | X509KeyStorageFlags.MachineKeySet);

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
            if (!nameIDFormat.HasValue) nameIDFormat = SAML2Enum.NameIDFormat.unspecified;

            // rtnProtocol
            rtnProtocol = SAML2Bindings.GetProtocolBindingInRequest(samlRequest, samlNsMgr);
            SAML2Enum.ProtocolBinding? protocolBinding = null;
            SAML2Enum.StringToEnum(rtnProtocol, out protocolBinding);
            if (!protocolBinding.HasValue) protocolBinding = SAML2Enum.ProtocolBinding.HttpRedirect;

            string id1 = "";
            string id2 = "";

            // SamlResponseを作成する。
            XmlDocument samlResponse2 = SAML2Bindings.CreateResponse(
                Config.OAuth2IssuerId, rtnUrl, SAML2Enum.StatusCode.Success, out id1);

            // SamlAssertionを作成する。
            XmlDocument samlAssertion = SAML2Bindings.CreateAssertion(
                id1, Config.OAuth2IssuerId, "hogehoge", nameIDFormat.Value,
                SAML2Enum.AuthnContextClassRef.unspecified, 3600, rtnUrl, out id2);

            // ResponseにAssertionを組込
            samlResponse = samlResponse2.OuterXml.Replace(
                "{Assertion}", samlAssertion.GetElementsByTagName("saml:Assertion")[0].OuterXml);

            // 返しのProtocol Binding
            switch (protocolBinding)
            {
                case SAML2Enum.ProtocolBinding.HttpRedirect:
                    // SamlResponseのエンコと、QueryStringを生成（ + 署名）
                    queryString = SAML2Bindings.EncodeAndSignRedirect(
                        SAML2Enum.RequestOrResponse.Response,
                        samlResponse, relayState, dsX509);
                    break;
                case SAML2Enum.ProtocolBinding.HttpPost:
                    // SamlRequestのエンコと署名
                    samlResponse = SAML2Bindings.EncodeAndSignPost(
                        samlResponse, id1, dsX509.X509Certificate.GetRSAPrivateKey());
                    break;
            }

            return protocolBinding;
        }
    }
}
