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
//* クラス名        ：CmnSamlAttributes
//* クラス日本語名  ：アサーションの AttributeStatement（出す側と読む側の両方）
//*
//* 作成日時        ：－
//* 作成者          ：－
//* 更新履歴        ：－
//*
//*  日時        更新者            内容
//*  ----------  ----------------  -------------------------------------------------
//*  2026/10/12  玄人 幸道         新規（#286 の段階 4）
//**********************************************************************************

using System;
using System.Collections.Generic;
using System.Xml;

using Touryo.Infrastructure.Framework.Authentication;

/// <summary>MultiPurposeAuthSite.SamlProviders</summary>
namespace MultiPurposeAuthSite.SamlProviders
{
    /// <summary>
    /// アサーションの `AttributeStatement`（#286 の段階 4）。
    /// </summary>
    /// <remarks>
    /// **出す側（IdP）と読む側（SP）を 1 つの型に置いている。**
    /// **名前が片方だけ変わると気付けない**ためである
    /// （この配備は、同じ製品が上流にも下流にもなる）。
    ///
    /// **なぜ要るか。** **`NameID` だけでは、メアドと利用者名を運べない。**
    /// **段階 2 までは `NameIDFormat=emailAddress` の `NameID` をメアドとして扱っていた**ので、
    ///
    /// | | |
    /// |---|---|
    /// | **`Persistent`（PPID）の配備** | **メアドが分からず、利用者を作れない** |
    /// | 新規作成時の名前 | **メアドの `@` より前**しか使えない（OIDC は `preferred_username`） |
    /// | **検証済みのメアドか** | **言う方法が無い**（OIDC は `email_verified`） |
    ///
    /// **出す値は、OIDC 側のクレームに 1 対 1 で対応させている。**
    ///
    /// | OIDC | SAML2 の `Name` | `FriendlyName` | `NameFormat` |
    /// |---|---|---|---|
    /// | `email` | `urn:oid:0.9.2342.19200300.100.1.3` | `mail` | uri |
    /// | `preferred_username` | `urn:oid:0.9.2342.19200300.100.1.1` | `uid` | uri |
    /// | `email_verified` | **`email_verified`** | － | **basic** |
    ///
    /// **`urn:oid:…` は X.500/LDAP Attribute Profile**（SAML V2.0 の prof-attr-x500）であり、
    /// **他の IdP（Shibboleth / ADFS など）とも合う。**
    ///
    /// **`email_verified` に相当する標準の属性は無い。**
    /// **OIDC の名前をそのまま basic の属性として出す**
    /// （**独自の名前は作らない。** 読む側は、**無ければ従来どおりに倒す**）。
    ///
    /// **読む側は緩い。** **他の IdP が別名で出してくる**ので、
    /// **`Name` と `FriendlyName` の両方を鍵にし、別名も見る**（`EmailAliases` ほか）。
    /// **出す側は 1 つの名前だけ**（上の表）。
    /// </remarks>
    public static class CmnSamlAttributes
    {
        #region 定数

        /// <summary>NameFormat（uri。`urn:oid:…` に使う）</summary>
        public const string NameFormatUri = "urn:oasis:names:tc:SAML:2.0:attrname-format:uri";

        /// <summary>NameFormat（basic。`email_verified` に使う）</summary>
        public const string NameFormatBasic = "urn:oasis:names:tc:SAML:2.0:attrname-format:basic";

        /// <summary>メアド（X.500/LDAP の `mail`）</summary>
        public const string NameEmail = "urn:oid:0.9.2342.19200300.100.1.3";

        /// <summary>メアドの FriendlyName</summary>
        public const string FriendlyNameEmail = "mail";

        /// <summary>利用者名（X.500/LDAP の `uid`。OIDC の `preferred_username` に対応）</summary>
        public const string NameUserName = "urn:oid:0.9.2342.19200300.100.1.1";

        /// <summary>利用者名の FriendlyName</summary>
        public const string FriendlyNameUserName = "uid";

        /// <summary>メアドが検証済みか（OIDC の `email_verified`）</summary>
        public const string NameEmailVerified = "email_verified";

        /// <summary>メアドの別名（読む側だけが使う）</summary>
        private static readonly string[] EmailAliases = new string[]
        {
            CmnSamlAttributes.NameEmail,
            CmnSamlAttributes.FriendlyNameEmail,
            "email",
            "emailAddress",
            "emailaddress",
            // ADFS / WS-Federation の名前
            "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress"
        };

        /// <summary>利用者名の別名（同上）</summary>
        private static readonly string[] UserNameAliases = new string[]
        {
            CmnSamlAttributes.NameUserName,
            CmnSamlAttributes.FriendlyNameUserName,
            "preferred_username",
            "username",
            "displayName",
            "displayname",
            // ADFS / WS-Federation の名前
            "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/name"
        };

        /// <summary>メアドが検証済みかの別名（同上）</summary>
        private static readonly string[] EmailVerifiedAliases = new string[]
        {
            CmnSamlAttributes.NameEmailVerified,
            "emailVerified",
            "emailverified",
            "mailVerified"
        };

        #endregion

        #region 出す側（IdP）

        /// <summary>
        /// アサーションに `AttributeStatement` を足す。
        /// </summary>
        /// <param name="assertion">`CreateAssertion` が作ったアサーション</param>
        /// <param name="email">メアド（空なら出さない）</param>
        /// <param name="userName">利用者名（空なら出さない）</param>
        /// <param name="emailVerified">メアドが検証済みか</param>
        /// <remarks>
        /// **署名の前に呼ぶこと。** **署名は応答の全体に対して行う**ので
        /// （`EncodeAndSignPost` / `EncodeAndSignRedirect`）、
        /// **後から足すと署名が合わなくなる。**
        ///
        /// **`AuthnStatement` の後ろに足す。**
        /// SAML Core のスキーマは、**`Conditions` の後の文は順不同**である
        /// （`AuthnStatement` / `AttributeStatement` の choice）。
        ///
        /// **値は DOM で入れる**（文字列の連結で組まない）。
        /// **メアドや利用者名に `&amp;` や `&lt;` が入っていても壊れない。**
        /// </remarks>
        public static void AppendStatement(
            XmlDocument assertion, string email, string userName, bool emailVerified)
        {
            if (assertion == null)
            {
                return;
            }

            XmlNodeList nodes = assertion.GetElementsByTagName("saml:Assertion");

            if (nodes == null || nodes.Count == 0)
            {
                return;
            }

            XmlNode root = nodes[0];

            XmlElement statement = assertion.CreateElement(
                "saml", "AttributeStatement", SAML2Const.UrnAssertion);

            bool any = false;

            if (!string.IsNullOrEmpty(email))
            {
                statement.AppendChild(CmnSamlAttributes.CreateAttribute(
                    assertion, CmnSamlAttributes.NameEmail,
                    CmnSamlAttributes.FriendlyNameEmail,
                    CmnSamlAttributes.NameFormatUri, email));

                //  **検証済みかどうかは、メアドを出すときだけ意味がある。**
                statement.AppendChild(CmnSamlAttributes.CreateAttribute(
                    assertion, CmnSamlAttributes.NameEmailVerified, "",
                    CmnSamlAttributes.NameFormatBasic,
                    emailVerified ? "true" : "false"));

                any = true;
            }

            if (!string.IsNullOrEmpty(userName))
            {
                statement.AppendChild(CmnSamlAttributes.CreateAttribute(
                    assertion, CmnSamlAttributes.NameUserName,
                    CmnSamlAttributes.FriendlyNameUserName,
                    CmnSamlAttributes.NameFormatUri, userName));

                any = true;
            }

            if (any)
            {
                //  **空の `AttributeStatement` は出さない**（SAML Core 2.7.3.1 は
                //    `Attribute` を 1 つ以上求める）。
                root.AppendChild(statement);
            }
        }

        /// <summary>`saml:Attribute` を 1 つ作る</summary>
        /// <param name="doc">XmlDocument</param>
        /// <param name="name">Name</param>
        /// <param name="friendlyName">FriendlyName（空なら付けない）</param>
        /// <param name="nameFormat">NameFormat</param>
        /// <param name="value">値</param>
        /// <returns>XmlElement</returns>
        private static XmlElement CreateAttribute(
            XmlDocument doc, string name, string friendlyName, string nameFormat, string value)
        {
            XmlElement attribute = doc.CreateElement(
                "saml", "Attribute", SAML2Const.UrnAssertion);

            attribute.SetAttribute("Name", name);
            attribute.SetAttribute("NameFormat", nameFormat);

            if (!string.IsNullOrEmpty(friendlyName))
            {
                attribute.SetAttribute("FriendlyName", friendlyName);
            }

            XmlElement attributeValue = doc.CreateElement(
                "saml", "AttributeValue", SAML2Const.UrnAssertion);

            attributeValue.InnerText = value;
            attribute.AppendChild(attributeValue);

            return attribute;
        }

        #endregion

        #region 読む側（SP）

        /// <summary>
        /// 応答のアサーションから、属性を読む。
        /// </summary>
        /// <param name="samlResponse">応答の XmlDocument</param>
        /// <param name="samlNsMgr">XmlNamespaceManager</param>
        /// <returns>
        /// 属性（`Name` と `FriendlyName` の両方を鍵にする。値は最初の `AttributeValue`）。
        /// **1 つも無ければ空の辞書**を返す（null は返さない）。
        /// </returns>
        /// <remarks>
        /// **複数の値を持つ属性は、最初の 1 つだけを採る。**
        /// **この配備が使う 3 つは、いずれも単一値**である。
        ///
        /// **鍵を 2 つ入れるのは、読む側を緩くするため**である
        /// （`Name` が `urn:oid:…` でも、`FriendlyName` が `mail` なら引ける）。
        /// </remarks>
        public static Dictionary<string, string> Read(
            XmlDocument samlResponse, XmlNamespaceManager samlNsMgr)
        {
            Dictionary<string, string> ret =
                new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);

            if (samlResponse == null || samlNsMgr == null)
            {
                return ret;
            }

            XmlNodeList attributes = samlResponse.SelectNodes(
                "/samlp:Response/saml:Assertion/saml:AttributeStatement/saml:Attribute",
                samlNsMgr);

            if (attributes == null)
            {
                return ret;
            }

            foreach (XmlNode attribute in attributes)
            {
                XmlNode value = attribute.SelectSingleNode("saml:AttributeValue", samlNsMgr);

                if (value == null)
                {
                    continue;
                }

                string name = CmnSamlAttributes.Attr(attribute, "Name");
                string friendlyName = CmnSamlAttributes.Attr(attribute, "FriendlyName");

                if (!string.IsNullOrEmpty(name) && !ret.ContainsKey(name))
                {
                    ret.Add(name, value.InnerText);
                }

                if (!string.IsNullOrEmpty(friendlyName) && !ret.ContainsKey(friendlyName))
                {
                    ret.Add(friendlyName, value.InnerText);
                }
            }

            return ret;
        }

        /// <summary>属性から、メアドを引く</summary>
        /// <param name="attributes">`Read` の戻り</param>
        /// <returns>メアド（無ければ空）</returns>
        public static string GetEmail(IDictionary<string, string> attributes)
        {
            return CmnSamlAttributes.Pick(attributes, CmnSamlAttributes.EmailAliases);
        }

        /// <summary>属性から、利用者名を引く</summary>
        /// <param name="attributes">`Read` の戻り</param>
        /// <returns>利用者名（無ければ空）</returns>
        public static string GetUserName(IDictionary<string, string> attributes)
        {
            return CmnSamlAttributes.Pick(attributes, CmnSamlAttributes.UserNameAliases);
        }

        /// <summary>属性から、メアドが検証済みかを引く</summary>
        /// <param name="attributes">`Read` の戻り</param>
        /// <returns>
        /// 上流が言った値（`true` / `false` の文字列）。
        /// **言っていなければ空**（呼び出し側が、従来どおりの判断に倒す）。
        /// </returns>
        public static string GetEmailVerified(IDictionary<string, string> attributes)
        {
            return CmnSamlAttributes.Pick(attributes, CmnSamlAttributes.EmailVerifiedAliases);
        }

        /// <summary>別名の並びから、最初に見つかった値を返す</summary>
        /// <param name="attributes">属性</param>
        /// <param name="aliases">別名（優先順）</param>
        /// <returns>値（無ければ空）</returns>
        private static string Pick(IDictionary<string, string> attributes, string[] aliases)
        {
            if (attributes == null || attributes.Count == 0)
            {
                return "";
            }

            foreach (string alias in aliases)
            {
                string value = "";

                if (attributes.TryGetValue(alias, out value)
                    && !string.IsNullOrEmpty(value))
                {
                    return value;
                }
            }

            return "";
        }

        /// <summary>属性値を読む（無ければ空）</summary>
        /// <param name="node">XmlNode</param>
        /// <param name="name">属性の名前</param>
        /// <returns>値</returns>
        private static string Attr(XmlNode node, string name)
        {
            if (node == null || node.Attributes == null)
            {
                return "";
            }

            XmlNode attr = node.Attributes[name];

            return (attr == null) ? "" : attr.Value;
        }

        #endregion
    }
}
