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
//* クラス名        ：UserClaimsTests
//* クラス日本語名  ：email / phone のクレームの組み立て
//*
//* 作成者          ：玄人 幸道
//* 更新履歴        ：
//*
//*  日時        更新者            内容
//*  ----------  ----------------  -------------------------------------------------
//*  2026/11/10  玄人 幸道         新規作成（#354）
//**********************************************************************************

using System.Collections.Generic;

using MultiPurposeAuthSite.Util.Sts;

using Touryo.Infrastructure.Framework.Authentication;

using Xunit;

namespace MultiPurposeAuthSite.Tests.Unit.Sts
{
    /// <summary>
    /// UserClaims.AddContactClaims（#354）。
    /// **E2E では電話番号を持つ利用者を作れない**（SMS の確認が要る）ので、
    /// **値の在るときに返ること**と、**`*_verified` が真偽値であること**は、ここで確かめる。
    /// </summary>
    public class UserClaimsTests
    {
        /// <summary>利用者を作る</summary>
        private static ApplicationUser User(string email, bool emailConfirmed, string phone, bool phoneConfirmed)
        {
            return new ApplicationUser()
            {
                Email = email,
                EmailConfirmed = emailConfirmed,
                PhoneNumber = phone,
                PhoneNumberConfirmed = phoneConfirmed
            };
        }

        /// <summary>電話番号が在れば、phone_number と phone_number_verified（真偽値）を返す</summary>
        [Fact]
        [Basis("OIDC Core 1.0 §5.1（phone_number は文字列、phone_number_verified は boolean）/ #354")]
        public void 電話番号が在ればphone_numberとverifiedを返す()
        {
            Dictionary<string, object> claims = new Dictionary<string, object>();

            UserClaims.AddContactClaims(claims,
                UserClaimsTests.User("a@example.com", true, "+81 90-0000-0000", true), OAuth2AndOIDCConst.Scope_Phone);

            Assert.Equal("+81 90-0000-0000", claims[OAuth2AndOIDCConst.phone_number]);
            Assert.IsType<bool>(claims[OAuth2AndOIDCConst.phone_number_verified]);
            Assert.True((bool)claims[OAuth2AndOIDCConst.phone_number_verified]);

            //  **phone の scope では、email を足さない**
            Assert.False(claims.ContainsKey(OAuth2AndOIDCConst.Scope_Email));
        }

        /// <summary>電話番号が空・null なら、phone_number も phone_number_verified も返さない</summary>
        /// <param name="phone">電話番号</param>
        [Theory]
        [InlineData("")]
        [InlineData(null)]
        [Basis("OIDC Core 1.0 §5.3.2（値の無いクレームは名前ごと省き、null や空文字列で返さない）/ #354")]
        public void 電話番号が無ければphoneのクレームを返さない(string phone)
        {
            Dictionary<string, object> claims = new Dictionary<string, object>();

            UserClaims.AddContactClaims(claims,
                UserClaimsTests.User("a@example.com", true, phone, false), OAuth2AndOIDCConst.Scope_Phone);

            Assert.False(claims.ContainsKey(OAuth2AndOIDCConst.phone_number));
            Assert.False(claims.ContainsKey(OAuth2AndOIDCConst.phone_number_verified));
        }

        /// <summary>メール アドレスが在れば、email と email_verified（真偽値）を返す</summary>
        [Fact]
        [Basis("OIDC Core 1.0 §5.1（email は文字列、email_verified は boolean）/ #354")]
        public void メールアドレスが在ればemailとverifiedを返す()
        {
            Dictionary<string, object> claims = new Dictionary<string, object>();

            UserClaims.AddContactClaims(claims,
                UserClaimsTests.User("a@example.com", false, "", false), OAuth2AndOIDCConst.Scope_Email);

            Assert.Equal("a@example.com", claims[OAuth2AndOIDCConst.Scope_Email]);
            Assert.IsType<bool>(claims[OAuth2AndOIDCConst.email_verified]);
            Assert.False((bool)claims[OAuth2AndOIDCConst.email_verified]);

            //  **email の scope では、phone を足さない**
            Assert.False(claims.ContainsKey(OAuth2AndOIDCConst.phone_number));
        }

        /// <summary>メール アドレスが空・null なら、email も email_verified も返さない</summary>
        /// <param name="email">メール アドレス</param>
        [Theory]
        [InlineData("")]
        [InlineData(null)]
        [Basis("OIDC Core 1.0 §5.3.2（値の無いクレームは名前ごと省き、null や空文字列で返さない）/ #354")]
        public void メールアドレスが無ければemailのクレームを返さない(string email)
        {
            Dictionary<string, object> claims = new Dictionary<string, object>();

            UserClaims.AddContactClaims(claims,
                UserClaimsTests.User(email, true, "", false), OAuth2AndOIDCConst.Scope_Email);

            Assert.False(claims.ContainsKey(OAuth2AndOIDCConst.Scope_Email));
            Assert.False(claims.ContainsKey(OAuth2AndOIDCConst.email_verified));
        }

        /// <summary>email / phone 以外の scope では、何も足さない</summary>
        [Fact]
        [Basis("#354（設計：AddContactClaims は email / phone の scope だけを扱う）")]
        public void ほかのscopeでは何も足さない()
        {
            Dictionary<string, object> claims = new Dictionary<string, object>();

            UserClaims.AddContactClaims(claims,
                UserClaimsTests.User("a@example.com", true, "+81 90-0000-0000", true), OAuth2AndOIDCConst.Scope_Profile);

            Assert.Empty(claims);
        }
    }
}
