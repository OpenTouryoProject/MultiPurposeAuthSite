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
//* クラス名        ：RefreshTokenProvider
//* クラス日本語名  ：RefreshTokenProvider（ライブラリ）
//*                   --------------------------------------------------
//*                   Instance methodが必要なため singleton。
//*
//* 作成日時        ：－
//* 作成者          ：－
//* 更新履歴        ：－
//*
//*  日時        更新者            内容
//*  ----------  ----------------  -------------------------------------------------
//*  2017/04/24  西野 大介         新規
//**********************************************************************************

using MultiPurposeAuthSite.Co;
using ExtOAuth2 = MultiPurposeAuthSite.Extensions.OAuth2;

using System;
using System.Threading.Tasks;

using Microsoft.Owin.Security;
using Microsoft.Owin.Security.Infrastructure;
using Microsoft.Owin.Security.DataHandler.Serializer;

using Touryo.Infrastructure.Public.Security;

namespace MultiPurposeAuthSite.TokenProviders
{
    /// <summary>
    /// RefreshTokenのProvider
    /// SerializeTicket一時保存する。
    /// </summary>
    /// <remarks>c# - OWIN Security - How to Implement OAuth2 Refresh Tokens - Stack Overflow</remarks>
    /// <see cref="http://stackoverflow.com/questions/20637674/owin-security-how-to-implement-oauth2-refresh-tokens"/>
    /// <seealso cref="https://tools.ietf.org/html/rfc6749#section-1.5"/>
    public class RefreshTokenProvider : IAuthenticationTokenProvider
    {
        /// <summary>シングルトン</summary>
        private static RefreshTokenProvider _RefreshTokenProvider = new RefreshTokenProvider();

        /// <summary>GetInstance</summary>
        /// <returns>RefreshTokenProvider</returns>
        public static RefreshTokenProvider GetInstance()
        {
            return RefreshTokenProvider._RefreshTokenProvider;
        }

        #region instance

        #region Create

        /// <summary>Create</summary>
        /// <param name="context">AuthenticationTokenCreateContext</param>
        public void Create(AuthenticationTokenCreateContext context)
        {
            this.CreateRefreshToken(context);
        }

        public Task CreateAsync(AuthenticationTokenCreateContext context)
        {
            return Task.Factory.StartNew(() => this.CreateRefreshToken(context));
        }

        /// <summary>CreateRefreshToken</summary>
        /// <param name="context"></param>
        private void CreateRefreshToken(AuthenticationTokenCreateContext context)
        {
            if (Config.EnableRefreshToken)
            {
                // EnableRefreshToken == true

                string tokenId = GetPassword.Base64UrlSecret(128); // Guid.NewGuid().ToString();

                // copy properties and set the desired lifetime of refresh token.
                AuthenticationProperties refreshTokenProperties = new AuthenticationProperties(context.Ticket.Properties.Dictionary)
                {
                    // IssuedUtcとExpiredUtcという有効期限プロパティをAuthenticationTicketに追加
                    IssuedUtc = context.Ticket.Properties.IssuedUtc,
                    ExpiresUtc = DateTime.UtcNow.Add(Config.OAuth2RefreshTokenExpireTimeSpanFromDays) // System.TimeSpan.FromSeconds(20)) // Debug時  
                };

                // AuthenticationTicket.IdentityのClaimsIdentity値を含む
                // 有効期限付きの新しいAuthenticationTicketを作成する。
                AuthenticationTicket refreshTokenTicket = new AuthenticationTicket(context.Ticket.Identity, refreshTokenProperties);

                TicketSerializer serializer = new TicketSerializer();

                // 新しいRefreshTokenのAuthenticationTicketをストアに保存         
                ExtOAuth2.RefreshTokenProvider.Create(tokenId, serializer.Serialize(refreshTokenTicket));

                context.SetToken(tokenId);
            }
            else
            {
                // EnableRefreshToken == false
            }
        }

        #endregion

        #region Receive

        /// <summary>Receive</summary>
        /// <param name="context">AuthenticationTokenReceiveContext</param>
        public void Receive(AuthenticationTokenReceiveContext context)
        {
            this.ReceiveRefreshToken(context);
        }

        /// <summary>ReceiveAsync</summary>
        /// <param name="context">AuthenticationTokenReceiveContext</param>
        /// <returns>Task</returns>
        public Task ReceiveAsync(AuthenticationTokenReceiveContext context)
        {
            return Task.Factory.StartNew(() => this.ReceiveRefreshToken(context));
        }

        /// <summary>ReceiveRefreshToken</summary>
        /// <param name="context">AuthenticationTokenReceiveContext</param>
        private void ReceiveRefreshToken(AuthenticationTokenReceiveContext context)
        {
            if (Config.EnableRefreshToken)
            {
                // EnableRefreshToken == true

                // RefreshTokenのAuthenticationTicketを受け取り、ストアから削除する。
                TicketSerializer serializer = new TicketSerializer();
                
                byte[] temp = ExtOAuth2.RefreshTokenProvider.Receive(context.Token);
                if (temp == null)
                {
                    // == null
                }
                else
                {
                    // != null
                    context.SetTicket(serializer.Deserialize(temp));
                }
            }
            else
            {
                // EnableRefreshToken == false
            }
        }

        #endregion

        #endregion

        #region static

        #region Reference

        /// <summary>（インスタンス化不要な直接的な）参照</summary>
        /// <param name="tokenId">string</param>
        /// <returns>AuthenticationTicket</returns>
        /// <remarks>OAuth 2.0 Token Introspectionのサポートのために必要</remarks>
        public static AuthenticationTicket ReferDirectly(string tokenId)
        {
            if (Config.EnableRefreshToken)
            {
                // EnableRefreshToken == true

                // ストアのRefreshTokenのAuthenticationTicketを参照する。
                TicketSerializer serializer = new TicketSerializer();
                byte[] temp = ExtOAuth2.RefreshTokenProvider.Refer(tokenId);
                if (temp == null)
                {
                    // == null
                    return null;
                }
                else
                {
                    // != null
                    return serializer.Deserialize(temp);
                }
            }
            else
            {
                // EnableRefreshToken == false
                return null;
            }
        }

        #endregion

        #region Delete

        /// <summary>（インスタンス化不要な直接的な）削除</summary>
        /// <param name="tokenId">string</param>
        /// <returns>削除できたか否か</returns>
        /// <remarks>OAuth 2.0 Token Revocationサポート</remarks>
        public static bool DeleteDirectly(string tokenId)
        {
            if (Config.EnableRefreshToken)
            {
                // EnableRefreshToken == true

                // RefreshTokenのAuthenticationTicketをストアから削除する。
                return ExtOAuth2.RefreshTokenProvider.Delete(tokenId);
            }
            else
            {
                // EnableRefreshToken == false
                return false;
            }
        }

        #endregion

        #endregion
    }
}