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
//* クラス名        ：OpenIDConnectCodeFilter
//* クラス日本語名  ：OpenIDConnectCodeFilter（ライブラリ）
//*
//* 作成日時        ：－
//* 作成者          ：－
//* 更新履歴        ：－
//*
//*  日時        更新者            内容
//*  ----------  ----------------  -------------------------------------------------
//*  2017/07/14  西野 大介         新規
//**********************************************************************************

using System;
using System.Text;
using System.IO;
using System.Web;
using System.Collections.Generic;

using Newtonsoft.Json;

using Touryo.Infrastructure.Framework.Authentication;

namespace MultiPurposeAuthSite.Models.ASPNETIdentity.OIDCFilter
{
    /// <summary>
    /// OpenIDConnectCodeFilter
    /// OpenID Connect : response_type=codeに対応
    /// </summary>
    public class OpenIDConnectCodeFilter : Stream
    {
        #region Member
        /// <summary>HttpResponse</summary>
        private HttpResponse _response;
        /// <summary>Stream</summary>
        private Stream _responseStream;
        /// <summary>MemoryStream</summary>
        private MemoryStream _tempBuffer;
        #endregion

        #region Property
        /// <summary>HttpResponse</summary>
        private HttpResponse Response
        {
            get { return this._response; }
        }
        /// <summary>Stream</summary>
        private Stream ResponseStream
        {
            get { return this._responseStream; }
        }
        /// <summary>MemoryStream</summary>
        private MemoryStream TempBuffer
        {
            get { return this._tempBuffer; }
        }
        #endregion

        #region Constructor

        /// <summary>Constructor</summary>
        /// <param name="context">HttpContext</param>
        public OpenIDConnectCodeFilter(HttpContext context)
        {
            // レスポンスオブジェクト参照を取得
            this._response = context.Response;
            // レスポンスフィルタチェインを構築
            this._responseStream = context.Response.Filter;
            // バッファを構築
            this._tempBuffer = new MemoryStream();
        }

        #endregion

        #region Write & Flush

        /// <summary>CanWrite</summary>
        public override bool CanWrite
        {
            get { return true; }
        }

        /// <summary>Write</summary>
        /// <param name="buffer">byte[]</param>
        /// <param name="offset">offset</param>
        /// <param name="count">count</param>
        public override void Write(byte[] buffer, int offset, int count)
        {
            if (Response.StatusCode == 200 && Response.ContentType.ToLower().Contains("application/json"))
            {
                // レスポンスをバッファに蓄える
                TempBuffer.Write(buffer, offset, count);
            }
            else
            {
                ResponseStream.Write(buffer, offset, count);
            }
        }

        /// <summary>Flush</summary>
        public override void Flush()
        {
            byte[] bb = TempBuffer.GetBuffer();

            if (bb != null && bb.Length > 0)
            {
                // 書き換え処理
                Encoding enc = Response.ContentEncoding;
                string content = enc.GetString(bb);
                
                // JSON形式なので、JsonConvertでaccess_tokenを抜き出す。
                Dictionary<string, object> accessTokenResponse = 
                    JsonConvert.DeserializeObject<Dictionary<string, object>>(content);

                // access_tokenを
                if (accessTokenResponse.ContainsKey(OAuth2AndOIDCConst.AccessToken))
                {
                    string access_token = (string)accessTokenResponse[OAuth2AndOIDCConst.AccessToken];

                    string id_token = IdToken.ChangeToIdTokenFromAccessToken(
                        access_token, "", "", HashClaimType.None,
                        ASPNETIdentityConfig.OAuth2JWT_pfx, ASPNETIdentityConfig.OAuth2JWTPassword);

                    if (!string.IsNullOrEmpty(id_token))
                    {
                        // responseにid_tokenとして、このJWTを追加する。
                        accessTokenResponse.Add(OAuth2AndOIDCConst.IDToken, id_token);
                        bb = enc.GetBytes(JsonConvert.SerializeObject(accessTokenResponse));
                    }           
                }
            }

            ResponseStream.Write(bb, 0, bb.Length);
            ResponseStream.Flush();
        }

        #endregion

        #region その他

        /// <summary>CanRead</summary>
        public override bool CanRead
        {
            get { return false; }
        }

        /// <summary>Read</summary>
        /// <param name="buffer">byte[]</param>
        /// <param name="offset">int</param>
        /// <param name="count">int</param>
        /// <returns></returns>
        public override int Read(byte[] buffer, int offset, int count)
        {
            throw new NotSupportedException();
        }

        /// <summary>CanSeek</summary>
        public override bool CanSeek
        {
            get { return false; }
        }

        /// <summary>Seek</summary>
        /// <param name="offset">long</param>
        /// <param name="origin">SeekOrigin</param>
        /// <returns>long</returns>
        public override long Seek(long offset, SeekOrigin origin)
        {
            throw new NotSupportedException();
        }

        /// <summary>Length</summary>
        public override long Length
        {
            get { throw new NotSupportedException(); }
        }

        /// <summary>Position</summary>
        public override long Position
        {
            get { throw new NotSupportedException(); }
            set { throw new NotSupportedException(); }
        }

        /// <summary>SetLength</summary>
        /// <param name="value">long</param>
        public override void SetLength(long value)
        {
            throw new NotSupportedException();
        }

        #endregion
    }
}