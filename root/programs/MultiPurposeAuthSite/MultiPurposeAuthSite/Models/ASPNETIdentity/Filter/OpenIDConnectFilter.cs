using System;
using System.Text;
using System.IO;
using System.Web;

namespace MultiPurposeAuthSite.Models.ASPNETIdentity.Filter
{
    public class OpenIDConnectFilter : Stream
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
        public OpenIDConnectFilter(HttpContext context)
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

                content = content.Replace("書き換え前", "書き換え後");

                // ・正規表現でaccess_tokenを抜き出す。
                // ・access_tokenがJWTである場合、payloadからscopeを削除する。
                // ・編集したpayloadを再度JWTとして署名する。
                // ・このJWTをresponseにid_tokenを追加する。

                bb = enc.GetBytes(content);
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