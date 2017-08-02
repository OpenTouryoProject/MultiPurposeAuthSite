//**********************************************************************************
//* Copyright (C) 2007,2016 Hitachi Solutions,Ltd.
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
//* クラス名        ：WebAPIHelper
//* クラス日本語名  ：WebAPIHelper（ライブラリ）
//*
//* 作成日時        ：－
//* 作成者          ：－
//* 更新履歴        ：－
//*
//*  日時        更新者            内容
//*  ----------  ----------------  -------------------------------------------------
//*  2017/04/24  西野 大介         新規
//**********************************************************************************

using MultiPurposeAuthSite.Models.ASPNETIdentity;

using System;
using System.Text;
using System.Web.Mvc;
using System.Collections.Generic;
using System.Threading.Tasks;

using System.Net;
using System.Net.Http;
using System.Net.Http.Headers;

using Newtonsoft.Json;
using Newtonsoft.Json.Linq;

using Touryo.Infrastructure.Public.Str;
using Touryo.Infrastructure.Public.Util;

namespace MultiPurposeAuthSite.Models.Util
{
    /// <summary>WebAPIHelper（ライブラリ）</summary>
    public class WebAPIHelper
    {
        #region member variable

        /// <summary>Singleton (instance)</summary>
        private static WebAPIHelper _webAPIHelper = new WebAPIHelper();

        /// <summary>WebAPIにアクセスするためのHttpClient</summary>
        /// <remarks>
        /// HttpClientの類の使い方 - マイクロソフト系技術情報 Wiki
        ///  > HttpClientクラス > ポイント
        /// https://techinfoofmicrosofttech.osscons.jp/index.php?HttpClient%E3%81%AE%E9%A1%9E%E3%81%AE%E4%BD%BF%E3%81%84%E6%96%B9#l0c18008
        /// Singletonで使うので、ここではstaticではない。
        /// </remarks>
        private HttpClient _webAPIHttpClient = null;

        #endregion

        #region constructor

        /// <summary>constructor</summary>
        private WebAPIHelper()
        {
            // WebAPIにアクセスするためのHttpClient
            this._webAPIHttpClient = HttpClientBuilder(EnumProxyType.Internet);
        }

        #endregion

        #region property

        /// <summary>WebAPIHttpClient</summary>
        private HttpClient WebAPIHttpClient
        {
            get
            {
                return this._webAPIHttpClient;
            }
        }

        #endregion

        #region GetInstance

        /// <summary>GetInstance</summary>
        /// <returns>OAuthHelper</returns>
        public static WebAPIHelper GetInstance()
        {
            return WebAPIHelper._webAPIHelper;
        }

        #endregion

        #region instanceメソッド

        #region HttpClient

        #region Client Builder

        /// <summary>
        /// WebAPIにアクセスするためのHttpClientを生成するメソッド
        /// </summary>
        /// <returns>
        /// HttpClient
        /// </returns>
        private HttpClient HttpClientBuilder(EnumProxyType proxyType)
        {
            IWebProxy proxy = null;

            switch (proxyType)
            {
                case EnumProxyType.Internet:
                    proxy = CreateProxy.GetInternetProxy();
                    break;
                case EnumProxyType.Intranet:
                    proxy = CreateProxy.GetIntranetProxy();
                    break;
                case EnumProxyType.Debug:
                    proxy = CreateProxy.GetDebugProxy();
                    break;
            }

            HttpClientHandler handler = new HttpClientHandler
            {
                Proxy = proxy,
            };
            
            return new HttpClient(handler);
            //return new HttpClient();
        }

        #endregion

        #region OnlinePaymentWebAPI

        /// <summary>CreateaOnlinePaymentCustomerAsync</summary>
        /// <param name="email">email</param>
        /// <param name="token">token</param>
        /// <returns></returns>
        public async Task<JObject> CreateaOnlinePaymentCustomerAsync(string email, string token)
        {
            // URL
            string secretKey = "";
            Uri webApiEndpointUri = null;

            if (ASPNETIdentityConfig.EnableStripe)
            {
                webApiEndpointUri = new Uri("https://api.stripe.com/v1/customers");
                secretKey = ASPNETIdentityConfig.Stripe_SK + ":";
            }
            else if (ASPNETIdentityConfig.EnablePAYJP)
            {
                webApiEndpointUri = new Uri("https://api.pay.jp/v1/customers");
                secretKey = ASPNETIdentityConfig.PAYJP_SK + ":"; // 「:」はUID:PWDの「:」
            }
            else
            {
                throw new NotSupportedException("Payment service is not enabled.");
            }
            
            // 通信用の変数
            HttpRequestMessage httpRequestMessage = null;
            HttpResponseMessage httpResponseMessage = null;

            // HttpRequestMessage (Method & RequestUri)
            httpRequestMessage = new HttpRequestMessage
            {
                Method = HttpMethod.Post,
                RequestUri = webApiEndpointUri
            };

            // HttpRequestMessage (Headers)
            httpRequestMessage.Headers.Authorization = new AuthenticationHeaderValue(
                "Basic", CustomEncode.ToBase64String(CustomEncode.StringToByte(secretKey, CustomEncode.us_ascii)));

            if (ASPNETIdentityConfig.EnableStripe)
            {
                httpRequestMessage.Content = new FormUrlEncodedContent(
                    new Dictionary<string, string>
                    {
                        { "email", email },
                        { "source", token }
                    });
            }
            else if (ASPNETIdentityConfig.EnablePAYJP)
            {
                httpRequestMessage.Content = new FormUrlEncodedContent(
                    new Dictionary<string, string>
                    {
                        { "email", email },
                        { "card", token }
                    });
            }
            else
            {
                throw new NotSupportedException("Payment service is not enabled.");
            }

            httpRequestMessage.Content.Headers.ContentType = new MediaTypeHeaderValue("application/x-www-form-urlencoded");

            // HttpResponseMessage
            httpResponseMessage = await _webAPIHttpClient.SendAsync(httpRequestMessage);
            return (JObject)JsonConvert.DeserializeObject(await httpResponseMessage.Content.ReadAsStringAsync());
        }

        /// <summary>ChargeToOnlinePaymentCustomersAsync</summary>
        /// <param name="customerId">customerId</param>
        /// <param name="currency">currency(jpy, etc.)</param>
        /// <param name="amount">amount</param>
        /// <returns>JObject</returns>
        public async Task<JObject> ChargeToOnlinePaymentCustomersAsync(string customerId, string currency, string amount)
        {
            // URL
            string secretKey = "";
            Uri webApiEndpointUri = null;

            if (ASPNETIdentityConfig.EnableStripe)
            {
                webApiEndpointUri = new Uri("https://api.stripe.com/v1/charges");
                secretKey = ASPNETIdentityConfig.Stripe_SK;
            }
            else if (ASPNETIdentityConfig.EnablePAYJP)
            {
                webApiEndpointUri = new Uri("https://api.pay.jp/v1/charges");
                secretKey = ASPNETIdentityConfig.PAYJP_SK + ":"; // 「:」はUID:PWDの「:」
            }
            else
            {
                throw new NotSupportedException("Payment service is not enabled.");
            }

            // 通信用の変数
            HttpRequestMessage httpRequestMessage = null;
            HttpResponseMessage httpResponseMessage = null;

            // HttpRequestMessage (Method & RequestUri)
            httpRequestMessage = new HttpRequestMessage
            {
                Method = HttpMethod.Post,
                RequestUri = webApiEndpointUri
            };

            // HttpRequestMessage (Headers)
            httpRequestMessage.Headers.Authorization = new AuthenticationHeaderValue(
                "Basic", CustomEncode.ToBase64String(CustomEncode.StringToByte(secretKey, CustomEncode.us_ascii)));

            httpRequestMessage.Content = new FormUrlEncodedContent(
                new Dictionary<string, string>
                {
                    { "amount", amount },
                    { "currency", currency },
                    { "customer", customerId }
                });
            httpRequestMessage.Content.Headers.ContentType = new MediaTypeHeaderValue("application/x-www-form-urlencoded");

            // HttpResponseMessage
            httpResponseMessage = await _webAPIHttpClient.SendAsync(httpRequestMessage);
            return (JObject)JsonConvert.DeserializeObject(await httpResponseMessage.Content.ReadAsStringAsync());
        }

        #endregion

        #region ServerServiceWebAPI

        /// <summary>GetIndustryTypeFromServerService</summary>
        /// <returns>IndustryType</returns>
        public async Task<List<SelectListItem>> GetIndustryTypeFromServerService()
        {
            // URL
            Uri webApiEndpointUri = new Uri(GetConfigParameter.GetConfigValue("ServerServiceOfIndustryTypeURI")); 

            // 通信用の変数
            HttpRequestMessage httpRequestMessage = null;
            HttpResponseMessage httpResponseMessage = null;

            // HttpRequestMessage (Method & RequestUri)
            httpRequestMessage = new HttpRequestMessage
            {
                Method = HttpMethod.Post,
                RequestUri = webApiEndpointUri
            };
            
            httpRequestMessage.Content = new StringContent(
                JsonConvert.SerializeObject(new
                {
                    language = "ja"
                }),
                Encoding.UTF8, "application/json");

            //httpRequestMessage.Content.Headers.ContentType = new MediaTypeHeaderValue("application/json");

            // HttpResponseMessage
            httpResponseMessage = await _webAPIHttpClient.SendAsync(httpRequestMessage);
            Dictionary<string, string> dic = JsonConvert.DeserializeObject<Dictionary<string, string>>(await httpResponseMessage.Content.ReadAsStringAsync());
            List<SelectListItem> items = new List<SelectListItem>();
            items.Add(new SelectListItem { Value = null, Text = "" });

            foreach (string key in dic.Keys)
            {
                SelectListItem item = new SelectListItem();
                item.Value = key;
                item.Text = dic[key];
                items.Add(item);
            }

            return items;
        }

        /// <summary>GetCountryFromServerService</summary>
        /// <returns>Country</returns>
        public async Task<List<SelectListItem>> GetCountryFromServerService()
        {
            // URL
            Uri webApiEndpointUri = new Uri(GetConfigParameter.GetConfigValue("ServerServiceOfCountryURI"));

            // 通信用の変数
            HttpRequestMessage httpRequestMessage = null;
            HttpResponseMessage httpResponseMessage = null;

            // HttpRequestMessage (Method & RequestUri)
            httpRequestMessage = new HttpRequestMessage
            {
                Method = HttpMethod.Post,
                RequestUri = webApiEndpointUri
            };

            httpRequestMessage.Content = new StringContent(
                 JsonConvert.SerializeObject(new
                 {
                     language = "ja"
                 }),
                 Encoding.UTF8, "application/json");

            //httpRequestMessage.Content.Headers.ContentType = new MediaTypeHeaderValue("application/json");

            // HttpResponseMessage
            httpResponseMessage = await _webAPIHttpClient.SendAsync(httpRequestMessage);
            Dictionary<string, string> dic = JsonConvert.DeserializeObject<Dictionary<string, string>>(await httpResponseMessage.Content.ReadAsStringAsync());
            List<SelectListItem> items = new List<SelectListItem>();
            items.Add(new SelectListItem { Value = null, Text = "" });

            foreach (string key in dic.Keys)
            {
                SelectListItem item = new SelectListItem();
                item.Value = key;
                item.Text = dic[key];
                items.Add(item);
            }

            return items;
        }

        #endregion

        #endregion

        #endregion
    }
}