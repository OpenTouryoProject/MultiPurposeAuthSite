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
//* クラス名        ：ProxySelectionTests
//* クラス日本語名  ：要求先の分類ごとのプロキシの組（#406）
//*
//* 作成者          ：玄人 幸道
//* 更新履歴        ：
//*
//*  日時        更新者            内容
//*  ----------  ----------------  -------------------------------------------------
//*  2026/11/18  玄人 幸道         新規作成（#406）
//**********************************************************************************

using System;
using System.Collections.Generic;
using System.Net;

using MultiPurposeAuthSite.Network;

using Xunit;

namespace MultiPurposeAuthSite.Tests.Unit.Sts
{
    /// <summary>
    /// `CreateProxy` の分類ごとの組（E2E はプロキシを通せないので、組の選び方をここで測る）
    /// </summary>
    public class ProxySelectionTests
    {
        /// <summary>設定の値を、大文字小文字を問わず組に直す。無い・読めない値は既定</summary>
        /// <param name="value">設定の値</param>
        /// <param name="expected">期待する組</param>
        [Theory]
        [Basis("#406（設計：CreateProxy.ParseProxyType のコメント）")]
        [InlineData("Internet", EnumProxyType.Internet)]
        [InlineData("intranet", EnumProxyType.Intranet)]
        [InlineData(" DEBUG ", EnumProxyType.Debug)]
        [InlineData("None", EnumProxyType.None)]
        [InlineData("", EnumProxyType.Intranet)]
        [InlineData(null, EnumProxyType.Intranet)]
        [InlineData("proxy", EnumProxyType.Intranet)]
        [InlineData("7", EnumProxyType.Intranet)]
        public void 設定の値を組に直し読めなければ既定(string value, EnumProxyType expected)
        {
            Assert.Equal(expected, CreateProxy.ParseProxyType(value, EnumProxyType.Intranet));
        }

        /// <summary>None だけが UseProxy を false にする（OS の既定のプロキシも使わない）</summary>
        [Fact]
        [Basis("#406（設計：CreateProxy.UsesProxy のコメント）")]
        public void NoneだけがOSの既定のプロキシも使わない()
        {
            Assert.False(CreateProxy.UsesProxy(EnumProxyType.None));
            Assert.True(CreateProxy.UsesProxy(EnumProxyType.Internet));
            Assert.True(CreateProxy.UsesProxy(EnumProxyType.Intranet));
            Assert.True(CreateProxy.UsesProxy(EnumProxyType.Debug));
        }

        /// <summary>分類ごとの既定（外部ログインは Internet、ほかは Intranet）と、設定での切り替え</summary>
        [Fact]
        [Basis("#406（設計：CreateProxy.For* のコメント。既定は以前の振る舞い）")]
        public void 分類ごとの既定と設定での切り替え()
        {
            try
            {
                TestConfig.Set(new Dictionary<string, string>());

                Assert.Equal(EnumProxyType.Intranet, CreateProxy.ForIdFederation);
                Assert.Equal(EnumProxyType.Intranet, CreateProxy.ForClientRegisteredUrls);
                Assert.Equal(EnumProxyType.Intranet, CreateProxy.ForBackChannelLogout);
                Assert.Equal(EnumProxyType.Internet, CreateProxy.ForExternalLogin);

                TestConfig.Set(new Dictionary<string, string>()
                {
                    { "ProxyForIdFederation", "None" },
                    { "ProxyForClientRegisteredUrls", "Internet" },
                    { "ProxyForBackChannelLogout", "Debug" },
                    { "ProxyForExternalLogin", "Intranet" }
                });

                Assert.Equal(EnumProxyType.None, CreateProxy.ForIdFederation);
                Assert.Equal(EnumProxyType.Internet, CreateProxy.ForClientRegisteredUrls);
                Assert.Equal(EnumProxyType.Debug, CreateProxy.ForBackChannelLogout);
                Assert.Equal(EnumProxyType.Intranet, CreateProxy.ForExternalLogin);
            }
            finally
            {
                TestConfig.Set(new Dictionary<string, string>());
            }
        }

        /// <summary>組の Use*Proxy が true なら、その組の URL のプロキシを作る。None・false なら null</summary>
        [Fact]
        [Basis("#406（設計：CreateProxy.GetProxy のコメント）")]
        public void 組のプロキシを作りNoneや使わない組はnull()
        {
            try
            {
                TestConfig.Set(new Dictionary<string, string>()
                {
                    { "UseInternetProxy", "true" },
                    { "InternetProxyURL", "http://proxy-internet.example:8080" },
                    { "UseIntranetProxy", "false" },
                    { "UseDebugProxy", "false" }
                });

                IWebProxy internet = CreateProxy.GetProxy(EnumProxyType.Internet);

                Assert.NotNull(internet);
                Assert.Equal(new Uri("http://proxy-internet.example:8080/"),
                    internet.GetProxy(new Uri("https://rp.example/")));

                Assert.Null(CreateProxy.GetProxy(EnumProxyType.Intranet));
                Assert.Null(CreateProxy.GetProxy(EnumProxyType.None));
            }
            finally
            {
                TestConfig.Set(new Dictionary<string, string>());
            }
        }
    }
}
