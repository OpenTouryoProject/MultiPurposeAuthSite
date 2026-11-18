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
//* クラス名        ：OutboundUrlPolicyTests
//* クラス日本語名  ：クライアントが登録した URL へ取りに行ってよいかの判定（#376）
//*
//* 作成者          ：玄人 幸道
//* 更新履歴        ：
//*
//*  日時        更新者            内容
//*  ----------  ----------------  -------------------------------------------------
//*  2026/11/18  玄人 幸道         新規作成（#376）
//**********************************************************************************

using System;
using System.Collections.Generic;
using System.Net;

using MultiPurposeAuthSite.Co;
using MultiPurposeAuthSite.Extensions.Sts;

using Xunit;

namespace MultiPurposeAuthSite.Tests.Unit.Sts
{
    /// <summary>
    /// `OutboundUrlPolicy`（名前解決は差し替える。E2E は内部のアドレスで断ることだけを測り、ここで組み合わせを測る）
    /// </summary>
    public class OutboundUrlPolicyTests
    {
        /// <summary>名前解決の差し替え：どのホストも、このアドレスに解決する</summary>
        /// <param name="address">アドレス</param>
        /// <returns>名前解決</returns>
        private static Func<string, IPAddress[]> To(string address)
        {
            return host => new IPAddress[] { IPAddress.Parse(address) };
        }

        /// <summary>公開のアドレスに解決される https は許す</summary>
        [Fact]
        [Basis("#376（設計：OutboundUrlPolicy の remarks）")]
        public void 公開のアドレスのhttpsは許す()
        {
            Assert.True(OutboundUrlPolicy.IsAllowed("https://rp.example.com/jwks", false, null, To("1.1.1.1")));
        }

        /// <summary>内部のアドレスに解決される https は断る</summary>
        /// <param name="address">アドレス</param>
        [Theory]
        [Basis("RFC 1918 §3 / RFC 4193 §3.1 / RFC 6890 §2.2.2 / RFC 5737 / RFC 3849 / RFC 6052 / RFC 3056 / #376")]
        [InlineData("10.1.2.3")]
        [InlineData("172.16.0.1")]
        [InlineData("172.31.255.255")]
        [InlineData("192.168.1.1")]
        [InlineData("169.254.169.254")]
        [InlineData("100.64.0.1")]
        [InlineData("0.0.0.0")]
        [InlineData("192.0.0.8")]
        [InlineData("198.18.0.1")]
        [InlineData("224.0.0.1")]
        [InlineData("255.255.255.255")]
        [InlineData("::")]
        [InlineData("fd00::1")]
        [InlineData("fe80::1")]
        [InlineData("ff02::1")]
        [InlineData("::ffff:10.0.0.1")]
        [InlineData("192.0.2.1")]
        [InlineData("198.51.100.1")]
        [InlineData("203.0.113.1")]
        [InlineData("::a00:1")]
        [InlineData("2001::1")]
        [InlineData("2001:db8::1")]
        [InlineData("64:ff9b::a9fe:a9fe")]
        [InlineData("64:ff9b:1::1")]
        [InlineData("2002:a00:1::1")]
        [InlineData("100::1")]
        public void 内部のアドレスは断る(string address)
        {
            Assert.False(OutboundUrlPolicy.IsAllowed("https://rp.example.com/jwks", false, null, To(address)));
        }

        /// <summary>プライベートの範囲の外（境界）は許す</summary>
        /// <param name="address">アドレス</param>
        [Theory]
        [Basis("RFC 1918 §3 / RFC 6052 / RFC 3056 / #376")]
        [InlineData("172.15.255.255")]
        [InlineData("172.32.0.0")]
        [InlineData("100.128.0.0")]
        [InlineData("2606:4700:4700::1111")]
        [InlineData("64:ff9b::808:808")]
        [InlineData("2002:808:808::1")]
        public void プライベートの範囲の外は許す(string address)
        {
            Assert.True(OutboundUrlPolicy.IsAllowed("https://rp.example.com/jwks", false, null, To(address)));
        }

        /// <summary>1 つでも内部のアドレスに解決されれば断る</summary>
        [Fact]
        [Basis("#376（設計：OutboundUrlPolicy.IsAllowed のコメント）")]
        public void 解決の結果に1つでも内部のアドレスが在れば断る()
        {
            Assert.False(OutboundUrlPolicy.IsAllowed("https://rp.example.com/jwks", false, null,
                host => new IPAddress[] { IPAddress.Parse("1.1.1.1"), IPAddress.Parse("10.0.0.1") }));
        }

        /// <summary>名前解決できなければ断る</summary>
        [Fact]
        [Basis("#376（設計：OutboundUrlPolicy.IsAllowed のコメント）")]
        public void 名前解決できなければ断る()
        {
            Assert.False(OutboundUrlPolicy.IsAllowed("https://rp.example.com/jwks", false, null, host => new IPAddress[0]));
            Assert.False(OutboundUrlPolicy.IsAllowed("https://rp.example.com/jwks", false, null,
                host => { throw new System.Net.Sockets.SocketException(); }));
        }

        /// <summary>ループバックは、既定では断り、設定で開ければ http も許す</summary>
        [Fact]
        [Basis("OIDC Registration 1.0 §2 / #376")]
        public void ループバックは設定で開けたときだけ許す()
        {
            Assert.False(OutboundUrlPolicy.IsAllowed("http://localhost:44305/jwks", false, null, To("127.0.0.1")));
            Assert.False(OutboundUrlPolicy.IsAllowed("https://localhost:44305/jwks", false, null, To("127.0.0.1")));
            Assert.False(OutboundUrlPolicy.IsAllowed("https://[::1]:44305/jwks", false, null, To("::1")));

            Assert.True(OutboundUrlPolicy.IsAllowed("http://localhost:44305/jwks", true, null, To("127.0.0.1")));
            Assert.True(OutboundUrlPolicy.IsAllowed("https://[::1]:44305/jwks", true, null, To("::1")));
        }

        /// <summary>ループバックでない http は、設定で開けても断る</summary>
        [Fact]
        [Basis("OIDC Registration 1.0 §2 / #376")]
        public void ループバックでないhttpは断る()
        {
            Assert.False(OutboundUrlPolicy.IsAllowed("http://rp.example.com/jwks", true, null, To("1.1.1.1")));
            Assert.False(OutboundUrlPolicy.IsAllowed("ftp://rp.example.com/jwks", true, null, To("1.1.1.1")));
            Assert.False(OutboundUrlPolicy.IsAllowed("not a url", true, null, To("1.1.1.1")));
        }

        /// <summary>ループバックを開けても、ほかの内部のアドレスは断る</summary>
        [Fact]
        [Basis("#376（設計：OutboundUrlPolicy の remarks）")]
        public void ループバックを開けてもプライベートは断る()
        {
            Assert.False(OutboundUrlPolicy.IsAllowed("https://rp.example.com/jwks", true, null, To("10.0.0.1")));
        }

        /// <summary>許可の一覧のホストは、内部のアドレスでも許す（スキームは外さない）</summary>
        [Fact]
        [Basis("#376（設計：Config.OutboundUrlAllowedHosts のコメント）")]
        public void 許可の一覧のホストは内部のアドレスでも許す()
        {
            string[] allowed = new string[] { "Localhost.Emobix.Co.Uk" };

            Assert.True(OutboundUrlPolicy.IsAllowed("https://localhost.emobix.co.uk:8443/jwks", false, allowed, To("172.18.0.5")));
            Assert.False(OutboundUrlPolicy.IsAllowed("https://other.example/jwks", false, allowed, To("172.18.0.5")));
            Assert.False(OutboundUrlPolicy.IsAllowed("http://localhost.emobix.co.uk:8443/jwks", false, allowed, To("172.18.0.5")));
        }

        /// <summary>IsAllowedAddress：ループバックは、設定で開けたときだけ（IPv4 を写した IPv6 も）</summary>
        [Fact]
        [Basis("#376（設計：OutboundUrlPolicy.IsAllowedAddress のコメント）")]
        public void IsAllowedAddressはループバックを設定で開けたときだけ許す()
        {
            Assert.False(OutboundUrlPolicy.IsAllowedAddress(IPAddress.Parse("127.0.0.1"), false));
            Assert.False(OutboundUrlPolicy.IsAllowedAddress(IPAddress.Parse("::1"), false));
            Assert.False(OutboundUrlPolicy.IsAllowedAddress(IPAddress.Parse("::ffff:127.0.0.1"), false));
            Assert.True(OutboundUrlPolicy.IsAllowedAddress(IPAddress.Parse("127.0.0.1"), true));
            Assert.True(OutboundUrlPolicy.IsAllowedAddress(IPAddress.Parse("::ffff:127.0.0.1"), true));
            Assert.False(OutboundUrlPolicy.IsAllowedAddress(IPAddress.Parse("10.0.0.1"), true));
            Assert.False(OutboundUrlPolicy.IsAllowedAddress(null, true));
        }

        /// <summary>設定：既定は閉じ、許可の一覧はカンマで分けて前後の空白を除く</summary>
        [Fact]
        [Basis("#376（設計：Config.OutboundUrlAllowLoopbackHttp・OutboundUrlAllowedHosts のコメント）")]
        public void 設定の既定は閉じ許可の一覧はカンマで分ける()
        {
            try
            {
                TestConfig.Set(new Dictionary<string, string>());

                Assert.False(Config.OutboundUrlAllowLoopbackHttp);
                Assert.Empty(Config.OutboundUrlAllowedHosts);

                TestConfig.Set(new Dictionary<string, string>()
                {
                    { "OutboundUrlAllowLoopbackHttp", "True" },
                    { "OutboundUrlAllowedHosts", " a.example , ,B.example " }
                });

                Assert.True(Config.OutboundUrlAllowLoopbackHttp);
                Assert.Equal(new string[] { "a.example", "B.example" }, Config.OutboundUrlAllowedHosts);

                TestConfig.Set(new Dictionary<string, string>()
                {
                    { "OutboundUrlAllowLoopbackHttp", "yes" }
                });

                Assert.False(Config.OutboundUrlAllowLoopbackHttp);
            }
            finally
            {
                TestConfig.Set(new Dictionary<string, string>());
            }
        }
    }
}
