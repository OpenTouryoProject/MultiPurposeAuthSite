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
//* クラス名        ：StartupHook / AcceptAnyClientCertificate
//* クラス日本語名  ：E2E 専用 : net10.0 版に、テストのときだけクライアント証明書を受け付けさせる（#226）
//*
//* 作成日時        ：－
//* 作成者          ：－
//* 更新履歴        ：－
//*
//*  日時        更新者            内容
//*  ----------  ----------------  -------------------------------------------------
//*  2026/09/22  玄人 幸道         新規（#226 : mTLS の経路を E2E で確かめる）
//**********************************************************************************

using System;
using System.IO;
using System.Runtime.Loader;

using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Server.Kestrel.Https;

[assembly: HostingStartup(typeof(MultiPurposeAuthSite.Tests.MtlsTestHook.AcceptAnyClientCertificate))]

/// <summary>
/// DOTNET_STARTUP_HOOKS の入口（名前空間なし・この名前であることが決まり）
/// </summary>
/// <remarks>
/// **アプリのコードを変えずに、テストのときだけ Kestrel の HTTPS の既定を変える**（#226）。
///   1. test.ps1 -Launch が、起動するサイトにだけ DOTNET_STARTUP_HOOKS でこの DLL を渡す
///   2. ここで、自分を名前で解決できるようにし、ASPNETCORE_HOSTINGSTARTUPASSEMBLIES に自分を足す
///   3. AcceptAnyClientCertificate（IHostingStartup）が、Kestrel の設定を足す
///
/// **Development 以外では何もしない。** 発行元を問わずに証明書を受け付けるので、
/// 本番の構成で読まれることがあってはならない（アプリは Subject だけで照合するため）。
/// </remarks>
internal class StartupHook
{
    /// <summary>Main の前に呼ばれる</summary>
    public static void Initialize()
    {
        if (!string.Equals(Environment.GetEnvironmentVariable("ASPNETCORE_ENVIRONMENT"),
            "Development", StringComparison.OrdinalIgnoreCase))
        {
            Console.Error.WriteLine("[MtlsTestHook] ASPNETCORE_ENVIRONMENT が Development ではないので、何もしない。");
            return;
        }

        string self = typeof(StartupHook).Assembly.Location;
        string name = Path.GetFileNameWithoutExtension(self);

        // IHostingStartup は名前で読まれる。アプリの deps.json に無いので、ここで解決させる。
        AssemblyLoadContext.Default.Resolving += (context, assemblyName) =>
            assemblyName.Name == name ? context.LoadFromAssemblyPath(self) : null;

        const string key = "ASPNETCORE_HOSTINGSTARTUPASSEMBLIES";
        string current = Environment.GetEnvironmentVariable(key);
        Environment.SetEnvironmentVariable(key,
            string.IsNullOrEmpty(current) ? name : current + ";" + name);

        Console.WriteLine("[MtlsTestHook] クライアント証明書を受け付ける（E2E 専用。#226）");
    }
}

namespace MultiPurposeAuthSite.Tests.MtlsTestHook
{
    /// <summary>Kestrel に、発行元を問わずクライアント証明書を受け付けさせる</summary>
    /// <remarks>
    /// ・ClientCertificateMode.AllowCertificate : 要求はするが、無くても通す（他のテストに影響しない）
    /// ・AllowAnyClientCertificate : 自己署名の証明書を通す（既定ではチェーンの検証で TLS が切れる）
    /// ・CheckCertificateRevocation = false : 自己署名の証明書には失効の情報が無い
    /// </remarks>
    public class AcceptAnyClientCertificate : IHostingStartup
    {
        /// <summary>Configure</summary>
        /// <param name="builder">IWebHostBuilder</param>
        public void Configure(IWebHostBuilder builder)
        {
            builder.ConfigureKestrel(options => options.ConfigureHttpsDefaults(https =>
            {
                https.ClientCertificateMode = ClientCertificateMode.AllowCertificate;
                https.AllowAnyClientCertificate();
                https.CheckCertificateRevocation = false;
            }));
        }
    }
}
