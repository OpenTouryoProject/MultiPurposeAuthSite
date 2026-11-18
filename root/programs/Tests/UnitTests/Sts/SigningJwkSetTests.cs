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
//* クラス名        ：SigningJwkSetTests
//* クラス日本語名  ：自分の署名鍵の表を読む（#407）
//*
//* 作成者          ：玄人 幸道
//* 更新履歴        ：
//*
//*  日時        更新者            内容
//*  ----------  ----------------  -------------------------------------------------
//*  2026/11/18  玄人 幸道         新規作成（#407）
//**********************************************************************************

using System;
using System.Collections.Generic;
using System.IO;

using MultiPurposeAuthSite.Util.Sts;

using Xunit;

namespace MultiPurposeAuthSite.Tests.Unit.Sts
{
    /// <summary>
    /// `SigningJwkSet.Reader`（読む関数を差し替え、ファイルの置き換えと重なったときを作る。E2E では狙って重ねられない）
    /// </summary>
    public class SigningJwkSetTests
    {
        /// <summary>JWK Set（kid は k1）</summary>
        private const string SetK1 = "{\"keys\":[{\"kty\":\"oct\",\"kid\":\"k1\",\"k\":\"AAAA\"}]}";

        /// <summary>JWK Set（kid は k2）</summary>
        private const string SetK2 = "{\"keys\":[{\"kty\":\"oct\",\"kid\":\"k2\",\"k\":\"BBBB\"}]}";

        /// <summary>読めないとき、やり直して読めれば、その中身を返す</summary>
        [Fact]
        [Basis("#407（設計：SigningJwkSet の remarks）")]
        public void 読めなくてもやり直して読めればその中身()
        {
            int calls = 0;
            SigningJwkSet.Reader reader = new SigningJwkSet.Reader(() =>
            {
                calls++;

                if (calls < SigningJwkSet.MaxAttempts)
                {
                    throw new IOException("being used by another process");
                }

                return Tuple.Create(SetK1, "\"e1\"");
            }, TimeSpan.Zero);

            Assert.Equal(SetK1, reader.Get(out string etag));
            Assert.Equal("\"e1\"", etag);
            Assert.Equal(SigningJwkSet.MaxAttempts, calls);
        }

        /// <summary>やり直しても読めなければ、前に読めた中身で続ける</summary>
        [Fact]
        [Basis("#407（設計：SigningJwkSet の remarks）")]
        public void やり直しても読めなければ前に読めた中身で続ける()
        {
            bool broken = false;
            int brokenCalls = 0;
            SigningJwkSet.Reader reader = new SigningJwkSet.Reader(() =>
            {
                if (broken)
                {
                    brokenCalls++;
                    throw new UnauthorizedAccessException();
                }

                return Tuple.Create(SetK1, "\"e1\"");
            }, TimeSpan.Zero);

            Assert.NotNull(reader.GetJwkObject("k1"));

            broken = true;

            //  **前の中身で続けるときはログを書く**（ログは設定を読むので、設定を入れておく）。
            try
            {
                TestConfig.Set(new Dictionary<string, string>());

                Assert.Equal(SetK1, reader.Get(out string etag));
                Assert.Equal("\"e1\"", etag);
                Assert.Equal(SigningJwkSet.MaxAttempts, brokenCalls);
                Assert.NotNull(reader.GetJwkObject("k1"));
            }
            finally
            {
                TestConfig.Set(new Dictionary<string, string>());
            }
        }

        /// <summary>一度も読めていなければ、例外のまま（設定の誤りを黙って通さない）</summary>
        [Fact]
        [Basis("#407（設計：SigningJwkSet の remarks）")]
        public void 一度も読めていなければ例外のまま()
        {
            SigningJwkSet.Reader reader = new SigningJwkSet.Reader(
                () => { throw new IOException("being used by another process"); }, TimeSpan.Zero);

            Assert.Throws<IOException>(() => reader.Get(out string etag));
        }

        /// <summary>中身が変われば、新しい表から引く（無い kid は null）</summary>
        [Fact]
        [Basis("#407（設計：SigningJwkSet の remarks。解析は ETag が変わったときだけ）")]
        public void 中身が変われば新しい表から引く()
        {
            string content = SetK1;
            string etag = "\"e1\"";
            SigningJwkSet.Reader reader = new SigningJwkSet.Reader(() => Tuple.Create(content, etag), TimeSpan.Zero);

            Assert.NotNull(reader.GetJwkObject("k1"));
            Assert.Null(reader.GetJwkObject("k2"));

            content = SetK2;
            etag = "\"e2\"";

            Assert.Null(reader.GetJwkObject("k1"));
            Assert.NotNull(reader.GetJwkObject("k2"));
        }

        /// <summary>壊れた中身（直接上書きの書きかけ）は、読めないと同じに扱い、前の中身で続ける。壊れた中身は覚えない</summary>
        [Fact]
        [Basis("#407（設計：SigningJwkSet.Reader.Read の remarks。別モデルのレビューの指摘）")]
        public void 壊れた中身は前の中身で続け覚えない()
        {
            string content = SetK1;
            string etag = "\"e1\"";
            SigningJwkSet.Reader reader = new SigningJwkSet.Reader(() => Tuple.Create(content, etag), TimeSpan.Zero);

            Assert.NotNull(reader.GetJwkObject("k1"));

            content = "{\"keys\":[";
            etag = "\"broken\"";

            try
            {
                TestConfig.Set(new Dictionary<string, string>());

                Assert.Equal(SetK1, reader.Get(out string returned));
                Assert.Equal("\"e1\"", returned);
                Assert.NotNull(reader.GetJwkObject("k1"));
            }
            finally
            {
                TestConfig.Set(new Dictionary<string, string>());
            }

            content = SetK2;
            etag = "\"e2\"";

            Assert.NotNull(reader.GetJwkObject("k2"));
        }

        /// <summary>最後に読めてから FallbackLifetime（1 分）を過ぎたら、前の中身に落とさず例外にする</summary>
        [Fact]
        [Basis("#407（設計：SigningJwkSet.FallbackLifetime の remarks。別モデルのレビューの指摘）")]
        public void 最後に読めてから1分を過ぎたら前の中身に落とさない()
        {
            bool broken = false;
            DateTime now = new DateTime(2026, 11, 18, 0, 0, 0, DateTimeKind.Utc);
            SigningJwkSet.Reader reader = new SigningJwkSet.Reader(() =>
            {
                if (broken)
                {
                    throw new IOException("being used by another process");
                }

                return Tuple.Create(SetK1, "\"e1\"");
            }, TimeSpan.Zero, () => now);

            Assert.NotNull(reader.GetJwkObject("k1"));

            broken = true;

            try
            {
                TestConfig.Set(new Dictionary<string, string>());

                now = now + SigningJwkSet.FallbackLifetime;
                Assert.Equal(SetK1, reader.Get(out string within));

                now = now + TimeSpan.FromSeconds(1);
                Assert.Throws<IOException>(() => reader.Get(out string beyond));
            }
            finally
            {
                TestConfig.Set(new Dictionary<string, string>());
            }
        }

        /// <summary>ファイルが無ければ、やり直さず、前の中身にも落とさない（意図して撤去したなら、古い表を出し続けない）</summary>
        [Fact]
        [Basis("#407（設計：SigningJwkSet.Reader.Read の remarks。別モデルのレビューの指摘）")]
        public void ファイルが無ければ前の中身に落とさない()
        {
            bool removed = false;
            int removedCalls = 0;
            SigningJwkSet.Reader reader = new SigningJwkSet.Reader(() =>
            {
                if (removed)
                {
                    removedCalls++;
                    throw new FileNotFoundException();
                }

                return Tuple.Create(SetK1, "\"e1\"");
            }, TimeSpan.Zero);

            Assert.NotNull(reader.GetJwkObject("k1"));

            removed = true;

            Assert.Throws<FileNotFoundException>(() => reader.Get(out string etag));
            Assert.Equal(1, removedCalls);
        }

        /// <summary>読めない・壊れている・無い以外の例外は、やり直さず、前の中身にも落とさない</summary>
        [Fact]
        [Basis("#407（設計：SigningJwkSet の remarks。やり直すのは IOException・UnauthorizedAccessException だけ）")]
        public void 読めない以外の例外はやり直さない()
        {
            int calls = 0;
            SigningJwkSet.Reader reader = new SigningJwkSet.Reader(() =>
            {
                calls++;
                throw new InvalidOperationException();
            }, TimeSpan.Zero);

            Assert.Throws<InvalidOperationException>(() => reader.Get(out string etag));
            Assert.Equal(1, calls);
        }
    }
}
