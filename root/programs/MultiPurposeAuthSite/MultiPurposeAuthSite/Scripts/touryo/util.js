//**********************************************************************************
//* Copyright (C) 2017 Hitachi Solutions,Ltd.
//**********************************************************************************

// Apache License
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

//**********************************************************************************
//* ファイル名        ：util.js
//* ファイル日本語名  ：util処理
//*
//* 作成日時        ：－
//* 作成者          ：－
//* 更新履歴        ：－
//*
//*  日時        更新者            内容
//*  ----------  ----------------  -------------------------------------------------
//*  2019/03/0?  西野 大介         新規作成
//**********************************************************************************

// ---------------------------------------------------------------
// ランダムな文字列を生成する
// ---------------------------------------------------------------
// 引数    len
// 戻り値  Random String
// ---------------------------------------------------------------
function Fx_GetRandomString(len) {
    //使用文字の定義
    var str = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!#$%&=~/*-+";

    //ランダムな文字列の生成
    var result = "";
    for (var i = 0; i < len; i++) {
        result += str.charAt(Math.floor(Math.random() * str.length));
    }
    return result;
}

// ---------------------------------------------------------------
// To Base64Url
// ---------------------------------------------------------------
// 引数    Array or ArrayBuffer
// 戻り値  Base64Url String
// ---------------------------------------------------------------
function Fx_CoerceToBase64Url(thing) {
    // Array or ArrayBuffer to Uint8Array
    // - Array to Uint8Array
    if (Array.isArray(thing)) {
        thing = Uint8Array.from(thing);
    }
    // - ArrayBuffer to Uint8Array
    if (thing instanceof ArrayBuffer) {
        thing = new Uint8Array(thing);
    }

    // Uint8Array to base64
    if (thing instanceof Uint8Array) {
        var str = "";
        var len = thing.byteLength;

        for (var i = 0; i < len; i++) {
            str += String.fromCharCode(thing[i]);
        }
        thing = window.btoa(str);
    }

    // Check type of thing.
    if (typeof thing !== "string") {
        throw new Error("could not coerce to string");
    }

    // base64 to base64url.
    // NOTE: "=" at the end of challenge is optional, strip it off here
    thing = thing.replace(/\+/g, "-").replace(/\//g, "_").replace(/=*$/g, "");

    return thing;
}

// ---------------------------------------------------------------
// To ArrayBuffer
// ---------------------------------------------------------------
// 引数    base64url or base64 String
// 戻り値  ArrayBuffer
// ---------------------------------------------------------------
function Fx_CoerceToArrayBuffer(thing) {
    if (typeof thing === "string") {
        // base64url or base64 String to Uint8Array
        // - base64url to base64
        thing = thing.replace(/-/g, "+").replace(/_/g, "/");
        // - base64 to Uint8Array
        var str = window.atob(thing);
        var bytes = new Uint8Array(str.length);
        for (var i = 0; i < str.length; i++) {
            bytes[i] = str.charCodeAt(i);
        }
        thing = bytes;
    }
    else {
        // Array to Uint8Array
        if (Array.isArray(thing)) {
            thing = new Uint8Array(thing);
        }
    }

    // Uint8Array to ArrayBuffer
    if (thing instanceof Uint8Array) {
        thing = thing.buffer;
    }

    // Check type of thing.
    if (!(thing instanceof ArrayBuffer)) {
        throw new TypeError("could not coerce to ArrayBuffer");
    }

    return thing;
}

// ---------------------------------------------------------------
// Debug出力
// ---------------------------------------------------------------
// 引数    testLabel: ラベル, object: オブジェクト
// 戻り値  －
// ---------------------------------------------------------------
function Fx_DebugOutput(testLabel, object) {
    console.log(testLabel);
    if (object) {
        console.log(object);
        console.log(JSON.stringify(object));
    }
}