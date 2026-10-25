# ClientRegistrationProvider の設計メモ

対象：`CommonLibrary/Extensions/Sts/ClientRegistrationProvider.cs`
（動的クライアント登録。RFC 7591 の登録、RFC 7592 の管理）

**今の仕様は、ソースの冒頭の `/* */` と remarks を見ること。**
ここには、段階ごとの決定と経緯を残す。

## 段階の一覧

| 段階 | 内容 |
|---|---|
| #307 の段階 1 | 登録（RFC 7591 の `POST`）。器は既存の `Saml2OAuth2Data` で、RFC 7591 §2 の列を足した |
| #307 の段階 2 | 管理 API（RFC 7592 の `GET` / `PUT` / `DELETE`）と `registration_access_token` |
| #307 の段階 3 | `jwks` / `tls_client_auth_subject_dn` / `token_endpoint_auth_method` / `token_endpoint_auth_signing_alg` を受ける |
| #307 の段階 4 | `software_statement` を検証して受ける |
| #307 の段階 5-a | 所有者を `Saml2OAuth2Data.OwnerUserId` へ移し、1 利用者 n クライアントにした |
| #307 の段階 5-b | `client_credentials` のトークンでも登録できる（所有者は、認証したクライアントの所有者） |
| #309 の段階 1 | `jwks_uri` を受け付ける |
| #309 の段階 2 | `software_statement` が主張した `jwks_uri` も温める |
| #310 の段階 2 / 3 | `backchannel_logout_uri` / `frontchannel_logout_uri` を動的登録で変えさせない |
| #314 | 受け付ける `response_types` を `CmnEndpoints.SupportedResponseTypes` に寄せた |
| #294 | 汎用部品を Open棟梁 の実装へ置き換え、文字列リテラルを定数にした。`auth` も動的登録で付けさせない |

## #307 の段階 1（登録）

- **認可は `client_registration` scope のアクセス トークン**とした
- **自分と同じ強さの scope（`client_registration`）を、動的登録で付けさせない。** 付けられると、権限を際限なく増やせる
- **`scope` の列が空なら、絞らない**と決めた（`PUT` で `scope` を省くと絞りが消えるのは、この決めによる）
- **登録種別は `normal`。** FAPI の登録は、鍵や証明書の登録を要するので、動的登録では作らない
- **`response_types` は、要素の中の空白を `+` にして保管する**（空白は区切りと区別が付かない）
- **1 利用者 1 件に絞っていた**（2 件目は `403` ＋ `access_denied`）。
  これは仕様の要求ではなく、**器の都合**だった。所有者が `Users.ClientID`（1 枠・NOT NULL・一意）だったためである → 段階 5-a で外した
- **この段階で作った登録には `registration_access_token` が無い。** そのため、管理 API では触れない（管理画面から直す）

## #307 の段階 2（管理 API）

- **`client_secret` は `GET` / `PUT` で返さない**（RFC 7592 §3 では任意）。トークンが漏れても、秘密は漏らさない
- **`PUT` では秘密を作り直さない**
- **`grant_types` / `response_types` は、応答では列から読む。** `POST` / `GET` / `PUT` で同じ形にするためである
- **`DELETE` の後、発行済みのアクセス トークンは使えなくなる**（登録が無くなると `Helper.HasClient` が false になる）
- **`Users.ClientID` の後始末で悩んだ。**
  NOT NULL ＋ 一意索引 ＋ `Saml2OAuth2Data` からの外部キーがあり、空にすると `sql` で `DELETE` が 500 になった（`mem` では出なかった）
  → 段階 5-a で列ごと落とした
- **所有者は `ClientName`（利用者名）で引き直していた** → 名前は変わり得るので、段階 5-a で Id（`OwnerUserId`）にした

## #307 の段階 3（クライアント認証の方法）

- **`client_secret` は、方法に関わらず発行する。** デバイス フローのように、秘密しか使えない口が在るためである
- **`PUT` で、鍵と DN は「省いたら消える」にしない。** 管理画面から入れた鍵を、`PUT` で消してはならないためである
  （`private_key_jwt` / `tls_client_auth` を明記するなら、材料も毎回送る。材料が無ければ `400`）
- **デバイス フロー × `private_key_jwt` は断る。** RFC 8628 の口は `client_assertion` を読んでいないので、永久に認証できない
- **既知でない `token_endpoint_auth_method` は拒否する**（#224 と同じ方針。「一番厳しいものに倒す」はしない）

## #307 の段階 4（`software_statement`）

- **statement は保管しない。応答にも返さない**（§3.2.1 で任意）。そのため、この段階で列は増えていない（既存の配備に `ALTER` が要らない）
- **`RequireSoftwareStatement` は `PUT` にも効かせる。**
  効かせないと、`PUT` で statement を省いて「主張されていた値」を自分の値に書き換えられる（statement は保管しないので、省かれたことしか分からない）

## #307 の段階 5-a（所有者を `OwnerUserId` へ）

- **所有者を `Saml2OAuth2Data.OwnerUserId`（`Users.Id`）へ移した。**
  以前は `user.ClientID = client_id; CmnUserStore.Update(user);` で、利用者の行を書き換えていた。いまは利用者の行に触らない
- **1 利用者 n クライアントにした。上限は設けていない**（設定キーも増やしていない）。
  「条件分岐を増やさない」という決めである。洪水はレート制限で受ける（#305 の段階 3。口の名前 `register`）
- **`POST` を upsert にはしない。** `client_secret` を作り直すか据え置くかの判断が常について回り、間違えると既存の RP が止まる。更新は `PUT` で行う
- **`Users.ClientID` を落とした**ので、`DELETE` での後始末の悩み（段階 2）は消えた

## #307 の段階 5-b（`client_credentials` でも登録できる）

- **段階 1 〜 5-a では、利用者の居ないトークンを `401` に倒していた。**
  所有者を AT の `sub` からしか引けなかったためで、ROPC（利用者のパスワード）を開けないと動的登録が使えなかった
- **利用者の居ないトークンでは、認証したクライアントの所有者を、作る登録の所有者にする**ようにした
- **見分けは `sub` でする**（`client_credentials` のトークンは、`sub` にクライアント名が入る）。
  「利用者が消えたトークン」を、クライアントの所有者に付け替えないためである

## #309 の段階 1（`jwks_uri`）

- **要求の経路（`/token` など）では取りに行かない。** クライアント認証の鎖が同期で、そこで待つと net48 で止まる（#309 の起票）。
  取りに行くのは、登録の口（`WarmUpJwksUriAsync`）と背景（`RemoteJwkSetStore.RefillInBackground`）だけである
- **読めない `jwks_uri` は、登録のその場で断る**（決め (B)）。後から黙って `private_key_jwt` が通らなくなるより、その場で分かる方が良い
- **`jwks` と `jwks_uri` は排他**（RFC 7591 §2）。`PUT` で持ち越して両方にならないように、要求が片方を入れたら、もう片方は持ち越さない

## #309 の段階 2（statement の `jwks_uri` も温める）

- **段階 1 では、statement が主張した `jwks_uri` を温めず、`Validate` で断っていた。**
  「署名を検証する前に、本文の外の URL へ出て行かない」という理由だった
- **行き先の範囲が変わらないので、過剰だった。** 同じ呼び出し元は、本文の `jwks_uri` に任意の URL を書ける（そちらは段階 1 で既に取りに行く）

## #310 の段階 2 / 3（ログアウトの通知先）

- **`backchannel_logout_uri` / `frontchannel_logout_uri` は、動的登録では変えさせない。**
  RFC 7591 のメタデータではないので、画面と設定ファイルからだけ入れる（`PUT` では現行を持ち越す）

## #294（整理）

- **`auth`（同意画面を出さない）も、動的登録では付けさせない。**
  自分で登録できると、同意画面を飛ばすかをクライアントが決めることになる（`ANALYSIS-IdP.md` の C-27）
- **ソースのコメントから段階情報を外し、ここへ移した**
