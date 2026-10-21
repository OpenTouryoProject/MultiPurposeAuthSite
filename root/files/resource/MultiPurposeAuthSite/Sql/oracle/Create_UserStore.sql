-- For the information of using Oracle database and ODP.NET managed driver
-- for the user store of multi-purpose authentication site, see the following site.
--     Oracle11gXE + ODP.NET Managed Driver - マイクロソフト系技術情報 Wiki
--     https://techinfoofmicrosofttech.osscons.jp/index.php?Oracle11gXE%20%2B%20ODP.NET%20Managed%20Driver

--UserClaimsのIDENTITY

CREATE TABLE "Users"(              -- Users
    "Id" NVARCHAR2(38) NOT NULL,             -- PK, guid
    "UserName" NVARCHAR2(256) NOT NULL,
    "NormalizedUserName" NVARCHAR2(256) NOT NULL,
    "Email" NVARCHAR2(256) NULL,
    "NormalizedEmail" NVARCHAR2(256) NOT NULL,
    "EmailConfirmed" NUMBER(3) NOT NULL,
    "PasswordHash" NVARCHAR2(2000) NULL,
    "SecurityStamp" NVARCHAR2(2000) NULL,
    "PhoneNumber" NVARCHAR2(256) NULL,
    "PhoneNumberConfirmed" NUMBER(3) NOT NULL,
    "TwoFactorEnabled" NUMBER(3) NOT NULL,
    "LockoutEndDateUtc" TIMESTAMP NULL,
    "LockoutEnabled" NUMBER(3) NOT NULL,
    "AccessFailedCount" NUMBER(10) NOT NULL,
    "TotpAuthenticatorKey" NVARCHAR2(256) NULL,
    -- 追加の情報
    --   **ClientID は落とした**（#307 の段階 5-a）。
    --     **所有者は Saml2OAuth2Data.OwnerUserId が持つ**（1 利用者 n クライアント）。
    "UnstructuredData" NCLOB NULL,
    "DeviceToken" NVARCHAR2(2000) NULL,
    "CreatedDate" TIMESTAMP NOT NULL,
    "PasswordChangeDate" TIMESTAMP NOT NULL,
    CONSTRAINT "PK.Users" PRIMARY KEY ("Id")
);

CREATE TABLE "Roles"(              -- Roles
    "Id" NVARCHAR2(38) NOT NULL,             -- PK, guid
    "Name" NVARCHAR2(256) NOT NULL,
    "NormalizedName" NVARCHAR2(256) NOT NULL,
    CONSTRAINT "PK.Roles" PRIMARY KEY ("Id")
);

CREATE TABLE "UserRoles"(          -- 関連エンティティ (Users *--- UserRoles ---* Roles)
    "UserId" NVARCHAR2(38) NOT NULL,         -- PK, guid
    "RoleId" NVARCHAR2(38) NOT NULL,         -- PK, guid
    CONSTRAINT "PK.UserRoles" PRIMARY KEY ("UserId", "RoleId")
);

CREATE TABLE "UserLogins"(       -- Users ---* UserLogins
    "UserId" NVARCHAR2(38) NOT NULL,           -- PK
    -- **連携キーの幅**（#292。上流が n 件になると、長い値を踏む確率が上がる）。
    --   LoginProvider : **相手の `iss` / entityID**（URI なので Const.MaxLengthOfUri と同じ 512）
    --   ProviderKey   : **相手の `sub` / NameID**（`sub` は 255 文字以内、persistent な
    --                   NameID は 256 文字以内と決まっている）
    --   **PK は 3 列で (38 + 512 + 256) * 2 = 1612 バイト**になる。
    --   **SQL Server 2016 以降が前提**（索引キーは 1700 バイトまで。2014 以前は 900）。
    "LoginProvider" NVARCHAR2(512) NOT NULL,   -- *PK
    "ProviderKey" NVARCHAR2(256) NOT NULL,     -- *PK
    CONSTRAINT "PK.UserLogins" PRIMARY KEY ("UserId", "LoginProvider", "ProviderKey")
);

-- TS_UserClaimID.NEXTVAL
-- 注意 : CREATE SEQUENCE の行末にコメントを書くと、sqlplus が次の
--        CREATE TABLE を飲み込み、ORA-03405 で失敗する。コメントは独立行に置く。
CREATE SEQUENCE TS_UserClaimID;
CREATE TABLE "UserClaims"(       -- Users ---* UserClaims
    "Id" NUMBER(10) NOT NULL,                  -- PK (キー長に問題があるため"Id" "NUMBER(10)"を使用)
    "UserId" NVARCHAR2(38) NOT NULL,           -- *PK
    "Issuer" NVARCHAR2(128) NOT NULL,          -- *PK
    "ClaimType" NVARCHAR2(1024) NULL,
    "ClaimValue" NVARCHAR2(1024) NULL,
    CONSTRAINT "PK.UserClaims" PRIMARY KEY ("Id")
);

CREATE TABLE "TotpTokens"(       -- Users ---* TotpTokens
    "UserId" NVARCHAR2(38) NOT NULL,           -- PK
    "LoginProvider" NVARCHAR2(128) NOT NULL,   -- *PK
    "Name" NVARCHAR2(128) NOT NULL,            -- *PK
    "Value" NVARCHAR2(128) NULL,
    CONSTRAINT "PK.TotpTokens" PRIMARY KEY ("UserId", "LoginProvider", "Name")
);

CREATE TABLE "AuthenticationCodeDictionary"(
    "Key" NVARCHAR2(64) NOT NULL,            -- PK
    "Value" NVARCHAR2(2000) NOT NULL,        -- AuthenticationCode
    "CreatedDate" DATE NOT NULL,
    CONSTRAINT "PK.AuthCodeDictionary" PRIMARY KEY ("Key")
);

CREATE TABLE "RefreshTokenDictionary"(
    "Key" NVARCHAR2(256) NOT NULL,           -- PK
    "Value" NVARCHAR2(2000) NOT NULL,        -- RefreshToken
    "CreatedDate" DATE NOT NULL,
    "FamilyId" NVARCHAR2(64) NOT NULL,       -- 一族（同じ認可から派生したもの）の識別子（#188）
    "UsedDate" DATE,                         -- 使った時刻（NULL なら未使用）（#188）
    CONSTRAINT "PK.RefreshTokenDictionary" PRIMARY KEY ("Key")
);

-- sub（Subject Identifier）の対応表（#151 の段階 2）
--   **発行した sub を記録する。** 以後はここから引くので、
--   subject_types の既定や PPID の作り方を変えても、**発行済みの sub は動かない。**
--   Sector : いまは client_id。**sector_identifier_uri に対応したら、その解決結果が入る**
--            （列の意味は「Sector Identifier」。OIDC Core 8.1）
--   Sub    : uname のとき利用者名（最大 256）、public のとき UserId、pairwise のとき PPID
CREATE TABLE "SubjectIdentifier"(
    "Sector" NVARCHAR2(256) NOT NULL,        -- *PK, Sector Identifier（いまは client_id）
    "UserId" NVARCHAR2(38) NOT NULL,         -- *PK, guid
    "Sub" NVARCHAR2(256) NOT NULL,           -- 発行した sub
    "CreatedDate" DATE NOT NULL,
    CONSTRAINT "PK.SubjectIdentifier" PRIMARY KEY ("Sector", "UserId")
);

CREATE TABLE "ConsentGrant"(   -- 同意の記録（#272 の段階 2）
    "UserId" NVARCHAR2(38) NOT NULL,               -- *PK, guid
    "ClientID" NVARCHAR2(256) NOT NULL,         -- *PK
    "Scopes" NVARCHAR2(1024) NOT NULL,            -- 許可した scope（空白区切り。辞書順）
    "CreatedDate" DATE NOT NULL,
    "UpdatedDate" DATE NOT NULL,             -- scope を足したときに更新
    CONSTRAINT "PK.ConsentGrant" PRIMARY KEY ("UserId", "ClientID")
);

-- セッション × クライアントの台帳（#310 の段階 1。SQL Server 側の注と同じ）
CREATE TABLE "SessionClient"(
    "SessionId" NVARCHAR2(38) NOT NULL,         -- *PK, guid（OP のセッション）
    "ClientID" NVARCHAR2(256) NOT NULL,         -- *PK
    "Sid" NVARCHAR2(38) NOT NULL,               -- そのクライアントに名乗った sid（guid）
    "UserId" NVARCHAR2(38) NOT NULL,            -- Users.Id
    "CreatedDate" DATE NOT NULL,
    CONSTRAINT "PK.SessionClient" PRIMARY KEY ("SessionId", "ClientID")
);

CREATE TABLE "CustomizedConfirmation"(
    "UserId" NVARCHAR2(38) NOT NULL,         -- PK, guid
    "Value" NVARCHAR2(2000) NOT NULL,        -- Value
    "CreatedDate" DATE NOT NULL,
    CONSTRAINT "PK.CustomizedConfirmation" PRIMARY KEY ("UserId")
);

CREATE TABLE "Saml2OAuth2Data"(   -- 専用列に切り出した（#270）
    "ClientID" NVARCHAR2(256) NOT NULL,      -- PK
    "ClientSecret" NVARCHAR2(512) NULL,      -- 暗号文が入る（#297）
    "RedirectUriSaml" NVARCHAR2(512) NULL,           -- Const.MaxLengthOfUri
    "RedirectUriCode" NVARCHAR2(2000) NULL,          -- Const.MaxLengthOfUriList（空白区切りの列挙。#306）
    "RedirectUriToken" NVARCHAR2(2000) NULL,         -- Const.MaxLengthOfUriList（空白区切りの列挙。#306）
    "PostLogoutRedirectUri" NVARCHAR2(512) NULL,     -- Const.MaxLengthOfUri
    "WebOrigins" NCLOB NULL,                         -- 空白・カンマ区切りの列挙
    "JwkRsaPublickey" NCLOB NULL,
    "JwkECDsaPublickey" NCLOB NULL,
    "TlsClientAuthSubjectDn" NVARCHAR2(512) NULL,
    "SubjectTypes" NVARCHAR2(32) NULL,
    "IdTokenSignedResponseAlg" NVARCHAR2(16) NULL,
    "TokenEndpointAuthSigningAlg" NVARCHAR2(16) NULL,
    "RequestObjectSigningAlg" NVARCHAR2(16) NULL,
    "ClientMode" NVARCHAR2(32) NULL,                 -- oauth2_oidc_mode
    "RequirePkce" NUMBER(3) NOT NULL,                -- 真は -1（Users の bool 列と同じ）
    "ClientName" NVARCHAR2(256) NULL,                -- Users.UserName と同じ幅
    -- RFC 7591 §2 のクライアント メタデータ（#307 の段階 1）。末尾に足してある（ALTER … ADD で揃う）
    "Scopes" NVARCHAR2(2000) NULL,                   -- Const.MaxLengthOfScopeList（空白区切りの列挙）
    "GrantTypes" NVARCHAR2(256) NULL,                -- Const.MaxLengthOfTypeList（空白区切りの列挙）
    "ResponseTypes" NVARCHAR2(256) NULL,             -- Const.MaxLengthOfTypeList（空白区切り。要素内の空白は「+」）
    "JwksUri" NVARCHAR2(512) NULL,                   -- Const.MaxLengthOfUri（段階 1 では動的登録で受け付けない）
    "ClientUri" NVARCHAR2(512) NULL,                 -- Const.MaxLengthOfUri
    "LogoUri" NVARCHAR2(512) NULL,                   -- Const.MaxLengthOfUri
    "TosUri" NVARCHAR2(512) NULL,                    -- Const.MaxLengthOfUri
    "PolicyUri" NVARCHAR2(512) NULL,                 -- Const.MaxLengthOfUri
    "Contacts" NVARCHAR2(2000) NULL,                 -- Const.MaxLengthOfContacts（空白区切りの列挙）
    "SoftwareId" NVARCHAR2(256) NULL,                -- Const.MaxLengthOfSoftwareId
    "SoftwareVersion" NVARCHAR2(64) NULL,            -- Const.MaxLengthOfSoftwareVersion
    -- RFC 7592 の管理 API（#307 の段階 2）。末尾に足してある（ALTER … ADD で揃う）
    "RegistrationAccessToken" NVARCHAR2(128) NULL,   -- Const.MaxLengthOfTokenHash（ハッシュが入る）
    -- クライアント認証の方法（#307 の段階 3）。末尾に足してある（ALTER … ADD で揃う）
    "TokenEndpointAuthMethod" NVARCHAR2(32) NULL,    -- Const.MaxLengthOfAuthMethod（空なら秘密ベースの 2 つ）
    -- 所有者（#307 の段階 5-a）。末尾に足してある（ALTER … ADD で揃う）
    --   **Users."Id" を指す**（名前ではない）。**NULL 可。**
    "OwnerUserId" NVARCHAR2(38) NULL,
    -- ログアウトを伝える先（#310 の段階 2）。末尾に足してある（ALTER … ADD で揃う）
    --   **logout_token を POST する先**（Back-Channel Logout 1.0 §2.2）。**空なら伝えない。**
    "BackChannelLogoutUri" NVARCHAR2(512) NULL,      -- Const.MaxLengthOfUri
    CONSTRAINT "PK.Saml2OAuth2Data" PRIMARY KEY ("ClientID")
);

CREATE TABLE "IdFederationUpstreams"(   -- ID 連携の上流 IdP の登録（#292 の段階 2）
    -- **設定（appSettings の IdFederationUpstreams）と同じ項目**を持つ。
    --   **UpstreamKey が、設定の「鍵」に当たる**（Key は予約語なので避けた）。
    "UpstreamKey" NVARCHAR2(128) NOT NULL,   -- PK
    "DisplayName" NVARCHAR2(256) NULL,
    "Protocol" NVARCHAR2(16) NOT NULL,       -- oidc / saml2
    "Enabled" NUMBER(3) NOT NULL,            -- 真は -1（Users の bool 列と同じ）
    "Issuer" NVARCHAR2(256) NULL,
    "ClientID" NVARCHAR2(256) NULL,
    "ClientSecret" NVARCHAR2(512) NULL,      -- **暗号文が入る**（#297）
    "DiscoveryUrl" NVARCHAR2(512) NULL,
    "JwkSetUri" NVARCHAR2(512) NULL,
    "MetadataUrl" NVARCHAR2(512) NULL,
    "CerFilePath" NVARCHAR2(512) NULL,
    "AuthorizeEndpoint" NVARCHAR2(512) NULL,
    "TokenEndpoint" NVARCHAR2(512) NULL,
    "UserInfoEndpoint" NVARCHAR2(512) NULL,
    "SsoEndpoint" NVARCHAR2(512) NULL,
    -- **この上流へ送る AuthnRequest に署名する鍵**（#292 の段階 4-b）。空なら共通設定。
    "SigningPfxFilePath" NVARCHAR2(512) NULL,
    "SigningPfxPassword" NVARCHAR2(512) NULL,  -- 暗号文が入る（#297）
    CONSTRAINT "PK.IdFederationUpstreams" PRIMARY KEY ("UpstreamKey")
);

CREATE TABLE "SoftwareStatementIssuers"(   -- software_statement の発行者の登録（#308 の段階 1）
    -- **設定（appSettings の SoftwareStatementIssuers）と同じ項目**を持つ。
    --   **IssuerKey が、設定の「鍵」に当たる**（Key は予約語なので避けた）。
    --   **これは「ベンダ（発行者）の台帳」**で、**クライアントの登録ではない。**
    "IssuerKey" NVARCHAR2(128) NOT NULL,       -- PK
    "DisplayName" NVARCHAR2(256) NULL,
    "Enabled" NUMBER(3) NOT NULL,              -- 真は -1（Users の bool 列と同じ）
    "Issuer" NVARCHAR2(256) NULL,
    "CerFilePath" NVARCHAR2(512) NULL,         -- 空白かカンマ区切りで n 本（#307 の段階 6）
    "CerBody" NCLOB NULL,                      -- **本文**（PEM / Base64。公開鍵なので平文）
    "Alg" NVARCHAR2(16) NULL,
    "AllowedScope" NVARCHAR2(2000) NULL,
    "AllowedGrantTypes" NVARCHAR2(2000) NULL,
    CONSTRAINT "PK.SoftwareStatementIssuers" PRIMARY KEY ("IssuerKey")
);

CREATE TABLE "FIDO2Data"(
    "PublicKeyId" NVARCHAR2(256) NOT NULL,   -- PK
    "UserName" NVARCHAR2(256) NOT NULL,      -- Value
    "UnstructuredData" NCLOB NULL, -- FIDO2 Unstructured Data
    CONSTRAINT "PK.FIDO2Data" PRIMARY KEY ("PublicKeyId")
);

CREATE TABLE "DeviceAuthZData"(
    -- sqlserver の IDENTITY(1,1) / pstgrs の serial に相当する。
    -- **シーケンス＋NOT NULL にすると、INSERT 側が Id を渡さないため ORA-01400 になる**
    -- （provider の INSERT は Id を渡さない。UserClaims だけは明示しているので別）。
    "Id" NUMBER(10) GENERATED BY DEFAULT AS IDENTITY, -- PK (キー長に問題があるため"Id" "NUMBER(10)"を使用)
    "DeviceCode" NVARCHAR2(38) NOT NULL,         -- device_code(guid)
    "UserCode" NVARCHAR2(10) NOT NULL,           -- user_code(10文字以下)
    "AuthReqExp" NUMBER(19) NOT NULL,            -- UNIX時刻(long)
    "TempData" NVARCHAR2(256) NULL,              -- TempData
    "AuthZCode" NVARCHAR2(64) NULL,              -- AuthZCode
    "Result" NUMBER(3) NULL,                     -- Result of Verify
    -- **最後にポーリングされた時刻**（UNIX 時刻。#305 の段階 1）。
    --   **interval より短い間隔で来たら slow_down を返す**（RFC 8628 §3.5 / CIBA §11）。
    --   **NULL は「まだ 1 度も来ていない」**（初回は slow_down にしない）。
    "LastPolledAt" NUMBER(19) NULL,
    CONSTRAINT "PK.DeviceAuthZData" PRIMARY KEY ("Id")
);

CREATE TABLE "CibaData"(
    -- sqlserver の IDENTITY(1,1) / pstgrs の serial に相当する（上の DeviceAuthZData と同じ理由）。
    "Id" NUMBER(10) GENERATED BY DEFAULT AS IDENTITY, -- PK (キー長に問題があるため"Id" "NUMBER(10)"を使用)
    "ClientNotificationToken" NVARCHAR2(800) NOT NULL, -- 乱数(800)
    "AuthReqId" NVARCHAR2(800) NOT NULL,         -- 乱数(800)
    "AuthReqExp" NUMBER(19) NOT NULL,            -- UNIX時刻(long)
    "AuthZCode" NVARCHAR2(64) NOT NULL,          -- AuthZCode
    "UnstructuredData" NCLOB NULL,     -- binding_message, user_code, etc.
    "Result" NUMBER(3) NULL,                     -- Result of CIBA
    "UserId" NVARCHAR2(128) NULL,                -- 承認する利用者 (Users.Id)
    -- **最後にポーリングされた時刻**（UNIX 時刻。#305 の段階 1）。
    --   **interval より短い間隔で来たら slow_down を返す**（RFC 8628 §3.5 / CIBA §11）。
    --   **NULL は「まだ 1 度も来ていない」**（初回は slow_down にしない）。
    "LastPolledAt" NUMBER(19) NULL,
    CONSTRAINT "PK.CibaData" PRIMARY KEY ("Id")
);

-- **認証の失敗を数える**（#305 の段階 2）。
--   **何に対する失敗か**は鍵の接頭辞で分ける（`client:<client_id>` / `device_verify:<利用者>`）。
--   **一定回数で一定時間断る**（`AuthFailureMaxAttempts` / `AuthFailureLockoutSeconds`）。
--   **成功したら消す。** **表に持つ**ので、インスタンスを増やしても効く。
CREATE TABLE "AuthFailure"(
    "FailureKey" NVARCHAR2(256) NOT NULL,   -- PK
    "FailedCount" NUMBER(10) NOT NULL,      -- 連続して失敗した回数
    "LockoutEndAt" NUMBER(19) NULL,         -- 断る期限（UNIX時刻）
    CONSTRAINT "PK.AuthFailure" PRIMARY KEY ("FailureKey")
);

CREATE TABLE "OAuth2Revocation"(
    "Jti" NVARCHAR2(38) NOT NULL,            -- PK, guid
    "CreatedDate" DATE NOT NULL,
    CONSTRAINT "PK.OAuth2Revocation" PRIMARY KEY ("Jti")
);

CREATE TABLE "IssuedToken"(
    "Jti" NVARCHAR2(38) NOT NULL,                -- PK, guid
    "Value" NVARCHAR2(2000) NOT NULL,
    "ClientID" NVARCHAR2(38) NOT NULL,
    "Audience" NVARCHAR2(38) NOT NULL,
    "CreatedDate" DATE NOT NULL,
    CONSTRAINT "PK.IssuedToken" PRIMARY KEY ("Jti")
);

CREATE TABLE "RequestObject"(
    "Urn" NVARCHAR2(38) NOT NULL,                -- PK, guid（接頭辞付きのキーも入る。38文字に収まるものだけ。#243）
    "Value" NVARCHAR2(2000) NOT NULL,
    "CreatedDate" DATE NOT NULL,
    CONSTRAINT "PK.RequestObject" PRIMARY KEY ("Urn")
);

-- INDEX
--- UNIQUE INDEX
---- Users
ALTER TABLE "Users" ADD CONSTRAINT "UserNameIndex" UNIQUE ("UserName");
ALTER TABLE "Users" ADD CONSTRAINT "NormalizedUserNameIndex" UNIQUE ("NormalizedUserName");
ALTER TABLE "Users" ADD CONSTRAINT "NormalizedEmailIndex" UNIQUE ("NormalizedEmail");
---- Roles
ALTER TABLE "Roles" ADD CONSTRAINT "RoleNameIndex" UNIQUE ("Name");
ALTER TABLE "Roles" ADD CONSTRAINT "NormalizedNameIndex" UNIQUE ("NormalizedName");
---- DeviceAuthZData
ALTER TABLE "DeviceAuthZData" ADD CONSTRAINT "DeviceAuthZDeviceCodeIndex" UNIQUE ("DeviceCode");
ALTER TABLE "DeviceAuthZData" ADD CONSTRAINT "DeviceAuthZUserCodeIndex" UNIQUE ("UserCode");
---- CibaData
-- 下の 2 列は 800 文字だが、NVARCHAR2(800) への一意制約は通る（実機で確認済み）。
ALTER TABLE "CibaData" ADD CONSTRAINT "CibaClientNotificationTokenIndex" UNIQUE ("ClientNotificationToken");
ALTER TABLE "CibaData" ADD CONSTRAINT "CibaAuthReqIdIndex" UNIQUE ("AuthReqId");

--- INDEX
---- UserRoles
CREATE INDEX "IX_UserRoles.UserId" ON "UserRoles" ("UserId" ASC);
CREATE INDEX "IX_UserRoles.RoleId" ON "UserRoles" ("RoleId" ASC);
---- UserLogins
CREATE INDEX "IX_UserLogins.UserId" ON "UserLogins" ("UserId" ASC);
---- UserClaims
CREATE INDEX "IX_UserClaims.UserId" ON "UserClaims" ("UserId" ASC);
---- SubjectIdentifier
---- **逆引き（sub → 利用者）用。** 同じ Sector で 2 人が同じ sub を持ってはいけないので一意
CREATE UNIQUE INDEX "IX_SubjectIdentifier.Sector_Sub" ON "SubjectIdentifier" ("Sector" ASC, "Sub" ASC);
---- TotpTokens
CREATE INDEX "IX_TotpTokens.UserId" ON "TotpTokens" ("UserId" ASC);
---- SessionClient
---- **逆引き（sid → セッション）用。** sid は新しい guid なので一意（#310 の段階 1）
CREATE UNIQUE INDEX "IX_SessionClient.Sid" ON "SessionClient" ("Sid" ASC);
CREATE INDEX "IX_SessionClient.UserId" ON "SessionClient" ("UserId" ASC);

-- CONSTRAINT
---- UserRoles
ALTER TABLE "UserRoles" ADD CONSTRAINT "FK.UserRoles.Users_UserId" FOREIGN KEY("UserId") REFERENCES "Users" ("Id") ON DELETE CASCADE;
-- 使用中のRoleは削除できない（ON DELETE を付けない）。
-- 注意 : 文の行末にコメントを書くと、sqlplus が次の文を飲み込み、ORA-03405 で失敗する。
ALTER TABLE "UserRoles" ADD CONSTRAINT "FK.UserRoles.Roles_RoleId" FOREIGN KEY("RoleId") REFERENCES "Roles" ("Id");
---- UserLogins
ALTER TABLE "UserLogins" ADD CONSTRAINT "FK.UserLogins.Users_UserId" FOREIGN KEY("UserId") REFERENCES "Users" ("Id") ON DELETE CASCADE;
---- UserClaims
ALTER TABLE "UserClaims" ADD CONSTRAINT "FK.UserClaims.Users_UserId" FOREIGN KEY("UserId") REFERENCES "Users" ("Id") ON DELETE CASCADE;
---- TotpTokens
ALTER TABLE "TotpTokens" ADD CONSTRAINT "FK.TotpTokens.Users_UserId" FOREIGN KEY("UserId") REFERENCES "Users" ("Id") ON DELETE CASCADE;
---- Saml2OAuth2Data
-- **所有者は OwnerUserId で結ぶ**（#307 の段階 5-a。SQL Server 側の注と同じ）。
ALTER TABLE "Saml2OAuth2Data" ADD CONSTRAINT "FK.Saml2OAuth2Data.Users_OwnerUserId" FOREIGN KEY("OwnerUserId") REFERENCES "Users" ("Id") ON DELETE CASCADE;
---- FIDO2Data
ALTER TABLE "FIDO2Data" ADD CONSTRAINT "FK.FIDO2Data.Users_UserName" FOREIGN KEY("UserName") REFERENCES "Users" ("UserName") ON DELETE CASCADE;
---- ConsentGrant
ALTER TABLE "ConsentGrant" ADD CONSTRAINT "FK.ConsentGrant.Users_UserId" FOREIGN KEY("UserId") REFERENCES "Users" ("Id") ON DELETE CASCADE;
---- SubjectIdentifier
ALTER TABLE "SubjectIdentifier" ADD CONSTRAINT "FK.SubjectIdentifier.Users_UserId" FOREIGN KEY("UserId") REFERENCES "Users" ("Id") ON DELETE CASCADE;
---- SessionClient
ALTER TABLE "SessionClient" ADD CONSTRAINT "FK.SessionClient.Users_UserId" FOREIGN KEY("UserId") REFERENCES "Users" ("Id") ON DELETE CASCADE;