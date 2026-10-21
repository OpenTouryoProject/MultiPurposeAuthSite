
-- TABLE
CREATE TABLE Users(                -- Users
    Id varchar(38) NOT NULL,                 -- PK, guid
    UserName varchar(256) NOT NULL,
    NormalizedUserName varchar(256) NOT NULL,
    Email varchar(256) NULL,
    NormalizedEmail varchar(256) NOT NULL,
    EmailConfirmed boolean NOT NULL,
    PasswordHash varchar(2000) NULL,
    SecurityStamp varchar(2000) NULL,
    PhoneNumber varchar(256) NULL,
    PhoneNumberConfirmed boolean NOT NULL,
    TwoFactorEnabled boolean NOT NULL,
    LockoutEndDateUtc timestamp NULL,
    LockoutEnabled boolean NOT NULL,
    AccessFailedCount integer NOT NULL,
    TotpAuthenticatorKey varchar(256) NULL,
    -- 追加の情報
    --   **ClientID は落とした**（#307 の段階 5-a）。
    --     **所有者は Saml2OAuth2Data.OwnerUserId が持つ**（1 利用者 n クライアント）。
    UnstructuredData text NULL,
    DeviceToken varchar(2000) NULL,
    CreatedDate timestamp NOT NULL,
    PasswordChangeDate timestamp NOT NULL,
    CONSTRAINT PK_Users PRIMARY KEY (Id)
);

CREATE TABLE Roles(                -- Roles
    Id varchar(38) NOT NULL,                 -- PK, guid
    Name varchar(256) NOT NULL,
    NormalizedName varchar(256) NOT NULL,
    CONSTRAINT PK_Roles PRIMARY KEY (Id)
);

CREATE TABLE UserRoles(            -- 関連エンティティ (Users *--- UserRoles ---* Roles)
    UserId varchar(38) NOT NULL,             -- PK, guid
    RoleId varchar(38) NOT NULL,             -- PK, guid
    CONSTRAINT PK_UserRoles PRIMARY KEY (
        UserId,
        RoleId)
);

CREATE TABLE UserLogins(       -- Users ---* UserLogins
    UserId varchar(38) NOT NULL,             -- PK
    -- **連携キーの幅**（#292。上流が n 件になると、長い値を踏む確率が上がる）。
    --   LoginProvider : **相手の `iss` / entityID**（URI なので Const.MaxLengthOfUri と同じ 512）
    --   ProviderKey   : **相手の `sub` / NameID**（`sub` は 255 文字以内、persistent な
    --                   NameID は 256 文字以内と決まっている）
    --   **PK は 3 列で (38 + 512 + 256) * 2 = 1612 バイト**になる。
    --   **SQL Server 2016 以降が前提**（索引キーは 1700 バイトまで。2014 以前は 900）。
    LoginProvider varchar(512) NOT NULL,     -- *PK
    ProviderKey varchar(256) NOT NULL,       -- *PK
    CONSTRAINT PK_UserLogins PRIMARY KEY (
        UserId,
        LoginProvider,
        ProviderKey)
);

CREATE TABLE UserClaims(       -- Users ---* UserClaims
    Id serial NOT NULL,                      -- PK (キー長に問題があるためId intを使用)
    UserId varchar(38) NOT NULL,             -- *PK
    Issuer varchar(128) NOT NULL,            -- *PK
    ClaimType varchar(1024) NULL,
    ClaimValue varchar(1024) NULL,
    CONSTRAINT PK_UserClaims PRIMARY KEY (Id)
);

CREATE TABLE TotpTokens(       -- Users ---* TotpTokens
    UserId varchar(38) NOT NULL,             -- PK
    LoginProvider varchar(128) NOT NULL,     -- *PK
    Name varchar(128) NOT NULL,              -- *PK
    Value varchar(128) NULL,
    CONSTRAINT PK_TotpTokens PRIMARY KEY (
        UserId,
        LoginProvider,
        Name)
);

CREATE TABLE AuthenticationCodeDictionary(
    Key varchar(64) NOT NULL,                -- PK
    Value varchar(2000) NOT NULL,            -- AuthenticationCode
    CreatedDate timestamp NOT NULL,
    CONSTRAINT PK_AuthenticationCodeDictionary PRIMARY KEY (Key)
);

CREATE TABLE RefreshTokenDictionary(
    Key varchar(256) NOT NULL,               -- PK
    Value varchar(2000) NOT NULL,            -- RefreshToken
    CreatedDate timestamp NOT NULL,
    FamilyId varchar(64) NOT NULL,           -- 一族（同じ認可から派生したもの）の識別子（#188）
    UsedDate timestamp,                      -- 使った時刻（NULL なら未使用）（#188）
    CONSTRAINT PK_RefreshTokenDictionary PRIMARY KEY (Key)
);

-- sub（Subject Identifier）の対応表（#151 の段階 2）
--   **発行した sub を記録する。** 以後はここから引くので、
--   subject_types の既定や PPID の作り方を変えても、**発行済みの sub は動かない。**
--   Sector : いまは client_id。**sector_identifier_uri に対応したら、その解決結果が入る**
--            （列の意味は「Sector Identifier」。OIDC Core 8.1）
--   Sub    : uname のとき利用者名（最大 256）、public のとき UserId、pairwise のとき PPID
CREATE TABLE SubjectIdentifier(
    Sector varchar(256) NOT NULL,            -- *PK, Sector Identifier（いまは client_id）
    UserId varchar(38) NOT NULL,             -- *PK, guid
    Sub varchar(256) NOT NULL,               -- 発行した sub
    CreatedDate timestamp NOT NULL,
    CONSTRAINT PK_SubjectIdentifier PRIMARY KEY (Sector, UserId)
);

CREATE TABLE ConsentGrant(   -- 同意の記録（#272 の段階 2）
    UserId varchar(38) NOT NULL,                   -- *PK, guid
    ClientID varchar(256) NOT NULL,             -- *PK
    Scopes varchar(1024) NOT NULL,                -- 許可した scope（空白区切り。辞書順）
    CreatedDate timestamp NOT NULL,
    UpdatedDate timestamp NOT NULL,          -- scope を足したときに更新
    CONSTRAINT PK_ConsentGrant PRIMARY KEY (UserId, ClientID)
);

-- セッション × クライアントの台帳（#310 の段階 1。SQL Server 側の注と同じ）
CREATE TABLE SessionClient(
    SessionId varchar(38) NOT NULL,                -- *PK, guid（OP のセッション）
    ClientID varchar(256) NOT NULL,             -- *PK
    Sid varchar(38) NOT NULL,                   -- そのクライアントに名乗った sid（guid）
    UserId varchar(38) NOT NULL,                -- Users.Id
    CreatedDate timestamp NOT NULL,
    CONSTRAINT PK_SessionClient PRIMARY KEY (SessionId, ClientID)
);

CREATE TABLE CustomizedConfirmation(
    UserId varchar(38) NOT NULL,             -- PK, guid
    Value varchar(2000) NOT NULL,            -- Value
    CreatedDate timestamp NOT NULL,
    CONSTRAINT PK_CustomizedConfirmation PRIMARY KEY (UserId)
);

CREATE TABLE Saml2OAuth2Data(   -- 専用列に切り出した（#270）
    ClientID varchar(256) NOT NULL,          -- PK
    ClientSecret varchar(512) NULL,          -- 暗号文が入る（#297）
    RedirectUriSaml varchar(512) NULL,               -- Const.MaxLengthOfUri
    RedirectUriCode varchar(2000) NULL,              -- Const.MaxLengthOfUriList（空白区切りの列挙。#306）
    RedirectUriToken varchar(2000) NULL,             -- Const.MaxLengthOfUriList（空白区切りの列挙。#306）
    PostLogoutRedirectUri varchar(512) NULL,         -- Const.MaxLengthOfUri
    WebOrigins text NULL,                            -- 空白・カンマ区切りの列挙
    JwkRsaPublickey text NULL,
    JwkECDsaPublickey text NULL,
    TlsClientAuthSubjectDn varchar(512) NULL,
    SubjectTypes varchar(32) NULL,
    IdTokenSignedResponseAlg varchar(16) NULL,
    TokenEndpointAuthSigningAlg varchar(16) NULL,
    RequestObjectSigningAlg varchar(16) NULL,
    ClientMode varchar(32) NULL,                     -- oauth2_oidc_mode
    RequirePkce boolean NOT NULL,
    ClientName varchar(256) NULL,                    -- Users.UserName と同じ幅
    -- RFC 7591 §2 のクライアント メタデータ（#307 の段階 1）。末尾に足してある（ALTER … ADD で揃う）
    Scopes varchar(2000) NULL,                       -- Const.MaxLengthOfScopeList（空白区切りの列挙）
    GrantTypes varchar(256) NULL,                    -- Const.MaxLengthOfTypeList（空白区切りの列挙）
    ResponseTypes varchar(256) NULL,                 -- Const.MaxLengthOfTypeList（空白区切り。要素内の空白は「+」）
    JwksUri varchar(512) NULL,                       -- Const.MaxLengthOfUri（段階 1 では動的登録で受け付けない）
    ClientUri varchar(512) NULL,                     -- Const.MaxLengthOfUri
    LogoUri varchar(512) NULL,                       -- Const.MaxLengthOfUri
    TosUri varchar(512) NULL,                        -- Const.MaxLengthOfUri
    PolicyUri varchar(512) NULL,                     -- Const.MaxLengthOfUri
    Contacts varchar(2000) NULL,                     -- Const.MaxLengthOfContacts（空白区切りの列挙）
    SoftwareId varchar(256) NULL,                    -- Const.MaxLengthOfSoftwareId
    SoftwareVersion varchar(64) NULL,                -- Const.MaxLengthOfSoftwareVersion
    -- RFC 7592 の管理 API（#307 の段階 2）。末尾に足してある（ALTER … ADD で揃う）
    RegistrationAccessToken varchar(128) NULL,       -- Const.MaxLengthOfTokenHash（ハッシュが入る）
    -- クライアント認証の方法（#307 の段階 3）。末尾に足してある（ALTER … ADD で揃う）
    TokenEndpointAuthMethod varchar(32) NULL,        -- Const.MaxLengthOfAuthMethod（空なら秘密ベースの 2 つ）
    -- 所有者（#307 の段階 5-a）。末尾に足してある（ALTER … ADD で揃う）
    --   **Users.Id を指す**（名前ではない）。**NULL 可。**
    --   **引用符なしなので、識別子は小文字に畳まれる**（ownerluserid ではなく owneruserid）。
    OwnerUserId varchar(38) NULL,
    -- ログアウトを伝える先（#310 の段階 2）。末尾に足してある（ALTER … ADD で揃う）
    --   **logout_token を POST する先**（Back-Channel Logout 1.0 §2.2）。**空なら伝えない。**
    --   **引用符なしなので、識別子は小文字に畳まれる**（backchannellogouturi）。
    BackChannelLogoutUri varchar(512) NULL,
    -- ブラウザ経由で伝える先（#310 の段階 3）。末尾に足してある（ALTER … ADD で揃う）
    --   **iframe で開く URL**（Front-Channel Logout 1.0 §2）。**空なら伝えない。**
    --   **引用符なしなので、識別子は小文字に畳まれる**（frontchannellogouturi）。
    FrontChannelLogoutUri varchar(512) NULL,
    CONSTRAINT PK_Saml2OAuth2Data PRIMARY KEY (ClientID)
);

CREATE TABLE IdFederationUpstreams(   -- ID 連携の上流 IdP の登録（#292 の段階 2）
    -- **設定（appSettings の IdFederationUpstreams）と同じ項目**を持つ。
    --   **UpstreamKey が、設定の「鍵」に当たる**（Key は予約語なので避けた）。
    --   **引用符なしで書いているので、識別子は小文字に畳まれる**（DataProvider が小文字で引く）。
    UpstreamKey varchar(128) NOT NULL,       -- PK
    DisplayName varchar(256) NULL,
    Protocol varchar(16) NOT NULL,           -- oidc / saml2
    Enabled boolean NOT NULL,
    Issuer varchar(256) NULL,
    ClientID varchar(256) NULL,
    ClientSecret varchar(512) NULL,          -- **暗号文が入る**（#297）
    DiscoveryUrl varchar(512) NULL,
    JwkSetUri varchar(512) NULL,
    MetadataUrl varchar(512) NULL,
    CerFilePath varchar(512) NULL,
    AuthorizeEndpoint varchar(512) NULL,
    TokenEndpoint varchar(512) NULL,
    UserInfoEndpoint varchar(512) NULL,
    SsoEndpoint varchar(512) NULL,
    -- **この上流へ送る AuthnRequest に署名する鍵**（#292 の段階 4-b）。空なら共通設定。
    SigningPfxFilePath varchar(512) NULL,
    SigningPfxPassword varchar(512) NULL,    -- 暗号文が入る（#297）
    CONSTRAINT PK_IdFederationUpstreams PRIMARY KEY (UpstreamKey)
);

CREATE TABLE SoftwareStatementIssuers(   -- software_statement の発行者の登録（#308 の段階 1）
    -- **設定（appSettings の SoftwareStatementIssuers）と同じ項目**を持つ。
    --   **IssuerKey が、設定の「鍵」に当たる**（Key は予約語なので避けた）。
    --   **引用符なしで書いているので、識別子は小文字に畳まれる**（Provider が小文字で引く）。
    --   **これは「ベンダ（発行者）の台帳」**で、**クライアントの登録ではない。**
    IssuerKey varchar(128) NOT NULL,         -- PK
    DisplayName varchar(256) NULL,
    Enabled boolean NOT NULL,
    Issuer varchar(256) NULL,
    CerFilePath varchar(512) NULL,           -- 空白かカンマ区切りで n 本（#307 の段階 6）
    CerBody text NULL,                       -- **本文**（PEM / Base64。公開鍵なので平文）
    Alg varchar(16) NULL,
    AllowedScope varchar(2000) NULL,
    AllowedGrantTypes varchar(2000) NULL,
    CONSTRAINT PK_SoftwareStatementIssuers PRIMARY KEY (IssuerKey)
);

CREATE TABLE FIDO2Data(
    PublicKeyId varchar(256) NOT NULL,       -- PK
    UserName varchar(256) NOT NULL,          -- Value
    UnstructuredData text NULL,     -- FIDO2 Unstructured Data
    CONSTRAINT PK_FIDO2Data PRIMARY KEY (PublicKeyId)
);

CREATE TABLE DeviceAuthZData(
    Id serial NOT NULL,                               -- PK (キー長に問題があるためId intを使用)
    DeviceCode varchar(38) NOT NULL,                  -- device_code(guid)
    UserCode varchar(10) NOT NULL,                    -- user_code(10文字以下)
    AuthReqExp bigint NOT NULL,                       -- UNIX時刻(long)
    TempData varchar(256) NULL,                       -- TempData
    AuthZCode varchar(64) NULL,                       -- AuthZCode
    Result boolean NULL,                              -- Result of Verify
    -- **最後にポーリングされた時刻**（UNIX 時刻。#305 の段階 1）。
    --   **interval より短い間隔で来たら slow_down を返す**（RFC 8628 §3.5 / CIBA §11）。
    --   **NULL は「まだ 1 度も来ていない」**（初回は slow_down にしない）。
    LastPolledAt bigint NULL,
    CONSTRAINT PK_DeviceAuthZData PRIMARY KEY (Id)
);

CREATE TABLE CibaData(
    Id serial NOT NULL,                               -- PK (キー長に問題があるためId intを使用)
    ClientNotificationToken varchar(800) NOT NULL,    -- 乱数(800)
    AuthReqId varchar(800) NOT NULL,                  -- 乱数(800)
    AuthReqExp bigint NOT NULL,                       -- UNIX時刻(long)
    AuthZCode varchar(64) NOT NULL,                   -- AuthZCode
    UnstructuredData text NULL,              -- binding_message, user_code, etc.
    Result boolean NULL,                              -- Result of CIBA
    UserId varchar(128) NULL,                         -- 承認する利用者 (Users.Id)
    -- **最後にポーリングされた時刻**（UNIX 時刻。#305 の段階 1）。
    --   **interval より短い間隔で来たら slow_down を返す**（RFC 8628 §3.5 / CIBA §11）。
    --   **NULL は「まだ 1 度も来ていない」**（初回は slow_down にしない）。
    LastPolledAt bigint NULL,
    CONSTRAINT PK_CibaData PRIMARY KEY (Id)
);

-- **認証の失敗を数える**（#305 の段階 2）。
--   **何に対する失敗か**は鍵の接頭辞で分ける（`client:<client_id>` / `device_verify:<利用者>`）。
--   **一定回数で一定時間断る**（`AuthFailureMaxAttempts` / `AuthFailureLockoutSeconds`）。
--   **成功したら消す。** **表に持つ**ので、インスタンスを増やしても効く。
CREATE TABLE AuthFailure(
    FailureKey varchar(256) NOT NULL,                 -- PK
    FailedCount int NOT NULL,                         -- 連続して失敗した回数
    LockoutEndAt bigint NULL,                         -- 断る期限（UNIX時刻）
    CONSTRAINT PK_AuthFailure PRIMARY KEY (FailureKey)
);

CREATE TABLE OAuth2Revocation(
    Jti varchar(38) NOT NULL,                -- PK, guid
    CreatedDate timestamp NOT NULL,
    CONSTRAINT PK_OAuth2Revocation PRIMARY KEY (Jti)
);

CREATE TABLE IssuedToken(
    Jti varchar(38) NOT NULL,                -- PK, guid
    Value varchar(2000) NOT NULL,
    ClientID varchar(38) NOT NULL,
    Audience varchar(38) NOT NULL,
    CreatedDate timestamp NOT NULL,
    CONSTRAINT PK_IssuedToken PRIMARY KEY (Jti)
);

CREATE TABLE RequestObject(
    Urn varchar(38) NOT NULL,                -- PK, guid（接頭辞付きのキーも入る。38文字に収まるものだけ。#243）
    Value varchar(2000) NOT NULL,
    CreatedDate timestamp NOT NULL,
    CONSTRAINT PK_RequestObject PRIMARY KEY (Urn)
);

-- 使った DPoP の証明の台帳（#311 の段階 3。SQL Server 側の注と同じ）
CREATE TABLE DPoPProof(
    ProofId varchar(64) NOT NULL,            -- PK, 証明の指紋（43文字）
    CreatedDate timestamp NOT NULL,
    CONSTRAINT PK_DPoPProof PRIMARY KEY (ProofId)
);

-- INDEX
---- Users
CREATE UNIQUE INDEX UserNameIndex ON Users (UserName);
CREATE UNIQUE INDEX NormalizedUserNameIndex ON Users (NormalizedUserName);
CREATE UNIQUE INDEX NormalizedEmailNameIndex ON Users (NormalizedEmail);
---- Roles
CREATE UNIQUE INDEX RoleNameIndex ON Roles (Name);
CREATE UNIQUE INDEX NormalizedNameIndex ON Roles (NormalizedName);
---- DeviceAuthZData
CREATE UNIQUE INDEX DeviceAuthZDeviceCodeIndex ON DeviceAuthZData (DeviceCode);
CREATE UNIQUE INDEX DeviceAuthZUserCodeIndex ON DeviceAuthZData (UserCode);
---- CibaData
CREATE UNIQUE INDEX CibaClientNotificationTokenIndex ON CibaData (ClientNotificationToken);
CREATE UNIQUE INDEX CibaAuthReqIdIndex ON CibaData (AuthReqId);
---- UserRoles
CREATE INDEX IX_UserRoles_UserId ON UserRoles (UserId);
CREATE INDEX IX_UserRoles_RoleId ON UserRoles (RoleId);
---- UserLogins
CREATE INDEX IX_UserLogins_UserId ON UserLogins (UserId);
---- UserClaims
CREATE INDEX IX_UserClaims_UserId ON UserClaims (UserId);
---- SubjectIdentifier
---- **逆引き（sub → 利用者）用。** 同じ Sector で 2 人が同じ sub を持ってはいけないので一意
CREATE UNIQUE INDEX IX_SubjectIdentifier_Sector_Sub ON SubjectIdentifier (Sector, Sub);
---- TotpTokens
CREATE INDEX IX_TotpTokens_UserId ON TotpTokens (UserId);
---- SessionClient
---- **逆引き（sid → セッション）用。** sid は新しい guid なので一意（#310 の段階 1）
CREATE UNIQUE INDEX IX_SessionClient_Sid ON SessionClient (Sid);
CREATE INDEX IX_SessionClient_UserId ON SessionClient (UserId);

-- CONSTRAINT
---- UserRoles
ALTER TABLE UserRoles ADD CONSTRAINT FK_UserRoles_Users_UserId FOREIGN KEY(UserId) REFERENCES Users (Id) ON DELETE CASCADE;
ALTER TABLE UserRoles ADD CONSTRAINT FK_UserRoles_Roles_RoleId FOREIGN KEY(RoleId) REFERENCES Roles (Id) ON DELETE NO ACTION; -- 使用中のRoleは削除できない。
---- UserLogins
ALTER TABLE UserLogins ADD CONSTRAINT FK_UserLogins_Users_UserId FOREIGN KEY(UserId) REFERENCES Users (Id) ON DELETE CASCADE;
---- UserClaims
ALTER TABLE UserClaims ADD CONSTRAINT FK_UserClaims_Users_UserId FOREIGN KEY(UserId) REFERENCES Users (Id) ON DELETE CASCADE;
---- TotpTokens
ALTER TABLE TotpTokens ADD CONSTRAINT FK_TotpTokens_Users_UserId FOREIGN KEY(UserId) REFERENCES Users (Id) ON DELETE CASCADE;
---- Saml2OAuth2Data
-- **所有者は OwnerUserId で結ぶ**（#307 の段階 5-a。SQL Server 側の注と同じ）。
ALTER TABLE Saml2OAuth2Data ADD CONSTRAINT FK_Saml2OAuth2Data_Users_OwnerUserId FOREIGN KEY(OwnerUserId) REFERENCES Users (Id) ON DELETE CASCADE;
---- FIDO2Data
ALTER TABLE FIDO2Data ADD CONSTRAINT FK_FIDO2Data_Users_UserName FOREIGN KEY(UserName) REFERENCES Users (UserName) ON DELETE CASCADE;
---- ConsentGrant
ALTER TABLE ConsentGrant ADD CONSTRAINT FK_ConsentGrant_Users_UserId FOREIGN KEY(UserId) REFERENCES Users (Id) ON DELETE CASCADE;
---- SubjectIdentifier
ALTER TABLE SubjectIdentifier ADD CONSTRAINT FK_SubjectIdentifier_Users_UserId FOREIGN KEY(UserId) REFERENCES Users (Id) ON DELETE CASCADE;
---- SessionClient
ALTER TABLE SessionClient ADD CONSTRAINT FK_SessionClient_Users_UserId FOREIGN KEY(UserId) REFERENCES Users (Id) ON DELETE CASCADE;
