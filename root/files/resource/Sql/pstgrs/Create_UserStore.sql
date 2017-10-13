
-- TABLE
CREATE TABLE Users(                -- Users
    Id varchar(38) NOT NULL,                 -- PK, guid
    UserName varchar(256) NOT NULL,
    Email varchar(256) NULL,
    EmailConfirmed boolean NOT NULL,
    PasswordHash varchar(2000) NULL,
    SecurityStamp varchar(2000) NULL,
    PhoneNumber varchar(256) NULL,
    PhoneNumberConfirmed boolean NOT NULL,
    TwoFactorEnabled boolean NOT NULL,
    LockoutEndDateUtc timestamp NULL,
    LockoutEnabled boolean NOT NULL,
    AccessFailedCount integer NOT NULL,
    -- 追加の情報
    ParentId varchar(38) NULL,               -- guid
    ClientID varchar(256) NOT NULL,
    PaymentInformation varchar(256) NULL,
    UnstructuredData varchar(2000) NULL,
    FIDO2PublicKey varchar(2000) NULL,
    CreatedDate timestamp NOT NULL,
    CONSTRAINT PK_Users PRIMARY KEY (Id)
);

CREATE TABLE Roles(                -- Roles
    Id varchar(38) NOT NULL,                 -- PK, guid
    Name varchar(256) NOT NULL,
    ParentId varchar(38) NULL,               -- guid
    CONSTRAINT PK_Roles PRIMARY KEY (Id)
);

CREATE TABLE UserRoles(            -- 関連エンティティ (Users *--- UserRoles ---* Roles)
    UserId varchar(38) NOT NULL,             -- PK, guid
    RoleId varchar(38) NOT NULL,             -- PK, guid
    CONSTRAINT PK_UserRoles PRIMARY KEY (
        UserId,
        RoleId)
);

CREATE TABLE UserLogins(           -- Users ---* UserLogins
    UserId varchar(38) NOT NULL,             -- PK, guid
    LoginProvider varchar(128) NOT NULL,     -- PK
    ProviderKey varchar(128) NOT NULL,       -- PK
    CONSTRAINT PK_UserLogins PRIMARY KEY (
        UserId,
        LoginProvider,
        ProviderKey)
);

CREATE TABLE UserClaims(           -- Users ---* UserClaims
    Id serial NOT NULL,                      -- PK (キー長に問題があるためId intを使用)
    UserId varchar(38) NOT NULL,                -- *PK, guid
    Issuer varchar(128) NOT NULL,               -- *PK(LoginProvider) *PK(実質的に複合主キー)
    ClaimType varchar(1024) NULL,
    ClaimValue varchar(1024) NULL,
    CONSTRAINT PK_UserClaims PRIMARY KEY (Id)
);

CREATE TABLE AuthenticationCodeDictionary(
    Key varchar(64) NOT NULL,                -- PK
    Value varchar(1024) NOT NULL,            -- AuthenticationCode
    CreatedDate timestamp NOT NULL,
    CONSTRAINT PK_AuthenticationCodeDictionary PRIMARY KEY (Key)
);

CREATE TABLE RefreshTokenDictionary(
    Key varchar(256) NOT NULL,               -- PK
    Value bytea NOT NULL,                    -- RefreshToken
    CreatedDate timestamp NOT NULL,
    CONSTRAINT PK_RefreshTokenDictionary PRIMARY KEY (Key)
);

CREATE TABLE CustomizedConfirmation(
    UserId varchar(38) NOT NULL,             -- PK, guid
    Value varchar(2000) NOT NULL,            -- Value
    CreatedDate timestamp NOT NULL,
    CONSTRAINT PK_CustomizedConfirmation PRIMARY KEY (UserId)
);

CREATE TABLE OAuth2Data(           -- OAuth2Data
    ClientID varchar(256) NOT NULL,          -- PK
    UnstructuredData varchar(2000) NULL,     -- OAuth2 Unstructured Data
    CONSTRAINT PK_OAuth2Data PRIMARY KEY (ClientID)
);

-- INDEX
---- Users
CREATE UNIQUE INDEX UserNameIndex ON Users (UserName);
CREATE UNIQUE INDEX ClientIDIndex ON Users (ClientID);
---- Roles
CREATE UNIQUE INDEX RoleNameIndex ON Roles (Name);
---- UserRoles
CREATE INDEX IX_UserRoles_UserId ON UserRoles (UserId);
CREATE INDEX IX_UserRoles_RoleId ON UserRoles (RoleId);
---- UserLogins
CREATE INDEX IX_UserLogins_UserId ON UserLogins (UserId);
---- UserClaims
CREATE INDEX IX_UserClaims_UserId ON UserClaims (UserId);

-- CONSTRAINT
---- UserRoles
ALTER TABLE UserRoles ADD CONSTRAINT FK_UserRoles_Users_UserId FOREIGN KEY(UserId) REFERENCES Users (Id) ON DELETE CASCADE;
ALTER TABLE UserRoles ADD CONSTRAINT FK_UserRoles_Roles_RoleId FOREIGN KEY(RoleId) REFERENCES Roles (Id) ON DELETE NO ACTION; -- 使用中のRoleは削除できない。
---- UserLogins
ALTER TABLE UserLogins ADD CONSTRAINT FK_UserLogins_Users_UserId FOREIGN KEY(UserId) REFERENCES Users (Id) ON DELETE CASCADE;
---- UserClaims
ALTER TABLE UserClaims ADD CONSTRAINT FK_UserClaims_Users_UserId FOREIGN KEY(UserId) REFERENCES Users (Id) ON DELETE CASCADE;
---- OAuth2Data
ALTER TABLE OAuth2Data ADD CONSTRAINT FK_OAuth2Data_Users_ClientID FOREIGN KEY(ClientID) REFERENCES Users (ClientID) ON DELETE CASCADE;
