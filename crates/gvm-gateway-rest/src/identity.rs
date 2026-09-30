// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Greenbone AG

//! Identity and access-control DTOs, request parsing, handlers, and OpenAPI transforms.

use std::fmt;

use aide::transform::TransformOperation;
use axum::{
    body::Bytes,
    extract::{OriginalUri, Path, Query, State},
    http::HeaderMap,
    response::Response,
    Json,
};
use gvm_gateway_app::GatewayService;
use gvm_gateway_domain::{
    CreateGroupInput, CreatePermissionInput, CreateRoleInput, CreateUserInput, GatewayError, Group,
    GroupPage, IdentityQuery, ModifyGroupInput, ModifyPermissionInput, ModifyRoleInput,
    ModifyUserInput, ModifyUserSettingInput, Permission, PermissionPage, Role, RolePage, User,
    UserPage, UserSetting, UserSettingList, UserSettingQuery,
};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::{
    dto::{
        datetime_schema, parse_uuid, password_schema, PaginationResponse, ResourceCreatedResponse,
        ResourceRefResponse,
    },
    handler::{
        create_resource, delete_resource, get_resource, list_resource, update_resource,
        ValidateInto,
    },
    open_enum::open_string_enum,
    openapi::{created_json, ok_json, problem_response, ResourceIdPathDoc},
    query::{parse_collection_query, parse_filter_only_query, DeleteResourceQueryParams},
    targets::validate_uuid,
};

#[derive(Clone, Debug, Serialize, JsonSchema)]
struct IdentityMetaResponse {
    id: Uuid,
    name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    comment: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    owner: Option<IdentityOwnerResponse>,
    #[serde(rename = "creationTime", skip_serializing_if = "Option::is_none")]
    creation_time: Option<String>,
    #[serde(rename = "modificationTime", skip_serializing_if = "Option::is_none")]
    modification_time: Option<String>,
    writable: bool,
    #[serde(rename = "inUse")]
    in_use: bool,
}

impl From<gvm_gateway_domain::IdentityResourceMeta> for IdentityMetaResponse {
    fn from(meta: gvm_gateway_domain::IdentityResourceMeta) -> Self {
        Self {
            id: parse_uuid(&meta.id),
            name: meta.name,
            comment: meta.comment,
            owner: meta.owner.map(IdentityOwnerResponse::from),
            creation_time: meta.creation_time,
            modification_time: meta.modification_time,
            writable: meta.writable,
            in_use: meta.in_use,
        }
    }
}

#[derive(Clone, Debug, Serialize, JsonSchema)]
#[schemars(rename = "IdentityOwner")]
struct IdentityOwnerResponse {
    name: String,
}

impl From<gvm_gateway_domain::IdentityOwner> for IdentityOwnerResponse {
    fn from(owner: gvm_gateway_domain::IdentityOwner) -> Self {
        Self { name: owner.name }
    }
}

open_string_enum! {
    /// User authentication backend type.
    pub(crate) enum AuthenticationType {
        File => "file",
        LdapConnect => "ldap_connect",
        RadiusConnect => "radius_connect",
    }
}

#[derive(Clone, Debug, Serialize, JsonSchema)]
#[schemars(rename = "User")]
struct UserResponse {
    #[serde(flatten)]
    meta: IdentityMetaResponse,
    roles: Vec<ResourceRefResponse>,
    groups: Vec<ResourceRefResponse>,
    #[serde(rename = "hostsAllow", skip_serializing_if = "Option::is_none")]
    hosts_allow: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    hosts: Option<String>,
    #[serde(rename = "authenticationType", skip_serializing_if = "Option::is_none")]
    authentication_type: Option<AuthenticationType>,
}

impl From<User> for UserResponse {
    fn from(user: User) -> Self {
        Self {
            meta: IdentityMetaResponse::from(user.meta),
            roles: user
                .roles
                .into_iter()
                .map(ResourceRefResponse::from)
                .collect(),
            groups: user
                .groups
                .into_iter()
                .map(ResourceRefResponse::from)
                .collect(),
            hosts_allow: user.hosts_allow,
            hosts: user.hosts,
            authentication_type: user
                .authentication_type
                .as_deref()
                .map(AuthenticationType::parse),
        }
    }
}

#[derive(Clone, Debug, Serialize, JsonSchema)]
#[schemars(rename = "UserList")]
struct UserListResponse {
    data: Vec<UserResponse>,
    pagination: PaginationResponse,
}

impl From<UserPage> for UserListResponse {
    fn from(page: UserPage) -> Self {
        Self {
            data: page.data.into_iter().map(UserResponse::from).collect(),
            pagination: PaginationResponse::from(page.pagination),
        }
    }
}

#[derive(Clone, Debug, Serialize, JsonSchema)]
#[schemars(rename = "Group")]
struct GroupResponse {
    #[serde(flatten)]
    meta: IdentityMetaResponse,
    users: Vec<String>,
}

impl From<Group> for GroupResponse {
    fn from(group: Group) -> Self {
        Self {
            meta: IdentityMetaResponse::from(group.meta),
            users: group.users,
        }
    }
}

#[derive(Clone, Debug, Serialize, JsonSchema)]
#[schemars(rename = "GroupList")]
struct GroupListResponse {
    data: Vec<GroupResponse>,
    pagination: PaginationResponse,
}

impl From<GroupPage> for GroupListResponse {
    fn from(page: GroupPage) -> Self {
        Self {
            data: page.data.into_iter().map(GroupResponse::from).collect(),
            pagination: PaginationResponse::from(page.pagination),
        }
    }
}

#[derive(Clone, Debug, Serialize, JsonSchema)]
#[schemars(rename = "Role")]
struct RoleResponse {
    #[serde(flatten)]
    meta: IdentityMetaResponse,
    users: Vec<String>,
}

impl From<Role> for RoleResponse {
    fn from(role: Role) -> Self {
        Self {
            meta: IdentityMetaResponse::from(role.meta),
            users: role.users,
        }
    }
}

#[derive(Clone, Debug, Serialize, JsonSchema)]
#[schemars(rename = "RoleList")]
struct RoleListResponse {
    data: Vec<RoleResponse>,
    pagination: PaginationResponse,
}

impl From<RolePage> for RoleListResponse {
    fn from(page: RolePage) -> Self {
        Self {
            data: page.data.into_iter().map(RoleResponse::from).collect(),
            pagination: PaginationResponse::from(page.pagination),
        }
    }
}

#[derive(Clone, Debug, Serialize, JsonSchema)]
#[schemars(rename = "Permission")]
struct PermissionResponse {
    #[serde(flatten)]
    meta: IdentityMetaResponse,
    #[serde(rename = "subjectType", skip_serializing_if = "Option::is_none")]
    subject_type: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    subject: Option<ResourceRefResponse>,
    #[serde(rename = "resourceType", skip_serializing_if = "Option::is_none")]
    resource_type: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    resource: Option<ResourceRefResponse>,
}

impl From<Permission> for PermissionResponse {
    fn from(permission: Permission) -> Self {
        Self {
            meta: IdentityMetaResponse::from(permission.meta),
            subject_type: permission.subject_type,
            subject: permission.subject.map(ResourceRefResponse::from),
            resource_type: permission.resource_type,
            resource: permission.resource.map(ResourceRefResponse::from),
        }
    }
}

#[derive(Clone, Debug, Serialize, JsonSchema)]
#[schemars(rename = "PermissionList")]
struct PermissionListResponse {
    data: Vec<PermissionResponse>,
    pagination: PaginationResponse,
}

impl From<PermissionPage> for PermissionListResponse {
    fn from(page: PermissionPage) -> Self {
        Self {
            data: page
                .data
                .into_iter()
                .map(PermissionResponse::from)
                .collect(),
            pagination: PaginationResponse::from(page.pagination),
        }
    }
}

#[derive(Clone, Serialize, JsonSchema)]
#[schemars(rename = "UserSetting")]
struct UserSettingResponse {
    id: Uuid,
    name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    value: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    comment: Option<String>,
}

impl fmt::Debug for UserSettingResponse {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("UserSettingResponse")
            .field("id", &self.id)
            .field("name", &self.name)
            .field("value", &self.value.as_ref().map(|_| "<redacted>"))
            .field("comment", &self.comment)
            .finish()
    }
}

impl From<UserSetting> for UserSettingResponse {
    fn from(setting: UserSetting) -> Self {
        Self {
            id: parse_uuid(&setting.id),
            name: setting.name,
            value: setting.value,
            comment: setting.comment,
        }
    }
}

#[derive(Clone, Debug, Serialize, JsonSchema)]
#[schemars(rename = "UserSettingList")]
struct UserSettingListResponse {
    data: Vec<UserSettingResponse>,
}

impl From<UserSettingList> for UserSettingListResponse {
    fn from(list: UserSettingList) -> Self {
        Self {
            data: list
                .data
                .into_iter()
                .map(UserSettingResponse::from)
                .collect(),
        }
    }
}

#[derive(Clone, Debug, Serialize, JsonSchema)]
#[schemars(rename = "IdentityResourceBase")]
struct IdentityResourceBaseDoc {
    id: Uuid,
    name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    comment: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    owner: Option<IdentityOwnerResponse>,
    #[serde(rename = "creationTime", skip_serializing_if = "Option::is_none")]
    #[schemars(schema_with = "datetime_schema")]
    creation_time: Option<String>,
    #[serde(rename = "modificationTime", skip_serializing_if = "Option::is_none")]
    #[schemars(schema_with = "datetime_schema")]
    modification_time: Option<String>,
    writable: bool,
    #[serde(rename = "inUse")]
    in_use: bool,
}

#[derive(Clone, Debug, Serialize)]
struct UserDoc;

impl JsonSchema for UserDoc {
    fn schema_name() -> std::borrow::Cow<'static, str> {
        std::borrow::Cow::Borrowed("User")
    }

    fn json_schema(generator: &mut schemars::SchemaGenerator) -> schemars::Schema {
        let _ = generator.subschema_for::<IdentityResourceBaseDoc>();
        serde_json::from_value(serde_json::json!({
            "allOf": [
                { "$ref": "#/components/schemas/IdentityResourceBase" },
                {
                    "type": "object",
                    "properties": {
                        "roles": {
                            "type": "array",
                            "items": { "$ref": "#/components/schemas/ResourceRef" }
                        },
                        "groups": {
                            "type": "array",
                            "items": { "$ref": "#/components/schemas/ResourceRef" }
                        },
                        "hostsAllow": { "type": "boolean" },
                        "hosts": { "type": "string" },
                        "authenticationType": {
                            "$ref": "#/components/schemas/AuthenticationType"
                        }
                    }
                }
            ]
        }))
        .expect("static User schema is valid")
    }
}

#[derive(Clone, Debug, Serialize)]
struct GroupDoc;

impl JsonSchema for GroupDoc {
    fn schema_name() -> std::borrow::Cow<'static, str> {
        std::borrow::Cow::Borrowed("Group")
    }

    fn json_schema(generator: &mut schemars::SchemaGenerator) -> schemars::Schema {
        let _ = generator.subschema_for::<IdentityResourceBaseDoc>();
        identity_users_schema()
    }
}

#[derive(Clone, Debug, Serialize)]
struct RoleDoc;

impl JsonSchema for RoleDoc {
    fn schema_name() -> std::borrow::Cow<'static, str> {
        std::borrow::Cow::Borrowed("Role")
    }

    fn json_schema(generator: &mut schemars::SchemaGenerator) -> schemars::Schema {
        let _ = generator.subschema_for::<IdentityResourceBaseDoc>();
        identity_users_schema()
    }
}

#[derive(Clone, Debug, Serialize)]
struct PermissionDoc;

impl JsonSchema for PermissionDoc {
    fn schema_name() -> std::borrow::Cow<'static, str> {
        std::borrow::Cow::Borrowed("Permission")
    }

    fn json_schema(generator: &mut schemars::SchemaGenerator) -> schemars::Schema {
        let _ = generator.subschema_for::<IdentityResourceBaseDoc>();
        serde_json::from_value(serde_json::json!({
            "allOf": [
                { "$ref": "#/components/schemas/IdentityResourceBase" },
                {
                    "type": "object",
                    "properties": {
                        "subjectType": {
                            "type": "string",
                            "enum": ["user", "group", "role"]
                        },
                        "subject": { "$ref": "#/components/schemas/ResourceRef" },
                        "resourceType": { "type": "string" },
                        "resource": { "$ref": "#/components/schemas/ResourceRef" }
                    }
                }
            ]
        }))
        .expect("static Permission schema is valid")
    }
}

fn identity_users_schema() -> schemars::Schema {
    serde_json::from_value(serde_json::json!({
        "allOf": [
            { "$ref": "#/components/schemas/IdentityResourceBase" },
            {
                "type": "object",
                "properties": {
                    "users": {
                        "type": "array",
                        "items": { "type": "string" }
                    }
                }
            }
        ]
    }))
    .expect("static identity extension schema is valid")
}

#[derive(Clone, Debug, Serialize, JsonSchema)]
#[schemars(rename = "UserList")]
struct UserListDoc {
    data: Vec<UserDoc>,
    pagination: PaginationResponse,
}

#[derive(Clone, Debug, Serialize, JsonSchema)]
#[schemars(rename = "GroupList")]
struct GroupListDoc {
    data: Vec<GroupDoc>,
    pagination: PaginationResponse,
}

#[derive(Clone, Debug, Serialize, JsonSchema)]
#[schemars(rename = "RoleList")]
struct RoleListDoc {
    data: Vec<RoleDoc>,
    pagination: PaginationResponse,
}

#[derive(Clone, Debug, Serialize, JsonSchema)]
#[schemars(rename = "PermissionList")]
struct PermissionListDoc {
    data: Vec<PermissionDoc>,
    pagination: PaginationResponse,
}

#[derive(Clone, Debug, Default, Deserialize, JsonSchema, Serialize)]
struct IdentityListQueryDoc {
    filter: Option<String>,
    #[serde(rename = "filterId")]
    filter_id: Option<Uuid>,
    #[serde(default = "default_page")]
    #[schemars(default = "default_page")]
    #[schemars(range(min = 1))]
    page: Option<u32>,
    #[serde(rename = "perPage")]
    #[serde(default = "default_per_page")]
    #[schemars(default = "default_per_page")]
    #[schemars(range(min = 1, max = 1000))]
    per_page: Option<u32>,
}

#[derive(Clone, Debug, Default, Deserialize, JsonSchema, Serialize)]
struct UserSettingListQueryDoc {
    filter: Option<String>,
    #[serde(rename = "filterId")]
    filter_id: Option<Uuid>,
}

fn default_page() -> Option<u32> {
    Some(1)
}

fn default_per_page() -> Option<u32> {
    Some(25)
}

#[derive(Clone, Debug, Deserialize, JsonSchema, Serialize)]
enum PermissionSubjectTypeDoc {
    #[serde(rename = "user")]
    User,
    #[serde(rename = "group")]
    Group,
    #[serde(rename = "role")]
    Role,
}

#[derive(Clone, Debug, Deserialize, JsonSchema, Serialize)]
#[schemars(rename = "CreateUser")]
#[serde(deny_unknown_fields)]
struct CreateUserDoc {
    name: String,
    comment: Option<String>,
    #[schemars(schema_with = "password_schema")]
    password: Option<String>,
    hosts: Option<String>,
    roles: Option<Vec<Uuid>>,
    #[serde(rename = "authenticationType")]
    authentication_type: Option<AuthenticationType>,
}

#[derive(Clone, Debug, Deserialize, JsonSchema, Serialize)]
#[schemars(rename = "ModifyUser")]
#[serde(deny_unknown_fields)]
struct ModifyUserDoc {
    name: Option<String>,
    comment: Option<String>,
    #[schemars(schema_with = "password_schema")]
    password: Option<String>,
    hosts: Option<String>,
    /// Assigned role identifiers. Omitted or null leaves existing roles
    /// unchanged; an empty array clears all roles.
    roles: Option<Vec<Uuid>>,
    #[serde(rename = "authenticationType")]
    authentication_type: Option<AuthenticationType>,
}

#[derive(Clone, Debug, Deserialize, JsonSchema, Serialize)]
#[schemars(rename = "CreateGroup")]
#[serde(deny_unknown_fields)]
struct CreateGroupDoc {
    name: String,
    comment: Option<String>,
    users: Option<Vec<String>>,
}

#[derive(Clone, Debug, Deserialize, JsonSchema, Serialize)]
#[schemars(rename = "ModifyGroup")]
#[serde(deny_unknown_fields)]
struct ModifyGroupDoc {
    comment: Option<String>,
    users: Option<Vec<String>>,
}

#[derive(Clone, Debug, Deserialize, JsonSchema, Serialize)]
#[schemars(rename = "CreateRole")]
#[serde(deny_unknown_fields)]
struct CreateRoleDoc {
    name: String,
    comment: Option<String>,
    users: Option<Vec<String>>,
}

#[derive(Clone, Debug, Deserialize, JsonSchema, Serialize)]
#[schemars(rename = "ModifyRole")]
#[serde(deny_unknown_fields)]
struct ModifyRoleDoc {
    comment: Option<String>,
    users: Option<Vec<String>>,
}

#[derive(Clone, Debug, Deserialize, JsonSchema, Serialize)]
#[schemars(rename = "CreatePermission")]
#[serde(deny_unknown_fields)]
struct CreatePermissionDoc {
    name: Option<String>,
    comment: Option<String>,
    #[serde(rename = "subjectType")]
    subject_type: Option<PermissionSubjectTypeDoc>,
    #[serde(rename = "subjectId")]
    subject_id: Option<Uuid>,
    #[serde(rename = "resourceType")]
    resource_type: Option<String>,
    #[serde(rename = "resourceId")]
    resource_id: Option<Uuid>,
}

#[derive(Clone, Debug, Deserialize, JsonSchema, Serialize)]
#[schemars(rename = "ModifyPermission")]
#[serde(deny_unknown_fields)]
struct ModifyPermissionDoc {
    name: Option<String>,
    comment: Option<String>,
    #[serde(rename = "subjectType")]
    subject_type: Option<PermissionSubjectTypeDoc>,
    #[serde(rename = "subjectId")]
    subject_id: Option<Uuid>,
    #[serde(rename = "resourceType")]
    resource_type: Option<String>,
    #[serde(rename = "resourceId")]
    resource_id: Option<Uuid>,
}

#[derive(Clone, Deserialize, JsonSchema, Serialize)]
#[schemars(rename = "ModifyUserSetting")]
#[serde(deny_unknown_fields)]
struct ModifyUserSettingDoc {
    value: String,
}

impl fmt::Debug for ModifyUserSettingDoc {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ModifyUserSettingDoc")
            .field("value", &"<redacted>")
            .finish()
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct IdentityListQuery {
    filter_string: Option<String>,
    filter_id: Option<String>,
    page: u32,
    per_page: u32,
}

impl IdentityListQuery {
    fn try_from_query_string(query: &str) -> Result<Self, GatewayError> {
        let parsed = parse_collection_query(query)?;

        Ok(Self {
            filter_string: parsed.filter_string,
            filter_id: parsed.filter_id,
            page: parsed.page,
            per_page: parsed.per_page,
        })
    }

    fn into_domain(self) -> IdentityQuery {
        IdentityQuery {
            filter_string: self.filter_string,
            filter_id: self.filter_id,
            page: self.page,
            per_page: self.per_page,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct UserSettingsListQuery {
    filter_string: Option<String>,
    filter_id: Option<String>,
}

impl UserSettingsListQuery {
    fn try_from_query_string(query: &str) -> Result<Self, GatewayError> {
        let parsed = parse_filter_only_query(query)?;

        Ok(Self {
            filter_string: parsed.filter_string,
            filter_id: parsed.filter_id,
        })
    }

    fn into_domain(self) -> UserSettingQuery {
        UserSettingQuery {
            filter_string: self.filter_string,
            filter_id: self.filter_id,
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
struct CreateUserRequest {
    name: Option<String>,
    comment: Option<String>,
    password: Option<String>,
    hosts: Option<String>,
    roles: Option<Vec<String>>,
    #[serde(rename = "authenticationType")]
    authentication_type: Option<String>,
}

impl CreateUserRequest {
    fn validate(self) -> Result<CreateUserInput, GatewayError> {
        let name = require_name(self.name)?;
        let role_ids = validate_uuid_list("roles", self.roles.unwrap_or_default())?;
        validate_auth_type(self.authentication_type.as_deref())?;
        Ok(CreateUserInput {
            name,
            comment: self.comment,
            password: self.password,
            hosts: self.hosts,
            role_ids,
            authentication_type: self.authentication_type,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
struct ModifyUserRequest {
    name: Option<String>,
    comment: Option<String>,
    password: Option<String>,
    hosts: Option<String>,
    /// Assigned role identifiers. Omitted or null leaves existing roles
    /// unchanged; an empty array clears all roles.
    roles: Option<Vec<String>>,
    #[serde(rename = "authenticationType")]
    authentication_type: Option<String>,
}

impl ModifyUserRequest {
    fn validate(self) -> Result<ModifyUserInput, GatewayError> {
        let role_ids = self
            .roles
            .map(|roles| validate_uuid_list("roles", roles))
            .transpose()?;
        validate_auth_type(self.authentication_type.as_deref())?;
        Ok(ModifyUserInput {
            name: self.name,
            comment: self.comment,
            password: self.password,
            hosts: self.hosts,
            role_ids,
            authentication_type: self.authentication_type,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
struct CreateGroupRequest {
    name: Option<String>,
    comment: Option<String>,
    users: Option<Vec<String>>,
}

impl CreateGroupRequest {
    fn validate(self) -> Result<CreateGroupInput, GatewayError> {
        Ok(CreateGroupInput {
            name: require_name(self.name)?,
            comment: self.comment,
            users: self.users.unwrap_or_default(),
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
struct ModifyGroupRequest {
    comment: Option<String>,
    users: Option<Vec<String>>,
}

impl ModifyGroupRequest {
    fn validate(self) -> ModifyGroupInput {
        ModifyGroupInput {
            comment: self.comment,
            users: self.users,
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
struct CreateRoleRequest {
    name: Option<String>,
    comment: Option<String>,
    users: Option<Vec<String>>,
}

impl CreateRoleRequest {
    fn validate(self) -> Result<CreateRoleInput, GatewayError> {
        Ok(CreateRoleInput {
            name: require_name(self.name)?,
            comment: self.comment,
            users: self.users.unwrap_or_default(),
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
struct ModifyRoleRequest {
    comment: Option<String>,
    users: Option<Vec<String>>,
}

impl ModifyRoleRequest {
    fn validate(self) -> ModifyRoleInput {
        ModifyRoleInput {
            comment: self.comment,
            users: self.users,
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
struct CreatePermissionRequest {
    name: Option<String>,
    comment: Option<String>,
    #[serde(rename = "subjectType")]
    subject_type: Option<String>,
    #[serde(rename = "subjectId")]
    subject_id: Option<String>,
    #[serde(rename = "resourceType")]
    resource_type: Option<String>,
    #[serde(rename = "resourceId")]
    resource_id: Option<String>,
}

impl CreatePermissionRequest {
    fn validate(self) -> Result<CreatePermissionInput, GatewayError> {
        validate_subject_type(self.subject_type.as_deref())?;
        validate_optional_uuid("subjectId", self.subject_id.as_deref())?;
        validate_optional_uuid("resourceId", self.resource_id.as_deref())?;
        Ok(CreatePermissionInput {
            name: self.name,
            comment: self.comment,
            subject_type: self.subject_type,
            subject_id: self.subject_id,
            resource_type: self.resource_type,
            resource_id: self.resource_id,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
struct ModifyPermissionRequest {
    name: Option<String>,
    comment: Option<String>,
    #[serde(rename = "subjectType")]
    subject_type: Option<String>,
    #[serde(rename = "subjectId")]
    subject_id: Option<String>,
    #[serde(rename = "resourceType")]
    resource_type: Option<String>,
    #[serde(rename = "resourceId")]
    resource_id: Option<String>,
}

impl ModifyPermissionRequest {
    fn validate(self) -> Result<ModifyPermissionInput, GatewayError> {
        validate_subject_type(self.subject_type.as_deref())?;
        validate_optional_uuid("subjectId", self.subject_id.as_deref())?;
        validate_optional_uuid("resourceId", self.resource_id.as_deref())?;
        Ok(ModifyPermissionInput {
            name: self.name,
            comment: self.comment,
            subject_type: self.subject_type,
            subject_id: self.subject_id,
            resource_type: self.resource_type,
            resource_id: self.resource_id,
        })
    }
}

#[derive(Clone, Deserialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
struct ModifyUserSettingRequest {
    value: Option<String>,
}

impl fmt::Debug for ModifyUserSettingRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ModifyUserSettingRequest")
            .field("value", &self.value.as_ref().map(|_| "<redacted>"))
            .finish()
    }
}

impl ModifyUserSettingRequest {
    fn validate(self) -> Result<ModifyUserSettingInput, GatewayError> {
        let value = self
            .value
            .ok_or_else(|| GatewayError::InvalidInput("value is required".to_string()))?;
        Ok(ModifyUserSettingInput { value })
    }
}

/// Lists users visible to the authenticated principal.
pub async fn list_users(
    State(service): State<GatewayService>,
    headers: HeaderMap,
    uri: OriginalUri,
) -> Response {
    list_resource(
        service,
        headers,
        uri,
        |query| IdentityListQuery::try_from_query_string(query).map(IdentityListQuery::into_domain),
        |service, session, query| async move { service.list_users(&session, query).await },
        UserListResponse::from,
    )
    .await
}

/// Creates a user.
pub async fn create_user(
    State(service): State<GatewayService>,
    headers: HeaderMap,
    uri: OriginalUri,
    body: Bytes,
) -> Response {
    create_resource::<CreateUserInput, CreateUserRequest, _, _>(
        service,
        headers,
        uri,
        body,
        |service, session, input| async move { service.create_user(&session, input).await },
    )
    .await
}

/// Returns one user by ID.
pub async fn get_user(
    State(service): State<GatewayService>,
    headers: HeaderMap,
    Path(id): Path<String>,
    uri: OriginalUri,
) -> Response {
    get_resource(service, headers, id, uri, |service, session, resource_id| async move {
        service.get_user(&session, &resource_id).await
    },
        UserResponse::from,
    )
    .await
}

/// Updates one user by ID.
pub async fn update_user(
    State(service): State<GatewayService>,
    headers: HeaderMap,
    Path(id): Path<String>,
    uri: OriginalUri,
    body: Bytes,
) -> Response {
    update_resource::<ModifyUserInput, ModifyUserRequest, User, UserResponse, _, _>(
        service,
        headers,
        id,
        uri,
        body,
        |service, session, resource_id, input| async move {
            service.modify_user(&session, &resource_id, input).await
        },
        UserResponse::from,
    )
    .await
}

/// Deletes one user by ID.
pub async fn delete_user(
    State(service): State<GatewayService>,
    headers: HeaderMap,
    Path(id): Path<String>,
    uri: OriginalUri,
) -> Response {
    delete_resource(
        service,
        headers,
        id,
        uri,
        |service, session, resource_id, ultimate| async move {
            service.delete_user(&session, &resource_id, ultimate).await
        },
    )
    .await
}

/// Lists groups visible to the authenticated principal.
pub async fn list_groups(
    State(service): State<GatewayService>,
    headers: HeaderMap,
    uri: OriginalUri,
) -> Response {
    list_resource(
        service,
        headers,
        uri,
        |query| IdentityListQuery::try_from_query_string(query).map(IdentityListQuery::into_domain),
        |service, session, query| async move { service.list_groups(&session, query).await },
        GroupListResponse::from,
    )
    .await
}

/// Creates a group.
pub async fn create_group(
    State(service): State<GatewayService>,
    headers: HeaderMap,
    uri: OriginalUri,
    body: Bytes,
) -> Response {
    create_resource::<CreateGroupInput, CreateGroupRequest, _, _>(
        service,
        headers,
        uri,
        body,
        |service, session, input| async move { service.create_group(&session, input).await },
    )
    .await
}

/// Returns one group by ID.
pub async fn get_group(
    State(service): State<GatewayService>,
    headers: HeaderMap,
    Path(id): Path<String>,
    uri: OriginalUri,
) -> Response {
    get_resource(service, headers, id, uri, |service, session, resource_id| async move {
        service.get_group(&session, &resource_id).await
    },
        GroupResponse::from,
    )
    .await
}

/// Updates one group by ID.
pub async fn update_group(
    State(service): State<GatewayService>,
    headers: HeaderMap,
    Path(id): Path<String>,
    uri: OriginalUri,
    body: Bytes,
) -> Response {
    update_resource::<ModifyGroupInput, ModifyGroupRequest, Group, GroupResponse, _, _>(
        service,
        headers,
        id,
        uri,
        body,
        |service, session, resource_id, input| async move {
            service.modify_group(&session, &resource_id, input).await
        },
        GroupResponse::from,
    )
    .await
}

/// Deletes one group by ID.
pub async fn delete_group(
    State(service): State<GatewayService>,
    headers: HeaderMap,
    Path(id): Path<String>,
    uri: OriginalUri,
) -> Response {
    delete_resource(
        service,
        headers,
        id,
        uri,
        |service, session, resource_id, ultimate| async move {
            service.delete_group(&session, &resource_id, ultimate).await
        },
    )
    .await
}

/// Lists roles visible to the authenticated principal.
pub async fn list_roles(
    State(service): State<GatewayService>,
    headers: HeaderMap,
    uri: OriginalUri,
) -> Response {
    list_resource(
        service,
        headers,
        uri,
        |query| IdentityListQuery::try_from_query_string(query).map(IdentityListQuery::into_domain),
        |service, session, query| async move { service.list_roles(&session, query).await },
        RoleListResponse::from,
    )
    .await
}

/// Creates a role.
pub async fn create_role(
    State(service): State<GatewayService>,
    headers: HeaderMap,
    uri: OriginalUri,
    body: Bytes,
) -> Response {
    create_resource::<CreateRoleInput, CreateRoleRequest, _, _>(
        service,
        headers,
        uri,
        body,
        |service, session, input| async move { service.create_role(&session, input).await },
    )
    .await
}

/// Returns one role by ID.
pub async fn get_role(
    State(service): State<GatewayService>,
    headers: HeaderMap,
    Path(id): Path<String>,
    uri: OriginalUri,
) -> Response {
    get_resource(service, headers, id, uri, |service, session, resource_id| async move {
        service.get_role(&session, &resource_id).await
    },
        RoleResponse::from,
    )
    .await
}

/// Updates one role by ID.
pub async fn update_role(
    State(service): State<GatewayService>,
    headers: HeaderMap,
    Path(id): Path<String>,
    uri: OriginalUri,
    body: Bytes,
) -> Response {
    update_resource::<ModifyRoleInput, ModifyRoleRequest, Role, RoleResponse, _, _>(
        service,
        headers,
        id,
        uri,
        body,
        |service, session, resource_id, input| async move {
            service.modify_role(&session, &resource_id, input).await
        },
        RoleResponse::from,
    )
    .await
}

/// Deletes one role by ID.
pub async fn delete_role(
    State(service): State<GatewayService>,
    headers: HeaderMap,
    Path(id): Path<String>,
    uri: OriginalUri,
) -> Response {
    delete_resource(
        service,
        headers,
        id,
        uri,
        |service, session, resource_id, ultimate| async move {
            service.delete_role(&session, &resource_id, ultimate).await
        },
    )
    .await
}

/// Lists permissions visible to the authenticated principal.
pub async fn list_permissions(
    State(service): State<GatewayService>,
    headers: HeaderMap,
    uri: OriginalUri,
) -> Response {
    list_resource(
        service,
        headers,
        uri,
        |query| IdentityListQuery::try_from_query_string(query).map(IdentityListQuery::into_domain),
        |service, session, query| async move { service.list_permissions(&session, query).await },
        PermissionListResponse::from,
    )
    .await
}

/// Creates a permission.
pub async fn create_permission(
    State(service): State<GatewayService>,
    headers: HeaderMap,
    uri: OriginalUri,
    body: Bytes,
) -> Response {
    create_resource::<CreatePermissionInput, CreatePermissionRequest, _, _>(
        service,
        headers,
        uri,
        body,
        |service, session, input| async move { service.create_permission(&session, input).await },
    )
    .await
}

/// Returns one permission by ID.
pub async fn get_permission(
    State(service): State<GatewayService>,
    headers: HeaderMap,
    Path(id): Path<String>,
    uri: OriginalUri,
) -> Response {
    get_resource(
        service,
        headers,
        id,
        uri,
        |service, session, resource_id| async move {
            service.get_permission(&session, &resource_id).await
        },
        PermissionResponse::from,
    )
    .await
}

/// Updates one permission by ID.
pub async fn update_permission(
    State(service): State<GatewayService>,
    headers: HeaderMap,
    Path(id): Path<String>,
    uri: OriginalUri,
    body: Bytes,
) -> Response {
    update_resource::<
        ModifyPermissionInput,
        ModifyPermissionRequest,
        Permission,
        PermissionResponse,
        _,
        _,
    >(
        service,
        headers,
        id,
        uri,
        body,
        |service, session, resource_id, input| async move {
            service
                .modify_permission(&session, &resource_id, input)
                .await
        },
        PermissionResponse::from,
    )
    .await
}

/// Deletes one permission by ID.
pub async fn delete_permission(
    State(service): State<GatewayService>,
    headers: HeaderMap,
    Path(id): Path<String>,
    uri: OriginalUri,
) -> Response {
    delete_resource(
        service,
        headers,
        id,
        uri,
        |service, session, resource_id, ultimate| async move {
            service
                .delete_permission(&session, &resource_id, ultimate)
                .await
        },
    )
    .await
}

/// Lists user settings for the authenticated principal.
pub async fn list_user_settings(
    State(service): State<GatewayService>,
    headers: HeaderMap,
    uri: OriginalUri,
) -> Response {
    list_resource(
        service,
        headers,
        uri,
        |query| {
            UserSettingsListQuery::try_from_query_string(query)
                .map(UserSettingsListQuery::into_domain)
        },
        |service, session, query| async move { service.list_user_settings(&session, query).await },
        UserSettingListResponse::from,
    )
    .await
}

/// Returns one user setting by ID.
pub async fn get_user_setting(
    State(service): State<GatewayService>,
    headers: HeaderMap,
    Path(id): Path<String>,
    uri: OriginalUri,
) -> Response {
    get_resource(
        service,
        headers,
        id,
        uri,
        |service, session, resource_id| async move {
            service.get_user_setting(&session, &resource_id).await
        },
        UserSettingResponse::from,
    )
    .await
}

/// Updates one user setting by ID.
pub async fn update_user_setting(
    State(service): State<GatewayService>,
    headers: HeaderMap,
    Path(id): Path<String>,
    uri: OriginalUri,
    body: Bytes,
) -> Response {
    update_resource::<
        ModifyUserSettingInput,
        ModifyUserSettingRequest,
        UserSetting,
        UserSettingResponse,
        _,
        _,
    >(
        service,
        headers,
        id,
        uri,
        body,
        |service, session, resource_id, input| async move {
            service
                .modify_user_setting(&session, &resource_id, input)
                .await
        },
        UserSettingResponse::from,
    )
    .await
}

impl ValidateInto<CreateUserInput> for CreateUserRequest {
    fn validate_into(self) -> Result<CreateUserInput, GatewayError> {
        self.validate()
    }
}

impl ValidateInto<ModifyUserInput> for ModifyUserRequest {
    fn validate_into(self) -> Result<ModifyUserInput, GatewayError> {
        self.validate()
    }
}

impl ValidateInto<CreateGroupInput> for CreateGroupRequest {
    fn validate_into(self) -> Result<CreateGroupInput, GatewayError> {
        self.validate()
    }
}

impl ValidateInto<ModifyGroupInput> for ModifyGroupRequest {
    fn validate_into(self) -> Result<ModifyGroupInput, GatewayError> {
        Ok(self.validate())
    }
}

impl ValidateInto<CreateRoleInput> for CreateRoleRequest {
    fn validate_into(self) -> Result<CreateRoleInput, GatewayError> {
        self.validate()
    }
}

impl ValidateInto<ModifyRoleInput> for ModifyRoleRequest {
    fn validate_into(self) -> Result<ModifyRoleInput, GatewayError> {
        Ok(self.validate())
    }
}

impl ValidateInto<CreatePermissionInput> for CreatePermissionRequest {
    fn validate_into(self) -> Result<CreatePermissionInput, GatewayError> {
        self.validate()
    }
}

impl ValidateInto<ModifyPermissionInput> for ModifyPermissionRequest {
    fn validate_into(self) -> Result<ModifyPermissionInput, GatewayError> {
        self.validate()
    }
}

impl ValidateInto<ModifyUserSettingInput> for ModifyUserSettingRequest {
    fn validate_into(self) -> Result<ModifyUserSettingInput, GatewayError> {
        self.validate()
    }
}

fn require_name(name: Option<String>) -> Result<String, GatewayError> {
    name.filter(|value| !value.trim().is_empty())
        .ok_or_else(|| GatewayError::InvalidInput("name is required".to_string()))
}

fn validate_optional_uuid(field: &str, value: Option<&str>) -> Result<(), GatewayError> {
    if let Some(value) = value {
        validate_uuid(field, value)?;
    }
    Ok(())
}

fn validate_uuid_list(field: &str, values: Vec<String>) -> Result<Vec<String>, GatewayError> {
    for value in &values {
        validate_uuid(field, value)?;
    }
    Ok(values)
}

fn validate_auth_type(value: Option<&str>) -> Result<(), GatewayError> {
    if let Some(value) = value {
        match value {
            "file" | "ldap_connect" | "radius_connect" => Ok(()),
            _ => Err(GatewayError::InvalidInput(format!(
                "authenticationType must be one of file, ldap_connect, radius_connect; got {value}"
            ))),
        }
    } else {
        Ok(())
    }
}

fn validate_subject_type(value: Option<&str>) -> Result<(), GatewayError> {
    if let Some(value) = value {
        match value {
            "user" | "group" | "role" => Ok(()),
            _ => Err(GatewayError::InvalidInput(format!(
                "subjectType must be one of user, group, role; got {value}"
            ))),
        }
    } else {
        Ok(())
    }
}

fn collection_list_docs<'a>(
    op: TransformOperation<'a>,
    operation_id: &'static str,
    tag: &'static str,
    summary: &'static str,
    description: &'static str,
) -> TransformOperation<'a> {
    op.id(operation_id)
        .tag(tag)
        .summary(summary)
        .description(description)
        .security_requirement("bearerAuth")
}

pub(crate) fn list_users_docs(op: TransformOperation<'_>) -> TransformOperation<'_> {
    let op = collection_list_docs(
        op,
        "getUsers",
        "Users",
        "List users",
        "Returns a paginated list of users.",
    )
    .input::<axum::extract::Query<IdentityListQueryDoc>>()
    .response_with::<200, Json<UserListDoc>, _>(ok_json("Paginated list of users"));
    let op = problem_response::<400>(op, "Invalid request");
    let op = problem_response::<401>(op, "Authentication required or session expired");
    problem_response::<403>(op, "Forbidden")
}

pub(crate) fn create_user_docs(op: TransformOperation<'_>) -> TransformOperation<'_> {
    let op = collection_list_docs(
        op,
        "createUser",
        "Users",
        "Create a user",
        "Creates a new user.",
    )
    .input::<Json<CreateUserDoc>>()
    .response_with::<201, Json<ResourceCreatedResponse>, _>(created_json("User created"));
    let op = problem_response::<400>(op, "Invalid request");
    let op = problem_response::<401>(op, "Authentication required or session expired");
    problem_response::<403>(op, "Forbidden")
}

pub(crate) fn get_user_docs(op: TransformOperation<'_>) -> TransformOperation<'_> {
    let op = collection_list_docs(
        op,
        "getUser",
        "Users",
        "Get a user",
        "Returns one user by ID.",
    )
    .input::<Path<ResourceIdPathDoc>>()
    .response_with::<200, Json<UserDoc>, _>(ok_json("User details"));
    let op = problem_response::<400>(op, "Invalid request");
    let op = problem_response::<401>(op, "Authentication required or session expired");
    let op = problem_response::<403>(op, "Forbidden");
    problem_response::<404>(op, "Resource not found")
}

pub(crate) fn update_user_docs(op: TransformOperation<'_>) -> TransformOperation<'_> {
    let op = collection_list_docs(
        op,
        "modifyUser",
        "Users",
        "Modify a user",
        "Updates an existing user.",
    )
    .input::<(Path<ResourceIdPathDoc>, Json<ModifyUserDoc>)>()
    .response_with::<200, Json<UserDoc>, _>(ok_json("User updated"));
    let op = problem_response::<400>(op, "Invalid request");
    let op = problem_response::<401>(op, "Authentication required or session expired");
    let op = problem_response::<403>(op, "Forbidden");
    problem_response::<404>(op, "Resource not found")
}

pub(crate) fn delete_user_docs(op: TransformOperation<'_>) -> TransformOperation<'_> {
    let op = collection_list_docs(
        op,
        "deleteUser",
        "Users",
        "Delete a user",
        "Deletes a user. Pass `ultimate=true` to request permanent backend deletion instead of the default non-ultimate delete.",
    )
    .input::<(Path<ResourceIdPathDoc>, Query<DeleteResourceQueryParams>)>()
    .response_with::<204, (), _>(|response| response.description("User deleted"));
    let op = problem_response::<400>(op, "Invalid request");
    let op = problem_response::<401>(op, "Authentication required or session expired");
    let op = problem_response::<403>(op, "Forbidden");
    problem_response::<404>(op, "Resource not found")
}

pub(crate) fn list_groups_docs(op: TransformOperation<'_>) -> TransformOperation<'_> {
    let op = collection_list_docs(
        op,
        "getGroups",
        "Groups",
        "List groups",
        "Returns a paginated list of groups.",
    )
    .input::<axum::extract::Query<IdentityListQueryDoc>>()
    .response_with::<200, Json<GroupListDoc>, _>(ok_json("Paginated list of groups"));
    let op = problem_response::<400>(op, "Invalid request");
    let op = problem_response::<401>(op, "Authentication required or session expired");
    problem_response::<403>(op, "Forbidden")
}

pub(crate) fn create_group_docs(op: TransformOperation<'_>) -> TransformOperation<'_> {
    let op = collection_list_docs(
        op,
        "createGroup",
        "Groups",
        "Create a group",
        "Creates a new group.",
    )
    .input::<Json<CreateGroupDoc>>()
    .response_with::<201, Json<ResourceCreatedResponse>, _>(created_json("Group created"));
    let op = problem_response::<400>(op, "Invalid request");
    let op = problem_response::<401>(op, "Authentication required or session expired");
    problem_response::<403>(op, "Forbidden")
}

pub(crate) fn get_group_docs(op: TransformOperation<'_>) -> TransformOperation<'_> {
    let op = collection_list_docs(
        op,
        "getGroup",
        "Groups",
        "Get a group",
        "Returns one group by ID.",
    )
    .input::<Path<ResourceIdPathDoc>>()
    .response_with::<200, Json<GroupDoc>, _>(ok_json("Group details"));
    let op = problem_response::<400>(op, "Invalid request");
    let op = problem_response::<401>(op, "Authentication required or session expired");
    let op = problem_response::<403>(op, "Forbidden");
    problem_response::<404>(op, "Resource not found")
}

pub(crate) fn update_group_docs(op: TransformOperation<'_>) -> TransformOperation<'_> {
    let op = collection_list_docs(
        op,
        "modifyGroup",
        "Groups",
        "Modify a group",
        "Updates an existing group.",
    )
    .input::<(Path<ResourceIdPathDoc>, Json<ModifyGroupDoc>)>()
    .response_with::<200, Json<GroupDoc>, _>(ok_json("Group updated"));
    let op = problem_response::<400>(op, "Invalid request");
    let op = problem_response::<401>(op, "Authentication required or session expired");
    let op = problem_response::<403>(op, "Forbidden");
    problem_response::<404>(op, "Resource not found")
}

pub(crate) fn delete_group_docs(op: TransformOperation<'_>) -> TransformOperation<'_> {
    let op = collection_list_docs(
        op,
        "deleteGroup",
        "Groups",
        "Delete a group",
        "Deletes a group. Pass `ultimate=true` to request permanent backend deletion instead of the default non-ultimate delete.",
    )
    .input::<(Path<ResourceIdPathDoc>, Query<DeleteResourceQueryParams>)>()
    .response_with::<204, (), _>(|response| response.description("Group deleted"));
    let op = problem_response::<400>(op, "Invalid request");
    let op = problem_response::<401>(op, "Authentication required or session expired");
    let op = problem_response::<403>(op, "Forbidden");
    problem_response::<404>(op, "Resource not found")
}

pub(crate) fn list_roles_docs(op: TransformOperation<'_>) -> TransformOperation<'_> {
    let op = collection_list_docs(
        op,
        "getRoles",
        "Roles",
        "List roles",
        "Returns a paginated list of roles.",
    )
    .input::<axum::extract::Query<IdentityListQueryDoc>>()
    .response_with::<200, Json<RoleListDoc>, _>(ok_json("Paginated list of roles"));
    let op = problem_response::<400>(op, "Invalid request");
    let op = problem_response::<401>(op, "Authentication required or session expired");
    problem_response::<403>(op, "Forbidden")
}

pub(crate) fn create_role_docs(op: TransformOperation<'_>) -> TransformOperation<'_> {
    let op = collection_list_docs(
        op,
        "createRole",
        "Roles",
        "Create a role",
        "Creates a new role.",
    )
    .input::<Json<CreateRoleDoc>>()
    .response_with::<201, Json<ResourceCreatedResponse>, _>(created_json("Role created"));
    let op = problem_response::<400>(op, "Invalid request");
    let op = problem_response::<401>(op, "Authentication required or session expired");
    problem_response::<403>(op, "Forbidden")
}

pub(crate) fn get_role_docs(op: TransformOperation<'_>) -> TransformOperation<'_> {
    let op = collection_list_docs(
        op,
        "getRole",
        "Roles",
        "Get a role",
        "Returns one role by ID.",
    )
    .input::<Path<ResourceIdPathDoc>>()
    .response_with::<200, Json<RoleDoc>, _>(ok_json("Role details"));
    let op = problem_response::<400>(op, "Invalid request");
    let op = problem_response::<401>(op, "Authentication required or session expired");
    let op = problem_response::<403>(op, "Forbidden");
    problem_response::<404>(op, "Resource not found")
}

pub(crate) fn update_role_docs(op: TransformOperation<'_>) -> TransformOperation<'_> {
    let op = collection_list_docs(
        op,
        "modifyRole",
        "Roles",
        "Modify a role",
        "Updates an existing role.",
    )
    .input::<(Path<ResourceIdPathDoc>, Json<ModifyRoleDoc>)>()
    .response_with::<200, Json<RoleDoc>, _>(ok_json("Role updated"));
    let op = problem_response::<400>(op, "Invalid request");
    let op = problem_response::<401>(op, "Authentication required or session expired");
    let op = problem_response::<403>(op, "Forbidden");
    problem_response::<404>(op, "Resource not found")
}

pub(crate) fn delete_role_docs(op: TransformOperation<'_>) -> TransformOperation<'_> {
    let op = collection_list_docs(
        op,
        "deleteRole",
        "Roles",
        "Delete a role",
        "Deletes a role. Pass `ultimate=true` to request permanent backend deletion instead of the default non-ultimate delete.",
    )
    .input::<(Path<ResourceIdPathDoc>, Query<DeleteResourceQueryParams>)>()
    .response_with::<204, (), _>(|response| response.description("Role deleted"));
    let op = problem_response::<400>(op, "Invalid request");
    let op = problem_response::<401>(op, "Authentication required or session expired");
    let op = problem_response::<403>(op, "Forbidden");
    problem_response::<404>(op, "Resource not found")
}

pub(crate) fn list_permissions_docs(op: TransformOperation<'_>) -> TransformOperation<'_> {
    let op = collection_list_docs(
        op,
        "getPermissions",
        "Permissions",
        "List permissions",
        "Returns a paginated list of permissions.",
    )
    .input::<axum::extract::Query<IdentityListQueryDoc>>()
    .response_with::<200, Json<PermissionListDoc>, _>(ok_json("Paginated list of permissions"));
    let op = problem_response::<400>(op, "Invalid request");
    let op = problem_response::<401>(op, "Authentication required or session expired");
    problem_response::<403>(op, "Forbidden")
}

pub(crate) fn create_permission_docs(op: TransformOperation<'_>) -> TransformOperation<'_> {
    let op = collection_list_docs(
        op,
        "createPermission",
        "Permissions",
        "Create a permission",
        "Creates a new permission.",
    )
    .input::<Json<CreatePermissionDoc>>()
    .response_with::<201, Json<ResourceCreatedResponse>, _>(created_json("Permission created"));
    let op = problem_response::<400>(op, "Invalid request");
    let op = problem_response::<401>(op, "Authentication required or session expired");
    problem_response::<403>(op, "Forbidden")
}

pub(crate) fn get_permission_docs(op: TransformOperation<'_>) -> TransformOperation<'_> {
    let op = collection_list_docs(
        op,
        "getPermission",
        "Permissions",
        "Get a permission",
        "Returns one permission by ID.",
    )
    .input::<Path<ResourceIdPathDoc>>()
    .response_with::<200, Json<PermissionDoc>, _>(ok_json("Permission details"));
    let op = problem_response::<400>(op, "Invalid request");
    let op = problem_response::<401>(op, "Authentication required or session expired");
    let op = problem_response::<403>(op, "Forbidden");
    problem_response::<404>(op, "Resource not found")
}

pub(crate) fn update_permission_docs(op: TransformOperation<'_>) -> TransformOperation<'_> {
    let op = collection_list_docs(
        op,
        "modifyPermission",
        "Permissions",
        "Modify a permission",
        "Updates an existing permission.",
    )
    .input::<(Path<ResourceIdPathDoc>, Json<ModifyPermissionDoc>)>()
    .response_with::<200, Json<PermissionDoc>, _>(ok_json("Permission updated"));
    let op = problem_response::<400>(op, "Invalid request");
    let op = problem_response::<401>(op, "Authentication required or session expired");
    let op = problem_response::<403>(op, "Forbidden");
    problem_response::<404>(op, "Resource not found")
}

pub(crate) fn delete_permission_docs(op: TransformOperation<'_>) -> TransformOperation<'_> {
    let op = collection_list_docs(
        op,
        "deletePermission",
        "Permissions",
        "Delete a permission",
        "Deletes a permission. Pass `ultimate=true` to request permanent backend deletion instead of the default non-ultimate delete.",
    )
    .input::<(Path<ResourceIdPathDoc>, Query<DeleteResourceQueryParams>)>()
    .response_with::<204, (), _>(|response| response.description("Permission deleted"));
    let op = problem_response::<400>(op, "Invalid request");
    let op = problem_response::<401>(op, "Authentication required or session expired");
    let op = problem_response::<403>(op, "Forbidden");
    problem_response::<404>(op, "Resource not found")
}

pub(crate) fn list_user_settings_docs(op: TransformOperation<'_>) -> TransformOperation<'_> {
    let op = collection_list_docs(
        op,
        "getUserSettings",
        "User Settings",
        "List current user settings",
        "Returns current-user settings.",
    )
    .input::<axum::extract::Query<UserSettingListQueryDoc>>()
    .response_with::<200, Json<UserSettingListResponse>, _>(ok_json("Current-user settings"));
    let op = problem_response::<400>(op, "Invalid request");
    problem_response::<401>(op, "Authentication required or session expired")
}

pub(crate) fn get_user_setting_docs(op: TransformOperation<'_>) -> TransformOperation<'_> {
    let op = collection_list_docs(
        op,
        "getUserSetting",
        "User Settings",
        "Get one current-user setting",
        "Returns one current-user setting by ID.",
    )
    .input::<Path<ResourceIdPathDoc>>()
    .response_with::<200, Json<UserSettingResponse>, _>(ok_json("User setting details"));
    let op = problem_response::<400>(op, "Invalid request");
    let op = problem_response::<401>(op, "Authentication required or session expired");
    problem_response::<404>(op, "Resource not found")
}

pub(crate) fn update_user_setting_docs(op: TransformOperation<'_>) -> TransformOperation<'_> {
    let op = collection_list_docs(
        op,
        "modifyUserSetting",
        "User Settings",
        "Update one current-user setting",
        "Updates one current-user setting by ID.",
    )
    .input::<(Path<ResourceIdPathDoc>, Json<ModifyUserSettingDoc>)>()
    .response_with::<200, Json<UserSettingResponse>, _>(ok_json("User setting updated"));
    let op = problem_response::<400>(op, "Invalid request");
    let op = problem_response::<401>(op, "Authentication required or session expired");
    problem_response::<404>(op, "Resource not found")
}

#[cfg(test)]
#[path = "identity_test.rs"]
mod identity_test;
