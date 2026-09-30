// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Greenbone AG

//! Identity and access-control domain types and commands.

use std::fmt;

use serde::{Deserialize, Serialize};

use crate::{Pagination, ResourceRef};

/// Common paginated query options used by identity resources.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct IdentityQuery {
    /// Optional GMP filter string.
    pub filter_string: Option<String>,
    /// Optional saved filter identifier.
    pub filter_id: Option<String>,
    /// Requested page number.
    pub page: u32,
    /// Requested page size.
    pub per_page: u32,
}

/// Filter options used by current-user settings.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct UserSettingQuery {
    /// Optional GMP filter string.
    pub filter_string: Option<String>,
    /// Optional saved filter identifier.
    pub filter_id: Option<String>,
}

/// Common resource metadata shared by identity resources.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct IdentityResourceMeta {
    /// Resource identifier.
    pub id: String,
    /// Resource name.
    pub name: String,
    /// Optional comment.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub comment: Option<String>,
    /// Optional owner reference.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub owner: Option<IdentityOwner>,
    /// Optional creation timestamp.
    #[serde(rename = "creationTime", skip_serializing_if = "Option::is_none")]
    pub creation_time: Option<String>,
    /// Optional modification timestamp.
    #[serde(rename = "modificationTime", skip_serializing_if = "Option::is_none")]
    pub modification_time: Option<String>,
    /// Whether the resource is writable.
    pub writable: bool,
    /// Whether the resource is in use.
    #[serde(rename = "inUse")]
    pub in_use: bool,
}

/// Owner metadata exposed by typed gvmd identity responses.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct IdentityOwner {
    /// Owner name. Current gvmd identity responses do not provide an owner id.
    pub name: String,
}

/// Domain user representation.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct User {
    /// Shared resource metadata.
    #[serde(flatten)]
    pub meta: IdentityResourceMeta,
    /// Role references assigned to the user.
    pub roles: Vec<ResourceRef>,
    /// Group references assigned to the user.
    pub groups: Vec<ResourceRef>,
    /// Whether host restrictions act as an allow-list.
    #[serde(rename = "hostsAllow", skip_serializing_if = "Option::is_none")]
    pub hosts_allow: Option<bool>,
    /// Host restriction expression.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hosts: Option<String>,
    /// Optional authentication type.
    #[serde(rename = "authenticationType", skip_serializing_if = "Option::is_none")]
    pub authentication_type: Option<String>,
}

/// Paginated user list response.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct UserPage {
    /// Page items.
    pub data: Vec<User>,
    /// Pagination metadata.
    pub pagination: Pagination,
}

/// User create command.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CreateUserInput {
    /// Name.
    pub name: String,
    /// Optional comment.
    pub comment: Option<String>,
    /// Optional password.
    pub password: Option<String>,
    /// Optional host restriction expression.
    pub hosts: Option<String>,
    /// Assigned role identifiers.
    pub role_ids: Vec<String>,
    /// Optional authentication type.
    pub authentication_type: Option<String>,
}

/// User update command.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct ModifyUserInput {
    /// Optional replacement name.
    pub name: Option<String>,
    /// Optional comment.
    pub comment: Option<String>,
    /// Optional password.
    pub password: Option<String>,
    /// Optional host restriction expression.
    pub hosts: Option<String>,
    /// Assigned role identifiers.
    pub role_ids: Option<Vec<String>>,
    /// Optional authentication type.
    pub authentication_type: Option<String>,
}

/// Domain group representation.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Group {
    /// Shared resource metadata.
    #[serde(flatten)]
    pub meta: IdentityResourceMeta,
    /// Group members represented as gvmd usernames.
    pub users: Vec<String>,
}

/// Paginated group list response.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct GroupPage {
    /// Page items.
    pub data: Vec<Group>,
    /// Pagination metadata.
    pub pagination: Pagination,
}

/// Group create command.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CreateGroupInput {
    /// Name.
    pub name: String,
    /// Optional comment.
    pub comment: Option<String>,
    /// Group members represented as gvmd usernames.
    pub users: Vec<String>,
}

/// Group update command.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct ModifyGroupInput {
    /// Optional comment.
    pub comment: Option<String>,
    /// Group members represented as gvmd usernames.
    pub users: Option<Vec<String>>,
}

/// Domain role representation.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Role {
    /// Shared resource metadata.
    #[serde(flatten)]
    pub meta: IdentityResourceMeta,
    /// Role members represented as gvmd usernames.
    pub users: Vec<String>,
}

/// Paginated role list response.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RolePage {
    /// Page items.
    pub data: Vec<Role>,
    /// Pagination metadata.
    pub pagination: Pagination,
}

/// Role create command.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CreateRoleInput {
    /// Name.
    pub name: String,
    /// Optional comment.
    pub comment: Option<String>,
    /// Role members represented as gvmd usernames.
    pub users: Vec<String>,
}

/// Role update command.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct ModifyRoleInput {
    /// Optional comment.
    pub comment: Option<String>,
    /// Role members represented as gvmd usernames.
    pub users: Option<Vec<String>>,
}

/// Domain permission representation.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Permission {
    /// Shared resource metadata.
    #[serde(flatten)]
    pub meta: IdentityResourceMeta,
    /// Subject kind.
    #[serde(rename = "subjectType", skip_serializing_if = "Option::is_none")]
    pub subject_type: Option<String>,
    /// Subject reference.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub subject: Option<ResourceRef>,
    /// Resource kind.
    #[serde(rename = "resourceType", skip_serializing_if = "Option::is_none")]
    pub resource_type: Option<String>,
    /// Granted resource reference.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub resource: Option<ResourceRef>,
}

/// Paginated permission list response.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PermissionPage {
    /// Page items.
    pub data: Vec<Permission>,
    /// Pagination metadata.
    pub pagination: Pagination,
}

/// Permission create command.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct CreatePermissionInput {
    /// Optional permission name.
    pub name: Option<String>,
    /// Optional comment.
    pub comment: Option<String>,
    /// Optional subject type.
    pub subject_type: Option<String>,
    /// Optional subject identifier.
    pub subject_id: Option<String>,
    /// Optional resource type.
    pub resource_type: Option<String>,
    /// Optional resource identifier.
    pub resource_id: Option<String>,
}

/// Permission update command.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct ModifyPermissionInput {
    /// Optional permission name.
    pub name: Option<String>,
    /// Optional comment.
    pub comment: Option<String>,
    /// Optional subject type.
    pub subject_type: Option<String>,
    /// Optional subject identifier.
    pub subject_id: Option<String>,
    /// Optional resource type.
    pub resource_type: Option<String>,
    /// Optional resource identifier.
    pub resource_id: Option<String>,
}

/// Current-user setting representation.
#[derive(Clone, Deserialize, Eq, PartialEq, Serialize)]
pub struct UserSetting {
    /// Setting identifier.
    pub id: String,
    /// Setting name.
    pub name: String,
    /// Optional setting value.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub value: Option<String>,
    /// Optional setting comment.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub comment: Option<String>,
}

impl fmt::Debug for UserSetting {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("UserSetting")
            .field("id", &self.id)
            .field("name", &self.name)
            .field("value", &self.value.as_ref().map(|_| "<redacted>"))
            .field("comment", &self.comment)
            .finish()
    }
}

/// Current-user settings response.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct UserSettingList {
    /// Settings visible to the current user.
    pub data: Vec<UserSetting>,
}

/// User-setting update command.
#[derive(Clone, Eq, PartialEq)]
pub struct ModifyUserSettingInput {
    /// Setting value to apply.
    pub value: String,
}

impl fmt::Debug for ModifyUserSettingInput {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ModifyUserSettingInput")
            .field("value", &"<redacted>")
            .finish()
    }
}
