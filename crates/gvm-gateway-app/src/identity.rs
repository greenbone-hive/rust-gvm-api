// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Greenbone AG

//! Identity and access-control use cases.

use gvm_gateway_domain::{
    CreateGroupInput, CreatePermissionInput, CreateRoleInput, CreateUserInput, GatewayError, Group,
    GroupPage, IdentityQuery, ModifyGroupInput, ModifyPermissionInput, ModifyRoleInput,
    ModifyUserInput, ModifyUserSettingInput, Permission, PermissionPage, Role, RolePage, User,
    UserPage, UserSetting, UserSettingList, UserSettingQuery,
};

use crate::GatewayService;

impl GatewayService {
    /// Lists users for an authenticated session.
    pub async fn list_users(
        &self,
        session_token: &str,
        query: IdentityQuery,
    ) -> Result<UserPage, GatewayError> {
        self.execute_with_resource(
            "users.list",
            session_token,
            "list",
            "user",
            None,
            |session| async move { self.identity.list_users(&session.token, &query).await },
        )
        .await
    }

    /// Creates a new user for an authenticated session.
    pub async fn create_user(
        &self,
        session_token: &str,
        input: CreateUserInput,
    ) -> Result<String, GatewayError> {
        self.execute_with_resource(
            "users.create",
            session_token,
            "create",
            "user",
            None,
            |session| async move { self.identity.create_user(&session.token, input).await },
        )
        .await
    }

    /// Fetches a user for an authenticated session.
    pub async fn get_user(&self, session_token: &str, id: &str) -> Result<User, GatewayError> {
        self.execute_with_resource(
            "users.get",
            session_token,
            "read",
            "user",
            Some(id),
            |session| async move { self.identity.get_user(&session.token, id).await },
        )
        .await
    }

    /// Modifies a user for an authenticated session.
    pub async fn modify_user(
        &self,
        session_token: &str,
        id: &str,
        input: ModifyUserInput,
    ) -> Result<User, GatewayError> {
        self.execute_with_resource(
            "users.modify",
            session_token,
            "modify",
            "user",
            Some(id),
            |session| async move { self.identity.modify_user(&session.token, id, input).await },
        )
        .await
    }

    /// Deletes a user for an authenticated session.
    pub async fn delete_user(&self, session_token: &str, id: &str) -> Result<(), GatewayError> {
        self.execute_with_resource(
            "users.delete",
            session_token,
            "delete",
            "user",
            Some(id),
            |session| async move { self.identity.delete_user(&session.token, id).await },
        )
        .await
    }

    /// Lists groups for an authenticated session.
    pub async fn list_groups(
        &self,
        session_token: &str,
        query: IdentityQuery,
    ) -> Result<GroupPage, GatewayError> {
        self.execute_with_resource(
            "groups.list",
            session_token,
            "list",
            "group",
            None,
            |session| async move { self.identity.list_groups(&session.token, &query).await },
        )
        .await
    }

    /// Creates a new group for an authenticated session.
    pub async fn create_group(
        &self,
        session_token: &str,
        input: CreateGroupInput,
    ) -> Result<String, GatewayError> {
        self.execute_with_resource(
            "groups.create",
            session_token,
            "create",
            "group",
            None,
            |session| async move { self.identity.create_group(&session.token, input).await },
        )
        .await
    }

    /// Fetches a group for an authenticated session.
    pub async fn get_group(&self, session_token: &str, id: &str) -> Result<Group, GatewayError> {
        self.execute_with_resource(
            "groups.get",
            session_token,
            "read",
            "group",
            Some(id),
            |session| async move { self.identity.get_group(&session.token, id).await },
        )
        .await
    }

    /// Modifies a group for an authenticated session.
    pub async fn modify_group(
        &self,
        session_token: &str,
        id: &str,
        input: ModifyGroupInput,
    ) -> Result<Group, GatewayError> {
        self.execute_with_resource(
            "groups.modify",
            session_token,
            "modify",
            "group",
            Some(id),
            |session| async move { self.identity.modify_group(&session.token, id, input).await },
        )
        .await
    }

    /// Deletes a group for an authenticated session.
    pub async fn delete_group(
        &self,
        session_token: &str,
        id: &str,
        ultimate: bool,
    ) -> Result<(), GatewayError> {
        self.execute_with_resource(
            "groups.delete",
            session_token,
            "delete",
            "group",
            Some(id),
            |session| async move {
                self.identity
                    .delete_group(&session.token, id, ultimate)
                    .await
            },
        )
        .await
    }

    /// Lists roles for an authenticated session.
    pub async fn list_roles(
        &self,
        session_token: &str,
        query: IdentityQuery,
    ) -> Result<RolePage, GatewayError> {
        self.execute_with_resource(
            "roles.list",
            session_token,
            "list",
            "role",
            None,
            |session| async move { self.identity.list_roles(&session.token, &query).await },
        )
        .await
    }

    /// Creates a new role for an authenticated session.
    pub async fn create_role(
        &self,
        session_token: &str,
        input: CreateRoleInput,
    ) -> Result<String, GatewayError> {
        self.execute_with_resource(
            "roles.create",
            session_token,
            "create",
            "role",
            None,
            |session| async move { self.identity.create_role(&session.token, input).await },
        )
        .await
    }

    /// Fetches a role for an authenticated session.
    pub async fn get_role(&self, session_token: &str, id: &str) -> Result<Role, GatewayError> {
        self.execute_with_resource(
            "roles.get",
            session_token,
            "read",
            "role",
            Some(id),
            |session| async move { self.identity.get_role(&session.token, id).await },
        )
        .await
    }

    /// Modifies a role for an authenticated session.
    pub async fn modify_role(
        &self,
        session_token: &str,
        id: &str,
        input: ModifyRoleInput,
    ) -> Result<Role, GatewayError> {
        self.execute_with_resource(
            "roles.modify",
            session_token,
            "modify",
            "role",
            Some(id),
            |session| async move { self.identity.modify_role(&session.token, id, input).await },
        )
        .await
    }

    /// Deletes a role for an authenticated session.
    pub async fn delete_role(
        &self,
        session_token: &str,
        id: &str,
        ultimate: bool,
    ) -> Result<(), GatewayError> {
        self.execute_with_resource(
            "roles.delete",
            session_token,
            "delete",
            "role",
            Some(id),
            |session| async move {
                self.identity
                    .delete_role(&session.token, id, ultimate)
                    .await
            },
        )
        .await
    }

    /// Lists permissions for an authenticated session.
    pub async fn list_permissions(
        &self,
        session_token: &str,
        query: IdentityQuery,
    ) -> Result<PermissionPage, GatewayError> {
        self.execute_with_resource(
            "permissions.list",
            session_token,
            "list",
            "permission",
            None,
            |session| async move { self.identity.list_permissions(&session.token, &query).await },
        )
        .await
    }

    /// Creates a new permission for an authenticated session.
    pub async fn create_permission(
        &self,
        session_token: &str,
        input: CreatePermissionInput,
    ) -> Result<String, GatewayError> {
        self.execute_with_resource(
            "permissions.create",
            session_token,
            "create",
            "permission",
            None,
            |session| async move { self.identity.create_permission(&session.token, input).await },
        )
        .await
    }

    /// Fetches a permission for an authenticated session.
    pub async fn get_permission(
        &self,
        session_token: &str,
        id: &str,
    ) -> Result<Permission, GatewayError> {
        self.execute_with_resource(
            "permissions.get",
            session_token,
            "read",
            "permission",
            Some(id),
            |session| async move { self.identity.get_permission(&session.token, id).await },
        )
        .await
    }

    /// Modifies a permission for an authenticated session.
    pub async fn modify_permission(
        &self,
        session_token: &str,
        id: &str,
        input: ModifyPermissionInput,
    ) -> Result<Permission, GatewayError> {
        self.execute_with_resource(
            "permissions.modify",
            session_token,
            "modify",
            "permission",
            Some(id),
            |session| async move {
                self.identity
                    .modify_permission(&session.token, id, input)
                    .await
            },
        )
        .await
    }

    /// Deletes a permission for an authenticated session.
    pub async fn delete_permission(
        &self,
        session_token: &str,
        id: &str,
        ultimate: bool,
    ) -> Result<(), GatewayError> {
        self.execute_with_resource(
            "permissions.delete",
            session_token,
            "delete",
            "permission",
            Some(id),
            |session| async move {
                self.identity
                    .delete_permission(&session.token, id, ultimate)
                    .await
            },
        )
        .await
    }

    /// Lists current-user settings for an authenticated session.
    pub async fn list_user_settings(
        &self,
        session_token: &str,
        query: UserSettingQuery,
    ) -> Result<UserSettingList, GatewayError> {
        self.execute_with_resource(
            "user_settings.list",
            session_token,
            "list",
            "user_setting",
            None,
            |session| async move {
                self.identity
                    .list_user_settings(&session.token, &query)
                    .await
            },
        )
        .await
    }

    /// Fetches one current-user setting for an authenticated session.
    pub async fn get_user_setting(
        &self,
        session_token: &str,
        id: &str,
    ) -> Result<UserSetting, GatewayError> {
        self.execute_with_resource(
            "user_settings.get",
            session_token,
            "read",
            "user_setting",
            Some(id),
            |session| async move { self.identity.get_user_setting(&session.token, id).await },
        )
        .await
    }

    /// Modifies one current-user setting for an authenticated session.
    pub async fn modify_user_setting(
        &self,
        session_token: &str,
        id: &str,
        input: ModifyUserSettingInput,
    ) -> Result<UserSetting, GatewayError> {
        self.execute_with_resource(
            "user_settings.modify",
            session_token,
            "modify",
            "user_setting",
            Some(id),
            |session| async move {
                self.identity
                    .modify_user_setting(&session.token, id, input)
                    .await
            },
        )
        .await
    }
}
