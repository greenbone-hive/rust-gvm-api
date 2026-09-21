// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Greenbone AG
use super::super::*;

#[async_trait]
impl IdentityPort for GvmdAdapter {
    async fn list_users(
        &self,
        session_token: &str,
        query: &IdentityQuery,
    ) -> Result<UserPage, GatewayError> {
        let filter_id = query
            .filter_id
            .as_deref()
            .map(parse_entity_id)
            .transpose()?;
        let parsed = self
            .execute_with_session(
                session_token,
                "users.list",
                GetUsersRequest {
                    filter_string: self
                        .paginated_filter_resolving_filter_id(
                            session_token,
                            None,
                            query.filter_string.as_deref(),
                            filter_id.as_ref(),
                            query.page,
                            query.per_page,
                            &[],
                        )
                        .await?,
                    filter_id: None,
                    trash: None,
                    details: Some(true),
                },
            )
            .await?;
        let items = parsed
            .items
            .into_iter()
            .map(user_from_gmp)
            .collect::<Vec<_>>();
        let total = gvmd_total(parsed.counts.filtered, parsed.counts.total, items.len());

        Ok(UserPage {
            data: items,
            pagination: paged_pagination(total, query.page, query.per_page),
        })
    }

    async fn create_user(
        &self,
        session_token: &str,
        input: CreateUserInput,
    ) -> Result<String, GatewayError> {
        let role_ids = input
            .role_ids
            .into_iter()
            .map(|value| parse_entity_id(&value))
            .collect::<Result<Vec<_>, _>>()?;
        let auth_type = input
            .authentication_type
            .as_deref()
            .map(parse_user_auth_type)
            .transpose()?;
        let mut request = CreateUserRequest::new(input.name);
        request.comment = input.comment;
        request.password = input.password;
        request.host_access = input.hosts.map(UserHostAccess::allow);
        request.role_ids = role_ids;
        request.auth_source = auth_type;
        let parsed = self
            .execute_with_session(session_token, "users.create", request)
            .await?;
        Ok(parsed.id.to_string())
    }

    async fn get_user(&self, session_token: &str, id: &str) -> Result<User, GatewayError> {
        Ok(user_from_gmp(self.get_gmp_user(session_token, id).await?))
    }

    async fn modify_user(
        &self,
        session_token: &str,
        id: &str,
        input: ModifyUserInput,
    ) -> Result<User, GatewayError> {
        let user_id = parse_entity_id(id)?;
        let ModifyUserInput {
            name,
            comment,
            password,
            hosts,
            role_ids,
            authentication_type,
        } = input;
        let host_access = match hosts {
            Some(hosts) => UserHostAccess::allow(hosts),
            None => self
                .get_gmp_user(session_token, id)
                .await?
                .host_access()
                .unwrap_or_else(|| UserHostAccess::allow("")),
        };
        let role_ids = role_ids
            .map(|role_ids| {
                role_ids
                    .into_iter()
                    .map(|value| parse_entity_id(&value))
                    .collect::<Result<Vec<_>, _>>()
                    .map(CollectionUpdate::from)
            })
            .transpose()?
            .unwrap_or_default();
        let auth_type = authentication_type
            .as_deref()
            .map(parse_user_auth_type)
            .transpose()?;
        let mut request = ModifyUserRequest::new(user_id, host_access);
        request.new_name = name;
        request.comment = comment;
        request.password = password;
        request.role_ids = role_ids;
        request.auth_source = auth_type;
        self.execute_with_session(session_token, "users.modify", request)
            .await?;
        self.get_user(session_token, id).await
    }

    async fn delete_user(
        &self,
        session_token: &str,
        id: &str,
        _ultimate: bool,
    ) -> Result<(), GatewayError> {
        self.execute_with_session(
            session_token,
            "users.delete",
            DeleteUserRequest::new(parse_entity_id(id)?),
        )
        .await?;
        Ok(())
    }

    async fn list_groups(
        &self,
        session_token: &str,
        query: &IdentityQuery,
    ) -> Result<GroupPage, GatewayError> {
        let filter_id = query
            .filter_id
            .as_deref()
            .map(parse_entity_id)
            .transpose()?;
        let parsed = self
            .execute_with_session(
                session_token,
                "groups.list",
                GetGroupsRequest {
                    filter_string: self
                        .paginated_filter_resolving_filter_id(
                            session_token,
                            None,
                            query.filter_string.as_deref(),
                            filter_id.as_ref(),
                            query.page,
                            query.per_page,
                            &[],
                        )
                        .await?,
                    filter_id: None,
                    trash: None,
                    details: Some(true),
                },
            )
            .await?;
        let items = parsed
            .items
            .into_iter()
            .map(group_from_gmp)
            .collect::<Vec<_>>();
        let total = gvmd_total(parsed.counts.filtered, parsed.counts.total, items.len());

        Ok(GroupPage {
            data: items,
            pagination: paged_pagination(total, query.page, query.per_page),
        })
    }

    async fn create_group(
        &self,
        session_token: &str,
        input: CreateGroupInput,
    ) -> Result<String, GatewayError> {
        let mut request = CreateGroupRequest::new(input.name);
        request.comment = input.comment;
        request.users = input.users;
        let parsed = self
            .execute_with_session(session_token, "groups.create", request)
            .await?;
        Ok(parsed.id.to_string())
    }

    async fn get_group(&self, session_token: &str, id: &str) -> Result<Group, GatewayError> {
        let parsed = self
            .execute_with_session(
                session_token,
                "groups.get",
                GetGroupRequest::new(parse_entity_id(id)?),
            )
            .await?;
        let group = parsed
            .items
            .into_iter()
            .next()
            .ok_or_else(|| GatewayError::NotFound(format!("group {id} not found")))?;
        Ok(group_from_gmp(group))
    }

    async fn modify_group(
        &self,
        session_token: &str,
        id: &str,
        input: ModifyGroupInput,
    ) -> Result<Group, GatewayError> {
        let current = self.get_group(session_token, id).await?;
        let request = ModifyGroupRequest::new(
            parse_entity_id(id)?,
            current.meta.name,
            input.comment.or(current.meta.comment).unwrap_or_default(),
            input.users.unwrap_or(current.users),
        );
        self.execute_with_session(session_token, "groups.modify", request)
            .await?;
        self.get_group(session_token, id).await
    }

    async fn delete_group(
        &self,
        session_token: &str,
        id: &str,
        ultimate: bool,
    ) -> Result<(), GatewayError> {
        self.execute_with_session(
            session_token,
            "groups.delete",
            DeleteGroupRequest::new(parse_entity_id(id)?, ultimate),
        )
        .await?;
        Ok(())
    }

    async fn list_roles(
        &self,
        session_token: &str,
        query: &IdentityQuery,
    ) -> Result<RolePage, GatewayError> {
        let filter_id = query
            .filter_id
            .as_deref()
            .map(parse_entity_id)
            .transpose()?;
        let filter_string = self
            .paginated_filter_resolving_filter_id(
                session_token,
                None,
                query.filter_string.as_deref(),
                filter_id.as_ref(),
                query.page,
                query.per_page,
                &[],
            )
            .await?;
        let parsed = self
            .execute_with_session(
                session_token,
                "roles.list",
                GetRolesRequest {
                    filter_string,
                    filter_id: None,
                    trash: None,
                    details: Some(true),
                },
            )
            .await?;
        let items = parsed
            .items
            .into_iter()
            .map(role_from_gmp)
            .collect::<Vec<_>>();
        let total = gvmd_total(parsed.counts.filtered, parsed.counts.total, items.len());

        Ok(RolePage {
            data: items,
            pagination: paged_pagination(total, query.page, query.per_page),
        })
    }

    async fn create_role(
        &self,
        session_token: &str,
        input: CreateRoleInput,
    ) -> Result<String, GatewayError> {
        let mut request = CreateRoleRequest::new(input.name);
        request.comment = input.comment;
        request.users = input.users;
        let parsed = self
            .execute_with_session(session_token, "roles.create", request)
            .await?;
        Ok(parsed.id.to_string())
    }

    async fn get_role(&self, session_token: &str, id: &str) -> Result<Role, GatewayError> {
        let parsed = self
            .execute_with_session(
                session_token,
                "roles.get",
                GetRoleRequest::new(parse_entity_id(id)?),
            )
            .await?;
        let role = parsed
            .items
            .into_iter()
            .next()
            .ok_or_else(|| GatewayError::NotFound(format!("role {id} not found")))?;
        Ok(role_from_gmp(role))
    }

    async fn modify_role(
        &self,
        session_token: &str,
        id: &str,
        input: ModifyRoleInput,
    ) -> Result<Role, GatewayError> {
        let current = self.get_role(session_token, id).await?;
        let request = ModifyRoleRequest::new(
            parse_entity_id(id)?,
            current.meta.name,
            input.comment.or(current.meta.comment).unwrap_or_default(),
            input.users.unwrap_or(current.users),
        );
        self.execute_with_session(session_token, "roles.modify", request)
            .await?;
        self.get_role(session_token, id).await
    }

    async fn delete_role(
        &self,
        session_token: &str,
        id: &str,
        ultimate: bool,
    ) -> Result<(), GatewayError> {
        self.execute_with_session(
            session_token,
            "roles.delete",
            DeleteRoleRequest::new(parse_entity_id(id)?, ultimate),
        )
        .await?;
        Ok(())
    }

    async fn list_permissions(
        &self,
        session_token: &str,
        query: &IdentityQuery,
    ) -> Result<PermissionPage, GatewayError> {
        let filter_id = query
            .filter_id
            .as_deref()
            .map(parse_entity_id)
            .transpose()?;
        let filter_string = self
            .paginated_filter_resolving_filter_id(
                session_token,
                None,
                query.filter_string.as_deref(),
                filter_id.as_ref(),
                query.page,
                query.per_page,
                &[],
            )
            .await?;
        let parsed = self
            .execute_with_session(
                session_token,
                "permissions.list",
                GetPermissionsRequest {
                    filter_string,
                    filter_id: None,
                    trash: None,
                    details: Some(true),
                },
            )
            .await?;
        let items = parsed
            .items
            .into_iter()
            .map(permission_from_gmp)
            .collect::<Vec<_>>();
        let total = gvmd_total(parsed.counts.filtered, parsed.counts.total, items.len());

        Ok(PermissionPage {
            data: items,
            pagination: paged_pagination(total, query.page, query.per_page),
        })
    }

    async fn create_permission(
        &self,
        session_token: &str,
        input: CreatePermissionInput,
    ) -> Result<String, GatewayError> {
        let name = input
            .name
            .ok_or_else(|| GatewayError::InvalidInput("name is required".to_string()))?;
        let subject_id = input
            .subject_id
            .as_deref()
            .ok_or_else(|| GatewayError::InvalidInput("subjectId is required".to_string()))
            .and_then(parse_entity_id)?;
        let subject_type = input
            .subject_type
            .as_deref()
            .ok_or_else(|| GatewayError::InvalidInput("subjectType is required".to_string()))
            .and_then(parse_permission_subject_type)?;
        let mut request =
            CreatePermissionRequest::new(name, PermissionSubject::new(subject_id, subject_type));
        request.comment = input.comment;
        request.resource = match input.resource_id.as_deref() {
            Some(resource_id) => {
                let mut resource = PermissionResource::new(parse_entity_id(resource_id)?);
                resource.resource_type = input.resource_type;
                Some(resource)
            }
            None if input.resource_type.is_some() => {
                return Err(GatewayError::InvalidInput(
                    "resourceType requires resourceId".to_string(),
                ));
            }
            None => None,
        };
        let parsed = self
            .execute_with_session(session_token, "permissions.create", request)
            .await?;
        Ok(parsed.id.to_string())
    }

    async fn get_permission(
        &self,
        session_token: &str,
        id: &str,
    ) -> Result<Permission, GatewayError> {
        let parsed = self
            .execute_with_session(
                session_token,
                "permissions.get",
                GetPermissionRequest::new(parse_entity_id(id)?),
            )
            .await?;
        let permission = parsed
            .items
            .into_iter()
            .next()
            .ok_or_else(|| GatewayError::NotFound(format!("permission {id} not found")))?;
        Ok(permission_from_gmp(permission))
    }

    async fn modify_permission(
        &self,
        session_token: &str,
        id: &str,
        input: ModifyPermissionInput,
    ) -> Result<Permission, GatewayError> {
        let mut request = ModifyPermissionRequest::new(parse_entity_id(id)?);
        request.comment = input.comment;
        request.name = input.name;
        request.resource_id = input
            .resource_id
            .as_deref()
            .map(parse_entity_id)
            .transpose()?
            .map(ScalarUpdate::Set)
            .unwrap_or_default();
        request.resource_type = input.resource_type;
        request.subject_type = input
            .subject_type
            .as_deref()
            .map(parse_permission_subject_type)
            .transpose()?;
        request.subject_id = input
            .subject_id
            .as_deref()
            .map(parse_entity_id)
            .transpose()?;
        self.execute_with_session(session_token, "permissions.modify", request)
            .await?;
        self.get_permission(session_token, id).await
    }

    async fn delete_permission(
        &self,
        session_token: &str,
        id: &str,
        ultimate: bool,
    ) -> Result<(), GatewayError> {
        self.execute_with_session(
            session_token,
            "permissions.delete",
            DeletePermissionRequest::new(parse_entity_id(id)?, ultimate),
        )
        .await?;
        Ok(())
    }

    async fn list_user_settings(
        &self,
        session_token: &str,
        query: &UserSettingQuery,
    ) -> Result<UserSettingList, GatewayError> {
        let filter_id = query
            .filter_id
            .as_deref()
            .map(parse_entity_id)
            .transpose()?;
        let filter = self
            .filter_resolving_filter_id(
                session_token,
                None,
                query.filter_string.as_deref(),
                filter_id.as_ref(),
                &[],
            )
            .await?;
        let parsed = self
            .execute_with_session(
                session_token,
                "user_settings.list",
                GetUserSettingsRequest::new(GetUserSettingsOpts {
                    filter,
                    filter_id: None,
                }),
            )
            .await?;
        let mut items = parsed
            .settings
            .into_iter()
            .map(user_setting_from_gmp)
            .collect::<Vec<_>>();
        items.sort_by(|left, right| left.name.cmp(&right.name));

        Ok(UserSettingList { data: items })
    }

    async fn get_user_setting(
        &self,
        session_token: &str,
        id: &str,
    ) -> Result<UserSetting, GatewayError> {
        let parsed = self
            .execute_with_session(
                session_token,
                "user_settings.get",
                GetUserSettingRequest::new(parse_entity_id(id)?),
            )
            .await?;
        parsed
            .settings
            .into_iter()
            .next()
            .map(user_setting_from_gmp)
            .ok_or_else(|| GatewayError::NotFound(format!("user setting {id} not found")))
    }

    async fn modify_user_setting(
        &self,
        session_token: &str,
        id: &str,
        input: ModifyUserSettingInput,
    ) -> Result<UserSetting, GatewayError> {
        self.execute_with_session(
            session_token,
            "user_settings.modify",
            ModifyUserSettingRequest::new(
                parse_entity_id(id)?,
                ModifyUserSettingOpts { value: input.value },
            ),
        )
        .await?;
        self.get_user_setting(session_token, id).await
    }
}
