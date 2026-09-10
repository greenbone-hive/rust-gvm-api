// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Greenbone AG
use super::super::*;

#[async_trait]
impl ScanConfigPort for GvmdAdapter {
    async fn list_configs(
        &self,
        session_token: &str,
        query: &GenericConfigQuery,
    ) -> Result<GenericConfigPage, GatewayError> {
        let client = self.session_client(session_token)?;
        let filter_id = query
            .filter_id
            .as_deref()
            .map(|value| {
                EntityId::new(value)
                    .map_err(|_| GatewayError::InvalidInput("invalid filterId".to_string()))
            })
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
        let response = client
            .lock()
            .await?
            .call(get_configs(GetConfigsOpts {
                config_id: None,
                filter_string,
                filter_id: None,
                trash: None,
                details: Some(true),
                families: None,
                preferences: None,
                tasks: None,
                usage_type: query.usage_type.as_deref().map(parse_config_usage_type),
            }))
            .await
            .map_err(map_gvm_error)?;
        let parsed = GetConfigsResponse::from_response(&response).map_err(map_parse_error)?;
        let mut items = parsed
            .items
            .into_iter()
            .map(generic_config_from_gmp)
            .collect::<Vec<_>>();
        items.sort_by(|left, right| {
            left.usage_type
                .cmp(&right.usage_type)
                .then_with(|| left.name.cmp(&right.name))
                .then_with(|| left.id.cmp(&right.id))
        });
        let total = gvmd_total(parsed.counts.filtered, parsed.counts.total, items.len());

        Ok(GenericConfigPage {
            data: items,
            pagination: paged_pagination(total, query.page, query.per_page),
        })
    }

    async fn get_config(
        &self,
        session_token: &str,
        id: &str,
    ) -> Result<GenericConfig, GatewayError> {
        let client = self.session_client(session_token)?;
        let response = client
            .lock()
            .await?
            .call(get_config(
                &parse_entity_id(id)?,
                GetConfigOpts {
                    details: Some(true),
                    families: None,
                    preferences: None,
                    tasks: None,
                    usage_type: None,
                },
            ))
            .await
            .map_err(map_gvm_error)?;
        let parsed = GetConfigsResponse::from_response(&response).map_err(map_parse_error)?;
        parsed
            .items
            .into_iter()
            .next()
            .map(generic_config_from_gmp)
            .ok_or_else(|| GatewayError::NotFound(format!("config {id} not found")))
    }

    async fn delete_config(
        &self,
        session_token: &str,
        id: &str,
        ultimate: bool,
    ) -> Result<(), GatewayError> {
        let client = self.session_client(session_token)?;
        let response = client
            .lock()
            .await?
            .call(delete_config(
                &parse_entity_id(id)?,
                DeleteConfigOpts {
                    ultimate: ultimate.then_some(true),
                },
            ))
            .await
            .map_err(map_gvm_error)?;
        ActionResponse::from_response(&response).map_err(map_parse_error)?;
        Ok(())
    }

    async fn clone_config(&self, session_token: &str, id: &str) -> Result<String, GatewayError> {
        let client = self.session_client(session_token)?;
        let response = client
            .lock()
            .await?
            .call(clone_config(
                &parse_entity_id(id)?,
                CloneConfigOpts::default(),
            ))
            .await
            .map_err(map_gvm_error)?;
        let parsed = CreateConfigResponse::from_response(&response).map_err(map_parse_error)?;
        Ok(parsed.id.to_string())
    }

    async fn list_scan_configs(
        &self,
        session_token: &str,
        query: &ScanConfigQuery,
    ) -> Result<ScanConfigPage, GatewayError> {
        let client = self.session_client(session_token)?;
        let filter_id = query
            .filter_id
            .as_deref()
            .map(|value| {
                EntityId::new(value)
                    .map_err(|_| GatewayError::InvalidInput("invalid filterId".to_string()))
            })
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
        let response = client
            .lock()
            .await?
            .call(get_scan_configs(GetScanConfigsOpts {
                filter_string,
                filter_id: None,
                trash: None,
                details: Some(true),
            }))
            .await
            .map_err(map_gvm_error)?;
        let parsed = GetScanConfigsResponse::from_response(&response).map_err(map_parse_error)?;
        let items = parsed
            .items
            .into_iter()
            .map(scan_config_from_gmp)
            .collect::<Vec<_>>();
        let total = gvmd_total(parsed.counts.filtered, parsed.counts.total, items.len());

        Ok(ScanConfigPage {
            data: items,
            pagination: paged_pagination(total, query.page, query.per_page),
        })
    }

    async fn create_scan_config(
        &self,
        session_token: &str,
        input: CreateScanConfigInput,
    ) -> Result<String, GatewayError> {
        let client = self.session_client(session_token)?;
        let base_id = input
            .base_scan_config_id
            .as_deref()
            .map(parse_entity_id)
            .transpose()?;
        let response = client
            .lock()
            .await?
            .call(create_scan_config(
                &input.name,
                base_id.as_ref(),
                ConfigOpts {
                    comment: input.comment,
                    usage_type: None,
                },
            ))
            .await
            .map_err(map_gvm_error)?;
        let parsed = CreateScanConfigResponse::from_response(&response).map_err(map_parse_error)?;
        Ok(parsed.id.to_string())
    }

    async fn get_scan_config(
        &self,
        session_token: &str,
        id: &str,
    ) -> Result<ScanConfig, GatewayError> {
        let client = self.session_client(session_token)?;
        let response = client
            .lock()
            .await?
            .call(get_scan_config(&parse_entity_id(id)?))
            .await
            .map_err(map_gvm_error)?;
        let parsed = GetScanConfigsResponse::from_response(&response).map_err(map_parse_error)?;
        parsed
            .items
            .into_iter()
            .next()
            // A policy shares the config resource family but must not be
            // readable through the scan-config route; treat it as absent so the
            // discriminator holds symmetrically with `get_policy`.
            .filter(|item| item.usage_type.as_deref() != Some("policy"))
            .map(scan_config_from_gmp)
            .ok_or_else(|| GatewayError::NotFound(format!("scan config {id} not found")))
    }

    async fn modify_scan_config(
        &self,
        session_token: &str,
        id: &str,
        input: ModifyScanConfigInput,
    ) -> Result<ScanConfig, GatewayError> {
        let client = self.session_client(session_token)?;
        let config_id = parse_entity_id(id)?;
        let response = client
            .lock()
            .await?
            .call(modify_config_generic(
                &config_id,
                ModifyConfigOpts {
                    name: input.name,
                    comment: input.comment,
                    usage_type: Some(ConfigUsageType::Scan),
                },
            ))
            .await
            .map_err(map_gvm_error)?;
        let _ = ActionResponse::from_response(&response).map_err(map_parse_error)?;
        drop(client);
        self.get_scan_config(session_token, id).await
    }

    async fn delete_scan_config(
        &self,
        session_token: &str,
        id: &str,
        ultimate: bool,
    ) -> Result<(), GatewayError> {
        let client = self.session_client(session_token)?;
        let response = client
            .lock()
            .await?
            .call(delete_scan_config(&parse_entity_id(id)?, ultimate))
            .await
            .map_err(map_gvm_error)?;
        let _ = ActionResponse::from_response(&response).map_err(map_parse_error)?;
        Ok(())
    }

    async fn list_scan_config_nvts(
        &self,
        session_token: &str,
        id: &str,
        query: &ScanConfigNvtQuery,
    ) -> Result<ScanConfigNvtPage, GatewayError> {
        let client = self.session_client(session_token)?;
        let response = client
            .lock()
            .await?
            .call(get_scan_config_nvts(GetNvtsOpts {
                filter_string: paginated_filter(None, None, query.page, query.per_page)?,
                filter_id: None,
                details: Some(true),
                preferences: Some(true),
                preference_count: Some(true),
                timeout: Some(true),
                config_id: Some(parse_entity_id(id)?),
                preferences_config_id: Some(parse_entity_id(id)?),
                family: query.family.clone(),
                sort_order: Some("ascending".to_string()),
                sort_field: Some("name".to_string()),
            }))
            .await
            .map_err(map_gvm_error)?;
        let parsed = GetNvtsResponse::from_response(&response).map_err(map_parse_error)?;
        let items = parsed
            .items
            .into_iter()
            .map(nvt_from_gmp)
            .collect::<Vec<_>>();
        let total = gvmd_total(parsed.counts.filtered, parsed.counts.total, items.len());
        Ok(ScanConfigNvtPage {
            data: items,
            pagination: paged_pagination(total, query.page, query.per_page),
        })
    }

    async fn get_scan_config_nvt(
        &self,
        session_token: &str,
        id: &str,
        oid: &str,
    ) -> Result<Nvt, GatewayError> {
        let client = self.session_client(session_token)?;
        let response = client
            .lock()
            .await?
            .call(get_scan_config_nvts(GetNvtsOpts {
                filter_string: Some(format!("oid={oid}")),
                filter_id: None,
                details: Some(true),
                preferences: Some(true),
                preference_count: Some(true),
                timeout: Some(true),
                config_id: Some(parse_entity_id(id)?),
                preferences_config_id: Some(parse_entity_id(id)?),
                family: None,
                sort_order: None,
                sort_field: None,
            }))
            .await
            .map_err(map_gvm_error)?;
        let parsed = GetNvtsResponse::from_response(&response).map_err(map_parse_error)?;
        parsed
            .items
            .into_iter()
            .find(|item| item.oid == oid)
            .map(nvt_from_gmp)
            .ok_or_else(|| {
                GatewayError::NotFound(format!("NVT {oid} not selected by scan config {id}"))
            })
    }

    async fn list_scan_config_preferences(
        &self,
        session_token: &str,
        id: &str,
        query: &ScanConfigPreferenceQuery,
    ) -> Result<Vec<ScanConfigPreference>, GatewayError> {
        let client = self.session_client(session_token)?;
        let response = client
            .lock()
            .await?
            .call(get_scan_config_preferences(GetScanConfigPreferencesOpts {
                nvt_oid: query.nvt_oid.clone(),
                config_id: Some(parse_entity_id(id)?),
            }))
            .await
            .map_err(map_gvm_error)?;
        let parsed =
            GetScanConfigPreferencesResponse::from_response(&response).map_err(map_parse_error)?;
        Ok(parsed.items.into_iter().map(preference_from_gmp).collect())
    }

    async fn get_scan_config_preference(
        &self,
        session_token: &str,
        id: &str,
        name: &str,
        query: &ScanConfigPreferenceQuery,
    ) -> Result<ScanConfigPreference, GatewayError> {
        let client = self.session_client(session_token)?;
        let response = client
            .lock()
            .await?
            .call(get_scan_config_preference(
                name,
                GetScanConfigPreferencesOpts {
                    nvt_oid: query.nvt_oid.clone(),
                    config_id: Some(parse_entity_id(id)?),
                },
            ))
            .await
            .map_err(map_gvm_error)?;
        let parsed =
            GetScanConfigPreferencesResponse::from_response(&response).map_err(map_parse_error)?;
        parsed
            .items
            .into_iter()
            .next()
            .map(preference_from_gmp)
            .ok_or_else(|| GatewayError::NotFound(format!("preference {name} not found")))
    }

    async fn set_scan_config_nvt_selection(
        &self,
        session_token: &str,
        id: &str,
        family: &str,
        nvt_oids: Vec<String>,
    ) -> Result<(), GatewayError> {
        let client = self.session_client(session_token)?;
        let response = client
            .lock()
            .await?
            .call(modify_scan_config_set_nvt_selection(
                &parse_entity_id(id)?,
                family,
                &nvt_oids,
            ))
            .await
            .map_err(map_gvm_error)?;
        ActionResponse::from_response(&response).map_err(map_parse_error)?;
        Ok(())
    }

    async fn set_scan_config_family_selection(
        &self,
        session_token: &str,
        id: &str,
        input: SetScanConfigFamilySelectionInput,
    ) -> Result<(), GatewayError> {
        let families = input
            .families
            .into_iter()
            .map(|family| NvtFamilySelection {
                name: family.name,
                growing: family.growing,
                all: family.all,
            })
            .collect::<Vec<_>>();
        let client = self.session_client(session_token)?;
        let response = client
            .lock()
            .await?
            .call(modify_scan_config_set_family_selection(
                &parse_entity_id(id)?,
                &families,
                input.auto_add_new_families,
            ))
            .await
            .map_err(map_gvm_error)?;
        ActionResponse::from_response(&response).map_err(map_parse_error)?;
        Ok(())
    }

    async fn set_scan_config_preference(
        &self,
        session_token: &str,
        id: &str,
        name: &str,
        nvt_oid: Option<String>,
        value: Option<String>,
    ) -> Result<(), GatewayError> {
        let config_id = parse_entity_id(id)?;
        let client = self.session_client(session_token)?;
        let response = if let Some(nvt_oid) = nvt_oid {
            client
                .lock()
                .await?
                .call(modify_scan_config_set_nvt_preference(
                    &config_id,
                    name,
                    &nvt_oid,
                    value.as_deref(),
                ))
                .await
        } else {
            client
                .lock()
                .await?
                .call(modify_scan_config_set_scanner_preference(
                    &config_id,
                    name,
                    value.as_deref(),
                ))
                .await
        }
        .map_err(map_gvm_error)?;
        ActionResponse::from_response(&response).map_err(map_parse_error)?;
        Ok(())
    }

    async fn list_policies(
        &self,
        session_token: &str,
        query: &ScanConfigQuery,
    ) -> Result<ScanConfigPage, GatewayError> {
        let client = self.session_client(session_token)?;
        let filter_id = query
            .filter_id
            .as_deref()
            .map(|value| {
                EntityId::new(value)
                    .map_err(|_| GatewayError::InvalidInput("invalid filterId".to_string()))
            })
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
        let response = client
            .lock()
            .await?
            .call(get_policies(GetScanConfigsOpts {
                filter_string,
                filter_id: None,
                trash: None,
                details: Some(true),
            }))
            .await
            .map_err(map_gvm_error)?;
        let parsed = GetScanConfigsResponse::from_response(&response).map_err(map_parse_error)?;
        let items = parsed
            .items
            .into_iter()
            .map(scan_config_from_gmp)
            .collect::<Vec<_>>();
        let total = gvmd_total(parsed.counts.filtered, parsed.counts.total, items.len());

        Ok(ScanConfigPage {
            data: items,
            pagination: paged_pagination(total, query.page, query.per_page),
        })
    }

    async fn get_policy(&self, session_token: &str, id: &str) -> Result<ScanConfig, GatewayError> {
        // Fetch through the policy-scoped `get_configs usage_type="policy"`
        // command filtered to this id, so a scan-config id is not readable as a
        // policy (and vice versa).
        let _ = parse_entity_id(id)?;
        let client = self.session_client(session_token)?;
        let response = client
            .lock()
            .await?
            .call(get_policies(GetScanConfigsOpts {
                filter_string: Some(format!("uuid={id}")),
                filter_id: None,
                trash: None,
                details: Some(true),
            }))
            .await
            .map_err(map_gvm_error)?;
        let parsed = GetScanConfigsResponse::from_response(&response).map_err(map_parse_error)?;
        parsed
            .items
            .into_iter()
            .next()
            .map(scan_config_from_gmp)
            .ok_or_else(|| GatewayError::NotFound(format!("policy {id} not found")))
    }

    async fn create_policy(
        &self,
        session_token: &str,
        input: CreateScanConfigInput,
    ) -> Result<String, GatewayError> {
        let client = self.session_client(session_token)?;
        let response = client
            .lock()
            .await?
            .call(create_policy(
                &input.name,
                ConfigOpts {
                    comment: input.comment,
                    usage_type: None,
                },
            ))
            .await
            .map_err(map_gvm_error)?;
        let parsed = CreateScanConfigResponse::from_response(&response).map_err(map_parse_error)?;
        Ok(parsed.id.to_string())
    }

    async fn modify_policy(
        &self,
        session_token: &str,
        id: &str,
        input: ModifyScanConfigInput,
    ) -> Result<ScanConfig, GatewayError> {
        let client = self.session_client(session_token)?;
        let config_id = parse_entity_id(id)?;
        let response = client
            .lock()
            .await?
            .call(modify_config_generic(
                &config_id,
                ModifyConfigOpts {
                    name: input.name,
                    comment: input.comment,
                    usage_type: Some(ConfigUsageType::Policy),
                },
            ))
            .await
            .map_err(map_gvm_error)?;
        let _ = ActionResponse::from_response(&response).map_err(map_parse_error)?;
        drop(client);
        self.get_policy(session_token, id).await
    }

    async fn delete_policy(&self, session_token: &str, id: &str) -> Result<(), GatewayError> {
        let client = self.session_client(session_token)?;
        let response = client
            .lock()
            .await?
            .call(delete_policy_cmd(&parse_entity_id(id)?))
            .await
            .map_err(map_gvm_error)?;
        let _ = ActionResponse::from_response(&response).map_err(map_parse_error)?;
        Ok(())
    }
}

fn preference_from_gmp(
    preference: gvm_gmp::responses::ScanConfigPreference,
) -> ScanConfigPreference {
    ScanConfigPreference {
        nvt: preference.nvt.map(|nvt| ScanConfigPreferenceNvt {
            oid: nvt.oid,
            name: nvt.name,
        }),
        name: preference.name,
        id: preference.id,
        preference_type: preference.type_,
        value: preference.value,
        alternatives: preference.alternatives,
        default: preference.default,
    }
}
