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
        let parsed = self
            .execute_with_session(
                session_token,
                "configs.list",
                GetConfigsRequest::new(GetConfigsOpts {
                    config_id: None,
                    filter_string,
                    filter_id: None,
                    trash: None,
                    details: Some(true),
                    families: None,
                    preferences: None,
                    tasks: None,
                    usage_type: query.usage_type.as_deref().map(parse_config_usage_type),
                }),
            )
            .await?;
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
        let parsed = self
            .execute_with_session(
                session_token,
                "configs.get",
                GetConfigRequest::new(
                    parse_entity_id(id)?,
                    GetConfigOpts {
                        details: Some(true),
                        families: None,
                        preferences: None,
                        tasks: None,
                        usage_type: None,
                    },
                ),
            )
            .await?;
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
        self.execute_with_session(
            session_token,
            "configs.delete",
            DeleteConfigRequest::new(
                parse_entity_id(id)?,
                DeleteConfigOpts {
                    ultimate: ultimate.then_some(true),
                },
            ),
        )
        .await?;
        Ok(())
    }

    async fn clone_config(&self, session_token: &str, id: &str) -> Result<String, GatewayError> {
        let parsed = self
            .execute_with_session(
                session_token,
                "configs.clone",
                CloneConfigRequest::new(parse_entity_id(id)?, CloneConfigOpts::default()),
            )
            .await?;
        Ok(parsed.id.to_string())
    }

    async fn list_scan_configs(
        &self,
        session_token: &str,
        query: &ScanConfigQuery,
    ) -> Result<ScanConfigPage, GatewayError> {
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
        let parsed = self
            .execute_with_session(
                session_token,
                "scan_configs.list",
                GetScanConfigsRequest::new(GetScanConfigsOpts {
                    filter_string,
                    filter_id: None,
                    trash: None,
                    details: Some(true),
                }),
            )
            .await?;
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
        let base_id = input
            .base_scan_config_id
            .as_deref()
            .map(parse_entity_id)
            .transpose()?;
        let parsed = self
            .execute_with_session(
                session_token,
                "scan_configs.create",
                CreateScanConfigRequest::new(
                    input.name,
                    base_id,
                    ConfigOpts {
                        comment: input.comment,
                        usage_type: None,
                    },
                ),
            )
            .await?;
        Ok(parsed.id.to_string())
    }

    async fn get_scan_config(
        &self,
        session_token: &str,
        id: &str,
    ) -> Result<ScanConfig, GatewayError> {
        let parsed = self
            .execute_with_session(
                session_token,
                "scan_configs.get",
                GetScanConfigRequest::new(parse_entity_id(id)?),
            )
            .await?;
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
        let config_id = parse_entity_id(id)?;
        self.execute_with_session(
            session_token,
            "scan_configs.modify",
            ModifyConfigRequest::new(
                config_id,
                ModifyConfigOpts {
                    name: input.name,
                    comment: input.comment,
                    usage_type: Some(ConfigUsageType::Scan),
                },
            ),
        )
        .await?;
        self.get_scan_config(session_token, id).await
    }

    async fn delete_scan_config(
        &self,
        session_token: &str,
        id: &str,
        ultimate: bool,
    ) -> Result<(), GatewayError> {
        self.execute_with_session(
            session_token,
            "scan_configs.delete",
            DeleteScanConfigRequest::new(parse_entity_id(id)?, ultimate),
        )
        .await?;
        Ok(())
    }

    async fn list_scan_config_nvts(
        &self,
        session_token: &str,
        id: &str,
        query: &ScanConfigNvtQuery,
    ) -> Result<ScanConfigNvtPage, GatewayError> {
        let config_id = parse_entity_id(id)?;
        let families = if let Some(family) = &query.family {
            vec![family.clone()]
        } else {
            self.execute_with_session(
                session_token,
                "nvt_families.list",
                GetNvtFamiliesRequest::new(),
            )
            .await?
            .items
            .into_iter()
            .map(|family| family.name)
            .collect()
        };
        let mut items = Vec::new();
        for family in families {
            let mut request = GetScanConfigNvtsRequest::new(config_id.clone(), family);
            request.details = Some(true);
            request.preferences = Some(true);
            request.preference_count = Some(true);
            request.timeout = Some(true);
            request.sort_order = Some(SortOrder::Ascending);
            request.sort_field = Some("name".to_string());
            let parsed = self
                .execute_with_session(session_token, "scan_configs.nvts.list", request)
                .await?;
            items.extend(parsed.items.into_iter().map(nvt_from_gmp));
        }
        items.sort_by(|left, right| left.name.cmp(&right.name));
        let total = items.len() as u32;
        Ok(ScanConfigNvtPage {
            data: paged_slice(items, query.page, query.per_page),
            pagination: paged_pagination(total, query.page, query.per_page),
        })
    }

    async fn get_scan_config_nvt(
        &self,
        session_token: &str,
        id: &str,
        oid: &str,
    ) -> Result<Nvt, GatewayError> {
        let mut request = GetScanConfigNvtRequest::new(oid);
        request.config_id = Some(parse_entity_id(id)?);
        request.timeout = Some(true);
        let parsed = self
            .execute_with_session(session_token, "scan_configs.nvts.get", request)
            .await?;
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
        let parsed = self
            .execute_with_session(
                session_token,
                "scan_configs.preferences.list",
                GetScanConfigPreferencesRequest::new(GetScanConfigPreferencesOpts {
                    nvt_oid: query.nvt_oid.clone(),
                    config_id: Some(parse_entity_id(id)?),
                }),
            )
            .await?;
        Ok(parsed.items.into_iter().map(preference_from_gmp).collect())
    }

    async fn get_scan_config_preference(
        &self,
        session_token: &str,
        id: &str,
        name: &str,
        query: &ScanConfigPreferenceQuery,
    ) -> Result<ScanConfigPreference, GatewayError> {
        let parsed = self
            .execute_with_session(
                session_token,
                "scan_configs.preferences.get",
                GetScanConfigPreferenceRequest::new(
                    name,
                    GetScanConfigPreferencesOpts {
                        nvt_oid: query.nvt_oid.clone(),
                        config_id: Some(parse_entity_id(id)?),
                    },
                ),
            )
            .await?;
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
        self.execute_with_session(
            session_token,
            "scan_configs.nvts.set",
            ModifyScanConfigSetNvtSelectionRequest::new(parse_entity_id(id)?, family, nvt_oids),
        )
        .await?;
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
        self.execute_with_session(
            session_token,
            "scan_configs.families.set",
            ModifyScanConfigSetFamilySelectionRequest::new(
                parse_entity_id(id)?,
                families,
                input.auto_add_new_families,
            ),
        )
        .await?;
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
        if let Some(nvt_oid) = nvt_oid {
            self.execute_with_session(
                session_token,
                "scan_configs.preferences.set_nvt",
                ModifyScanConfigSetNvtPreferenceRequest::new(config_id, name, nvt_oid, value),
            )
            .await?;
        } else {
            self.execute_with_session(
                session_token,
                "scan_configs.preferences.set_scanner",
                ModifyScanConfigSetScannerPreferenceRequest::new(config_id, name, value),
            )
            .await?;
        }
        Ok(())
    }

    async fn list_policies(
        &self,
        session_token: &str,
        query: &ScanConfigQuery,
    ) -> Result<ScanConfigPage, GatewayError> {
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
        let parsed = self
            .execute_with_session(
                session_token,
                "policies.list",
                GetPoliciesRequest::new(GetScanConfigsOpts {
                    filter_string,
                    filter_id: None,
                    trash: None,
                    details: Some(true),
                }),
            )
            .await?;
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
        let parsed = self
            .execute_with_session(
                session_token,
                "policies.get",
                GetPoliciesRequest::new(GetScanConfigsOpts {
                    filter_string: Some(format!("uuid={id}")),
                    filter_id: None,
                    trash: None,
                    details: Some(true),
                }),
            )
            .await?;
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
        let parsed = self
            .execute_with_session(
                session_token,
                "policies.create",
                CreatePolicyRequest::new(
                    input.name,
                    ConfigOpts {
                        comment: input.comment,
                        usage_type: None,
                    },
                ),
            )
            .await?;
        Ok(parsed.id.to_string())
    }

    async fn modify_policy(
        &self,
        session_token: &str,
        id: &str,
        input: ModifyScanConfigInput,
    ) -> Result<ScanConfig, GatewayError> {
        let config_id = parse_entity_id(id)?;
        self.execute_with_session(
            session_token,
            "policies.modify",
            ModifyConfigRequest::new(
                config_id,
                ModifyConfigOpts {
                    name: input.name,
                    comment: input.comment,
                    usage_type: Some(ConfigUsageType::Policy),
                },
            ),
        )
        .await?;
        self.get_policy(session_token, id).await
    }

    async fn delete_policy(&self, session_token: &str, id: &str) -> Result<(), GatewayError> {
        self.execute_with_session(
            session_token,
            "policies.delete",
            DeletePolicyRequest::new(parse_entity_id(id)?),
        )
        .await?;
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
