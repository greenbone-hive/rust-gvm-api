// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Greenbone AG

use super::super::*;

impl E2eHarness {
    pub async fn list_all_scan_config_nvts(
        &self,
        token: &str,
        scan_config_id: &str,
        family: Option<&str>,
    ) -> Result<Vec<NvtCatalogEntry>> {
        let mut page = 1;
        let mut nvts = Vec::new();
        loop {
            let page_value = page.to_string();
            let mut query = vec![("page", page_value.as_str()), ("perPage", "1000")];
            if let Some(family) = family {
                query.push(("family", family));
            }
            let request = self.authed_path_segments_with_query(
                Method::GET,
                &["api", "v1", "scan-configs", scan_config_id, "nvts"],
                &query,
                token,
            )?;
            let response: ListResponse<NvtCatalogEntry> = self
                .send_json(request, StatusCode::OK, "list selected scan-config NVTs")
                .await?;
            nvts.extend(response.data);
            if page >= response.pagination.total_pages {
                return Ok(nvts);
            }
            page += 1;
        }
    }

    pub async fn list_all_feed_nvts_for_family(
        &self,
        token: &str,
        family: &str,
    ) -> Result<Vec<NvtCatalogEntry>> {
        let mut page = 1;
        let mut nvts = Vec::new();
        loop {
            let query = form_urlencoded::Serializer::new(String::new())
                .append_pair("family", family)
                .append_pair("page", &page.to_string())
                .append_pair("perPage", "1000")
                .finish();
            let response: ListResponse<NvtCatalogEntry> = self
                .send_json(
                    self.authed(Method::GET, &format!("/api/v1/nvts?{query}"), token),
                    StatusCode::OK,
                    "list feed NVTs for selected family",
                )
                .await?;
            nvts.extend(response.data);
            if page >= response.pagination.total_pages {
                return Ok(nvts);
            }
            page += 1;
        }
    }

    pub async fn delete_scan_config_permanently(
        &self,
        token: &str,
        scan_config_id: &str,
    ) -> Result<()> {
        self.send_empty(
            self.authed_path_segments_with_query(
                Method::DELETE,
                &["api", "v1", "scan-configs", scan_config_id],
                &[("ultimate", "true")],
                token,
            )?,
            StatusCode::NO_CONTENT,
            "permanently delete scan config",
        )
        .await
    }

    pub async fn list_scan_config_preferences(
        &self,
        token: &str,
        scan_config_id: &str,
        nvt_oid: Option<&str>,
    ) -> Result<Vec<ScanConfigPreference>> {
        let segments = &["api", "v1", "scan-configs", scan_config_id, "preferences"];
        let request = match nvt_oid {
            Some(nvt_oid) => self.authed_path_segments_with_query(
                Method::GET,
                segments,
                &[("nvtOid", nvt_oid)],
                token,
            )?,
            None => self.authed_path_segments(Method::GET, segments, token)?,
        };
        let response: ScanConfigPreferenceList = self
            .send_json(request, StatusCode::OK, "list scan-config preferences")
            .await?;
        Ok(response.data)
    }

    pub async fn set_scan_config_family_selection(
        &self,
        token: &str,
        scan_config_id: &str,
        selection: &SetScanConfigFamilySelection,
    ) -> Result<()> {
        self.send_empty(
            self.authed_path_segments(
                Method::PUT,
                &[
                    "api",
                    "v1",
                    "scan-configs",
                    scan_config_id,
                    "family-selection",
                ],
                token,
            )?
            .json(selection),
            StatusCode::NO_CONTENT,
            "replace scan-config family selection",
        )
        .await
    }

    pub async fn set_scan_config_nvt_selection(
        &self,
        token: &str,
        scan_config_id: &str,
        family: &str,
        nvt_oids: Vec<String>,
    ) -> Result<()> {
        self.send_empty(
            self.authed_path_segments(
                Method::PUT,
                &[
                    "api",
                    "v1",
                    "scan-configs",
                    scan_config_id,
                    "families",
                    family,
                    "nvts",
                ],
                token,
            )?
            .json(&SetScanConfigNvtSelection { nvt_oids }),
            StatusCode::NO_CONTENT,
            "replace scan-config family NVT selection",
        )
        .await
    }

    pub async fn set_scan_config_preference(
        &self,
        token: &str,
        scan_config_id: &str,
        name: &str,
        nvt_oid: Option<&str>,
        value: Option<&str>,
    ) -> Result<()> {
        self.send_empty(
            self.authed_path_segments(
                Method::PUT,
                &[
                    "api",
                    "v1",
                    "scan-configs",
                    scan_config_id,
                    "preferences",
                    name,
                ],
                token,
            )?
            .json(&SetScanConfigPreference {
                nvt_oid: nvt_oid.map(ToOwned::to_owned),
                value: value.map(ToOwned::to_owned),
            }),
            StatusCode::NO_CONTENT,
            "set or reset scan-config preference",
        )
        .await
    }

    pub async fn probe_credential_store_capability(
        &self,
        token: &str,
    ) -> Result<CredentialStoreCapability> {
        Ok(match self.list_credential_stores(token).await? {
            Some(stores) => CredentialStoreCapability::Supported(stores),
            None => CredentialStoreCapability::Unsupported,
        })
    }

    pub async fn get_credential_store(
        &self,
        token: &str,
        credential_store_id: &str,
    ) -> Result<CredentialStore> {
        self.send_json(
            self.authed_path_segments(
                Method::GET,
                &["api", "v1", "credential-stores", credential_store_id],
                token,
            )?,
            StatusCode::OK,
            "get credential store",
        )
        .await
    }

    pub async fn update_credential_store_comment(
        &self,
        token: &str,
        credential_store_id: &str,
        comment: &str,
    ) -> Result<CredentialStore> {
        self.send_json(
            self.authed_path_segments(
                Method::PUT,
                &["api", "v1", "credential-stores", credential_store_id],
                token,
            )?
            .json(&json!({ "comment": comment })),
            StatusCode::OK,
            "update credential-store comment",
        )
        .await
    }

    pub async fn verify_credential_store(
        &self,
        token: &str,
        credential_store_id: &str,
    ) -> Result<()> {
        self.send_empty(
            self.authed_path_segments(
                Method::POST,
                &[
                    "api",
                    "v1",
                    "credential-stores",
                    credential_store_id,
                    "actions",
                    "verify",
                ],
                token,
            )?,
            StatusCode::NO_CONTENT,
            "verify credential store",
        )
        .await
    }

    pub async fn create_store_backed_credential(
        &self,
        token: &str,
        request: &StoreBackedCredentialRequest,
    ) -> Result<CreatedResource> {
        let response = self
            .authed(Method::POST, "/api/v1/credentials", token)
            .json(request)
            .send()
            .await
            .context("create store-backed credential: send HTTP request")?;
        let status = response.status();
        let location = response
            .headers()
            .get(header::LOCATION)
            .map(|value| value.to_str())
            .transpose()
            .context("create store-backed credential: parse Location header")?
            .map(ToOwned::to_owned);
        if status != StatusCode::CREATED {
            bail!(
                "create store-backed credential: expected HTTP {} but received {}; response body suppressed because it may identify an external secret",
                StatusCode::CREATED,
                status
            );
        }
        let created: ResourceCreated = response
            .json()
            .await
            .context("create store-backed credential: parse success response")?;
        Ok(CreatedResource {
            id: created.id,
            location: location.context(
                "create store-backed credential: success response omitted Location header",
            )?,
        })
    }

    pub async fn delete_credential_permanently(
        &self,
        token: &str,
        credential_id: &str,
    ) -> Result<()> {
        self.send_empty(
            self.authed_path_segments_with_query(
                Method::DELETE,
                &["api", "v1", "credentials", credential_id],
                &[("ultimate", "true")],
                token,
            )?,
            StatusCode::NO_CONTENT,
            "permanently delete credential",
        )
        .await
    }

    pub async fn assert_credential_store_unsupported_matrix(
        &self,
        token: &str,
        valid_uuid: &str,
        request: &StoreBackedCredentialRequest,
    ) -> Result<()> {
        let calls = [
            (
                "get credential store",
                self.authed_path_segments(
                    Method::GET,
                    &["api", "v1", "credential-stores", valid_uuid],
                    token,
                )?,
            ),
            (
                "update credential store",
                self.authed_path_segments(
                    Method::PUT,
                    &["api", "v1", "credential-stores", valid_uuid],
                    token,
                )?
                .json(&json!({})),
            ),
            (
                "verify credential store",
                self.authed_path_segments(
                    Method::POST,
                    &[
                        "api",
                        "v1",
                        "credential-stores",
                        valid_uuid,
                        "actions",
                        "verify",
                    ],
                    token,
                )?,
            ),
            (
                "create store-backed credential",
                self.authed(Method::POST, "/api/v1/credentials", token)
                    .json(request),
            ),
        ];

        for (action, call) in calls {
            let response = call
                .send()
                .await
                .with_context(|| format!("{action}: send unsupported-capability request"))?;
            let status = response.status();
            let content_type = response
                .headers()
                .get(header::CONTENT_TYPE)
                .and_then(|value| value.to_str().ok())
                .unwrap_or("")
                .to_string();
            if status != StatusCode::NOT_IMPLEMENTED {
                bail!(
                    "{action}: expected HTTP {} but received {}; response body suppressed because it may identify an external secret",
                    StatusCode::NOT_IMPLEMENTED,
                    status
                );
            }
            if !content_type.starts_with("application/problem+json") {
                bail!("{action}: expected an RFC 9457 application/problem+json response");
            }
            let problem: ProblemResponse = response
                .json()
                .await
                .with_context(|| format!("{action}: parse RFC 9457 response"))?;
            if problem.status != StatusCode::NOT_IMPLEMENTED.as_u16() {
                bail!("{action}: RFC 9457 status did not match HTTP status");
            }
            if problem.code != "not_implemented" {
                bail!(
                    "{action}: expected RFC 9457 code not_implemented but received {}",
                    problem.code
                );
            }
        }
        Ok(())
    }
}
