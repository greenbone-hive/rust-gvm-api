// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Greenbone AG

//! Supporting-resource use cases.

use gvm_gateway_domain::{
    CreateFilterInput, CreateHostInput, CreateNoteInput, CreateOverrideInput, CreateTagInput,
    Filter, FilterPage, GatewayError, Host, HostPage, ModifyFilterInput, ModifyHostInput,
    ModifyNoteInput, ModifyOverrideInput, ModifyTagInput, Note, NotePage, Nvt, NvtFamilyPage,
    NvtPage, Override, OverridePage, ReportFormat, ReportFormatPage, SupportingResourceQuery, Tag,
    TagPage, Ticket, TicketPage, TlsCertificateAsset, TlsCertificateAssetPage, VulnerabilityPage,
};

use crate::GatewayService;

impl GatewayService {
    /// Lists hosts for an authenticated session.
    pub async fn list_hosts(
        &self,
        session_token: &str,
        query: SupportingResourceQuery,
    ) -> Result<HostPage, GatewayError> {
        self.execute_with_resource(
            "hosts.list",
            session_token,
            "list",
            "host",
            None,
            |session| async move {
                self.supporting_resources
                    .list_hosts(&session.token, &query)
                    .await
            },
        )
        .await
    }

    /// Lists TLS certificate assets for an authenticated session.
    pub async fn list_tls_certificates(
        &self,
        session_token: &str,
        query: SupportingResourceQuery,
    ) -> Result<TlsCertificateAssetPage, GatewayError> {
        self.execute_with_resource(
            "tls_certificates.list",
            session_token,
            "list",
            "tls_certificate",
            None,
            |session| async move {
                self.supporting_resources
                    .list_tls_certificates(&session.token, &query)
                    .await
            },
        )
        .await
    }

    /// Fetches a TLS certificate asset for an authenticated session.
    pub async fn get_tls_certificate(
        &self,
        session_token: &str,
        id: &str,
    ) -> Result<TlsCertificateAsset, GatewayError> {
        self.execute_with_resource(
            "tls_certificates.get",
            session_token,
            "read",
            "tls_certificate",
            Some(id),
            |session| async move {
                self.supporting_resources
                    .get_tls_certificate(&session.token, id)
                    .await
            },
        )
        .await
    }

    /// Fetches a host for an authenticated session.
    pub async fn get_host(&self, session_token: &str, id: &str) -> Result<Host, GatewayError> {
        self.execute_with_resource(
            "hosts.get",
            session_token,
            "read",
            "host",
            Some(id),
            |session| async move { self.supporting_resources.get_host(&session.token, id).await },
        )
        .await
    }

    /// Creates a host asset for an authenticated session.
    pub async fn create_host(
        &self,
        session_token: &str,
        input: CreateHostInput,
    ) -> Result<String, GatewayError> {
        self.execute_with_resource(
            "hosts.create",
            session_token,
            "create",
            "host",
            None,
            |session| async move {
                self.supporting_resources
                    .create_host(&session.token, input)
                    .await
            },
        )
        .await
    }

    /// Modifies a host asset for an authenticated session.
    pub async fn modify_host(
        &self,
        session_token: &str,
        id: &str,
        input: ModifyHostInput,
    ) -> Result<Host, GatewayError> {
        self.execute_with_resource(
            "hosts.modify",
            session_token,
            "modify",
            "host",
            Some(id),
            |session| async move {
                self.supporting_resources
                    .modify_host(&session.token, id, input)
                    .await
            },
        )
        .await
    }

    /// Deletes a host asset for an authenticated session.
    pub async fn delete_host(
        &self,
        session_token: &str,
        id: &str,
        ultimate: bool,
    ) -> Result<(), GatewayError> {
        self.execute_with_resource(
            "hosts.delete",
            session_token,
            "delete",
            "host",
            Some(id),
            |session| async move {
                self.supporting_resources
                    .delete_host(&session.token, id, ultimate)
                    .await
            },
        )
        .await
    }

    /// Lists report formats for an authenticated session.
    pub async fn list_report_formats(
        &self,
        session_token: &str,
        query: SupportingResourceQuery,
    ) -> Result<ReportFormatPage, GatewayError> {
        self.execute_with_resource(
            "report_formats.list",
            session_token,
            "list",
            "report_format",
            None,
            |session| async move {
                self.supporting_resources
                    .list_report_formats(&session.token, &query)
                    .await
            },
        )
        .await
    }

    /// Fetches a report format for an authenticated session.
    pub async fn get_report_format(
        &self,
        session_token: &str,
        id: &str,
    ) -> Result<ReportFormat, GatewayError> {
        self.execute_with_resource(
            "report_formats.get",
            session_token,
            "read",
            "report_format",
            Some(id),
            |session| async move {
                self.supporting_resources
                    .get_report_format(&session.token, id)
                    .await
            },
        )
        .await
    }

    /// Lists saved filters for an authenticated session.
    pub async fn list_filters(
        &self,
        session_token: &str,
        query: SupportingResourceQuery,
    ) -> Result<FilterPage, GatewayError> {
        self.execute_with_resource(
            "filters.list",
            session_token,
            "list",
            "filter",
            None,
            |session| async move {
                self.supporting_resources
                    .list_filters(&session.token, &query)
                    .await
            },
        )
        .await
    }

    /// Fetches a saved filter for an authenticated session.
    pub async fn get_filter(&self, session_token: &str, id: &str) -> Result<Filter, GatewayError> {
        self.execute_with_resource(
            "filters.get",
            session_token,
            "read",
            "filter",
            Some(id),
            |session| async move {
                self.supporting_resources
                    .get_filter(&session.token, id)
                    .await
            },
        )
        .await
    }

    /// Creates a saved filter for an authenticated session.
    pub async fn create_filter(
        &self,
        session_token: &str,
        input: CreateFilterInput,
    ) -> Result<String, GatewayError> {
        self.execute_with_resource(
            "filters.create",
            session_token,
            "create",
            "filter",
            None,
            |session| async move {
                self.supporting_resources
                    .create_filter(&session.token, input)
                    .await
            },
        )
        .await
    }

    /// Modifies a saved filter for an authenticated session.
    pub async fn modify_filter(
        &self,
        session_token: &str,
        id: &str,
        input: ModifyFilterInput,
    ) -> Result<Filter, GatewayError> {
        self.execute_with_resource(
            "filters.modify",
            session_token,
            "modify",
            "filter",
            Some(id),
            |session| async move {
                self.supporting_resources
                    .modify_filter(&session.token, id, input)
                    .await
            },
        )
        .await
    }

    /// Deletes a saved filter for an authenticated session.
    pub async fn delete_filter(
        &self,
        session_token: &str,
        id: &str,
        ultimate: bool,
    ) -> Result<(), GatewayError> {
        self.execute_with_resource(
            "filters.delete",
            session_token,
            "delete",
            "filter",
            Some(id),
            |session| async move {
                self.supporting_resources
                    .delete_filter(&session.token, id, ultimate)
                    .await
            },
        )
        .await
    }

    /// Clones a saved filter for an authenticated session.
    pub async fn clone_filter(
        &self,
        session_token: &str,
        id: &str,
    ) -> Result<String, GatewayError> {
        self.execute_with_resource(
            "filters.clone",
            session_token,
            "create",
            "filter",
            Some(id),
            |session| async move {
                self.supporting_resources
                    .clone_filter(&session.token, id)
                    .await
            },
        )
        .await
    }

    /// Lists tags for an authenticated session.
    pub async fn list_tags(
        &self,
        session_token: &str,
        query: SupportingResourceQuery,
    ) -> Result<TagPage, GatewayError> {
        self.execute_with_resource(
            "tags.list",
            session_token,
            "list",
            "tag",
            None,
            |session| async move {
                self.supporting_resources
                    .list_tags(&session.token, &query)
                    .await
            },
        )
        .await
    }

    /// Fetches a tag for an authenticated session.
    pub async fn get_tag(&self, session_token: &str, id: &str) -> Result<Tag, GatewayError> {
        self.execute_with_resource(
            "tags.get",
            session_token,
            "read",
            "tag",
            Some(id),
            |session| async move { self.supporting_resources.get_tag(&session.token, id).await },
        )
        .await
    }

    /// Creates a tag for an authenticated session.
    pub async fn create_tag(
        &self,
        session_token: &str,
        input: CreateTagInput,
    ) -> Result<String, GatewayError> {
        self.execute_with_resource(
            "tags.create",
            session_token,
            "create",
            "tag",
            None,
            |session| async move {
                self.supporting_resources
                    .create_tag(&session.token, input)
                    .await
            },
        )
        .await
    }

    /// Modifies a tag for an authenticated session.
    pub async fn modify_tag(
        &self,
        session_token: &str,
        id: &str,
        input: ModifyTagInput,
    ) -> Result<Tag, GatewayError> {
        self.execute_with_resource(
            "tags.modify",
            session_token,
            "modify",
            "tag",
            Some(id),
            |session| async move {
                self.supporting_resources
                    .modify_tag(&session.token, id, input)
                    .await
            },
        )
        .await
    }

    /// Deletes a tag for an authenticated session.
    pub async fn delete_tag(
        &self,
        session_token: &str,
        id: &str,
        ultimate: bool,
    ) -> Result<(), GatewayError> {
        self.execute_with_resource(
            "tags.delete",
            session_token,
            "delete",
            "tag",
            Some(id),
            |session| async move {
                self.supporting_resources
                    .delete_tag(&session.token, id, ultimate)
                    .await
            },
        )
        .await
    }

    /// Clones a tag for an authenticated session.
    pub async fn clone_tag(&self, session_token: &str, id: &str) -> Result<String, GatewayError> {
        self.execute_with_resource(
            "tags.clone",
            session_token,
            "create",
            "tag",
            Some(id),
            |session| async move {
                self.supporting_resources
                    .clone_tag(&session.token, id)
                    .await
            },
        )
        .await
    }

    /// Lists tickets for an authenticated session.
    pub async fn list_tickets(
        &self,
        session_token: &str,
        query: SupportingResourceQuery,
    ) -> Result<TicketPage, GatewayError> {
        self.execute_with_resource(
            "tickets.list",
            session_token,
            "list",
            "ticket",
            None,
            |session| async move {
                self.supporting_resources
                    .list_tickets(&session.token, &query)
                    .await
            },
        )
        .await
    }

    /// Fetches a ticket for an authenticated session.
    pub async fn get_ticket(&self, session_token: &str, id: &str) -> Result<Ticket, GatewayError> {
        self.execute_with_resource(
            "tickets.get",
            session_token,
            "read",
            "ticket",
            Some(id),
            |session| async move {
                self.supporting_resources
                    .get_ticket(&session.token, id)
                    .await
            },
        )
        .await
    }

    /// Lists notes for an authenticated session.
    pub async fn list_notes(
        &self,
        session_token: &str,
        query: SupportingResourceQuery,
    ) -> Result<NotePage, GatewayError> {
        self.execute_with_resource(
            "notes.list",
            session_token,
            "list",
            "note",
            None,
            |session| async move {
                self.supporting_resources
                    .list_notes(&session.token, &query)
                    .await
            },
        )
        .await
    }

    /// Fetches a note for an authenticated session.
    pub async fn get_note(&self, session_token: &str, id: &str) -> Result<Note, GatewayError> {
        self.execute_with_resource(
            "notes.get",
            session_token,
            "read",
            "note",
            Some(id),
            |session| async move { self.supporting_resources.get_note(&session.token, id).await },
        )
        .await
    }

    /// Creates a note for an authenticated session.
    pub async fn create_note(
        &self,
        session_token: &str,
        input: CreateNoteInput,
    ) -> Result<String, GatewayError> {
        self.execute_with_resource(
            "notes.create",
            session_token,
            "create",
            "note",
            None,
            |session| async move {
                self.supporting_resources
                    .create_note(&session.token, input)
                    .await
            },
        )
        .await
    }

    /// Modifies a note for an authenticated session.
    pub async fn modify_note(
        &self,
        session_token: &str,
        id: &str,
        input: ModifyNoteInput,
    ) -> Result<Note, GatewayError> {
        self.execute_with_resource(
            "notes.modify",
            session_token,
            "modify",
            "note",
            Some(id),
            |session| async move {
                self.supporting_resources
                    .modify_note(&session.token, id, input)
                    .await
            },
        )
        .await
    }

    /// Deletes a note for an authenticated session.
    pub async fn delete_note(
        &self,
        session_token: &str,
        id: &str,
        ultimate: bool,
    ) -> Result<(), GatewayError> {
        self.execute_with_resource(
            "notes.delete",
            session_token,
            "delete",
            "note",
            Some(id),
            |session| async move {
                self.supporting_resources
                    .delete_note(&session.token, id, ultimate)
                    .await
            },
        )
        .await
    }

    /// Lists overrides for an authenticated session.
    pub async fn list_overrides(
        &self,
        session_token: &str,
        query: SupportingResourceQuery,
    ) -> Result<OverridePage, GatewayError> {
        self.execute_with_resource(
            "overrides.list",
            session_token,
            "list",
            "override",
            None,
            |session| async move {
                self.supporting_resources
                    .list_overrides(&session.token, &query)
                    .await
            },
        )
        .await
    }

    /// Fetches an override for an authenticated session.
    pub async fn get_override(
        &self,
        session_token: &str,
        id: &str,
    ) -> Result<Override, GatewayError> {
        self.execute_with_resource(
            "overrides.get",
            session_token,
            "read",
            "override",
            Some(id),
            |session| async move {
                self.supporting_resources
                    .get_override(&session.token, id)
                    .await
            },
        )
        .await
    }

    /// Creates an override for an authenticated session.
    pub async fn create_override(
        &self,
        session_token: &str,
        input: CreateOverrideInput,
    ) -> Result<String, GatewayError> {
        self.execute_with_resource(
            "overrides.create",
            session_token,
            "create",
            "override",
            None,
            |session| async move {
                self.supporting_resources
                    .create_override(&session.token, input)
                    .await
            },
        )
        .await
    }

    /// Modifies an override for an authenticated session.
    pub async fn modify_override(
        &self,
        session_token: &str,
        id: &str,
        input: ModifyOverrideInput,
    ) -> Result<Override, GatewayError> {
        self.execute_with_resource(
            "overrides.modify",
            session_token,
            "modify",
            "override",
            Some(id),
            |session| async move {
                self.supporting_resources
                    .modify_override(&session.token, id, input)
                    .await
            },
        )
        .await
    }

    /// Deletes an override for an authenticated session.
    pub async fn delete_override(
        &self,
        session_token: &str,
        id: &str,
        ultimate: bool,
    ) -> Result<(), GatewayError> {
        self.execute_with_resource(
            "overrides.delete",
            session_token,
            "delete",
            "override",
            Some(id),
            |session| async move {
                self.supporting_resources
                    .delete_override(&session.token, id, ultimate)
                    .await
            },
        )
        .await
    }

    /// Lists NVTs for an authenticated session.
    pub async fn list_nvts(
        &self,
        session_token: &str,
        query: SupportingResourceQuery,
    ) -> Result<NvtPage, GatewayError> {
        self.execute_with_resource(
            "nvts.list",
            session_token,
            "list",
            "nvt",
            None,
            |session| async move {
                self.supporting_resources
                    .list_nvts(&session.token, &query)
                    .await
            },
        )
        .await
    }

    /// Lists vulnerabilities (SecInfo) for an authenticated session.
    pub async fn list_vulnerabilities(
        &self,
        session_token: &str,
        query: SupportingResourceQuery,
    ) -> Result<VulnerabilityPage, GatewayError> {
        self.execute_with_resource(
            "vulnerabilities.list",
            session_token,
            "list",
            "vulnerability",
            None,
            |session| async move {
                self.supporting_resources
                    .list_vulnerabilities(&session.token, &query)
                    .await
            },
        )
        .await
    }

    /// Fetches an NVT for an authenticated session.
    pub async fn get_nvt(&self, session_token: &str, oid: &str) -> Result<Nvt, GatewayError> {
        self.execute_with_resource(
            "nvts.get",
            session_token,
            "read",
            "nvt",
            Some(oid),
            |session| async move { self.supporting_resources.get_nvt(&session.token, oid).await },
        )
        .await
    }

    /// Lists NVT families for an authenticated session.
    pub async fn list_nvt_families(
        &self,
        session_token: &str,
        page: u32,
        per_page: u32,
    ) -> Result<NvtFamilyPage, GatewayError> {
        self.execute_with_resource(
            "nvt_families.list",
            session_token,
            "list",
            "nvt_family",
            None,
            |session| async move {
                self.supporting_resources
                    .list_nvt_families(&session.token, page, per_page)
                    .await
            },
        )
        .await
    }
}
