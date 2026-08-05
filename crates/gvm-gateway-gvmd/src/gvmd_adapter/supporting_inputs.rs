// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Greenbone AG

use std::str::FromStr;

use gvm_gateway_domain::{
    CreateFilterInput, CreateHostInput, CreateNoteInput, CreateOverrideInput, CreateTagInput,
    GatewayError, ModifyFilterInput, ModifyHostInput, ModifyNoteInput, ModifyOverrideInput,
    ModifyTagInput,
};
use gvm_gmp::commands::{
    filters::FilterOpts, hosts::HostOpts, notes::NoteOpts, overrides::OverrideOpts, tags::TagOpts,
};
use gvm_gmp::enums::{EntityType, FilterType};

use crate::conversions::parse_entity_id;

fn parse_filter_type(value: &str) -> Result<FilterType, GatewayError> {
    FilterType::from_str(value)
        .map_err(|_| GatewayError::InvalidInput(format!("invalid filter type: {value}")))
}

fn parse_entity_type(value: &str) -> Result<EntityType, GatewayError> {
    EntityType::from_str(value)
        .map_err(|_| GatewayError::InvalidInput(format!("invalid resource type: {value}")))
}

pub(super) fn host_opts_from_create_input(input: CreateHostInput) -> HostOpts {
    HostOpts {
        comment: input.comment,
        value: Some(input.value),
    }
}

pub(super) fn host_opts_from_modify_input(input: ModifyHostInput) -> HostOpts {
    HostOpts {
        comment: input.comment,
        value: input.value,
    }
}

pub(super) fn filter_opts_from_create_input(
    input: CreateFilterInput,
) -> Result<FilterOpts, GatewayError> {
    Ok(FilterOpts {
        comment: input.comment,
        term: input.term,
        filter_type: input
            .filter_type
            .as_deref()
            .map(parse_filter_type)
            .transpose()?,
        sort_order: None,
    })
}

pub(super) fn filter_opts_from_modify_input(
    input: ModifyFilterInput,
) -> Result<FilterOpts, GatewayError> {
    Ok(FilterOpts {
        comment: input.comment,
        term: input.term,
        filter_type: input
            .filter_type
            .as_deref()
            .map(parse_filter_type)
            .transpose()?,
        sort_order: None,
    })
}

pub(super) fn tag_opts_from_create_input(input: CreateTagInput) -> Result<TagOpts, GatewayError> {
    Ok(TagOpts {
        comment: input.comment,
        value: input.value,
        resource_type: input
            .resource_type
            .as_deref()
            .map(parse_entity_type)
            .transpose()?,
        resource_id: input
            .resource_id
            .as_deref()
            .map(parse_entity_id)
            .transpose()?,
        severity: None,
        active: input.active,
    })
}

pub(super) fn tag_opts_from_modify_input(input: ModifyTagInput) -> Result<TagOpts, GatewayError> {
    Ok(TagOpts {
        comment: input.comment,
        value: input.value,
        resource_type: input
            .resource_type
            .as_deref()
            .map(parse_entity_type)
            .transpose()?,
        resource_id: input
            .resource_id
            .as_deref()
            .map(parse_entity_id)
            .transpose()?,
        severity: None,
        active: input.active,
    })
}

pub(super) fn note_opts_from_create_input(
    input: CreateNoteInput,
) -> Result<NoteOpts, GatewayError> {
    Ok(NoteOpts {
        text: input.text,
        hosts: input.hosts,
        port: input.port,
        severity: input.severity,
        task_id: input.task_id.as_deref().map(parse_entity_id).transpose()?,
        result_id: input
            .result_id
            .as_deref()
            .map(parse_entity_id)
            .transpose()?,
        active: input.active,
        orphan: input.orphan,
    })
}

pub(super) fn note_opts_from_modify_input(
    input: ModifyNoteInput,
) -> Result<NoteOpts, GatewayError> {
    Ok(NoteOpts {
        text: input.text,
        hosts: input.hosts.unwrap_or_default(),
        port: input.port,
        severity: input.severity,
        task_id: input.task_id.as_deref().map(parse_entity_id).transpose()?,
        result_id: input
            .result_id
            .as_deref()
            .map(parse_entity_id)
            .transpose()?,
        active: input.active,
        orphan: input.orphan,
    })
}

pub(super) fn override_opts_from_create_input(
    input: CreateOverrideInput,
) -> Result<OverrideOpts, GatewayError> {
    Ok(OverrideOpts {
        text: input.text,
        hosts: input.hosts,
        port: input.port,
        severity: input.severity,
        new_severity: input.new_severity,
        task_id: input.task_id.as_deref().map(parse_entity_id).transpose()?,
        result_id: input
            .result_id
            .as_deref()
            .map(parse_entity_id)
            .transpose()?,
        active: input.active,
    })
}

pub(super) fn override_opts_from_modify_input(
    input: ModifyOverrideInput,
) -> Result<OverrideOpts, GatewayError> {
    Ok(OverrideOpts {
        text: input.text,
        hosts: input.hosts.unwrap_or_default(),
        port: input.port,
        severity: input.severity,
        new_severity: input.new_severity,
        task_id: input.task_id.as_deref().map(parse_entity_id).transpose()?,
        result_id: input
            .result_id
            .as_deref()
            .map(parse_entity_id)
            .transpose()?,
        active: input.active,
    })
}
