// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Greenbone AG

use std::str::FromStr;

use gvm_gateway_domain::{
    CreateFilterInput, CreateHostInput, CreateNoteInput, CreateOverrideInput, CreateTagInput,
    GatewayError, ModifyFilterInput, ModifyHostInput, ModifyNoteInput, ModifyOverrideInput,
    ModifyTagInput, Note, Override,
};
use gvm_gmp::enums::{EntityType, FilterType};
use gvm_gmp::{
    commands::{
        filters::{CreateFilterRequest, ModifyFilterRequest},
        hosts::{CreateHostRequest, ModifyHostRequest},
        notes::{CreateNoteRequest, ModifyNoteRequest},
        overrides::{CreateOverrideRequest, ModifyOverrideRequest},
        tags::{CreateTagRequest, ModifyTagRequest, TagResourceUpdate, TagResources},
    },
    EntityId,
};

use crate::conversions::parse_entity_id;

fn parse_filter_type(value: &str) -> Result<FilterType, GatewayError> {
    FilterType::from_str(value)
        .map_err(|_| GatewayError::InvalidInput(format!("invalid filter type: {value}")))
}

fn parse_entity_type(value: &str) -> Result<EntityType, GatewayError> {
    EntityType::from_str(value)
        .map_err(|_| GatewayError::InvalidInput(format!("invalid resource type: {value}")))
}

pub(super) fn host_request_from_create_input(input: CreateHostInput) -> CreateHostRequest {
    let mut request = CreateHostRequest::new(input.value);
    request.comment = input.comment;
    request
}

pub(super) fn host_request_from_modify_input(
    host_id: EntityId,
    input: ModifyHostInput,
    current_comment: Option<String>,
) -> ModifyHostRequest {
    // Canonical host modification is a complete comment replacement. The
    // REST/domain input is patch-shaped, so omission retains the current
    // value while an explicit empty string still clears it.
    ModifyHostRequest::new(
        host_id,
        input.comment.or(current_comment).unwrap_or_default(),
    )
}

pub(super) fn filter_request_from_create_input(
    input: CreateFilterInput,
) -> Result<CreateFilterRequest, GatewayError> {
    let mut request = CreateFilterRequest::new(input.name);
    request.comment = input.comment;
    request.term = input.term;
    request.filter_type = input
        .filter_type
        .as_deref()
        .map(parse_filter_type)
        .transpose()?;
    Ok(request)
}

pub(super) fn filter_request_from_modify_input(
    filter_id: EntityId,
    input: ModifyFilterInput,
) -> Result<ModifyFilterRequest, GatewayError> {
    let mut request = ModifyFilterRequest::new(filter_id);
    request.comment = input.comment;
    request.term = input.term;
    request.filter_type = input
        .filter_type
        .as_deref()
        .map(parse_filter_type)
        .transpose()?;
    Ok(request)
}

pub(super) fn tag_request_from_create_input(
    input: CreateTagInput,
) -> Result<CreateTagRequest, GatewayError> {
    let resource_type = input
        .resource_type
        .as_deref()
        .ok_or_else(|| GatewayError::InvalidInput("resourceType is required".to_string()))
        .and_then(parse_entity_type)?;
    let mut resources = TagResources::new(resource_type);
    if let Some(resource_id) = input.resource_id.as_deref() {
        resources.resource_ids.push(parse_entity_id(resource_id)?);
    }
    let mut request = CreateTagRequest::new(input.name, resources);
    request.comment = input.comment;
    request.value = input.value;
    request.active = input.active;
    Ok(request)
}

pub(super) fn tag_request_from_modify_input(
    tag_id: EntityId,
    input: ModifyTagInput,
) -> Result<ModifyTagRequest, GatewayError> {
    let mut request = ModifyTagRequest::new(tag_id);
    request.comment = input.comment;
    request.value = input.value;
    request.active = input.active;
    request.resource_update = match input.resource_type.as_deref() {
        Some(resource_type) => {
            let mut resources = TagResources::new(parse_entity_type(resource_type)?);
            if let Some(resource_id) = input.resource_id.as_deref() {
                resources.resource_ids.push(parse_entity_id(resource_id)?);
            }
            Some(TagResourceUpdate::new(resources))
        }
        None if input.resource_id.is_some() => {
            return Err(GatewayError::InvalidInput(
                "resourceId requires resourceType".to_string(),
            ));
        }
        None => None,
    };
    Ok(request)
}

pub(super) fn note_request_from_create_input(
    input: CreateNoteInput,
) -> Result<CreateNoteRequest, GatewayError> {
    let text = input
        .text
        .ok_or_else(|| GatewayError::InvalidInput("text is required".to_string()))?;
    let mut request = CreateNoteRequest::new(input.nvt_oid, text);
    request.hosts = input.hosts;
    request.port = input.port;
    request.severity = parse_optional_severity(input.severity, "severity")?;
    request.task_id = input.task_id.as_deref().map(parse_entity_id).transpose()?;
    request.result_id = input
        .result_id
        .as_deref()
        .map(parse_entity_id)
        .transpose()?;
    request.days_active = input.active.map(active_days);
    Ok(request)
}

pub(super) fn note_request_from_modify_input(
    note_id: EntityId,
    input: ModifyNoteInput,
    current: Note,
) -> Result<ModifyNoteRequest, GatewayError> {
    let text = input
        .text
        .or(current.text)
        .ok_or_else(|| GatewayError::InvalidInput("text is required".to_string()))?;
    let mut request = ModifyNoteRequest::new(note_id, text);
    request.hosts = input.hosts.unwrap_or(current.hosts);
    request.port = input.port.or(current.port);
    request.severity = parse_optional_severity(input.severity.or(current.severity), "severity")?;
    let task_id = input.task_id.or_else(|| current.task.map(|task| task.id));
    request.task_id = task_id.as_deref().map(parse_entity_id).transpose()?;
    let result_id = input
        .result_id
        .or_else(|| current.result.map(|result| result.id));
    request.result_id = result_id.as_deref().map(parse_entity_id).transpose()?;
    request.days_active = input.active.map(active_days);
    Ok(request)
}

pub(super) fn override_request_from_create_input(
    input: CreateOverrideInput,
) -> Result<CreateOverrideRequest, GatewayError> {
    let text = input
        .text
        .ok_or_else(|| GatewayError::InvalidInput("text is required".to_string()))?;
    let new_severity = parse_required_severity(input.new_severity, "newSeverity")?;
    let mut request = CreateOverrideRequest::new(input.nvt_oid, text, new_severity);
    request.hosts = input.hosts;
    request.port = input.port;
    request.severity = parse_optional_severity(input.severity, "severity")?;
    request.task_id = input.task_id.as_deref().map(parse_entity_id).transpose()?;
    request.result_id = input
        .result_id
        .as_deref()
        .map(parse_entity_id)
        .transpose()?;
    request.days_active = input.active.map(active_days);
    Ok(request)
}

pub(super) fn override_request_from_modify_input(
    override_id: EntityId,
    input: ModifyOverrideInput,
    current: Override,
) -> Result<ModifyOverrideRequest, GatewayError> {
    let text = input
        .text
        .or(current.text)
        .ok_or_else(|| GatewayError::InvalidInput("text is required".to_string()))?;
    let new_severity =
        parse_required_severity(input.new_severity.or(current.new_severity), "newSeverity")?;
    let mut request = ModifyOverrideRequest::new(override_id, text, new_severity);
    request.hosts = input.hosts.unwrap_or(current.hosts);
    request.port = input.port.or(current.port);
    request.severity = parse_optional_severity(input.severity.or(current.severity), "severity")?;
    let task_id = input.task_id.or_else(|| current.task.map(|task| task.id));
    request.task_id = task_id.as_deref().map(parse_entity_id).transpose()?;
    let result_id = input
        .result_id
        .or_else(|| current.result.map(|result| result.id));
    request.result_id = result_id.as_deref().map(parse_entity_id).transpose()?;
    request.days_active = input.active.map(active_days);
    Ok(request)
}

fn parse_optional_severity(
    value: Option<String>,
    field: &str,
) -> Result<Option<f64>, GatewayError> {
    value
        .map(|value| {
            value.parse::<f64>().map_err(|_| {
                GatewayError::InvalidInput(format!("{field} must be a numeric severity"))
            })
        })
        .transpose()
}

fn parse_required_severity(value: Option<String>, field: &str) -> Result<f64, GatewayError> {
    parse_optional_severity(value, field)?
        .ok_or_else(|| GatewayError::InvalidInput(format!("{field} is required")))
}

const fn active_days(active: bool) -> i32 {
    if active {
        -1
    } else {
        0
    }
}

#[cfg(test)]
#[path = "supporting_inputs_test.rs"]
mod supporting_inputs_test;
