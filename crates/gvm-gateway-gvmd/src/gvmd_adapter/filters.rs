// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Greenbone AG

use gvm_gateway_domain::{GatewayError, Pagination};
use gvm_gmp::{FilterFragmentError, PaginatedFilter, Pagination as GmpPagination};

pub(super) fn paged_pagination(total: u32, page: u32, per_page: u32) -> Pagination {
    let total_pages = if total == 0 {
        0
    } else {
        ((total - 1) / per_page) + 1
    };

    Pagination {
        page,
        per_page,
        total,
        total_pages,
    }
}

pub(super) fn gvmd_total(filtered: Option<u32>, total: Option<u32>, current_len: usize) -> u32 {
    filtered.or(total).unwrap_or(current_len as u32)
}

pub(super) fn paged_slice<T>(items: Vec<T>, page: u32, per_page: u32) -> Vec<T> {
    let offset = u64::from(page.saturating_sub(1)) * u64::from(per_page);
    let Ok(start) = usize::try_from(offset) else {
        return Vec::new();
    };
    items
        .into_iter()
        .skip(start)
        .take(per_page as usize)
        .collect()
}

pub(super) fn needs_client_side_pagination_fallback<T>(items: &[T], total: u32, page: u32) -> bool {
    page > 1 && items.is_empty() && total == 0
}

pub(super) fn paginated_filter(
    prefix: Option<&str>,
    filter_string: Option<&str>,
    page: u32,
    per_page: u32,
) -> Result<Option<String>, GatewayError> {
    paginated_filter_with_reserved_terms(prefix, filter_string, page, per_page, &[])
}

pub(super) fn paginated_filter_with_reserved_terms(
    prefix: Option<&str>,
    filter_string: Option<&str>,
    page: u32,
    per_page: u32,
    reserved_terms: &[&str],
) -> Result<Option<String>, GatewayError> {
    let mut filter = PaginatedFilter::new();
    if let Some(prefix) = prefix {
        filter = filter.with_clause(prefix);
    }
    filter = filter
        .try_with_filter_string(filter_string, reserved_terms)
        .map_err(map_filter_fragment_error)?;
    Ok(filter
        .with_pagination(GmpPagination::new(page as usize, per_page as usize))
        .build())
}

pub(super) fn composed_filter(
    prefix: Option<&str>,
    saved_filter_string: Option<&str>,
    filter_string: Option<&str>,
    pagination: Option<GmpPagination>,
    reserved_terms: &[&str],
) -> Result<Option<String>, GatewayError> {
    let mut filter = PaginatedFilter::new();
    filter = filter.with_filter_string(saved_filter_string);
    if let Some(prefix) = prefix {
        filter = filter.with_clause(prefix);
    }
    filter = filter
        .try_with_filter_string(filter_string, reserved_terms)
        .map_err(map_filter_fragment_error)?;
    if let Some(pagination) = pagination {
        filter = filter.with_pagination(pagination);
    }
    Ok(filter.build())
}

fn map_filter_fragment_error(error: FilterFragmentError) -> GatewayError {
    match error {
        FilterFragmentError::ReservedTerm { term } => {
            GatewayError::InvalidInput(format!("filter contains reserved term '{term}'"))
        }
    }
}
