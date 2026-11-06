// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2026 Greenbone AG

//! Helpers for response enums that must preserve unknown backend values.

use schemars::json_schema;
use serde_json::json;

pub(crate) const OPEN_ENUM_DESCRIPTION: &str = "Known values are listed for documentation and client generation. This list is not exhaustive; unknown future values may also be returned verbatim, and clients must preserve them.";

pub(crate) fn closed_string_enum_schema(name: &str, known_values: &[&str]) -> schemars::Schema {
    let mut schema = json_schema!({
        "title": name,
        "type": "string",
        "enum": known_values
    });

    if let Some(object) = schema.as_object_mut() {
        object.insert("enum".to_string(), json!(known_values));
    }

    schema
}

pub(crate) fn open_string_enum_schema(name: &str, known_values: &[&str]) -> schemars::Schema {
    let mut schema = json_schema!({
        "title": name,
        "type": "string",
        "anyOf": [
            {
                "type": "string",
                "enum": known_values
            },
            {
                "type": "string"
            }
        ],
        "description": OPEN_ENUM_DESCRIPTION
    });

    if let Some(object) = schema.as_object_mut() {
        object.insert(
            "anyOf".to_string(),
            json!([
                {
                    "type": "string",
                    "enum": known_values
                },
                {
                    "type": "string"
                }
            ]),
        );
    }

    schema
}

pub(crate) fn open_u32_enum_schema(name: &str, known_values: &[u32]) -> schemars::Schema {
    let mut schema = json_schema!({
        "title": name,
        "type": "integer",
        "format": "uint32",
        "anyOf": [
            {
                "type": "integer",
                "format": "uint32",
                "enum": known_values
            },
            {
                "type": "integer",
                "format": "uint32"
            }
        ],
        "description": OPEN_ENUM_DESCRIPTION
    });

    if let Some(object) = schema.as_object_mut() {
        object.insert(
            "anyOf".to_string(),
            json!([
                {
                    "type": "integer",
                    "format": "uint32",
                    "enum": known_values
                },
                {
                    "type": "integer",
                    "format": "uint32"
                }
            ]),
        );
    }

    schema
}

macro_rules! open_string_enum {
    (
        $(#[$meta:meta])*
        $vis:vis enum $name:ident {
            $($variant:ident => $value:literal),+ $(,)?
        }
    ) => {
        $(#[$meta])*
        #[derive(Clone, Debug, Eq, PartialEq)]
        $vis enum $name {
            $($variant,)+
            Unknown(String),
        }

        impl $name {
            pub(crate) fn parse(value: &str) -> Self {
                match value {
                    $($value => Self::$variant,)+
                    _ => Self::Unknown(value.to_string()),
                }
            }

            pub(crate) fn as_str(&self) -> &str {
                match self {
                    $(Self::$variant => $value,)+
                    Self::Unknown(value) => value.as_str(),
                }
            }

            pub(crate) fn known_values() -> &'static [&'static str] {
                &[$($value),+]
            }
        }

        impl Serialize for $name {
            fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
            where
                S: serde::Serializer,
            {
                serializer.serialize_str(self.as_str())
            }
        }

        impl<'de> serde::Deserialize<'de> for $name {
            fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
            where
                D: serde::Deserializer<'de>,
            {
                let value = <String as serde::Deserialize<'de>>::deserialize(deserializer)?;
                Ok(Self::parse(&value))
            }
        }

        impl schemars::JsonSchema for $name {
            fn schema_name() -> std::borrow::Cow<'static, str> {
                std::borrow::Cow::Borrowed(stringify!($name))
            }

            fn json_schema(
                _generator: &mut schemars::SchemaGenerator,
            ) -> schemars::Schema {
                crate::open_enum::open_string_enum_schema(
                    stringify!($name),
                    Self::known_values(),
                )
            }
        }
    };
}

macro_rules! open_u32_enum {
    (
        $(#[$meta:meta])*
        $vis:vis enum $name:ident {
            $($variant:ident => $value:literal),+ $(,)?
        }
    ) => {
        $(#[$meta])*
        #[derive(Clone, Debug, Eq, PartialEq)]
        $vis enum $name {
            $($variant,)+
            Unknown(u32),
        }

        impl $name {
            pub(crate) fn parse(value: u32) -> Self {
                match value {
                    $($value => Self::$variant,)+
                    _ => Self::Unknown(value),
                }
            }

            pub(crate) fn as_u32(&self) -> u32 {
                match self {
                    $(Self::$variant => $value,)+
                    Self::Unknown(value) => *value,
                }
            }

            pub(crate) fn known_values() -> &'static [u32] {
                &[$($value),+]
            }
        }

        impl serde::Serialize for $name {
            fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
            where
                S: serde::Serializer,
            {
                serializer.serialize_u32(self.as_u32())
            }
        }

        impl<'de> serde::Deserialize<'de> for $name {
            fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
            where
                D: serde::Deserializer<'de>,
            {
                let value = <u32 as serde::Deserialize<'de>>::deserialize(deserializer)?;
                Ok(Self::parse(value))
            }
        }

        impl schemars::JsonSchema for $name {
            fn schema_name() -> std::borrow::Cow<'static, str> {
                std::borrow::Cow::Borrowed(stringify!($name))
            }

            fn json_schema(
                _generator: &mut schemars::SchemaGenerator,
            ) -> schemars::Schema {
                crate::open_enum::open_u32_enum_schema(
                    stringify!($name),
                    Self::known_values(),
                )
            }
        }
    };
}

pub(crate) use open_string_enum;
pub(crate) use open_u32_enum;
