/*
 * Copyright Cedar Contributors
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
//! This module defines Cedar extension values.

use super::extension_types::datetime::{Datetime, Duration};
use super::extension_types::decimal::Decimal;

type IPAddr = super::extension_types::ipaddr::IPNet;

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub enum Ext {
    Decimal { d: Decimal },
    Ipaddr { ip: IPAddr },
    Datetime { dt: Datetime },
    Duration { d: Duration },
}

impl Ext {
    #[allow(
        clippy::needless_pass_by_value,
        reason = "Pass by value expected by consumer"
    )]
    pub fn parse_decimal(str: String) -> Option<Ext> {
        super::extension_types::decimal::parse(&str).map(|d| Ext::Decimal { d })
    }

    #[allow(
        clippy::needless_pass_by_value,
        reason = "Pass by value expected by consumer"
    )]
    pub fn parse_datetime(str: String) -> Option<Ext> {
        super::extension_types::datetime::Datetime::parse(&str).map(|dt| Ext::Datetime { dt })
    }

    #[allow(
        clippy::needless_pass_by_value,
        reason = "Pass by value expected by consumer"
    )]
    pub fn parse_duration(str: String) -> Option<Ext> {
        super::extension_types::datetime::Duration::parse(&str).map(|d| Ext::Duration { d })
    }
}
