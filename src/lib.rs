//! opensecmon – security advisory monitoring for your own hardware and software.

pub mod agent;
pub mod agent_code;
pub mod agent_packages;
pub mod alerts;
pub mod audit;
pub mod auth;
pub mod config;
pub mod crypto;
pub mod csaf;
pub mod error;
pub mod host;
pub mod http_client;
pub mod i18n;
pub mod inventory;
pub mod mail;
pub mod maintenance;
pub mod matching;
pub mod situation;
pub mod sources;
pub mod storage;
pub mod tls;
pub mod version;
pub mod web;

#[cfg(test)]
mod fuzz;
