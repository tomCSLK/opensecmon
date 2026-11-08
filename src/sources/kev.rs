//! CISA Known Exploited Vulnerabilities: one JSON file (about 2 MB), fetched only when it changed
//! (ETag/Last-Modified) and then replaced as a whole. CC0.

use std::collections::HashMap;
use std::time::Duration;

use anyhow::{Context as _, bail};
use serde::Deserialize;

use crate::http_client::{self, Get, Outcome};
use crate::sources::Context;
use crate::sources::cve5::{clip, is_cve_id};
use crate::storage::cves::{refresh_derived, refresh_kev_prios};
use crate::storage::sources::{SourceState, Success};

const MAX_BYTES: u64 = 64 << 20;
const TIMEOUT: Duration = Duration::from_secs(300);
const MAX_ENTRIES: usize = 100_000;

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct Catalog {
    #[serde(default)]
    catalog_version: String,
    #[serde(deserialize_with = "crate::csaf::list")]
    vulnerabilities: Vec<RawEntry>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(rename_all = "camelCase", default)]
struct RawEntry {
    #[serde(rename = "cveID")]
    cve_id: String,
    vendor_project: String,
    product: String,
    vulnerability_name: String,
    date_added: String,
    short_description: String,
    required_action: String,
    due_date: String,
    known_ransomware_campaign_use: String,
    notes: String,
}

/// One entry of the catalog, checked and cut to size.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Entry {
    pub cve_id: String,
    pub vendor: String,
    pub product: String,
    pub name: String,
    pub description: String,
    pub date_added: String,
    pub due_date: String,
    pub ransomware: String,
    pub required_action: String,
    pub notes: String,
}

/// A date `YYYY-MM-DD`, or nothing.
fn date(s: &str) -> Option<String> {
    s.trim()
        .parse::<jiff::civil::Date>()
        .ok()
        .map(|d| d.to_string())
}

/// Reads the catalog: its version and the valid entries (an entry without CVE id or date is skipped).
pub fn parse(bytes: &[u8]) -> anyhow::Result<(String, Vec<Entry>)> {
    let catalog: Catalog =
        crate::csaf::with_budget(MAX_ENTRIES + 1, || serde_json::from_slice(bytes))
            .context("the catalog is not valid JSON")?;
    if catalog.vulnerabilities.len() > MAX_ENTRIES {
        bail!("the catalog has more than {MAX_ENTRIES} entries");
    }
    let mut entries = Vec::with_capacity(catalog.vulnerabilities.len());
    let mut seen = std::collections::HashSet::new();
    for raw in catalog.vulnerabilities {
        let id = raw.cve_id.trim();
        let Some(date_added) = date(&raw.date_added) else {
            continue;
        };
        if !is_cve_id(id) || !seen.insert(id.to_owned()) {
            continue;
        }
        entries.push(Entry {
            cve_id: id.to_owned(),
            vendor: clip(raw.vendor_project.trim(), 200),
            product: clip(raw.product.trim(), 200),
            name: clip(raw.vulnerability_name.trim(), 500),
            description: clip(raw.short_description.trim(), 4000),
            date_added,
            due_date: date(&raw.due_date).unwrap_or_default(),
            ransomware: clip(raw.known_ransomware_campaign_use.trim(), 40),
            required_action: clip(raw.required_action.trim(), 2000),
            notes: clip(raw.notes.trim(), 4000),
        });
    }
    if entries.is_empty() {
        bail!("the catalog has no valid entries");
    }
    Ok((clip(catalog.catalog_version.trim(), 40), entries))
}

pub async fn run(ctx: &Context, state: &SourceState) -> anyhow::Result<Success> {
    let get = Get::new(&ctx.endpoints.kev, MAX_BYTES, TIMEOUT)
        .accept("application/json")
        .conditional(state.etag.as_deref(), state.last_modified.as_deref());
    let fetched = match http_client::get_bytes(&get).await? {
        Outcome::NotModified => return Ok(Success::default()),
        Outcome::Fresh(fetched) => fetched,
    };
    let (version, entries) = parse(&fetched.body)?;
    ctx.progress.add(entries.len() as u64);
    let (new, changed) = store(&ctx.pool, &entries).await?;
    Ok(Success {
        etag: fetched.etag,
        last_modified: fetched.last_modified,
        cursor: None,
        version: Some(version),
        item_count: Some(entries.len() as i64),
        new,
        changed,
        warning: None,
    })
}

/// Replaces the catalog; returns how many entries are new and how many changed.
pub async fn store(pool: &sqlx::SqlitePool, entries: &[Entry]) -> crate::error::Result<(i64, i64)> {
    let old: HashMap<String, Entry> = sqlx::query_as::<
        _,
        (
            String,
            String,
            String,
            String,
            String,
            String,
            String,
            String,
            String,
            String,
        ),
    >(
        "SELECT cve_id, vendor, product, name, description, date_added, due_date, ransomware,
                required_action, notes FROM kev",
    )
    .fetch_all(pool)
    .await?
    .into_iter()
    .map(|r| {
        (
            r.0.clone(),
            Entry {
                cve_id: r.0,
                vendor: r.1,
                product: r.2,
                name: r.3,
                description: r.4,
                date_added: r.5,
                due_date: r.6,
                ransomware: r.7,
                required_action: r.8,
                notes: r.9,
            },
        )
    })
    .collect();
    let (mut new, mut changed) = (0, 0);
    for e in entries {
        match old.get(&e.cve_id) {
            None => new += 1,
            Some(o) if o != e => changed += 1,
            Some(_) => {}
        }
    }

    let mut tx = pool.begin().await?;
    sqlx::query("DELETE FROM kev").execute(&mut *tx).await?;
    for e in entries {
        sqlx::query(
            "INSERT INTO kev (cve_id, vendor, product, name, description, date_added, due_date, ransomware,
                              required_action, notes)
             VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        )
        .bind(&e.cve_id)
        .bind(&e.vendor)
        .bind(&e.product)
        .bind(&e.name)
        .bind(&e.description)
        .bind(&e.date_added)
        .bind(&e.due_date)
        .bind(&e.ransomware)
        .bind(&e.required_action)
        .bind(&e.notes)
        .execute(&mut *tx)
        .await?;
    }
    // Both updates go through indexes (the partial index on kev_added, the unique id): a scan of all
    // CVEs took six seconds per statement on the full database.
    let removed: Vec<String> = sqlx::query_scalar(
        "SELECT id FROM cves
         WHERE kev_added IS NOT NULL AND NOT EXISTS (SELECT 1 FROM kev WHERE kev.cve_id = cves.id)",
    )
    .fetch_all(&mut *tx)
    .await?;
    for id in &removed {
        sqlx::query("UPDATE cves SET kev_added = NULL WHERE id = ?")
            .bind(id)
            .execute(&mut *tx)
            .await?;
        refresh_derived(&mut tx, id).await?;
    }
    sqlx::query(
        "UPDATE cves SET kev_added = (SELECT date_added FROM kev WHERE kev.cve_id = cves.id)
         WHERE id IN (SELECT cve_id FROM kev)
           AND kev_added IS NOT (SELECT date_added FROM kev WHERE kev.cve_id = cves.id)",
    )
    .execute(&mut *tx)
    .await?;
    refresh_kev_prios(&mut tx).await?;
    tx.commit().await?;
    Ok((new, changed))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::http_client::testserver::{ok_with, serve_and_record, status};
    use crate::sources::testutil::{context, state};
    use crate::sources::{SourceId, Sources};

    fn catalog(entries: &[(&str, &str)]) -> String {
        let list: Vec<String> = entries
            .iter()
            .map(|(id, added)| {
                format!(
                    r#"{{"cveID": "{id}", "vendorProject": "Example", "product": "Widget",
                        "vulnerabilityName": "Widget RCE", "dateAdded": "{added}", "shortDescription": "x",
                        "requiredAction": "Patch.", "dueDate": "2026-11-25",
                        "knownRansomwareCampaignUse": "Unknown", "notes": "", "cwes": []}}"#
                )
            })
            .collect();
        format!(
            r#"{{"title": "CISA Catalog", "catalogVersion": "2026.11.04", "count": {},
                "vulnerabilities": [{}]}}"#,
            entries.len(),
            list.join(",")
        )
    }

    #[test]
    fn the_catalog_is_read_and_bad_entries_are_skipped() {
        let text = catalog(&[
            ("CVE-2024-27834", "2026-11-04"),
            ("not-a-cve", "2026-11-04"),
            ("CVE-2024-1", "2026-11-04"),
            ("CVE-2024-27835", "yesterday"),
            ("CVE-2024-27834", "2026-11-05"),
        ]);
        let (version, entries) = parse(text.as_bytes()).unwrap();
        assert_eq!(version, "2026.11.04");
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].date_added, "2026-11-04");
        assert_eq!(entries[0].ransomware, "Unknown");
        assert!(parse(b"{}").is_err());
        assert!(parse(catalog(&[]).as_bytes()).is_err());
    }

    #[test]
    fn the_real_catalog_can_be_read() {
        // A copy fetched once into dev/cache/ (not in the repository); skipped without it.
        let Ok(bytes) = std::fs::read("dev/cache/kev.json") else {
            return;
        };
        let (_, entries) = parse(&bytes).unwrap();
        assert!(entries.len() > 1000);
    }

    #[tokio::test]
    async fn a_run_stores_the_catalog_marks_the_cves_and_asks_conditionally_next_time() {
        let body = catalog(&[
            ("CVE-2026-0001", "2026-11-04"),
            ("CVE-2026-0002", "2026-11-03"),
        ]);
        let (addr, mut requests) = serve_and_record(vec![
            ok_with("ETag: \"k1\"\r\n", body.as_bytes()),
            status(304, ""),
        ])
        .await;
        let (ctx, _dir) = context(&format!("http://{addr}")).await;
        sqlx::query(
            "INSERT INTO cves (id, state, record_updated, cvss_score) VALUES ('CVE-2026-0001', 'published', 'x', 5.0)",
        )
        .execute(&ctx.pool)
        .await
        .unwrap();

        let sources = Sources::new(
            ctx.pool.clone(),
            ctx.work_dir.clone(),
            (*ctx.endpoints).clone(),
            false,
        );
        sources.run(SourceId::Kev).await;
        let s = state(&ctx, SourceId::Kev).await;
        assert_eq!(s.last_error, None);
        assert_eq!((s.last_new, s.last_changed), (Some(2), Some(0)));
        assert_eq!(s.version.as_deref(), Some("2026.11.04"));
        assert_eq!(s.item_count, Some(2));
        assert_eq!(s.etag.as_deref(), Some("\"k1\""));
        let (added, prio): (Option<String>, i64) =
            sqlx::query_as("SELECT kev_added, prio FROM cves WHERE id = 'CVE-2026-0001'")
                .fetch_one(&ctx.pool)
                .await
                .unwrap();
        assert_eq!(added.as_deref(), Some("2026-11-04"));
        assert_eq!(prio, 90, "KEV lifts the priority to at least 90");

        sources.run(SourceId::Kev).await;
        let _ = requests.recv().await.unwrap();
        let second = requests.recv().await.unwrap().to_ascii_lowercase();
        assert!(second.contains("if-none-match: \"k1\""), "{second}");
        let s = state(&ctx, SourceId::Kev).await;
        assert_eq!((s.last_new, s.last_changed), (Some(0), Some(0)));
        assert_eq!(s.item_count, Some(2), "a 304 keeps the stored state");
    }

    #[tokio::test]
    async fn a_cve_that_leaves_the_catalog_loses_its_mark() {
        let (ctx, _dir) = context("http://127.0.0.1:9").await;
        sqlx::query("INSERT INTO cves (id, state, record_updated) VALUES ('CVE-2026-0001', 'published', 'x')")
            .execute(&ctx.pool)
            .await
            .unwrap();
        let entry = |id: &str| Entry {
            cve_id: id.into(),
            vendor: String::new(),
            product: String::new(),
            name: String::new(),
            description: String::new(),
            date_added: "2026-11-01".into(),
            due_date: String::new(),
            ransomware: String::new(),
            required_action: String::new(),
            notes: String::new(),
        };
        assert_eq!(
            store(&ctx.pool, &[entry("CVE-2026-0001")]).await.unwrap(),
            (1, 0)
        );
        assert_eq!(
            store(&ctx.pool, &[entry("CVE-2026-0002")]).await.unwrap(),
            (1, 0)
        );
        let (added, prio): (Option<String>, i64) =
            sqlx::query_as("SELECT kev_added, prio FROM cves WHERE id = 'CVE-2026-0001'")
                .fetch_one(&ctx.pool)
                .await
                .unwrap();
        assert_eq!((added, prio), (None, 0));
    }
}
