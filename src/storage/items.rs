//! The software computers and hosts report beside their packages (table `agent_items`, by the `origin_ref` of
//! their assets) and the rules of the user that turn it into assets (table `item_rules`); the built-in rules and
//! the keys are in [`crate::inventory::items`].

use std::collections::{BTreeSet, HashMap};

use sqlx::SqlitePool;

use crate::error::Result;
use crate::inventory::items::{self, Item, ItemType, Resolution, Rule, Source};
use crate::storage::assets::{Checked, Input};
use crate::storage::inventory::PackageSync;

/// Replaces the entries of a computer or host (with every full report or reading).
pub async fn replace(
    tx: &mut sqlx::SqliteConnection,
    origin_ref: &str,
    list: &[Item],
) -> Result<()> {
    delete_all(&mut *tx, origin_ref).await?;
    for i in list {
        sqlx::query(
            "INSERT OR IGNORE INTO agent_items
                 (origin_ref, type, item_id, item_key, name, version, publisher, winget_id, scope)
             VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
        )
        .bind(origin_ref)
        .bind(i.item_type.as_str())
        .bind(&i.id)
        .bind(&i.key)
        .bind(&i.name)
        .bind(&i.version)
        .bind(&i.publisher)
        .bind(&i.winget_id)
        .bind(if i.user_scope { "user" } else { "machine" })
        .execute(&mut *tx)
        .await?;
    }
    Ok(())
}

/// Removes the entries of a computer or host (when it is removed).
pub async fn delete_all(tx: &mut sqlx::SqliteConnection, origin_ref: &str) -> Result<()> {
    sqlx::query("DELETE FROM agent_items WHERE origin_ref = ?")
        .bind(origin_ref)
        .execute(&mut *tx)
        .await?;
    Ok(())
}

type RuleRow = (i64, String, String, String, String, String, i64);

fn rule_of(r: RuleRow) -> Option<Rule> {
    let (id, item_type, key, action, vendor_name, product_name, created_ms) = r;
    Some(Rule {
        id,
        item_type: ItemType::parse(&item_type)?,
        key,
        resolution: if action == "ignore" {
            Resolution::Ignore
        } else {
            Resolution::Asset {
                vendor_name,
                product_name,
            }
        },
        created_ms,
    })
}

const RULE_COLUMNS: &str = "id, type, item_key, action, vendor_name, product_name, created_ms";

/// The rules of the user, newest first.
pub async fn list_rules<'e, E: sqlx::SqliteExecutor<'e>>(executor: E) -> Result<Vec<Rule>> {
    let rows: Vec<RuleRow> = sqlx::query_as(&format!(
        "SELECT {RULE_COLUMNS} FROM item_rules ORDER BY created_ms DESC, id DESC"
    ))
    .fetch_all(executor)
    .await?;
    Ok(rows.into_iter().filter_map(rule_of).collect())
}

/// The rules of the user by type and key.
pub async fn rules<'e, E: sqlx::SqliteExecutor<'e>>(
    executor: E,
) -> Result<HashMap<(ItemType, String), Rule>> {
    Ok(list_rules(executor)
        .await?
        .into_iter()
        .map(|r| ((r.item_type, r.key.clone()), r))
        .collect())
}

pub async fn rule(pool: &SqlitePool, id: i64) -> Result<Option<Rule>> {
    let row: Option<RuleRow> = sqlx::query_as(&format!(
        "SELECT {RULE_COLUMNS} FROM item_rules WHERE id = ?"
    ))
    .bind(id)
    .fetch_optional(pool)
    .await?;
    Ok(row.and_then(rule_of))
}

/// Sets the rule of an entry (a rule for the same type and key is replaced); returns its id.
pub async fn set_rule(
    pool: &SqlitePool,
    item_type: ItemType,
    key: &str,
    resolution: &Resolution,
    now_ms: i64,
) -> Result<i64> {
    let (action, vendor, product) = match resolution {
        Resolution::Asset {
            vendor_name,
            product_name,
        } => ("asset", vendor_name.as_str(), product_name.as_str()),
        Resolution::Ignore | Resolution::Unassigned => ("ignore", "", ""),
    };
    let (id,): (i64,) = sqlx::query_as(
        "INSERT INTO item_rules (type, item_key, action, vendor_name, product_name, created_ms)
         VALUES (?, ?, ?, ?, ?, ?)
         ON CONFLICT (type, item_key) DO UPDATE SET action = excluded.action,
             vendor_name = excluded.vendor_name, product_name = excluded.product_name,
             created_ms = excluded.created_ms
         RETURNING id",
    )
    .bind(item_type.as_str())
    .bind(key)
    .bind(action)
    .bind(vendor)
    .bind(product)
    .bind(now_ms)
    .fetch_one(pool)
    .await?;
    Ok(id)
}

pub async fn delete_rule(pool: &SqlitePool, id: i64) -> Result<Option<Rule>> {
    let Some(r) = rule(pool, id).await? else {
        return Ok(None);
    };
    sqlx::query("DELETE FROM item_rules WHERE id = ?")
        .bind(id)
        .execute(pool)
        .await?;
    Ok(Some(r))
}

/// The computers and hosts (`origin_ref`) that reported an entry of this type and key.
pub async fn origins_with(
    pool: &SqlitePool,
    item_type: ItemType,
    key: &str,
) -> Result<Vec<String>> {
    let ids: Vec<(String,)> = sqlx::query_as(
        "SELECT DISTINCT origin_ref FROM agent_items WHERE type = ? AND item_key = ? ORDER BY origin_ref",
    )
    .bind(item_type.as_str())
    .bind(key)
    .fetch_all(pool)
    .await?;
    Ok(ids.into_iter().map(|(id,)| id).collect())
}

/// The asset an entry becomes, if any.
fn asset_of(
    rules: &HashMap<(ItemType, String), Rule>,
    item_type: ItemType,
    key: &str,
    name: &str,
    version: &str,
    publisher: &str,
    host: &str,
) -> Option<Checked> {
    let (
        Resolution::Asset {
            vendor_name,
            product_name,
        },
        _,
    ) = items::resolve(rules, item_type, key, publisher, name)
    else {
        return None;
    };
    let version = items::item_version(item_type, name, version);
    Input {
        kind: "software".into(),
        vendor_name,
        product_name,
        version,
        host: host.to_owned(),
        ..Default::default()
    }
    .check()
    .ok()
}

/// The origin of the assets of a computer or host ('agent' or 'ssh'), by its `origin_ref`.
fn origin_of(origin_ref: &str) -> &'static str {
    if origin_ref.starts_with("ssh:") {
        "ssh"
    } else {
        "agent"
    }
}

/// Makes the software assets of a computer or host match its entries and the rules: one asset per product and
/// version (two versions of a program stay two assets). The assets of the same product keep their id (and their
/// matches) when the version changes.
pub async fn sync_origin(
    tx: &mut sqlx::SqliteConnection,
    origin_ref: &str,
    host: &str,
    now_ms: i64,
) -> Result<PackageSync> {
    let rules = rules(&mut *tx).await?;
    let rows: Vec<(String, String, String, String, String)> = sqlx::query_as(
        "SELECT type, item_key, name, version, publisher FROM agent_items WHERE origin_ref = ?
         ORDER BY type, item_key, item_id",
    )
    .bind(origin_ref)
    .fetch_all(&mut *tx)
    .await?;
    let mut seen = BTreeSet::new();
    let mut desired = Vec::new();
    for (item_type, key, name, version, publisher) in rows {
        let Some(item_type) = ItemType::parse(&item_type) else {
            continue;
        };
        if let Some(c) = asset_of(&rules, item_type, &key, &name, &version, &publisher, host)
            && seen.insert((c.vendor.clone(), c.product.clone(), c.version.clone()))
        {
            desired.push(c);
        }
    }
    sync_software(tx, origin_of(origin_ref), origin_ref, &desired, now_ms).await
}

/// A stored software asset: id, version, host.
type Stored = (i64, String, String);

/// Makes the software assets of one source exactly `desired`; see [`sync_origin`].
pub async fn sync_software(
    tx: &mut sqlx::SqliteConnection,
    origin: &str,
    origin_ref: &str,
    desired: &[Checked],
    now_ms: i64,
) -> Result<PackageSync> {
    let existing: Vec<(i64, String, String, String, String)> = sqlx::query_as(
        "SELECT id, vendor, product, version, host FROM assets
         WHERE origin_ref = ? AND kind = 'software' ORDER BY id",
    )
    .bind(origin_ref)
    .fetch_all(&mut *tx)
    .await?;
    let mut by_product: HashMap<(String, String), Vec<Stored>> = HashMap::new();
    for (id, vendor, product, version, host) in existing {
        by_product
            .entry((vendor, product))
            .or_default()
            .push((id, version, host));
    }
    let mut sync = PackageSync::default();
    // First the assets whose version stays, then the others of the same product take a new version.
    let mut rest = Vec::new();
    for c in desired {
        let list = by_product.get_mut(&(c.vendor.clone(), c.product.clone()));
        match list.and_then(|l| l.iter().position(|e| e.1 == c.version).map(|p| (l, p))) {
            Some((list, pos)) => {
                let (id, _, host) = list.remove(pos);
                if host != c.host {
                    crate::storage::assets::update(&mut *tx, id, c, now_ms).await?;
                    sync.updated += 1;
                }
            }
            None => rest.push(c),
        }
    }
    for c in rest {
        let reuse = by_product
            .get_mut(&(c.vendor.clone(), c.product.clone()))
            .filter(|l| !l.is_empty())
            .map(|l| l.remove(0));
        match reuse {
            Some((id, ..)) => {
                crate::storage::assets::update(&mut *tx, id, c, now_ms).await?;
                sync.changed.push(id);
                sync.updated += 1;
            }
            None => {
                let id = crate::storage::assets::add_from(&mut *tx, c, origin, origin_ref, now_ms)
                    .await?;
                sync.changed.push(id);
                sync.added += 1;
            }
        }
    }
    for (id, ..) in by_product.into_values().flatten() {
        sqlx::query("DELETE FROM assets WHERE id = ?")
            .bind(id)
            .execute(&mut *tx)
            .await?;
        sync.removed += 1;
    }
    Ok(sync)
}

/// The name of a computer or host by its `origin_ref` (`None` if it is gone).
async fn origin_name(pool: &SqlitePool, origin_ref: &str) -> Result<Option<String>> {
    let id = |p: &str| {
        origin_ref
            .strip_prefix(p)
            .and_then(|n| n.parse::<i64>().ok())
    };
    if let Some(id) = id("agent:") {
        return Ok(crate::storage::agents::device(pool, id)
            .await?
            .map(|d| d.name));
    }
    if let Some(id) = id("ssh:") {
        return Ok(crate::storage::inventory::host(pool, id)
            .await?
            .map(|h| h.name));
    }
    Ok(None)
}

/// Applies the rules again to the computers and hosts that reported an entry (after a rule was set or removed);
/// returns the assets to match.
pub async fn resync(pool: &SqlitePool, origins: &[String], now_ms: i64) -> Result<Vec<i64>> {
    let mut changed = Vec::new();
    for origin_ref in origins {
        let Some(name) = origin_name(pool, origin_ref).await? else {
            continue;
        };
        // A write transaction from the start: one that reads first cannot write once the matching has written
        // in between (SQLITE_BUSY at once instead of waiting).
        let mut tx = pool.begin_with("BEGIN IMMEDIATE").await?;
        let sync = sync_origin(&mut tx, origin_ref, &name, now_ms).await?;
        tx.commit().await?;
        changed.extend(sync.changed);
    }
    Ok(changed)
}

/// Applies the rules again to all computers and hosts with entries: at start-up, so that rules built into a new
/// version (or a changed way of taking the version) reach computers whose reports have not changed since.
pub async fn resync_all(pool: &SqlitePool, now_ms: i64) -> Result<Vec<i64>> {
    let origins: Vec<String> =
        sqlx::query_scalar("SELECT DISTINCT origin_ref FROM agent_items ORDER BY origin_ref")
            .fetch_all(pool)
            .await?;
    resync(pool, &origins, now_ms).await
}

/// One entry as the page "Unassigned" shows it: all computers and hosts with the same type and key together.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Group {
    pub item_type: ItemType,
    pub key: String,
    /// The name most computers show, and the publisher.
    pub name: String,
    pub publisher: String,
    /// The versions reported (sorted, distinct).
    pub versions: Vec<String>,
    /// The computers and hosts (names, sorted).
    pub computers: Vec<String>,
    /// Their `origin_ref`.
    pub origins: BTreeSet<String>,
    /// Installed for one user only on some computer.
    pub user_scope: bool,
    pub resolution: Resolution,
    pub source: Source,
}

/// Type, key, name, version, publisher, scope, `origin_ref` and name of the computer or host.
type GroupRow = (
    String,
    String,
    String,
    String,
    String,
    String,
    String,
    String,
);

/// All entries of all computers and hosts, grouped by type and key, resolved by the rules (without Windows itself).
pub async fn groups(pool: &SqlitePool) -> Result<Vec<Group>> {
    let rules = rules(pool).await?;
    let rows: Vec<GroupRow> = sqlx::query_as(
        "SELECT i.type, i.item_key, i.name, i.version, i.publisher, i.scope, i.origin_ref,
                COALESCE(d.name, h.name)
         FROM agent_items i
         LEFT JOIN agent_devices d ON i.origin_ref = 'agent:' || d.id
         LEFT JOIN ssh_hosts h ON i.origin_ref = 'ssh:' || h.id
         WHERE i.type != 'os' AND COALESCE(d.name, h.name) IS NOT NULL
         ORDER BY i.type, i.item_key",
    )
    .fetch_all(pool)
    .await?;
    let mut out: Vec<Group> = Vec::new();
    let mut names: HashMap<String, usize> = HashMap::new();
    for (item_type, key, name, version, publisher, scope, origin_ref, device) in rows {
        let Some(item_type) = ItemType::parse(&item_type) else {
            continue;
        };
        let same = out
            .last()
            .is_some_and(|g| g.item_type == item_type && g.key == key);
        if !same {
            names.clear();
            let (resolution, source) = items::resolve(&rules, item_type, &key, &publisher, &name);
            out.push(Group {
                item_type,
                key: key.clone(),
                name: name.clone(),
                publisher: String::new(),
                versions: Vec::new(),
                computers: Vec::new(),
                origins: BTreeSet::new(),
                user_scope: false,
                resolution,
                source,
            });
        }
        let g = out.last_mut().expect("pushed above");
        let n = names.entry(name.clone()).or_default();
        *n += 1;
        if *n > names.get(&g.name).copied().unwrap_or(0) {
            g.name = name;
        }
        if g.publisher.is_empty() {
            g.publisher = publisher;
        }
        if !version.is_empty() && !g.versions.contains(&version) {
            g.versions.push(version);
        }
        if g.origins.insert(origin_ref) {
            g.computers.push(device);
        }
        g.user_scope |= scope == "user";
    }
    for g in &mut out {
        g.versions
            .sort_by(|a, b| crate::version::compare(crate::version::Scheme::Generic, a, b));
        g.computers.sort();
    }
    Ok(out)
}

/// The entries no rule decides.
pub async fn unassigned(pool: &SqlitePool) -> Result<Vec<Group>> {
    let mut list: Vec<Group> = groups(pool)
        .await?
        .into_iter()
        .filter(|g| g.resolution == Resolution::Unassigned)
        .collect();
    list.sort_by(|a, b| {
        b.origins
            .len()
            .cmp(&a.origins.len())
            .then_with(|| a.name.to_lowercase().cmp(&b.name.to_lowercase()))
    });
    Ok(list)
}

/// One entry by type and key, whatever decides it.
pub async fn group(pool: &SqlitePool, item_type: ItemType, key: &str) -> Result<Option<Group>> {
    Ok(groups(pool)
        .await?
        .into_iter()
        .find(|g| g.item_type == item_type && g.key == key))
}

/// The number of unassigned entries in all and per computer or host (by `origin_ref`).
pub async fn unassigned_counts(pool: &SqlitePool) -> Result<(usize, HashMap<String, usize>)> {
    let list = unassigned(pool).await?;
    let mut per_origin: HashMap<String, usize> = HashMap::new();
    for g in &list {
        for o in &g.origins {
            *per_origin.entry(o.clone()).or_default() += 1;
        }
    }
    Ok((list.len(), per_origin))
}
