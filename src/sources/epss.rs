//! FIRST EPSS: the daily CSV (gzip, about 3 MB) with the probability of exploitation in the next 30 days
//! for every CVE and its percentile. The table is replaced as a whole when a new file is published.

use std::time::Duration;

use anyhow::{Context as _, bail};

use crate::http_client::{self, Get, Outcome, gunzip};
use crate::sources::Context;
use crate::sources::cve5::{clip, is_cve_id};
use crate::storage::cves::{in_batches, refresh_all_prios};
use crate::storage::sources::{SourceState, Success};

const MAX_DOWNLOAD: u64 = 64 << 20;
const MAX_UNPACKED: u64 = 256 << 20;
const TIMEOUT: Duration = Duration::from_secs(600);
const MAX_ROWS: usize = 2_000_000;
/// Rows per INSERT statement (three parameters each).
const ROWS_PER_INSERT: usize = 500;

/// The parsed file: model version, score date and the rows `(cve, score, percentile)`.
#[derive(Debug, PartialEq)]
pub struct Scores {
    pub model: String,
    pub date: String,
    pub rows: Vec<(String, f64, f64)>,
}

/// Reads the CSV: `#model_version:…,score_date:…`, the header `cve,epss,percentile`, then the rows. Rows
/// that do not fit (bad id, value outside 0..1) are skipped.
pub fn parse(text: &str) -> anyhow::Result<Scores> {
    let mut model = String::new();
    let mut date = String::new();
    let mut rows = Vec::new();
    let mut header_seen = false;
    for line in text.lines() {
        let line = line.trim();
        if let Some(comment) = line.strip_prefix('#') {
            for part in comment.split(',') {
                if let Some((key, value)) = part.split_once(':') {
                    match key.trim() {
                        "model_version" => model = clip(value.trim(), 40),
                        "score_date" => date = clip(value.trim(), 10),
                        _ => {}
                    }
                }
            }
            continue;
        }
        if !header_seen {
            if line != "cve,epss,percentile" {
                bail!("unexpected header {:?}", clip(line, 60));
            }
            header_seen = true;
            continue;
        }
        let mut fields = line.split(',');
        let (Some(id), Some(score), Some(percentile), None) =
            (fields.next(), fields.next(), fields.next(), fields.next())
        else {
            continue;
        };
        let (Ok(score), Ok(percentile)) = (score.parse::<f64>(), percentile.parse::<f64>()) else {
            continue;
        };
        if !is_cve_id(id) || !(0.0..=1.0).contains(&score) || !(0.0..=1.0).contains(&percentile) {
            continue;
        }
        if rows.len() == MAX_ROWS {
            bail!("more than {MAX_ROWS} rows");
        }
        rows.push((id.to_owned(), score, percentile));
    }
    if rows.is_empty() {
        bail!("no scores in the file");
    }
    Ok(Scores { model, date, rows })
}

pub async fn run(ctx: &Context, state: &SourceState) -> anyhow::Result<Success> {
    let get = Get::new(&ctx.endpoints.epss, MAX_DOWNLOAD, TIMEOUT)
        .conditional(state.etag.as_deref(), state.last_modified.as_deref());
    let fetched = match http_client::get_bytes(&get).await? {
        Outcome::NotModified => return Ok(Success::default()),
        Outcome::Fresh(fetched) => fetched,
    };
    let body = fetched.body;
    let scores = tokio::task::spawn_blocking(move || -> anyhow::Result<Scores> {
        // The file is a .csv.gz (not a gzip transfer encoding); a plain CSV is accepted too.
        let unpacked = if body.starts_with(&[0x1f, 0x8b]) {
            gunzip(&body, MAX_UNPACKED)?
        } else {
            body
        };
        let text = std::str::from_utf8(&unpacked).context("the file is not UTF-8")?;
        parse(text)
    })
    .await??;
    let (new, changed) = store(ctx, &scores).await?;
    Ok(Success {
        etag: fetched.etag,
        last_modified: fetched.last_modified,
        cursor: None,
        version: Some(
            format!("{} {}", scores.model, scores.date)
                .trim()
                .to_owned(),
        ),
        item_count: Some(scores.rows.len() as i64),
        new,
        changed,
        warning: None,
    })
}

/// Replaces the scores (built aside in `epss_new`, then swapped in) and copies them to the CVEs. Returns
/// how many CVEs got a score for the first time and how many changed.
async fn store(ctx: &Context, scores: &Scores) -> crate::error::Result<(i64, i64)> {
    let pool = &ctx.pool;
    sqlx::query("DROP TABLE IF EXISTS epss_new")
        .execute(pool)
        .await?;
    sqlx::query(
        "CREATE TABLE epss_new (cve_id TEXT PRIMARY KEY NOT NULL, score REAL NOT NULL,
                                percentile REAL NOT NULL) STRICT, WITHOUT ROWID",
    )
    .execute(pool)
    .await?;
    for chunk in scores.rows.chunks(ROWS_PER_INSERT * 20) {
        let mut tx = pool.begin().await?;
        for rows in chunk.chunks(ROWS_PER_INSERT) {
            let mut sql =
                String::from("INSERT OR REPLACE INTO epss_new (cve_id, score, percentile) VALUES ");
            sql.push_str(&vec!["(?, ?, ?)"; rows.len()].join(", "));
            let mut query = sqlx::query(&sql);
            for (id, score, percentile) in rows {
                query = query.bind(id).bind(score).bind(percentile);
            }
            query.execute(&mut *tx).await?;
        }
        tx.commit().await?;
        ctx.progress.add(chunk.len() as u64);
    }
    let mut tx = pool.begin().await?;
    sqlx::query("DROP TABLE epss").execute(&mut *tx).await?;
    sqlx::query("ALTER TABLE epss_new RENAME TO epss")
        .execute(&mut *tx)
        .await?;
    tx.commit().await?;
    let new: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM cves JOIN epss ON epss.cve_id = cves.id WHERE cves.epss IS NULL",
    )
    .fetch_one(pool)
    .await?;
    let updated = in_batches(
        pool,
        "UPDATE cves SET epss = epss.score, epss_percentile = epss.percentile FROM epss
         WHERE cves.seq > ?1 AND cves.seq <= ?2 AND epss.cve_id = cves.id
           AND (cves.epss IS NOT epss.score OR cves.epss_percentile IS NOT epss.percentile)",
    )
    .await?;
    let dropped = in_batches(
        pool,
        "UPDATE cves SET epss = NULL, epss_percentile = NULL
         WHERE seq > ?1 AND seq <= ?2 AND epss IS NOT NULL
           AND NOT EXISTS (SELECT 1 FROM epss WHERE epss.cve_id = cves.id)",
    )
    .await?;
    refresh_all_prios(pool).await?;
    let changed = i64::try_from(updated + dropped)
        .unwrap_or(i64::MAX)
        .saturating_sub(new);
    Ok((new, changed))
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::http_client::testserver::{gzip, ok_with, serve};
    use crate::sources::testutil::{context, state};
    use crate::sources::{SourceId, Sources};

    pub(crate) const CSV: &str = "#model_version:v2026.06.15,score_date:2026-11-05T12:03:04Z\n\
                       cve,epss,percentile\n\
                       CVE-1999-0001,0.04753,0.91915\n\
                       CVE-2026-0001,0.5,0.99\n\
                       CVE-2026-0002,1.5,0.5\n\
                       garbage\n";

    #[test]
    fn the_csv_is_read_and_bad_rows_are_skipped() {
        let scores = parse(CSV).unwrap();
        assert_eq!(scores.model, "v2026.06.15");
        assert_eq!(scores.date, "2026-11-05");
        assert_eq!(
            scores.rows,
            [
                ("CVE-1999-0001".to_owned(), 0.04753, 0.91915),
                ("CVE-2026-0001".to_owned(), 0.5, 0.99)
            ]
        );
        assert!(parse("cve,score\nCVE-2026-0001,0.1").is_err());
        assert!(parse("cve,epss,percentile\n").is_err());
    }

    #[test]
    fn the_real_file_can_be_read() {
        // A copy fetched once into dev/cache/ (not in the repository); skipped without it.
        let Ok(bytes) = std::fs::read("dev/cache/epss.csv.gz") else {
            return;
        };
        let text = String::from_utf8(gunzip(&bytes, MAX_UNPACKED).unwrap()).unwrap();
        let scores = parse(&text).unwrap();
        assert!(scores.rows.len() > 300_000, "{}", scores.rows.len());
    }

    #[tokio::test]
    async fn a_run_replaces_the_scores_and_updates_the_cves() {
        let addr = serve(vec![
            ok_with("ETag: \"e1\"\r\n", &gzip(CSV.as_bytes())),
            ok_with(
                "ETag: \"e2\"\r\n",
                b"cve,epss,percentile\nCVE-2026-0002,0.01,0.2\n",
            ),
        ])
        .await;
        let (ctx, _dir) = context(&format!("http://{addr}")).await;
        sqlx::query(
            "INSERT INTO cves (id, state, record_updated, cvss_score)
             VALUES ('CVE-2026-0001', 'published', 'x', 7.0), ('CVE-2026-0002', 'published', 'x', NULL)",
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

        sources.run(SourceId::Epss).await;
        let s = state(&ctx, SourceId::Epss).await;
        assert_eq!(s.last_error, None);
        assert_eq!(s.version.as_deref(), Some("v2026.06.15 2026-11-05"));
        assert_eq!(
            (s.item_count, s.last_new, s.last_changed),
            (Some(2), Some(1), Some(0))
        );
        let (epss, prio): (Option<f64>, i64) =
            sqlx::query_as("SELECT epss, prio FROM cves WHERE id = 'CVE-2026-0001'")
                .fetch_one(&ctx.pool)
                .await
                .unwrap();
        assert_eq!((epss, prio), (Some(0.5), 69), "7.0 × 7 + 0.99 × 20 = 68.8");

        sources.run(SourceId::Epss).await;
        let s = state(&ctx, SourceId::Epss).await;
        assert_eq!(
            (s.item_count, s.last_new, s.last_changed),
            (Some(1), Some(1), Some(1))
        );
        let rows: Vec<(String, Option<f64>, i64)> =
            sqlx::query_as("SELECT id, epss, prio FROM cves ORDER BY id")
                .fetch_all(&ctx.pool)
                .await
                .unwrap();
        assert_eq!(
            rows,
            [
                ("CVE-2026-0001".to_owned(), None, 49),
                ("CVE-2026-0002".to_owned(), Some(0.01), 4)
            ]
        );
    }
}
