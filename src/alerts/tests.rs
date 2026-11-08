use super::*;
use crate::mail::testsmtp::{Behavior, TestSmtp};
use crate::mail::{MailInput, Security};
use crate::storage::matches::{Confidence, Found, Method, Subject};
use crate::storage::{connect, migrate};

const MIN: i64 = 60_000;

struct Env {
    _dir: tempfile::TempDir,
    pool: SqlitePool,
    secrets: SecretBox,
    smtp: TestSmtp,
}

async fn env_with(behavior: Behavior) -> Env {
    let dir = tempfile::tempdir().unwrap();
    let pool = connect(&dir.path().join("n.db")).await.unwrap();
    migrate(&pool).await.unwrap();
    let secrets = SecretBox::from_key([5u8; 32]);
    let smtp = TestSmtp::spawn(behavior).await;
    let input = MailInput {
        enabled: true,
        host: "127.0.0.1".to_owned(),
        port: smtp.port,
        security: Security::None,
        username: String::new(),
        password: None,
        from_address: "opensecmon@example.org".to_owned(),
        recipients: "admin@example.org".to_owned(),
        language: Lang::De,
    };
    mail_store::save(&pool, &secrets, &input.check().unwrap())
        .await
        .unwrap();
    for (id, host) in [(1, "server01"), (2, "pi01")] {
        sqlx::query(
            "INSERT INTO assets (id, kind, product, product_name, version, host, created_ms, updated_ms)
             VALUES (?, 'package', 'openssh', 'openssh', '1:9.6p1-1', ?, 0, 0)",
        )
        .bind(id)
        .bind(host)
        .execute(&pool)
        .await
        .unwrap();
    }
    Env {
        _dir: dir,
        pool,
        secrets,
        smtp,
    }
}

async fn env() -> Env {
    env_with(Behavior::default()).await
}

/// A CVE with a priority, optionally in KEV.
async fn cve(pool: &SqlitePool, id: &str, prio: i64, kev: bool) {
    sqlx::query(
        "INSERT INTO cves (id, state, title, prio, cvss_score, epss, kev_added)
         VALUES (?, 'published', ?, ?, 7.5, 0.02, ?)",
    )
    .bind(id)
    .bind(format!("Problem in {id}"))
    .bind(prio)
    .bind(kev.then_some("2026-11-01"))
    .execute(pool)
    .await
    .unwrap();
}

/// Lets the matching "find" `vulns` for asset `asset` (in addition to what it found before).
async fn found(pool: &SqlitePool, asset: i64, vulns: &[&str], now: i64) {
    let known: Vec<String> = sqlx::query_scalar("SELECT vuln FROM matches WHERE asset_id = ?")
        .bind(asset)
        .fetch_all(pool)
        .await
        .unwrap();
    let all: Vec<Found> = known
        .iter()
        .map(String::as_str)
        .chain(vulns.iter().copied())
        .map(|v| Found {
            vuln: v.to_owned(),
            title: String::new(),
            confidence: Confidence::High,
            method: Method::Distro,
            fixed: "1:9.6p1-2".to_owned(),
            evidence: vec!["DSA-1".to_owned()],
            base_prio: 0,
            rating: crate::storage::matches::Rating::None,
        })
        .collect();
    matches::sync(pool, Subject::Asset(asset), &all, now)
        .await
        .unwrap();
}

async fn alerts(pool: &SqlitePool) -> Vec<(String, i64, String)> {
    sqlx::query_as("SELECT vuln, asset_id, alert FROM matches ORDER BY id")
        .fetch_all(pool)
        .await
        .unwrap()
}

/// Header and decoded body of a received mail (lettre picks quoted-printable or base64 for the body).
fn decoded(m: &crate::mail::testsmtp::Received) -> String {
    use base64::Engine;
    let data = m.data.replace("\r\n", "\n");
    let (head, body) = data.split_once("\n\n").unwrap_or((&data, ""));
    let lower = head.to_ascii_lowercase();
    let text = if lower.contains("content-transfer-encoding: base64") {
        let joined: String = body.split_whitespace().collect();
        let bytes = base64::engine::general_purpose::STANDARD
            .decode(joined)
            .unwrap();
        String::from_utf8(bytes).unwrap()
    } else if lower.contains("content-transfer-encoding: quoted-printable") {
        let joined = body.replace("=\n", "");
        let mut bytes = Vec::new();
        let raw = joined.as_bytes();
        let mut i = 0;
        while i < raw.len() {
            if raw[i] == b'=' && i + 2 < raw.len() {
                let hex = std::str::from_utf8(&raw[i + 1..i + 3]).unwrap();
                bytes.push(u8::from_str_radix(hex, 16).unwrap());
                i += 3;
            } else {
                bytes.push(raw[i]);
                i += 1;
            }
        }
        String::from_utf8(bytes).unwrap()
    } else {
        body.to_owned()
    };
    format!("{head}\n{text}")
}

fn settings() -> Settings {
    Settings::default()
}

#[test]
fn the_conditions_follow_the_settings() {
    let mut r = compose::tests_support::row(1, "CVE-2026-0001", 70, false, "h");
    let mut s = settings();
    assert!(reasons(&s, &r).is_empty(), "priority 70 is below 85");
    r.kev = true;
    assert_eq!(reasons(&s, &r), [Reason::Kev, Reason::Prio(90, 85)]);
    r.kev = false;
    s.cvss_on = true;
    s.cvss_min = 9.0;
    assert_eq!(reasons(&s, &r), [Reason::Cvss(9.8, 9.0)]);
    s.cvss_on = false;
    s.epss_on = true;
    s.epss_min = 40.0;
    assert_eq!(reasons(&s, &r), [Reason::Epss(50.0, 40.0)]);
    // Below the confidence nothing counts, not even KEV.
    r.kev = true;
    r.confidence = "low".to_owned();
    assert!(reasons(&s, &r).is_empty());
    s.min_confidence = Confidence::Low;
    assert!(reasons(&s, &r).contains(&Reason::Kev));
    // A muted match (below the minimum of its asset) is never mailed.
    r.kev = false;
    r.min_prio = 75;
    assert!(r.muted());
    assert!(reasons(&s, &r).is_empty());
}

#[test]
fn retries_double_up_to_two_hours() {
    assert_eq!(retry_delay(1), 15 * MIN);
    assert_eq!(retry_delay(2), 30 * MIN);
    assert_eq!(retry_delay(4), 120 * MIN);
    assert_eq!(retry_delay(40), 120 * MIN);
}

#[test]
fn report_times_are_local() {
    let tz = TimeZone::get("Europe/Berlin").unwrap();
    // 2026-11-06 06:30 UTC = 07:30 in Berlin; the report at 07:00 local was 06:00 UTC.
    let now = 1_793_946_600_000;
    assert_eq!(slot_ms(&tz, now, 7 * 60), 1_793_944_800_000);
    assert_eq!(next_slot_ms(&tz, now, 7 * 60), 1_793_944_800_000 + DAY_MS);
    // 08:00 local has not come yet today: yesterday's counts.
    assert_eq!(slot_ms(&tz, now, 8 * 60), 1_793_948_400_000 - DAY_MS);
    assert_eq!(next_slot_ms(&tz, now, 8 * 60), 1_793_948_400_000);
    // Summer time ends on 2026-10-25: 07:00 local was 06:00 UTC after and 05:00 UTC before.
    let after = 1_792_915_200_000; // 2026-10-25 08:00 UTC
    assert_eq!(slot_ms(&tz, after, 7 * 60), after - 2 * 3_600_000);
    assert_eq!(
        slot_ms(&tz, after - DAY_MS, 7 * 60),
        after - DAY_MS - 3 * 3_600_000
    );
}

#[tokio::test]
async fn switching_on_takes_the_backlog_as_known_and_new_matches_go_out_bundled() {
    let e = env().await;
    cve(&e.pool, "CVE-2026-0001", 95, true).await;
    cve(&e.pool, "CVE-2026-0002", 90, false).await;
    cve(&e.pool, "CVE-2026-0003", 30, false).await;
    found(&e.pool, 1, &["CVE-2026-0001", "CVE-2026-0003"], 0).await;

    let t0 = 1_000 * MIN;
    assert_eq!(
        instant_round(&e.pool, &e.secrets, t0).await.unwrap(),
        Instant::Baseline(1)
    );
    assert!(e.smtp.received().is_empty());
    assert_eq!(
        alerts(&e.pool).await,
        [
            ("CVE-2026-0001".to_owned(), 1, "quiet".to_owned()),
            ("CVE-2026-0003".to_owned(), 1, String::new()),
        ]
    );
    assert_eq!(
        instant_round(&e.pool, &e.secrets, t0 + MIN).await.unwrap(),
        Instant::Idle
    );

    // A new critical match waits for the bundle, then goes out.
    found(&e.pool, 1, &["CVE-2026-0002"], t0 + 2 * MIN).await;
    assert_eq!(
        instant_round(&e.pool, &e.secrets, t0 + 2 * MIN)
            .await
            .unwrap(),
        Instant::Waiting(1)
    );
    assert_eq!(
        instant_round(&e.pool, &e.secrets, t0 + 11 * MIN)
            .await
            .unwrap(),
        Instant::Waiting(1)
    );
    assert_eq!(
        instant_round(&e.pool, &e.secrets, t0 + 12 * MIN)
            .await
            .unwrap(),
        Instant::Sent(1)
    );
    let mails = e.smtp.received();
    assert_eq!(mails.len(), 1);
    let text = decoded(&mails[0]);
    assert!(text.contains("Neuer Treffer: CVE-2026-0002"), "{text}");
    assert!(text.contains("openssh 1:9.6p1-1 auf server01"), "{text}");
    let log = mail_store::recent_notifications(&e.pool, 5).await.unwrap();
    assert_eq!((log[0].kind, log[0].ok), (Kind::Match, true));

    // The same vulnerability on a second host is not mailed again.
    found(&e.pool, 2, &["CVE-2026-0002"], t0 + 13 * MIN).await;
    assert_eq!(
        instant_round(&e.pool, &e.secrets, t0 + 13 * MIN)
            .await
            .unwrap(),
        Instant::Idle
    );
    assert_eq!(
        alerts(&e.pool).await[3],
        ("CVE-2026-0002".to_owned(), 2, "quiet".to_owned())
    );
    assert_eq!(e.smtp.received().len(), 1);

    // Lower thresholds take what qualifies now as known instead of mailing it.
    let s = Settings {
        prio_min: 20,
        ..settings()
    };
    store::save(&e.pool, &s, t0).await.unwrap();
    assert_eq!(
        instant_round(&e.pool, &e.secrets, t0 + 14 * MIN)
            .await
            .unwrap(),
        Instant::Baseline(1)
    );
    assert_eq!(e.smtp.received().len(), 1);
}

#[tokio::test]
async fn without_bundling_a_match_goes_out_in_the_next_round_and_triaged_ones_stay_quiet() {
    let e = env().await;
    store::save(
        &e.pool,
        &Settings {
            bundle: false,
            public_url: "https://sec.example.org".to_owned(),
            ..settings()
        },
        0,
    )
    .await
    .unwrap();
    cve(&e.pool, "CVE-2026-0001", 95, false).await;
    cve(&e.pool, "CVE-2026-0002", 95, false).await;
    instant_round(&e.pool, &e.secrets, MIN).await.unwrap();
    found(&e.pool, 1, &["CVE-2026-0001", "CVE-2026-0002"], 2 * MIN).await;
    // Done before the mail went out: not mailed.
    sqlx::query("UPDATE matches SET state = 'done' WHERE vuln = 'CVE-2026-0002'")
        .execute(&e.pool)
        .await
        .unwrap();
    assert_eq!(
        instant_round(&e.pool, &e.secrets, 2 * MIN).await.unwrap(),
        Instant::Sent(1)
    );
    let text = decoded(&e.smtp.received()[0]);
    assert!(
        text.contains("https://sec.example.org/?sel=CVE-2026-0001"),
        "{text}"
    );
    assert!(!text.contains("CVE-2026-0002"), "{text}");
}

#[tokio::test]
async fn a_failed_mail_is_retried_later_and_logged() {
    let e = env_with(Behavior {
        reject_recipients: true,
        ..Behavior::default()
    })
    .await;
    store::save(
        &e.pool,
        &Settings {
            bundle: false,
            ..settings()
        },
        0,
    )
    .await
    .unwrap();
    cve(&e.pool, "CVE-2026-0001", 95, false).await;
    instant_round(&e.pool, &e.secrets, MIN).await.unwrap();
    found(&e.pool, 1, &["CVE-2026-0001"], 2 * MIN).await;
    assert_eq!(
        instant_round(&e.pool, &e.secrets, 2 * MIN).await.unwrap(),
        Instant::Failed
    );
    assert_eq!(
        instant_round(&e.pool, &e.secrets, 3 * MIN).await.unwrap(),
        Instant::Waiting(1)
    );
    assert_eq!(
        instant_round(&e.pool, &e.secrets, 18 * MIN).await.unwrap(),
        Instant::Failed
    );
    let log = mail_store::recent_notifications(&e.pool, 5).await.unwrap();
    assert_eq!(log.len(), 2);
    assert!(!log[0].ok);
    assert_eq!(alerts(&e.pool).await[0].2, "", "still to be mailed");
}

#[tokio::test]
async fn mail_switched_off_sends_nothing_and_switching_on_does_not_flood() {
    let e = env().await;
    sqlx::query("UPDATE mail_settings SET enabled = 0")
        .execute(&e.pool)
        .await
        .unwrap();
    cve(&e.pool, "CVE-2026-0001", 95, true).await;
    found(&e.pool, 1, &["CVE-2026-0001"], MIN).await;
    assert_eq!(
        instant_round(&e.pool, &e.secrets, MIN).await.unwrap(),
        Instant::Off
    );
    assert_eq!(
        instant_round(&e.pool, &e.secrets, 20 * MIN).await.unwrap(),
        Instant::Off
    );
    sqlx::query("UPDATE mail_settings SET enabled = 1")
        .execute(&e.pool)
        .await
        .unwrap();
    assert_eq!(
        instant_round(&e.pool, &e.secrets, 30 * MIN).await.unwrap(),
        Instant::Baseline(1)
    );
    assert_eq!(
        instant_round(&e.pool, &e.secrets, 60 * MIN).await.unwrap(),
        Instant::Idle
    );
    assert!(e.smtp.received().is_empty());
}

#[tokio::test]
async fn the_report_goes_out_once_a_day_at_its_time() {
    let e = env().await;
    let tz = TimeZone::get("Europe/Berlin").unwrap();
    let seven = 1_793_944_800_000; // 2026-11-06 07:00 Berlin
    cve(&e.pool, "CVE-2026-0001", 95, true).await;
    found(&e.pool, 1, &["CVE-2026-0001"], seven - 3_600_000).await;

    // Switched on at 07:30: today's 07:00 is not caught up.
    assert_eq!(
        report_round(&e.pool, &e.secrets, &tz, seven + 30 * MIN)
            .await
            .unwrap(),
        Report::Armed
    );
    assert_eq!(
        report_round(&e.pool, &e.secrets, &tz, seven + 31 * MIN)
            .await
            .unwrap(),
        Report::NotYet
    );
    assert_eq!(
        report_round(&e.pool, &e.secrets, &tz, seven + DAY_MS + MIN)
            .await
            .unwrap(),
        Report::Sent
    );
    assert_eq!(
        report_round(&e.pool, &e.secrets, &tz, seven + DAY_MS + 2 * MIN)
            .await
            .unwrap(),
        Report::NotYet
    );
    let mails = e.smtp.received();
    assert_eq!(mails.len(), 1);
    let text = decoded(&mails[0]);
    assert!(text.contains("Tagesbericht 07.11.2026"), "{text}");
    assert!(
        text.contains("[Priorität 95, Kritisch] CVE-2026-0001 · KEV"),
        "{text}"
    );

    // The next day: the match is done, sources fine, nothing new: skipped.
    sqlx::query("UPDATE matches SET state = 'done'")
        .execute(&e.pool)
        .await
        .unwrap();
    assert_eq!(
        report_round(&e.pool, &e.secrets, &tz, seven + 2 * DAY_MS + MIN)
            .await
            .unwrap(),
        Report::Skipped
    );
    assert_eq!(e.smtp.received().len(), 1);

    // "Send now" sends even an empty report.
    let sent = send_report_now(&e.pool, &e.secrets, &tz, seven + 2 * DAY_MS + 5 * MIN)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(sent, ["admin@example.org"]);
    assert_eq!(e.smtp.received().len(), 2);
}

#[tokio::test]
async fn the_report_lists_failed_sources_and_new_matches_since_the_last_one() {
    let e = env().await;
    cve(&e.pool, "CVE-2026-0001", 40, false).await;
    found(&e.pool, 1, &["CVE-2026-0001"], 5 * MIN).await;
    sqlx::query(
        "UPDATE source_state SET last_error = 'HTTP 503', failures = 2, last_success_ms = NULL
         WHERE source = 'kev'",
    )
    .execute(&e.pool)
    .await
    .unwrap();
    let s = Settings {
        report_due: true,
        ..settings()
    };
    let r = build_report(&e.pool, &s, Lang::En, 10 * MIN, Some(MIN))
        .await
        .unwrap();
    assert_eq!(r.new.as_ref().unwrap().len(), 1);
    assert!(
        r.open.as_ref().unwrap().is_empty(),
        "priority 40 is not critical"
    );
    assert_eq!(r.due.as_ref().unwrap().len(), 0);
    let failed = r.sources.as_ref().unwrap();
    assert_eq!(failed.len(), 1);
    assert_eq!(failed[0].error, "HTTP 503");
    let r = build_report(&e.pool, &s, Lang::En, 10 * MIN, Some(6 * MIN))
        .await
        .unwrap();
    assert!(r.new.as_ref().unwrap().is_empty());
}
