-- Phase 8: an asset may show its matches in the inbox only from a priority on (`min_prio`, 0 = all). Matches below
-- are "muted": they stay stored and show when the inbox is filtered by their asset, but leave the views, the
-- counts, the page "Situation" and the mails. Kernel source packages read over SSH start at 65 (band "high"):
-- they bring hundreds to thousands of matches, most of them without a fix.
ALTER TABLE assets ADD COLUMN min_prio INTEGER NOT NULL DEFAULT 0 CHECK (min_prio BETWEEN 0 AND 100);

UPDATE assets SET min_prio = 65
WHERE origin = 'ssh' AND kind = 'package'
  AND (product = 'linux' OR (product LIKE 'linux-%' AND product NOT IN ('linux-firmware', 'linux-base', 'linux-atm')
       AND product NOT LIKE 'linux-meta%'));
