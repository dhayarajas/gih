# Querying the database

Everything an investigation stores lives in one SQLite file. The report is a
view over it; this is how to read the same data directly.

## Where the file is

`~/.ghost_hunter/investigations.db` (`DEFAULT_DB_PATH` in
`src/storage/database.py`), unless you passed `--db`:

```bash
python3 -m src.cli --db /tmp/case.db investigate --username octocat
sqlite3 /tmp/case.db
```

The `database.path` key in `config/config.yaml` is **not** read by anything —
`--db` and the default above are what decide the location.

## Getting in and out

```bash
sqlite3 ~/.ghost_hunter/investigations.db
```

```
.tables                 -- list tables
.schema artifacts       -- one table's definition
.headers on             -- column names in output
.mode column            -- aligned columns (.mode line for tall rows, .mode json for JSON)
.quit                   -- leave (Ctrl-D also works)
```

If the prompt changes to `...>` it is waiting for the `;` that ends your
statement. Type `;` and Enter.

A one-off query without entering the shell:

```bash
sqlite3 -header -column ~/.ghost_hunter/investigations.db "SELECT * FROM investigations;"
```

Read-only, which is the safe way to look at a database an investigation may be
writing to:

```bash
sqlite3 "file:$HOME/.ghost_hunter/investigations.db?mode=ro" "SELECT COUNT(*) FROM artifacts;"
```

## Tables

| Table | Holds |
| --- | --- |
| `investigations` | one row per run: `investigation_id` (`INV-xxxxxxxx`), `title`, `status`, `created_at` |
| `artifacts` | every finding: `artifact_type`, `value`, `source`, `confidence`, `metadata` (JSON text), `depth` |
| `artifact_links` | directed edges between artifacts: `source_artifact`, `target_artifact`, `link_type`, `confidence`, `evidence` |
| `platform_presence` | accounts found on platforms: `platform_name`, `profile_url`, `username`, `display_name`, `bio`, `follower_count` |
| `evidence` | preserved raw tool output: `tool`, `command`, `exit_status`, `sha256`, `byte_size`, `stored_path` (the bytes are on disk under `evidence.directory`) |
| `investigation_metadata` | key/value extras attached to a run |
| `audit_trail` | lifecycle events: `action`, `entity_type`, `entity_id`, `performed_at` |
| `comments` | analyst notes, created on first use by `src/collaboration/comments.py` |
| `geocode_cache` | place name → coordinates for the report map, shared across investigations; a miss is cached too |

Identity profiles and risk scores are **not** stored — the linker and scorer
derive them from `artifacts` and `artifact_links` each time a report is built.

## Queries

Shell variable for brevity in the rest of this file:

```bash
DB=~/.ghost_hunter/investigations.db
INV=INV-fb2b248d
```

The most recent runs, and how much each found:

```sql
SELECT i.investigation_id, i.title, i.created_at,
       (SELECT COUNT(*) FROM artifacts a WHERE a.investigation_id = i.investigation_id) AS artifacts
FROM investigations i
ORDER BY i.created_at DESC
LIMIT 10;
```

Everything one run found, most confident first:

```sql
SELECT artifact_type, value, source, confidence, depth
FROM artifacts
WHERE investigation_id = 'INV-fb2b248d'
ORDER BY confidence DESC, artifact_type;
```

What kinds of thing it found:

```sql
SELECT artifact_type, COUNT(*) AS n
FROM artifacts WHERE investigation_id = 'INV-fb2b248d'
GROUP BY artifact_type ORDER BY n DESC;
```

Which tool or module produced what — the same view the report's Tool Run Status
section shows:

```sql
SELECT source, COUNT(*) AS artifacts, ROUND(AVG(confidence), 2) AS avg_confidence
FROM artifacts WHERE investigation_id = 'INV-fb2b248d'
GROUP BY source ORDER BY artifacts DESC;
```

Accounts found, with the bio the parsers recovered:

```sql
SELECT platform_name, username, profile_url, follower_count, bio
FROM platform_presence WHERE investigation_id = 'INV-fb2b248d';
```

The links, resolved to the values they connect (an evidence chain is a walk over
this table):

```sql
SELECT s.artifact_type || ':' || s.value AS from_artifact,
       l.link_type, ROUND(l.confidence, 2) AS confidence,
       t.artifact_type || ':' || t.value AS to_artifact
FROM artifact_links l
JOIN artifacts s ON s.artifact_id = l.source_artifact
JOIN artifacts t ON t.artifact_id = l.target_artifact
WHERE l.investigation_id = 'INV-fb2b248d'
ORDER BY l.confidence DESC;
```

What was found *from* one artifact:

```sql
SELECT t.artifact_type, t.value, l.link_type
FROM artifact_links l JOIN artifacts t ON t.artifact_id = l.target_artifact
WHERE l.source_artifact = (
    SELECT artifact_id FROM artifacts
    WHERE investigation_id = 'INV-fb2b248d' AND value = 'octocat'
);
```

How each external tool run ended, and how long it took — this is where a
`timeout` is distinguishable from a failure:

```sql
SELECT tool, operation, target, exit_status,
       ROUND(duration_seconds, 1) AS seconds, byte_size
FROM evidence WHERE investigation_id = 'INV-fb2b248d'
ORDER BY duration_seconds DESC;
```

The slowest tools across every run, which is the question worth asking of a run
that took too long:

```sql
SELECT tool, COUNT(*) AS runs, ROUND(AVG(duration_seconds), 1) AS avg_seconds,
       ROUND(MAX(duration_seconds), 1) AS worst
FROM evidence GROUP BY tool ORDER BY avg_seconds DESC;
```

The exact command behind a finding, and the file holding its verbatim output:

```sql
SELECT command, tool_version, sha256, stored_path
FROM evidence WHERE investigation_id = 'INV-fb2b248d' AND tool = 'whois';
```

`python3 -m src.cli evidence --id INV-fb2b248d` re-hashes those files against
the recorded digests and exits non-zero if any no longer match.

Breach records, which are artifacts with metadata rather than a table of their
own. Three types carry them, depending on which source found it: `breach_data`
(Have I Been Pwned via the breach module), `breach` (the email-breach plugin)
and `leak_record` (LeakOSINT) — so filter on all three rather than guessing one:

```sql
SELECT artifact_type, value,
       json_extract(metadata, '$.breach_date') AS breach_date,
       json_extract(metadata, '$.pwn_count') AS accounts,
       json_extract(metadata, '$.database') AS leak_database
FROM artifacts
WHERE investigation_id = 'INV-fb2b248d'
  AND artifact_type IN ('breach_data', 'breach', 'leak_record');
```

`breach_date` and `pwn_count` are on `breach_data`/`breach`; a `leak_record`
carries `database`, `info`, `query` and `fields` instead and has no date. Which
types a given run actually holds is worth checking before filtering on one:

```sql
SELECT DISTINCT artifact_type FROM artifacts WHERE investigation_id = 'INV-fb2b248d';
```

`metadata` is JSON *text*; `json_extract` reads into it, and `json_each` expands
a list — the classes of data a breach exposed, for instance:

```sql
SELECT a.value, j.value AS data_class
FROM artifacts a, json_each(json_extract(a.metadata, '$.data_classes')) j
WHERE a.investigation_id = 'INV-fb2b248d';
```

The same value seen in more than one investigation — how the report's
cross-investigation section finds its matches:

```sql
SELECT value, artifact_type, COUNT(DISTINCT investigation_id) AS runs,
       GROUP_CONCAT(DISTINCT investigation_id) AS seen_in
FROM artifacts
GROUP BY value, artifact_type HAVING runs > 1
ORDER BY runs DESC;
```

What the map resolved, and what it could not:

```sql
SELECT place, latitude, longitude, display_name FROM geocode_cache;
SELECT place FROM geocode_cache WHERE latitude IS NULL;   -- cached misses
```

## Exporting

```bash
sqlite3 -header -csv $DB "SELECT * FROM artifacts WHERE investigation_id='$INV';" > artifacts.csv
sqlite3 $DB ".mode json" "SELECT * FROM artifacts WHERE investigation_id='$INV';" > artifacts.json
sqlite3 $DB ".dump" > backup.sql                       # whole database as SQL
sqlite3 $DB ".backup /tmp/snapshot.db"                  # consistent file copy, even while in use
```

The reporter does the same thing at a higher level:
`python3 -m src.cli report --id INV-xxxxxxxx --format json` (or `csv`), and
`--redact` masks personal detail on the way out.

## Deleting a run

There is no cascade, so the child rows have to go first:

```sql
BEGIN;
DELETE FROM artifact_links WHERE investigation_id = 'INV-fb2b248d';
DELETE FROM platform_presence WHERE investigation_id = 'INV-fb2b248d';
DELETE FROM investigation_metadata WHERE investigation_id = 'INV-fb2b248d';
DELETE FROM audit_trail WHERE investigation_id = 'INV-fb2b248d';
DELETE FROM comments WHERE investigation_id = 'INV-fb2b248d';
DELETE FROM evidence WHERE investigation_id = 'INV-fb2b248d';
DELETE FROM artifacts WHERE investigation_id = 'INV-fb2b248d';
DELETE FROM investigations WHERE investigation_id = 'INV-fb2b248d';
COMMIT;
VACUUM;
```

The preserved-output files under `evidence.directory` are not removed by this;
the `stored_path` of each row names the file to delete.

## Two cautions

The database holds names, emails, phone numbers, bios and breach records
verbatim — redaction happens when a report is generated, not in storage. Treat
the file itself as sensitive, and take a `.backup` copy before running anything
that writes.
