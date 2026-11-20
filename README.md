# gsutil `rsync -r` Path Traversal

**Severity:** High, CVSS 3.1 **8.1**

**Vector:** `CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:H/A:H`

**Affected versions:** `<= 5.38`

**Component:** `gslib.commands.rsync`

**CWE:** CWE-22 (Improper Limitation of a Pathname to a Restricted Directory)

**Discovered and reported by:** Sai Teja Erukude

---

## Summary

When downloading a bucket recursively, `gsutil rsync -r` can use a cloud object
name containing `..` components to construct a path outside the selected local
sync folder.

```text
Object name:     x/../../escaped/owned.txt
Selected folder: <workdir>/sync-root
Built path:      <workdir>/sync-root/x/../../escaped/owned.txt
Actual write:    <workdir>/escaped/owned.txt
```

## Impact

An attacker who controls object names and contents in a bucket or prefix that
a victim downloads may cause files to be written outside the sync folder.
Existing destination files can be deleted or overwritten. The effect is limited
by the filesystem permissions of the account running gsutil.

The victim must initiate the affected synchronization. This PoC writes only a
harmless marker outside `sync-root` and inside the PoC directory.

## Technical detail

```text
Cloud object listing
  -> _DiffIterator.__iter__()
  -> ConstructDstUrl(): append the object subpath to the local destination
  -> _RsyncFunc()
  -> PerformCopy()
  -> _GetDownloadFile(): create directories and remove an existing destination
  -> _ValidateAndCompleteDownload(): rename the download to its destination
```

Cloud URL parsing accepts embedded parent-directory components. The rsync path
does not apply the destination containment check present in the `cp` command.
Download hash validation checks file contents, not whether the local path is safe.

## Proof of concept

[`run_poc.py`](./run_poc.py) exercises the installed gsutil package's internal
functions without contacting Google Cloud Storage or requiring credentials.
It checks path construction, the destination passed to `PerformCopy()`, and
download completion using a local temporary file. It does not run the public
`gsutil rsync` command or download from a real bucket.

Run from this repository on Windows:

```powershell
py -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
.\.venv\Scripts\python.exe -B .\run_poc.py
```

Expected key output for the vulnerable installation:

```text
[package] gsutil 5.38 from ...
[storage_url] embedded '../' accepted: PASS
[construct_dst_url] escaped sync root: PASS
[rsync_worker] PerformCopy received escaped dst: PASS
[download_sink] wrote escaped file: PASS
PoC verification passed
```

A successful vulnerability demonstration exits with code **0** and sets
`success` to `true`. Use `--json` for machine-readable output. `--cleanup`
removes the runner's local sync directory and escaped marker after saving evidence.

The runner creates `sync-root/`, writes `escaped/owned.txt`, and rewrites
`evidence/`. Preserve the included evidence before rerunning it.

Saved artifacts:

- [JSON evidence](./evidence/summary.json)
- [Escaped file contents](./evidence/escaped-file-content.txt)
- [Marker file](./escaped/owned.txt)
- [Demo video](./gsutil-rsync-traversal-demo.mkv)

## Remediation

See [`fix.md`](./fix.md) for the proposed containment check in
`_DiffIterator.__iter__()` and its validation limits. The guard rejects
destinations outside or equal to the sync root before scheduling a copy or
attribute update.

The PoC bypasses this iterator, so use iterator or public-command tests to
validate the fix. Keep the local destination under trusted control; the guard
does not prevent a local attacker from replacing filesystem links between
validation and writing. Until patched, avoid recursive downloads from
attacker-controlled buckets.

## Credit

Discovered and reported by **Sai Teja Erukude**.

Disclosure was coordinated through VulnCheck.

## References

- [gsutil repository](https://github.com/GoogleCloudPlatform/gsutil)
- [Proposed fix PR #1951](https://github.com/GoogleCloudPlatform/gsutil/pull/1951)
- [rsync source at gsutil 5.38](https://github.com/GoogleCloudPlatform/gsutil/blob/v5.38/gslib/commands/rsync.py)
- [gsutil documentation](https://docs.cloud.google.com/storage/docs/gsutil)
- [CWE-22: Improper Limitation of a Pathname to a Restricted Directory](https://cwe.mitre.org/data/definitions/22.html)
- [Suggested fix](./fix.md)
