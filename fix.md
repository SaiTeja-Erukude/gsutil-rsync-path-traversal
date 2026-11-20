# Minimal fix: gsutil rsync path traversal

This guide describes the minimal fix for the issue found in **gsutil 5.38**.
The accompanying [patch](./patches/rsync-path-traversal.patch) includes the source
change and regression tests. The installed package used for the saved PoC
evidence remains unpatched.

## The issue

A cloud object named `x/../../escaped/owned.txt` can make `rsync` save a file
outside the folder you selected. The `..` components mean "go up one folder."

```text
Selected folder: <workdir>/sync-root
Built path:      <workdir>/sync-root/x/../../escaped/owned.txt
Actual file:     <workdir>/escaped/owned.txt
```

## The minimal change

Add one containment check in **`gslib/commands/rsync.py`**, inside
`_DiffIterator.__iter__()`. This function already knows both the selected
folder and the destination it constructed, so no new helper or command
attribute is needed.

Insert the following immediately after the complete assignment to
`dst_url_str_would_copy_to` ending in
`recursion_requested=self.recursion_requested).url_string`, and before
`if dst_url_str is None:`. Keep the indentation shown.

```python
          if self.base_src_url.IsCloudUrl() and self.base_dst_url.IsFileUrl():
            try:
              root = os.path.normcase(
                  os.path.realpath(self.base_dst_url.object_name))
              destination = os.path.normcase(os.path.realpath(
                  StorageUrlFromString(dst_url_str_would_copy_to).object_name))
              safe = (destination != root and
                      os.path.commonpath([root, destination]) == root)
            except (OSError, ValueError):
              safe = False
            if not safe:
              raise CommandException(
                  'Unsafe rsync destination: path escapes or names the sync root.')
```

All required imports already exist in the module.

The check resolves the actual destination and requires it to be **inside the
selected folder**. It runs before rsync schedules a copy or attribute update.
Unsafe paths raise an error; ordinary nested paths continue to work.

No changes to `PerformCopy()` or new helper functions are needed for this
specific command path. Names containing `..` can remain allowed when their
resolved destination stays inside the folder.

## Verification

After applying the patch, verify that:

- `safe/nested.txt` still syncs normally.
- `x/../../escaped/owned.txt` raises the safety error before a copy is scheduled.
- An existing file outside the folder is neither deleted nor overwritten.
- A sibling such as `sync-root-other` is rejected too.
- Both ordinary and parallel (`-m`) syncs enforce the check.

Validation: all 15 relevant unit tests passed against the patched source,
including rejection of escaped paths before `PerformCopy()` and dispatch of a
normal nested file. Storage was mocked; live-cloud and parallel-download tests
have not been run. The new tests are included in the patch.

From a gsutil source checkout with its test dependencies available:

```powershell
python gsutil.py test -u -p 1 rsync.TestRsyncUnit rsync_funcs
```

The existing `run_poc.py` calls lower-level functions directly and bypasses this
iterator. Use iterator or public-command tests to verify this patch; that PoC
alone cannot judge whether this command path is fixed.

This is a targeted fix for object-name traversal. It does not protect direct
calls to private download functions or prevent a local attacker from changing
filesystem links between checking and writing. Keep the local destination
under trusted control.
