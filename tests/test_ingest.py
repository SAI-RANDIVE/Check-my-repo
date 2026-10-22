"""Ingestion: URL validation, zip-slip / symlink / bomb protection, local paths."""

from __future__ import annotations

import stat
import zipfile
from pathlib import Path

import pytest

from app.config import get_settings
from app.ingest import IngestError, extract_upload, local_target, safe_extract_zip, validate_github_url


@pytest.mark.parametrize("url", ["https://github.com/adeyosemanputra/pygoat", "https://github.com/juice-shop/juice-shop.git",
                                 "https://github.com/a/b/"])
def test_valid_github_urls(url: str) -> None:
    assert validate_github_url(url)


@pytest.mark.parametrize("url", ["http://github.com/a/b", "https://gitlab.com/a/b", "https://github.com/a",
                                 "https://github.com/a/b/tree/main", "file:///etc/passwd", "https://github.com/a/b;rm -rf"])
def test_invalid_github_urls(url: str) -> None:
    with pytest.raises(IngestError):
        validate_github_url(url)


def make_zip(path: Path, entries: dict[str, bytes], symlink: str | None = None) -> Path:
    with zipfile.ZipFile(path, "w") as zf:
        for name, data in entries.items():
            zf.writestr(name, data)
        if symlink:
            info = zipfile.ZipInfo(symlink)
            info.external_attr = (stat.S_IFLNK | 0o777) << 16
            zf.writestr(info, "/etc/passwd")
    return path


@pytest.mark.parametrize("evil", ["../evil.txt", "a/../../evil.txt", "/abs/evil.txt", "C:/Windows/evil.txt", "..\\evil.txt"])
def test_zip_slip_blocked(tmp_path: Path, evil: str) -> None:
    z = make_zip(tmp_path / "x.zip", {"ok.txt": b"1", evil: b"pwned"})
    dest = tmp_path / "out"
    dest.mkdir()
    with pytest.raises(IngestError, match="zip-slip"):
        safe_extract_zip(z, dest)
    assert not (tmp_path / "evil.txt").exists()


def test_zip_symlink_blocked(tmp_path: Path) -> None:
    z = make_zip(tmp_path / "s.zip", {"ok.txt": b"1"}, symlink="link")
    dest = tmp_path / "out"
    dest.mkdir()
    with pytest.raises(IngestError, match="symbolic link"):
        safe_extract_zip(z, dest)


def test_zip_bomb_blocked(tmp_path: Path) -> None:
    settings = get_settings().model_copy(update={"max_repo_mb": 1})
    z = tmp_path / "b.zip"
    with zipfile.ZipFile(z, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("big.txt", b"0" * (3 * 1024 * 1024))
    dest = tmp_path / "out"
    dest.mkdir()
    with pytest.raises(IngestError, match="limit"):
        safe_extract_zip(z, dest, settings)


def test_upload_extracts_single_top_level_dir(tmp_path: Path) -> None:
    z = make_zip(tmp_path / "shop.zip", {"shop-main/app.py": b"print(1)\n", "shop-main/requirements.txt": b"Django==3.2.0\n"})
    t = extract_upload(z, "shop.zip")
    try:
        assert t.root.name == "shop-main" and (t.root / "app.py").is_file() and t.source_type == "zip"
    finally:
        tmp = t._temp_dirs[0]
        t.cleanup()
    assert not tmp.exists()


def test_local_path_can_be_disabled(tmp_path: Path) -> None:
    with pytest.raises(IngestError, match="disabled"):
        local_target(str(tmp_path), allow=False)
    assert local_target(str(tmp_path), allow=True).root == tmp_path.resolve()
