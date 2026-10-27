#!/usr/bin/env python3
"""Tests for documentation and release artifacts."""

import json
import os
import pytest

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)

DOCS_DIR = os.path.join(HERE, 'docs')
if not os.path.isdir(DOCS_DIR):
    DOCS_DIR = os.path.join(ROOT, 'docs')
MAN_DIR = os.path.join(DOCS_DIR, 'man')

RELEASE_DIR = os.path.join(HERE, 'release')
if not os.path.isdir(RELEASE_DIR):
    RELEASE_DIR = os.path.join(ROOT, 'release')

MAN_PAGES = ['pqblocks.3', 'pqblocks_hybrid.3', 'pqblocks_policy.5']
REQUIRED_FIELDS_IN_RELEASE = ['package-card.md', 'RELEASE-NOTES.md', 'UPGRADE.md', 'SIGNATURES.json']


def test_man_pages_exist():
    """All required man pages must exist."""
    for page in MAN_PAGES:
        path = os.path.join(MAN_DIR, page)
        assert os.path.isfile(path), f"Man page missing: {path}"


def test_man_pages_are_non_empty():
    """All man pages must be non-empty and valid."""
    for page in MAN_PAGES:
        path = os.path.join(MAN_DIR, page)
        assert os.path.getsize(path) > 100, f"Man page too short: {path}"
        with open(path, 'r') as f:
            content = f.read()
        assert '.TH ' in content, f"Man page missing .TH header: {page}"
        assert '.SH ' in content, f"Man page missing .SH sections: {page}"


def test_man_pages_have_required_structure():
    """Man pages must have NAME, SYNOPSIS, DESCRIPTION sections."""
    required_sections = ['.SH NAME', '.SH SYNOPSIS', '.SH DESCRIPTION']
    for page in MAN_PAGES:
        path = os.path.join(MAN_DIR, page)
        with open(path, 'r') as f:
            content = f.read()
        for section in required_sections:
            assert section in content, f"Man page {page} missing section: {section}"


def test_release_directory_exists():
    """Release directory must exist."""
    assert os.path.isdir(RELEASE_DIR), f"Release directory missing: {RELEASE_DIR}"


def test_release_directory_not_empty():
    """Release directory must contain required artifacts."""
    for artifact in REQUIRED_FIELDS_IN_RELEASE:
        path = os.path.join(RELEASE_DIR, artifact)
        assert os.path.isfile(path), f"Release artifact missing: {artifact}"


def test_catalog_card_exists_and_valid():
    """Package card must exist and contain required fields."""
    path = os.path.join(RELEASE_DIR, 'package-card.md')
    assert os.path.isfile(path), "package-card.md missing"
    with open(path, 'r') as f:
        content = f.read()
    assert 'pqblocks' in content.lower() or 'hybrid' in content.lower(), "package-card.md missing product name"
    assert 'hybrid' in content.lower() or 'post-quantum' in content.lower(), \
        "package-card.md missing technology description"


def test_release_notes_exist():
    """RELEASE-NOTES.md must exist with version history."""
    path = os.path.join(RELEASE_DIR, 'RELEASE-NOTES.md')
    assert os.path.isfile(path), "RELEASE-NOTES.md missing"
    with open(path, 'r') as f:
        content = f.read()
    assert len(content) > 200, "RELEASE-NOTES.md too short"
    assert '1.0.0' in content, "RELEASE-NOTES.md missing version 1.0.0"


def test_upgrade_guide_exists():
    """UPGRADE.md must exist with upgrade instructions."""
    path = os.path.join(RELEASE_DIR, 'UPGRADE.md')
    assert os.path.isfile(path), "UPGRADE.md missing"
    with open(path, 'r') as f:
        content = f.read()
    assert len(content) > 200, "UPGRADE.md too short"


def test_signatures_json_valid():
    """SIGNATURES.json must exist and be valid JSON."""
    path = os.path.join(RELEASE_DIR, 'SIGNATURES.json')
    assert os.path.isfile(path), "SIGNATURES.json missing"
    with open(path, 'r') as f:
        data = json.load(f)
    assert isinstance(data, dict), "SIGNATURES.json must be a JSON object"


def test_release_docs_have_no_hype():
    """Release docs must not contain forbidden hype terms."""
    forbidden = ['quantum speedup', 'quantum-powered', 'unbreakable',
                 'revolutionary', 'blazingly', 'world-class', 'cutting-edge']
    docs_to_check = []
    for artifact in REQUIRED_FIELDS_IN_RELEASE:
        path = os.path.join(RELEASE_DIR, artifact)
        if os.path.isfile(path):
            with open(path, 'r') as f:
                docs_to_check.append(f.read().lower())
    for doc in docs_to_check:
        for term in forbidden:
            assert term not in doc, f"Forbidden hype term found: '{term}'"


def test_man_pages_have_no_hype():
    """Man pages must not contain forbidden hype terms."""
    forbidden = ['quantum speedup', 'quantum-powered', 'unbreakable',
                 'revolutionary', 'blazingly', 'world-class', 'cutting-edge',
                 'quantum-proof']
    for page in MAN_PAGES:
        path = os.path.join(MAN_DIR, page)
        if os.path.isfile(path):
            with open(path, 'r') as f:
                content = f.read().lower()
            for term in forbidden:
                assert term not in content, f"Forbidden hype term in {page}: '{term}'"


def test_release_notes_have_version_1_0_0():
    """Release notes must document version 1.0.0."""
    path = os.path.join(RELEASE_DIR, 'RELEASE-NOTES.md')
    if os.path.isfile(path):
        with open(path, 'r') as f:
            content = f.read()
        assert '1.0.0' in content or 'v1.0.0' in content or 'version 1' in content.lower(), \
            "RELEASE-NOTES.md missing version 1.0.0 information"


def test_catalog_card_has_primitive_disclaimer():
    """Package card must clarify this is a hybrid wrapper, not raw crypto."""
    path = os.path.join(RELEASE_DIR, 'package-card.md')
    if os.path.isfile(path):
        with open(path, 'r') as f:
            content = f.read().lower()
        assert 'hybrid' in content or 'wrapper' in content, \
            "Package card should describe hybrid wrapper nature"
