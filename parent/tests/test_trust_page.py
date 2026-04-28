from __future__ import annotations

from quill_parent.config import Settings
from quill_parent.trust import render_trust_page


def test_renders_with_known_values() -> None:
    settings = Settings(
        git_commit="abc123def",
        image_digest="sha256:cafebabe",
    )
    html = render_trust_page(settings)
    assert "abc123def" in html
    assert "sha256:cafebabe" in html
    # The page must explicitly assert "No" against prompt content retention.
    assert "Prompt content" in html
    assert "No</td>" in html
    # No JavaScript on the trust page.
    assert "<script" not in html.lower()


def test_renders_without_pcr0() -> None:
    settings = Settings()
    html = render_trust_page(settings)
    assert "(unset)" in html  # no PCR0 configured yet
