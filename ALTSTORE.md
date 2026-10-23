# Egzon's AltStore source

Add this URL in **AltStore Classic → Sources → +**:

https://raw.githubusercontent.com/egzonkurtishi01-jpg/vitrine/main/altstore-source.json

The source becomes available after the first successful **Build reviewed Vitrine source** workflow run. The IPA is published to GitHub Releases before the source is updated.

Use the same Apple account as the existing Spotify installation. Keep the Live Activity extension if you want lock-screen, Apple Watch, and CarPlay dashboard lyrics. Removing extensions during signing can remove those features. Signing and App ID limits still apply.

## Publishing another update

1. Review the upstream Vitrine release and pin its full commit in the build workflow's checkout and `SOURCE_COMMIT`.
2. For a new Spotify base, update the reference URL and SHA-256 only after checking compatibility. Update the host version in the extension build and the packaging script as well.
3. Set the new Vitrine version and a new, unique app build number in the packaging script and workflow. The app and extension build numbers must match. Update the publication tag/title.
4. Run **Build reviewed Vitrine source** in GitHub Actions. It builds Vitrine without its debug driver, packages the IPA, verifies archive integrity and preserved Spotify files, records hashes, and publishes the IPA and source metadata.
5. Verify a device launch and the desired features. A successful build alone does not establish device or CarPlay compatibility.

The source offers updates after they are built and published. It does not automatically adopt new upstream releases. Published release assets are immutable; use a new tag and build number for a correction.

The proprietary Spotify code and resources match the previous working community base. The provider regenerated the Vitrine loading entries; the replacement was compared and pinned to its new SHA-256. Its authenticity is not established by compiling Vitrine from source. Build provenance is attached to each release.
