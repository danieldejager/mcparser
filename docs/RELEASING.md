# Releasing

Pushing a `v*` tag runs `.github/workflows/release.yml`, which builds every
platform package and attaches it to the GitHub release.

## macOS signing and notarization

The macOS job signs the app with a Developer ID Application certificate
(hardened runtime), notarizes it with an App Store Connect API key, and
staples the ticket to the app and the disk image. This only happens when all
six secrets below exist in the repository (Settings, Secrets and variables,
Actions). If any one is missing, as on forks and pull request runs, the job
builds the same unsigned disk image as before and logs a notice saying the
build is unsigned.

| Secret | What it is | Where it comes from |
| --- | --- | --- |
| `CSC_LINK` | Base64 of the Developer ID Application certificate exported as `.p12` | Create the certificate at developer.apple.com (Certificates, Identifiers and Profiles), install it, export it with its private key from Keychain Access, then `base64 -i cert.p12 \| pbcopy` |
| `CSC_KEY_PASSWORD` | Password set when exporting the `.p12` | Chosen during the Keychain Access export |
| `APPLE_API_KEY` | Full text of the App Store Connect API key file (`AuthKey_XXXX.p8`) | App Store Connect, Users and Access, Integrations, Team Keys. The file can be downloaded once only |
| `APPLE_API_KEY_ID` | Key ID of that API key | Shown next to the key in App Store Connect |
| `APPLE_API_ISSUER` | Issuer ID (a UUID) | Shown above the key list in App Store Connect |
| `APPLE_TEAM_ID` | Ten character team ID | developer.apple.com, Membership details |

The job writes the `.p8` text to a temporary file, points `APPLE_API_KEY` at
that path for electron-builder, and deletes the file at the end of the job.

### Verifying a signed build

Download the disk image from the release, open it, and check the app:

```sh
codesign --verify --deep --strict --verbose=2 /Volumes/McParser*/McParser.app
spctl --assess --type execute --verbose /Volumes/McParser*/McParser.app
xcrun stapler validate /Volumes/McParser*/McParser.app
xcrun stapler validate McParser-*.dmg
```

`spctl` should report `source=Notarized Developer ID` and both `stapler`
checks should report that the validate action worked.
