# Google Drive: import and encrypted backup

The box can do two things with Google Drive:

- **Import (read-only).** A family member connects their own Google account and picks one Drive folder. The box copies the text-like files from it into `files/people/<person>/from-drive/<folder>/`. Nothing is ever written to their Drive.
- **Encrypted backup.** The admin's Google account holds encrypted copies of the whole box. The box encrypts before uploading, so Google only ever holds ciphertext. Restoring needs the recovery code, which only the family has.

Code: `src/familybox/cloud/`. Tests: `tests/test_cloud.py` (a fake Google over `httpx.MockTransport`, no network).

## What Ethan must do once

The box can't create a Google OAuth client for itself. Do this in the Google Cloud console with the account that will own the app.

1. **Create a project**, for example "familybox".
2. **Enable the Google Drive API** (APIs and Services, Library, "Google Drive API", Enable).
3. **Set up the OAuth consent screen** (Google Auth Platform, Branding / Audience / Data access):
   - User type: **External**. Publishing status: **Testing**.
   - Add each family member's Google address as a **test user** (up to 100). Nobody else can sign in while the app is in Testing.
   - Scopes: `openid`, `.../auth/userinfo.email`, `.../auth/drive.readonly`, `.../auth/drive.file`.
   - Family members will see a "Google hasn't verified this app" screen. That is expected in Testing mode; they click Continue.
4. **Create an OAuth client** (Clients, Create client), type **Web application**, and add these **Authorized redirect URIs**:
   - `http://127.0.0.1:8765/cloud/callback` (the CLI's default; change with `FAMILYBOX_CLI_REDIRECT`)
   - the box web page's loopback callback, for example `http://127.0.0.1:<web port>/cloud/callback`, for the laptop demo
   - the forwarder page's exact HTTPS URL, if you host one (see below), for example `https://<you>.github.io/familybox/oauth-forwarder.html`

   Google matches these exactly: scheme, host, port and path.
5. **Give the box the client**, in its environment (not in git):

   ```
   GOOGLE_OAUTH_CLIENT_ID=....apps.googleusercontent.com
   GOOGLE_OAUTH_CLIENT_SECRET=...
   FAMILYBOX_OAUTH_REDIRECT=https://<you>.github.io/familybox/oauth-forwarder.html   # only if you host the forwarder
   ```

Two Testing-mode facts to know:

- **Refresh tokens expire after 7 days** for apps in Testing with External users. After that, `status` still shows the account but the next import or backup says "connect again". Publishing the app removes this, but `drive.readonly` is a *restricted* scope, so publishing needs Google's verification and a security assessment. For the hackathon and for a family, Testing mode is the right setting.
- A **Desktop app** client type also works for loopback (any port, no registration needed), but it can't use the forwarder. One Web application client covers all three ways of connecting below.

## Why connecting from a phone on the home network is awkward

Google only redirects back to two kinds of address:

- **Loopback** (`127.0.0.1` / `localhost`) for local apps, and
- **public HTTPS** addresses for web apps.

A family box lives on a home-network address such as `https://familybox.local:8443` or `192.168.1.20`. Google refuses both, so a browser on a phone can't be sent straight back to the box. The box supports three ways around this:

1. **Loopback (laptop demo).** When the browser runs on the same machine as the box, the web page passes `http://127.0.0.1:<port>/cloud/callback` and Google redirects there directly.
2. **Forwarder page (phone on the home network).** Set `FAMILYBOX_OAUTH_REDIRECT` to a tiny static page on any public HTTPS host. The file is `docs/oauth-forwarder.html`; it is not deployed by this repo. When the box's own callback is a home-network address, the box sends Google the forwarder URL and puts its own callback address inside `state` (`<nonce>.<base64url(callback)>`). Google sends the browser to the forwarder, which immediately sends it on to the box with `?code&state`.
   - **The forwarder can't use the code.** The box keeps the PKCE verifier, and Google only trades the code for tokens when that verifier is sent with it. The exchange also needs the client secret, which only the box has. The code works once and expires within minutes.
   - The page has no server, stores nothing, loads nothing from elsewhere (strict Content-Security-Policy), sets no-referrer, wipes the code from its own address bar, and only forwards to private addresses (`.local`, `.lan`, `.home.arpa`, 10.x, 192.168.x, 172.16-31.x, 127.x, fc00::/7). It can't be used as an open redirect to a public site.
   - The box checks the nonce in `state` against its own records, so a forged or replayed `state` is refused.
3. **Paste the code (CLI fallback).** `familybox cloud connect --as <person>` prints the sign-in link. After signing in, the browser lands on `http://127.0.0.1:8765/...`, which usually shows "can't connect". That is fine: copy the whole address from the address bar (or just the `code=` value) and paste it into the terminal.

Google's **device flow** ("enter this code on another device") would avoid all of this, but Google doesn't allow `drive.readonly` in the device flow (only `drive.file` and `drive.appdata` among Drive scopes), so import can't use it.

## How sign-in is protected

- OAuth 2.0 authorization code flow with **PKCE (S256)**. The verifier (86 random URL-safe characters) never leaves the box.
- `state` is a random 192-bit nonce, stored server-side in `runtime/cloud/pending.json` with the person it belongs to, the PKCE verifier and the exact redirect URI. It expires after **10 minutes** and is **single use**: it is removed the first time it comes back, even if the exchange then fails.
- Scopes: `openid email` (to show which account is connected), `drive.readonly` (import), `drive.file` (backups; the box can only see files it created itself).
- Tokens live in `runtime/cloud/<person>.json` with **0600** permissions in a 0700 folder. Access tokens refresh automatically a minute before they expire, and once more if Google answers 401. No command prints a token.
- `disconnect` asks Google to revoke the grant and deletes the local tokens. Files already imported stay.

## Import

`import_folder(cfg, person, folder)` where `folder` is a Drive folder **name**, **link** or **id**. If two folders share a name, the box asks for the link instead.

- Lists the folder and **one level of subfolders**. Deeper folders are skipped and reported.
- Downloads only `.txt .md .pdf .json .csv` (up to 50 MB each). **Google Docs are exported as plain text** (`.txt`). Sheets, Slides, images and everything else are skipped and reported.
- Writes to `files/people/<person>/from-drive/<folder>/[<subfolder>/]<name>`, files 0600 and folders 0700. Names are sanitized (no slashes, no leading dots, safe characters only). The box refuses to write if any folder on that path is a symlink, so an import can never land in another person's folder or outside the box.
- Keeps a manifest of Drive id and `modifiedTime` in `runtime/cloud/<person>.import.json`, so importing again only downloads files that changed.
- Rebuilds the search index afterwards. File contents go to the box's disk and nowhere else.

Imported files follow the box's normal rules: they belong to that person, and a subfolder named `health` is treated as health records.

## Backup

`init_backup_key(cfg)` makes a random 32-byte key at `runtime/cloud/backup.key` (0600) and returns the **recovery code** once: the key in base32, in groups of four (13 groups). Write it down and keep it away from the box. Without it nobody, including you and Google, can open a backup. Running it again refuses unless forced, because a new key means a new code.

`backup_now(cfg)`:

1. Makes a tar of `files/` and `family.toml`. It never includes `runtime/` (Google tokens, TLS keys, sessions, the backup key, the search index, OAuth state). Symlinks and special files are left out.
2. Encrypts it on the box with libsodium **secretstream XChaCha20-Poly1305** in 64 KiB chunks. File layout: `FBXBKUP` magic, format version (1), an 8-byte key id (lets restore say "wrong recovery code"), the 24-byte stream header, then the chunks, the last one marked final. Every chunk is authenticated, and the header is bound to every chunk, so any changed, reordered, cut-off or extended byte fails.
3. Uploads it to the **admin's** Drive (the person with `admin = true` in `family.toml`) as an app-created file `familybox-backup-<UTC timestamp>.fbx`. Multipart upload up to 5 MB, resumable upload in 8 MiB pieces above that.

`restore(cfg, source, recovery_code)` takes a Drive file id (downloaded with the admin's connection) or a path to a `.fbx` file on the box. It checks Google's SHA-256 and the one recorded at backup time when available, decrypts and verifies the whole file before writing anything, then checks every entry: absolute paths, `..`, anything outside `files/` and `family.toml`, symlinks, hard links and devices are all refused, and so is any existing symlink on the way to a target. If one entry is bad, nothing is written. Restored files are 0600. Files on the box that are not in the backup are left alone. The search index is rebuilt afterwards.

To rebuild a lost box: install, copy `family.toml`, connect the admin (`familybox cloud connect --as <admin>`), then `familybox cloud restore --as <admin> <drive file id>` and type the recovery code.

### What Google can and can't see

| Google can see | Google can't see |
| --- | --- |
| That the admin's account uses this app, and when | Any file's contents |
| Each backup's file name (`familybox-backup-<time>.fbx`) and size | File names, folder names or how many people are in the box |
| The box's public IP address when it uploads | `family.toml`, SSNs, health records, anything inside the tar |
| For import: the folder and files a person picked, because they are already in that person's Drive | The recovery code or the backup key (they never leave the box) |

The size of a backup roughly tells Google how much the family stores. Someone with root on the box can read the key, the tokens and the files themselves; that is outside the box's threat model (see docs/PLAN.md).

## Commands

```
familybox cloud status     --as maya
familybox cloud connect    --as maya [--redirect http://127.0.0.1:8765/cloud/callback]
familybox cloud import     --as maya "Maya school"          # name, Drive link or folder id
familybox cloud disconnect --as maya
familybox cloud backup-key --as dana [--force]               # admin only; shows the recovery code once
familybox cloud backup     --as dana                         # admin only
familybox cloud restore    --as dana <drive file id | path.fbx>   # admin only; asks for the recovery code
```

## Interface for the web page

All in `familybox.cloud`. Errors the person can act on raise `CloudError` (and `BackupError`, a subclass) with a message that is safe to show.

```python
status(cfg, person_id) -> {"connected", "account_email", "last_import", "last_backup", "backup_key_set"}
begin_connect(cfg, person_id, redirect_uri) -> str           # Google URL; redirect_uri is the box's own callback
finish_connect(cfg, state, code) -> dict                     # status() plus "person"
import_folder(cfg, person_id, folder) -> {"imported": int, "skipped": int, "folder": str,
                                          "folder_id", "files": [paths], "skipped_files": [{"name", "reason"}]}
backup_now(cfg) -> {"bytes", "sha256", "drive_file_id", "name"}
init_backup_key(cfg, *, force=False) -> recovery code (show once)
restore(cfg, source, recovery_code) -> {"restored_files", "bytes", "sha256", "source"}
disconnect(cfg, person_id) -> status()
set_client_factory(factory | None)                           # inject an httpx.Client maker (tests)
```

The web page should always pass its own callback URL (for example `<its origin>/cloud/callback`) as `redirect_uri`. The box decides whether Google gets that address directly (loopback or public HTTPS) or the forwarder (home-network address with `FAMILYBOX_OAUTH_REDIRECT` set). The callback handler reads `code` and `state` from the query string and calls `finish_connect`. If Google returns `error=access_denied`, show that instead. `finish_connect` works out the person from `state`, so the callback must not trust a person id from the query string.

## Known limits

- Backups run when asked; there is no schedule yet, and old backups on Drive are not pruned.
- Small backups are built in memory for the multipart upload (up to 5 MB); larger ones stream in 8 MiB pieces.
- Import does not delete local copies of files later removed from Drive, and does not go deeper than one level of subfolders.
- Scanned PDFs are imported but not searchable (no OCR, same as the rest of the box).
- Losing the recovery code means the backups can't be opened. Replacing the key (`--force`) means older backups need the old code.
- The box has not yet been tested against the real Google API; everything here runs against a faithful fake. The first real run needs the OAuth client from the setup above.
