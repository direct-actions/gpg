# gpg
GitHub Actions for interacting with GPG - search/import keys, encrypt/tar, sign, decrypt, etc.

## Actions
### encrypt
The [encrypt](encrypt) action can be used to encrypt a file or command output,
and write the encrypted output to a file, with options to display the encrypted
output in Base64 to the console, or artifact the file. Any key can be used, but
if a search parameter is specified, a key will be imported from a keyserver and
used.
```
      - uses: direct-actions/gpg/encrypt@v0.0
        with:
          input-command: echo '${{ toJSON(secrets) }}'
          search: rob@zwissler.org
```

### keys/import
The [keys/import](keys/import) action can be used to import keys from a
keyserver, URLs, or a local file. The simplest invocation will search for a
single key that matches the search critera, and import from a keyserver.
```
      - uses: direct-actions/gpg/keys/import@v0.0
        with:
          search: rob@zwissler.org
```

### keys/search
The [keys/search](keys/search) action can be used to search a keyserver
for keys, returning the key metadata in JSON format. The simplest invocation
requires only the search string (email, key fingerprint or key ID). Additional
options are available for using a non-default keyserver, or fine tuning the
behavior.
```
      - uses: direct-actions/gpg/keys/search@v0.0
        with:
          search: rob@zwissler.org
```
