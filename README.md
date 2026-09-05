# Token Status List CLI

Command line application for [Token Status List](https://github.com/aarmam/token-status-list)

## Run
```shell
mvn spring-boot:run
```

## Inspect available commands
```shell
shell:>help
AVAILABLE COMMANDS

Built-In Commands
       help: Display help about available commands
       stacktrace: Display the full stacktrace of the last error.
       clear: Clear the shell screen.
       quit, exit: Exit the shell.
       history: Display or save the history of previously run commands
       version: Show version info
       script: Read and execute commands from a file.

Default
       generate: Generates the status list in specified format
       load, l: Loads the status list in JSON or CBOR Hex format
       get, g: Gets the status at index
       set, s: Sets the status at index
       save: Saves the status list in JSON or CBOR Hex format
       sign: Generates and signs the status list token in specified format
       aggregate: Writes a Status List Aggregation listing the given Status List Token URIs
```

## Files written

| File | Contents | Serve as |
|------|----------|----------|
| `status_list.json` / `status_list.cbor` | the unsigned Status List | - |
| `status_list.txt` | the decoded statuses, written on `load` | - |
| `status_list_token.jwt` | the signed token | `application/statuslist+jwt` |
| `status_list_token.cwt` | the signed token, raw binary per Section 8.2 | `application/statuslist+cwt` |
| `status_list_token.cwt.hex` | the same token in hex, for inspection | - |
| `status_list_aggregation.json` | the Section 9.3 aggregation | `application/json` |

## Configuration

`application.yml` under `status-list`:

| Property | Purpose |
|----------|---------|
| `path` | directory the files above are written to |
| `uri` | the `sub` claim of the token; must match the `uri` in the Referenced Token |
| `aggregation-uri` | optional Status List Aggregation link embedded in the list (Section 9.2) |
| `expires` | `exp` claim; see the note in `application.yml` on choosing it alongside `time-to-live` |
| `time-to-live` | `ttl` claim, how long the token may be cached (Section 13.7) |
| `signing-eku-oid` | OID of `id-kp-oauthStatusSigning` (Section 10), still TBD in the draft; set it to have `sign` warn when the certificate lacks it |

Implements [draft-ietf-oauth-status-list-21](https://datatracker.ietf.org/doc/html/draft-ietf-oauth-status-list).