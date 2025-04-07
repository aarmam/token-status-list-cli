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
```