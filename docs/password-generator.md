# Password Generator

Current implementation:
- charset mode with configurable classes and optional ambiguous-character filtering
- diceware mode using the EFF large word list (`7776` entries)

CLI:
- `cargo run -q -p npw-cli -- generate --mode charset --length 20`
- `cargo run -q -p npw-cli -- generate --mode diceware --words 5 --separator -`
