# Hive Vanity Key Generator

A key generator for [Hive](https://hive.io) that lets you generate a custom public key through brute force.

## Installation

```bash
git clone github.com/CADawg/hive-vanity-key-gen
cd hive-vanity-key-gen
go build
# All settings are optional, defaults are:
# Default string: "Hive"
# Default file: None (Console output)
# Default case sensitivity: false
./hive-vanity-key-gen [desired string] [file to save in] [true if case sensitve search, otherwise blank or false]
```

Setting case sensitivity to true will require a much longer amount of time than a case-insensitive search.

## Example Text Output

```text
Keypair:
Public: STM5heLLoLgyx4F7SVCmaDzRE2uy7SxkBzBULR6yZkrhrsiYRhy4f
Private: 5**************************************************
```