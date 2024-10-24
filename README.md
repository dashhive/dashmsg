# dashmsg

Sign and Verify messages with Dash Private Keys

```bash
dashmsg sign --cointype 0x4c \
    'XK5DHnAiSj6HQNsNcDkawd9qdp8UFMdYftdVZFuRreTMJtbJhk8i' \
    'dte2022-akerdemelidis|estoever|mmason'
```

```bash
dashmsg verify \
    'XyBmeuLa8y3D3XmzPvCTj5PVh7WvMPkLn1' \
    'dte2022-akerdemelidis|estoever|mmason' \
    'H2Opy9NX72iPZRcDVEHrFn2qmVwWMgc+DKILdVxl1yfmcL2qcpu9esw9wcD7RH0/dJHnIISe5j39EYahorWQM7I='
```

Also useful for and inspecting debugging:

-   coin type (network) byte
-   payment address of private key
-   i (quadrant), r, and s of signature

## Usage

```bash
dashmsg help
```

```txt
dashmsg v0.9.1 (xxxxxxx) 2022-03-13T11:45:52-0700

Usage
    dashmsg <command> [flags] args...

See usage: dashmsg help <command>

Commands:
    version
    gen [--cointype '0xcc'] [name.wif]
    sign [--cointype '0x4c'] <key> <msg>
    inspect [--cointype '0x4c'] <key | address | signature>
    decode (alias of inspect)
    verify <payment address> <msg> <signature>

Examples:
    dashmsg gen ./dash.wif

    dashmsg sign dash.wif ./msg.txt
    dashmsg sign dash.wif 'my message'
    dashmsg sign 'Xxxx...ccc' 'my message'

    dashmsg inspect --verbose 'Xxxxxxxxxxxxxxxxxxxxxxxxxxxxcccccc'

    dashmsg verify Xxxx...ccc 'my message' 'II....signature...'
    dashmsg verify ./addr.b58c.txt ./msg.txt ./sig.b64.txt
```

## How to Build

```bash
git clone https://github.com/dashhive/dashmsg
pushd ./dashmsg/
```

```bash
go build -mod=vendor -o dashmsg ./cmd/dashmsg/
```

### GoReleaser

Because one of the dependencies requires `CGO_ENABLED=1` and uses low-level syscalls (I have no idea why - probably completely unnecessary), it must be built on and released from the respective OSes.

```bash
goreleaser -f .goreleaser.yml --rm-dist --single-target --skip-validate
```

```txt
--single-target - build only for the current OS
--skip-validate - uploads the image even though it can update the checksums
```

**Note**: MacOS actually can build both the amd64 and arm64 versions on an M1.

## Go Library

Documentation at <https://pkg.go.dev/github.com/dashhive/dashmsg>.
