# dashmsg

Sign and Verify messages with Dash Private Keys

```bash
dashmsg sign \
    'XK5DHnAiSj6HQNsNcDkawd9qdp8UFMdYftdVZFuRreTMJtbJhk8i' \
    'dte2022-akerdemelidis|estoever|mmason'
```

```bash
dashmsg verify \
    'Xn4A2vv5fb7LvmiiXPPMexYbSbiQ29rzDu' \
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
dashmsg v0.9.0 (gxxxxxx) 2022-03-12T01:33:52-0700

Usage
 dashmsg <command> [flags] args...

See usage: dashmsg help <command>

Commands:
    version
    gen [name.wif]
    sign <key> <msg>
    inspect <key | address | signature>
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

## Go Library

Documentation at <https://pkg.go.dev/github.com/dashhive/dashmsg>.
