#!/bin/bash
set -e
set -u

my_priv="0x00"
my_coin="0x80"
my_message='silly message'
echo "Message: ${my_message}"

my_wif="$(
    go run cmd/dashmsg/main.go gen --cointype "${my_priv}"
)"

my_sig="$(
    go run cmd/dashmsg/main.go sign --cointype "${my_coin}" "${my_wif}" "${my_message}"
)"

my_addr="$(
    go run cmd/dashmsg/main.go inspect --cointype "${my_coin}" "${my_wif}" |
        grep 'Address' | cut -d':' -f2 | cut -d' ' -f2
)"

go run cmd/dashmsg/main.go verify "${my_addr}" "${my_message}" "${my_sig}"

# Inspect
echo ""
echo "Inspect..."
echo "WIF: ${my_wif} (pub cointype: ${my_coin})"
go run cmd/dashmsg/main.go inspect --cointype "${my_coin}" "${my_wif}"
echo ''
echo ''
echo "Signature: ${my_sig}"
go run cmd/dashmsg/main.go inspect "${my_sig}"
echo ''
echo ''
echo "Address: ${my_addr}"
go run cmd/dashmsg/main.go inspect "${my_addr}"

echo ''
echo 'PASS'
echo ''
