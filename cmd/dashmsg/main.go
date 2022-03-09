package main

import (
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"
	"math/big"
	"os"

	"github.com/anaskhan96/base58check"
	secp256k1 "github.com/ethereum/go-ethereum/crypto"
)

var randReader io.Reader = rand.Reader

var (
	name    = "dashmsg"
	version = "0.0.0"
	date    = "0001-01-01T00:00:00Z"
	commit  = "0000000"
)

var (
	//checkVersion = "4c" // Dash (vs 0x00 for BC)
	wifVersion = "cc" // Dash (vs 0x80 for BC)
	magicBytes = []byte("DarkCoin Signed Message:\n")
)

func usage() {
	fmt.Println(ver())
	fmt.Println()
	fmt.Println("Usage")
	fmt.Printf(" %s <command> [flags] args...\n", name)
	fmt.Println("")
	fmt.Printf("See usage: %s help <command>\n", name)
	fmt.Println("")
	fmt.Println("Commands:")
	fmt.Println("    version")
	fmt.Println("    gen")
	fmt.Println("    sign")
	fmt.Println("    inspect (decode)")
	fmt.Println("    verify")
	fmt.Println("")
	fmt.Println("Examples:")
	fmt.Println("    dashmsg gen --priv dash.wif")
	fmt.Println("")
	fmt.Println("    dashmsg sign --priv dash.wif --file ./msg.txt")
	fmt.Println("    dashmsg sign --priv dash.wif --msg 'my message'")
	fmt.Println("    dashmsg sign --wif 'Xxxxxxxxxxzzzz' --msg 'my message'")
	fmt.Println("")
	fmt.Println("    dashmsg inspect --verbose 'xxxx.yyyy.zzzz'")
	fmt.Println("")
	fmt.Println("    dashmsg verify ./pub.jwk.json 'xxxx.yyyy.zzzz'")
	// TODO fmt.Println("    dashmsg verify --issuer https://example.com '{ \"sub\": \"xxxx\" }'")
	fmt.Println("")
}

func ver() string {
	return fmt.Sprintf("%s v%s (%s) %s", name, version, commit[:7], date)
}

func main() {
	args := os.Args[:]

	if len(args) < 2 || "help" == args[1] {
		// top-level help
		if len(args) <= 2 {
			usage()
			os.Exit(0)
			return
		}
		// move help to subcommand argument
		self := args[0]
		args = append([]string{self}, args[2:]...)
		args = append(args, "--help")
	}

	switch args[1] {
	case "version":
		fmt.Println(ver())
		os.Exit(0)
		return
	case "gen":
		gen(args[2:])
	case "sign":
		sign(args[2:])
	case "decode":
		fallthrough
	case "inspect":
		inspect(args[2:])
	case "verify":
		usage()
		//verify(args[2:])
	default:
		usage()
		os.Exit(1)
		return
	}
}

func gen(args []string) {
	wif := genHelper()
	fmt.Println(wif)
	// TODO write to file (if args)
}

func genHelper() string {
	priv, _ := ecdsa.GenerateKey(secp256k1.S256(), randReader)
	b := priv.D.Bytes()

	hexkey := hex.EncodeToString(b)
	compressed := "01"
	wif, _ := base58check.Encode(wifVersion, hexkey+compressed)

	return wif
}

func inspect(args []string) {
	if len(args) < 1 {
		fmt.Fprintf(os.Stderr, "usage: %s inspect <addr-or-key>\n", os.Args[0])
		os.Exit(1)
		return
	}
	addr := args[0]
	hex, err := base58check.Decode(addr)
	if nil != err {
		fmt.Fprintf(os.Stderr, "error: could not decode address: %v", err)
		os.Exit(1)
		return
	}
	fmt.Println(hex)
}

func wifToECPrivateKey(wif string) (*ecdsa.PrivateKey, error) {
	dHex, err := base58check.Decode(wif)
	if nil != err {
		return nil, err
	}
	// remove the "version" and "compressed" bytes
	//fmt.Println("version:", dHex[0:2])
	//fmt.Println("compressed:", dHex[66:])
	dHex = dHex[2:66]

	// can't get error here because base58check passed
	d, _ := hex.DecodeString(dHex)
	//fmt.Println("Priv Hex", dHex)

	di := &big.Int{}
	di.SetBytes(d)

	curve := secp256k1.S256()
	x, y := curve.ScalarBaseMult(d)

	priv := &ecdsa.PrivateKey{
		PublicKey: ecdsa.PublicKey{
			Curve: curve,
			X:     x,
			Y:     y,
		},
		D: di,
	}
	//fmt.Println("PrivateKey:", hex.EncodeToString(di.Bytes()))
	//fmt.Println("PublicKey (x):", hex.EncodeToString(x.Bytes()))
	//fmt.Println("PublicKey (y):", hex.EncodeToString(y.Bytes()))
	return priv, nil
}

func magicify(magicBytes, msg []byte) []byte {
	magicBytesLen := len(magicBytes)
	prefix1 := encodeToBCVarint(magicBytesLen)
	//var messageBuffer = Buffer.from(this.message);
	msgLen := len(msg)
	prefix2 := encodeToBCVarint(msgLen)

	bufLen := len(prefix1) + len(magicBytes) + len(prefix2) + len(msg)
	buf := make([]byte, 0, bufLen)
	buf = append(buf, prefix1...)
	buf = append(buf, magicBytes...)
	buf = append(buf, prefix2...)
	buf = append(buf, msg...)

	return buf
}

func magicHash(magicBytes, msg []byte) []byte {
	buf := magicify(magicBytes, msg)
	//fmt.Println("Magic Hash In:", hex.EncodeToString(buf))
	hash := doubleHash(buf)
	//fmt.Println("Magic Hash Out:", hex.EncodeToString(hash))

	return hash
}

func doubleHash(buf []byte) []byte {
	hash1 := sha256.Sum256(buf)
	hash2 := sha256.Sum256(hash1[:])
	return hash2[:]
}

// Encode as up to 1+8 bytes
func encodeToBCVarint(n int) []byte {
	// See https://wiki.bitcoinsv.io/index.php/VarInt
	var buf []byte

	if n < 253 {
		buf = make([]byte, 1)
		buf[0] = byte(n)
	} else if n < 0x10000 {
		buf = make([]byte, 1+2)
		buf[0] = 253
		binary.LittleEndian.PutUint16(buf[1:], uint16(n))
	} else if n < 0x100000000 {
		buf = make([]byte, 1+4)
		buf[0] = 254
		binary.LittleEndian.PutUint32(buf[1:], uint32(n))
	} else {
		buf = make([]byte, 1+8)
		buf[0] = 255

		binary.LittleEndian.PutUint64(buf[1:], uint64(n))
	}

	return buf
}

func sign(args []string) {
	if len(args) < 2 {
		fmt.Fprintf(os.Stderr, "usage: %s sign <addr-or-key> <msg>\n", os.Args[0])
		os.Exit(1)
		return
	}
	wif := args[0]
	msg := []byte(args[1])

	//wif := genHelper()
	priv, err := wifToECPrivateKey(wif)
	if nil != err {
		fmt.Fprintf(os.Stderr, "error: could not decode private key: %v", err)
		os.Exit(1)
		return
	}

	sig, err := signHelper(priv, msg)
	if nil != err {
		fmt.Fprintf(os.Stderr, "error: could not sign message: %v", err)
		os.Exit(1)
		return
	}
	b64 := base64.StdEncoding.EncodeToString(sig)

	//fmt.Println("Signature:")
	//fmt.Println(len(hex), len(hex)/2, hex)
	fmt.Println(b64)
}

func signHelper(priv *ecdsa.PrivateKey, msg []byte) ([]byte, error) {
	//pubKeyHash := secp256k1.PubkeyToAddress(prv.PublicKey).Bytes()
	//pubKeyHashHex := hex.EncodeToString(pubKeyHash)
	//addr, _ := base58check.Encode(checkVersion, pubKeyHashHex)
	//fmt.Println("PubKeyHash Bytes:", pubKeyHash)
	//fmt.Println("PubKeyHash:", addr)

	//fmt.Printf("%q\n", magicBytes)
	//fmt.Printf("%q\n", msg)

	hash := magicHash(magicBytes, msg)
	rsig, _ := secp256k1.Sign(hash[:], priv)
	sig := make([]byte, 0, 65)
	// +4 for compressed
	recovery := rsig[64] + 27 + 4
	// sig[64] is recovery bit
	sig = append(sig, recovery)
	sig = append(sig, rsig[0:64]...)
	//hex := hex.EncodeToString(sig)

	return sig, nil
}
