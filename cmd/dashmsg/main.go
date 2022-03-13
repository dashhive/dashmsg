package main

import (
	"bytes"
	"crypto/ecdsa"
	"encoding/base64"
	"encoding/hex"
	"flag"
	"fmt"
	"io/ioutil"
	"os"
	"strings"

	"github.com/anaskhan96/base58check"
	"github.com/dashhive/dashmsg"
)

var (
	name    = "dashmsg"
	version = "0.0.0"
	date    = "0001-01-01T00:00:00Z"
	commit  = "0000000"
)

func usage() {
	fmt.Println(ver())
	fmt.Println()
	fmt.Println("Usage")
	fmt.Printf("    %s <command> [flags] args...\n", name)
	fmt.Println("")
	fmt.Printf("See usage: %s help <command>\n", name)
	fmt.Println("")
	fmt.Println("Commands:")
	fmt.Println("    version")
	fmt.Println("    gen [--cointype '0xcc'] [name.wif]")
	fmt.Println("    sign [--cointype '0x4c'] <key> <msg>")
	fmt.Println("    inspect [--cointype '0x4c'] <key | address | signature>")
	fmt.Println("    decode (alias of inspect)")
	fmt.Println("    verify <payment address> <msg> <signature>")
	fmt.Println("")
	fmt.Println("Examples:")
	fmt.Println("    dashmsg gen ./dash.wif")
	fmt.Println("")
	fmt.Println("    dashmsg sign dash.wif ./msg.txt")
	fmt.Println("    dashmsg sign dash.wif 'my message'")
	fmt.Println("    dashmsg sign 'Xxxx...ccc' 'my message'")
	fmt.Println("")
	fmt.Println("    dashmsg inspect --verbose 'Xxxxxxxxxxxxxxxxxxxxxxxxxxxxcccccc'")
	fmt.Println("")
	fmt.Println("    dashmsg verify Xxxx...ccc 'my message' 'II....signature...'")
	fmt.Println("    dashmsg verify ./addr.b58c.txt ./msg.txt ./sig.b64.txt")
	fmt.Println("")
}

func ver() string {
	return fmt.Sprintf("%s v%s (%s) %s", name, version, commit[:7], date)
}

func main() {
	args := os.Args[:]

	if len(os.Args) > 1 &&
		("version" == strings.TrimLeft(os.Args[1], "-") ||
			"-V" == os.Args[1]) {
		fmt.Println(ver())
		os.Exit(0)
		return
	}

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
	case "gen":
		gen(args[2:])
	case "sign":
		sign(args[2:])
	case "decode":
		fallthrough
	case "inspect":
		inspect(args[2:])
	case "verify":
		verify(args[2:])
	default:
		usage()
		os.Exit(1)
		return
	}
}

func gen(args []string) {
	var cointype string

	flags := flag.NewFlagSet("gen", flag.ExitOnError)
	flags.StringVar(&cointype, "cointype", "", "the magic version (hex) string of the private key")
	flags.Parse(args)

	cointype = strings.TrimPrefix(cointype, "0x")

	wif := dashmsg.GenerateWIF(cointype)

	if len(flags.Args()) == 1 {
		b := []byte(wif)
		b = append(b, '\n')
		ioutil.WriteFile(flags.Args()[0], b, 0644)
		fmt.Printf("wrote Private Key (as WIF) to %q\n", flags.Args()[0])
		return
	}

	fmt.Println(wif)
}

func inspect(args []string) {
	var cointype string

	flags := flag.NewFlagSet("inspect", flag.ExitOnError)
	flags.StringVar(&cointype, "cointype", "", "the magic version (hex) string of the private key")
	flags.Parse(args)

	cointype = strings.TrimPrefix(cointype, "0x")

	if len(flags.Args()) != 1 {
		fmt.Fprintf(os.Stderr, "usage: %s inspect <addr-or-key>\n", os.Args[0])
		os.Exit(1)
		return
	}
	input := flags.Args()[0]

	var usererr error
	inputlen := len(input)

	switch inputlen {
	case 88:
		sig, err := dashmsg.DecodeSignature(input)
		if nil != err {
			usererr = err
			break
		}

		fmt.Printf("I     (0): %d (quadrant)\n", sig.I)
		fmt.Printf("R  (1-32): %s\n", hex.EncodeToString(sig.R))
		fmt.Printf("S (33-64): %s\n", hex.EncodeToString(sig.S))
		return

	case 52:
		wif := input
		hexstr, err := base58check.Decode(input)
		if nil != err {
			usererr = err
			break
		}

		privCointype, priv, err := dashmsg.WIFToPrivateKey(wif)
		if nil != err {
			usererr = err
			break
		}
		if 0 == len(cointype) {
			cointype = privCointype
		}

		pubBytes := dashmsg.MarshalPublicKey(priv.PublicKey)
		pkh := dashmsg.PublicKeyToAddress(cointype, priv.PublicKey)

		fmt.Printf("PrivateKey (hex): %s (coin type)\n", privCointype)
		fmt.Printf("                : %s\n", hexstr[2:66])
		fmt.Printf("                : %s (compressed)\n", hexstr[66:])
		fmt.Println()
		fmt.Printf("PublicKey  (hex): %s (uncompressed)\n", hex.EncodeToString(pubBytes[:1]))
		fmt.Printf("               x: %s\n", hex.EncodeToString(pubBytes[1:33]))
		fmt.Printf("               y: %s\n", hex.EncodeToString(pubBytes[33:65]))
		fmt.Println()
		fmt.Printf("Address   (b58c): %s\n", pkh)
		return

	case 34:
		hex, err := base58check.Decode(input)
		if nil != err {
			usererr = err
			break
		}

		fmt.Printf("Address    (hex): %s (coin type)\n", hex[:2])
		fmt.Printf("                : %s\n", hex[2:])
		return
	default:
		usererr = fmt.Errorf("string with length %d does not look like a signature, private key, public key", inputlen)

	}

	fmt.Fprintf(os.Stderr, "error: could not decode address: %v\n", usererr)
	os.Exit(1)
}

func sign(args []string) {
	var cointype string

	flags := flag.NewFlagSet("sign", flag.ExitOnError)
	flags.StringVar(&cointype, "cointype", "", "the magic version (hex) string of the private key")
	flags.Parse(args)

	cointype = strings.TrimPrefix(cointype, "0x")

	if len(flags.Args()) <= 1 {
		fmt.Fprintf(os.Stderr, "usage: %s sign <addr-or-key> <msg>\n", os.Args[0])
		os.Exit(1)
		return
	}
	wifname := flags.Args()[0]
	payload := flags.Args()[1]

	_, priv, err := readWif(wifname)
	if nil != err {
		fmt.Fprintf(os.Stderr, "error: could not decode private key: %v\n", err)
		os.Exit(1)
		return
	}

	b := readFileOrString(payload)

	sig, err := dashmsg.MagicSign(priv, b)
	if nil != err {
		fmt.Fprintf(os.Stderr, "error: could not sign message: %v\n", err)
		os.Exit(1)
		return
	}
	b64 := base64.StdEncoding.EncodeToString(sig)

	fmt.Println(b64)
}

func verify(args []string) {
	flags := flag.NewFlagSet("verify", flag.ExitOnError)
	flags.Parse(args)

	if len(flags.Args()) <= 2 {
		fmt.Fprintf(os.Stderr, "usage: %s verify <payaddr> <signature> <msg>\n", os.Args[0])
		os.Exit(1)
		return
	}

	addrname := flags.Args()[0]
	msgname := flags.Args()[1]
	signame := flags.Args()[2]

	addrBytes := readFileOrString(addrname)
	addr := string(addrBytes)

	msg := readFileOrString(msgname)
	magichash := dashmsg.MagicHash(msg)

	sigBytes := readFileOrString(signame)
	sig := string(sigBytes)

	sigBytes, err := base64.StdEncoding.DecodeString(sig)
	if nil != err {
		fmt.Fprintf(os.Stderr, "error: could not decode signature: %v\n", err)
		os.Exit(1)
		return
	}

	pub, err := dashmsg.SigToPub(magichash, sigBytes)
	if nil != err {
		fmt.Fprintf(os.Stderr, "error: could not verify message: %v\n", err)
		os.Exit(1)
		return
	}

	cointype, err := dashmsg.AddressToCointype(addr)
	if nil != err {
		// Neither a valid file nor string. Blast!
		fmt.Printf("can't detect coin type of %q: %v\n", addr, err)
		os.Exit(1)
		return
	}

	if dashmsg.PublicKeyToAddress(cointype, *pub) == addr {
		fmt.Println("Verified: true")
		return
	}

	fmt.Println("Invalid Signature")
}

func readFileOrString(str string) []byte {
	b, err := ioutil.ReadFile(str)
	if nil != err {
		b = []byte(str)
	} else {
		b = bytes.TrimSpace(b)
	}
	return b
}

func readWif(wifname string) (string, *ecdsa.PrivateKey, error) {
	// Read as file
	wif := readFileOrString(wifname)

	cointype, priv, err := dashmsg.WIFToPrivateKey(string(wif))
	if nil != err {
		// Neither a valid file nor string. Blast!
		return "", nil, fmt.Errorf(
			"could not read private key as file (or parse as string) %q:\n%s",
			wifname, err,
		)
	}

	return cointype, priv, nil
}
