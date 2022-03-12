package dashmsg

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"io"
	"math/big"

	"github.com/anaskhan96/base58check"
	secp256k1crypto "github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/crypto/secp256k1"
)

var (
	// CheckVersion is the magic version byte signifying the payment address coin type (i.e. Dash, Public Key)
	CheckVersion = "4c" // Dash (vs 0x00 for BC)

	// WIFVersion is the magic version byte signifying the wallet type (i.e. Dash, Private Key)
	WIFVersion = "cc" // Dash (vs 0x80 for BC)
	// MagicBytes is the secure delimiter that scopes a message to a particular network
	MagicBytes = []byte("DarkCoin Signed Message:\n")
)

var randReader io.Reader = rand.Reader

// GenerateWIF creates a new wallet private key as WIF
func GenerateWIF() string {
	priv, _ := ecdsa.GenerateKey(secp256k1.S256(), randReader)
	b := priv.D.Bytes()

	hexkey := hex.EncodeToString(b)
	compressed := "01"
	wif, _ := base58check.Encode(WIFVersion, hexkey+compressed)

	return wif
}

// WIFToPrivateKey converts from base58check (WIF) to a standard(ish) ECDSA private key
func WIFToPrivateKey(wif string) (*ecdsa.PrivateKey, error) {
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

/*
func WIFToPrivateKey(wif string) (*ecdsa.PrivateKey, error) {
}
*/

// MagicSign scopes the signature of a message to the Dash network
func MagicSign(priv *ecdsa.PrivateKey, msg []byte) ([]byte, error) {
	hash := MagicHash(msg)
	rsig, _ := secp256k1crypto.Sign(hash[:], priv)
	sig := make([]byte, 0, 65)
	// +4 for compressed
	recovery := rsig[64] + 27 + 4
	// sig[64] is recovery bit
	sig = append(sig, recovery)
	sig = append(sig, rsig[0:64]...)
	//hex := hex.EncodeToString(sig)

	return sig, nil
}

// SigToPub computes the public key from the message's magichash and the recovery signature (has the magic byte, a.k.a. "i" at the front of it)
func SigToPub(magichash, dsig []byte) (*ecdsa.PublicKey, error) {
	rsig := make([]byte, 0, 65)

	recovery := dsig[0] - (27 + 4)
	sig := dsig[1:]
	rsig = append(rsig, sig...)
	rsig = append(rsig, recovery)

	return secp256k1crypto.SigToPub(magichash, rsig)
}

// PublicKeyToAddress transforms a PublicKey into a PubKeyHash address is Base58Check format
func PublicKeyToAddress(pub ecdsa.PublicKey) string {
	pubKeyHash := secp256k1crypto.PubkeyToAddress(pub).Bytes()
	pubKeyHashHex := hex.EncodeToString(pubKeyHash)
	addr, _ := base58check.Encode(CheckVersion, pubKeyHashHex)
	//fmt.Println("PubKeyHash Bytes:", pubKeyHash)
	//fmt.Println("PubKeyHash:", addr)

	return addr
}

// MarshalPublicKey uses elliptic.Marshal to output the secp256k1.S256() curve public key
func MarshalPublicKey(pub ecdsa.PublicKey) []byte {
	return elliptic.Marshal(secp256k1crypto.S256(), pub.X, pub.Y)
}

// CompactSignature is the 65-byte Dash signature with the magic "i" recovery int as the first byte
type CompactSignature struct {
	I int
	R []byte
	S []byte
}

// DecodeSignature will break a Dash message signature into its component parts of "i" (the pub key recovery int), and "r" and "s" - the normal (non-ASN.1) ECDSA signature parts
func DecodeSignature(b64 string) (*CompactSignature, error) {
	b, err := base64.StdEncoding.DecodeString(b64)
	if nil != err {
		return nil, err
	}

	magicI := int(b[0])
	i := magicI - (27 + 4)
	sig := &CompactSignature{
		I: i,
		R: b[1:33],
		S: b[33:65],
	}

	return sig, nil
}

// MagicHash combines the magic bytes and message, with their respective lengths (encoded as BCVarint) prepended to each, and then double hashes the result
func MagicHash(msg []byte) []byte {
	buf := MagicConcat(MagicBytes, msg)
	//fmt.Println("Magic Hash In:", hex.EncodeToString(buf))
	hash := DoubleHash(buf)
	//fmt.Println("Magic Hash Out:", hex.EncodeToString(hash))

	return hash
}

// MagicConcat combines the magic bytes (which signify the network the message belongs to) and message, with their respective lengths (encoded as BCVarint) prepended to each
func MagicConcat(magicBytes, msg []byte) []byte {
	magicBytesLen := len(magicBytes)
	prefix1 := EncodeToBCVarint(magicBytesLen)
	//var messageBuffer = Buffer.from(this.message);
	msgLen := len(msg)
	prefix2 := EncodeToBCVarint(msgLen)

	bufLen := len(prefix1) + len(magicBytes) + len(prefix2) + len(msg)
	buf := make([]byte, 0, bufLen)
	buf = append(buf, prefix1...)
	buf = append(buf, magicBytes...)
	buf = append(buf, prefix2...)
	buf = append(buf, msg...)

	return buf
}

// DoubleHash simply runs one sha256 sum in series with another
func DoubleHash(buf []byte) []byte {
	hash1 := sha256.Sum256(buf)
	hash2 := sha256.Sum256(hash1[:])
	return hash2[:]
}

// EncodeToBCVarint is a special variable-width byte encoding for 8, 16, 32, or 64-bit integers. For integers less than 253 bytes it uses a single bit. 253, 254, and 255 signify a 16, 32, and 64-bit (2, 4, and 8-byte) little-endian encodings respectively.
func EncodeToBCVarint(m int) []byte {
	// See https://wiki.bitcoinsv.io/index.php/VarInt
	var buf []byte

	n := int64(m)

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
