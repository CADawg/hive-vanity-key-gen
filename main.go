package main

import (
	"crypto/sha256"
	"fmt"
	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	"golang.org/x/crypto/ripemd160"
	"os"
	"runtime"
	"strings"
	"sync/atomic"
	"time"

	"github.com/decred/base58"
)

var target = "hive"
var caseSensitive = false

var startTime = time.Now()
var count = new(atomic.Int64)
var found = new(atomic.Int64)
var file *os.File

func main() {
	if len(os.Args) > 1 {
		target = os.Args[1]

		if len(os.Args) > 2 {
			var err error
			file, err = os.OpenFile(os.Args[2], os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)

			if err != nil {
				panic(err)
			}
		}

		if len(os.Args) > 3 {
			if os.Args[3] == "true" {
				// case sensitive
				caseSensitive = true
			}
		}
	}

	defer func(file *os.File) {
		_ = file.Close()
	}(file)

	for i := 0; i < runtime.NumCPU(); i++ {
		go func() {
			for {
				// generate secp256k1 keypair
				priv, err := secp256k1.GeneratePrivateKey()

				if err != nil {
					panic(err)
				}

				// serialize private key
				pub := priv.PubKey()

				// serialize to pub key string
				pubStr := GetPublicKeyString(pub)

				if (!caseSensitive && strings.Contains(strings.ToLower(*pubStr), strings.ToLower(target))) || (caseSensitive && strings.Contains(*pubStr, target)) {
					println("found key with target in it")

					// print public key
					println(*pubStr)
					println(PrivKeyToWif(priv))

					if file != nil {
						_, _ = file.WriteString("Keypair:\n")
						_, _ = file.WriteString("Public: " + *pubStr + "\n")
						_, _ = file.WriteString("Private: " + PrivKeyToWif(priv) + "\n\n")
					}

					found.Store(found.Load() + 1)
				}

				// increment counter
				count.Store(count.Load() + 1)
			}
		}()
	}

	go func() {
		// print keys per second
		for {
			time.Sleep(1 * time.Second)
			fmt.Printf("Keys per second: %f\n", float64(count.Load())/(time.Since(startTime).Seconds()))
			fmt.Printf("Matches per second: %f\n", float64(found.Load())/(time.Since(startTime).Seconds()))

		}
	}()

	var c chan struct{}

	<-c
}

func GetPublicKeyString(pubKey *secp256k1.PublicKey) *string {
	if pubKey == nil {
		return nil
	}

	pubKeyBytes := pubKey.SerializeCompressed()

	// get ripemd160 hash
	hasher := ripemd160.New()
	_, err := hasher.Write(pubKeyBytes)

	if err != nil {
		return nil
	}

	// get checksum
	checksum := hasher.Sum(nil)[:4]

	// append checksum to public key

	pubKeyBytes = append(pubKeyBytes, checksum...)

	// encode to base58
	encoded := base58.Encode(pubKeyBytes)

	// add prefix
	encoded = "STM" + encoded

	return &encoded
}

func PrivKeyToWif(priv *secp256k1.PrivateKey) string {
	// need to do inverse of KeyPairFromWif

	// serialize private key
	privKey := priv.Serialize()

	// add version byte
	version := [1]byte{0x80}

	// add checksum
	checksum := checksum(append(version[:], privKey...))

	// concatenate version, privKey and checksum
	payload := append(version[:], privKey...)

	// base58 encode
	return base58.Encode(append(payload, checksum[:]...))
}

func checksum(input []byte) [4]byte {
	var calculatedChecksum [4]byte
	intermediateHash := sha256.Sum256(input)
	finalHash := sha256.Sum256(intermediateHash[:])
	copy(calculatedChecksum[:], finalHash[:])
	return calculatedChecksum
}
