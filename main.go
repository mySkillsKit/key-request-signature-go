package main

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	_ "crypto/sha256"
	"encoding/hex"
	"fmt"
	Rsa "github.com/dvsekhvalnov/jose2go/keys/rsa"
	"io/ioutil"
)

func main() {

	keyBytes, err := ioutil.ReadFile(`/Users/avas/Downloads/app_aggregator_test_254_req_private_key.pem`)
	if err != nil {
		fmt.Println("ReadFile invalid key file", err)
		return
	}

	privateKey, err := Rsa.ReadPrivate(keyBytes)
	if err != nil {
		fmt.Println("ReadPrivate invalid key format", err)
		return
	}

	var (
		body      = []byte(`{"account":"15235212222","amount":100,"service_id":137,"extra_fields":{"merchant_id":"PLN00001"}}`)
		publicKey = &privateKey.PublicKey
		opts      rsa.PSSOptions
		newhash   = crypto.SHA256
		pssh      = newhash.New()
	)

	opts.SaltLength = rsa.PSSSaltLengthAuto
	pssh.Write(body)

	var hashed = pssh.Sum(nil)
	signature, err := rsa.SignPSS(rand.Reader, privateKey, newhash, hashed, &opts)
	if err != nil {
		fmt.Println("err rsa.SignPSS", err)
		return
	}

	fmt.Println("PSS Signature hex:", hex.EncodeToString(signature))

	//Verify Signature
	if err := rsa.VerifyPSS(publicKey, newhash, hashed, signature, &opts); err != nil {
		fmt.Println("err rsa.VerifyPSS", err)
		return
	}

	fmt.Println("Verify Signature successful")
	return
}
