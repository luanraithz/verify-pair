package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha512"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"flag"
	"io/ioutil"
)

const (
	message = "my-test-message"
)

func Decrypt(privateKeyBytes []byte, encryptedMessage []byte) (string, error) {
	privateKey, err := exportPEMStrToPrivKey(privateKeyBytes)
	if err != nil {
		return "", err
	}
	decodeMessage, err := rsa.DecryptOAEP(sha512.New(), rand.Reader, privateKey, encryptedMessage, nil)

	return string(decodeMessage), err
}

func Encrypt(publicKeyBytes []byte, message string) ([]byte, error) {
	messageBytes := []byte(message)
	publicKey, err := exportPEMStrToPubKey(publicKeyBytes)
	if err != nil {
		return nil, err
	}

	cipherText, err := rsa.EncryptOAEP(sha512.New(), rand.Reader, publicKey, messageBytes, nil)

	return cipherText, err
}

func exportPEMStrToPrivKey(priv []byte) (*rsa.PrivateKey, error) {
	block, _ := pem.Decode(priv)
	if block == nil {
		return nil, errors.New("Error while decoding the private rsa certificate")
	}
	return x509.ParsePKCS1PrivateKey(block.Bytes)
}

func exportPEMStrToPubKey(pub []byte) (*rsa.PublicKey, error) {
	block, _ := pem.Decode(pub)
	if block == nil {
		return nil, errors.New("Error while decoding the public rsa certificate")
	}
	return x509.ParsePKCS1PublicKey(block.Bytes)
}

func must(err error) {
	if err != nil {
		panic(err)
	}
}

func main() {
	privateKeyFile := flag.String("pr", "./private.pem", "Path to the private key (certifcate string or base64)")
	publicKeyFile := flag.String("pu", "./public.pem", "Path to the public key (certifcate string or base64)")
	flag.Parse()

	private, err := ioutil.ReadFile(*privateKeyFile)
	must(err)
	public, err := ioutil.ReadFile(*publicKeyFile)
	must(err)

	// Try to parse from base64
	privateKey, err := base64.StdEncoding.DecodeString(string(private))
	if err != nil {
		privateKey = private
	}
	publicKey, err := base64.StdEncoding.DecodeString(string(public))
	if err != nil {
		publicKey = public
	}

	encrypted, err := Encrypt(publicKey, message)
	must(err)
	dec, err := Decrypt(privateKey, encrypted)

	must(err)
	if dec != message {
		panic("Decrypted content is different")
	}

	println("Keys verifed")
}
