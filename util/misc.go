package util

import (
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io/ioutil"
	"os"
)

// ToJSON is a convenience method for serializing to JSON.
// Use ToJSONNice for output seen by humans.
func ToJSON(v interface{}) string {
	s, _ := json.MarshalIndent(v, "", "   ")
	return string(s)
}

// ArgsHaveOption checks command line arguments for an option
func ArgsHaveOption(long, short string) (hasOption bool, foundAt int) {
	for i, arg := range os.Args {
		if arg == "--"+long || arg == "-"+short {
			return true, i
		}
	}
	return false, 0
}

// SaveKeyPair saves a key pair using the PEM format
func SaveKeyPair(pubkey, privkey, pubfile, privfile string) error {
	// saveKeyPair decodes the keys because PEM base64s them too, and decoding means that the pubkey in duck format is the same as the data in the PEM file. (which is nice but an arbitrary decision)
	d, _ := base64.StdEncoding.DecodeString(privkey)
	b := pem.EncodeToMemory(&pem.Block{
		Type:  "DUCKCOIN (ECDSA) PRIVATE KEY",
		Bytes: d,
	})
	if err := ioutil.WriteFile(privfile, b, 0600); err != nil {
		return err
	}

	d, _ = base64.StdEncoding.DecodeString(pubkey)
	b = pem.EncodeToMemory(&pem.Block{
		Type:  "DUCKCOIN (ECDSA) PUBLIC KEY",
		Bytes: d,
	})
	if err := ioutil.WriteFile(pubfile, b, 0644); err != nil {
		return err
	}

	return nil
}

// loadKeyPair loads a key pair from pubfile and privfile
func loadKeyPair(pubfile, privfile string) (pub, priv string, err error) {
	// see comment in util.SaveKeyPair for why the keys are base64 encoded before returning
	data, err := ioutil.ReadFile(pubfile)
	if err != nil {
		return "", "", err
	}
	key, _ := pem.Decode(data)
	if key == nil {
		return "", "", errors.New("could not decode PEM data from " + pubfile)
	}
	pubkey := base64.StdEncoding.EncodeToString(key.Bytes)
	data, err = ioutil.ReadFile(privfile)
	if err != nil {
		return "", "", err
	}
	key, _ = pem.Decode(data)
	if key == nil {
		return "", "", errors.New("could not decode PEM data from " + privfile)
	}
	privkey := base64.StdEncoding.EncodeToString(key.Bytes)
	return pubkey, privkey, nil
}

func LoadKeysAndAddr(pubfile, privfile string) (pub, priv string, addr Address, err error) {
	pub, priv, err = loadKeyPair(pubfile, privfile)
	if err != nil {
		return "", "", Address{}, err
	}
	return pub, priv, KeyToAddress(pub), nil
}

// IsValidBase64 checks if a string is valid base64
func IsValidBase64(s string) bool {
	_, err := base64.StdEncoding.DecodeString(s)
	return err == nil
}
