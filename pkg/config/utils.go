// Copyright 2020 The frp Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package config

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/base64"
	"strings"
)

func GetMapWithoutPrefix(set map[string]string, prefix string) map[string]string {
	m := make(map[string]string)

	for key, value := range set {
		if strings.HasPrefix(key, prefix) {
			m[strings.TrimPrefix(key, prefix)] = value
		}
	}

	if len(m) == 0 {
		return nil
	}

	return m
}

func GetMapByPrefix(set map[string]string, prefix string) map[string]string {
	m := make(map[string]string)

	for key, value := range set {
		if strings.HasPrefix(key, prefix) {
			m[key] = value
		}
	}

	if len(m) == 0 {
		return nil
	}

	return m
}

var randBytes = []byte{33, 63, 47, 21, 35, 15, 24, 64, 78, 53, 78, 89, 33, 55, 14, 05}

const MySecret string = "abc&1*2^7%b^#~#^s0^=)^34"

func Encrypt(text string) (string, error) {
	block, err := aes.NewCipher([]byte(MySecret))
	if err != nil {
		return "", err
	}

	plainText := []byte(text)
	cfb := cipher.NewCFBEncrypter(block, randBytes)
	cipherText := make([]byte, len(plainText))
	cfb.XORKeyStream(cipherText, plainText)

	return base64.StdEncoding.EncodeToString(cipherText), nil
}

func Decrypt(text string) (string, error) {
	block, err := aes.NewCipher([]byte(MySecret))
	if err != nil {
		return "", err
	}

	cipherText, err := base64.StdEncoding.DecodeString(text)
	if err != nil {
		return "", err
	}
	cfb := cipher.NewCFBDecrypter(block, randBytes)
	plainText := make([]byte, len(cipherText))
	cfb.XORKeyStream(plainText, cipherText)

	return string(plainText), nil
}
