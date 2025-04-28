package main

import (
	"example.com/"
	"encoding/hex"
	"fmt"
)

// --- Helper Functions ---

func main() {
	// Example Inputs
	bdkHex := "0123456789ABCDEFFEDCBA9876543210"
	ksnHex := "FFFF9876543210E00001"
	dataHex := "3132333435363738" // "12345678" in ASCII

	// Decode hex to bytes
	bdk, _ := hex.DecodeString(bdkHex)
	ksn, _ := hex.DecodeString(ksnHex)
	data, _ := hex.DecodeString(dataHex)

	// 1. Generate IPEK
	ipek := dukpt.GenerateIPEK(bdk, ksn)

	// 2. Derive Session Key
	sessionKey := deriveKey(ipek, ksn)

	// 3. Encrypt
	encrypted := encryptTransactionData(sessionKey, data)
	fmt.Println("Encrypted Data:", hex.EncodeToString(encrypted))

	// 4. Decrypt
	decrypted := decryptTransactionData(sessionKey, encrypted)
	fmt.Println("Decrypted Data (Hex):", hex.EncodeToString(decrypted))
	fmt.Println("Decrypted Data (ASCII):", string(decrypted))
}
