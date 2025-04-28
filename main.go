package main

import (
	"crypto/des"
	"encoding/hex"
	"fmt"
)

// --- Helper Functions ---

// 3DES Encrypt
func tripleDESEncrypt(key, data []byte) []byte {
	block, err := des.NewTripleDESCipher(key)
	if err != nil {
		panic(err)
	}
	out := make([]byte, 8)
	block.Encrypt(out, data)
	return out
}

// 3DES Decrypt
func tripleDESDecrypt(key, data []byte) []byte {
	block, err := des.NewTripleDESCipher(key)
	if err != nil {
		panic(err)
	}
	out := make([]byte, 8)
	block.Decrypt(out, data)
	return out
}

// XOR two byte slices
func xor(a, b []byte) []byte {
	if len(a) != len(b) {
		panic("xor: lengths do not match")
	}
	result := make([]byte, len(a))
	for i := range a {
		result[i] = a[i] ^ b[i]
	}
	return result
}

// Mask KSN (zero transaction counter bits)
func maskKSN(ksn []byte) []byte {
	masked := make([]byte, 8)
	copy(masked, ksn[:8])
	masked[7] &= 0xE0
	return masked
}

// Generate IPEK from BDK and KSN
func generateIPEK(bdk, ksn []byte) []byte {
	ksnMasked := maskKSN(ksn)

	key1 := bdk[:16]
	leftKey := key1[:8]
	rightKey := key1[8:]

	// Step 1: Encrypt KSN masked with left and right halves of BDK
	ipekLeft := tripleDESEncrypt(append(leftKey, rightKey...), ksnMasked)

	// Modify BDK by XORing certain bytes to derive second key
	bdkMask := []byte{0xC0, 0xC0, 0xC0, 0xC0, 0x00, 0x00, 0x00, 0x00}
	leftKey = xor(leftKey, bdkMask)
	rightKey = xor(rightKey, bdkMask)

	ipekRight := tripleDESEncrypt(append(leftKey, rightKey...), ksnMasked)

	return append(ipekLeft, ipekRight...)
}

// Derive transaction key
func deriveKey(ipek, ksn []byte) []byte {
	counter := make([]byte, 3)
	copy(counter, ksn[7:])
	counter[0] &= 0x1F // 5 bits only

	curKey := ipek

	for shift := 0; shift < 21; shift++ {
		bit := uint(1 << shift)
		if (uint32(counter[0])<<16|uint32(counter[1])<<8|uint32(counter[2]))&uint32(bit) != 0 {
			newKSN := make([]byte, 8)
			copy(newKSN, ksn[:8])
			newKSN[5] |= byte((bit >> 16) & 0xFF)
			newKSN[6] |= byte((bit >> 8) & 0xFF)
			newKSN[7] |= byte(bit & 0xFF)

			curKey = generateSessionKey(curKey, newKSN)
		}
	}

	return generateSessionKey(curKey, ksn)
}

// Generate session key
func generateSessionKey(key, ksn []byte) []byte {
	leftKey := key[:8]
	rightKey := key[8:]

	// Mask
	ksnMasked := make([]byte, 8)
	copy(ksnMasked, ksn[2:10])
	ksnMasked[5] &= 0xE0
	ksnMasked[6] = 0x00
	ksnMasked[7] = 0x00

	// Encrypt
	encLeft := tripleDESEncrypt(append(leftKey, rightKey...), ksnMasked)

	// Mask key (flip bits)
	mask := []byte{0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00}
	leftKeyMasked := xor(leftKey, mask)
	rightKeyMasked := xor(rightKey, mask)

	encRight := tripleDESEncrypt(append(leftKeyMasked, rightKeyMasked...), ksnMasked)

	return append(encLeft, encRight...)
}

// Encrypt transaction data using DUKPT
func encryptTransactionData(sessionKey, data []byte) []byte {
	return tripleDESEncrypt(sessionKey, data)
}

// Decrypt transaction data using DUKPT
func decryptTransactionData(sessionKey, encryptedData []byte) []byte {
	return tripleDESDecrypt(sessionKey, encryptedData)
}

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
	ipek := generateIPEK(bdk, ksn)

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
