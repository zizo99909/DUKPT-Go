package dukpt

import "crypto/des"

func expandKey(key []byte) []byte {
	if len(key) == 16 {
		return append(key, key[:8]...)
	}
	return key
}

// 3DES Encrypt
func TripleDESEncrypt(key, data []byte) []byte {
	key = expandKey(key)
	block, err := des.NewTripleDESCipher(key)
	if err != nil {
		panic(err)
	}
	out := make([]byte, 8)
	block.Encrypt(out, data)
	return out
}

// 3DES Decrypt
func TripleDESDecrypt(key, data []byte) []byte {
	key = expandKey(key)
	block, err := des.NewTripleDESCipher(key)
	if err != nil {
		panic(err)
	}
	out := make([]byte, 8)
	block.Decrypt(out, data)
	return out
}

// XOR two byte slices
func Xor(a, b []byte) []byte {
	if len(a) != len(b) {
		panic("Xor: lengths do not match")
	}
	result := make([]byte, len(a))
	for i := range a {
		result[i] = a[i] ^ b[i]
	}
	return result
}

// Mask KSN (zero transaction counter bits)
func MaskKSN(ksn []byte) []byte {
	masked := make([]byte, 8)
	copy(masked, ksn[:8])
	masked[7] &= 0xE0
	return masked
}

// Generate IPEK from BDK and KSN
func GenerateIPEK(bdk, ksn []byte) []byte {
	ksnMasked := MaskKSN(ksn)

	key1 := bdk[:16]
	leftKey := key1[:8]
	rightKey := key1[8:]

	// Step 1: Encrypt KSN masked with left and right halves of BDK
	ipekLeft := TripleDESEncrypt(append(leftKey, rightKey...), ksnMasked)

	// Modify BDK by XORing certain bytes to derive second key
	bdkMask := []byte{0xC0, 0xC0, 0xC0, 0xC0, 0x00, 0x00, 0x00, 0x00}
	leftKey = Xor(leftKey, bdkMask)
	rightKey = Xor(rightKey, bdkMask)

	ipekRight := TripleDESEncrypt(append(leftKey, rightKey...), ksnMasked)

	return append(ipekLeft, ipekRight...)
}

// Derive transaction key
func DeriveKey(ipek, ksn []byte) []byte {
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

			curKey = GenerateSessionKey(curKey, newKSN)
		}
	}

	return GenerateSessionKey(curKey, ksn)
}

// Generate session key
func GenerateSessionKey(key, ksn []byte) []byte {
	leftKey := key[:8]
	rightKey := key[8:]

	// Mask
	ksnMasked := make([]byte, 8)
	copy(ksnMasked, ksn[2:])
	ksnMasked[5] &= 0xE0
	ksnMasked[6] = 0x00
	ksnMasked[7] = 0x00

	// Encrypt
	encLeft := TripleDESEncrypt(append(leftKey, rightKey...), ksnMasked)

	// Mask key (flip bits)
	mask := []byte{0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00}
	leftKeyMasked := Xor(leftKey, mask)
	rightKeyMasked := Xor(rightKey, mask)

	encRight := TripleDESEncrypt(append(leftKeyMasked, rightKeyMasked...), ksnMasked)

	return append(encLeft, encRight...)
}

// Encrypt transaction data using DUKPT
func EncryptTransactionData(sessionKey, data []byte) []byte {
	return TripleDESEncrypt(sessionKey, data)
}

// Decrypt transaction data using DUKPT
func DecryptTransactionData(sessionKey, encryptedData []byte) []byte {
	return TripleDESDecrypt(sessionKey, encryptedData)
}
