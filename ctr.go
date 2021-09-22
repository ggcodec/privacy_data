package dataCbcCipher

import (
	"crypto/cipher"
)

// AesCtrEnCipher Ctr模式加密
func (a *Aes)AesCtrEnCipher(plainText []byte) ([]byte,[]byte){
	iv := ivRand(aesBlockSize)
	dst := make([]byte, len(plainText))
	// 创建一个使用ctr分组接口
	stream := cipher.NewCTR(a.AesCipher, iv)
	stream.XORKeyStream(dst, plainText)

	return dst,iv
}

// AesCtrDeCipher Ctr模式解密
func (a *Aes)AesCtrDeCipher(cipherText ,iv []byte) []byte {
	plainText := make([]byte, len(cipherText))
	stream1 := cipher.NewCTR(a.AesCipher, iv)
	stream1.XORKeyStream(plainText, cipherText)
	//log.FmtInfo("解密",string(plainText))
	return plainText
}
