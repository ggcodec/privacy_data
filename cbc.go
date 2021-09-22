package dataCbcCipher

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/des"
	"fmt"
	"github.com/ggcodec/Printlog"
	"math/rand"
)

const (
	desBlockSize = 8
	aesBlockSize = 16
)

var (
	log         = Printlog.NewPrintlog()
	longLetters = []byte("0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJ" +
		"KLMNOPQRSTUVWXYZ=_")
)

// Aes 加密实例
type Aes struct {
	AesCipher cipher.Block
}

// Des 加密实例
type Des struct {
	DesCipher cipher.Block
}

// 随机生成初始向量的函数
func ivRand(n int) []byte {
	if n <= 0 {
		return []byte{}
	}
	b := make([]byte, n)
	arc := uint8(0)
	if _, err := rand.Read(b[:]); err != nil {
		return []byte{}
	}
	for i, x := range b {
		arc = x & 63
		b[i] = longLetters[arc]
	}
	return b
}

// Ciphers 获取block 对象
func CiphersDes(d *Des, key []byte) error {
	if len(key) == 8 {
		// desCipher
		// des key 必须填充8个字节
		desCipher, err := des.NewCipher(key)
		if err != nil {
			log.FmtWaring("this is desCipher error: ", err)
		}
		d.DesCipher = desCipher
		return nil
	}
	return fmt.Errorf("key 的长度不符合des标准")
}

func CiphersAes(a *Aes, key []byte) error {
	if len(key) == 16 {
		// aesCipher
		// aes key 必须填充16/24/32个字节
		aesCipher, err := aes.NewCipher(key)
		if err != nil {
			log.FmtWaring("this is aesCipher error: ", err)
		}
		a.AesCipher = aesCipher
		return nil
	}
	return fmt.Errorf("key 的长度不符合des标准")
}

// paddingLastGroup 明文尾部字节填充
func paddingLastGroup(plainText []byte, blockSize int) []byte {
	// 1. 求出最后一个组中剩余的字节数
	padNum := blockSize - len(plainText)%blockSize
	// 2. 创建一个心得切片，长度== padNum ，每个紫戒指byte（PadNum）
	char := []byte{byte(padNum)}
	newPlain := bytes.Repeat(char, padNum)

	// 3. NewPlain 数组追加到原始明文的后边,newPlain... 代表将切片或字符串拆解为单个字节后追加
	newText := append(plainText, newPlain...)
	return newText
}

// 去掉填充数据
func unPaddingLastGroup(plainText []byte) []byte {
	// 1. 取出最后分组的最后一个字节
	plainTextNum := len(plainText)
	lastChar := plainText[plainTextNum-1]
	number := int(lastChar) // 尾部填充的字节个数
	return plainText[:plainTextNum-number]

}

// DesCbcEncrypt des 加密
func (d *Des) DesCbcEncrypt(plainText []byte) ([]byte, []byte) {
	// 2. 明文填充
	blockSize := d.DesCipher.BlockSize()
	newText := paddingLastGroup(plainText, blockSize)

	// 3. 加密
	iv := ivRand(desBlockSize)
	desBlockMode := cipher.NewCBCEncrypter(d.DesCipher, iv)

	desBlockMode.CryptBlocks(newText, newText)
	return newText, iv
}

// DesCbcDecrypt des解密
func (d *Des) DesCbcDecrypt(cipherText, iv []byte) []byte {
	desBlockMode := cipher.NewCBCDecrypter(d.DesCipher, iv)
	desBlockMode.CryptBlocks(cipherText, cipherText)
	newDstText := unPaddingLastGroup(cipherText)
	return newDstText
}

// AesCbcEncrypt 加密
func (a *Aes) AesCbcEncrypt(plainText []byte) ([]byte, []byte) {
	// 2. 明文填充
	blockSize := a.AesCipher.BlockSize()
	newText := paddingLastGroup(plainText, blockSize)

	// 3. 加密
	iv := ivRand(aesBlockSize)
	desBlockMode := cipher.NewCBCEncrypter(a.AesCipher, iv)

	desBlockMode.CryptBlocks(newText, newText)
	return newText, iv
}

// AesCbcDecrypt aes解密
func (a *Aes) AesCbcDecrypt(cipherText, iv []byte) []byte {
	desBlockMode := cipher.NewCBCDecrypter(a.AesCipher, iv)
	desBlockMode.CryptBlocks(cipherText, cipherText)
	newDstText := unPaddingLastGroup(cipherText)
	return newDstText
}

func NewAesCipher(key []byte) *Aes {
	aeser := &Aes{}
	err := CiphersAes(aeser,key)
	if err != nil {log.FmtPanic(err)}
	return aeser
}

func NewDesCipher(key []byte) *Des {
	deser := &Des{}
	err := CiphersDes(deser,key)
	if err != nil {log.FmtPanic(err)}
	return deser
}
