# 数据加解密
- 版本：v1.0
- ctr 模式aes 加密
- cbc 模式aes/des 加密

## 注意事项
- 在本包中初始化向量是随机生成的指定长度字符串，需要自行接收处理，解密时需要用到
- aes 加密 key 需要指定16个字节长度的字符切片
- des 加密 key 需要指定8个字节长度的字符切片
- 无论哪种方式的加密在解密的时候使用的key 和iv 都必须要与加密时使用的key 和iv 一致

## 数据加解密包使用方法
- 加密：
    1. 创建des 加密实例：name := NewDesCipher(key)
    2. 开始加密数据，使用name.DesEncrypt([]byte(加密数据))会返回密文和初始向量字符串
- 解密：
    1. 创建des 解密实例：name := NewDesCipher(key)
    2. 开始解密数据，deserDe.DesDecrypt(cipherText[密文],iv[加密函数第二个返回值就是iv])
  
- 包使用代码示例：
```go
package main

import (
	// 包名较长建议起个别名
  dataen "github.com/ggcodec/privacy_data"
  "github.com/ggcodec/Printlog"
)

// 代码包使用示例
func main() {
  log := Printlog.NewPrintlog()
  aesKey := []byte("zhangsan12312312")
  desKey := []byte("zhangsan")

  src := []byte("这是一段加密数据，以此来验证我们的数据是否通过了加密或者解密！")

  // cbc aes 加密
  maes := dataen.NewAesCipher(aesKey)
  cipherText ,iv := maes.AesCbcEncrypt(src)

  // cbc aes 解密
  maes1 := dataen.NewAesCipher(aesKey)
  plainText  := maes1.AesCbcDecrypt(cipherText,iv)
  log.FmtInfo("aes CBC解密：",string(plainText))

  // cbc des 加密
  mdes := dataen.NewDesCipher(desKey)
  cipherText ,iv = mdes.DesCbcEncrypt(src)

  // cbc des 解密
  mdes1 := dataen.NewDesCipher(desKey)
  plainText = mdes1.DesCbcDecrypt(cipherText ,iv)
  log.FmtInfo("des CBC解密：",string(plainText))

  // ctr aes 加密
  aesctr := dataen.NewAesCipher(aesKey)
  cipherText, iv = aesctr.AesCtrEnCipher(src)

  // ctr aes 解密密
  aesctr1 := dataen.NewAesCipher(aesKey)
  plainText = aesctr1.AesCtrDeCipher(cipherText, iv)
  log.FmtInfo("aes CTR解密：",string(plainText))
}

```
