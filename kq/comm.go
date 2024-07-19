package kq

import (
	"bufio"
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"github.com/jinzhu/copier"
	"github.com/segmentio/kafka-go/sasl"
	"github.com/segmentio/kafka-go/sasl/plain"
	"github.com/segmentio/kafka-go/sasl/scram"
	"log"
	"os"
)

func saslMech(c KqSaslCaConf) sasl.Mechanism {
	var (
		mech sasl.Mechanism
		err  error
	)

	if len(c.Username) > 0 && len(c.Password) > 0 {
		if c.SASL_WAY == SASL_SCRAM {
			mech, err = scram.Mechanism(scram.SHA512, c.Username, c.Password)
			if err != nil {
				log.Fatal(err)
			}
		} else {
			mech = plain.Mechanism{
				Username: c.Username,
				Password: c.Password,
			}
		}
	}

	return mech
}

func tlsConfig(c KqSaslCaConf) *tls.Config {
	var (
		err                       error
		caCert, certCert, keyCert []byte
		certificate               tls.Certificate
		tlsConfig                 *tls.Config
	)
	if len(c.CaFile) > 0 || len(c.CaPEM) > 0 {
		if c.CA_WAY == CA_TEXT {
			if len(c.CaPEM) > 0 {
				caCert = Base64ToPEM(c.CaPEM, "CERTIFICATE")
			}
			if len(c.CertPEM) > 0 && len(c.KeyPEM) > 0 {
				certCert = Base642PEM(c.CertPEM)
				keyCert = Base64ToPEM(c.KeyPEM, "RSA PRIVATE KEY")
			}
		} else {
			caCert, err = os.ReadFile(c.CaFile)
			if err != nil {
				log.Fatal(err)
			}
			if len(c.CertFile) > 0 {
				certCert, err = os.ReadFile(c.CertFile)
				if err != nil {
					log.Fatal(err)
				}
			}
			if len(c.KeyFile) > 0 {
				keyCert, err = os.ReadFile(c.KeyFile)
				if err != nil {
					log.Fatal(err)
				}
			}
		}
		// Define TLS configuration
		caCertPool := x509.NewCertPool()
		ok := caCertPool.AppendCertsFromPEM(caCert)
		if !ok {
			log.Printf("Ca PEM mismatch ...")
			log.Fatal(err)
		}

		if len(certCert) > 0 && len(keyCert) > 0 {
			certificate, err = tls.X509KeyPair(certCert, keyCert)
			if err != nil {
				log.Fatal(err)
			}

		}
		tlsConfig = &tls.Config{
			RootCAs:            caCertPool,
			InsecureSkipVerify: true,
			//MinVersion:         tls.VersionTLS12,
		}
		if len(certificate.Certificate) > 0 {
			tlsConfig.Certificates = []tls.Certificate{certificate}
		}
	}
	return tlsConfig
}

func scConf(c interface{}) KqSaslCaConf {
	var sc KqSaslCaConf
	err := copier.Copy(&sc, c)
	if err != nil {
		return KqSaslCaConf{}
	}
	return sc
}

func VerifyCertPemStr(certStr string) bool {
	// 将字符串转换为PEM格式
	block, _ := pem.Decode([]byte(certStr))
	if block == nil {
		//证书解析失败
		return false
	}

	// 解析证书
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		//证书解析失败
		log.Fatal(err)
		return false
	}
	// 使用证书对象
	log.Printf("证书主题: %+v\n", cert.Subject)
	return true
}

func Base64ToPEM(base64String string, certType string) []byte {
	// 将Base64编码的字符串解码成byte slice
	data, err := base64.StdEncoding.DecodeString(base64String)
	if err != nil {
		panic(err)
	}

	// 创建PEM块
	pemBlock := &pem.Block{
		Type:  certType, // PEM类型，通常为"PUBLIC KEY" 根据需要可以改为"RSA PRIVATE KEY", "PUBLIC KEY"等 CERTIFICATE
		Bytes: data,     // 公钥数据
	}

	// 将PEM块编码成字节切片，即得到PEM格式的公钥
	return pem.EncodeToMemory(pemBlock)
}

func Base642PEM(base64Key string) []byte {
	const pemHeader = "-----BEGIN CERTIFICATE-----\n"
	const pemFooter = "\n-----END CERTIFICATE-----"

	// 创建一个bufio.Writer，用于写入PEM格式的数据
	var pemBuffer bytes.Buffer
	pemWriter := bufio.NewWriter(&pemBuffer)

	// 写入PEM头部
	pemWriter.WriteString(pemHeader)

	// 将Base64字符串按64个字符一组分割并写入
	sc := len(base64Key)
	var keof bool
	for i := 0; i < sc; i += 64 {
		end := i + 64
		if end > sc {
			end = sc
			keof = true
		}
		line := base64Key[i:end]
		pemWriter.WriteString(line)
		if keof {
			break
		}
		pemWriter.WriteString("\n")
	}

	// 写入PEM尾部
	pemWriter.WriteString(pemFooter)

	// 确保所有内容都被写入到底层缓冲区
	pemWriter.Flush()

	// 返回PEM格式的公钥字符串
	//pemBuffer.String()
	return pemBuffer.Bytes()
}
