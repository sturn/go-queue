package kq

import "github.com/zeromicro/go-zero/core/service"

const (
	firstOffset        = "first"
	lastOffset         = "last"
	defaultCompression = 2
	defaultSASL_WAY    = 1
	SASL_SCRAM         = 2
	SASL_PLAIN         = 1
	defaultCA_WAY      = 1
	CA_FILE            = 1
	CA_TEXT            = 2
)

type KqConf struct {
	service.ServiceConf
	Brokers    []string
	Group      string
	Topic      string
	Offset     string `json:",options=first|last,default=last"`
	Conns      int    `json:",default=1"`
	Consumers  int    `json:",default=8"`
	Processors int    `json:",default=8"`
	MinBytes   int    `json:",default=10240"`    // 10K
	MaxBytes   int    `json:",default=10485760"` // 10M
	KqSaslCaConf
}

type KqPusherConf struct {
	Brokers     []string
	Topic       string
	Compression int8 `json:",options=1|2|3|4,default=2"`
	KqSaslCaConf
}

type KqSaslCaConf struct {
	Username    string `json:",optional"`
	Password    string `json:",optional"`
	ForceCommit bool   `json:",default=true"`
	SASL_WAY    int8   `json:",options=1|2,default=1"`
	CA_WAY      int8   `json:",options=1|2,default=1"`
	CaFile      string `json:",optional"`
	CertFile    string `json:",optional"`
	KeyFile     string `json:",optional"`
	CaPEM       string `json:",optional"`
	CertPEM     string `json:",optional"`
	KeyPEM      string `json:",optional"`
}
