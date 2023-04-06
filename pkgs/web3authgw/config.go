package web3authgw

import (
	"encoding/json"
	"os"
)

type Config struct {
	NoncePassword  string            `json:"nonce_password"`
	HostMapping    map[string]string `json:"host_mapping"`
	PublicKey2Name map[string]string `json:"public_key_2_name"`
}

func NewConfig(path string) *Config {
	body, err := os.ReadFile(path)
	if err != nil {
		panic(err)
	}
	var cfg Config
	json.Unmarshal(body, &cfg)
	return &cfg
}
