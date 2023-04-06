package main

import (
	"flag"

	"github.com/lijianying10/web3gateway/pkgs/web3authgw"
)

var configFilePath string

func main() {
	flag.StringVar(&configFilePath, "c", "config.json", "config file")
	flag.Parse()
	cfg := web3authgw.NewConfig(configFilePath)
	rt := web3authgw.NewRuntime(cfg)
	rt.Run()
}
