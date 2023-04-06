package web3authgw

import (
	"encoding/hex"
	"testing"
)

func TestMetaMask(t *testing.T) {
	_, err := hex.DecodeString("0x4824d3775c641eaec67965561e06dce5954ac10aeebae62924467d85fe82e54c6867a3f1376a1bb6ad2fddbbc88d952851f943f4efc4a74f62bc24e54ca0103b1c")
	if err != nil {
		t.Error(err)
	}
}
