package web3authgw

type VerifyRequest struct {
	PublicKey string `json:"publicKey"`
	Sign      string `json:"sign"`
	Nonce     string `json:"nonce"`
	Message   string `json:"message"` // for metamask
	Redirect  string `json:"redirect"`
}
