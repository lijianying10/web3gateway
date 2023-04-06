package web3authgw

import (
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/golang-jwt/jwt"
	"github.com/google/uuid"

	"github.com/lijianying10/web3gateway/pkgs/misc"
)

type Runtime struct {
	cfg       *Config
	encrypter *misc.EncryptAesRuntime
}

func NewRuntime(cfg *Config) *Runtime {
	enc, err := misc.NewEncryptAesRuntime([]byte(cfg.NoncePassword))
	if err != nil {
		panic(err)
	}
	return &Runtime{
		cfg:       cfg,
		encrypter: enc,
	}
}

type Claims struct {
	Pubkey string `json:"pubkey"`
	jwt.StandardClaims
}

func (rt *Runtime) ping(w http.ResponseWriter, req *http.Request) {
	w.Write([]byte("pong"))
}

type ETHVerifyRequest struct {
	Account string `json:"account,omitempty"`
	Sign    string `json:"sign,omitempty"`
	Message string `json:"message,omitempty"`
}

func (rt *Runtime) metaMaskVerfiy(w http.ResponseWriter, req *http.Request) {
	body, err := io.ReadAll(req.Body)
	defer req.Body.Close()
	if err != nil {
		w.WriteHeader(500)
		w.Write([]byte("error read body"))
		return
	}
	var verifyDat VerifyRequest
	err = json.Unmarshal(body, &verifyDat)
	if err != nil {
		w.WriteHeader(500)
		w.Write([]byte("error decode body"))
		return
	}

	msgStr := strings.TrimPrefix(verifyDat.Message, "0x")
	msg, err := hex.DecodeString(msgStr)
	if err != nil {
		http.Error(w, "invalid message: "+err.Error(), http.StatusBadRequest)
		return
	}

	if !misc.ETHverifySig(verifyDat.PublicKey, verifyDat.Sign, msg) {
		w.WriteHeader(401)
		w.Write([]byte("fail to verify sign"))
		return
	}

	nonceByte, err := hex.DecodeString(strings.TrimPrefix(verifyDat.Message, "0x"))
	if err != nil {
		w.WriteHeader(401)
		w.Write([]byte("forbidden: can not verify sign during decode message reason: " + err.Error()))
		return
	}
	verifyDat.Nonce = string(nonceByte)

	rt.verifySuccessResponse(verifyDat, w)
}

func (rt *Runtime) verifySuccessResponse(verifyDat VerifyRequest, w http.ResponseWriter) {
	lines := strings.Split(verifyDat.Nonce, "\n")

	if len(lines) < 2 {
		w.WriteHeader(401)
		w.Write([]byte("forbidden: can not verify nonce, case 1 : "))
		return
	}
	nonceDecrypted, err := rt.encrypter.Decrypt(lines[1])
	if err != nil {
		w.WriteHeader(401)
		w.Write([]byte("forbidden: can not verify nonce, case 1.1"))
		return
	}
	elems := strings.Split(nonceDecrypted, " ")
	if len(elems) != 2 {
		w.WriteHeader(401)
		w.Write([]byte("forbidden: can not verify nonce, case 2"))
		return
	}
	_, err = uuid.Parse(elems[0])
	if err != nil {
		w.WriteHeader(401)
		w.Write([]byte("forbidden: can not verify nonce, case 3"))
		return
	}
	ts, err := strconv.ParseInt(elems[1], 10, 64)
	if err != nil {
		w.WriteHeader(401)
		w.Write([]byte("forbidden: can not verify nonce, case 4"))
		return
	}

	if time.Now().Unix()-ts > 60*3 {
		w.WriteHeader(401)
		w.Write([]byte("forbidden: can not verify nonce, sign message timeout, please hard refresh page."))
		return
	}

	if _, ok := rt.cfg.PublicKey2Name[verifyDat.PublicKey]; !ok {
		w.WriteHeader(401)
		w.Write([]byte("forbidden: not recoginze public key: " + verifyDat.PublicKey))
		return
	}

	expirationTime := time.Now().Add(5 * 30 * 24 * time.Hour)
	claims := &Claims{
		Pubkey: verifyDat.PublicKey,
		StandardClaims: jwt.StandardClaims{
			ExpiresAt: expirationTime.Unix(),
		},
	}
	// Declare the token with the algorithm used for signing, and the claims
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	// Create the JWT string
	tokenString, err := token.SignedString([]byte(rt.cfg.NoncePassword))
	if err != nil {
		fmt.Println("Jwt gen error: ", err.Error())
		// If there is an error in creating the JWT return an internal server error
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte("jwt token gen error"))
		return
	}
	http.SetCookie(w, &http.Cookie{
		Name:    TokenCookieName,
		Value:   tokenString,
		Expires: expirationTime,
		Path:    "/",
	})

	if verifyDat.Redirect != "" {
		w.WriteHeader(200)
		w.Header().Add("Location", verifyDat.Redirect)
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(fmt.Sprintf(`{"redirect":"%s"}`, verifyDat.Redirect)))
		return
	}
	w.WriteHeader(200)
	w.Write([]byte("login successful"))
	w.Write([]byte("ok"))
}

func (rt *Runtime) web3verify(w http.ResponseWriter, req *http.Request) {
	body, err := io.ReadAll(req.Body)
	defer req.Body.Close()
	if err != nil {
		w.WriteHeader(500)
		w.Write([]byte("error read body"))
		return
	}
	var verifyDat VerifyRequest
	err = json.Unmarshal(body, &verifyDat)
	if err != nil {
		w.WriteHeader(500)
		w.Write([]byte("error decode body"))
		return
	}
	decodedSign, err := hex.DecodeString(verifyDat.Sign)
	if err != nil {
		w.WriteHeader(400)
		w.Write([]byte("bad signature"))
		return
	}
	//if !ed25519.Verify(base58.Decode(verifyDat.PublicKey), []byte(verifyDat.Nonce), decodedSign) {
	if !ed25519.Verify(misc.Base58Decode(verifyDat.PublicKey), []byte(verifyDat.Nonce), decodedSign) {
		w.WriteHeader(401)
		w.Write([]byte("forbidden: can not verify sign"))
		return
	}

	rt.verifySuccessResponse(verifyDat, w)
}

func (rt *Runtime) web3login(w http.ResponseWriter, req *http.Request) {
	nonce := fmt.Sprintf("%s %d", uuid.NewString(), time.Now().Unix())
	encryptedNonce, err := rt.encrypter.Encrypt(nonce)
	if err != nil {
		panic(err) // Program bug
	}
	msg := fmt.Sprintf("Please sign following message to login\n%s", encryptedNonce)

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-cache")
	fmt.Fprintf(w, `
<!DOCTYPE html>
<html>
<head>
</head>
<body>
<h2 id="msg">Please sign message by crypto wallet</h2> </br>
<button id="metamask">login with metamask</button>
<button id="btn_solana">login with solana</button>
</body>
<script
  src="https://code.jquery.com/jquery-3.6.3.min.js"
  integrity="sha256-pvPw+upLPUjgMXY0G+8O0xUf+/Im1MZjXxxgOcBQBXU="
  crossorigin="anonymous"></script>
<script>

var buf2hex = function (buffer) {
  return [...new Uint8Array(buffer)].map((x) => x.toString(16).padStart(2, '0')).join('');
}

function getUrlParameter(name) {
   name = name.replace(/[\[]/, "\\[").replace(/[\]]/, "\\]");
   var regex = new RegExp("[\\?&]" + name + "=([^&#]*)"),
   results = regex.exec(location.search);
   return results === null ? "" : decodeURIComponent(results[1].replace(/\+/g, " "));
}

$("#metamask").click(async function(){
	if (typeof window.ethereum == 'undefined') {
		alert('MetaMask is not installed!');
		return;
	}
	const accounts = await ethereum.request({ method: 'eth_requestAccounts' });
	const account = accounts[0];
	const msg = '%s';
	console.log(msg)
	console.log(account)
    const sign = await ethereum.request({
        method: 'personal_sign',
        params: [msg, account],
    });
	console.log(sign);
	const signedMessage = {};
	signedMessage.sign = sign;
	signedMessage.message = msg;
	signedMessage.publicKey = account;
	signedMessage.redirect = getUrlParameter("redirect");
    $.ajax({
        type: "POST",
        url: '/web3authgw/metamask_verify',
        data: JSON.stringify(signedMessage),
        dataType: "json",
        success: function(data, textStatus) {
            console.log("data")
            if (data.redirect) {
                window.location.href = data.redirect;
            }
        }
    }).done(function( data ) {$("#msg").text(data)})
      .fail(function( data ) {console.log(data);$("#msg").text(data.statusText+" "+data.responseText)});
})

$("#btn_solana").click(async function(){
    await solana.connect();
    const nonce = `+"`"+`%s`+"`"+`;
    const encodedMessage = new TextEncoder().encode(nonce);
    const signedMessage = await solana.signMessage(encodedMessage, 'utf-8');
    signedMessage.nonce = nonce;
    signedMessage.sign = buf2hex(signedMessage.signature);
    signedMessage.redirect = getUrlParameter('redirect');
    console.log(signedMessage);
    $.ajax({
        type: "POST",
        url: '/web3authgw/verify',
        data: JSON.stringify(signedMessage),
        dataType: "json",
        success: function(data, textStatus) {
            console.log("data")
            if (data.redirect) {
                window.location.href = data.redirect;
            }
        }
    }).done(function( data ) {$("#msg").text(data)})
      .fail(function( data ) {console.log(data);$("#msg").text(data.statusText+" "+data.responseText)});
});
</script>
</html>

`, "0x"+hex.EncodeToString([]byte(msg)), msg)
}

func (rt *Runtime) GetNonceMessage() string {
	nonce := fmt.Sprintf("%s %d", uuid.NewString(), time.Now().Unix())
	return fmt.Sprintf("Please sign following nonce message to login\n%s", nonce)
}

func (rt *Runtime) GetMessagePhantom(w http.ResponseWriter, req *http.Request) {
	msg := rt.GetNonceMessage()
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Header().Set("Cache-Control", "no-cache")
	fmt.Fprint(w, msg)
}

func (rt *Runtime) GetMessageMetaMask(w http.ResponseWriter, req *http.Request) {
	msg := rt.GetNonceMessage()
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Header().Set("Cache-Control", "no-cache")
	fmt.Fprint(w, "0x"+hex.EncodeToString([]byte(msg)))
}

func (rt *Runtime) Run() {
	reverseProxy := NewProxyHandler(rt.cfg)
	http.Handle("/", reverseProxy)
	http.Handle("/assets/", http.StripPrefix("/assets", http.FileServer(http.Dir("./assets"))))
	http.HandleFunc("/ping", rt.ping)
	http.HandleFunc(RouterLogin, rt.web3login)
	http.HandleFunc(RouterVerify, rt.web3verify)
	http.HandleFunc(RouterMetaMaskVerify, rt.metaMaskVerfiy)
	http.HandleFunc(RouterGetMessageMetamask, rt.GetMessageMetaMask)
	http.HandleFunc(RouterGetMessagePhantom, rt.GetMessagePhantom)
	fmt.Println("server start")
	http.ListenAndServe(":8000", nil)
}
