package crypthash

import (
	"crypto/tls"
	"database/sql"
	"encoding/json"
	"fmt"
	"math/rand"
	"net/http"
	"time"

	"github.com/gorilla/mux"
)

type (
	Codex struct {
		Key    []int
		Hasher []int
	}
	IpCoder struct {
		Ip string
		Codex
	}
)

var (
	messageSize    = 0
	codexTransfert = make(chan *IpCoder)
	randomizer     = rand.New(rand.NewSource(time.Now().UnixNano()))
)

func MakeAuthServer(db *sql.DB, addr string, port string, sizer int) *http.Server {
	messageSize = sizer
	router := mux.NewRouter()
	router.HandleFunc("/Auth", authHandler)
	cfg := &tls.Config{
		MinVersion:               tls.VersionTLS12,
		CurvePreferences:         []tls.CurveID{tls.CurveP521, tls.CurveP384, tls.CurveP256},
		PreferServerCipherSuites: true,
		CipherSuites: []uint16{
			tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
			tls.TLS_RSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_RSA_WITH_AES_256_CBC_SHA,
		},
	}
	listener := &http.Server{
		Addr:         addr + ":" + port,
		Handler:      router,
		TLSConfig:    cfg,
		TLSNextProto: make(map[string]func(*http.Server, *tls.Conn, http.Handler), 0),
	}
	return listener
}

func authHandler(w http.ResponseWriter, r *http.Request) {
	// clientPort := r.Host
	clientIp := r.RemoteAddr
	codex := KeyGen(messageSize)
	codexTransfert <- &IpCoder{Ip: clientIp, Codex: codex}
	toClient, err := json.Marshal(codex)
	if err != nil {
		fmt.Println(err)
	}
	w.Header().Add("Strict-Transport-Security", "max-age=63072000; includeSubDomains")
	w.Write(toClient)
}

func SurveNewIpCodex() *IpCoder {
	return <-codexTransfert
}

// retourne un encodage pour un message de taille length
func KeyGen(length int) Codex {
	if length < 20 {
		return Codex{}
	}
	var key []int
	for i := 0; i < length; i++ {
		key = append(key, randomizer.Intn(20))
	}
	cutLength := randomizer.Intn(length/10) + 5
	numberCut := length / cutLength
	if length%cutLength != 0 {
		numberCut++
	}
	var baseOrder []int
	for i := 0; i < numberCut; i++ {
		baseOrder = append(baseOrder, i)
	}
	var hasher []int
	for i := 0; i < numberCut; i++ {
		rand := randomizer.Intn(len(baseOrder))
		hasher = append(hasher, baseOrder[rand])
		baseOrder = append(baseOrder[:rand], baseOrder[rand+1:]...)
	}
	return Codex{Key: key, Hasher: hasher}
}

func Encrypt(message []byte, codex Codex) []byte {
	var crypt []byte
	for i, b := range message {
		crypt = append(crypt, byte(int(b)+codex.Key[i]))
	}
	cutLength := len(codex.Key) / len(codex.Hasher)
	if len(codex.Key)%len(codex.Hasher) != 0 {
		cutLength++
	}
	cutNumber := len(crypt) / cutLength
	if len(crypt)%cutLength != 0 {
		cutNumber++
	}
	var hashCrypt []byte
	for _, i := range codex.Hasher {
		if i < cutNumber {
			startPosition := i * cutLength
			endPosition := (i + 1) * cutLength
			var arr []byte
			if endPosition > len(crypt) {
				arr = crypt[startPosition:]
			} else {
				arr = crypt[startPosition:endPosition]
			}
			hashCrypt = append(hashCrypt, arr...)
		}
	}
	return hashCrypt
}

func Decrypt(crypt []byte, codex Codex) []byte {
	cutLength := len(codex.Key) / len(codex.Hasher)
	if len(codex.Key)%len(codex.Hasher) != 0 {
		cutLength++
	}
	cutNumber := len(crypt) / cutLength
	if len(crypt)%cutLength != 0 {
		cutNumber++
	}
	diferenceDeLength := 0
	if cutLength > len(crypt) {
		diferenceDeLength = cutLength - len(crypt)
	} else if len(crypt)%cutLength != 0 {
		diferenceDeLength = cutLength - (len(crypt) % cutLength)
	}
	var dehashedCrypt []byte
	for i := 0; i < cutNumber; i++ {
		ref := -1
		reduce := false
		for _, hashPos := range codex.Hasher {
			if hashPos <= cutNumber-1 {
				ref += 1
			}
			if hashPos == i {
				break
			}
			if hashPos == cutNumber-1 && diferenceDeLength != 0 {
				reduce = true
			}
		}
		startPosition := ref * cutLength
		endPosition := startPosition + cutLength
		if reduce {
			startPosition -= diferenceDeLength
			endPosition -= diferenceDeLength
		}
		if i == cutNumber-1 {
			endPosition -= diferenceDeLength
		}
		var arr []byte
		if endPosition > len(crypt) {
			arr = crypt[startPosition:]
		} else {
			arr = crypt[startPosition:endPosition]
		}
		dehashedCrypt = append(dehashedCrypt, arr...)
	}
	var message []byte
	for i, b := range dehashedCrypt {
		message = append(message, byte(int(b)-codex.Key[i]))
	}
	return message
}

func GenRandomString(length int, minParticle int, maxParticle int) string {
	str := ""
	ensemble := maxParticle - minParticle
	if ensemble < 2 {
		return ""
	}
	for i := 0; i < length; i++ {
		rand := randomizer.Intn(ensemble) + minParticle
		str = str + string(rune(rand))
	}
	return str
}
