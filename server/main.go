package main

import (
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"path"
	"runtime"

	"github.com/btcsuite/btcd/btcec"
	"github.com/gorilla/mux"
)

func userHomeDir() string {
	if runtime.GOOS == "windows" {
		home := os.Getenv("HOMEDRIVE") + os.Getenv("HOMEPATH")
		if home == "" {
			home = os.Getenv("USERPROFILE")
		}
		return home
	}
	return os.Getenv("HOME")
}

func createKeys() error {
	homeDir := userHomeDir()
	keyFileStub := path.Join(homeDir, ".minerid", "minerid")

	privKey, err := btcec.NewPrivateKey(btcec.S256())
	if err != nil {
		return err
	}

	dir, _ := path.Split(keyFileStub)
	_ = os.MkdirAll(dir, 0700)

	keyFilename := keyFileStub + ".key"

	if _, err := os.Stat(keyFilename); err == nil {
		// File exists
		err = fmt.Errorf("File %q already exists", keyFilename)
		return err
	}

	keyFile, err := os.Create(keyFileStub + ".key")
	if err != nil {
		return err
	}

	defer keyFile.Close()

	b := privKey.Serialize()

	_, err = fmt.Fprintf(keyFile, "%x\n", b)
	if err != nil {
		return err
	}

	pubFile, err := os.Create(keyFileStub + ".pub")
	if err != nil {
		return err
	}

	defer pubFile.Close()

	b = privKey.PubKey().SerializeCompressed()
	_, err = fmt.Fprintf(pubFile, "%x\n", b)
	if err != nil {
		return err
	}

	return nil
}

func signMessage(message []byte) (sig string, err error) {
	homeDir := userHomeDir()
	keyFileStub := path.Join(homeDir, ".minerid", "minerid")

	// Keys
	keyBytes, err := ioutil.ReadFile(keyFileStub + ".key")
	if err != nil {
		log.Printf("Error reading key file [%v]", err)
		return
	}

	// Remove trailing CR...
	if keyBytes[len(keyBytes)-1] == 0x0a {
		keyBytes = keyBytes[:len(keyBytes)-1]
	}
	// Convert it to hex...
	keyBytes, err = hex.DecodeString(string(keyBytes))
	if err != nil {
		log.Printf("Error decoding keyBytes [%v]", err)
		return
	}

	// Reconstruct the PrivKey...
	privKey, _ := btcec.PrivKeyFromBytes(btcec.S256(), keyBytes)

	messageHash := sha256.Sum256(message)
	s, err := privKey.Sign(messageHash[:])

	if err != nil {
		return
	}

	sig = hex.EncodeToString(s.Serialize())
	return
}

func signHandler(w http.ResponseWriter, r *http.Request) {
	hash := mux.Vars(r)["hash"]
	if hash == "" {
		w.WriteHeader(http.StatusBadRequest)
		io.WriteString(w, "ERROR\n")
		return
	}

	sig, err := signMessage([]byte(hash))
	if err != nil {
		w.WriteHeader(http.StatusServiceUnavailable)
		io.WriteString(w, "ERROR\n")
		return
	}

	w.WriteHeader(http.StatusOK)
	io.WriteString(w, fmt.Sprintf("%s\n", sig))
}

func generateHandler(w http.ResponseWriter, r *http.Request) {
	err := createKeys()
	if err != nil {
		w.WriteHeader(http.StatusServiceUnavailable)
		io.WriteString(w, "ERROR\n")
	} else {
		w.WriteHeader(http.StatusOK)
		io.WriteString(w, "OK\n")
	}
}

func getHandler(w http.ResponseWriter, r *http.Request) {
	homeDir := userHomeDir()
	keyFileStub := path.Join(homeDir, ".minerid", "minerid")

	keyBytes, err := ioutil.ReadFile(keyFileStub + ".pub")
	if err != nil {
		w.WriteHeader(http.StatusServiceUnavailable)
		io.WriteString(w, "ERROR\n")
	} else {
		w.WriteHeader(http.StatusOK)
		io.WriteString(w, fmt.Sprintf("%s\n", keyBytes))
	}
}

func notFound(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusBadRequest)
	io.WriteString(w, "BAD\n")
}

func main() {
	useCerts := flag.Bool("certs", true, "use certificates")
	port := flag.Int("port", 8443, "port")
	flag.Parse()
	// Create a CA certificate pool and add ca.crt to it
	caCert, err := ioutil.ReadFile("ca.crt")
	if err != nil {
		log.Fatal(err)
	}
	caCertPool := x509.NewCertPool()
	caCertPool.AppendCertsFromPEM(caCert)

	// Create the TLS Config with the CA pool and enable Client certificate validation
	tlsConfig := &tls.Config{
		ClientCAs:  caCertPool,
		ClientAuth: tls.RequireAndVerifyClientCert,
	}
	tlsConfig.BuildNameToCertificate()

	router := mux.NewRouter().StrictSlash(true)

	router.HandleFunc("/generate", generateHandler).Methods("GET")
	router.HandleFunc("/{hash:[0-9a-fA-F]+}", signHandler).Methods("GET")
	router.HandleFunc("/", getHandler).Methods("GET")
	router.NotFoundHandler = http.HandlerFunc(notFound)

	// Create a Server instance to listen on port 8443 with the TLS config
	server := &http.Server{
		Addr:      fmt.Sprintf("localhost:%d", *port),
		TLSConfig: tlsConfig,
		Handler:   router,
	}
	if !*useCerts {
		server.TLSConfig = nil
		// Listen to HTTPS connections with the server certificate and wait
		log.Fatal(server.ListenAndServe())
	}
	// Listen to HTTPS connections with the server certificate and wait
	log.Fatal(server.ListenAndServeTLS("ca.crt", "./authority/ca.key"))
}
