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

	"github.com/btcsuite/btcd/btcec"
	"github.com/gorilla/mux"
)

var keyFileDirectory = ".minerid"
var keyFileName = "minerid"

func currentDir() string {
	dir, err := os.Getwd()
	if err != nil {
		log.Fatal(err)
	}
	return dir
}

func createKeys() error {
	currDir := currentDir()
	keyFileStub := path.Join(currDir, keyFileDirectory, keyFileName)

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

	_, err = fmt.Fprintf(keyFile, "%x", b)
	if err != nil {
		return err
	}

	pubFile, err := os.Create(keyFileStub + ".pub")
	if err != nil {
		return err
	}

	defer pubFile.Close()

	b = privKey.PubKey().SerializeCompressed()
	_, err = fmt.Fprintf(pubFile, "%x", b)
	if err != nil {
		return err
	}

	return nil
}

func signMessage(message []byte) (sig string, err error) {
	currDir := currentDir()
	keyFileStub := path.Join(currDir, keyFileDirectory, keyFileName)

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
		io.WriteString(w, "ERROR")
		return
	}

	sig, err := signMessage([]byte(hash))
	if err != nil {
		w.WriteHeader(http.StatusServiceUnavailable)
		io.WriteString(w, "ERROR")
		return
	}

	w.WriteHeader(http.StatusOK)
	io.WriteString(w, fmt.Sprintf("%s", sig))
}

func generateHandler(w http.ResponseWriter, r *http.Request) {
	err := createKeys()
	if err != nil {
		w.WriteHeader(http.StatusServiceUnavailable)
		io.WriteString(w, "ERROR")
	} else {
		w.WriteHeader(http.StatusCreated)
		io.WriteString(w, "OK")
	}
}

func getHandler(w http.ResponseWriter, r *http.Request) {
	currDir := currentDir()
	keyFileStub := path.Join(currDir, keyFileDirectory, keyFileName)

	keyBytes, err := ioutil.ReadFile(keyFileStub + ".pub")
	if err != nil {
		w.WriteHeader(http.StatusNotFound)
		io.WriteString(w, "ERROR")
	} else {
		w.WriteHeader(http.StatusOK)
		io.WriteString(w, fmt.Sprintf("%s", keyBytes))
	}
}
func deleteHandler(w http.ResponseWriter, r *http.Request) {
	currDir := currentDir()
	keyFileStub := path.Join(currDir, keyFileDirectory, keyFileName)

	// if pub exists remove it
	if _, err := os.Stat(keyFileStub + ".pub"); err == nil {
		err := os.Remove(keyFileStub + ".pub")
		if err != nil {
			w.WriteHeader(http.StatusServiceUnavailable)
			io.WriteString(w, "ERROR")
		}
	}
	// if key exists remove it
	if _, err := os.Stat(keyFileStub + ".key"); err == nil {
		err = os.Remove(keyFileStub + ".key")
		if err != nil {
			w.WriteHeader(http.StatusServiceUnavailable)
			io.WriteString(w, "ERROR")
		}
	}
	w.WriteHeader(http.StatusOK)
	io.WriteString(w, "OK")
}

func notFound(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusNotFound)
	io.WriteString(w, "BAD")
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

	router.HandleFunc("/key", generateHandler).Methods("POST")
	router.HandleFunc("/key", getHandler).Methods("GET")
	router.HandleFunc("/key", deleteHandler).Methods("DELETE")
	router.HandleFunc("/sign/{hash:[0-9a-fA-F]+}", signHandler).Methods("GET")
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
