package main

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"math/big"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
)

const (
	PROFILE_HTTP uint = 0x25
	PROFILE_SMB  uint = 0x15
)

const (
	TASK_GET    byte = 0
	TASK_RESULT byte = 1

	TASK_QUICK byte = 0x5
	TASK_OUT   byte = 0x7
)

func (handler *HTTP) validate_config_fmt(cfg HTTPConfig) error {
	return nil
}

func copy_method(original *HTTPMethod) *HTTPMethod {
	if original == nil {
		return nil
	}

	copied := &HTTPMethod{
		EmptyResponse: make([]byte, len(original.EmptyResponse)),
	}
	copy(copied.EmptyResponse, original.EmptyResponse)

	copied.ServerHeaders = make(map[string]string)
	for k, v := range original.ServerHeaders {
		copied.ServerHeaders[k] = v
	}

	copied.ClientHeaders = make(map[string]string)
	for k, v := range original.ClientHeaders {
		copied.ClientHeaders[k] = v
	}

	copied.URI = make(map[string]URIConfig)
	for k, v := range original.URI {
		uriConfig := URIConfig{
			ClientParams: make([]map[string]interface{}, len(v.ClientParams)),
		}

		if v.ServerOutput != nil {
			uriConfig.ServerOutput = &OutputConfig{
				Mask:      v.ServerOutput.Mask,
				Format:    v.ServerOutput.Format,
				Parameter: v.ServerOutput.Parameter,
				Header:    v.ServerOutput.Header,
				Body:      v.ServerOutput.Body,
				Prepend:   v.ServerOutput.Prepend,
				Append:    v.ServerOutput.Append,
			}
		}

		if v.ClientOutput != nil {
			uriConfig.ClientOutput = &OutputConfig{
				Mask:      v.ClientOutput.Mask,
				Format:    v.ClientOutput.Format,
				Parameter: v.ClientOutput.Parameter,
				Header:    v.ClientOutput.Header,
				Body:      v.ClientOutput.Body,
				Prepend:   v.ClientOutput.Prepend,
				Append:    v.ClientOutput.Append,
			}
		}

		for i, param := range v.ClientParams {
			uriConfig.ClientParams[i] = make(map[string]interface{})
			for key, value := range param {
				uriConfig.ClientParams[i][key] = value
			}
		}

		copied.URI[k] = uriConfig
	}

	return copied
}

func (handler *HTTP) get_uri_config(path string, http_method *HTTPMethod) *URIConfig {
	if http_method == nil {
		return nil
	}

	fmt.Printf("[INFO] Request with HTTP method\n")

	for each_uri, each_config := range http_method.URI {
		fmt.Printf("[DEBUG] Looped uri: %s\n", each_uri)

		if each_uri == path {
			return &each_config
		}
	}

	return nil
}

func (handler *HTTP) get_all_hosts() []string {
	var hosts []string
	for _, cb := range handler.Config.Callbacks {
		hosts = append(hosts, cb.Hosts...)
	}
	return hosts
}

func (handler *HTTP) get_all_uris(method *HTTPMethod) []string {
	var uris []string
	if method != nil {
		for uri := range method.URI {
			uris = append(uris, uri)
		}
	}
	return uris
}

func (handler *HTTP) get_callback_by_host(host string) *Callback {
	if host == "" {
		return nil
	}

	fmt.Printf("[DEBUG] Looking for callback with address: %s\n", host)
	fmt.Printf("[DEBUG] Total callbacks available: %d\n", len(handler.Config.Callbacks))

	for i := range handler.Config.Callbacks {
		callback := handler.Config.Callbacks[i]
		fmt.Printf("[DEBUG] Checking callback %d with %d hosts\n", i, len(callback.Hosts))

		for j, callbackHost := range callback.Hosts {
			fmt.Printf("[DEBUG][%d][%d] Comparing: '%s' == '%s'? %v\n",
				i, j, callbackHost, host, strings.EqualFold(callbackHost, host))

			if strings.EqualFold(callbackHost, host) {
				fmt.Printf("[SUCCESS] Found callback at index %d for host: %s\n", i, host)
				return &callback
			}
		}
	}

	fmt.Printf("[WARNING] No callback found for address: %s\n", host)
	return nil
}

func (handler *HTTP) gen_self_signed_cert(certFile, keyFile string) error {
	var (
		certData   []byte
		keyData    []byte
		certBuffer bytes.Buffer
		keyBuffer  bytes.Buffer
		privateKey *rsa.PrivateKey
		err        error
	)

	privateKey, err = rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return fmt.Errorf("failed to generate private key: %v", err)
	}

	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		return fmt.Errorf("failed to generate serial number: %v", err)
	}

	template := x509.Certificate{
		SerialNumber: serialNumber,
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(365 * 24 * time.Hour),

		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}

	template.DNSNames = []string{handler.Config.HostBind}

	certData, err = x509.CreateCertificate(rand.Reader, &template, &template, &privateKey.PublicKey, privateKey)
	if err != nil {
		return fmt.Errorf("failed to create certificate: %v", err)
	}

	err = pem.Encode(&certBuffer, &pem.Block{Type: "CERTIFICATE", Bytes: certData})
	if err != nil {
		return fmt.Errorf("failed to write certificate: %v", err)
	}

	handler.Config.SslCert = certBuffer.Bytes()
	err = os.WriteFile(certFile, handler.Config.SslCert, 0644)
	if err != nil {
		return fmt.Errorf("failed to create certificate file: %v", err)
	}

	keyData = x509.MarshalPKCS1PrivateKey(privateKey)
	err = pem.Encode(&keyBuffer, &pem.Block{Type: "RSA PRIVATE KEY", Bytes: keyData})
	if err != nil {
		return fmt.Errorf("failed to write private key: %v", err)
	}

	handler.Config.SslKey = keyBuffer.Bytes()
	err = os.WriteFile(keyFile, handler.Config.SslKey, 0644)
	if err != nil {
		return fmt.Errorf("failed to create key file: %v", err)
	}

	return nil
}

func (handler *HTTP) validate_url_pattern(input string) bool {
	if input == "" {
		return true
	}

	parsedUrl, err := url.Parse(input)
	if err != nil {
		return false
	}

	if parsedUrl.Host == "" {
		return false
	}

	if strings.Contains(parsedUrl.Host, ":") {
		parts := strings.Split(parsedUrl.Host, ":")

		if len(parts) != 2 {
			return false
		}

		portStr := parts[1]
		port, err := strconv.Atoi(portStr)

		if err != nil {
			return false
		}

		if port < 1 || port > 65535 {
			return false
		}
	}

	return true
}

func (handler *HTTP) apply_server_headers(ctx *gin.Context, method *HTTPMethod) {
	if method == nil {
		return
	}

	if method.ServerHeaders != nil && len(method.ServerHeaders) > 0 {
		for key, value := range method.ServerHeaders {
			ctx.Header(key, value)
		}
	}
}

func formatHexDump(data []byte, bytesPerLine int) string {
	var result strings.Builder
	var ascii strings.Builder

	for i := 0; i < len(data); i += bytesPerLine {
		// Endereço hexadecimal
		result.WriteString(fmt.Sprintf("%08x  ", i))

		// Bytes hexadecimais
		for j := 0; j < bytesPerLine; j++ {
			if i+j < len(data) {
				result.WriteString(fmt.Sprintf("%02x ", data[i+j]))
			} else {
				result.WriteString("   ")
			}

			// Adicionar espaço extra no meio da linha
			if j == bytesPerLine/2-1 {
				result.WriteString(" ")
			}
		}

		result.WriteString(" ")

		// Caracteres ASCII
		ascii.Reset()
		for j := 0; j < bytesPerLine; j++ {
			if i+j < len(data) {
				b := data[i+j]
				if b >= 32 && b <= 126 {
					ascii.WriteByte(b)
				} else {
					ascii.WriteByte('.')
				}
			}
		}

		result.WriteString("|")
		result.WriteString(ascii.String())
		result.WriteString("|\n")
	}

	return result.String()
}

func (handler *HTTP) get_callback_by_uri(uri string, method string) (*Callback, *URIConfig, *HTTPMethod) {
	fmt.Printf("[DEBUG] Searching for callback with URI: %s, Method: %s\n", uri, method)

	for _, callback := range handler.Config.Callbacks {
		var http_method *HTTPMethod

		switch method {
		case "GET":
			http_method = callback.Get
		case "POST":
			http_method = callback.Post
		default:
			continue
		}

		if http_method == nil {
			fmt.Printf("[DEBUG] Callback has no %s method\n", method)
			continue
		}

		if uri_config, exists := http_method.URI[uri]; exists {
			fmt.Printf("[DEBUG] Found matching URI in callback\n")
			return &callback, &uri_config, http_method
		}
	}

	fmt.Printf("[DEBUG] No matching URI found in any callback\n")
	return nil, nil, nil
}

func (handler *HTTP) get_all_endpoints() map[string][]string {
	endpoints := make(map[string][]string)

	for i, callback := range handler.Config.Callbacks {
		callback_key := fmt.Sprintf("Callback[%d](%s)", i, callback.Hosts[0])

		if callback.Get != nil {
			for uri := range callback.Get.URI {
				endpoints[callback_key] = append(endpoints[callback_key], fmt.Sprintf("GET %s", uri))
			}
		}

		if callback.Post != nil {
			for uri := range callback.Post.URI {
				endpoints[callback_key] = append(endpoints[callback_key], fmt.Sprintf("POST %s", uri))
			}
		}
	}

	return endpoints
}

func Xor(bin []byte, key []byte) {
	if len(key) == 0 || len(bin) == 0 {
		return
	}

	j := 0
	for i := 0; i < len(bin); i++ {
		if j == len(key) {
			j = 0
		}

		bin[i] = bin[i] ^ key[j]

		j++
	}
}
