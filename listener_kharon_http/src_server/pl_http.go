package main

import (
	"bytes"
	"crypto/rand"
	"encoding/base32"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	// "strconv"
	// "net/url"
	"net/http"
	"os"
	"strings"
	"time"
	"io"

	"github.com/gin-gonic/gin"
	"golang.org/x/net/context"
)

// convert_hex_escapes converts \xHH sequences to real bytes
func convert_hex_escapes(input string) []byte {
	var result []byte
	i := 0

	for i < len(input) {
		if i < len(input)-3 && input[i] == '\\' && input[i+1] == 'x' {
			// Try to convert \xHH
			hexStr := input[i+2 : i+4]
			if is_valid_hex(hexStr) {
				// Convert hex to byte
				byteVal, err := hex.DecodeString(hexStr)
				if err == nil {
					result = append(result, byteVal...)
					i += 4
					continue
				}
			}
		}
		// If not valid \xHH, add the character as is
		result = append(result, input[i])
		i++
	}

	return result
}

// checks if the string contains only valid hexadecimal characters
func is_valid_hex(s string) bool {
	if len(s) != 2 {
		return false
	}
	for _, c := range s {
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')) {
			return false
		}
	}
	return true
}

// checks if the string contains \xHH sequences
func contains_hex_escapes(input string) bool {
	for i := 0; i < len(input)-3; i++ {
		if input[i] == '\\' && input[i+1] == 'x' && is_valid_hex(input[i+2:i+4]) {
			return true
		}
	}
	return false
}

func (handler *HTTP) parse_json_callback(profileContent string) []Callback {
	var jsonData map[string]interface{}
	json.Unmarshal([]byte(profileContent), &jsonData)

	callbacksRaw := jsonData["callbacks"].([]interface{})
	var callbacks []Callback
	var addresses []string

	for _, callbackItem := range callbacksRaw {
		callbackMap := callbackItem.(map[string]interface{})

		userAgent := callbackMap["user_agent"].(string)

		var serverError *ServerError
		if seRaw, ok := callbackMap["server_error"].(map[string]interface{}); ok {
			response := ""
			if resp, ok := seRaw["response"].(string); ok {
				response = resp
			}

			fmt.Printf("[DEBUG] Error response: %s [%d]\n", response, int(seRaw["http_status"].(float64)))

			headers := make(map[string]string)
			if headersRaw, ok := seRaw["headers"].(map[string]interface{}); ok {
				for key, value := range headersRaw {
					if strValue, ok := value.(string); ok {
						headers[key] = strValue
					}
				}
			}

			serverError = &ServerError{
				Status:   int(seRaw["http_status"].(float64)),
				Response: response,
				Headers:  headers,
			}
		}

		var getMethod *HTTPMethod
		if getRaw, ok := callbackMap["get"].(map[string]interface{}); ok {
			getMethod = parse_http_method(getRaw)
		}

		var postMethod *HTTPMethod
		if postRaw, ok := callbackMap["post"].(map[string]interface{}); ok {
			postMethod = parse_http_method(postRaw)
		}

		hostsRaw := callbackMap["hosts"].([]interface{})
		var hosts []string
		for _, host := range hostsRaw {
			hosts = append(hosts, host.(string))
		}

		for _, host := range hosts {
			addresses = append(addresses, host)

			newCallback := Callback{
				Hosts:     []string{host},
				UserAgent: userAgent,
				SrvError:  serverError,
				Get:       getMethod,
				Post:      postMethod,
			}

			callbacks = append(callbacks, newCallback)

			// Print callback configuration
			print_callback_config(len(callbacks)-1, newCallback)
		}
	}

	handler.Config.Addresses = strings.Join(addresses, ",")

	return callbacks
}

func parse_http_method(methodData map[string]interface{}) *HTTPMethod {
	// Parse server headers
	serverHeaders := make(map[string]string)
	if shRaw, ok := methodData["server_headers"].(map[string]interface{}); ok {
		for key, value := range shRaw {
			serverHeaders[key] = value.(string)
		}
	}

	// Parse client headers
	clientHeaders := make(map[string]string)
	if chRaw, ok := methodData["client_headers"].(map[string]interface{}); ok {
		for key, value := range chRaw {
			clientHeaders[key] = value.(string)
		}
	}

	// Parse empty response
	var emptyResponse []byte
	if erRaw, ok := methodData["empty_response"].(string); ok {
		if contains_hex_escapes(erRaw) {
			fmt.Printf("[DEBUG] empty_response contains \\xHH sequences\n")
			emptyResponse = convert_hex_escapes(erRaw)
			fmt.Printf("[DEBUG] empty_response converted to bytes: %v\n", emptyResponse)
		} else {
			emptyResponse = []byte(erRaw)
		}
	}

	uriConfigs := make(map[string]URIConfig)
	if uriRaw, ok := methodData["uri"].(map[string]interface{}); ok {
		for uriKey, uriData := range uriRaw {
			uriMap := uriData.(map[string]interface{})

			// Split routes BEFORE parsing configs
			routes := strings.FieldsFunc(uriKey, func(r rune) bool {
				return r == ' '
			})

			// For each route, create ONE INDEPENDENT copy of the configuration
			for _, route := range routes {
				route = strings.TrimSpace(route)
				if route == "" {
					continue
				}

				// IMPORTANT: Parse AGAIN for each route (don't reuse)
				serverOutput := parse_output_config(uriMap["server_output"])
				clientOutput := parse_output_config(uriMap["client_output"])

				var clientParams []map[string]interface{}
				if cpRaw, ok := uriMap["client_parameters"].([]interface{}); ok {
					for _, cp := range cpRaw {
						// Make deep copy of parameters
						paramCopy := make(map[string]interface{})
						paramMap := cp.(map[string]interface{})
						for k, v := range paramMap {
							paramCopy[k] = v
						}
						clientParams = append(clientParams, paramCopy)
					}
				}

				uriConfigs[route] = URIConfig{
					ServerOutput: serverOutput,
					ClientOutput: clientOutput,
					ClientParams: clientParams,
				}
			}
		}
	}

	return &HTTPMethod{
		ServerHeaders: serverHeaders,
		ClientHeaders: clientHeaders,
		EmptyResponse: emptyResponse,
		URI:           uriConfigs,
	}
}

func parse_output_config(outputData interface{}) *OutputConfig {
	if outputData == nil {
		return nil
	}

	outputMap := outputData.(map[string]interface{})
	output := &OutputConfig{}

	// Parse body
	if body, ok := outputMap["body"].(string); ok {
		if contains_hex_escapes(body) {
			fmt.Printf("[DEBUG] body contains \\xHH sequences, converting...\n")
			bodyBytes := convert_hex_escapes(body)
			output.Body = string(bodyBytes)
			fmt.Printf("[DEBUG] body converted to bytes: %v\n", bodyBytes)
		} else {
			output.Body = body
		}
	}

	// Parse mask
	if mask, ok := outputMap["mask"].(bool); ok {
		output.Mask = mask
	}

	// Parse header
	if header, ok := outputMap["header"].(string); ok {
		if contains_hex_escapes(header) {
			fmt.Printf("[DEBUG] header name contains \\xHH sequences: %s\n", header)
			headerBytes := convert_hex_escapes(header)
			fmt.Printf("[DEBUG] header converted to bytes: %v\n", headerBytes)
		}
		fmt.Printf("[DEBUG] header name: %s\n", header)
		output.Header = header
	}

	// Parse format
	if format, ok := outputMap["format"].(string); ok {
		if contains_hex_escapes(format) {
			fmt.Printf("[DEBUG] format contains \\xHH sequences: %s\n", format)
			formatBytes := convert_hex_escapes(format)
			fmt.Printf("[DEBUG] format converted to bytes: %v\n", formatBytes)
		}
		output.Format = format
	}

	// Parse parameter
	if parameter, ok := outputMap["parameter"].(string); ok {
		if contains_hex_escapes(parameter) {
			fmt.Printf("[DEBUG] parameter contains \\xHH sequences: %s\n", parameter)
			paramBytes := convert_hex_escapes(parameter)
			fmt.Printf("[DEBUG] parameter converted to bytes: %v\n", paramBytes)
		}
		output.Parameter = parameter
	}

	// Parse cookie
	if cookie, ok := outputMap["cookie"].(string); ok {
		if contains_hex_escapes(cookie) {
			fmt.Printf("[DEBUG] cookie contains \\xHH sequences: %s\n", cookie)
			cookieBytes := convert_hex_escapes(cookie)
			fmt.Printf("[DEBUG] cookie converted to bytes: %v\n", cookieBytes)
		}
		fmt.Printf("[DEBUG] cookie name: %s\n", cookie)
		output.Cookie = cookie
	}

	// Parse append
	if appendVal, ok := outputMap["append"].(string); ok {
		if contains_hex_escapes(appendVal) {
			fmt.Printf("[DEBUG] append contains \\xHH sequences\n")
			appendBytes := convert_hex_escapes(appendVal)
			output.Append = string(appendBytes)
			fmt.Printf("[DEBUG] append converted to bytes: %v\n", appendBytes)
		} else {
			output.Append = appendVal
		}
	}

	// Parse prepend
	if prependVal, ok := outputMap["prepend"].(string); ok {
		if contains_hex_escapes(prependVal) {
			fmt.Printf("[DEBUG] prepend contains \\xHH sequences\n")
			prependBytes := convert_hex_escapes(prependVal)
			output.Prepend = string(prependBytes)
			fmt.Printf("[DEBUG] prepend converted to bytes: %v\n", prependBytes)
		} else {
			output.Prepend = prependVal
		}
	}

	return output
}

func print_callback_config(index int, cb Callback) {
	fmt.Println("========================================")
	fmt.Printf("Callback #%d Configuration\n", index+1)
	fmt.Println("========================================")

	fmt.Println("\n[Hosts]")
	for i, host := range cb.Hosts {
		fmt.Printf("  Host %d: %s\n", i+1, host)
	}

	fmt.Printf("\n[User Agent]\n  %s\n", cb.UserAgent)

	if cb.SrvError != nil {
		fmt.Println("\n[Server Error]")
		fmt.Printf("  Status Code: %d\n", cb.SrvError.Status)
		fmt.Printf("  Response: %s\n", cb.SrvError.Response)
	}

	if cb.Get != nil {
		fmt.Println("\n[GET Method]")
		print_http_method_config(cb.Get)
	}

	if cb.Post != nil {
		fmt.Println("\n[POST Method]")
		print_http_method_config(cb.Post)
	}

	fmt.Println("========================================\n")
}

func print_http_method_config(method *HTTPMethod) {
	fmt.Println("  Server Headers:")
	for key, value := range method.ServerHeaders {
		fmt.Printf("    %s: %s\n", key, value)
	}

	fmt.Println("  Client Headers:")
	for key, value := range method.ClientHeaders {
		fmt.Printf("    %s: %s\n", key, value)
	}

	fmt.Printf("  Empty Response: %s\n", string(method.EmptyResponse))

	fmt.Println("  URI Configurations:")
	for uriPath, uriConfig := range method.URI {
		fmt.Printf("    Path: %s\n", uriPath)

		if uriConfig.ServerOutput != nil {
			fmt.Println("      Server Output:")
			print_output_config(uriConfig.ServerOutput, 8)
		}

		if uriConfig.ClientOutput != nil {
			fmt.Println("      Client Output:")
			print_output_config(uriConfig.ClientOutput, 8)
		}

		if len(uriConfig.ClientParams) > 0 {
			fmt.Println("      Client Parameters:")
			for j, param := range uriConfig.ClientParams {
				fmt.Printf("        Param %d:\n", j+1)
				for pkey, pval := range param {
					fmt.Printf("          %s: %v\n", pkey, pval)
				}
			}
		}
	}
}

func print_output_config(output *OutputConfig, indent int) {
	indentStr := strings.Repeat(" ", indent)

	fmt.Printf("%sMask: %v\n", indentStr, output.Mask)
	fmt.Printf("%sFormat: %s\n", indentStr, output.Format)
	fmt.Printf("%sHeader: %s\n", indentStr, output.Header)
	fmt.Printf("%sParameter: %s\n", indentStr, output.Parameter)
	fmt.Printf("%sCookie: %s\n", indentStr, output.Cookie)
	fmt.Printf("%sBody: %s\n", indentStr, output.Body)
	fmt.Printf("%sPrepend: %s\n", indentStr, output.Prepend)
	fmt.Printf("%sAppend: %s\n", indentStr, output.Append)
}

func (handler *HTTP) Start(ts Teamserver) error {
	var err error = nil

	cfg := handler.Config

	if cfg.ProfileContent == "" {
		return fmt.Errorf("profile content is empty - cannot parse callback configuration")
	}

	fileContent, err := base64.StdEncoding.DecodeString( cfg.ProfileContent )
	fmt.Printf("callback file content %s\nlength: %d bytes\n", fileContent, len(fileContent))

	handler.Config.Callbacks = handler.parse_json_callback( string( fileContent ) )
	
	fmt.Printf("[DEBUG] Parsed %d callbacks\n", len(handler.Config.Callbacks))

	err = handler.validate_config_fmt(handler.Config) 
	if err != nil {
		return err
	}

	gin.SetMode(gin.ReleaseMode)
	router := gin.New()

	router.GET( "/*endpoint", handler.process_request)
	router.POST("/*endpoint", handler.process_request)

	handler.Active = true

	handler.Server = &http.Server{
		Addr:    fmt.Sprintf("%s:%d", handler.Config.HostBind, handler.Config.PortBind),
		Handler: router,
	}

	if handler.Config.Ssl {
		fmt.Printf("   Started listener: https://%s:%d\n", handler.Config.HostBind, handler.Config.PortBind)

		listenerPath := ListenerDataDir + "/" + handler.Name
		_, err = os.Stat(listenerPath)
		if os.IsNotExist(err) {
			err = os.Mkdir(listenerPath, os.ModePerm)
			if err != nil {
				return fmt.Errorf("failed to create %s folder: %s", listenerPath, err.Error())
			}
		}

		handler.Config.SslCertPath = listenerPath + "/listener.crt"
		handler.Config.SslKeyPath = listenerPath + "/listener.key"

		if len(handler.Config.SslCert) == 0 || len(handler.Config.SslKey) == 0 {
			err = handler.gen_self_signed_cert(handler.Config.SslCertPath, handler.Config.SslKeyPath)
			if err != nil {
				handler.Active = false
				fmt.Println("Error generating self-signed certificate:", err)
				return err
			}
		} else {
			err = os.WriteFile(handler.Config.SslCertPath, handler.Config.SslCert, 0600)
			if err != nil {
				return err
			}
			err = os.WriteFile(handler.Config.SslKeyPath, handler.Config.SslKey, 0600)
			if err != nil {
				return err
			}
		}

		go func() {
			err = handler.Server.ListenAndServeTLS(handler.Config.SslCertPath, handler.Config.SslKeyPath)
			if err != nil && !errors.Is(err, http.ErrServerClosed) {
				fmt.Printf("Error starting HTTPS server: %v\n", err)
				return
			}
			handler.Active = true
		}()

	} else {
		fmt.Printf("   Started listener: http://%s:%d\n", handler.Config.HostBind, handler.Config.PortBind)

		go func() {
			err := handler.Server.ListenAndServe()
			if err != nil && !errors.Is(err, http.ErrServerClosed) {
				fmt.Printf("Error starting HTTP server: %v\n", err)
				return
			}
			handler.Active = true
		}()
	}

	time.Sleep(500 * time.Millisecond)
	return err
}

func (handler *HTTP) Stop() error {
	var (
		ctx          context.Context
		cancel       context.CancelFunc
		err          error = nil
		listenerPath       = ListenerDataDir + "/" + handler.Name
	)

	ctx, cancel = context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	_, err = os.Stat(listenerPath)
	if err == nil {
		err = os.RemoveAll(listenerPath)
		if err != nil {
			return fmt.Errorf("failed to remove %s folder: %s", listenerPath, err.Error())
		}
	}

	err = handler.Server.Shutdown(ctx)
	return err
}

func (handler *HTTP) process_request(ctx *gin.Context) {
	var (
		err            error
		agentType      string
		oldID          []byte
		oldAgentID     string
		agentExist     bool

		agentData      []byte
		responseData   []byte

		key       []byte
		crypt     *LokyCrypt
		encrypted []byte

		server ServerRequest
		client ClientRequest

		callbackByHost *Callback
		callback       *Callback
		serverOutput   *OutputConfig
		clientOutput   *OutputConfig
		uriConfig      *URIConfig
		httpMethod     *HTTPMethod
		srvError       *ServerError
	)

	client.Uri        = ctx.Request.URL.Path
	client.HttpMethod = ctx.Request.Method
	client.Address    = ctx.Request.Host
	client.UserAgent  = ctx.GetHeader("User-Agent")
	client.Params     = ctx.Request.URL.Query()

	fmt.Printf("[DEBUG] Incoming request - URI: %s, Method: %s, UA: %s\n", client.Uri, client.HttpMethod, client.UserAgent)

	callbackByHost = handler.get_callback_by_host(client.Address)
	if callbackByHost == nil {
		fmt.Printf("[ERROR] No callback found for host: %s\n", client.Address)
		ctx.Writer.Write([]byte("Bad Request"))
		ctx.Status(http.StatusBadRequest)
		return
	}

	srvError = callbackByHost.SrvError

	fmt.Printf("[DEBUG] Server error headers: %v\n", srvError.Headers)

	errorRet := func(valid bool, strError string) {
		fmt.Printf("[ERROR] Rejecting request: %s\n", strError)

		if srvError != nil {
			if srvError.Headers != nil && len(srvError.Headers) > 0 {
				for key, value := range srvError.Headers {
					ctx.Header(key, value)
				}
			}

			ctx.Status(srvError.Status)
			ctx.Writer.Write([]byte(srvError.Response))
		} else {
			ctx.Writer.Write([]byte("Bad Request"))
			ctx.Status(http.StatusBadRequest)
		}

		ctx.Abort()
	}

	fmt.Printf("[DEBUG] Looking for callback with URI: %s\n", client.Uri)
	callback, uriConfig, httpMethod = handler.get_callback_by_uri(client.Uri, client.HttpMethod)
	if callback == nil || uriConfig == nil || httpMethod == nil {
		fmt.Printf("[DEBUG] No valid callback found for URI: %s and method: %s\n", client.Uri, client.HttpMethod)
		fmt.Printf("[DEBUG] Available endpoints: %v\n", handler.get_all_endpoints())
		errorRet(false, "no matching endpoint configuration")
		return
	}

	fmt.Printf("[DEBUG] Found callback for URI: %s\n", client.Uri)

	if client.UserAgent != callback.UserAgent {
		fmt.Printf("[DEBUG] UserAgent mismatch - Expected: %s, Got: %s\n", callback.UserAgent, client.UserAgent)
		errorRet(false, "invalid user agent")
		return
	}
	fmt.Printf("[DEBUG] UserAgent validated\n")

	if httpMethod.ClientHeaders != nil && len(httpMethod.ClientHeaders) > 0 {
		for expectedHeader := range httpMethod.ClientHeaders {
			if ctx.GetHeader(expectedHeader) == "" {
				errorRet(false, fmt.Sprintf("Missing expected header: %s", expectedHeader))
			}
		}
	}

	fmt.Printf("[DEBUG] Headers validated\n")

	clientOutput = uriConfig.ClientOutput
	serverOutput = uriConfig.ServerOutput

	if httpMethod != nil {
		server.EmptyResp = httpMethod.EmptyResponse
	}

	fmt.Printf("[INFO] Processing valid request for path: %s from %s with method %s\n", client.Uri, client.Address, client.HttpMethod)

	agentType, oldID, agentExist, err = handler.parse_client_data(ctx, &client, clientOutput)
	if err != nil {
		errorRet(false, fmt.Sprintf("failed to parse beat and data: %v", err))
		return
	}

	agentData = client.Payload

	// New agent
	if !agentExist {
		if len(oldID) < 8 {
			errorRet(false, "oldID too short")
			return
		}

		oldAgentID = string(oldID[:8])
		fmt.Printf("[INFO] Creating new agent: %s\n", oldAgentID)

		agentDataRes, err := ModuleObject.ts.TsAgentCreate(agentType, oldAgentID, client.Payload, handler.Name, client.Address, true)
		if err != nil {
			errorRet(false, fmt.Sprintf("failed to create agent: %v", err))
			return
		}

		randomID := make([]byte, 19)
		_, err = rand.Read(randomID)
		if err != nil {
			errorRet(false, fmt.Sprintf("failed to generate random ID: %v", err))
			return
		}

		newID := []byte(agentDataRes.Id + hex.EncodeToString(randomID))

		fmt.Printf("[DEBUG] New ID: %s\n", newID)
		fmt.Printf("[DEBUG] Old ID: %s\n", oldID)

		key 	  = handler.Config.EncryptKey
		crypt 	  = NewLokyCrypt(key, key)
		encrypted = crypt.Encrypt(newID)

		combined := append(oldID, encrypted...)

		switch serverOutput.Format {
		case "hex":
			responseData = []byte(hex.EncodeToString(combined))
		case "base32":
			responseData = []byte(base32.StdEncoding.EncodeToString(combined))
		case "base64":
			responseData = []byte(base64.StdEncoding.EncodeToString(combined))
		case "base64url":
			responseData = []byte(base64.URLEncoding.EncodeToString(combined))
		case "raw":
			responseData = combined
		}

		server.Payload = responseData

	// Existing agent
	} else if len(agentData) > 0 {
		if len(oldID) >= 8 {
			oldAgentID = string(oldID[:8])
		} else {
			oldAgentID = hex.EncodeToString(oldID)
		}

		fmt.Printf("[INFO] Processing data for existing agent id: %s\n", oldAgentID)

		_ = ModuleObject.ts.TsAgentSetTick(oldAgentID, handler.Name)

		if len(agentData) > 0 {
			taskAction := agentData[0]

			switch taskAction {
			case TASK_GET:
				hostedData, err := ModuleObject.ts.TsAgentGetHostedAll(oldAgentID, 0x12c0000)
				if err != nil {
					fmt.Printf("[ERROR] Failed to get hosted data: %v\n", err)
				} else if len(hostedData) > 0 {
					key = handler.Config.EncryptKey
					crypt = NewLokyCrypt(key, key)
					encrypted = crypt.Encrypt(hostedData)

					combined := append(oldID, encrypted...)

					switch serverOutput.Format {
					case "hex":
						responseData = []byte(hex.EncodeToString(combined))
					case "base32":
						responseData = []byte(base32.StdEncoding.EncodeToString(combined))
					case "base64":
						responseData = []byte(base64.StdEncoding.EncodeToString(combined))
					case "base64url":
						responseData = []byte(base64.URLEncoding.EncodeToString(combined))
					case "raw":
						responseData = combined
					}

					fmt.Printf("[INFO] Response key: %02x\n", key)

					server.Payload = responseData
				}
			case TASK_RESULT:
				if len(agentData) > 1 {
					processData := agentData[1:]
					_ = ModuleObject.ts.TsAgentProcessData(oldAgentID, processData)
				}
			case TASK_OUT:
				msgTypePattern := append([]byte{0x0, 0x0, 0x0, 0x1, 0x0, 0x0, 0x0}, agentData...)
				_ = ModuleObject.ts.TsAgentProcessData(oldAgentID, msgTypePattern)
			case TASK_QUICK:
				msgTypePattern := append([]byte{0x0, 0x0, 0x0, 0x1, 0x0, 0x0, 0x0}, agentData...)
				_ = ModuleObject.ts.TsAgentProcessData(oldAgentID, msgTypePattern)
			default:
				fmt.Printf("[ERROR] Unknown data type: %d\n", taskAction)
			}
		}
	}

	handler.apply_server_headers(ctx, httpMethod)

	if len(server.Payload) > 0 {
		fmt.Printf("[INFO] Sending response (%d bytes) to agent: %s\n", len(server.Payload), oldAgentID)
		fmt.Println(formatHexDump(server.Payload, 16))

		if serverOutput != nil && serverOutput.Header != "" {
			ctx.Writer.Header().Set(serverOutput.Header, string(server.Payload))
			ctx.Status(http.StatusOK)

			if len(serverOutput.Body) > 0 {
				ctx.Writer.Write([]byte(serverOutput.Body))
			}
		} else if serverOutput != nil && serverOutput.Parameter != "" {
			ctx.Status(http.StatusOK)
			ctx.Writer.Write([]byte(server.Payload))
		} else if serverOutput != nil && serverOutput.Cookie != "" {
			ctx.Writer.Header().Set("Set-Cookie", fmt.Sprintf("%s=%s", serverOutput.Cookie, string(server.Payload)))
			ctx.Status(http.StatusOK)

			if len(serverOutput.Body) > 0 {
				ctx.Writer.Write([]byte(serverOutput.Body))
			}
		} else {
			ctx.Writer.Write([]byte(server.Payload))
			ctx.Status(http.StatusOK)
		}
	} else {
		fmt.Printf("[INFO] Sending empty response to agent: %s\n", oldAgentID)
		fmt.Println(formatHexDump(server.Payload, 16))

		if serverOutput != nil && serverOutput.Header != "" {
			fmt.Printf("[DEBUG] Output in header: %s\n", serverOutput.Header)
			ctx.Writer.Header().Set(serverOutput.Header, string(server.EmptyResp))
			ctx.Status(http.StatusOK)

			if len(serverOutput.Body) > 0 {
				ctx.Writer.Write([]byte(serverOutput.Body))
			}
		} else if serverOutput != nil && serverOutput.Parameter != "" {
			// Parameter output - response in body
			fmt.Printf("[DEBUG] Output in parameter\n")
			ctx.Status(http.StatusOK)
			ctx.Writer.Write([]byte(server.EmptyResp))
		} else if serverOutput != nil && serverOutput.Cookie != "" {
			// Cookie output - response in Set-Cookie header
			fmt.Printf("[DEBUG] Output in cookie: %s\n", serverOutput.Cookie)
			ctx.Writer.Header().Set("Set-Cookie", fmt.Sprintf("%s=%s", serverOutput.Cookie, string(server.EmptyResp)))
			ctx.Status(http.StatusOK)

			if len(serverOutput.Body) > 0 {
				ctx.Writer.Write([]byte(serverOutput.Body))
			}
		} else {
			fmt.Printf("[DEBUG] Output in body\n")
			ctx.Writer.Write([]byte(server.EmptyResp))
			ctx.Status(http.StatusOK)
		}
	}

	ctx.Abort()
}

func (handler *HTTP) parse_client_data(ctx *gin.Context, client *ClientRequest, output *OutputConfig) (string, []byte, bool, error) {
	var (
		old_agent_id   []byte
		agent_adp_id   []byte
		full_data 	   io.Reader
		processed_data []byte
		agent_exist    bool

		key            []byte
		crypt          *LokyCrypt
		encrypted_data []byte
		decrypted_data []byte
	)
    
	if output.Header != "" {
		headerValue := ctx.GetHeader(output.Header)
		if headerValue == "" {
			return "", nil, false, errors.New("header not found")
		}

		headerValue = strings.ReplaceAll(headerValue, " ", "+")
		
		full_data = bytes.NewBuffer([]byte(headerValue))
	} else if output.Cookie != "" {
		cookieValue, err := ctx.Cookie(output.Cookie)
		if err != nil || cookieValue == "" {
			return "", nil, false, errors.New("cookie not found")
		}

		cookieValue = strings.ReplaceAll(cookieValue, " ", "+")
		
		full_data = bytes.NewBuffer([]byte(cookieValue))
	} else if output.Parameter != "" {
		fmt.Printf("param key: %s\n", output.Parameter)
		paramValue := ctx.Query(output.Parameter)
		fmt.Printf("param value from Query: %s\n", paramValue)
		if paramValue == "" {
			paramValue = ctx.Param(output.Parameter)
			fmt.Printf("param value from Param: %s\n", paramValue)
		}
		if paramValue == "" {
			return "", nil, false, errors.New("parameter not found")
		}
		
		full_data = bytes.NewBuffer([]byte(paramValue))
	} else {
		body_data, err := io.ReadAll(ctx.Request.Body)
		if err != nil {
			return "", nil, false, fmt.Errorf("failed to read request body: %v", err)
		}

		ctx.Request.Body = io.NopCloser(bytes.NewBuffer(body_data))
		full_data = bytes.NewBuffer(body_data)
	}
    
    agent_data, err := io.ReadAll(full_data)
    if err != nil {
        return "", nil, false, fmt.Errorf("failed to read agent data: %v", err)
    }

	fmt.Println(formatHexDump(agent_data, 16))
    
    if len(agent_data) == 0 {
        return "", nil, false, errors.New("missing agent data")
    }
    
    processed_data = agent_data
    
    if output.Prepend != "" {
        prepend_bytes := []byte(output.Prepend)
        if len(agent_data) >= len(prepend_bytes) && bytes.HasPrefix(agent_data, prepend_bytes) {
            processed_data = agent_data[len(prepend_bytes):]
        } else {
            return "", nil, false, errors.New("prepend not found in data")
        }
    }
    
    if output.Append != "" {
        append_data := []byte(output.Append)
        if len(processed_data) >= len(append_data) && bytes.HasSuffix(processed_data, append_data) {
            processed_data = processed_data[:len(processed_data) - len(append_data)]
        } else {
            return "", nil, false, errors.New("append not found in data")
        }
    }
    
    var formatted []byte
    switch output.Format {
    case "base32":
        decoded, err := base32.StdEncoding.DecodeString(string(processed_data))
        if err != nil {
            return "", nil, false, fmt.Errorf("base32 decode failed: %v", err)
        }
        formatted = decoded
    case "base64":
        decoded, err := base64.StdEncoding.DecodeString(string(processed_data))
        if err != nil {
            return "", nil, false, fmt.Errorf("base64 decode failed: %v", err)
        }
        formatted = decoded
    case "base64url":
        decoded, err := base64.URLEncoding.DecodeString(string(processed_data))
        if err != nil {
            return "", nil, false, fmt.Errorf("base64url decode failed: %v", err)
        }
        formatted = decoded
	case "hex": {
		decoded, err := hex.DecodeString(string(processed_data))
		if err != nil {
			return "", nil, false, fmt.Errorf("hex decode failed: %v", err)
		}
		formatted = decoded
	}
    default:
        formatted = processed_data
    }
    
    if len(formatted) < 36 {
        return "", nil, false, fmt.Errorf("insufficient data length: got %d bytes, need at least 36", len(formatted))
    }
    
    total_len := len(formatted)
    if total_len < 36 { 
        return "", nil, false, errors.New("data too short for decryption")
    }

	old_agent_id = formatted[:36]
	agent_adp_id = old_agent_id[:8]

	fmt.Printf("old agentid: %s\n", old_agent_id)

    agent_exist = ModuleObject.ts.TsAgentIsExists(string(agent_adp_id))
    if !agent_exist {
		extracted_key := formatted[total_len-16:]
		
		handler.Config.EncryptKey = make([]byte, 16)
		copy(handler.Config.EncryptKey, extracted_key)
		
		key = handler.Config.EncryptKey
		encrypted_data = formatted[36 : total_len-16]
	} else {
		key = handler.Config.EncryptKey
		encrypted_data = formatted[36:]
	}

    fmt.Printf("fmt key: %v\n", key)
    fmt.Printf("fmt key handler: %v\n", handler.Config.EncryptKey)
    
    if len(encrypted_data) == 0 {
        return "", nil, false, errors.New("no encrypted data available")
    }
    
    crypt = NewLokyCrypt(key, key)
    decrypted_data = crypt.Decrypt(encrypted_data)
    
    client.Payload = decrypted_data
    
    return "c17a905a", old_agent_id, agent_exist, nil
}