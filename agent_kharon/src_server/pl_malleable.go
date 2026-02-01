package main

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"strings"
	"unicode/utf16"
)

const (
	OUTPUT_TYPE_PARAMETER = 0
	OUTPUT_TYPE_HEADER    = 1
	OUTPUT_TYPE_BODY      = 2
	OUTPUT_TYPE_COOKIE    = 3

	OUTPUT_FMT_RAW       = 0
	OUTPUT_FMT_HEX       = 1
	OUTPUT_FMT_BASE32    = 2
	OUTPUT_FMT_BASE64    = 3
	OUTPUT_FMT_BASE64URL = 4
)

func BuildMalleableHTTPBytes(profileContent string) ([]byte, int, error) {
	var json_data map[string]interface{}
	if err := json.Unmarshal([]byte(profileContent), &json_data); err != nil {
		fmt.Printf("[DEBUG] Error parsing JSON: %v\n", err)
		return nil, 0, fmt.Errorf("failed to parse profile: %v", err)
	}

	callbacks_raw := json_data["callbacks"].([]interface{})
	fmt.Printf("[DEBUG] Found %d callbacks\n", len(callbacks_raw))

	buf := new(bytes.Buffer)

	var all_hosts []string
	for _, callback_item := range callbacks_raw {
		callback_map := callback_item.(map[string]interface{})
		hosts_raw := callback_map["hosts"].([]interface{})
		for _, host := range hosts_raw {
			all_hosts = append(all_hosts, host.(string))
		}
	}

	totalCallbacks := int32(len(all_hosts))
	binary.Write(buf, binary.LittleEndian, totalCallbacks)
	fmt.Printf("[DEBUG] Writing %d callbacks\n", totalCallbacks)
	fmt.Printf("[DEBUG] Hosts: %v\n", all_hosts)

	first_callback := callbacks_raw[0].(map[string]interface{})
	user_agent := first_callback["user_agent"].(string)
	get_config, has_get := first_callback["get"].(map[string]interface{})
	post_config, has_post := first_callback["post"].(map[string]interface{})

	fmt.Printf("[DEBUG] has_get=%v, has_post=%v\n", has_get, has_post)

	for i, host := range all_hosts {
		fmt.Printf("[DEBUG] Processing callback %d/%d\n", i+1, len(all_hosts))
		host_str, port := parseHostPort(host)

		fmt.Printf("[DEBUG] Host: %s, Port: %d\n", host_str, port)
		fmt.Printf("[DEBUG] UserAgent: %s\n", user_agent)

		writeWideString(buf, host_str)

		binary.Write(buf, binary.LittleEndian, int32(port))
		fmt.Printf("[DEBUG] Wrote port: %d\n", port)

		writeWideString(buf, user_agent)

		methodFlag := int32(0)
		if has_get && has_post {
			methodFlag = 0x200
		} else if has_post {
			methodFlag = 0x150
		} else if has_get {
			methodFlag = 0x100
		}
		fmt.Printf("[DEBUG] MethodFlag: 0x%x\n", methodFlag)
		binary.Write(buf, binary.LittleEndian, methodFlag)

		if methodFlag == 0x150 || methodFlag == 0x200 {
			fmt.Println("[DEBUG] Writing POST config")
			writeHTTPMethodConfig(buf, post_config)
		}

		if methodFlag == 0x100 || methodFlag == 0x200 {
			fmt.Println("[DEBUG] Writing GET config")
			writeHTTPMethodConfig(buf, get_config)
		}
	}

	fmt.Printf("[DEBUG] Total buffer size: %d bytes\n", buf.Len())
	return buf.Bytes(), len(all_hosts), nil
}

func writeHTTPMethodConfig(buf *bytes.Buffer, method_config map[string]interface{}) {
	fmt.Println("[DEBUG] Starting")

	headers_str := extractHeadersForMalleable(method_config)
	fmt.Printf("[DEBUG] Headers: %q\n", headers_str)
	writeWideString(buf, headers_str)

	empty_resp := extractEmptyResponse(method_config)
	binary.Write(buf, binary.LittleEndian, int32(len(empty_resp)))
	buf.Write(empty_resp)
	fmt.Printf("[DEBUG] Empty response size: %d\n", len(empty_resp))

	cookies := extractCookies(method_config)
	binary.Write(buf, binary.LittleEndian, int32(len(cookies)))
	fmt.Printf("[DEBUG] Cookies count: %d\n", len(cookies))

	for idx, cookie := range cookies {
		name := cookie["name"]
		value := cookie["value"]
		fmt.Printf("[DEBUG] Cookie %d: %s = %s\n", idx+1, name, value)
		writeWideString(buf, name)
		writeWideString(buf, value)
	}

	endpoints := extractEndpointsUnique(method_config)
	binary.Write(buf, binary.LittleEndian, int32(len(endpoints)))
	fmt.Printf("[DEBUG] Endpoints count: %d\n", len(endpoints))

	for j, endpoint := range endpoints {
		path := endpoint["path"].(string)
		paramsStr := endpoint["parameters_string"].(string)
		fmt.Printf("[DEBUG] Endpoint %d: path=%s, params=%s\n", j+1, path, paramsStr)

		writeWideString(buf, path)
		
		clientParams := endpoint["client_parameters"].([]map[string]interface{})
		if clientParams == nil {
			clientParams = []map[string]interface{}{}
		}
		fmt.Printf("[DEBUG] Client parameters count: %d\n", len(clientParams))
		
		writeWideString(buf, paramsStr)
		
		clientOut := endpoint["client_output"].(map[string]interface{})
		writeOutputConfig(buf, clientOut, "Client")

		serverOut := endpoint["server_output"].(map[string]interface{})
		writeOutputConfig(buf, serverOut, "Server")
	}

	fmt.Println("[DEBUG] Done")
}

func parseHostPort(hostPort string) (string, int) {
	fmt.Printf("[DEBUG] Parsing: %s\n", hostPort)
	host := hostPort
	port := 443

	if strings.HasPrefix(hostPort, "[") {
		if idx := strings.Index(hostPort, "]"); idx != -1 {
			host = hostPort[1:idx]
			rest := strings.TrimSpace(hostPort[idx+1:])
			if strings.HasPrefix(rest, ":") {
				var p int
				fmt.Sscanf(strings.TrimSpace(rest[1:]), "%d", &p)
				if p > 0 {
					port = p
				}
			}
			fmt.Printf("[DEBUG] IPv6: host=%s, port=%d\n", host, port)
			return host, port
		}
	}

	if strings.Contains(hostPort, ":") {
		parts := strings.SplitN(hostPort, ":", 2)
		host = strings.TrimSpace(parts[0])
		var p int
		fmt.Sscanf(strings.TrimSpace(parts[1]), "%d", &p)
		if p > 0 {
			port = p
		}
	}

	fmt.Printf("[DEBUG] Result: host=%s, port=%d\n", host, port)
	return host, port
}

func writeWideString(buf *bytes.Buffer, s string) {
	fmt.Printf("[DEBUG] String: %q\n", s)
	utf16Encoded := utf16.Encode([]rune(s))

	dataSize := int32((len(utf16Encoded) + 1) * 2)

	binary.Write(buf, binary.LittleEndian, dataSize)

	for _, ch := range utf16Encoded {
		binary.Write(buf, binary.LittleEndian, ch)
	}

	binary.Write(buf, binary.LittleEndian, uint16(0))

	fmt.Printf("[DEBUG] Size: %d bytes\n", dataSize)
}

func extractHeadersForMalleable(config map[string]interface{}) string {
	fmt.Println("[DEBUG] Starting")
	if headers, ok := config["client_headers"].(map[string]interface{}); ok {
		fmt.Printf("[DEBUG] Found %d headers\n", len(headers))
		var headerLines []string
		for key, val := range headers {
			line := fmt.Sprintf("%s: %v", key, val)
			headerLines = append(headerLines, line)
			fmt.Printf("[DEBUG] Header: %s\n", line)
		}
		if len(headerLines) > 0 {
			result := strings.Join(headerLines, "\r\n")
			fmt.Printf("[DEBUG] Result length: %d\n", len(result))
			return result
		}
	}
	fmt.Println("[DEBUG] No headers found")
	return ""
}

func extractCookies(config map[string]interface{}) []map[string]string {
	fmt.Println("[DEBUG] Starting")
	var cookies []map[string]string

	if headers, ok := config["client_headers"].(map[string]interface{}); ok {
		fmt.Printf("[DEBUG] Found %d client headers\n", len(headers))
		for key, val := range headers {
			fmt.Printf("[DEBUG] Checking header: %s\n", key)
			if strings.ToLower(key) == "cookie" {
				fmt.Printf("[DEBUG] Found Cookie header\n")
				if cookieStr, ok := val.(string); ok {
					fmt.Printf("[DEBUG] Cookie value: %q\n", cookieStr)
					cookiePairs := strings.Split(cookieStr, ";")
					fmt.Printf("[DEBUG] Split into %d pairs\n", len(cookiePairs))

					for pidx, pair := range cookiePairs {
						pair = strings.TrimSpace(pair)
						if pair == "" {
							continue
						}

						parts := strings.SplitN(pair, "=", 2)
						if len(parts) == 2 {
							cookieName := strings.TrimSpace(parts[0])
							cookieValue := strings.TrimSpace(parts[1])

							if cookieName != "" {
								fmt.Printf("[extractCookies] Pair %d: %s = %s\n", pidx+1, cookieName, cookieValue)
								cookies = append(cookies, map[string]string{
									"name":  cookieName,
									"value": cookieValue,
								})
							}
						}
					}
				}
				break
			}
		}
	} else {
		fmt.Println("[DEBUG] No client_headers found")
	}

	fmt.Printf("[DEBUG] Total cookies: %d\n", len(cookies))
	return cookies
}

func decodeEscapeSequences(s string) []byte {
	fmt.Printf("[DEBUG] Input: %q\n", s)
	var result []byte
	i := 0
	for i < len(s) {
		if i+3 < len(s) && s[i] == '\\' && s[i+1] == 'x' {
			var b byte
			_, err := fmt.Sscanf(s[i+2:i+4], "%02x", &b)
			if err == nil {
				fmt.Printf("[DEBUG] Converted \\x%s to 0x%02x\n", s[i+2:i+4], b)
				result = append(result, b)
				i += 4
				continue
			}
		}
		result = append(result, s[i])
		i++
	}
	fmt.Printf("[DEBUG] Output: %d bytes\n", len(result))
	// for idx, b := range result {
		// fmt.Printf("[decodeEscapeSequences] Byte %d: 0x%02x\n", idx, b)
	// }
	return result
}

func extractEmptyResponse(config map[string]interface{}) []byte {
	fmt.Println("[DEBUG] Starting")
	if er, ok := config["empty_response"].(string); ok {
		fmt.Printf("[DEBUG] Value: %q\n", er)
		result := decodeEscapeSequences(er)
		fmt.Printf("[DEBUG] Size: %d bytes\n", len(result))

		fmt.Print("[DEBUG] Hex: ")
		for _, b := range result {
			fmt.Printf("%02x ", b)
		}
		fmt.Println()

		return result
	}
	fmt.Println("[DEBUG] No empty_response found")
	return []byte{}
}

func buildQueryString(params []map[string]interface{}) string {
	fmt.Printf("[DEBUG] Processing %d params\n", len(params))
	if params == nil || len(params) == 0 {
		fmt.Println("[DEBUG] Empty or nil params")
		return ""
	}

	var parts []string

	for pidx, paramMap := range params {
		fmt.Printf("[DEBUG] Param %d has %d items\n", pidx+1, len(paramMap))
		for key, val := range paramMap {
			part := fmt.Sprintf("%s=%v", key, val)
			parts = append(parts, part)
			fmt.Printf("[DEBUG] Added: %s\n", part)
		}
	}

	result := strings.Join(parts, "&")
	fmt.Printf("[DEBUG] Result: %q\n", result)
	return result
}

func extractEndpointsUnique(config map[string]interface{}) []map[string]interface{} {
	fmt.Println("[DEBUG] Starting")
	var endpoints []map[string]interface{}

	if uri, ok := config["uri"].(map[string]interface{}); ok {
		fmt.Printf("[DEBUG] Found %d URI groups\n", len(uri))
		
		for uri_key, uriData := range uri {
			fmt.Printf("[extractEndpointsUnique] Processing URI key: %q\n", uri_key)
			uriMap := uriData.(map[string]interface{})

			var client_params []map[string]interface{}
			if cp_raw, ok := uriMap["client_parameters"].([]interface{}); ok {
				fmt.Printf("[DEBUG] Found %d client parameters\n", len(cp_raw))
				for _, cp := range cp_raw {
					if paramMap, ok := cp.(map[string]interface{}); ok {
						client_params = append(client_params, paramMap)
					}
				}
			} else {
				fmt.Printf("[DEBUG] No client parameters found\n")
				client_params = nil
			}

			queryString := buildQueryString(client_params)

			paths := strings.FieldsFunc(uri_key, func(r rune) bool {
				return r == ' '
			})
			fmt.Printf("[DEBUG] Split %q into %d paths: %v\n", uri_key, len(paths), paths)

			for idx, path := range paths {
				path = strings.TrimSpace(path)
				if path == "" {
					fmt.Printf("[DEBUG] Skipping empty path\n")
					continue
				}

				fmt.Printf("[DEBUG] Adding endpoint %d: %q\n", idx+1, path)
				endpoint := map[string]interface{}{
					"path":               path,
					"client_output":      uriMap["client_output"],
					"server_output":      uriMap["server_output"],
					"client_parameters":  client_params,
					"parameters_string":  queryString,
				}
				endpoints = append(endpoints, endpoint)
			}
		}
	} else {
		fmt.Println("[DEBUG] No URI found")
	}

	fmt.Printf("[DEBUG] Total endpoints created: %d\n", len(endpoints))
	return endpoints
}

func decodeEscapeSequencesFalseBody(s string) []byte {
	fmt.Printf("[DEBUG] Input: %q\n", s)
	
	hasEscapeSequences := false
	for i := 0; i < len(s)-3; i++ {
		if s[i] == '\\' && s[i+1] == 'x' {
			hasEscapeSequences = true
			break
		}
	}
	
	if !hasEscapeSequences {
		fmt.Println("[DEBUG] No escape sequences found, encoding as CHAR (ASCII)")
		return encodeStringBytes(s)
	}
	
	var result []byte
	i := 0
	for i < len(s) {
		if i+3 < len(s) && s[i] == '\\' && s[i+1] == 'x' {
			var b byte
			_, err := fmt.Sscanf(s[i+2:i+4], "%02x", &b)
			if err == nil {
				fmt.Printf("[DEBUG] Converted \\x%s to 0x%02x\n", s[i+2:i+4], b)
				result = append(result, b)
				i += 4
				continue
			}
		}
		result = append(result, s[i])
		i++
	}
	fmt.Printf("[DEBUG] Output: %d bytes\n", len(result))
	return result
}

func encodeStringBytes(s string) []byte {
	fmt.Printf("[DEBUG] Encoding string as CHAR: %q\n", s)
	var buf bytes.Buffer
	
	byteArray := []byte(s)
	
	for _, b := range byteArray {
		buf.WriteByte(b)
	}
	
	buf.WriteByte(0)
	
	result := buf.Bytes()
	fmt.Printf("[DEBUG] Output: %d bytes (string len: %d + 1 null terminator)\n", len(result), len(s))
	return result
}

func writeOutputConfig(buf *bytes.Buffer, output map[string]interface{}, outputType string) {
	fmt.Printf("[DEBUG] Processing %s\n", outputType)

	mask := int32(0)
	if m, ok := output["mask"].(bool); ok && m {
		mask = 1
	}
	binary.Write(buf, binary.LittleEndian, mask)
	fmt.Printf("[DEBUG] Mask: %d\n", mask)

	out_type := OUTPUT_TYPE_BODY
	header_name := ""

	if val, ok := output["parameter"].(string); ok && val != "" {
		out_type = OUTPUT_TYPE_PARAMETER
		header_name = val
		fmt.Printf("[DEBUG] Type: PARAMETER (%s)\n", val)
	} else if val, ok := output["header"].(string); ok && val != "" {
		out_type = OUTPUT_TYPE_HEADER
		header_name = val
		fmt.Printf("[DEBUG] Type: HEADER (%s)\n", val)
	} else if val, ok := output["cookie"].(string); ok && val != "" {
		out_type = OUTPUT_TYPE_COOKIE
		header_name = val
		fmt.Printf("[DEBUG] Type: COOKIE (%s)\n", val)
	} else {
		fmt.Println("[DEBUG] Type: BODY")
	}

	binary.Write(buf, binary.LittleEndian, int32(out_type))

	format := int32(OUTPUT_FMT_RAW)
	out_fmt_name := "raw"

	if f, ok := output["format"].(string); ok {
		fmt.Printf("[DEBUG] Format string: %s\n", f)
		switch f {
		case "hex":
			format = OUTPUT_FMT_HEX
			out_fmt_name = "hex"
		case "base32":
			format = OUTPUT_FMT_BASE32
			out_fmt_name = "base32"
		case "base64":
			format = OUTPUT_FMT_BASE64
			out_fmt_name = "base64"
		case "base64url":
			format = OUTPUT_FMT_BASE64URL
			out_fmt_name = "base64url"
		}
	}

	binary.Write(buf, binary.LittleEndian, format)
	fmt.Printf("[DEBUG] Format: %s (%d)\n", out_fmt_name, format)

	if max, ok := output["max_chunk"].(int); ok {
		binary.Write(buf, binary.LittleEndian, int32(max))
	} else {
		binary.Write(buf, binary.LittleEndian, int32(0))
	}

	if out_type != OUTPUT_TYPE_BODY {
		writeWideString(buf, header_name)
	}

	append_str := ""
	if a, ok := output["append"].(string); ok {
		append_str = a
	}
	append_bytes := decodeEscapeSequences(append_str)
	binary.Write(buf, binary.LittleEndian, int32(len(append_bytes)))
	if len(append_bytes) > 0 {
		buf.Write(append_bytes)
	}
	fmt.Printf("[DEBUG] Append: %d bytes (%q)\n", len(append_bytes), append_str)

	prepend_str := ""
	if p, ok := output["prepend"].(string); ok {
		prepend_str = p
	}
	prepend_bytes := decodeEscapeSequences(prepend_str)
	binary.Write(buf, binary.LittleEndian, int32(len(prepend_bytes)))
	if len(prepend_bytes) > 0 {
		buf.Write(prepend_bytes)
	}
	fmt.Printf("[DEBUG] Prepend: %d bytes (%q)\n", len(prepend_bytes), prepend_str)

	body_str := ""

	if out_type == OUTPUT_TYPE_PARAMETER || out_type == OUTPUT_TYPE_HEADER || out_type == OUTPUT_TYPE_COOKIE {
		if b, ok := output["body"].(string); ok {
			body_str = b
		}
	}

	body_bytes := decodeEscapeSequencesFalseBody(body_str)
	binary.Write(buf, binary.LittleEndian, int32(len(body_bytes)))
	if len(body_bytes) > 0 {
		buf.Write(body_bytes)
	}
	fmt.Printf("[DEBUG] Body: %d bytes (%q)\n", len(body_bytes), body_str)

	fmt.Printf("[DEBUGqq] Done with %s\n", outputType)
}