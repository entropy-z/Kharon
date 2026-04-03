package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"

	ax "github.com/Adaptix-Framework/axc2"
)

type Teamserver interface {
	TsAgentIsExists(agentId string) bool
	TsAgentCreate(agentCrc string, agentId string, beat []byte, listenerName string, ExternalIP string, Async bool) (ax.AgentData, error)
	TsAgentProcessData(agentId string, bodyData []byte) error
	TsAgentUpdateData(newAgentData ax.AgentData) error
	TsAgentTerminate(agentId string, terminateTaskId string) error

	TsAgentUpdateDataPartial(agentId string, updateData interface{}) error
	TsAgentSetTick(agentId string, listenerName string) error

	TsAgentConsoleOutput(agentId string, messageType int, message string, clearText string, store bool)

	TsAgentGetHostedAll(agentId string, maxDataSize int) ([]byte, error)
	TsAgentGetHostedTasks(agentId string, maxDataSize int) ([]byte, error)
	TsAgentGetHostedTasksCount(agentId string, count int, maxDataSize int) ([]byte, error)

	TsTaskRunningExists(agentId string, taskId string) bool
	TsTaskCreate(agentId string, cmdline string, client string, taskData ax.TaskData)
	TsTaskUpdate(agentId string, updateData ax.TaskData)

	TsTaskGetAvailableAll(agentId string, availableSize int) ([]ax.TaskData, error)
	TsTaskGetAvailableTasks(agentId string, availableSize int) ([]ax.TaskData, int, error)
	TsTaskGetAvailableTasksCount(agentId string, maxCount int, availableSize int) ([]ax.TaskData, int, error)
	TsTasksPivotExists(agentId string, first bool) bool
	TsTaskGetAvailablePivotAll(agentId string, availableSize int) ([]ax.TaskData, error)

	TsClientGuiDisksWindows(taskData ax.TaskData, drives []ax.ListingDrivesDataWin)
	TsClientGuiFilesStatus(taskData ax.TaskData)
	TsClientGuiFilesWindows(taskData ax.TaskData, path string, files []ax.ListingFileDataWin)
	TsClientGuiFilesUnix(taskData ax.TaskData, path string, files []ax.ListingFileDataUnix)
	TsClientGuiProcessWindows(taskData ax.TaskData, process []ax.ListingProcessDataWin)
	TsClientGuiProcessUnix(taskData ax.TaskData, process []ax.ListingProcessDataUnix)

	TsCredentilsAdd(creds []map[string]interface{}) error
	TsCredentilsEdit(credId string, username string, password string, realm string, credType string, tag string, storage string, host string) error
	TsCredentialsSetTag(credsId []string, tag string) error
	TsCredentilsDelete(credsId []string) error

	TsDownloadAdd(agentId string, fileId string, fileName string, fileSize int64) error
	TsDownloadUpdate(fileId string, state int, data []byte) error
	TsDownloadClose(fileId string, reason int) error
	TsDownloadDelete(fileid []string) error
	TsDownloadSave(agentId string, fileId string, filename string, content []byte) error
	TsDownloadGetFilepath(fileId string) (string, error)
	TsUploadGetFilepath(fileId string) (string, error)
	TsUploadGetFileContent(fileId string) ([]byte, error)

	TsListenerInteralHandler(watermark string, data []byte) (string, error)

	TsGetPivotInfoByName(pivotName string) (string, string, string)
	TsGetPivotInfoById(pivotId string) (string, string, string)
	TsGetPivotByName(pivotName string) *ax.PivotData
	TsGetPivotById(pivotId string) *ax.PivotData
	TsPivotCreate(pivotId string, pAgentId string, chAgentId string, pivotName string, isRestore bool) error
	TsPivotDelete(pivotId string) error

	TsScreenshotAdd(agentId string, Note string, Content []byte) error
	TsScreenshotNote(screenId string, note string) error
	TsScreenshotDelete(screenId string) error

	TsTargetsAdd(targets []map[string]interface{}) error
	TsTargetsCreateAlive(agentData ax.AgentData) (string, error)
	TsTargetsEdit(targetId string, computer string, domain string, address string, os int, osDesk string, tag string, info string, alive bool) error
	TsTargetSetTag(targetsId []string, tag string) error
	TsTargetRemoveSessions(agentsId []string) error
	TsTargetDelete(targetsId []string) error

	TsTunnelStart(TunnelId string) (string, error)
	TsTunnelCreateSocks4(AgentId string, Info string, Lhost string, Lport int) (string, error)
	TsTunnelCreateSocks5(AgentId string, Info string, Lhost string, Lport int, UseAuth bool, Username string, Password string) (string, error)
	TsTunnelCreateLportfwd(AgentId string, Info string, Lhost string, Lport int, Thost string, Tport int) (string, error)
	TsTunnelCreateRportfwd(AgentId string, Info string, Lport int, Thost string, Tport int) (string, error)
	TsTunnelUpdateRportfwd(tunnelId int, result bool) (string, string, error)

	TsTunnelStopSocks(AgentId string, Port int)
	TsTunnelStopLportfwd(AgentId string, Port int)
	TsTunnelStopRportfwd(AgentId string, Port int)

	TsTunnelConnectionClose(channelId int, writeOnly bool)
	TsTunnelConnectionHalt(channelId int, errorCode byte)
	TsTunnelConnectionResume(AgentId string, channelId int, ioDirect bool)
	TsTunnelConnectionData(channelId int, data []byte)
	TsTunnelConnectionAccept(tunnelId int, channelId int)

	TsTerminalConnExists(terminalId string) bool
	TsTerminalGetPipe(AgentId string, terminalId string) (*io.PipeReader, *io.PipeWriter, error)
	TsTerminalConnResume(agentId string, terminalId string, ioDirect bool)
	TsTerminalConnData(terminalId string, data []byte)
	TsTerminalConnClose(terminalId string, status string) error

	TsExtenderDataLoad(extenderName string, key string) ([]byte, error)
	TsExtenderDataSave(extenderName string, key string, value []byte) error
	TsExtenderDataDelete(extenderName string, key string) error
	TsExtenderDataKeys(extenderName string) ([]string, error)
	TsExtenderDataDeleteAll(extenderName string) error

	TsConvertCpToUTF8(input string, codePage int) string
	TsConvertUTF8toCp(input string, codePage int) string
	TsWin32Error(errorCode uint) string
}

type PluginListener struct{}

type ModuleExtender struct {
	ts Teamserver
	pl *PluginListener
}

var (
	ModuleObject    *ModuleExtender
	ModuleDir       string
	ListenerDataDir string
	ListenersObject []any
)

const AgentWatermark = "c17a905a"

// ==================== Plugin Initialization ====================

func InitPlugin(ts any, moduleDir string, listenerDir string) ax.PluginListener {
	ModuleDir = moduleDir
	ListenerDataDir = listenerDir

	ModuleObject = &ModuleExtender{
		ts: ts.(Teamserver),
		pl: &PluginListener{},
	}
	return &PluginListener{}
}

// ==================== Listener Lifecycle ====================

func (pl *PluginListener) Create(name string, data string, listenerCustomData []byte) (ax.ExtenderListener, ax.ListenerData, []byte, error) {
	var (
		listenerData ax.ListenerData
		customData   []byte
		conf         TransportConfig
		err          error
	)

	if listenerCustomData == nil {
		err = json.Unmarshal([]byte(data), &conf)
		if err != nil {
			return nil, listenerData, customData, err
		}

		err = validConfig(data)
		if err != nil {
			return nil, listenerData, customData, err
		}

		conf.Protocol = "bind_smb"
	} else {
		err = json.Unmarshal(listenerCustomData, &conf)
		if err != nil {
			return nil, listenerData, customData, err
		}
	}

	transport := &TransportSMB{
		Name:   name,
		Config: conf,
		Active: true,
	}

	listenerData = ax.ListenerData{
		AgentAddr: fmt.Sprintf("\\\\.\\pipe\\%s", conf.Pipename),
		Watermark: "c17a905a", // Kharon agent watermark — must match for TsListenerInteralHandler routing
		Status:    "Active",
	}

	var buffer bytes.Buffer
	err = json.NewEncoder(&buffer).Encode(conf)
	if err != nil {
		return nil, listenerData, customData, err
	}
	customData = buffer.Bytes()

	listener := &Listener{
		transport: transport,
	}

	ListenersObject = append(ListenersObject, transport)

	return listener, listenerData, customData, nil
}

// Start is a no-op for internal listeners (no port binding)
func (l *Listener) Start() error {
	return nil
}

func (l *Listener) Edit(config string) (ax.ListenerData, []byte, error) {
	for _, value := range ListenersObject {
		transport := value.(*TransportSMB)
		if transport.Name == l.transport.Name {
			listenerData := ax.ListenerData{
				AgentAddr: fmt.Sprintf("\\\\.\\pipe\\%s", transport.Config.Pipename),
				Status:    "Active",
			}
			if !transport.Active {
				listenerData.Status = "Stopped"
			}

			var buffer bytes.Buffer
			err := json.NewEncoder(&buffer).Encode(transport.Config)
			if err != nil {
				return listenerData, nil, err
			}

			return listenerData, buffer.Bytes(), nil
		}
	}
	return ax.ListenerData{}, nil, errors.New("listener not found")
}

func (l *Listener) Stop() error {
	var (
		index int
		ok    bool
	)

	for ind, value := range ListenersObject {
		transport := value.(*TransportSMB)
		if transport.Name == l.transport.Name {
			transport.Active = false
			index = ind
			ok = true
			break
		}
	}

	if ok {
		ListenersObject = append(ListenersObject[:index], ListenersObject[index+1:]...)
	} else {
		return errors.New("listener not found")
	}

	return nil
}

func (l *Listener) GetProfile() ([]byte, error) {
	var buffer bytes.Buffer
	err := json.NewEncoder(&buffer).Encode(l.transport.Config)
	if err != nil {
		return nil, err
	}
	return buffer.Bytes(), nil
}

// ==================== InternalHandler ====================
// Called by the teamserver when a parent beacon forwards pivot data
// from a child SMB beacon. The data parameter contains the raw
// encrypted checkin blob from the child.

func (l *Listener) InternalHandler(data []byte) (string, error) {
	if len(data) < 52 {
		return "", fmt.Errorf("insufficient data length: got %d bytes, need at least 52 (36 UUID + 16 key)", len(data))
	}

	totalLen := len(data)

	// processDecryptedData handles format detection and routing to TsAgentProcessData.
	// decryptedData = Decrypt(data[36:]) — starts AFTER UUID.
	// PostTask (0x01): strip type byte, pass [jobCount][jobs] to ProcessData
	// QuickMsg (0x05) / QuickOut (0x07): wrap with 7-byte header like HTTP listener
	processDecryptedData := func(agentID string, decryptedData []byte) {
		if len(decryptedData) <= 1 {
			fmt.Printf("[IH-DBG] processDecryptedData: too short (%d) for agent %s\n", len(decryptedData), agentID)
			return
		}
		firstByte := decryptedData[0]
		fmt.Printf("[IH-DBG] processDecryptedData: agent=%s, len=%d, firstByte=0x%02x\n", agentID, len(decryptedData), firstByte)
		var taskData []byte
		if firstByte == 0x05 || firstByte == 0x07 {
			msgTypePattern := append([]byte{0x0, 0x0, 0x0, 0x1, 0x0, 0x0, 0x0}, decryptedData...)
			taskData = msgTypePattern
		} else if firstByte == 0x01 {
			taskData = decryptedData[1:]
		} else {
			fmt.Printf("[IH-DBG] processDecryptedData: UNKNOWN format 0x%02x, passing raw\n", firstByte)
			taskData = decryptedData
		}
		err := ModuleObject.ts.TsAgentProcessData(agentID, taskData)
		if err != nil {
			fmt.Printf("[IH-DBG] TsAgentProcessData ERROR: %v\n", err)
		}
	}

	// Try to match against known agents by UUID in first 8 bytes
	if totalLen >= 36 {
		testAgentID := string(data[:8])
		fmt.Printf("[IH-DBG] InternalHandler: len=%d, testAgentID='%s', exists=%v\n",
			totalLen, testAgentID, ModuleObject.ts.TsAgentIsExists(testAgentID))

		if ModuleObject.ts.TsAgentIsExists(testAgentID) {
			storedKey, err := ModuleObject.ts.TsExtenderDataLoad(l.transport.Name, "key_"+testAgentID)
			if err == nil && len(storedKey) == 16 {
				encryptedData := data[36:]
				crypt := NewLokyCrypt(storedKey, storedKey)
				decryptedData := crypt.Decrypt(encryptedData)

				_ = ModuleObject.ts.TsAgentSetTick(testAgentID, l.transport.Name)
				processDecryptedData(testAgentID, decryptedData)

				return testAgentID, nil
			}
		}

		// Look up key by the original UUID prefix (data[:8]).
		// The key was stored as key_<originalUUID> at first checkin, and also
		// as key_<serverAssignedId>. Using the original UUID is the most reliable
		// way to find the correct key — avoids false matches from key scanning.
		origPrefix := string(data[:8])
		storedKey, keyErr := ModuleObject.ts.TsExtenderDataLoad(l.transport.Name, "key_"+origPrefix)
		if keyErr == nil && len(storedKey) == 16 {
			encryptedData := data[36:]
			crypt := NewLokyCrypt(storedKey, storedKey)
			decryptedData := crypt.Decrypt(encryptedData)

			// Find the server-assigned agent ID for this original UUID
			agentID := origPrefix // fallback
			keys, _ := ModuleObject.ts.TsExtenderDataKeys(l.transport.Name)
			for _, k := range keys {
				if len(k) > 4 && k[:4] == "key_" {
					candidateID := k[4:]
					if candidateID != origPrefix && ModuleObject.ts.TsAgentIsExists(candidateID) {
						// Check if this agent has the same key
						candidateKey, _ := ModuleObject.ts.TsExtenderDataLoad(l.transport.Name, k)
						if len(candidateKey) == 16 && string(candidateKey) == string(storedKey) {
							agentID = candidateID
							break
						}
					}
				}
			}

			fmt.Printf("[IH-DBG] direct key match: origUUID='%s' → agent=%s\n", origPrefix, agentID)
			_ = ModuleObject.ts.TsAgentSetTick(agentID, l.transport.Name)
			processDecryptedData(agentID, decryptedData)

			return agentID, nil
		}
	}

	// New agent: extract key from last 16 bytes
	// Format: [0:36] UUID (plaintext) | [36:len-16] encrypted beat | [len-16:] 16-byte key
	extractedKey := make([]byte, 16)
	copy(extractedKey, data[totalLen-16:])

	oldAgentId := data[:36]
	encryptedBeat := data[36 : totalLen-16]

	agentIdFull := string(oldAgentId)
	agentId := agentIdFull[:8]

	// Decrypt the beat data using the extracted key
	crypt := NewLokyCrypt(extractedKey, extractedKey)
	decryptedBeat := crypt.Decrypt(encryptedBeat)

	// Clear old stored keys (prevent stale key matching across sessions)
	oldKeys, _ := ModuleObject.ts.TsExtenderDataKeys(l.transport.Name)
	for _, k := range oldKeys {
		if len(k) > 4 && k[:4] == "key_" {
			ModuleObject.ts.TsExtenderDataDelete(l.transport.Name, k)
		}
	}

	// Store the agent's encryption key for future communications
	err := ModuleObject.ts.TsExtenderDataSave(l.transport.Name, "key_"+agentId, extractedKey)
	if err != nil {
		return "", fmt.Errorf("failed to save agent key: %v", err)
	}

	// Register the agent with the teamserver (Async=false — SMB is synchronous)
	agentDataRes, err := ModuleObject.ts.TsAgentCreate(AgentWatermark, agentId, decryptedBeat, l.transport.Name, "", false)
	if err != nil {
		return "", fmt.Errorf("failed to create agent: %v", err)
	}

	newAgentID := agentDataRes.Id

	// If the teamserver assigned a different ID, save the key under the new ID too
	if newAgentID != agentId {
		_ = ModuleObject.ts.TsExtenderDataSave(l.transport.Name, "key_"+newAgentID, extractedKey)
	}

	return newAgentID, nil
}
