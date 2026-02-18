package main

import (
	// "database/sql/driver"
	"encoding/hex"
	"encoding/json"
	"io"
	"math/rand"
	"time"

	ax "github.com/Adaptix-Framework/axc2"
)

const (
	OS_UNKNOWN = 0
	OS_WINDOWS = 1
	OS_LINUX   = 2
	OS_MAC     = 3

	TYPE_TASK       = 1
	TYPE_BROWSER    = 2
	TYPE_JOB        = 3
	TYPE_TUNNEL     = 4
	TYPE_PROXY_DATA = 5

	MESSAGE_INFO    = 5
	MESSAGE_ERROR   = 6
	MESSAGE_SUCCESS = 7

	DOWNLOAD_STATE_RUNNING  = 1
	DOWNLOAD_STATE_STOPPED  = 2
	DOWNLOAD_STATE_FINISHED = 3
	DOWNLOAD_STATE_CANCELED = 4
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

	TsDownloadAdd(agentId string, fileId string, fileName string, fileSize int) error
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
	TsTunnelPause(channelId int)
	TsTunnelResume(channelId int)

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

	TsConvertCpToUTF8(input string, codePage int) string
	TsConvertUTF8toCp(input string, codePage int) string
	TsWin32Error(errorCode uint) string
}

type PluginAgent struct{}
type ExtenderAgent struct{}

type ModuleExtender struct {
	ts  Teamserver
	pa  *PluginAgent
	ext *ExtenderAgent
}

var (
	ModuleObject   *ModuleExtender
	ModuleDir      string
	AgentWatermark string
)

func (p *PluginAgent) GetExtender() ax.ExtenderAgent {
	return ModuleObject.ext
}

func InitPlugin(ts any, moduleDir string, watermark string) ax.PluginAgent {
	ModuleDir = moduleDir
	AgentWatermark = watermark

	ModuleObject = &ModuleExtender{
		ts:  ts.(Teamserver),
		pa:  &PluginAgent{},
		ext: &ExtenderAgent{},
	}

	return ModuleObject.pa
}

func (pa *PluginAgent) GenerateProfiles(profile ax.BuildProfile) ([][]byte, error) {
	var (
		agentProfiles [][]byte
		listenerMap   map[string]any
		err           error
	)

	for _, transportProfile := range profile.ListenerProfiles {
		err = json.Unmarshal(transportProfile.Profile, &listenerMap)
		if err != nil {
			return nil, err
		}
	}

	return agentProfiles, nil
}

func (pa *PluginAgent) BuildPayload(profile ax.BuildProfile, agentProfiles [][]byte) ([]byte, string, error) {
	var (
		agentProfile []byte
		listenerMap  map[string]any
		err          error
	)

	for _, transportProfile := range profile.ListenerProfiles {
		err = json.Unmarshal(transportProfile.Profile, &listenerMap)
		agentProfile = transportProfile.Profile
		if err != nil {
			return nil, "", err
		}
	}

	return AgentGenerateBuild(profile.AgentConfig, agentProfile, listenerMap)
}

func (ext *ExtenderAgent) Encrypt(data []byte, key []byte) ([]byte, error) {
	return data, nil
}

func (ext *ExtenderAgent) Decrypt(data []byte, key []byte) ([]byte, error) {
	return data, nil
}

func (pa *PluginAgent) CreateAgent(beat []byte) (ax.AgentData, ax.ExtenderAgent, error) {
	return CreateAgent(beat)
}

func (ext *ExtenderAgent) CreateCommand(agentData ax.AgentData, args map[string]any) (ax.TaskData, ax.ConsoleMessageData, error) {
	return CreateTask(ModuleObject.ts, agentData, args)
}

func (ext *ExtenderAgent) PackTasks(agentData ax.AgentData, tasks []ax.TaskData) ([]byte, error) {
	packedData, err := PackTasks(agentData, tasks)
	if err != nil || tasks == nil {
		return nil, err
	}

	return ext.Encrypt(packedData, agentData.SessionKey)
}

func (ext *ExtenderAgent) PivotPackData(pivotId string, data []byte) (ax.TaskData, error) {
	packData, err := PackPivotTasks(pivotId, data)
	if err != nil {
		return ax.TaskData{}, err
	}

	randomBytes := make([]byte, 16)
	rand.Read(randomBytes)
	uid := hex.EncodeToString(randomBytes)[:8]

	taskData := ax.TaskData{
		TaskId: uid,
		Type:   TYPE_PROXY_DATA,
		Data:   packData,
		Sync:   false,
	}

	return taskData, nil
}

func (ext *ExtenderAgent) ProcessData(agentData ax.AgentData, packedData []byte) error {
	decryptData, err := ext.Decrypt(packedData, agentData.SessionKey)
	if err != nil {
		return err
	}

	taskData := ax.TaskData{
		Type:        TYPE_TASK,
		AgentId:     agentData.Id,
		FinishDate:  time.Now().Unix(),
		MessageType: MESSAGE_SUCCESS,
		Completed:   true,
		Sync:        true,
	}

	resultTasks := ProcessTasksResult(ModuleObject.ts, agentData, taskData, decryptData)

	for _, task := range resultTasks {
		ModuleObject.ts.TsTaskUpdate(agentData.Id, task)
	}

	return nil
}

/// SYNC

func SyncBrowserDisks(ts Teamserver, taskData ax.TaskData, drivesSlice []ax.ListingDrivesDataWin) {
	ts.TsClientGuiDisksWindows(taskData, drivesSlice)
}

func SyncBrowserFiles(ts Teamserver, taskData ax.TaskData, path string, filesSlice []ax.ListingFileDataWin) {
	ts.TsClientGuiFilesWindows(taskData, path, filesSlice)
}

func SyncBrowserFilesStatus(ts Teamserver, taskData ax.TaskData) {
	ts.TsClientGuiFilesStatus(taskData)
}

func SyncBrowserProcess(ts Teamserver, taskData ax.TaskData, processlist []ax.ListingProcessDataWin) {
	ts.TsClientGuiProcessWindows(taskData, processlist)
}

/// TUNNEL

func (ext *ExtenderAgent) TunnelCallbacks() ax.TunnelCallbacks {
	return ax.TunnelCallbacks{
		ConnectTCP: TunnelMessageConnectTCP,
		ConnectUDP: TunnelMessageConnectUDP,
		WriteTCP:   TunnelMessageWriteTCP,
		WriteUDP:   TunnelMessageWriteUDP,
		Pause:      TunnelMessagePause,
		Resume:     TunnelMessageResume,
		Close:      TunnelMessageClose,
		Reverse:    TunnelMessageReverse,
	}
}

func makeProxyTask(packData []byte) ax.TaskData {
	return ax.TaskData{Type: ax.TASK_TYPE_PROXY_DATA, Data: packData, Sync: false}
}

func TunnelMessagePause(channelId int) ax.TaskData {
	var packData []byte

	array := []interface{}{COMMAND_TUNNEL_PAUSE, channelId}
	packData, _ = PackArray(array)

	return makeProxyTask(packData)
}

func TunnelMessageResume(channelId int) ax.TaskData {
	var packData []byte

	array := []interface{}{COMMAND_TUNNEL_RESUME, channelId}
	packData, _ = PackArray(array)

	return makeProxyTask(packData)
}

func TunnelMessageConnectTCP(channelId int, tunnelType int, addressType int, address string, port int) ax.TaskData {
	packData, _ := TunnelCreateTCP(channelId, address, port)

	taskData := ax.TaskData{
		Type: TYPE_PROXY_DATA,
		Data: packData,
		Sync: false,
	}

	return taskData
}

func TunnelMessageConnectUDP(channelId int, tunnelType int, addressType int, address string, port int) ax.TaskData {
	packData, _ := TunnelCreateUDP(channelId, address, port)

	taskData := ax.TaskData{
		Type: TYPE_PROXY_DATA,
		Data: packData,
		Sync: false,
	}

	return taskData
}

func TunnelMessageWriteTCP(channelId int, data []byte) ax.TaskData {
	packData, _ := TunnelWriteTCP(channelId, data)

	taskData := ax.TaskData{
		Type: TYPE_PROXY_DATA,
		Data: packData,
		Sync: false,
	}

	return taskData
}

func TunnelMessageWriteUDP(channelId int, data []byte) ax.TaskData {
	packData, _ := TunnelWriteUDP(channelId, data)

	taskData := ax.TaskData{
		Type: TYPE_PROXY_DATA,
		Data: packData,
		Sync: false,
	}

	return taskData
}

func TunnelMessageClose(channelId int) ax.TaskData {
	packData, _ := TunnelClose(channelId)

	taskData := ax.TaskData{
		Type: TYPE_PROXY_DATA,
		Data: packData,
		Sync: false,
	}

	return taskData
}

func TunnelMessageReverse(tunnelId int, port int) ax.TaskData {
	packData, _ := TunnelReverse(tunnelId, port)

	taskData := ax.TaskData{
		Type: TYPE_PROXY_DATA,
		Data: packData,
		Sync: false,
	}

	return taskData
}

/// TERMINAL

func (ext *ExtenderAgent) TerminalCallbacks() ax.TerminalCallbacks {
	return ax.TerminalCallbacks{
		Start: TerminalMessageStart,
		Write: TerminalMessageWrite,
		Close: TerminalMessageClose,
	}
}

func TerminalMessageStart(terminalId int, program string, sizeH, sizeW, oemCP int) ax.TaskData {
	packData, err := TerminalStart(terminalId, program, sizeH, sizeW)
	if err != nil {
		return ax.TaskData{}
	}

	taskData := ax.TaskData{
		Type: TYPE_PROXY_DATA,
		Data: packData,
		Sync: false,
	}

	return taskData
}

func TerminalMessageWrite(terminalId int, oemCP int, data []byte) ax.TaskData {
	packData, err := TerminalWrite(terminalId, data)
	if err != nil {
		return ax.TaskData{}
	}
	taskData := ax.TaskData{
		Type: TYPE_PROXY_DATA,
		Data: packData,
		Sync: false,
	}

	return taskData
}

func TerminalMessageClose(terminalId int) ax.TaskData {
	packData, err := TerminalClose(terminalId)
	if err != nil {
		return ax.TaskData{}
	}

	taskData := ax.TaskData{
		Type: TYPE_PROXY_DATA,
		Data: packData,
		Sync: false,
	}

	return taskData
}
