package main

import (
	"errors"
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

type Listener struct {
	transport *HTTP
}

type ModuleExtender struct {
	ts Teamserver
	pl *PluginListener
}

var (
	ModuleObject    *ModuleExtender
	ModuleDir       string
	ListenerDataDir string
	ListenersObject []any //*HTTP
)

func InitPlugin(ts any, moduleDir string, listenerDir string) ax.PluginListener {
	ModuleDir = moduleDir
	ListenerDataDir = listenerDir

	ModuleObject = &ModuleExtender{
		ts: ts.(Teamserver),
		pl: &PluginListener{},
	}
	return &PluginListener{}
}

func (m *ModuleExtender) ListenerValid(data string) error {
	return m.HandlerListenerValid(data)
}

func (pl *PluginListener) Create(name string, data string, listenerCustomData []byte) (ax.ExtenderListener, ax.ListenerData, []byte, error) {
	extender, listenerData, customData, listener, err := ModuleObject.HandlerCreateListenerDataAndStart(name, data, listenerCustomData)
	if err != nil {
		return extender, listenerData, customData, err
	}

	ListenersObject = append(ListenersObject, listener)

	return extender, listenerData, customData, nil
}

func (l* Listener) Start() error {
	return l.transport.Start( ModuleObject.ts )
}

func (l *Listener) Edit(config string) (ax.ListenerData, []byte, error) {
	for _, value := range ListenersObject {
		listenerData, customData, ok := ModuleObject.HandlerEditListenerData(l.transport.Name, value, config)
		if ok {
			return listenerData, customData, nil
		}
	}
	return ax.ListenerData{}, nil, errors.New("listener not found")
}

func (l *Listener) Stop() error {
	var (
		index int
		err   error
		ok    bool
	)

	for ind, value := range ListenersObject {
		ok, err = ModuleObject.HandlerListenerStop(l.transport.Name, value)
		if ok {
			index = ind
			break
		}
	}

	if ok {
		ListenersObject = append(ListenersObject[:index], ListenersObject[index+1:]...)
	} else {
		return errors.New("listener not found")
	}

	return err
}

func (l *Listener) GetProfile() ([]byte, error) {

	profile, ok := ModuleObject.HandlerListenerGetProfile(l.transport.Name, l.transport)
	if ok {
		return profile, nil
	}
	
	return nil, errors.New("listener not found")
}

func (l *Listener) InternalHandler(data []byte) (string, error) {
	return "", errors.New("listener not found")
}
