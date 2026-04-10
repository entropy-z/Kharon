package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"strconv"

	ax "github.com/Adaptix-Framework/axc2"
)

type Teamserver interface {
	TsAgentIsExists(agentId string) bool
	TsAgentCreate(agentCrc string, agentId string, beat []byte, listenerName string, ExternalIP string, Async bool) (ax.AgentData, error)
	TsAgentProcessData(agentId string, bodyData []byte) error
	TsAgentUpdateData(newAgentData ax.AgentData) error
	TsAgentSetTick(agentId string, listenerName string) error
	TsAgentGetHostedAll(agentId string, maxDataSize int) ([]byte, error)

	TsExtenderDataLoad(extenderName string, key string) ([]byte, error)
	TsExtenderDataSave(extenderName string, key string, value []byte) error
	TsExtenderDataDelete(extenderName string, key string) error
	TsExtenderDataKeys(extenderName string) ([]string, error)
}

type PluginListener struct{}

type Listener struct {
	transport *TransportDNS
}

type ModuleExtender struct {
	ts Teamserver
	pl *PluginListener
}

var (
	ModuleObject    *ModuleExtender
	ModuleDir       string
	ListenerDataDir string
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

func (pl *PluginListener) Create(name string, data string, listenerCustomData []byte) (ax.ExtenderListener, ax.ListenerData, []byte, error) {
	var config DNSConfig
	if err := json.Unmarshal([]byte(data), &config); err != nil {
		return nil, ax.ListenerData{}, nil, fmt.Errorf("invalid config: %v", err)
	}

	config.Protocol = "dns"
	config.Domains = splitDomains(config.Domain)

	if config.PktSize <= 0 {
		config.PktSize = defaultChunkSize
	}
	if config.TTL <= 0 {
		config.TTL = 10
	}

	transport := &TransportDNS{
		Config:          config,
		Name:            name,
		Active:          false,
		upFrags:         make(map[string]*dnsFragBuf),
		downFrags:       make(map[string]*dnsDownBuf),
		pendingCheckins: make(map[string][]byte),
		needsReset:      make(map[string]bool),
		rng:             newRng(),
	}

	listener := &Listener{transport: transport}

	listenerData := ax.ListenerData{
		Name:      name,
		Type:      "external",
		Protocol:  "dns",
		BindHost:  config.HostBind,
		BindPort:  strconv.Itoa(config.PortBind),
		AgentAddr: config.Domain,
		Status:    "Listen",
		Data:      data,
	}

	if err := transport.Start(ModuleObject.ts); err != nil {
		return nil, ax.ListenerData{}, nil, err
	}

	configBytes, _ := json.Marshal(config)
	return listener, listenerData, configBytes, nil
}

func (l *Listener) Start() error {
	return l.transport.Start(ModuleObject.ts)
}

func (l *Listener) Edit(config string) (ax.ListenerData, []byte, error) {
	return ax.ListenerData{}, nil, errors.New("edit not supported for DNS listener")
}

func (l *Listener) Stop() error {
	return l.transport.Stop()
}

func (l *Listener) GetProfile() ([]byte, error) {
	profile := map[string]interface{}{
		"protocol":      "dns",
		"host_bind":     l.transport.Config.HostBind,
		"port_bind":     l.transport.Config.PortBind,
		"domain":        l.transport.Config.Domain,
		"pkt_size":      l.transport.Config.PktSize,
		"ttl":           l.transport.Config.TTL,
		"burst_enabled": l.transport.Config.BurstEnabled,
		"burst_sleep":   l.transport.Config.BurstSleep,
		"burst_jitter":  l.transport.Config.BurstJitter,
	}
	return json.Marshal(profile)
}

func (l *Listener) InternalHandler(data []byte) (string, error) {
	return "", errors.New("not supported")
}
