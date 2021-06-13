package koko

import (
	"github.com/jumpserver/koko/pkg/jms-sdk-go/model"
	"github.com/jumpserver/koko/pkg/jms-sdk-go/service"
	"github.com/jumpserver/koko/pkg/logger"
	"github.com/jumpserver/koko/pkg/srvconn"
	"sync"
	"time"
)

type Application struct {
	terminalConf *model.TerminalConfig
	jmsService   *service.JMService
	sync.Mutex

	vscodeClients map[string]*vscodeReq
}

func (a *Application) run() {
	for {
		time.Sleep(time.Minute)
		conf, err := a.jmsService.GetTerminalConfig()
		if err != nil {
			logger.Errorf("Update terminal config failed: %s", err)
			continue
		}
		a.UpdateTerminalConfig(conf)
	}
}

func (a *Application) UpdateTerminalConfig(conf model.TerminalConfig) {
	a.Lock()
	defer a.Unlock()
	a.terminalConf = &conf
}

func (a *Application) GetTerminalConfig() model.TerminalConfig {
	a.Lock()
	defer a.Unlock()
	return *a.terminalConf
}

func (a *Application) getVSCodeReq(reqId string) *vscodeReq {
	a.Lock()
	defer a.Unlock()
	return a.vscodeClients[reqId]
}

func (a *Application) addVSCodeReq(vsReq *vscodeReq) {
	a.Lock()
	defer a.Unlock()
	a.vscodeClients[vsReq.reqId] = vsReq
}

func (a *Application) deleteVSCodeReq(vsReq *vscodeReq) {
	delete(a.vscodeClients, vsReq.reqId)
}

type vscodeReq struct {
	reqId  string
	client *srvconn.SSHClient
}
