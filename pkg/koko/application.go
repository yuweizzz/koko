package koko

import (
	"github.com/jumpserver/koko/pkg/jms-sdk-go/model"
	"github.com/jumpserver/koko/pkg/jms-sdk-go/service"
	"github.com/jumpserver/koko/pkg/logger"
	"sync"
	"time"
)

type Application struct {
	terminalConf *model.TerminalConfig
	jmsService   *service.JMService
	sync.Mutex
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
