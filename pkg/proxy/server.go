package proxy

import (
	"fmt"

	"github.com/jumpserver/koko/pkg/jms-sdk-go/model"
	"github.com/jumpserver/koko/pkg/jms-sdk-go/service"
	"github.com/jumpserver/koko/pkg/srvconn"
)

type ConnectionOption func(options *ConnectionOptions)

type ConnectionOptions struct {
	ProtocolType string

	user       *model.User
	systemUser *model.SystemUser

	asset  *model.Asset
	ddbApp *model.DatabaseApplication
	k8sApp *model.K8sApplication
}

func NewSessionServer(conn UserConnection, jmsService *service.JMService, opts ...ConnectionOption) (*SessionServer, error) {
	connOpts := &ConnectionOptions{}
	for _, setter := range opts {
		setter(connOpts)
	}
	switch connOpts.ProtocolType {
	case srvconn.ProtocolTELNET:
	case srvconn.ProtocolSSH:
	case srvconn.ProtocolK8s:
		if !IsInstalledKubectlClient() {

			return nil, fmt.Errorf("", "")
		}
	case srvconn.ProtocolMySQL:
		if !IsInstalledMysqlClient() {
			return nil, fmt.Errorf("", "")
		}
	default:
		return nil, fmt.Errorf("%w: %s", srvconn.ErrUnSupportedProtocol, connOpts.ProtocolType)
	}

	return &SessionServer{
		UserConn:                 nil,
		authSystemUser:           nil,
		filterRules:              nil,
		JmsService:               nil,
		CreateSessionFunc:        nil,
		ConnectedSuccessCallback: nil,
		ConnectedFailedCallback:  nil,
		DisConnectedCallback:     nil,
		FinishReplayCallback:     nil,
	}, nil
}

type SessionServer struct {
	UserConn       UserConnection
	authSystemUser *model.SystemUserAuthInfo
	filterRules    []model.SystemUserFilterRule

	JmsService *service.JMService

	CreateSessionFunc        func() error
	ConnectedSuccessCallback func() error
	ConnectedFailedCallback  func(err error) error
	DisConnectedCallback     func() error
	FinishReplayCallback     func() error
}
