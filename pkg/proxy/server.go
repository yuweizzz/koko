package proxy

import (
	"errors"
	"fmt"
	"time"

	"github.com/jumpserver/koko/pkg/common"
	"github.com/jumpserver/koko/pkg/i18n"
	"github.com/jumpserver/koko/pkg/jms-sdk-go/model"
	"github.com/jumpserver/koko/pkg/jms-sdk-go/service"
	"github.com/jumpserver/koko/pkg/logger"
	"github.com/jumpserver/koko/pkg/srvconn"
	"github.com/jumpserver/koko/pkg/utils"
)

type ConnectionOption func(options *ConnectionOptions)

type ConnectionOptions struct {
	ProtocolType string

	user       *model.User
	systemUser *model.SystemUser

	asset  *model.Asset
	dbApp  *model.DatabaseApplication
	k8sApp *model.K8sApplication
}

func (opts ConnectionOptions) TerminalTitle() string {
	title := ""
	switch opts.ProtocolType {
	case srvconn.ProtocolTELNET,
		srvconn.ProtocolSSH:
		title = fmt.Sprintf("%s://%s@%s",
			opts.ProtocolType,
			opts.systemUser.Username,
			opts.asset.IP)
	case srvconn.ProtocolMySQL:
		title = fmt.Sprintf("%s://%s@%s",
			opts.ProtocolType,
			opts.systemUser.Username,
			opts.dbApp.Attrs.Host)
	case srvconn.ProtocolK8s:
		title = fmt.Sprintf("%s+%s",
			opts.ProtocolType,
			opts.k8sApp.Attrs.Cluster)
	}
	return title
}

var (
	ErrMissClient      = errors.New("the protocol client has not installed")
	ErrUnMatchProtocol = errors.New("the protocols are not matched")
	ErrAPIFailed       = errors.New("api failed")
	ErrPermission      = errors.New("no permission")
)

/*
	简单校验：
		资产协议是否匹配

	API 相关
		1. 获取 系统用户 的 Auth info--> 获取认证信息 ok
		2. 获取 授权的 上传下载权限---> 校验权限
		3. 获取需要的domain---> 网关信息
		4. 获取需要的过滤规则---> 获取命令过滤
		5. 获取当前的终端配置，（录像和命令存储配置)
		6. 获取授权的过期时间 --> 授权
*/

func NewSessionServer(conn UserConnection, jmsService *service.JMService, opts ...ConnectionOption) (*SessionServer, error) {
	connOpts := &ConnectionOptions{}
	for _, setter := range opts {
		setter(connOpts)
	}

	terminalConf, err := jmsService.GetTerminalConfig()
	if err != nil {
		return nil, fmt.Errorf("%w: %s", ErrAPIFailed, err)
	}
	filterRules, err := jmsService.GetSystemUserFilterRules(connOpts.systemUser.ID)
	if err != nil {
		return nil, fmt.Errorf("%w: %s", ErrAPIFailed, err)
	}
	var (
		apiSession *model.Session

		sysUserAuthInfo *model.SystemUserAuthInfo
		domainGateways  *model.Domain
		expireInfo      *model.ExpireInfo
		//commandParser   ParseEngine
	)

	switch connOpts.ProtocolType {
	case srvconn.ProtocolTELNET, srvconn.ProtocolSSH:
		if !connOpts.asset.IsSupportProtocol(connOpts.systemUser.Protocol) {
			msg := i18n.T("System user <%s> and asset <%s> protocol are inconsistent.")
			msg = fmt.Sprintf(msg, connOpts.systemUser.Username, connOpts.asset.Hostname)
			utils.IgnoreErrWriteString(conn, utils.WrapperWarn(msg))
			return nil, fmt.Errorf("%w: %s", ErrUnMatchProtocol, msg)
		}

		authInfo, err := jmsService.GetSystemUserAuthById(connOpts.systemUser.ID, connOpts.asset.ID,
			connOpts.user.ID, connOpts.user.Username)
		if err != nil {
			return nil, fmt.Errorf("%w: %s", ErrAPIFailed, err)
		}
		sysUserAuthInfo = &authInfo

		if connOpts.asset.Domain != "" {
			domain, err := jmsService.GetDomainGateways(connOpts.asset.Domain)
			if err != nil {
				return nil, fmt.Errorf("%w: %s", ErrAPIFailed, err)
			}
			domainGateways = &domain
		}

		expireInfo, err := jmsService.ValidateAssetConnectPermission(connOpts.user.ID,
			connOpts.asset.ID, connOpts.systemUser.ID)
		if err != nil {
			return nil, fmt.Errorf("%w: %s", ErrAPIFailed, err)
		}
		if !expireInfo.HasPermission {
			return nil, ErrPermission
		}

		apiSession = &model.Session{
			ID:           common.UUID(),
			User:         connOpts.user.String(),
			SystemUser:   connOpts.systemUser.String(),
			LoginFrom:    conn.LoginFrom(),
			RemoteAddr:   conn.RemoteAddr(),
			Protocol:     connOpts.systemUser.Protocol,
			UserID:       connOpts.user.ID,
			SystemUserID: connOpts.systemUser.ID,
			Asset:        connOpts.asset.String(),
			AssetID:      connOpts.asset.ID,
			OrgID:        connOpts.asset.OrgID,
		}
	case srvconn.ProtocolK8s:
		if !IsInstalledKubectlClient() {
			msg := i18n.T("%s protocol client not installed.")
			msg = fmt.Sprintf(msg, connOpts.k8sApp.TypeName)
			utils.IgnoreErrWriteString(conn, utils.WrapperWarn(msg))
			logger.Errorf("Conn[%s] %s", conn.ID(), msg)
			return nil, fmt.Errorf("%w: %s", ErrMissClient, connOpts.ProtocolType)
		}
		authInfo, err := jmsService.GetUserApplicationAuthInfo(connOpts.systemUser.ID, connOpts.k8sApp.ID,
			connOpts.user.ID, connOpts.user.Username)
		if err != nil {
			return nil, fmt.Errorf("%w: %s", ErrAPIFailed, err)
		}
		sysUserAuthInfo = &authInfo
		if connOpts.k8sApp.Domain != "" {
			domain, err := jmsService.GetDomainGateways(connOpts.k8sApp.Domain)
			if err != nil {
				return nil, fmt.Errorf("%w: %s", ErrAPIFailed, err)
			}
			domainGateways = &domain
		}
		apiSession = &model.Session{
			ID:           common.UUID(),
			User:         connOpts.user.String(),
			SystemUser:   connOpts.systemUser.String(),
			LoginFrom:    conn.LoginFrom(),
			RemoteAddr:   conn.RemoteAddr(),
			Protocol:     connOpts.systemUser.Protocol,
			SystemUserID: connOpts.systemUser.ID,
			UserID:       connOpts.user.ID,
			Asset:        connOpts.k8sApp.Name,
			AssetID:      connOpts.k8sApp.ID,
			OrgID:        connOpts.k8sApp.OrgID,
		}
	case srvconn.ProtocolMySQL:
		if !IsInstalledMysqlClient() {
			msg := i18n.T("Database %s protocol client not installed.")
			msg = fmt.Sprintf(msg, connOpts.dbApp.TypeName)
			utils.IgnoreErrWriteString(conn, utils.WrapperWarn(msg))
			logger.Errorf("Conn[%s] %s", conn.ID(), msg)
			return nil, fmt.Errorf("%w: %s", ErrMissClient, connOpts.ProtocolType)
		}
		authInfo, err := jmsService.GetUserApplicationAuthInfo(connOpts.systemUser.ID, connOpts.dbApp.ID,
			connOpts.user.ID, connOpts.user.Username)
		if err != nil {
			return nil, fmt.Errorf("%w: %s", ErrAPIFailed, err)
		}
		sysUserAuthInfo = &authInfo
		if connOpts.dbApp.Domain != "" {
			domain, err := jmsService.GetDomainGateways(connOpts.dbApp.Domain)
			if err != nil {
				return nil, err
			}
			domainGateways = &domain
		}

		expirePermInfo, err := jmsService.ValidateApplicationPermission(connOpts.user.ID, connOpts.dbApp.ID, connOpts.systemUser.ID)
		if err != nil {
			return nil, fmt.Errorf("%w: %s", ErrAPIFailed, err)
		}
		expireInfo = &expirePermInfo
		apiSession = &model.Session{
			ID:           common.UUID(),
			User:         connOpts.user.String(),
			SystemUser:   connOpts.systemUser.String(),
			LoginFrom:    conn.LoginFrom(),
			RemoteAddr:   conn.RemoteAddr(),
			Protocol:     connOpts.systemUser.Protocol,
			UserID:       connOpts.user.ID,
			SystemUserID: connOpts.systemUser.ID,
			Asset:        connOpts.dbApp.Name,
			AssetID:      connOpts.dbApp.ID,
			OrgID:        connOpts.dbApp.OrgID,
		}
	default:
		msg := i18n.T("Terminal only support protocol ssh/telnet, please use web terminal to access")
		msg = utils.WrapperWarn(msg)
		utils.IgnoreErrWriteString(conn, msg)
		logger.Errorf("Conn[%s] checking requisite failed: %s", conn.ID(), msg)
		return nil, fmt.Errorf("%w: `%s`", srvconn.ErrUnSupportedProtocol, connOpts.ProtocolType)
	}

	return &SessionServer{
		UserConn:   conn,
		jmsService: jmsService,

		authSystemUser: sysUserAuthInfo,
		filterRules:    filterRules,
		terminalConf:   &terminalConf,
		domainGateways: domainGateways,
		expireInfo:     expireInfo,
		CreateSessionCallback: func() error {
			return jmsService.CreateSession(*apiSession)
		},
		ConnectedSuccessCallback: func() error {
			return jmsService.SessionSuccess(apiSession.ID)
		},
		ConnectedFailedCallback: func(err error) error {
			return jmsService.SessionFailed(apiSession.ID, err)
		},
		DisConnectedCallback: func() error {
			return jmsService.SessionDisconnect(apiSession.ID)
		},
		FinishReplayCallback: func() error {
			return jmsService.FinishReply(apiSession.ID)
		},
	}, nil
}

type SessionServer struct {
	UserConn   UserConnection
	jmsService *service.JMService

	connOpts *ConnectionOptions

	authSystemUser *model.SystemUserAuthInfo
	filterRules    []model.SystemUserFilterRule
	terminalConf   *model.TerminalConfig
	domainGateways *model.Domain
	expireInfo     *model.ExpireInfo
	platform       *model.Platform

	CreateSessionCallback    func() error
	ConnectedSuccessCallback func() error
	ConnectedFailedCallback  func(err error) error
	DisConnectedCallback     func() error
	FinishReplayCallback     func() error
}

func (s *SessionServer) CheckPermissionExpired(now time.Time) bool {
	return s.expireInfo.ExpireAt < now.Unix()
}

func (s *SessionServer) GetFilterParser() ParseEngine {
	return nil
}

func (s *SessionServer)GenerateRecordCommand(){

}

func (s *SessionServer) Proxy() {

}
