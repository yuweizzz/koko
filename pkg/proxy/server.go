package proxy

import (
	"errors"
	"fmt"
	"github.com/jumpserver/koko/pkg/config"
	"sort"
	"strings"
	"time"

	"github.com/jumpserver/koko/pkg/common"
	"github.com/jumpserver/koko/pkg/exchange"
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
		1. 获取 系统用户 的 Auth info--> 获取认证信息
		2. 获取 授权权限---> 校验权限
		3. 获取需要的domain---> 网关信息
		4. 获取需要的过滤规则---> 获取命令过滤
		5. 获取当前的终端配置，（录像和命令存储配置)
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
	// 过滤规则排序
	sort.Sort(model.FilterRules(filterRules))
	var (
		apiSession *model.Session

		sysUserAuthInfo *model.SystemUserAuthInfo
		domainGateways  *model.Domain
		expireInfo      *model.ExpireInfo
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

		permInfo, err := jmsService.ValidateAssetConnectPermission(connOpts.user.ID,
			connOpts.asset.ID, connOpts.systemUser.ID)
		if err != nil {
			return nil, fmt.Errorf("%w: %s", ErrAPIFailed, err)
		}
		expireInfo = &permInfo
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
		permInfo, err := jmsService.ValidateRemoteAppPermission(connOpts.user.ID,
			connOpts.k8sApp.ID, connOpts.systemUser.ID)
		if err != nil {
			return nil, fmt.Errorf("%w: %s", ErrAPIFailed, err)
		}
		expireInfo = &permInfo
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

	if !expireInfo.HasPermission {
		return nil, ErrPermission
	}

	return &SessionServer{
		ID:         apiSession.ID,
		UserConn:   conn,
		jmsService: jmsService,

		systemUserAuthInfo: sysUserAuthInfo,

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
	}, nil
}

type SessionServer struct {
	ID         string
	UserConn   UserConnection
	jmsService *service.JMService

	manager exchange.RoomManager

	connOpts *ConnectionOptions

	systemUserAuthInfo *model.SystemUserAuthInfo

	filterRules    []model.SystemUserFilterRule
	terminalConf   *model.TerminalConfig
	domainGateways *model.Domain
	expireInfo     *model.ExpireInfo
	platform       *model.Platform

	CreateSessionCallback    func() error
	ConnectedSuccessCallback func() error
	ConnectedFailedCallback  func(err error) error
	DisConnectedCallback     func() error
}

func (s *SessionServer) CheckPermissionExpired(now time.Time) bool {
	return s.expireInfo.ExpireAt < now.Unix()
}

func (s *SessionServer) GetFilterParser() ParseEngine {
	switch s.connOpts.ProtocolType {
	case srvconn.ProtocolSSH,
		srvconn.ProtocolTELNET, srvconn.ProtocolK8s:
		shellParser := Parser{
			id:             s.ID,
			protocolType:   s.connOpts.ProtocolType,
			jmsService:     s.jmsService,
			cmdFilterRules: s.filterRules,
		}
		shellParser.initial()
		return &shellParser
	case srvconn.ProtocolMySQL:
		dbParser := DBParser{
			id:             s.ID,
			cmdFilterRules: s.filterRules,
		}
		dbParser.initial()
		return &dbParser
	}
	return nil
}

func (s *SessionServer) GetReplayRecorder() *ReplyRecorder {

	return nil
}

func (s *SessionServer) GetCommandRecorder() *CommandRecorder {

	return nil
}

func (s *SessionServer) GenerateCommandItem(input, output string,
	riskLevel int64, createdDate time.Time) *model.Command {
	switch s.connOpts.ProtocolType {
	case srvconn.ProtocolTELNET, srvconn.ProtocolSSH:
		return &model.Command{
			SessionID:   s.ID,
			OrgID:       s.connOpts.asset.OrgID,
			User:        s.connOpts.user.String(),
			Server:      s.connOpts.asset.Hostname,
			SystemUser:  s.connOpts.systemUser.String(),
			Input:       input,
			Output:      output,
			Timestamp:   createdDate.Unix(),
			RiskLevel:   riskLevel,
			DateCreated: createdDate.UTC(),
		}

	case srvconn.ProtocolMySQL:
		return &model.Command{
			SessionID:   s.ID,
			OrgID:       s.connOpts.dbApp.OrgID,
			User:        s.connOpts.user.String(),
			Server:      s.connOpts.dbApp.Name,
			SystemUser:  s.connOpts.systemUser.String(),
			Input:       input,
			Output:      output,
			Timestamp:   createdDate.Unix(),
			RiskLevel:   riskLevel,
			DateCreated: createdDate.UTC(),
		}

	case srvconn.ProtocolK8s:
		return &model.Command{
			SessionID: s.ID,
			OrgID:     s.connOpts.k8sApp.OrgID,
			User:      s.connOpts.user.String(),
			Server: fmt.Sprintf("%s(%s)", s.connOpts.k8sApp.Name,
				s.connOpts.k8sApp.Attrs.Cluster),
			SystemUser:  s.connOpts.systemUser.String(),
			Input:       input,
			Output:      output,
			Timestamp:   createdDate.Unix(),
			RiskLevel:   riskLevel,
			DateCreated: createdDate.UTC(),
		}
	}
	return nil
}

func (s *SessionServer) getUsernameIfNeed() (err error) {
	if s.systemUserAuthInfo.Username == "" {
		logger.Infof("Conn[%s] need manuel input system user username", s.UserConn.ID())
		var username string
		term := utils.NewTerminal(s.UserConn, "username: ")
		for {
			username, err = term.ReadLine()
			if err != nil {
				return err
			}
			username = strings.TrimSpace(username)
			if username != "" {
				break
			}
		}
		s.systemUserAuthInfo.Username = username
		logger.Infof("Conn[%s] get username from user input: %s", s.UserConn.ID(), username)
	}
	return
}

func (s *SessionServer) getAuthPasswordIfNeed() (err error) {
	if s.systemUserAuthInfo.Password == "" {
		term := utils.NewTerminal(s.UserConn, "password: ")
		line, err := term.ReadPassword(fmt.Sprintf("%s's password: ", s.systemUserAuthInfo.Username))
		if err != nil {
			logger.Errorf("Conn[%s] get password from user err: %s", s.UserConn.ID(), err.Error())
			return err
		}
		s.systemUserAuthInfo.Password = line
		logger.Infof("Conn[%s] get password from user input", s.UserConn.ID())
	}
	return nil
}

func (s *SessionServer) checkRequiredAuth() error {
	switch s.connOpts.ProtocolType {
	case srvconn.ProtocolK8s:
		if s.systemUserAuthInfo.Token == "" {
			msg := utils.WrapperWarn(i18n.T("You get auth token failed"))
			utils.IgnoreErrWriteString(s.UserConn, msg)
			return errors.New("no auth token")
		}
	case srvconn.ProtocolMySQL, srvconn.ProtocolTELNET:
		if err := s.getUsernameIfNeed(); err != nil {
			msg := utils.WrapperWarn(i18n.T("Get auth username failed"))
			utils.IgnoreErrWriteString(s.UserConn, msg)
			return fmt.Errorf("get auth username failed: %s", err)
		}
		if err := s.getAuthPasswordIfNeed(); err != nil {
			msg := utils.WrapperWarn(i18n.T("Get auth password failed"))
			utils.IgnoreErrWriteString(s.UserConn, msg)
			return fmt.Errorf("get auth password failed: %s", err)
		}
	case srvconn.ProtocolSSH:
		if err := s.getUsernameIfNeed(); err != nil {
			msg := utils.WrapperWarn(i18n.T("Get auth username failed"))
			utils.IgnoreErrWriteString(s.UserConn, msg)
			return err
		}
		// todo: 获取复用的 SSHClient
		if s.checkRequireReuseClient() {

		}

		if s.systemUserAuthInfo.PrivateKey == "" {
			if err := s.getAuthPasswordIfNeed(); err != nil {
				msg := utils.WrapperWarn(i18n.T("Get auth password failed"))
				utils.IgnoreErrWriteString(s.UserConn, msg)
				return err
			}
		}
	default:
		return errors.New("no auth info")
	}
	return nil
}

const (
	linuxPlatform = "linux"
)

func (s *SessionServer) checkRequireReuseClient() bool {
	if config.GetConf().ReuseConnection {
		platformMatched := s.connOpts.asset.Platform == linuxPlatform
		protocolMatched := s.connOpts.systemUser.Protocol == model.ProtocolSSH
		return platformMatched && protocolMatched
	}
	return false
}

func (s *SessionServer) getCacheSSHConn() (srvConn *srvconn.SSHConnection, ok bool) {
	keyId := MakeReuseSSHClientKey(s.connOpts.user.ID, s.connOpts.asset.ID,
		s.connOpts.systemUser.ID, s.systemUserAuthInfo.Username, s.connOpts.asset.IP)
	srvconn.GetClientFromCache(keyId)

	return
}

func (s *SessionServer) Proxy() {
	if err := s.checkRequiredAuth(); err != nil {
		logger.Errorf("Conn[%s]: check basic auth failed: %s", s.UserConn.ID(), err)
		return
	}

	if err := s.CreateSessionCallback(); err != nil {
		msg := i18n.T("Connect with api server failed")
		msg = utils.WrapperWarn(msg)
		utils.IgnoreErrWriteString(s.UserConn, msg)
		logger.Errorf("Conn[%s] submit session %s to core server err: %s",
			s.UserConn.ID(), s.ID, msg)
		return
	}
	logger.Infof("Conn[%s] create session %s success", s.UserConn.ID(), s.ID)

	utils.IgnoreErrWriteWindowTitle(s.UserConn, s.connOpts.TerminalTitle())

}

func MakeReuseSSHClientKey(userId, assetId, sysUserId, username, ip string) string {
	return fmt.Sprintf("%s_%s_%s_%s_%s", userId, assetId, sysUserId, username, ip)
}
