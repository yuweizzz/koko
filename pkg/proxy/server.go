package proxy

import (
	"context"
	"errors"
	"fmt"
	gossh "golang.org/x/crypto/ssh"
	"net"
	"net/url"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/jumpserver/koko/pkg/common"
	"github.com/jumpserver/koko/pkg/config"
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
	ErrNoAuthInfo      = errors.New("no auth info")
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

	connOpts *ConnectionOptions

	systemUserAuthInfo *model.SystemUserAuthInfo

	filterRules    []model.SystemUserFilterRule
	terminalConf   *model.TerminalConfig
	domainGateways *model.Domain
	expireInfo     *model.ExpireInfo
	platform       *model.Platform

	cacheSSHConnection *srvconn.SSHConnection

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
		if s.checkReuseSSHClient() {
			if cacheConn, ok := s.getCacheSSHConn(); ok {
				s.cacheSSHConnection = cacheConn
				return nil
			}
		}

		if s.systemUserAuthInfo.PrivateKey == "" {
			if err := s.getAuthPasswordIfNeed(); err != nil {
				msg := utils.WrapperWarn(i18n.T("Get auth password failed"))
				utils.IgnoreErrWriteString(s.UserConn, msg)
				return err
			}
		}
	default:
		return ErrNoAuthInfo
	}
	return nil
}

const (
	linuxPlatform = "linux"
)

func (s *SessionServer) checkReuseSSHClient() bool {
	if config.GetConf().ReuseConnection {
		platformMatched := s.connOpts.asset.Platform == linuxPlatform
		protocolMatched := s.connOpts.systemUser.Protocol == model.ProtocolSSH
		return platformMatched && protocolMatched
	}
	return false
}

func (s *SessionServer) getCacheSSHConn() (srvConn *srvconn.SSHConnection, ok bool) {
	keyId := MakeReuseSSHClientKey(s.connOpts.user.ID, s.connOpts.asset.ID,
		s.connOpts.systemUser.ID, s.systemUserAuthInfo.Username)
	sshClient, ok := srvconn.GetClientFromCache(keyId)
	if !ok {
		return nil, ok
	}
	sess, err := sshClient.NewSession()
	if err != nil {
		return nil, false
	}
	pty := s.UserConn.Pty()
	cacheConn, err := srvconn.NewSSHConnection(sess, srvconn.SSHCharset(s.platform.Charset),
		srvconn.SSHPtyWin(srvconn.Windows{
			Width:  pty.Window.Width,
			Height: pty.Window.Height,
		}), srvconn.SSHTerm(pty.Term))
	if err != nil {
		_ = sess.Close()
		return nil, false
	}
	return cacheConn, true
}

func (s *SessionServer) createAvailableGateWay() (*domainGateway, error) {
	var dGateway *domainGateway
	if s.domainGateways != nil {
		switch s.connOpts.ProtocolType {
		case srvconn.ProtocolK8s:
			dstHost, dstPort, err := ParseUrlHostAndPort(s.connOpts.k8sApp.Attrs.Cluster)
			if err != nil {
				return nil, err
			}
			dGateway = &domainGateway{
				domain:  s.domainGateways,
				dstIP:   dstHost,
				dstPort: dstPort,
			}
		case srvconn.ProtocolMySQL:
			dGateway = &domainGateway{
				domain:  s.domainGateways,
				dstIP:   s.connOpts.dbApp.Attrs.Host,
				dstPort: s.connOpts.dbApp.Attrs.Port,
			}
		default:

		}
	}
	return dGateway, nil
}

// getSSHConn 获取ssh连接
func (s *SessionServer) getK8sConConn(localTunnelAddr *net.TCPAddr) (srvConn *srvconn.K8sCon, err error) {
	clusterServer := s.connOpts.k8sApp.Attrs.Cluster
	if localTunnelAddr != nil {
		originUrl, err := url.Parse(clusterServer)
		if err != nil {
			return nil, err
		}
		clusterServer = ReplaceURLHostAndPort(originUrl, "127.0.0.1", localTunnelAddr.Port)
	}
	srvConn, err = srvconn.NewK8sConnection(
		srvconn.K8sToken(s.systemUserAuthInfo.Token),
		srvconn.K8sClusterServer(clusterServer),
		srvconn.K8sUsername(s.systemUserAuthInfo.Username),
		srvconn.K8sSkipTls(true),
		srvconn.K8sPtyWin(srvconn.Windows{
			Width:  s.UserConn.Pty().Window.Width,
			Height: s.UserConn.Pty().Window.Height,
		}),
	)
	return
}

func (s *SessionServer) getMysqlConn(localTunnelAddr *net.TCPAddr) (srvConn *srvconn.MySQLConn, err error) {
	host := s.connOpts.dbApp.Attrs.Host
	port := s.connOpts.dbApp.Attrs.Port
	if localTunnelAddr != nil {
		host = "127.0.0.1"
		port = localTunnelAddr.Port
	}
	srvConn, err = srvconn.NewMySQLConnection(
		srvconn.SqlHost(host),
		srvconn.SqlPort(port),
		srvconn.SqlUsername(s.systemUserAuthInfo.Username),
		srvconn.SqlPassword(s.systemUserAuthInfo.Password),
		srvconn.SqlDBName(s.connOpts.dbApp.Attrs.Database),
		srvconn.SqlPtyWin(srvconn.Windows{
			Width:  s.UserConn.Pty().Window.Width,
			Height: s.UserConn.Pty().Window.Height,
		}),
	)
	return
}

func (s *SessionServer) getSSHConn() (srvConn *srvconn.SSHConnection, err error) {
	key := MakeReuseSSHClientKey(s.connOpts.user.ID, s.connOpts.asset.ID, s.systemUserAuthInfo.ID,
		s.systemUserAuthInfo.Username)
	timeout := config.GlobalConfig.SSHTimeout
	sshAuthOpts := make([]srvconn.SSHClientOption, 0, 6)
	sshAuthOpts = append(sshAuthOpts, srvconn.SSHClientUsername(s.systemUserAuthInfo.Username))
	sshAuthOpts = append(sshAuthOpts, srvconn.SSHClientHost(s.connOpts.asset.IP))
	sshAuthOpts = append(sshAuthOpts, srvconn.SSHClientPort(s.connOpts.asset.ProtocolPort(s.systemUserAuthInfo.Protocol)))
	sshAuthOpts = append(sshAuthOpts, srvconn.SSHClientPassword(s.systemUserAuthInfo.Password))
	sshAuthOpts = append(sshAuthOpts, srvconn.SSHClientTimeout(timeout))
	if s.systemUserAuthInfo.PrivateKey != "" {
		// 先使用 password 解析 PrivateKey
		if signer, err1 := gossh.ParsePrivateKeyWithPassphrase([]byte(s.systemUserAuthInfo.PrivateKey),
			[]byte(s.systemUserAuthInfo.Password)); err1 == nil {
			sshAuthOpts = append(sshAuthOpts, srvconn.SSHClientPrivateAuth(signer))
		} else {
			// 如果之前使用password解析失败，则去掉 password, 尝试直接解析 PrivateKey 防止错误的passphrase
			if signer, err1 = gossh.ParsePrivateKey([]byte(s.systemUserAuthInfo.PrivateKey)); err1 == nil {
				sshAuthOpts = append(sshAuthOpts, srvconn.SSHClientPrivateAuth(signer))
			}
		}
	}
	if s.domainGateways != nil {
		proxyArgs := make([]srvconn.SSHClientOptions, 0, len(s.domainGateways.Gateways))
		for i := range s.domainGateways.Gateways {
			gateway := s.domainGateways.Gateways[i]
			proxyArg := srvconn.SSHClientOptions{
				Host:       gateway.IP,
				Port:       strconv.Itoa(gateway.Port),
				Username:   gateway.Username,
				Password:   gateway.Password,
				PrivateKey: gateway.PrivateKey,
				Timeout:    timeout,
			}
			proxyArgs = append(proxyArgs, proxyArg)
		}
		sshAuthOpts = append(sshAuthOpts, srvconn.SSHClientProxyClient(proxyArgs...))
	}
	sshClient, err := srvconn.NewSSHClient(sshAuthOpts...)
	if err != nil {
		logger.Errorf("Get new SSH client err: %s", err)
		return nil, err
	}
	sess, err := sshClient.NewSession()
	if err != nil {
		logger.Errorf("SSH client(%s) start sftp client session err %s", sshClient, err)
		_ = sshClient.Close()
		return nil, err
	}
	if config.GetConf().ReuseConnection {
		srvconn.AddClientCache(key, sshClient)
	}
	pty := s.UserConn.Pty()
	sshConn, err := srvconn.NewSSHConnection(sess, srvconn.SSHCharset(s.platform.Charset),
		srvconn.SSHPtyWin(srvconn.Windows{
			Width:  pty.Window.Width,
			Height: pty.Window.Height,
		}), srvconn.SSHTerm(pty.Term))
	if err != nil {
		_ = sess.Close()
		return nil, err
	}
	return sshConn, nil

}

func (s *SessionServer) getTelnetConn() (srvConn *srvconn.TelnetConnection, err error) {
	telnetOpts := make([]srvconn.TelnetOption, 0, 8)
	timeout := config.GlobalConfig.SSHTimeout
	pty := s.UserConn.Pty()
	cusString := s.terminalConf.TelnetRegex
	if cusString != "" {
		successPattern, err2 := regexp.Compile(cusString)
		if err2 != nil {
			logger.Errorf("Conn[%s] telnet custom regex %s compile err: %s",
				s.UserConn.ID(), cusString, err)
			return nil, err2
		}
		telnetOpts = append(telnetOpts, srvconn.TelnetCustomSuccessPattern(successPattern))
	}

	telnetOpts = append(telnetOpts, srvconn.TelnetHost(s.connOpts.asset.IP))
	telnetOpts = append(telnetOpts, srvconn.TelnetPort(s.connOpts.asset.ProtocolPort(s.systemUserAuthInfo.Protocol)))
	telnetOpts = append(telnetOpts, srvconn.TelnetUsername(s.systemUserAuthInfo.Username))
	telnetOpts = append(telnetOpts, srvconn.TelnetUPassword(s.systemUserAuthInfo.Password))
	telnetOpts = append(telnetOpts, srvconn.TelnetUTimeout(timeout))
	telnetOpts = append(telnetOpts, srvconn.TelnetPtyWin(srvconn.Windows{
		Width:  pty.Window.Width,
		Height: pty.Window.Height,
	}))
	telnetOpts = append(telnetOpts, srvconn.TelnetCharset(s.platform.Charset))
	if s.domainGateways != nil {
		proxyArgs := make([]srvconn.SSHClientOptions, 0, len(s.domainGateways.Gateways))
		for i := range s.domainGateways.Gateways {
			gateway := s.domainGateways.Gateways[i]
			proxyArg := srvconn.SSHClientOptions{
				Host:       gateway.IP,
				Port:       strconv.Itoa(gateway.Port),
				Username:   gateway.Username,
				Password:   gateway.Password,
				PrivateKey: gateway.PrivateKey,
				Timeout:    timeout,
			}
			proxyArgs = append(proxyArgs, proxyArg)
		}
		telnetOpts = append(telnetOpts, srvconn.TelnetProxyOptions(proxyArgs))
	}
	//telnetConn, err := srvconn.NewTelnetConnection(telnetOpts...)
	return srvconn.NewTelnetConnection(telnetOpts...)
}
func (s *SessionServer) getServerConn(proxyAddr *net.TCPAddr) (srvconn.ServerConnection, error) {

	switch s.connOpts.ProtocolType {
	case srvconn.ProtocolSSH:
		if s.cacheSSHConnection != nil {
			return s.cacheSSHConnection, nil
		}
		return s.getSSHConn()
	case srvconn.ProtocolTELNET:
		return s.getTelnetConn()
	case srvconn.ProtocolK8s:
		return s.getK8sConConn(proxyAddr)
	case srvconn.ProtocolMySQL:
		return s.getMysqlConn(proxyAddr)
	default:
		return nil, ErrUnMatchProtocol
	}
}

func (s *SessionServer) Proxy() {
	if err := s.checkRequiredAuth(); err != nil {
		logger.Errorf("Conn[%s]: check basic auth failed: %s", s.UserConn.ID(), err)
		return
	}
	defer func() {
		if s.cacheSSHConnection != nil {
			_ = s.cacheSSHConnection.Close()
		}
	}()
	ctx, cancel := context.WithCancel(s.UserConn.Context())
	sw := commonSwitch{
		ID:            s.ID,
		MaxIdleTime:   s.terminalConf.MaxIdleTime,
		keepAliveTime: 60,
		ctx:           ctx,
		cancel:        cancel,
		p:             s,
	}
	if err := s.CreateSessionCallback(); err != nil {
		msg := i18n.T("Connect with api server failed")
		msg = utils.WrapperWarn(msg)
		utils.IgnoreErrWriteString(s.UserConn, msg)
		logger.Errorf("Conn[%s] submit session %s to core server err: %s",
			s.UserConn.ID(), s.ID, msg)
		return
	}
	AddCommonSwitch(&sw)
	defer RemoveCommonSwitch(&sw)

	var proxyAddr *net.TCPAddr
	if s.domainGateways != nil {
		switch s.connOpts.ProtocolType {
		case srvconn.ProtocolMySQL, srvconn.ProtocolK8s:
			dGateway, err := s.createAvailableGateWay()
			if err != nil {
				logger.Error(err)
				return
			}
			err = dGateway.Start()
			if err != nil {
				logger.Error(err)
				return
			}
			defer dGateway.Stop()
			proxyAddr = dGateway.GetListenAddr()
		default:
		}
	}

	srvCon, err := s.getServerConn(proxyAddr)
	if err != nil {
		logger.Error(err)
		s.sendConnectErrorMsg(err)
		return
	}
	logger.Infof("Conn[%s] create session %s success", s.UserConn.ID(), s.ID)
	utils.IgnoreErrWriteWindowTitle(s.UserConn, s.connOpts.TerminalTitle())
	if err = sw.Bridge(s.UserConn, srvCon); err != nil {
		logger.Error(err)
	}
}

func (s *SessionServer) sendConnectErrorMsg(err error) {
	msg := fmt.Sprintf("Connect K8s %s error: %s\r\n", s.connOpts.k8sApp.Attrs.Cluster, err)
	utils.IgnoreErrWriteString(s.UserConn, msg)
	logger.Error(msg)
	token := s.systemUserAuthInfo.Token
	if token != "" {
		tokenLen := len(token)
		showLen := tokenLen / 2
		hiddenLen := tokenLen - showLen
		msg2 := fmt.Sprintf("Try token: %s", token[:showLen]+strings.Repeat("*", hiddenLen))
		logger.Errorf(msg2)
	}
}

func MakeReuseSSHClientKey(userId, assetId, sysUserId, username string) string {
	return fmt.Sprintf("%s_%s_%s_%s", userId, assetId, sysUserId, username)
}

func ParseUrlHostAndPort(clusterAddr string) (host string, port int, err error) {
	clusterUrl, err := url.Parse(clusterAddr)
	if err != nil {
		return "", 0, err
	}
	// URL host 是包含port的结果
	hostAndPort := strings.Split(clusterUrl.Host, ":")
	var (
		dstHost string
		dstPort int
	)
	dstHost = hostAndPort[0]
	switch len(hostAndPort) {
	case 2:
		dstPort, err = strconv.Atoi(hostAndPort[1])
		if err != nil {
			return "", 0, fmt.Errorf("%w: %s", ErrInvalidPort, err)
		}
	default:
		switch clusterUrl.Scheme {
		case "https":
			dstPort = 443
		default:
			dstPort = 80
		}
	}
	return dstHost, dstPort, nil
}

var ErrInvalidPort = errors.New("invalid port")
