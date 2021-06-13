package koko

import (
	"fmt"
	"io"
	"net"
	"strconv"

	"github.com/gliderlabs/ssh"
	"github.com/pkg/sftp"
	gossh "golang.org/x/crypto/ssh"

	"github.com/jumpserver/koko/pkg/auth"
	"github.com/jumpserver/koko/pkg/common"
	"github.com/jumpserver/koko/pkg/config"
	"github.com/jumpserver/koko/pkg/handler"
	"github.com/jumpserver/koko/pkg/i18n"
	"github.com/jumpserver/koko/pkg/jms-sdk-go/model"
	"github.com/jumpserver/koko/pkg/logger"
	"github.com/jumpserver/koko/pkg/srvconn"
	"github.com/jumpserver/koko/pkg/sshd"
	"github.com/jumpserver/koko/pkg/utils"
)

const (
	nextAuthMethod = "keyboard-interactive"
)

func (a *Application) GetSSHAddr() string {
	cf := config.GlobalConfig
	return net.JoinHostPort(cf.BindHost, cf.SSHPort)
}
func (a *Application) GetSSHSigner() ssh.Signer {
	conf := a.GetTerminalConfig()
	singer, err := sshd.ParsePrivateKeyFromString(conf.HostKey)
	if err != nil {
		logger.Fatal(err)
	}
	return singer
}

func (a *Application) KeyboardInteractiveAuth(ctx ssh.Context,
	challenger gossh.KeyboardInteractiveChallenge) sshd.AuthStatus {
	return auth.SSHKeyboardInteractiveAuth(ctx, challenger)
}

const ctxID = "ctxID"

func (a *Application) PasswordAuth(ctx ssh.Context, password string) sshd.AuthStatus {
	ctx.SetValue(ctxID, ctx.SessionID())
	tConfig := a.GetTerminalConfig()
	if !tConfig.PasswordAuth {
		logger.Info("Core API disable password auth auth")
		return sshd.AuthFailed
	}
	sshAuthHandler := auth.SSHPasswordAndPublicKeyAuth(a.jmsService)
	return sshAuthHandler(ctx, password, "")
}

func (a *Application) PublicKeyAuth(ctx ssh.Context, key ssh.PublicKey) sshd.AuthStatus {
	ctx.SetValue(ctxID, ctx.SessionID())
	tConfig := a.GetTerminalConfig()
	if !tConfig.PublicKeyAuth {
		logger.Info("Core API disable publickey auth")
		return sshd.AuthFailed
	}
	publicKey := common.Base64Encode(string(key.Marshal()))
	sshAuthHandler := auth.SSHPasswordAndPublicKeyAuth(a.jmsService)
	return sshAuthHandler(ctx, "", publicKey)
}

func (a *Application) NextAuthMethodsHandler(ctx ssh.Context) []string {
	return []string{nextAuthMethod}
}

func (a *Application) SFTPHandler(sess ssh.Session) {
	currentUser, ok := sess.Context().Value(auth.ContextKeyUser).(*model.User)
	if !ok || currentUser.ID == "" {
		logger.Errorf("SFTP User not found, exit.")
		return
	}
	host, _, _ := net.SplitHostPort(sess.RemoteAddr().String())
	userSftp := handler.NewSFTPHandler(a.jmsService, currentUser, host)
	handlers := sftp.Handlers{
		FileGet:  userSftp,
		FilePut:  userSftp,
		FileCmd:  userSftp,
		FileList: userSftp,
	}
	reqID := common.UUID()
	logger.Infof("SFTP request %s: Handler start", reqID)
	req := sftp.NewRequestServer(sess, handlers)
	if err := req.Serve(); err == io.EOF {
		logger.Debugf("SFTP request %s: Exited session.", reqID)
	} else if err != nil {
		logger.Errorf("SFTP request %s: Server completed with error %s", reqID, err)
	}
	_ = req.Close()
	userSftp.Close()
	logger.Infof("SFTP request %s: Handler exit.", reqID)
}

func (a *Application) LocalPortForwardingPermission(ctx ssh.Context, destinationHost string, destinationPort uint32) bool {
	return config.GlobalConfig.EnableLocalPortForward
}
func (a *Application) DirectTCPIPChannelHandler(ctx ssh.Context, newChan gossh.NewChannel, destAddr string) {
	if !config.GetConf().EnableVscodeSupport {
		_ = newChan.Reject(gossh.Prohibited, "port forwarding is disabled")
		return
	}
	reqId, ok := ctx.Value(ctxID).(string)
	if !ok {
		_ = newChan.Reject(gossh.Prohibited, "port forwarding is disabled")
		return
	}
	vsReq := a.getVSCodeReq(reqId)
	if vsReq == nil {
		_ = newChan.Reject(gossh.Prohibited, "port forwarding is disabled")
		return
	}
	dConn, err := vsReq.client.Dial("tcp", destAddr)
	if err != nil {
		_ = newChan.Reject(gossh.ConnectionFailed, err.Error())
		return
	}
	ch, reqs, err := newChan.Accept()
	if err != nil {
		_ = dConn.Close()
		_ = newChan.Reject(gossh.ConnectionFailed, err.Error())
		return
	}
	defer ch.Close()
	defer dConn.Close()
	go gossh.DiscardRequests(reqs)
	go func() {
		defer ch.Close()
		defer dConn.Close()
		_, _ = io.Copy(ch, dConn)
	}()
	_, _ = io.Copy(dConn, ch)
}

func (a *Application) SessionHandler(sess ssh.Session) {
	user, ok := sess.Context().Value(auth.ContextKeyUser).(*model.User)
	if !ok || user.ID == "" {
		logger.Errorf("SSH User %s not found, exit.", sess.User())
		utils.IgnoreErrWriteString(sess, "Not auth user.\n")
		return
	}
	termConf := a.GetTerminalConfig()
	directReq := sess.Context().Value(auth.ContextKeyDirectLoginFormat)
	if pty, winChan, isPty := sess.Pty(); isPty {
		if directRequest, ok3 := directReq.(*auth.DirectLoginAssetReq); ok3 {
			directSrv, err := handler.NewDirectHandler(sess, a.jmsService,
				handler.DirectAssetIP(directRequest.AssetIP),
				handler.DirectUser(user),
				handler.DirectTerminalConf(&termConf),
				handler.DirectSystemUsername(directRequest.SysUsername),
			)
			if err != nil {
				logger.Errorf("User %s direct request err: %s", user.Name, err)
				return
			}
			directSrv.Dispatch()
			return
		}

		interactiveSrv := handler.NewInteractiveHandler(sess, user, a.jmsService, termConf)
		logger.Infof("User %s request pty %s", sess.User(), pty.Term)
		go interactiveSrv.WatchWinSizeChange(winChan)
		interactiveSrv.Dispatch()
		return
	}
	if !config.GetConf().EnableVscodeSupport {
		utils.IgnoreErrWriteString(sess, "No PTY requested.\n")
		return
	}
	if directRequest, ok3 := directReq.(*auth.DirectLoginAssetReq); ok3 {
		selectedAssets, err := a.jmsService.GetUserPermAssetsByIP(user.ID, directRequest.AssetIP)
		if err != nil {
			logger.Error(err)
			utils.IgnoreErrWriteString(sess, err.Error())
			return
		}
		if len(selectedAssets) != 1 {
			msg := fmt.Sprintf(i18n.T("Must be unique asset for %s"), directRequest.AssetIP)
			utils.IgnoreErrWriteString(sess, msg)
			logger.Error(msg)
			return
		}
		selectSysUsers, err := a.jmsService.GetSystemUsersByUserIdAndAssetId(user.ID, selectedAssets[0].ID)
		if err != nil {
			logger.Error(err)
			utils.IgnoreErrWriteString(sess, err.Error())
			return
		}

		matched := make([]model.SystemUser, 0, len(selectSysUsers))
		for i := range selectSysUsers {
			if selectSysUsers[i].Username == directRequest.SysUsername {
				matched = append(matched, selectSysUsers[i])
			}
		}
		if len(matched) != 1 {
			msg := fmt.Sprintf(i18n.T("Must be unique system user for %s"), directRequest.SysUsername)
			utils.IgnoreErrWriteString(sess, msg)
			logger.Error(msg)
			return
		}
		a.proxyVscode(sess, user, selectedAssets[0], selectSysUsers[0])
	}

}

func (a *Application) proxyVscode(sess ssh.Session, user *model.User, asset model.Asset,
	systemUser model.SystemUser) {
	ctxId, ok := sess.Context().Value(ctxID).(string)
	if !ok {
		return
	}
	systemUserAuthInfo, err := a.jmsService.GetSystemUserAuthById(systemUser.ID, asset.ID,
		user.ID, user.Username)
	if err != nil {
		logger.Errorf("Get system user auth failed: %s", err)
		return
	}
	var domainGateways *model.Domain
	if asset.Domain != "" {
		domainInfo, err := a.jmsService.GetDomainGateways(asset.Domain)
		if err != nil {
			logger.Errorf("Get system user auth failed: %s", err)
			return
		}
		domainGateways = &domainInfo
	}
	timeout := config.GlobalConfig.SSHTimeout
	sshAuthOpts := make([]srvconn.SSHClientOption, 0, 7)
	sshAuthOpts = append(sshAuthOpts, srvconn.SSHClientUsername(systemUserAuthInfo.Username))
	sshAuthOpts = append(sshAuthOpts, srvconn.SSHClientHost(asset.IP))
	sshAuthOpts = append(sshAuthOpts, srvconn.SSHClientPort(asset.ProtocolPort(systemUserAuthInfo.Protocol)))
	sshAuthOpts = append(sshAuthOpts, srvconn.SSHClientPassword(systemUserAuthInfo.Password))
	sshAuthOpts = append(sshAuthOpts, srvconn.SSHClientTimeout(timeout))
	if systemUserAuthInfo.PrivateKey != "" {
		// 先使用 password 解析 PrivateKey
		if signer, err1 := gossh.ParsePrivateKeyWithPassphrase([]byte(systemUserAuthInfo.PrivateKey),
			[]byte(systemUserAuthInfo.Password)); err1 == nil {
			sshAuthOpts = append(sshAuthOpts, srvconn.SSHClientPrivateAuth(signer))
		} else {
			// 如果之前使用password解析失败，则去掉 password, 尝试直接解析 PrivateKey 防止错误的passphrase
			if signer, err1 = gossh.ParsePrivateKey([]byte(systemUserAuthInfo.PrivateKey)); err1 == nil {
				sshAuthOpts = append(sshAuthOpts, srvconn.SSHClientPrivateAuth(signer))
			}
		}
	}

	if domainGateways != nil {
		proxyArgs := make([]srvconn.SSHClientOptions, 0, len(domainGateways.Gateways))
		for i := range domainGateways.Gateways {
			gateway := domainGateways.Gateways[i]
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
		logger.Errorf("Get SSH Client failed: %s", err)
		return
	}
	defer sshClient.Close()
	goSess, err := sshClient.AcquireSession()
	if err != nil {
		logger.Errorf("Get SSH session failed: %s", err)
		return
	}
	defer goSess.Close()
	stdOut, err := goSess.StdoutPipe()
	if err != nil {
		logger.Errorf("Get SSH session StdoutPipe failed: %s", err)
		return
	}
	stdin, err := goSess.StdinPipe()
	if err != nil {
		logger.Errorf("Get SSH session StdinPipe failed: %s", err)
		return
	}
	err = goSess.Shell()
	if err != nil {
		logger.Errorf("Get SSH session shell failed: %s", err)
		return
	}
	vsReq := &vscodeReq{
		reqId:  ctxId,
		client: sshClient,
	}
	a.addVSCodeReq(vsReq)
	defer a.deleteVSCodeReq(vsReq)
	go func() {
		defer goSess.Close()
		defer sess.Close()
		_, _ = io.Copy(stdin, sess)
	}()
	go func() {
		defer goSess.Close()
		defer sess.Close()
		_, _ = io.Copy(sess, stdOut)
	}()
	<-sess.Context().Done()
	sshClient.ReleaseSession(goSess)
	logger.Infof("vscode client(%s) proxy end", sshClient)
}
