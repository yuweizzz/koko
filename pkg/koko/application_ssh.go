package koko

import (
	"fmt"

	"io"
	"net"
	"time"

	"github.com/gliderlabs/ssh"
	"github.com/pkg/sftp"
	gossh "golang.org/x/crypto/ssh"

	"github.com/jumpserver/koko/pkg/auth"
	"github.com/jumpserver/koko/pkg/common"
	"github.com/jumpserver/koko/pkg/config"
	"github.com/jumpserver/koko/pkg/handler"
	"github.com/jumpserver/koko/pkg/jms-sdk-go/model"
	"github.com/jumpserver/koko/pkg/logger"
	"github.com/jumpserver/koko/pkg/sshd"
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
	// todo vscode 支持
}

func (a *Application) SessionHandler(sess ssh.Session) {
	fmt.Println("sid: ", sess.Context().Value(ctxID))
	time.Sleep(100 * time.Second)
}
