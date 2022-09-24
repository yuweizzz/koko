package sshd

import (
	"net"
	"strconv"

	"github.com/gliderlabs/ssh"
	"github.com/pires/go-proxyproto"
	gossh "golang.org/x/crypto/ssh"

	"github.com/jumpserver/koko/pkg/auth"
	"github.com/jumpserver/koko/pkg/config"
	"github.com/jumpserver/koko/pkg/handler"
	"github.com/jumpserver/koko/pkg/logger"
)

var sshServer *ssh.Server

func StartServer() {
	handler.Initial()
	conf := config.GetConf()
	hostKey := HostKey{Value: conf.HostKey, Path: conf.HostKeyFile}
	logger.Debug("Loading host key")
	signer, err := hostKey.Load()
	if err != nil {
		logger.Fatal("Load host key error: ", err)
	}

	addr := net.JoinHostPort(conf.BindHost, conf.SSHPort)
	logger.Infof("Start SSH server at %s", addr)
	sshServer = &ssh.Server{
		Addr:                       addr,
		KeyboardInteractiveHandler: auth.CheckMFA,
		PasswordHandler:            auth.CheckUserPassword,
		PublicKeyHandler:           auth.CheckUserPublicKey,
		NextAuthMethodsHandler:     auth.MFAAuthMethods,
		HostSigners:                []ssh.Signer{signer},
		Handler:                    handler.SessionHandler,
		// Default Enable LocalPortForwarding
		LocalPortForwardingCallback: func(ctx ssh.Context, destinationHost string, destinationPort uint32) bool {
			return true
		},
		SubsystemHandlers: map[string]ssh.SubsystemHandler{
			"sftp": handler.SftpHandler,
		},
		// Handler direct-tcpip request
		ChannelHandlers: map[string]ssh.ChannelHandler{
			"session": ssh.DefaultSessionHandler,
			"direct-tcpip": func(srv *ssh.Server, conn *gossh.ServerConn, newChan gossh.NewChannel, ctx ssh.Context) {
				d := localForwardChannelData{}
				if err := gossh.Unmarshal(newChan.ExtraData(), &d); err != nil {
					newChan.Reject(gossh.ConnectionFailed, "error parsing forward data: "+err.Error())
					return
				}
			
				if srv.LocalPortForwardingCallback == nil || !srv.LocalPortForwardingCallback(ctx, d.DestAddr, d.DestPort) {
					newChan.Reject(gossh.Prohibited, "port forwarding is disabled")
					return
				}
			
				dest := net.JoinHostPort(d.DestAddr, strconv.FormatInt(int64(d.DestPort), 10))
				handler.DirectTCPIPChannelHandler(ctx, newChan, dest)
			},
		},
	}
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		logger.Fatal(err)
	}
	proxyListener := &proxyproto.Listener{Listener: ln}
	logger.Fatal(sshServer.Serve(proxyListener))
}

func StopServer() {
	err := sshServer.Close()
	if err != nil {
		logger.Errorf("SSH server close failed: %s", err.Error())
	}
	logger.Info("Close ssh server")
}

type localForwardChannelData struct {
	DestAddr string
	DestPort uint32

	OriginAddr string
	OriginPort uint32
}
