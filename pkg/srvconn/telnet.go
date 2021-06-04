package srvconn

import gossh "golang.org/x/crypto/ssh"

type TelnetOption func(*TelnetConfig)

type TelnetConfig struct {
	Host     string
	Port     string
	Username string
	Password string

	proxyClient *gossh.Client
}
