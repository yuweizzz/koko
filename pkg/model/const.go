package model

type contextKey int64

const (
	ContextKeyUser contextKey = iota + 1
	ContextKeyRemoteAddr
	ContextKeyClient
	ContextKeyConfirmRequired
	ContextKeyConfirmFailed
)

const (
	HighRiskFlag = "1"
	LessRiskFlag = "0"
)
const (
	DangerLevel = 5
	NormalLevel = 0
)