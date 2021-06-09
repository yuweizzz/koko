package service

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/jumpserver/koko/pkg/jms-sdk-go/model"
	"github.com/jumpserver/koko/pkg/logger"
)

func (s *JMService) SubmitCommandConfirm(sid string, ruleId string, cmd string) (res ConfirmResponse, err error) {
	/*
		{
		session_id: sid,
		rule_id : ruleId,
		command: cmd,
		}
	*/
	data := map[string]string{
		"session_id":         sid,
		"cmd_filter_rule_id": ruleId,
		"run_command":        cmd,
	}
	_, err = s.authClient.Post(CommandConfirmURL, data, &res)
	return
}

func (s *JMService) CheckIfNeedAssetLoginConfirm(userId, assetId, systemUserId,
	sysUsername string) (res CheckAssetConfirmResponse, err error) {
	data := map[string]string{
		"user_id":              userId,
		"asset_id":             assetId,
		"system_user_id":       systemUserId,
		"system_user_username": sysUsername,
	}

	_, err = s.authClient.Post(AssetLoginConfirmURL, data, &res)
	return
}

func (s *JMService) CheckIfNeedAppConnectionConfirm(userID, assetID, systemUserID string) (bool, error) {

	return false, nil
}

func (s *JMService) CancelConfirmByRequestInfo(req requestInfo) (err error) {
	res := make(map[string]interface{})
	err = s.sendRequestByRequestInfo(req, &res)
	return
}

func (s *JMService) CheckConfirmStatusByRequestInfo(req requestInfo) (res ConfirmStatusResponse, err error) {
	err = s.sendRequestByRequestInfo(req, &res)
	return
}

func (s *JMService) sendRequestByRequestInfo(req requestInfo, res interface{}) (err error) {
	switch strings.ToUpper(req.Method) {
	case http.MethodGet:
		_, err = s.authClient.Get(req.URL, res)
	case http.MethodDelete:
		_, err = s.authClient.Delete(req.URL, res)
	default:
		err = fmt.Errorf("unsupport method %s", req.Method)
	}
	return
}

type ConfirmResponse struct {
	CheckConfirmStatus requestInfo `json:"check_confirm_status"`
	CloseConfirm       requestInfo `json:"close_confirm"`
	TicketDetailUrl    string      `json:"ticket_detail_url"`
	Reviewers          []string    `json:"reviewers"`
}

type requestInfo struct {
	Method string `json:"method"`
	URL    string `json:"url"`
}

type ConfirmStatusResponse struct {
	Status    string `json:"status"`
	Action    string `json:"action"`
	Processor string `json:"processor"`
}

type connectionConfirmOption struct {
	user       *model.User
	systemUser *model.SystemUser

	targetType string
	targetID   string
}

func NewLoginConfirm(opts ...ConfirmOption) LoginConfirmService {
	var option connectionConfirmOption
	for _, setter := range opts {
		setter(&option)
	}
	return LoginConfirmService{option: &option}
}

type LoginConfirmService struct {
	option *connectionConfirmOption

	checkReqInfo    requestInfo
	cancelReqInfo   requestInfo
	reviewers       []string
	ticketDetailUrl string

	processor string // 此审批的处理人

	jmsService *JMService
}

func (c *LoginConfirmService) CheckIsNeedLoginConfirm() (bool, error) {
	userID := c.option.user.ID
	systemUserID := c.option.systemUser.ID
	systemUsername := c.option.systemUser.Username
	targetID := c.option.targetID
	switch c.option.targetType {
	case model.AppType:
		return c.jmsService.CheckIfNeedAppConnectionConfirm(userID, targetID, systemUserID)
	default:
		res, err := c.jmsService.CheckIfNeedAssetLoginConfirm(userID, targetID,
			systemUserID, systemUsername)
		if err != nil {
			return false, err
		}
		c.reviewers = res.Reviewers
		c.checkReqInfo = res.CheckConfirmStatus
		c.cancelReqInfo = res.CloseConfirm
		c.ticketDetailUrl = res.TicketDetailUrl
		return res.NeedConfirm, nil
	}
}

func (c *LoginConfirmService) WaitLoginConfirm(ctx context.Context) Status {
	return c.waitConfirmFinish(ctx)
}

func (c *LoginConfirmService) GetReviewers() []string {
	reviewers := make([]string, len(c.reviewers))
	copy(reviewers, c.reviewers)
	return reviewers
}

func (c *LoginConfirmService) GetTicketUrl() string {
	return c.ticketDetailUrl
}

func (c *LoginConfirmService) GetProcessor() string {
	return c.processor
}

func (c *LoginConfirmService) waitConfirmFinish(ctx context.Context) Status {
	// 10s 请求一次
	t := time.NewTicker(10 * time.Second)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			c.cancelConfirm()
			return StatusCancel
		case <-t.C:
			statusRes, err := c.jmsService.CheckConfirmStatusByRequestInfo(c.checkReqInfo)
			if err != nil {
				logger.Errorf("Check confirm status err: %s", err.Error())
				continue
			}
			switch statusRes.Status {
			case approve:
				c.processor = statusRes.Processor
				return StatusApprove
			case reject:
				c.processor = statusRes.Processor
				return StatusReject
			case await:
				continue
			default:
				logger.Errorf("Receive unknown login confirm status %s",
					statusRes.Status)
			}
		}
	}
}

func (c *LoginConfirmService) cancelConfirm() {
	if err := c.jmsService.CancelConfirmByRequestInfo(c.cancelReqInfo); err != nil {
		logger.Errorf("Cancel confirm request err: %s", err.Error())
	}
}

const (
	approve = "approve"
	reject  = "reject"
	await   = "await"
)

type Status int

const (
	StatusApprove Status = iota + 1
	StatusReject
	StatusCancel
)

type CheckAssetConfirmResponse struct {
	NeedConfirm        bool        `json:"need_confirm"`
	CheckConfirmStatus requestInfo `json:"check_confirm_status"`
	CloseConfirm       requestInfo `json:"close_confirm"`
	TicketDetailUrl    string      `json:"ticket_detail_url"`
	Reviewers          []string    `json:"reviewers"`
}

type ConfirmOption func(*connectionConfirmOption)

func ConfirmWithUser(user *model.User) ConfirmOption {
	return func(option *connectionConfirmOption) {
		option.user = user
	}
}

func ConfirmWithSystemUser(sysUser *model.SystemUser) ConfirmOption {
	return func(option *connectionConfirmOption) {
		option.systemUser = sysUser
	}
}

func ConfirmWithTargetType(targetType string) ConfirmOption {
	return func(option *connectionConfirmOption) {
		option.targetType = targetType
	}
}

func ConfirmWithTargetID(targetID string) ConfirmOption {
	return func(option *connectionConfirmOption) {
		option.targetID = targetID
	}
}
