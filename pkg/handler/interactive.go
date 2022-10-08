package handler

import (
	"fmt"
	"io"
	"strconv"
	"strings"
	"sync"
	"time"

	gossh "golang.org/x/crypto/ssh"
	"github.com/gliderlabs/ssh"
	"github.com/xlab/treeprint"

	"github.com/jumpserver/koko/pkg/common"
	"github.com/jumpserver/koko/pkg/config"
	"github.com/jumpserver/koko/pkg/i18n"
	"github.com/jumpserver/koko/pkg/logger"
	"github.com/jumpserver/koko/pkg/model"
	"github.com/jumpserver/koko/pkg/service"
	"github.com/jumpserver/koko/pkg/utils"
	"github.com/jumpserver/koko/pkg/srvconn"
)

var clients = make(map[string]*gossh.Client)

func SessionHandler(sess ssh.Session) {
	user, ok := sess.Context().Value(model.ContextKeyUser).(*model.User)
	if !ok || user.ID == "" {
		logger.Errorf("SSH User %s not found, exit.", sess.User())
		return
	}
	system_user := sess.Context().Value(model.ContextKeySystemUser)
	if system_user == nil {
		if pty, _, ok := sess.Pty(); ok {
			handler := newInteractiveHandler(sess, user)
			logger.Infof("Request %s: User %s request pty %s", handler.sess.ID(), sess.User(), pty.Term)
			go handler.watchWinSizeChange()
			handler.Dispatch()
		} else {
			utils.IgnoreErrWriteString(sess, "No PTY requested.\n")
			return
		}
	} else {
		system_user := sess.Context().Value(model.ContextKeySystemUser).(*string)
		asset_ip := sess.Context().Value(model.ContextKeyAssetIP).(*string)
		selectedAssets, err := service.GetUserPermAssetsByIP(user.ID, *asset_ip)
		if err != nil {
			logger.Error(err)
			utils.IgnoreErrWriteString(sess, err.Error())
			return
		}
		if len(selectedAssets) != 1 {
			msg := fmt.Sprintf(i18n.T("Must be unique asset for %s"), asset_ip)
			utils.IgnoreErrWriteString(sess, msg)
			logger.Error(msg)
			return
		}
		selectSysUsers := service.GetUserAssetSystemUsers(user.ID, selectedAssets[0].ID)
		matched := make([]model.SystemUser, 0, len(selectSysUsers))
		for i := range selectSysUsers {
			if selectSysUsers[i].Username == *system_user {
				matched = append(matched, selectSysUsers[i])
			}
		}
		if len(matched) != 1 {
			msg := fmt.Sprintf(i18n.T("Must be unique system user for %s"), *system_user)
			utils.IgnoreErrWriteString(sess, msg)
			logger.Error(msg)
			return
		}
		endSystemUser := matched[0]
		endAsset := selectedAssets[0]
		var info model.SystemUserAuthInfo
		if endSystemUser.UsernameSameWithUser {
			endSystemUser.Username = user.Username
			info = service.GetUserAssetAuthInfo(endSystemUser.ID, endAsset.ID, user.ID, user.Username)
		} else {
			info = service.GetSystemUserAssetAuthInfo(endSystemUser.ID, endAsset.ID)
		}
		endSystemUser.Password = info.Password
		endSystemUser.PrivateKey = info.PrivateKey

		proxyVscode(sess, user, endAsset, endSystemUser)
		return
	}
}

func newInteractiveHandler(sess ssh.Session, user *model.User) *interactiveHandler {
	wrapperSess := NewWrapperSession(sess)
	term := utils.NewTerminal(wrapperSess, "Opt> ")
	handler := &interactiveHandler{
		sess: wrapperSess,
		user: user,
		term: term,
	}
	handler.Initial()
	return handler
}

type interactiveHandler struct {
	sess         *WrapperSession
	user         *model.User
	term         *utils.Terminal
	winWatchChan chan bool

	selectHandler *UserSelectHandler

	nodes model.NodeList

	assetLoadPolicy string

	wg sync.WaitGroup
}

func (h *interactiveHandler) Initial() {
	conf := config.GetConf()
	if conf.ClientAliveInterval > 0 {
		go h.keepSessionAlive(time.Duration(conf.ClientAliveInterval) * time.Second)
	}
	h.assetLoadPolicy = strings.ToLower(conf.AssetLoadPolicy)
	h.displayBanner()
	h.winWatchChan = make(chan bool, 5)
	h.selectHandler = &UserSelectHandler{
		user:     h.user,
		h:        h,
		pageInfo: &pageInfo{},
	}
	switch h.assetLoadPolicy {
	case "all":
		allAssets := service.GetAllUserPermsAssets(h.user.ID)
		h.selectHandler.SetAllLocalData(allAssets)
	}
	h.firstLoadData()

}

func (h *interactiveHandler) firstLoadData() {
	h.wg.Add(1)
	go func() {
		defer h.wg.Done()
		h.loadUserNodes()
	}()
}

func (h *interactiveHandler) displayBanner() {
	h.term.SetPrompt("Opt> ")
	displayBanner(h.sess, h.user.Name)
}

func (h *interactiveHandler) watchWinSizeChange() {
	sessChan := h.sess.WinCh()
	winChan := sessChan
	defer logger.Infof("Request %s: Windows change watch close", h.sess.Uuid)
	for {
		select {
		case <-h.sess.Sess.Context().Done():
			return
		case sig, ok := <-h.winWatchChan:
			if !ok {
				return
			}
			switch sig {
			case false:
				winChan = nil
			case true:
				winChan = sessChan
			}
		case win, ok := <-winChan:
			if !ok {
				return
			}
			logger.Debugf("Term window size change: %d*%d", win.Height, win.Width)
			_ = h.term.SetSize(win.Width, win.Height)
		}
	}
}

func (h *interactiveHandler) keepSessionAlive(keepAliveTime time.Duration) {
	t := time.NewTicker(keepAliveTime)
	defer t.Stop()
	for {
		select {
		case <-h.sess.Sess.Context().Done():
			return
		case <-t.C:
			_, err := h.sess.Sess.SendRequest("keepalive@openssh.com", true, nil)
			if err != nil {
				logger.Errorf("Request %s: Send user %s keepalive packet failed: %s",
					h.sess.Uuid, h.user.Name, err)
				continue
			}
			logger.Debugf("Request %s: Send user %s keepalive packet success", h.sess.Uuid, h.user.Name)
		}
	}
}

func (h *interactiveHandler) pauseWatchWinSize() {
	h.winWatchChan <- false
}

func (h *interactiveHandler) resumeWatchWinSize() {
	h.winWatchChan <- true
}

func (h *interactiveHandler) chooseSystemUser(systemUsers []model.SystemUser) (systemUser model.SystemUser, ok bool) {

	length := len(systemUsers)
	switch length {
	case 0:
		warningInfo := i18n.T("No system user found.")
		_, _ = io.WriteString(h.term, warningInfo+"\n\r")
		return model.SystemUser{}, false
	case 1:
		return systemUsers[0], true
	default:
	}
	displaySystemUsers := selectHighestPrioritySystemUsers(systemUsers)
	if len(displaySystemUsers) == 1 {
		return displaySystemUsers[0], true
	}

	idLabel := i18n.T("ID")
	nameLabel := i18n.T("Name")
	usernameLabel := i18n.T("Username")

	labels := []string{idLabel, nameLabel, usernameLabel}
	fields := []string{"ID", "Name", "Username"}

	data := make([]map[string]string, len(displaySystemUsers))
	for i, j := range displaySystemUsers {
		row := make(map[string]string)
		row["ID"] = strconv.Itoa(i + 1)
		row["Name"] = j.Name
		row["Username"] = j.Username
		data[i] = row
	}
	w, _ := h.term.GetSize()
	table := common.WrapperTable{
		Fields: fields,
		Labels: labels,
		FieldsSize: map[string][3]int{
			"ID":       {0, 0, 5},
			"Name":     {0, 8, 0},
			"Username": {0, 10, 0},
		},
		Data:        data,
		TotalSize:   w,
		TruncPolicy: common.TruncMiddle,
	}
	table.Initial()

	h.term.SetPrompt("ID> ")
	selectTip := i18n.T("Tips: Enter system user ID and directly login")
	backTip := i18n.T("Back: B/b")
	for {
		utils.IgnoreErrWriteString(h.term, table.Display())
		utils.IgnoreErrWriteString(h.term, utils.WrapperString(selectTip, utils.Green))
		utils.IgnoreErrWriteString(h.term, utils.CharNewLine)
		utils.IgnoreErrWriteString(h.term, utils.WrapperString(backTip, utils.Green))
		utils.IgnoreErrWriteString(h.term, utils.CharNewLine)
		line, err := h.term.ReadLine()
		if err != nil {
			return
		}
		line = strings.TrimSpace(line)
		switch strings.ToLower(line) {
		case "q", "b", "quit", "exit", "back":
			return
		}
		if num, err := strconv.Atoi(line); err == nil {
			if num > 0 && num <= len(displaySystemUsers) {
				return displaySystemUsers[num-1], true
			}
		}
	}
}

func (h *interactiveHandler) refreshAssetsAndNodesData() {
	switch h.assetLoadPolicy {
	case "all":
		h.wg.Add(1)
		go func() {
			defer h.wg.Done()
			allAssets := service.GetAllUserPermsAssets(h.user.ID)
			h.selectHandler.SetAllLocalData(allAssets)
		}()
	default:
		// 异步获取资产已经是最新的了,不需要刷新
	}
	h.wg.Add(1)
	go func() {
		defer h.wg.Done()
		h.loadUserNodes()
	}()
	h.wg.Wait()
	_, err := io.WriteString(h.term, i18n.T("Refresh done")+"\n\r")
	if err != nil {
		logger.Error("refresh Assets Nodes err:", err)
	}
}

func (h *interactiveHandler) loadUserNodes() {
	h.nodes = service.GetUserNodes(h.user.ID)
}

func ConstructAssetNodeTree(assetNodes []model.Node) treeprint.Tree {
	model.SortAssetNodesByKey(assetNodes)
	var treeMap = map[string]treeprint.Tree{}
	tree := treeprint.New()
	for i := 0; i < len(assetNodes); i++ {
		r := strings.LastIndex(assetNodes[i].Key, ":")
		if r < 0 {
			subtree := tree.AddBranch(fmt.Sprintf("%s.%s(%s)",
				strconv.Itoa(i+1), assetNodes[i].Name,
				strconv.Itoa(assetNodes[i].AssetsAmount)))
			treeMap[assetNodes[i].Key] = subtree
			continue
		}
		if _, ok := treeMap[assetNodes[i].Key[:r]]; !ok {
			subtree := tree.AddBranch(fmt.Sprintf("%s.%s(%s)",
				strconv.Itoa(i+1), assetNodes[i].Name,
				strconv.Itoa(assetNodes[i].AssetsAmount)))
			treeMap[assetNodes[i].Key] = subtree
			continue
		}
		if subtree, ok := treeMap[assetNodes[i].Key[:r]]; ok {
			nodeTree := subtree.AddBranch(fmt.Sprintf("%s.%s(%s)",
				strconv.Itoa(i+1), assetNodes[i].Name,
				strconv.Itoa(assetNodes[i].AssetsAmount)))
			treeMap[assetNodes[i].Key] = nodeTree
		}
	}
	return tree
}

func selectHighestPrioritySystemUsers(systemUsers []model.SystemUser) []model.SystemUser {
	length := len(systemUsers)
	if length == 0 {
		return systemUsers
	}
	var result = make([]model.SystemUser, 0)
	model.SortSystemUserByPriority(systemUsers)

	highestPriority := systemUsers[length-1].Priority

	result = append(result, systemUsers[length-1])
	for i := length - 2; i >= 0; i-- {
		if highestPriority == systemUsers[i].Priority {
			result = append(result, systemUsers[i])
		}
	}
	return result
}

func getPageSize(term *utils.Terminal) int {
	var (
		pageSize  int
		minHeight = 8 // 分页显示的最小高度

	)
	_, height := term.GetSize()
	conf := config.GetConf()
	switch conf.AssetListPageSize {
	case "auto":
		pageSize = height - minHeight
	case "all":
		return PAGESIZEALL
	default:
		if value, err := strconv.Atoi(conf.AssetListPageSize); err == nil {
			pageSize = value
		} else {
			pageSize = height - minHeight
		}
	}
	if pageSize <= 0 {
		pageSize = 1
	}
	return pageSize
}

func proxyVscode(sess ssh.Session, user *model.User, asset model.Asset, systemUser model.SystemUser) {
	var timeout time.Duration = 10 * time.Minute
	sshClient, err := srvconn.NewClient(user, &asset, &systemUser, timeout, true)
	ctx := sess.Context().Value(model.ContextKeyCtxID).(string)
	clients[ctx] = sshClient.Getclient()
	defer delete(clients, ctx)
	if err != nil {
		logger.Errorf("Get SSH Client failed: %s", err)
		return
	}
	defer sshClient.Close()
	goSess, err := sshClient.NewSession()
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
	logger.Infof("User %s start vscode request to %s", user.Name, sshClient)
	go func() {
		io.Copy(stdin, sess)
		logger.Infof("User %s vscode request %s stdin end", user.Name, sshClient)
	}()
	go func() {
		io.Copy(sess, stdOut)
		logger.Infof("User %s vscode request %s stdout end", user.Name, sshClient)
	}()
	<-sess.Context().Done()
	sshClient.Close()
	logger.Infof("User %s end vscode request %s", user.Name, sshClient)
}

func DirectTCPIPChannelHandler(ctx ssh.Context, newChan gossh.NewChannel, destAddr string) {
	ctxid := ctx.Value(model.ContextKeyCtxID).(string)
	system_user := ctx.Value(model.ContextKeySystemUser).(*string)
	asset_ip := ctx.Value(model.ContextKeyAssetIP).(*string)
	user := ctx.Value(model.ContextKeyUser).(*model.User)
	client := clients[ctxid]
	dConn, err := client.Dial("tcp", destAddr)
	if err != nil {
		newChan.Reject(gossh.ConnectionFailed, err.Error())
		return
	}
	defer dConn.Close()
	ch, reqs, err := newChan.Accept()
	if err != nil {
		dConn.Close()
		newChan.Reject(gossh.ConnectionFailed, err.Error())
		return
	}
	logger.Infof("User %s start port forwarding to %s, user is %s", user.Name, *asset_ip, *system_user)
	defer ch.Close()
	go gossh.DiscardRequests(reqs)
	go func() {
		defer ch.Close()
		defer dConn.Close()
		io.Copy(ch, dConn)
	}()
	io.Copy(dConn, ch)
	logger.Infof("User %s end port forwarding to %s, user is %s", user.Name, *asset_ip, *system_user)
}
