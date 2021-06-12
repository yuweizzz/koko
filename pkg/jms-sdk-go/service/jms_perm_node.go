package service

import (
	"fmt"
	"github.com/jumpserver/koko/pkg/logger"

	"github.com/jumpserver/koko/pkg/jms-sdk-go/model"
)

func (s *JMService) GetUserNodeAssets(userID, nodeID string, params model.PaginationParam) (resp model.PaginationResponse) {
	Url := fmt.Sprintf(UserPermsNodeAssetsListURL, userID, nodeID)
	return s.getPaginationResult(Url, params)
}

func (s *JMService) GetUserNodes(userId string) (nodes model.NodeList) {
	Url := fmt.Sprintf(UserPermsNodesListURL, userId)
	_, err := s.authClient.Get(Url, &nodes)
	if err != nil {
		logger.Errorf("Get user nodes error: %s", err)
	}
	return
}

func (s *JMService) RefreshUserNodes(userId string) (nodes model.NodeList) {
	params := map[string]string{
		"rebuild_tree": "1",
	}
	Url := fmt.Sprintf(UserPermsNodesListURL, userId)
	_, err := s.authClient.Get(Url, &nodes, params)
	if err != nil {
		logger.Errorf("Refresh user nodes error: %s", err)
	}
	return
}
