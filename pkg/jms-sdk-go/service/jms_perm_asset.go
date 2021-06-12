package service

import (
	"fmt"
	"github.com/jumpserver/koko/pkg/jms-sdk-go/model"
	"github.com/jumpserver/koko/pkg/logger"
)

func (s *JMService) SearchPermAsset(userId, key string) (res model.AssetList, err error) {
	Url := fmt.Sprintf(UserPermsAssetsURL, userId)
	payload := map[string]string{"search": key}
	_, err = s.authClient.Get(Url, &res, payload)
	return
}

func (s *JMService) GetSystemUsersByUserIdAndAssetId(userId, assetId string) (sysUsers []model.SystemUser, err error) {
	Url := fmt.Sprintf(UserPermsAssetSystemUsersURL, userId, assetId)
	_, err = s.authClient.Get(Url, &sysUsers)
	return
}

func (s *JMService) GetAllUserPermsAssets(userId string) (assets []map[string]interface{}) {
	var params model.PaginationParam
	res := s.GetUserPermsAssets(userId, params)
	return res.Data
}

func (s *JMService) GetUserPermsAssets(userID string, params model.PaginationParam) (resp model.PaginationResponse) {
	Url := fmt.Sprintf(UserPermsAssetsURL, userID)
	return s.getPaginationResult(Url, params)
}

func (s *JMService) RefreshUserAllPermsAssets(userId string) (assets []map[string]interface{}) {
	var params model.PaginationParam
	params.Refresh = true
	res := s.GetUserPermsAssets(userId, params)
	return res.Data
}

func (s *JMService) GetUserAssetByID(userId, assetId string) (assets []model.Asset) {
	params := map[string]string{
		"id": assetId,
	}
	Url := fmt.Sprintf(UserPermsAssetsURL, userId)
	_, err := s.authClient.Get(Url, &assets, params)
	if err != nil {
		logger.Errorf("Get user asset by ID error: %s", err)
	}
	return
}
