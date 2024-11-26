package main

import (
	"fmt"
	"sync"
	"time"
)

// Struct to hold cached authentication data
type AuthData struct {
	SourceIP string
	SdpKey   string
}

type AuthManager struct {
	dataMap sync.Map
}

func NewAuthManager() *AuthManager {
	return &AuthManager{
		dataMap: sync.Map{},
	}
}

func (am *AuthManager) getSdpKey(machineID string) (string, error) {
	if authData, exists := am.dataMap.Load(machineID); exists {
		return authData.(AuthData).SdpKey, nil
	}
	return "", fmt.Errorf("machineID not found in AuthManager: %s", machineID)
}

func (am *AuthManager) getSdpSourceIP(machineID string) (string, error) {
	if authData, exists := am.dataMap.Load(machineID); exists {
		return authData.(AuthData).SourceIP, nil
	}
	return "", fmt.Errorf("machineID not found in AuthManager: %s", machineID)
}

func (am *AuthManager) isDataExists(machineID string) bool {
	_, isKey := am.dataMap.Load(machineID)
	return isKey
}

func (am *AuthManager) storeData(machineID string, data interface{}) {
	// Store the authData in the dataMap
	am.dataMap.Store(machineID, data)
	go func() {
		time.Sleep(20 * time.Second)
		am.dataMap.Delete(machineID)
	}()
}
