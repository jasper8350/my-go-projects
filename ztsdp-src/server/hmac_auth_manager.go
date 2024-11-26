package main

import (
	"fmt"
	"log"
	"net"
	"sync"
	"time"
)

// Struct to hold cached hmac authentication data
type HmacAuthData struct {
	SourceIP  net.IP
	Timestamp uint64
	MachineID string
}

// Define a type for HmacAuthManager
type HmacAuthManager struct {
	dataMap sync.Map
}

// Define a function to create and initialize a new HmacAuthManager value
func NewHmacAuthManager() *HmacAuthManager {
	return &HmacAuthManager{
		dataMap: sync.Map{},
	}
}

// Define a method for HmacAuthManager to check if a data exists
func (ham *HmacAuthManager) isDataExists(key string) bool {
	_, exists := ham.dataMap.Load(key)
	return exists
}

// Define a method for HmacAuthManager to store a data
func (ham *HmacAuthManager) storeData(key string, data interface{}) {
	ham.dataMap.Store(key, data)
}

// Define a method for HmacAuthManager to print a single data
func (ham *HmacAuthManager) printData(hmacValue string) {
	// Find the value for the given key using Load method
	if value, exists := ham.dataMap.Load(hmacValue); exists {
		data := value.(HmacAuthData)
		log.Printf("HMAC=%s, SourceIP=%s, Timestamp=%s", hmacValue, data.SourceIP, time.Unix(int64(data.Timestamp), 0).Format(time.RFC3339))
	}
}

// Define a method for HmacAuthManager to print all the data and the total count
func (ham *HmacAuthManager) printDataMap() {
	count := 0
	ham.dataMap.Range(func(key, value interface{}) bool {
		// Print the key
		fmt.Println("HMAC:", key.(string))

		// Print the value information including Timestamp as a formatted time
		data := value.(HmacAuthData)
		fmt.Println("  SourceIP:", data.SourceIP)
		fmt.Println("  Timestamp:", time.Unix(int64(data.Timestamp), 0).Format(time.RFC3339))
		count++
		return true
	})
	fmt.Println("Total:", count)
}
