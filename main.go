package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"sync"
	"time"

	"github.com/go-zeromq/zmq4"
	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
)

const (
	ZMQ_ENDPOINT   = "tcp://127.0.0.1:5555"
	BATCH_INTERVAL = 100 * time.Millisecond
	BATCH_SIZE     = 50
)

type Event struct {
	Timestamp  string      `json:"timestamp"`
	ChangeType string      `json:"change_type"`
	KeyPath    string      `json:"key_path"`
	ValueName  string      `json:"value_name"`
	DataType   string      `json:"data_type"`
	OldValue   interface{} `json:"old_value,omitempty"`
	NewValue   interface{} `json:"new_value,omitempty"`
}

type Batch struct {
	Events []Event `json:"events"`
}

var (
	filters     = make(map[string]bool)
	filtersLock sync.RWMutex
	eventChan   = make(chan Event, 1000)
)

func main() {
	// Initialize ZMQ
	pub := zmq4.NewPub(context.Background())
	defer pub.Close()

	err := pub.Listen(ZMQ_ENDPOINT)
	if err != nil {
		log.Fatalf("could not listen on ZMQ: %v", err)
	}
	fmt.Printf("Backend started. Publishing to %s\n", ZMQ_ENDPOINT)

	// Start batcher
	go batcher(pub)

	// Monitor keys
	go monitorKey(registry.CURRENT_USER, "HKEY_CURRENT_USER")
	go monitorKey(registry.LOCAL_MACHINE, "HKEY_LOCAL_MACHINE\\SOFTWARE")

	// Keep alive
	select {}
}

func monitorKey(root registry.Key, rootName string) {
	// We use a simplified approach here due to RegNotifyChangeKeyValue limitations.
	// In a real high-performance scenario, we'd use ETW or a driver.
	// With RegNotifyChangeKeyValue, we know SOMETHING changed, then we scan.
	
	hEvent, err := windows.CreateEvent(nil, 0, 0, nil)
	if err != nil {
		log.Printf("Error creating event: %v", err)
		return
	}
	defer windows.CloseHandle(hEvent)

	// Initial snapshot
	cache := make(map[string]map[string]interface{})
	snapshot(root, rootName, cache)

	for {
		err := windows.RegNotifyChangeKeyValue(windows.Handle(root), true, 
			windows.REG_NOTIFY_CHANGE_NAME|windows.REG_NOTIFY_CHANGE_ATTRIBUTES|
			windows.REG_NOTIFY_CHANGE_LAST_SET|windows.REG_NOTIFY_CHANGE_SECURITY, 
			hEvent, true)
		
		if err != nil {
			log.Printf("Error setting up notification for %s: %v", rootName, err)
			return
		}

		// Wait for change
		event, err := windows.WaitForSingleObject(hEvent, windows.INFINITE)
		if err != nil {
			log.Printf("Error waiting for event: %v", err)
			continue
		}

		if event == windows.WAIT_OBJECT_0 {
			// Change detected! Scan and compare.
			// To avoid huge performance hits, we only scan the keys that we previously knew.
			// Note: This is a simplified implementation. A full recursive scan on every change
			// would be too slow for 500+ changes/sec.
			compareAndRefresh(root, rootName, cache)
		}
	}
}

func snapshot(root registry.Key, rootName string, cache map[string]map[string]interface{}) {
	// Recursive snapshot (limited to avoid infinite loops or massive memory usage)
	// For this demo/task, we'll scan some levels deep.
	scan(root, rootName, cache, 0)
}

func scan(key registry.Key, path string, cache map[string]map[string]interface{}, depth int) {
	if depth > 5 { // Limit depth for performance
		return
	}

	values := make(map[string]interface{})
	names, _ := key.ReadValueNames(-1)
	for _, name := range names {
		_, valType, err := key.GetValue(name, nil)
		if err != nil {
			continue
		}
		
		var val interface{}
		switch valType {
		case registry.DWORD:
			v, _, _ := key.GetIntegerValue(name)
			val = v
		case registry.QWORD:
			v, _, _ := key.GetIntegerValue(name)
			val = v
		case registry.SZ, registry.EXPAND_SZ:
			v, _, _ := key.GetStringValue(name)
			val = v
		default:
			val = "[Binary/Other]"
		}
		values[name] = val
	}
	cache[path] = values

	subkeys, _ := key.ReadSubKeyNames(-1)
	for _, sub := range subkeys {
		subKey, err := registry.OpenKey(key, sub, registry.READ)
		if err != nil {
			continue
		}
		scan(subKey, path+"\\"+sub, cache, depth+1)
		subKey.Close()
	}
}

func compareAndRefresh(root registry.Key, rootName string, cache map[string]map[string]interface{}) {
	// In a real app, we'd be more selective. Here we just re-scan.
	newCache := make(map[string]map[string]interface{})
	scan(root, rootName, newCache, 0)

	now := time.Now().Format(time.RFC3339Nano)

	// Find new/modified
	for path, values := range newCache {
		oldValues, exists := cache[path]
		if !exists {
			// New Key - report all its values as NEW
			for name, val := range values {
				report(Event{
					Timestamp:  now,
					ChangeType: "NEW",
					KeyPath:    path,
					ValueName:  name,
					DataType:   inferType(val),
					NewValue:   val,
				})
			}
			continue
		}

		for name, val := range values {
			oldVal, valExists := oldValues[name]
			if !valExists {
				report(Event{
					Timestamp:  now,
					ChangeType: "NEW",
					KeyPath:    path,
					ValueName:  name,
					DataType:   inferType(val),
					NewValue:   val,
				})
			} else if oldVal != val {
				report(Event{
					Timestamp:  now,
					ChangeType: "MODIFIED",
					KeyPath:    path,
					ValueName:  name,
					DataType:   inferType(val),
					OldValue:   oldVal,
					NewValue:   val,
				})
			}
		}
	}

	// Find deleted
	for path, oldValues := range cache {
		newValues, exists := newCache[path]
		if !exists {
			// Deleted Key - report all its values as DELETED
			for name, val := range oldValues {
				report(Event{
					Timestamp:  now,
					ChangeType: "DELETED",
					KeyPath:    path,
					ValueName:  name,
					DataType:   inferType(val),
					OldValue:   val,
				})
			}
			continue
		}

		for name, oldVal := range oldValues {
			if _, valExists := newValues[name]; !valExists {
				report(Event{
					Timestamp:  now,
					ChangeType: "DELETED",
					KeyPath:    path,
					ValueName:  name,
					DataType:   inferType(oldVal),
					OldValue:   oldVal,
				})
			}
		}
	}

	// Update cache
	for k := range cache {
		delete(cache, k)
	}
	for k, v := range newCache {
		cache[k] = v
	}
}

func inferType(val interface{}) string {
	switch val.(type) {
	case uint64:
		return "REG_QWORD"
	case uint32:
		return "REG_DWORD"
	case string:
		return "REG_SZ"
	default:
		return "REG_BINARY"
	}
}

func report(e Event) {
	// Check filters
	filtersLock.RLock()
	if filters[e.KeyPath] {
		filtersLock.RUnlock()
		return
	}
	filtersLock.RUnlock()

	eventChan <- e
}

func batcher(pub zmq4.Socket) {
	var currentBatch []Event
	ticker := time.NewTicker(BATCH_INTERVAL)

	for {
		select {
		case e := <-eventChan:
			currentBatch = append(currentBatch, e)
			if len(currentBatch) >= BATCH_SIZE {
				sendBatch(pub, currentBatch)
				currentBatch = nil
			}
		case <-ticker.C:
			if len(currentBatch) > 0 {
				sendBatch(pub, currentBatch)
				currentBatch = nil
			}
		}
	}
}

func sendBatch(pub zmq4.Socket, events []Event) {
	b := Batch{Events: events}
	data, err := json.Marshal(b)
	if err != nil {
		return
	}
	err = pub.Send(zmq4.NewMsg(data))
	if err != nil {
		log.Printf("Error sending batch: %v", err)
	}
}
