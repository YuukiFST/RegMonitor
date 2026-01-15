package main

import (
	"context"
	"encoding/json"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/go-zeromq/zmq4"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
)

const (
	DefaultZMQEndpoint   = "tcp://127.0.0.1:5555"
	DefaultBatchInterval = 100 * time.Millisecond
	DefaultBatchSize     = 50
	DefaultMaxScanDepth  = 5
	DefaultEventChanSize = 1000
	DefaultWaitTimeoutMS = 500
	DefaultMaxEvents     = 5000
	ConfigFilePath       = "config.json"
)

type Config struct {
	ZMQEndpoint     string   `json:"zmq_endpoint"`
	BatchIntervalMS int      `json:"batch_interval_ms"`
	BatchSize       int      `json:"batch_size"`
	MaxScanDepth    int      `json:"max_scan_depth"`
	FilterPaths     []string `json:"filtros_paths"`
}

func loadConfig() *Config {
	cfg := &Config{
		ZMQEndpoint:     DefaultZMQEndpoint,
		BatchIntervalMS: int(DefaultBatchInterval.Milliseconds()),
		BatchSize:       DefaultBatchSize,
		MaxScanDepth:    DefaultMaxScanDepth,
		FilterPaths:     []string{},
	}

	data, err := os.ReadFile(ConfigFilePath)
	if err != nil {
		log.Warn().Err(err).Str("path", ConfigFilePath).Msg("config file not found, using defaults")
		return cfg
	}

	if err := json.Unmarshal(data, cfg); err != nil {
		log.Warn().Err(err).Msg("failed to parse config, using defaults")
		return cfg
	}

	if cfg.ZMQEndpoint == "" {
		cfg.ZMQEndpoint = DefaultZMQEndpoint
	}
	if cfg.BatchIntervalMS <= 0 {
		cfg.BatchIntervalMS = int(DefaultBatchInterval.Milliseconds())
	}
	if cfg.BatchSize <= 0 {
		cfg.BatchSize = DefaultBatchSize
	}
	if cfg.MaxScanDepth <= 0 {
		cfg.MaxScanDepth = DefaultMaxScanDepth
	}

	log.Info().
		Str("endpoint", cfg.ZMQEndpoint).
		Int("batch_size", cfg.BatchSize).
		Int("filters", len(cfg.FilterPaths)).
		Msg("config loaded")

	return cfg
}

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

type RegistryCache struct {
	mu   sync.RWMutex
	data map[string]map[string]interface{}
}

func NewRegistryCache() *RegistryCache {
	return &RegistryCache{
		data: make(map[string]map[string]interface{}),
	}
}

func (c *RegistryCache) Get(path string) (map[string]interface{}, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	v, ok := c.data[path]
	return v, ok
}

func (c *RegistryCache) Set(path string, values map[string]interface{}) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.data[path] = values
}

func (c *RegistryCache) Delete(path string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	delete(c.data, path)
}

func (c *RegistryCache) Keys() []string {
	c.mu.RLock()
	defer c.mu.RUnlock()
	keys := make([]string, 0, len(c.data))
	for k := range c.data {
		keys = append(keys, k)
	}
	return keys
}

func (c *RegistryCache) ReplaceAll(newData map[string]map[string]interface{}) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.data = newData
}

func (c *RegistryCache) Snapshot() map[string]map[string]interface{} {
	c.mu.RLock()
	defer c.mu.RUnlock()
	snapshot := make(map[string]map[string]interface{}, len(c.data))
	for k, v := range c.data {
		copyV := make(map[string]interface{}, len(v))
		for kk, vv := range v {
			copyV[kk] = vv
		}
		snapshot[k] = copyV
	}
	return snapshot
}

var (
	filters     = make(map[string]bool)
	filtersLock sync.RWMutex
	eventChan   = make(chan Event, DefaultEventChanSize)
	appConfig   *Config
)

func main() {
	zerolog.TimeFieldFormat = zerolog.TimeFormatUnix
	consoleWriter := zerolog.ConsoleWriter{Out: os.Stdout, TimeFormat: time.RFC3339}
	log.Logger = zerolog.New(consoleWriter).With().Timestamp().Caller().Logger()

	appConfig = loadConfig()

	filtersLock.Lock()
	for _, path := range appConfig.FilterPaths {
		filters[strings.ToLower(path)] = true
	}
	filtersLock.Unlock()

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()

	pub := zmq4.NewPub(ctx)
	defer pub.Close()

	err := pub.Listen(appConfig.ZMQEndpoint)
	if err != nil {
		log.Fatal().Err(err).Str("endpoint", appConfig.ZMQEndpoint).Msg("failed to listen on ZMQ")
	}
	log.Info().Str("endpoint", appConfig.ZMQEndpoint).Msg("backend started")

	var wg sync.WaitGroup

	wg.Add(1)
	go func() {
		defer wg.Done()
		batcher(ctx, pub)
	}()

	wg.Add(1)
	go func() {
		defer wg.Done()
		monitorKey(ctx, registry.CURRENT_USER, "HKEY_CURRENT_USER")
	}()

	wg.Add(1)
	go func() {
		defer wg.Done()
		monitorKey(ctx, registry.LOCAL_MACHINE, "HKEY_LOCAL_MACHINE\\SOFTWARE")
	}()

	<-ctx.Done()
	log.Info().Msg("shutdown signal received, stopping monitors...")

	wg.Wait()
	log.Info().Msg("backend stopped cleanly")
}

func monitorKey(ctx context.Context, root registry.Key, rootName string) {
	hEvent, err := windows.CreateEvent(nil, 0, 0, nil)
	if err != nil {
		log.Error().Err(err).Str("root", rootName).Msg("failed to create event")
		return
	}
	defer windows.CloseHandle(hEvent)

	cache := NewRegistryCache()
	scanIntoCache(root, rootName, cache, 0)
	log.Info().Str("root", rootName).Msg("initial snapshot complete")

	for {
		select {
		case <-ctx.Done():
			log.Debug().Str("root", rootName).Msg("monitor stopping")
			return
		default:
		}

		err := windows.RegNotifyChangeKeyValue(
			windows.Handle(root),
			true,
			windows.REG_NOTIFY_CHANGE_NAME|
				windows.REG_NOTIFY_CHANGE_ATTRIBUTES|
				windows.REG_NOTIFY_CHANGE_LAST_SET|
				windows.REG_NOTIFY_CHANGE_SECURITY,
			hEvent,
			true,
		)
		if err != nil {
			log.Error().Err(err).Str("root", rootName).Msg("failed to setup notification")
			return
		}

		event, err := windows.WaitForSingleObject(hEvent, DefaultWaitTimeoutMS)
		if err != nil {
			log.Warn().Err(err).Str("root", rootName).Msg("wait error")
			continue
		}

		if event == windows.WAIT_OBJECT_0 {
			compareAndRefresh(root, rootName, cache)
		}
	}
}

func scanIntoCache(key registry.Key, path string, cache *RegistryCache, depth int) {
	if depth > appConfig.MaxScanDepth {
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
	cache.Set(path, values)

	subkeys, _ := key.ReadSubKeyNames(-1)
	for _, sub := range subkeys {
		subKey, err := registry.OpenKey(key, sub, registry.READ)
		if err != nil {
			continue
		}
		scanIntoCache(subKey, path+"\\"+sub, cache, depth+1)
		subKey.Close()
	}
}

func compareAndRefresh(root registry.Key, rootName string, cache *RegistryCache) {
	newCache := NewRegistryCache()
	scanIntoCache(root, rootName, newCache, 0)

	now := time.Now().Format(time.RFC3339Nano)
	oldSnapshot := cache.Snapshot()
	newSnapshot := newCache.Snapshot()

	for path, values := range newSnapshot {
		oldValues, exists := oldSnapshot[path]
		if !exists {
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

	for path, oldValues := range oldSnapshot {
		newValues, exists := newSnapshot[path]
		if !exists {
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

	cache.ReplaceAll(newSnapshot)
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
	filtersLock.RLock()
	keyLower := strings.ToLower(e.KeyPath)
	for filterPath := range filters {
		if keyLower == filterPath || strings.HasPrefix(keyLower, filterPath+"\\") {
			filtersLock.RUnlock()
			return
		}
	}
	filtersLock.RUnlock()

	select {
	case eventChan <- e:
	default:
		log.Warn().Str("path", e.KeyPath).Msg("event channel full, dropping event")
	}
}

func batcher(ctx context.Context, pub zmq4.Socket) {
	var currentBatch []Event
	ticker := time.NewTicker(time.Duration(appConfig.BatchIntervalMS) * time.Millisecond)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			if len(currentBatch) > 0 {
				sendBatch(pub, currentBatch)
			}
			log.Debug().Msg("batcher stopped")
			return
		case e := <-eventChan:
			currentBatch = append(currentBatch, e)
			if len(currentBatch) >= appConfig.BatchSize {
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
		log.Error().Err(err).Msg("failed to marshal batch")
		return
	}
	if err := pub.Send(zmq4.NewMsg(data)); err != nil {
		log.Error().Err(err).Int("events", len(events)).Msg("failed to send batch")
	} else {
		log.Debug().Int("events", len(events)).Msg("batch sent")
	}
}
