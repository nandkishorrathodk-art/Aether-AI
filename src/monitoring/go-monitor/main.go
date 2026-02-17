package main

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"image/png"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"github.com/kbinani/screenshot"
)

type Screenshot struct {
	Timestamp   string `json:"timestamp"`
	Width       int    `json:"width"`
	Height      int    `json:"height"`
	Format      string `json:"format"`
	Base64Data  string `json:"base64_data,omitempty"`
	FilePath    string `json:"file_path,omitempty"`
}

type MonitorConfig struct {
	Interval       int    `json:"interval"`
	SaveScreenshot bool   `json:"save_screenshot"`
	DataPath       string `json:"data_path"`
}

type MonitorService struct {
	config      MonitorConfig
	running     bool
	latest      *Screenshot
	totalCount  int64
	stopChan    chan bool
}

func NewMonitorService(config MonitorConfig) *MonitorService {
	if config.SaveScreenshot {
		os.MkdirAll(config.DataPath, 0755)
	}
	return &MonitorService{
		config:   config,
		stopChan: make(chan bool),
	}
}

func (m *MonitorService) CaptureScreen() (*Screenshot, error) {
	n := screenshot.NumActiveDisplays()
	if n == 0 {
		return nil, fmt.Errorf("no active displays found")
	}

	bounds := screenshot.GetDisplayBounds(0)
	img, err := screenshot.CaptureRect(bounds)
	if err != nil {
		return nil, err
	}

	timestamp := time.Now()
	screenshot := &Screenshot{
		Timestamp: timestamp.Format(time.RFC3339),
		Width:     bounds.Dx(),
		Height:    bounds.Dy(),
		Format:    "png",
	}

	if m.config.SaveScreenshot {
		filename := fmt.Sprintf("screenshot_%s.png", timestamp.Format("20060102_150405"))
		filePath := filepath.Join(m.config.DataPath, filename)
		
		file, err := os.Create(filePath)
		if err == nil {
			png.Encode(file, img)
			file.Close()
			screenshot.FilePath = filePath
		}
	}

	var buf bytes.Buffer
	png.Encode(&buf, img)
	screenshot.Base64Data = base64.StdEncoding.EncodeToString(buf.Bytes())

	return screenshot, nil
}

func (m *MonitorService) Start() {
	if m.running {
		return
	}
	m.running = true

	go func() {
		ticker := time.NewTicker(time.Duration(m.config.Interval) * time.Second)
		defer ticker.Stop()

		for {
			select {
			case <-ticker.C:
				screenshot, err := m.CaptureScreen()
				if err == nil {
					m.latest = screenshot
					m.totalCount++
				}
			case <-m.stopChan:
				return
			}
		}
	}()
}

func (m *MonitorService) Stop() {
	if !m.running {
		return
	}
	m.running = false
	m.stopChan <- true
}

func (m *MonitorService) Status() map[string]interface{} {
	return map[string]interface{}{
		"running":          m.running,
		"capture_interval": m.config.Interval,
		"screenshot_count": m.totalCount,
		"latest":           m.latest,
	}
}

var monitor *MonitorService

func handleStart(w http.ResponseWriter, r *http.Request) {
	monitor.Start()
	json.NewEncoder(w).Encode(map[string]string{"status": "started"})
}

func handleStop(w http.ResponseWriter, r *http.Request) {
	monitor.Stop()
	json.NewEncoder(w).Encode(map[string]string{"status": "stopped"})
}

func handleStatus(w http.ResponseWriter, r *http.Request) {
	json.NewEncoder(w).Encode(monitor.Status())
}

func handleCapture(w http.ResponseWriter, r *http.Request) {
	screenshot, err := monitor.CaptureScreen()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	json.NewEncoder(w).Encode(screenshot)
}

func main() {
	config := MonitorConfig{
		Interval:       30,
		SaveScreenshot: false,
		DataPath:       "./data/monitoring",
	}

	if configPath := os.Getenv("MONITOR_CONFIG"); configPath != "" {
		data, err := os.ReadFile(configPath)
		if err == nil {
			json.Unmarshal(data, &config)
		}
	}

	monitor = NewMonitorService(config)

	http.HandleFunc("/start", handleStart)
	http.HandleFunc("/stop", handleStop)
	http.HandleFunc("/status", handleStatus)
	http.HandleFunc("/capture", handleCapture)

	port := os.Getenv("MONITOR_PORT")
	if port == "" {
		port = "9001"
	}

	fmt.Printf("Screen Monitor Service running on :%s\n", port)
	http.ListenAndServe(":"+port, nil)
}
