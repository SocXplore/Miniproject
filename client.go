package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/csv"
	"encoding/hex"
	"encoding/json"
	"image/jpeg"

	"io"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/kbinani/screenshot"
)

var (
	// CHANGE THIS WHEN USING REAL NETWORK
	serverIP        = "192.168.42.1:8080"
	clientID        = getClientID()
	uploadURL       = "http://" + serverIP + "/upload?id=" + clientID
	cmdPollURL      = "http://" + serverIP + "/cmd/poll?id=" + clientID
	cmdResultURL    = "http://" + serverIP + "/cmd/result?id=" + clientID
	procPollURL     = "http://" + serverIP + "/proc/poll?id=" + clientID
	procResultURL   = "http://" + serverIP + "/proc/result?id=" + clientID
	svcPollURL      = "http://" + serverIP + "/svc/poll?id=" + clientID
	svcResultURL    = "http://" + serverIP + "/svc/result?id=" + clientID
	svcStopPollURL  = "http://" + serverIP + "/svc/stop/poll?id=" + clientID
	svcStartPollURL = "http://" + serverIP + "/svc/start/poll?id=" + clientID
	filePollURL     = "http://" + serverIP + "/file/poll?id=" + clientID
	fileResultURL   = "http://" + serverIP + "/file/result?id=" + clientID
	killURL         = "http://" + serverIP + "/kill?id=" + clientID
	edrCmdPollURL   = "http://" + serverIP + "/edr/cmd/poll?id=" + clientID
)

/* ---------- TYPES ---------- */

type ShellCommand struct {
	Command string
}

type ShellResponse struct {
	Output string
}

type Process struct {
	PID            int    `json:"pid"`
	Name           string `json:"name"`
	ExecutablePath string `json:"executable_path"`
	CommandLine    string `json:"command_line"`
	Hash           string `json:"hash"`
}

type Service struct {
	Name        string `json:"name"`
	DisplayName string `json:"display_name"`
	Status      string `json:"status"`
	StartType   string `json:"start_type"`
	PathName    string `json:"path_name"`
	Hash        string `json:"hash"`
}

type KillRequest struct {
	PID int `json:"pid"`
}

type FileInfo struct {
	Name    string `json:"name"`
	Size    int64  `json:"size"`
	IsDir   bool   `json:"is_dir"`
	ModTime string `json:"mod_time"`
	Path    string `json:"path"`
}

type FileRequest struct {
	Action string `json:"action"`
	Path   string `json:"path"`
}

type EDRCommand struct {
	Type string `json:"type"` // "isolate" or "unisolate"
}

type StopServiceRequest struct {
	Service string `json:"service"`
}

/* ---------- HELPERS ---------- */

func getClientID() string {
	hostname, err := os.Hostname()
	if err != nil {
		return "unknown"
	}
	return hostname
}

func sendSystemInfo() {
	info := map[string]string{
		"os":      runtime.GOOS,
		"version": runtime.Version(),
	}
	data, _ := json.Marshal(info)
	resp, err := http.Post(uploadURL, "application/json", bytes.NewReader(data))
	if err != nil {
		log.Println("Isolax: sendSystemInfo failed:", err)
		return
	}
	resp.Body.Close()
	log.Println("Isolax: system info sent to", uploadURL)
}

func runCmd(name string, args ...string) {
	cmd := exec.Command(name, args...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		log.Printf("Isolax: %s %v FAILED: %v | out: %s", name, args, err, string(out))
	} else {
		log.Printf("Isolax: %s %v OK: %s", name, args, string(out))
	}
}

func hashFile(path string) string {
	if path == "" {
		return "N/A"
	}
	f, err := os.Open(path)
	if err != nil {
		return "ACCESS_DENIED"
	}
	defer f.Close()

	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "READ_ERROR"
	}

	return hex.EncodeToString(h.Sum(nil))
}

/* ---------- ISOLATION (WINDOWS + LINUX) ---------- */

func applyIsolation() {
	serverHost := strings.Split(serverIP, ":")[0]

	switch runtime.GOOS {
	case "windows":
		log.Println("Isolax: applying STRONG Windows isolation for", serverHost)

		// 1. Purge ALL existing rules to ensure no allow rules persist
		log.Println("Isolax: PURGING all existing firewall rules...")
		runCmd("netsh", "advfirewall", "firewall", "delete", "rule", "name=all")

		// 2. Set Default Policy to BLOCK
		runCmd("netsh", "advfirewall", "set", "allprofiles", "state", "on") 
		runCmd("netsh", "advfirewall", "set", "allprofiles", "firewallpolicy", "blockinbound,blockoutbound")
		log.Println("Isolax: applying STRONG Windows isolation")

		// 3. Allow Only C2
		// Allow OUTBOUND to controller
		runCmd("netsh", "advfirewall", "firewall", "add", "rule",
			"name=IsolaxAllowOut", "dir=out", "action=allow",
			"remoteip="+serverHost, "profile=any", "protocol=any")

		// Allow INBOUND from controller (optional but nice)
		runCmd("netsh", "advfirewall", "firewall", "add", "rule",
			"name=IsolaxAllowIn", "dir=in", "action=allow",
			"remoteip="+serverHost, "profile=any", "protocol=any")

		log.Println("Isolax: Windows isolation ACTIVE (only", serverHost, "allowed)")

	case "linux":
		log.Println("Isolax: applying Linux isolation for", serverHost)

		// Clean previous chain if exists
		runCmd("iptables", "-D", "OUTPUT", "-j", "ISOLAX-OUT")
		runCmd("iptables", "-F", "ISOLAX-OUT")
		runCmd("iptables", "-X", "ISOLAX-OUT")

		// New chain
		runCmd("iptables", "-N", "ISOLAX-OUT")
		// allow traffic to controller
		runCmd("iptables", "-A", "ISOLAX-OUT", "-d", serverHost, "-j", "ACCEPT")
		// drop everything else
		runCmd("iptables", "-A", "ISOLAX-OUT", "-j", "DROP")
		// hook chain
		runCmd("iptables", "-A", "OUTPUT", "-j", "ISOLAX-OUT")

		log.Println("Isolax: Linux isolation ACTIVE (only", serverHost, "allowed)")

	default:
		log.Println("Isolax: isolation not implemented for OS:", runtime.GOOS)
	}
}

func removeIsolation() {
	switch runtime.GOOS {
	case "windows":
		log.Println("Isolax: removing Windows isolation (reset firewall)")
		runCmd("netsh", "advfirewall", "reset")

	case "linux":
		log.Println("Isolax: removing Linux isolation (iptables cleanup)")
		runCmd("iptables", "-D", "OUTPUT", "-j", "ISOLAX-OUT")
		runCmd("iptables", "-F", "ISOLAX-OUT")
		runCmd("iptables", "-X", "ISOLAX-OUT")

	default:
		log.Println("Isolax: removeIsolation not implemented for OS:", runtime.GOOS)
	}
}

func edrPoller() {
	log.Println("Isolax: EDR poller started →", edrCmdPollURL)

	for {
		resp, err := http.Get(edrCmdPollURL)
		if err != nil {
			log.Println("Isolax: edrPoll error:", err)
			time.Sleep(5 * time.Second)
			continue
		}
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()

		var cmd EDRCommand
		if json.Unmarshal(body, &cmd) != nil || cmd.Type == "" {
			time.Sleep(2 * time.Second)
			continue
		}

		log.Println("Isolax: received EDR command:", cmd.Type)

		if cmd.Type == "isolate" {
			applyIsolation()
		} else if cmd.Type == "unisolate" {
			removeIsolation()
		}

		time.Sleep(1 * time.Second)
	}
}

/* ---------- PROCESSES & FILES ---------- */

func listProcesses() ([]Process, error) {
	var processes []Process

	if runtime.GOOS == "windows" {
		// Use PowerShell to get process info via WMI/CIM
		// Get-CimInstance Win32_Process | Select-Object ProcessId, Name, ExecutablePath, CommandLine | ConvertTo-Csv -NoTypeInformation
		psCmd := "Get-CimInstance Win32_Process | Select-Object ProcessId, Name, ExecutablePath, CommandLine | ConvertTo-Csv -NoTypeInformation"
		cmd := exec.Command("powershell", "-NoProfile", "-Command", psCmd)
		out, err := cmd.Output()
		if err != nil {
			return nil, err
		}

		// Parse CSV
		r := csv.NewReader(bytes.NewReader(out))
		records, err := r.ReadAll()
		if err != nil {
			return nil, err
		}

		// Map headers
		var headerIdxs = make(map[string]int)
		if len(records) > 0 {
			for i, col := range records[0] {
				headerIdxs[col] = i
			}
		}

		for i, row := range records {
			if i == 0 {
				continue
			} // skip header
			if len(row) < 3 {
				continue
			}

			// Helper to get field safely
			get := func(name string) string {
				if idx, ok := headerIdxs[name]; ok && idx < len(row) {
					return row[idx]
				}
				return ""
			}

			pidStr := get("ProcessId")
			pid, _ := strconv.Atoi(pidStr)
			name := get("Name")
			exe := get("ExecutablePath")
			cmdLine := get("CommandLine")

			if pid == 0 {
				continue
			}

			// Hash the exe
			hash := "N/A"
			if exe != "" {
				hash = hashFile(exe)
			}

			processes = append(processes, Process{
				PID:            pid,
				Name:           name,
				ExecutablePath: exe,
				CommandLine:    cmdLine,
				Hash:           hash,
			})
		}
	} else {
		// Linux /proc
		files, err := ioutil.ReadDir("/proc")
		if err != nil {
			return nil, err
		}

		for _, f := range files {
			if !f.IsDir() {
				continue
			}
			pid, err := strconv.Atoi(f.Name())
			if err != nil {
				continue // not a pid directory
			}

			// Path
			exePath, _ := os.Readlink(filepath.Join("/proc", f.Name(), "exe"))

			// Cmdline
			cmdContent, _ := ioutil.ReadFile(filepath.Join("/proc", f.Name(), "cmdline"))
			cmdLine := strings.ReplaceAll(string(cmdContent), "\x00", " ")
			cmdLine = strings.TrimSpace(cmdLine)

			// Name (comm)
			commContent, _ := ioutil.ReadFile(filepath.Join("/proc", f.Name(), "comm"))
			name := strings.TrimSpace(string(commContent))
			if name == "" {
				name = filepath.Base(exePath)
			}

			// Hash
			hash := "N/A"
			if exePath != "" {
				hash = hashFile(exePath)
			}

			processes = append(processes, Process{
				PID:            pid,
				Name:           name,
				ExecutablePath: exePath,
				CommandLine:    cmdLine,
				Hash:           hash,
			})
		}
	}



	return processes, nil
}

func listFiles(path string) ([]FileInfo, error) {
	var files []FileInfo

	if path == "/" && runtime.GOOS == "windows" {
		return getWindowsDrives()
	}

	entries, err := ioutil.ReadDir(path)
	if err != nil {
		return nil, err
	}

	if path != "/" && path != "" {
		parent := filepath.Dir(path)
		files = append(files, FileInfo{
			Name:  "..",
			IsDir: true,
			Path:  parent,
		})
	}

	for _, entry := range entries {
		fullPath := filepath.Join(path, entry.Name())
		files = append(files, FileInfo{
			Name:    entry.Name(),
			Size:    entry.Size(),
			IsDir:   entry.IsDir(),
			ModTime: entry.ModTime().Format("2006-01-02 15:04:05"),
			Path:    fullPath,
		})
	}

	return files, nil
}

func getWindowsDrives() ([]FileInfo, error) {
	var drives []FileInfo
	for i := 'A'; i <= 'Z'; i++ {
		drive := string(i) + ":\\"
		if _, err := os.Stat(drive); err == nil {
			drives = append(drives, FileInfo{
				Name:  drive,
				IsDir: true,
				Path:  drive,
			})
		}
	}
	return drives, nil
}

func listServices() ([]Service, error) {
	var services []Service

	if runtime.GOOS == "windows" {
		// Use PowerShell to get service info via WMI
		// Get-CimInstance Win32_Service | Select-Object Name, DisplayName, State, StartMode, PathName | ConvertTo-Csv -NoTypeInformation
		psCmd := "Get-CimInstance Win32_Service | Select-Object Name, DisplayName, State, StartMode, PathName | ConvertTo-Csv -NoTypeInformation"
		cmd := exec.Command("powershell", "-NoProfile", "-Command", psCmd)
		out, err := cmd.Output()
		if err != nil {
			log.Printf("Isolax: PowerShell service query failed: %v", err)
			return nil, err
		}

		// Remove UTF-8 BOM if present (PowerShell often adds this)
		outStr := string(out)
		if strings.HasPrefix(outStr, "\uFEFF") {
			outStr = strings.TrimPrefix(outStr, "\uFEFF")
		}

		// Parse CSV
		r := csv.NewReader(strings.NewReader(outStr))
		r.FieldsPerRecord = -1 // Allow variable number of fields
		records, err := r.ReadAll()
		if err != nil {
			log.Printf("Isolax: CSV parsing failed: %v", err)
			return nil, err
		}

		if len(records) == 0 {
			log.Printf("Isolax: No service records returned from PowerShell")
			return services, nil
		}

		// Map headers
		var headerIdxs = make(map[string]int)
		for i, col := range records[0] {
			headerIdxs[col] = i
		}

		log.Printf("Isolax: Found %d service records (including header)", len(records))

		for i, row := range records {
			if i == 0 {
				continue
			} // skip header

			if len(row) < 3 {
				log.Printf("Isolax: Skipping record %d - insufficient fields (%d < 3): %v", i, len(row), row)
				continue
			}

			// Helper to get field safely
			get := func(name string) string {
				if idx, ok := headerIdxs[name]; ok && idx < len(row) {
					return row[idx]
				}
				return ""
			}

			name := get("Name")
			displayName := get("DisplayName")
			status := get("State")
			startType := get("StartMode")
			pathName := get("PathName")

			if name == "" {
				log.Printf("Isolax: Skipping service record - empty Name field at index %d", i)
				continue
			}

			// Hash the service executable
			hash := "N/A"
			if pathName != "" {
				// Extract executable path from quoted paths
				pathName = strings.Trim(pathName, "\"")
				// Remove command line arguments if present
				parts := strings.Fields(pathName)
				if len(parts) > 0 {
					hash = hashFile(parts[0])
				}
			}

			services = append(services, Service{
				Name:        name,
				DisplayName: displayName,
				Status:      status,
				StartType:   startType,
				PathName:    pathName,
				Hash:        hash,
			})
		}

		log.Printf("Isolax: Successfully collected %d services from Windows", len(services))
	} else {
		// Linux systemd services
		cmd := exec.Command("systemctl", "list-units", "--type=service", "--all", "--no-legend", "--output=json")
		out, err := cmd.Output()
		if err != nil {
			return nil, err
		}

		var systemdServices []map[string]interface{}
		if err := json.Unmarshal(out, &systemdServices); err != nil {
			return nil, err
		}

		for _, svc := range systemdServices {
			name, _ := svc["unit"].(string)
			if name == "" {
				continue
			}

			// Remove .service suffix
			name = strings.TrimSuffix(name, ".service")

			// Get active state
			activeState, _ := svc["active"].(string)

			// Try to find service file and hash it
			hash := "N/A"
			commonPaths := []string{
				"/etc/systemd/system/" + name + ".service",
				"/usr/lib/systemd/system/" + name + ".service",
				"/lib/systemd/system/" + name + ".service",
			}
			for _, path := range commonPaths {
				if _, err := os.Stat(path); err == nil {
					hash = hashFile(path)
					break
				}
			}

			services = append(services, Service{
				Name:        name,
				DisplayName: name,
				Status:      activeState,
				StartType:   "systemd",
				PathName:    "",
				Hash:        hash,
			})
		}
	}

	return services, nil
}

/* ---------- POLLERS ---------- */

func shellPoller() {
	for {
		resp, err := http.Get(cmdPollURL)
		if err != nil {
			time.Sleep(5 * time.Second)
			continue
		}
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()

		var cmd ShellCommand
		if json.Unmarshal(body, &cmd) != nil || cmd.Command == "" {
			time.Sleep(2 * time.Second)
			continue
		}

		var out []byte
		if runtime.GOOS == "windows" {
			out, _ = exec.Command("cmd", "/C", cmd.Command).CombinedOutput()
		} else {
			out, _ = exec.Command("sh", "-c", cmd.Command).CombinedOutput()
		}

		res := ShellResponse{Output: string(out)}
		data, _ := json.Marshal(res)
		_, _ = http.Post(cmdResultURL, "application/json", bytes.NewReader(data))

		time.Sleep(1 * time.Second)
	}
}

func procPoller() {
	for {
		resp, err := http.Get(procPollURL)
		if err != nil {
			time.Sleep(2 * time.Second)
			continue
		}
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()

		var cmd map[string]string
		if json.Unmarshal(body, &cmd) != nil || cmd["command"] != "list" {
			time.Sleep(300 * time.Millisecond)
			continue
		}

		procs, err := listProcesses()
		if err != nil {
			time.Sleep(500 * time.Millisecond)
			continue
		}

		payload := map[string][]Process{"processes": procs}
		data, _ := json.Marshal(payload)
		_, _ = http.Post(procResultURL, "application/json", bytes.NewReader(data))

		time.Sleep(300 * time.Millisecond)
	}
}

func svcPoller() {
	for {
		resp, err := http.Get(svcPollURL)
		if err != nil {
			log.Printf("Isolax: svcPoller http.Get failed: %v", err)
			time.Sleep(2 * time.Second)
			continue
		}
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()

		var cmd map[string]string
		if json.Unmarshal(body, &cmd) != nil || cmd["command"] != "list" {
			time.Sleep(300 * time.Millisecond)
			continue
		}

		log.Println("Isolax: svcPoller received 'list' command, fetching services...")
		svcs, err := listServices()
		if err != nil {
			log.Printf("Isolax: listServices() failed: %v", err)
			time.Sleep(500 * time.Millisecond)
			continue
		}

		log.Printf("Isolax: svcPoller collected %d services, sending to server...", len(svcs))
		payload := map[string][]Service{"services": svcs}
		data, _ := json.Marshal(payload)
		resp, err = http.Post(svcResultURL, "application/json", bytes.NewReader(data))
		if err != nil {
			log.Printf("Isolax: svcPoller http.Post failed: %v", err)
		} else {
			log.Printf("Isolax: svcPoller successfully posted %d services to %s", len(svcs), svcResultURL)
			resp.Body.Close()
		}

		time.Sleep(300 * time.Millisecond)
	}
}

func svcStopPoller() {
	for {
		resp, err := http.Get(svcStopPollURL)
		if err != nil {
			time.Sleep(2 * time.Second)
			continue
		}
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()

		var req StopServiceRequest
		if json.Unmarshal(body, &req) != nil || req.Service == "" {
			time.Sleep(1 * time.Second)
			continue
		}

		log.Println("Isolax: stop service request for:", req.Service)

		if runtime.GOOS == "windows" {
			err := exec.Command("net", "stop", req.Service).Run()
			if err != nil {
				log.Printf("Isolax: failed to stop service %s: %v", req.Service, err)
			} else {
				log.Printf("Isolax: successfully stopped service %s", req.Service)
			}
		} else {
			err := exec.Command("systemctl", "stop", req.Service).Run()
			if err != nil {
				log.Printf("Isolax: failed to stop service %s: %v", req.Service, err)
			} else {
				log.Printf("Isolax: successfully stopped service %s", req.Service)
			}
		}

		time.Sleep(1 * time.Second)
	}
}

func svcStartPoller() {
	for {
		resp, err := http.Get(svcStartPollURL)
		if err != nil {
			time.Sleep(2 * time.Second)
			continue
		}
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()

		var req StopServiceRequest
		if json.Unmarshal(body, &req) != nil || req.Service == "" {
			time.Sleep(1 * time.Second)
			continue
		}

		log.Println("Isolax: start service request for:", req.Service)

		if runtime.GOOS == "windows" {
			err := exec.Command("net", "start", req.Service).Run()
			if err != nil {
				log.Printf("Isolax: failed to start service %s: %v", req.Service, err)
			} else {
				log.Printf("Isolax: successfully started service %s", req.Service)
			}
		} else {
			err := exec.Command("systemctl", "start", req.Service).Run()
			if err != nil {
				log.Printf("Isolax: failed to start service %s: %v", req.Service, err)
			} else {
				log.Printf("Isolax: successfully started service %s", req.Service)
			}
		}

		time.Sleep(1 * time.Second)
	}
}

func filePoller() {
	for {
		resp, err := http.Get(filePollURL)
		if err != nil {
			time.Sleep(2 * time.Second)
			continue
		}
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()

		var req FileRequest
		if json.Unmarshal(body, &req) != nil || req.Action == "" {
			time.Sleep(300 * time.Millisecond)
			continue
		}

		switch req.Action {
		case "list":
			files, err := listFiles(req.Path)
			if err != nil {
				files = []FileInfo{}
			}
			data, _ := json.Marshal(files)
			_, _ = http.Post(fileResultURL, "application/json", bytes.NewReader(data))
		}

		time.Sleep(300 * time.Millisecond)
	}
}

func processKiller() {
	for {
		resp, err := http.Get(killURL)
		if err != nil {
			time.Sleep(5 * time.Second)
			continue
		}
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()

		var req KillRequest
		if json.Unmarshal(body, &req) != nil || req.PID == 0 {
			time.Sleep(3 * time.Second)
			continue
		}

		if runtime.GOOS == "windows" {
			_ = exec.Command("taskkill", "/PID", strconv.Itoa(req.PID), "/F").Run()
		} else {
			if p, err := os.FindProcess(req.PID); err == nil {
				_ = p.Kill()
			}
		}

		time.Sleep(3 * time.Second)
	}
}

/* ---------- MAIN ---------- */

func main() {
	log.Printf("[Isolax] client %s starting, server %s, OS %s", clientID, serverIP, runtime.GOOS)

	// heartbeat for system info (so server always sees client)
	go func() {
		for {
			sendSystemInfo()
			time.Sleep(10 * time.Second)
		}
	}()

	go edrPoller()
	go shellPoller()
	go procPoller()
	go svcPoller()
	go svcStopPoller()
	go svcStartPoller()
	go filePoller()
	go processKiller()

	for {
		img, err := screenshot.CaptureDisplay(0)
		if err != nil {
			log.Println("Isolax: screenshot failed:", err)
			time.Sleep(5 * time.Second)
			continue
		}

		var buf bytes.Buffer
		if err := jpeg.Encode(&buf, img, &jpeg.Options{Quality: 75}); err != nil {
			log.Println("Isolax: jpeg encode failed:", err)
			continue
		}

		// Use NewRequest to set headers
		req, err := http.NewRequest("POST", uploadURL, &buf)
		if err != nil {
			log.Println("Isolax: failed to create request:", err)
			continue
		}
		req.Header.Set("Content-Type", "image/jpeg")
		req.Header.Set("X-Client-OS", runtime.GOOS)
		req.Header.Set("X-Client-Ver", runtime.Version())
		hostname, _ := os.Hostname()
		req.Header.Set("X-Client-Hostname", hostname)

		client := &http.Client{Timeout: 5 * time.Second}
		resp, err := client.Do(req)
		if err == nil {
			resp.Body.Close()
		} else {
			log.Println("Isolax: upload frame failed:", err)
		}

		time.Sleep(100 * time.Millisecond)
	}
}
