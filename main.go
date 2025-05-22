package main

import (
	"bufio"
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os/exec"
	"strings"
	"time"

	"github.com/joho/godotenv"
	_ "modernc.org/sqlite"
)

var (
	ipChan2    chan out
	taskIDChan chan procOut

	// (you can also promote the others if you want)
	processChannel chan procData
	localPortChan  chan string
	ipChan1        chan string
	pingResultChan chan PingResult
	IPDataChan     chan IPData
)

type out struct {
	remoteip   string
	localport  string
	remoteport string
	protocol   string
}

type procData struct {
	pid         string
	processName string
	localport   string
}
type procOut struct {
	process   string
	localport string
}
type IPData struct {
	IP         string
	LocalPort  string
	RemotePort string
	Protocol   string
	Town       string
	Country    string
	Latitude   float64
	Longitude  float64
	ASN        string
}
type PingResult struct {
	IP       string
	Duration string
	Err      error
}

type iplinks struct {
	Protocol    string
	LocalPort   string
	RemoteIP    string
	RemotePort  string
	ASN         string
	PID         string
	ProcessName string
	City        string
	Country     string
	Latitude    float64
	Longitude   float64
	PingResult  string
	IsLocal     bool
}

type iptrace struct {
	IP        string
	City      string
	Country   string
	Latitude  float64
	Longitude float64
	Ping      string
}

func ping(ip string) (string, error) {
	cmd := exec.Command("ping", "-n", "1", ip)
	output, err := cmd.Output()
	if err != nil {
		return "0", err
	}
	// Parse the output to find the time taken for the ping
	lines := strings.Split(string(output), "\n")
	for _, line := range lines {
		if strings.Contains(line, "time=") {
			parts := strings.Fields(line)
			for _, part := range parts {
				if strings.HasPrefix(part, "time=") {
					timeStr := strings.TrimPrefix(part, "time=")
					timeStr = strings.TrimSuffix(timeStr, "ms")
					return timeStr, nil
				}
			}
		}
	}
	return "0", fmt.Errorf("ping time not found")
}

func isIP(s string) bool {
	return net.ParseIP(s) != nil
}
func isPrivateIP(ipStr string) bool {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return false
	}
	privateBlocks := []string{
		"0.0.0.0/8",
		"127.0.0.1/8",
		"10.0.0.0/8",
		"172.16.0.0/12",
		"192.168.0.0/16",
		"::1/128",
		"fc00::/7",
	}
	for _, cidr := range privateBlocks {
		_, block, _ := net.ParseCIDR(cidr)
		if block.Contains(ip) {
			return true
		}
	}
	return false
}

func ip_trace(ip string) (latitude, longitude float64, city, country string, ASN string, err error) {
	if isPrivateIP(ip) {
		return 0, 0, "Your city", "Your country", "This is your device or local connection", nil
	}
	pairs, err := godotenv.Read()
	if err != nil {
		log.Fatalf("Could not read .env: %v", err)
	}

	apiKey := pairs["API_KEY"]
	if apiKey == "" {
		fmt.Println("API_KEY not set")
		return
	}

	latitude, longitude = 0, 0
	city, country = "Unknown", "Unknown"
	resp, err := http.Get("https://api.apibundle.io/ip-lookup?apikey=" + apiKey + "&ip=" + string(ip))
	if err != nil {
		log.Fatalln(err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		log.Fatalln(err)
	}

	var (
		result map[string]interface{}
	)

	if err := json.Unmarshal(body, &result); err != nil {
		log.Fatalln(err)
	}

	fmt.Println("result:", result)

	if raw, exists := result["latitude"]; exists && raw != nil {
		if lat, ok := raw.(float64); ok {
			latitude = lat
		} else {
			log.Println("latitude exists but is not a float64")
			return 0, 0, "Unknown", "Unknown", "unknown", nil
		}
	} else {
		log.Println("latitude missing or null")
		return 0, 0, "Unknown", "Unknown", "unknown", nil
	}
	if raw, ok := result["longitude"]; ok {
		longitude = raw.(float64)
	} else {
		log.Println("No longitude found")
	}

	if rawCity, exists := result["city"]; exists && rawCity != nil {
		if cityMap, ok := rawCity.(map[string]interface{}); ok {
			if nameRaw, exists := cityMap["name"]; exists && nameRaw != nil {
				if nameStr, ok := nameRaw.(string); ok && nameStr != "" {
					city = nameStr
				}
			}
		}
	}

	if rawCountry, exists := result["country"]; exists && rawCountry != nil {
		if countryMap, ok := rawCountry.(map[string]interface{}); ok {
			if nameRaw, exists := countryMap["name"]; exists && nameRaw != nil {
				if nameStr, ok := nameRaw.(string); ok && nameStr != "" {
					country = nameStr
				}
			}
		}
	}
	if rawConnection, exists := result["connections"]; exists && rawConnection != nil {
		if countryMap, ok := rawConnection.(map[string]interface{}); ok {
			if nameRaw, exists := countryMap["aso"]; exists && nameRaw != nil {
				if nameStr, ok := nameRaw.(string); ok && nameStr != "" {
					ASN = nameStr
				}
			}
		}
	}
	return

}

func hello(w http.ResponseWriter, req *http.Request) {
	db, err := sql.Open("sqlite", "./ipConnections.db")
	if err != nil {
		panic(err)
	}
	defer db.Close()
	// Test the connection
	err = db.Ping()
	if err != nil {
		panic(err)
	}

	cmd := exec.Command("netstat", "-ano")
	stdout, _ := cmd.StdoutPipe()
	_ = cmd.Start()
	scanner := bufio.NewScanner(stdout)
	for scanner.Scan() {
		line := scanner.Text()
		fields := strings.Fields(line)
		fmt.Println("fields:", fields)
		if len(fields) >= 4 && !(strings.Contains(fields[1], "[") || strings.Contains(fields[2], "*") || strings.Contains(fields[2], "::")) {
			protocol := fields[0]
			if protocol == "Proto" {
				continue
			} else {
				taskID := fields[len(fields)-1]

				if !(isPrivateIP(fields[2])) {

					localAddr := fields[1]
					localPortChan <- localAddr
					remoteAddr := fields[2]
					_, localPort, err := net.SplitHostPort(localAddr)
					taskIDChan <- procOut{
						process:   taskID,
						localport: localPort,
					}
					if err != nil {
						log.Println("Error parsing local address:", err)
						continue
					}
					remoteIP, remotePort, err := net.SplitHostPort(remoteAddr)
					if err != nil {
						log.Println("Error parsing remote address:", err)
						continue
					}
					if isPrivateIP(remoteIP) {
						continue
					} else {
						ipChan2 <- out{
							remoteip:   remoteIP,
							localport:  localPort,
							remoteport: remotePort,
							protocol:   protocol,
						}
					}

				}
			}
		} else {
			// IF YOU WANT TO 1. GET IPV6 SUPPORT OR 2. INCREASE SUPPORT FOR UDP THIS IS WHERE IT IS, AND THE NESTED IF STATEMENT
			// OF isPrivateIP(fields[2]) IS WHERE YOU NEED TO CHANGE THE CODE TO MAKE IT COMPATIBLE OR WORK ON "LOCAL NETWORKS"
			continue
		}
	}
	_ = cmd.Wait()
	insertConnections(context.Background(), db, pingResultChan, IPDataChan, processChannel, localPortChan)

	rows, err := db.Query("SELECT * FROM connection_data")
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	type ConnectionRow struct {
		PID         string  `json:"pid"`
		ProcessName string  `json:"process_name"`
		Protocol    string  `json:"protocol"`
		LocalPort   string  `json:"local_port"`
		RemoteIP    string  `json:"remote_ip"`
		RemotePort  string  `json:"remote_port"`
		ASN         string  `json:"asn"`
		City        string  `json:"city"`
		Country     string  `json:"country"`
		Latitude    float64 `json:"latitude"`
		Longitude   float64 `json:"longitude"`
		PingResult  string  `json:"ping_result"`
	}

	var results []ConnectionRow
	for rows.Next() {
		var r ConnectionRow
		if err := rows.Scan(
			&r.PID, &r.ProcessName, &r.Protocol, &r.LocalPort,
			&r.RemoteIP, &r.RemotePort, &r.ASN, &r.City, &r.Country,
			&r.Latitude, &r.Longitude, &r.PingResult,
		); err != nil {
			continue

		}
		fmt.Println("r:", r)
		results = append(results, r)
	}
	fmt.Println("results:", results)
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	json.NewEncoder(w).Encode(results)
}
func dev(w http.ResponseWriter, req *http.Request) {

	db, err := sql.Open("sqlite", "./ipConnections.db")
	if err != nil {
		panic(err)
	}

	// Test the connection
	err = db.Ping()
	if err != nil {
		panic(err)
	}

	fmt.Println("Connected to SQLite database!")
	rows, err := db.Query("SELECT * FROM connection_data")

	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	if err := json.NewEncoder(w).Encode(rows); err != nil {
		// we can’t write another HTTP error here, so just log
		fmt.Println("failed to write response:", err)
		return
	}

}

func headers(w http.ResponseWriter, req *http.Request) {
	if req.Method != http.MethodPost {
		http.Error(w, "Only POST allowed", http.StatusMethodNotAllowed)
		return
	}
	ip := strings.TrimPrefix(req.URL.Path, "/")
	if !isIP(ip) {
		http.Error(w, "Invalid IP address", http.StatusBadRequest)
		return
	}

	cmd := exec.Command("tracert", "-d", "-4", ip)
	cmdOutput, err := cmd.Output()
	if err != nil {
		http.Error(w, "Error executing command", http.StatusInternalServerError)
		return
	}

	output := string(cmdOutput)
	var iplist []string
	var hops []iptrace
	// split on the Windows line ending (“\r\n”) or just “\n”
	lines := strings.Split(output, "\r\n")
	for _, line := range lines {
		if line == "" {
			continue
		}
		// now you’ve got each line of tracert
		fields := strings.Fields(line)
		// fields[0] might be hop number, fields[1],fields[2],fields[3] the ms times, fields[4] the IP
		fmt.Printf("addr=%s\n",
			fields[len(fields)-1],
		)
		ip1 := strings.Split(fields[len(fields)-1], "addr=")[0]
		if isIP(ip1) {
			iplist = append(iplist, ip1)
			if err != nil {
				http.Error(w, "Error executing command 2", http.StatusInternalServerError)
				return
			}

		}
	}
	if iplist[len(iplist)-1] != ip {
		http.Error(w, "trace failed", http.StatusNotFound)
		return
	}

	for _, ip := range iplist {
		lat, lon, city, country, _, err := ip_trace(ip)
		if lat == 0 && lon == 0 {
			city = "Unknown"
			country = "Unknown"
		}
		if err != nil {
			return
		}
		pingTime, err := ping(ip)
		if err != nil {
			pingTime = "IMCP unreachable"
		}
		hops = append(hops, iptrace{
			IP:        ip,
			City:      city,
			Country:   country,
			Latitude:  lat,
			Longitude: lon,
			Ping:      pingTime,
		})
	}
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	if err := json.NewEncoder(w).Encode(hops); err != nil {
		// we can’t write another HTTP error here, so just log
		fmt.Println("failed to write response:", err)
	}

}

func insertConnections(
	ctx context.Context,
	db *sql.DB,
	pingCh <-chan PingResult,
	ipDataCh <-chan IPData,
	procCh <-chan procData,
	localPortCh <-chan string,
) {
	fmt.Println("insertConnections: starting")

	// Wipe the table first
	if _, err := db.Exec("DELETE FROM connection_data"); err != nil {
		log.Fatalf("insertConnections: failed to clear table: %v", err)
	}
	log.Println("Cleared connection_data table")

	// Prepare insert statement
	stmt, err := db.Prepare(`
		INSERT OR REPLACE INTO connection_data (
			PID, ProcessName, Protocol, LocalPort,
			RemoteIP, RemotePort, ASN, City, Country,
			Latitude, Longitude, PingResult
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
	`)
	if err != nil {
		log.Fatalf("insertConnections: prepare stmt: %v", err)
	}
	defer stmt.Close()

	// Buffers for incoming data
	pingMap := make(map[string]string)   // remoteIP -> ping duration
	ipMap := make(map[string]IPData)     // localPort -> IPData
	procMap := make(map[string]procData) // localPort -> procData
	localPorts := make(map[string]struct{})

	idleTimeout := 20 * time.Second
	timer := time.NewTimer(idleTimeout)
	defer timer.Stop()

	tryInsert := func(localPort string) {
		ipd, ipOk := ipMap[localPort]
		pd, procOk := procMap[localPort]
		ping, pingOk := pingMap[ipd.IP]

		if ipOk && procOk && pingOk {
			_, err := stmt.Exec(
				pd.pid,
				pd.processName,
				ipd.Protocol,
				ipd.LocalPort,
				ipd.IP,
				ipd.RemotePort,
				ipd.ASN,
				ipd.Town,
				ipd.Country,
				ipd.Latitude,
				ipd.Longitude,
				ping,
			)
			if err != nil {
				log.Printf("insertConnections: exec insert: %v", err)
			} else {
				log.Printf("Inserted: localPort=%v remoteIP=%v pid=%v", localPort, ipd.IP, pd.pid)
			}
			// Optionally delete these if you don't want duplicate inserts
			// delete(ipMap, localPort)
			// delete(procMap, localPort)
			// (do not delete pingMap since multiple ports may share an IP)
		}
	}

	for {
		select {
		case <-ctx.Done():
			log.Println("insertConnections: context cancelled, exiting.")
			return

		case localPort := <-localPortCh:
			if !timer.Stop() {
				<-timer.C
			}
			timer.Reset(idleTimeout)
			localPorts[localPort] = struct{}{}
			// try insert immediately in case we already have the rest
			tryInsert(localPort)

		case pr := <-pingCh:
			if !timer.Stop() {
				<-timer.C
			}
			timer.Reset(idleTimeout)
			pingMap[pr.IP] = pr.Duration
			// for all localPorts using this IP, try insert
			for lp := range localPorts {
				if ipd, ok := ipMap[lp]; ok && ipd.IP == pr.IP {
					tryInsert(lp)
				}
			}

		case ipd := <-ipDataCh:
			if !timer.Stop() {
				<-timer.C
			}
			timer.Reset(idleTimeout)
			ipMap[ipd.LocalPort] = ipd
			localPorts[ipd.LocalPort] = struct{}{}
			tryInsert(ipd.LocalPort)

		case pd := <-procCh:
			if !timer.Stop() {
				<-timer.C
			}
			timer.Reset(idleTimeout)
			procMap[pd.localport] = pd
			localPorts[pd.localport] = struct{}{}
			tryInsert(pd.localport)

		case <-timer.C:
			log.Println("insertConnections: idle timeout, returning")
			return
		}
	}
}

func execWithRetry(db *sql.DB, query string, args ...interface{}) error {
	const (
		maxRetries = 15
		delay      = 100 * time.Millisecond
	)
	for i := 0; i < maxRetries; i++ {
		if _, err := db.Exec(query, args...); err != nil {
			// only retry if it's the locked‐database error
			if strings.Contains(err.Error(), "database is locked") {
				time.Sleep(delay)
				continue
			}
			return err // some other error: bail out
		}
		return nil // success
	}
	return fmt.Errorf("execWithRetry: still locked after %d retries", maxRetries)
}

func main() {
	fmt.Println("Starting server...")
	localPortChan = make(chan string, 500)
	processChannel = make(chan procData, 500)
	ipChan2 = make(chan out, 500)
	taskIDChan = make(chan procOut, 500)
	ipChan1 = make(chan string, 500)
	pingResultChan = make(chan PingResult, 500)
	IPDataChan = make(chan IPData, 500)

	db, err := sql.Open("sqlite", "./ipConnections.db")
	if err != nil {
		panic(err)
	}
	defer db.Close()

	// Test the connection
	err = db.Ping()
	if err != nil {
		panic(err)
	}

	// right after sql.Open:
	db.SetMaxOpenConns(1)

	// let SQLite wait rather than fail immediately when it’s locked
	if _, err := db.Exec("PRAGMA busy_timeout = 5000"); err != nil {
		log.Fatal(err)
	}

	// allow readers to proceed even while a writer is in progress
	if _, err := db.Exec("PRAGMA journal_mode = WAL"); err != nil {
		log.Fatal(err)
	}

	// ✅ Start goroutines to consume from channels (for debugging/logging)
	const workerCount = 100 // Even with 2 cores, you can run 10 workers

	for i := 0; i < workerCount; i++ {
		seen := make(map[string]struct{}, 50)
		go func() {

			for ip := range ipChan1 {
				// skip if we've already pinged it
				if _, ok := seen[ip]; ok {
					continue
				}
				seen[ip] = struct{}{}

				// do the ping
				pingTime, err := ping(ip)
				if err != nil {
					pingTime = "ICMP unreachable"
				}
				// log the result
				fmt.Println("chan1 IP:", ip, "Ping Time:", pingTime)
				pingResultChan <- PingResult{
					IP:       ip,
					Duration: pingTime,
					Err:      err,
				}
			}
		}()
	}

	type writesql struct {
		ip        string
		city      string
		country   string
		latitude  float64
		longitude float64
		ping      string
		asn       string
	}
	writesqlchan := make(chan writesql, 500)

	go func() {
		for o := range writesqlchan {
			fmt.Println("writesql-IP:", o.ip, "City:", o.city, "Country:", o.country)
			err := execWithRetry(db, `
				INSERT OR IGNORE INTO ip_data
				(IP, City, Country, latitude, longitude, ping, ASN)
				VALUES (?, ?, ?, ?, ?, ?, ?)`,
				o.ip, o.city, o.country, o.latitude, o.longitude, o.ping, o.asn,
			)
			if err != nil {
				log.Fatal("Insert failed:", err)
			}
		}
	}()
	const workerCount2 = 1 // i am too lazy and unskilled (this code is already eating me away) so someone please deploy concurrency
	for j := 0; j < workerCount2; j++ {
		go func() {
			for o := range ipChan2 {
				ipChan1 <- o.remoteip
				localport := o.localport
				ip := o.remoteip
				remoteport := o.remoteport
				protocol := o.protocol

				fmt.Println("chan2 IP:", ip)
				row := db.QueryRow(`
    SELECT IP, City, Country, latitude, longitude, ping, ASN, created_at
    FROM ip_data
    WHERE IP = ?
`, ip)

				ipAddr := ""
				city := sql.NullString{}
				country := sql.NullString{}
				latitude := sql.NullFloat64{}
				longitude := sql.NullFloat64{}
				ping := sql.NullString{}
				asn := sql.NullString{}
				createdAt := time.Time{}

				err := row.Scan(&ipAddr, &city, &country, &latitude, &longitude, &ping, &asn, &createdAt)
				if err != nil {
					if err == sql.ErrNoRows {
						fmt.Println("No entry found for IP:", ip)
						latitude, longitude, city, country, asn, err := ip_trace(ip)
						if err != nil {
							fmt.Println("Error in ip_trace:", err)
							continue
						}
						writesqlchan <- writesql{
							ip:        ip,
							city:      city,
							country:   country,
							latitude:  latitude,
							longitude: longitude,
							ping:      "NOT BEING USED",
							asn:       asn,
						}
					} else {
						log.Fatal("Query error:", err)
					}
				} else {
					if createdAt.Before(time.Now().Add(-168 * time.Hour)) {

						// Entry is older than 7 days, so we can update it
						// get details about ip from ip_trace
						latitude, longitude, city, country, asn, err := ip_trace(ip)
						if err != nil {
							fmt.Println("Error in ip_trace:", err)
							continue
						}
						_, err = db.Exec(`
			UPDATE ip_data
			SET City = ?, Country = ?, latitude = ?, longitude = ?, ASN = ?
			WHERE IP = ?`, city, country, latitude, longitude, asn, ip)
						if err != nil {
							log.Fatal("Update error:", err)
						} else {
							fmt.Println("Updated entry for IP:", ip)
						}
					} else {
						fmt.Println("Entry for IP is still valid:", ip)
					}

				}
				// Send the IP data to the channel
				IPDataChan <- IPData{

					IP:         ip,
					Town:       city.String,      // unwrap NullString
					Country:    country.String,   // …
					Latitude:   latitude.Float64, // unwrap NullFloat64
					Longitude:  longitude.Float64,
					ASN:        asn.String,
					LocalPort:  localport,
					RemotePort: remoteport,
					Protocol:   protocol,
				}
			}
		}()
	}

	const workers = 100
	for k := 0; k < workers; k++ {
		go func() {
			for o := range taskIDChan {
				pid := o.process

				cmd := exec.Command("powershell", "-Command",
					fmt.Sprintf("(Get-Process -Id %s).ProcessName", pid),
				)
				output, err := cmd.Output()
				if err != nil {
					log.Printf("Get-Process %s failed: %v", pid, err)
					continue
				}
				name := strings.TrimSpace(string(output))
				log.Printf("Resolved PID=%s → %q (port %s)", pid, name, o.localport)

				processChannel <- procData{
					pid:         pid,
					processName: name,
					localport:   o.localport,
				}
			}
		}()
	}

	http.HandleFunc("/netstat", dev)
	http.HandleFunc("/connections", hello)
	http.HandleFunc("/", headers)

	http.ListenAndServe("127.0.0.1:8090", nil)
	fmt.Println("Server started at http://127.0.0.1:8090")
}
