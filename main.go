package main

import (
	"bufio"
	"crypto/rand"
	"embed"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"io/fs"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"gopkg.in/yaml.v2"
)

var (
	config        Config
	dataDir       string // Директория, из которой будут скачиваться файлы
	allowlistPath string
	blocklistPath string
	mu            sync.Mutex
)

//go:embed static/*
var content embed.FS

type List struct {
	Blocklist []string `json:"blocklist"`
	Allowlist []string `json:"allowlist"`
}

type Config struct {
	EnableLogging        bool   `yaml:"enableLogging"`
	EnableConsoleLogging bool   `yaml:"enableConsoleLogging"`
	LogDir               string `yaml:"logDir"`
	LogFile              string `yaml:"logFile"`
	DataDir              string `yaml:"dataDir"`
	AllowlistPath        string `yaml:"allowlistPath"`
	BlocklistPath        string `yaml:"blocklistPath"`
	WebServerOptions     struct {
		Port string `yaml:"port"`
		Username string `yaml:"username"`
        Password string `yaml:"password"`
	} `yaml:"webServerOptions"`
}

// initConfig - Initialize the configuration
func initConfig(configFile string) {
	// Open the config file
	file, err := os.Open(configFile)
	if err != nil {
		log.Printf("Error opening config file: %v\n", err)
		return
	}
	defer file.Close()

	// Read parameters from the config file
	decoder := yaml.NewDecoder(file)
	if err := decoder.Decode(&config); err != nil {
		log.Printf("Error decoding config file: %v\n", err)
		return
	}
}

var sessionToken string

func init() {
    sessionToken = generateSessionToken(32) // 32 байта → 64 hex символа
}

func generateSessionToken(n int) string {
    b := make([]byte, n)
    _, err := rand.Read(b)
    if err != nil {
        panic("failed to generate random session token: " + err.Error())
    }
    return hex.EncodeToString(b)
}

func loginHandler(w http.ResponseWriter, r *http.Request) {
    switch r.Method {
    case http.MethodGet:
        html := `
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Admin Login</title>
  <link href="https://stackpath.bootstrapcdn.com/bootstrap/4.5.2/css/bootstrap.min.css" rel="stylesheet">
  <style>
    body {
      background-color: #212529;
      display: flex;
      justify-content: center;
      align-items: center;
      height: 100vh;
      color: #fff;
    }
    .login-card {
      width: 100%;
      max-width: 400px;
      border: none;
      border-radius: 12px;
      box-shadow: 0 4px 15px rgba(0,0,0,0.4);
      background-color: #2c3034;
    }
    .login-card .card-header {
      border-bottom: none;
    }
    .login-card label {
      color: #ddd;
    }
    .login-card .form-control {
      background-color: #343a40;
      border: 1px solid #495057;
      color: #fff;
    }
    .login-card .form-control:focus {
      background-color: #3d434a;
      border-color: #0d6efd;
      color: #fff;
      box-shadow: none;
    }
    .login-card .btn-primary {
      background-color: #0d6efd;
      border: none;
    }
    .login-card .btn-primary:hover {
      background-color: #0b5ed7;
    }
  </style>
</head>
<body>
  <div class="card login-card">
    <div class="card-header bg-dark text-white text-center">
      <h4>Admin Login</h4>
    </div>
    <div class="card-body">
      <form method="POST" action="/login">
        <div class="form-group">
          <label for="username">Username</label>
          <input name="username" id="username" class="form-control" placeholder="Enter username" required>
        </div>
        <div class="form-group mt-3">
          <label for="password">Password</label>
          <input name="password" type="password" id="password" class="form-control" placeholder="Enter password" required>
        </div>
        <button type="submit" class="btn btn-primary w-100 mt-4">Login</button>
      </form>
    </div>
    <div class="card-footer text-center text-muted">
      &copy; Do-Tek LLC, 2024 - <span id="year"></span>
    </div>
  </div>

  <script>
    document.getElementById("year").textContent = new Date().getFullYear();
  </script>
</body>
</html>
        `
        w.Header().Set("Content-Type", "text/html; charset=utf-8")
        w.Write([]byte(html))

    case http.MethodPost:
        if err := r.ParseForm(); err != nil {
            http.Error(w, "Bad Request", http.StatusBadRequest)
            return
        }

        user := r.FormValue("username")
        pass := r.FormValue("password")

        if user == config.WebServerOptions.Username && pass == config.WebServerOptions.Password {
            http.SetCookie(w, &http.Cookie{
                Name:     "session",
                Value:    sessionToken,
                Path:     "/",
                HttpOnly: true,
                Expires:  time.Now().Add(12 * time.Hour),
            })
            http.Redirect(w, r, "/", http.StatusFound)
            return
        }

        http.Error(w, "Unauthorized", http.StatusUnauthorized)

    default:
        http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
    }
}




func logoutHandler(w http.ResponseWriter, r *http.Request) {
    http.SetCookie(w, &http.Cookie{
        Name:     "session",
        Value:    "",
        Path:     "/",
        Expires:  time.Now().Add(-1 * time.Hour), // просрочить cookie
    })
    http.Redirect(w, r, "/login", http.StatusFound)
}

func authMiddleware(next http.Handler) http.Handler {
    return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        // исключения
        if r.URL.Path == "/login" || r.URL.Path == "/api/downloadFile" {
            next.ServeHTTP(w, r)
            return
        }

        c, err := r.Cookie("session")
        if err != nil || c.Value != sessionToken {
            http.Redirect(w, r, "/login", http.StatusFound)
            return
        }

        next.ServeHTTP(w, r)
    })
}

// IsDirExists - Check if directory exists
func IsDirExists(path string) bool {
	_, err := os.Stat(path)
	if err == nil {
		return true
	}
	if os.IsNotExist(err) {
		return false
	}
	return false
}

// GenerateDirs - Create directory if not exists
func GenerateDirs(directoryPath string) {
	// Check if directory exists
	if _, err := os.Stat(directoryPath); os.IsNotExist(err) {
		// Catalog does not exist, create it
		err := os.MkdirAll(directoryPath, 0755)
		if err != nil {
			//fmt.Println("Error creating directory:", err)
			return
		}
		fmt.Println("Directory created:", directoryPath)
	} else if err != nil {
		// Called another error
		fmt.Println("Error checking directory:", err)
		return
	} else {
		// Catalog already exists
		//fmt.Println("Directory already exists:", directoryPath)
		return
	}
}

// Эндпоинт для скачивания файлов из директории data
func downloadFile(w http.ResponseWriter, r *http.Request) {
	fileName := r.URL.Query().Get("file")
	if fileName == "" {
		log.Println("Download file. Missing file parameter (filename is empty)")
		http.Error(w, "Missing file parameter", http.StatusBadRequest)
		return
	}

	// Очищаем имя файла, чтобы избежать перехода в другие директории
	fileName = filepath.Clean(fileName)
	filePath := filepath.Join(dataDir, fileName)

	// Проверка существования файла
	if _, err := os.Stat(filePath); os.IsNotExist(err) {
		log.Println("Download file. File not found:", filePath)
		http.Error(w, "File not found", http.StatusNotFound)
		return
	}

	// Отправляем файл на скачивание
	w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=%s", fileName))
	w.Header().Set("Content-Type", "application/octet-stream")
	http.ServeFile(w, r, filePath)
}

func sortLines(lines []string) []string {
	sort.Sort(sort.Reverse(sort.StringSlice(lines)))
	return lines
}

func readLines(filePath string) ([]string, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var lines []string
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		lines = append(lines, scanner.Text())
	}
	sort.Strings(lines)
	return lines, scanner.Err()
}

func writeLines(filePath string, lines []string) error {
	file, err := os.Create(filePath)
	if err != nil {
		return err
	}
	defer file.Close()

	writer := bufio.NewWriter(file)
	for _, line := range lines {
		fmt.Fprintln(writer, line)
	}
	return writer.Flush()
}

func getList(w http.ResponseWriter, r *http.Request) {
	mu.Lock()
	defer mu.Unlock()

	blocklist, err := readLines(blocklistPath)
	if err != nil {
		log.Println("Get list. Failed to read blocklist:", err)
		http.Error(w, "Failed to read blocklist", http.StatusInternalServerError)
		return
	}

	allowlist, err := readLines(allowlistPath)
	if err != nil {
		log.Println("Get list. Failed to read allowlist:", err)
		http.Error(w, "Failed to read allowlist", http.StatusInternalServerError)
		return
	}

	// Sort lines in reverse order
	//blocklist = sortLines(blocklist)
	//allowlist = sortLines(allowlist)

	// Sort lines in alphabetical order
	sort.Strings(blocklist)
	sort.Strings(allowlist)

	response := List{
		Blocklist: blocklist,
		Allowlist: allowlist,
	}

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(response); err != nil {
		log.Println("Get list. Failed to encode response:", err)
		http.Error(w, "Failed to encode response", http.StatusInternalServerError)
	}
}

func getPaginatedList(w http.ResponseWriter, r *http.Request) {
	mu.Lock()
	defer mu.Unlock()

	listType := r.URL.Query().Get("list")
	pageStr := r.URL.Query().Get("page")
	searchQuery := r.URL.Query().Get("search")

	var filePath string
	var list []string

	switch listType {
	case "blocklist":
		filePath = blocklistPath
	case "allowlist":
		filePath = allowlistPath
	default:
		log.Println("Paginator. Invalid list type:", listType)
		http.Error(w, "Invalid list type", http.StatusBadRequest)
		return
	}

	var err error
	list, err = readLines(filePath)
	if err != nil {
		log.Println("Paginator. Failed to read file:", err)
		http.Error(w, "Failed to read file", http.StatusInternalServerError)
		return
	}

	// Filter by search query
	if searchQuery != "" {
		var filteredList []string
		searchLower := strings.ToLower(searchQuery)
		for _, item := range list {
			if strings.Contains(strings.ToLower(item), searchLower) {
				filteredList = append(filteredList, item)
			}
		}
		list = filteredList
	}

	// Пагинация
	page, err := strconv.Atoi(pageStr)
	if err != nil || page < 1 {
		page = 1
	}

	const pageSize = 50
	start := (page - 1) * pageSize
	end := start + pageSize

	if start > len(list) {
		start = len(list)
	}
	if end > len(list) {
		end = len(list)
	}

	paginatedList := list[start:end]

	response := struct {
		List       []string `json:"list"`
		TotalCount int      `json:"totalCount"`
	}{
		List:       paginatedList,
		TotalCount: len(list),
	}

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(response); err != nil {
		log.Println("Paginator. Failed to encode response:", err)
		http.Error(w, "Failed to encode response", http.StatusInternalServerError)
	}
}

func addDomain(w http.ResponseWriter, r *http.Request) {
	mu.Lock()
	defer mu.Unlock()

	var request struct {
		Domain string `json:"domain"`
		List   string `json:"list"`
	}

	if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
		log.Println("Add domain. Invalid request:", err)
		http.Error(w, "Invalid request", http.StatusBadRequest)
		return
	}

	var filePath string
	if request.List == "blocklist" {
		filePath = blocklistPath
	} else if request.List == "allowlist" {
		filePath = allowlistPath
	} else {
		log.Println("Add domain. Invalid list type:", request.List, filePath)
		http.Error(w, "Invalid list type", http.StatusBadRequest)
		return
	}

	lines, err := readLines(filePath)
	if err != nil {
		log.Println("Add domain. Failed to read file:", err)
		http.Error(w, "Failed to read file", http.StatusInternalServerError)
		return
	}

	lines = append(lines, request.Domain)
	// Sort lines after adding
	//lines = sortLines(lines) // Sort in reverse order
	sort.Strings(lines) // Sort in alphabetical order
	if err := writeLines(filePath, lines); err != nil {
		log.Println("Add domain. Failed to write file:", err)
		http.Error(w, "Failed to write file", http.StatusInternalServerError)
	}
	log.Println("Domain added:", request.Domain)
}

func removeDomain(w http.ResponseWriter, r *http.Request) {
	mu.Lock()
	defer mu.Unlock()

	var request struct {
		Domain string `json:"domain"`
		List   string `json:"list"`
	}

	if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
		log.Println("Remove domain. Invalid request:", err)
		http.Error(w, "Invalid request", http.StatusBadRequest)
		return
	}

	var filePath string
	if request.List == "blocklist" {
		filePath = blocklistPath
	} else if request.List == "allowlist" {
		filePath = allowlistPath
	} else {
		log.Println("Remove domain. Invalid list type:", filePath)
		http.Error(w, "Invalid list type", http.StatusBadRequest)
		return
	}

	lines, err := readLines(filePath)
	if err != nil {
		log.Println("Remove domain. Failed to read file:", err)
		http.Error(w, "Failed to read file", http.StatusInternalServerError)
		return
	}

	updatedLines := remove(lines, request.Domain)
	// Sort lines after removing
	//lines = sortLines(lines) // Sort in reverse order
	sort.Strings(lines) // Sort in alphabetical order
	if err := writeLines(filePath, updatedLines); err != nil {
		log.Println("Remove domain. Failed to write file:", err)
		http.Error(w, "Failed to write file", http.StatusInternalServerError)
	}
	log.Println("Domain removed:", request.Domain)
}

func remove(slice []string, s string) []string {
	for i, v := range slice {
		if v == s {
			return append(slice[:i], slice[i+1:]...)
		}
	}
	return slice
}

func downloadList(w http.ResponseWriter, r *http.Request) {
	list := r.URL.Query().Get("list")
	var filePath string
	if list == "blocklist" {
		filePath = blocklistPath
	} else if list == "allowlist" {
		filePath = allowlistPath
	} else {
		log.Println("Failed to download. Invalid list type:", filePath)
		http.Error(w, "Invalid list type", http.StatusBadRequest)
		return
	}

	w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=%s.txt", list))
	w.Header().Set("Content-Type", "text/plain")
	http.ServeFile(w, r, filePath)
}

func uploadList(w http.ResponseWriter, r *http.Request) {
	list := r.URL.Query().Get("list")
	var filePath string
	if list == "blocklist" {
		filePath = blocklistPath
	} else if list == "allowlist" {
		filePath = allowlistPath
	} else {
		log.Println("Failed to upload. Invalid list type:", filePath)
		http.Error(w, "Invalid list type", http.StatusBadRequest)
		return
	}

	file, _, err := r.FormFile("file")
	if err != nil {
		log.Println("Failed to get file:", err)
		http.Error(w, "Failed to get file", http.StatusBadRequest)
		return
	}
	defer file.Close()

	out, err := os.Create(filePath)
	if err != nil {
		log.Println("Failed to create file:", err)
		http.Error(w, "Failed to create file", http.StatusInternalServerError)
		return
	}
	defer out.Close()

	if _, err := io.Copy(out, file); err != nil {
		log.Println("Failed to write file:", err)
		http.Error(w, "Failed to write file", http.StatusInternalServerError)
	}
}

// Обёртка для логирования IP клиента
func logIP(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		clientIP := r.RemoteAddr
		log.Printf("Client IP: %s", clientIP)
		next.ServeHTTP(w, r)
	})
}

func main() {

	// Check if the config file is provided from the command line
	if len(os.Args) < 2 {
		log.Println("Usage: go run main.go <config.yml>")
		return
	}

	configFile := os.Args[1]
	initConfig(configFile)

	// Set variables according to the config
	dataDir = config.DataDir
	allowlistPath = config.AllowlistPath
	blocklistPath = config.BlocklistPath

	// Enable logging to file and stdout
	if config.EnableLogging {

		if !IsDirExists(config.LogDir) {
			GenerateDirs(config.LogDir)
		}
		logPath := config.LogDir + "/" + config.LogFile
		// logFile, err := os.Create(config.LogFile) // Recreate it every zbld restart
		logFile, err := os.OpenFile(logPath+"_"+time.Now().Format("2006-01-02")+".log", os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0666)
		if err != nil {
			log.Fatal("Log file creation error:", err)
		}
		defer func(logFile *os.File) {
			err := logFile.Close()
			if err != nil {
				log.Printf("Error closing log file: %v", err)
				return // ignore error
			}
		}(logFile)

		multiWriter := io.Writer(logFile)
		if config.EnableConsoleLogging {
			// Create multiwriter for logging to file and stdout
			multiWriter = io.MultiWriter(logFile, os.Stdout)
		}
		// Setups logger to use multiwriter
		log.SetOutput(multiWriter)
		log.Printf("Logging: Enabled. Log file: %s\n", logPath)
	}

	// Create a file server handler to serve static files
	staticFiles, err := fs.Sub(content, "static")
	if err != nil {
		log.Println("Error creating static files handler:", err)
		return
	}

	mux := http.NewServeMux()

	// публичные маршруты
	mux.HandleFunc("/login", loginHandler)
	mux.HandleFunc("/logout", logoutHandler)
	mux.HandleFunc("/api/downloadFile", downloadFile)

	// защищённые
	protected := http.NewServeMux()
	protected.HandleFunc("/api/list", getList)
	protected.HandleFunc("/api/paginated-list", getPaginatedList)
	protected.HandleFunc("/api/add", addDomain)
	protected.HandleFunc("/api/remove", removeDomain)
	protected.HandleFunc("/api/download", downloadList)
	protected.HandleFunc("/api/upload", uploadList)


	// ... остальные API
	protected.Handle("/", logIP(http.FileServer(http.FS(staticFiles))))

	// оборачиваем всё в authMiddleware
	mux.Handle("/", authMiddleware(protected))

	fmt.Println("Server started at :", config.WebServerOptions.Port)
	if err := http.ListenAndServe(":"+config.WebServerOptions.Port, mux); err != nil {
		fmt.Println("Server failed to start:", err)
	}




	// http.HandleFunc("/api/list", getList)
	// http.HandleFunc("/api/paginated-list", getPaginatedList)
	// http.HandleFunc("/api/add", addDomain)
	// http.HandleFunc("/api/remove", removeDomain)
	// http.HandleFunc("/api/download", downloadList)
	// http.HandleFunc("/api/upload", uploadList)
	// http.HandleFunc("/api/downloadFile", downloadFile)

	// // Regular file server
	// //http.Handle("/", http.FileServer(http.Dir("./static")))

	// // Embed static files into the binary
	// //http.Handle("/", http.FileServer(http.FS(staticFiles)))
	// // Оборачиваем FileServer с логированием IP клиента
	// http.Handle("/", logIP(http.FileServer(http.FS(staticFiles))))

	// fmt.Println("Server started at :", config.WebServerOptions.Port)
	// if err := http.ListenAndServe(":"+config.WebServerOptions.Port, nil); err != nil {
	// 	fmt.Println("Server failed to start:", err)
	// }
}
