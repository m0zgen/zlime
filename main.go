package main

import (
	"bufio"
	"embed"
	"encoding/json"
	"fmt"
	"io"
	"io/fs"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
)

var (
	dataDir       = "data" // Директория, из которой будут скачиваться файлы
	blocklistPath = "data/blocklist.txt"
	allowlistPath = "data/allowlist.txt"
	mu            sync.Mutex
)

//go:embed static/*
var content embed.FS

type List struct {
	Blocklist []string `json:"blocklist"`
	Allowlist []string `json:"allowlist"`
}

// Эндпоинт для скачивания файлов из директории data
func downloadFile(w http.ResponseWriter, r *http.Request) {
	fileName := r.URL.Query().Get("file")
	if fileName == "" {
		http.Error(w, "Missing file parameter", http.StatusBadRequest)
		return
	}

	// Очищаем имя файла, чтобы избежать перехода в другие директории
	fileName = filepath.Clean(fileName)
	filePath := filepath.Join(dataDir, fileName)

	// Проверка существования файла
	if _, err := os.Stat(filePath); os.IsNotExist(err) {
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
		http.Error(w, "Failed to read blocklist", http.StatusInternalServerError)
		return
	}

	allowlist, err := readLines(allowlistPath)
	if err != nil {
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
		http.Error(w, "Invalid list type", http.StatusBadRequest)
		return
	}

	var err error
	list, err = readLines(filePath)
	if err != nil {
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
		http.Error(w, "Invalid request", http.StatusBadRequest)
		return
	}

	var filePath string
	if request.List == "blocklist" {
		filePath = blocklistPath
	} else if request.List == "allowlist" {
		filePath = allowlistPath
	} else {
		http.Error(w, "Invalid list type", http.StatusBadRequest)
		return
	}

	lines, err := readLines(filePath)
	if err != nil {
		http.Error(w, "Failed to read file", http.StatusInternalServerError)
		return
	}

	lines = append(lines, request.Domain)
	// Sort lines after adding
	//lines = sortLines(lines) // Sort in reverse order
	sort.Strings(lines) // Sort in alphabetical order
	if err := writeLines(filePath, lines); err != nil {
		http.Error(w, "Failed to write file", http.StatusInternalServerError)
	}
}

func removeDomain(w http.ResponseWriter, r *http.Request) {
	mu.Lock()
	defer mu.Unlock()

	var request struct {
		Domain string `json:"domain"`
		List   string `json:"list"`
	}

	if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
		http.Error(w, "Invalid request", http.StatusBadRequest)
		return
	}

	var filePath string
	if request.List == "blocklist" {
		filePath = blocklistPath
	} else if request.List == "allowlist" {
		filePath = allowlistPath
	} else {
		http.Error(w, "Invalid list type", http.StatusBadRequest)
		return
	}

	lines, err := readLines(filePath)
	if err != nil {
		http.Error(w, "Failed to read file", http.StatusInternalServerError)
		return
	}

	updatedLines := remove(lines, request.Domain)
	// Sort lines after removing
	//lines = sortLines(lines) // Sort in reverse order
	sort.Strings(lines) // Sort in alphabetical order
	if err := writeLines(filePath, updatedLines); err != nil {
		http.Error(w, "Failed to write file", http.StatusInternalServerError)
	}
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
		http.Error(w, "Invalid list type", http.StatusBadRequest)
		return
	}

	file, _, err := r.FormFile("file")
	if err != nil {
		http.Error(w, "Failed to get file", http.StatusBadRequest)
		return
	}
	defer file.Close()

	out, err := os.Create(filePath)
	if err != nil {
		http.Error(w, "Failed to create file", http.StatusInternalServerError)
		return
	}
	defer out.Close()

	if _, err := io.Copy(out, file); err != nil {
		http.Error(w, "Failed to write file", http.StatusInternalServerError)
	}
}

func main() {
	// Create a file server handler to serve static files
	staticFiles, err := fs.Sub(content, "static")
	if err != nil {
		fmt.Println("Error creating static files handler:", err)
		return
	}

	http.HandleFunc("/api/list", getList)
	http.HandleFunc("/api/paginated-list", getPaginatedList)
	http.HandleFunc("/api/add", addDomain)
	http.HandleFunc("/api/remove", removeDomain)
	http.HandleFunc("/api/download", downloadList)
	http.HandleFunc("/api/upload", uploadList)
	http.HandleFunc("/api/downloadFile", downloadFile)

	// Regular file server
	//http.Handle("/", http.FileServer(http.Dir("./static")))

	// Embed static files into the binary
	http.Handle("/", http.FileServer(http.FS(staticFiles)))

	fmt.Println("Server started at :8080")
	if err := http.ListenAndServe(":8080", nil); err != nil {
		fmt.Println("Server failed to start:", err)
	}
}
