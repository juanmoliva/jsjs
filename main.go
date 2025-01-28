package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"
	"sync"

	"github.com/BishopFox/jsluice"
	"github.com/juanmoliva/ureal/pkg/requests"
	flag "github.com/spf13/pflag"
)

func main() {
	var Threads int
	var DebugMode bool
	var Proxy string
	var Headers []string

	flag.IntVarP(&Threads, "threads", "t", 5, "number of threads, default 5")
	flag.BoolVarP(&DebugMode, "debug", "d", false, "enable debug mode")
	flag.StringVar(&Proxy, "proxy", "", "proxy URL")
	flag.StringArrayVarP(&Headers, "header", "H", []string{}, "HTTP header to include in the request")

	flag.Parse()

	var HeadersMap = make(map[string]string)
	for _, header := range Headers {
		parts := strings.Split(header, ":")
		if len(parts) != 2 {
			fmt.Fprintf(os.Stderr, "invalid header: %s\n", header)
			os.Exit(1)
		}
		HeadersMap[parts[0]] = parts[1]
	}

	// spin up an output worker
	output := make(chan string)
	errs := make(chan error)
	done := make(chan any)

	go func() {

		for {
			select {
			case out := <-output:
				if out == "" {
					continue
				}
				fmt.Println(out)
			case err := <-errs:
				fmt.Fprintf(os.Stderr, "error: %s\n", err)
			case <-done:
				return
			}
		}
	}()

	jobs := make(chan string)

	httpClientConfig := requests.HttpClientConfig{
		DebugMode: DebugMode,
		Proxy:     Proxy,
	}

	var httpClients []requests.HttpClient
	for i := 0; i < Threads; i++ {
		httpClients = append(httpClients, requests.NewClient(httpClientConfig))
	}

	var wg sync.WaitGroup
	for i := 0; i < Threads; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			for url := range jobs {
				source, err := getSource(url, &httpClients[i], HeadersMap)

				if err != nil {
					errs <- err
					continue
				}

				extractURLsAndSecrets(url, source, output, errs)
			}
		}(i)
	}

	var r io.Reader = os.Stdin
	input := bufio.NewScanner(r)

	for input.Scan() {
		url := input.Text()

		if strings.HasPrefix(url, "http://") || strings.HasPrefix(url, "https://") {
			jobs <- url
		}
	}
	close(jobs)

	wg.Wait()
	done <- struct{}{}
	close(output)
	close(errs)

}

func getSource(url string, client *requests.HttpClient, headers map[string]string) ([]byte, error) {

	httpReqConfig := requests.HttpReqConfig{
		HTTPMethod:  requests.GET,
		HTTPHeaders: headers,
	}

	httpResp, err := client.Make(url, httpReqConfig)
	if err != nil {
		return nil, err
	}

	return httpResp.Body, nil
}

var patternsJson = "[   {     \"name\": \"base64\",     \"value\": \"(eyJ|YTo|Tzo|PD[89]|rO0)[%a-zA-Z0-9+/]+={0,2}\",     \"severity\": \"low\"   },   {     \"name\": \"genericSecret\",     \"key\": \"(secret|private|apiKey|token|api_key|apikey)\",     \"value\": \"[%a-zA-Z0-9+/]+\"   },  {    \"name\": \"firebaseConfig\",    \"severity\": \"high\",    \"object\": [      {\"key\": \"apiKey\", \"value\": \"^AIza.+\"},      {\"key\": \"authDomain\"},      {\"key\": \"projectId\"},      {\"key\": \"storageBucket\"}    ]  }]"

func extractURLsAndSecrets(filename string, source []byte, output chan string, errs chan error) {
	seen := make(map[string]any, 0)

	analyzer := jsluice.NewAnalyzer(source)

	// parse patterns
	patternsReader := strings.NewReader(patternsJson)
	patterns, err := jsluice.ParseUserPatterns(patternsReader)
	if err != nil {
		errs <- err
		return
	}

	analyzer.AddSecretMatchers(patterns.SecretMatchers())

	matches := analyzer.GetSecrets()
	for _, match := range matches {

		match.Filename = filename

		j, err := json.Marshal(match)
		if err != nil {
			continue
		}
		output <- string(j)
	}

	for _, m := range analyzer.GetURLs() {
		m.Filename = filename

		if _, exists := seen[m.URL]; exists {
			continue
		}

		seen[m.URL] = struct{}{}

		j, err := json.Marshal(m)
		if err != nil {
			errs <- err
			continue
		}
		output <- string(j)
	}

	// strings to find xss sources. non case sensitive.
	domXssStrings := []string{
		"location.search",
		"location.hash",
		"searchparam",
		"urlsearch",
		"urlparam",
		"postMessage",
		"istener('message",
		"istener(\"message)",
	}

	for _, domXssString := range domXssStrings {
		if strings.Contains(strings.ToLower(string(source)), domXssString) {
			count := strings.Count(strings.ToLower(string(source)), domXssString)
			output <- fmt.Sprintf("{\"filename\": \"%s\", \"kind\": \"xssSource\", \"sourceFound\": \"%s\", \"count\": %d}", filename, domXssString, count)
		}
	}

}
