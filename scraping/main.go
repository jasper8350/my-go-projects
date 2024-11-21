package main

import (
	"encoding/json"
	"log"
	"net/http"
	"net/url"
	"os"
	"strings"

	"github.com/PuerkitoBio/goquery"
)

func main() {
	startURL := "https://docs.genians.com/nac/6.0/release/ko/"
	visited := make(map[string]bool)
	dataMap := make(map[string]bool) // 중복 제거를 위한 맵

	crawl(startURL, visited, dataMap)

	// 중복이 제거된 데이터를 슬라이스로 변환
	var uniqueData []string
	for item := range dataMap {
		uniqueData = append(uniqueData, item)
	}

	// JSON으로 변환
	jsonData, err := json.MarshalIndent(uniqueData, "", "  ")
	if err != nil {
		log.Fatal(err)
	}

	// JSON 파일로 저장
	err = os.WriteFile("data.json", jsonData, 0644)
	if err != nil {
		log.Fatal(err)
	}
}

func crawl(pageURL string, visited map[string]bool, dataMap map[string]bool) {
	if visited[pageURL] {
		return
	}

	visited[pageURL] = true

	res, err := http.Get(pageURL)
	if err != nil {
		log.Println(err)
		return
	}
	defer res.Body.Close()

	if res.StatusCode != 200 {
		log.Printf("Error: status code %d for %s\n", res.StatusCode, pageURL)
		return
	}

	doc, err := goquery.NewDocumentFromReader(res.Body)
	if err != nil {
		log.Println(err)
		return
	}

	doc.Find("p").Each(func(index int, item *goquery.Selection) {
		text := strings.TrimSpace(item.Text())
		if text != "" {
			dataMap[text] = true // 중복 제거를 위해 맵에 추가
		}
	})

	doc.Find("a").Each(func(index int, item *goquery.Selection) {
		href, exists := item.Attr("href")
		if exists {
			absoluteURL := resolveURL(href, pageURL)
			if strings.HasPrefix(absoluteURL, pageURL) && !visited[absoluteURL] {
				crawl(absoluteURL, visited, dataMap)
			}
		}
	})
}

func resolveURL(href string, base string) string {
	u, err := url.Parse(href)
	if err != nil {
		return ""
	}

	baseParsed, err := url.Parse(base)
	if err != nil {
		return ""
	}

	return baseParsed.ResolveReference(u).String()
}
