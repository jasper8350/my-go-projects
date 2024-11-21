// Create by Jasper 2024.11.19
// First Commit 24.11.20
package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"path/filepath"
	"strings"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/app"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/widget"
)

type Message struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

type RequestBody struct {
	Model       string    `json:"model"`
	Messages    []Message `json:"messages"`
	MaxTokens   int       `json:"max_tokens"`
	Temperature float64   `json:"temperature"`
	TopP        float64   `json:"top_p"`
	Stream      bool      `json:"stream"`
}

type Choice struct {
	Message struct {
		Content string `json:"content"`
	} `json:"message"`
}

type Response struct {
	Choices []Choice `json:"choices"`
}

var messages []Message
var chatHistory *widget.Entry

func loadAPIKey() string {
	homeDir, err := os.UserHomeDir()
	if err != nil {
		fmt.Println("홈 디렉토리를 찾을 수 없습니다:", err)
		return ""
	}

	configPath := filepath.Join(homeDir, "ask-perplexity-key.conf")
	content, err := ioutil.ReadFile(configPath)
	if err != nil {
		fmt.Println("설정 파일을 읽을 수 없습니다:", err)
		return ""
	}

	return strings.TrimSpace(string(content))
}

func init() {
	messages = append(messages, Message{
		Role:    "system",
		Content: "모든 응답은 반드시 한국어로 해주세요. 질문이 영어로 들어와도 한국어로 답변해주세요. 답변할 때는 가능한 한 자세하고 구체적으로 설명해주세요. 예시나 부연설명을 포함하여 충분히 긴 답변을 제공해주세요.",
	})
}

func sendMessage(apiKey string, userInput string) string {
	url := "https://api.perplexity.ai/chat/completions"

	messages = append(messages, Message{
		Role:    "user",
		Content: userInput + " (자세하게 설명해주세요)",
	})

	requestBody := RequestBody{
		Model:       "llama-3.1-sonar-large-128k-online",
		Messages:    messages,
		MaxTokens:   2000,
		Temperature: 0.8,
		TopP:        0.9,
		Stream:      false,
	}

	jsonData, err := json.Marshal(requestBody)
	if err != nil {
		return fmt.Sprintf("Error marshaling JSON: %v", err)
	}

	req, err := http.NewRequest("POST", url, bytes.NewBuffer(jsonData))
	if err != nil {
		return fmt.Sprintf("Error creating request: %v", err)
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+apiKey)
	req.Header.Set("Accept-Language", "ko-KR")

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Sprintf("Error making request: %v", err)
	}
	defer resp.Body.Close()

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return fmt.Sprintf("Error reading response: %v", err)
	}

	var response Response
	err = json.Unmarshal(body, &response)
	if err != nil {
		return fmt.Sprintf("Error parsing response: %v", err)
	}

	if len(response.Choices) > 0 {
		messages = append(messages, Message{
			Role:    "assistant",
			Content: response.Choices[0].Message.Content,
		})
		return response.Choices[0].Message.Content
	}

	return "응답을 받지 못했습니다"
}

func handleMessage(input *widget.Entry, chatHistory *widget.Entry, apiKey string) {
	userMessage := input.Text
	if userMessage == "" {
		return
	}

	chatHistory.SetText(chatHistory.Text + "\n사용자: " + userMessage)

	response := sendMessage(apiKey, userMessage)
	chatHistory.SetText(chatHistory.Text + "\nAI: " + response)

	input.SetText("")
}

func main() {
	apiKey := loadAPIKey()
	if apiKey == "" {
		fmt.Println("API 키를 설정 파일에서 찾을 수 없습니다")
		return
	}

	myApp := app.New()
	window := myApp.NewWindow("Perplexity AI 채팅")

	chatHistory = widget.NewMultiLineEntry()
	chatHistory.MultiLine = true
	chatHistory.Wrapping = fyne.TextWrapWord
	chatHistory.Disable()

	input := widget.NewMultiLineEntry()
	input.MultiLine = true
	input.Wrapping = fyne.TextWrapWord
	input.SetPlaceHolder("메시지를 입력하세요 :)")

	sendButton := widget.NewButton("전송", func() {
		handleMessage(input, chatHistory, apiKey)
	})

	inputContainer := container.NewBorder(nil, nil, nil, sendButton, input)
	content := container.NewBorder(
		nil,
		container.NewPadded(inputContainer),
		nil,
		nil,
		container.NewPadded(chatHistory),
	)

	window.SetContent(content)
	window.Resize(fyne.NewSize(800, 600))
	window.ShowAndRun()
}
