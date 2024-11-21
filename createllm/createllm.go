package main

import (
	"fmt"
	"io/ioutil"
	"log"
	"os/exec"
)

func main() {
	// 외부 파일 읽기
	jsonData, err := ioutil.ReadFile("/home/jasper/다운로드/workspace/scraping/data.json")
	if err != nil {
		log.Fatalf("Failed to read JSON file: %v", err)
	}

	// 시스템 메시지 생성
	systemMessage := fmt.Sprintf(`
다음은 추가적인 지식과 설정입니다:

%s

이 정보를 포함하여 genian 제품에 대해 답변시 참조하여 주세요.
`, string(jsonData))

	// Modelfile 생성
	modelfileContent := fmt.Sprintf(`
FROM /home/jasper/Llama-3-Open-Ko-8B-Q5_K_M.gguf

TEMPLATE """{{- if .System }}
<s>{{ .System }}</s>
{{- end }}
<s>Human:
{{ .Prompt }}</s>
<s>Assistant:
"""

SYSTEM """
%s

A chat between a curious user and an artificial intelligence assistant. The assistant gives helpful, detailed, and polite answers to the user's questions. 모든 대답은 한국어(Korean)으로 대답해줘.
"""

PARAMETER temperature 0.7
PARAMETER num_predict 3000
PARAMETER num_ctx 4096
PARAMETER stop <s>
PARAMETER stop </s>


`, systemMessage)

	err = ioutil.WriteFile("/home/jasper/Modelfile", []byte(modelfileContent), 0644)
	if err != nil {
		log.Fatalf("Failed to write Modelfile: %v", err)
	}

	// Ollama 명령 실행
	cmd := exec.Command("ollama", "create", "genian-test1", "-f", "/home/jasper/Modelfile")

	output, err := cmd.CombinedOutput()
	if err != nil {
		log.Fatalf("Failed to create model: %v\nOutput: %s", err, output)
	}

	fmt.Println("Model created successfully.")
}
