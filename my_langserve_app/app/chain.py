from langchain_community.chat_models import ChatOllama
from langchain_core.output_parsers import StrOutputParser
from langchain_core.prompts import ChatPromptTemplate

# Ollama 모델 로드
llm = ChatOllama(model='llama3.1:latest')

# 프롬프트 설정
prompt = ChatPromptTemplate.from_template('{topic}에 대하여 간략히 설명해 줘.')

# 체인 구성
chain = prompt | llm | StrOutputParser()
