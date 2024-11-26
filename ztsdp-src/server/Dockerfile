# 최종 이미지 생성
FROM ubuntu:latest

# 필요한 패키지 설치
RUN apt-get update && \
    apt-get install -y ca-certificates iptables && \
    rm -rf /var/lib/apt/lists/*

# 컴파일된 바이너리를 현재 디렉토리에서 복사
COPY ./ztsdpd /usr/local/bin/
COPY ./startup.sh /etc/init.d/

# 컨테이너 실행시 실행할 명령 설정
CMD ["/etc/init.d/startup.sh" "start"]
