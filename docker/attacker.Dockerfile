# 어태커 컨테이너 (Kali rolling 최소 구성)
FROM kalilinux/kali-rolling
ENV DEBIAN_FRONTEND=noninteractive
ENV PYTHONDONTWRITEBYTECODE=1

# policy, 모델 API 호출, 명시된 공격 도구에 필요한 최소 패키지
RUN sed -i 's|http://http.kali.org/kali/|http://kali.download/kali/|' /etc/apt/sources.list.d/kali.sources \
    && apt-get update && apt-get install -y --no-install-recommends \
    python3 python3-pip python3-requests python3-yaml curl ca-certificates \
    sqlmap nmap hashcat john ocl-icd-libopencl1 pocl-opencl-icd \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY pyproject.toml ./
COPY src ./src
COPY knowledge ./knowledge
ENV PYTHONPATH=/app/src
RUN python3 -m pip install --no-cache-dir --break-system-packages .

# scenario는 이미지에 넣지 않고 실행할 때 마운트한다.
#   예: -v %cd%\scenarios:/app/scenarios
# 에이전트 로직만 담는다. 모델은 밖(call_llm).
ENTRYPOINT ["python3", "-B", "-m", "ranger.agent"]
