# CIRCL Vulnerability-Lookup を Claude のカスタムコネクタとして使うための中継サーバー。
# 外に開くのは 8080 番だけ。中で動くのは Python の小さなサーバー1つ。
FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PORT=8080

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY server.py .

# root では動かさない
RUN useradd --system --uid 10001 app
USER 10001

EXPOSE 8080
CMD ["python", "/app/server.py"]
