FROM public.ecr.aws/docker/library/python:3-slim AS builder
COPY . /app
WORKDIR /app
RUN pip3 install --no-cache-dir --target=/app -r requirements.txt

FROM public.ecr.aws/docker/library/python:3-slim AS worker
COPY --from=builder /app /app
WORKDIR /app
ENV PYTHONPATH /app
CMD ["/app/main.py"]
