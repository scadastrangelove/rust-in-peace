FROM python:3.11-slim
WORKDIR /work
COPY app.py /work/app/app.py
COPY public-request.json /work/public-request.json
RUN mkdir -p /work/state && chmod 1777 /work/state
USER 10001:10001
ENTRYPOINT ["python3", "/work/app/app.py"]
