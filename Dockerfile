FROM mwader/static-ffmpeg:6.0-1 AS ffmpeg

FROM python:3.10.11-slim

RUN apt-get update && apt-get install -y make

WORKDIR /app

COPY . /app/

RUN make install

EXPOSE 5000

CMD ["python", "web.py"]

