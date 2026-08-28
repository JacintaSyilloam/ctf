docker build -t web_note . 
docker run --name=web_note --rm -p4512:2025 -it web_note