## Building
```
docker build . -t p0f
```

## Testing
```
docker run --name p0f -d -i -t p0f /bin/sh && docker exec -u root -it p0f sh
```

## Running (json logs stored in logs folder)
```
mkdir logs
docker compose up
```