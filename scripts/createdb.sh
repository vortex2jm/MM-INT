docker run \
    --name influx_db -d \
    -p 8086:8086 \
    -v /home/joao/Code/ic/MPolka-Int-Database/influxdb_volume:/var/lib/influxdb2 \
    influxdb:latest
