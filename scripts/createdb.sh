docker run \
    --name influx_db -d \
    -p 8086:8086 \
    -v /home/vagrant/MM-INT/influxdb_volume:/var/lib/influxdb2 \
    influxdb:latest
