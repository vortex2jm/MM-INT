from influxdb_client import InfluxDBClient, WritePrecision
from influxdb_client.client.write_api import SYNCHRONOUS

class DataBase:
    def __init__(self, token, org, bucket, url='http://localhost:8086'):
        self.__token = token
        self.__org = org
        self.__bucket = bucket
        self.__url = url
        self.__write_api = InfluxDBClient(url=self.__url, token=self.__token, org=self.__org).write_api(write_options=SYNCHRONOUS)
    
    def write_data(self, point):
        self.__write_api.write(org=self.__org, bucket=self.__bucket, record=point, write_precision=WritePrecision.MS)

    @staticmethod
    def parse_packet(pkt):
        print(pkt)
        return

if __name__ == '__main__':
    pass
