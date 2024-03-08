from influxdb_client import InfluxDBClient, WritePrecision, Point
from influxdb_client.client.write_api import SYNCHRONOUS

class DataBase:
  def __init__(self, token, org, bucket, url='http://localhost:8086'):
    self.__token = token
    self.__org = org
    self.__bucket = bucket
    self.__url = url
    self.__write_api = InfluxDBClient(url=self.__url, token=self.__token, org=self.__org).write_api(write_options=SYNCHRONOUS)
  
  def write_data(self, points):
    for point in points:
      self.__write_api.write(org=self.__org, bucket=self.__bucket, record=point, write_precision=WritePrecision.MS)
  
  @staticmethod
  def parse_packet(monitoring_data):
    points = []
    count = 0
    port = 1
    for x in range(8):
        # Aritmetic for indexes
        queue = 0
        if count == 2:
            port+=1
            count=0
        if x % 2 != 0:
            queue = 1   
        count +=1
        # Creating data points
        p = Point('IntData').tag('switch_id', monitoring_data['swid']).tag('port', f'p{port}').tag('queue', f'q{queue}')\
        .field('depth', monitoring_data[f'p{port}q{queue}'])
        points.append(p)
    
    return points

if __name__ == '__main__':
    pass
