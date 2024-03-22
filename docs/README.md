# Usage

## Setting up database

Before following the steps below, ensure you have already executed [installation](../README.md) tutorial.

The tool is based on [InfluxDB](https://www.influxdata.com/). You've already created a docker container instance for it. Therefore, you should access the client through your browser. Then, type the following link in the URL bar:

```
http://localhost:8086
```

After that you'll encounter the following page:

![](./assets/influxstart.png)

Get started and create new credentials to your database. You can choose *username*, *password* and *Initial Bucket Name*, but the *Initial Organization Name* must be **MM-Int** like in the image below:

![](./assets/influxcred.png)


Copy the *TOKEN* in the next page and paste into **.env.examle**. You also have to rename this file to **.env**. 

![](./assets/influxtoken.png)

Click on **Configure Later** and lets create new buckets

![](./assets/influxinitial.png)

Here you should create 4 buckets. You can choose the names, but I suggest choose simple names, cause each one will store data from each edge switch in the topology. In this case, I have named as **e1, e2, e3 and e4**.

![](./assets/influxbucket.png)


## Running Topology

In the root directory execute the following command:
```bash
sudo python3 main.py -s 3
```
or 
```bash
sudo python3 main.py -s 1
```

The flag *-s* selects the solution. If you don't know about the 
solutions, you can read the article with details.


## Managing tool

If you've done everything correctly so far, the Mininet CLI should be open.
