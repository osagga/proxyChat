# proxyChat
<img width="238" alt="screen shot 2018-03-17 at 9 53 49 am" src="https://user-images.githubusercontent.com/5073889/37556522-d7480cca-29cd-11e8-88de-4eeff8bd0b31.png" class="center">

Group chat app that uses NuCypher

# Setup
Configure the NuCypher Mock network through: https://github.com/nucypher/mock-net
  - Make sure to install `pyUmbral` as shown in the link above.

## Dependencies:
- JsonPickle ([here](https://github.com/jsonpickle/jsonpickle))
  - Install as follows:
    ```bash
    pip3 install -U jsonpickle
    ```

## Server setup:
```
python3 node.py [IP] [PORT]
```
Ex: 
```
python3 node.py 127.0.0.1 8081
```


## Client setup: 
```
python3 client.py [node_IP] [node_PORT]
```
Ex: 
```
python3 client.py 127.0.0.1 8081
```