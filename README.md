# teeth

This is a collection of tools aimed at exposing ethernet network interfaces over TCP.
Teeth can be useful in situation in which you don't have low level access to an
ethernet interface.

The `teethd` service is expected to run on a Linux machine, a client implementing the
`teeth.h` protocol can run on any machine.

## Building

### REST service

You need python3, the `venv` module, and likely an internet connection.

```shell
python3 -m venv rest/.venv
. rest/.venv/bin/activate
pip install -r rest/requirements.txt
```

### teethd

```shell
mkdir build
cmake -Bbuild -S.
cmake --build build --config Release
```

## Running

### REST service

```shell
cd rest
. .venv/bin/activate
uvicorn teeth:app
```

Output should be similar to:

```text
INFO:     Started server process [160205]
INFO:     Waiting for application startup.
INFO:     Application startup complete.
INFO:     Uvicorn running on http://127.0.0.1:8000 (Press CTRL+C to quit)
```

Point your browser at http://127.0.0.1:8000/docs to interact with the service.

### teethd

To run the daemon, you need two ethernet network interfaces plugging into your machine. Assuming `eth0` being
the nic you want the daemon to listen on and `eth1` being the nic you want to receive/send from:

```shell
sudo ./build/teethd eth0 eth1 -v
```

Output should be similar to:

```text
INFO: eth1 supports software rx timestamps
INFO: listen on port 12345
```


Now you are ready to monitor the network traffic on `eth1` with `build/teeth-dump` or generate frames with `build/teeth-gen`.

## REST service and daemon integration

The role of the REST service is to make nics exposed through the daemon discoverable.
To this end, the daemon must register the port it runs on.
For the example above, this can be achieved like so:

```shell
curl -q --no-progress-meter \
  -X PATCH http://127.0.0.1:8000/nics/eth1 \
  -H 'accept: application/json' \
  -H 'Content-Type: application/json' \
  -d "{\"name\":\"eth1\",\"port\":12345}"
```

Output should be similar to:

```JSON
{"name":"eth1","state":["NO-CARRIER","BROADCAST","MULTICAST","UP"],"port":12345,"mac":"11:22:33:44:55:66"}
```
