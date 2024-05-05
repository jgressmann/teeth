# SPDX-License-Identifier: MIT
#
# Copyright (c) 2024 Jean Gressmann <jean@0x42.de>
#

from fastapi import FastAPI, status, HTTPException
from fastapi.responses import RedirectResponse
from pydantic import BaseModel, Field
from pydantic_settings import BaseSettings, YamlConfigSettingsSource, SettingsConfigDict, PydanticBaseSettingsSource
from typing import List, Tuple, Type
import re
import subprocess
import threading
from contextlib import asynccontextmanager
import logging
import time

# logging.basicConfig(format="")
logger = logging.getLogger(__file__)

class Settings(BaseSettings):
    nics_to_filter: List[str] = Field([], title="Network interfaces to filter out")
    model_config = SettingsConfigDict(yaml_file="config.yaml")

    @classmethod
    def settings_customise_sources(
        cls,
        settings_cls: Type[BaseSettings],
        init_settings: PydanticBaseSettingsSource,
        env_settings: PydanticBaseSettingsSource,
        dotenv_settings: PydanticBaseSettingsSource,
        file_secret_settings: PydanticBaseSettingsSource,
    ) -> Tuple[PydanticBaseSettingsSource, ...]:
        return (YamlConfigSettingsSource(settings_cls),)


class Interface(BaseModel):
    name: str = Field(title="Network interface name", description="Linux name of the interface")
    state: List[str] | None = Field([], description="interface state flags such as UP, BROADCAST, MULTICAST")
    port: int | None = Field(None, description="TCP port the interface is available on")
    mac: str | None = Field(None, title="Network interface MAC address")


class TimeUtc(BaseModel):
    nanos: int = Field(title="Time stamp in nanoseconds")


interfaces: List[Interface] = []
shutdown_event = threading.Event()
state_lock = threading.Lock()
settings = Settings()

print(settings)

def poll_interface_state():
    global shutdown_event
    global state_lock
    global interfaces
    global settings
#     1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN group default qlen 1000
#     link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00
#     inet 127.0.0.1/8 scope host lo
#        valid_lft forever preferred_lft forever
#     inet6 ::1/128 scope host
#        valid_lft forever preferred_lft forever
# 2: enp9s0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc fq_codel master br0 state UP group default qlen 1000
#     link/ether 38:d5:47:7c:07:53

    name_and_flags = re.compile("^\\d+:\\s+(\\S+):\\s+<([^>]*)>.*$")
    mac = re.compile("^\\s*link/ether\\s+([0-9a-fA-F:]+)\\s+.*$")
    wait_s = 0


    while not shutdown_event.wait(wait_s):
        wait_s = 1
        nics: List[Interface] = []

        proc = subprocess.run(["ip", "link"], capture_output=True)

        if proc.returncode == 0:
            nic = None

            for line in proc.stdout.decode("utf-8").splitlines():
                m = name_and_flags.match(line)

                if m:
                    name = m[1]
                    flags = m[2]

                    if name not in settings.nics_to_filter:
                        nic = Interface(name=name, state=flags.split(","))
                        nics.append(nic)

                else:
                    m = mac.match(line)

                    if m and nic:
                        nic.mac = m[1]
                        nic = None

            for nic in nics:
                for itf in interfaces:
                    if itf.name == nic.name:
                        nic.port = itf.port
                        break


            with state_lock:
                interfaces = nics


@asynccontextmanager
async def lifespan(app: FastAPI):
    global shutdown_event

    shutdown_event.clear()
    poll_thread = threading.Thread(group=None, target=poll_interface_state, name="poll interfaces", args=())
    poll_thread.start()
    yield
    shutdown_event.set()
    poll_thread.join()


app = FastAPI(
    title="Teeth",
    description="Configure ethernet interfaces to TCP mapping",
    version="0.0.1",
    lifespan=lifespan)

@app.get("/", response_class=RedirectResponse, description="Redirect to OpenAPI description")
async def root():
    return RedirectResponse(url="/openapi.json")


@app.get("/nics", description="Get the list of interfaces", response_model=List[Interface], response_model_exclude_unset=True)
async def nics_get():
    return interfaces


@app.patch("/nics/{name}", response_model=Interface, description="Patch interface with TCP port", response_model_exclude_unset=True)
async def nics_patch(name: str, nic: Interface):
    global state_lock

    with state_lock:
        for i, itf in enumerate(interfaces):
            if itf.name == name:
                # itf.client = nic.client
                itf.port = nic.port

                return itf


    raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Item not found")

@app.get("/time/utc", response_model=TimeUtc, description="Get system time (UTC)")
async def time_utc_get():
    return TimeUtc(nanos=time.clock_gettime_ns(time.CLOCK_REALTIME))


@app.put("/time/utc", description="Set system time (UTC)")
async def time_utc_put(time_stamp: TimeUtc):
    try:
        time.clock_settime_ns(time.CLOCK_REALTIME, time_stamp.nanos)
    except Exception as e:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=str(e))























