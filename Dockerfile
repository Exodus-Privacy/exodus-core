FROM python:3.9-slim-bullseye

COPY ./requirements.txt /opt/requirements.txt
RUN pip3 install -r /opt/requirements.txt

COPY . /exodus-core
WORKDIR /exodus-core

ENV PATH "${PATH}:/exodus-core/exodus_core/dexdump/"
