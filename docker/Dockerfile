# This should match the default Python version in the test actions
ARG python_version=3.8
FROM python:${python_version}-slim as base

WORKDIR /work

RUN pip3 install poetry && \
    poetry config virtualenvs.create false --local && \
    apt update -y && apt install -y gcc

ADD poetry.lock .
ADD pyproject.toml .
ADD tunelo ./tunelo

RUN poetry install --no-dev

EXPOSE 8001
CMD [ "tunelo-api" ]
