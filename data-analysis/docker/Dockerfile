########################################################################################
FROM python:3.8-slim-buster
########################################################################################

USER root

RUN useradd -m runner
RUN mkdir -p /usr/share/man/man1
RUN apt-get update && apt-get install -y git && apt-get -y autoremove && apt-get clean

USER runner

WORKDIR /home/runner

COPY --chown=runner requirements.txt .
RUN python -m pip install -r requirements.txt --no-warn-script-location

COPY --chown=runner src src/
COPY --chown=runner data data/
COPY --chown=runner .env* .

RUN if test ! -f .env; then cp .env.example .env; fi

ENTRYPOINT ["python", "-u", "src/run_all.py", "-d", "./data/update_data.p"]
