# vim:set ft=dockerfile:
FROM vertexproject/synapse:v2.x.x

RUN apt-get update && apt-get install -y -qq libmagic-dev

COPY entrypoint.sh /vertex/synapse/entrypoint.sh

WORKDIR /vertex

COPY requirements.txt .
RUN python -m pip install -r requirements.txt

COPY fileparser ./fileparser/

EXPOSE 4443
EXPOSE 27492

ENTRYPOINT ["tini", "--", "/vertex/synapse/entrypoint.sh"]

HEALTHCHECK --start-period=10s --retries=1 --timeout=10s --interval=30s CMD python -m synapse.tools.healthcheck -c cell:///vertex/storage/